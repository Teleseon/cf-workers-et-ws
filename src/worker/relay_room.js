/**
 * EasyTier WebSocket 中继房间（Cloudflare Durable Object）
 *
 * 核心职责：
 * - 接受 WebSocket 连接，通过 DO Hibernation API 管理生命周期
 * - 心跳检测（10s 发 Ping / 25s 无 Pong 则踢出）
 * - 消息路由：HandShake / Ping / Pong / RpcReq / RpcResp / 转发
 * - 断线清理：防抖锁防止重复清理引发广播风暴
 *
 * 关于 setInterval 与 DO Hibernation：
 * DO 休眠时 JS 执行暂停，setInterval 回调不会触发。
 * 恢复时 constructor 被重新调用，_restoreSocket → _startHeartbeat
 * 会重新创建定时器，所以心跳在恢复后仍然有效。
 */

import { Buffer } from 'buffer';
import { parseHeader, createHeader } from './core/packet.js';
import { PacketType, HEADER_SIZE, MY_PEER_ID } from './core/constants.js';
import { loadProtos } from './core/protos.js';
import {
  handleHandshake,
  handlePing,
  handleForwarding,
  updateNetworkGroupActivity,
  removeNetworkGroupActivity,
} from './core/basic_handlers.js';
import { handleRpcReq, handleRpcResp } from './core/rpc_handler.js';
import { getPeerManager } from './core/peer_manager.js';
import { wrapPacket, randomU64String } from './core/crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

// 心跳参数（与 wrangler.toml 中的环境变量对应）
const HEARTBEAT_INTERVAL_MS  = 10_000; // 多久发一次 Ping
const CONNECTION_TIMEOUT_MS  = 25_000; // 多久无 Pong 则踢出
const HEARTBEAT_CHECK_MS     = 5_000;  // 定时器检查间隔

export class RelayRoom {
  constructor(state, env) {
    this.state       = state;
    this.env         = env;
    this.types       = loadProtos();
    this.peerManager = getPeerManager();
    this.peerManager.setTypes(this.types);

    // DO Hibernation 恢复后，重建所有 WebSocket 的内存状态
    this.state.getWebSockets().forEach(ws => this._restoreSocket(ws));
  }

  // ──────────────────────────────────────────────────────────────
  // HTTP → WebSocket 升级
  // ──────────────────────────────────────────────────────────────

  async fetch(request) {
    const url    = new URL(request.url);
    // 【修复】原版运算符优先级 bug：'/' + env.WS_PATH || '/ws'
    // 当 WS_PATH 为 undefined 时会得到 '/undefined' 而非 '/ws'
    const wsPath = this.env.WS_PATH ? `/${this.env.WS_PATH}` : '/ws';

    if (url.pathname !== wsPath) {
      return new Response('Not found', { status: 404 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected websocket', { status: 400 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    this.state.acceptWebSocket(server);
    this._initSocket(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  // ──────────────────────────────────────────────────────────────
  // DO WebSocket 事件回调
  // ──────────────────────────────────────────────────────────────

  async webSocketMessage(ws, message) {
    try {
      const buffer = _toBuffer(message);
      if (!buffer) {
        console.warn('[ws] Unsupported message type:', typeof message);
        return;
      }

      ws.lastSeen = Date.now();

      const header = parseHeader(buffer);
      if (!header) {
        console.error('[ws] parseHeader failed, hex=', buffer.toString('hex').slice(0, 64));
        return;
      }

      const payload = buffer.subarray(HEADER_SIZE);
      this._routeMessage(ws, header, payload, buffer);
    } catch (e) {
      // 单条消息失败不关闭连接，记录后继续；心跳负责超时踢出
      console.error('[ws] Message handling error:', e);
    }
  }

  async webSocketClose(ws) {
    this._cleanup(ws);
  }

  async webSocketError(ws) {
    this._cleanup(ws);
  }

  // ──────────────────────────────────────────────────────────────
  // 消息路由
  // ──────────────────────────────────────────────────────────────

  _routeMessage(ws, header, payload, fullBuffer) {
    const { packetType, fromPeerId, toPeerId } = header;

    switch (packetType) {
      case PacketType.HandShake:
        handleHandshake(ws, header, payload, this.types);
        break;

      case PacketType.Ping:
        handlePing(ws, header, payload);
        break;

      case PacketType.Pong:
        this._handlePong(ws);
        break;

      case PacketType.RpcReq:
        // 【修复】原版有大量冗余的重复判断（PacketType.Invalid 重复 3 次）
        // 和错误的 toPeerId===0 路由逻辑。清理为：
        // - toPeerId 为 null/undefined/MY_PEER_ID → 本地处理
        // - toPeerId === 0 (Invalid) → 丢弃（无效包）
        // - 其他 → 转发
        if (toPeerId == null || toPeerId === MY_PEER_ID) {
          handleRpcReq(ws, header, payload, this.types);
        } else if (toPeerId === PacketType.Invalid) {
          // Invalid toPeerId，静默丢弃
        } else {
          handleForwarding(ws, header, fullBuffer, this.types);
        }
        break;

      case PacketType.RpcResp:
        if (toPeerId == null || toPeerId === MY_PEER_ID) {
          handleRpcResp(ws, header, payload, this.types);
        } else {
          handleForwarding(ws, header, fullBuffer, this.types);
        }
        break;

      case PacketType.Data:
      default:
        handleForwarding(ws, header, fullBuffer, this.types);
        break;
    }
  }

  // ──────────────────────────────────────────────────────────────
  // Socket 初始化 / 恢复
  // ──────────────────────────────────────────────────────────────

  _initSocket(ws, meta = {}) {
    const now = Date.now();
    ws.peerId          = meta.peerId          || null;
    ws.groupKey        = meta.groupKey        || null;
    ws.domainName      = meta.domainName      || null;
    ws.serverSessionId = meta.serverSessionId || randomU64String();
    ws.weAreInitiator  = false;
    ws.crypto          = { enabled: false };
    ws.lastSeen        = now;
    ws.lastPingSent    = 0;
    // 【修复】初始化为当前时间而非 0，避免首次心跳检查时因"0距今已超时"
    // 将从未 Pong 的连接立即踢出（冷启动后给客户端足够时间完成握手）
    ws.lastPongReceived  = now;
    ws.heartbeatInterval = null;
    ws.isCleanedUp       = false;
    // 挂载 env 引用，供 wrapPacket 读取 LATENCY_FIRST 等标志
    ws._env = this.env;

    ws.serializeAttachment?.({
      peerId:          ws.peerId,
      groupKey:        ws.groupKey,
      domainName:      ws.domainName,
      serverSessionId: ws.serverSessionId,
    });

    this._startHeartbeat(ws);
  }

  /** DO Hibernation 恢复后重建内存状态 */
  _restoreSocket(ws) {
    const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
    this._initSocket(ws, meta);
    if (ws.peerId && ws.groupKey) {
      this.peerManager.addPeer(ws.peerId, ws);
    }
  }

  // ──────────────────────────────────────────────────────────────
  // 心跳
  // ──────────────────────────────────────────────────────────────

  _startHeartbeat(ws) {
    if (ws.heartbeatInterval) clearInterval(ws.heartbeatInterval);

    ws.heartbeatInterval = setInterval(() => {
      try {
        if (ws.readyState !== WS_OPEN) {
          this._cleanup(ws);
          return;
        }

        const now = Date.now();

        // 发送 Ping
        if (now - ws.lastPingSent >= HEARTBEAT_INTERVAL_MS) {
          this._sendPing(ws);
          ws.lastPingSent = now;
        }

        // 超时检测
        if (now - ws.lastPongReceived > CONNECTION_TIMEOUT_MS) {
          console.log(`[Heartbeat] Timeout for peer ${ws.peerId}, closing`);
          this._cleanup(ws);
          try { ws.close(); } catch (_) {}
        }
      } catch (e) {
        console.error('[Heartbeat] Error in interval:', e);
      }
    }, HEARTBEAT_CHECK_MS);
  }

  _sendPing(ws) {
    try {
      if (ws.readyState !== WS_OPEN) return;
      const pingData = Buffer.from('ping');
      const header   = createHeader(MY_PEER_ID, ws.peerId, PacketType.Ping, pingData.length);
      ws.send(Buffer.concat([header, pingData]));
    } catch (e) {
      console.error(`[Heartbeat] Failed to send ping to peer ${ws.peerId}:`, e);
    }
  }

  _handlePong(ws) {
    ws.lastPongReceived = Date.now();
  }

  // ──────────────────────────────────────────────────────────────
  // 断线清理（含防抖锁，防止重复触发广播风暴）
  // ──────────────────────────────────────────────────────────────

  _cleanup(ws) {
    if (ws.isCleanedUp) return;
    ws.isCleanedUp = true;

    if (ws.heartbeatInterval) {
      clearInterval(ws.heartbeatInterval);
      ws.heartbeatInterval = null;
    }

    if (!ws.peerId) return;

    const groupKey = ws.groupKey;
    const removed  = this.peerManager.removePeer(ws);
    if (removed) {
      try {
        this.peerManager.broadcastRouteUpdate(this.types, groupKey, null, { forceFull: true });
      } catch (_) {}
    }

    if (groupKey && typeof removeNetworkGroupActivity === 'function') {
      try { removeNetworkGroupActivity(groupKey); }
      catch (e) { console.error('[Cleanup] removeNetworkGroupActivity error:', e); }
    }
  }
}

// ──────────────────────────────────────────────────────────────
// 工具函数
// ──────────────────────────────────────────────────────────────

/** 将 WebSocket message 统一转为 Buffer */
function _toBuffer(message) {
  if (message instanceof ArrayBuffer) return Buffer.from(message);
  if (message instanceof Uint8Array)  return Buffer.from(message);
  if (ArrayBuffer.isView(message) && message.buffer) return Buffer.from(message.buffer);
  return null;
}
