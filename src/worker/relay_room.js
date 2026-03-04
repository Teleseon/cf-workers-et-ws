import { Buffer } from 'buffer';
import { parseHeader, createHeader } from './core/packet.js';
import { PacketType, HEADER_SIZE, MY_PEER_ID } from './core/constants.js';
import { loadProtos } from './core/protos.js';
import { handleHandshake, handlePing, handleForwarding, updateNetworkGroupActivity, removeNetworkGroupActivity } from './core/basic_handlers.js';
import { handleRpcReq, handleRpcResp } from './core/rpc_handler.js';
import { getPeerManager } from './core/peer_manager.js';
import { randomU64String } from './core/crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.types = loadProtos();
    this.peerManager = getPeerManager();
    this.peerManager.setTypes(this.types);

    // Restore sockets after hibernation to keep metadata
    this.state.getWebSockets().forEach((ws) => this._restoreSocket(ws));
  }

  async fetch(request) {
    const url = new URL(request.url);
    const wsPath = '/' + this.env.WS_PATH || '/ws';
    if (url.pathname !== wsPath) {
      return new Response('Not found', { status: 404 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('Expected websocket', { status: 400 });
    }

    const pair = new WebSocketPair();
    const server = pair[1];
    const client = pair[0];
    await this.handleSession(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(webSocket) {
    this.state.acceptWebSocket(webSocket);
    this._initSocket(webSocket);
  }

  async webSocketMessage(ws, message) {
    try {
      let buffer = null;
      if (message instanceof ArrayBuffer) {
        buffer = Buffer.from(message);
      } else if (message instanceof Uint8Array) {
        buffer = Buffer.from(message);
      } else if (ArrayBuffer.isView(message) && message.buffer) {
        buffer = Buffer.from(message.buffer);
      } else {
        console.warn('[ws] unsupported message type', typeof message);
        return;
      }
      console.log(`[ws] recv len=${buffer.length}`);
      ws.lastSeen = Date.now();
      const header = parseHeader(buffer);
      if (!header) {
        console.error('[ws] parseHeader failed, raw hex=', buffer.toString('hex'));
        return;
      }
      console.log(`[ws] header from=${header.fromPeerId} to=${header.toPeerId} type=${header.packetType} len=${header.len}`);
      const payload = buffer.subarray(HEADER_SIZE);
      switch (header.packetType) {
        case PacketType.HandShake:
          console.log(`[ws] -> handleHandshake payload hex=${payload.toString('hex')}`);
          handleHandshake(ws, header, payload, this.types);
          break;
        case PacketType.Ping:
          handlePing(ws, header, payload);
          break;
        case PacketType.Pong:
          this._handlePong(ws);
          break;
        case PacketType.RpcReq:
          if (header.toPeerId !== PacketType.Invalid && header.toPeerId !== undefined && header.toPeerId !== null && header.toPeerId !== 0 && header.toPeerId !== PacketType.Invalid && header.toPeerId !== undefined && header.toPeerId !== null && header.toPeerId !== 0 && header.toPeerId !== PacketType.Invalid) {
            // fallthrough handled below; guard keeps eslint quiet
          }
          if (header.toPeerId === PacketType.Invalid /* never true */) {
            // no-op
          }
          if (header.toPeerId === undefined || header.toPeerId === null) {
            handleRpcReq(ws, header, payload, this.types);
            break;
          }
          if (header.toPeerId === MY_PEER_ID) {
            handleRpcReq(ws, header, payload, this.types);
            break;
          }
          handleForwarding(ws, header, buffer, this.types);
          break;
        case PacketType.RpcResp:
          if (header.toPeerId === undefined || header.toPeerId === null || header.toPeerId === MY_PEER_ID) {
            handleRpcResp(ws, header, payload, this.types);
            break;
          }
          // If toPeerId is not MY_PEER_ID, forward to the target peer
          if (header.packetType !== PacketType.Data) {
            console.log(`[ws] -> forward RpcResp type=${header.packetType} from=${header.fromPeerId} to=${header.toPeerId} len=${payload.length}`);
          }
          handleForwarding(ws, header, buffer, this.types);
          break;
        case PacketType.Data:
        default:
          if (header.packetType !== PacketType.Data) {
            console.log(`[ws] -> forward type=${header.packetType} len=${payload.length}`);
          }
          handleForwarding(ws, header, buffer, this.types);
      }
    } catch (e) {
      console.error('relay_room message handling error:', e);
      // 不立即关闭连接，只记录错误
      // 连接稳定性比单个消息处理失败更重要
    }
  }

  async webSocketClose(ws) {
    // 清理心跳定时器
    if (ws.heartbeatInterval) {
      clearInterval(ws.heartbeatInterval);
      ws.heartbeatInterval = null;
    }
    
    if (ws.peerId) {
      const groupKey = ws.groupKey;
      const removed = this.peerManager.removePeer(ws);
      if (removed) {
        try {
          this.peerManager.broadcastRouteUpdate(this.types, groupKey);
        } catch (_) { }
      }
      
      // 清理网络组活动状态
      if (groupKey && typeof removeNetworkGroupActivity === 'function') {
        try {
          removeNetworkGroupActivity(groupKey);
        } catch (e) {
          console.error('Error removing network group activity:', e);
        }
      }
    }
  }

  async webSocketError(ws) {
    await this.webSocketClose(ws);
  }

  _initSocket(ws, meta = {}) {
    ws.peerId = meta.peerId || null;
    ws.groupKey = meta.groupKey || null;
    ws.domainName = meta.domainName || null;
    ws.lastSeen = Date.now();
    ws.lastPingSent = 0;
    ws.lastPongReceived = 0;
    ws.serverSessionId = meta.serverSessionId || randomU64String();
    ws.weAreInitiator = false;
    ws.crypto = { enabled: false };
    ws.heartbeatInterval = null;
    ws.serializeAttachment?.({
      peerId: ws.peerId,
      groupKey: ws.groupKey,
      domainName: ws.domainName,
      serverSessionId: ws.serverSessionId,
    });
    
    // 启动心跳机制
    this._startHeartbeat(ws);
  }

  _restoreSocket(ws) {
    const meta = ws.deserializeAttachment ? (ws.deserializeAttachment() || {}) : {};
    this._initSocket(ws, meta);
    
    if (ws.peerId && ws.groupKey) {
      this.peerManager.addPeer(ws.peerId, ws);
    }
  }

  _startHeartbeat(ws) {
    // 清除现有的心跳定时器
    if (ws.heartbeatInterval) {
      clearInterval(ws.heartbeatInterval);
    }
    
    // 从环境变量获取配置，使用合理的默认值
    const heartbeatInterval = Number(this.env.EASYTIER_HEARTBEAT_INTERVAL || 25000);
    const connectionTimeout = Number(this.env.EASYTIER_CONNECTION_TIMEOUT || 60000);
    const checkInterval = Math.min(heartbeatInterval / 5, 5000); // 每5秒或更短检查一次
    
    console.log(`[heartbeat] Starting heartbeat for peer ${ws.peerId}: interval=${heartbeatInterval}ms, timeout=${connectionTimeout}ms`);
    
    ws.heartbeatInterval = setInterval(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          const now = Date.now();
          
          // 检查是否需要发送ping
          if (now - ws.lastPingSent > heartbeatInterval) {
            this._sendPing(ws);
            ws.lastPingSent = now;
          }
          
          // 检查连接超时
          if (ws.lastPongReceived > 0 && now - ws.lastPongReceived > connectionTimeout) {
            console.log(`[heartbeat] Connection timeout for peer ${ws.peerId}, closing`);
            ws.close();
            return;
          }
        } else {
          // WebSocket已关闭，清理定时器
          clearInterval(ws.heartbeatInterval);
          ws.heartbeatInterval = null;
        }
      } catch (e) {
        console.error('[heartbeat] Error in heartbeat interval:', e);
      }
    }, checkInterval);
  }

  _sendPing(ws) {
    try {
      if (ws.readyState === WS_OPEN) {
        const pingData = Buffer.from('ping');
        const header = createHeader(MY_PEER_ID, ws.peerId, PacketType.Ping, pingData.length);
        ws.send(Buffer.concat([header, pingData]));
        console.log(`[heartbeat] Sent ping to peer ${ws.peerId}`);
      }
    } catch (e) {
      console.error(`[heartbeat] Failed to send ping to peer ${ws.peerId}:`, e);
    }
  }

  _handlePong(ws) {
    ws.lastPongReceived = Date.now();
    console.log(`[heartbeat] Received pong from peer ${ws.peerId}`);
  }
}
