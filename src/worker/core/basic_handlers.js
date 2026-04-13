/**
 * EasyTier 基础消息处理器
 *
 * 涵盖：握手 / Ping-Pong / 转发 / 网络组管理
 */

import { MAGIC, VERSION, MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { getPeerManager } from './peer_manager.js';
import { wrapPacket, randomU64String } from './crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

// ──────────────────────────────────────────────────────────────
// 网络组内存注册表
// 注意：这些 Map 的生命周期随 Durable Object 实例，不跨实例共享
// ──────────────────────────────────────────────────────────────

/** networkName -> Set<digestHex> */
const networkDigestRegistry = new Map();

/** groupKey (networkName:digestHex) -> { createdAt, peerCount, lastActivity } */
const networkGroups = new Map();

export function updateNetworkGroupActivity(groupKey) {
  const group = networkGroups.get(groupKey);
  if (group) {
    group.lastActivity = Date.now();
    group.peerCount    = (group.peerCount || 0) + 1;
  }
}

export function removeNetworkGroupActivity(groupKey) {
  const group = networkGroups.get(groupKey);
  if (!group) return;
  group.peerCount = Math.max(0, (group.peerCount || 1) - 1);

  // 24 小时无活动 + 零连接时清理
  if (group.peerCount === 0 && Date.now() - group.lastActivity > 86_400_000) {
    networkGroups.delete(groupKey);
    console.log(`[NetworkGroup] Cleaned up inactive group: ${groupKey}`);
  }
}

export function getNetworkGroupsByNetwork(networkName) {
  const result = [];
  for (const [groupKey, group] of networkGroups.entries()) {
    if (groupKey.startsWith(`${networkName}:`)) {
      result.push({ groupKey, ...group });
    }
  }
  return result;
}

// ──────────────────────────────────────────────────────────────
// 握手
// ──────────────────────────────────────────────────────────────

/**
 * 处理客户端握手请求
 *
 * 【修复】原版有两处 setTimeout（10ms 发响应 + 50ms 推路由），
 * 10ms 延迟在 CF Workers 中不必要（Workers 消息循环是单次请求，
 * 无需等待客户端"准备好"），保留 50ms 推路由 setTimeout 以避免
 * 在握手 send() 完成前立刻塞入大包导致客户端解析失败。
 *
 * 【修复】错误处理中 `e.message && e.message.includes('decode') || e.message.includes('Invalid')`
 * 的运算符优先级 bug：当 e.message 为 undefined 时第二个 .includes() 会 throw TypeError。
 * 改为统一先判断 e.message 存在性。
 */
export function handleHandshake(ws, header, payload, types) {
  try {
    const req = types.HandshakeRequest.decode(payload);

    if (req.magic !== MAGIC) {
      ws.close();
      return;
    }

    const clientNetworkName = req.networkName || '';

    // 私有模式拦截
    const env                = ws._env || {};
    const privateNetworkName = env.EASYTIER_NETWORK_NAME || '';
    if (privateNetworkName && clientNetworkName !== privateNetworkName) {
      console.error(`[Private Mode] Rejected: expected "${privateNetworkName}", got "${clientNetworkName}"`);
      ws.close(1008, 'Network name mismatch');
      return;
    }

    const isPublicServer  = !privateNetworkName;
    const serverNetworkName =
      privateNetworkName ||
      env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME ||
      'public_server';

    // 密码摘要 → groupKey
    const clientDigest = req.networkSecretDigrest
      ? Buffer.from(req.networkSecretDigrest)
      : Buffer.alloc(0);
    const digestHex = clientDigest.toString('hex');

    let existingDigests = networkDigestRegistry.get(clientNetworkName);
    if (!existingDigests) {
      existingDigests = new Set();
      networkDigestRegistry.set(clientNetworkName, existingDigests);
    }
    if (digestHex.length > 0 && !existingDigests.has(digestHex)) {
      existingDigests.add(digestHex);
      console.log(`[Handshake] New digest for network "${clientNetworkName}": ${digestHex}`);
    }

    const groupKey = `${clientNetworkName}:${digestHex}`;
    if (!networkGroups.has(groupKey)) {
      networkGroups.set(groupKey, { createdAt: Date.now(), peerCount: 0, lastActivity: Date.now() });
      console.log(`[Handshake] Created network group: ${groupKey}`);
    }

    // 更新 WebSocket 元数据
    ws.domainName = clientNetworkName;
    ws.groupKey   = groupKey;
    ws.peerId     = req.myPeerId;
    if (!ws.serverSessionId)   ws.serverSessionId   = randomU64String();
    if (ws.weAreInitiator === undefined) ws.weAreInitiator = false;
    ws.crypto = { enabled: false };

    // 注册到 PeerManager
    const pm = getPeerManager();
    pm.addPeer(req.myPeerId, ws);
    updateNetworkGroupActivity(groupKey);
    pm.updatePeerInfo(groupKey, req.myPeerId, {
      peerId:        req.myPeerId,
      version:       1,
      lastUpdate:    { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      instId:        { part1: 0, part2: 0, part3: 0, part4: 0 },
      networkLength: Number(env.EASYTIER_NETWORK_LENGTH || 24),
    });
    pm.setPublicServerFlag(isPublicServer);

    // 构造并立即发送握手响应（无需 setTimeout 10ms）
    const respPayload = {
      magic:                MAGIC,
      myPeerId:             MY_PEER_ID,
      version:              VERSION,
      networkName:          serverNetworkName,
      networkSecretDigrest: new Uint8Array(32),
    };
    const respBuffer = types.HandshakeRequest.encode(respPayload).finish();
    const respHeader = createHeader(MY_PEER_ID, req.myPeerId, PacketType.HandShake, respBuffer.length);
    ws.send(Buffer.concat([respHeader, Buffer.from(respBuffer)]));
    console.log(`[Handshake] Response sent to peer ${req.myPeerId}`);

    // 初始路由推送（50ms 后，确保客户端 HandShake 帧处理完毕）
    setTimeout(() => {
      if (ws.readyState !== WS_OPEN) return;
      try {
        pm.pushRouteUpdateTo(req.myPeerId, ws, types, { forceFull: true });
        pm.broadcastRouteUpdate(types, groupKey, null, { forceFull: true });
        console.log(`[Handshake] Initial route updates sent to peer ${req.myPeerId}`);
      } catch (e) {
        console.error(`[Handshake] Failed to push initial route update to ${req.myPeerId}:`, e.message);
      }
    }, 50);

  } catch (e) {
    console.error('[Handshake] Error:', e);
    // 【修复】原版 `e.message && e.message.includes('decode') || e.message.includes('Invalid')`
    // 存在运算符优先级 bug，当 e.message 为 undefined 时会 throw。
    const msg = e && e.message ? e.message : '';
    if (msg.includes('decode') || msg.includes('Invalid')) {
      ws.close();
    }
    // 其他错误不立即关闭，让心跳机制处理
  }
}

// ──────────────────────────────────────────────────────────────
// Ping 处理
// ──────────────────────────────────────────────────────────────

export function handlePing(ws, header, payload) {
  const msg = wrapPacket(createHeader, MY_PEER_ID, header.fromPeerId, PacketType.Pong, payload, ws,
                         { env: ws._env });
  ws.send(msg);
}

// ──────────────────────────────────────────────────────────────
// 转发
// ──────────────────────────────────────────────────────────────

/**
 * 将消息转发给目标 peer
 * 严格要求 source 和 target 在同一 groupKey 内，防止跨网络泄漏
 */
export function handleForwarding(sourceWs, header, fullMessage, types) {
  const targetPeerId = header.toPeerId;
  const pm          = getPeerManager();
  const targetWs    = pm.getPeerWs(targetPeerId, sourceWs && sourceWs.groupKey);

  if (!targetWs || targetWs.readyState !== WS_OPEN) return;

  const srcGroup = sourceWs && sourceWs.groupKey;
  const dstGroup = targetWs.groupKey;
  if (srcGroup && dstGroup && srcGroup !== dstGroup) {
    console.warn(`[Forward] Cross-group forward blocked: ${srcGroup} -> ${dstGroup}`);
    return;
  }

  try {
    targetWs.send(fullMessage);
  } catch (e) {
    console.error(`[Forward] Failed to forward to ${targetPeerId}: ${e.message}`);
    pm.removePeer(targetWs);
    try {
      pm.broadcastRouteUpdate(types, srcGroup);
    } catch (err) {
      console.error(`[Forward] Broadcast after forward failure failed: ${err.message}`);
    }
  }
}
