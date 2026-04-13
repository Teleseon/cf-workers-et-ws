import { MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { getPeerManager } from './peer_manager.js';
import { wrapPacket, randomU64String } from './crypto.js';
import { gzipMaybe, gunzipMaybe, isCompressionAvailable } from './compress.js';
import { getPeerCenterState, calcPeerCenterDigestFromMap, buildPeerCenterResponseMap } from './global_state.js';

// ──────────────────────────────────────────────────────────────
// transactionId 工具（原版在 handleRpcReq / handleRpcResp /
// sendRpcResponse 中各写了一遍相同的 50 行；提取为一个函数）
// ──────────────────────────────────────────────────────────────

/**
 * 将 protobufjs 可能返回的各种 int64 类型统一转为 { low, high, unsigned } 形式，
 * 以便安全地传回 protobuf 编码。
 */
function toLongForProto(value) {
  if (value === null || value === undefined) return value;

  if (value && typeof value === 'object' &&
      typeof value.low === 'number' && typeof value.high === 'number') {
    return value; // 已是 Long-like 对象
  }

  if (typeof value === 'bigint') {
    return { low: Number(value & 0xffffffffn), high: Number((value >> 32n) & 0xffffffffn), unsigned: false };
  }

  if (typeof value === 'string') {
    try {
      const big = BigInt(value);
      return { low: Number(big & 0xffffffffn), high: Number((big >> 32n) & 0xffffffffn), unsigned: false };
    } catch {
      console.warn(`[RPC] Failed to parse transactionId string: ${value}`);
      return value;
    }
  }

  if (typeof value === 'number') {
    return { low: value | 0, high: Math.floor(value / 4294967296), unsigned: false };
  }

  return value;
}

/**
 * 将任意 int64 格式的 transactionId 转为可读字符串（仅用于日志）
 */
function txIdToString(txId) {
  if (txId === null || txId === undefined) return 'null';
  if (typeof txId === 'bigint') return txId.toString();
  if (typeof txId === 'string') return txId;
  if (typeof txId === 'number') return String(txId);
  if (txId.constructor && txId.constructor.name === 'Long') return txId.toString();
  if (typeof txId.low === 'number' && typeof txId.high === 'number') {
    const combined = (BigInt(txId.high) << 32n) | BigInt(txId.low >>> 0);
    return combined.toString();
  }
  return String(txId);
}

// ──────────────────────────────────────────────────────────────
// 辅助
// ──────────────────────────────────────────────────────────────

function pm() {
  return getPeerManager();
}

const COMPRESS_THRESHOLD = 256; // bytes；小包不压缩节省 CPU

/**
 * 向指定 peer 发送 RpcResp 包
 */
function sendRpcResponse(ws, toPeerId, reqRpcPacket, types, responseBodyBytes) {
  if (!ws || ws.readyState !== 1) {
    console.error(`[RPC] sendRpcResponse aborted: socket not open (state=${ws ? ws.readyState : 'nil'}) toPeer=${toPeerId}`);
    return;
  }

  // 可选压缩
  let responseBody     = responseBodyBytes;
  let compressionInfo  = { algo: 1, acceptedAlgo: 1 };
  const compressEnabled = (ws._env && ws._env.EASYTIER_COMPRESS_RPC !== '0') ||
                          (typeof process !== 'undefined' && process.env.EASYTIER_COMPRESS_RPC !== '0');
  if (compressEnabled && responseBodyBytes && responseBodyBytes.length > COMPRESS_THRESHOLD && isCompressionAvailable()) {
    try {
      responseBody    = gzipMaybe(responseBodyBytes);
      compressionInfo = { algo: 2, acceptedAlgo: 1 };
    } catch (e) {
      console.warn(`[RPC] Compress response failed: ${e.message}`);
    }
  }

  const rpcResponseBytes = types.RpcResponse.encode({
    response: responseBody,
    error: null,
    runtimeUs: 0,
  }).finish();

  const txIdStr = txIdToString(reqRpcPacket.transactionId);
  console.log(`[RPC] sendRpcResponse -> toPeer=${toPeerId} txId=${txIdStr} len=${rpcResponseBytes.length}`);

  const rpcRespPacket = {
    fromPeer:        MY_PEER_ID,
    toPeer:          toPeerId,
    transactionId:   toLongForProto(reqRpcPacket.transactionId),
    descriptor:      reqRpcPacket.descriptor,
    body:            rpcResponseBytes,
    isRequest:       false,
    totalPieces:     1,
    pieceIdx:        0,
    traceId:         reqRpcPacket.traceId,
    compressionInfo,
  };

  const buf = wrapPacket(createHeader, MY_PEER_ID, toPeerId, PacketType.RpcResp,
                         types.RpcPacket.encode(rpcRespPacket).finish(), ws,
                         { env: ws._env });
  try {
    ws.send(buf);
    console.log(`[RPC] RpcResp -> toPeer=${toPeerId} txId=${txIdStr} SUCCESS`);
  } catch (e) {
    console.error(`[RPC] sendRpcResponse to ${toPeerId} failed: ${e.message}`);
    throw e; // 让调用方感知失败
  }
}

// ──────────────────────────────────────────────────────────────
// 入口：处理 RPC 请求
// ──────────────────────────────────────────────────────────────

export function handleRpcReq(ws, header, payload, types) {
  try {
    const rpcPacket = types.RpcPacket.decode(payload);
    console.log(`[RPC] handleRpcReq from=${header.fromPeerId} txId=${txIdToString(rpcPacket.transactionId)}`);

    // 解压
    if (rpcPacket.compressionInfo && rpcPacket.compressionInfo.algo > 1 && isCompressionAvailable()) {
      try {
        rpcPacket.body = gunzipMaybe(rpcPacket.body);
        rpcPacket.compressionInfo.algo = 1;
      } catch (e) {
        console.error(`[RPC] Decompress failed from ${header.fromPeerId}: ${e.message}`);
        return;
      }
    }

    // 剥离 RpcRequest 外层 wrapper（部分客户端会多包一层）
    let innerBody = rpcPacket.body;
    try {
      const wrapper = types.RpcRequest.decode(rpcPacket.body);
      if (wrapper.request && wrapper.request.length > 0) innerBody = wrapper.request;
    } catch {
      // 忽略，直接使用 raw body
    }

    const desc = rpcPacket.descriptor || {};

    // ── PeerCenterRpc ──
    if (_isPeerCenterRpc(desc)) {
      _handlePeerCenterRpc(ws, header, rpcPacket, innerBody, types, desc);
      return;
    }

    // ── OspfRouteRpc ──
    if (_isOspfRouteRpc(desc)) {
      if (desc.methodIndex === 0 || desc.methodIndex === 1) {
        const req = types.SyncRouteInfoRequest.decode(innerBody);
        console.log(`[RPC] SyncRouteInfo from=${header.fromPeerId} session=${req.mySessionId} initiator=${req.isInitiator}`);
        _handleSyncRouteInfo(ws, header.fromPeerId, rpcPacket, req, types);
        return;
      }
      console.log(`[RPC] Unhandled OspfRouteRpc methodIndex=${desc.methodIndex}`);
      return;
    }

    console.log(`[RPC] Unhandled service=${desc.serviceName} proto=${desc.protoName}`);
  } catch (e) {
    console.error('[RPC] handleRpcReq decode error:', e);
  }
}

// ──────────────────────────────────────────────────────────────
// 入口：处理 RPC 响应
// ──────────────────────────────────────────────────────────────

export function handleRpcResp(ws, header, payload, types) {
  try {
    const rpcPacket = types.RpcPacket.decode(payload);
    console.log(`[RPC] handleRpcResp from=${header.fromPeerId} txId=${txIdToString(rpcPacket.transactionId)}`);

    // 解压
    if (rpcPacket.compressionInfo && rpcPacket.compressionInfo.algo > 1 && isCompressionAvailable()) {
      try {
        rpcPacket.body = gunzipMaybe(rpcPacket.body);
        rpcPacket.compressionInfo.algo = 1;
      } catch (e) {
        console.error(`[RPC] RpcResp decompress failed from ${header.fromPeerId}: ${e.message}`);
        return;
      }
    }

    const desc = rpcPacket.descriptor || {};

    // OspfRouteRpc 响应：更新 session ack
    if (_isOspfRouteRpc(desc)) {
      let respBody = rpcPacket.body;
      try {
        const wrapper = types.RpcResponse.decode(rpcPacket.body);
        if (wrapper.response && wrapper.response.length > 0) respBody = wrapper.response;
      } catch (e) {
        console.warn(`[RPC] RpcResp wrapper decode failed from ${header.fromPeerId}: ${e.message}`);
      }

      try {
        const resp = types.SyncRouteInfoResponse.decode(respBody);
        if (resp && resp.sessionId && ws && ws.groupKey !== undefined) {
          pm().onRouteSessionAck(ws.groupKey, header.fromPeerId, resp.sessionId, ws.weAreInitiator);
          console.log(`[RPC] SyncRouteInfoResponse ack from=${header.fromPeerId} sessionId=${resp.sessionId}`);
        }
      } catch (e) {
        console.error(`[RPC] Decode SyncRouteInfoResponse failed from ${header.fromPeerId}: ${e.message}`);
      }
      return;
    }

    // 通用响应日志
    try {
      const decoded = types.RpcResponse.decode(rpcPacket.body);
      if (decoded.error) {
        console.warn(`[RPC] RpcResp error from ${header.fromPeerId}:`, decoded.error);
      } else {
        console.log(`[RPC] RpcResp from=${header.fromPeerId} ok`);
      }
    } catch {
      // 忽略
    }
  } catch (e) {
    console.error('[RPC] handleRpcResp decode error:', e);
  }
}

// ──────────────────────────────────────────────────────────────
// 内部：PeerCenter RPC
// ──────────────────────────────────────────────────────────────

function _handlePeerCenterRpc(ws, header, rpcPacket, innerBody, types, desc) {
  const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
  const state    = getPeerCenterState(groupKey);

  if (desc.methodIndex === 0) {
    // ReportPeers
    const req = types.ReportPeersRequest.decode(innerBody);
    const directPeers = {};
    if (req.peerInfos && req.peerInfos.directPeers) {
      for (const [dstId, info] of Object.entries(req.peerInfos.directPeers)) {
        directPeers[String(dstId)] = {
          latencyMs: (info && typeof info.latencyMs === 'number') ? info.latencyMs : 0,
        };
      }
    }
    state.globalPeerMap.set(String(req.myPeerId), { directPeers, lastSeen: Date.now() });

    const snapshot = buildPeerCenterResponseMap(groupKey, state, pm());
    state.digest   = calcPeerCenterDigestFromMap(snapshot);

    sendRpcResponse(ws, header.fromPeerId, rpcPacket, types,
                    types.ReportPeersResponse.encode({}).finish());
    return;
  }

  if (desc.methodIndex === 1) {
    // GetGlobalPeerMap — 支持摘要短路（digest 未变则返回空响应）
    const req       = types.GetGlobalPeerMapRequest.decode(innerBody);
    const reqDigest = req.digest !== null && req.digest !== undefined ? String(req.digest) : '0';

    if (reqDigest !== '0' && reqDigest === state.digest) {
      sendRpcResponse(ws, header.fromPeerId, rpcPacket, types,
                      types.GetGlobalPeerMapResponse.encode({}).finish());
      return;
    }

    const snapshot = buildPeerCenterResponseMap(groupKey, state, pm());
    state.digest   = calcPeerCenterDigestFromMap(snapshot);
    sendRpcResponse(ws, header.fromPeerId, rpcPacket, types,
                    types.GetGlobalPeerMapResponse.encode({
                      globalPeerMap: snapshot,
                      digest: state.digest,
                    }).finish());
    return;
  }

  console.log(`[RPC] Unhandled PeerCenterRpc methodIndex=${desc.methodIndex}`);
}

// ──────────────────────────────────────────────────────────────
// 内部：SyncRouteInfo
// ──────────────────────────────────────────────────────────────

function _handleSyncRouteInfo(ws, fromPeerId, reqRpcPacket, syncReq, types) {
  const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';

  if (!ws.serverSessionId) ws.serverSessionId = randomU64String();

  if (typeof syncReq.isInitiator === 'boolean') {
    ws.weAreInitiator = !syncReq.isInitiator;
  }
  pm().onRouteSessionAck(groupKey, fromPeerId, syncReq.mySessionId, ws.weAreInitiator);

  // 处理 peer 信息
  let hasNewPeers = false;
  let hasSubPeers = false;

  if (syncReq.peerInfos && syncReq.peerInfos.items) {
    const items = syncReq.peerInfos.items;
    console.log(`[SyncRoute] Processing ${items.length} peer infos from ${fromPeerId}`);

    // 【修复 Bug1】：isNew 检查必须在 updatePeerInfo 写入之前完成，
    //   否则 infos.has() 永远返回 true，hasNewPeers 永远为 false。
    // 【修复 Bug2】：将 listPeerIdsInGroup（内含 Array.from）和 Set 构造
    //   提到循环外，避免 O(n²) 的重复调用（原版每个 item 都调用一次）。
    const existingInfos = pm()._getPeerInfosMap(groupKey, false);
    const directSet     = new Set(pm().listPeerIdsInGroup(groupKey));

    for (const info of items) {
      // 保留客户端的 STUN 信息；若为 0 则默认 FullCone，鼓励 P2P 打洞
      if (!info.udpStunInfo) info.udpStunInfo = 3;

      const isServer = info.peerId === MY_PEER_ID;

      if (!isServer) {
        // 先判断 isNew（updatePeerInfo 调用前），再写入
        const isNew = !existingInfos || !existingInfos.has(info.peerId);
        if (isNew) hasNewPeers = true;
        if (!directSet.has(info.peerId)) {
          hasSubPeers = true;
          console.log(`[SyncRoute] Discovered sub-peer ${info.peerId} via ${fromPeerId}`);
        }
      }

      pm().updatePeerInfo(groupKey, info.peerId, info);
    }

    // 记录子设备到全局 PeerCenter 状态
    if (hasSubPeers) {
      const subPeerEntries = {};
      for (const info of items) {
        if (info.peerId !== MY_PEER_ID && info.peerId !== fromPeerId) {
          subPeerEntries[String(info.peerId)] = { latencyMs: 10 };
        }
      }
      if (Object.keys(subPeerEntries).length > 0) {
        const state = getPeerCenterState(groupKey);
        state.globalPeerMap.set(String(fromPeerId), { directPeers: subPeerEntries, lastSeen: Date.now() });
        console.log(`[PeerCenter] Updated ${fromPeerId} with ${Object.keys(subPeerEntries).length} sub-peers`);
      }
    }
  }

  // 发送 SyncRouteInfoResponse
  const respBytes = types.SyncRouteInfoResponse.encode({
    isInitiator: !syncReq.isInitiator,
    sessionId:   ws.serverSessionId,
  }).finish();

  try {
    sendRpcResponse(ws, fromPeerId, reqRpcPacket, types, respBytes);
    console.log(`[SyncRoute] SyncRouteInfoResponse sent to ${fromPeerId}`);
  } catch (e) {
    console.error(`[SyncRoute] CRITICAL: Failed to send SyncRouteInfoResponse to ${fromPeerId}: ${e.message}`);
    // 不重新抛出：确保后续的路由推送仍能执行
  }

  // 推送路由信息给请求方
  try {
    pm().pushRouteUpdateTo(fromPeerId, ws, types, { forceFull: true });
  } catch (e) {
    console.error(`[SyncRoute] Failed to push route update to ${fromPeerId}:`, e);
  }

  // 若拓扑变化，广播给组内其他 peer
  if (hasNewPeers || hasSubPeers) {
    try {
      pm().broadcastRouteUpdate(types, groupKey, fromPeerId, { forceFull: true });
      console.log(`[SyncRoute] Broadcast route update for group ${groupKey}`);
    } catch (e) {
      console.error(`[SyncRoute] Broadcast failed for group ${groupKey}:`, e);
    }
  }
}

// ──────────────────────────────────────────────────────────────
// 服务名匹配工具
// ──────────────────────────────────────────────────────────────

function _isPeerCenterRpc(desc) {
  return (desc.serviceName === 'peer_rpc.PeerCenterRpc' || desc.serviceName === 'PeerCenterRpc') &&
         (!desc.protoName || desc.protoName === 'peer_rpc');
}

function _isOspfRouteRpc(desc) {
  return (desc.serviceName === 'peer_rpc.OspfRouteRpc' || desc.serviceName === 'OspfRouteRpc') &&
         (!desc.protoName ||
          desc.protoName === 'peer_rpc' ||
          desc.protoName === 'peer_rpc.OspfRouteRpc' ||
          desc.protoName === 'OspfRouteRpc');
}
