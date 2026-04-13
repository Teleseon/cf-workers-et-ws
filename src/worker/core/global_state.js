/**
 * 全局 Peer 中心状态管理
 *
 * 注意：在 Cloudflare Durable Objects 中，单个 DO 实例是单线程的，
 * 这里的 Map 在同一 DO 实例内是安全的。
 * 跨 DO 实例不共享内存（每个 Room 独立），这是正确的设计。
 */
import { MY_PEER_ID } from './constants.js';

// groupKey -> { globalPeerMap: Map<string, PeerEntry>, digest: string, lastTouch: number }
const peerCenterStateByGroup = new Map();

const PEER_CENTER_TTL_MS =
  Number(process.env.EASYTIER_PEER_CENTER_TTL_MS || 180_000);
const PEER_CENTER_CLEAN_INTERVAL =
  Math.max(30_000, Math.min(PEER_CENTER_TTL_MS / 2, 120_000));

let lastPeerCenterClean = 0;

/**
 * 获取（或懒创建）指定 group 的 PeerCenter 状态对象
 */
export function getPeerCenterState(groupKey) {
  const k = String(groupKey || '');
  let s = peerCenterStateByGroup.get(k);
  if (!s) {
    s = { globalPeerMap: new Map(), digest: '0' };
    peerCenterStateByGroup.set(k, s);
  }

  const now = Date.now();
  if (now - lastPeerCenterClean > PEER_CENTER_CLEAN_INTERVAL) {
    _cleanPeerCenterState(now);
  }
  s.lastTouch = now;
  return s;
}

function _cleanPeerCenterState(now = Date.now()) {
  lastPeerCenterClean = now;
  for (const [gk, s] of peerCenterStateByGroup.entries()) {
    for (const [pid, info] of s.globalPeerMap.entries()) {
      if (now - (info.lastSeen || 0) > PEER_CENTER_TTL_MS) {
        s.globalPeerMap.delete(pid);
      }
    }
    if (now - (s.lastTouch || 0) > PEER_CENTER_TTL_MS && s.globalPeerMap.size === 0) {
      peerCenterStateByGroup.delete(gk);
    }
  }
}

/**
 * 从 globalPeerMap 移除指定 peer 及其作为其他 peer 子设备的所有引用
 */
export function cleanPeerAndSubPeers(groupKey, peerId) {
  const state = getPeerCenterState(groupKey);
  const pid = String(peerId);

  state.globalPeerMap.delete(pid);

  for (const [otherPeerId, peerInfo] of state.globalPeerMap.entries()) {
    if (peerInfo.directPeers && peerInfo.directPeers[pid]) {
      delete peerInfo.directPeers[pid];
      console.log(`[GlobalCleanup] Removed sub-peer ${pid} from peer ${otherPeerId}`);
    }
  }

  console.log(`[GlobalCleanup] Cleaned peer ${pid} and its sub-peers from group ${groupKey}`);
}

/**
 * 计算 PeerCenter 快照的轻量摘要（用于增量同步判断）
 *
 * 使用 djb2-like 哈希（原版相同逻辑，保留一致性）
 */
export function calcPeerCenterDigestFromMap(mapObj) {
  const str = JSON.stringify(mapObj);
  let hash = 0n;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5n) - hash + BigInt(str.charCodeAt(i))) & 0xFFFFFFFFFFFFFFFFn;
  }
  return hash.toString();
}

/**
 * 构建发送给客户端的 PeerCenter 响应 Map
 *
 * 合并直连 peer、路由发现 peer 和全局子设备信息，
 * 确保每个 peer 都有与服务端的连接条目（latencyMs: 0）。
 */
export function buildPeerCenterResponseMap(groupKey, state, peerManager) {
  const directPeerIds = peerManager.listPeerIdsInGroup(groupKey);
  const directSet = new Set(directPeerIds);
  const allKnown = new Set(directPeerIds);

  // 通过路由信息发现的 peer
  const infos = peerManager._getPeerInfosMap(groupKey, false);
  if (infos) {
    for (const pid of infos.keys()) allKnown.add(pid);
  }

  // 全局 peer map 中记录的 peer 及其子设备
  for (const [peerId, peerInfo] of state.globalPeerMap.entries()) {
    allKnown.add(Number(peerId));
    if (peerInfo.directPeers) {
      for (const subId of Object.keys(peerInfo.directPeers)) {
        allKnown.add(Number(subId));
      }
    }
  }

  const out = {};
  for (const peerId of allKnown) {
    const key      = String(peerId);
    const existing = state.globalPeerMap.get(key);
    const entry    = existing ? { ...existing } : { directPeers: {} };
    if (!entry.directPeers) entry.directPeers = {};

    // 直连 peer 显示与服务器的链路
    if (directSet.has(peerId)) {
      entry.directPeers[String(MY_PEER_ID)] = { latencyMs: 0 };
    }

    // 保留全局 map 中已有的子设备信息
    if (existing && existing.directPeers) {
      for (const [subId, subInfo] of Object.entries(existing.directPeers)) {
        entry.directPeers[subId] = { ...subInfo };
      }
    }

    out[key] = entry;
  }

  console.log(`[PeerCenter] Built response map for group ${groupKey} with ${allKnown.size} peers`);
  return out;
}
