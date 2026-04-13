/**
 * EasyTier 对等节点管理器
 *
 * 负责：peer 注册/注销、路由信息聚合、连接位图生成、路由广播
 *
 * 核心设计：
 * - 全局单调递增版本号（globalNetworkVersion）：防止 Worker 重启或
 *   P2P 交叉污染导致的版本回退，确保客户端必须接收新路由
 * - 基于时间戳初始化的版本号：比任何客户端缓存的旧版本都大
 * - 全连接拓扑 ConnBitmap：鼓励所有 peer 之间尝试 P2P 打洞
 */

import { Buffer } from 'buffer';
import { MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { wrapPacket, randomU64String } from './crypto.js';
import { getPeerCenterState, cleanPeerAndSubPeers } from './global_state.js';

const WS_OPEN = 1; // Cloudflare Workers 运行时中 WebSocket.OPEN 的值

// ──────────────────────────────────────────────────────────────
// 纯函数工具
// ──────────────────────────────────────────────────────────────

function parseIpv4ToU32Be(ip) {
  const parts = String(ip).trim().split('.').map(Number);
  if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) {
    throw new Error(`Invalid IPv4: ${ip}`);
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function mask32FromLen(len) {
  const l = Number(len);
  if (!Number.isFinite(l) || l <= 0) return 0;
  if (l >= 32) return 0xFFFFFFFF >>> 0;
  return (0xFFFFFFFF << (32 - l)) >>> 0;
}

function deriveSameNetworkIpv4(peerAddr, networkLength, myPeerId) {
  const mask     = mask32FromLen(networkLength);
  const net      = (peerAddr >>> 0) & mask;
  const hostBits = 32 - Number(networkLength);
  if (!Number.isFinite(hostBits) || hostBits <= 1 || hostBits > 30) return null;

  const hostMax  = (1 << hostBits) >>> 0;
  const peerHost = (peerAddr >>> 0) & (~mask >>> 0);
  let host = (Number(myPeerId) % 250) + 2;
  if (host >= hostMax) host = (Number(myPeerId) % Math.max(hostMax - 2, 1)) + 1;
  if (host === peerHost) {
    host = (host + 1) % hostMax;
    if (host === 0) host = 1;
  }
  return (net | host) >>> 0;
}

function randomUint32() {
  return Math.floor(Math.random() * 4294967296);
}

function makeInstId() {
  return { part1: randomUint32(), part2: randomUint32(), part3: randomUint32(), part4: randomUint32() };
}

/**
 * 为不在本地 peerInfos 中的已知子设备创建临时 stub 信息
 * （不保存到 peerInfosByGroup，只用于路由推送）
 */
function makeStubPeerInfo(peerId, networkLength) {
  return {
    peerId,
    version:         1,
    lastUpdate:      { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
    instId:          makeInstId(),
    cost:            1,
    hostname:        'CF-ETSV',
    easytierVersion: 'cf-et-ws',
    featureFlag:     { isPublicServer: false, avoidRelayData: false, kcpInput: false, noRelayKcp: false },
    networkLength:   Number(networkLength || 24),
    peerRouteId:     randomU64String(),
    groups:          [],
    udpStunInfo:     1, // OpenInternet，鼓励 P2P 打洞
  };
}

// ──────────────────────────────────────────────────────────────
// PeerManager
// ──────────────────────────────────────────────────────────────

export class PeerManager {
  constructor() {
    /** groupKey -> Map<peerId, WebSocket> */
    this.peersByGroup = new Map();
    /** groupKey -> Map<peerId, RoutePeerInfo> */
    this.peerInfosByGroup = new Map();
    /** groupKey -> Map<peerId, session> */
    this.routeSessions = new Map();
    /** groupKey -> Map<peerId, version number> */
    this.peerConnVersions = new Map();

    this.types = null;
    this.myInfo = null; // 懒初始化，避免在全局作用域调用随机函数

    this.allowVirtualIP      = false;
    this.ipConfiguredByEnv   = !!process.env.EASYTIER_IPV4_ADDR;
    this.netConfiguredByEnv  = process.env.EASYTIER_NETWORK_LENGTH !== undefined;
    this.ipAutoAssigned      = false;
    this.pureP2PMode         = process.env.EASYTIER_DISABLE_RELAY === '1';
    this.sessionTtlMs        = Number(process.env.EASYTIER_SESSION_TTL_MS || 3 * 60 * 1000);
    this.lastSessionCleanup  = 0;

    // 全局单调递增版本号，初始化为当前秒数截断（确保大于任何旧缓存版本）
    this.globalNetworkVersion = Math.floor(Date.now() / 1000) % 2_000_000_000;
  }

  setTypes(types) {
    this.types = types;
  }

  // ── myInfo 管理 ──

  ensureMyInfo() {
    if (this.myInfo) return this.myInfo;
    const info = {
      peerId:          MY_PEER_ID,
      instId:          makeInstId(),
      cost:            1,
      version:         1,
      featureFlag: {
        isPublicServer: true,
        avoidRelayData: this.pureP2PMode,
        kcpInput:       false,
        noRelayKcp:     false,
      },
      networkLength:    Number(process.env.EASYTIER_NETWORK_LENGTH || 24),
      easytierVersion:  process.env.EASYTIER_VERSION || 'cf-et-ws',
      lastUpdate:       { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      hostname:         process.env.EASYTIER_HOSTNAME || 'CF-ETSV',
      udpStunInfo:      1, // OpenInternet
      peerRouteId:      randomU64String(),
      groups:           [],
    };

    if (this.allowVirtualIP) {
      const ipEnv = process.env.EASYTIER_IPV4_ADDR;
      if (ipEnv) {
        info.ipv4Addr      = { addr: parseIpv4ToU32Be(ipEnv) };
        this.ipAutoAssigned = false;
      } else if (process.env.EASYTIER_AUTO_IPV4_ADDR === '1') {
        const octet  = (Number(MY_PEER_ID) % 250) + 2;
        info.ipv4Addr = { addr: parseIpv4ToU32Be(`10.0.0.${octet}`) };
        this.ipAutoAssigned = true;
      }
    }

    this.myInfo = info;
    return info;
  }

  bumpMyInfoVersion() {
    const info  = this.ensureMyInfo();
    info.version = (info.version || 0) + 1;
    info.lastUpdate = { seconds: Math.floor(Date.now() / 1000), nanos: 0 };
  }

  setPublicServerFlag(isPublicServer) {
    const info = this.ensureMyInfo();
    const next = !!isPublicServer;
    if (!!(info.featureFlag && info.featureFlag.isPublicServer) !== next) {
      info.featureFlag = { ...info.featureFlag, isPublicServer: next };
      this.bumpMyInfoVersion();
    }
  }

  setPureP2PMode(enabled) {
    const next = !!enabled;
    if (next === this.pureP2PMode) return;
    this.pureP2PMode = next;
    const info = this.ensureMyInfo();
    info.featureFlag = { ...info.featureFlag, avoidRelayData: next };
    this.bumpMyInfoVersion();
  }

  isPureP2PMode() { return !!this.pureP2PMode; }

  // ── 版本号管理 ──

  _getPeerConnVersionMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peerConnVersions.get(k);
    if (!m && create) { m = new Map(); this.peerConnVersions.set(k, m); }
    return m;
  }

  bumpPeerConnVersion(groupKey, peerId) {
    const m = this._getPeerConnVersionMap(groupKey, true);
    const next = (m.get(peerId) || 0) + 1;
    m.set(peerId, next);
    return next;
  }

  getPeerConnVersion(groupKey, peerId) {
    const m = this._getPeerConnVersionMap(groupKey, false);
    return m ? (m.get(peerId) || 0) : 0;
  }

  bumpAllPeerConnVersions(groupKey) {
    const all = new Set(this.listPeerIdsInGroup(groupKey));
    const infos = this._getPeerInfosMap(groupKey, false);
    if (infos) for (const pid of infos.keys()) all.add(pid);
    all.add(MY_PEER_ID);
    for (const pid of all) this.bumpPeerConnVersion(groupKey, pid);
  }

  // ── 内部 Map 访问器 ──

  _getPeersMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peersByGroup.get(k);
    if (!m && create) { m = new Map(); this.peersByGroup.set(k, m); }
    return m;
  }

  _getPeerInfosMap(groupKey, create = false) {
    const k = String(groupKey || '');
    let m = this.peerInfosByGroup.get(k);
    if (!m && create) { m = new Map(); this.peerInfosByGroup.set(k, m); }
    return m;
  }

  // ── Session 管理 ──

  _getSession(groupKey, peerId, create = false) {
    const now = Date.now();
    const cleanInterval = Math.max(30_000, Math.min(this.sessionTtlMs / 2, 120_000));
    if (now - this.lastSessionCleanup > cleanInterval) this.cleanupSessions(now);

    const gk = String(groupKey || '');
    let g = this.routeSessions.get(gk);
    if (!g && create) { g = new Map(); this.routeSessions.set(gk, g); }
    if (!g) return null;

    let s = g.get(peerId);
    if (!s && create) {
      s = {
        mySessionId:       null,
        dstSessionId:      null,
        weAreInitiator:    false,
        peerInfoVerMap:    new Map(),
        connBitmapVerMap:  new Map(),
        foreignNetVer:     0,
        lastTouch:         now,
        lastConnBitmapSig: null,
      };
      g.set(peerId, s);
    }
    if (s) s.lastTouch = now;
    return s;
  }

  cleanupSessions(nowTs = Date.now()) {
    this.lastSessionCleanup = nowTs;
    for (const [gk, m] of this.routeSessions.entries()) {
      for (const [pid, s] of m.entries()) {
        if (nowTs - (s.lastTouch || 0) > this.sessionTtlMs) m.delete(pid);
      }
      if (m.size === 0) this.routeSessions.delete(gk);
    }
  }

  onRouteSessionAck(groupKey, peerId, theirSessionId, weAreInitiator) {
    const s = this._getSession(groupKey, peerId, true);
    const isNewSession = s.dstSessionId !== theirSessionId;
    if (isNewSession) {
      console.log(`[Session] New session for peer ${peerId}, resetting version info`);
      s.peerInfoVerMap.clear();
      s.connBitmapVerMap.clear();
      s.foreignNetVer    = 0;
      s.lastConnBitmapSig = null;
      // 重连后强制重置连接版本
      this._getPeerConnVersionMap(groupKey, true).set(peerId, 1);
    }
    s.dstSessionId = theirSessionId;
    if (typeof weAreInitiator === 'boolean') s.weAreInitiator = weAreInitiator;
    console.log(`[Session] Updated peer ${peerId}: newSession=${isNewSession}`);
  }

  // ── Peer 注册 / 注销 ──

  addPeer(peerId, ws) {
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    const peers    = this._getPeersMap(groupKey, true);
    if (!peers.has(peerId)) this.bumpAllPeerConnVersions(groupKey);
    peers.set(peerId, ws);
  }

  removePeer(ws) {
    const peerId   = ws && ws.peerId;
    const groupKey = ws && ws.groupKey ? String(ws.groupKey) : '';
    if (!peerId) return false;

    try { cleanPeerAndSubPeers(groupKey, peerId); }
    catch (e) { console.warn(`[PeerCleanup] Failed to clean global state for peer ${peerId}:`, e.message); }

    const peers   = this._getPeersMap(groupKey, false);
    const existed = !!(peers && peers.has(peerId));
    if (peers) peers.delete(peerId);

    const infos = this._getPeerInfosMap(groupKey, false);
    if (infos) infos.delete(peerId);

    const sessions = this.routeSessions.get(String(groupKey));
    if (sessions) {
      sessions.delete(peerId);
      if (sessions.size === 0) this.routeSessions.delete(String(groupKey));
    }

    const connVers = this._getPeerConnVersionMap(groupKey, false);
    if (connVers) connVers.delete(peerId);

    if (existed && peers && peers.size > 0) this.bumpAllPeerConnVersions(groupKey);

    // 组内无 peer 时清理所有相关状态
    if (!peers || peers.size === 0) {
      this.peersByGroup.delete(String(groupKey));
      this.peerInfosByGroup.delete(String(groupKey));
      this.peerConnVersions.delete(String(groupKey));
    }

    console.log(`[PeerCleanup] Removed peer ${peerId} from group ${groupKey}`);
    return true;
  }

  getPeerWs(peerId, groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? peers.get(peerId) : undefined;
  }

  listPeerIdsInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.keys()) : [];
  }

  listPeersInGroup(groupKey) {
    const peers = this._getPeersMap(groupKey, false);
    return peers ? Array.from(peers.entries()) : [];
  }

  updatePeerInfo(groupKey, peerId, info) {
    const infos = this._getPeerInfosMap(groupKey, true);
    if (!infos.has(peerId)) this.bumpAllPeerConnVersions(groupKey);
    infos.set(peerId, info);

    // 自动 IP 派生（仅在开启 virtual IP 且未手动配置时）
    if (this.allowVirtualIP && !this.ipConfiguredByEnv && this.ipAutoAssigned) {
      this._tryDeriveIpFromPeer(info, groupKey);
    }
  }

  _tryDeriveIpFromPeer(info, groupKey) {
    const myInfo  = this.ensureMyInfo();
    const peerIp  = info && info.ipv4Addr && typeof info.ipv4Addr.addr === 'number'
      ? (info.ipv4Addr.addr >>> 0) : null;
    const netLen  = Number(info && (info.networkLength || info.network_length) || myInfo.networkLength || 24);

    if (peerIp === null || !Number.isFinite(netLen) || netLen <= 0) return;

    const derived = deriveSameNetworkIpv4(peerIp, netLen, MY_PEER_ID);
    if (derived === null) return;

    let changed = false;
    if (!this.netConfiguredByEnv && myInfo.networkLength !== netLen) {
      myInfo.networkLength = netLen;
      changed = true;
    }
    const prevAddr = myInfo.ipv4Addr && typeof myInfo.ipv4Addr.addr === 'number'
      ? (myInfo.ipv4Addr.addr >>> 0) : null;
    if (prevAddr !== derived) {
      myInfo.ipv4Addr = { addr: derived };
      changed = true;
    }
    if (changed) {
      this.bumpMyInfoVersion();
      this.ipAutoAssigned = false;
    }
  }

  // ── 路由广播 ──

  broadcastRouteUpdate(types, groupKey, excludePeerId, opts = {}) {
    const forceFull = opts.forceFull !== false; // 默认 true
    if (groupKey !== undefined) {
      const peers = this._getPeersMap(groupKey, false);
      if (!peers) return;
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) {
          this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
        }
      }
      return;
    }
    for (const [, peers] of this.peersByGroup.entries()) {
      for (const [peerId, ws] of peers.entries()) {
        if (peerId === excludePeerId) continue;
        if (ws.readyState === WS_OPEN) {
          this.pushRouteUpdateTo(peerId, ws, types, { forceFull });
        }
      }
    }
  }

  pushRouteUpdateTo(targetPeerId, ws, types, opts = {}) {
    const forceFull = !!opts.forceFull;
    const groupKey  = ws && ws.groupKey ? String(ws.groupKey) : '';
    const session   = this._getSession(groupKey, targetPeerId, true);
    const myInfo    = this.ensureMyInfo();

    if (!ws.serverSessionId) ws.serverSessionId = randomU64String();
    session.mySessionId = ws.serverSessionId;

    const forceFullLocal = forceFull || !session.dstSessionId;

    // 收集所有相关 peer（直连 + 路由发现 + 全局子设备）
    const allPeers = new Set(this.listPeerIdsInGroup(groupKey));
    const infos = this._getPeerInfosMap(groupKey, false);
    if (infos) for (const pid of infos.keys()) allPeers.add(pid);

    try {
      const globalState = getPeerCenterState(groupKey);
      for (const [peerId, peerInfo] of globalState.globalPeerMap.entries()) {
        allPeers.add(Number(peerId));
        if (peerInfo.directPeers) {
          for (const subId of Object.keys(peerInfo.directPeers)) allPeers.add(Number(subId));
        }
      }
    } catch (e) {
      console.warn(`[RouteUpdate] Failed to get global peer state for group ${groupKey}:`, e.message);
    }

    allPeers.add(targetPeerId);
    const relevantPeers = [
      MY_PEER_ID,
      ...Array.from(allPeers).filter(p => p !== MY_PEER_ID).sort((a, b) => Number(a) - Number(b)),
    ];

    // 构建 peerInfos
    const peerInfosItems = [];
    for (const pid of relevantPeers) {
      let info = pid === MY_PEER_ID
        ? myInfo
        : this._getPeerInfosMap(groupKey, false)?.get(pid);

      if (!info && pid !== MY_PEER_ID) {
        // 检查是否是已知子设备，避免为完全未知的 peer 生成 stub
        let isKnownSubPeer = false;
        try {
          const gs = getPeerCenterState(groupKey);
          isKnownSubPeer = Array.from(gs.globalPeerMap.values()).some(
            pi => pi.directPeers && String(pid) in pi.directPeers
          );
        } catch (e) {
          console.warn(`[RouteUpdate] Failed to check global state for peer ${pid}:`, e.message);
        }
        if (!isKnownSubPeer) continue;
        info = makeStubPeerInfo(pid, myInfo.networkLength || 24);
      }

      if (!info) continue;

      const version = info.version || 1;
      const prev    = forceFullLocal ? 0 : (session.peerInfoVerMap.get(pid) || 0);
      if (forceFullLocal || version > prev) {
        peerInfosItems.push(info);
        session.peerInfoVerMap.set(pid, version);
      }
    }

    // 构建连接位图（全连接拓扑）
    let connBitmap = null;
    if (relevantPeers.length > 0) {
      const connVersions = this._getPeerConnVersionMap(groupKey, true);
      const peerIdVersions = relevantPeers.map(pid => ({
        peerId: pid, version: connVersions.get(pid) || 1,
      }));

      const N          = peerIdVersions.length;
      const bitmapSize = Math.ceil((N * N) / 8);
      const bitmap     = new Uint8Array(bitmapSize);

      // 全连接：所有 peer 对之间置位
      for (let i = 0; i < N; i++) {
        for (let j = 0; j < N; j++) {
          const idx = i * N + j;
          bitmap[Math.floor(idx / 8)] |= 1 << (idx % 8);
        }
      }

      const bitmapBuf = Buffer.from(bitmap);
      const sig = `${peerIdVersions.map(p => p.peerId).join(',')}|${bitmapBuf.toString('hex')}`;

      // 拓扑变化或强制推送时，全局版本号 +1
      if (forceFullLocal || sig !== session.lastConnBitmapSig) {
        this.globalNetworkVersion += 1;
        session.lastConnBitmapSig = sig;
        console.log(`[ConnBitmap] Topology changed, global version -> ${this.globalNetworkVersion}`);
      }

      const currentVersion = this.globalNetworkVersion;
      for (const pv of peerIdVersions) pv.version = currentVersion;

      connBitmap = { peerIds: peerIdVersions, bitmap: bitmapBuf, version: currentVersion };
    }

    // 外网信息（foreign network）
    const foreignNetworkInfos = this._buildForeignNetworkInfos(session, allPeers, ws);

    // 编码并发送
    if (!types) throw new Error('PeerManager types not set');

    const reqPayload = {
      myPeerId:            MY_PEER_ID,
      mySessionId:         ws.serverSessionId,
      isInitiator:         !!ws.weAreInitiator,
      peerInfos:           peerInfosItems.length > 0 ? { items: peerInfosItems } : null,
      rawPeerInfos:        peerInfosItems.length > 0
        ? peerInfosItems.map(info => types.RoutePeerInfo.encode(info).finish())
        : null,
      connBitmap,
      foreignNetworkInfos,
    };

    const rpcReqPacket = {
      fromPeer:      MY_PEER_ID,
      toPeer:        targetPeerId,
      transactionId: Number(BigInt.asUintN(32, BigInt(randomU64String()))),
      descriptor: {
        domainName:  ws.domainName || 'public_server',
        protoName:   'OspfRouteRpc',
        serviceName: 'OspfRouteRpc',
        methodIndex: process.env.EASYTIER_OSPF_ROUTE_METHOD_INDEX
          ? Number(process.env.EASYTIER_OSPF_ROUTE_METHOD_INDEX)
          : 1,
      },
      body:         types.RpcRequest.encode({
        request:   types.SyncRouteInfoRequest.encode(reqPayload).finish(),
        timeoutMs: 5000,
      }).finish(),
      isRequest:    true,
      totalPieces:  1,
      pieceIdx:     0,
      traceId:      0,
      compressionInfo: { algo: 1, acceptedAlgo: 1 },
    };

    const env = ws._env;
    const rpcPacketBytes = types.RpcPacket.encode(rpcReqPacket).finish();
    try {
      ws.send(wrapPacket(createHeader, MY_PEER_ID, targetPeerId, PacketType.RpcReq, rpcPacketBytes, ws, { env }));
    } catch (e) {
      // 发送失败（连接可能已断开），忽略；心跳机制会处理后续清理
      console.warn(`[RouteUpdate] Failed to send to peer ${targetPeerId}: ${e.message}`);
    }
  }

  _buildForeignNetworkInfos(session, allPeers, ws) {
    const env  = ws && ws._env;
    const mode = ((env && env.EASYTIER_HANDSHAKE_MODE) || process.env.EASYTIER_HANDSHAKE_MODE || 'foreign').toLowerCase();
    if (mode === 'same' || mode === 'same_network') return null;

    const version = session.foreignNetVer + 1;
    session.foreignNetVer = version;

    const networkName =
      (env && env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME) ||
      process.env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME ||
      'dev-websocket-relay';

    return {
      infos: [{
        key: { peerId: MY_PEER_ID, networkName },
        value: {
          foreignPeerIds:       Array.from(allPeers),
          lastUpdate:           { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
          version,
          networkSecretDigest:  Buffer.alloc(32), // 32 字节全零，符合 proto 定义
          myPeerIdForThisNetwork: MY_PEER_ID,
        },
      }],
    };
  }
}

// ──────────────────────────────────────────────────────────────
// 单例
// ──────────────────────────────────────────────────────────────

let peerManagerInstance = null;

export function getPeerManager() {
  if (!peerManagerInstance) peerManagerInstance = new PeerManager();
  return peerManagerInstance;
}
