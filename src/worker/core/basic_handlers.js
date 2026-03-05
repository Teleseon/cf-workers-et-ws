import { MAGIC, VERSION, MY_PEER_ID, PacketType } from './constants.js';
import { createHeader } from './packet.js';
import { getPeerManager } from './peer_manager.js';
import { wrapPacket, randomU64String } from './crypto.js';

const WS_OPEN = (typeof WebSocket !== 'undefined' && WebSocket.OPEN) ? WebSocket.OPEN : 1;

// 支持多密码：每个网络名称可以对应多个密码摘要
const networkDigestRegistry = new Map(); // networkName -> Set of digests
const networkGroups = new Map(); // networkName:digest -> group metadata

// 网络组管理功能
function updateNetworkGroupActivity(groupKey) {
  const group = networkGroups.get(groupKey);
  if (group) {
    group.lastActivity = Date.now();
    group.peerCount = (group.peerCount || 0) + 1;
  }
}

function removeNetworkGroupActivity(groupKey) {
  const group = networkGroups.get(groupKey);
  if (group) {
    group.peerCount = Math.max(0, (group.peerCount || 1) - 1);
    
    // 如果网络组没有活跃的对等节点，可以清理（可选）
    if (group.peerCount === 0 && Date.now() - group.lastActivity > 24 * 60 * 60 * 1000) {
      // 24小时无活动，清理网络组
      networkGroups.delete(groupKey);
      console.log(`Cleaned up inactive network group: ${groupKey}`);
    }
  }
}

function getNetworkGroupsByNetwork(networkName) {
  const groups = [];
  for (const [groupKey, group] of networkGroups.entries()) {
    if (groupKey.startsWith(`${networkName}:`)) {
      groups.push({
        groupKey,
        ...group
      });
    }
  }
  return groups;
}

function handleHandshake(ws, header, payload, types) {
  try {
    const req = types.HandshakeRequest.decode(payload);
    try {
      const dig = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
      console.log(`Handshake networkSecretDigest(hex)=${dig.toString('hex')}`);
    } catch (_) {
      // ignore
    }

    if (req.magic !== MAGIC) {
      console.error('Invalid magic');
      ws.close();
      return;
    }

    const clientNetworkName = req.networkName || '';
    const clientDigest = req.networkSecretDigrest ? Buffer.from(req.networkSecretDigrest) : Buffer.alloc(0);
    const digestHex = clientDigest.toString('hex');
    
    // 支持多密码：检查该网络名称下是否已存在此密码摘要
    let existingDigests = networkDigestRegistry.get(clientNetworkName);
    if (!existingDigests) {
      existingDigests = new Set();
      networkDigestRegistry.set(clientNetworkName, existingDigests);
    }
    
    // 如果密码摘要不为空且不在现有摘要集合中，则创建新的网络组
    if (digestHex.length > 0 && !existingDigests.has(digestHex)) {
      existingDigests.add(digestHex);
      console.log(`Adding new digest for network "${clientNetworkName}": ${digestHex}`);
    }
    
    // 生成网络组键：网络名称:密码摘要
    const groupKey = `${clientNetworkName}:${digestHex}`;
    
    // 初始化网络组元数据（如果不存在）
    if (!networkGroups.has(groupKey)) {
      networkGroups.set(groupKey, {
        createdAt: Date.now(),
        peerCount: 0,
        lastActivity: Date.now()
      });
      console.log(`Created new network group: ${groupKey}`);
    }
    const serverNetworkName = process.env.EASYTIER_PUBLIC_SERVER_NETWORK_NAME || 'public_server';
    const digest = new Uint8Array(32);

    ws.domainName = clientNetworkName;

    // 修复握手响应格式：确保所有字段正确设置
    const respPayload = {
      magic: MAGIC,
      myPeerId: MY_PEER_ID,
      version: VERSION,
      features: ["node-server-v1"],
      networkName: serverNetworkName,
      networkSecretDigrest: digest
    };
    
    console.log(`Handshake response payload:`, {
      magic: respPayload.magic,
      myPeerId: respPayload.myPeerId,
      version: respPayload.version,
      features: respPayload.features,
      networkName: respPayload.networkName,
      networkSecretDigrestLength: respPayload.networkSecretDigrest ? respPayload.networkSecretDigrest.length : 0
    });

    ws.groupKey = groupKey;
    ws.peerId = req.myPeerId;
    const pm = getPeerManager();
    pm.addPeer(req.myPeerId, ws);
    
    // 更新网络组活动状态
    updateNetworkGroupActivity(groupKey);
    pm.updatePeerInfo(ws.groupKey, req.myPeerId, {
      peerId: req.myPeerId,
      version: 1,
      lastUpdate: { seconds: Math.floor(Date.now() / 1000), nanos: 0 },
      instId: { part1: 0, part2: 0, part3: 0, part4: 0 },
      networkLength: Number(process.env.EASYTIER_NETWORK_LENGTH || 24),
    });
    pm.setPublicServerFlag(true);
    ws.crypto = { enabled: false };

    const respBuffer = types.HandshakeRequest.encode(respPayload).finish();
    const respHeader = createHeader(MY_PEER_ID, req.myPeerId, PacketType.HandShake, respBuffer.length);
    
    // 改进发送逻辑：添加延迟确保客户端准备好接收
    setTimeout(() => {
      try {
        // 检查连接状态
        if (ws.readyState !== WS_OPEN) {
          console.error(`WebSocket not open when sending handshake response to ${req.myPeerId}, state: ${ws.readyState}`);
          return;
        }
        
        ws.send(Buffer.concat([respHeader, Buffer.from(respBuffer)]));
        console.log(`Handshake response sent to peer ${req.myPeerId}, payload length: ${respBuffer.length}`);
      } catch (sendError) {
        console.error(`Failed to send handshake response to ${req.myPeerId}:`, sendError);
        // 不立即关闭连接，让心跳机制处理
      }
    }, 10); // 10ms延迟确保客户端准备好
    
    if (!ws.serverSessionId) {
      ws.serverSessionId = randomU64String();
    }
    if (ws.weAreInitiator === undefined) {
      ws.weAreInitiator = false;
    }

    setTimeout(() => {
      try {
        if (ws.readyState === WS_OPEN) {
          const pm = getPeerManager();
          
          // 为新设备推送完整的路由信息
          pm.pushRouteUpdateTo(req.myPeerId, ws, types, { forceFull: true });
          
          // 为所有现有设备广播路由更新，包括新设备
          // 确保所有设备都能获得最新的连接位图
          pm.broadcastRouteUpdate(types, ws.groupKey, null, { forceFull: true });
          
          console.log(`[Handshake] Initial route updates completed for peer ${req.myPeerId}`);
        }
      } catch (e) {
        console.error(`Failed to push initial route update to ${req.myPeerId}:`, e.message);
      }
    }, 50);

  } catch (e) {
    console.error('Handshake error:', e);
    // 改进错误处理：只在严重错误时关闭连接
    if (e.message && e.message.includes('decode') || e.message.includes('Invalid')) {
      ws.close();
    }
    // 其他错误不关闭连接，让心跳机制处理
  }
}

function handlePing(ws, header, payload) {
  const msg = wrapPacket(createHeader, MY_PEER_ID, header.fromPeerId, PacketType.Pong, payload, ws);
  ws.send(msg);
}

function handleForwarding(sourceWs, header, fullMessage, types) {
  const targetPeerId = header.toPeerId;
  const pm = getPeerManager();
  const targetWs = pm.getPeerWs(targetPeerId, sourceWs && sourceWs.groupKey);

  if (targetWs && targetWs.readyState === WS_OPEN) {
    const srcGroup = sourceWs && sourceWs.groupKey;
    const dstGroup = targetWs && targetWs.groupKey;
    if (srcGroup && dstGroup && srcGroup !== dstGroup) {
      return;
    }
    try {
      targetWs.send(fullMessage);
    } catch (e) {
      console.error(`Forward to ${targetPeerId} failed: ${e.message}`);
      pm.removePeer(targetWs);
      try {
        pm.broadcastRouteUpdate(types, srcGroup);
      } catch (err) {
        console.error(`Broadcast after forward failure failed: ${err.message}`);
      }
    }
  } else {
  }
}

export {
  handleHandshake,
  handlePing,
  handleForwarding,
  updateNetworkGroupActivity,
  removeNetworkGroupActivity,
  getNetworkGroupsByNetwork
};
