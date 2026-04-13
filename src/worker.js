/**
 * Cloudflare Worker 入口
 *
 * 路由：
 *   GET  /healthz              → 健康检查
 *   GET  /admin/networks       → 列出已知网络组（来自 DO）
 *   *    /{WS_PATH}            → WebSocket 升级 → RelayRoom DO
 *
 * 注意：
 * - globalNetworkState 已移除，原实现中该 Map 从未被写入，
 *   /admin/networks 始终返回空列表，属于死代码。
 * - 如需真实网络状态，应通过 DO stub 的 fetch 从 RelayRoom 查询。
 */

import { RelayRoom } from './worker/relay_room';

export { RelayRoom };

export default {
  async fetch(request, env) {
    const url      = new URL(request.url);
    const pathname = url.pathname;

    // 健康检查
    if (pathname === '/healthz') {
      return new Response('ok', { status: 200 });
    }

    // 管理端点（预留，当前仅作占位）
    if (pathname === '/admin/networks') {
      return _handleNetworkAdmin(request, env);
    }

    // WebSocket 升级 → 路由到 RelayRoom Durable Object
    // 【修复】原版 '/' + env.WS_PATH || '/ws' 存在运算符优先级 bug，
    // 当 WS_PATH 为 undefined 时得到 '/undefined' 而非 '/ws'
    const wsPath = env.WS_PATH ? `/${env.WS_PATH}` : '/ws';
    if (pathname === wsPath || pathname === `${wsPath}/`) {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return new Response('Expected WebSocket upgrade', { status: 400 });
      }

      const roomId  = url.searchParams.get('room') || 'default';
      const options = env.LOCATION_HINT ? { locationHint: env.LOCATION_HINT } : {};
      const stub    = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId), options);
      return stub.fetch(request);
    }

    return new Response('Not found', { status: 404 });
  },
};

// ──────────────────────────────────────────────────────────────
// 管理端点
// 当前返回空列表占位；真实状态应从 RelayRoom DO 查询
// ──────────────────────────────────────────────────────────────

async function _handleNetworkAdmin(request) {
  if (request.method !== 'GET') {
    return _jsonResponse({ success: false, error: 'Method not allowed' }, 405);
  }

  const action = new URL(request.url).searchParams.get('action');
  if (action === 'list') {
    return _jsonResponse({
      success:   true,
      networks:  [],
      note:      'Real-time network state is stored in RelayRoom Durable Objects. Query individual room stubs for live data.',
      timestamp: Date.now(),
    });
  }

  return _jsonResponse({ success: false, error: 'Invalid action' }, 400);
}

function _jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
