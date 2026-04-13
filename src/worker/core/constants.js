// ============================================================
// EasyTier WebSocket Relay - 常量定义
// ============================================================

export const MAGIC = 0xd1e1a5e1;
export const VERSION = 1;
export const MY_PEER_ID = 10000001; // 服务端保留 Peer ID
export const HEADER_SIZE = 16;

/** 包类型枚举（与 EasyTier 协议对齐） */
export const PacketType = {
  Invalid:              0,
  Data:                 1,
  HandShake:            2,
  RoutePacket:          3, // deprecated
  Ping:                 4,
  Pong:                 5,
  TaRpc:                6, // deprecated
  Route:                7, // deprecated
  RpcReq:               8,
  RpcResp:              9,
  ForeignNetworkPacket: 10,
  KcpSrc:               11,
  KcpDst:               12,
};

/** Header flags 位掩码 */
export const HeaderFlag = {
  Encrypted:    0x01,
  LatencyFirst: 0x02,
};
