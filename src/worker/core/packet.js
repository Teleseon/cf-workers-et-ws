import { Buffer } from 'buffer';
import { HEADER_SIZE, HeaderFlag } from './constants.js';

/**
 * 解析包头（16 字节固定格式）
 * @param {Buffer} buffer
 * @returns {object|null}
 */
export function parseHeader(buffer) {
  if (!buffer || buffer.length < HEADER_SIZE) return null;
  return {
    fromPeerId:    buffer.readUInt32LE(0),
    toPeerId:      buffer.readUInt32LE(4),
    packetType:    buffer.readUInt8(8),
    flags:         buffer.readUInt8(9),
    forwardCounter: buffer.readUInt8(10),
    reserved:      buffer.readUInt8(11),
    len:           buffer.readUInt32LE(12),
  };
}

/**
 * 创建包头
 *
 * @param {number} fromPeerId
 * @param {number} toPeerId
 * @param {number} packetType
 * @param {number} payloadLen
 * @param {number} [flags=0]       - 调用方已合并好的 flags（含加密位、延迟优先位等）
 * @param {number} [forwardCounter=1]
 * @returns {Buffer}
 */
export function createHeader(fromPeerId, toPeerId, packetType, payloadLen, flags = 0, forwardCounter = 1) {
  const buf = Buffer.alloc(HEADER_SIZE);
  buf.writeUInt32LE(fromPeerId,   0);
  buf.writeUInt32LE(toPeerId,     4);
  buf.writeUInt8(packetType,      8);
  buf.writeUInt8(flags,           9);
  buf.writeUInt8(forwardCounter, 10);
  buf.writeUInt8(0,              11); // reserved
  buf.writeUInt32LE(payloadLen,  12);
  return buf;
}

/**
 * 返回根据环境变量决定是否追加 LatencyFirst 标志后的 flags 值
 * 调用方在构造最终 flags 时使用此函数，而不是在 createHeader 内部读取 env，
 * 以避免在 CF Workers 热路径中每次都访问进程全局。
 *
 * @param {number} baseFlags
 * @param {object} env  - CF Workers env 绑定对象
 * @returns {number}
 */
export function applyLatencyFirstFlag(baseFlags, env) {
  if (env && env.EASYTIER_LATENCY_FIRST === '1') {
    return baseFlags | HeaderFlag.LatencyFirst;
  }
  return baseFlags;
}
