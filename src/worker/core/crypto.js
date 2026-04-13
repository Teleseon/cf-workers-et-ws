import crypto from 'crypto';
import { HeaderFlag } from './constants.js';

// ──────────────────────────────────────────────
// 内部工具
// ──────────────────────────────────────────────

const U64_MASK = (1n << 64n) - 1n;

function rotl64(x, b) {
  return ((x << BigInt(b)) | (x >> (64n - BigInt(b)))) & U64_MASK;
}

function readUInt64LE(buf, offset) {
  let r = 0n;
  for (let i = 0; i < 8; i++) {
    r |= BigInt(buf[offset + i]) << (8n * BigInt(i));
  }
  return r;
}

function sipRound(v) {
  v.v0 = (v.v0 + v.v1) & U64_MASK;
  v.v1 = rotl64(v.v1, 13);
  v.v1 ^= v.v0;
  v.v0 = rotl64(v.v0, 32);

  v.v2 = (v.v2 + v.v3) & U64_MASK;
  v.v3 = rotl64(v.v3, 16);
  v.v3 ^= v.v2;

  v.v0 = (v.v0 + v.v3) & U64_MASK;
  v.v3 = rotl64(v.v3, 21);
  v.v3 ^= v.v0;

  v.v2 = (v.v2 + v.v1) & U64_MASK;
  v.v1 = rotl64(v.v1, 17);
  v.v1 ^= v.v2;
  v.v2 = rotl64(v.v2, 32);
}

/** SipHash-1-3（与 EasyTier 的 Rust 侧对齐） */
function sipHash13(msg, k0 = 0n, k1 = 0n) {
  const b = BigInt(msg.length) << 56n;
  const v = {
    v0: 0x736f6d6570736575n ^ k0,
    v1: 0x646f72616e646f6dn ^ k1,
    v2: 0x6c7967656e657261n ^ k0,
    v3: 0x7465646279746573n ^ k1,
  };

  const fullLen = msg.length - (msg.length % 8);
  for (let i = 0; i < fullLen; i += 8) {
    const m = readUInt64LE(msg, i);
    v.v3 ^= m;
    sipRound(v);
    v.v0 ^= m;
  }

  let m = b;
  const left = msg.length % 8;
  for (let i = 0; i < left; i++) {
    m |= BigInt(msg[fullLen + i]) << (8n * BigInt(i));
  }

  v.v3 ^= m;
  sipRound(v);
  v.v0 ^= m;

  v.v2 ^= 0xffn;
  sipRound(v); sipRound(v); sipRound(v);

  return (v.v0 ^ v.v1 ^ v.v2 ^ v.v3) & U64_MASK;
}

/** 流式 SipHash 哈希器（与原版保持相同语义） */
class DefaultHasher {
  constructor() {
    this.parts = [];
    this.total = 0;
  }

  write(buf) {
    if (!buf || buf.length === 0) return;
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    this.parts.push(b);
    this.total += b.length;
  }

  finish() {
    const msg = this.parts.length === 1
      ? this.parts[0]
      : Buffer.concat(this.parts, this.total);
    return sipHash13(msg);
  }
}

function u64ToBeBytes(u64) {
  const out = Buffer.alloc(8);
  let x = u64;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// ──────────────────────────────────────────────
// 公开 API
// ──────────────────────────────────────────────

/**
 * 从网络密钥派生 128-bit 和 256-bit 对称密钥
 */
export function deriveKeys(networkSecret = '') {
  const secretBuf = Buffer.from(networkSecret, 'utf8');

  const h128 = new DefaultHasher();
  h128.write(secretBuf);
  const first = u64ToBeBytes(h128.finish());
  const key128 = Buffer.alloc(16);
  first.copy(key128, 0);
  h128.write(key128.subarray(0, 8));
  const second = u64ToBeBytes(h128.finish());
  second.copy(key128, 8);

  const h256 = new DefaultHasher();
  h256.write(secretBuf);
  h256.write(Buffer.from('easytier-256bit-key', 'utf8'));
  const key256 = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    const chunkStart = i * 8;
    if (chunkStart > 0) h256.write(key256.subarray(0, chunkStart));
    h256.write(Buffer.from([i]));
    u64ToBeBytes(h256.finish()).copy(key256, chunkStart, 0, 8);
  }

  return { key128, key256 };
}

/**
 * 生成字符串摘要（用于网络密钥校验）
 */
export function generateDigestFromStr(str1, str2, digestLen = 32) {
  const len = Number(digestLen);
  if (!Number.isInteger(len) || len <= 0 || (len % 8) !== 0) {
    throw new Error('digest length must be a positive multiple of 8');
  }

  const hasher = new DefaultHasher();
  hasher.write(Buffer.from(String(str1 || ''), 'utf8'));
  hasher.write(Buffer.from(String(str2 || ''), 'utf8'));

  const digest = Buffer.alloc(len);
  const shards = len / 8;
  for (let i = 0; i < shards; i++) {
    u64ToBeBytes(hasher.finish()).copy(digest, i * 8);
    hasher.write(digest.subarray(0, (i + 1) * 8));
  }
  return digest;
}

/** AES-GCM 加密（nonce 随机，附 tag + nonce 于尾部） */
export function encryptAesGcm(payload, key) {
  const nonce = crypto.randomBytes(12);
  const algo = key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
  const cipher = crypto.createCipheriv(algo, key, nonce);
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ciphertext, tag, nonce]);
}

/** AES-GCM 解密 */
export function decryptAesGcm(payload, key) {
  if (payload.length < 28) {
    throw new Error(`Encrypted payload too short: ${payload.length}`);
  }
  const textLen = payload.length - 28;
  const ciphertext = payload.subarray(0, textLen);
  const tag       = payload.subarray(textLen, textLen + 16);
  const nonce     = payload.subarray(textLen + 16);
  const algo = key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
  const decipher = crypto.createDecipheriv(algo, key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** 生成随机 u64，以十进制字符串返回（避免 JS number 精度截断） */
export function randomU64String() {
  const b = crypto.randomBytes(8);
  let x = 0n;
  for (let i = 0; i < 8; i++) x = (x << 8n) | BigInt(b[i]);
  return x.toString();
}

export function sha256() {
  return crypto.createHash('sha256');
}

/**
 * 封装数据包（含可选加密）
 *
 * 【修复】原版在 createHeader 之后再次 writeUInt8(flags, 9)，
 * 会完全覆盖 createHeader 内写入的 LATENCY_FIRST 位。
 * 现在改为：先算出最终 flags（加密位 | 延迟优先位），统一传给 createHeader，
 * 不再二次覆盖。
 *
 * @param {Function} createHeaderFn  - 来自 packet.js 的 createHeader
 * @param {number}   fromPeerId
 * @param {number}   toPeerId
 * @param {number}   packetType
 * @param {Buffer|Uint8Array} payload
 * @param {object}   ws              - WebSocket 连接对象（含 crypto 状态）
 * @param {object}   [opts]
 * @param {boolean}  [opts.disableEncrypt=false]
 * @param {object}   [opts.env]      - CF Workers env（用于读取 LATENCY_FIRST）
 * @returns {Buffer}
 */
export function wrapPacket(createHeaderFn, fromPeerId, toPeerId, packetType, payload, ws, opts = {}) {
  const encryptionEnabled = !!(ws && ws.crypto && ws.crypto.enabled);
  const disableEncrypt    = !!opts.disableEncrypt;

  let body  = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let flags = 0;

  // 加密（握手包 type=2 不加密）
  if (encryptionEnabled && !disableEncrypt && packetType !== 2) {
    const algo = ws.crypto.algorithm || 'aes-gcm';
    if (algo === 'aes-gcm') {
      body = encryptAesGcm(body, ws.crypto.key128);
    } else if (algo === 'aes-256-gcm') {
      body = encryptAesGcm(body, ws.crypto.key256);
    } else {
      throw new Error(`Unsupported encryption algorithm: ${algo}`);
    }
    flags |= HeaderFlag.Encrypted;
  }

  // 延迟优先标志（从 env 读取，合并到 flags，避免二次覆盖）
  const env = opts.env || (ws && ws._env);
  if (env && env.EASYTIER_LATENCY_FIRST === '1') {
    flags |= HeaderFlag.LatencyFirst;
  }

  const headerBuf = createHeaderFn(fromPeerId, toPeerId, packetType, body.length, flags);
  return Buffer.concat([headerBuf, body]);
}
