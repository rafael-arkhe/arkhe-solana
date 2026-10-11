/**
 * Cryptographic & mathematical utilities for Arkhe Preflight v21.
 * Strict implementations of RFC 8785 Canonical JSON, SHA-256,
 * Base58 decoding/encoding, and Clopper-Pearson binomial quantile.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP: Record<string, number> = {};
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_MAP[BASE58_ALPHABET[i]] = i;
}

export function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading zeros ('1' in base58)
  let leadingZeros = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leadingZeros++;
  }

  // Allocate enough space
  const bytes = [0];
  for (const c of str) {
    const value = BASE58_MAP[c];
    if (value === undefined) {
      throw new Error(`Invalid Base58 character: "${c}"`);
    }

    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }

    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Result array
  const result: number[] = [];
  for (let i = 0; i < leadingZeros; i++) {
    result.push(0);
  }
  for (let i = bytes.length - 1; i >= 0; i--) {
    result.push(bytes[i]);
  }

  return new Uint8Array(result);
}

export function base58Encode(buffer: Uint8Array): string {
  if (buffer.length === 0) return '';

  let leadingZeros = 0;
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    leadingZeros++;
  }

  const digits = [0];
  for (const byte of buffer) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = '';
  for (let i = 0; i < leadingZeros; i++) {
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * SHA-256 hash of an ASCII or UTF-8 string or byte array
 */
export async function sha256(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
    return bytesToHex(new Uint8Array(hashBuffer));
  }
  // Fallback to sync SHA-256
  return sha256Sync(bytes);
}

/**
 * SHA-256 ASCII synchronous implementation (matches python _h_ascii exactly)
 */
export function sha256AsciiSync(str: string): string {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i) & 0xff;
  }
  return sha256Sync(bytes);
}

/**
 * Pure TypeScript SHA-256 implementation for synchronous and deterministic operations
 */
export function sha256Sync(data: Uint8Array): string {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const len = data.length;
  const bitLen = len * 8;
  const withOne = len + 1;
  const padLen = (withOne % 64 <= 56) ? (56 - (withOne % 64)) : (120 - (withOne % 64));
  const totalLen = withOne + padLen + 8;

  const padded = new Uint8Array(totalLen);
  padded.set(data, 0);
  padded[len] = 0x80;

  // Append length in bits (big-endian 64-bit)
  const view = new DataView(padded.buffer);
  const highBits = Math.floor(bitLen / 0x100000000);
  const lowBits = bitLen >>> 0;
  view.setUint32(totalLen - 8, highBits, false);
  view.setUint32(totalLen - 4, lowBits, false);

  const w = new Uint32Array(64);

  for (let i = 0; i < totalLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      w[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = [h0, h1, h2, h3, h4, h5, h6, h7];
  return out.map(val => val.toString(16).padStart(8, '0')).join('');
}

function rotr(n: number, b: number): number {
  return ((n >>> b) | (n << (32 - b))) >>> 0;
}

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS)
 * Deterministic serialization according to RFC 8785.
 */
export function canonicalJsonString(obj: unknown): string {
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') {
    if (!Number.isFinite(obj)) {
      throw new Error('RFC 8785 does not permit NaN or Infinity');
    }
    // JS Number.prototype.toString() matches ES6 / RFC 8785 section 3.2.2.3
    if (Object.is(obj, -0)) return '0';
    return obj.toString();
  }
  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJsonString(item)).join(',') + ']';
  }
  if (typeof obj === 'object') {
    // Sort keys by UTF-16 code units (as required by RFC 8785)
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs: string[] = [];
    for (const key of keys) {
      const val = (obj as Record<string, unknown>)[key];
      if (val !== undefined && typeof val !== 'symbol' && typeof val !== 'function') {
        pairs.push(JSON.stringify(key) + ':' + canonicalJsonString(val));
      }
    }
    return '{' + pairs.join(',') + '}';
  }
  throw new Error(`Unsupported type for RFC 8785: ${typeof obj}`);
}

export function canonicalSha256(obj: unknown): string {
  const jsonStr = canonicalJsonString(obj);
  return sha256Sync(new TextEncoder().encode(jsonStr));
}

/**
 * Clopper-Pearson Exact Binomial Upper Bound (Confidence Alpha)
 * Matches scipy.stats.beta.ppf(1.0 - confidence_alpha, fp + 1, n - fp)
 */
export function clopperPearsonUpper(fp: number, n: number, confidenceAlpha: number): number | null {
  if (n <= 0) return null;
  if (fp === 0) {
    // Exact closed-form for zero false positives: 1 - alpha^(1/n)
    return 1.0 - Math.pow(confidenceAlpha, 1.0 / n);
  }
  if (fp >= n) {
    return 1.0;
  }

  // Quantile 1 - confidenceAlpha of Beta(fp + 1, n - fp)
  const a = fp + 1;
  const b = n - fp;
  const p = 1.0 - confidenceAlpha;

  return betaQuantile(p, a, b);
}

/**
 * Incomplete Beta function and inverse Beta quantile (accurate to > 1e-7)
 */
function betaQuantile(p: number, a: number, b: number): number {
  if (p <= 0) return 0;
  if (p >= 1) return 1;

  // Initial estimate using Carter approximation
  let x: number;
  const mean = a / (a + b);
  const variance = (a * b) / ((a + b) * (a + b) * (a + b + 1));
  const sd = Math.sqrt(variance);

  // Normal quantile estimate
  const z = rationalApproximation(p);
  x = mean + z * sd;
  if (x <= 0 || x >= 1) {
    x = mean;
  }

  // Newton-Raphson refinement
  for (let iter = 0; iter < 50; iter++) {
    const fx = regularizedIncompleteBeta(x, a, b) - p;
    if (Math.abs(fx) < 1e-12) break;

    // Derivative is Beta PDF
    const dfx = betaPdf(x, a, b);
    if (dfx <= 0) break;

    const dx = fx / dfx;
    x -= dx;
    if (x <= 0) x = 1e-7;
    if (x >= 1) x = 1.0 - 1e-7;
    if (Math.abs(dx) < 1e-10) break;
  }

  return Math.max(0, Math.min(1, x));
}

function rationalApproximation(t: number): number {
  // Abramowitz and Stegun approximation for standard normal quantile
  const isLower = t < 0.5;
  const p = isLower ? t : 1.0 - t;
  const w = Math.sqrt(-2.0 * Math.log(p));
  const c0 = 2.515517;
  const c1 = 0.802853;
  const c2 = 0.010328;
  const d1 = 1.432788;
  const d2 = 0.189269;
  const d3 = 0.001308;
  const num = c0 + c1 * w + c2 * w * w;
  const den = 1.0 + d1 * w + d2 * w * w + d3 * w * w * w;
  const z = w - num / den;
  return isLower ? -z : z;
}

function logGamma(x: number): number {
  // Lanczos approximation (g=7)
  const p = [
    0.99999999999980993,
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7
  ];
  if (x < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  }
  x -= 1;
  let a = p[0];
  const t = x + 7.5;
  for (let i = 1; i < p.length; i++) {
    a += p[i] / (x + i);
  }
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}

function betaPdf(x: number, a: number, b: number): number {
  if (x <= 0 || x >= 1) return 0;
  const logBeta = logGamma(a) + logGamma(b) - logGamma(a + b);
  const logVal = (a - 1) * Math.log(x) + (b - 1) * Math.log(1 - x) - logBeta;
  return Math.exp(logVal);
}

function regularizedIncompleteBeta(x: number, a: number, b: number): number {
  if (x <= 0) return 0;
  if (x >= 1) return 1;

  // Use symmetry if x > (a + 1) / (a + b + 2)
  if (x > (a + 1) / (a + b + 2)) {
    return 1.0 - regularizedIncompleteBeta(1 - x, b, a);
  }

  // Continued fraction (Lentz's method)
  const logBeta = logGamma(a) + logGamma(b) - logGamma(a + b);
  const factor = Math.exp(a * Math.log(x) + b * Math.log(1 - x) - logBeta) / a;

  let c = 1.0;
  let d = 1.0 - (a + b) * x / (a + 1);
  if (Math.abs(d) < 1e-30) d = 1e-30;
  d = 1.0 / d;
  let f = d;

  for (let m = 1; m <= 200; m++) {
    // Even step
    let numerator = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m));
    d = 1.0 + numerator * d;
    if (Math.abs(d) < 1e-30) d = 1e-30;
    c = 1.0 + numerator / c;
    if (Math.abs(c) < 1e-30) c = 1e-30;
    d = 1.0 / d;
    f *= c * d;

    // Odd step
    numerator = -((a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1));
    d = 1.0 + numerator * d;
    if (Math.abs(d) < 1e-30) d = 1e-30;
    c = 1.0 + numerator / c;
    if (Math.abs(c) < 1e-30) c = 1e-30;
    d = 1.0 / d;
    const delta = c * d;
    f *= delta;

    if (Math.abs(delta - 1.0) < 1e-12) break;
  }

  return factor * f;
}
