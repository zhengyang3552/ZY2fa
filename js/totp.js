/**
 * ZY2fa · TOTP engine (RFC 6238) + otpauth:// parsing (Key Uri Format)
 *
 * Pure functions with no DOM or storage dependencies, so the whole module can
 * be unit-tested under Node with a WebCrypto polyfill or a browser.
 */

/** Errors carry a machine-readable `code` plus a message safe to show users. */
export class TotpError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'TotpError';
    this.code = code;
  }
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const ALGORITHMS = Object.freeze(['SHA1', 'SHA256', 'SHA512']);
export const DIGITS = Object.freeze([6, 8]);
export const PERIODS = Object.freeze([30, 60]);

const WEB_CRYPTO_NAMES = Object.freeze({
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512',
});

/* ------------------------------------------------------------------------ */
/*  Base32                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Normalise a user-supplied secret: strip spaces/dashes/padding, uppercase.
 * Returns the canonical base32 form (no padding) used at rest.
 */
export function normalizeSecret(input) {
  return String(input ?? '')
    .replace(/[\s\-_]/g, '')
    .replace(/=+$/, '')
    .toUpperCase();
}

/** Decode RFC 4648 base32 into bytes, rejecting anything ambiguous. */
export function base32Decode(input) {
  const clean = normalizeSecret(input);
  if (!clean) {
    throw new TotpError('SECRET_EMPTY', '密钥不能为空');
  }

  const invalid = clean.match(/[^A-Z2-7]/);
  if (invalid) {
    throw new TotpError(
      'SECRET_CHARSET',
      `密钥包含无效字符「${invalid[0]}」，base32 只允许 A–Z 和 2–7`,
    );
  }

  // 8 base32 chars → 5 bytes. Anything shorter carries < 25 bits of entropy.
  if (clean.length < 8) {
    throw new TotpError('SECRET_SHORT', '密钥太短，至少需要 8 位字符');
  }

  const byteLength = Math.floor((clean.length * 5) / 8);
  const bytes = new Uint8Array(byteLength);
  let buffer = 0;
  let bits = 0;
  let offset = 0;

  for (const ch of clean) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset] = (buffer >>> bits) & 0xff;
      offset += 1;
      // Keep only the unconsumed low bits, otherwise the accumulator overflows
      // the 32-bit shift range after ~6 characters.
      buffer &= (1 << bits) - 1;
    }
  }

  return bytes;
}

/* ------------------------------------------------------------------------ */
/*  TOTP                                                                    */
/* ------------------------------------------------------------------------ */

function assertCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new TotpError(
      'NO_WEBCRYPTO',
      '当前环境不支持 Web Crypto，请通过 https 或 localhost 打开本应用',
    );
  }
}

const hmacKeyCache = new Map();

async function importHmacKey(secretBytes, algorithm) {
  // Keyed by the full secret so distinct secrets can never collide.
  const cacheKey = `${algorithm}:${Array.from(secretBytes).join('.')}`;
  const cached = hmacKeyCache.get(cacheKey);
  if (cached) return cached;

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: WEB_CRYPTO_NAMES[algorithm] },
    false,
    ['sign'],
  );

  // Bound the cache so long sessions with many edits cannot leak entries.
  if (hmacKeyCache.size > 64) hmacKeyCache.clear();
  hmacKeyCache.set(cacheKey, key);
  return key;
}

/** HOTP for a specific counter (RFC 4226 §5.3 dynamic truncation). */
export async function generateHOTP({ secretBytes, algorithm = 'SHA1', digits = 6 }, counter) {
  assertCrypto();

  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new TotpError('BAD_COUNTER', '无效的时间计数器');
  }
  if (!WEB_CRYPTO_NAMES[algorithm]) {
    throw new TotpError('BAD_ALGORITHM', `不支持的哈希算法：${algorithm}`);
  }
  if (!DIGITS.includes(digits)) {
    throw new TotpError('BAD_DIGITS', `验证码位数只支持 6 或 8，收到 ${digits}`);
  }

  const key = await importHmacKey(secretBytes, algorithm);

  const message = new ArrayBuffer(8);
  const view = new DataView(message);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000), false);
  view.setUint32(4, counter % 0x1_0000_0000, false);

  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    (signature[offset + 1] << 16) |
    (signature[offset + 2] << 8) |
    signature[offset + 3];

  const code = String(binary % 10 ** digits).padStart(digits, '0');
  return code;
}

/** Time-step counters for an instant. */
export function stepAt(period, timestampMs = Date.now()) {
  const seconds = Math.floor(timestampMs / 1000);
  return {
    counter: Math.floor(seconds / period),
    remaining: period - (seconds % period),
  };
}

/**
 * Current TOTP for an account.
 * @returns {Promise<{code: string, counter: number, remaining: number, period: number}>}
 */
export async function generateTOTP(account, timestampMs = Date.now()) {
  const { secretBytes, algorithm = 'SHA1', digits = 6, period = 30 } = account;
  if (!secretBytes?.length) {
    throw new TotpError('SECRET_EMPTY', '账户缺少密钥');
  }
  if (!Number.isFinite(period) || period <= 0) {
    throw new TotpError('BAD_PERIOD', '无效的时间步长');
  }

  const { counter, remaining } = stepAt(period, timestampMs);
  const code = await generateHOTP({ secretBytes, algorithm, digits }, counter);
  return { code, counter, remaining, period };
}

/* ------------------------------------------------------------------------ */
/*  otpauth:// parsing                                                      */
/* ------------------------------------------------------------------------ */

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value ?? '').replace(/\+/g, ' '));
  } catch {
    return String(value ?? '');
  }
}

const OTPAUTH_RE = /^otpauth:\/\//i;
const BARE_SECRET_RE = /^[A-Za-z2-7\s\-=_]+$/;

/**
 * Parse an `otpauth://totp/...` URI, or a bare base32 secret.
 *
 * @param {string} raw
 * @returns {{issuer: string, label: string, secret: string, algorithm: string,
 *            digits: number, period: number, warnings: string[]}}
 */
export function parseOtpAuthUri(raw) {
  const text = String(raw ?? '').trim();
  if (!text) {
    throw new TotpError('URI_EMPTY', '请粘贴 otpauth:// 链接或密钥');
  }

  // A bare secret is a common paste; accept it so users can add accounts from
  // a service that only shows the key.
  if (!OTPAUTH_RE.test(text) && !text.includes('://') && BARE_SECRET_RE.test(text)) {
    const secret = normalizeSecret(text);
    base32Decode(secret); // validates charset + length
    return {
      issuer: '',
      label: '',
      secret,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      warnings: ['未识别到链接格式，已按纯密钥处理；请手动补全名称'],
    };
  }

  if (!OTPAUTH_RE.test(text)) {
    throw new TotpError(
      'URI_SCHEME',
      '链接格式不正确，应以 otpauth://totp/ 开头',
    );
  }

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new TotpError('URI_INVALID', '无法解析该链接，请检查是否被截断或包含多余空格');
  }

  const type = url.hostname.toLowerCase();
  if (type === 'hotp') {
    throw new TotpError('URI_HOTP', '本应用只支持基于时间的 TOTP，暂不支持 HOTP 计数器模式');
  }
  if (type !== 'totp') {
    throw new TotpError('URI_TYPE', `不支持的验证类型：otpauth://${type}`);
  }

  const params = url.searchParams;
  const secret = normalizeSecret(params.get('secret'));
  if (!secret) {
    throw new TotpError('URI_NO_SECRET', '链接中缺少 secret 参数');
  }
  const secretBytes = base32Decode(secret); // throws on bad charset/length

  const rawLabel = safeDecode(url.pathname.replace(/^\//, ''));
  const warnings = [];

  // Label may be "Issuer:account" or just "account".
  let issuer = safeDecode(params.get('issuer') ?? '').trim();
  let label = rawLabel;
  const separator = rawLabel.indexOf(':');
  if (separator >= 0) {
    const labelIssuer = rawLabel.slice(0, separator).trim();
    label = rawLabel.slice(separator + 1).trim();
    if (!issuer && labelIssuer) issuer = labelIssuer;
    else if (issuer && labelIssuer && issuer !== labelIssuer) {
      warnings.push('链接中的发行方名称前后不一致，已采用 issuer 参数');
    }
  }
  if (!issuer) issuer = '未命名服务';

  const algorithmParam = String(params.get('algorithm') ?? 'SHA1').toUpperCase().replace('-', '');
  const algorithm = ALGORITHMS.includes(algorithmParam) ? algorithmParam : 'SHA1';
  if (!ALGORITHMS.includes(algorithmParam)) {
    warnings.push(`未知算法「${params.get('algorithm')}」，已回退为 SHA1`);
  }

  const digitsParam = Number.parseInt(params.get('digits') ?? '6', 10);
  const digits = DIGITS.includes(digitsParam) ? digitsParam : 6;
  if (!DIGITS.includes(digitsParam)) {
    warnings.push(`不支持的位数「${params.get('digits')}」，已回退为 6 位`);
  }

  const periodParam = Number.parseInt(params.get('period') ?? '30', 10);
  const period = Number.isFinite(periodParam) && periodParam > 0 && periodParam <= 300 ? periodParam : 30;
  if (period !== periodParam) {
    warnings.push(`不支持的时间步长「${params.get('period')}」，已回退为 30 秒`);
  }
  if (secretBytes.length < 10) {
    warnings.push('密钥长度偏短（不足 80 位），该账户的安全性可能较弱');
  }

  return { issuer, label, secret, algorithm, digits, period, warnings };
}

/** Build a shareable otpauth URI from an account (used by export). */
export function buildOtpAuthUri(account) {
  const { issuer, label, secret, algorithm, digits, period } = account;
  const name = label ? `${issuer}:${label}` : issuer;
  const params = new URLSearchParams({ secret });
  if (issuer) params.set('issuer', issuer);
  if (algorithm && algorithm !== 'SHA1') params.set('algorithm', algorithm);
  if (digits && digits !== 6) params.set('digits', String(digits));
  if (period && period !== 30) params.set('period', String(period));
  return `otpauth://totp/${encodeURIComponent(name)}?${params.toString()}`;
}
