/**
 * ZY2fa · vault
 * At-rest persistence for account secrets, with optional PIN encryption.
 *
 * Two envelopes can live under the storage key:
 *   plain : { v, mode: 'plain', accounts: [...] }
 *   pin   : { v, mode: 'pin', kdf: {...}, cipher: { iv, data } }
 *
 * With a PIN set, secrets never touch disk in the clear: the accounts blob is
 * encrypted with AES-256-GCM using a key derived from the PIN via PBKDF2-
 * SHA256. The GCM auth tag doubles as the PIN check — a wrong PIN fails
 * decryption rather than comparing against a stored hash, so there is nothing
 * offline-crackable beyond the KDF itself.
 *
 * The PIN cannot be recovered. Losing it means losing the vault; the UI states
 * this before enabling it.
 */

import { bytesToBase64, base64ToBytes } from './utils.js';
import { normalizeAccount, SCHEMA_VERSION } from './store.js';

export const STORAGE_KEY = 'zy2fa.vault.v1';
export const RECOVERY_PREFIX = 'zy2fa.recovered.';

const KDF_ITERATIONS = 210_000; // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
const CIPHER_AAD = 'ZY2fa:v1';
const KEY_BITS = 256;

export class VaultError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
    this.cause = cause;
  }
}

/* ------------------------------------------------------------------------ */
/*  Storage probe                                                           */
/* ------------------------------------------------------------------------ */

let storageAvailable = null;

/** Detect private-mode / disabled-storage early so the UI can warn once. */
export function isStorageAvailable() {
  if (storageAvailable !== null) return storageAvailable;
  try {
    const probe = '__zy2fa_probe__';
    localStorage.setItem(probe, '1');
    localStorage.removeItem(probe);
    storageAvailable = true;
  } catch {
    storageAvailable = false;
  }
  return storageAvailable;
}

function readRaw() {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch (err) {
    throw new VaultError('STORAGE_READ', '无法读取本地存储，请检查浏览器是否禁用了站点数据', err);
  }
}

function writeRaw(value) {
  try {
    localStorage.setItem(STORAGE_KEY, value);
  } catch (err) {
    const quota = err?.name === 'QuotaExceededError' || err?.code === 22;
    throw new VaultError(
      quota ? 'QUOTA' : 'STORAGE_WRITE',
      quota ? '本地存储空间不足，本次修改未保存' : '写入本地存储失败，本次修改未保存',
      err,
    );
  }
}

/* ------------------------------------------------------------------------ */
/*  Crypto helpers                                                          */
/* ------------------------------------------------------------------------ */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function requireSubtle() {
  if (!globalThis.crypto?.subtle) {
    throw new VaultError('NO_WEBCRYPTO', '当前环境不支持加密接口，请通过 https 或 localhost 打开本应用');
  }
}

async function deriveKey(pin, salt, iterations) {
  requireSubtle();
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

/* ------------------------------------------------------------------------ */
/*  Vault                                                                   */
/* ------------------------------------------------------------------------ */

export class Vault {
  #key = null;

  #envelope = null;

  #issues = [];

  #recovered = null;

  /** 'plain' | 'pin' | 'empty' */
  get mode() {
    if (!this.#envelope) return 'empty';
    return this.#envelope.mode === 'pin' ? 'pin' : 'plain';
  }

  get isLocked() {
    return this.mode === 'pin' && !this.#key;
  }

  get isEncrypted() {
    return this.mode === 'pin';
  }

  /** Rows dropped during the last load (invalid secret, etc.). */
  get issues() {
    return this.#issues;
  }

  /** Raw payload salvaged from an unreadable vault, if any. */
  get recoveredPayload() {
    return this.#recovered;
  }

  get updatedAt() {
    return this.#envelope?.updatedAt ?? null;
  }

  /**
   * Read the envelope from disk. Never throws for corrupt data — the raw value
   * is quarantined so the user can download it, and the vault starts empty.
   * An encrypted vault comes back locked.
   */
  async init() {
    this.#key = null;
    this.#issues = [];
    this.#recovered = null;

    const raw = readRaw();
    if (!raw) {
      this.#envelope = null;
      return { mode: 'empty', accounts: [], locked: false };
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return this.#quarantine(raw, '本地数据已损坏，无法解析');
    }

    if (!parsed || typeof parsed !== 'object') {
      return this.#quarantine(raw, '本地数据格式异常');
    }

    if (parsed.mode === 'pin') {
      const valid =
        parsed.kdf?.salt &&
        parsed.cipher?.iv &&
        parsed.cipher?.data &&
        Number.isFinite(parsed.kdf?.iterations);
      if (!valid) return this.#quarantine(raw, '加密数据缺少必要字段');
      this.#envelope = parsed;
      return { mode: 'pin', accounts: [], locked: true };
    }

    // Plain (or legacy bare-array) envelopes.
    const rows = Array.isArray(parsed) ? parsed : parsed.accounts;
    if (!Array.isArray(rows)) {
      return this.#quarantine(raw, '找不到账户列表');
    }

    this.#envelope = {
      v: SCHEMA_VERSION,
      mode: 'plain',
      accounts: [],
      updatedAt: parsed.updatedAt ?? null,
    };

    const accounts = this.#normalizeRows(rows);
    this.#envelope.accounts = accounts;
    return { mode: 'plain', accounts, locked: false, issues: this.#issues };
  }

  /** Normalise rows, collecting per-row failures instead of aborting. */
  #normalizeRows(rows) {
    const out = [];
    const seen = new Set();
    rows.forEach((row, index) => {
      try {
        const account = normalizeAccount(row, { lenient: true });
        if (seen.has(account.id)) account.id = `${account.id}-${index}`;
        seen.add(account.id);
        out.push(account);
      } catch (err) {
        this.#issues.push({ index, reason: err.message || '无法解析' });
      }
    });
    return out;
  }

  /** Move unreadable data aside; keep it downloadable, then clear the slot. */
  #quarantine(raw, reason) {
    this.#envelope = null;
    this.#recovered = raw;
    try {
      localStorage.setItem(`${RECOVERY_PREFIX}${Date.now()}`, raw);
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* Storage is unwritable; the in-memory copy is still surfaced. */
    }
    return { mode: 'empty', accounts: [], locked: false, recovered: raw, reason };
  }

  /** Decrypt with the PIN. Throws VaultError('PIN_WRONG') on mismatch. */
  async unlock(pin) {
    if (this.mode !== 'pin') return { accounts: this.#envelope?.accounts ?? [] };
    const { kdf, cipher } = this.#envelope;

    const key = await deriveKey(pin, base64ToBytes(kdf.salt), kdf.iterations);
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(cipher.iv), additionalData: encoder.encode(CIPHER_AAD) },
        key,
        base64ToBytes(cipher.data),
      );
    } catch (err) {
      throw new VaultError('PIN_WRONG', '密码不正确，请重试', err);
    }

    let rows;
    try {
      const parsed = JSON.parse(decoder.decode(plaintext));
      rows = Array.isArray(parsed) ? parsed : parsed.accounts;
    } catch (err) {
      throw new VaultError('CORRUPT', '保险库内容已损坏，无法读取', err);
    }
    if (!Array.isArray(rows)) {
      throw new VaultError('CORRUPT', '保险库内容缺少账户列表');
    }

    this.#key = key;
    this.#issues = [];
    const accounts = this.#normalizeRows(rows);
    return { accounts, issues: this.#issues };
  }

  /** Drop the in-memory key. Data on disk is untouched. */
  lock() {
    this.#key = null;
  }

  /** Persist accounts in whichever mode is active. */
  async save(accounts) {
    const clean = accounts.map(({ secretBytes, ...rest }) => rest);
    const now = Date.now();

    if (this.mode === 'pin') {
      if (!this.#key) throw new VaultError('LOCKED', '保险库已锁定，无法保存');
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: encoder.encode(CIPHER_AAD) },
        this.#key,
        encoder.encode(JSON.stringify({ v: SCHEMA_VERSION, accounts: clean })),
      );
      const envelope = {
        v: SCHEMA_VERSION,
        mode: 'pin',
        kdf: this.#envelope.kdf,
        cipher: { alg: 'AES-GCM', iv: bytesToBase64(iv), data: bytesToBase64(ciphertext) },
        updatedAt: now,
      };
      writeRaw(JSON.stringify(envelope));
      this.#envelope = envelope;
      return;
    }

    const envelope = { v: SCHEMA_VERSION, mode: 'plain', accounts: clean, updatedAt: now };
    writeRaw(JSON.stringify(envelope));
    this.#envelope = envelope;
  }

  /** Turn on encryption for the current accounts. */
  async enablePin(pin, accounts) {
    requireSubtle();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pin, salt, KDF_ITERATIONS);

    // Verify the key round-trips before committing, so a subtly broken
    // crypto environment cannot strand the user's data behind a bad key.
    // A fresh IV is used here — never reuse an IV with the same key.
    const probeIv = crypto.getRandomValues(new Uint8Array(12));
    const probe = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: probeIv, additionalData: encoder.encode('probe') },
      key,
      encoder.encode('ok'),
    );
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: probeIv, additionalData: encoder.encode('probe') },
      key,
      probe,
    );

    this.#envelope = {
      v: SCHEMA_VERSION,
      mode: 'pin',
      kdf: { alg: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt: bytesToBase64(salt) },
      cipher: { alg: 'AES-GCM', iv: '', data: '' },
      updatedAt: Date.now(),
    };
    this.#key = key;
    await this.save(accounts);
  }

  /** Verify the current PIN without changing anything. */
  async verifyPin(pin) {
    if (this.mode !== 'pin') return true;
    const { kdf, cipher } = this.#envelope;
    const key = await deriveKey(pin, base64ToBytes(kdf.salt), kdf.iterations);
    try {
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(cipher.iv), additionalData: encoder.encode(CIPHER_AAD) },
        key,
        base64ToBytes(cipher.data),
      );
      return true;
    } catch {
      throw new VaultError('PIN_WRONG', '密码不正确，请重试');
    }
  }

  /** Re-encrypt under a new PIN (must prove the old one first). */
  async changePin(currentPin, nextPin, accounts) {
    await this.verifyPin(currentPin);
    await this.enablePin(nextPin, accounts);
  }

  /** Remove encryption; writes the accounts back in plain text. */
  async disablePin(pin, accounts) {
    await this.verifyPin(pin);
    this.#key = null;
    this.#envelope = { v: SCHEMA_VERSION, mode: 'plain', accounts: [], updatedAt: Date.now() };
    await this.save(accounts);
  }

  /** Delete everything, including quarantined payloads. */
  async wipe() {
    this.#key = null;
    this.#envelope = null;
    this.#recovered = null;
    this.#issues = [];
    try {
      localStorage.removeItem(STORAGE_KEY);
      Object.keys(localStorage)
        .filter((k) => k.startsWith(RECOVERY_PREFIX))
        .forEach((k) => localStorage.removeItem(k));
    } catch (err) {
      throw new VaultError('STORAGE_WRITE', '清除本地数据失败', err);
    }
  }

  /** Approximate bytes used by this app's keys. */
  usage() {
    let bytes = 0;
    const keys = Object.keys(localStorage).filter(
      (k) => k === STORAGE_KEY || k.startsWith(RECOVERY_PREFIX),
    );
    for (const key of keys) {
      bytes += (key.length + (localStorage.getItem(key)?.length ?? 0)) * 2;
    }
    return bytes;
  }

  recoveryCount() {
    return Object.keys(localStorage).filter((k) => k.startsWith(RECOVERY_PREFIX)).length;
  }
}

export const vault = new Vault();
