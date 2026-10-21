/**
 * ZY2fa · data model
 * Validation, normalisation, migration, search and sort for account records.
 * Storage is deliberately not handled here — see vault.js.
 */

import { uid, clamp } from './utils.js';
import {
  ALGORITHMS,
  DIGITS,
  parseOtpAuthUri,
  base32Decode,
  normalizeSecret,
} from './totp.js';

export const SCHEMA_VERSION = 1;
export const APP_TAG = 'ZY2fa';

const LIMITS = Object.freeze({
  issuer: 64,
  label: 128,
  secret: 256,
  accounts: 300,
});

export class ValidationError extends Error {
  constructor(field, message) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

const text = (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max);

/* ------------------------------------------------------------------------ */
/*  Normalisation                                                           */
/* ------------------------------------------------------------------------ */

/**
 * Coerce an untrusted record into a valid account, or throw ValidationError.
 * `lenient` downgrades unusable optional fields to defaults instead of throwing
 * (used by import, where one odd field should not reject a whole backup).
 */
export function normalizeAccount(raw, { lenient = false } = {}) {
  if (!raw || typeof raw !== 'object') {
    throw new ValidationError('account', '账户数据格式不正确');
  }

  const secret = normalizeSecret(raw.secret);
  if (!secret) throw new ValidationError('secret', '密钥不能为空');
  if (secret.length > LIMITS.secret) throw new ValidationError('secret', '密钥长度超出限制');

  try {
    base32Decode(secret);
  } catch (err) {
    if (!lenient) throw new ValidationError('secret', err.message);
    throw err;
  }

  let issuer = text(raw.issuer, LIMITS.issuer);
  let label = text(raw.label, LIMITS.label);

  // A record with neither name still needs *something* to render.
  if (!issuer && !label) {
    if (lenient) issuer = '未命名服务';
    else throw new ValidationError('issuer', '请填写服务名称');
  }
  if (!issuer) issuer = label;

  const algorithmRaw = String(raw.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
  const algorithm = ALGORITHMS.includes(algorithmRaw) ? algorithmRaw : 'SHA1';

  const digitsNum = Number.parseInt(raw.digits ?? 6, 10);
  const digits = DIGITS.includes(digitsNum) ? digitsNum : 6;

  const periodNum = Number.parseInt(raw.period ?? 30, 10);
  const period = Number.isFinite(periodNum) ? clamp(periodNum, 5, 300) : 30;

  const now = Date.now();
  const createdAt = Number.isFinite(raw.createdAt) && raw.createdAt > 0 ? raw.createdAt : now;

  return {
    id: typeof raw.id === 'string' && raw.id.length >= 8 ? raw.id : uid(),
    issuer,
    label: label || '',
    secret,
    algorithm,
    digits,
    period,
    createdAt,
    updatedAt: Number.isFinite(raw.updatedAt) ? raw.updatedAt : createdAt,
  };
}

/** Attach the decoded key so the TOTP engine need not re-decode per render. */
export function withSecretBytes(account) {
  try {
    return { ...account, secretBytes: base32Decode(account.secret) };
  } catch {
    return { ...account, secretBytes: null };
  }
}

/* ------------------------------------------------------------------------ */
/*  Duplicates & conflict resolution                                        */
/* ------------------------------------------------------------------------ */

const identity = (a) => `${a.secret}|${a.issuer.toLowerCase()}|${a.label.toLowerCase()}`;

export function findDuplicate(accounts, candidate) {
  const key = identity(candidate);
  return accounts.find((a) => identity(a) === key) ?? null;
}

/** Same secret, different label — almost always the same account re-imported. */
export function findSecretClash(accounts, candidate) {
  return accounts.find((a) => a.secret === candidate.secret && identity(a) !== identity(candidate)) ?? null;
}

/* ------------------------------------------------------------------------ */
/*  Query                                                                   */
/* ------------------------------------------------------------------------ */

export const SORT_OPTIONS = Object.freeze([
  { value: 'created', label: '添加时间' },
  { value: 'name', label: '名称' },
  { value: 'issuer', label: '按服务' },
]);

export function filterAndSort(accounts, { query = '', sort = 'created' } = {}) {
  const needle = query.trim().toLowerCase();
  const matched = needle
    ? accounts.filter(
        (a) =>
          a.issuer.toLowerCase().includes(needle) ||
          a.label.toLowerCase().includes(needle),
      )
    : [...accounts];

  const collator = new Intl.Collator('zh-Hans-CN', { numeric: true, sensitivity: 'base' });
  matched.sort((a, b) => {
    if (sort === 'name') return collator.compare(a.issuer, b.issuer) || collator.compare(a.label, b.label);
    if (sort === 'issuer') return collator.compare(a.label, b.label) || collator.compare(a.issuer, b.issuer);
    return b.createdAt - a.createdAt; // newest first
  });
  return matched;
}

/* ------------------------------------------------------------------------ */
/*  Export                                                                  */
/* ------------------------------------------------------------------------ */

export function buildBackup(accounts) {
  return {
    app: APP_TAG,
    version: SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    encrypted: false,
    count: accounts.length,
    accounts: accounts.map(({ secretBytes, ...rest }) => rest),
  };
}

/* ------------------------------------------------------------------------ */
/*  Import                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Parse an import payload from several plausible shapes:
 *   1. ZY2fa backup object           { app, accounts: [...] }
 *   2. Generic object                { accounts: [...] } / { tokens: [...] }
 *   3. Bare array of account objects
 *   4. Bare array of otpauth:// strings
 *   5. Newline-separated otpauth:// or base32 secrets (plain text export)
 *
 * Never throws for individual bad rows — those are reported as `skipped`
 * with a reason, so a partially valid file still imports.
 */
export function parseImportPayload(input) {
  const raw = typeof input === 'string' ? input.trim() : input;
  if (!raw || (typeof raw === 'string' && !raw.length)) {
    throw new ValidationError('payload', '导入内容为空');
  }

  let parsed = raw;
  if (typeof raw === 'string') {
    if (/^[[{]/.test(raw)) {
      try {
        parsed = JSON.parse(raw);
      } catch (err) {
        throw new ValidationError('payload', `JSON 解析失败：${err.message}`);
      }
    } else {
      // Plain-text export: one otpauth URI (or secret) per line.
      const lines = raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));
      if (!lines.length) throw new ValidationError('payload', '没有找到可导入的内容');
      parsed = lines;
    }
  }

  let rows;
  if (Array.isArray(parsed)) {
    rows = parsed;
  } else if (parsed && typeof parsed === 'object') {
    const candidate = parsed.accounts ?? parsed.tokens ?? parsed.items;
    if (!Array.isArray(candidate)) {
      throw new ValidationError('payload', '未在文件中找到 accounts 数组');
    }
    if (parsed.encrypted) {
      throw new ValidationError('payload', '该备份已加密，请先解密后再导入');
    }
    rows = candidate;
  } else {
    throw new ValidationError('payload', '无法识别的文件格式');
  }

  if (rows.length > LIMITS.accounts) {
    throw new ValidationError('payload', `单次最多导入 ${LIMITS.accounts} 个账户，文件包含 ${rows.length} 个`);
  }

  const accounts = [];
  const skipped = [];

  rows.forEach((row, index) => {
    try {
      if (typeof row === 'string') {
        const uri = row.trim();
        if (!uri) return;
        const parsedUri = parseOtpAuthUri(uri);
        accounts.push(normalizeAccount(parsedUri, { lenient: true }));
        return;
      }
      accounts.push(normalizeAccount(row, { lenient: true }));
    } catch (err) {
      skipped.push({ index: index + 1, reason: err.message || '无法解析' });
    }
  });

  if (!accounts.length) {
    const detail = skipped.length ? `：${skipped[0].reason}` : '';
    throw new ValidationError('payload', `没有可导入的有效账户${detail}`);
  }

  return { accounts, skipped };
}

/** Merge imported accounts into an existing list, de-duplicating by identity. */
export function mergeAccounts(existing, incoming) {
  const result = [...existing];
  let added = 0;
  let duplicates = 0;

  for (const candidate of incoming) {
    if (findDuplicate(result, candidate)) {
      duplicates += 1;
      continue;
    }
    if (result.length >= LIMITS.accounts) {
      return { accounts: result, added, duplicates, overflow: incoming.length - added - duplicates };
    }
    // Fresh id so an import can never clobber an unrelated local record.
    result.push({ ...candidate, id: uid(), updatedAt: Date.now() });
    added += 1;
  }

  return { accounts: result, added, duplicates, overflow: 0 };
}

/* ------------------------------------------------------------------------ */
/*  PIN policy                                                              */
/* ------------------------------------------------------------------------ */

export const PIN_MIN_LENGTH = 6;

export function validatePin(pin, { confirm } = {}) {
  const value = String(pin ?? '');
  if (!value) throw new ValidationError('pin', '请输入密码');
  if (value.length < PIN_MIN_LENGTH) {
    throw new ValidationError('pin', `密码至少需要 ${PIN_MIN_LENGTH} 位`);
  }
  if (value.length > 128) throw new ValidationError('pin', '密码过长');
  if (confirm !== undefined && value !== confirm) {
    throw new ValidationError('confirm', '两次输入的密码不一致');
  }
  return value;
}
