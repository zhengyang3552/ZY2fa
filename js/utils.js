/**
 * ZY2fa · shared helpers
 * Small, dependency-free utilities used across the app.
 */

/* ------------------------------------------------------------------ DOM */
export const $ = (selector, scope = document) => scope.querySelector(selector);
export const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];

/** Escape text destined for an innerHTML template. */
export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[ch]);
}

/* ------------------------------------------------------------------ ids */
export function uid() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  // Fallback for older Safari / insecure contexts.
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
  else for (let i = 0; i < 16; i += 1) bytes[i] = Math.floor(Math.random() * 256);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/* ------------------------------------------------------------- formatting */
/** "123456" → "123 456"; "12345678" → "1234 5678". Helps the eye chunk digits. */
export function groupCode(code) {
  const value = String(code ?? '');
  const mid = Math.ceil(value.length / 2);
  return `${value.slice(0, mid)} ${value.slice(mid)}`.trim();
}

/** Up to two initials for the account avatar. */
export function initials(issuer, label) {
  const source = String(issuer || label || '?').trim();
  if (!source) return '?';
  const words = source.split(/[\s\-_.@]+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return source.slice(0, 2).toUpperCase();
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** i;
  return `${value >= 10 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

export function formatRelative(ts) {
  if (!ts) return '—';
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const days = Math.floor(diff / 86_400_000);
  if (days < 30) return `${days} 天前`;
  return new Date(ts).toLocaleDateString('zh-CN');
}

/* ------------------------------------------------------------------ misc */
export const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

/** Trailing-edge debounce. */
export function debounce(fn, wait = 160) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Rough PIN strength: 0-4. Length dominates, character variety nudges. */
export function pinStrength(pin) {
  const value = String(pin ?? '');
  if (!value) return 0;
  if (/^\d+$/.test(value)) {
    if (value.length < 6) return 1;
    if (value.length < 8) return 2;
    if (value.length < 12) return 3;
    return 4;
  }
  let score = value.length >= 6 ? 2 : 1;
  if (value.length >= 10) score += 1;
  if (/[^A-Za-z0-9]/.test(value) || (/[A-Z]/.test(value) && /[a-z]/.test(value))) score += 1;
  return clamp(score, 0, 4);
}

/* --------------------------------------------------------------- clipboard */
/**
 * Copy text, preferring the async Clipboard API and falling back to a hidden
 * textarea. Rejects with a readable message so callers can surface it.
 */
export async function copyText(text) {
  const value = String(text ?? '');
  if (!value) throw new Error('没有可复制的内容');

  if (navigator.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch (err) {
      // Permission denied / document not focused → try the legacy path.
      if (err?.name === 'NotAllowedError' || err?.name === 'SecurityError') {
        /* fall through */
      } else {
        throw err;
      }
    }
  }

  const area = document.createElement('textarea');
  area.value = value;
  area.setAttribute('readonly', '');
  area.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none;';
  document.body.append(area);
  const active = document.activeElement;
  area.select();
  area.setSelectionRange(0, value.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  } finally {
    area.remove();
    if (active instanceof HTMLElement) active.focus({ preventScroll: true });
  }
  if (!ok) throw new Error('浏览器拒绝了复制操作，请手动选择文本复制');
}

/* ---------------------------------------------------------------- download */
export function downloadFile(filename, content, mime = 'application/json') {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  // Give Safari a tick before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

/* ---------------------------------------------------------------- base64 */
export function bytesToBase64(bytes) {
  let binary = '';
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const chunk = 0x8000;
  for (let i = 0; i < view.length; i += chunk) {
    binary += String.fromCharCode(...view.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(String(b64));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
