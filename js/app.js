/**
 * ZY2fa · application controller
 * Owns state, rendering and the event wiring. All persistence goes through
 * vault.js; all crypto through totp.js; markup lives in index.html.
 */

import {
  $, $$, esc, uid, groupCode, initials, formatBytes, formatRelative,
  debounce, pinStrength, copyText, downloadFile, clamp,
} from './utils.js';

import {
  generateTOTP, stepAt, parseOtpAuthUri, buildOtpAuthUri,
  base32Decode, TotpError,
} from './totp.js';

import {
  normalizeAccount, withSecretBytes, findDuplicate, findSecretClash, filterAndSort,
  buildBackup, parseImportPayload, mergeAccounts, validatePin,
  ValidationError, PIN_MIN_LENGTH, SORT_OPTIONS,
} from './store.js';

import { vault, VaultError, isStorageAvailable } from './vault.js';

import {
  icon, toast, confirmDialog, openMenu, closeMenu, openDialog, closeDialog,
  bindDialog, setFieldError,
} from './ui.js';

/* ------------------------------------------------------------------------ */
/*  Constants & state                                                       */
/* ------------------------------------------------------------------------ */

const THEME_KEY = 'zy2fa.theme';
const AUTOLOCK_KEY = 'zy2fa.autolock';
const AUTO_LOCK_MS = 5 * 60 * 1000;
const TICK_MS = 200;
const EXPIRING_AT = 10; // seconds left before the warning state
const CRITICAL_AT = 5; // seconds left before the error state

const THEME_LABELS = { light: '浅色', dark: '深色', system: '跟随系统' };

const state = {
  accounts: [],
  query: '',
  sort: 'created',
  theme: 'system',
  route: 'codes',
  pinMode: 'enable',
  editingId: null,
  codes: new Map(), // accountId → { code, counter, remaining }
  inFlight: new Set(),
  notices: [],
  booted: false,
  hiddenAt: null,
  autoLock: false,
};

const el = {
  appBar: $('#appBar'),
  appBody: $('#appBody'),
  gate: $('#gate'),
  gateForm: $('#gateForm'),
  gatePin: $('#gatePin'),
  gateSubmit: $('#gateSubmit'),
  gateError: $('#gateError'),
  gateReset: $('#gateReset'),
  accountList: $('#accountList'),
  emptyState: $('#emptyState'),
  emptyTitle: $('#emptyTitle'),
  emptyDesc: $('#emptyDesc'),
  codesSummary: $('#codesSummary'),
  countLabel: $('#countLabel'),
  searchInput: $('#searchInput'),
  searchClear: $('#searchClear'),
  noticeSlot: $('#noticeSlot'),
  btnSort: $('#btnSort'),
  sortLabel: $('#sortLabel'),
  btnAdd: $('#btnAdd'),
  btnTheme: $('#btnTheme'),
  btnLockTop: $('#btnLockTop'),
  encBadge: $('#encBadge'),
  themeSegmented: $('#themeSegmented'),
  themeHint: $('#themeHint'),
  dlgAccount: $('#dlgAccount'),
  accountForm: $('#accountForm'),
  dlgAccountTitle: $('#dlgAccountTitle'),
  uriInput: $('#uriInput'),
  issuerInput: $('#issuerInput'),
  labelInput: $('#labelInput'),
  secretInput: $('#secretInput'),
  periodInput: $('#periodInput'),
  algoSegmented: $('#algoSegmented'),
  digitsSegmented: $('#digitsSegmented'),
  previewBox: $('#previewBox'),
  previewText: $('#previewText'),
  btnSaveAccount: $('#btnSaveAccount'),
  btnParseUri: $('#btnParseUri'),
  btnToggleSecret: $('#btnToggleSecret'),
  dlgPin: $('#dlgPin'),
  pinForm: $('#pinForm'),
  pinTitle: $('#dlgPinTitle'),
  pinSubtitle: $('#dlgPinSubtitle'),
  currentPinField: $('#currentPinField'),
  currentPin: $('#currentPin'),
  newPinField: $('#newPinField'),
  newPin: $('#newPin'),
  confirmPinField: $('#confirmPinField'),
  confirmPin: $('#confirmPin'),
  pinStrength: $('#pinStrength'),
  pinWarning: $('#pinWarning'),
  btnConfirmPin: $('#btnConfirmPin'),
  statAccounts: $('#statAccounts'),
  statEncrypted: $('#statEncrypted'),
  statUsage: $('#statUsage'),
  statUpdated: $('#statUpdated'),
  pinHint: $('#pinHint'),
  btnPinPrimary: $('#btnPinPrimary'),
  btnLockNow: $('#btnLockNow'),
  autoLockToggle: $('#autoLockToggle'),
  dataCountHint: $('#dataCountHint'),
  dataCountBadge: $('#dataCountBadge'),
  btnWipe: $('#btnWipe'),
  importText: $('#importText'),
  importFile: $('#importFile'),
  btnImport: $('#btnImport'),
  btnImportClear: $('#btnImportClear'),
  btnExportFile: $('#btnExportFile'),
  btnExportClipboard: $('#btnExportClipboard'),
  btnExportUris: $('#btnExportUris'),
};

/* ------------------------------------------------------------------------ */
/*  Small helpers                                                           */
/* ------------------------------------------------------------------------ */

const findAccount = (id) => state.accounts.find((a) => a.id === id);

function storageGet(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* Preferences are best-effort; storage failure is surfaced elsewhere. */
  }
}

const nowSecondsLeft = (period) => stepAt(period).remaining;

/** Fingerprint used to detect duplicate secrets on add. */
const describeAccount = (a) => (a.label ? `${a.issuer} · ${a.label}` : a.issuer);

/* ------------------------------------------------------------------------ */
/*  Theme                                                                   */
/* ------------------------------------------------------------------------ */

function applyTheme(theme, { persist = true } = {}) {
  const value = ['light', 'dark', 'system'].includes(theme) ? theme : 'system';
  state.theme = value;

  const root = document.documentElement;
  if (value === 'system') root.removeAttribute('data-theme');
  else root.dataset.theme = value;

  if (persist) storageSet(THEME_KEY, value);

  // Keep browser chrome in step with the surface colour.
  const surface = getComputedStyle(root).getPropertyValue('--md-sys-color-surface').trim();
  if (surface) {
    let meta = $('meta[name="theme-color"]:not([media])');
    if (!meta) {
      meta = document.createElement('meta');
      meta.name = 'theme-color';
      document.head.append(meta);
    }
    meta.content = surface;
  }

  el.themeHint.textContent =
    value === 'system'
      ? `跟随系统（当前为${window.matchMedia('(prefers-color-scheme: dark)').matches ? '深色' : '浅色'}）`
      : `固定为${THEME_LABELS[value]}模式`;

  $$('[data-theme-value]', el.themeSegmented).forEach((btn) => {
    btn.setAttribute('aria-checked', String(btn.dataset.themeValue === value));
  });

  el.btnTheme.setAttribute(
    'aria-label',
    `切换外观（当前：${THEME_LABELS[value]}）`,
  );
}

function initTheme() {
  const saved = storageGet(THEME_KEY);
  applyTheme(saved || 'system', { persist: false });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (state.theme === 'system') applyTheme('system', { persist: false });
  });

  $$('[data-theme-value]', el.themeSegmented).forEach((btn) => {
    btn.addEventListener('click', () => {
      applyTheme(btn.dataset.themeValue);
      toast(`外观已切换为${THEME_LABELS[state.theme]}`);
    });
  });

  el.btnTheme.addEventListener('click', () => {
    openMenu(el.btnTheme, [
      { label: '浅色', icon: 'sun', onSelect: () => applyTheme('light') },
      { label: '深色', icon: 'moon', onSelect: () => applyTheme('dark') },
      { label: '跟随系统', icon: 'contrast', onSelect: () => applyTheme('system') },
    ]);
  });
}

/* ------------------------------------------------------------------------ */
/*  Notices (persistent banners)                                            */
/* ------------------------------------------------------------------------ */

const noticeDismissed = new Set();

function addNotice(id, { variant = 'info', message, action }) {
  if (noticeDismissed.has(id)) return;
  if (state.notices.some((n) => n.id === id)) return;
  state.notices.push({ id, variant, message, action });
}

function renderNotices() {
  if (!el.noticeSlot) return;
  if (!state.notices.length) {
    el.noticeSlot.innerHTML = '';
    return;
  }

  el.noticeSlot.innerHTML = state.notices
    .map(
      (n) => `
      <div class="banner banner--${n.variant}" data-notice="${esc(n.id)}" style="margin-bottom:var(--md-sys-spacing-3)">
        ${icon(n.variant === 'error' ? 'warning' : 'info', 'icon icon--sm')}
        <span style="flex:1">${n.message}</span>
        ${n.action ? `<button class="btn btn--text" data-notice-action="${esc(n.id)}" type="button">${esc(n.action)}</button>` : ''}
        <button class="icon-btn" data-notice-dismiss="${esc(n.id)}" type="button" aria-label="关闭提示">
          ${icon('close', 'icon icon--sm')}
        </button>
      </div>`,
    )
    .join('');

  el.noticeSlot.querySelectorAll('[data-notice-action]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const notice = state.notices.find((n) => n.id === btn.dataset.noticeAction);
      notice?.onAction?.();
    });
  });

  el.noticeSlot.querySelectorAll('[data-notice-dismiss]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = btn.dataset.noticeDismiss;
      noticeDismissed.add(id);
      state.notices = state.notices.filter((n) => n.id !== id);
      renderNotices();
    });
  });
}

/* ------------------------------------------------------------------------ */
/*  Card rendering                                                          */
/* ------------------------------------------------------------------------ */

function cardTemplate(account) {
  const title = describeAccount(account);
  return `
    <li class="account-card" data-id="${esc(account.id)}">
      <div class="account-card__head">
        <span class="avatar" aria-hidden="true">${esc(initials(account.issuer, account.label))}</span>
        <div class="account-card__meta">
          <p class="account-card__issuer" title="${esc(account.issuer)}">${esc(account.issuer)}</p>
          <p class="account-card__label" title="${esc(account.label || account.issuer)}">
            ${esc(account.label || '未填写账户标识')}
          </p>
        </div>
        <button class="icon-btn account-card__menu" type="button" data-action="menu"
                aria-label="${esc(title)} 的更多操作" aria-haspopup="menu" aria-expanded="false">
          ${icon('more', 'icon icon--sm')}
        </button>
      </div>

      <div class="account-card__code-row">
        <button class="code-btn" type="button" data-action="copy"
                aria-label="复制 ${esc(title)} 的验证码" title="点击复制验证码">
          <span class="code-btn__value" data-role="code">···&nbsp;···</span>
          <span class="code-btn__icon" data-role="copy-icon">${icon('copy', 'icon icon--sm')}</span>
        </button>

        <div class="totp-ring" role="timer" aria-live="off">
          <svg class="totp-ring__svg" viewBox="0 0 36 36" aria-hidden="true">
            <circle class="totp-ring__track" cx="18" cy="18" r="15"></circle>
            <circle class="totp-ring__value" cx="18" cy="18" r="15" data-role="ring"
                    style="--period:${account.period}s"></circle>
          </svg>
          <span class="totp-ring__seconds" data-role="seconds">--</span>
        </div>
      </div>
    </li>`;
}

/** Full repaint of one card from cached code state. */
function paintCard(account) {
  const li = el.accountList.querySelector(`[data-id="${CSS.escape(account.id)}"]`);
  if (!li) return;

  const cached = state.codes.get(account.id);
  const codeEl = li.querySelector('[data-role="code"]');
  const ringEl = li.querySelector('[data-role="ring"]');
  const secEl = li.querySelector('[data-role="seconds"]');

  if (!cached || !cached.code) {
    codeEl.textContent = cached?.error ? '— — —' : '··· ···';
    secEl.textContent = '--';
    li.classList.remove('is-expiring', 'is-critical');
    return;
  }

  codeEl.textContent = groupCode(cached.code);
  const label = `复制 ${describeAccount(account)} 的验证码 ${cached.code.split('').join(' ')}`;
  li.querySelector('[data-action="copy"]').setAttribute('aria-label', label);

  // Re-derive the phase at paint time. A card can be re-rendered mid-step
  // (search, sort, tab switch), so the ring must resume part-way rather than
  // restart from full: a negative animation-delay seeks to the right offset.
  const { remaining } = stepAt(account.period);
  if (ringEl) {
    const elapsed = account.period - remaining;
    ringEl.style.setProperty('--period', `${account.period}s`);
    ringEl.style.animation = 'none';
    void ringEl.getBoundingClientRect(); // force style flush
    ringEl.style.animation = '';
    ringEl.style.animationDelay = `${-elapsed}s`;
  }

  paintCountdown(li, account, remaining);
}

function paintCountdown(li, account, remaining) {
  const secEl = li.querySelector('[data-role="seconds"]');
  if (!secEl) return;

  if (secEl.textContent !== String(remaining)) {
    secEl.textContent = String(remaining);
    li.querySelector('.totp-ring')?.setAttribute(
      'aria-label',
      `剩余 ${remaining} 秒刷新`,
    );
  }

  const critical = remaining <= CRITICAL_AT;
  const expiring = !critical && remaining <= EXPIRING_AT;
  li.classList.toggle('is-critical', critical);
  li.classList.toggle('is-expiring', expiring);
}

function renderList() {
  const visible = filterAndSort(state.accounts, { query: state.query, sort: state.sort });
  const total = state.accounts.length;

  el.accountList.innerHTML = visible.map(cardTemplate).join('');

  // Empty states: distinguish "no accounts" from "no matches".
  const showEmpty = visible.length === 0;
  el.emptyState.hidden = !showEmpty;
  if (showEmpty) {
    if (total === 0) {
      el.emptyTitle.textContent = '还没有添加任何账户';
      el.emptyDesc.textContent =
        '添加账户后，这里会显示每 30 秒刷新的动态验证码。所有密钥只保存在这台设备的浏览器里。';
      $('#emptyImport').hidden = false;
    } else {
      el.emptyTitle.textContent = '没有匹配的账户';
      el.emptyDesc.textContent = `没有找到包含「${state.query}」的服务或账户，换个关键词试试。`;
      $('#emptyImport').hidden = true;
    }
  }

  el.codesSummary.textContent =
    total === 0 ? '共 0 个账户' : `共 ${total} 个账户${state.query ? `，匹配 ${visible.length} 个` : ''}`;
  el.countLabel.textContent = total ? `${visible.length} / ${total}` : '';

  // Prime codes for the cards just rendered.
  visible.forEach((account) => refreshCode(account));
}

/* ------------------------------------------------------------------------ */
/*  Code ticking                                                            */
/* ------------------------------------------------------------------------ */

async function refreshCode(account, { force = false } = {}) {
  if (!account.secretBytes) {
    state.codes.set(account.id, { code: '', counter: -1, remaining: 0, error: '密钥无法解码' });
    paintCard(account);
    return;
  }
  if (state.inFlight.has(account.id)) return;

  const { counter, remaining } = stepAt(account.period);
  const cached = state.codes.get(account.id);

  // Cache hit: repaint from cache (the DOM may be freshly rebuilt) without
  // recomputing the HMAC.
  if (!force && cached?.counter === counter && cached.code) {
    cached.remaining = remaining;
    paintCard(account);
    return;
  }

  state.inFlight.add(account.id);
  try {
    const result = await generateTOTP(account);
    state.codes.set(account.id, result);
  } catch (err) {
    state.codes.set(account.id, { code: '', counter, remaining, error: err.message });
    if (!(err instanceof TotpError)) console.error('[ZY2fa] TOTP 生成失败', err);
  } finally {
    state.inFlight.delete(account.id);
    paintCard(account);
  }
}

let tickTimer = null;

function tick() {
  // Only do work when the list is on screen and the tab is visible.
  if (document.hidden || state.route !== 'codes') return;

  for (const account of state.accounts) {
    const cached = state.codes.get(account.id);
    const { counter, remaining } = stepAt(account.period);

    if (!cached || cached.counter !== counter) {
      refreshCode(account);
      continue;
    }

    if (cached.remaining !== remaining) {
      cached.remaining = remaining;
      const li = el.accountList.querySelector(`[data-id="${CSS.escape(account.id)}"]`);
      if (li) paintCountdown(li, account, remaining);
    }
  }
}

function startTicking() {
  if (tickTimer) return;
  tickTimer = setInterval(tick, TICK_MS);
}

/* ------------------------------------------------------------------------ */
/*  Persistence                                                             */
/* ------------------------------------------------------------------------ */

async function persist({ silent = false } = {}) {
  try {
    await vault.save(state.accounts);
    refreshStats();
    if (!silent) return true;
    return true;
  } catch (err) {
    const message = err instanceof VaultError ? err.message : '保存失败，请重试';
    toast(message, { variant: 'error' });
    if (err instanceof VaultError && err.code === 'LOCKED') {
      lockNow({ silent: true });
    }
    return false;
  }
}

function setAccounts(accounts) {
  state.accounts = accounts.map(withSecretBytes);
  state.codes.clear();
}

/**
 * Apply a mutation and persist it. If the write fails, the in-memory state is
 * rolled back so the UI never claims a change that is not actually stored.
 */
async function commit(mutate) {
  const snapshot = state.accounts;
  const codes = new Map(state.codes);
  mutate();

  const ok = await persist();
  if (!ok) {
    state.accounts = snapshot;
    state.codes = codes;
    renderList();
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------------ */
/*  Views & routing                                                         */
/* ------------------------------------------------------------------------ */

function setRoute(route) {
  const next = ['codes', 'backup', 'settings'].includes(route) ? route : 'codes';
  state.route = next;

  $$('.view').forEach((view) => {
    view.classList.toggle('is-active', view.id === `view-${next}`);
  });
  $$('.nav__item').forEach((item) => {
    if (item.dataset.route === next) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });

  el.btnAdd.hidden = next !== 'codes';
  closeMenu();

  if (next === 'backup') refreshStats();
  if (next === 'settings') refreshSettings();
  if (next === 'codes') {
    renderList();
    tick();
  }

  window.scrollTo(0, 0);
}

function initRouter() {
  const apply = () => {
    const hash = window.location.hash.replace(/^#\/?/, '');
    setRoute(hash || 'codes');
  };
  window.addEventListener('hashchange', apply);
  apply();
}

/* ------------------------------------------------------------------------ */
/*  Stats & settings view                                                   */
/* ------------------------------------------------------------------------ */

function refreshStats() {
  const encrypted = vault.isEncrypted;
  el.statAccounts.textContent = String(state.accounts.length);
  el.statEncrypted.textContent = encrypted ? (vault.isLocked ? '已锁定' : '已加密') : '否';
  el.statUsage.textContent = formatBytes(vault.usage());
  el.statUpdated.textContent = formatRelative(vault.updatedAt);

  el.encBadge.hidden = !encrypted;
  el.btnLockTop.hidden = !encrypted;
  el.btnLockNow.hidden = !encrypted;

  const count = state.accounts.length;
  el.dataCountHint.textContent = count ? `${count} 个账户已保存到本机` : '尚未添加任何账户';
  el.dataCountBadge.textContent = String(count);
}

function refreshSettings() {
  const encrypted = vault.isEncrypted;

  el.pinHint.textContent = encrypted
    ? '已开启。密钥以 AES-256-GCM 加密保存，页面重开后需要输入密码才能解锁。'
    : '未开启。密钥以明文保存在浏览器 localStorage 中，同一台电脑的其他使用者可能读取。';
  el.btnPinPrimary.textContent = encrypted ? '修改密码' : '开启加密';
  el.btnLockNow.hidden = !encrypted;

  el.autoLockToggle.checked = state.autoLock;
  el.autoLockToggle.disabled = !encrypted;
  el.autoLockToggle.closest('.switch').style.opacity = encrypted ? '1' : '0.5';

  const wipeBtn = el.btnWipe;
  wipeBtn.disabled = state.accounts.length === 0 && !encrypted;
  refreshStats();
}

/* ------------------------------------------------------------------------ */
/*  Add / edit dialog                                                       */
/* ------------------------------------------------------------------------ */

const draft = {
  algorithm: 'SHA1',
  digits: 6,
};

function resetAccountForm() {
  el.accountForm.reset();
  el.uriInput.value = '';
  el.issuerInput.value = '';
  el.labelInput.value = '';
  el.secretInput.value = '';
  el.secretInput.type = 'text';
  el.periodInput.value = '30';
  draft.algorithm = 'SHA1';
  draft.digits = 6;
  syncSegmented(el.algoSegmented, 'algo', 'SHA1');
  syncSegmented(el.digitsSegmented, 'digits', '6');
  $$('.field', el.accountForm).forEach((f) => setFieldError(f, ''));
  $('#advanced', el.accountForm).open = false;
  updatePreviewSoon();
}

function syncSegmented(container, dataKey, value) {
  $$('[role="radio"]', container).forEach((btn) => {
    btn.setAttribute('aria-checked', String(btn.dataset[dataKey] === String(value)));
  });
}

function openAccountDialog(accountId = null) {
  state.editingId = accountId;
  resetAccountForm();

  if (accountId) {
    const account = findAccount(accountId);
    if (!account) {
      toast('该账户已不存在', { variant: 'error' });
      return;
    }
    el.dlgAccountTitle.textContent = '编辑账户';
    el.btnSaveAccount.textContent = '保存修改';
    el.issuerInput.value = account.issuer;
    el.labelInput.value = account.label;
    el.secretInput.value = account.secret;
    el.periodInput.value = String(account.period);
    draft.algorithm = account.algorithm;
    draft.digits = account.digits;
    syncSegmented(el.algoSegmented, 'algo', account.algorithm);
    syncSegmented(el.digitsSegmented, 'digits', String(account.digits));
    updatePreviewSoon();
  } else {
    el.dlgAccountTitle.textContent = '添加账户';
    el.btnSaveAccount.textContent = '保存';
  }

  openDialog(el.dlgAccount);
  setTimeout(() => el.uriInput.focus({ preventScroll: true }), 60);
}

const updatePreviewSoon = debounce(updatePreview, 220);

async function updatePreview() {
  const secret = el.secretInput.value.trim();
  if (!secret) {
    el.previewText.textContent = '填写密钥后可实时预览';
    el.previewBox.className = 'banner';
    return;
  }

  const period = clamp(Number.parseInt(el.periodInput.value, 10) || 30, 5, 300);
  try {
    const secretBytes = base32Decode(secret);
    const { code } = await generateTOTP({
      secretBytes,
      algorithm: draft.algorithm,
      digits: draft.digits,
      period,
    });
    el.previewText.textContent = `预览 ${groupCode(code)}（${draft.algorithm} · ${draft.digits} 位 · ${period}s）`;
    el.previewBox.className = 'banner banner--info';
  } catch (err) {
    el.previewText.textContent = err.message || '密钥无效';
    el.previewBox.className = 'banner banner--warning';
  }
}

function toggleSegmented(container, dataKey, onSelect) {
  container.addEventListener('click', (event) => {
    const btn = event.target.closest('[role="radio"]');
    if (!btn || btn.getAttribute('aria-checked') === 'true') return;
    const value = btn.dataset[dataKey];
    syncSegmented(container, dataKey, value);
    onSelect(value);
  });
  container.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    const items = $$('[role="radio"]', container);
    const index = items.indexOf(document.activeElement);
    if (index < 0) return;
    event.preventDefault();
    const next = items[(index + (event.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length];
    next.focus();
    next.click();
  });
}

async function parseUriIntoForm() {
  const raw = el.uriInput.value.trim();
  if (!raw) {
    toast('请先粘贴 otpauth 链接', { variant: 'error' });
    el.uriInput.focus();
    return;
  }

  try {
    const parsed = parseOtpAuthUri(raw);
    el.issuerInput.value = parsed.issuer;
    el.labelInput.value = parsed.label;
    el.secretInput.value = parsed.secret;
    el.periodInput.value = String(parsed.period);
    draft.algorithm = parsed.algorithm;
    draft.digits = parsed.digits;
    syncSegmented(el.algoSegmented, 'algo', parsed.algorithm);
    syncSegmented(el.digitsSegmented, 'digits', String(parsed.digits));
    setFieldError($('[data-field="uri"]', el.accountForm), '');
    setFieldError($('[data-field="secret"]', el.accountForm), '');

    await updatePreview();
    toast(
      parsed.warnings.length ? parsed.warnings[0] : '已解析链接并填入字段',
      { variant: parsed.warnings.length ? 'error' : 'success' },
    );
  } catch (err) {
    setFieldError($('[data-field="uri"]', el.accountForm), err.message || '链接无法解析');
  }
}

async function saveAccount() {
  $$('.field', el.accountForm).forEach((f) => setFieldError(f, ''));

  const candidate = {
    id: state.editingId ?? uid(),
    issuer: el.issuerInput.value.trim(),
    label: el.labelInput.value.trim(),
    secret: el.secretInput.value,
    algorithm: draft.algorithm,
    digits: draft.digits,
    period: clamp(Number.parseInt(el.periodInput.value, 10) || 30, 5, 300),
  };

  let account;
  try {
    account = normalizeAccount(candidate);
  } catch (err) {
    const field = err.field === 'secret' ? 'secret' : err.field === 'issuer' ? 'issuer' : 'issuer';
    setFieldError($(`[data-field="${field}"]`, el.accountForm), err.message);
    (field === 'secret' ? el.secretInput : el.issuerInput).focus();
    return;
  }

  const existing = state.editingId ? findAccount(state.editingId) : null;
  const others = state.accounts.filter((a) => a.id !== account.id);

  // Exact duplicate: same secret + same issuer + same label.
  const duplicate = findDuplicate(others, account);
  if (duplicate) {
    const proceed = await confirmDialog({
      title: '已存在相同账户',
      message: `「${describeAccount(duplicate)}」使用了相同的密钥，继续添加会产生两个完全一样的验证码。`,
      confirmText: '仍然添加',
      cancelText: '取消',
    });
    if (!proceed) return;
  } else {
    // Softer case: same secret under a different label — usually the same
    // account imported twice, occasionally two logins sharing a seed.
    const clash = findSecretClash(others, account);
    if (clash) {
      const proceed = await confirmDialog({
        title: '密钥已被使用',
        message: `「${describeAccount(clash)}」已经使用同一个密钥。若这是同一个账户，建议直接编辑原记录而不是新增。`,
        confirmText: '仍然添加',
        cancelText: '返回修改',
      });
      if (!proceed) return;
    }
  }

  if (existing) {
    account.createdAt = existing.createdAt;
    account.updatedAt = Date.now();
  }

  const saved = await commit(() => {
    if (existing) {
      state.accounts = state.accounts.map((a) =>
        a.id === existing.id ? withSecretBytes(account) : a,
      );
    } else {
      state.accounts = [...state.accounts, withSecretBytes(account)];
    }
  });
  if (!saved) return;

  closeDialog(el.dlgAccount);
  state.codes.delete(account.id);
  setRoute('codes');
  renderList();
  refreshSettings();
  toast(existing ? '账户已更新' : `已添加「${account.issuer}」`, { variant: 'success' });
}

/* ------------------------------------------------------------------------ */
/*  Card actions                                                            */
/* ------------------------------------------------------------------------ */

async function copyAccountCode(accountId, cardEl) {
  const account = findAccount(accountId);
  const cached = state.codes.get(accountId);
  if (!account || !cached?.code) {
    toast('验证码还没生成，请稍候再试', { variant: 'error' });
    return;
  }

  try {
    await copyText(cached.code);
    cardEl?.classList.add('is-copied');
    const iconSlot = cardEl?.querySelector('[data-role="copy-icon"]');
    if (iconSlot) iconSlot.innerHTML = icon('check', 'icon icon--sm');
    setTimeout(() => {
      cardEl?.classList.remove('is-copied');
      if (iconSlot) iconSlot.innerHTML = icon('copy', 'icon icon--sm');
    }, 1400);
    toast(`已复制「${account.issuer}」的验证码`);
  } catch (err) {
    toast(err.message || '复制失败', { variant: 'error' });
  }
}

async function deleteAccount(accountId) {
  const account = findAccount(accountId);
  if (!account) return;

  const ok = await confirmDialog({
    title: '删除账户？',
    message: `「${describeAccount(account)}」将从本机移除。如果这是唯一的验证方式，删除后将无法登录该服务。`,
    confirmText: '删除',
    cancelText: '保留',
    danger: true,
  });
  if (!ok) return;

  const saved = await commit(() => {
    state.accounts = state.accounts.filter((a) => a.id !== accountId);
    state.codes.delete(accountId);
  });
  if (!saved) return;

  renderList();
  refreshSettings();
  toast(`已删除「${describeAccount(account)}」`);
}

function openAccountMenu(accountId, anchor) {
  const account = findAccount(accountId);
  if (!account) return;

  anchor.setAttribute('aria-expanded', 'true');
  openMenu(anchor, [
    {
      label: '复制验证码',
      icon: 'copy',
      onSelect: () => copyAccountCode(accountId, el.accountList.querySelector(`[data-id="${CSS.escape(accountId)}"]`)),
    },
    {
      label: '复制 otpauth 链接',
      icon: 'link',
      onSelect: async () => {
        try {
          await copyText(buildOtpAuthUri(account));
          toast('已复制 otpauth 链接，可导入其他验证器');
        } catch (err) {
          toast(err.message, { variant: 'error' });
        }
      },
    },
    { label: '编辑', icon: 'edit', onSelect: () => openAccountDialog(accountId) },
    {
      label: '删除',
      icon: 'trash',
      danger: true,
      onSelect: () => deleteAccount(accountId),
    },
  ]);

  // Reset aria-expanded whenever the menu closes for any reason.
  const reset = () => {
    anchor.setAttribute('aria-expanded', 'false');
    document.removeEventListener('pointerdown', reset, true);
  };
  setTimeout(() => document.addEventListener('pointerdown', reset, true), 0);
}

/* ------------------------------------------------------------------------ */
/*  Lock gate & PIN                                                         */
/* ------------------------------------------------------------------------ */

function showGate({ reason = '' } = {}) {
  el.gate.hidden = false;
  el.appBody.hidden = true;
  el.btnAdd.hidden = true;
  gateAttempts = 0;
  gateRateUntil = 0;
  el.gatePin.value = '';
  el.gateError.textContent = reason;
  setTimeout(() => el.gatePin.focus({ preventScroll: true }), 80);
}

function hideGate() {
  el.gate.hidden = true;
  el.appBody.hidden = false;
  el.btnAdd.hidden = state.route !== 'codes';
}

let gateAttempts = 0;
/** Timestamp before which unlock attempts are refused (failure back-off). */
let gateRateUntil = 0;

function lockNow({ silent = false, reason = '保险库已锁定' } = {}) {
  vault.lock();
  state.accounts = [];
  state.codes.clear();
  closeMenu();
  renderList();
  showGate({ reason: silent ? '' : reason });
  if (!silent) toast('已锁定保险库');
}

async function handleUnlock(event) {
  event.preventDefault();
  if (el.gateSubmit.disabled) return;

  const pin = el.gatePin.value;
  if (!pin) {
    el.gateError.textContent = '请输入密码';
    el.gatePin.focus();
    return;
  }

  // Simple client-side throttle: slow down after repeated failures.
  if (gateRateUntil > Date.now()) {
    el.gateError.textContent = '尝试过于频繁，请稍后再试';
    return;
  }

  el.gateSubmit.disabled = true;
  el.gateSubmit.textContent = '解密中…';
  el.gateError.textContent = '';

  try {
    const { accounts } = await vault.unlock(pin);
    setAccounts(accounts);
    hideGate();
    renderList();
    refreshStats();
    refreshSettings();
    toast('已解锁', { variant: 'success' });
    gateAttempts = 0;
  } catch (err) {
    gateAttempts += 1;
    el.gatePin.value = '';
    el.gatePin.focus();

    if (err instanceof VaultError && err.code === 'PIN_WRONG') {
      el.gateError.textContent = `密码不正确（已尝试 ${gateAttempts} 次）`;
      if (gateAttempts >= 3) {
        gateRateUntil = Date.now() + Math.min(30_000, 2 ** (gateAttempts - 3) * 1000);
        el.gateError.textContent = '密码连续错误，请等待几秒后重试';
      }
    } else {
      el.gateError.textContent = err.message || '解锁失败';
    }
  } finally {
    el.gateSubmit.disabled = false;
    el.gateSubmit.textContent = '解锁';
  }
}

function openPinDialog(mode) {
  state.pinMode = mode;

  const config = {
    enable: {
      title: '开启本地加密',
      subtitle: '设置一个密码。密钥会用该密码派生的密钥加密后保存，忘记密码将无法恢复。',
      showCurrent: false,
      showNew: true,
      confirmText: '开启加密',
      warning: true,
    },
    change: {
      title: '修改密码',
      subtitle: '先用当前密码验证身份，再设置新密码。修改后旧密码立即失效。',
      showCurrent: true,
      showNew: true,
      confirmText: '保存',
      warning: true,
    },
    disable: {
      title: '关闭本地加密',
      subtitle: '关闭后密钥将以明文写入 localStorage。请确认这台设备只有你使用。',
      showCurrent: true,
      showNew: false,
      confirmText: '关闭加密',
      warning: true,
    },
  }[mode];

  el.pinTitle.textContent = config.title;
  el.pinSubtitle.textContent = config.subtitle;
  el.btnConfirmPin.textContent = config.confirmText;
  el.currentPinField.hidden = !config.showCurrent;
  el.newPinField.hidden = !config.showNew;
  el.confirmPinField.hidden = !config.showNew;
  el.pinWarning.hidden = !config.warning;

  el.pinForm.reset();
  el.pinStrength.dataset.level = '0';
  $$('.field', el.pinForm).forEach((f) => setFieldError(f, ''));

  openDialog(el.dlgPin);
  setTimeout(() => {
    (config.showCurrent ? el.currentPin : el.newPin).focus({ preventScroll: true });
  }, 60);
}

async function submitPin(event) {
  event.preventDefault();
  if (el.btnConfirmPin.disabled) return;

  $$('.field', el.pinForm).forEach((f) => setFieldError(f, ''));
  const current = el.currentPin.value;
  const next = el.newPin.value;
  const confirm = el.confirmPin.value;

  try {
    if (state.pinMode !== 'enable') {
      try {
        validatePin(current);
      } catch (err) {
        setFieldError($('[data-field="currentPin"]', el.pinForm), err.message);
        el.currentPin.focus();
        return;
      }
    }

    if (state.pinMode !== 'disable') {
      try {
        validatePin(next, { confirm });
      } catch (err) {
        const target = err.field === 'confirm' ? 'confirmPin' : 'newPin';
        setFieldError($(`[data-field="${target}"]`, el.pinForm), err.message);
        (target === 'confirmPin' ? el.confirmPin : el.newPin).focus();
        return;
      }
    }

    el.btnConfirmPin.disabled = true;
    const original = el.btnConfirmPin.textContent;
    el.btnConfirmPin.textContent = '处理中…';

    try {
      if (state.pinMode === 'enable') {
        await vault.enablePin(next, state.accounts);
        toast('加密已开启，下次打开需要输入密码', { variant: 'success' });
      } else if (state.pinMode === 'change') {
        await vault.changePin(current, next, state.accounts);
        toast('密码已更新', { variant: 'success' });
      } else {
        await vault.disablePin(current, state.accounts);
        state.autoLock = false;
        storageSet(AUTOLOCK_KEY, 'false');
        toast('加密已关闭，密钥以明文保存');
      }
      closeDialog(el.dlgPin);
      refreshSettings();
      refreshStats();
    } finally {
      el.btnConfirmPin.disabled = false;
      el.btnConfirmPin.textContent = original;
    }
  } catch (err) {
    const fieldByCode = {
      PIN_WRONG: 'currentPin',
      pin: 'newPin',
      confirm: 'confirmPin',
    };
    const fieldName = fieldByCode[err.code] ?? fieldByCode[err.field];
    if (fieldName) {
      setFieldError($(`[data-field="${fieldName}"]`, el.pinForm), err.message);
      (fieldName === 'currentPin' ? el.currentPin : fieldName === 'newPin' ? el.newPin : el.confirmPin).focus();
    } else {
      toast(err.message || '操作失败', { variant: 'error' });
    }
  }
}

/* ------------------------------------------------------------------------ */
/*  Import / export                                                         */
/* ------------------------------------------------------------------------ */

async function exportBackup(kind) {
  if (!state.accounts.length) {
    toast('还没有可导出的账户', { variant: 'error' });
    return;
  }

  try {
    if (kind === 'file') {
      const payload = buildBackup(state.accounts);
      const stamp = new Date().toISOString().slice(0, 10);
      downloadFile(`zy2fa-backup-${stamp}.json`, JSON.stringify(payload, null, 2));
      toast(`已导出 ${state.accounts.length} 个账户`);
    } else if (kind === 'clipboard') {
      await copyText(JSON.stringify(buildBackup(state.accounts), null, 2));
      toast('备份 JSON 已复制到剪贴板');
    } else {
      await copyText(state.accounts.map(buildOtpAuthUri).join('\n'));
      toast('otpauth 列表已复制');
    }
  } catch (err) {
    toast(err.message || '导出失败', { variant: 'error' });
  }
}

async function runImport() {
  const raw = el.importText.value.trim();
  if (!raw) {
    toast('请先粘贴备份内容或选择文件', { variant: 'error' });
    el.importText.focus();
    return;
  }

  el.btnImport.disabled = true;
  try {
    const { accounts: incoming, skipped } = parseImportPayload(raw);
    const { accounts, added, duplicates, overflow } = mergeAccounts(state.accounts, incoming);

    if (!added) {
      const parts = [];
      if (duplicates) parts.push(`${duplicates} 个已存在`);
      if (skipped.length) parts.push(`${skipped.length} 个无法解析`);
      toast(`没有新增账户（${parts.join('，') || '内容为空'}）`, { variant: 'error' });
      return;
    }

    const saved = await commit(() => setAccounts(accounts));
    if (!saved) return;

    el.importText.value = '';
    el.importFile.value = '';
    renderList();
    refreshSettings();
    setRoute('codes');

    const extra = [];
    if (duplicates) extra.push(`跳过重复 ${duplicates} 个`);
    if (skipped.length) extra.push(`忽略无效 ${skipped.length} 个`);
    if (overflow) extra.push(`超出上限未导入 ${overflow} 个`);
    toast(
      `已导入 ${added} 个账户${extra.length ? `，${extra.join('，')}` : ''}`,
      { variant: skipped.length ? 'error' : 'success' },
    );
    if (skipped.length) console.warn('[ZY2fa] 导入时跳过的条目', skipped);
  } catch (err) {
    toast(err.message || '导入失败', { variant: 'error' });
  } finally {
    el.btnImport.disabled = false;
  }
}

async function readImportFile(file) {
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) {
    toast('文件超过 5 MB，请确认是否选择了正确的备份文件', { variant: 'error' });
    el.importFile.value = '';
    return;
  }
  try {
    el.importText.value = await file.text();
    toast(`已读取「${file.name}」`);
  } catch (err) {
    toast(`文件读取失败：${err.message}`, { variant: 'error' });
  } finally {
    el.importFile.value = '';
  }
}

/* ------------------------------------------------------------------------ */
/*  Wipe                                                                    */
/* ------------------------------------------------------------------------ */

async function wipeAll() {
  const first = await confirmDialog({
    title: '清除全部数据？',
    message: '所有账户密钥与本地设置都会被删除，且无法恢复。',
    detail: '如果还没有导出备份，请先取消并前往「备份」页面导出。',
    confirmText: '继续',
    cancelText: '取消',
    danger: true,
  });
  if (!first) return;

  const second = await confirmDialog({
    title: '最后确认',
    message: `即将删除 ${state.accounts.length} 个账户。此操作不可撤销。`,
    confirmText: '确认删除',
    cancelText: '取消',
    danger: true,
  });
  if (!second) return;

  try {
    await vault.wipe();
    state.accounts = [];
    state.codes.clear();
    state.autoLock = false;
    storageSet(AUTOLOCK_KEY, 'false');
    hideGate();
    renderList();
    refreshSettings();
    refreshStats();
    toast('本地数据已清除');
  } catch (err) {
    toast(err.message || '清除失败', { variant: 'error' });
  }
}

/* ------------------------------------------------------------------------ */
/*  Auto-lock                                                               */
/* ------------------------------------------------------------------------ */

function initAutoLock() {
  state.autoLock = storageGet(AUTOLOCK_KEY) === 'true';

  el.autoLockToggle.addEventListener('change', () => {
    if (!vault.isEncrypted) {
      el.autoLockToggle.checked = false;
      toast('请先开启本地加密', { variant: 'error' });
      return;
    }
    state.autoLock = el.autoLockToggle.checked;
    storageSet(AUTOLOCK_KEY, String(state.autoLock));
    toast(state.autoLock ? '离开 5 分钟后自动锁定' : '已关闭自动锁定');
  });

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      state.hiddenAt = Date.now();
      return;
    }

    const away = state.hiddenAt ? Date.now() - state.hiddenAt : 0;
    state.hiddenAt = null;

    if (vault.isEncrypted && state.autoLock && !vault.isLocked && away > AUTO_LOCK_MS) {
      lockNow({ silent: false, reason: '离开超过 5 分钟，已自动锁定' });
      return;
    }

    // Coming back from a background tab: the system clock may have moved on,
    // so immediately reconcile codes instead of waiting for the next tick.
    if (!el.appBody.hidden) {
      if (state.route === 'codes') renderList();
      tick();
    }
  });
}

/* ------------------------------------------------------------------------ */
/*  Events                                                                  */
/* ------------------------------------------------------------------------ */

function bindEvents() {
  /* --- navigation --- */
  initRouter();

  /* --- theme --- */
  initTheme();

  /* --- search --- */
  const onSearch = debounce(() => {
    state.query = el.searchInput.value;
    el.searchClear.hidden = !state.query;
    renderList();
  }, 150);
  el.searchInput.addEventListener('input', onSearch);
  el.searchClear.addEventListener('click', () => {
    el.searchInput.value = '';
    state.query = '';
    el.searchClear.hidden = true;
    renderList();
    el.searchInput.focus();
  });

  /* --- sort --- */
  el.btnSort.addEventListener('click', () => {
    el.btnSort.setAttribute('aria-expanded', 'true');
    openMenu(
      el.btnSort,
      SORT_OPTIONS.map((option) => ({
        label: option.label,
        icon: state.sort === option.value ? 'check' : undefined,
        onSelect: () => {
          state.sort = option.value;
          el.sortLabel.textContent = option.label;
          renderList();
        },
      })),
    );
    setTimeout(() => el.btnSort.setAttribute('aria-expanded', 'false'), 0);
  });

  /* --- account list (delegated) --- */
  el.accountList.addEventListener('click', (event) => {
    const card = event.target.closest('.account-card');
    if (!card) return;
    const id = card.dataset.id;
    const action = event.target.closest('[data-action]')?.dataset.action;

    if (action === 'copy') copyAccountCode(id, card);
    else if (action === 'menu') openAccountMenu(id, event.target.closest('[data-action="menu"]'));
  });

  /* --- add / edit --- */
  el.btnAdd.addEventListener('click', () => openAccountDialog());
  $('#emptyAdd').addEventListener('click', () => openAccountDialog());
  $('#emptyImport').addEventListener('click', () => {
    window.location.hash = '#/backup';
  });

  bindDialog(el.dlgAccount);
  bindDialog(el.dlgPin);
  el.btnParseUri.addEventListener('click', parseUriIntoForm);
  el.uriInput.addEventListener('paste', () => setTimeout(parseUriIntoForm, 60));

  [el.secretInput, el.periodInput].forEach((input) =>
    input.addEventListener('input', updatePreviewSoon),
  );

  el.btnToggleSecret.addEventListener('click', () => {
    const show = el.secretInput.type === 'password';
    el.secretInput.type = show ? 'text' : 'password';
    el.btnToggleSecret.innerHTML = icon(show ? 'eye' : 'eye-off', 'icon icon--sm');
  });

  toggleSegmented(el.algoSegmented, 'algo', (value) => {
    draft.algorithm = value;
    updatePreview();
  });
  toggleSegmented(el.digitsSegmented, 'digits', (value) => {
    draft.digits = Number.parseInt(value, 10);
    updatePreview();
  });

  el.accountForm.addEventListener('submit', (event) => {
    event.preventDefault();
    saveAccount();
  });

  /* --- gate --- */
  el.gateForm.addEventListener('submit', handleUnlock);
  el.gateReset.addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: '清除本地数据？',
      message: '密码无法找回。继续将删除本机所有账户，之后可以重新导入备份。',
      confirmText: '清除并重来',
      cancelText: '取消',
      danger: true,
    });
    if (!ok) return;
    try {
      await vault.wipe();
      state.accounts = [];
      state.codes.clear();
      hideGate();
      renderList();
      refreshSettings();
      refreshStats();
      toast('已清除，保险库为空');
    } catch (err) {
      toast(err.message, { variant: 'error' });
    }
  });

  /* --- settings --- */
  el.btnPinPrimary.addEventListener('click', () => {
    if (!globalThis.crypto?.subtle) {
      toast('当前环境不支持加密接口，请通过 https 或 localhost 访问', { variant: 'error' });
      return;
    }
    openPinDialog(vault.isEncrypted ? 'change' : 'enable');
  });

  el.btnLockNow.addEventListener('click', () => lockNow());
  el.btnLockTop.addEventListener('click', () => lockNow());
  el.pinForm.addEventListener('submit', submitPin);
  el.newPin.addEventListener('input', () => {
    el.pinStrength.dataset.level = String(pinStrength(el.newPin.value));
  });

  el.btnWipe.addEventListener('click', wipeAll);

  /* --- backup --- */
  el.btnExportFile.addEventListener('click', () => exportBackup('file'));
  el.btnExportClipboard.addEventListener('click', () => exportBackup('clipboard'));
  el.btnExportUris.addEventListener('click', () => exportBackup('uris'));
  el.btnImport.addEventListener('click', runImport);
  el.btnImportClear.addEventListener('click', () => {
    el.importText.value = '';
    el.importFile.value = '';
    el.importText.focus();
  });
  el.importFile.addEventListener('change', (event) => readImportFile(event.target.files?.[0]));

  el.importText.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') runImport();
  });

  /* --- global --- */
  window.addEventListener('scroll', () => {
    el.appBar.classList.toggle('is-stuck', window.scrollY > 4);
  }, { passive: true });

  document.addEventListener('keydown', (event) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;

    if ((event.key === '/' || ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k')) && !typing) {
      event.preventDefault();
      if (state.route !== 'codes') window.location.hash = '#/codes';
      el.searchInput.focus();
      el.searchInput.select();
    }

    if (event.key.toLowerCase() === 'n' && !typing && !event.metaKey && !event.ctrlKey && !el.appBody.hidden) {
      event.preventDefault();
      openAccountDialog();
    }
  });

  // Surface unexpected async failures instead of losing them in the console.
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    if (reason instanceof TotpError || reason instanceof VaultError || reason instanceof ValidationError) {
      event.preventDefault();
      toast(reason.message, { variant: 'error' });
    }
  });
}

/* ------------------------------------------------------------------------ */
/*  Boot                                                                    */
/* ------------------------------------------------------------------------ */

function fatal(message, detail = '') {
  el.gate.hidden = true;
  el.appBody.hidden = true;
  el.btnAdd.hidden = true;

  const panel = document.createElement('div');
  panel.className = 'gate';
  panel.innerHTML = `
    <div class="gate__card">
      <div class="gate__icon" style="background:var(--md-sys-color-error-container);color:var(--md-sys-color-on-error-container)">
        ${icon('warning', 'icon')}
      </div>
      <div>
        <h2 class="gate__title">应用无法启动</h2>
        <p class="gate__desc">${esc(message)}</p>
        ${detail ? `<p class="gate__desc" style="margin-top:8px;font-family:var(--md-sys-font-mono);font-size:12px">${esc(detail)}</p>` : ''}
      </div>
      <button class="btn btn--tonal btn--block" type="button" onclick="location.reload()">重新加载</button>
    </div>`;
  document.body.append(panel);
}

async function boot() {
  bindEvents();
  initAutoLock();
  startTicking();

  // Environment checks — these degrade the experience rather than blocking it.
  if (!globalThis.crypto?.subtle) {
    addNotice('crypto', {
      variant: 'error',
      message: '当前页面不是安全上下文，浏览器禁用了 Web Crypto，验证码无法生成。请通过 https 或 localhost 打开。',
    });
  }

  if (!isStorageAvailable()) {
    addNotice('storage', {
      variant: 'warning',
      message: '浏览器禁用了本地存储（可能处于无痕模式）。本次添加的账户在关闭页面后会丢失，建议改用普通窗口。',
    });
  }

  let result;
  try {
    result = await vault.init();
  } catch (err) {
    fatal('读取本地数据失败。', err.message);
    return;
  }

  if (result.recovered) {
    addNotice('recovered', {
      variant: 'warning',
      message: `检测到损坏的本地数据（${esc(result.reason || '格式异常')}）。原始内容已备份在浏览器存储中，可下载后手工修复。`,
      action: '下载原始数据',
      onAction: () => {
        downloadFile(`zy2fa-corrupt-${Date.now()}.txt`, result.recovered, 'text/plain');
      },
    });
  }

  if (result.issues?.length) {
    addNotice('issues', {
      variant: 'warning',
      message: `有 ${result.issues.length} 条账户记录无法读取（密钥格式异常），已跳过。`,
    });
  }

  renderNotices();
  refreshStats();
  refreshSettings();

  if (result.locked) {
    showGate({
      reason: '',
    });
    return;
  }

  setAccounts(result.accounts ?? []);
  hideGate();
  renderList();
  state.booted = true;

  if (!state.accounts.length && !noticeDismissed.size) {
    setTimeout(() => {
      if (state.accounts.length === 0) {
        toast('点击右下角「添加账户」开始使用', {
          action: '了解用法',
          onAction: () => openAccountDialog(),
          duration: 6000,
        });
      }
    }, 900);
  }
}

function start() {
  boot().catch((err) => {
    console.error('[ZY2fa] 启动失败', err);
    fatal('启动过程中出现未预期的错误。', err?.message ?? String(err));
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
