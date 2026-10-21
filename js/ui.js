/**
 * ZY2fa · UI primitives
 * Snackbar, confirmation dialog, dropdown menu, and accessible dialog helpers.
 * These wrap native elements so focus handling and Escape behaviour stay
 * browser-correct instead of being reimplemented.
 */

import { $, esc } from './utils.js';

/* ------------------------------------------------------------------------ */
/*  Icons (sprite ids from index.html)                                      */
/* ------------------------------------------------------------------------ */
export const icon = (name, cls = 'icon') =>
  `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;

/* ------------------------------------------------------------------------ */
/*  Snackbar                                                                */
/* ------------------------------------------------------------------------ */

let host = null;
const live = [];
const MAX_VISIBLE = 3;

function ensureHost() {
  if (host?.isConnected) return host;
  host = $('.snackbar-host');
  if (!host) {
    host = document.createElement('div');
    host.className = 'snackbar-host';
    host.setAttribute('role', 'status');
    host.setAttribute('aria-live', 'polite');
    document.body.append(host);
  }
  return host;
}

/**
 * Show a transient message.
 * @param {string} message
 * @param {{variant?: 'default'|'error'|'success', action?: string,
 *          onAction?: () => void, duration?: number}} [options]
 */
export function toast(message, options = {}) {
  const { variant = 'default', action, onAction, duration } = options;
  const parent = ensureHost();

  const el = document.createElement('div');
  el.className = `snackbar${variant === 'error' ? ' snackbar--error' : ''}`;
  el.setAttribute('role', variant === 'error' ? 'alert' : 'status');

  const glyph = variant === 'error' ? 'warning' : variant === 'success' ? 'check-circle' : 'info';
  el.innerHTML = `
    ${icon(glyph, 'icon snackbar__icon')}
    <span class="snackbar__text">${esc(message)}</span>
  `;

  let timer;
  const dismiss = () => {
    clearTimeout(timer);
    el.classList.remove('is-visible');
    const index = live.indexOf(el);
    if (index >= 0) live.splice(index, 1);
    setTimeout(() => el.remove(), 320);
  };

  if (action && onAction) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'snackbar__action';
    btn.textContent = action;
    btn.addEventListener('click', () => {
      dismiss();
      onAction();
    });
    el.append(btn);
  }

  parent.append(el);
  live.push(el);
  while (live.length > MAX_VISIBLE) live[0] && live.shift().remove();

  requestAnimationFrame(() => el.classList.add('is-visible'));

  const ms = duration ?? (variant === 'error' ? 5200 : 2800);
  timer = setTimeout(dismiss, ms);

  // Hovering holds the message so it can actually be read.
  el.addEventListener('pointerenter', () => clearTimeout(timer));
  el.addEventListener('pointerleave', () => {
    timer = setTimeout(dismiss, 1600);
  });

  return dismiss;
}

/* ------------------------------------------------------------------------ */
/*  Dialog helpers                                                          */
/* ------------------------------------------------------------------------ */

export function openDialog(dialog) {
  if (!dialog) return;
  if (dialog.open) return;
  if (typeof dialog.showModal === 'function') dialog.showModal();
  else dialog.setAttribute('open', '');
}

export function closeDialog(dialog, returnValue = '') {
  if (!dialog?.open) return;
  dialog.close(returnValue);
}

/** Wire a dialog's [data-close] buttons and click-outside-to-dismiss. */
export function bindDialog(dialog, { onClose } = {}) {
  dialog.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', () => closeDialog(dialog));
  });

  // Clicking the backdrop (i.e. the dialog element itself, outside its
  // content) closes it — matching platform dialog behaviour.
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) closeDialog(dialog);
  });

  dialog.addEventListener('close', () => {
    onClose?.(dialog.returnValue);
  });
}

/**
 * Modal confirmation. Resolves true when confirmed, false otherwise —
 * including on Escape or backdrop dismissal.
 */
export function confirmDialog({
  title,
  message,
  detail = '',
  confirmText = '确定',
  cancelText = '取消',
  danger = false,
} = {}) {
  return new Promise((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'dialog dialog--narrow';

    dialog.innerHTML = `
      <div class="dialog__header">
        <h2 class="dialog__title">${esc(title)}</h2>
        ${message ? `<p class="dialog__subtitle">${esc(message)}</p>` : ''}
      </div>
      ${detail ? `<div class="dialog__body"><div class="banner banner--warning">${icon('warning')}<span>${esc(detail)}</span></div></div>` : ''}
      <div class="dialog__footer">
        <button class="btn btn--text" data-close type="button">${esc(cancelText)}</button>
        <button class="btn ${danger ? 'btn--danger' : 'btn--filled'}" data-confirm type="button">${esc(confirmText)}</button>
      </div>
    `;

    document.body.append(dialog);

    const finish = (value) => {
      resolve(value);
      dialog.close();
      setTimeout(() => dialog.remove(), 260);
    };

    dialog.querySelector('[data-confirm]').addEventListener('click', () => finish(true));
    dialog.querySelectorAll('[data-close]').forEach((b) =>
      b.addEventListener('click', () => finish(false)),
    );
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      finish(false);
    });
    dialog.addEventListener('click', (event) => {
      if (event.target === dialog) finish(false);
    });

    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');

    // Focus the safe action by default so Enter never destroys data.
    requestAnimationFrame(() => dialog.querySelector('[data-close]')?.focus());
  });
}

/* ------------------------------------------------------------------------ */
/*  Dropdown menu                                                           */
/* ------------------------------------------------------------------------ */

let activeMenu = null;

export function closeMenu() {
  if (!activeMenu) return;
  const { el, cleanup } = activeMenu;
  activeMenu = null;
  cleanup();
  el.classList.remove('is-open');
  setTimeout(() => el.remove(), 200);
}

/**
 * Open a menu anchored to an element.
 * @param {HTMLElement} anchor
 * @param {{label: string, icon?: string, danger?: boolean, onSelect: () => void}[]} items
 */
export function openMenu(anchor, items) {
  closeMenu();

  const el = document.createElement('div');
  el.className = 'menu';
  el.setAttribute('role', 'menu');

  el.innerHTML = items
    .map(
      (item, i) =>
        `<button class="menu__item${item.danger ? ' menu__item--danger' : ''}" role="menuitem"
                 type="button" data-index="${i}">
           ${item.icon ? icon(item.icon, 'icon icon--sm') : ''}
           <span>${esc(item.label)}</span>
         </button>`,
    )
    .join('');

  document.body.append(el);

  // Position: below the anchor, right-aligned, flipped up if it would clip.
  // offsetWidth/Height are used because the entry scale transform would
  // otherwise shrink the measured box by 4%.
  const rect = anchor.getBoundingClientRect();
  const menuWidth = el.offsetWidth;
  const menuHeight = el.offsetHeight;
  const margin = 8;
  let top = rect.bottom + 4;
  if (top + menuHeight > window.innerHeight - margin) {
    top = Math.max(margin, rect.top - menuHeight - 4);
  }
  let left = rect.right - menuWidth;
  left = Math.min(Math.max(margin, left), window.innerWidth - menuWidth - margin);
  el.style.top = `${Math.round(top)}px`;
  el.style.left = `${Math.round(left)}px`;

  const onPointerDown = (event) => {
    if (!el.contains(event.target)) closeMenu();
  };
  const onKeyDown = (event) => {
    const buttons = [...el.querySelectorAll('.menu__item')];
    const index = buttons.indexOf(document.activeElement);
    if (event.key === 'Escape') {
      event.preventDefault();
      closeMenu();
      anchor.focus({ preventScroll: true });
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      buttons[(index + 1) % buttons.length]?.focus();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      buttons[(index - 1 + buttons.length) % buttons.length]?.focus();
    } else if (event.key === 'Tab') {
      closeMenu();
    }
  };

  el.addEventListener('click', (event) => {
    const btn = event.target.closest('.menu__item');
    if (!btn) return;
    const item = items[Number(btn.dataset.index)];
    closeMenu();
    item?.onSelect?.();
  });

  document.addEventListener('pointerdown', onPointerDown, true);
  document.addEventListener('keydown', onKeyDown);
  window.addEventListener('resize', closeMenu, { once: true });

  activeMenu = {
    el,
    cleanup: () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown);
    },
  };

  requestAnimationFrame(() => {
    el.classList.add('is-open');
    el.querySelector('.menu__item')?.focus({ preventScroll: true });
  });
}

/* ------------------------------------------------------------------------ */
/*  Field error helpers                                                     */
/* ------------------------------------------------------------------------ */

export function setFieldError(fieldEl, message = '') {
  if (!fieldEl) return;
  const support = fieldEl.querySelector('.field__support');
  fieldEl.classList.toggle('field--error', Boolean(message));

  if (support) {
    support.querySelector('[data-error]')?.remove();
    if (message) {
      const wrap = document.createElement('span');
      wrap.dataset.error = 'true';
      wrap.style.display = 'flex';
      wrap.style.alignItems = 'center';
      wrap.style.gap = '4px';
      wrap.innerHTML = `${icon('warning', 'icon icon--xs')}<span></span>`;
      wrap.lastElementChild.textContent = message;
      support.prepend(wrap);
    }
  }

  const input = fieldEl.querySelector('input, textarea');
  input?.setAttribute('aria-invalid', message ? 'true' : 'false');
}

export function clearFieldErrors(root) {
  root.querySelectorAll('.field--error').forEach((f) => setFieldError(f, ''));
}
