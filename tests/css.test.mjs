/**
 * ZY2fa · stylesheet invariants
 *
 * A few CSS declarations are load-bearing in ways that fail silently: the page
 * looks plausible until a dialog is taller than the viewport. These assertions
 * exist because two such bugs already shipped once — a global `* { margin: 0 }`
 * reset that also cancelled the UA's `dialog { margin: auto }` centring, and a
 * `flex: 1` scroll container missing `min-height: 0`, which clipped the dialog
 * body and pushed the footer out of reach.
 *
 * Run with: node --test tests/core.test.mjs tests/css.test.mjs
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

const components = read('css/components.css');
const base = read('css/base.css');
const layout = read('css/layout.css');

/** Remove an at-rule and its block, counting braces so nesting is safe. */
function stripAtRule(css, atRule) {
  let out = css;
  let index = out.indexOf(atRule);
  while (index >= 0) {
    const start = out.indexOf('{', index);
    if (start < 0) break;
    let depth = 0;
    let end = start;
    for (; end < out.length; end += 1) {
      if (out[end] === '{') depth += 1;
      else if (out[end] === '}') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    out = out.slice(0, index) + out.slice(end + 1);
    index = out.indexOf(atRule);
  }
  return out;
}

/** Extract the body of the first rule whose selector matches exactly. */
function rule(css, selector) {
  const index = css.indexOf(`\n${selector} {`);
  if (index < 0) return '';
  const start = css.indexOf('{', index);
  let depth = 0;
  for (let i = start; i < css.length; i += 1) {
    if (css[i] === '{') depth += 1;
    else if (css[i] === '}') {
      depth -= 1;
      if (depth === 0) return css.slice(start + 1, i);
    }
  }
  return '';
}

describe('stylesheet sanity', () => {
  test('all stylesheets have balanced braces', () => {
    for (const [name, css] of [
      ['base.css', base],
      ['components.css', components],
      ['layout.css', layout],
    ]) {
      const open = (css.match(/{/g) || []).length;
      const close = (css.match(/}/g) || []).length;
      assert.equal(open, close, `${name}: ${open} { vs ${close} }`);
    }
  });

  test('no declaration uses a raw colour outside tokens.css', () => {
    const offenders = [];
    for (const [name, css] of [
      ['base.css', base],
      ['components.css', components],
      ['layout.css', layout],
    ]) {
      // Print rules intentionally use pure #000/#fff for ink, so they are
      // excluded from the token rule (stripped brace-aware, not by regex).
      const stripped = stripAtRule(css, '@media print');
      for (const match of stripped.matchAll(/(?:color|background(?:-color)?|border-color)\s*:\s*(#[0-9a-f]{3,8})/gi)) {
        offenders.push(`${name}: ${match[0]}`);
      }
    }
    assert.deepEqual(offenders, [], `raw colours must come from tokens: ${offenders.join(', ')}`);
  });
});

describe('dialog layout invariants', () => {
  test('dialog restores margin:auto (the global reset kills UA centring)', () => {
    assert.match(base, /\*\s*\{[^}]*margin:\s*0/, 'precondition: global margin reset exists');
    const dialog = rule(components, '.dialog');
    assert.ok(dialog, '.dialog rule missing');
    assert.match(dialog, /margin:\s*auto/, '.dialog must re-declare margin:auto to stay centred');
  });

  test('dialog constrains its height with a vh fallback', () => {
    const dialog = rule(components, '.dialog');
    assert.match(dialog, /max-height:\s*\d+vh/, 'need a plain vh fallback before dvh');
    assert.match(dialog, /max-height:\s*min\([^)]*dvh/, 'need a dvh-based max-height');
  });

  test('dialog body can shrink and scroll', () => {
    const body = rule(components, '.dialog__body');
    assert.match(body, /overflow-y:\s*auto/);
    assert.match(body, /min-height:\s*0/, 'flex children need min-height:0 to scroll inside a max-height parent');
    assert.match(body, /flex:\s*1 1 auto|flex:\s*1/);
  });

  test('header and footer are not squeezed by the scrolling body', () => {
    for (const selector of ['.dialog__header', '.dialog__footer']) {
      assert.match(rule(components, selector), /flex:\s*0 0 auto/, `${selector} must not shrink`);
    }
  });

  test('compact windows switch the dialog to full screen', () => {
    assert.match(components, /@media \(max-height: 520px\)/);
    assert.match(components, /height:\s*100dvh/, 'full-screen dialog height');
  });
});

describe('page layout invariants', () => {
  test('content reserves room for the FAB and bottom navigation', () => {
    assert.match(
      layout,
      /padding:[^;]*calc\(152px \+ env\(safe-area-inset-bottom, 0px\)\)/,
      'content bottom padding must clear the FAB (96px offset + 56px height)',
    );
  });

  test('view header children may shrink instead of overflowing', () => {
    assert.match(layout, /\.view-head > \* \{\s*min-width:\s*0/);
  });

  test('reduced motion is honoured', () => {
    assert.match(base, /@media \(prefers-reduced-motion: reduce\)/);
    assert.match(base, /\.totp-ring__value \{\s*animation:\s*none !important/);
  });
});
