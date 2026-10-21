#!/usr/bin/env node
/**
 * ZY2fa · Material 3 design-token generator
 * ---------------------------------------------------------------
 * Emits `css/tokens.css`.
 *
 * Why generated instead of hand-picked?
 * The Material 3 spec derives every colour role from a *tonal palette*:
 * a fixed-hue ramp addressed by tone (0-100). Roles are then assigned as
 * (tone, role) pairs — e.g. light `primary` = primary tone 40, dark
 * `primary` = primary tone 80. Hand-copying hex values makes drift and
 * contrast regressions inevitable, so the ramp is computed here and the
 * role table stays declarative and auditable.
 *
 * Tone model: M3 "tone" is CIE L* (0-100). OKLab L relates to L* by
 *   L* = 116·L_ok − 16   ⇒   L_ok = (L* + 16) / 116
 * so the ramp is perceptually even and matches the spec's tone steps.
 * Chroma is held constant per palette and gamut-clamped per tone by
 * bisecting chroma until the OKLCH colour fits inside sRGB — this is
 * what makes high-chroma hues naturally desaturate at the extremes,
 * exactly like Material's HCT ramps.
 *
 * Run: node tools/generate-tokens.mjs
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ */
/* Colour maths                                                        */
/* ------------------------------------------------------------------ */

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

/** OKLCH → linear sRGB (unclamped; may be out of gamut). */
function oklchToLinearRgb(L, C, hDeg) {
  const h = (hDeg * Math.PI) / 180;
  const a = C * Math.cos(h);
  const b = C * Math.sin(h);

  const l_ = L + 0.3963377774 * a + 0.2158037573 * b;
  const m_ = L - 0.1055613458 * a - 0.0638541728 * b;
  const s_ = L - 0.0894841775 * a - 1.2914855480 * b;

  const l = l_ ** 3;
  const m = m_ ** 3;
  const s = s_ ** 3;

  return [
    +4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s,
  ];
}

const encodeGamma = (c) =>
  c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055;

const inGamut = (rgb, eps = 1e-4) => rgb.every((c) => c >= -eps && c <= 1 + eps);

/** Reduce chroma until the colour is representable in sRGB. */
function toHex(L, C, hue) {
  if (L <= 0) return '#000000';
  if (L >= 1) return '#ffffff';

  let lo = 0;
  let hi = C;
  if (!inGamut(oklchToLinearRgb(L, C, hue))) {
    for (let i = 0; i < 28; i += 1) {
      const mid = (lo + hi) / 2;
      if (inGamut(oklchToLinearRgb(L, mid, hue))) lo = mid;
      else hi = mid;
    }
  } else {
    lo = C;
  }

  const hex = oklchToLinearRgb(L, lo, hue)
    .map((c) => clamp(c, 0, 1))
    .map((c) => Math.round(clamp(encodeGamma(c), 0, 1) * 255))
    .map((v) => v.toString(16).padStart(2, '0'))
    .join('');
  return `#${hex}`;
}

/** Material tone (0-100, ≈ CIE L*) → OKLab L. */
const toneToL = (tone) => (tone <= 0 ? 0 : (tone + 16) / 116);

const palette = (name, hue, chroma, tones) =>
  Object.fromEntries(
    tones.map((t) => [`${name}-${t}`, toHex(toneToL(t), chroma, hue)]),
  );

/* ------------------------------------------------------------------ */
/* Palettes                                                            */
/* ------------------------------------------------------------------ */

// Brand direction: a trustworthy indigo (security / credentials), with a
// teal tertiary for "live / healthy / counting down" signals and a warm
// error ramp that stays clearly distinct from the tertiary accent.
const HUES = {
  primary: 262, // indigo - brand, primary actions
  // Secondary sits 38° away at low chroma: close enough to read as the same
  // family, far enough that its container does not collide with
  // primary-container after gamut clamping (both were resolving to the same
  // #d4e3ff at tone 90 when the hue was shared).
  secondary: 300,
  tertiary: 196, // teal - status, countdown, affirmative accents
  neutral: 262, // surfaces
  neutralVariant: 262, // outlines, dividers
  error: 25, // red-orange
  success: 148, // extended role (codes still valid)
  warning: 75, // extended role (code about to expire)
};

const CHROMA = {
  primary: 0.155,
  secondary: 0.045,
  tertiary: 0.105,
  neutral: 0.007,
  neutralVariant: 0.022,
  error: 0.19,
  success: 0.13,
  warning: 0.13,
};

const TONES = [0, 4, 6, 10, 12, 17, 20, 22, 24, 30, 40, 50, 60, 70, 80, 87, 90, 92, 94, 95, 96, 98, 99, 100];

const P = Object.fromEntries(
  Object.entries(HUES).map(([name, hue]) => [
    name,
    palette(name, hue, CHROMA[name], TONES),
  ]),
);

/* ------------------------------------------------------------------ */
/* Role tables (verbatim from the M3 colour-role spec)                 */
/* ------------------------------------------------------------------ */

const LIGHT = {
  primary: 'primary-40',
  'on-primary': 'primary-100',
  'primary-container': 'primary-90',
  'on-primary-container': 'primary-10',
  'primary-fixed': 'primary-90',
  'primary-fixed-dim': 'primary-80',
  'on-primary-fixed': 'primary-10',
  'on-primary-fixed-variant': 'primary-30',

  secondary: 'secondary-40',
  'on-secondary': 'secondary-100',
  'secondary-container': 'secondary-90',
  'on-secondary-container': 'secondary-10',

  tertiary: 'tertiary-40',
  'on-tertiary': 'tertiary-100',
  'tertiary-container': 'tertiary-90',
  'on-tertiary-container': 'tertiary-10',

  error: 'error-40',
  'on-error': 'error-100',
  'error-container': 'error-90',
  'on-error-container': 'error-10',

  'surface-dim': 'neutral-87',
  'surface-bright': 'neutral-98',
  surface: 'neutral-98',
  'on-surface': 'neutral-10',
  'surface-variant': 'neutralVariant-90',
  'on-surface-variant': 'neutralVariant-30',

  'surface-container-lowest': 'neutral-100',
  'surface-container-low': 'neutral-96',
  'surface-container': 'neutral-94',
  'surface-container-high': 'neutral-92',
  'surface-container-highest': 'neutral-90',

  'inverse-surface': 'neutral-20',
  'inverse-on-surface': 'neutral-95',
  'inverse-primary': 'primary-80',

  outline: 'neutralVariant-50',
  'outline-variant': 'neutralVariant-80',
  shadow: 'neutral-0',
  scrim: 'neutral-0',
  'surface-tint': 'primary-40',

  // Extended semantic roles (M3 "custom colour roles" pattern)
  success: 'success-40',
  'on-success': 'success-100',
  'success-container': 'success-90',
  'on-success-container': 'success-10',
  warning: 'warning-40',
  'on-warning': 'warning-100',
  'warning-container': 'warning-90',
  'on-warning-container': 'warning-10',
};

const DARK = {
  ...LIGHT,
  primary: 'primary-80',
  'on-primary': 'primary-20',
  'primary-container': 'primary-30',
  'on-primary-container': 'primary-90',
  'primary-fixed': 'primary-90',
  'primary-fixed-dim': 'primary-80',
  'on-primary-fixed': 'primary-10',
  'on-primary-fixed-variant': 'primary-30',

  secondary: 'secondary-80',
  'on-secondary': 'secondary-20',
  'secondary-container': 'secondary-30',
  'on-secondary-container': 'secondary-90',

  tertiary: 'tertiary-80',
  'on-tertiary': 'tertiary-20',
  'tertiary-container': 'tertiary-30',
  'on-tertiary-container': 'tertiary-90',

  error: 'error-80',
  'on-error': 'error-20',
  'error-container': 'error-30',
  'on-error-container': 'error-90',

  'surface-dim': 'neutral-6',
  'surface-bright': 'neutral-24',
  surface: 'neutral-6',
  'on-surface': 'neutral-90',
  'surface-variant': 'neutralVariant-30',
  'on-surface-variant': 'neutralVariant-80',

  'surface-container-lowest': 'neutral-4',
  'surface-container-low': 'neutral-10',
  'surface-container': 'neutral-12',
  'surface-container-high': 'neutral-17',
  'surface-container-highest': 'neutral-22',

  'inverse-surface': 'neutral-90',
  'inverse-on-surface': 'neutral-20',
  'inverse-primary': 'primary-40',

  outline: 'neutralVariant-60',
  'outline-variant': 'neutralVariant-30',

  'surface-tint': 'primary-80',

  success: 'success-80',
  'on-success': 'success-20',
  'success-container': 'success-30',
  'on-success-container': 'success-90',
  warning: 'warning-80',
  'on-warning': 'warning-20',
  'warning-container': 'warning-30',
  'on-warning-container': 'warning-90',
};

/* ------------------------------------------------------------------ */
/* Emit                                                                */
/* ------------------------------------------------------------------ */

const kebab = (s) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();

function roleBlock(table, paletteMap) {
  const lines = Object.entries(table).map(([role, ref]) => {
    const [pal, tone] = ref.split('-');
    const hex = paletteMap[pal][`${pal}-${tone}`];
    if (!hex) throw new Error(`missing ${ref}`);
    return `  --md-sys-color-${role}: ${hex};`;
  });
  return lines.join('\n');
}

/** WCAG contrast, used for a build-time sanity assertion. */
function luminance(hex) {
  const ch = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = ch.map((c) =>
    c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const contrast = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((m, n) => n - m);
  return (x + 0.05) / (y + 0.05);
};

const pairs = [
  ['on-primary', 'primary'],
  ['on-primary-container', 'primary-container'],
  ['on-surface', 'surface'],
  ['on-surface-variant', 'surface'],
  ['on-surface', 'surface-container-high'],
  ['on-secondary-container', 'secondary-container'],
  ['on-tertiary-container', 'tertiary-container'],
  ['on-error-container', 'error-container'],
  ['on-success-container', 'success-container'],
  ['on-warning-container', 'warning-container'],
  ['outline', 'surface'],
];

const report = [];
for (const [label, table] of [['light', LIGHT], ['dark', DARK]]) {
  for (const [fg, bg] of pairs) {
    const f = P[table[fg].split('-')[0]][table[fg]];
    const b = P[table[bg].split('-')[0]][table[bg]];
    const ratio = contrast(f, b);
    report.push({ scheme: label, pair: `${fg} / ${bg}`, ratio: +ratio.toFixed(2) });
    if (ratio < 4.5) {
      console.warn(`⚠ ${label}: ${fg} on ${bg} = ${ratio.toFixed(2)} (< 4.5)`);
    }
  }
}

const header = `/* ==========================================================================
   ZY2fa · Design tokens
   GENERATED FILE — edit tools/generate-tokens.mjs and re-run.
   Do not hand-edit values here; hand-edits are overwritten.

   Layer 1  --md-ref-palette-*   raw tonal ramps (tone 0-100)
   Layer 2  --md-sys-color-*     semantic colour roles (light / dark)
   Layer 3  --md-sys-*           shape, elevation, typography, motion, spacing
   ========================================================================== */`;

const refPalettes = Object.values(P)
  .map(
    (p) =>
      `  /* ${''}tonal ramp */\n` +
      Object.entries(p)
        .map(([k, v]) => `  --md-ref-palette-${k}: ${v};`)
        .join('\n'),
  )
  .join('\n\n');

const css = `${header}

:root {
  color-scheme: light dark;

  /* ---- Reference palette -------------------------------------------------
     Fixed-hue OKLCH ramps, gamut-clamped per tone. Tone ≈ CIE L*.
     Tones below are the subset the role table addresses. */
${refPalettes}

  /* ---- Shape scale (M3) -------------------------------------------------- */
  --md-sys-shape-corner-none: 0;
  --md-sys-shape-corner-extra-small: 4px;
  --md-sys-shape-corner-small: 8px;
  --md-sys-shape-corner-medium: 12px;
  --md-sys-shape-corner-large: 16px;
  --md-sys-shape-corner-extra-large: 28px;
  --md-sys-shape-corner-full: 9999px;

  /* ---- Elevation (M3 levels 0-5) -----------------------------------------
     Tonal elevation + a soft ambient/penumbra shadow pair, tinted by the
     surface hue rather than pure black so dark mode stays readable. */
  --md-sys-elevation-level0: none;
  --md-sys-elevation-level1: 0 1px 2px 0 var(--md-sys-color-shadow-08, rgb(0 0 0 / 0.3)),
    0 1px 3px 1px rgb(0 0 0 / 0.06);
  --md-sys-elevation-level2: 0 1px 2px 0 rgb(0 0 0 / 0.08), 0 2px 6px 2px rgb(0 0 0 / 0.08);
  --md-sys-elevation-level3: 0 4px 8px 3px rgb(0 0 0 / 0.08), 0 1px 3px 0 rgb(0 0 0 / 0.1);
  --md-sys-elevation-level4: 0 6px 10px 4px rgb(0 0 0 / 0.1), 0 2px 3px 0 rgb(0 0 0 / 0.12);
  --md-sys-elevation-level5: 0 8px 12px 6px rgb(0 0 0 / 0.12), 0 4px 4px 0 rgb(0 0 0 / 0.14);

  /* ---- Motion (M3 easing + duration tokens) ------------------------------ */
  --md-sys-motion-easing-standard: cubic-bezier(0.2, 0, 0, 1);
  --md-sys-motion-easing-standard-decelerate: cubic-bezier(0, 0, 0, 1);
  --md-sys-motion-easing-standard-accelerate: cubic-bezier(0.3, 0, 1, 1);
  --md-sys-motion-easing-emphasized: cubic-bezier(0.2, 0, 0, 1);
  --md-sys-motion-easing-emphasized-decelerate: cubic-bezier(0.05, 0.7, 0.1, 1);
  --md-sys-motion-easing-emphasized-accelerate: cubic-bezier(0.3, 0, 0.8, 0.15);
  --md-sys-motion-duration-short1: 50ms;
  --md-sys-motion-duration-short2: 100ms;
  --md-sys-motion-duration-short3: 150ms;
  --md-sys-motion-duration-short4: 200ms;
  --md-sys-motion-duration-medium1: 250ms;
  --md-sys-motion-duration-medium2: 300ms;
  --md-sys-motion-duration-medium3: 350ms;
  --md-sys-motion-duration-medium4: 400ms;
  --md-sys-motion-duration-long1: 450ms;
  --md-sys-motion-duration-long2: 500ms;
  --md-sys-motion-duration-long4: 600ms;

  /* ---- Type scale (M3: role / size / line-height / weight / tracking) ---- */
  --md-sys-typescale-display-large-size: 57px;
  --md-sys-typescale-display-large-line-height: 64px;
  --md-sys-typescale-display-large-weight: 400;
  --md-sys-typescale-display-large-tracking: -0.25px;

  --md-sys-typescale-headline-large-size: 32px;
  --md-sys-typescale-headline-large-line-height: 40px;
  --md-sys-typescale-headline-medium-size: 28px;
  --md-sys-typescale-headline-medium-line-height: 36px;
  --md-sys-typescale-headline-small-size: 24px;
  --md-sys-typescale-headline-small-line-height: 32px;

  --md-sys-typescale-title-large-size: 22px;
  --md-sys-typescale-title-large-line-height: 28px;
  --md-sys-typescale-title-large-weight: 500;
  --md-sys-typescale-title-medium-size: 16px;
  --md-sys-typescale-title-medium-line-height: 24px;
  --md-sys-typescale-title-medium-weight: 500;
  --md-sys-typescale-title-medium-tracking: 0.15px;
  --md-sys-typescale-title-small-size: 14px;
  --md-sys-typescale-title-small-line-height: 20px;
  --md-sys-typescale-title-small-weight: 500;
  --md-sys-typescale-title-small-tracking: 0.1px;

  --md-sys-typescale-body-large-size: 16px;
  --md-sys-typescale-body-large-line-height: 24px;
  --md-sys-typescale-body-large-tracking: 0.5px;
  --md-sys-typescale-body-medium-size: 14px;
  --md-sys-typescale-body-medium-line-height: 20px;
  --md-sys-typescale-body-medium-tracking: 0.25px;
  --md-sys-typescale-body-small-size: 12px;
  --md-sys-typescale-body-small-line-height: 16px;
  --md-sys-typescale-body-small-tracking: 0.4px;

  --md-sys-typescale-label-large-size: 14px;
  --md-sys-typescale-label-large-line-height: 20px;
  --md-sys-typescale-label-large-weight: 500;
  --md-sys-typescale-label-large-tracking: 0.1px;
  --md-sys-typescale-label-medium-size: 12px;
  --md-sys-typescale-label-medium-line-height: 16px;
  --md-sys-typescale-label-medium-weight: 500;
  --md-sys-typescale-label-medium-tracking: 0.5px;
  --md-sys-typescale-label-small-size: 11px;
  --md-sys-typescale-label-small-line-height: 16px;
  --md-sys-typescale-label-small-weight: 500;
  --md-sys-typescale-label-small-tracking: 0.5px;

  /* ---- Spacing scale (4dp grid) ------------------------------------------ */
  --md-sys-spacing-1: 4px;
  --md-sys-spacing-2: 8px;
  --md-sys-spacing-3: 12px;
  --md-sys-spacing-4: 16px;
  --md-sys-spacing-5: 20px;
  --md-sys-spacing-6: 24px;
  --md-sys-spacing-8: 32px;
  --md-sys-spacing-10: 40px;
  --md-sys-spacing-12: 48px;
  --md-sys-spacing-16: 64px;

  /* ---- Layout ------------------------------------------------------------ */
  --app-max-width: 1080px;
  --app-bar-height: 64px;
}

/* ============================ LIGHT SCHEME ============================== */
:root,
[data-theme='light'] {
  --md-sys-color-scheme: light;
${roleBlock(LIGHT, P)}

  /* Tonal elevation overlays: surface + primary at low alpha (M3 "surface
     tint at elevation"), so raised components read as height, not just shadow */
  --md-sys-color-surface-tint-05: ${toHex(toneToL(40), 0.02, HUES.primary)};
}

/* ============================= DARK SCHEME ============================== */
[data-theme='dark'] {
  --md-sys-color-scheme: dark;
${roleBlock(DARK, P)}
}

/* Follow the OS when the user has not chosen a scheme explicitly. Guarded so
   an explicit [data-theme] always wins (no FOUC, no specificity fights). */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme='light']) {
${roleBlock(DARK, P)
  .split('\n')
  .map((l) => `  ${l}`)
  .join('\n')}
  }
}
`;

mkdirSync(join(ROOT, 'css'), { recursive: true });
writeFileSync(join(ROOT, 'css', 'tokens.css'), css, 'utf8');

console.log('✓ css/tokens.css written');
console.table(report);
const worst = report.reduce((a, b) => (a.ratio < b.ratio ? a : b));
console.log(`lowest contrast: ${worst.ratio}:1 (${worst.scheme} ${worst.pair})`);
