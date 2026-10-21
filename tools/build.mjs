#!/usr/bin/env node
/**
 * ZY2fa · production build
 *
 * Produces `dist/` — a self-contained folder that can be dropped on any static
 * host (or GitHub Pages) as-is:
 *
 *   dist/index.html
 *   dist/app.<hash>.css      tokens + base + components + layout, minified
 *   dist/app.<hash>.js       the ES module graph, bundled + minified
 *   dist/.nojekyll
 *
 * Why bundle at build time when the source runs unbundled?
 * The source stays framework-free and needs no dev server beyond a static one,
 * but the deployed artifact should be one CSS file and one JS file with
 * content-hashed names — fewer requests and immutable caching. esbuild is a
 * devDependency only; it never ships.
 *
 * If esbuild is not installed (offline checkout), the build degrades to copying
 * the sources verbatim rather than failing, so `npm run build` always works.
 */

import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIST = join(ROOT, 'dist');

/** Stylesheet order matters: tokens define the variables everything else uses. */
const CSS_ENTRIES = [
  'css/tokens.css',
  'css/base.css',
  'css/components.css',
  'css/layout.css',
];

const JS_ENTRY = 'js/app.js';

const BANNER = 'ZY2fa — TOTP authenticator · MIT';

const hash = (buf) => createHash('sha256').update(buf).digest('hex').slice(0, 10);
const rel = (p) => relative(ROOT, p).split('\\').join('/');
const kb = (n) => `${(n / 1024).toFixed(1)} kB`;

async function loadEsbuild() {
  try {
    return await import('esbuild');
  } catch {
    return null;
  }
}

/** Fail loudly rather than shipping a broken page. */
function assertNoRemoteRefs(html) {
  const remote = html.match(/(?:src|href)="https?:\/\//g);
  if (remote) {
    throw new Error(`index.html references remote assets (${remote.join(', ')}); the build must stay self-contained`);
  }
}

async function main() {
  const started = Date.now();
  const esbuild = await loadEsbuild();

  await rm(DIST, { recursive: true, force: true });
  await mkdir(DIST, { recursive: true });

  let html = await readFile(join(ROOT, 'index.html'), 'utf8');
  assertNoRemoteRefs(html);

  const rows = [];

  if (!esbuild) {
    // Fallback: ship the sources unchanged. Still a valid static bundle.
    for (const dir of ['css', 'js']) {
      await cp(join(ROOT, dir), join(DIST, dir), { recursive: true });
    }
    await writeFile(
      join(DIST, 'index.html'),
      html.replace(
        '</head>',
        '  <meta name="zy2fa-build" content="unbundled">\n</head>',
      ),
      'utf8',
    );
    console.warn('! esbuild 未安装，已退化为原样拷贝（run `npm install` for a minified build）');
    rows.push(['css/', 'copied', '-'], ['js/', 'copied', '-']);
  } else {
    /* ---------------------------------------------------------------- CSS */
    const cssSource = (
      await Promise.all(
        CSS_ENTRIES.map(async (f) => `/* ${f} */\n${await readFile(join(ROOT, f), 'utf8')}`),
      )
    ).join('\n');

    const cssResult = await esbuild.transform(cssSource, {
      loader: 'css',
      minify: true,
      legalComments: 'none',
      banner: `/*! ${BANNER} */`,
    });

    const cssName = `app.${hash(cssResult.code)}.css`;
    await writeFile(join(DIST, cssName), cssResult.code, 'utf8');
    rows.push([`css × ${CSS_ENTRIES.length}`, cssName, kb(Buffer.byteLength(cssResult.code))]);

    /* ----------------------------------------------------------------- JS */
    const jsTarget = join(DIST, 'app.js');
    const jsResult = await esbuild.build({
      entryPoints: [join(ROOT, JS_ENTRY)],
      outfile: jsTarget,
      bundle: true,
      format: 'esm',
      minify: true,
      sourcemap: false,
      legalComments: 'none',
      banner: { js: `/*! ${BANNER} */` },
      // Match the browsers the CSS already assumes (dialog, color-mix, dvh).
      target: ['chrome111', 'edge111', 'firefox113', 'safari16.4'],
      logLevel: 'warning',
    });

    if (jsResult.errors.length) {
      throw new Error(`esbuild failed: ${jsResult.errors.map((e) => e.text).join('; ')}`);
    }

    const jsCode = await readFile(jsTarget, 'utf8');
    const jsName = `app.${hash(jsCode)}.js`;
    await writeFile(join(DIST, jsName), jsCode, 'utf8');
    await rm(jsTarget, { force: true });
    rows.push([JS_ENTRY, jsName, kb(Buffer.byteLength(jsCode))]);

    /* --------------------------------------------------------------- HTML */
    // Drop the four <link>s, keep the inline theme bootstrap, swap the module src.
    html = html.replace(
      /\s*<link rel="stylesheet" href="css\/[^"]+">\s*/g,
      '\n',
    );
    html = html.replace(
      '</head>',
      `  <link rel="stylesheet" href="./${cssName}">\n</head>`,
    );
    html = html.replace(
      /<script type="module" src="js\/app\.js"><\/script>/,
      `<script type="module" src="./${jsName}"></script>`,
    );

    await writeFile(join(DIST, 'index.html'), html, 'utf8');
    rows.push(['index.html', 'rewritten', kb(Buffer.byteLength(html))]);
  }

  // GitHub Pages: skip Jekyll so dotfiles/hashed names are served verbatim.
  await writeFile(join(DIST, '.nojekyll'), '', 'utf8');

  const files = await readdir(DIST);
  const totalSize = (
    await Promise.all(files.map(async (f) => Buffer.byteLength(await readFile(join(DIST, f)))))
  ).reduce((a, b) => a + b, 0);

  const pad = rows.reduce((m, r) => Math.max(m, r[0].length), 0);
  console.log('\n  ZY2fa build\n');
  for (const [from, to, size] of rows) {
    console.log(`  ${from.padEnd(pad)}  →  ${to.padEnd(28)} ${size.padStart(9)}`);
  }
  console.log(`\n  dist/  ${files.length} files, ${kb(totalSize)}, ${Date.now() - started}ms`);
  console.log(`  ${existsSync(join(DIST, 'index.html')) ? '✓' : '✗'} index.html present\n`);
}

main().catch((err) => {
  console.error(`\n  build failed: ${err.message}\n`);
  process.exit(1);
});
