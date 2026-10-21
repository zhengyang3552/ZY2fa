#!/usr/bin/env node
/**
 * ZY2fa · zero-dependency static server.
 *
 * ES modules and Web Crypto both require a real origin, so opening
 * index.html via file:// will not work. This serves the project over
 * http://localhost — a "potentially trustworthy" origin, which is what
 * the browser needs for crypto.subtle.
 *
 * Usage: node serve.mjs [port]
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.argv[2] ?? process.env.PORT ?? 5173);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname.endsWith('/')) pathname += 'index.html';

    // Resolve inside ROOT only — never serve above the project directory.
    const target = normalize(join(ROOT, pathname));
    if (!target.startsWith(ROOT.endsWith(sep) ? ROOT : ROOT + sep)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('403 Forbidden');
      return;
    }

    const info = await stat(target);
    if (info.isDirectory()) {
      res.writeHead(302, { location: `${pathname}/` });
      res.end();
      return;
    }

    const body = await readFile(target);
    res.writeHead(200, {
      'content-type': MIME[extname(target).toLowerCase()] ?? 'application/octet-stream',
      'cache-control': 'no-cache',
      'x-content-type-options': 'nosniff',
    });
    res.end(body);
  } catch (err) {
    const notFound = err?.code === 'ENOENT' || err?.code === 'ENOTDIR';
    res.writeHead(notFound ? 404 : 500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(notFound ? '404 Not Found' : `500 ${err.message}`);
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  ZY2fa  →  http://localhost:${PORT}\n  Ctrl+C to stop.\n`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`端口 ${PORT} 已被占用，换一个：node serve.mjs 5174`);
    process.exit(1);
  }
  throw err;
});
