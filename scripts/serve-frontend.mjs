#!/usr/bin/env node
// Tiny static file server for the frontend. Supports CORS so the
// distributed frontend can talk to scanner nodes on different origins.
// Usage:
//   node scripts/serve-frontend.mjs [port]
//   PORT=4000 node scripts/serve-frontend.mjs
//
// Defaults: port 4000, serves ./frontend/ at the document root.

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', 'frontend');
const PORT = parseInt(process.env.PORT || process.argv[2] || '4000', 10);

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.map': 'application/json',
};

const server = createServer(async (req, res) => {
    const url = decodeURIComponent(req.url.split('?')[0]);
    let path = url === '/' ? '/index.html' : url;
    // Path traversal guard
    const fullPath = join(ROOT, path);
    if (!fullPath.startsWith(ROOT)) {
        res.writeHead(403); res.end('forbidden'); return;
    }
    try {
        const s = await stat(fullPath);
        if (s.isDirectory()) {
            const idx = join(fullPath, 'index.html');
            const data = await readFile(idx);
            res.writeHead(200, {
                'Content-Type': 'text/html; charset=utf-8',
                'Access-Control-Allow-Origin': '*',
                'Cache-Control': 'no-cache',
            });
            res.end(data);
            return;
        }
        const data = await readFile(fullPath);
        res.writeHead(200, {
            'Content-Type': MIME[extname(fullPath).toLowerCase()] || 'application/octet-stream',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-cache',
        });
        res.end(data);
    } catch (e) {
        if (e.code === 'ENOENT') {
            // SPA fallback
            try {
                const data = await readFile(join(ROOT, 'index.html'));
                res.writeHead(200, {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Access-Control-Allow-Origin': '*',
                });
                res.end(data);
            } catch (e2) {
                res.writeHead(404); res.end('not found');
            }
            return;
        }
        res.writeHead(500); res.end(e.message);
    }
});

// Respond to OPTIONS preflight
server.on('request', (req, res) => {
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Max-Age': '3600',
        });
        res.end();
    }
});

server.listen(PORT, () => {
    console.log(`[frontend] serving ${ROOT} at http://127.0.0.1:${PORT}/`);
});
