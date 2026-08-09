#!/usr/bin/env node
/**
 * NAS Performance Monitor
 * Synology DS723+ – runs without Docker, collects from /proc + docker CLI
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const auth = require('./modules/auth.js');
const header = require('./modules/header.js');
const docker = require('./modules/docker.js');
const categories = require('./modules/categories.js');
const disk = require('./modules/disk.js');
const network = require('./modules/network.js');
const monitor = require('./modules/monitor.js');
const sysInfo = require('./modules/process.js');
const logger = require('./modules/logger.js');
const prune        = require('./modules/prune.js');
const imageUpdates = require('./modules/image-updates.js');
const api          = require('./modules/api.js');
const { spawn } = require('child_process');
const crypto = require('crypto');
const {
  PORT, SETTINGS_FILE,
  loadSettings, saveSettingsFile,
} = require('./modules/config.js');

/** @type {AppSettings} */
let appSettings = loadSettings();

logger.setDependencies({ getSettings: () => appSettings });
const { logDebug, logInfo, logWarn, logError, getClientIp, auditLog, warnThresholdMs } = logger;

if (!fs.existsSync(SETTINGS_FILE)) {
  try { appSettings = saveSettingsFile(appSettings); }
  catch (e) { logError('Failed to initialize settings file', { error: e.message || 'unknown error' }); }
}

// Initialize auth module with dependencies
auth.setDependencies(appSettings, logError);
categories.setDependencies(logError);

// ─── Docker helpers ───────────────────────────────────────────────────────────

const DOCKER = docker.findDocker();
const FAVICON_FILE = path.join(__dirname, 'favicon.ico');
const PWA_DIR = path.join(__dirname, 'pwa');
const MANIFEST_FILE = path.join(PWA_DIR, 'manifest.webmanifest');
const SERVICE_WORKER_FILE = path.join(PWA_DIR, 'sw.js');
const PWA_ICON_FILE = path.join(PWA_DIR, 'pwa-icon.svg');
const PWA_ICON_WHALE_FILE = path.join(PWA_DIR, 'pwa-icon-whale.svg');
const PWA_ICON_192_FILE = path.join(PWA_DIR, 'pwa-icon-192.png');
const PWA_ICON_512_FILE = path.join(PWA_DIR, 'pwa-icon-512.png');
const STYLES_FILE = path.join(__dirname, 'styles.css');
const PREVIEW_DIR = path.join(__dirname, 'preview');

function formatBytes(bytes) {
  if (!bytes) return '0B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(1)}${units[i]}`;
}

docker.setDependencies({
  appSettings,
  logError,
  logInfo,
  auditLog,
  formatBytes,
  getCache: () => cache,
  refreshCache,
  ifaceToDockerNet: network.ifaceToDockerNet,
  prevContainerNetSnapshot: network.prevContainerNetSnapshot,
});

sysInfo.setDependencies({
  readFile: monitor.readFile,
  collectNetRates: network.collectNetRates,
});

// ─── Cache layer ──────────────────────────────────────────────────────────────

let diskScanHistory = disk.loadHistory();
logInfo('Disk history loaded from disk', { scans: diskScanHistory.length });

let cache = {
  processes: [],
  containers: [],
  summary: {},
  lastUpdate: 0,
};

let collecting = false;

async function refreshCache() {
  if (collecting) return;
  collecting = true;
  try {
    const [processes, containers, summary] = await Promise.all([
      monitor.collectProcesses(),
      docker.collectContainers(),
      sysInfo.collectSystemSummary(),
    ]);
    cache = { processes, containers, summary, lastUpdate: Date.now() };
  } catch (e) {
    logError('Cache refresh failed', { error: e.message });
  } finally {
    collecting = false;
  }
}

// Initial + periodic refresh
refreshCache();
let refreshTimer = setInterval(refreshCache, appSettings.refreshIntervalSeconds * 1000);

function resetRefreshTimer() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(refreshCache, appSettings.refreshIntervalSeconds * 1000);
}

prune.setDependencies({
  logError,
  logInfo,
  runDocker: docker.runDocker,
  DOCKER,
  getSettings: () => appSettings,
});

imageUpdates.setDependencies({
  logError,
  logInfo,
  runDocker: docker.runDocker,
  DOCKER,
  getSettings: () => appSettings,
});

api.setDependencies({
  logError,
  logInfo,
  logWarn,
  auditLog,
  getCache: () => cache,
  refreshCache,
  appSettings: () => appSettings,
  resetRefreshTimer,
  disk,
  prune,
  imageUpdates,
  auth,
  formatBytes,
  DOCKER,
  diskScanHistory: () => diskScanHistory,
  setDiskScanHistory: (h) => { diskScanHistory = h; },
  updateAppSettings: (s) => { appSettings = s; },
});

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const HTML_PATH = path.join(__dirname, 'index.html');

const server = http.createServer(async (req, res) => {
  const startedAt = Date.now();
  let requestPath = '(invalid-url)';
  const method = req.method || 'GET';
  let reqUser = 'unknown';

  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    const meta = {
      method,
      path: requestPath,
      status: res.statusCode,
      durationMs,
      user: reqUser,
    };
    if (requestPath.startsWith('/api/')) {
      logDebug('REST API call', meta);
    }
    if (durationMs >= warnThresholdMs()) {
      logWarn('Slow request detected', meta);
    }
  });

  let url;
  try {
    url = new URL(req.url, `http://localhost`);
  } catch {
    logError('Malformed request URL', { method, rawUrl: req.url || '', remoteIp: req.socket?.remoteAddress || '' });
    res.writeHead(400); res.end('Bad request'); return;
  }
  requestPath = url.pathname;
  reqUser = auth.requestUser(req);

  if (url.pathname === '/login') {
    if (!auth.isAuthEnabled()) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }
    if (req.method === 'GET') {
      const expired = url.searchParams.get('expired') === '1';
      auth.sendLoginPage(res, expired ? 'Your session has expired. Please sign in again.' : '');
      return;
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const params = Object.fromEntries(new URLSearchParams(body));
        const user = params.user || '';
        const pass = params.pass || '';
        if (auth.checkCredentials(user, pass)) {
          const token = auth.createSession(user);
          auth.setAuthCookie(res, token);
          logInfo('User login succeeded', { user, remoteIp: req.socket?.remoteAddress || '' });
          res.writeHead(302, { Location: '/' });
          res.end();
        } else {
          logWarn('User login failed', { user, remoteIp: req.socket?.remoteAddress || '' });
          auth.sendLoginPage(res, 'Invalid username or password.');
        }
      });
      return;
    }
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
    return;
  }

  if (url.pathname === '/logout') {
    logInfo('User logout', { user: reqUser, remoteIp: req.socket?.remoteAddress || '' });
    const token = auth.getSessionId(req);
    auth.deleteSession(token);
    auditLog('logout', { user: reqUser, status: 'success' }, req);
    auth.clearAuthCookie(res);
    res.writeHead(302, { Location: '/login' });
    res.end();
    return;
  }

  const UI_FILES = new Set([
    'utils.js', 'state.js', 'menu.js', 'menu-ui.js', 'setting.js',
    'render.js', 'processes-ui.js', 'disk-ui.js', 'network-ui.js', 'prune-ui.js',
    'docker-ui.js', 'compose-ui.js', 'console-ui.js',
    'credentials-ui.js', 'volumes-ui.js', 'networks-ui.js', 'image-updates-ui.js',
    'syntax-highlight.js',
  ]);
  if (url.pathname.startsWith('/ui/')) {
    const file = url.pathname.slice(4); // strip leading '/ui/'
    if (UI_FILES.has(file)) {
      const script = fs.readFileSync(path.join(__dirname, 'ui', file), 'utf8');
      header.sendJavaScript(res, script);
      return;
    }
  }

  // Locally-vendored third-party assets (xterm, etc.) so the UI works offline
  // and is immune to CDN path changes.
  const VENDOR_FILES = {
    'xterm.min.js':      'application/javascript; charset=utf-8',
    'xterm.min.css':     'text/css; charset=utf-8',
    'addon-fit.min.js':  'application/javascript; charset=utf-8',
  };
  if (url.pathname.startsWith('/vendor/')) {
    const file = url.pathname.slice(8); // strip leading '/vendor/'
    if (Object.prototype.hasOwnProperty.call(VENDOR_FILES, file)) {
      if (header.sendFile(res, path.join(__dirname, 'vendor', file), VENDOR_FILES[file])) return;
    }
    header.sendNotFound(res, 'vendor asset not found');
    return;
  }

  if (url.pathname === '/styles.css') {
    if (header.sendFile(res, STYLES_FILE, 'text/css; charset=utf-8')) return;
    header.sendNotFound(res, 'styles not found');
    return;
  }

  if (url.pathname === '/favicon.ico') {
    if (header.sendFile(res, FAVICON_FILE, 'image/x-icon', null)) return;
    res.writeHead(200, {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'no-cache',
    });
    res.end(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#4f8ef7" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10.189V14"/><path d="M12 2v3"/><path d="M19 13V7a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v6"/><path d="M19.38 20A11.6 11.6 0 0 0 21 14l-8.188-3.639a2 2 0 0 0-1.624 0L3 14a11.6 11.6 0 0 0 2.81 7.76"/><path d="M2 21c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1s1.2 1 2.5 1c2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/></svg>`);
    return;
  }

  if (url.pathname === '/pwa/manifest.webmanifest') {
    if (header.sendFile(res, MANIFEST_FILE, 'application/manifest+json; charset=utf-8')) return;
    header.sendNotFound(res, 'manifest not found');
    return;
  }

  if (url.pathname === '/pwa/sw.js') {
    if (header.sendFile(res, SERVICE_WORKER_FILE, 'application/javascript; charset=utf-8')) return;
    header.sendNotFound(res, 'service worker not found');
    return;
  }

  if (url.pathname === '/pwa/pwa-icon.svg') {
    if (header.sendFile(res, PWA_ICON_FILE, 'image/svg+xml; charset=utf-8')) return;
    header.sendNotFound(res, 'icon not found');
    return;
  }

  if (url.pathname === '/pwa/pwa-icon-whale.svg') {
    if (header.sendFile(res, PWA_ICON_WHALE_FILE, 'image/svg+xml; charset=utf-8')) return;
    header.sendNotFound(res, 'icon not found');
    return;
  }

  if (url.pathname === '/pwa/pwa-icon-192.png') {
    if (header.sendFile(res, PWA_ICON_192_FILE, 'image/png', null)) return;
    header.sendNotFound(res, 'icon not found');
    return;
  }

  if (url.pathname === '/pwa/pwa-icon-512.png') {
    if (header.sendFile(res, PWA_ICON_512_FILE, 'image/png', null)) return;
    header.sendNotFound(res, 'icon not found');
    return;
  }

  if (url.pathname === '/api/homepage/widget') {
    const apiKey = process.env.HOMEPAGE_API_KEY;
    if (apiKey) {
      const authHeader = req.headers['authorization'] || '';
      if (authHeader !== `Bearer ${apiKey}`) {
        res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }
    await api.handleHomepageWidget(req, res);
    return;
  }

  if (url.pathname === '/api/homepage/containers') {
    const apiKey = process.env.HOMEPAGE_API_KEY;
    if (apiKey) {
      const authHeader = req.headers['authorization'] || '';
      if (authHeader !== `Bearer ${apiKey}`) {
        res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }
    await api.handleHomepageContainers(req, res);
    return;
  }


  if (!auth.isAuthenticated(req)) {
    logInfo('Authentication required for request', {
      method,
      path: url.pathname,
      remoteIp: req.socket?.remoteAddress || '',
    });
    if (url.pathname.startsWith('/api/') || url.pathname === '/api/stream') {
      res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: 'Authentication required' }));
      return;
    }
    // A stale/expired session cookie (as opposed to a first-time anonymous
    // visit with no cookie at all) gets the "session expired" messaging.
    const hadSessionCookie = !!auth.getSessionId(req);
    res.writeHead(302, { Location: hadSessionCookie ? '/login?expired=1' : '/login' });
    res.end();
    return;
  }

  if (await docker.handleApi(req, res, url, reqUser)) {
    return;
  }

  if (url.pathname === '/preview' || url.pathname === '/preview/') {
    const files = fs.existsSync(PREVIEW_DIR) ? fs.readdirSync(PREVIEW_DIR).filter(f => f.endsWith('.html')).sort() : [];
    const items = files.map(f =>
      `<li><a href="/preview/${f}">${f}</a></li>`
    ).join('\n');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Preview Files</title>
<style>
  body{background:#0d0f14;color:#f2ffff;font-family:monospace;padding:32px;font-size:14px;}
  h1{font-size:16px;letter-spacing:1.5px;text-transform:uppercase;color:#6b7fa3;margin-bottom:20px;}
  ul{list-style:none;padding:0;display:flex;flex-direction:column;gap:8px;}
  a{color:#4f8ef7;text-decoration:none;padding:8px 14px;border:1px solid #2a2f4a;border-radius:8px;display:inline-block;}
  a:hover{border-color:#4f8ef7;background:rgba(79,142,247,.08);}
</style></head><body><h1>Preview Files</h1><ul>${items}</ul></body></html>`);
    return;
  }

  if (url.pathname.startsWith('/preview/')) {
    const name = path.basename(url.pathname);
    const file = path.join(PREVIEW_DIR, name);
    if (name.endsWith('.html') && fs.existsSync(file)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(fs.readFileSync(file, 'utf8'));
    } else {
      header.sendNotFound(res, 'preview file not found');
    }
    return;
  }

  if (url.pathname === '/') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
    });
    res.end(fs.readFileSync(HTML_PATH, 'utf8'));
    return;
  }

  // ── Category routes ──────────────────────────────────────────────────────────
  if (categories.registerRoutes(req, res, url)) return;

  if (await api.handleApi(req, res, url, reqUser, { saveSettingsFile, prune, CREDENTIALS_FILE: auth.CREDENTIALS_FILE })) return;


  res.writeHead(404);
  res.end('Not found');
});


prune.scheduleAutoPrune();
imageUpdates.scheduleImageUpdateCheck();

// ─── WebSocket console (docker exec PTY) ─────────────────────────────────────
// Minimal WebSocket server using Node's built-in http upgrade — no external deps.

function wsHandshake(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
}

function wsRead(buf) {
  // Parse a single WebSocket frame and return { data, fin }
  if (buf.length < 2) return null;
  const b0 = buf[0], b1 = buf[1];
  const masked = !!(b1 & 0x80);
  let payloadLen = b1 & 0x7f;
  let offset = 2;
  if (payloadLen === 126) { payloadLen = buf.readUInt16BE(2); offset = 4; }
  else if (payloadLen === 127) { payloadLen = Number(buf.readBigUInt64BE(2)); offset = 10; }
  if (buf.length < offset + (masked ? 4 : 0) + payloadLen) return null;
  let payload;
  if (masked) {
    const mask = buf.slice(offset, offset + 4); offset += 4;
    payload = Buffer.alloc(payloadLen);
    for (let i = 0; i < payloadLen; i++) payload[i] = buf[offset + i] ^ mask[i % 4];
  } else {
    payload = buf.slice(offset, offset + payloadLen);
  }
  return { opcode: b0 & 0x0f, data: payload, total: offset + payloadLen };
}

function wsSend(socket, data) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x81, len]);
  } else if (len < 65536) {
    header = Buffer.from([0x81, 126, len >> 8, len & 0xff]);
  } else {
    header = Buffer.allocUnsafe(10);
    header[0] = 0x81; header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  try { socket.write(Buffer.concat([header, payload])); } catch {}
}

server.on('upgrade', (req, socket, head) => {
  if (!auth.isAuthenticated(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const url = new URL(req.url, `http://localhost`);

  // ─── Pull progress terminal ───────────────────────────────────────────────
  if (url.pathname === '/ws/pull-progress') {
    wsHandshake(req, socket);
    const { spawn } = require('child_process');
    // xterm needs CRLF; docker pull / compose emit bare LF which would
    // stagger each line. Normalize to CRLF without doubling existing CRLFs.
    const send = (text) => {
      try { wsSend(socket, String(text).replace(/\r\n/g, '\n').replace(/\n/g, '\r\n')); } catch {}
    };
    let currentProc = null;
    let pullBuf = Buffer.alloc(0);

    const runPulls = async ({ images, containersMap, restart }) => {
      const total = (images || []).length;
      for (let i = 0; i < total; i++) {
        const image = images[i];
        send(`\r\n\x1b[1;36m┌─── [${i + 1}/${total}] Pulling: ${image}\x1b[0m\r\n\r\n`);

        const ok = await new Promise((resolve) => {
          currentProc = spawn(DOCKER, ['pull', image], { stdio: ['ignore', 'pipe', 'pipe'] });
          currentProc.stdout.on('data', d => send(d.toString()));
          currentProc.stderr.on('data', d => send(d.toString()));
          currentProc.on('close', code => {
            currentProc = null;
            if (code === 0) {
              send(`\r\n\x1b[32m✓ ${image} pulled successfully\x1b[0m\r\n`);
            } else {
              send(`\r\n\x1b[31m✗ Pull failed for ${image} (exit code ${code})\x1b[0m\r\n`);
            }
            resolve(code === 0);
          });
          currentProc.on('error', e => {
            currentProc = null;
            send(`\r\n\x1b[31m✗ Error: ${e.message}\x1b[0m\r\n`);
            resolve(false);
          });
        });

        if (ok && restart && containersMap && Array.isArray(containersMap[image])) {
          for (const ctr of containersMap[image].filter(Boolean)) {
            send(`\r\n\x1b[34m  ↻ Recreating container: ${ctr}…\x1b[0m\r\n`);
            const result = await docker.applyImageUpdate(ctr, (type, text) => send(text));
            if (result.ok) {
              send(`\r\n\x1b[32m  ✓ ${ctr} recreated with new image\x1b[0m\r\n`);
              imageUpdates.appendLog([`RECREATE OK  container=${ctr}`]);
            } else if (result.standalone) {
              send(`\r\n\x1b[33m  ⚠ ${ctr}: ${result.error}\x1b[0m\r\n`);
              imageUpdates.appendLog([`RECREATE SKIP  container=${ctr} (standalone)`]);
            } else {
              send(`\r\n\x1b[31m  ✗ Failed to recreate ${ctr}: ${result.error}\x1b[0m\r\n`);
              imageUpdates.appendLog([`RECREATE FAIL  container=${ctr} error=${result.error}`]);
            }
          }
        }
        imageUpdates.appendLog([ok ? `PULL OK  ${image}` : `PULL FAIL ${image}`]);
      }
      send(`\r\n\x1b[1;32m══════════════════════════════════════════\r\n  All operations complete.\r\n══════════════════════════════════════════\x1b[0m\r\n`);
      try { socket.end(); } catch {}
    };

    socket.on('data', chunk => {
      pullBuf = Buffer.concat([pullBuf, chunk]);
      while (pullBuf.length > 0) {
        const frame = wsRead(pullBuf);
        if (!frame) break;
        pullBuf = pullBuf.slice(frame.total);
        if (frame.opcode === 8) { try { if (currentProc) currentProc.kill(); socket.end(); } catch {} break; }
        if (frame.opcode === 1 || frame.opcode === 2) {
          try {
            const msg = JSON.parse(frame.data.toString());
            if (msg.type === 'start') runPulls(msg).catch(e => send(`\r\n\x1b[31m✗ Fatal: ${e.message}\x1b[0m\r\n`));
          } catch {}
        }
      }
    });
    socket.on('error', () => { try { if (currentProc) currentProc.kill(); } catch {} });
    socket.on('close', () => { try { if (currentProc) currentProc.kill(); } catch {} });
    return;
  }

  if (!url.pathname.startsWith('/ws/console/')) {
    socket.destroy(); return;
  }
  const parts  = url.pathname.split('/');
  const cid    = parts[4];
  const shell  = parts[5] === 'sh' ? 'sh' : 'bash';
  if (!cid) { socket.destroy(); return; }

  wsHandshake(req, socket);

  const { spawn } = require('child_process');

  // Spawn docker exec without -t (no PTY needed on server side)
  // Use `sh -i` or `bash -i` — the -i flag forces interactive mode even without a TTY
  const pty = spawn(DOCKER, ['exec', '-i', cid, shell, '-i'], {
    env: { ...process.env, TERM: 'xterm-256color' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  // Forward output → browser
  pty.stdout.on('data', d => wsSend(socket, d));
  pty.stderr.on('data', d => wsSend(socket, d));
  pty.on('exit', (code) => {
    wsSend(socket, `\r\n[Process exited with code ${code ?? ''}]\r\n`);
    try { socket.end(); } catch {}
  });
  pty.on('error', e => {
    wsSend(socket, `\r\n[Error: ${e.message}]\r\n`);
    try { socket.end(); } catch {}
  });

  // Trigger initial prompt after short delay
  setTimeout(() => { try { pty.stdin.write('\n'); } catch {} }, 200);

  // Forward browser → pty stdin
  let buf = Buffer.alloc(0);
  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length > 0) {
      const frame = wsRead(buf);
      if (!frame) break;
      buf = buf.slice(frame.total);
      if (frame.opcode === 8) { try { pty.kill(); socket.end(); } catch {} break; }
      if (frame.opcode === 1 || frame.opcode === 2) {
        try {
          const msg = JSON.parse(frame.data.toString());
          if (msg.type === 'resize') {
            try { pty.stdin.write(`stty cols ${msg.cols} rows ${msg.rows}\n`); } catch {}
            return;
          }
        } catch {}
        try { pty.stdin.write(frame.data); } catch {}
      }
    }
  });

  socket.on('error', () => { try { pty.kill(); } catch {} });
  socket.on('close', ()  => { try { pty.kill(); } catch {} });
  pty.on('error', e => {
    wsSend(socket, `\r\n[Error: ${e.message}]\r\n`);
    try { socket.end(); } catch {}
  });
});

// Load persisted sessions on startup
auth.loadSessionsFromFile();
auth.startSessionCleanup();

server.listen(PORT, '0.0.0.0', () => {
  logInfo('NAS Monitor backend started', {
    bind: `http://0.0.0.0:${PORT}`,
    dockerBinary: DOCKER,
    totalRamGb: Number((monitor.TOTAL_MEM_KB / 1024 / 1024).toFixed(1)),
  });
  logInfo('Runtime settings loaded', {
    logLevel: appSettings.logLevel,
    authenticationType: appSettings.authenticationType,
    warnThresholdSeconds: appSettings.warnThresholdSeconds,
    pruneIntervalHours: appSettings.pruneIntervalHours,
    composeInactivityTimeoutSeconds: appSettings.composeInactivityTimeoutSeconds,
    configFolders: appSettings.configFolders,
    dataFolders: appSettings.dataFolders,
  });
});

process.on('uncaughtException', err => {
  logError('Uncaught exception in backend process', {
    error: err?.message || String(err),
    stack: err?.stack || '',
  });
});

process.on('unhandledRejection', reason => {
  const message = reason && reason.message ? reason.message : String(reason);
  const stack = reason && reason.stack ? reason.stack : '';
  logError('Unhandled promise rejection in backend process', { error: message, stack });
});