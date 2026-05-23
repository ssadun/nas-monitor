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
const prune  = require('./modules/prune.js');
const { exec, execFile, spawn } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const {
  PORT, SETTINGS_FILE,
  loadSettings, saveSettingsFile,
} = require('./modules/config.js');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

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
const STYLES_FILE = path.join(__dirname, 'styles.css');

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

async function collectDiskUsage(scanPath, maxDepth = 4) {
  const results = await disk.collectUsage(scanPath, maxDepth);
  return results;
}

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
      auth.sendLoginPage(res);
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
    'containers-ui.js', 'compose-ui.js', 'console-ui.js',
    'credentials-ui.js', 'volumes-ui.js', 'networks-ui.js',
  ]);
  if (url.pathname.startsWith('/ui/')) {
    const file = url.pathname.slice(4); // strip leading '/ui/'
    if (UI_FILES.has(file)) {
      const script = fs.readFileSync(path.join(__dirname, 'ui', file), 'utf8');
      header.sendJavaScript(res, script);
      return;
    }
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
    res.end(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🐋</text></svg>`);
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
    res.writeHead(302, { Location: '/login' });
    res.end();
    return;
  }

  if (await docker.handleApi(req, res, url, reqUser)) {
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

  if (url.pathname === '/api/data') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    });
    res.end(JSON.stringify(cache));
    return;
  }

  if (url.pathname === '/api/data/refresh') {
    try {
      await refreshCache();
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache',
      });
      res.end(JSON.stringify(cache));
    } catch (e) {
      res.writeHead(500, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      });
      logError('API refresh failed', { error: e.message || 'refresh failed', user: reqUser });
      res.end(JSON.stringify({ error: e.message || 'refresh failed' }));
    }
    return;
  }

  // SSE for live push
  if (url.pathname === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    const intervalMs = appSettings.refreshIntervalSeconds * 1000;
    res.write(`retry: ${intervalMs}\n\n`);

    const send = () => {
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ ...cache, refreshIntervalSeconds: appSettings.refreshIntervalSeconds })}\n\n`);
      }
    };

    send();
    const iv = setInterval(send, intervalMs);
    req.on('close', () => clearInterval(iv));
    return;
  }


  if (url.pathname === '/api/disk') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    });
    try {
      const scanPath = url.searchParams.get('path') || '/volume1';
      const maxDepth = Math.min(parseInt(url.searchParams.get('depth') || '4'), 8);
      const safe = scanPath.replace(/\.\./g, '').replace(/\/+/g, '/') || '/volume1';
      const data = await collectDiskUsage(safe, maxDepth);
      // Store scan in history (keep last 20)
      diskScanHistory.unshift({ ...data, id: Date.now() });
      if (diskScanHistory.length > disk.DISK_HISTORY_MAX) diskScanHistory.pop();
      disk.saveHistory(diskScanHistory);
      res.end(JSON.stringify(data));
    } catch (e) {
      res.end(JSON.stringify({ error: e.message, tree: null, topFiles: [] }));
    }
    return;
  }

  if (url.pathname === '/api/disk/history') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(JSON.stringify(diskScanHistory.map(s => ({
      id: s.id, path: s.path, scannedAt: s.scannedAt,
      totalBytes: s.tree ? s.tree.sizeBytes : 0,
      error: s.error,
    }))));
    return;
  }

  if (url.pathname.startsWith('/api/disk/history/') && req.method === 'GET') {
    const id = parseInt(url.pathname.split('/').pop());
    const scan = diskScanHistory.find(s => s.id === id);
    res.writeHead(scan ? 200 : 404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(scan || { error: 'Not found' }));
    return;
  }

  if (url.pathname.startsWith('/api/disk/history/') && req.method === 'DELETE') {
    const id = parseInt(url.pathname.split('/').pop());
    if (!id) {
      res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid scan id' }));
      return;
    }
    const before = diskScanHistory.length;
    diskScanHistory = diskScanHistory.filter(s => s.id !== id);
    if (diskScanHistory.length === before) {
      res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'Scan not found' }));
      return;
    }
    try {
      disk.saveHistory(diskScanHistory);
      logInfo('Disk scan history entry deleted', { user: reqUser, scanId: id, remaining: diskScanHistory.length });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: true, remaining: diskScanHistory.length }));
    } catch (e) {
      logError('Failed to persist disk history delete', { user: reqUser, scanId: id, error: e.message });
      res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return;
  }

  if (url.pathname.startsWith('/api/logs/')) {
    // SSE log tail: /api/logs/:id
    const id = url.pathname.split('/')[3];
    if (!id) { res.writeHead(400); res.end(); return; }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 2000\n\n');

    const { spawn } = require('child_process');
    const tail = spawn(DOCKER, ['logs', '--tail', '200', '--follow', '--timestamps', id]);

    const send = (data) => {
      if (!res.writableEnded) {
        const lines = data.toString().split('\n').filter(Boolean);
        for (const line of lines) {
          res.write(`data: ${JSON.stringify(line)}\n\n`);
        }
      }
    };

    tail.stdout.on('data', send);
    tail.stderr.on('data', send);
    tail.on('error', (e) => {
      if (!res.writableEnded) res.write(`data: ${JSON.stringify('[Error: ' + e.message + ']')}\n\n`);
    });

    req.on('close', () => { try { tail.kill(); } catch {} });
    return;
  }


  if (url.pathname === '/api/prune/scan') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const data = await prune.scanUnused();
      res.end(JSON.stringify(data));
    } catch (e) {
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (url.pathname === '/api/prune/run' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const selected = JSON.parse(body);
        const summary = await prune.runPrune(selected);
        auditLog('prune_run', { user: reqUser, details: Object.keys(selected).filter(k => selected[k]).join(','), status: 'success' }, req);
        res.end(JSON.stringify({ ok: true, summary }));
      } catch (e) {
        auditLog('prune_run', { user: reqUser, status: 'failed', error: e.message }, req);
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/prune/log') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const raw = fs.existsSync(prune.PRUNE_LOG_FILE) ? fs.readFileSync(prune.PRUNE_LOG_FILE, 'utf8') : '';
      res.end(JSON.stringify({ log: raw }));
    } catch (e) {
      logError('Failed to read prune log file', { error: e.message });
      res.end(JSON.stringify({ log: '' }));
    }
    return;
  }

  // GET /api/settings  — return runtime settings
  if (url.pathname === '/api/settings' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    });
    res.end(JSON.stringify({ ok: true, settings: appSettings }));
    return;
  }

  // POST /api/settings  — body: { logLevel, authenticationType, warnThresholdSeconds, pruneIntervalHours, composeInactivityTimeoutSeconds, dockerConfigFolder, dockerDataFolder }
  if (url.pathname === '/api/settings' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const input = JSON.parse(body || '{}');
        const previous = { ...appSettings };
        appSettings = saveSettingsFile({ ...appSettings, ...input });
        const changed = Object.keys(appSettings).filter(k => appSettings[k] !== previous[k]);
        auditLog('settings_change', {
          user: reqUser,
          status: 'success',
          details: changed.map(k => `${k}: ${JSON.stringify(previous[k])} → ${JSON.stringify(appSettings[k])}`).join(', '),
        }, req);
        logInfo('Application settings updated', {
          user: reqUser,
          logLevel: appSettings.logLevel,
          authenticationType: appSettings.authenticationType,
          warnThresholdSeconds: appSettings.warnThresholdSeconds,
          pruneIntervalHours: appSettings.pruneIntervalHours,
          composeInactivityTimeoutSeconds: appSettings.composeInactivityTimeoutSeconds,
          dockerConfigFolder: appSettings.dockerConfigFolder,
          dockerDataFolder: appSettings.dockerDataFolder,
        });
        if (previous.authenticationType !== appSettings.authenticationType) {
          logInfo('Authentication mode changed', {
            previous: previous.authenticationType,
            current: appSettings.authenticationType,
          });
        }
        if (previous.pruneIntervalHours !== appSettings.pruneIntervalHours) {
          prune.scheduleAutoPrune();
          logInfo('Auto-prune interval changed', {
            previousHours: previous.pruneIntervalHours,
            currentHours: appSettings.pruneIntervalHours,
          });
        }
        if (previous.composeInactivityTimeoutSeconds !== appSettings.composeInactivityTimeoutSeconds) {
          logInfo('Compose inactivity timeout changed', {
            previousSeconds: previous.composeInactivityTimeoutSeconds,
            currentSeconds: appSettings.composeInactivityTimeoutSeconds,
          });
        }
        if (previous.refreshIntervalSeconds !== appSettings.refreshIntervalSeconds) {
          resetRefreshTimer();
          logInfo('Refresh interval changed', {
            previousSeconds: previous.refreshIntervalSeconds,
            currentSeconds: appSettings.refreshIntervalSeconds,
          });
        }
        res.end(JSON.stringify({ ok: true, settings: appSettings }));
      } catch (e) {
        logError('Failed to update settings', { error: e.message, user: reqUser });
        auditLog('settings_change', { user: reqUser, status: 'failed', details: e.message }, req);
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // POST /api/change-credentials  — body: { currentPassword, newUsername, newPassword }
  if (url.pathname === '/api/change-credentials' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { currentPassword, newUsername, newPassword } = JSON.parse(body);
        const creds = auth.loadCredentials();
        // Verify current password first
        const currentUser = creds ? creds.username : '';
        if (creds && !auth.checkCredentials(currentUser, currentPassword || '')) {
          logWarn('Credential change failed due to invalid current password', { user: reqUser });
          auditLog('credentials_change', { user: reqUser, status: 'failed', details: 'invalid current password' }, req);
          res.end(JSON.stringify({ ok: false, error: 'Current password is incorrect.' }));
          return;
        }
        if (!newUsername || newUsername.trim().length < 1) {
          res.end(JSON.stringify({ ok: false, error: 'Username cannot be empty.' }));
          return;
        }
        if (!newPassword || newPassword.length < 8) {
          res.end(JSON.stringify({ ok: false, error: 'New password must be at least 8 characters.' }));
          return;
        }
        auth.saveCredentials(newUsername.trim(), newPassword);
        logInfo('Credentials updated', { user: reqUser, newUsername: newUsername.trim() });
        auditLog('credentials_change', { user: reqUser, details: newUsername.trim(), status: 'success' }, req);
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        logError('Failed to change credentials', { error: e.message, user: reqUser });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // ── Category routes ──────────────────────────────────────────────────────────
  if (categories.registerRoutes(req, res, url)) return;

  // ── Network Management Endpoints ────────────────────────────────────────────
  // GET /api/network/list  — list all Docker networks (excluding system ones)
  if (url.pathname === '/api/network/list' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    (async () => {
      try {
        const systemNetworks = new Set(['bridge', 'host', 'none']);
        const shellQuote = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
        const output = await runDocker(`network ls --format '{{json .}}'`);
        const listed = output
          .split('\n')
          .filter(line => line.trim())
          .map(line => {
            try { return JSON.parse(line); } catch { return null; }
          })
          .filter(n => n && !systemNetworks.has(n.Name));

        if (!listed.length) {
          res.end(JSON.stringify([]));
          return;
        }

        const namesArg = listed.map(n => shellQuote(n.Name)).join(' ');
        let inspectByName = {};
        try {
          const { stdout } = await execAsync(`"${DOCKER}" network inspect ${namesArg}`, { timeout: 10000 });
          const inspected = JSON.parse(stdout || '[]');
          inspectByName = Object.fromEntries((Array.isArray(inspected) ? inspected : []).map(n => [n.Name, n]));
        } catch {}

        const networks = listed.map(n => {
          const inspected = inspectByName[n.Name] || {};
          const ipamCfg = Array.isArray(inspected?.IPAM?.Config) ? inspected.IPAM.Config : [];
          const subnet = (ipamCfg.find(cfg => cfg && cfg.Subnet) || {}).Subnet || '';
          const containersObj = inspected.Containers || {};
          const containers = Object.values(containersObj).map(c => c?.Name).filter(Boolean);
          return {
            name: n.Name,
            id: n.ID,
            driver: n.Driver || inspected.Driver || '',
            scope: n.Scope || inspected.Scope || '',
            subnet,
            containers,
          };
        });
        res.end(JSON.stringify(networks));
      } catch (e) {
        res.end(JSON.stringify([]));
      }
    })();
    return;
  }

  // POST /api/network/create  — body: { name, driver, subnet }
  if (url.pathname === '/api/network/create' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const shellQuote = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
        const { name, driver, subnet } = JSON.parse(body);
        if (!name) {
          res.end(JSON.stringify({ ok: false, error: 'Network name required' }));
          return;
        }
        if (['bridge', 'host', 'none'].includes(name)) {
          res.end(JSON.stringify({ ok: false, error: 'Cannot create network with system name' }));
          return;
        }
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid network name format' }));
          return;
        }
        
        let cmd = `"${DOCKER}" network create --driver ${shellQuote(driver || 'bridge')}`;
        if (subnet) {
          cmd += ` --subnet ${shellQuote(subnet)}`;
        }
        cmd += ` ${shellQuote(name)}`;
        
        try {
          const { stdout } = await execAsync(cmd, { timeout: 15000 });
          res.end(JSON.stringify({ 
            ok: true, 
            id: stdout.trim(),
            message: `Network "${name}" created successfully` 
          }));
        } catch (e) {
          res.end(JSON.stringify({ ok: false, error: e.message }));
        }
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: 'Invalid request: ' + e.message }));
      }
    });
    return;
  }

  // POST /api/network/update  — body: { name, driver, subnet }
  // Docker networks cannot be updated in-place, so this recreates and reconnects containers.
  if (url.pathname === '/api/network/update' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const shellQuote = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
        const { name, driver, subnet } = JSON.parse(body);
        if (!name) {
          res.end(JSON.stringify({ ok: false, error: 'Network name required' }));
          return;
        }
        if (['bridge', 'host', 'none'].includes(name)) {
          res.end(JSON.stringify({ ok: false, error: 'Cannot edit system network' }));
          return;
        }

        let inspect;
        try {
          const { stdout } = await execAsync(`"${DOCKER}" network inspect ${shellQuote(name)}`, { timeout: 10000 });
          const arr = JSON.parse(stdout || '[]');
          inspect = Array.isArray(arr) ? arr[0] : null;
        } catch {
          inspect = null;
        }
        if (!inspect) {
          res.end(JSON.stringify({ ok: false, error: `Network "${name}" not found` }));
          return;
        }

        const targetDriver = driver || inspect.Driver || 'bridge';
        const currentSubnet = (Array.isArray(inspect?.IPAM?.Config) ? inspect.IPAM.Config : []).find(cfg => cfg?.Subnet)?.Subnet || '';
        const targetSubnet = subnet || '';
        if ((inspect.Driver || '') === targetDriver && currentSubnet === targetSubnet) {
          res.end(JSON.stringify({ ok: true, message: 'No changes detected' }));
          return;
        }

        const containers = Object.values(inspect.Containers || {}).map(c => c?.Name).filter(Boolean);

        for (const c of containers) {
          try {
            await execAsync(`"${DOCKER}" network disconnect -f ${shellQuote(name)} ${shellQuote(c)}`, { timeout: 10000 });
          } catch {}
        }

        await execAsync(`"${DOCKER}" network rm ${shellQuote(name)}`, { timeout: 10000 });

        let createCmd = `"${DOCKER}" network create --driver ${shellQuote(targetDriver)}`;
        if (targetSubnet) {
          createCmd += ` --subnet ${shellQuote(targetSubnet)}`;
        }
        createCmd += ` ${shellQuote(name)}`;
        await execAsync(createCmd, { timeout: 15000 });

        const reconnectErrors = [];
        for (const c of containers) {
          try {
            await execAsync(`"${DOCKER}" network connect ${shellQuote(name)} ${shellQuote(c)}`, { timeout: 10000 });
          } catch (e) {
            reconnectErrors.push(`${c}: ${e.message}`);
          }
        }

        res.end(JSON.stringify({
          ok: true,
          message: reconnectErrors.length
            ? `Network "${name}" updated, but some containers failed to reconnect`
            : `Network "${name}" updated successfully`,
          reconnectErrors,
        }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // POST /api/network/delete  — body: { name }
  if (url.pathname === '/api/network/delete' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const shellQuote = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
        const { name } = JSON.parse(body);
        if (!name) {
          res.end(JSON.stringify({ ok: false, error: 'Network name required' }));
          return;
        }
        if (['bridge', 'host', 'none'].includes(name)) {
          res.end(JSON.stringify({ ok: false, error: 'Cannot delete system network' }));
          return;
        }
        
        try {
          await execAsync(`"${DOCKER}" network rm ${shellQuote(name)}`, { timeout: 10000 });
          res.end(JSON.stringify({ 
            ok: true, 
            message: `Network "${name}" deleted successfully` 
          }));
        } catch (e) {
          res.end(JSON.stringify({ ok: false, error: e.message }));
        }
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: 'Invalid request: ' + e.message }));
      }
    });
    return;
  }


  res.writeHead(404);
  res.end('Not found');
});


// ─── Health Check ─────────────────────────────────────────────────────────────

async function checkDiskSpace() {
  try {
    const { stdout } = await execAsync('df -k /', { timeout: 5000 });
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) return { usagePct: null, totalKB: null, usedKB: null, availKB: null };
    const parts = lines[1].trim().split(/\s+/);
    const totalKB = parseInt(parts[1]) || 0;
    const usedKB  = parseInt(parts[2]) || 0;
    const availKB = parseInt(parts[3]) || 0;
    const usagePct = totalKB > 0 ? parseFloat(((usedKB / totalKB) * 100).toFixed(1)) : null;
    return { usagePct, totalKB, usedKB, availKB };
  } catch {
    return { usagePct: null, totalKB: null, usedKB: null, availKB: null };
  }
}

async function healthCheck(req, res) {
  try {
    const pkgPath = path.join(__dirname, 'package.json');
    const pkg = fs.existsSync(pkgPath) ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : { version: 'dev' };
    const dockerAvail = fs.existsSync(DOCKER);
    const diskSpace = await checkDiskSpace();
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    const health = {
      status: 'healthy',
      uptime: process.uptime(),
      version: pkg.version,
      checks: {
        dockerAvailable: dockerAvail,
        credentialsExists: fs.existsSync(CREDENTIALS_FILE),
        diskSpace,
        memory: {
          rss: formatBytes(memUsage.rss),
          heapUsed: formatBytes(memUsage.heapUsed),
          heapTotal: formatBytes(memUsage.heapTotal),
        },
        cpu: {
          userMs: cpuUsage.user,
          systemMs: cpuUsage.system,
        },
      },
    };
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(JSON.stringify(health));
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'error', error: e.message }));
  }
}

prune.scheduleAutoPrune();

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
    dockerConfigFolder: appSettings.dockerConfigFolder,
    dockerDataFolder: appSettings.dockerDataFolder,
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