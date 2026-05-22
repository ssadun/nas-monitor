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
const { exec, execFile, spawn } = require('child_process');
const { promisify } = require('util');

const crypto = require('crypto');
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const PORT = process.env.PORT || 3232;

// ─── App settings + logging ─────────────────────────────────────────────────
const SETTINGS_FILE = path.join(__dirname, 'data', 'settings.json');
const LEGACY_SETTINGS_FILE = path.join(__dirname, 'setting.json');
/**
 * @typedef {Object} AppSettings
 * @property {'DEBUG'|'INFO'|'WARN'|'ERROR'} logLevel
 * @property {boolean} authenticationType
 * @property {number} sessionTimeoutHours
 * @property {number} warnThresholdSeconds
 * @property {number} pruneIntervalHours
 * @property {number} composeInactivityTimeoutSeconds
 * @property {string} dockerConfigFolder
 * @property {string} dockerDataFolder
 * @property {number} refreshIntervalSeconds
 */

const LOG_LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };
/** @type {AppSettings} */
const DEFAULT_SETTINGS = {
  logLevel: 'INFO',
  authenticationType: true,
  sessionTimeoutHours: 4,
  warnThresholdSeconds: 3,
  pruneIntervalHours: 24,
  composeInactivityTimeoutSeconds: 120,
  dockerConfigFolder: '/volume1/docker/_config',
  dockerDataFolder: '/volume1/docker/_data',
  refreshIntervalSeconds: 3,
};

function normalizeSettings(raw = {}) {
  const level = String(raw.logLevel || DEFAULT_SETTINGS.logLevel).toUpperCase();
  const safeLevel = Object.prototype.hasOwnProperty.call(LOG_LEVELS, level) ? level : DEFAULT_SETTINGS.logLevel;
  const auth = raw.authenticationType;
  const timeoutRaw = raw.sessionTimeoutHours ?? DEFAULT_SETTINGS.sessionTimeoutHours;
  const timeoutNum = Number(timeoutRaw);
  const thresholdRaw = raw.warnThresholdSeconds ?? raw.thresholdSeconds ?? DEFAULT_SETTINGS.warnThresholdSeconds;
  const thresholdNum = Number(thresholdRaw);
  const pruneHoursRaw = raw.pruneIntervalHours ?? DEFAULT_SETTINGS.pruneIntervalHours;
  const pruneHoursNum = Number(pruneHoursRaw);
  const composeInactivityRaw = raw.composeInactivityTimeoutSeconds ?? DEFAULT_SETTINGS.composeInactivityTimeoutSeconds;
  const composeInactivityNum = Number(composeInactivityRaw);
  const dockerConfigFolder = String(raw.dockerConfigFolder || DEFAULT_SETTINGS.dockerConfigFolder).trim() || DEFAULT_SETTINGS.dockerConfigFolder;
  const dockerDataFolder = String(raw.dockerDataFolder || DEFAULT_SETTINGS.dockerDataFolder).trim() || DEFAULT_SETTINGS.dockerDataFolder;
  const refreshIntervalRaw = raw.refreshIntervalSeconds ?? DEFAULT_SETTINGS.refreshIntervalSeconds;
  const refreshIntervalNum = Number(refreshIntervalRaw);
  /** @type {AppSettings} */
  const normalized = {
    logLevel: safeLevel,
    authenticationType: typeof auth === 'boolean' ? auth : DEFAULT_SETTINGS.authenticationType,
    sessionTimeoutHours: Number.isFinite(timeoutNum) && timeoutNum > 0 ? timeoutNum : DEFAULT_SETTINGS.sessionTimeoutHours,
    warnThresholdSeconds: Number.isFinite(thresholdNum) && thresholdNum >= 0 ? thresholdNum : DEFAULT_SETTINGS.warnThresholdSeconds,
    pruneIntervalHours: Number.isFinite(pruneHoursNum) && pruneHoursNum > 0 ? pruneHoursNum : DEFAULT_SETTINGS.pruneIntervalHours,
    composeInactivityTimeoutSeconds: Number.isFinite(composeInactivityNum) && composeInactivityNum > 0
      ? composeInactivityNum
      : DEFAULT_SETTINGS.composeInactivityTimeoutSeconds,
    dockerConfigFolder,
    dockerDataFolder,
    refreshIntervalSeconds: Number.isFinite(refreshIntervalNum) && refreshIntervalNum >= 1 && refreshIntervalNum <= 60
      ? refreshIntervalNum
      : DEFAULT_SETTINGS.refreshIntervalSeconds,
  };
  return normalized;
}

function loadSettings() {
  try {
    const data = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    return normalizeSettings(data);
  } catch (e) {
    try {
      const legacyData = JSON.parse(fs.readFileSync(LEGACY_SETTINGS_FILE, 'utf8'));
      const normalized = normalizeSettings(legacyData);
      try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(normalized, null, 2), 'utf8'); } catch {}
      return normalized;
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }
}

function saveSettingsFile(nextSettings) {
  const normalized = normalizeSettings(nextSettings);
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

/** @type {AppSettings} */
let appSettings = loadSettings();
if (!fs.existsSync(SETTINGS_FILE)) {
  try { appSettings = saveSettingsFile(appSettings); }
  catch (e) { logError('Failed to initialize settings file', { error: e.message || 'unknown error' }); }
}

// Initialize auth module with dependencies
auth.setDependencies(appSettings, logError);
categories.setDependencies(logError);

function shouldLog(level) {
  const current = LOG_LEVELS[String(appSettings.logLevel || 'INFO').toUpperCase()] ?? LOG_LEVELS.INFO;
  const incoming = LOG_LEVELS[level] ?? LOG_LEVELS.INFO;
  return incoming >= current;
}

function formatMeta(meta) {
  const entries = Object.entries(meta || {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return '';
  return ' ' + entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ');
}

function writeLog(level, message, meta = {}) {
  if (!shouldLog(level)) return;
  const ts = new Date().toISOString();
  const line = `[${ts}] [${level}] ${message}${formatMeta(meta)}`;
  if (level === 'ERROR') console.error(line);
  else console.log(line);
}

function logDebug(message, meta) { writeLog('DEBUG', message, meta); }
function logInfo(message, meta) { writeLog('INFO', message, meta); }
function logWarn(message, meta) { writeLog('WARN', message, meta); }
function logError(message, meta) { writeLog('ERROR', message, meta); }

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.socket.remoteAddress || 'unknown';
}

function auditLog(action, details, req) {
  const ts = new Date().toISOString();
  const ip = getClientIp(req);
  const user = details.user || 'unknown';
  const status = details.status || 'success';
  const auditLine = JSON.stringify({
    timestamp: ts,
    action,
    user,
    ip,
    status,
    details: details.details || ''
  });

  try {
    fs.appendFileSync(path.join(__dirname, 'logs', 'audit.log'), auditLine + '\n');
  } catch (e) {
    logError('Failed to write audit log', { error: e.message });
  }
}


function warnThresholdMs() {
  return Math.max(0, Number(appSettings.warnThresholdSeconds || 3) * 1000);
}

// ─── /proc helpers ───────────────────────────────────────────────────────────

function readFile(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

function getTotalMemKB() {
  const line = readFile('/proc/meminfo').split('\n').find(l => l.startsWith('MemTotal:'));
  return line ? parseInt(line.split(/\s+/)[1]) : 1;
}

function getBootTime() {
  const line = readFile('/proc/stat').split('\n').find(l => l.startsWith('btime'));
  return line ? parseInt(line.split(' ')[1]) : 0;
}

const BOOT_TIME = getBootTime();
const TOTAL_MEM_KB = getTotalMemKB();
const CLK_TCK = 100; // Hz – standard Linux

function parseProcStat(pid) {
  try {
    const raw = readFile(`/proc/${pid}/stat`);
    if (!raw) return null;
    // comm is between first ( and last ) to handle spaces
    const commStart = raw.indexOf('(');
    const commEnd = raw.lastIndexOf(')');
    const comm = raw.slice(commStart + 1, commEnd);
    const rest = raw.slice(commEnd + 2).split(' ');
    return {
      state: rest[0],
      ppid: parseInt(rest[1]),
      utime: parseInt(rest[11]),
      stime: parseInt(rest[12]),
      starttime: parseInt(rest[19]),
      comm,
    };
  } catch { return null; }
}

function parseProcStatus(pid) {
  const lines = readFile(`/proc/${pid}/status`).split('\n');
  const get = (key) => {
    const l = lines.find(x => x.startsWith(key + ':'));
    return l ? l.split(':')[1].trim() : '';
  };
  return {
    name: get('Name'),
    uid: get('Uid').split('\t')[0],
    vmRSS: parseInt(get('VmRSS')) || 0,
    threads: parseInt(get('Threads')) || 1,
  };
}

function getOwner(uid) {
  try {
    const passwd = fs.readFileSync('/etc/passwd', 'utf8');
    const line = passwd.split('\n').find(l => l.split(':')[2] === String(uid));
    return line ? line.split(':')[0] : String(uid);
  } catch { return String(uid); }
}

function getCmdline(pid) {
  try {
    return readFile(`/proc/${pid}/cmdline`).replace(/\0/g, ' ').trim();
  } catch { return ''; }
}

function parseProcIO(pid) {
  // /proc/<pid>/io requires root on most kernels; returns null if unreadable
  try {
    const raw = readFile(`/proc/${pid}/io`);
    if (!raw) return null;
    const get = (key) => {
      const line = raw.split('\n').find(l => l.startsWith(key + ':'));
      return line ? parseInt(line.split(':')[1].trim()) : 0;
    };
    return {
      readBytes:  get('read_bytes'),
      writeBytes: get('write_bytes'),
    };
  } catch { return null; }
}

// CPU snapshots for delta calculations
let prevCpuSnapshot = {};
let prevSystemCpu = 0;
let prevDiskSnapshot = {}; // pid -> { readBytes, writeBytes, ts }

function getSystemCpuTotal() {
  const line = readFile('/proc/stat').split('\n')[0];
  const parts = line.split(/\s+/).slice(1).map(Number);
  return parts.reduce((a, b) => a + b, 0);
}

function snapshotProcCpu(pid) {
  const stat = parseProcStat(pid);
  if (!stat) return 0;
  return stat.utime + stat.stime;
}

// ─── Collect all processes ────────────────────────────────────────────────────

function getAllPids() {
  return fs.readdirSync('/proc')
    .filter(d => /^\d+$/.test(d))
    .map(Number);
}

async function collectProcesses() {
  const pids = getAllPids();
  const systemCpu = getSystemCpuTotal();
  const systemDelta = Math.max(systemCpu - prevSystemCpu, 1);
  const uptime = parseFloat(readFile('/proc/uptime').split(' ')[0]);
  const nowTs = Date.now();

  const processes = [];

  for (const pid of pids) {
    const stat = parseProcStat(pid);
    if (!stat) continue;
    const status = parseProcStatus(pid);

    const procCpu = stat.utime + stat.stime;
    const isFirstSnapshot = prevCpuSnapshot[pid] === undefined;
    const prevCpu = isFirstSnapshot ? procCpu : prevCpuSnapshot[pid];
    const cpuDelta = isFirstSnapshot ? 0 : Math.max(0, procCpu - prevCpu);
    const cpuPercent = parseFloat(((cpuDelta / systemDelta) * 100).toFixed(2));

    prevCpuSnapshot[pid] = procCpu;

    const memPercent = parseFloat(((status.vmRSS / TOTAL_MEM_KB) * 100).toFixed(2));
    const startEpoch = BOOT_TIME + (stat.starttime / CLK_TCK);
    const startDate = new Date(startEpoch * 1000).toISOString();

    const cmdline = getCmdline(pid);
    // Mark our own process (nas-monitor server.js) and its children
    const isSelf = pid === process.pid || stat.ppid === process.pid ||
      (cmdline.includes(__dirname) && cmdline.includes('server.js'));

    // Disk I/O rate from /proc/<pid>/io
    let diskReadKBs = 0, diskWriteKBs = 0;
    const io = parseProcIO(pid);
    if (io) {
      const prev = prevDiskSnapshot[pid];
      if (prev && nowTs > prev.ts) {
        const dtSec = (nowTs - prev.ts) / 1000;
        diskReadKBs  = parseFloat(Math.max(0, (io.readBytes  - prev.readBytes)  / 1024 / dtSec).toFixed(2));
        diskWriteKBs = parseFloat(Math.max(0, (io.writeBytes - prev.writeBytes) / 1024 / dtSec).toFixed(2));
      }
      prevDiskSnapshot[pid] = { readBytes: io.readBytes, writeBytes: io.writeBytes, ts: nowTs };
    }

    processes.push({
      pid,
      ppid: stat.ppid,
      name: status.name || stat.comm,
      owner: getOwner(status.uid),
      cpu: Math.max(0, cpuPercent),
      mem: memPercent,
      memKB: status.vmRSS,
      status: stat.state,
      start: startDate,
      cmdline,
      threads: status.threads,
      isSelf,
      diskReadKBs,
      diskWriteKBs,
    });
  }

  prevSystemCpu = systemCpu;

  return processes;
}

// ─── Docker helpers ───────────────────────────────────────────────────────────

const DOCKER_PATHS = [
  '/usr/bin/docker',
  '/usr/local/bin/docker',
  '/bin/docker',
  '/usr/syno/bin/docker',
  '/var/packages/ContainerManager/target/usr/bin/docker',
  '/var/packages/Docker/target/usr/bin/docker',
];

function findDocker() {
  for (const p of DOCKER_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return 'docker'; // fallback to PATH
}

const DOCKER = findDocker();
const DOCKER_COMPOSE_PATHS = [
  '/usr/bin/docker-compose',
  '/usr/local/bin/docker-compose',
  '/bin/docker-compose',
];
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

// ─── Network rate tracking ────────────────────────────────────────────────────
let prevNetSnapshot = {};         // iface  → { rxBytes, txBytes, ts }
let prevContainerNetSnapshot = {}; // fullId → { rxBytes, txBytes, ts }
let ifaceToDockerNet = {};         // hostIface → docker network name (e.g. "docker-c5c36d39" → "nas")

docker.setDependencies({
  appSettings,
  logError,
  logInfo,
  auditLog,
  readFile,
  formatBytes,
  getCache: () => cache,
  refreshCache,
  ifaceToDockerNet,
  prevContainerNetSnapshot,
});

// Read network stats from inside a container's net namespace via /proc/<pid>/net/dev.
// Each process's /proc/<pid>/net/dev shows the network interfaces visible from that
// process's network namespace — i.e. the container's own eth0/lo/etc., not the host's.
function readContainerNetDev(pid) {
  const raw = readFile(`/proc/${pid}/net/dev`);
  if (!raw) return null;
  let rxBytes = 0, txBytes = 0;
  const lines = raw.split('\n').slice(2).filter(Boolean);
  for (const l of lines) {
    const parts = l.trim().split(/\s+/);
    const iface = parts[0].replace(':', '');
    if (iface === 'lo') continue;          // skip loopback
    rxBytes += parseInt(parts[1]) || 0;   // column 2  = RX bytes
    txBytes += parseInt(parts[9]) || 0;   // column 10 = TX bytes
  }
  return { rxBytes, txBytes };
}

// ─── System summary ───────────────────────────────────────────────────────────

async function collectSystemSummary() {
  const meminfo = readFile('/proc/meminfo');
  const getMemVal = (key) => {
    const l = meminfo.split('\n').find(x => x.startsWith(key));
    return l ? parseInt(l.split(/\s+/)[1]) : 0;
  };

  const memTotal = getMemVal('MemTotal:');
  const memAvail = getMemVal('MemAvailable:');
  const memUsed = memTotal - memAvail;

  // CPU overall
  const statLines = readFile('/proc/stat').split('\n');
  const cpuLine = statLines[0].split(/\s+/).slice(1).map(Number);
  const idle = cpuLine[3] + (cpuLine[4] || 0);
  const total = cpuLine.reduce((a, b) => a + b, 0);

  // Load average
  const loadavg = readFile('/proc/loadavg').split(' ');

  // Uptime
  const uptime = parseFloat(readFile('/proc/uptime').split(' ')[0]);

  // Disk info via df
  let diskInfo = [];
  let diskTotalBytes = 0;
  let diskUsedBytes = 0;
  try {
    const { stdout } = await execAsync('df -k --output=source,size,used,avail,pcent,target 2>/dev/null | tail -n +2');
    diskInfo = stdout.trim().split('\n').map(l => {
      const [source, size, used, avail, pcent, target] = l.trim().split(/\s+/);
      return { source, size: parseInt(size), used: parseInt(used), avail: parseInt(avail), pcent, target };
    }).filter(d => d.target && !d.target.startsWith('/sys') && !d.target.startsWith('/proc') && !d.target.startsWith('/dev/shm'));

    // On Synology, /volume1 and all its sub-mounts (/volume1/@docker, /volume1/@appstore, etc.)
    // share the same underlying device and report the same total size — summing them causes
    // massive overcounting. Only keep exact top-level /volumeN mount points.
    const volumeMounts = diskInfo.filter(d => /^\/volume\d+$/.test(d.target));

    if (volumeMounts.length > 0) {
      // Deduplicate by source device in case the same device appears twice
      const seen = new Set();
      for (const d of volumeMounts) {
        if (seen.has(d.source)) continue;
        seen.add(d.source);
        diskTotalBytes += (d.size || 0) * 1024;
        diskUsedBytes  += (d.used || 0) * 1024;
      }
    } else {
      // Non-Synology fallback: largest single real disk (no summing to avoid double-count)
      const real = diskInfo
        .filter(d => !d.target.startsWith('/dev') && d.size > 1024 * 1024)
        .sort((a, b) => b.size - a.size);
      const seen = new Set();
      for (const d of real) {
        if (seen.has(d.source)) continue;
        seen.add(d.source);
        diskTotalBytes += (d.size || 0) * 1024;
        diskUsedBytes  += (d.used || 0) * 1024;
      }
    }
  } catch {}

  // Network
  const netLines = readFile('/proc/net/dev').split('\n').slice(2).filter(Boolean);
  const nets = netLines.map(l => {
    const parts = l.trim().split(/\s+/);
    const iface = parts[0].replace(':', '');
    return {
      iface,
      rxBytes: parseInt(parts[1]),
      txBytes: parseInt(parts[9]),
      dockerNetName: ifaceToDockerNet[iface] || '', // e.g. "nas" for docker-c5c36d39
    };
  }).filter(n => n.iface !== 'lo');

  // Compute per-interface KB/s rates using previous snapshot
  const now = Date.now();
  let totalRxKBs = 0;
  let totalTxKBs = 0;
  const netsWithRate = nets.map(n => {
    const prev = prevNetSnapshot[n.iface];
    let rxKBs = 0, txKBs = 0;
    if (prev && now > prev.ts) {
      const dtSec = (now - prev.ts) / 1000;
      rxKBs = Math.max(0, (n.rxBytes - prev.rxBytes) / 1024 / dtSec);
      txKBs = Math.max(0, (n.txBytes - prev.txBytes) / 1024 / dtSec);
    }
    prevNetSnapshot[n.iface] = { rxBytes: n.rxBytes, txBytes: n.txBytes, ts: now };
    totalRxKBs += rxKBs;
    totalTxKBs += txKBs;
    return { ...n, rxKBs: parseFloat(rxKBs.toFixed(2)), txKBs: parseFloat(txKBs.toFixed(2)) };
  });

  return {
    memTotal: memTotal * 1024,
    memUsed: memUsed * 1024,
    memAvail: memAvail * 1024,
    cpuIdle: idle,
    cpuTotal: total,
    load1: parseFloat(loadavg[0]),
    load5: parseFloat(loadavg[1]),
    load15: parseFloat(loadavg[2]),
    uptimeSeconds: uptime,
    disks: diskInfo,
    diskTotal: diskTotalBytes,
    diskUsed: diskUsedBytes,
    nets: netsWithRate,
    netInKBs: parseFloat(totalRxKBs.toFixed(2)),
    netOutKBs: parseFloat(totalTxKBs.toFixed(2)),
  };
}

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
      collectProcesses(),
      docker.collectContainers(),
      collectSystemSummary(),
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

  if (url.pathname === '/modules/menu.js') {
    const menuScript = fs.readFileSync(path.join(__dirname, 'modules', 'menu.js'), 'utf8');
    header.sendJavaScript(res, menuScript);
    return;
  }

  if (url.pathname === '/modules/setting.js') {
    const settingScript = fs.readFileSync(path.join(__dirname, 'modules', 'setting.js'), 'utf8');
    header.sendJavaScript(res, settingScript);
    return;
  }

  if (url.pathname === '/modules/menu-ui.js') {
    const menuUiScript = fs.readFileSync(path.join(__dirname, 'modules', 'menu-ui.js'), 'utf8');
    header.sendJavaScript(res, menuUiScript);
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
      const data = await scanUnused();
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
        const summary = await runPrune(selected);
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
      const raw = fs.existsSync(PRUNE_LOG_FILE) ? fs.readFileSync(PRUNE_LOG_FILE, 'utf8') : '';
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
          scheduleAutoPrune();
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

const PRUNE_LOG_FILE = path.join(__dirname, 'logs', 'prune.log');
const PRUNE_LOG_RETAIN_DAYS = 30;

function appendPruneLog(lines) {
  try {
    const now = new Date().toISOString();
    const text = lines.map(l => `[${now}] ${l}`).join('\n') + '\n';
    fs.appendFileSync(PRUNE_LOG_FILE, text, 'utf8');
    // Trim entries older than 30 days
    const raw = fs.readFileSync(PRUNE_LOG_FILE, 'utf8');
    const cutoff = Date.now() - PRUNE_LOG_RETAIN_DAYS * 86400000;
    const kept = raw.split('\n').filter(line => {
      const m = line.match(/^\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\]/);
      if (!m) return false;
      return new Date(m[1]).getTime() > cutoff;
    });
    fs.writeFileSync(PRUNE_LOG_FILE, kept.join('\n') + (kept.length ? '\n' : ''), 'utf8');
  } catch (e) {
    logError('Failed to append prune log', { error: e.message });
  }
}

async function scanUnused() {
  const result = { images: [], networks: [], volumes: [], buildCache: [], buildCacheTotal: '', buildCacheReclaimable: '' };

  // ── Images: port of the shell script approach ────────────────────────────
  try {
    // Get all image details in one batch call first
    const allImgOut = await runDocker(`images --format '{{json .}}'`);
    const imageMap = {}; // shortId → detail object
    if (allImgOut) {
      allImgOut.split('\n').filter(Boolean).forEach(l => {
        try {
          const img = JSON.parse(l);
          // Store by both short ID (first 12) and full ID variants
          const shortId = (img.ID || '').replace('sha256:', '').slice(0, 12);
          imageMap[shortId] = img;
          imageMap[img.ID]  = img;
        } catch {}
      });
    }

    // Get unique short IDs (same as docker images -q | sort -u)
    const imgIdsOut = await runDocker(`images -q`);
    if (imgIdsOut) {
      const shortIds = [...new Set(imgIdsOut.split('\n').filter(Boolean))];

      for (const imgId of shortIds) {
        // Count containers using this image (running + stopped)
        const countOut = await runDocker(`ps -a -q --filter "ancestor=${imgId}"`);
        const count = countOut ? countOut.split('\n').filter(Boolean).length : 0;
        if (count === 0) {
          const img = imageMap[imgId] || imageMap[imgId.slice(0,12)] || {};
          const repository = img.Repository || '';
          const tag        = img.Tag        || '';
          const size       = img.Size       || '';
          const created    = img.CreatedSince || '';
          const name       = (repository && repository !== '<none>')
            ? `${repository}:${tag}`
            : '<dangling>';
          result.images.push({
            id: imgId, name, repository, tag, size, created,
            reason: name === '<dangling>' ? 'dangling' : 'unused',
          });
        }
      }
    }
  } catch {}

  // ── Networks: inspect each non-builtin network and check Containers field ──
  try {
    const netLs = await runDocker(`network ls --format '{{json .}}'`);
    if (netLs) {
      const nets = netLs.split('\n').filter(Boolean).map(l => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean).filter(n => !['bridge','host','none'].includes(n.Name));

      for (const net of nets) {
        try {
          const inspectOut = await runDocker(`network inspect ${net.ID} --format '{{json .}}'`);
          if (!inspectOut) continue;
          const ni = JSON.parse(inspectOut);
          const containerCount = ni.Containers ? Object.keys(ni.Containers).length : 0;
          if (containerCount === 0) {
            result.networks.push({ id: net.ID, name: net.Name, driver: net.Driver, scope: net.Scope, reason: 'unused' });
          }
        } catch {}
      }
    }
  } catch {}

  // ── Volumes: port of the shell script — check each volume against ps -a ──
  try {
    const volNamesOut = await runDocker(`volume ls -q`);
    if (volNamesOut) {
      const volNames = volNamesOut.split('\n').filter(Boolean);
      for (const vol of volNames) {
        const usedOut = await runDocker(`ps -a -q --filter "volume=${vol}"`);
        const isUsed  = usedOut && usedOut.split('\n').filter(Boolean).length > 0;
        if (!isUsed) {
          const detailOut = await runDocker(`volume inspect --format '{{json .}}' ${vol}`);
          let driver = '', mountpoint = '', created = '';
          if (detailOut) {
            try {
              const v   = JSON.parse(detailOut);
              driver     = v.Driver     || '';
              mountpoint = v.Mountpoint || '';
              // CreatedAt is like "2024-01-15T10:23:45Z"
              if (v.CreatedAt) {
                try { created = new Date(v.CreatedAt).toLocaleDateString(); } catch { created = v.CreatedAt; }
              }
            } catch {}
          }
          result.volumes.push({ id: vol, name: vol, driver, mountpoint, created, reason: 'unused' });
        }
      }
    }
  } catch {}

  // ── Build cache: docker builder du --verbose ──────────────────────────────
  try {
    // Use without --verbose since the table format is the same and more reliable
    const { stdout } = await execAsync(`"${DOCKER}" builder du 2>/dev/null`, { timeout: 15000 });
    if (stdout) {
      const lines = stdout.trim().split('\n');

      // Extract summary lines (Shared/Private/Reclaimable/Total at the bottom)
      const totalLine = lines.find(l => /^Total:/i.test(l.trim()));
      if (totalLine) result.buildCacheTotal = totalLine.replace(/^Total:\s*/i, '').trim();
      const reclaimableLine = lines.find(l => /^Reclaimable:/i.test(l.trim()));
      if (reclaimableLine) result.buildCacheReclaimable = reclaimableLine.replace(/^Reclaimable:\s*/i, '').trim();

      // Parse the table rows — skip header line and summary lines
      // Summary lines start with: Shared: Private: Reclaimable: Total:
      const summaryPrefixes = /^(Shared|Private|Reclaimable|Total):/i;

      let headerFound = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        // Header line starts with "ID"
        if (/^ID\s+RECLAIMABLE/i.test(trimmed)) { headerFound = true; continue; }
        if (!headerFound) continue;
        // Skip summary lines
        if (summaryPrefixes.test(trimmed)) continue;
        // Split on 2+ spaces — handles variable-width columns
        const cols = trimmed.split(/\s{2,}/);
        if (cols.length >= 3) {
          result.buildCache.push({
            id:           cols[0] || '',
            reclaimable:  cols[1] || '',
            size:         cols[2] || '',
            lastAccessed: cols[3] || '',
          });
        }
      }
    }
  } catch {}

  return result;
}

async function runPrune(selected) {
  const logLines = [`=== Prune started ===`];
  const summary = { images: 0, networks: 0, volumes: 0, errors: [], pruneOutput: '' };

  if (selected.pruneSystem) {
    // ── Step 1: system prune (images, containers, networks, build cache) ──
    try {
      const { stdout, stderr } = await execAsync(
        `"${DOCKER}" system prune -a --force`, { timeout: 120000 }
      );
      const out = (stdout + stderr).trim();
      logLines.push(`SYSTEM PRUNE:\n${out}`);
      summary.pruneOutput = out;
    } catch (e) {
      const msg = `SYSTEM PRUNE FAILED: ${e.message}`;
      logLines.push(msg); summary.errors.push(msg);
    }

    // ── Step 2: volume prune separately (--volumes flag not supported on older Docker) ──
    try {
      const { stdout, stderr } = await execAsync(
        `"${DOCKER}" volume prune -a --force`, { timeout: 60000 }
      );
      const volOut = (stdout + stderr).trim();
      logLines.push(`VOLUME PRUNE:\n${volOut}`);
      summary.pruneOutput += (summary.pruneOutput ? '\n' : '') + volOut;
    } catch (e) {
      const msg = `VOLUME PRUNE FAILED: ${e.message}`;
      logLines.push(msg); summary.errors.push(msg);
    }
  }

  logLines.push(`=== Done. ${summary.errors.length} errors. ===`);
  appendPruneLog(logLines);
  return summary;
}

// ─── Auto-prune scheduler ─────────────────────────────────────────────────────
let autoPruneTimer = null;

function getPruneIntervalMs() {
  const hours = Number(appSettings.pruneIntervalHours || DEFAULT_SETTINGS.pruneIntervalHours);
  return Math.max(1, hours) * 60 * 60 * 1000;
}

function scheduleAutoPrune() {
  if (autoPruneTimer) {
    clearTimeout(autoPruneTimer);
    autoPruneTimer = null;
  }
  const intervalMs = getPruneIntervalMs();
  autoPruneTimer = setTimeout(async () => {
    try {
      appendPruneLog(['=== Scheduled auto-prune triggered ===']);
      const found = await scanUnused();
      const total = found.images.length + found.networks.length + found.volumes.length;
      if (total > 0) {
        await runPrune({ pruneSystem: true });
      } else {
        appendPruneLog(['Nothing to prune.']);
      }
    } catch (e) {
      appendPruneLog([`Auto-prune error: ${e.message}`]);
    }
    // Schedule next interval
    scheduleAutoPrune();
  }, intervalMs);
  logInfo('Auto-prune scheduled', {
    everyHours: Number((intervalMs / 3600000).toFixed(2)),
    nextRunInMinutes: Math.round(intervalMs / 60000),
  });
}
scheduleAutoPrune();

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
    totalRamGb: Number((TOTAL_MEM_KB / 1024 / 1024).toFixed(1)),
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