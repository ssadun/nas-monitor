#!/usr/bin/env node
/**
 * NAS Performance Monitor
 * Synology DS723+ – runs without Docker, collects from /proc + docker CLI
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec, execFile, spawn } = require('child_process');
const { promisify } = require('util');

const crypto = require('crypto');
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const PORT = process.env.PORT || 3232;

// ─── App settings + logging ─────────────────────────────────────────────────
const SETTINGS_FILE = path.join(__dirname, 'settings.json');
const LEGACY_SETTINGS_FILE = path.join(__dirname, 'setting.json');
const LOG_LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };
const DEFAULT_SETTINGS = {
  logLevel: 'INFO',
  authenticationType: true,
  warnThresholdSeconds: 3,
  pruneIntervalHours: 24,
  composeInactivityTimeoutSeconds: 120,
  dockerConfigFolder: '/volume1/docker/_config',
  dockerDataFolder: '/volume1/docker/_data',
};

function normalizeSettings(raw = {}) {
  const level = String(raw.logLevel || DEFAULT_SETTINGS.logLevel).toUpperCase();
  const safeLevel = Object.prototype.hasOwnProperty.call(LOG_LEVELS, level) ? level : DEFAULT_SETTINGS.logLevel;
  const auth = raw.authenticationType;
  const thresholdRaw = raw.warnThresholdSeconds ?? raw.thresholdSeconds ?? DEFAULT_SETTINGS.warnThresholdSeconds;
  const thresholdNum = Number(thresholdRaw);
  const pruneHoursRaw = raw.pruneIntervalHours ?? DEFAULT_SETTINGS.pruneIntervalHours;
  const pruneHoursNum = Number(pruneHoursRaw);
  const composeInactivityRaw = raw.composeInactivityTimeoutSeconds ?? DEFAULT_SETTINGS.composeInactivityTimeoutSeconds;
  const composeInactivityNum = Number(composeInactivityRaw);
  const dockerConfigFolder = String(raw.dockerConfigFolder || DEFAULT_SETTINGS.dockerConfigFolder).trim() || DEFAULT_SETTINGS.dockerConfigFolder;
  const dockerDataFolder = String(raw.dockerDataFolder || DEFAULT_SETTINGS.dockerDataFolder).trim() || DEFAULT_SETTINGS.dockerDataFolder;
  return {
    logLevel: safeLevel,
    authenticationType: typeof auth === 'boolean' ? auth : DEFAULT_SETTINGS.authenticationType,
    warnThresholdSeconds: Number.isFinite(thresholdNum) && thresholdNum >= 0 ? thresholdNum : DEFAULT_SETTINGS.warnThresholdSeconds,
    pruneIntervalHours: Number.isFinite(pruneHoursNum) && pruneHoursNum > 0 ? pruneHoursNum : DEFAULT_SETTINGS.pruneIntervalHours,
    composeInactivityTimeoutSeconds: Number.isFinite(composeInactivityNum) && composeInactivityNum > 0
      ? composeInactivityNum
      : DEFAULT_SETTINGS.composeInactivityTimeoutSeconds,
    dockerConfigFolder,
    dockerDataFolder,
  };
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

let appSettings = loadSettings();
if (!fs.existsSync(SETTINGS_FILE)) {
  try { appSettings = saveSettingsFile(appSettings); }
  catch (e) { logError('Failed to initialize settings file', { error: e.message || 'unknown error' }); }
}

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

function warnThresholdMs() {
  return Math.max(0, Number(appSettings.warnThresholdSeconds || 3) * 1000);
}

// ─── Credentials file (PBKDF2-hashed) ────────────────────────────────────────
const CREDENTIALS_FILE = path.join(__dirname, 'credentials.json');
const PBKDF2_ITER  = 100_000;
const PBKDF2_LEN   = 64;
const PBKDF2_ALGO  = 'sha512';

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITER, PBKDF2_LEN, PBKDF2_ALGO).toString('hex');
}

function loadCredentials() {
  try {
    const data = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf8'));
    if (data.username && data.passwordHash && data.salt) return data;
  } catch {}
  // Fall back to env vars — migrate them into the file on first use
  const user = process.env.AUTH_USER || process.env.NAS_MONITOR_USER || '';
  const pass = process.env.AUTH_PASS || process.env.NAS_MONITOR_PASS || '';
  if (user && pass) {
    const salt = crypto.randomBytes(32).toString('hex');
    const creds = { username: user, passwordHash: hashPassword(pass, salt), salt };
    try { fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(creds, null, 2), 'utf8'); } catch {}
    return creds;
  }
  return null; // no credentials configured → auth disabled
}

function saveCredentials(username, password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const creds = { username, passwordHash: hashPassword(password, salt), salt };
  fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(creds, null, 2), 'utf8');
  return creds;
}

function checkCredentials(username, password) {
  const creds = loadCredentials();
  if (!creds) return true; // no creds configured → open access
  if (username !== creds.username) return false;
  return crypto.timingSafeEqual(
    Buffer.from(hashPassword(password, creds.salt), 'hex'),
    Buffer.from(creds.passwordHash, 'hex')
  );
}

const SESSION_COOKIE = 'nas-monitor-session';
const SESSION_TTL = 1000 * 60 * 60 * 4; // 4h
const sessions = new Map();

function isAuthEnabled() {
  return Boolean(appSettings.authenticationType) && Boolean(loadCredentials());
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, c) => {
    const [k, v] = c.split('=');
    if (!k || v === undefined) return acc;
    acc[k.trim()] = decodeURIComponent(v.trim());
    return acc;
  }, {});
}

function getSessionId(req) {
  return parseCookies(req)[SESSION_COOKIE] || '';
}

function createSession(username = '') {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, {
    expiresAt: Date.now() + SESSION_TTL,
    username: String(username || '').trim() || 'unknown',
  });
  return token;
}

function validateSessionId(token) {
  if (!token) return false;
  const data = sessions.get(token);
  if (!data) {
    sessions.delete(token);
    return false;
  }
  const expiresAt = typeof data === 'number' ? data : Number(data.expiresAt || 0);
  if (!expiresAt || expiresAt < Date.now()) {
    sessions.delete(token);
    return false;
  }
  const username = typeof data === 'number' ? 'unknown' : (data.username || 'unknown');
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL, username });
  return true;
}

function getSessionUser(req) {
  const token = getSessionId(req);
  if (!validateSessionId(token)) return '';
  const data = sessions.get(token);
  if (data && typeof data === 'object' && data.username) return data.username;
  return 'unknown';
}

function isAuthenticated(req) {
  if (!isAuthEnabled()) return true;
  return validateSessionId(getSessionId(req));
}

function requestUser(req) {
  if (!isAuthEnabled()) return 'auth-disabled';
  return getSessionUser(req) || 'anonymous';
}

// periodic cleanup for expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of sessions.entries()) {
    const expiry = typeof data === 'number' ? data : Number(data.expiresAt || 0);
    if (expiry < now) sessions.delete(token);
  }
}, 60 * 60 * 1000);

function setAuthCookie(res, token) {
  const expires = new Date(Date.now() + SESSION_TTL).toUTCString();
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Expires=${expires}; HttpOnly; Path=/; SameSite=Strict`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=Strict`);
}

function sendLoginPage(res, message = '') {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NAS Monitor — Sign In</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🐋</text></svg>"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #0d0f14;
    --bg2:     #141720;
    --bg3:     #1c2030;
    --bg4:     #242840;
    --border:  #2a2f4a;
    --border2: #353b5e;
    --text:    #e2e8ff;
    --text2:   #8891b8;
    --text3:   #545b7a;
    --accent:  #4f8ef7;
    --red:     #ef4444;
    --green:   #22c55e;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'Space Grotesk', sans-serif;
  }
  html, body {
    height: 100%; background: var(--bg);
    color: var(--text); font-family: var(--sans);
  }

  /* ── animated grid background ── */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(79,142,247,.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(79,142,247,.04) 1px, transparent 1px);
    background-size: 48px 48px;
    mask-image: radial-gradient(ellipse 80% 80% at 50% 50%, black 40%, transparent 100%);
    pointer-events: none;
  }

  /* ── glow orbs ── */
  .orb {
    position: fixed; border-radius: 50%; filter: blur(80px);
    pointer-events: none; opacity: .18;
  }
  .orb1 { width: 500px; height: 500px; background: #4f8ef7; top: -120px; left: -100px; }
  .orb2 { width: 400px; height: 400px; background: #7c3aed; bottom: -80px; right: -80px; }
  .orb3 { width: 300px; height: 300px; background: #06b6d4; top: 40%; left: 60%; }

  /* ── layout ── */
  .page {
    min-height: 100vh;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    padding: 24px; position: relative; z-index: 1;
  }

  /* ── card ── */
  .card {
    width: 100%; max-width: 400px;
    background: rgba(20,23,32,.85);
    border: 1px solid var(--border2);
    border-radius: 20px;
    padding: 40px 36px;
    backdrop-filter: blur(20px);
    box-shadow: 0 32px 80px rgba(0,0,0,.6), 0 0 0 1px rgba(79,142,247,.06);
    animation: rise .4s cubic-bezier(.22,1,.36,1) both;
  }
  @keyframes rise { from { opacity:0; transform:translateY(18px); } to { opacity:1; transform:none; } }

  /* ── logo area ── */
  .logo-area {
    display: flex; flex-direction: column; align-items: center; gap: 10px;
    margin-bottom: 32px;
  }
  .logo-icon {
    font-size: 48px; line-height: 1;
    filter: drop-shadow(0 0 18px rgba(79,142,247,.5));
    animation: float 3s ease-in-out infinite;
  }
  @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-6px)} }
  .logo-name {
    font-size: 22px; font-weight: 700; letter-spacing: -.3px;
  }
  .logo-name span { color: var(--accent); }
  .logo-sub {
    font-family: var(--mono); font-size: 11px;
    letter-spacing: 2px; text-transform: uppercase; color: var(--text3);
  }

  /* ── live indicator ── */
  .live-pill {
    display: inline-flex; align-items: center; gap: 6px;
    background: rgba(34,197,94,.1); border: 1px solid rgba(34,197,94,.25);
    border-radius: 20px; padding: 3px 10px;
    font-family: var(--mono); font-size: 11px; color: var(--green);
    margin-top: 2px;
  }
  .live-dot {
    width: 6px; height: 6px; border-radius: 50%; background: var(--green);
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.7)} }

  /* ── divider ── */
  .divider {
    height: 1px; background: linear-gradient(90deg, transparent, var(--border2), transparent);
    margin-bottom: 28px;
  }

  /* ── form ── */
  .field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 16px; }
  .field label {
    font-size: 11px; font-weight: 600; letter-spacing: 1.2px;
    text-transform: uppercase; color: var(--text3); font-family: var(--mono);
  }
  .input-wrap { position: relative; }
  .input-icon {
    position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
    color: var(--text3); font-size: 14px; pointer-events: none;
    transition: color .2s;
  }
  .field:focus-within .input-icon { color: var(--accent); }
  input[type=text], input[type=password] {
    width: 100%; padding: 11px 12px 11px 38px;
    background: var(--bg3); border: 1px solid var(--border2);
    border-radius: 10px; color: var(--text);
    font-family: var(--sans); font-size: 14px;
    outline: none; transition: border-color .2s, box-shadow .2s;
  }
  input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(79,142,247,.15);
  }
  input::placeholder { color: var(--text3); }

  /* ── submit button ── */
  .submit-btn {
    width: 100%; margin-top: 8px;
    padding: 12px;
    background: linear-gradient(135deg, #4f8ef7 0%, #7c3aed 100%);
    border: none; border-radius: 10px;
    color: #fff; font-family: var(--sans); font-size: 15px; font-weight: 700;
    cursor: pointer; letter-spacing: .2px;
    position: relative; overflow: hidden;
    transition: opacity .15s, transform .15s, box-shadow .15s;
    box-shadow: 0 4px 20px rgba(79,142,247,.35);
  }
  .submit-btn:hover { opacity: .92; transform: translateY(-1px); box-shadow: 0 8px 28px rgba(79,142,247,.45); }
  .submit-btn:active { transform: translateY(0); opacity: 1; }
  .submit-btn::after {
    content: '';
    position: absolute; inset: 0;
    background: linear-gradient(rgba(255,255,255,.08), transparent);
    pointer-events: none;
  }

  /* ── error ── */
  .error-box {
    display: flex; align-items: center; gap: 8px;
    background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3);
    border-radius: 8px; padding: 10px 14px; margin-top: 14px;
    font-size: 13px; color: #fca5a5; font-family: var(--mono);
    animation: shake .35s cubic-bezier(.36,.07,.19,.97);
  }
  @keyframes shake {
    0%,100%{transform:translateX(0)} 20%{transform:translateX(-6px)}
    40%{transform:translateX(6px)}   60%{transform:translateX(-4px)}
    80%{transform:translateX(4px)}
  }

  /* ── footer ── */
  .card-footer {
    margin-top: 28px; text-align: center;
    font-family: var(--mono); font-size: 11px; color: var(--text3);
    letter-spacing: .5px;
  }
</style>
</head>
<body>
  <div class="orb orb1"></div>
  <div class="orb orb2"></div>
  <div class="orb orb3"></div>
  <div class="page">
    <div class="card">
      <div class="logo-area">
        <div class="logo-icon">🐋</div>
        <div class="logo-name">NAS <span>Monitor</span></div>
        <div class="logo-sub">Real-time system monitor</div>
        <div class="live-pill"><div class="live-dot"></div> System Online</div>
      </div>
      <div class="divider"></div>
      <form method="POST" action="/login">
        <div class="field">
          <label>Username</label>
          <div class="input-wrap">
            <span class="input-icon">👤</span>
            <input type="text" name="user" placeholder="Enter username" autocomplete="username" required autofocus/>
          </div>
        </div>
        <div class="field">
          <label>Password</label>
          <div class="input-wrap">
            <span class="input-icon">🔑</span>
            <input type="password" name="pass" placeholder="Enter password" autocomplete="current-password" required/>
          </div>
        </div>
        <button type="submit" class="submit-btn">Sign In →</button>
        ${message ? `<div class="error-box">⚠ ${message}</div>` : ''}
      </form>
      <div class="card-footer">Secure access · Session protected</div>
    </div>
  </div>
</body>
</html>`;
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html);
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
const COMPOSE_BACKUP_ROOT = process.env.COMPOSE_BACKUP_ROOT || '/volume1/docker/_backups';
const COMPOSE_FILE_CANDIDATES = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];
const COMPOSE_DISCOVERY_TTL_MS = 30 * 1000;
const NEW_COMPOSE_TEMPLATE_FILE = path.join(__dirname, 'compose.yaml');
const DEFAULT_NEW_COMPOSE_TEMPLATE = `services:\n  my-service:\n    container_name: my-service\n    hostname: my-service\n    environment:\n      TZ: Europe/Istanbul\n    volumes:\n      - ../../_data:/data\n    restart: unless-stopped\n    image: my-service:latest\n`;

function getComposeConfigRoot() {
  return process.env.COMPOSE_CONFIG_ROOT || appSettings.dockerConfigFolder || DEFAULT_SETTINGS.dockerConfigFolder;
}

function getContainerDataRoot() {
  return process.env.CONTAINER_DATA_ROOT || appSettings.dockerDataFolder || DEFAULT_SETTINGS.dockerDataFolder;
}

function ensureComposeTemplateFile() {
  if (fs.existsSync(NEW_COMPOSE_TEMPLATE_FILE)) return;
  try {
    fs.writeFileSync(NEW_COMPOSE_TEMPLATE_FILE, DEFAULT_NEW_COMPOSE_TEMPLATE, 'utf8');
    logInfo('Created default compose template file', { templateFile: NEW_COMPOSE_TEMPLATE_FILE });
  } catch (e) {
    logError('Failed to create default compose template file', { templateFile: NEW_COMPOSE_TEMPLATE_FILE, error: e.message });
  }
}

function readComposeTemplatePayload() {
  ensureComposeTemplateFile();
  try {
    return {
      ok: true,
      templateFile: NEW_COMPOSE_TEMPLATE_FILE,
      content: fs.readFileSync(NEW_COMPOSE_TEMPLATE_FILE, 'utf8'),
    };
  } catch (e) {
    return { ok: false, error: e.message || 'Failed to read compose template file' };
  }
}

function saveComposeTemplatePayload(content) {
  if (typeof content !== 'string') return { ok: false, error: 'content must be a string' };
  const next = String(content || '').trim();
  if (!next) return { ok: false, error: 'Template content cannot be empty' };
  try {
    fs.writeFileSync(NEW_COMPOSE_TEMPLATE_FILE, content, 'utf8');
    return { ok: true, templateFile: NEW_COMPOSE_TEMPLATE_FILE };
  } catch (e) {
    return { ok: false, error: e.message || 'Failed to save compose template file' };
  }
}

function findDockerComposeBinary() {
  for (const p of DOCKER_COMPOSE_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return 'docker-compose';
}

const DOCKER_COMPOSE = findDockerComposeBinary();

function stripInlineYamlComment(value) {
  return String(value || '').replace(/\s+#.*$/, '').trim();
}

function unquoteYamlScalar(value) {
  const cleaned = stripInlineYamlComment(value);
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
    return cleaned.slice(1, -1);
  }
  return cleaned;
}

function parseComposePortSpec(spec) {
  const cleaned = unquoteYamlScalar(spec);
  if (!cleaned) return null;
  const [portPart, protoRaw] = cleaned.split('/');
  const proto = (protoRaw || 'tcp').trim();
  const segments = portPart.split(':').map(s => s.trim()).filter(Boolean);
  if (!segments.length) return null;

  let host = '';
  let container = '';
  if (segments.length === 1) {
    host = segments[0];
    container = segments[0];
  } else if (segments.length === 2) {
    host = segments[0];
    container = segments[1];
  } else {
    host = segments[segments.length - 2];
    container = segments[segments.length - 1];
  }

  const hostMatch = host.match(/\d+(?:-\d+)?/);
  const containerMatch = container.match(/\d+(?:-\d+)?/);
  if (!hostMatch && !containerMatch) return null;

  return {
    host: hostMatch ? hostMatch[0] : '',
    container: containerMatch ? containerMatch[0] : '',
    proto,
  };
}

function parseComposeServices(raw) {
  const services = [];
  const lines = String(raw || '').replace(/\r/g, '').split('\n');
  let inServices = false;
  let servicesIndent = 0;
  let current = null;
  let currentIndent = 0;
  let inPorts = false;
  let portsIndent = 0;

  const flushCurrent = () => {
    if (!current) return;
    services.push({
      service: current.service,
      containerName: current.containerName || '',
      image: current.image || '',
      ports: current.ports || [],
      displayName: current.containerName || current.service,
    });
    current = null;
    inPorts = false;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = line.match(/^\s*/)[0].length;
    if (!inServices) {
      if (trimmed === 'services:' || trimmed.startsWith('services:')) {
        inServices = true;
        servicesIndent = indent;
      }
      continue;
    }

    if (indent <= servicesIndent && !trimmed.startsWith('-')) {
      flushCurrent();
      break;
    }

    if (indent === servicesIndent + 2 && /^[A-Za-z0-9_.-]+:\s*$/.test(trimmed)) {
      flushCurrent();
      current = { service: trimmed.slice(0, -1), ports: [] };
      currentIndent = indent;
      continue;
    }

    if (!current) continue;

    if (inPorts && indent <= portsIndent) inPorts = false;

    if (indent === currentIndent + 2) {
      const m = trimmed.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
      if (!m) continue;
      const [, key, value] = m;
      if (key === 'container_name') {
        current.containerName = unquoteYamlScalar(value);
      } else if (key === 'image') {
        current.image = unquoteYamlScalar(value);
      } else if (key === 'ports') {
        inPorts = true;
        portsIndent = indent;
      }
      continue;
    }

    if (inPorts && indent > portsIndent && trimmed.startsWith('- ')) {
      const parsed = parseComposePortSpec(trimmed.slice(2));
      if (parsed) current.ports.push(parsed);
    }
  }

  flushCurrent();
  return services;
}

let composeDiscoveryCache = { ts: 0, projects: [] };

function discoverComposeProjects(force = false) {
  const now = Date.now();
  if (!force && now - composeDiscoveryCache.ts < COMPOSE_DISCOVERY_TTL_MS) {
    return composeDiscoveryCache.projects;
  }

  const projects = [];
  const composeRoot = getComposeConfigRoot();
  try {
    const entries = fs.readdirSync(composeRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const projectDir = path.join(composeRoot, entry.name);
      const composeFileName = COMPOSE_FILE_CANDIDATES.find(name => fs.existsSync(path.join(projectDir, name)));
      if (!composeFileName) continue;

      const composeFile = path.join(projectDir, composeFileName);
      let services = [];
      try {
        services = parseComposeServices(fs.readFileSync(composeFile, 'utf8'));
      } catch {}

      projects.push({
        project: entry.name,
        dir: projectDir,
        composeFile,
        services,
      });
    }
  } catch {}

  composeDiscoveryCache = { ts: now, projects };
  return projects;
}

function buildComposeSyntheticId(project, service) {
  return `compose:${project}:${service}`;
}

function parseComposeSyntheticId(id) {
  const raw = String(id || '');
  if (!raw.startsWith('compose:')) return null;
  const parts = raw.split(':');
  if (parts.length < 3) return null;
  return {
    project: parts[1],
    service: parts.slice(2).join(':'),
  };
}

function findComposeServiceTarget(projectName, serviceName) {
  const project = discoverComposeProjects().find(p => p.project === projectName);
  if (!project) return null;
  const service = project.services.find(s => s.service === serviceName);
  if (!service) return null;
  return { project, service };
}

function findComposeProject(projectName) {
  return discoverComposeProjects().find(p => p.project === projectName) || null;
}

function isPathInsideRoot(filePath, rootPath) {
  const resolvedFile = path.resolve(filePath);
  const resolvedRoot = path.resolve(rootPath);
  return resolvedFile === resolvedRoot || resolvedFile.startsWith(resolvedRoot + path.sep);
}

function isValidContainerFolderName(name) {
  return /^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$/.test(String(name || ''));
}

function normalizeContainerSubPath(subPath = '') {
  const raw = String(subPath || '').trim().replace(/\\/g, '/');
  const cleaned = raw.replace(/^\/+/, '').replace(/\/+/g, '/');
  if (!cleaned) return '';
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.some(seg => seg === '.' || seg === '..')) return null;
  return parts.join('/');
}

function resolveContainerDataPath(containerName, subPath = '') {
  if (!isValidContainerFolderName(containerName)) return null;
  const dataRoot = getContainerDataRoot();
  const basePath = path.join(dataRoot, containerName);
  if (!isPathInsideRoot(basePath, dataRoot)) return null;
  const normalizedSubPath = normalizeContainerSubPath(subPath);
  if (normalizedSubPath === null) return null;
  const targetPath = normalizedSubPath ? path.join(basePath, normalizedSubPath) : basePath;
  if (!isPathInsideRoot(targetPath, basePath)) return null;
  return { basePath, targetPath, subPath: normalizedSubPath || '' };
}

function getSafeComposeFilePath(projectName, explicitComposeFile = '') {
  const composeRoot = getComposeConfigRoot();
  const explicit = String(explicitComposeFile || '').trim();
  if (explicit && fs.existsSync(explicit) && isPathInsideRoot(explicit, composeRoot)) {
    return explicit;
  }

  const project = findComposeProject(projectName);
  if (!project || !project.composeFile) return '';
  if (!fs.existsSync(project.composeFile) || !isPathInsideRoot(project.composeFile, composeRoot)) return '';
  return project.composeFile;
}

function readComposeFilePayload(projectName, explicitComposeFile = '') {
  const composeFile = getSafeComposeFilePath(projectName, explicitComposeFile);
  if (!composeFile) return { ok: false, error: 'Compose file not found.' };
  try {
    return {
      ok: true,
      composeFile,
      composeFileName: path.basename(composeFile),
      composeFileContent: fs.readFileSync(composeFile, 'utf8'),
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function runComposeProject(composeFile, args, timeout = 30000) {
  const cwd = path.dirname(composeFile);
  try {
    return await execFileAsync(DOCKER, ['compose', '-f', composeFile, ...args], { cwd, timeout });
  } catch (error) {
    logWarn('Primary docker compose command failed, trying fallback', {
      composeFile,
      args: args.join(' '),
      error: error?.message || 'unknown error',
    });
    return await execFileAsync(DOCKER_COMPOSE, ['-f', composeFile, ...args], { cwd, timeout });
  }
}

function spawnComposeCommand(command, args, cwd, onChunk, timeout = 120000, onSpawn = null, isCancelled = null) {
  return new Promise(resolve => {
    let settled = false;
    const child = spawn(command, args, { cwd, env: process.env });
    if (typeof onSpawn === 'function') {
      try { onSpawn(child); } catch {}
    }

    let idleTimer = null;
    const resetIdleTimer = () => {
      if (timeout <= 0) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        if (settled) return;
        try { child.kill('SIGTERM'); } catch {}
        logError('Compose command timed out due to inactivity', {
          command,
          args: args.join(' '),
          cwd,
          inactivityTimeoutSeconds: Math.floor(timeout / 1000),
        });
        settled = true;
        resolve({ ok: false, code: null, error: `Timed out after ${Math.floor(timeout / 1000)}s of inactivity` });
      }, timeout);
    };
    resetIdleTimer();

    child.stdout.on('data', buf => {
      resetIdleTimer();
      onChunk('stdout', String(buf || ''));
    });
    child.stderr.on('data', buf => {
      resetIdleTimer();
      onChunk('stderr', String(buf || ''));
    });

    child.on('error', err => {
      if (settled) return;
      if (idleTimer) clearTimeout(idleTimer);
      logError('Compose command failed to spawn', {
        command,
        args: args.join(' '),
        cwd,
        error: err?.message || 'unknown error',
      });
      settled = true;
      resolve({ ok: false, code: null, error: err.message || 'Failed to spawn compose process' });
    });

    child.on('close', code => {
      if (settled) return;
      if (idleTimer) clearTimeout(idleTimer);
      settled = true;
      if (typeof isCancelled === 'function' && isCancelled()) {
        resolve({ ok: false, code: null, error: 'Compose run cancelled by user' });
        return;
      }
      if (code !== 0) {
        logError('Compose command exited with non-zero code', {
          command,
          args: args.join(' '),
          cwd,
          code,
        });
      }
      resolve({ ok: code === 0, code, error: code === 0 ? '' : `compose exited with code ${code}` });
    });
  });
}

async function runComposeUpStream(composeFile, service, onChunk, options = {}) {
  const { onSpawn = null, isCancelled = null } = options;
  const cwd = path.dirname(composeFile);
  const inactivityTimeoutMs = Math.max(1000, Number(appSettings.composeInactivityTimeoutSeconds || DEFAULT_SETTINGS.composeInactivityTimeoutSeconds) * 1000);
  const primaryArgs = ['compose', '-f', composeFile, 'up', '-d', service];
  const fallbackArgs = ['-f', composeFile, 'up', '-d', service];

  onChunk('status', `Running: docker compose -f ${composeFile} up -d ${service}`);
  let result = await spawnComposeCommand(DOCKER, primaryArgs, cwd, onChunk, inactivityTimeoutMs, onSpawn, isCancelled);
  if (result.ok) return result;

  // Fall back to docker-compose only if docker command appears unavailable.
  const dockerMissing = /ENOENT|not found|spawn/i.test(result.error || '');
  if (!dockerMissing) return result;

  onChunk('status', `Falling back: docker-compose -f ${composeFile} up -d ${service}`);
  return await spawnComposeCommand(DOCKER_COMPOSE, fallbackArgs, cwd, onChunk, inactivityTimeoutMs, onSpawn, isCancelled);
}

function getComposeSyntheticDetail(id) {
  const synthetic = parseComposeSyntheticId(id);
  if (!synthetic) return null;
  const target = findComposeServiceTarget(synthetic.project, synthetic.service);
  if (!target) return { error: 'Compose service not found.' };
  const { project, service } = target;
  const composeFilePayload = readComposeFilePayload(project.project, project.composeFile);
  return {
    id: buildComposeSyntheticId(project.project, service.service),
    fullId: '',
    name: service.displayName,
    status: 'configured',
    running: false,
    created: '',
    startedAt: '',
    finishedAt: '',
    uptime: 'Defined in compose',
    restartCount: 0,
    restartPolicy: { name: 'compose', maximumRetryCount: 0 },
    image: service.image || '',
    imageId: '',
    imageHash: '',
    imageSize: '',
    cmd: `docker compose up -d ${service.service}`,
    entrypoint: '',
    memUsage: '',
    memPercent: '',
    cpu: '',
    blockIO: '',
    portConfig: (service.ports || []).map(p => ({
      containerPort: p.container ? `${p.container}/${p.proto || 'tcp'}` : '',
      hostIp: '0.0.0.0',
      hostPort: p.host || '',
    })),
    volumes: [],
    networks: [],
    env: [],
    labels: [
      { key: 'compose.project', value: project.project },
      { key: 'compose.service', value: service.service },
      { key: 'compose.file', value: project.composeFile },
    ],
    composeProject: project.project,
    composeService: service.service,
    composeManaged: true,
    composeOnly: true,
    composeFile: composeFilePayload.ok ? composeFilePayload.composeFile : project.composeFile,
    composeFileName: composeFilePayload.ok ? composeFilePayload.composeFileName : path.basename(project.composeFile),
    composeFileContent: composeFilePayload.ok ? composeFilePayload.composeFileContent : '',
    composeFileError: composeFilePayload.ok ? '' : composeFilePayload.error,
  };
}

async function runDocker(args) {
  try {
    const { stdout } = await execAsync(`"${DOCKER}" ${args}`, { timeout: 8000 });
    return stdout.trim();
  } catch (e) {
    logError('Docker command failed', {
      args,
      error: e?.message || 'unknown error',
    });
    return '';
  }
}

function shellQuote(v) {
  return `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
}

function statAccessInfo(targetPath) {
  try {
    const st = fs.statSync(targetPath);
    const mode = (st.mode & 0o777).toString(8).padStart(3, '0');
    return {
      owner: `${st.uid}:${st.gid}`,
      mode,
      uid: st.uid,
      gid: st.gid,
    };
  } catch {
    return { owner: '', mode: '', uid: null, gid: null };
  }
}

async function buildVolumeUsageMap() {
  const usageMap = {};
  const psOut = await runDocker(`ps -a --format '{{json .}}'`);
  if (!psOut) return usageMap;

  const containers = psOut.split('\n').filter(Boolean).map(line => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);
  const ids = containers.map(c => c.ID).filter(Boolean);
  if (!ids.length) return usageMap;

  try {
    const { stdout } = await execAsync(`"${DOCKER}" inspect ${ids.map(shellQuote).join(' ')} --format '{{json .}}'`, { timeout: 25000 });
    const inspected = String(stdout || '').split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);

    for (const c of inspected) {
      const containerName = String(c.Name || '').replace(/^\//, '') || (c.Config && c.Config.Hostname) || '';
      const isRunning = Boolean(c.State && c.State.Running);
      for (const m of (c.Mounts || [])) {
        if (m && m.Type === 'volume' && m.Name) {
          if (!usageMap[m.Name]) usageMap[m.Name] = [];
          usageMap[m.Name].push({
            id: String(c.Id || '').slice(0, 12),
            name: containerName,
            status: isRunning ? 'running' : 'stopped',
            destination: m.Destination || '',
          });
        }
      }
    }
  } catch (e) {
    logError('Failed to inspect containers for volume usage', { error: e.message || 'unknown error' });
  }

  return usageMap;
}

async function collectDockerVolumes() {
  const usageMap = await buildVolumeUsageMap();
  const out = await runDocker(`volume ls --format '{{json .}}'`);
  if (!out) return [];

  const listed = out.split('\n').filter(Boolean).map(line => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);

  const names = listed.map(v => v.Name).filter(Boolean);
  if (!names.length) return [];

  let inspectArr = [];
  try {
    const { stdout } = await execAsync(`"${DOCKER}" volume inspect ${names.map(shellQuote).join(' ')}`, { timeout: 25000 });
    const parsed = JSON.parse(stdout || '[]');
    inspectArr = Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    logError('Failed to inspect docker volumes', { error: e.message || 'unknown error' });
  }

  const byName = Object.fromEntries(inspectArr.map(v => [v.Name, v]));
  return names.map(name => {
    const iv = byName[name] || {};
    const labels = iv.Labels || {};
    const stack = labels['com.docker.compose.project'] || labels['stack'] || '-';
    const mountpoint = iv.Mountpoint || '';
    const access = mountpoint ? statAccessInfo(mountpoint) : { owner: '', mode: '', uid: null, gid: null };
    const containers = usageMap[name] || [];
    const runningContainers = containers.filter(c => c.status === 'running').map(c => c.name).filter(Boolean);
    return {
      name,
      stack,
      driver: iv.Driver || '',
      mountpoint,
      ownership: access.owner || '-',
      mode: access.mode || '-',
      createdAt: iv.CreatedAt || '',
      createdDate: iv.CreatedAt ? new Date(iv.CreatedAt).toLocaleString() : '-',
      runningOn: runningContainers,
      labels,
      access,
      containers,
      options: iv.Options || {},
      scope: iv.Scope || '',
    };
  });
}

async function collectContainers() {
  // Get container list with IDs (--all includes stopped/exited containers)
  const listJson = await runDocker(
    `ps --all --no-trunc --format '{{json .}}'`
  );
  if (!listJson) return [];

  const containers = listJson.split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);

  // Get stats (one-shot)
  const statsJson = await runDocker(
    `stats --no-stream --no-trunc --format '{{json .}}'`
  );
  const statsMap = {};
  if (statsJson) {
    statsJson.split('\n').filter(Boolean).forEach(line => {
      try {
        const s = JSON.parse(line);
        statsMap[s.ID] = s;
      } catch {}
    });
  }

  // ── Batch-fetch network definitions for all running containers ───────────────
  // docker inspect gives NetworkSettings.Networks: { <netName>: { IPAddress, Gateway, ... } }
  const allIds = containers.map(c => c.ID).filter(Boolean);

  // Build driver + hostIface map from docker network ls + network inspect
  const networkDriverMap = {}; // networkName → { driver, hostIface }
  try {
    // Read all actual host interfaces once for candidate matching
    const hostIfaces = new Set(
      readFile('/proc/net/dev').split('\n').slice(2).filter(Boolean)
        .map(l => l.trim().split(/\s+/)[0].replace(':', ''))
    );

    function resolveHostIface(networkId, explicitName) {
      // 1. Explicit name set in Options (highest priority)
      if (explicitName && hostIfaces.has(explicitName)) return explicitName;
      if (explicitName) return explicitName; // trust it even if not seen yet

      if (!networkId) return '';
      // 2. Try all known naming conventions, verify against /proc/net/dev
      const candidates = [
        'docker-' + networkId.slice(0, 8),   // Synology DSM: docker-c5c36d39
        'br-'     + networkId.slice(0, 12),  // Standard Linux: br-c5c36d39320a
        'br-'     + networkId.slice(0, 8),   // Some distros use 8 chars
        'docker'  + networkId.slice(0, 7),   // docker0-style short
      ];
      for (const c of candidates) {
        if (hostIfaces.has(c)) return c;
      }
      // 3. Fallback: prefix-search /proc/net/dev for docker-<id prefix>
      const idPrefixes = [networkId.slice(0, 8), networkId.slice(0, 12)];
      for (const iface of hostIfaces) {
        for (const pfx of idPrefixes) {
          if (iface.includes(pfx)) return iface;
        }
      }
      return '';
    }

    const netLs = await runDocker(`network ls --format '{{json .}}'`);
    if (netLs) {
      const netIds = [];
      netLs.split('\n').filter(Boolean).forEach(line => {
        try {
          const n = JSON.parse(line);
          networkDriverMap[n.Name] = { driver: n.Driver || '', hostIface: '', id: n.ID || '' };
          if (n.ID) netIds.push(n.ID);
        } catch {}
      });

      // Batch inspect all networks to get the host bridge interface name
      if (netIds.length) {
        const netInspect = await runDocker(`network inspect ${netIds.join(' ')} --format '{{json .}}'`);
        if (netInspect) {
          netInspect.split('\n').filter(Boolean).forEach(line => {
            try {
              const ni = JSON.parse(line);
              const entry = Object.values(networkDriverMap).find(e => e.id === ni.Id || e.id === (ni.Id||'').slice(0,12));
              if (!entry) return;
              if (ni.Driver === 'host') {
                entry.hostIface = 'host';
              } else if (ni.Driver === 'bridge' && ni.Id) {
                const explicit = (ni.Options && ni.Options['com.docker.network.bridge.name']) || '';
                entry.hostIface = resolveHostIface(ni.Id, explicit);
              }
            } catch {}
          });
        }
      }
    }
  } catch {}

  // Build reverse map: hostIface → docker network name
  ifaceToDockerNet = {};
  Object.entries(networkDriverMap).forEach(([netName, entry]) => {
    if (entry.hostIface && entry.hostIface !== 'host') {
      ifaceToDockerNet[entry.hostIface] = netName;
    }
  }); 

  const inspectMetaMap = {}; // fullId → compose metadata
  const netDefsMap = {}; // fullId → [ { name, driver, ip, gateway, macAddr } ]
  if (allIds.length) {
    try {
      const inspectOut = await runDocker(
        `inspect --format '{{json .}}' ${allIds.join(' ')}`
      );
      if (inspectOut) {
        inspectOut.split('\n').filter(Boolean).forEach(line => {
          try {
            const obj = JSON.parse(line);
            const fullId = obj.Id;
            const labels = obj.Config && obj.Config.Labels ? obj.Config.Labels : {};
            inspectMetaMap[fullId] = {
              composeProject: labels['com.docker.compose.project'] || '',
              composeService: labels['com.docker.compose.service'] || '',
              composeWorkingDir: labels['com.docker.compose.project.working_dir'] || '',
              composeConfigFiles: labels['com.docker.compose.project.config_files'] || '',
            };
            const nets = obj.NetworkSettings && obj.NetworkSettings.Networks
              ? obj.NetworkSettings.Networks : {};
            netDefsMap[fullId] = Object.entries(nets).map(([netName, n]) => {
              const meta = networkDriverMap[netName] || {};
              return {
                name:      netName,
                driver:    meta.driver    || '',
                hostIface: meta.hostIface || '',
                ip:        n.IPAddress  || '',
                gateway:   n.Gateway    || '',
                macAddr:   n.MacAddress || '',
              };
            });
          } catch {}
        });
      }
    } catch {}
  }

  // Get top pids per container
  const result = [];
  for (const c of containers) {
    const id = c.ID;
    const stats = statsMap[id] || {};
    const inspectMeta = inspectMetaMap[id] || {};

    // docker top gives us PIDs on the host
    const topOut = await runDocker(`top ${id} -eo pid,ppid`);
    const pids = [];
    if (topOut) {
      const lines = topOut.split('\n').slice(1); // skip header
      for (const l of lines) {
        const parts = l.trim().split(/\s+/);
        if (parts[0] && /^\d+$/.test(parts[0])) {
          pids.push(parseInt(parts[0]));
        }
      }
    }

    // Parse mem usage and limit
    const memUsageRaw = stats.MemUsage || '0B / 0B';
    const netIO = stats.NetIO || '0B / 0B';
    const blockIO = stats.BlockIO || '0B / 0B';

    // Get image size
    let imageSize = '';
    try {
      const imgOut = await runDocker(`inspect --format '{{.Config.Image}}' ${id}`);
      if (imgOut) {
        const imgSizeOut = await runDocker(`image inspect --format '{{.Size}}' ${imgOut.trim()}`);
        if (imgSizeOut) {
          imageSize = formatBytes(parseInt(imgSizeOut));
        }
      }
    } catch {}

    // Parse ports — format: "0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp"
    const portsRaw = c.Ports || '';
    const ports = [];
    if (portsRaw) {
      const seen = new Set();
      for (const part of portsRaw.split(',')) {
        const m = part.trim().match(/(?:[\d.]+:)?(\d+)->(\d+)\/(tcp|udp)/);
        if (m && !seen.has(m[1])) {
          seen.add(m[1]);
          ports.push({ host: m[1], container: m[2], proto: m[3] });
        }
      }
    }

    // ── Per-container network rates via /proc/<pid>/net/dev ──────────────────
    // The first PID from docker top runs inside the container's network namespace.
    // Reading /proc/<pid>/net/dev from the HOST gives us that namespace's interface
    // stats — i.e. the container's own cumulative RX/TX bytes, not the host bridge.
    let vethRxKBs = 0, vethTxKBs = 0;
    let vethRxBytes = 0, vethTxBytes = 0;
    let netMode = 'veth';
    const netPid = pids[0];
    if (netPid) {
      const nsNet = readContainerNetDev(netPid);
      if (nsNet) {
        vethRxBytes = nsNet.rxBytes;
        vethTxBytes = nsNet.txBytes;
        const nowNet = Date.now();
        const prevCN = prevContainerNetSnapshot[id];
        if (prevCN && nowNet > prevCN.ts) {
          const dtSec = (nowNet - prevCN.ts) / 1000;
          vethRxKBs = parseFloat(Math.max(0, (nsNet.rxBytes - prevCN.rxBytes) / 1024 / dtSec).toFixed(2));
          vethTxKBs = parseFloat(Math.max(0, (nsNet.txBytes - prevCN.txBytes) / 1024 / dtSec).toFixed(2));
        }
        prevContainerNetSnapshot[id] = { rxBytes: nsNet.rxBytes, txBytes: nsNet.txBytes, ts: Date.now() };
      } else {
        netMode = 'host'; // likely host-network container — no separate namespace
      }
    }

    result.push({
      name: (c.Names || c.Name || '').replace(/^\//, ''),
      id: id.slice(0, 12),
      fullId: id,
      image: c.Image || '',
      status: c.Status || '',
      state: c.State || '',
      cpu: stats.CPUPerc || '0%',
      memUsage: memUsageRaw.split('/')[0].trim(),
      memLimit: memUsageRaw.split('/')[1]?.trim() || '',
      memPercent: stats.MemPerc || '0%',
      netIn: netIO.split('/')[0].trim(),
      netOut: netIO.split('/')[1]?.trim() || '',
      blockIO: blockIO,
      imageSize,
      ports,
      pids: pids,
      processCount: stats.PIDs || pids.length,
      networks: netDefsMap[id] || [],
      // Per-container real-time network rates (from /proc/<pid>/net/dev namespace)
      vethRxKBs,
      vethTxKBs,
      vethRxBytes,
      vethTxBytes,
      netMode,
      composeProject: inspectMeta.composeProject || '',
      composeService: inspectMeta.composeService || '',
      composeDir: inspectMeta.composeWorkingDir || '',
      composeFile: (inspectMeta.composeConfigFiles || '').split(',').map(s => s.trim()).find(Boolean) || '',
      composeManaged: Boolean(
        inspectMeta.composeProject ||
        inspectMeta.composeService ||
        inspectMeta.composeWorkingDir ||
        inspectMeta.composeConfigFiles
      ),
      composeOnly: false,
    });
  }

  const composeProjects = discoverComposeProjects(true);
  const composeProjectMap = new Map(composeProjects.map(project => [project.project, project]));
  const matchedComposeKeys = new Set();
  const matchedContainerNames = new Set(result.map(container => container.name));

  for (const container of result) {
    const project = container.composeProject ? composeProjectMap.get(container.composeProject) : null;
    if (!project) continue;
    const service = project.services.find(s =>
      s.service === container.composeService ||
      s.containerName === container.name ||
      s.displayName === container.name
    );
    if (!service) continue;

    matchedComposeKeys.add(`${project.project}/${service.service}`);
    container.composeProject = project.project;
    container.composeService = service.service;
    container.composeFile = container.composeFile || project.composeFile;
    container.composeDir = container.composeDir || project.dir;
    container.composeManaged = true;
    if ((!container.ports || !container.ports.length) && service.ports.length) {
      container.ports = service.ports;
    }
  }

  for (const project of composeProjects) {
    for (const service of project.services) {
      const composeKey = `${project.project}/${service.service}`;
      if (matchedComposeKeys.has(composeKey) || matchedContainerNames.has(service.displayName)) continue;

      result.push({
        name: service.displayName,
        id: buildComposeSyntheticId(project.project, service.service),
        fullId: '',
        image: service.image || '',
        status: 'Defined in compose',
        state: 'configured',
        cpu: '–',
        memUsage: '–',
        memLimit: '',
        memPercent: '–',
        netIn: '–',
        netOut: '–',
        blockIO: '–',
        imageSize: '',
        ports: service.ports || [],
        pids: [],
        processCount: 0,
        networks: [],
        vethRxKBs: 0,
        vethTxKBs: 0,
        vethRxBytes: 0,
        vethTxBytes: 0,
        netMode: 'compose',
        composeProject: project.project,
        composeService: service.service,
        composeDir: project.dir,
        composeFile: project.composeFile,
        composeManaged: true,
        composeOnly: true,
      });
    }
  }

  return result;
}

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

const DISK_HISTORY_FILE = path.join(__dirname, 'disk-history.json');
const DISK_HISTORY_MAX = 20;

const CAT_ASSIGNMENTS_FILE = path.join(__dirname, 'category-assignments.json');
const CAT_DEFS_FILE = path.join(__dirname, 'category-defs.json');

const DEFAULT_CAT_DEFS = [
  { id: 'media',       label: 'Media',       icon: '🎬', color: '#a78bfa', dot: '#8b5cf6' },
  { id: 'performance', label: 'Performance', icon: '⚡', color: '#f97316', dot: '#f97316' },
  { id: 'utilities',  label: 'Utilities',   icon: '🔧', color: '#06b6d4', dot: '#06b6d4' },
  { id: 'system',     label: 'System',      icon: '🖥',  color: '#22c55e', dot: '#22c55e' },
];

function loadCatDefs() {
  try {
    const data = JSON.parse(fs.readFileSync(CAT_DEFS_FILE, 'utf8'));
    return Array.isArray(data) && data.length ? data : DEFAULT_CAT_DEFS;
  } catch { return DEFAULT_CAT_DEFS; }
}

function saveCatDefs(data) {
  try {
    fs.writeFileSync(CAT_DEFS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    logError('Failed to save category definitions file', { error: e.message });
  }
}

function loadCatAssignments() {
  try {
    return JSON.parse(fs.readFileSync(CAT_ASSIGNMENTS_FILE, 'utf8'));
  } catch { return {}; }
}

function saveCatAssignments(data) {
  try {
    fs.writeFileSync(CAT_ASSIGNMENTS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    logError('Failed to save category assignments file', { error: e.message });
  }
}

function loadDiskHistory() {
  try {
    const raw = fs.readFileSync(DISK_HISTORY_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveDiskHistory(history) {
  try {
    fs.writeFileSync(DISK_HISTORY_FILE, JSON.stringify(history), 'utf8');
  } catch (e) {
    logError('Failed to save disk history file', { error: e.message });
  }
}

let diskScanHistory = loadDiskHistory();
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
      collectContainers(),
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
setInterval(refreshCache, 3000);

// ─── Disk usage scanner ───────────────────────────────────────────────────────

const fsp = require('fs').promises;

async function diskWalkTree(dirPath, depth, maxDepth) {
  const node = { path: dirPath, name: dirPath.split('/').pop() || dirPath, sizeBytes: 0, children: [] };
  let entries;
  try { entries = await fsp.readdir(dirPath, { withFileTypes: true }); } catch { return node; }

  for (const e of entries) {
    const full = dirPath.replace(/\/$/, '') + '/' + e.name;
    try {
      if (e.isSymbolicLink()) continue;
      if (e.isFile()) {
        const st = await fsp.stat(full);
        node.sizeBytes += st.size;
      } else if (e.isDirectory()) {
        if (depth < maxDepth) {
          const child = await diskWalkTree(full, depth + 1, maxDepth);
          node.sizeBytes += child.sizeBytes;
          node.children.push(child);
        } else {
          // At max depth: count size without going deeper in tree
          const sz = await diskCountSize(full);
          node.sizeBytes += sz;
          node.children.push({ path: full, name: e.name, sizeBytes: sz, children: [] });
        }
      }
    } catch {}
  }
  node.children.sort((a, b) => b.sizeBytes - a.sizeBytes);
  return node;
}

async function diskCountSize(dirPath) {
  let total = 0;
  let entries;
  try { entries = await fsp.readdir(dirPath, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const full = dirPath.replace(/\/$/, '') + '/' + e.name;
    try {
      if (e.isSymbolicLink()) continue;
      if (e.isFile()) {
        const st = await fsp.stat(full);
        total += st.size;
      } else if (e.isDirectory()) {
        total += await diskCountSize(full);
      }
    } catch {}
  }
  return total;
}

async function diskCollectFiles(dirPath, fileList, depth, maxDepth) {
  if (depth > maxDepth) return;
  let entries;
  try { entries = await fsp.readdir(dirPath, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = dirPath.replace(/\/$/, '') + '/' + e.name;
    try {
      if (e.isSymbolicLink()) continue;
      if (e.isFile()) {
        const st = await fsp.stat(full);
        fileList.push({ path: full, name: e.name, sizeBytes: st.size, mtime: st.mtimeMs });
      } else if (e.isDirectory()) {
        await diskCollectFiles(full, fileList, depth + 1, maxDepth);
      }
    } catch {}
  }
}

async function collectDiskUsage(scanPath, maxDepth = 4) {
  const results = { path: scanPath, scannedAt: Date.now(), tree: null, topFiles: [], error: null };
  try {
    results.tree = await diskWalkTree(scanPath, 0, maxDepth);
    const allFiles = [];
    await diskCollectFiles(scanPath, allFiles, 0, maxDepth + 2);
    results.topFiles = allFiles.sort((a, b) => b.sizeBytes - a.sizeBytes).slice(0, 50);
  } catch (e) {
    results.error = e.message;
  }
  return results;
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

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
  reqUser = requestUser(req);

  if (url.pathname === '/login') {
    if (!isAuthEnabled()) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }
    if (req.method === 'GET') {
      sendLoginPage(res);
      return;
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        const params = Object.fromEntries(new URLSearchParams(body));
        const user = params.user || '';
        const pass = params.pass || '';
        if (checkCredentials(user, pass)) {
          const token = createSession(user);
          setAuthCookie(res, token);
          logInfo('User login succeeded', { user, remoteIp: req.socket?.remoteAddress || '' });
          res.writeHead(302, { Location: '/' });
          res.end();
        } else {
          logWarn('User login failed', { user, remoteIp: req.socket?.remoteAddress || '' });
          sendLoginPage(res, 'Invalid username or password.');
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
    clearAuthCookie(res);
    res.writeHead(302, { Location: '/login' });
    res.end();
    return;
  }

  if (!isAuthenticated(req)) {
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

  if (url.pathname === '/') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
    });
    res.end(HTML);
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
    res.write('retry: 3000\n\n');

    const send = () => {
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify(cache)}\n\n`);
      }
    };

    send();
    const iv = setInterval(send, 3000);
    req.on('close', () => clearInterval(iv));
    return;
  }

  if (url.pathname === '/api/compose/up' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { project, service } = JSON.parse(body || '{}');
        if (!project || !service) {
          logError('Compose up rejected: missing project or service', { user: reqUser, project, service });
          res.end(JSON.stringify({ ok: false, error: 'project and service are required' }));
          return;
        }

        const target = findComposeServiceTarget(project, service);
        if (!target) {
          logError('Compose up target not found', { user: reqUser, project, service });
          res.end(JSON.stringify({ ok: false, error: 'Compose service not found under configured compose root.' }));
          return;
        }

        const { stdout, stderr } = await runComposeProject(target.project.composeFile, ['up', '-d', target.service.service], 60000);
        logInfo('Compose up completed', {
          user: reqUser,
          project: target.project.project,
          service: target.service.service,
        });
        res.end(JSON.stringify({
          ok: true,
          output: `${stdout || ''}${stderr || ''}`.trim(),
          project: target.project.project,
          service: target.service.service,
        }));
      } catch (e) {
        logError('Compose up failed', { user: reqUser, error: e.message || 'unknown error' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/compose/up/stream' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      let activeChild = null;
      let clientClosed = false;
      const cancelActiveCompose = () => {
        clientClosed = true;
        if (activeChild && !activeChild.killed) {
          try { activeChild.kill('SIGTERM'); } catch {}
          setTimeout(() => {
            try {
              if (activeChild && !activeChild.killed) activeChild.kill('SIGKILL');
            } catch {}
          }, 1500);
        }
      };
      // Use response-side close and aborted events. req.close can fire on normal request completion.
      res.on('close', cancelActiveCompose);
      req.on('aborted', cancelActiveCompose);

      res.writeHead(200, {
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });

      const send = payload => {
        if (!res.writableEnded && !res.destroyed) res.write(JSON.stringify(payload) + '\n');
      };
      const sendChunk = (type, text) => {
        const lines = String(text || '').replace(/\r/g, '').split('\n').filter(Boolean);
        for (const line of lines) send({ type, message: line });
      };

      try {
        const { project, service } = JSON.parse(body || '{}');
        if (!project || !service) {
          logError('Compose stream rejected: missing project or service', { user: reqUser, project, service });
          send({ type: 'error', message: 'project and service are required' });
          send({ type: 'done', ok: false });
          res.end();
          return;
        }

        const target = findComposeServiceTarget(project, service);
        if (!target) {
          logError('Compose stream failed: target not found', { user: reqUser, project, service });
          send({ type: 'error', message: 'Compose service not found under configured compose root.' });
          send({ type: 'done', ok: false });
          res.end();
          return;
        }

        send({ type: 'status', message: 'Reading compose project…' });
        const result = await runComposeUpStream(target.project.composeFile, target.service.service, sendChunk, {
          onSpawn: child => { activeChild = child; },
          isCancelled: () => clientClosed,
        });
        if (clientClosed) {
          logInfo('Compose stream cancelled by client', { user: reqUser, project, service });
          if (!res.writableEnded && !res.destroyed) res.end();
          return;
        }
        if (result.ok) {
          logInfo('Compose stream completed', { user: reqUser, project, service });
          send({ type: 'done', ok: true, message: 'Compose up completed successfully.' });
        } else {
          logError('Compose stream failed', {
            user: reqUser,
            project,
            service,
            error: result.error || 'compose up failed',
          });
          send({ type: 'error', message: result.error || 'compose up failed' });
          send({ type: 'done', ok: false });
        }
      } catch (e) {
        logError('Compose stream failed with unexpected error', { user: reqUser, error: e.message || 'Unexpected error' });
        send({ type: 'error', message: e.message || 'Unexpected error' });
        send({ type: 'done', ok: false });
      }
      res.end();
    });
    return;
  }

  if (url.pathname === '/api/compose/template' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    const payload = readComposeTemplatePayload();
    res.end(JSON.stringify(payload));
    return;
  }

  if (url.pathname === '/api/compose/template' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { content } = JSON.parse(body || '{}');
        const saved = saveComposeTemplatePayload(content);
        if (saved.ok) {
          logInfo('Compose template updated', { user: reqUser, templateFile: saved.templateFile });
          res.end(JSON.stringify(saved));
        } else {
          logError('Compose template update failed', { user: reqUser, error: saved.error || 'unknown error' });
          res.end(JSON.stringify(saved));
        }
      } catch (e) {
        logError('Compose template update failed', { user: reqUser, error: e.message || 'Unexpected error' });
        res.end(JSON.stringify({ ok: false, error: e.message || 'Unexpected error' }));
      }
    });
    return;
  }

  if (url.pathname === '/api/compose/create' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name, content } = JSON.parse(body || '{}');

        // Validate name: alphanumeric, hyphens, underscores only
        if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project name. Use only letters, numbers, hyphens and underscores.' }));
          return;
        }
        if (typeof content !== 'string' || !content.trim()) {
          res.end(JSON.stringify({ ok: false, error: 'compose.yaml content is required.' }));
          return;
        }

        const composeRoot = getComposeConfigRoot();
        const projectDir  = path.join(composeRoot, name);
        const composeFile = path.join(projectDir, 'compose.yaml');

        // Safety: ensure target stays inside the root
        if (!isPathInsideRoot(projectDir, composeRoot)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project path.' }));
          return;
        }
        if (fs.existsSync(projectDir)) {
          res.end(JSON.stringify({ ok: false, error: `Project "${name}" already exists.` }));
          return;
        }

        fs.mkdirSync(projectDir, { recursive: true });
        fs.writeFileSync(composeFile, content, 'utf8');

        // Build an open target so UI can jump straight into the created compose file.
        const parsedServices = parseComposeServices(content);
        const firstService = parsedServices[0] || null;
        const openTarget = firstService
          ? {
              id: buildComposeSyntheticId(name, firstService.service),
              name: firstService.displayName || firstService.service,
              stateClass: 'configured',
            }
          : null;

        // Invalidate discovery cache so new project appears immediately
        composeDiscoveryCache = { ts: 0, projects: [] };
        await refreshCache();

        res.end(JSON.stringify({ ok: true, composeFile, openTarget }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/compose/backups' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const result = [];
      if (fs.existsSync(COMPOSE_BACKUP_ROOT)) {
        const projects = fs.readdirSync(COMPOSE_BACKUP_ROOT).filter(e => {
          try { return fs.statSync(path.join(COMPOSE_BACKUP_ROOT, e)).isDirectory(); } catch { return false; }
        });
        for (const project of projects) {
          const dir = path.join(COMPOSE_BACKUP_ROOT, project);
          const files = fs.readdirSync(dir).map(f => {
            const fp = path.join(dir, f);
            let mtime = null;
            try { mtime = fs.statSync(fp).mtime.toISOString(); } catch {}
            return { name: f, mtime };
          }).sort((a, b) => (b.mtime || '').localeCompare(a.mtime || ''));
          result.push({ project, path: dir, files });
        }
        result.sort((a, b) => a.project.localeCompare(b.project));
      }
      res.end(JSON.stringify({ ok: true, backups: result }));
    } catch (e) {
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return;
  }

  if (url.pathname === '/api/compose/archive' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { project } = JSON.parse(body || '{}');
        if (!project || !/^[a-zA-Z0-9_-]+$/.test(project)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project name.' }));
          return;
        }

        const composeRoot = getComposeConfigRoot();
        const sourceDir = path.join(composeRoot, project);
        const backupDir = path.join(COMPOSE_BACKUP_ROOT, project);
        if (!isPathInsideRoot(sourceDir, composeRoot) || !isPathInsideRoot(backupDir, COMPOSE_BACKUP_ROOT)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project path.' }));
          return;
        }
        if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
          res.end(JSON.stringify({ ok: false, error: 'Compose project folder not found.' }));
          return;
        }

        fs.mkdirSync(backupDir, { recursive: true });
        const moved = [];
        const entries = fs.readdirSync(sourceDir);
        for (const entry of entries) {
          const src = path.join(sourceDir, entry);
          let dst = path.join(backupDir, entry);
          if (fs.existsSync(dst)) {
            const stamp = new Date().toISOString().replace(/[:.]/g, '-');
            dst = path.join(backupDir, `${entry}.${stamp}`);
          }
          fs.renameSync(src, dst);
          moved.push(path.basename(dst));
        }

        try {
          fs.rmdirSync(sourceDir);
        } catch {
          fs.rmSync(sourceDir, { recursive: true, force: true });
        }

        composeDiscoveryCache = { ts: 0, projects: [] };
        await refreshCache();
        res.end(JSON.stringify({ ok: true, backupDir, moved }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/compose/restore' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { project } = JSON.parse(body || '{}');
        if (!project || !/^[a-zA-Z0-9_-]+$/.test(project)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project name.' }));
          return;
        }

        const backupDir = path.join(COMPOSE_BACKUP_ROOT, project);
        const composeRoot = getComposeConfigRoot();
        const targetDir = path.join(composeRoot, project);
        if (!isPathInsideRoot(backupDir, COMPOSE_BACKUP_ROOT) || !isPathInsideRoot(targetDir, composeRoot)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid project path.' }));
          return;
        }
        if (!fs.existsSync(backupDir) || !fs.statSync(backupDir).isDirectory()) {
          res.end(JSON.stringify({ ok: false, error: 'Backup project folder not found.' }));
          return;
        }

        fs.mkdirSync(targetDir, { recursive: true });
        const moved = [];
        const entries = fs.readdirSync(backupDir);
        for (const entry of entries) {
          const src = path.join(backupDir, entry);
          let dst = path.join(targetDir, entry);
          if (fs.existsSync(dst)) {
            const stamp = new Date().toISOString().replace(/[:.]/g, '-');
            dst = path.join(targetDir, `${entry}.${stamp}`);
          }
          fs.renameSync(src, dst);
          moved.push(path.basename(dst));
        }

        const remaining = fs.readdirSync(backupDir);
        if (!remaining.length) {
          try {
            fs.rmdirSync(backupDir);
          } catch {
            fs.rmSync(backupDir, { recursive: true, force: true });
          }
        }

        composeDiscoveryCache = { ts: 0, projects: [] };
        await refreshCache();
        res.end(JSON.stringify({ ok: true, targetDir, moved }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  if (url.pathname === '/api/compose/file' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const project     = url.searchParams.get('project') || '';
      const composeFile = url.searchParams.get('composeFile') || '';
      const payload = readComposeFilePayload(project, composeFile);
      res.end(JSON.stringify(payload));
    } catch (e) {
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return;
  }

  if (url.pathname === '/api/compose/file' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { project, composeFile, content } = JSON.parse(body || '{}');
        if (!project) {
          res.end(JSON.stringify({ ok: false, error: 'project is required' }));
          return;
        }
        if (typeof content !== 'string') {
          res.end(JSON.stringify({ ok: false, error: 'content must be a string' }));
          return;
        }

        const safeComposeFile = getSafeComposeFilePath(project, composeFile);
        if (!safeComposeFile) {
          res.end(JSON.stringify({ ok: false, error: 'Compose file not found under configured compose root.' }));
          return;
        }

        fs.writeFileSync(safeComposeFile, content, 'utf8');
        composeDiscoveryCache = { ts: 0, projects: [] };
        await refreshCache();
        res.end(JSON.stringify({ ok: true, composeFile: safeComposeFile }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
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
      if (diskScanHistory.length > DISK_HISTORY_MAX) diskScanHistory.pop();
      saveDiskHistory(diskScanHistory);
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
      saveDiskHistory(diskScanHistory);
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

  if (!url.pathname.startsWith('/api/container/detail/') && !url.pathname.startsWith('/api/container/restart-policy/') && !url.pathname.startsWith('/api/container/folders') && url.pathname.startsWith('/api/container/')) {
    // /api/container/:action?id=xxx  (start|stop|restart|delete)
    const action = url.pathname.split('/')[3];
    const id = url.searchParams.get('id');
    if (!id || !['start','stop','restart','delete'].includes(action)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid action or id' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      // delete = stop first (ignore error if already stopped), then rm
      if (action === 'delete') {
        try { await execAsync(`"${DOCKER}" stop ${id}`, { timeout: 15000 }); } catch {}
        const { stdout, stderr } = await execAsync(`"${DOCKER}" rm ${id}`, { timeout: 10000 });
        logInfo('Container action completed', { user: reqUser, action, id });
        res.end(JSON.stringify({ ok: true, output: (stdout + stderr).trim() }));
      } else {
        const { stdout, stderr } = await execAsync(`"${DOCKER}" ${action} ${id}`, { timeout: 15000 });
        logInfo('Container action completed', { user: reqUser, action, id });
        res.end(JSON.stringify({ ok: true, output: (stdout + stderr).trim() }));
      }
    } catch (e) {
      logError('Container action failed', { user: reqUser, action, id, error: e.message });
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

  if (url.pathname.startsWith('/api/container/detail/')) {
    const id = decodeURIComponent(url.pathname.split('/')[4] || '');
    if (!id) { res.writeHead(400); res.end('{}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const syntheticDetail = getComposeSyntheticDetail(id);
      if (syntheticDetail) {
        res.end(JSON.stringify(syntheticDetail));
        return;
      }

      const raw = await runDocker(`inspect ${id}`);
      if (!raw) { res.end(JSON.stringify({ error: 'Not found' })); return; }
      const arr = JSON.parse(raw);
      const d   = arr[0];
      if (!d)   { res.end(JSON.stringify({ error: 'Empty response' })); return; }

      // Image details
      let imageHash = '', imageSize = '';
      try {
        const imgRaw = await runDocker(`image inspect --format '{{json .}}' ${d.Image}`);
        if (imgRaw) {
          const img = JSON.parse(imgRaw);
          imageHash = img.Id ? img.Id.replace('sha256:', '').slice(0, 12) : '';
          imageSize = img.Size ? formatBytes(img.Size) : '';
        }
      } catch {}

      // Port config
      const portConfig = [];
      if (d.HostConfig && d.HostConfig.PortBindings) {
        Object.entries(d.HostConfig.PortBindings).forEach(([containerPort, bindings]) => {
          (bindings || []).forEach(b => {
            portConfig.push({ containerPort, hostIp: b.HostIp || '0.0.0.0', hostPort: b.HostPort || '' });
          });
        });
      }

      // Volumes — with size on disk via du -sh on each mountpoint
      const volumes = [];
      if (d.Mounts) {
        for (const m of d.Mounts) {
          let sizeOnDisk = '';
          if (m.Source) {
            try {
              const { stdout } = await execAsync(`du -sh "${m.Source}" 2>/dev/null`, { timeout: 8000 });
              sizeOnDisk = stdout ? stdout.trim().split(/\s+/)[0] : '';
            } catch {}
          }
          volumes.push({ type: m.Type || '', source: m.Source || '', destination: m.Destination || '', mode: m.Mode || '', rw: m.RW, sizeOnDisk });
        }
      }

      // Networks
      const networks = [];
      if (d.NetworkSettings && d.NetworkSettings.Networks) {
        Object.entries(d.NetworkSettings.Networks).forEach(([name, n]) => {
          networks.push({ name, ip: n.IPAddress || '', gateway: n.Gateway || '', mac: n.MacAddress || '', subnet: (n.IPAMConfig && n.IPAMConfig.IPv4Address) || '' });
        });
      }

      // ENV as key-value pairs
      const env = (d.Config && d.Config.Env || []).map(e => {
        const idx = e.indexOf('=');
        return idx >= 0 ? { key: e.slice(0, idx), value: e.slice(idx + 1) } : { key: e, value: '' };
      });

      // Labels
      const labels = Object.entries(d.Config && d.Config.Labels || {}).map(([k, v]) => ({ key: k, value: v }));
      const currentContainer = cache.containers.find(c => c.id === id || c.fullId === id) || {};
      const composeProject = currentContainer.composeProject || (d.Config && d.Config.Labels && d.Config.Labels['com.docker.compose.project']) || '';
      const composeService = currentContainer.composeService || (d.Config && d.Config.Labels && d.Config.Labels['com.docker.compose.service']) || '';
      const composeFile = currentContainer.composeFile || '';
      const composeManaged = Boolean(currentContainer.composeManaged || composeProject || composeService || composeFile);
      const composeFilePayload = composeManaged ? readComposeFilePayload(composeProject, composeFile) : null;

      res.end(JSON.stringify({
        id:           d.Id ? d.Id.slice(0, 12) : '',
        fullId:       d.Id || '',
        name:         (d.Name || '').replace(/^\//, ''),
        status:       d.State ? d.State.Status : '',
        running:      d.State ? d.State.Running : false,
        created:      d.Created || '',
        startedAt:    d.State ? d.State.StartedAt : '',
        finishedAt:   d.State ? d.State.FinishedAt : '',
        uptime:       d.State ? d.State.Status : '',
        restartCount: d.RestartCount || 0,
        restartPolicy: {
          name:              (d.HostConfig && d.HostConfig.RestartPolicy && d.HostConfig.RestartPolicy.Name)              || 'no',
          maximumRetryCount: (d.HostConfig && d.HostConfig.RestartPolicy && d.HostConfig.RestartPolicy.MaximumRetryCount) || 0,
        },
        image:        d.Config ? d.Config.Image : '',
        imageId:      d.Image || '',
        imageHash,
        imageSize,
        cmd:          d.Config && d.Config.Cmd       ? d.Config.Cmd.join(' ')         : '',
        entrypoint:   d.Config && d.Config.Entrypoint ? d.Config.Entrypoint.join(' ') : '',
        memUsage:     currentContainer.memUsage  || '',
        memPercent:   currentContainer.memPercent || '',
        cpu:          currentContainer.cpu        || '',
        blockIO:      currentContainer.blockIO    || '',
        portConfig,
        volumes,
        networks,
        env,
        labels,
        composeProject,
        composeService,
        composeManaged,
        composeOnly: false,
        composeFile: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFile : composeFile,
        composeFileName: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFileName : (composeFile ? path.basename(composeFile) : ''),
        composeFileContent: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFileContent : '',
        composeFileError: composeFilePayload && !composeFilePayload.ok ? composeFilePayload.error : '',
      }));
    } catch (e) {
      res.end(JSON.stringify({ error: e.message }));
    }
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
        res.end(JSON.stringify({ ok: true, summary }));
      } catch (e) {
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
        res.end(JSON.stringify({ ok: true, settings: appSettings }));
      } catch (e) {
        logError('Failed to update settings', { error: e.message, user: reqUser });
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
        const creds = loadCredentials();
        // Verify current password first
        const currentUser = creds ? creds.username : '';
        if (creds && !checkCredentials(currentUser, currentPassword || '')) {
          logWarn('Credential change failed due to invalid current password', { user: reqUser });
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
        saveCredentials(newUsername.trim(), newPassword);
        logInfo('Credentials updated', { user: reqUser, newUsername: newUsername.trim() });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        logError('Failed to change credentials', { error: e.message, user: reqUser });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // GET /api/category-defs  — return category definitions array
  if (url.pathname === '/api/category-defs' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(loadCatDefs()));
    return;
  }

  // POST /api/category-defs  — body: array of category objects
  if (url.pathname === '/api/category-defs' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const defs = JSON.parse(body);
        if (!Array.isArray(defs)) { res.end(JSON.stringify({ ok: false, error: 'expected array' })); return; }
        saveCatDefs(defs);
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // GET /api/categories  — return all assignments { containerName: categoryId }
  if (url.pathname === '/api/categories' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(loadCatAssignments()));
    return;
  }

  // POST /api/categories  — body: { containerId, categoryId }  (categoryId null = remove)
  if (url.pathname === '/api/categories' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { containerName, categoryId, purge } = JSON.parse(body);
        const assignments = loadCatAssignments();
        // purge: remove all assignments for a deleted category id
        if (purge) {
          for (const key of Object.keys(assignments)) {
            if (assignments[key] === purge) delete assignments[key];
          }
          saveCatAssignments(assignments);
          res.end(JSON.stringify({ ok: true, assignments }));
          return;
        }
        if (!containerName) { res.end(JSON.stringify({ ok: false, error: 'containerName required' })); return; }
        if (categoryId === null || categoryId === undefined) {
          delete assignments[containerName];
        } else {
          assignments[containerName] = categoryId;
        }
        saveCatAssignments(assignments);
        res.end(JSON.stringify({ ok: true, assignments }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

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

  // POST /api/container/restart-policy/:id  — body: { policy, maxRetries }
  if (url.pathname.startsWith('/api/container/restart-policy/') && req.method === 'POST') {
    const id = url.pathname.split('/')[4];
    if (!id) { res.writeHead(400); res.end(JSON.stringify({ ok: false, error: 'Missing id' })); return; }
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { policy, maxRetries } = JSON.parse(body);
        const VALID = ['no', 'always', 'unless-stopped', 'on-failure'];
        if (!VALID.includes(policy)) {
          res.end(JSON.stringify({ ok: false, error: `Invalid policy "${policy}". Must be one of: ${VALID.join(', ')}` }));
          return;
        }
        // Build restart flag: on-failure allows optional :N max retries
        const restartFlag = (policy === 'on-failure' && maxRetries > 0)
          ? `on-failure:${parseInt(maxRetries)}`
          : policy;
        const { stdout, stderr } = await execAsync(`"${DOCKER}" update --restart=${restartFlag} ${id}`, { timeout: 10000 });
        res.end(JSON.stringify({ ok: true, output: (stdout + stderr).trim(), policy, maxRetries: maxRetries || 0 }));
      } catch (e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // GET /api/container/folders?name=<name>&subpath=<relative-path>  — browse data folder
  if (url.pathname === '/api/container/folders' && req.method === 'GET') {
    const name = url.searchParams.get('name') || '';
    const subpath = url.searchParams.get('subpath') || '';
    const resolved = resolveContainerDataPath(name, subpath);
    if (!resolved) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid container name or path' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    const exists = fs.existsSync(resolved.basePath);
    let entries = [];
    const currentExists = fs.existsSync(resolved.targetPath);
    if (exists && currentExists) {
      try {
        entries = fs.readdirSync(resolved.targetPath, { withFileTypes: true })
          .map(e => {
            const fullPath = path.join(resolved.targetPath, e.name);
            let sizeBytes = 0;
            let modifiedAt = '';
            try {
              const st = fs.statSync(fullPath);
              sizeBytes = st.size || 0;
              modifiedAt = st.mtime ? st.mtime.toISOString() : '';
            } catch {}
            return {
              name: e.name,
              type: e.isDirectory() ? 'dir' : 'file',
              sizeBytes,
              modifiedAt,
            };
          })
          .sort((a, b) => {
            if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
            return a.name.localeCompare(b.name);
          });
      } catch (e) {
        logError('Failed to browse container data folder', {
          user: reqUser,
          name,
          subpath: resolved.subPath,
          path: resolved.targetPath,
          error: e.message,
        });
      }
    }
    res.end(JSON.stringify({
      ok: true,
      path: resolved.targetPath,
      basePath: resolved.basePath,
      subpath: resolved.subPath,
      exists,
      currentExists,
      entries,
    }));
    return;
  }

  // POST /api/container/folders  — create base data folder + optional subfolders at parentPath
  if (url.pathname === '/api/container/folders' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name, subfolders, parentPath } = JSON.parse(body || '{}');
        const resolvedBase = resolveContainerDataPath(name, '');
        const resolvedParent = resolveContainerDataPath(name, parentPath || '');
        if (!resolvedBase || !resolvedParent) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid container name or parent path' }));
          return;
        }
        const basePath = resolvedBase.basePath;
        const parentDir = resolvedParent.targetPath;
        const created = [];
        if (!fs.existsSync(basePath)) {
          fs.mkdirSync(basePath, { recursive: true });
          created.push(name);
        }
        if (!fs.existsSync(parentDir)) {
          fs.mkdirSync(parentDir, { recursive: true });
        }
        if (Array.isArray(subfolders)) {
          for (const sub of subfolders) {
            const subName = String(sub || '').trim();
            if (!subName || path.isAbsolute(subName)) continue;
            // Reject path traversal: no segment may be '.' or '..'
            if (subName.split('/').some(seg => seg === '..' || seg === '.')) continue;
            // Allow only safe folder characters
            if (!/^[a-zA-Z0-9_.\-][a-zA-Z0-9_.\-\/]*$/.test(subName)) continue;
            const subPath = path.join(parentDir, subName);
            if (!isPathInsideRoot(subPath, basePath)) continue;
            if (!fs.existsSync(subPath)) {
              fs.mkdirSync(subPath, { recursive: true });
              created.push(subName);
            }
          }
        }
        logInfo('Container data folder ensured', {
          user: reqUser,
          container: name,
          createdCount: created.length,
          created,
        });
        res.end(JSON.stringify({ ok: true, path: basePath, created }));
      } catch (e) {
        logError('Failed to create container data folder', { user: reqUser, error: e.message });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // GET /api/container/folders/download?name=<container>&filePath=<relative-path>
  if (url.pathname === '/api/container/folders/download' && req.method === 'GET') {
    const name = url.searchParams.get('name') || '';
    const filePath = url.searchParams.get('filePath') || '';
    const resolved = resolveContainerDataPath(name, filePath);
    if (!resolved) {
      res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid container name or file path' }));
      return;
    }

    let st = null;
    try { st = fs.statSync(resolved.targetPath); } catch {}
    if (!st) {
      res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'File not found' }));
      return;
    }
    if (!st.isFile()) {
      res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'Only files can be downloaded' }));
      return;
    }

    const filename = path.basename(resolved.targetPath);
    const encodedFilename = encodeURIComponent(filename);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': st.size,
      'Content-Disposition': `attachment; filename="${filename.replace(/"/g, '')}"; filename*=UTF-8''${encodedFilename}`,
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    });

    const stream = fs.createReadStream(resolved.targetPath);
    stream.on('error', e => {
      logError('Container file download stream failed', {
        user: reqUser,
        container: name,
        filePath: resolved.subPath,
        error: e.message,
      });
      try {
        if (!res.writableEnded) {
          res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: false, error: 'Failed to read file' }));
        }
      } catch {}
    });
    stream.pipe(res);
    logInfo('Container file download started', { user: reqUser, container: name, filePath: resolved.subPath, sizeBytes: st.size });
    return;
  }

  // POST /api/container/folders/rename — rename folder within container data root
  if (url.pathname === '/api/container/folders/rename' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name, folderPath, newName } = JSON.parse(body || '{}');
        const resolved = resolveContainerDataPath(name, folderPath || '');
        if (!resolved) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid container name or folder path' }));
          return;
        }
        const cleanNewName = String(newName || '').trim();
        if (!/^[a-zA-Z0-9_.\-]+$/.test(cleanNewName)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid folder name' }));
          return;
        }
        const fromPath = resolved.targetPath;
        if (fromPath === resolved.basePath) {
          res.end(JSON.stringify({ ok: false, error: 'Root folder cannot be renamed' }));
          return;
        }
        let fromStat = null;
        try { fromStat = fs.statSync(fromPath); } catch {}
        if (!fromStat || !fromStat.isDirectory()) {
          res.end(JSON.stringify({ ok: false, error: 'Only folders can be renamed' }));
          return;
        }
        const toPath = path.join(path.dirname(fromPath), cleanNewName);
        if (!isPathInsideRoot(toPath, resolved.basePath)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid target folder path' }));
          return;
        }
        if (fs.existsSync(toPath)) {
          res.end(JSON.stringify({ ok: false, error: 'A file or folder with the target name already exists' }));
          return;
        }
        fs.renameSync(fromPath, toPath);
        logInfo('Container folder renamed', { user: reqUser, container: name, from: resolved.subPath, to: cleanNewName });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        logError('Failed to rename container folder', { user: reqUser, error: e.message });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // POST /api/container/folders/delete — delete folder (recursive) within container data root
  if (url.pathname === '/api/container/folders/delete' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name, folderPath } = JSON.parse(body || '{}');
        const resolved = resolveContainerDataPath(name, folderPath || '');
        if (!resolved) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid container name or folder path' }));
          return;
        }
        const targetPath = resolved.targetPath;
        if (targetPath === resolved.basePath) {
          res.end(JSON.stringify({ ok: false, error: 'Root folder cannot be deleted' }));
          return;
        }
        let st = null;
        try { st = fs.statSync(targetPath); } catch {}
        if (!st || !st.isDirectory()) {
          res.end(JSON.stringify({ ok: false, error: 'Only folders can be deleted' }));
          return;
        }
        fs.rmSync(targetPath, { recursive: true, force: false });
        logInfo('Container folder deleted', { user: reqUser, container: name, folderPath: resolved.subPath });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        logError('Failed to delete container folder', { user: reqUser, error: e.message });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // GET /api/docker/volumes/list — list docker volumes with metadata
  if (url.pathname === '/api/docker/volumes/list' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    try {
      const volumes = await collectDockerVolumes();
      res.end(JSON.stringify({ ok: true, volumes }));
    } catch (e) {
      logError('Failed to list docker volumes', { user: reqUser, error: e.message || 'unknown error' });
      res.end(JSON.stringify({ ok: false, error: e.message, volumes: [] }));
    }
    return;
  }

  // GET /api/docker/volumes/detail?name=<volumeName>
  if (url.pathname === '/api/docker/volumes/detail' && req.method === 'GET') {
    const name = String(url.searchParams.get('name') || '').trim();
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    if (!name) {
      res.end(JSON.stringify({ ok: false, error: 'name is required' }));
      return;
    }
    try {
      const volumes = await collectDockerVolumes();
      const volume = volumes.find(v => v.name === name);
      if (!volume) {
        res.end(JSON.stringify({ ok: false, error: 'Volume not found' }));
        return;
      }
      res.end(JSON.stringify({ ok: true, volume }));
    } catch (e) {
      logError('Failed to load docker volume detail', { user: reqUser, name, error: e.message || 'unknown error' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return;
  }

  // POST /api/docker/volumes/create — body: { name, driver, labels }
  if (url.pathname === '/api/docker/volumes/create' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name, driver, labels } = JSON.parse(body || '{}');
        const safeName = String(name || '').trim();
        if (!safeName) {
          res.end(JSON.stringify({ ok: false, error: 'Volume name required' }));
          return;
        }
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(safeName)) {
          res.end(JSON.stringify({ ok: false, error: 'Invalid volume name format' }));
          return;
        }
        let cmd = `"${DOCKER}" volume create --driver ${shellQuote(driver || 'local')}`;
        if (labels && typeof labels === 'object') {
          for (const [k, v] of Object.entries(labels)) {
            if (!k) continue;
            cmd += ` --label ${shellQuote(`${k}=${String(v ?? '')}`)}`;
          }
        }
        cmd += ` ${shellQuote(safeName)}`;
        const { stdout } = await execAsync(cmd, { timeout: 15000 });
        logInfo('Docker volume created', { user: reqUser, name: safeName, driver: driver || 'local' });
        res.end(JSON.stringify({ ok: true, id: String(stdout || '').trim(), name: safeName }));
      } catch (e) {
        logError('Failed to create docker volume', { user: reqUser, error: e.message || 'unknown error' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // POST /api/docker/volumes/delete — body: { name }
  if (url.pathname === '/api/docker/volumes/delete' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      try {
        const { name } = JSON.parse(body || '{}');
        const safeName = String(name || '').trim();
        if (!safeName) {
          res.end(JSON.stringify({ ok: false, error: 'Volume name required' }));
          return;
        }
        await execAsync(`"${DOCKER}" volume rm ${shellQuote(safeName)}`, { timeout: 15000 });
        logInfo('Docker volume deleted', { user: reqUser, name: safeName });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        logError('Failed to delete docker volume', { user: reqUser, error: e.message || 'unknown error' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
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

const PRUNE_LOG_FILE = path.join(__dirname, 'prune.log');
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
  if (!isAuthenticated(req)) {
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