// ═══════════════════════════════════════════════════════════════════════════
// auth.js - Authentication, credentials, and session management
// ═══════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ─── Constants ─────────────────────────────────────────────────────────────

const CREDENTIALS_FILE = path.join(__dirname, '..', 'data', 'credentials.json');
const PBKDF2_ITER = 100_000;
const PBKDF2_LEN = 64;
const PBKDF2_ALGO = 'sha512';

const SESSION_COOKIE = 'nas-monitor-session';
const SESSION_TTL_HOURS = 4; // default, can be overridden by settings.sessionTimeoutHours
const SESSIONS_FILE = path.join(__dirname, '..', 'logs', 'sessions.json');

const sessions = new Map();

// ─── Utilities passed from server.js ───────────────────────────────────────
// These are injected by server.js to avoid circular dependencies

let appSettings = {};
let logError = () => {};

function setDependencies(settings, errorLogger) {
  appSettings = settings;
  logError = errorLogger;
}

// ─── Password Hashing ──────────────────────────────────────────────────────

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITER, PBKDF2_LEN, PBKDF2_ALGO).toString('hex');
}

// ─── Credentials Management ───────────────────────────────────────────────

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
    try { fs.mkdirSync(path.dirname(CREDENTIALS_FILE), { recursive: true }); } catch {}
    try { fs.writeFileSync(CREDENTIALS_FILE, JSON.stringify(creds, null, 2), 'utf8'); } catch {}
    return creds;
  }
  return null; // no credentials configured → auth disabled
}

function saveCredentials(username, password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const creds = { username, passwordHash: hashPassword(password, salt), salt };
  fs.mkdirSync(path.dirname(CREDENTIALS_FILE), { recursive: true });
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

// ─── Session Management ───────────────────────────────────────────────────

function getSessionTTL() {
  const hours = Number(appSettings.sessionTimeoutHours) || SESSION_TTL_HOURS;
  return Math.max(1, hours) * 1000 * 60 * 60; // convert hours to milliseconds
}

function isAuthEnabled() {
  return Boolean(appSettings.authenticationType) && Boolean(loadCredentials());
}

function loadSessionsFromFile() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const data = fs.readFileSync(SESSIONS_FILE, 'utf8');
      const sessionsData = JSON.parse(data);
      for (const [token, sessionData] of Object.entries(sessionsData)) {
        sessions.set(token, sessionData);
      }
    }
  } catch (e) {
    logError('Failed to load sessions from file', { error: e.message });
  }
}

function saveSessionsToFile() {
  try {
    const data = {};
    for (const [token, sessionData] of sessions.entries()) {
      data[token] = sessionData;
    }
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(data), 'utf8');
  } catch (e) {
    logError('Failed to save sessions to file', { error: e.message });
  }
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
    expiresAt: Date.now() + getSessionTTL(),
    username: String(username || '').trim() || 'unknown',
  });
  saveSessionsToFile();
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
    saveSessionsToFile();
    return false;
  }
  const username = typeof data === 'number' ? 'unknown' : (data.username || 'unknown');
  sessions.set(token, { expiresAt: Date.now() + getSessionTTL(), username });
  saveSessionsToFile();
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

function setAuthCookie(res, token) {
  const expires = new Date(Date.now() + getSessionTTL()).toUTCString();
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Expires=${expires}; HttpOnly; Path=/; SameSite=Lax`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax`);
}

function deleteSession(token) {
  if (token) {
    sessions.delete(token);
    saveSessionsToFile();
  }
}

// ─── Periodic Session Cleanup ──────────────────────────────────────────────

function startSessionCleanup() {
  setInterval(() => {
    const now = Date.now();
    let changed = false;
    for (const [token, data] of sessions.entries()) {
      const expiry = typeof data === 'number' ? data : Number(data.expiresAt || 0);
      if (expiry < now) {
        sessions.delete(token);
        changed = true;
      }
    }
    if (changed) saveSessionsToFile();
  }, 60 * 60 * 1000);
}

// ─── Login Page HTML ───────────────────────────────────────────────────────

function sendLoginPage(res, message = '') {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NAS Monitor — Sign In</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="icon" href="/favicon.ico"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --main-bg:      #0d0f14;
    --menu-bg:     #141720;
    --card-bg:     #1c2030;
    --card-hover-bg:     #242840;
    --border:  #2a2f4a;
    --border2: #353b5e;
    --text:    #e2e8ff;
    --text2:   #8891b8;
    --text3:   #545b7a;
    --blue:  #4f8ef7;
    --red:     #ef4444;
    --green:   #22c55e;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'Space Grotesk', sans-serif;
  }
  html, body {
    height: 100%; background: var(--main-bg);
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
  .logo-name span { color: var(--blue); }
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
  .field:focus-within .input-icon { color: var(--blue); }
  input[type=text], input[type=password] {
    width: 100%; padding: 11px 12px 11px 38px;
    background: var(--card-bg); border: 1px solid var(--border2);
    border-radius: 10px; color: var(--text);
    font-family: var(--sans); font-size: 14px;
    outline: none; transition: border-color .2s, box-shadow .2s;
  }
  input:focus {
    border-color: var(--blue);
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

// ─── Exports ───────────────────────────────────────────────────────────────

module.exports = {
  CREDENTIALS_FILE,
  SESSION_COOKIE,
  SESSIONS_FILE,
  setDependencies,
  loadCredentials,
  saveCredentials,
  checkCredentials,
  getSessionTTL,
  isAuthEnabled,
  loadSessionsFromFile,
  saveSessionsToFile,
  createSession,
  validateSessionId,
  getSessionId,
  getSessionUser,
  isAuthenticated,
  requestUser,
  deleteSession,
  startSessionCleanup,
  setAuthCookie,
  clearAuthCookie,
  sendLoginPage,
};
