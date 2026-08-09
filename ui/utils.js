'use strict';

// ─── Session-expiry handling ───────────────────────────────────────────────
// Any API call can come back 401 once the session cookie expires while the
// SPA is still open. Intercept it once here instead of at each of the ~60
// fetch() call sites, and bounce to the login page with a message instead of
// leaving the raw "Authentication required" JSON on screen.
let _authRedirecting = false;
function redirectToExpiredLogin() {
  if (_authRedirecting) return;
  _authRedirecting = true;
  window.location.href = '/login?expired=1';
}

const _nativeFetch = window.fetch.bind(window);
window.fetch = async function (...args) {
  const res = await _nativeFetch(...args);
  if (res.status === 401) {
    redirectToExpiredLogin();
    return new Promise(() => {}); // navigation is imminent; don't let callers handle a 401
  }
  return res;
};

function el(id) { return document.getElementById(id); }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}

let _toastTimer = null;
function showToast(message, type = 'ok', ms = 2600) {
  const node = el('app-toast');
  if (!node) return;
  node.textContent = message;
  node.className = `app-toast ${type === 'err' ? 'err' : 'ok'} show`;
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => {
    node.classList.remove('show');
  }, ms);
}

function fmtBytes(b) {
  if (!b) return '0B';
  const u = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (b >= 1024 && i < u.length-1) { b/=1024; i++; }
  return b.toFixed(1)+u[i];
}

function fmtUptime(s) {
  const d = Math.floor(s/86400);
  const h = Math.floor((s%86400)/3600);
  const m = Math.floor((s%3600)/60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtDate(iso) {
  if (!iso) return '–';
  try {
    const d = new Date(iso);
    const now = new Date();
    if (now - d < 86400000) return d.toLocaleTimeString();
    return d.toLocaleDateString();
  } catch { return iso; }
}

function fmtFileDate(ms) {
  if (!ms) return '–';
  const d = new Date(ms);
  const now = new Date();
  const diff = now - d;
  if (diff < 86400000) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
}

function fileDateAge(ms) {
  if (!ms) return '';
  const diff = Date.now() - ms;
  const days = Math.floor(diff / 86400000);
  if (days === 0) return 'today';
  if (days === 1) return '1d ago';
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

function stateLabel(s) {
  const m = { S:'Sleep', R:'Run', D:'Disk', Z:'Zombie', T:'Stop', I:'Idle' };
  return m[s] || s || '–';
}

function cpuColor(v) {
  if (v >= 80) return 'red';
  if (v >= 50) return 'orange';
  if (v >= 20) return 'yellow';
  return 'green';
}
function cpuColorClass(v) {
  if (v >= 80) return 'critical';
  if (v >= 50) return 'high';
  return '';
}
function memColor(v) {
  if (v >= 90) return 'red';
  if (v >= 70) return 'orange';
  if (v >= 50) return 'yellow';
  return 'steel';
}
function memColorClass(v) {
  if (v >= 80) return 'critical';
  if (v >= 60) return 'high';
  return '';
}

function parseMemUsage(str) {
  if (!str) return 0;
  const m = str.match(/^([\d.]+)\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)?/i);
  if (!m) return 0;
  const val = parseFloat(m[1]);
  const unit = (m[2]||'B').toLowerCase();
  const map = { b:1, kb:1e3, kib:1024, mb:1e6, mib:1048576, gb:1e9, gib:1073741824, tb:1e12, tib:1099511627776 };
  return val * (map[unit] || 1);
}

function parseImgSize(str) {
  return parseMemUsage(str);
}

function cpuHex(v) {
  if (v >= 80) return 'var(--red)';
  if (v >= 50) return 'var(--orange)';
  if (v >= 20) return 'var(--yellow)';
  return 'var(--green)';
}
