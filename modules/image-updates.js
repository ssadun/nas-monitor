'use strict';

const fs   = require('fs');
const path = require('path');
const https = require('https');
const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const UPDATE_LOG_FILE    = path.join(__dirname, '..', 'logs', 'image-updates.log');
const UPDATE_LOG_RETAIN_DAYS = 30;
const UPDATE_STATE_FILE  = path.join(__dirname, '..', 'data', 'image-update-state.json');

let logError    = () => {};
let logInfo     = () => {};
let runDocker   = async () => '';
let DOCKER      = 'docker';
let getSettings = () => ({});

// Registry credentials: { "registry.example.com": { username, password } }
// keyed by registry hostname; "" or "docker.io" = Docker Hub
let _registryCredentials = {};

function setDependencies(deps = {}) {
  if (deps.logError)    logError    = deps.logError;
  if (deps.logInfo)     logInfo     = deps.logInfo;
  if (deps.runDocker)   runDocker   = deps.runDocker;
  if (deps.DOCKER)      DOCKER      = deps.DOCKER;
  if (deps.getSettings) getSettings = deps.getSettings;
}

function setRegistryCredentials(creds) {
  _registryCredentials = creds || {};
}

// ─── Log helpers ─────────────────────────────────────────────────────────────

function appendLog(lines) {
  try {
    const now = new Date().toISOString();
    const text = lines.map(l => `[${now}] ${l}`).join('\n') + '\n';
    fs.appendFileSync(UPDATE_LOG_FILE, text, 'utf8');
    const raw = fs.readFileSync(UPDATE_LOG_FILE, 'utf8');
    const cutoff = Date.now() - UPDATE_LOG_RETAIN_DAYS * 86400000;
    const kept = raw.split('\n').filter(line => {
      const m = line.match(/^\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\]/);
      if (!m) return false;
      return new Date(m[1]).getTime() > cutoff;
    });
    fs.writeFileSync(UPDATE_LOG_FILE, kept.join('\n') + (kept.length ? '\n' : ''), 'utf8');
  } catch (e) {
    logError('Failed to write image-updates log', { error: e.message });
  }
}

// ─── Scan state persistence (survives process restarts) ──────────────────────

function readLastRun() {
  try {
    const raw = JSON.parse(fs.readFileSync(UPDATE_STATE_FILE, 'utf8'));
    return typeof raw.lastRun === 'number' ? raw.lastRun : 0;
  } catch { return 0; }
}

function writeLastRun(ts) {
  try {
    fs.writeFileSync(UPDATE_STATE_FILE, JSON.stringify({ lastRun: ts }, null, 2), 'utf8');
  } catch (e) {
    logError('Failed to write image-update state', { error: e.message });
  }
}

// ─── Registry helpers ────────────────────────────────────────────────────────

function parseImageRef(imageRef) {
  // Returns { registry, repository, tag, digest }
  // imageRef examples:
  //   nginx:latest
  //   ghcr.io/user/repo:v1.2
  //   registry.example.com:5000/myimage@sha256:abc
  let ref = imageRef.trim();
  let digest = '';
  const atIdx = ref.lastIndexOf('@');
  if (atIdx !== -1) { digest = ref.slice(atIdx + 1); ref = ref.slice(0, atIdx); }

  let registry = '';
  let rest = ref;
  // If first segment contains a dot or colon (and isn't just a tag), it's a registry
  const slashIdx = ref.indexOf('/');
  if (slashIdx !== -1) {
    const first = ref.slice(0, slashIdx);
    if (first.includes('.') || first.includes(':') || first === 'localhost') {
      registry = first;
      rest = ref.slice(slashIdx + 1);
    }
  }

  const colonIdx = rest.lastIndexOf(':');
  let repository, tag;
  if (colonIdx !== -1 && !rest.slice(colonIdx + 1).includes('/')) {
    repository = rest.slice(0, colonIdx);
    tag = rest.slice(colonIdx + 1);
  } else {
    repository = rest;
    tag = 'latest';
  }

  // Docker Hub official images: nginx → library/nginx
  if (!registry && !repository.includes('/')) {
    repository = 'library/' + repository;
  }

  return { registry: registry || 'docker.io', repository, tag, digest };
}

function httpsGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const req = https.request({
      hostname: opts.hostname,
      path: opts.pathname + (opts.search || ''),
      method: 'GET',
      headers: { 'User-Agent': 'nas-monitor/1.0', ...headers },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(new Error('timeout')); });
    req.end();
  });
}

async function getDockerHubToken(repository) {
  const creds = _registryCredentials['docker.io'] || _registryCredentials[''] || null;
  let scope = `repository:${repository}:pull`;
  let authUrl = `https://auth.docker.io/token?service=registry.docker.io&scope=${encodeURIComponent(scope)}`;
  const headers = {};
  if (creds) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`).toString('base64');
  }
  const res = await httpsGet(authUrl, headers);
  if (res.status !== 200) throw new Error(`Docker Hub auth failed: ${res.status}`);
  return JSON.parse(res.body).token;
}

async function getGhcrToken(repository) {
  const creds = _registryCredentials['ghcr.io'] || null;
  const scope = `repository:${repository}:pull`;
  let authUrl = `https://ghcr.io/token?service=ghcr.io&scope=${encodeURIComponent(scope)}`;
  const headers = {};
  if (creds) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`).toString('base64');
  }
  const res = await httpsGet(authUrl, headers);
  if (res.status !== 200) {
    // GHCR may not need a token for public images — try anonymous
    return null;
  }
  try { return JSON.parse(res.body).token; } catch { return null; }
}

async function getRegistryDigest(parsed) {
  const { registry, repository, tag } = parsed;

  // Accept header for manifest digest — supports both v2 and OCI
  const ACCEPT = [
    'application/vnd.docker.distribution.manifest.v2+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.oci.image.index.v1+json',
  ].join(', ');

  if (registry === 'docker.io') {
    const token = await getDockerHubToken(repository);
    const url = `https://registry-1.docker.io/v2/${repository}/manifests/${tag}`;
    const res = await httpsGet(url, {
      'Authorization': `Bearer ${token}`,
      'Accept': ACCEPT,
    });
    if (res.status !== 200) throw new Error(`Docker Hub manifest fetch failed: ${res.status}`);
    return res.headers['docker-content-digest'] || null;
  }

  if (registry === 'ghcr.io') {
    const token = await getGhcrToken(repository);
    const url = `https://ghcr.io/v2/${repository}/manifests/${tag}`;
    const headers = { 'Accept': ACCEPT };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await httpsGet(url, headers);
    if (res.status !== 200) throw new Error(`GHCR manifest fetch failed: ${res.status}`);
    return res.headers['docker-content-digest'] || null;
  }

  // Generic registry — try the manifest directly, then follow a Bearer token
  // challenge if the registry demands one (e.g. lscr.io, ghcr-backed registries).
  const creds = _registryCredentials[registry] || null;
  const basicAuth = creds
    ? 'Basic ' + Buffer.from(`${creds.username}:${creds.password}`).toString('base64')
    : null;
  const url = `https://${registry}/v2/${repository}/manifests/${tag}`;
  const headers = { 'Accept': ACCEPT };
  if (basicAuth) headers['Authorization'] = basicAuth;

  let res = await httpsGet(url, headers);
  if (res.status === 401) {
    const token = await getBearerToken(res.headers['www-authenticate'], repository, basicAuth);
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      res = await httpsGet(url, headers);
    }
  }
  if (res.status !== 200) throw new Error(`Registry ${registry} manifest fetch failed: ${res.status}`);
  return res.headers['docker-content-digest'] || null;
}

// Parse a `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge
// and exchange it for a token via the advertised realm.
async function getBearerToken(wwwAuthenticate, repository, basicAuth) {
  if (!wwwAuthenticate || !/^bearer/i.test(wwwAuthenticate.trim())) return null;
  const params = {};
  for (const part of wwwAuthenticate.replace(/^[Bb]earer\s+/, '').split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    params[part.slice(0, eq).trim()] = part.slice(eq + 1).trim().replace(/^"|"$/g, '');
  }
  if (!params.realm) return null;

  const query = [];
  if (params.service) query.push('service=' + encodeURIComponent(params.service));
  query.push('scope=' + encodeURIComponent(params.scope || `repository:${repository}:pull`));
  const tokenUrl = params.realm + (params.realm.includes('?') ? '&' : '?') + query.join('&');

  const authHeaders = {};
  if (basicAuth) authHeaders['Authorization'] = basicAuth;
  const res = await httpsGet(tokenUrl, authHeaders);
  if (res.status !== 200) return null;
  try {
    const body = JSON.parse(res.body);
    return body.token || body.access_token || null;
  } catch { return null; }
}

// ─── Local image digest ───────────────────────────────────────────────────────

async function getLocalDigest(imageRef) {
  try {
    const out = await runDocker(`inspect --format "{{index .RepoDigests 0}}" ${imageRef}`);
    const line = (out || '').trim().split('\n')[0].trim();
    if (!line || line === '<no value>') return null;
    // format: repo@sha256:abc
    const at = line.lastIndexOf('@');
    return at !== -1 ? line.slice(at + 1) : null;
  } catch { return null; }
}

// ─── Scan all running containers for updates ─────────────────────────────────

async function scanUpdates() {
  const results = [];

  // Get all images currently used by containers
  let imagesOut = '';
  try {
    imagesOut = await runDocker(`ps -a --format "{{json .}}"`);
  } catch { return results; }

  const seen = new Set();
  const containers = (imagesOut || '').split('\n').filter(Boolean).map(l => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);

  // Collect unique images across all containers
  const imageRefs = [];
  for (const c of containers) {
    const img = c.Image || '';
    if (!img || seen.has(img)) continue;
    seen.add(img);
    imageRefs.push({ image: img, containers: containers.filter(x => x.Image === img).map(x => x.Names || x.Name || '') });
  }

  for (const { image, containers: ctrs } of imageRefs) {
    const entry = await checkImageUpdate(image);
    entry.containers = ctrs.flat ? ctrs.flat() : ctrs;
    results.push(entry);
  }

  return results;
}

// ─── Check a single image for an update ──────────────────────────────────────

async function checkImageUpdate(imageRef) {
  const entry = {
    image: imageRef,
    localDigest: null,
    remoteDigest: null,
    updateAvailable: false,
    error: null,
    registry: null,
    tag: null,
  };
  if (!imageRef) { entry.error = 'image required'; return entry; }
  try {
    const parsed = parseImageRef(imageRef);
    entry.registry = parsed.registry;
    entry.tag      = parsed.tag;
    entry.localDigest  = await getLocalDigest(imageRef);
    entry.remoteDigest = await getRegistryDigest(parsed);
    if (entry.localDigest && entry.remoteDigest) {
      entry.updateAvailable = entry.localDigest !== entry.remoteDigest;
    } else if (!entry.localDigest && entry.remoteDigest) {
      entry.error = 'no local digest — cannot compare';
    }
  } catch (e) {
    entry.error = e.message;
  }
  return entry;
}

// ─── Pull an image ────────────────────────────────────────────────────────────

async function pullImage(imageRef) {
  return new Promise((resolve) => {
    const args = [DOCKER, 'pull', imageRef];
    // Spawn directly so we capture incremental output
    const proc = require('child_process').spawn(args[0], args.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    proc.stdout.on('data', d => { out += d.toString(); });
    proc.stderr.on('data', d => { err += d.toString(); });
    proc.on('close', code => {
      const combined = (out + err).trim();
      if (code === 0) {
        appendLog([`PULL OK  ${imageRef}`, combined.split('\n').slice(-3).join(' | ')]);
        resolve({ ok: true, output: combined });
      } else {
        appendLog([`PULL FAIL ${imageRef}: ${combined.split('\n').slice(-1)[0]}`]);
        resolve({ ok: false, error: combined });
      }
    });
    proc.on('error', e => {
      appendLog([`PULL ERROR ${imageRef}: ${e.message}`]);
      resolve({ ok: false, error: e.message });
    });
  });
}

// ─── Scheduler ───────────────────────────────────────────────────────────────

let _scheduleTimer = null;

function scheduleImageUpdateCheck() {
  if (_scheduleTimer) { clearTimeout(_scheduleTimer); _scheduleTimer = null; }
  const settings = getSettings();
  const hours = settings.imageUpdateIntervalHours;
  if (!hours || hours <= 0) return;

  const intervalMs = hours * 60 * 60 * 1000;
  // Base the next run on when the scan last actually ran (persisted to disk),
  // not on process start time — otherwise a daily service restart resets the
  // countdown every time and the scan never gets far enough to fire.
  const lastRun = readLastRun();
  const elapsed = lastRun ? Date.now() - lastRun : intervalMs;
  const ms = Math.max(0, Math.min(intervalMs, intervalMs - elapsed));

  logInfo('Image update check scheduled', { nextRunInMinutes: Math.round(ms / 60000) });

  _scheduleTimer = setTimeout(async () => {
    writeLastRun(Date.now());
    logInfo('Running scheduled image update check');
    appendLog(['─── Scheduled scan started ───']);
    try {
      const results = await scanUpdates();
      const updates = results.filter(r => r.updateAvailable);
      appendLog([`Scan complete: ${results.length} images checked, ${updates.length} updates available`]);
      if (updates.length) {
        appendLog(updates.map(r => `  UPDATE AVAILABLE: ${r.image}`));

        const autoUpdate = settings.imageUpdateAutoApply;
        const autoRestart = settings.imageUpdateAutoRestart;

        if (autoUpdate) {
          for (const r of updates) {
            appendLog([`Auto-pulling: ${r.image}`]);
            const result = await pullImage(r.image);
            if (result.ok && autoRestart) {
              // Restart containers using this image
              for (const ctrName of (r.containers || [])) {
                if (!ctrName) continue;
                try {
                  await runDocker(`restart ${ctrName}`);
                  appendLog([`Auto-restarted: ${ctrName}`]);
                } catch (e) {
                  appendLog([`Restart failed ${ctrName}: ${e.message}`]);
                }
              }
            }
          }
        }
      }
    } catch (e) {
      appendLog([`Scan failed: ${e.message}`]);
      logError('Scheduled image update check failed', { error: e.message });
    }
    scheduleImageUpdateCheck(); // reschedule
  }, ms);
}

module.exports = {
  setDependencies,
  setRegistryCredentials,
  scanUpdates,
  checkImageUpdate,
  pullImage,
  scheduleImageUpdateCheck,
  parseImageRef,
  UPDATE_LOG_FILE,
  appendLog,
};
