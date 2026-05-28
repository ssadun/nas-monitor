'use strict';

const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

let _logError = () => {};
let _logInfo  = () => {};
let _logWarn  = () => {};
let _auditLog = () => {};
let _getCache = () => ({});
let _refreshCache = async () => {};
let _appSettings = () => ({});
let _resetRefreshTimer = () => {};
let _updateAppSettings = () => {};
let _disk = null;
let _prune = null;
let _imageUpdates = null;
let _auth = null;
let _formatBytes = (b) => String(b);
let _DOCKER = '';
let _diskScanHistory = () => [];
let _setDiskScanHistory = () => {};

function setDependencies(deps = {}) {
  if (deps.logError)           _logError           = deps.logError;
  if (deps.logInfo)            _logInfo            = deps.logInfo;
  if (deps.logWarn)            _logWarn            = deps.logWarn;
  if (deps.auditLog)           _auditLog           = deps.auditLog;
  if (deps.getCache)           _getCache           = deps.getCache;
  if (deps.refreshCache)       _refreshCache       = deps.refreshCache;
  if (deps.appSettings)        _appSettings        = deps.appSettings;
  if (deps.resetRefreshTimer)  _resetRefreshTimer  = deps.resetRefreshTimer;
  if (deps.updateAppSettings)  _updateAppSettings  = deps.updateAppSettings;
  if (deps.disk)               _disk               = deps.disk;
  if (deps.prune)              _prune              = deps.prune;
  if (deps.imageUpdates)       _imageUpdates       = deps.imageUpdates;
  if (deps.auth)               _auth               = deps.auth;
  if (deps.formatBytes)        _formatBytes        = deps.formatBytes;
  if (deps.DOCKER)             _DOCKER             = deps.DOCKER;
  if (deps.diskScanHistory)    _diskScanHistory    = deps.diskScanHistory;
  if (deps.setDiskScanHistory) _setDiskScanHistory = deps.setDiskScanHistory;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonOk(res, data) {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache' });
  res.end(JSON.stringify(data));
}

function jsonErr(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => resolve(body));
  });
}

const shellQuote = (v) => `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;

// ─── /api/data ────────────────────────────────────────────────────────────────

async function handleData(req, res) {
  jsonOk(res, _getCache());
}

async function handleDataRefresh(req, res, reqUser) {
  try {
    await _refreshCache();
    jsonOk(res, _getCache());
  } catch (e) {
    _logError('API refresh failed', { error: e.message || 'refresh failed', user: reqUser });
    jsonErr(res, 500, { error: e.message || 'refresh failed' });
  }
}

// ─── /api/stream ──────────────────────────────────────────────────────────────

function handleStream(req, res) {
  const settings = _appSettings();
  const intervalMs = settings.refreshIntervalSeconds * 1000;
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write(`retry: ${intervalMs}\n\n`);
  const send = () => {
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({ ..._getCache(), refreshIntervalSeconds: settings.refreshIntervalSeconds })}\n\n`);
    }
  };
  send();
  const iv = setInterval(send, intervalMs);
  req.on('close', () => clearInterval(iv));
}

// ─── /api/disk ────────────────────────────────────────────────────────────────

async function handleDisk(req, res, url) {
  try {
    const scanPath = url.searchParams.get('path') || '/volume1';
    const maxDepth = Math.min(parseInt(url.searchParams.get('depth') || '4'), 8);
    const safe = scanPath.replace(/\.\./g, '').replace(/\/+/g, '/') || '/volume1';
    const data = await _disk.collectUsage(safe, maxDepth);
    let history = _diskScanHistory();
    history.unshift({ ...data, id: Date.now() });
    if (history.length > _disk.DISK_HISTORY_MAX) history.pop();
    _disk.saveHistory(history);
    _setDiskScanHistory(history);
    jsonOk(res, data);
  } catch (e) {
    jsonOk(res, { error: e.message, tree: null, topFiles: [] });
  }
}

function handleDiskHistory(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(_diskScanHistory().map(s => ({
    id: s.id, path: s.path, scannedAt: s.scannedAt,
    totalBytes: s.tree ? s.tree.sizeBytes : 0,
    error: s.error,
  }))));
}

function handleDiskHistoryGet(req, res, id) {
  const scan = _diskScanHistory().find(s => s.id === id);
  res.writeHead(scan ? 200 : 404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(scan || { error: 'Not found' }));
}

async function handleDiskHistoryDelete(req, res, id, reqUser) {
  if (!id) {
    jsonErr(res, 400, { ok: false, error: 'Invalid scan id' });
    return;
  }
  let history = _diskScanHistory();
  const before = history.length;
  history = history.filter(s => s.id !== id);
  if (history.length === before) {
    jsonErr(res, 404, { ok: false, error: 'Scan not found' });
    return;
  }
  try {
    _disk.saveHistory(history);
    _setDiskScanHistory(history);
    _logInfo('Disk scan history entry deleted', { user: reqUser, scanId: id, remaining: history.length });
    jsonOk(res, { ok: true, remaining: history.length });
  } catch (e) {
    _logError('Failed to persist disk history delete', { user: reqUser, scanId: id, error: e.message });
    jsonErr(res, 500, { ok: false, error: e.message });
  }
}

// ─── /api/logs/:id ────────────────────────────────────────────────────────────

function handleLogs(req, res, id) {
  if (!id) { res.writeHead(400); res.end(); return; }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write('retry: 2000\n\n');
  const tail = spawn(_DOCKER, ['logs', '--tail', '200', '--follow', '--timestamps', id]);
  const send = (data) => {
    if (!res.writableEnded) {
      const lines = data.toString().split('\n').filter(Boolean);
      for (const line of lines) res.write(`data: ${JSON.stringify(line)}\n\n`);
    }
  };
  tail.stdout.on('data', send);
  tail.stderr.on('data', send);
  tail.on('error', (e) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify('[Error: ' + e.message + ']')}\n\n`);
  });
  req.on('close', () => { try { tail.kill(); } catch {} });
}

// ─── /api/prune ───────────────────────────────────────────────────────────────

async function handlePruneScan(req, res) {
  try {
    const data = await _prune.scanUnused();
    jsonOk(res, data);
  } catch (e) {
    jsonOk(res, { error: e.message });
  }
}

async function handlePruneRun(req, res, reqUser) {
  const body = await readBody(req);
  try {
    const selected = JSON.parse(body);
    const summary = await _prune.runPrune(selected);
    _auditLog('prune_run', { user: reqUser, details: Object.keys(selected).filter(k => selected[k]).join(','), status: 'success' }, req);
    jsonOk(res, { ok: true, summary });
  } catch (e) {
    _auditLog('prune_run', { user: reqUser, status: 'failed', error: e.message }, req);
    jsonOk(res, { ok: false, error: e.message });
  }
}

function handlePruneLog(req, res) {
  try {
    const raw = fs.existsSync(_prune.PRUNE_LOG_FILE) ? fs.readFileSync(_prune.PRUNE_LOG_FILE, 'utf8') : '';
    jsonOk(res, { log: raw });
  } catch (e) {
    _logError('Failed to read prune log file', { error: e.message });
    jsonOk(res, { log: '' });
  }
}

// ─── /api/image-updates ──────────────────────────────────────────────────────

async function handleImageUpdateScan(req, res, reqUser) {
  _imageUpdates.appendLog([`USER SCAN  user=${reqUser || 'unknown'}`]);
  try {
    const data = await _imageUpdates.scanUpdates();
    const updates = data.filter(r => r.updateAvailable).length;
    const errors = data.filter(r => r.error).length;
    _imageUpdates.appendLog([`SCAN OK    ${data.length} images checked, ${updates} updates, ${errors} errors`]);
    jsonOk(res, { ok: true, results: data });
  } catch (e) {
    _imageUpdates.appendLog([`SCAN FAIL  ${e.message}`]);
    jsonOk(res, { ok: false, error: e.message });
  }
}

async function handleImageUpdatePull(req, res, reqUser) {
  const body = await readBody(req);
  try {
    const { image, restart, containers } = JSON.parse(body);
    if (!image) { jsonOk(res, { ok: false, error: 'image required' }); return; }
    const action = restart ? 'PULL+RESTART' : 'PULL';
    _imageUpdates.appendLog([`USER ${action}  user=${reqUser || 'unknown'} image=${image}`]);
    const result = await _imageUpdates.pullImage(image);
    if (result.ok && restart && Array.isArray(containers)) {
      const restartResults = [];
      for (const ctr of containers) {
        if (!ctr) continue;
        try {
          const out = await new Promise((resolve) => {
            const docker = require('./docker.js');
            resolve(docker.runDocker ? docker.runDocker(`restart ${ctr}`) : '');
          });
          restartResults.push({ container: ctr, ok: true });
          _imageUpdates.appendLog([`RESTART OK  container=${ctr}`]);
        } catch (e) {
          restartResults.push({ container: ctr, ok: false, error: e.message });
          _imageUpdates.appendLog([`RESTART FAIL  container=${ctr} error=${e.message}`]);
        }
      }
      result.restartResults = restartResults;
    }
    _auditLog('image_pull', { user: reqUser, image, restart: !!restart, status: result.ok ? 'success' : 'failed' }, req);
    jsonOk(res, result);
  } catch (e) {
    _imageUpdates.appendLog([`PULL ERROR  image=${image || 'unknown'} error=${e.message}`]);
    jsonOk(res, { ok: false, error: e.message });
  }
}

function handleImageUpdateLog(req, res) {
  try {
    const raw = fs.existsSync(_imageUpdates.UPDATE_LOG_FILE)
      ? fs.readFileSync(_imageUpdates.UPDATE_LOG_FILE, 'utf8')
      : '';
    jsonOk(res, { log: raw });
  } catch (e) {
    jsonOk(res, { log: '' });
  }
}

// ─── /api/settings ────────────────────────────────────────────────────────────

function handleSettingsGet(req, res) {
  jsonOk(res, { ok: true, settings: _appSettings() });
}

async function handleSettingsPost(req, res, reqUser, saveSettingsFile, prune) {
  const body = await readBody(req);
  try {
    const input = JSON.parse(body || '{}');
    const previous = { ..._appSettings() };
    const updated = saveSettingsFile({ ..._appSettings(), ...input });
    _updateAppSettings(updated);
    const changed = Object.keys(updated).filter(k => updated[k] !== previous[k]);
    _auditLog('settings_change', {
      user: reqUser,
      status: 'success',
      details: changed.map(k => `${k}: ${JSON.stringify(previous[k])} → ${JSON.stringify(updated[k])}`).join(', '),
    }, req);
    _logInfo('Application settings updated', {
      user: reqUser,
      logLevel: updated.logLevel,
      authenticationType: updated.authenticationType,
      warnThresholdSeconds: updated.warnThresholdSeconds,
      pruneIntervalHours: updated.pruneIntervalHours,
      composeInactivityTimeoutSeconds: updated.composeInactivityTimeoutSeconds,
      configFolders: updated.configFolders,
      dataFolders: updated.dataFolders,
    });
    if (previous.authenticationType !== updated.authenticationType) {
      _logInfo('Authentication mode changed', { previous: previous.authenticationType, current: updated.authenticationType });
    }
    if (previous.pruneIntervalHours !== updated.pruneIntervalHours) {
      prune.scheduleAutoPrune();
      _logInfo('Auto-prune interval changed', { previousHours: previous.pruneIntervalHours, currentHours: updated.pruneIntervalHours });
    }
    if (previous.imageUpdateIntervalHours !== updated.imageUpdateIntervalHours ||
        previous.imageUpdateAutoApply     !== updated.imageUpdateAutoApply ||
        previous.imageUpdateAutoRestart   !== updated.imageUpdateAutoRestart) {
      if (_imageUpdates) _imageUpdates.scheduleImageUpdateCheck();
      _logInfo('Image update settings changed', { interval: updated.imageUpdateIntervalHours, autoApply: updated.imageUpdateAutoApply, autoRestart: updated.imageUpdateAutoRestart });
    }
    if (previous.composeInactivityTimeoutSeconds !== updated.composeInactivityTimeoutSeconds) {
      _logInfo('Compose inactivity timeout changed', { previousSeconds: previous.composeInactivityTimeoutSeconds, currentSeconds: updated.composeInactivityTimeoutSeconds });
    }
    if (previous.refreshIntervalSeconds !== updated.refreshIntervalSeconds) {
      _resetRefreshTimer();
      _logInfo('Refresh interval changed', { previousSeconds: previous.refreshIntervalSeconds, currentSeconds: updated.refreshIntervalSeconds });
    }
    jsonOk(res, { ok: true, settings: updated });
  } catch (e) {
    _logError('Failed to update settings', { error: e.message, user: reqUser });
    _auditLog('settings_change', { user: reqUser, status: 'failed', details: e.message }, req);
    jsonOk(res, { ok: false, error: e.message });
  }
}

// ─── /api/change-credentials ─────────────────────────────────────────────────

async function handleChangeCredentials(req, res, reqUser) {
  const body = await readBody(req);
  try {
    const { currentPassword, newUsername, newPassword } = JSON.parse(body);
    const creds = _auth.loadCredentials();
    const currentUser = creds ? creds.username : '';
    if (creds && !_auth.checkCredentials(currentUser, currentPassword || '')) {
      _logWarn('Credential change failed due to invalid current password', { user: reqUser });
      _auditLog('credentials_change', { user: reqUser, status: 'failed', details: 'invalid current password' }, req);
      jsonOk(res, { ok: false, error: 'Current password is incorrect.' });
      return;
    }
    if (!newUsername || newUsername.trim().length < 1) {
      jsonOk(res, { ok: false, error: 'Username cannot be empty.' });
      return;
    }
    if (!newPassword || newPassword.length < 8) {
      jsonOk(res, { ok: false, error: 'New password must be at least 8 characters.' });
      return;
    }
    _auth.saveCredentials(newUsername.trim(), newPassword);
    _logInfo('Credentials updated', { user: reqUser, newUsername: newUsername.trim() });
    _auditLog('credentials_change', { user: reqUser, details: newUsername.trim(), status: 'success' }, req);
    jsonOk(res, { ok: true });
  } catch (e) {
    _logError('Failed to change credentials', { error: e.message, user: reqUser });
    jsonOk(res, { ok: false, error: e.message });
  }
}

// ─── /api/network/* ───────────────────────────────────────────────────────────

async function handleNetworkList(req, res) {
  try {
    const systemNetworks = new Set(['bridge', 'host', 'none']);
    const output = await execAsync(`"${_DOCKER}" network ls --format '{{json .}}'`, { timeout: 10000 });
    const listed = output.stdout
      .split('\n')
      .filter(line => line.trim())
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(n => n && !systemNetworks.has(n.Name));

    if (!listed.length) { jsonOk(res, []); return; }

    const namesArg = listed.map(n => shellQuote(n.Name)).join(' ');
    let inspectByName = {};
    try {
      const { stdout } = await execAsync(`"${_DOCKER}" network inspect ${namesArg}`, { timeout: 10000 });
      const inspected = JSON.parse(stdout || '[]');
      inspectByName = Object.fromEntries((Array.isArray(inspected) ? inspected : []).map(n => [n.Name, n]));
    } catch {}

    const networks = listed.map(n => {
      const inspected = inspectByName[n.Name] || {};
      const ipamCfg = Array.isArray(inspected?.IPAM?.Config) ? inspected.IPAM.Config : [];
      const subnet = (ipamCfg.find(cfg => cfg && cfg.Subnet) || {}).Subnet || '';
      const containers = Object.values(inspected.Containers || {}).map(c => c?.Name).filter(Boolean);
      return { name: n.Name, id: n.ID, driver: n.Driver || inspected.Driver || '', scope: n.Scope || inspected.Scope || '', subnet, containers };
    });
    jsonOk(res, networks);
  } catch (e) {
    jsonOk(res, []);
  }
}

async function handleNetworkCreate(req, res) {
  const body = await readBody(req);
  try {
    const { name, driver, subnet } = JSON.parse(body);
    if (!name) { jsonOk(res, { ok: false, error: 'Network name required' }); return; }
    if (['bridge', 'host', 'none'].includes(name)) { jsonOk(res, { ok: false, error: 'Cannot create network with system name' }); return; }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(name)) { jsonOk(res, { ok: false, error: 'Invalid network name format' }); return; }
    let cmd = `"${_DOCKER}" network create --driver ${shellQuote(driver || 'bridge')}`;
    if (subnet) cmd += ` --subnet ${shellQuote(subnet)}`;
    cmd += ` ${shellQuote(name)}`;
    try {
      const { stdout } = await execAsync(cmd, { timeout: 15000 });
      jsonOk(res, { ok: true, id: stdout.trim(), message: `Network "${name}" created successfully` });
    } catch (e) {
      jsonOk(res, { ok: false, error: e.message });
    }
  } catch (e) {
    jsonOk(res, { ok: false, error: 'Invalid request: ' + e.message });
  }
}

async function handleNetworkUpdate(req, res) {
  const body = await readBody(req);
  try {
    const { name, driver, subnet } = JSON.parse(body);
    if (!name) { jsonOk(res, { ok: false, error: 'Network name required' }); return; }
    if (['bridge', 'host', 'none'].includes(name)) { jsonOk(res, { ok: false, error: 'Cannot edit system network' }); return; }

    let inspect;
    try {
      const { stdout } = await execAsync(`"${_DOCKER}" network inspect ${shellQuote(name)}`, { timeout: 10000 });
      const arr = JSON.parse(stdout || '[]');
      inspect = Array.isArray(arr) ? arr[0] : null;
    } catch { inspect = null; }
    if (!inspect) { jsonOk(res, { ok: false, error: `Network "${name}" not found` }); return; }

    const targetDriver = driver || inspect.Driver || 'bridge';
    const currentSubnet = (Array.isArray(inspect?.IPAM?.Config) ? inspect.IPAM.Config : []).find(cfg => cfg?.Subnet)?.Subnet || '';
    const targetSubnet = subnet || '';
    if ((inspect.Driver || '') === targetDriver && currentSubnet === targetSubnet) {
      jsonOk(res, { ok: true, message: 'No changes detected' }); return;
    }

    const containers = Object.values(inspect.Containers || {}).map(c => c?.Name).filter(Boolean);
    for (const c of containers) {
      try { await execAsync(`"${_DOCKER}" network disconnect -f ${shellQuote(name)} ${shellQuote(c)}`, { timeout: 10000 }); } catch {}
    }
    await execAsync(`"${_DOCKER}" network rm ${shellQuote(name)}`, { timeout: 10000 });

    let createCmd = `"${_DOCKER}" network create --driver ${shellQuote(targetDriver)}`;
    if (targetSubnet) createCmd += ` --subnet ${shellQuote(targetSubnet)}`;
    createCmd += ` ${shellQuote(name)}`;
    await execAsync(createCmd, { timeout: 15000 });

    const reconnectErrors = [];
    for (const c of containers) {
      try { await execAsync(`"${_DOCKER}" network connect ${shellQuote(name)} ${shellQuote(c)}`, { timeout: 10000 }); }
      catch (e) { reconnectErrors.push(`${c}: ${e.message}`); }
    }
    jsonOk(res, {
      ok: true,
      message: reconnectErrors.length ? `Network "${name}" updated, but some containers failed to reconnect` : `Network "${name}" updated successfully`,
      reconnectErrors,
    });
  } catch (e) {
    jsonOk(res, { ok: false, error: e.message });
  }
}

async function handleNetworkDelete(req, res) {
  const body = await readBody(req);
  try {
    const { name } = JSON.parse(body);
    if (!name) { jsonOk(res, { ok: false, error: 'Network name required' }); return; }
    if (['bridge', 'host', 'none'].includes(name)) { jsonOk(res, { ok: false, error: 'Cannot delete system network' }); return; }
    try {
      await execAsync(`"${_DOCKER}" network rm ${shellQuote(name)}`, { timeout: 10000 });
      jsonOk(res, { ok: true, message: `Network "${name}" deleted successfully` });
    } catch (e) {
      jsonOk(res, { ok: false, error: e.message });
    }
  } catch (e) {
    jsonOk(res, { ok: false, error: 'Invalid request: ' + e.message });
  }
}

// ─── /api/health ──────────────────────────────────────────────────────────────

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

async function handleHealth(req, res, CREDENTIALS_FILE) {
  try {
    const pkgPath = path.join(__dirname, '..', 'package.json');
    const pkg = fs.existsSync(pkgPath) ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : { version: 'dev' };
    const diskSpace = await checkDiskSpace();
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    const health = {
      status: 'healthy',
      uptime: process.uptime(),
      version: pkg.version,
      checks: {
        dockerAvailable: fs.existsSync(_DOCKER),
        credentialsExists: fs.existsSync(CREDENTIALS_FILE),
        diskSpace,
        memory: {
          rss: _formatBytes(memUsage.rss),
          heapUsed: _formatBytes(memUsage.heapUsed),
          heapTotal: _formatBytes(memUsage.heapTotal),
        },
        cpu: { userMs: cpuUsage.user, systemMs: cpuUsage.system },
      },
    };
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(health));
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'error', error: e.message }));
  }
}

// ─── /api/homepage/widget ────────────────────────────────────────────────────

function parseFormattedBytes(str) {
	if (!str) return 0;
	const match = String(str).match(/^([\d.]+)\s*(B|Ki?B|Mi?B|Gi?B|Ti?B)$/i);
	if (!match) return 0;
	const val = parseFloat(match[1]);
	const unit = match[2].toUpperCase().replace('IB', 'B');
	const mult = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
	return val * (mult[unit] || 1);
}

async function handleHomepageWidget(req, res) {
	const { containers } = _getCache();
	const running = containers.filter(c => c.state === 'running');

	const cpuPercent = running.reduce((sum, c) => sum + (parseFloat(c.cpu) || 0), 0);
	const memBytes = running.reduce((sum, c) => sum + parseFormattedBytes(c.memUsage), 0);

	const seenImages = new Set();
	let imageSizeBytes = 0;
	for (const c of containers) {
		const key = c.image || c.id;
		if (!seenImages.has(key) && c.imageSize) {
			seenImages.add(key);
			imageSizeBytes += parseFormattedBytes(c.imageSize);
		}
	}

	const netRxKBs = running.reduce((sum, c) => sum + (c.vethRxKBs || 0), 0);
	const netTxKBs = running.reduce((sum, c) => sum + (c.vethTxKBs || 0), 0);

	jsonOk(res, {
		containers: {
			running: running.length,
			total: containers.length,
			cpu_percent: parseFloat(cpuPercent.toFixed(1)),
			memory_gb: parseFloat((memBytes / 1024 ** 3).toFixed(2)),
			image_size_gb: parseFloat((imageSizeBytes / 1024 ** 3).toFixed(2)),
			net_rx_kbs: parseFloat(netRxKBs.toFixed(2)),
			net_tx_kbs: parseFloat(netTxKBs.toFixed(2)),
		},
	});
}

// ─── Main router ──────────────────────────────────────────────────────────────

async function handleApi(req, res, url, reqUser, { saveSettingsFile, prune, CREDENTIALS_FILE }) {
  const { pathname } = url;
  const method = req.method;

  if (pathname === '/api/data')                                         { await handleData(req, res); return true; }
  if (pathname === '/api/data/refresh')                                 { await handleDataRefresh(req, res, reqUser); return true; }
  if (pathname === '/api/stream')                                       { handleStream(req, res); return true; }
  if (pathname === '/api/disk' && method === 'GET')                     { await handleDisk(req, res, url); return true; }
  if (pathname === '/api/disk/history' && method === 'GET')             { handleDiskHistory(req, res); return true; }
  if (pathname.startsWith('/api/disk/history/') && method === 'GET') {
    const id = parseInt(pathname.split('/').pop());
    handleDiskHistoryGet(req, res, id); return true;
  }
  if (pathname.startsWith('/api/disk/history/') && method === 'DELETE') {
    const id = parseInt(pathname.split('/').pop());
    await handleDiskHistoryDelete(req, res, id, reqUser); return true;
  }
  if (pathname.startsWith('/api/logs/'))                                { const id = pathname.split('/')[3]; handleLogs(req, res, id); return true; }
  if (pathname === '/api/prune/scan')                                   { await handlePruneScan(req, res); return true; }
  if (pathname === '/api/prune/run' && method === 'POST')               { await handlePruneRun(req, res, reqUser); return true; }
  if (pathname === '/api/prune/log')                                    { handlePruneLog(req, res); return true; }
  if (pathname === '/api/image-updates/scan')                           { await handleImageUpdateScan(req, res, reqUser); return true; }
  if (pathname === '/api/image-updates/pull' && method === 'POST')      { await handleImageUpdatePull(req, res, reqUser); return true; }
  if (pathname === '/api/image-updates/log')                            { handleImageUpdateLog(req, res); return true; }
  if (pathname === '/api/settings' && method === 'GET')                 { handleSettingsGet(req, res); return true; }
  if (pathname === '/api/settings' && method === 'POST')                { await handleSettingsPost(req, res, reqUser, saveSettingsFile, prune); return true; }
  if (pathname === '/api/change-credentials' && method === 'POST')      { await handleChangeCredentials(req, res, reqUser); return true; }
  if (pathname === '/api/network/list' && method === 'GET')             { await handleNetworkList(req, res); return true; }
  if (pathname === '/api/network/create' && method === 'POST')          { await handleNetworkCreate(req, res); return true; }
  if (pathname === '/api/network/update' && method === 'POST')          { await handleNetworkUpdate(req, res); return true; }
  if (pathname === '/api/network/delete' && method === 'POST')          { await handleNetworkDelete(req, res); return true; }
  if (pathname === '/api/health')                                       { await handleHealth(req, res, CREDENTIALS_FILE); return true; }

  return false;
}

module.exports = { setDependencies, handleApi, handleHomepageWidget };
