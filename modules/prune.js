'use strict';

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const { DEFAULT_SETTINGS } = require('./config.js');

const execAsync = promisify(exec);

const PRUNE_LOG_FILE = path.join(__dirname, '..', 'logs', 'prune.log');
const PRUNE_LOG_RETAIN_DAYS = 30;

let logError = () => {};
let logInfo  = () => {};
let runDocker = async () => '';
let DOCKER = 'docker';
let getSettings = () => ({});

function setDependencies(deps = {}) {
  if (deps.logError)    logError    = deps.logError;
  if (deps.logInfo)     logInfo     = deps.logInfo;
  if (deps.runDocker)   runDocker   = deps.runDocker;
  if (deps.DOCKER)      DOCKER      = deps.DOCKER;
  if (deps.getSettings) getSettings = deps.getSettings;
}

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

  // ── Images ──────────────────────────────────────────────────────────────────
  try {
    const allImgOut = await runDocker(`images --format '{{json .}}'`);
    const imageMap = {};
    if (allImgOut) {
      allImgOut.split('\n').filter(Boolean).forEach(l => {
        try {
          const img = JSON.parse(l);
          const shortId = (img.ID || '').replace('sha256:', '').slice(0, 12);
          imageMap[shortId] = img;
          imageMap[img.ID]  = img;
        } catch {}
      });
    }

    const imgIdsOut = await runDocker(`images -q`);
    if (imgIdsOut) {
      const shortIds = [...new Set(imgIdsOut.split('\n').filter(Boolean))];
      for (const imgId of shortIds) {
        const countOut = await runDocker(`ps -a -q --filter "ancestor=${imgId}"`);
        const count = countOut ? countOut.split('\n').filter(Boolean).length : 0;
        if (count === 0) {
          const img = imageMap[imgId] || imageMap[imgId.slice(0, 12)] || {};
          const repository = img.Repository || '';
          const tag        = img.Tag        || '';
          const size       = img.Size       || '';
          const created    = img.CreatedSince || '';
          const name = (repository && repository !== '<none>')
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

  // ── Networks ─────────────────────────────────────────────────────────────────
  try {
    const netLs = await runDocker(`network ls --format '{{json .}}'`);
    if (netLs) {
      const nets = netLs.split('\n').filter(Boolean).map(l => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean).filter(n => !['bridge', 'host', 'none'].includes(n.Name));

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

  // ── Volumes ──────────────────────────────────────────────────────────────────
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
              const v    = JSON.parse(detailOut);
              driver     = v.Driver     || '';
              mountpoint = v.Mountpoint || '';
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

  // ── Build cache ───────────────────────────────────────────────────────────────
  try {
    const { stdout } = await execAsync(`"${DOCKER}" builder du 2>/dev/null`, { timeout: 15000 });
    if (stdout) {
      const lines = stdout.trim().split('\n');
      const totalLine = lines.find(l => /^Total:/i.test(l.trim()));
      if (totalLine) result.buildCacheTotal = totalLine.replace(/^Total:\s*/i, '').trim();
      const reclaimableLine = lines.find(l => /^Reclaimable:/i.test(l.trim()));
      if (reclaimableLine) result.buildCacheReclaimable = reclaimableLine.replace(/^Reclaimable:\s*/i, '').trim();

      const summaryPrefixes = /^(Shared|Private|Reclaimable|Total):/i;
      let headerFound = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (/^ID\s+RECLAIMABLE/i.test(trimmed)) { headerFound = true; continue; }
        if (!headerFound) continue;
        if (summaryPrefixes.test(trimmed)) continue;
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
  const hours = Number(getSettings().pruneIntervalHours || DEFAULT_SETTINGS.pruneIntervalHours);
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
    scheduleAutoPrune();
  }, intervalMs);
  logInfo('Auto-prune scheduled', {
    everyHours: Number((intervalMs / 3600000).toFixed(2)),
    nextRunInMinutes: Math.round(intervalMs / 60000),
  });
}

module.exports = {
  setDependencies,
  appendPruneLog,
  scanUnused,
  runPrune,
  scheduleAutoPrune,
  PRUNE_LOG_FILE,
};
