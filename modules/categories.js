// ═══════════════════════════════════════════════════════════════════════════
// categories.js - Container category definitions and assignments
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// ─── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_CAT_DEFS = [
  { id: 'media',       label: 'Media',       icon: 'clapperboard', color: '#a78bfa', dot: '#8b5cf6' },
  { id: 'performance', label: 'Performance', icon: 'zap',          color: '#f97316', dot: '#f97316' },
  { id: 'utilities',  label: 'Utilities',   icon: 'wrench',        color: '#06b6d4', dot: '#06b6d4' },
  { id: 'system',     label: 'System',      icon: 'monitor',       color: '#22c55e', dot: '#22c55e' },
];

// ─── Dependencies injected from server.js ──────────────────────────────────

let logError = () => {};
let CAT_ASSIGNMENTS_FILE = path.join(__dirname, '..', 'data', 'category-assignments.json');
let CAT_DEFS_FILE        = path.join(__dirname, '..', 'data', 'category-defs.json');

function setDependencies(errorLogger, dataDir) {
  logError = errorLogger;
  if (dataDir) {
    CAT_ASSIGNMENTS_FILE = path.join(dataDir, 'category-assignments.json');
    CAT_DEFS_FILE        = path.join(dataDir, 'category-defs.json');
  }
}

// ─── Category definitions ───────────────────────────────────────────────────

const EMOJI_TO_LUCIDE = {
  '🎬': 'clapperboard', '⚡': 'zap',      '🔧': 'wrench',   '🖥': 'monitor',
  '🌐': 'globe',        '🔒': 'lock',      '📊': 'bar-chart-2', '🗃': 'database',
  '🛠': 'settings',     '📦': 'package',   '🚀': 'rocket',   '🎮': 'gamepad-2',
  '🔑': 'key',          '💾': 'hard-drive','🧹': 'trash-2',  '📡': 'radio',
  '🤖': 'bot',          '🔬': 'microscope','🎵': 'music',    '📁': 'folder',
  '🏠': 'home',         '☁': 'cloud',      '🔥': 'flame',    '🧩': 'puzzle',
};

function migrateDef(def) {
  if (def.icon && EMOJI_TO_LUCIDE[def.icon]) {
    return { ...def, icon: EMOJI_TO_LUCIDE[def.icon] };
  }
  return def;
}

function loadCatDefs() {
  try {
    const data = JSON.parse(fs.readFileSync(CAT_DEFS_FILE, 'utf8'));
    return Array.isArray(data) && data.length ? data.map(migrateDef) : DEFAULT_CAT_DEFS;
  } catch { return DEFAULT_CAT_DEFS; }
}

function saveCatDefs(data) {
  try {
    fs.writeFileSync(CAT_DEFS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    logError('Failed to save category definitions file', { error: e.message });
  }
}

// ─── Category assignments ───────────────────────────────────────────────────

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

// ─── Route handlers ─────────────────────────────────────────────────────────

function registerRoutes(req, res, url) {
  // GET /api/category-defs
  if (url.pathname === '/api/category-defs' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(loadCatDefs()));
    return true;
  }

  // POST /api/category-defs — body: array of category objects
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
    return true;
  }

  // GET /api/categories — return all assignments { containerName: categoryId }
  if (url.pathname === '/api/categories' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(loadCatAssignments()));
    return true;
  }

  // POST /api/categories — body: { containerName, categoryId }  (categoryId null = remove)
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
    return true;
  }

  return false;
}

module.exports = { setDependencies, loadCatDefs, loadCatAssignments, saveCatDefs, saveCatAssignments, registerRoutes };
