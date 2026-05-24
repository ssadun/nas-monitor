'use strict';

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');

const DISK_HISTORY_FILE = path.join(__dirname, '..', 'data', 'disk-history.json');
const DISK_HISTORY_MAX = 20;

function loadHistory() {
  try {
    const raw = fs.readFileSync(DISK_HISTORY_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveHistory(history) {
  fs.writeFileSync(DISK_HISTORY_FILE, JSON.stringify(history), 'utf8');
}

async function walkTree(dirPath, depth, maxDepth) {
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
          const child = await walkTree(full, depth + 1, maxDepth);
          node.sizeBytes += child.sizeBytes;
          node.children.push(child);
        } else {
          const sz = await countSize(full);
          node.sizeBytes += sz;
          node.children.push({ path: full, name: e.name, sizeBytes: sz, children: [] });
        }
      }
    } catch {}
  }
  node.children.sort((a, b) => b.sizeBytes - a.sizeBytes);
  return node;
}

async function countSize(dirPath) {
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
        total += await countSize(full);
      }
    } catch {}
  }
  return total;
}

async function collectFiles(dirPath, fileList, depth, maxDepth) {
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
        await collectFiles(full, fileList, depth + 1, maxDepth);
      }
    } catch {}
  }
}

async function collectUsage(scanPath, maxDepth = 4) {
  const results = { path: scanPath, scannedAt: Date.now(), tree: null, topFiles: [], error: null };
  try {
    results.tree = await walkTree(scanPath, 0, maxDepth);
    const allFiles = [];
    await collectFiles(scanPath, allFiles, 0, maxDepth + 2);
    results.topFiles = allFiles.sort((a, b) => b.sizeBytes - a.sizeBytes).slice(0, 50);
  } catch (e) {
    results.error = e.message;
  }
  return results;
}

module.exports = {
  DISK_HISTORY_MAX,
  loadHistory,
  saveHistory,
  walkTree,
  countSize,
  collectFiles,
  collectUsage,
};
