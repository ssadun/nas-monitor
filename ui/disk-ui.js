// ─── Helpers ──────────────────────────────────────────────────────────────────
// ─── Disk Usage ───────────────────────────────────────────────────────────────
let diskCurrentData = null;
let diskFileSort = { key: 'sizeBytes', dir: -1 };
let diskCollapsed = new Set();
let diskScanning = false;
let diskAllExpanded = false;
let diskHistory = []; // stored locally too
let diskActiveHistoryIdx = -1;
let diskHistoryColorsReady = false;

function updateDiskDeleteButtonVisibility() {
  const btn = el('disk-delete-btn');
  if (!btn) return;
  const hasSelection = diskHistory.length > 0
    && diskActiveHistoryIdx >= 0
    && diskActiveHistoryIdx < diskHistory.length
    && !!diskHistory[diskActiveHistoryIdx]
    && !!diskHistory[diskActiveHistoryIdx].id;
  btn.style.display = hasSelection ? '' : 'none';
}

async function scanDisk() {
  if (diskScanning) return;
  diskScanning = true;
  const path = document.getElementById('disk-path-input').value.trim() || '/volume1';
  const depth = document.getElementById('disk-depth').value;
  const btn = el('disk-scan-btn');
  btn.querySelector('span').textContent = 'Scanning…';
  btn.disabled = true;
  // el('disk-scan-info').textContent ='⟳ Scanning ' + path + '…';
  el('disk-tree-wrap').innerHTML = `<div style="padding:30px;color:var(--text3);font-family:var(--mono);font-size:12px;text-align:center">Scanning ${esc(path)}…<br><span style="font-size:11px;opacity:.6">This may take a moment for large volumes</span></div>`;
  try {
    const res = await fetch(`/api/disk?path=${encodeURIComponent(path)}&depth=${depth}`);
    const data = await res.json();
    if (data.error) {
      // el('disk-scan-info').textContent ='⚠ ' + data.error;
    } else {
      diskCurrentData = data;
      diskCollapsed.clear();
      diskAllExpanded = false;
      // Collapse all children by default — only root is visible
      if (data.tree && data.tree.children) {
        data.tree.children.forEach(child => collapseAllNodes(child));
      }
      const total = data.tree ? fmtBytes(data.tree.sizeBytes) : '–';
      // el('disk-scan-info').textContent =`${esc(path)} – ${total} total`;
      el('disk-tree-root').textContent = path;
      const expandBtn = el('disk-expand-all-btn');
      if (expandBtn) { expandBtn.style.display = ''; expandBtn.querySelector('span').textContent = 'Expand All'; if (window.lucide) lucide.createIcons(); }
      // Add to local history
      diskHistory.unshift({ id: data.scannedAt || Date.now(), path, scannedAt: data.scannedAt, data });
      if (diskHistory.length > 20) diskHistory.pop();
      diskActiveHistoryIdx = 0;
      renderDiskHistory();
      renderDiskTree();
      renderDiskFiles();
    }
  } catch (e) {
    // el('disk-scan-info').textContent ='⚠ ' + e.message;
    el('disk-tree-wrap').innerHTML = `<div style="padding:30px;color:var(--red);font-family:var(--mono);font-size:12px">${esc(e.message)}</div>`;
  } finally {
    diskScanning = false;
    btn.querySelector('span').textContent = 'Scan';
    btn.disabled = false;
  }
}

async function loadHistoryScan(idx) {
  const entry = diskHistory[idx];
  if (!entry) return;
  diskActiveHistoryIdx = idx;

  // If we only have summary, fetch full data from server
  if (!entry.data) {
    // el('disk-scan-info').textContent ='⟳ Loading…';
    try {
      const res = await fetch(`/api/disk/history/${entry.id}`);
      const data = await res.json();
      if (data.error) {
        // el('disk-scan-info').textContent ='⚠ ' + data.error;
        return;
      }
      entry.data = data;
    } catch (e) {
      // el('disk-scan-info').textContent ='⚠ ' + e.message;
      return;
    }
  }

  diskCurrentData = entry.data;
  diskCollapsed.clear();
  diskAllExpanded = false;
  // Collapse all children by default
  if (entry.data.tree && entry.data.tree.children) {
    entry.data.tree.children.forEach(child => collapseAllNodes(child));
  }
  el('disk-path-input').value = entry.path;
  el('disk-tree-root').textContent = entry.path;
  const expandBtn = el('disk-expand-all-btn');
  if (expandBtn) { expandBtn.style.display = ''; expandBtn.querySelector('span').textContent = 'Expand All'; }
  const total = entry.data.tree ? fmtBytes(entry.data.tree.sizeBytes) : fmtBytes(entry.totalBytes || 0);
  // el('disk-scan-info').textContent =`${esc(entry.path)} – ${total} · ${new Date(entry.scannedAt).toLocaleString()}`;
  renderDiskHistory(idx);
  renderDiskTree();
  renderDiskFiles();
}

function renderDiskHistory(activeIdx) {
  if (typeof activeIdx === 'number') {
    diskActiveHistoryIdx = activeIdx;
  }
  if (diskHistory.length && diskActiveHistoryIdx >= diskHistory.length) {
    diskActiveHistoryIdx = diskHistory.length - 1;
  }
  const selectedIdx = diskActiveHistoryIdx;
  const list = el('disk-history-list');
  if (!diskHistory.length) {
    list.innerHTML = `<div style="padding:20px 14px;color:var(--text3);font-size:11px;font-family:var(--mono)">No scans yet</div>`;
    updateDiskDeleteButtonVisibility();
    return;
  }
  list.innerHTML = diskHistory.map((h, i) => {
    const active = i === selectedIdx;
    const dt = new Date(h.scannedAt);
    const now = new Date();
    const isToday = dt.toDateString() === now.toDateString();
    const dateStr = isToday
      ? 'Today, ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : dt.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }) + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const sizeBytes = h.data?.tree?.sizeBytes ?? h.totalBytes ?? 0;
    const size = sizeBytes ? fmtBytes(sizeBytes) : '–';
    const diskTotal = allData?.summary?.diskTotal || 0;
    const pct = diskTotal > 0 ? (sizeBytes / diskTotal) * 100 : 0;
    const sizeColor = pct > 60 ? 'var(--red)' : pct > 30 ? 'var(--orange)' : pct > 10 ? 'var(--pink)' : 'var(--steel)';
    return `<div onclick="loadHistoryScan(${i})" style="
      padding:8px 14px; cursor:pointer; border-left:3px solid ${active ? 'var(--accent)' : 'transparent'};
      background:${active ? 'rgba(79,142,247,.08)' : 'transparent'};
      transition:background .1s; border-bottom:1px solid rgba(42,47,74,.3);
    ">
      <div style="font-size:12px;font-family:var(--mono);color:${active ? 'var(--accent)' : 'var(--text)'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(h.path)}">${esc(h.path)}</div>
      <div style="font-size:11px;color:var(--text3);margin-top:2px;font-family:var(--mono)">${esc(dateStr)}</div>
      <div style="font-size:11px;color:${sizeColor};margin-top:1px;font-family:var(--mono)">${size}</div>
    </div>`;
  }).join('');
  updateDiskDeleteButtonVisibility();
}

async function deleteSelectedDiskScan() {
  if (!diskHistory.length) {
    // el('disk-scan-info').textContent ='⚠ No scan history to delete';
    return;
  }
  const idx = Math.max(0, Math.min(diskActiveHistoryIdx, diskHistory.length - 1));
  const target = diskHistory[idx];
  if (!target || !target.id) {
    // el('disk-scan-info').textContent ='⚠ No selected scan to delete';
    return;
  }
  const deleteBtn = el('disk-delete-btn');
  if (deleteBtn) { deleteBtn.disabled = true; deleteBtn.querySelector('span').textContent = 'Deleting…'; }
  try {
    const res = await fetch(`/api/disk/history/${encodeURIComponent(target.id)}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      // el('disk-scan-info').textContent ='⚠ ' + (data.error || `Delete failed (${res.status})`);
      return;
    }
    diskHistory.splice(idx, 1);
    if (!diskHistory.length) {
      diskActiveHistoryIdx = -1;
      diskCurrentData = null;
      // el('disk-scan-info').textContent ='Scan deleted';
      el('disk-tree-root').textContent = '';
      el('disk-tree-wrap').innerHTML = `<div style="padding:30px;color:var(--text3);font-family:var(--mono);font-size:12px;text-align:center">Click Scan to start</div>`;
      el('disk-file-count').textContent = '';
      el('disk-file-tbody').innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="emoji">📄</div>Click Scan to start</div></td></tr>`;
      const filesPanel = el('disk-files-panel');
      if (filesPanel) filesPanel.style.display = 'none';
      const treePanel = el('disk-tree-panel');
      if (treePanel) treePanel.style.display = 'none';
      const expandBtn = el('disk-expand-all-btn');
      if (expandBtn) expandBtn.style.display = 'none';
      renderDiskHistory();
      return;
    }
    const nextIdx = Math.min(idx, diskHistory.length - 1);
    await loadHistoryScan(nextIdx);
    // el('disk-scan-info').textContent ='✓ Scan deleted';
  } catch (e) {
    // el('disk-scan-info').textContent ='⚠ ' + e.message;
  } finally {
    if (deleteBtn) { deleteBtn.disabled = false; deleteBtn.querySelector('span').textContent = 'Delete'; }
  }
}

function toggleDiskNode(nodePath) {
  if (diskCollapsed.has(nodePath)) diskCollapsed.delete(nodePath);
  else diskCollapsed.add(nodePath);
  renderDiskTree();
}

// Recursively add all node paths to diskCollapsed
function collapseAllNodes(node) {
  if (!node) return;
  diskCollapsed.add(node.path);
  if (node.children) node.children.forEach(collapseAllNodes);
}

// Recursively remove all node paths from diskCollapsed
function expandAllNodes(node) {
  if (!node) return;
  diskCollapsed.delete(node.path);
  if (node.children) node.children.forEach(expandAllNodes);
}

function toggleAllDiskNodes() {
  if (!diskCurrentData || !diskCurrentData.tree) return;
  diskAllExpanded = !diskAllExpanded;
  if (diskAllExpanded) {
    expandAllNodes(diskCurrentData.tree);
  } else {
    diskCollapsed.clear();
    if (diskCurrentData.tree.children) {
      diskCurrentData.tree.children.forEach(child => collapseAllNodes(child));
    }
  }
  const btn = el('disk-expand-all-btn');
  if (btn) {
    const iconExpand   = `<i data-lucide="arrow-up-down" style="width:12px;height:12px;stroke-width:2;"></i>`;
    const iconCollapse = `<i data-lucide="fold-vertical" style="width:12px;height:12px;stroke-width:2;"></i>`;
    btn.innerHTML = diskAllExpanded
      ? iconCollapse + '<span>Collapse All</span>'
      : iconExpand   + '<span>Expand All</span>';
    lucide.createIcons({ nodes: [btn] });
  }
  renderDiskTree();
}

function renderDiskTree() {
  const treePanel = el('disk-tree-panel');
  if (!diskCurrentData || !diskCurrentData.tree) {
    if (treePanel) treePanel.style.display = 'none';
    return;
  }
  if (treePanel) treePanel.style.display = 'flex';
  const root = diskCurrentData.tree;
  const maxSize = root.sizeBytes || 1;
  let html = '<table style="width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px;">';
  html += `<thead><tr style="background:var(--bg3);position:sticky;top:0;z-index:5">
    <th style="padding:7px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);border-bottom:1px solid var(--border2)">NAME</th>
    <th style="padding:7px 12px;width:110px;text-align:left;font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);border-bottom:1px solid var(--border2)">SIZE</th>
    <th style="padding:7px 12px;width:180px;text-align:left;font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);border-bottom:1px solid var(--border2)">BAR</th>
  </tr></thead><tbody>`;

  function renderNode(node, depth) {
    if (!node) return;
    const isCollapsed = diskCollapsed.has(node.path);
    const hasChildren = node.children && node.children.length > 0;
    const pct = Math.min((node.sizeBytes / maxSize) * 100, 100);
    const barColor = pct > 60 ? 'var(--red)' : pct > 30 ? 'var(--orange)' : pct > 10 ? 'var(--accent)' : 'var(--text3)';
    const indent = depth * 18;
    const isRoot = depth === 0;

    html += `<tr style="border-bottom:1px solid rgba(42,47,74,.4);${isRoot ? 'background:rgba(79,142,247,.05)' : ''}">
      <td style="padding:5px 12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px">
        <div style="display:flex;align-items:center;padding-left:${indent}px;gap:4px">
          ${hasChildren
            ? `<button onclick="toggleDiskNode(${JSON.stringify(node.path).replace(/"/g,'&quot;')})" style="background:none;border:none;cursor:pointer;color:var(--text3);font-size:11px;padding:0 4px 0 0;flex-shrink:0">${isCollapsed ? '▶' : '▼'}</button>`
            : `<span style="display:inline-block;width:16px;flex-shrink:0"></span>`
          }
          <span style="color:${isRoot ? 'var(--accent)' : depth===0 ? 'var(--accent)' : 'var(--text)'}">${esc(node.name)}</span>
        </div>
      </td>
      <td style="padding:5px 12px;color:var(--text2);white-space:nowrap">${fmtBytes(node.sizeBytes)}</td>
      <td style="padding:5px 12px">
        <div style="display:flex;align-items:center;gap:6px">
          <div style="flex:1;height:5px;background:var(--bg4);border-radius:3px;overflow:hidden">
            <div style="width:${pct.toFixed(1)}%;height:100%;background:${barColor};border-radius:3px"></div>
          </div>
          <span style="font-size:10px;color:var(--text3);width:32px">${pct.toFixed(0)}%</span>
        </div>
      </td>
    </tr>`;

    if (hasChildren && !isCollapsed) {
      node.children.forEach(child => renderNode(child, depth + 1));
    }
  }

  renderNode(root, 0);
  html += '</tbody></table>';
  el('disk-tree-wrap').innerHTML = html;
}

function sortDisk(key) {
  if (diskFileSort.key === key) diskFileSort.dir *= -1;
  else { diskFileSort.key = key; diskFileSort.dir = -1; }
  renderDiskFiles();
}

function renderDiskFiles() {
  const panel = el('disk-files-panel');
  if (!diskCurrentData) {
    if (panel) panel.style.display = 'none';
    return;
  }
  if (panel) panel.style.display = 'flex';
  const files = [...(diskCurrentData.topFiles || [])].sort((a, b) => {
    const av = a[diskFileSort.key], bv = b[diskFileSort.key];
    return (av > bv ? 1 : av < bv ? -1 : 0) * diskFileSort.dir;
  });

  el('disk-file-count').textContent = files.length ? `(${files.length})` : '';
  const maxSize = files[0]?.sizeBytes || 1;

  if (!files.length) {
    el('disk-file-tbody').innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="emoji">📄</div>No files found</div></td></tr>`;
    return;
  }

  // Update sort arrows
  document.querySelectorAll('#disk-file-table th .sort-arrow').forEach(a => a.textContent = '↕');
  document.querySelectorAll('#disk-file-table th').forEach(th => {
    const m = th.getAttribute('onclick')?.match(/sortDisk\('([^']+)'\)/);
    if (m && m[1] === diskFileSort.key) {
      th.querySelector('.sort-arrow').textContent = diskFileSort.dir === -1 ? '↓' : '↑';
    }
  });

  el('disk-file-tbody').innerHTML = files.map(f => {
    const dir = f.path.slice(0, f.path.lastIndexOf('/')) || '/';
    const pct = Math.min((f.sizeBytes / maxSize) * 100, 100);
    const barColor = pct > 60 ? 'var(--red)' : pct > 30 ? 'var(--orange)' : 'var(--pink)';
    const mtimeStr = f.mtime ? fmtFileDate(f.mtime) : '–';
    const mtimeAge = f.mtime ? fileDateAge(f.mtime) : '';
    return `<tr style="border-bottom:1px solid rgba(42,47,74,.4)">
      <td style="padding:5px 12px;font-family:var(--mono);color:var(--text2);white-space:nowrap">
        <div style="display:flex;align-items:center;gap:6px">
          ${fmtBytes(f.sizeBytes)}
          <div style="width:40px;height:4px;background:var(--bg4);border-radius:2px;overflow:hidden;flex-shrink:0">
            <div style="width:${pct.toFixed(1)}%;height:100%;background:${barColor};border-radius:2px"></div>
          </div>
        </div>
      </td>
      <td style="padding:5px 12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.name)}</td>
      <td style="padding:5px 12px;white-space:nowrap;font-family:var(--mono);font-size:11px;" title="${esc(new Date(f.mtime).toLocaleString())}">
        <span style="color:var(--text2);">${esc(mtimeStr)}</span>
        ${mtimeAge ? `<span style="color:var(--text3);margin-left:4px;">${esc(mtimeAge)}</span>` : ''}
      </td>
      <td style="padding:5px 12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text3);font-size:11px" title="${esc(f.path)}">${esc(dir)}</td>
    </tr>`;
  }).join('');
}

