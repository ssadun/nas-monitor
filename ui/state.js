'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
let allData = { processes: [], containers: [], summary: {} };
let currentTab = sessionStorage.getItem('nas-monitor-tab') || 'containers';
let procView = 'flat';
let procSort = { key: 'cpu', dir: -1 };
let containerSort = { key: 'name', dir: 1 };
let filterText = '';
let filterMode = null;
let expandedContainers = new Set();
let collapsedProcs = new Set();
let allContainersExpanded = false;
let procByPid = {};
let pidContainerMap = {};
let streamEs = null;
let streamReconnectTimer = null;


// ─── SSE stream ───────────────────────────────────────────────────────────────
function startStream() {
  if (streamEs) {
    try { streamEs.close(); } catch {}
    streamEs = null;
  }
  const es = new EventSource('/api/stream');
  streamEs = es;
  es.onmessage = e => {
    if (streamEs !== es) return;
    const parsed = JSON.parse(e.data);
    if (parsed.refreshIntervalSeconds && parsed.refreshIntervalSeconds !== allData.refreshIntervalSeconds && allData.refreshIntervalSeconds != null) {
      startStream();
      return;
    }
    allData = parsed;
    document.querySelectorAll('.live-badge').forEach(el => {
      el.childNodes[el.childNodes.length - 1].textContent = ` LIVE · ${allData.refreshIntervalSeconds ?? 3}s`;
    });
    procByPid = {};
    allData.processes.forEach(p => procByPid[p.pid] = p);
    pidContainerMap = {};
    allData.containers.forEach(c => {
      (c.pids || []).forEach(pid => { pidContainerMap[pid] = c.name; });
    });
    render();
    updateSortHeaders();
    document.getElementById('loading').classList.add('done');
    if (diskHistory.length && !diskHistoryColorsReady && allData.summary?.diskTotal > 0) {
      diskHistoryColorsReady = true;
      renderDiskHistory();
    }
    const t = new Date(allData.lastUpdate);
    document.querySelectorAll('.last-update').forEach(el => {
      el.textContent = 'Updated ' + t.toLocaleTimeString();
    });
  };
  es.onerror = () => {
    if (streamEs !== es) return;
    if (streamReconnectTimer) clearTimeout(streamReconnectTimer);
    streamReconnectTimer = setTimeout(() => {
      try { es.close(); } catch {}
      startStream();
    }, 3000);
  };
}

function refreshContainerMonitoring() {
  startStream();
}

// ─── Tab switching ────────────────────────────────────────────────────────────
function logout() {
  fetch('/logout', { method: 'GET', credentials: 'same-origin' })
    .finally(() => { window.location.href = '/login'; });
}

function switchTab(name) {
  currentTab = name;
  sessionStorage.setItem('nas-monitor-tab', name);
  applySidebarColors(name);
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === 'tab-' + name);
  });
  document.getElementById('filter-input').value = '';
  filterText = '';
  render();
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  document.body.classList.toggle('sidebar-expanded');
  sidebar.classList.toggle('expanded');
  sessionStorage.setItem('sidebar-expanded', document.body.classList.contains('sidebar-expanded'));
  updateSidebarToggleLabel();
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  document.body.classList.remove('sidebar-expanded');
  sidebar.classList.remove('expanded');
  sessionStorage.setItem('sidebar-expanded', false);
  updateSidebarToggleLabel();
}

function switchTabFromSidebar(name) {
  switchTab(name);
}

// ─── Sorting ──────────────────────────────────────────────────────────────────
function sortTable(table, key) {
  if (isDragging) return;
  if (table === 'procs') {
    if (procSort.key === key) procSort.dir *= -1;
    else { procSort.key = key; procSort.dir = -1; }
  } else {
    if (containerSort.key === key) containerSort.dir *= -1;
    else { containerSort.key = key; containerSort.dir = -1; }
  }
  updateSortHeaders();
  render();
}

function updateSortHeaders() {
  document.querySelectorAll('#container-table th[onclick]').forEach(th => {
    const m = th.getAttribute('onclick').match(/sortTable\('containers','(.+?)'\)/);
    if (!m) return;
    const arrow = th.querySelector('.sort-arrow');
    if (containerSort.key === m[1]) {
      th.classList.add('sorted');
      if (arrow) arrow.textContent = containerSort.dir === -1 ? '↓' : '↑';
    } else {
      th.classList.remove('sorted');
      if (arrow) arrow.textContent = '↕';
    }
  });
  document.querySelectorAll('#proc-table th[onclick]').forEach(th => {
    const m = th.getAttribute('onclick').match(/sortTable\('procs','(.+?)'\)/);
    if (!m) return;
    const arrow = th.querySelector('.sort-arrow');
    if (procSort.key === m[1]) {
      th.classList.add('sorted');
      if (arrow) arrow.textContent = procSort.dir === -1 ? '↓' : '↑';
    } else {
      th.classList.remove('sorted');
      if (arrow) arrow.textContent = '↕';
    }
  });
}

function getSorted(arr, sort) {
  return [...arr].sort((a, b) => {
    let av = a[sort.key], bv = b[sort.key];
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return -sort.dir;
    if (av > bv) return sort.dir;
    return 0;
  });
}

// ─── Filter ───────────────────────────────────────────────────────────────────
function applyFilter() {
  filterText = document.getElementById('filter-input').value.toLowerCase();
  render();
}

function toggleFilter(mode) {
  filterMode = filterMode === mode ? null : mode;
  document.getElementById('high-cpu-btn').classList.toggle('active', filterMode === 'cpu');
  document.getElementById('high-mem-btn').classList.toggle('active', filterMode === 'mem');
  document.getElementById('container-filter-btn').classList.toggle('active', filterMode === 'container');
  render();
}

function matchesFilter(p) {
  if (filterMode === 'cpu' && p.cpu < 1) return false;
  if (filterMode === 'mem' && p.mem < 1) return false;
  if (filterMode === 'container' && !pidContainerMap[p.pid]) return false;
  if (filterText) {
    return String(p.pid).includes(filterText) ||
      (p.name||'').toLowerCase().includes(filterText) ||
      (p.owner||'').toLowerCase().includes(filterText) ||
      (p.cmdline||'').toLowerCase().includes(filterText);
  }
  return true;
}

// ─── Startup ──────────────────────────────────────────────────────────────────
startStream();

(async () => {
  try {
    const res = await fetch('/api/disk/history');
    const hist = await res.json();
    if (hist.length) {
      diskHistory = hist.map(h => ({
        id: h.id, path: h.path, scannedAt: h.scannedAt,
        data: null, summary: true, totalBytes: h.totalBytes
      }));
      renderDiskHistory();
    }
  } catch {}
})();
