// ─── Summary NW sparkline ring buffer ────────────────────────────────────────
const SUMMARY_NW_LEN = 30;
const summaryNwRx = [];
const summaryNwTx = [];

// ─── Summary bar ─────────────────────────────────────────────────────────────
function renderSummary() {
  const s = allData.summary;
  const containers = allData.containers;
  const processes = allData.processes;
  const composeDefined = containers.filter(c => c.composeOnly).length;

  // Containers
  const running = containers.filter(c => (c.state||'').toLowerCase() === 'running').length;
  el('s-containers').textContent = containers.length;
  el('s-containers-sub').textContent = running + ' running';

  // Processes
  el('s-procs').textContent = processes.length;
  const running_procs = processes.filter(p => p.status === 'R').length;
  el('s-procs-sub').textContent = running_procs + ' active';

  // CPU – compute avg from container cpu percents
  const cpus = containers.map(c => parseFloat(c.cpu)||0).filter(x=>!isNaN(x));
  const avgCpu = cpus.length ? (cpus.reduce((a,b)=>a+b,0)/cpus.length).toFixed(1) : '–';
  const totalCpu = cpus.reduce((a,b)=>a+b,0);
  const cpuPct = Math.min(totalCpu, 100);
  el('s-cpu').textContent = avgCpu + '%';
  el('s-cpu').className = 'metric-value ' + cpuColor(parseFloat(avgCpu));
  el('s-cpu-bar').style.width = cpuPct + '%';
  el('s-cpu-sub').textContent = `Load: ${(s.load1||0).toFixed(2)} ${(s.load5||0).toFixed(2)} ${(s.load15||0).toFixed(2)}`;

  // Mem (System Mem pie)
  if (s.memTotal) {
    const usedPct = (s.memUsed / s.memTotal * 100);
    const avPct   = (s.memAvail / s.memTotal * 100);
    const memColor = usedPct >= 90 ? 'red' : usedPct >= 70 ? 'orange' : 'green';
    const usedGb = (s.memUsed / (1024 ** 3)).toFixed(1);
    const totalGb = (s.memTotal / (1024 ** 3)).toFixed(1);
    el('s-sysmem').textContent = `${usedGb} GB`;
    el('s-sysmem').className = 'metric-value ' + memColor;
    el('s-sysmem-sub').textContent = `${totalGb} GB · ${usedPct.toFixed(1)}%`;
    drawMemPie(usedPct / 100, memColor);
  }

  // Uptime
  if (s.uptimeSeconds) {
    el('s-uptime').textContent = fmtUptime(s.uptimeSeconds);
  }
  el('s-load').textContent = 'load ' + (s.load1||0).toFixed(2);

  // Disk
  if (s.diskTotal > 0) {
    const diskPct = (s.diskUsed / s.diskTotal * 100);
    const diskColor = diskPct >= 90 ? 'red' : diskPct >= 70 ? 'orange' : 'yellow';
    el('s-disk').textContent = fmtBytes(s.diskUsed);
    el('s-disk').className = 'metric-value ' + diskColor;
    el('s-disk-sub').textContent = fmtBytes(s.diskTotal) + ' · ' + diskPct.toFixed(1) + '%';
    drawDiskPie(diskPct / 100, diskColor);
  } else {
    el('s-disk').textContent = '–';
    el('s-disk-sub').textContent = 'no volumes';
    drawDiskPie(0, 'text3');
  }

  // Network summary sparkline
  const rxKBs = s.netInKBs  || 0;
  const txKBs = s.netOutKBs || 0;
  summaryNwRx.push(rxKBs); if (summaryNwRx.length > SUMMARY_NW_LEN) summaryNwRx.shift();
  summaryNwTx.push(txKBs); if (summaryNwTx.length > SUMMARY_NW_LEN) summaryNwTx.shift();
  el('s-nw-in').textContent  = '↓ ' + rxKBs.toFixed(2) + ' KB/s';
  el('s-nw-out').textContent = '↑ ' + txKBs.toFixed(2) + ' KB/s';
  drawSummaryNwSparkline();

  // Container count + compose breakdown
  el('container-count-total').textContent = containers.length + ' containers';
  el('container-count-compose').textContent = composeDefined > 0
    ? `${composeDefined} from compose`
    : '0 from compose';
}

function drawSummaryNwSparkline() {
  const canvas = el('s-nw-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth || 120;
  const H = canvas.offsetHeight || 22;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  const maxVal = Math.max(1, ...summaryNwRx, ...summaryNwTx);
  const len = SUMMARY_NW_LEN;

  function drawLine(data, color) {
    if (data.length < 2) return;
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    data.forEach((v, i) => {
      const x = (i / (len - 1)) * W;
      const y = H - (v / maxVal) * (H - 2) - 1;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    // Fill area
    ctx.lineTo((data.length - 1) / (len - 1) * W, H);
    ctx.lineTo(0, H);
    ctx.closePath();
    ctx.fillStyle = color.replace(')', ', 0.12)').replace('rgb', 'rgba');
    ctx.fill();
  }

  // Grid midline
  ctx.beginPath();
  ctx.strokeStyle = 'rgba(42,47,74,0.8)';
  ctx.lineWidth = 0.5;
  ctx.setLineDash([2, 3]);
  ctx.moveTo(0, H / 2); ctx.lineTo(W, H / 2);
  ctx.stroke();
  ctx.setLineDash([]);

  drawLine(summaryNwRx, 'rgb(34,197,94)');      // --green
  drawLine(summaryNwTx, 'rgb(139,92,246)');    // --lavender
}

function drawDiskPie(fraction, colorName) {
  const canvas = el('s-disk-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, r = (Math.min(W, H) / 2) - 2;

  const colorMap = {
    green:  'rgb(34,197,94)',
    red:    'rgb(239,68,68)',
    orange: 'rgb(249,115,22)',
    yellow: 'rgb(234,179,8)',
    text3:  'rgb(84,91,122)',
  };
  const usedColor = colorMap[colorName] || colorMap.green;
  const freeColor = 'rgba(42,47,74,0.8)';

  ctx.clearRect(0, 0, W, H);

  const startAngle = -Math.PI / 2; // start from top
  const usedAngle  = fraction * 2 * Math.PI;

  // Free slice
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, r, startAngle + usedAngle, startAngle + 2 * Math.PI);
  ctx.closePath();
  ctx.fillStyle = freeColor;
  ctx.fill();

  // Used slice
  if (fraction > 0) {
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + usedAngle);
    ctx.closePath();
    ctx.fillStyle = usedColor;
    ctx.fill();
  }

  // Thin border ring
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.strokeStyle = 'rgba(42,47,74,0.5)';
  ctx.lineWidth = 1;
  ctx.stroke();
}

function drawMemPie(fraction, colorName) {
  const canvas = el('s-sysmem-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, r = (Math.min(W, H) / 2) - 2;

  const colorMap = {
    green:  'rgb(34,197,94)',
    orange: 'rgb(249,115,22)',
    red:    'rgb(239,68,68)',
  };
  const usedColor = colorMap[colorName] || colorMap.green;
  const freeColor = 'rgba(42,47,74,0.8)';

  ctx.clearRect(0, 0, W, H);

  const startAngle = -Math.PI / 2;
  const usedAngle  = fraction * 2 * Math.PI;

  // Free slice
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, r, startAngle + usedAngle, startAngle + 2 * Math.PI);
  ctx.closePath();
  ctx.fillStyle = freeColor;
  ctx.fill();

  // Used slice
  if (fraction > 0) {
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + usedAngle);
    ctx.closePath();
    ctx.fillStyle = usedColor;
    ctx.fill();
  }

  // Thin border ring
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.strokeStyle = 'rgba(42,47,74,0.5)';
  ctx.lineWidth = 1;
  ctx.stroke();
}

function isComposeBacked(container) {
  return Boolean(container && container.composeManaged && container.composeProject && container.composeService);
}

function isComposeOnly(container) {
  return Boolean(container && container.composeOnly);
}

function getContainerStateClass(container) {
  const raw = String(container && container.state || '').toLowerCase();
  return raw === 'configured' ? 'configured' : raw;
}

function renderContainerTitle(container) {
  return `<div style="display:flex;flex-direction:column;gap:2px;min-width:0;">
    <div class="container-name" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <span style="font-weight:500">${esc(container.name)}</span>
    </div>
  </div>`;
}

function openComposeUpAction(project, service, name) {
  openActionModal('composeUp', `${project}/${service}`, name, { project, service });
}

function renderActionIcon(icon) {
  return `<i data-lucide="${icon}" style="width:14px;height:14px;stroke-width:2;"></i>`;
}

// ─── depends_on grouping ──────────────────────────────────────────────────────
// Within each compose project, show the depended-upon container (the "main"
// one, e.g. gluetun) at depth 0, then indent containers that depend on it
// directly beneath it at depth 1.
function buildDependsOnOrder(list) {
  const composeGroups = new Map(); // "project|dir" -> [containers]
  const nonCompose = [];

  for (const c of list) {
    if (c.composeManaged && c.composeProject) {
      const key = (c.composeProject || '') + '|' + (c.composeDir || '');
      if (!composeGroups.has(key)) composeGroups.set(key, []);
      composeGroups.get(key).push(c);
    } else {
      nonCompose.push(c);
    }
  }

  const result = [];

  for (const group of composeGroups.values()) {
    // Any depends_on relationships at all in this group?
    const hasDeps = group.some(c => (c.composeDependsOn || []).length > 0);
    if (!hasDeps) {
      for (const c of group) result.push({ ...c, dependsOnDepth: 0 });
      continue;
    }

    const byService = new Map();
    for (const c of group) {
      if (c.composeService) byService.set(c.composeService, c);
    }

    // Build reverse map: serviceName -> [containers that depend on it]
    const dependents = new Map(); // serviceName -> Container[]
    for (const c of group) {
      for (const dep of (c.composeDependsOn || [])) {
        if (!dependents.has(dep)) dependents.set(dep, []);
        dependents.get(dep).push(c);
      }
    }

    // "Root" containers are those depended upon by others (e.g. gluetun).
    // They appear at depth 0; their dependents follow at depth 1.
    const isDependedUpon = new Set(dependents.keys());
    const emitted = new Set();

    const emit = (c, depth) => {
      if (emitted.has(c.id)) return;
      emitted.add(c.id);
      result.push({ ...c, dependsOnDepth: depth });
      // After this container, emit anything that depends on it
      const deps = dependents.get(c.composeService) || [];
      for (const dep of deps) emit(dep, depth + 1);
    };

    // Emit depended-upon containers first (they become the visual roots)
    for (const c of group) {
      if (isDependedUpon.has(c.composeService)) emit(c, 0);
    }
    // Emit any remaining containers (standalone services)
    for (const c of group) emit(c, 0);
  }

  return [...result, ...nonCompose];
}

// ─── Container table ──────────────────────────────────────────────────────────
function renderContainers() {
  const tbody = el('container-tbody');

  let list = allData.containers.map(c => ({
    ...c,
    cpuNum: parseFloat(c.cpu)||0,
    memNum: parseFloat(c.memPercent)||0,
    vethRxKBs: c.vethRxKBs || 0,
    vethTxKBs: c.vethTxKBs || 0,
    ip: (c.networks || []).map(n => n.ip || '').filter(Boolean).join(', '),
  }));

  if (filterText) {
    list = list.filter(c => {
      const categoryId = getCatForContainer(c.name);
      const categoryLabel = categoryId ? (CATEGORIES.find(cat => cat.id === categoryId) || {}).label : '';
      return c.name.toLowerCase().includes(filterText) ||
        (c.composeProject || '').toLowerCase().includes(filterText) ||
        (c.composeDir || '').toLowerCase().includes(filterText) ||
        (c.composeFile || '').toLowerCase().includes(filterText) ||
        (categoryLabel || '').toLowerCase().includes(filterText) ||
        (c.networks || []).some(n =>
          (n.name || '').toLowerCase().includes(filterText) ||
          (n.driver || '').toLowerCase().includes(filterText) ||
          (n.ip || '').toLowerCase().includes(filterText)
        ) ||
        (c.ports || []).some(p =>
          String(p.host).includes(filterText) ||
          String(p.container).includes(filterText) ||
          (p.hostIp || '').toLowerCase().includes(filterText) ||
          (p.proto || '').includes(filterText)
        );
    });
  }

  list = getSorted(list, containerSort);

  // Group depends_on: within each compose project, reorder so that containers
  // which are listed as depends_on dependencies appear directly after their
  // dependents, with a visual indent.
  list = buildDependsOnOrder(list);

  // Drop selections for containers that no longer exist (deleted, filtered out of the API response, etc.)
  const liveIds = new Set(allData.containers.map(c => c.id));
  for (const id of selectedContainers) {
    if (!liveIds.has(id)) selectedContainers.delete(id);
  }

  let html = '';
  for (const c of list) {
    const rowId = 'cr-' + c.id;
    const isExpanded = expandedContainers.has(c.id);
    const stateClass = getContainerStateClass(c);
    const rowClick = ` onclick="openCDetailModal('${c.id}','${esc(c.name)}','${stateClass}')"`;
    const isComposeParent = !c.dependsOnDepth && c.composeManaged && c.composeProject && c.composeService;
    const startAction = isComposeParent
      ? `openActionModal('composeUp','${esc(c.composeProject)}/${esc(c.composeService)}','${esc(c.name)}',{project:'${esc(c.composeProject)}',service:'${esc(c.composeService)}',parentStart:true})`
      : `openActionModal('start','${c.id}','${esc(c.name)}')`;
    const startTitle = isComposeParent ? 'Compose Up' : 'Start';
    const canArchiveFromList = stateClass === 'configured' && Boolean(c.composeProject);

    const depIndent = (c.dependsOnDepth || 0) * 20;
    const bulkSelectable = !isComposeOnly(c);
    html += `<tr id="${rowId}"${rowClick} ${c.dependsOnDepth ? 'class="depends-on-row"' : ''}>
      <td class="col-select" style="width:30px" onclick="event.stopPropagation()">
        <input type="checkbox" ${bulkSelectable ? '' : 'disabled'} ${selectedContainers.has(c.id) ? 'checked' : ''}
          onchange="toggleContainerSelect('${c.id}', this.checked)" style="width:14px;height:14px;cursor:pointer;accent-color:var(--accent);">
      </td>
      <td class="col-status" style="width:30px">
        <span class="status-dot ${stateClass}"></span>
      </td>
      <td class="col-name">
        <div style="display:flex;align-items:center;gap:6px;">
          ${c.dependsOnDepth ? '<span class="depends-on-arrow">⤷</span>' : ''}
          ${renderContainerTitle(c)}
        </div>
      </td>
      <td class="col-cpu ${cpuColor(c.cpuNum)}-text" style="font-family:var(--mono);font-size:12px;">${esc(c.cpu || '–')}</td>
      <td class="col-mem accent-text" style="font-family:var(--mono);font-size:12px;">${esc(c.memPercent || '–')}</td>
      <td class="col-mem-usage green-text">${esc(c.memUsage)}</td>
      <td class="col-net-in green-text" title="Docker cumulative: ${esc(c.netIn)}">${c.netMode==='host'?'<span class="muted" style="font-size:12px">host-net</span>':c.netMode==='compose'?'<span class="muted">–</span>':c.vethRxKBs?c.vethRxKBs.toFixed(2)+' KB/s':'<span class="muted">–</span>'}</td>
      <td class="col-net-out accent-text" title="Docker cumulative: ${esc(c.netOut)}">${c.netMode==='host'?'<span class="muted" style="font-size:12px">host-net</span>':c.netMode==='compose'?'<span class="muted">–</span>':c.vethTxKBs?c.vethTxKBs.toFixed(2)+' KB/s':'<span class="muted">–</span>'}</td>
      <td class="col-img-size muted">${esc(c.imageSize||'–')}</td>
      <td class="col-networks muted">${renderNetworks(c.networks)}</td>
      <td class="col-ports">${renderPorts(c.ports)}</td>
      <td class="col-actions" onclick="event.stopPropagation()">
        <div class="container-actions" style="display:flex;gap:4px;">
          <button class="action-btn start" title="${startTitle}"
            ${stateClass === 'running' || c.dependsOnDepth ? 'disabled' : ''}
            onclick="${startAction}">${renderActionIcon(isComposeParent ? 'upload' : 'play')}</button>
          <button class="action-btn restart" title="Restart"
            ${stateClass !== 'running' || isComposeOnly(c) ? 'disabled' : ''}
            onclick="openActionModal('restart','${c.id}','${esc(c.name)}')">${renderActionIcon('rotate-cw')}</button>
          <button class="action-btn stop" title="Stop"
            ${stateClass !== 'running' || isComposeOnly(c) ? 'disabled' : ''}
            onclick="openActionModal('stop','${c.id}','${esc(c.name)}')">${renderActionIcon('square')}</button>
          <button class="action-btn logs" title="Logs"
            ${stateClass !== 'running' ? 'disabled' : ''}
            onclick="openLogs('${c.id}','${esc(c.name)}')">${renderActionIcon('scroll-text')}</button>
        </div>
      </td>
      <td class="col-process" onclick="event.stopPropagation()">
        <button class="container-expand-btn ${isExpanded?'open':''}" ${isComposeOnly(c) ? 'disabled' : ''} onclick="toggleContainerRow('${c.id}', event)">
          ${isExpanded ? `▼ ${c.pids.length || c.processCount} ⚙ ` : `▶ ${c.pids.length || c.processCount} ⚙ `}
        </button>
      </td>
      <td class="col-category" onclick="event.stopPropagation()" style="white-space:nowrap;">
        ${renderCategoryBadge(c.id, c.name)}
      </td>
    </tr>`;

    if (isExpanded) {
      html += `<tr class="expanded-row">
        <td colspan="14" style="padding:0">
          <div class="sub-proc-wrap">
            ${renderSubProcTable(c.pids)}
          </div>
        </td>
      </tr>`;
    }
  }

  if (!html) html = `<tr><td colspan="14"><div class="empty-state"><div class="emoji"><i data-lucide="box" style="width:40px;height:40px;stroke-width:1.5;"></i></div>No containers found</div></td></tr>`;
  tbody.innerHTML = html;
  lucide.createIcons({ nodes: [tbody] });
  initTableResize();
  updateContainerBulkBar();
}

// ─── Container multi-select + bulk actions ────────────────────────────────────
const BULK_CONTAINER_ACTION_META = {
  start:   { label: 'Start',   past: 'Started' },
  restart: { label: 'Restart', past: 'Restarted' },
  stop:    { label: 'Stop',    past: 'Stopped' },
};

function toggleContainerSelect(id, checked) {
  if (checked) selectedContainers.add(id);
  else selectedContainers.delete(id);
  updateContainerBulkBar();
}

function toggleSelectAllContainers(checked) {
  const eligibleIds = (allData.containers || []).filter(c => !isComposeOnly(c)).map(c => c.id);
  if (checked) eligibleIds.forEach(id => selectedContainers.add(id));
  else eligibleIds.forEach(id => selectedContainers.delete(id));
  renderContainers();
}

function clearContainerSelection() {
  selectedContainers.clear();
  renderContainers();
}

function updateContainerBulkBar() {
  const bar = el('container-bulk-bar');
  if (!bar) return;
  const count = selectedContainers.size;
  bar.style.display = count > 0 ? 'flex' : 'none';
  const countLabel = el('container-bulk-count');
  if (countLabel) countLabel.textContent = `${count} Selected`;

  const selectAllCb = el('container-select-all');
  if (selectAllCb) {
    const eligible = (allData.containers || []).filter(c => !isComposeOnly(c));
    selectAllCb.disabled = eligible.length === 0;
    selectAllCb.checked = eligible.length > 0 && eligible.every(c => selectedContainers.has(c.id));
  }
}

function bulkContainerAction(action) {
  const meta = BULK_CONTAINER_ACTION_META[action];
  const actionMeta = ACTION_META[action];
  if (!meta || !actionMeta) return;

  const ids = Array.from(selectedContainers).filter(id =>
    (allData.containers || []).some(c => c.id === id)
  );
  if (!ids.length) return;

  // Confirmation step lives in the shared action modal itself (not a native confirm() dialog).
  _actionPending = { bulk: true, action, ids };
  el('action-modal').classList.remove('composeup-large');
  el('action-modal-icon').innerHTML = `<i data-lucide="${actionMeta.icon}" style="width:16px;height:16px;color:${actionMeta.color};"></i>`;
  el('action-modal-title').textContent = `Bulk ${meta.label}`;
  el('action-modal-container').textContent = `${ids.length} container(s) selected`;
  el('action-modal-desc').innerHTML = `${meta.label} ${ids.length} selected container(s)?`;
  el('action-progress').innerHTML = '';

  const confirmBtn = el('action-modal-confirm');
  confirmBtn.style.display = '';
  confirmBtn.className = `action-modal-btn ${actionMeta.btnClass}`;
  confirmBtn.innerHTML = `<i data-lucide="${actionMeta.icon}" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>${meta.label}`;
  confirmBtn.disabled = false;
  confirmBtn.onclick = () => runBulkContainerAction(action, ids);

  el('action-modal-cancel').style.display = '';
  el('action-modal-cancel').textContent = 'Cancel';
  el('action-modal-cancel').disabled = false;
  el('action-modal-cancel').onclick = closeActionModal;
  el('action-modal-close').style.display = '';

  el('action-modal').classList.add('open');
  lucide.createIcons({ nodes: [el('action-modal')] });
}

async function runBulkContainerAction(action, ids) {
  const meta = BULK_CONTAINER_ACTION_META[action];
  if (!meta) return;

  const bar = el('container-bulk-bar');
  const barButtons = bar ? bar.querySelectorAll('button') : [];
  barButtons.forEach(b => b.disabled = true);

  // Switch the modal from the confirm step into a live per-container progress list.
  _actionPending = { bulk: true, action, ids };
  el('action-modal-desc').innerHTML = '';
  el('action-progress').innerHTML = '';
  el('action-modal-confirm').style.display = 'none';
  el('action-modal-close').style.display = 'none';
  el('action-modal-cancel').textContent = 'Please Wait…';
  el('action-modal-cancel').disabled = true;
  el('action-modal-cancel').onclick = null;

  const steps = ids.map(id => {
    const c = (allData.containers || []).find(x => x.id === id);
    const name = c ? c.name : id;
    return { id, name, stepEl: addProgressStep(name, 'pending') };
  });

  let successCount = 0;
  const failures = [];

  for (const { id, name, stepEl } of steps) {
    updateStep(stepEl, 'active', name);
    try {
      const res = await fetch(`/api/container/${action}?id=${encodeURIComponent(id)}`);
      const data = await res.json();
      if (data.ok) {
        successCount++;
        updateStep(stepEl, 'done', name);
      } else {
        failures.push(name);
        updateStep(stepEl, 'error', `${name} — ${data.error || 'Failed'}`);
      }
    } catch (e) {
      failures.push(name);
      updateStep(stepEl, 'error', `${name} — ${e.message}`);
    }
  }

  el('action-modal-cancel').textContent = 'Close';
  el('action-modal-cancel').disabled = false;
  el('action-modal-cancel').onclick = closeActionModal;
  el('action-modal-close').style.display = '';
  _actionPending = null;

  barButtons.forEach(b => b.disabled = false);

  if (failures.length === 0) {
    showToast(`${meta.past} ${successCount} container(s)`, 'ok', 3000);
  } else if (successCount === 0) {
    showToast(`${meta.label} failed for all ${failures.length} container(s)`, 'err', 4500);
    console.warn('Bulk container action failures:', failures);
  } else {
    showToast(`${meta.past} ${successCount}, failed ${failures.length}`, 'err', 4500);
    console.warn('Bulk container action failures:', failures);
  }

  selectedContainers.clear();
  try {
    const r = await fetch('/api/data/refresh');
    const latest = await r.json();
    if (latest && Array.isArray(latest.containers)) allData = latest;
  } catch {}
  render();
}

function renderPorts(ports) {
  if (!ports || !ports.length) return '<span class="muted">–</span>';
  return ports.map(p => {
    const url = `http://${window.location.hostname}:${p.host}`;
    return `<a class="port-link" href="${url}" target="_blank" rel="noopener"
      onclick="event.stopPropagation()" title="Open ${url}">${p.host}</a>`;
  }).join('');
}

function renderNetworks(networks) {
  if (!networks || !networks.length) return '<span class="muted">–</span>';
  return networks.map(n => {
    const tip = [
      n.driver ? 'driver: ' + n.driver : '',
      n.ip     ? 'ip: '     + n.ip     : '',
      n.gateway? 'gw: '     + n.gateway: '',
      n.macAddr? 'mac: '    + n.macAddr: '',
    ].filter(Boolean).join('\n');
    const color = n.driver === 'host'    ? 'var(--orange)'
                : n.driver === 'overlay' ? 'var(--pink)'
                : 'var(--muted)';
    return `<span onclick="event.stopPropagation()" title="${esc(tip)}"
      style="display:inline-block;font-size:12px;font-family:var(--mono);
             padding:1px 6px;border-radius:4px;margin:1px 2px 1px 0;
             color:${color};white-space:nowrap;cursor:default;"
    >${esc(n.name)}${n.driver ? ' ' + '<span style="opacity:.55;">'+esc(n.driver)+'</span>' : ''}${n.ip ? ': '+esc(n.ip) : ''}</span>`;
  }).join('<br>');
}

function toggleContainerRow(id, evt) {
  if (evt) evt.stopPropagation();
  if (expandedContainers.has(id)) {
    expandedContainers.delete(id);
  } else {
    expandedContainers.add(id);
  }
  renderContainers();
}

function toggleAllContainers() {
  allContainersExpanded = !allContainersExpanded;
  if (allContainersExpanded) {
    allData.containers.forEach(c => expandedContainers.add(c.id));
  } else {
    expandedContainers.clear();
  }
  const btn = el('expand-all-btn');
  if (btn) {
    const iconExpand   = `<i data-lucide="arrow-up-down" style="width:14px;height:14px;stroke-width:2;"></i>`;
    const iconCollapse = `<i data-lucide="fold-vertical" style="width:14px;height:14px;stroke-width:2;"></i>`;
    btn.className = allContainersExpanded ? 'toolbar-btn expand' : 'toolbar-btn expand';
    btn.innerHTML = allContainersExpanded
      ? iconCollapse + '<span>Collapse All</span>'
      : iconExpand   + '<span>Expand All</span>';
    lucide.createIcons({ nodes: [btn] });
  }
  renderContainers();
}

function renderSubProcTable(pids) {
  if (!pids || !pids.length) return '<p style="padding:12px 16px;color:var(--muted);font-size:13px">No process info available.</p>';

  // Build tree structure for these pids
  const procs = pids.map(pid => procByPid[pid]).filter(Boolean);
  if (!procs.length) return '<p style="padding:12px 16px;color:var(--muted);font-size:13px">Process data not available (may need root access).</p>';

  // Group into tree
  const pidSet = new Set(pids);
  const roots = [];
  const childMap = {};
  for (const p of procs) {
    if (!pidSet.has(p.ppid)) {
      roots.push(p);
    } else {
      if (!childMap[p.ppid]) childMap[p.ppid] = [];
      childMap[p.ppid].push(p);
    }
  }

  let rows = '';
  function walk(p, depth) {
    const indent = depth * 16;
    const cpuPct = Math.min(p.cpu, 100);
    const memPct = Math.min(p.mem, 100);
    const pj = JSON.stringify(p).replace(/"/g,'&quot;');

    let expandBtn = '';
    if (depth > 0) {
      expandBtn = `<span style="color:var(--muted);font-size:13px;margin-right:6px;">⤷</span>`;
    }

    rows += `<tr>
      <td style="width:24px"><span class="status-dot ${p.status}"></span></td>
      <td class="pid-col muted">${p.pid}</td>
      <td class="name-col">
        <div class="proc-name" style="padding-left:${indent}px">
          ${expandBtn}
          <span class="proc-name-text" onclick="showProcDetailFromAttr(this)" data-proc="${pj}">${esc(p.name)}</span>
        </div>
      </td>
      <td class="owner-col muted">${esc(p.owner)}</td>
      <td class="cpu-col">
        <div class="cpu-bar">
          <div class="bar-track"><div class="bar-fill cpu ${cpuColorClass(p.cpu)}" style="width:${cpuPct}%"></div></div>
          <span class="${cpuColor(p.cpu)}-text">${p.cpu.toFixed(2)}%</span>
        </div>
      </td>
      <td class="mem-col">
        <div class="mem-bar">
          <div class="bar-track"><div class="bar-fill mem" style="width:${memPct}%"></div></div>
          <span class="accent-text">${p.mem.toFixed(2)}%</span>
        </div>
      </td>
      <td class="status-col"><span class="state-${p.status}">${stateLabel(p.status)}</span></td>
      <td class="start-col muted" style="font-size:13px">${fmtDate(p.start)}</td>
      <td class="cmd-col muted" style="font-size:13px;overflow:hidden;text-overflow:ellipsis"
        title="${esc(p.cmdline)}">${esc((p.cmdline||p.name).slice(0,80))}</td>
    </tr>`;
    (childMap[p.pid]||[]).forEach(ch => walk(ch, depth+1));
  }
  roots.forEach(p => walk(p, 0));

  return `<table class="sub-table">
    <thead>
      <tr>
        <th style="width:24px"></th>
        <th class="pid-col">PID</th>
        <th class="name-col">NAME</th>
        <th class="owner-col">OWNER</th>
        <th class="cpu-col">%CPU</th>
        <th class="mem-col">%MEM</th>
        <th class="status-col">STATUS</th>
        <th class="start-col">START</th>
        <th class="cmd-col">COMMAND LINE</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ─── Container Actions ────────────────────────────────────────────────────────
// ─── Container Action Modal ───────────────────────────────────────────────────
let _actionPending = null; // { action, id, name }
let _composeUpAbortController = null;

const ACTION_META = {
  start:   { icon: 'play',       label: 'Start Container',   color: 'var(--green)',  btnClass: 'ok',
              desc: c => `Start container <strong>${esc(c)}</strong>?`,
              steps: ['Sending start command…', 'Waiting for container to start…', 'Done'] },
  composeUp:{ icon: 'arrow-up-circle', label: 'Compose Up',  color: 'var(--accent)', btnClass: 'ok',
              desc: c => `Run <strong>docker compose up -d</strong> for <strong>${esc(c)}</strong>?`,
              steps: ['Reading compose project…', 'Running docker compose up -d…', 'Done'] },
  restart: { icon: 'rotate-cw',  label: 'Restart Container', color: 'var(--orange)', btnClass: 'restart',
              desc: c => `Restart container <strong>${esc(c)}</strong>? It will briefly go offline.`,
              steps: ['Sending restart command…', 'Waiting for container to come back up…', 'Done'] },
  stop:    { icon: 'square',     label: 'Stop Container',    color: 'var(--yellow)', btnClass: 'stop',
              desc: c => `Stop container <strong>${esc(c)}</strong>? Running processes inside will be terminated.`,
              steps: ['Sending stop command…', 'Waiting for container to stop…', 'Done'] },
  archive: { icon: 'archive',    label: 'Archive Compose',   color: 'var(--orange)', btnClass: 'ok',
              desc: c => `Archive compose config for <strong>${esc(c)}</strong>?<br><span style="font-size:12px;">This moves files from <code>/volume1/docker/_config/&lt;project&gt;</code> to <code>/volume1/docker/_backups/&lt;project&gt;</code>.</span>`,
              steps: ['Preparing archive target…', 'Moving compose files to backup…', 'Done'] },
  delete:  { icon: 'trash-2',    label: 'Delete Container',  color: 'var(--red)',    btnClass: 'cancel',
              desc: c => `Permanently delete container <strong>${esc(c)}</strong>?<br><span style="color:var(--red);font-size:12px;">⚠ This cannot be undone. The container will be stopped and removed.</span>`,
              steps: ['Stopping container…', 'Removing container…', 'Done'] },
};

function toggleActionMenu(event) {
  event.stopPropagation();
  const button = event.currentTarget || event.target;
  const containerActions = button.closest('.container-actions');
  if (!containerActions) {
    console.error('Could not find .container-actions');
    return;
  }
  const dropdown = containerActions.querySelector('.action-dropdown');
  if (!dropdown) {
    console.error('Could not find .action-dropdown');
    return;
  }
  const isOpen = dropdown.classList.contains('open');

  document.querySelectorAll('.action-dropdown.open').forEach(d => {
    if (d !== dropdown) d.classList.remove('open');
  });

  if (!isOpen) {
    dropdown.classList.add('open');
    setTimeout(() => {
      document.addEventListener('click', closeActionMenus);
    }, 0);
  } else {
    dropdown.classList.remove('open');
    document.removeEventListener('click', closeActionMenus);
  }
}

function closeActionMenus(event) {
  if (!event.target.closest('.action-dropdown') && !event.target.closest('.action-menu-btn')) {
    document.querySelectorAll('.action-dropdown.open').forEach(d => d.classList.remove('open'));
    document.removeEventListener('click', closeActionMenus);
  }
}

let resizingColIndex = null;
let resizingThElement = null;
let resizingStartX = 0;
let resizingStartWidth = 0;
let isDragging = false;

function startResize(e, colIndex) {
  e.preventDefault();
  e.stopPropagation();
  isDragging = true;

  // Get the th element - col-resizer's parent
  let th = e.target;
  while (th && th.tagName !== 'TH') {
    th = th.parentElement;
  }
  if (!th) return;

  resizingColIndex = colIndex;
  resizingThElement = th;
  resizingStartX = e.clientX;
  resizingStartWidth = parseInt(window.getComputedStyle(th).width);

  // Keep col-resize cursor while dragging
  document.body.style.cursor = 'col-resize';
  document.body.style.userSelect = 'none';

  console.log('Resize started:', { colIndex, startX: e.clientX, startWidth: resizingStartWidth });
  document.addEventListener('mousemove', onResizeMove, true);
  document.addEventListener('mouseup', endResize, true);
}

function onResizeMove(e) {
  if (resizingColIndex === null || !resizingThElement) return;
  const delta = e.clientX - resizingStartX;
  // Multiply delta by 1.5 to make changes more noticeable
  const newWidth = Math.max(50, resizingStartWidth + delta * 1.5);
  resizingThElement.style.width = newWidth + 'px';
  console.log('Moving:', { delta, multipliedDelta: delta * 1.5, newWidth });
}

function endResize() {
  console.log('Resize ended');
  document.removeEventListener('mousemove', onResizeMove, true);
  document.removeEventListener('mouseup', endResize, true);

  // Reset cursor
  document.body.style.cursor = '';
  document.body.style.userSelect = '';

  if (resizingThElement) {
    resizingThElement.style.opacity = '';
  }
  if (resizingColIndex !== null) {
    const table = document.getElementById('container-table');
    const ths = table.querySelectorAll('th');
    const widths = Array.from(ths).map(th => parseInt(window.getComputedStyle(th).width));
    localStorage.setItem('container-table-widths', JSON.stringify(widths));
  }
  resizingColIndex = null;
  resizingThElement = null;

  // Clear dragging flag after a small delay to prevent sort click
  setTimeout(() => { isDragging = false; }, 50);
}

function restoreColumnWidths() {
  const saved = localStorage.getItem('container-table-widths');
  if (!saved) return;
  try {
    const widths = JSON.parse(saved);
    const table = document.getElementById('container-table');
    const ths = table.querySelectorAll('th');
    ths.forEach((th, i) => {
      if (widths[i]) th.style.width = widths[i] + 'px';
    });
  } catch (e) {
    console.error('Failed to restore column widths:', e);
  }
}

function redistributeColumns() {
  const table = document.getElementById('container-table');
  if (!table) return;

  const ths = table.querySelectorAll('th');
  const containerWidth = table.offsetWidth;
  const columnCount = ths.length;

  // Only redistribute if we have explicit widths saved
  const saved = localStorage.getItem('container-table-widths');
  if (!saved) {
    // If no saved widths, distribute evenly
    const evenWidth = Math.floor(containerWidth / columnCount);
    ths.forEach(th => {
      th.style.width = evenWidth + 'px';
    });
    console.log('Distributed evenly:', evenWidth);
  }
}

function initTableResize() {
  const table = document.getElementById('container-table');
  if (!table) return;

  restoreColumnWidths();

  // Attach mousedown listeners to all col-resizers
  const resizers = table.querySelectorAll('.col-resizer');
  console.log('Found', resizers.length, 'resizers');

  resizers.forEach((resizer) => {
    resizer.addEventListener('mousedown', (e) => {
      const colIndex = parseInt(resizer.dataset.colIndex);
      console.log('Resizer clicked, col:', colIndex);
      startResize(e, colIndex);
    });
  });

  // Add window resize listener to redistribute columns
  window.addEventListener('resize', redistributeColumns);
}

function openActionModal(action, id, name, extra = {}) {
  _actionPending = { action, id, name, ...extra };
  const meta = ACTION_META[action];
  const isDeleteAction = action === 'delete';
  el('action-modal').classList.toggle('composeup-large', action === 'composeUp');

  // Set title icon using lucide
  const iconEl = el('action-modal-icon');
  iconEl.innerHTML = `<i data-lucide="${meta.icon}" style="width:16px;height:16px;color:${meta.color};"></i>`;

  el('action-modal-title').textContent   = meta.label;
  el('action-modal-container').textContent = name + '  ·  ' + id;
  el('action-modal-desc').innerHTML      = meta.desc(name);

  // Set confirm button with icon and proper class
  const confirmBtn = el('action-modal-confirm');
  confirmBtn.className = `action-modal-btn ${meta.btnClass}`;
  confirmBtn.innerHTML = `<i data-lucide="${meta.icon}" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>${meta.label}`;
  confirmBtn.dataset.action = action;
  confirmBtn.disabled = false;

  el('action-modal-cancel').style.display = isDeleteAction ? 'none' : '';
  el('action-modal-close').style.display  = '';
  el('action-progress').innerHTML = '';
  el('action-modal').classList.add('open');

  // Initialize lucide icons in the modal
  lucide.createIcons({ nodes: [el('action-modal')] });
}

function addProgressStep(text, state = 'active') {
  const icons = {
    active:  '<span class="spin"><i data-lucide="loader-2" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i></span>',
    done:    '<i data-lucide="check-circle" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i>',
    error:   '<i data-lucide="x-circle" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i>',
    pending: '<i data-lucide="circle" style="width:14px;height:14px;stroke-width:1.5;vertical-align:-3px;opacity:.4;"></i>',
  };
  const div = document.createElement('div');
  div.className = `action-progress-step ${state}`;
  div.innerHTML = `<span class="step-icon">${icons[state]}</span><span>${esc(text)}</span>`;
  el('action-progress').appendChild(div);
  lucide.createIcons({ nodes: [div] });
  return div;
}

function updateStep(stepEl, state, text) {
  const icons = {
    active:  '<span class="spin"><i data-lucide="loader-2" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i></span>',
    done:    '<i data-lucide="check-circle" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i>',
    error:   '<i data-lucide="x-circle" style="width:14px;height:14px;stroke-width:2;vertical-align:-3px;"></i>',
  };
  stepEl.className = `action-progress-step ${state}`;
  stepEl.innerHTML = `<span class="step-icon">${icons[state]}</span><span>${esc(text)}</span>`;
  lucide.createIcons({ nodes: [stepEl] });
}

async function executeAction() {
  if (!_actionPending) return;
  const { action, id, name, project, service, parentStart } = _actionPending;
  const meta = ACTION_META[action];
  const isComposeUpAction = action === 'composeUp';
  let composeCancelled = false;

  const setLocalContainerState = (containerId, state) => {
    if (!allData || !Array.isArray(allData.containers)) return;
    const item = allData.containers.find(c => c.id === containerId);
    if (!item) return;
    item.state = state;
    item.status = state;
    item.running = state === 'running';
    render();
  };

  const removeLocalContainer = (containerId) => {
    if (!allData || !Array.isArray(allData.containers)) return;
    const before = allData.containers.length;
    allData.containers = allData.containers.filter(c => c.id !== containerId);
    if (allData.containers.length !== before) render();
  };

  const refreshContainersNow = async () => {
    try {
      if (typeof refreshContainerMonitoring === 'function') refreshContainerMonitoring();
      const r = await fetch('/api/data/refresh');
      const latest = await r.json();
      if (latest && Array.isArray(latest.containers)) {
        allData = latest;
        render();
        return latest.containers;
      }
    } catch {}
    return Array.isArray(allData?.containers) ? allData.containers : [];
  };

  const refreshOpenCDetailBehind = async () => {
    const cdetailModal = el('cdetail-modal');
    if (!cdetailModal || !cdetailModal.classList.contains('open')) return;

    const idText = String(el('cdetail-id')?.textContent || '').trim();
    const currentId = idText ? idText.split('  · ')[0].trim() : '';
    if (!currentId) return;

    const currentName = String(el('cdetail-name')?.textContent || '').trim() || name || currentId;
    const activeTab = document.querySelector('.cdetail-tab.active')?.dataset?.tab || 'status';

    if (activeTab === 'compose' && hasUnsavedComposeChanges()) return;

    await openCDetailModal(currentId, currentName, 'configured');
    if (activeTab && activeTab !== 'status') switchCDetailTab(activeTab);
  };

  const waitForContainerCondition = async (predicate, tries = 18, intervalMs = 250) => {
    for (let i = 0; i < tries; i++) {
      const list = await refreshContainersNow();
      try {
        if (predicate(list || [])) return true;
      } catch {}
      await new Promise(r => setTimeout(r, intervalMs));
    }
    return false;
  };

  const resolveComposeResultTarget = async () => {
    let composeFallback = null;
    try {
      // Give Docker a short time window to register a newly created container in stats output.
      for (let i = 0; i < 16; i++) {
        const res = await fetch('/api/data/refresh');
        const latest = await res.json();
        if (latest && Array.isArray(latest.containers)) {
          allData = latest;
          const list = latest.containers;

          let containerTarget = list.find(c => !c.composeOnly && c.composeProject === project && c.composeService === service);
          if (!containerTarget && name) {
            const n = String(name).toLowerCase();
            containerTarget = list.find(c => !c.composeOnly && String(c.name || '').toLowerCase() === n);
          }
          if (!containerTarget && name) {
            try {
              const byNameRes = await fetch(`/api/container/detail/${encodeURIComponent(name)}`);
              const byName = await byNameRes.json();
              if (byName && !byName.error && byName.id) {
                containerTarget = {
                  id: byName.id,
                  name: byName.name || name,
                  status: byName.status || '',
                  composeOnly: false,
                };
              }
            } catch {}
          }
          if (containerTarget) return { kind: 'container', target: containerTarget };

          if (!composeFallback) {
            composeFallback = list.find(c => c.composeOnly && c.composeProject === project && c.composeService === service) || null;
          }
        }
        await new Promise(r => setTimeout(r, 500));
      }
    } catch {}
    return composeFallback ? { kind: 'compose', target: composeFallback } : { kind: 'none', target: null };
  };

  const openResolvedTargetDetail = (resolved) => {
    if (!resolved || !resolved.target) return;
    switchTab('containers');
    render();
    openCDetailModal(resolved.target.id, resolved.target.name, getContainerStateClass(resolved.target));
  };

  // Lock UI during execution — remove onclick so button is fully inert
  el('action-modal-confirm').disabled = true;
  el('action-modal-confirm').onclick = null;
  el('action-modal-confirm').textContent = 'Running…';
  el('action-modal-cancel').style.display = isComposeUpAction ? '' : 'none';
  if (isComposeUpAction) {
    el('action-modal-cancel').textContent = 'Cancel Run';
    el('action-modal-cancel').style.borderColor = 'var(--red)';
    el('action-modal-cancel').style.color = 'var(--red)';
    el('action-modal-cancel').onclick = () => {
      composeCancelled = true;
      if (_composeUpAbortController) {
        try { _composeUpAbortController.abort(); } catch {}
      }
    };
    el('action-modal-close').style.display = '';
    el('action-modal-close').onclick = () => {
      composeCancelled = true;
      if (_composeUpAbortController) {
        try { _composeUpAbortController.abort(); } catch {}
      }
      closeActionModal();
    };
  } else {
    el('action-modal-close').style.display = 'none';
  }
  el('action-progress').innerHTML = '';

  try {
    if (action === 'composeUp') {
      const s1 = addProgressStep(meta.steps[0], 'active');
      const s2 = addProgressStep(meta.steps[1], 'pending');
      const logBox = document.createElement('pre');
      logBox.className = 'action-stream-log';
      logBox.textContent = '';
      el('action-progress').appendChild(logBox);

      const appendLog = (line, type = 'stdout') => {
        const prefix = type === 'stderr' ? '[err] ' : type === 'status' ? '[info] ' : '';
        logBox.textContent += `${prefix}${line}\n`;
        logBox.scrollTop = logBox.scrollHeight;
      };

      _composeUpAbortController = new AbortController();
      const res = await fetch('/api/compose/up/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project, service, parentStart: parentStart || false }),
        signal: _composeUpAbortController.signal,
      });

      if (!res.ok || !res.body) {
        updateStep(s1, 'error', 'Failed: unable to start compose stream');
        updateStep(s2, 'error', 'Compose up did not start');
        showToast('Compose up failed: unable to start stream', 'err', 3400);
      } else {
        updateStep(s1, 'done', 'Compose project loaded.');
        updateStep(s2, 'active', meta.steps[1]);

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let failedMsg = '';
        let doneOk = false;
        let streamReadError = null;

        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            let idx;
            while ((idx = buffer.indexOf('\n')) >= 0) {
              const line = buffer.slice(0, idx).trim();
              buffer = buffer.slice(idx + 1);
              if (!line) continue;

              let evt;
              try { evt = JSON.parse(line); } catch { continue; }
              if (evt.message) appendLog(evt.message, evt.type);

              if (evt.type === 'error') {
                failedMsg = evt.message || 'compose up failed';
              }
              if (evt.type === 'done') {
                doneOk = !!evt.ok;
              }
            }
          }
        } catch (readErr) {
          streamReadError = readErr;
        }

        if (streamReadError) {
          const msg = String(streamReadError.message || '');
          const benignAbort = /aborted/i.test(msg);
          const isUserAbort = composeCancelled || streamReadError.name === 'AbortError';
          if (!(doneOk && benignAbort) && !isUserAbort) {
            throw streamReadError;
          }
        }

        if (composeCancelled) {
          addProgressStep('Compose up cancelled by user.', 'error');
          showToast('Compose up cancelled.', 'err', 2600);
        }

        else if (doneOk && !failedMsg) {
          updateStep(s2, 'done', 'Compose up completed.');
          addProgressStep(meta.steps[2], 'done');
          const resolved = await resolveComposeResultTarget();
          if (resolved.kind !== 'none') openResolvedTargetDetail(resolved);
          if (resolved.kind !== 'container') {
            showToast('Compose up finished but container was not detected.', 'err', 3600);
          }
        } else {
          updateStep(s2, 'error', 'Failed: ' + (failedMsg || 'unknown error'));
          const resolved = await resolveComposeResultTarget();
          if (resolved.kind !== 'none') openResolvedTargetDetail(resolved);
          if (resolved.kind === 'container') {
            showToast(`Compose up failed, but container was created: ${failedMsg || 'unknown error'}`, 'err', 4200);
          } else {
            showToast(`Compose up failed: ${failedMsg || 'unknown error'}`, 'err', 3600);
          }
        }
      }
    } else if (action === 'archive') {
      const s1 = addProgressStep(meta.steps[0], 'active');
      const res = await fetch('/api/compose/archive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project }),
      });
      const data = await res.json();
      if (data.ok) {
        updateStep(s1, 'done', meta.steps[1]);
        addProgressStep(meta.steps[2], 'done');
        el('action-modal-confirm').textContent = '✓ Archived';
        el('action-modal-confirm').style.background = '#16a34a';
        if (typeof refreshContainerMonitoring === 'function') refreshContainerMonitoring();
        closeActionModal();
        closeCDetailModal();
        return;
      } else {
        updateStep(s1, 'error', 'Failed: ' + (data.error || 'unknown error'));
        el('action-modal-confirm').textContent = '✕ Failed';
        el('action-modal-confirm').style.background = 'var(--red)';
      }
    } else if (action === 'delete') {
      removeLocalContainer(id);
      // Step 1: Stop
      const s1 = addProgressStep('Stopping container…', 'active');
      try {
        await fetch(`/api/container/stop?id=${encodeURIComponent(id)}`);
        updateStep(s1, 'done', 'Container stopped.');
      } catch {
        updateStep(s1, 'done', 'Already stopped (or stop skipped).');
      }
      // Step 2: Remove
      const s2 = addProgressStep('Removing container…', 'active');
      const res = await fetch(`/api/container/delete?id=${encodeURIComponent(id)}`);
      const data = await res.json();
      if (data.ok) {
        updateStep(s2, 'done', 'Container removed.');
        addProgressStep('Done — container deleted.', 'done');
        await waitForContainerCondition(list => !list.some(c => c.id === id));
        await refreshContainersNow();
        await refreshOpenCDetailBehind();
        closeCDetailModal();
        switchTab('containers');
      } else {
        updateStep(s2, 'error', 'Remove failed: ' + (data.error || 'unknown error'));
        await refreshContainersNow();
        await refreshOpenCDetailBehind();
      }
    } else {
      // start / stop / restart
      // When stopping a container that others depend on, stop the dependents first
      if (action === 'stop' && allData && Array.isArray(allData.containers)) {
        const stoppedContainer = allData.containers.find(c => c.id === id);
        if (stoppedContainer && stoppedContainer.composeService) {
          const dependents = allData.containers.filter(c =>
            c.id !== id &&
            c.composeProject === stoppedContainer.composeProject &&
            (c.composeDependsOn || []).includes(stoppedContainer.composeService) &&
            (c.state === 'running' || c.running)
          );
          for (const dep of dependents) {
            const sd = addProgressStep(`Stopping dependent: ${dep.name}…`, 'active');
            setLocalContainerState(dep.id, 'stopped');
            try {
              await fetch(`/api/container/stop?id=${encodeURIComponent(dep.id)}`);
              updateStep(sd, 'done', `Stopped ${dep.name}.`);
            } catch {
              updateStep(sd, 'error', `Failed to stop ${dep.name}.`);
            }
          }
        }
      }
      const s1 = addProgressStep(meta.steps[0], 'active');
      if (action === 'start') setLocalContainerState(id, 'running');
      if (action === 'stop') setLocalContainerState(id, 'stopped');
      const res = await fetch(`/api/container/${action}?id=${encodeURIComponent(id)}`);
      const data = await res.json();
      const cmdMap = { start: 'start', stop: 'stop', restart: 'restart', delete: 'rm -f' };
      if (cmdMap[action]) {
        const logBox = document.createElement('pre');
        logBox.className = 'action-stream-log';
        logBox.textContent = `$ docker ${cmdMap[action]} ${name}\n${data.output || data.error || ''}`;
        el('action-progress').appendChild(logBox);
        logBox.scrollTop = logBox.scrollHeight;
      }
      if (data.ok) {
        updateStep(s1, 'done', meta.steps[1]);
        addProgressStep(meta.steps[2], 'done');
        if (action === 'start') {
          await refreshContainersNow();
        } else if (action === 'stop') {
          // Don't block the UI while Docker transitions to stopped; refresh once more shortly after.
          setTimeout(async () => {
            await refreshContainersNow();
            await refreshOpenCDetailBehind();
          }, 1500);
        } else if (action === 'restart') {
          await waitForContainerCondition(list => list.some(c => c.id === id));
          await refreshContainersNow();
        }
      } else {
        updateStep(s1, 'error', 'Failed: ' + (data.error || 'unknown error'));
      }
      await refreshContainersNow();
      await refreshOpenCDetailBehind();
    }
  } catch (e) {
    addProgressStep('Error: ' + e.message, 'error');
    el('action-modal-confirm').textContent = '✕ Error';
    el('action-modal-confirm').style.background = 'var(--red)';
    if (action === 'composeUp') {
      if (composeCancelled || (e && e.name === 'AbortError')) {
        addProgressStep('Compose up cancelled by user.', 'error');
        showToast('Compose up cancelled.', 'err', 2600);
      } else {
        showToast(`Compose up error: ${e.message}`, 'err', 3600);
      }
    }
    if (action === 'start' || action === 'stop' || action === 'restart' || action === 'delete') {
      await refreshContainersNow();
      await refreshOpenCDetailBehind();
    }
  }

  // After completion: hide confirm, show only Close (styled red)
  el('action-modal-confirm').style.display = 'none';
  el('action-modal-close').style.display = '';
  el('action-modal-cancel').style.display = '';
  el('action-modal-cancel').textContent = 'Close';
  el('action-modal-cancel').style.borderColor = 'var(--red)';
  el('action-modal-cancel').style.color = 'var(--red)';
  el('action-modal-cancel').onclick = closeActionModal;
  _actionPending = null;
}

function closeActionModal() {
  el('action-modal').classList.remove('open');
  el('action-modal').classList.remove('composeup-large');
  _composeUpAbortController = null;
  _actionPending = null;
  // Reset for next open
  el('action-modal-confirm').style.display = '';
  el('action-modal-confirm').dataset.action = '';
  el('action-modal-confirm').style.background = '';
  el('action-modal-confirm').disabled = false;
  el('action-modal-confirm').onclick = executeAction;
  el('action-modal-cancel').textContent = 'Cancel';
  el('action-modal-cancel').style.borderColor = 'var(--red)';
  el('action-modal-cancel').style.color = 'var(--red)';
  el('action-modal-cancel').onclick = closeActionModal;
}

el('action-modal').addEventListener('click', e => { if (e.target === el('action-modal') && !_actionPending) closeActionModal(); });
let logEventSource = null;
let logLineCount = 0;
let logAutoScroll = true;

function openLogs(id, name) {
  closeLogModal(); // close any existing

  el('log-modal-title').textContent = `Logs — ${name}`;
  el('log-container-id').textContent = id;
  el('log-body').innerHTML = '';
  logLineCount = 0;
  logAutoScroll = true;
  el('log-autoscroll-btn').classList.add('on');
  el('log-count').textContent = '0 lines';
  el('log-modal').classList.add('open');

  logEventSource = new EventSource(`/api/logs/${encodeURIComponent(id)}`);
  logEventSource.onmessage = (e) => {
    const line = JSON.parse(e.data);
    appendLogLine(line);
  };
  logEventSource.onerror = () => {
    appendLogLine('[Connection lost — retrying…]');
  };
}

function appendLogLine(raw) {
  const body = el('log-body');
  logLineCount++;
  el('log-count').textContent = logLineCount + ' lines';

  // Split timestamp from message (docker --timestamps format: 2024-01-01T00:00:00Z message)
  const tsMatch = raw.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s(.*)$/s);
  let ts = '', msg = raw;
  if (tsMatch) { ts = tsMatch[1]; msg = tsMatch[2]; }

  const msgLower = msg.toLowerCase();
  const cls = msgLower.includes('error') || msgLower.includes('fatal') || msgLower.includes('exception') ? 'log-err'
    : msgLower.includes('warn') ? 'log-warn' : 'log-info';

  const div = document.createElement('div');
  div.className = 'log-line ' + cls;
  div.innerHTML = (ts ? `<span class="log-ts">${esc(ts)}</span>` : '') + esc(msg);
  body.appendChild(div);

  // Cap at 2000 lines to avoid memory growth
  while (body.children.length > 2000) body.removeChild(body.firstChild);

  if (logAutoScroll) body.scrollTop = body.scrollHeight;
}

function toggleLogAutoscroll() {
  logAutoScroll = !logAutoScroll;
  el('log-autoscroll-btn').classList.toggle('on', logAutoScroll);
  if (logAutoScroll) el('log-body').scrollTop = el('log-body').scrollHeight;
}

function clearLogs() {
  el('log-body').innerHTML = '';
  logLineCount = 0;
  el('log-count').textContent = '0 lines';
}

function closeLogModal() {
  el('log-modal').classList.remove('open');
  if (logEventSource) { logEventSource.close(); logEventSource = null; }
}

function handleComposeSaveShortcut(e) {
  const key = String(e.key || '').toLowerCase();
  if (!(e.ctrlKey || e.metaKey) || key !== 's') return;

  const active = document.activeElement;
  const newComposeModal = el('newcompose-modal');
  const newComposeOpen = newComposeModal.classList.contains('open');
  if (newComposeOpen && active && newComposeModal.contains(active)) {
    e.preventDefault();
    const saveBtn = el('newcompose-save-btn');
    if (!saveBtn || saveBtn.disabled) return;
    saveNewCompose();
    return;
  }

  const composePanel = el('cdetail-panel-compose');
  const composeVisible = composePanel && composePanel.style.display !== 'none';
  if (!composeVisible) return;

  let editor = null;
  if (active && active.id && active.id.startsWith('compose-editor-')) {
    editor = active;
  } else {
    editor = document.querySelector('#cdetail-panel-compose textarea[id^="compose-editor-"]');
  }
  if (!editor) return;

  const project = editor.dataset.project || '';
  const composeFile = editor.dataset.composeFile || '';
  const saveId = editor.dataset.saveId || '';
  const statusId = editor.dataset.statusId || '';
  if (!project || !saveId || !statusId) return;

  e.preventDefault();
  const saveBtn = document.getElementById(saveId);
  if (saveBtn && saveBtn.disabled) return;
  saveComposeFile(project, composeFile, editor.id, saveId, statusId);
}

el('log-modal').addEventListener('click', e => { if (e.target === el('log-modal')) closeLogModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeModal(); closeLogModal(); closePruneModal(); closePruneLogModal(); if (!_actionPending) closeActionModal(); closeCDetailModal(); closeConsoleModal(); closeNewComposeModal(); closeImageUpdatesModal(); closeImageUpdateLogModal(); } });
document.addEventListener('keydown', handleComposeSaveShortcut);
el('newcompose-modal').addEventListener('click', e => { if (e.target === el('newcompose-modal')) return; });


// ─── Main render ──────────────────────────────────────────────────────────────
function render() {
  renderSummary();
  if (currentTab === 'containers') renderContainers();
  else if (currentTab === 'network') renderNetwork();
  else if (currentTab === 'categories') renderCategories();
  else renderProcesses();
}
