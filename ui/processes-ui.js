// ─── Process table ────────────────────────────────────────────────────────────

function setView(v) {
  procView = v;
  el('view-flat').classList.toggle('active', v === 'flat');
  el('view-tree').classList.toggle('active', v === 'tree');
  collapsedProcs.clear();
  renderProcesses();
}

function renderProcesses() {
  const tbody = el('proc-tbody');
  // Inject containerName for sorting
  let procs = allData.processes.map(p => ({
    ...p, containerName: pidContainerMap[p.pid] || ''
  })).filter(matchesFilter);
  el('proc-count-info').textContent = procs.length + ' processes';

  let html = '';

  if (procView === 'flat') {
    procs = getSorted(procs, procSort);
    for (const p of procs) {
      html += procRow(p, 0, false, false);
    }
  } else {
    // Tree view
    const all = allData.processes;
    const pidSet = new Set(all.map(p => p.pid));
    const childMap = {};
    const roots = [];
    for (const p of all) {
      if (!pidSet.has(p.ppid) || p.ppid === p.pid) {
        roots.push(p);
      } else {
        if (!childMap[p.ppid]) childMap[p.ppid] = [];
        childMap[p.ppid].push(p);
      }
    }

    function filterMatch(p) {
      if (matchesFilter(p)) return true;
      return (childMap[p.pid]||[]).some(filterMatch);
    }

    function walkTree(p, depth) {
      if (!filterMatch(p)) return;
      const hasChildren = (childMap[p.pid]||[]).length > 0;
      const isCollapsed = collapsedProcs.has(p.pid);
      html += procRow(p, depth, hasChildren, isCollapsed);
      if (hasChildren && !isCollapsed) {
        const sorted = getSorted(childMap[p.pid], procSort);
        sorted.forEach(ch => walkTree(ch, depth + 1));
      }
    }
    getSorted(roots, procSort).forEach(p => walkTree(p, 0));
  }

  if (!html) html = `<tr><td colspan="12"><div class="empty-state"><div class="emoji"><i data-lucide="cpu" style="width:40px;height:40px;stroke-width:1.5;"></i></div>No processes match the filter</div></td></tr>`;
  tbody.innerHTML = html;
  lucide.createIcons({ nodes: [tbody] });
}

function procRow(p, depth, hasChildren, isCollapsed) {
  const indent = depth * 16;
  const cpuPct = Math.min(p.cpu, 100);
  const memPct = Math.min(p.mem, 100);

  let expandBtn = '';
  if (procView === 'tree' && hasChildren) {
    expandBtn = `<button class="toggle-btn" onclick="toggleProcCollapse(${p.pid},event)">${isCollapsed ? '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="m9 18 6-6-6-6"/></svg>' : '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="m6 9 6 6 6-6"/></svg>'}</button>`;
  } else if (procView === 'tree' && depth > 0) {
    expandBtn = `<span style="color:var(--muted);font-size:13px;margin-right:6px;">⤷</span>`;
  }

  const pj = JSON.stringify(p).replace(/"/g,'&quot;');

  return `<tr style="${p.isSelf ? 'border-left:2px solid var(--orange);background:rgba(249,115,22,.04);' : ''}">
    <td style="width:24px">
      <span class="status-dot ${p.status}"></span>
    </td>
    <td class="pid-col muted">${p.pid}</td>
    <td class="name-col">
      <div class="proc-name" style="padding-left:${indent}px">
        ${expandBtn}
        <span class="proc-name-text" onclick="showProcDetailFromAttr(this)"
          data-proc="${pj}">${esc(p.name)}</span>
      </div>
    </td>
    <td class="owner-col muted">${esc(p.owner)}</td>
    <td style="width:120px">${
      p.isSelf
        ? `<span class="self-tag" title="This is the nas-monitor process">nas-monitor</span>`
        : pidContainerMap[p.pid]
          ? `<span class="container-tag" title="${esc(pidContainerMap[p.pid])}">${esc(pidContainerMap[p.pid])}</span>`
          : ''
    }</td>
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
    <td style="width:100px;font-family:var(--mono);font-size:12px;white-space:nowrap;">
      ${(p.diskReadKBs > 0)
        ? `<span style="color:var(--green);">↓ ${p.diskReadKBs >= 1024 ? (p.diskReadKBs/1024).toFixed(1)+' MB/s' : p.diskReadKBs.toFixed(1)+' KB/s'}</span>`
        : `<span class="muted">–</span>`}
    </td>
    <td style="width:100px;font-family:var(--mono);font-size:12px;white-space:nowrap;">
      ${(p.diskWriteKBs > 0)
        ? `<span style="color:var(--orange);">↑ ${p.diskWriteKBs >= 1024 ? (p.diskWriteKBs/1024).toFixed(1)+' MB/s' : p.diskWriteKBs.toFixed(1)+' KB/s'}</span>`
        : `<span class="muted">–</span>`}
    </td>
    <td class="status-col">
      <span class="state-${p.status}">${stateLabel(p.status)}</span>
    </td>
    <td class="start-col muted" style="font-size:13px">${fmtDate(p.start)}</td>
    <td class="cmd-col muted" style="font-size:13px;max-width:300px;overflow:hidden;text-overflow:ellipsis"
      title="${esc(p.cmdline)}">${esc((p.cmdline||p.name).slice(0,80))}</td>
  </tr>`;
}

function toggleProcCollapse(pid, evt) {
  if (evt) evt.stopPropagation();
  if (collapsedProcs.has(pid)) collapsedProcs.delete(pid);
  else collapsedProcs.add(pid);
  renderProcesses();
}

// ─── Process detail modal ─────────────────────────────────────────────────────

function showProcDetailFromAttr(el_) {
  try {
    const p = JSON.parse(el_.getAttribute('data-proc').replace(/&quot;/g, '"'));
    showProcDetail(p);
  } catch(e) { console.error(e); }
}

function showProcDetail(p) {
  el('modal-title').innerHTML = `<span class="status-dot ${p.status}" style="width:10px;height:10px"></span> ${esc(p.name)} <span class="muted" style="font-size:14px">PID ${p.pid}</span>`;
  el('modal-body').innerHTML = `
    <div class="detail-item"><div class="detail-key">PID</div><div class="detail-val">${p.pid}</div></div>
    <div class="detail-item"><div class="detail-key">Parent PID</div><div class="detail-val">${p.ppid}</div></div>
    <div class="detail-item"><div class="detail-key">Name</div><div class="detail-val">${esc(p.name)}</div></div>
    <div class="detail-item"><div class="detail-key">Owner</div><div class="detail-val">${esc(p.owner)}</div></div>
    <div class="detail-item"><div class="detail-key">CPU %</div><div class="detail-val ${cpuColor(p.cpu)}-text">${p.cpu.toFixed(2)}%</div></div>
    <div class="detail-item"><div class="detail-key">Memory %</div><div class="detail-val">${p.mem.toFixed(2)}%</div></div>
    <div class="detail-item"><div class="detail-key">Memory (RSS)</div><div class="detail-val">${fmtBytes(p.memKB * 1024)}</div></div>
    <div class="detail-item"><div class="detail-key">Threads</div><div class="detail-val">${p.threads||1}</div></div>
    <div class="detail-item"><div class="detail-key">Status</div><div class="detail-val state-${p.status}">${stateLabel(p.status)} (${p.status})</div></div>
    <div class="detail-item"><div class="detail-key">Start Time</div><div class="detail-val">${p.start ? new Date(p.start).toLocaleString() : '–'}</div></div>
    <div class="detail-item full"><div class="detail-key">Command Line</div><div class="detail-val cmd">${esc(p.cmdline||p.name)}</div></div>
  `;
  el('modal').classList.add('open');
}

function closeModal() {
  el('modal').classList.remove('open');
}
el('modal').addEventListener('click', e => { if (e.target === el('modal')) closeModal(); });
