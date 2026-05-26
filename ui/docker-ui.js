// ─── Container Detail Modal ───────────────────────────────────────────────────
async function openCDetailModal(id, name, stateClass) {
  const modal = el('cdetail-modal');
  const idText = String(el('cdetail-id')?.textContent || '').trim();
  const currentId = idText ? idText.split('  · ')[0].trim() : '';
  if (modal.classList.contains('open') && currentId !== id && !(await confirmDismissComposeChanges())) return;
  if (currentId !== id) resetComposeEditorState();
  modal.classList.add('open');
  el('cdetail-name').textContent = name;
  el('cdetail-id').textContent   = id;
  el('cdetail-status-dot').className = `status-dot ${stateClass}`;
  el('cdetail-body').innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;">⟳ Loading container details…</div>`;

  try {
    const res  = await fetch(`/api/container/detail/${encodeURIComponent(id)}`);
    const d    = await res.json();
    if (d.error) {
      const err = String(d.error || '').toLowerCase();
      const isSynthetic = String(id || '').startsWith('compose:');
      if (!isSynthetic && err.includes('not found') && Array.isArray(allData?.containers)) {
        const fallback = allData.containers.find(c => c.composeOnly && String(c.name || '').toLowerCase() === String(name || '').toLowerCase());
        if (fallback && fallback.id && fallback.id !== id) {
          openCDetailModal(fallback.id, fallback.name || name, getContainerStateClass(fallback));
          return;
        }
      }
      el('cdetail-body').innerHTML = `<div style="padding:30px;color:var(--red);font-family:var(--mono);">⚠ ${esc(d.error)}</div>`;
      return;
    }

    // Update header with full name/id
    el('cdetail-name').textContent = d.name || name;
    el('cdetail-id').textContent   = d.id + (d.fullId ? '  ·  sha256:' + d.fullId.slice(0,12) : '');
    el('cdetail-status-dot').className = `status-dot ${(d.status||'').toLowerCase()}`;

    // Populate action buttons based on container mode/state
    const isRunning = d.running;
    const cid = d.id, cname = esc(d.name || name);
    const composeBacked = d.composeManaged && d.composeProject && d.composeService;
    const isComposeConfigured = String(d.status || '').toLowerCase() === 'configured' || Boolean(d.composeOnly);
    const composeStartOnclick = `openComposeUpAction('${esc(d.composeProject || '')}','${esc(d.composeService || '')}','${cname}')`;
    const standardStartOnclick = `openActionModal('start','${cid}','${cname}')`;

    if (isComposeConfigured) {
      // Registered only: show Compose Up + Archive, hide all other actions
      el('cdetail-actions').innerHTML = `
        <button class="cdetail-action-btn start" title="Compose Up" ${composeBacked && !isRunning ? '' : 'disabled'}
          onclick="${composeStartOnclick}"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>Compose Up</span></button>
        <button class="cdetail-action-btn archive" title="Archive compose config" ${d.composeProject ? '' : 'disabled'}
          onclick="openActionModal('archive','${cid}','${cname}',{project:'${esc(d.composeProject || '')}'})"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9"/><path d="M10 13h4"/></svg><span>Archive</span></button>`;
    } else {
      // Running/stopped containers: hide Compose Up + Archive, show standard controls
      el('cdetail-actions').innerHTML = `
        <button class="cdetail-action-btn start" title="Start" ${isRunning ? 'disabled' : ''}
          onclick="${standardStartOnclick}"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>Start</span></button>
        <button class="cdetail-action-btn restart" title="Restart" ${isRunning ? '' : 'disabled'}
          onclick="openActionModal('restart','${cid}','${cname}')"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg><span>Restart</span></button>
        <button class="cdetail-action-btn stop" title="Stop" ${isRunning ? '' : 'disabled'}
          onclick="openActionModal('stop','${cid}','${cname}')"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><rect x="3" y="3" width="18" height="18" rx="2"/></svg><span>Stop</span></button>
        <button class="cdetail-action-btn logs" title="Logs"
          onclick="openLogs('${cid}','${cname}')"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><path d="M15 12h-5"/><path d="M15 8H9"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/></svg><span>Logs</span></button>
        <button class="cdetail-action-btn delete" title="Delete" ${isRunning ? 'disabled' : ''}
          onclick="openActionModal('delete','${cid}','${cname}')"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg><span>Delete</span></button>`;
    }

    function kv(key, val, cls='') {
      return `<div class="cdetail-kv ${cls}"><div class="cdetail-key">${esc(key)}</div><div class="cdetail-val">${esc(String(val||'–'))}</div></div>`;
    }
    function kvHtml(key, html, cls='') {
      return `<div class="cdetail-kv ${cls}"><div class="cdetail-key">${esc(key)}</div><div class="cdetail-val">${html}</div></div>`;
    }
    function section(icon, title, content) {
      return `<div class="cdetail-section"><div class="cdetail-section-title"><i data-lucide="${icon}" style="width:16px;height:16px;vertical-align:-3px;margin-right:6px"></i>${esc(title)}</div>${content}</div>`;
    }
    function table(headers, rows, emptyMsg='No entries') {
      if (!rows.length) return `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;">${esc(emptyMsg)}</div>`;
      return `<table class="cdetail-table"><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
    }

    // ── Status card ──
    const stateColor = d.running ? 'var(--green)' : 'var(--red)';
    const uptimeStr  = d.startedAt && d.running
      ? (() => { const s = Math.floor((Date.now() - new Date(d.startedAt)) / 1000); const d2 = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60); return d2>0?`${d2}d ${h}h`:h>0?`${h}h ${m}m`:`${m}m`; })()
      : '–';

    const statusCard = `
      <div class="cdetail-status-card">
        <div style="display:flex;flex-direction:column;align-items:center;gap:4px;padding-right:14px;border-right:1px solid var(--border);">
          <span class="status-dot ${(d.status||'').toLowerCase()}" style="width:14px;height:14px;"></span>
          <span style="font-family:var(--mono);font-size:12px;font-weight:700;color:${stateColor};">${esc(d.status||'–')}</span>
        </div>
        <div class="cdetail-grid-3" style="flex:1;">
          ${kv('Uptime',   uptimeStr)}
          ${kv('CPU',      d.cpu||'–')}
          ${kv('Memory',   d.memUsage ? d.memUsage + (d.memPercent?' ('+d.memPercent+')':'') : '–')}
          ${kv('Created',  d.created  ? new Date(d.created).toLocaleString()  : '–')}
          ${kv('Started',  d.startedAt? new Date(d.startedAt).toLocaleString(): '–')}
          ${kv('Disk I/O', d.blockIO  || '–')}
        </div>
      </div>`;

    // ── Container Status section ──
    // Sum volume sizes — parse values like "420M", "1.2G", "512K", "63B"
    function parseSize(s) {
      if (!s || s === '–') return 0;
      const m = s.match(/^([\d.]+)\s*([KMGTB]?)i?B?$/i);
      if (!m) return 0;
      const n = parseFloat(m[1]);
      const u = (m[2]||'').toUpperCase();
      const mult = { '': 1, 'B': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4 };
      return n * (mult[u] || 1);
    }
    function fmtSizeBytes(bytes) {
      if (!bytes) return '0 B';
      const units = ['B','KB','MB','GB','TB'];
      let i = 0; let v = bytes;
      while (v >= 1024 && i < units.length-1) { v /= 1024; i++; }
      return v.toFixed(1) + ' ' + units[i];
    }
    const totalVolBytes = (d.volumes||[]).reduce((sum, v) => sum + parseSize(v.sizeOnDisk), 0);
    const totalVolStr = totalVolBytes > 0 ? fmtSizeBytes(totalVolBytes) : '–';

    const statusSection = section('bar-chart-2', 'Container Status', statusCard + `
      <div class="cdetail-grid">
        ${kv('ID',            d.id)}
        ${kv('Name',          d.name)}
        ${kv('Restart Count', d.restartCount)}
        ${kv('Finished At',   d.finishedAt && d.finishedAt !== '0001-01-01T00:00:00Z' ? new Date(d.finishedAt).toLocaleString() : '–')}
        ${kv('Total Volume Size', totalVolStr)}
        ${kvHtml('Restart Policy', `
          <div class="restart-policy-widget">
            <select class="restart-policy-select" id="rp-select-${d.id}" onchange="rpToggleRetries('${d.id}')">
              <option value="no"             ${(d.restartPolicy&&d.restartPolicy.name)==='no'             ? 'selected':''}>no (never restart)</option>
              <option value="always"         ${(d.restartPolicy&&d.restartPolicy.name)==='always'         ? 'selected':''}>always</option>
              <option value="unless-stopped" ${(d.restartPolicy&&d.restartPolicy.name)==='unless-stopped' ? 'selected':''}>unless-stopped</option>
              <option value="on-failure"     ${(d.restartPolicy&&d.restartPolicy.name)==='on-failure'     ? 'selected':''}>on-failure</option>
            </select>
            <input class="restart-policy-retries" id="rp-retries-${d.id}" type="number" min="0" max="99"
              placeholder="max retries"
              value="${(d.restartPolicy&&d.restartPolicy.name)==='on-failure' ? (d.restartPolicy.maximumRetryCount||0) : ''}"
              style="display:${(d.restartPolicy&&d.restartPolicy.name)==='on-failure'?'block':'none'}"/>
            <button class="cdetail-action-btn apply" id="rp-save-${d.id}"
              onclick="saveRestartPolicy('${d.id}')"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:4px;"><path d="M20 6 9 17l-5-5"/></svg><span>Apply</span></button>
            <span class="restart-policy-status" id="rp-status-${d.id}"></span>
          </div>`)}
      </div>`);

    // ── Container Details section ──
    const detailSection = section('clipboard-list', 'Container Details', `
      <div class="cdetail-grid" style="margin-bottom:12px;">
        ${kv('Image',      d.image)}
        ${kv('Image Hash', d.imageHash || '–')}
        ${kv('Image Size', d.imageSize || '–')}
      </div>
      ${kvHtml('CMD', `<span style="word-break:break-all;">${esc(d.cmd||'–')}</span>`, 'cdetail-val-full')}
      <div style="margin-top:10px;"></div>
      ${kvHtml('ENTRYPOINT', `<span style="word-break:break-all;">${esc(d.entrypoint||'–')}</span>`, 'cdetail-val-full')}
      <div style="margin-top:14px;">
        <div class="cdetail-key" style="margin-bottom:6px;">PORT CONFIGURATION</div>
        ${table(['Container Port','Host IP','Host Port'],
          (d.portConfig||[]).map(p=>`<tr><td>${esc(p.containerPort)}</td><td>${esc(p.hostIp)}</td><td>${esc(p.hostPort)}</td></tr>`),
          'No port mappings')}
      </div>
      <div style="margin-top:14px;">
        <div class="cdetail-key" style="margin-bottom:6px;">ENVIRONMENT VARIABLES</div>
        ${table(['Variable','Value'],
          (d.env||[]).map(e=>`<tr><td style="color:var(--accent);white-space:nowrap;">${esc(e.key)}</td><td style="color:var(--text2);">${esc(e.value)}</td></tr>`),
          'No environment variables')}
      </div>
      <div style="margin-top:14px;">
        <div class="cdetail-key" style="margin-bottom:6px;">LABELS</div>
        ${table(['Label','Value'],
          (d.labels||[]).map(l=>`<tr><td style="color:var(--accent);white-space:nowrap;max-width:250px;overflow:hidden;text-overflow:ellipsis;" title="${esc(l.key)}">${esc(l.key)}</td><td style="color:var(--text2);">${esc(l.value)}</td></tr>`),
          'No labels')}
      </div>`);

    // ── Volumes section ──
    const volumesSection = section('hard-drive', 'Volumes', table(
      ['Type','Source','Container Path','Mode','RW','SIZE'],
      (d.volumes||[]).map(v=>`<tr>
        <td style="color:var(--text3);">${esc(v.type)}</td>
        <td style="color:var(--accent);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(v.source)}">${esc(v.source)}</td>
        <td style="color:var(--text);">${esc(v.destination)}</td>
        <td style="color:var(--text3);">${esc(v.mode)}</td>
        <td style="${v.rw?'color:var(--green)':'color:var(--red)'};">${v.rw?'RW':'RO'}</td>
        <td style="color:var(--accent);white-space:nowrap;">${esc(v.sizeOnDisk||'–')}</td>
      </tr>`),
      'No volumes mounted'));

    // ── Networks section ──
    const networksSection = section('network', 'Connected Networks', table(
      ['Network Name','IP Address','Gateway','MAC Address'],
      (d.networks||[]).map(n=>`<tr>
        <td style="color:var(--accent);font-weight:600;">${esc(n.name)}</td>
        <td style="color:var(--accent);">${esc(n.ip||'–')}</td>
        <td style="color:var(--text3);">${esc(n.gateway||'–')}</td>
        <td style="color:var(--text3);">${esc(n.mac||'–')}</td>
      </tr>`),
      'No networks'));

    // ── Tab layout ──
    const isComposeOnly = d.composeOnly;
    const defaultTab = (isComposeOnly && composeBacked) ? 'compose' : 'status';
    const editorId = `compose-editor-${d.id}`;
    const statusId = `compose-save-status-${d.id}`;
    const saveId   = `compose-save-btn-${d.id}`;

    const statusPanelHtml = isComposeOnly
      ? `<div style="padding:48px 20px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;">No container running — use <strong style="color:var(--accent);font-style:normal;">Compose Up</strong> to start this service.</div>`
      : statusSection + detailSection + volumesSection + networksSection;

    const tabBar = `<div class="cdetail-tabs">
      <button class="cdetail-tab${defaultTab === 'status' ? ' active' : ''}" data-tab="status" onclick="switchCDetailTab('status')"><i data-lucide="activity" style="width:14px;height:14px;vertical-align:-2px;margin-right:5px"></i>Container Status</button>
      ${composeBacked ? `<button class="cdetail-tab${defaultTab === 'compose' ? ' active' : ''}" data-tab="compose" onclick="switchCDetailTab('compose')"><i data-lucide="file-code" style="width:14px;height:14px;vertical-align:-2px;margin-right:5px"></i>Compose File</button>` : ''}
      <button class="cdetail-tab" data-tab="folders" onclick="switchCDetailTab('folders')"><i data-lucide="folder" style="width:14px;height:14px;vertical-align:-2px;margin-right:5px"></i>Data Folders</button>
      <button class="cdetail-tab" data-tab="configfolder" onclick="switchCDetailTab('configfolder')"><i data-lucide="settings" style="width:14px;height:14px;vertical-align:-2px;margin-right:5px"></i>Configuration Folder</button>
    </div>`;

    el('cdetail-body').innerHTML = tabBar
      + `<div class="cdetail-tab-panel" id="cdetail-panel-status"${defaultTab !== 'status' ? ' style="display:none"' : ''}>`
      + statusPanelHtml
      + `</div>`
      + (composeBacked
          ? `<div class="cdetail-tab-panel compose-panel" id="cdetail-panel-compose"${defaultTab !== 'compose' ? ' style="display:none"' : ''}>`
            + `<div id="${editorId}-wrap" style="padding:20px;height:100%;box-sizing:border-box;display:flex;flex-direction:column;min-height:0;">`
            + `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;">⟳ Loading compose file…</div>`
            + `</div></div>`
          : '')
      + `<div class="cdetail-tab-panel" id="cdetail-panel-folders" style="display:none">`
      + `<div id="folders-content-${cid}" style="padding:16px;color:var(--text3);font-family:var(--mono);font-size:13px;">⟳ Loading…</div>`
      + `</div>`
      + `<div class="cdetail-tab-panel" id="cdetail-panel-configfolder" style="display:none">`
      + `<div id="configfolder-content-${cid}" style="padding:16px;color:var(--text3);font-family:var(--mono);font-size:13px;">⟳ Loading…</div>`
      + `</div>`;

    lucide.createIcons({ nodes: [el('cdetail-body')] });

    // ── Folders tabs ──
    loadFoldersTab(d.name, cid);
    loadConfigFolderTab(d.name, cid);

    // ── compose.yaml editor (compose-managed containers only) ──
    if (composeBacked) {
      try {
        const params = new URLSearchParams({ project: d.composeProject });
        if (d.composeFile) params.set('composeFile', d.composeFile);
        const fr = await fetch('/api/compose/file?' + params.toString());
        const fd = await fr.json();
        const wrap = document.getElementById(editorId + '-wrap');
        if (!wrap) return;
        if (!fd.ok) {
          wrap.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:12px;padding:8px 0;">⚠ ${esc(fd.error||'Failed to load compose file')}</div>`;
        } else {
          const composeUpInlineBtn = '';
          wrap.innerHTML = `
            <div class="compose-editor-head">
              <div style="font-size:11px;color:var(--text3);font-family:var(--mono);">${esc(fd.composeFile)}</div>
              ${composeUpInlineBtn}
            </div>
            <textarea id="${editorId}"
              class="compose-editor-textarea"
              data-project="${esc(d.composeProject)}"
              data-compose-file="${esc(fd.composeFile)}"
              data-save-id="${saveId}"
              data-status-id="${statusId}"
              spellcheck="false"
            ></textarea>
            <div style="display:flex;align-items:center;gap:10px;margin-top:8px;">
              <button id="${editorId}-edit" class="action-modal-btn blue"
                onclick="enableComposeEdit('${editorId}')"><i data-lucide="pencil" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;"></i>Edit</button>
              <button id="${editorId}-check" class="action-modal-btn blue" style="display:none;"
                onclick="checkComposeSyntax('${editorId}')"><i data-lucide="check" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;"></i>Apply</button>
              <span id="${statusId}" style="font-family:var(--mono);font-size:12px;"></span>
              <div style="flex:1;"></div>
              <button id="${saveId}" class="action-modal-btn ok" style="display:none;"
                onclick="saveComposeFile('${esc(d.composeProject)}','${esc(fd.composeFile)}','${editorId}','${saveId}','${statusId}')"><i data-lucide="save" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;"></i>Save</button>
            </div>`;
          const ta = document.getElementById(editorId);
          if (ta) {
            const originalValue = fd.composeFileContent || '';
            ta.value = originalValue;
            _composeEditorState = { editorId, originalValue };
            if (typeof initComposeHighlighting === 'function') {
              ta.classList.add('syntax-enabled');
              initComposeHighlighting(editorId);
            }
          }
          lucide.createIcons({ nodes: [wrap] });
        }
      } catch (e) {
        const wrap = document.getElementById(editorId + '-wrap');
        if (wrap) wrap.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:12px;padding:8px 0;">⚠ ${esc(e.message)}</div>`;
      }
    }

  } catch (e) {
    el('cdetail-body').innerHTML = `<div style="padding:30px;color:var(--red);font-family:var(--mono);">⚠ ${esc(e.message)}</div>`;
  }
}

