// ─── Docker Volumes Manager ──────────────────────────────────────────────────
let allDockerVolumes = [];

async function openDockerVolumesModal() {
  document.getElementById('volmgr-backdrop').classList.add('open');
  await refreshDockerVolumesList();
}

function closeDockerVolumesModal(e) {
  if (e && e.target !== document.getElementById('volmgr-backdrop')) return;
  document.getElementById('volmgr-backdrop').classList.remove('open');
}

async function refreshDockerVolumesList() {
  const body = document.getElementById('volmgr-body');
  body.innerHTML = `<div style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px;">Loading docker volumes…</div>`;
  try {
    const res = await fetch('/api/docker/volumes/list');
    const data = await res.json();
    if (!res.ok || !data.ok) {
      body.innerHTML = `<div style="text-align:center;color:var(--red);font-family:var(--mono);font-size:13px;padding:20px;">✗ ${esc(data.error || 'Failed to load volumes')}</div>`;
      return;
    }
    allDockerVolumes = Array.isArray(data.volumes) ? data.volumes : [];
    renderDockerVolumesList();
  } catch (e) {
    body.innerHTML = `<div style="text-align:center;color:var(--red);font-family:var(--mono);font-size:13px;padding:20px;">✗ ${esc(e.message)}</div>`;
  }
}

function renderDockerVolumesList() {
  const body = document.getElementById('volmgr-body');
  if (!allDockerVolumes.length) {
    body.innerHTML = `<div style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px;">No docker volumes found. Create one below.</div>`;
    return;
  }

  const rows = allDockerVolumes.map((v, i) => {
    const containerCount = Array.isArray(v.runningOn) ? v.runningOn.length : 0;
    const containerCountText = containerCount > 0 ? String(containerCount) : '–';
    return `<tr>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(v.stack || '-')}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(v.driver || '-')}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(v.mountpoint || '-')}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(v.ownership || '-')}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(v.createdDate || '-')}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(containerCountText)}</td>
      <td style="white-space:nowrap;"><div style="display:flex;gap:6px;justify-content:flex-end;">
        <button class="list-btn blue" onclick="openDockerVolumeDetail(${i})"><i data-lucide="eye" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>View</button>
        <button class="list-btn red" onclick="deleteDockerVolume(${i})"><i data-lucide="trash-2" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Delete</button>
      </div></td>
    </tr>`;
  }).join('');

  body.innerHTML = `
    <div style="font-size:11px;color:var(--text3);font-family:var(--mono);margin-bottom:8px;">${allDockerVolumes.length} volume(s)</div>
    <div style="overflow:auto;border:1px solid var(--border);border-radius:10px;">
      <table class="cdetail-table" style="min-width:980px;">
        <thead>
          <tr>
            <th>Stack</th>
            <th>Driver</th>
            <th>Mount Point</th>
            <th>Ownership</th>
            <th>Created Date</th>
            <th>Container Count</th>
            <th style="width:130px;">Actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  lucide.createIcons({ nodes: [body] });
}

function openDockerVolumeCreateForm() {
  const body = document.getElementById('volmgr-body');
  body.innerHTML = `
    <div class="catedit-form">
      <div class="catedit-row">
        <div class="catedit-label">Volume Name</div>
        <input class="filter-input netedit-input" id="volcreate-name" placeholder="e.g. app_data" />
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Driver</div>
        <select class="catedit-input" id="volcreate-driver">
          <option value="local" selected>local</option>
          <option value="nfs">nfs</option>
        </select>
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Stack Label (optional)</div>
        <input class="filter-input netedit-input" id="volcreate-stack" placeholder="e.g. my-stack" />
      </div>
      <div class="catedit-actions">
        <button class="action-modal-btn cancel" onclick="renderDockerVolumesList()"><i data-lucide="x" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>Cancel</button>
        <button class="action-modal-btn ok" onclick="createDockerVolume()"><i data-lucide="check" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>Create Volume</button>
      </div>
    </div>`;
  lucide.createIcons({ nodes: [body] });
}

async function createDockerVolume() {
  const name = String(document.getElementById('volcreate-name')?.value || '').trim();
  const driver = String(document.getElementById('volcreate-driver')?.value || 'local').trim();
  const stack = String(document.getElementById('volcreate-stack')?.value || '').trim();
  if (!name) {
    alert('Volume name is required');
    return;
  }
  try {
    const labels = stack ? { 'com.docker.compose.project': stack } : {};
    const res = await fetch('/api/docker/volumes/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, driver, labels }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      alert('Error: ' + (data.error || 'Failed to create volume'));
      return;
    }
    await refreshDockerVolumesList();
  } catch (e) {
    alert('Error creating volume: ' + e.message);
  }
}

async function openDockerVolumeDetail(idx) {
  const v = allDockerVolumes[idx];
  if (!v) return;
  const body = document.getElementById('volmgr-body');
  body.innerHTML = `<div style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px;">Loading volume details…</div>`;
  try {
    const res = await fetch('/api/docker/volumes/detail?name=' + encodeURIComponent(v.name));
    const data = await res.json();
    if (!res.ok || !data.ok || !data.volume) {
      body.innerHTML = `<div style="text-align:center;color:var(--red);font-family:var(--mono);font-size:13px;padding:20px;">✗ ${esc(data.error || 'Failed to load volume details')}</div>`;
      return;
    }
    const d = data.volume;
    const labels = d.labels && Object.keys(d.labels).length
      ? `<table class="cdetail-table"><thead><tr><th>Label</th><th>Value</th></tr></thead><tbody>${Object.entries(d.labels).map(([k,val]) => `<tr><td style="font-family:var(--mono);font-size:12px;color:var(--accent);">${esc(k)}</td><td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(String(val ?? ''))}</td></tr>`).join('')}</tbody></table>`
      : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;">No labels</div>`;
    const containers = Array.isArray(d.containers) && d.containers.length
      ? `<table class="cdetail-table"><thead><tr><th>Container</th><th>Status</th><th>Mount Path</th></tr></thead><tbody>${d.containers.map(c => `<tr><td style="font-family:var(--mono);font-size:12px;color:var(--text);">${esc(c.name || c.id || '-')}</td><td style="font-family:var(--mono);font-size:12px;color:${c.status==='running'?'var(--green)':'var(--text3)'};">${esc(c.status || '-')}</td><td style="font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(c.destination || '-')}</td></tr>`).join('')}</tbody></table>`
      : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;">No containers using this volume</div>`;

    const labelsHtml = d.labels && Object.keys(d.labels).length
      ? Object.entries(d.labels).map(([k,val]) => `<div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;"><span style="color:var(--text3);margin-right:20px;width:200px;display:inline-block;">${esc(k)}</span><span style="color:var(--text);">${esc(String(val ?? ''))}</span></div>`).join('')
      : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:8px 0;">No labels</div>`;
    
    const containersHtml = Array.isArray(d.containers) && d.containers.length
      ? `<table style="width:100%;border-collapse:collapse;">
           <thead style="border-bottom:1px solid var(--border);">
             <tr>
               <th style="text-align:left;padding:10px 0;font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;">Container Name</th>
               <th style="text-align:left;padding:10px 0;font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;">Mounted At</th>
               <th style="text-align:left;padding:10px 0;font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:0.5px;">Read-only</th>
             </tr>
           </thead>
           <tbody>
             ${d.containers.map(c => `
               <tr style="border-bottom:1px solid rgba(42,47,74,.5);">
                 <td style="padding:10px 0;font-family:var(--mono);font-size:12px;color:var(--accent);">${esc(c.name || c.id || '-')}</td>
                 <td style="padding:10px 0;font-family:var(--mono);font-size:12px;color:var(--text2);">${esc(c.destination || '-')}</td>
                 <td style="padding:10px 0;font-family:var(--mono);font-size:12px;color:var(--text2);">${c.readonly === true ? 'true' : 'true'}</td>
               </tr>
             `).join('')}
           </tbody>
         </table>`
      : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:8px 0;">No containers using this volume</div>`;

    body.innerHTML = `
      <div style="padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;">
        <div style="font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;">
          <i data-lucide="clipboard-list" style="width:16px;height:16px;color:var(--accent);"></i>
          Volume Details
        </div>
        <button class="list-btn blue" onclick="renderDockerVolumesList()"><i data-lucide="arrow-left" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Back</button>
      </div>

      <div style="margin-bottom:20px;">
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;">
          <span style="color:var(--text3);margin-right:20px;width:100px;display:inline-block;font-weight:600;">ID</span>
          <span style="color:var(--text);">${esc(d.name)}</span>
        </div>
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;">
          <span style="color:var(--text3);margin-right:20px;width:100px;display:inline-block;font-weight:600;">Created</span>
          <span style="color:var(--text);">${esc(d.createdDate || '-')}</span>
        </div>
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;">
          <span style="color:var(--text3);margin-right:20px;width:100px;display:inline-block;font-weight:600;">Mount path</span>
          <span style="color:var(--text);">${esc(d.mountpoint || '-')}</span>
        </div>
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;">
          <span style="color:var(--text3);margin-right:20px;width:100px;display:inline-block;font-weight:600;">Driver</span>
          <span style="color:var(--text);">${esc(d.driver || '-')}</span>
        </div>
        <div style="padding:12px 0;">
          <div style="color:var(--text3);margin-bottom:8px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">Labels</div>
          <div style="margin-left:0;">${labelsHtml}</div>
        </div>
      </div>

      <div style="padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:20px;">
        <div style="font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;">
          <i data-lucide="shield" style="width:16px;height:16px;color:var(--accent);"></i>
          Access Control
        </div>
      </div>

      <div style="margin-bottom:20px;">
        <div style="padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;">
          <span style="color:var(--text3);margin-right:20px;width:120px;display:inline-block;font-weight:600;">Ownership</span>
          <span style="color:var(--text);">${esc(d.access?.owner || '-')}</span>
          <a href="#" style="cursor:default;color:var(--accent);margin-left:10px;font-size:11px;text-decoration:none;opacity:0.5;">Change ownership</a>
        </div>
      </div>

      <div style="padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:20px;">
        <div style="font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;">
          <i data-lucide="package" style="width:16px;height:16px;color:var(--accent);"></i>
          Containers Using Volume
        </div>
      </div>

      <div style="margin-bottom:20px;">
        ${containersHtml}
      </div>
    `;
    lucide.createIcons({ nodes: [body] });
  } catch (e) {
    body.innerHTML = `<div style="text-align:center;color:var(--red);font-family:var(--mono);font-size:13px;padding:20px;">✗ ${esc(e.message)}</div>`;
  }
}

async function deleteDockerVolume(idx) {
  const v = allDockerVolumes[idx];
  if (!v) return;
  if (!confirm(`Delete volume "${v.name}"? This cannot be undone.`)) return;
  await deleteDockerVolumeByName(v.name);
}

async function deleteDockerVolumeByName(volumeName) {
  if (!confirm(`Delete volume "${volumeName}"? This cannot be undone.`)) return;
  try {
    const res = await fetch('/api/docker/volumes/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: volumeName }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      alert('Error: ' + (data.error || 'Failed to delete volume'));
      return;
    }
    await refreshDockerVolumesList();
  } catch (e) {
    alert('Error deleting volume: ' + e.message);
  }
}

