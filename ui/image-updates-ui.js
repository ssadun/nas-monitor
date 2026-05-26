// ─── Image Updates ────────────────────────────────────────────────────────────
let _imgUpdateResults = [];
let _imgUpdateSelected = new Set();

async function openImageUpdatesModal() {
  el('imgupdate-modal').classList.add('open');
  el('imgupdate-body').innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;"><span class="spin" style="font-size:20px;">⟳</span><br><br>Checking registries for updates…</div>`;
  el('imgupdate-summary').textContent = 'Scanning…';
  el('imgupdate-scan-btn').disabled = true;
  _imgUpdateSelected.clear();
  updateImgUpdateBulkButtons();

  try {
    const res = await fetch('/api/image-updates/scan');
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Scan failed');
    _imgUpdateResults = data.results || [];
    renderImageUpdatesBody();
  } catch (e) {
    el('imgupdate-body').innerHTML = `<div style="padding:30px;color:var(--red);font-family:var(--mono);font-size:12px;">⚠ Scan failed: ${esc(e.message)}</div>`;
    el('imgupdate-summary').textContent = 'Scan failed.';
  } finally {
    el('imgupdate-scan-btn').disabled = false;
  }
}

function renderImageUpdatesBody() {
  const results = _imgUpdateResults;
  if (!results.length) {
    el('imgupdate-body').innerHTML = `<div style="padding:40px;text-align:center;font-size:28px;">🐋<br><span style="font-size:14px;color:var(--text3);font-family:var(--mono);">No running containers found.</span></div>`;
    el('imgupdate-summary').textContent = 'No images to check.';
    updateImgUpdateBulkButtons();
    return;
  }

  const updates   = results.filter(r => r.updateAvailable);
  const errors    = results.filter(r => r.error && !r.updateAvailable);
  const upToDate  = results.filter(r => !r.updateAvailable && !r.error);

  let summary = `${results.length} image${results.length !== 1 ? 's' : ''} checked`;
  if (updates.length) summary += ` · <span style="color:var(--yellow);font-weight:600;">${updates.length} update${updates.length !== 1 ? 's' : ''} available</span>`;
  else summary += ' · <span style="color:var(--green);">all up to date</span>';
  if (errors.length) summary += ` · <span style="color:var(--red);">${errors.length} error${errors.length !== 1 ? 's' : ''}</span>`;
  el('imgupdate-summary').innerHTML = summary;

  const allUpdatable = updates.map(r => r.image);
  const allChecked = allUpdatable.length > 0 && allUpdatable.every(img => _imgUpdateSelected.has(img));

  const header = `
    <div style="display:grid;grid-template-columns:28px 1fr 90px 90px 160px;gap:8px;align-items:center;padding:6px 16px;background:var(--card-bg);border-bottom:1px solid var(--border2);">
      <span style="text-align:center;"><input type="checkbox" id="imgupdate-select-all" onchange="imgUpdateSelectAll(this.checked)" ${allChecked && allUpdatable.length > 0 ? 'checked' : ''} ${allUpdatable.length === 0 ? 'disabled' : ''} title="Select All Updates" style="width:14px;height:14px;cursor:pointer;accent-color:var(--accent);"></span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">IMAGE</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">REGISTRY</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">TAG</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">STATUS</span>
    </div>`;

  function renderRow(r) {
    const statusHtml = r.error
      ? `<span title="${esc(r.error)}" style="color:var(--text3);font-size:11px;font-family:var(--mono);">⚠ ${esc(r.error.slice(0, 40))}${r.error.length > 40 ? '…' : ''}</span>`
      : r.updateAvailable
        ? `<span style="color:var(--yellow);font-family:var(--mono);font-size:11px;font-weight:600;">● Update Available</span>`
        : `<span style="color:var(--green);font-family:var(--mono);font-size:11px;">✓ Up To Date</span>`;

    const ctrNames = (r.containers || []).filter(Boolean).join(', ');

    const isUpdatable = r.updateAvailable;
    const checkboxHtml = isUpdatable
      ? `<input type="checkbox" data-image="${esc(r.image)}" data-containers="${esc(JSON.stringify(r.containers || []))}" onchange="imgUpdateToggleSelect('${esc(r.image)}', this.checked)" ${_imgUpdateSelected.has(r.image) ? 'checked' : ''} style="width:14px;height:14px;cursor:pointer;accent-color:var(--accent);">`
      : `<input type="checkbox" disabled style="width:14px;height:14px;cursor:not-allowed;opacity:0.3;">`;

    return `<div class="imgupdate-row" style="display:grid;grid-template-columns:28px 1fr 90px 90px 160px;gap:8px;align-items:center;padding:8px 16px;border-bottom:1px solid rgba(42,47,74,.25);" title="${ctrNames ? 'Containers: ' + esc(ctrNames) : ''}">
      <span style="text-align:center;">${checkboxHtml}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(r.image)}">${esc(r.image)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3);">${esc(r.registry || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--accent);">${esc(r.tag || 'latest')}</span>
      <span>${statusHtml}</span>
    </div>`;
  }

  const rows = [
    ...updates.map(renderRow),
    ...errors.map(renderRow),
    ...upToDate.map(renderRow),
  ].join('');

  el('imgupdate-body').innerHTML = header + (rows || `<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px;">No images found.</div>`);
  lucide.createIcons({ nodes: [el('imgupdate-body')] });
  updateImgUpdateBulkButtons();
}

function closeImageUpdatesModal() {
  el('imgupdate-modal').classList.remove('open');
}

async function openImageUpdateLogModal() {
  el('imgupdate-log-modal').classList.add('open');
  el('imgupdate-log-body').textContent = 'Loading…';
  try {
    const res = await fetch('/api/image-updates/log');
    const data = await res.json();
    const raw = (data.log || '').trim();
    if (!raw) {
      el('imgupdate-log-body').innerHTML = '<span style="color:var(--text3);">No log entries yet.</span>';
    } else {
      const lines = raw.split('\n').reverse();
      el('imgupdate-log-body').innerHTML = lines.map(line => {
        if (line.startsWith('───') || /Scheduled scan started/.test(line)) return `<span style="color:var(--accent);opacity:.5;">${esc(line)}</span>`;
        if (/PULL FAIL|PULL ERROR|SCAN FAIL|Scan failed|RESTART FAIL|Restart failed/.test(line)) return `<span style="color:var(--red);">${esc(line)}</span>`;
        if (/UPDATE AVAILABLE/.test(line)) return `<span style="color:var(--yellow);">${esc(line)}</span>`;
        if (/PULL OK|RESTART OK|Auto-restarted|all up to date|SCAN OK/.test(line)) return `<span style="color:var(--green);">${esc(line)}</span>`;
        if (/USER SCAN|USER PULL/.test(line)) return `<span style="color:var(--cyan);">${esc(line)}</span>`;
        return `<span style="color:var(--text3);">${esc(line)}</span>`;
      }).join('\n');
    }
  } catch (e) {
    el('imgupdate-log-body').textContent = 'Failed to load log: ' + e.message;
  }
}

function closeImageUpdateLogModal() {
  el('imgupdate-log-modal').classList.remove('open');
}

// ─── Bulk selection helpers ──────────────────────────────────────────────────

function imgUpdateToggleSelect(image, checked) {
  if (checked) _imgUpdateSelected.add(image);
  else _imgUpdateSelected.delete(image);
  updateImgUpdateBulkButtons();
  updateSelectAllCheckbox();
}

function imgUpdateSelectAll(checked) {
  const updates = _imgUpdateResults.filter(r => r.updateAvailable);
  if (checked) {
    updates.forEach(r => _imgUpdateSelected.add(r.image));
  } else {
    _imgUpdateSelected.clear();
  }
  document.querySelectorAll('#imgupdate-body input[type="checkbox"][data-image]').forEach(cb => {
    cb.checked = checked;
  });
  updateImgUpdateBulkButtons();
}

function updateSelectAllCheckbox() {
  const selectAllCb = el('imgupdate-select-all');
  if (!selectAllCb) return;
  const updates = _imgUpdateResults.filter(r => r.updateAvailable);
  if (updates.length === 0) {
    selectAllCb.checked = false;
    selectAllCb.disabled = true;
  } else {
    selectAllCb.disabled = false;
    selectAllCb.checked = updates.every(r => _imgUpdateSelected.has(r.image));
  }
}

function updateImgUpdateBulkButtons() {
  const pullRestartBtn = el('imgupdate-bulk-pull-restart');
  if (!pullRestartBtn) return;
  const count = _imgUpdateSelected.size;
  pullRestartBtn.disabled = count === 0;
  pullRestartBtn.innerHTML = `<i data-lucide="refresh-cw" style="width:13px;height:13px;stroke-width:2;vertical-align:middle;margin-right:4px;"></i>Pull &amp; Restart${count > 0 ? ` (${count})` : ''}`;
  lucide.createIcons({ nodes: [pullRestartBtn] });
}

async function imgUpdateBulkPull() {
  if (_imgUpdateSelected.size === 0) return;

  const selected = Array.from(_imgUpdateSelected);
  showToast(`Pull & Restart: ${selected.length} image${selected.length !== 1 ? 's' : ''}…`, 'info', 2000);

  let successCount = 0;
  let failCount = 0;

  for (const image of selected) {
    const entry = _imgUpdateResults.find(r => r.image === image);
    const containers = entry ? (entry.containers || []) : [];

    try {
      const res = await fetch('/api/image-updates/pull', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image, restart: true, containers }),
      });
      const data = await res.json();
      if (data.ok) successCount++;
      else failCount++;
    } catch {
      failCount++;
    }
  }

  if (failCount === 0) {
    showToast(`Pull & Restart complete: ${successCount} image${successCount !== 1 ? 's' : ''}`, 'ok', 3000);
  } else {
    showToast(`Pull & Restart: ${successCount} succeeded, ${failCount} failed`, failCount > 0 ? 'err' : 'ok', 4000);
  }

  _imgUpdateSelected.clear();
  await openImageUpdatesModal();
}
