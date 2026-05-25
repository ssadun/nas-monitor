// ─── Image Updates ────────────────────────────────────────────────────────────
let _imgUpdateResults = [];

async function openImageUpdatesModal() {
  el('imgupdate-modal').classList.add('open');
  el('imgupdate-body').innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;"><span class="spin" style="font-size:20px;">⟳</span><br><br>Checking registries for updates…</div>`;
  el('imgupdate-summary').textContent = 'Scanning…';
  el('imgupdate-scan-btn').disabled = true;

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

  const header = `
    <div style="display:grid;grid-template-columns:1fr 90px 90px 160px 120px;gap:8px;align-items:center;padding:6px 16px;background:var(--card-bg);border-bottom:1px solid var(--border2);">
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">IMAGE</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">REGISTRY</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">TAG</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);">STATUS</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);text-align:right;">ACTIONS</span>
    </div>`;

  function renderRow(r) {
    const statusHtml = r.error
      ? `<span title="${esc(r.error)}" style="color:var(--text3);font-size:12px;font-family:var(--mono);">⚠ ${esc(r.error.slice(0, 40))}${r.error.length > 40 ? '…' : ''}</span>`
      : r.updateAvailable
        ? `<span style="color:var(--yellow);font-family:var(--mono);font-size:12px;font-weight:600;">● Update Available</span>`
        : `<span style="color:var(--green);font-family:var(--mono);font-size:12px;">✓ Up To Date</span>`;

    const ctrNames = (r.containers || []).filter(Boolean).join(', ');

    const actionBtns = r.updateAvailable
      ? `<div style="display:flex;gap:6px;justify-content:flex-end;">
           <button class="action-modal-btn ok" style="padding:3px 10px;font-size:12px;" onclick="imgUpdatePull('${esc(r.image)}', false)">Pull</button>
           <button class="action-modal-btn lavender" style="padding:3px 10px;font-size:12px;" onclick="imgUpdatePull('${esc(r.image)}', true, ${JSON.stringify(r.containers || []).replace(/"/g, '&quot;')})">Pull &amp; Restart</button>
         </div>`
      : '';

    return `<div class="imgupdate-row" style="display:grid;grid-template-columns:1fr 90px 90px 160px 120px;gap:8px;align-items:center;padding:8px 16px;border-bottom:1px solid rgba(42,47,74,.25);" title="${ctrNames ? 'Containers: ' + esc(ctrNames) : ''}">
      <span style="font-family:var(--mono);font-size:12px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(r.image)}">${esc(r.image)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3);">${esc(r.registry || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--accent);">${esc(r.tag || 'latest')}</span>
      <span>${statusHtml}</span>
      <span>${actionBtns}</span>
    </div>`;
  }

  const rows = [
    ...updates.map(renderRow),
    ...errors.map(renderRow),
    ...upToDate.map(renderRow),
  ].join('');

  el('imgupdate-body').innerHTML = header + (rows || `<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px;">No images found.</div>`);
}

async function imgUpdatePull(image, restart, containers) {
  const ctrs = Array.isArray(containers) ? containers : [];
  const btn = event.currentTarget || event.target;
  const origText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spin">⟳</span>';

  try {
    const res = await fetch('/api/image-updates/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image, restart, containers: ctrs }),
    });
    const data = await res.json();
    if (data.ok) {
      showToast(`Pulled ${image}${restart ? ' and restarted containers' : ''}`, 'ok', 3000);
      // Re-scan to refresh statuses
      await openImageUpdatesModal();
    } else {
      showToast(`Pull failed: ${data.error || 'unknown error'}`, 'err', 4000);
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  } catch (e) {
    showToast(`Pull error: ${e.message}`, 'err', 4000);
    btn.disabled = false;
    btn.innerHTML = origText;
  }
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
        if (line.startsWith('───')) return `<span style="color:var(--accent);opacity:.5;">${esc(line)}</span>`;
        if (/PULL FAIL|PULL ERROR|Scan failed|Restart failed/.test(line)) return `<span style="color:var(--red);">${esc(line)}</span>`;
        if (/UPDATE AVAILABLE/.test(line)) return `<span style="color:var(--yellow);">${esc(line)}</span>`;
        if (/PULL OK|Auto-restarted|all up to date/.test(line)) return `<span style="color:var(--green);">${esc(line)}</span>`;
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
