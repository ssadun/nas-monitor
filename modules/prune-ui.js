// ─── Prune ────────────────────────────────────────────────────────────────────
let pruneData = { images: [], networks: [], volumes: [] };

async function openPruneModal() {
  el('prune-modal').classList.add('open');
  el('prune-body').innerHTML = `<div style="padding:40px;text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;">⟳ Scanning for unused resources…</div>`;
  el('prune-summary').textContent = 'Scanning…';
  el('prune-confirm-btn').disabled = true;

  try {
    const res = await fetch('/api/prune/scan');
    pruneData = await res.json();
    renderPruneBody();
  } catch (e) {
    el('prune-body').innerHTML = `<div style="padding:30px;color:var(--red);font-family:var(--mono);font-size:12px;">⚠ Scan failed: ${esc(e.message)}</div>`;
  }
}

function renderPruneBody() {
  const { images, networks, volumes, buildCache, buildCacheTotal, buildCacheReclaimable } = pruneData;
  const total = images.length + networks.length + volumes.length + buildCache.length;

  el('prune-confirm-btn').disabled = total === 0;
  el('prune-select-all-btn').style.display = 'none';

  if (total === 0) {
    el('prune-body').innerHTML = `<div style="padding:40px;text-align:center;font-size:28px;">✅<br><span style="font-size:14px;color:var(--green);font-family:var(--mono);">Nothing to clean up!</span></div>`;
    el('prune-summary').textContent = 'Everything is tidy.';
    return;
  }

  el('prune-summary').textContent = `Found: ${images.length} image${images.length!==1?'s':''}, ${networks.length} network${networks.length!==1?'s':''}, ${volumes.length} volume${volumes.length!==1?'s':''}, ${buildCache.length} build cache entr${buildCache.length!==1?'ies':'y'}`;

  function previewList(items, nameKey) {
    if (!items.length) return '';
    const shown = items.slice(0, 10);
    const more  = items.length - shown.length;
    return shown.map(i => `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:1px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(i[nameKey] || i.name)}</div>`).join('')
      + (more > 0 ? `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);font-style:italic;">…and ${more} more</div>` : '');
  }

  function imageRows(items) {
    if (!items.length) return '';
    const shown = items.slice(0, 15);
    const more  = items.length - shown.length;
    const header = `
      <div style="display:flex;align-items:center;gap:10px;padding:5px 16px;background:var(--bg3);border-bottom:1px solid var(--border2);">
        <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);flex:1.2;">REPOSITORY</span>
        <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:60px;">TAG</span>
        <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:70px;text-align:right;">SIZE</span>
        <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:100px;text-align:right;">CREATED</span>
        <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:60px;text-align:right;">STATUS</span>
      </div>`;
    const rows = shown.map(i => `
      <div style="display:flex;align-items:center;gap:10px;padding:6px 16px;border-bottom:1px solid rgba(42,47,74,.25);">
        <span style="font-family:var(--mono);font-size:12px;color:var(--text);flex:1.2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${esc(i.repository || i.name)}">${esc(i.repository || i.name)}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text2);width:60px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(i.tag || '–')}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--cyan);width:70px;text-align:right;white-space:nowrap;">${esc(i.size || '–')}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3);width:100px;text-align:right;white-space:nowrap;">${esc(i.created || '–')}</span>
        <span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(249,115,22,.12);border:1px solid rgba(249,115,22,.3);color:var(--orange);font-family:var(--mono);width:60px;text-align:center;">${esc(i.reason)}</span>
      </div>`).join('');
    const moreRow = more > 0 ? `<div style="padding:5px 16px;font-family:var(--mono);font-size:11px;color:var(--text3);font-style:italic;">…and ${more} more</div>` : '';
    return header + rows + moreRow;
  }

  el('prune-body').innerHTML = `
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);background:rgba(249,115,22,.06);">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:18px;">⚠️</span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--orange);">docker system prune -a --volumes</span>
      </div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text3);line-height:1.6;">
        This will remove all stopped containers, unused networks, unused images, dangling volumes, and build cache.
        <span style="color:var(--red);">Running containers will not be affected.</span>
      </div>
    </div>
    ${images.length ? `
    <div style="padding:8px 16px 4px;background:var(--bg2);border-bottom:1px solid var(--border);">
      <span style="font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-family:var(--mono);">🖼 Images (${images.length})</span>
    </div>
    ${imageRows(images)}` : ''}
    ${networks.length ? `
    <div style="padding:8px 16px 4px;background:var(--bg2);border-bottom:1px solid var(--border);">
      <span style="font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-family:var(--mono);">🌐 Networks (${networks.length})</span>
    </div>
    ${networkRows(networks)}` : ''}
    ${volumes.length ? `
    <div style="padding:8px 16px 4px;background:var(--bg2);border-bottom:1px solid var(--border);">
      <span style="font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-family:var(--mono);">💾 Volumes (${volumes.length})</span>
    </div>
    ${volumeRows(volumes)}` : ''}
    ${buildCache.length ? `
    <div style="padding:8px 16px 4px;background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <span style="font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-family:var(--mono);">🔨 Build Cache (${buildCache.length})</span>
      ${buildCacheTotal ? `<span style="font-family:var(--mono);font-size:11px;color:var(--text3);">Total: <span style="color:var(--cyan);">${esc(buildCacheTotal)}</span>${buildCacheReclaimable ? `  ·  Reclaimable: <span style="color:var(--green);">${esc(buildCacheReclaimable)}</span>` : ''}</span>` : ''}
    </div>
    ${buildCacheRows(buildCache)}` : ''}`;
}

function networkRows(items) {
  if (!items.length) return '';
  const shown = items.slice(0, 15);
  const more  = items.length - shown.length;
  const header = `
    <div style="display:flex;align-items:center;gap:10px;padding:5px 16px;background:var(--bg3);border-bottom:1px solid var(--border2);">
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);flex:1;">NAME</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:80px;">DRIVER</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:60px;">SCOPE</span>
    </div>`;
  const rows = shown.map(n => `
    <div style="display:flex;align-items:center;gap:10px;padding:6px 16px;border-bottom:1px solid rgba(42,47,74,.25);">
      <span style="font-family:var(--mono);font-size:12px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${esc(n.name)}">${esc(n.name)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text2);width:80px;white-space:nowrap;">${esc(n.driver || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3);width:60px;white-space:nowrap;">${esc(n.scope || '–')}</span>
    </div>`).join('');
  const moreRow = more > 0 ? `<div style="padding:5px 16px;font-family:var(--mono);font-size:11px;color:var(--text3);font-style:italic;">…and ${more} more</div>` : '';
  return header + rows + moreRow;
}

function volumeRows(items) {
  if (!items.length) return '';
  const shown = items.slice(0, 15);
  const more  = items.length - shown.length;
  const header = `
    <div style="display:flex;align-items:center;gap:10px;padding:5px 16px;background:var(--bg3);border-bottom:1px solid var(--border2);">
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);flex:1;">NAME</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:60px;">DRIVER</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:90px;text-align:right;">CREATED</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);flex:1.5;padding-left:10px;">MOUNT PATH</span>
    </div>`;
  const rows = shown.map(v => `
    <div style="display:flex;align-items:center;gap:10px;padding:6px 16px;border-bottom:1px solid rgba(42,47,74,.25);">
      <span style="font-family:var(--mono);font-size:12px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${esc(v.name)}">${esc(v.name)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text2);width:60px;white-space:nowrap;">${esc(v.driver || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--cyan);width:90px;text-align:right;white-space:nowrap;">${esc(v.created || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3);flex:1.5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding-left:10px;"
        title="${esc(v.mountpoint)}">${esc(v.mountpoint || '–')}</span>
    </div>`).join('');
  const moreRow = more > 0 ? `<div style="padding:5px 16px;font-family:var(--mono);font-size:11px;color:var(--text3);font-style:italic;">…and ${more} more</div>` : '';
  return header + rows + moreRow;
}

function buildCacheRows(items) {
  if (!items.length) return '';
  const shown = items.slice(0, 20);
  const more  = items.length - shown.length;
  const header = `
    <div style="display:flex;align-items:center;gap:10px;padding:5px 16px;background:var(--bg3);border-bottom:1px solid var(--border2);">
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);flex:1;">ID</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:90px;text-align:right;">RECLAIMABLE</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:70px;text-align:right;">SIZE</span>
      <span style="font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.8px;color:var(--text3);width:130px;text-align:right;">LAST ACCESSED</span>
    </div>`;
  const rows = shown.map(c => `
    <div style="display:flex;align-items:center;gap:10px;padding:6px 16px;border-bottom:1px solid rgba(42,47,74,.25);">
      <span style="font-family:var(--mono);font-size:11px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${esc(c.id)}">${esc(c.id)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--green);width:90px;text-align:right;white-space:nowrap;">${esc(c.reclaimable || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--cyan);width:70px;text-align:right;white-space:nowrap;">${esc(c.size || '–')}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text3);width:130px;text-align:right;white-space:nowrap;">${esc(c.lastAccessed || '–')}</span>
    </div>`).join('');
  const moreRow = more > 0 ? `<div style="padding:5px 16px;font-family:var(--mono);font-size:11px;color:var(--text3);font-style:italic;">…and ${more} more</div>` : '';
  return header + rows + moreRow;
}

function pruneSelectAll() {} // no-op for system prune

async function confirmPrune() {
  el('prune-confirm-btn').disabled = true;
  el('prune-confirm-btn').textContent = '⟳ Running system prune…';


  try {
    const res = await fetch('/api/prune/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pruneSystem: true }),
    });
    const data = await res.json();
    if (data.ok) {
      const out = data.summary.pruneOutput || '';
      const reclaimedLine = out.split('\n').find(l => l.toLowerCase().includes('reclaimed')) || '';
      el('prune-body').innerHTML = `<div style="padding:30px 20px;text-align:center;">
        <div style="font-size:28px;margin-bottom:10px;">✅</div>
        <div style="font-size:14px;color:var(--green);font-family:var(--mono);margin-bottom:${reclaimedLine?'8px':'0'};">System prune complete.</div>
        ${reclaimedLine ? `<div style="font-size:12px;color:var(--cyan);font-family:var(--mono);">${esc(reclaimedLine.trim())}</div>` : ''}
        ${data.summary.errors && data.summary.errors.length ? `<div style="color:var(--red);font-size:12px;margin-top:8px;">${data.summary.errors.length} error(s) — see log.</div>` : ''}
      </div>`;
      el('prune-summary').textContent = 'Prune complete.';
      el('prune-confirm-btn').textContent = '✓ Done';
      el('prune-confirm-btn').disabled = false;
      el('prune-confirm-btn').onclick = closePruneModal;
    } else {
      el('prune-confirm-btn').textContent = '✕ Failed';
    }
  } catch (e) {
    el('prune-confirm-btn').textContent = '✕ Error';
  }
}

function closePruneModal() {
  el('prune-modal').classList.remove('open');
  el('prune-confirm-btn').textContent = '🗑 System Prune';
  el('prune-confirm-btn').disabled = false;
  el('prune-confirm-btn').onclick = confirmPrune;
  el('prune-select-all-btn').textContent = '☑ Select All';
}

async function openPruneLogModal() {
  el('prune-log-modal').classList.add('open');
  el('prune-log-body').textContent = 'Loading…';
  try {
    const res = await fetch('/api/prune/log');
    const data = await res.json();
    const lines = (data.log || '').trim().split('\n').filter(Boolean).reverse(); // newest first
    if (!lines.length) {
      el('prune-log-body').innerHTML = `<span style="color:var(--text3);">No prune activity yet.</span>`;
      return;
    }
    el('prune-log-body').innerHTML = lines.map(line => {
      const isSep    = line.includes('===');
      const isErr    = line.toLowerCase().includes('fail') || line.toLowerCase().includes('error');
      const color    = isSep ? 'var(--accent)' : isErr ? 'var(--red)' : 'var(--text)';
      return `<div style="color:${color};padding:1px 0;border-bottom:1px solid rgba(42,47,74,.2);">${esc(line)}</div>`;
    }).join('');
  } catch (e) {
    el('prune-log-body').textContent = 'Failed to load log.';
  }
}

function closePruneLogModal() {
  el('prune-log-modal').classList.remove('open');
}

el('prune-modal').addEventListener('click', e => { if (e.target === el('prune-modal')) closePruneModal(); });
el('prune-log-modal').addEventListener('click', e => { if (e.target === el('prune-log-modal')) closePruneLogModal(); });
el('cdetail-modal').addEventListener('click', e => {
  if (e.target !== el('cdetail-modal')) return;
  const composePanel = el('cdetail-panel-compose');
  if (composePanel && composePanel.style.display !== 'none') return;
  closeCDetailModal();
});

let _composeEditorState = { editorId: '', originalValue: '' };
let _composeDismissResolver = null;

function resetComposeEditorState() {
  _composeEditorState = { editorId: '', originalValue: '' };
}

function hasUnsavedComposeChanges() {
  if (!_composeEditorState.editorId) return false;
  const ta = document.getElementById(_composeEditorState.editorId);
  if (!ta) return false;
  return ta.value !== _composeEditorState.originalValue;
}

function closeComposeDismissModal(e) {
  if (e && e.target !== el('compose-dismiss-modal')) return;
  resolveComposeDismiss(false);
}

function resolveComposeDismiss(shouldDismiss) {
  el('compose-dismiss-modal').classList.remove('open');
  if (_composeDismissResolver) {
    const resolver = _composeDismissResolver;
    _composeDismissResolver = null;
    resolver(shouldDismiss);
  }
}

function confirmDismissComposeChanges() {
  if (!hasUnsavedComposeChanges()) return Promise.resolve(true);
  return new Promise(resolve => {
    _composeDismissResolver = resolve;
    el('compose-dismiss-modal').classList.add('open');
  });
}

window.addEventListener('beforeunload', e => {
  if (!hasUnsavedComposeChanges()) return;
  e.preventDefault();
  e.returnValue = '';
});

