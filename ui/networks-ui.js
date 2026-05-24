// ─── Network Management ────────────────────────────────────────────────────────
let allNetworks = [];
const SYSTEM_NETWORKS = new Set(['bridge', 'host', 'none']);
let _networkDeletePending = null;

async function openNetworkMgr() {
  try {
    const res = await fetch('/api/network/list');
    allNetworks = await res.json();
    // Filter out system networks
    allNetworks = allNetworks.filter(n => !SYSTEM_NETWORKS.has(n.name));
  } catch (e) {
    console.error('Failed to load networks:', e);
    allNetworks = [];
  }
  renderNetworkMgrList();
  document.getElementById('netmgr-backdrop').classList.add('open');
}

function closeNetworkMgr(e) {
  if (e && e.target !== document.getElementById('netmgr-backdrop')) return;
  document.getElementById('netmgr-backdrop').classList.remove('open');
}

function renderNetworkMgrList() {
  const body = document.getElementById('netmgr-body');
  if (!allNetworks.length) {
    body.innerHTML = `<div style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px;">No custom networks. Create one below.</div>`;
    return;
  }
  body.innerHTML = allNetworks.map((net, i) => `
    <div class="catmgr-row" id="netmgr-row-${i}">
      <div class="catmgr-row-icon" style="color:var(--coral)"><i data-lucide="cable"></i></div>
      <div class="catmgr-row-label" style="flex:1;">
        <div style="color:var(--text1);font-weight:500;">${esc(net.name)}</div>
        <div style="color:var(--text3);font-size:11px;margin-top:2px;">${esc(net.driver || 'unknown')} · ${net.containers ? net.containers.length + ' containers' : 'no containers'}</div>
      </div>
      <div class="catmgr-row-actions">
        <button class="catmgr-btn edit" onclick="openNetworkEditForm(${i})">Edit</button>
        <button class="catmgr-btn del"  onclick="openNetworkDeleteModal(${i})">Delete</button>
      </div>
    </div>
  `).join('');
  lucide.createIcons({ nodes: [body] });
}

function openNetworkEditForm(idx) {
  const isNew = idx === null;
  const net = isNew ? { name: '', driver: 'bridge', subnet: '' } : { ...allNetworks[idx] };
  
  const body = document.getElementById('netmgr-body');
  body.innerHTML = `
    <div class="catedit-form">
      <div class="catedit-row">
        <div class="catedit-label">Network Name</div>
        <input class="filter-input netedit-input" id="netedit-name" placeholder="e.g. my-network" value="${esc(net.name)}" ${isNew ? '' : 'disabled'}/>
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Driver</div>
        <select class="catedit-input" id="netedit-driver">
          <option value="bridge" ${net.driver === 'bridge' ? 'selected' : ''}>bridge</option>
          <option value="overlay" ${net.driver === 'overlay' ? 'selected' : ''}>overlay</option>
          <option value="macvlan" ${net.driver === 'macvlan' ? 'selected' : ''}>macvlan</option>
          <option value="ipvlan" ${net.driver === 'ipvlan' ? 'selected' : ''}>ipvlan</option>
        </select>
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Subnet (optional)</div>
        <input class="filter-input netedit-input" id="netedit-subnet" placeholder="e.g. 172.20.0.0/16" value="${esc(net.subnet || '')}"/>
      </div>
      <div class="catedit-actions">
        <button class="action-modal-btn cancel" onclick="renderNetworkMgrList()">Cancel</button>
        <button class="action-modal-btn ok" onclick="saveNetwork(${isNew ? 'null' : idx})">${isNew ? 'Create Network' : 'Update Network'}</button>
      </div>
    </div>
  `;
}

async function saveNetwork(idx) {
  const name = document.getElementById('netedit-name').value.trim();
  const driver = document.getElementById('netedit-driver').value;
  const subnet = document.getElementById('netedit-subnet').value.trim();
  
  if (!name) { alert('Network name is required'); return; }
  
  try {
    const isEdit = idx !== null;
    const endpoint = isEdit ? '/api/network/update' : '/api/network/create';
    const payload = isEdit
      ? { name: allNetworks[idx].name, driver, subnet: subnet || null }
      : { name, driver, subnet: subnet || null };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    
    if (!res.ok || !data.ok) {
      alert('Error: ' + (data.error || `Failed to ${isEdit ? 'update' : 'create'} network`));
      return;
    }
    
    // Reload and refresh UI
    await openNetworkMgr();
  } catch (e) {
    console.error('Failed to save network:', e);
    alert('Error saving network: ' + e.message);
  }
}

function openNetworkDeleteModal(idx) {
  const net = allNetworks[idx];
  if (!net || SYSTEM_NETWORKS.has(net.name)) return;
  _networkDeletePending = { idx, name: net.name };
  const containers = Array.isArray(net.containers) ? net.containers.length : 0;
  el('net-delete-network').textContent = net.name;
  el('net-delete-desc').innerHTML = `Permanently delete network <strong>${esc(net.name)}</strong>?<br><span style="color:var(--red);font-size:12px;">⚠ This cannot be undone.${containers > 0 ? ` ${containers} connected container(s) will be disconnected.` : ''}</span>`;
  el('net-delete-progress').innerHTML = '';
  const btn = el('net-delete-confirm');
  btn.textContent = 'Delete Network';
  btn.disabled = false;
  btn.dataset.mode = 'delete';
  el('net-delete-modal').classList.add('open');
}

function closeNetworkDeleteModal(e) {
  if (e && e.target !== el('net-delete-modal')) return;
  el('net-delete-modal').classList.remove('open');
  _networkDeletePending = null;
}

async function confirmDeleteNetwork() {
  const btn = el('net-delete-confirm');
  if (!btn) return;
  if (btn.dataset.mode === 'close') {
    closeNetworkDeleteModal();
    return;
  }
  if (!_networkDeletePending) return;

  const step = addProgressStep('Deleting network…', 'active');
  btn.disabled = true;

  try {
    const { name } = _networkDeletePending;
    const res = await fetch('/api/network/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });
    const data = await res.json();
    
    if (!res.ok || !data.ok) {
      updateStep(step, 'error', data.error || 'Failed to delete network');
      btn.textContent = 'Close';
      btn.dataset.mode = 'close';
      btn.disabled = false;
      return;
    }

    updateStep(step, 'done', 'Network deleted');
    btn.textContent = 'Close';
    btn.dataset.mode = 'close';
    btn.disabled = false;
    
    // Reload and refresh UI
    await openNetworkMgr();
  } catch (e) {
    console.error('Failed to delete network:', e);
    updateStep(step, 'error', 'Error deleting network: ' + e.message);
    btn.textContent = 'Close';
    btn.dataset.mode = 'close';
    btn.disabled = false;
  }
}





if ('serviceWorker' in navigator && window.isSecureContext) {
  window.addEventListener('load', () => {
    initTableResize();
    navigator.serviceWorker.register('/pwa/sw.js', { scope: '/' }).catch(err => {
      console.warn('Service worker registration failed:', err);
    });
  });
}

