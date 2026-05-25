// ─── Credentials modal ───────────────────────────────────────────────────────
function openCredentialsModal() {
  ['creds-current','creds-user','creds-pass','creds-confirm'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  document.getElementById('creds-error').style.display   = 'none';
  document.getElementById('creds-success').style.display = 'none';
  document.getElementById('creds-strength-fill').style.width = '0';
  document.getElementById('creds-strength-label').textContent = '';
  document.getElementById('creds-backdrop').classList.add('open');
  lucide.createIcons({ nodes: [document.getElementById('creds-backdrop')] });
  setTimeout(() => document.getElementById('creds-current').focus(), 80);
}

function closeCredentialsModal(e) {
  if (e && e.target !== document.getElementById('creds-backdrop')) return;
  document.getElementById('creds-backdrop').classList.remove('open');
}

function openSettingsModal() {
  document.getElementById('settings-backdrop').classList.add('open');
  lucide.createIcons({ nodes: [document.getElementById('settings-backdrop')] });
  if (typeof loadSettingsForm === 'function') loadSettingsForm();
}

function closeSettingsModal() {
  document.getElementById('settings-backdrop').classList.remove('open');
}

function checkCredsStrength(pw) {
  const fill  = document.getElementById('creds-strength-fill');
  const label = document.getElementById('creds-strength-label');
  if (!pw) { fill.style.width = '0'; label.textContent = ''; return; }
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const levels = [
    { w:'20%', color:'var(--red)',    text:'Very weak'  },
    { w:'40%', color:'var(--orange)', text:'Weak'       },
    { w:'60%', color:'var(--yellow)', text:'Fair'       },
    { w:'80%', color:'var(--accent)', text:'Strong'     },
    { w:'100%',color:'var(--green)',  text:'Very strong'},
  ];
  const lvl = levels[Math.min(score, 4)];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.color;
  label.style.color     = lvl.color;
  label.textContent     = lvl.text;
}

function togglePasswordVisibility(fieldId) {
  const input = document.getElementById(fieldId);
  if (!input) return;
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
}

async function submitCredentials() {
  const current = document.getElementById('creds-current').value;
  const user    = document.getElementById('creds-user').value.trim();
  const pass    = document.getElementById('creds-pass').value;
  const confirm = document.getElementById('creds-confirm').value;
  const errEl   = document.getElementById('creds-error');
  const okEl    = document.getElementById('creds-success');

  errEl.style.display = 'none';
  okEl.style.display  = 'none';

  if (!user)          { showCredsError('Username cannot be empty.'); return; }
  if (pass.length < 8){ showCredsError('Password must be at least 8 characters.'); return; }
  if (pass !== confirm){ showCredsError('Passwords do not match.'); return; }

  const btn = document.getElementById('creds-save-btn');
  btn.disabled = true; btn.textContent = 'Saving…';

  try {
    const res  = await fetch('/api/change-credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: current, newUsername: user, newPassword: pass }),
    });
    const data = await res.json();
    if (data.ok) {
      okEl.style.display = 'block';
      ['creds-current','creds-pass','creds-confirm'].forEach(id => {
        document.getElementById(id).value = '';
      });
      document.getElementById('creds-strength-fill').style.width = '0';
      document.getElementById('creds-strength-label').textContent = '';
    } else {
      showCredsError(data.error || 'Failed to update credentials.');
    }
  } catch (e) {
    showCredsError('Network error — could not save credentials.');
  } finally {
    btn.disabled = false; btn.textContent = 'Save Credentials';
  }
}

function showCredsError(msg) {
  const el = document.getElementById('creds-error');
  el.textContent = '⚠ ' + msg;
  el.style.display = 'block';
}



const DEFAULT_CATEGORIES = [
  { id: 'media',       label: 'Media',       icon: 'clapperboard', color: '#a78bfa', dot: '#8b5cf6' },
  { id: 'performance', label: 'Performance', icon: 'zap',          color: '#f97316', dot: '#f97316' },
  { id: 'utilities',  label: 'Utilities',   icon: 'wrench',        color: '#4f8ef7', dot: '#4f8ef7' },
  { id: 'system',     label: 'System',      icon: 'monitor',       color: '#22c55e', dot: '#22c55e' },
];

let CATEGORIES = [];

function catCssClass(id) { return 'cat-' + id.replace(/[^a-z0-9]/gi, '_'); }

function injectCatStyles() {
  let el = document.getElementById('cat-dynamic-styles');
  if (!el) { el = document.createElement('style'); el.id = 'cat-dynamic-styles'; document.head.appendChild(el); }
  el.textContent = CATEGORIES.map(cat => {
    const cls = catCssClass(cat.id);
    // parse hex to r,g,b for rgba()
    const hex = cat.dot.replace('#','');
    const r = parseInt(hex.slice(0,2),16), g = parseInt(hex.slice(2,4),16), b = parseInt(hex.slice(4,6),16);
    return `.cat-badge-btn.${cls}{background:rgba(${r},${g},${b},.12);border-color:rgba(${r},${g},${b},.4);color:${cat.color};}`;
  }).join('\n');
}

async function loadCategoryDefs() {
  try {
    const res = await fetch('/api/category-defs');
    const data = await res.json();
    CATEGORIES = data.length ? data : DEFAULT_CATEGORIES;
  } catch {
    CATEGORIES = DEFAULT_CATEGORIES;
  }
  injectCatStyles();
}

async function saveCategoryDefs() {
  try {
    await fetch('/api/category-defs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(CATEGORIES),
    });
  } catch (e) { console.error('Failed to save category defs:', e); }
  injectCatStyles();
}

// ── Category Manager Modal ───────────────────────────────────────────────────
const ICON_PALETTE = [
  'clapperboard','zap','wrench','monitor','globe','lock','bar-chart-2','database',
  'settings','package','rocket','gamepad-2','key','hard-drive','trash-2','radio',
  'bot','microscope','music','folder','home','cloud','flame','puzzle',
  'shield','server','wifi','terminal','cpu','layers','git-branch','box',
];
const COLOR_PALETTE = ['#ef4444','#f97316','#eab308','#22c55e','#4f8ef7','#3b82f6','#8b5cf6','#ec4899','#a78bfa','#34d399','#60a5fa','#f472b6','#fbbf24','#4ade80','#38bdf8','#c084fc'];

function openCatMgr() {
  renderCatMgrList();
  document.getElementById('catmgr-backdrop').classList.add('open');
}

function closeCatMgr(e) {
  if (e && e.target !== document.getElementById('catmgr-backdrop')) return;
  document.getElementById('catmgr-backdrop').classList.remove('open');
}

function renderCatMgrList() {
  const body = document.getElementById('catmgr-body');
  if (!CATEGORIES.length) {
    body.innerHTML = `<div style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:13px;padding:20px;">No categories yet. Add one below.</div>`;
    return;
  }
  body.innerHTML = CATEGORIES.map((cat, i) => `
    <div class="catmgr-row" id="catmgr-row-${i}">
      <div class="catmgr-row-icon" style="color:${cat.color};"><i data-lucide="${cat.icon}"></i></div>
      <div class="catmgr-row-label" style="color:${cat.color};">${esc(cat.label)}</div>
      <div class="catmgr-row-color" style="background:${cat.dot};"></div>
      <div class="catmgr-row-actions">
        <button class="catmgr-btn edit" onclick="openCatEditForm(${i})"><i data-lucide="pencil" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px"></i>Edit</button>
        <button class="catmgr-btn del"  onclick="deleteCat(${i})"><i data-lucide="trash-2" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px"></i>Delete</button>
      </div>
    </div>
  `).join('');
  lucide.createIcons({ nodes: [body] });
}

function openCatEditForm(idx) {
  const isNew = idx === null;
  const cat = isNew
    ? { id: '', label: '', icon: 'wrench', color: '#4f8ef7', dot: '#4f8ef7' }
    : { ...CATEGORIES[idx] };

  const body = document.getElementById('catmgr-body');
  body.innerHTML = `
    <div class="catedit-form">
      <div class="catedit-row">
        <div class="catedit-label">Label</div>
        <input class="catedit-input" id="catedit-label" placeholder="e.g. Networking" value="${esc(cat.label)}"/>
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Icon</div>
        <div class="catedit-icon-grid" id="catedit-icon-grid">
          ${ICON_PALETTE.map(ic => `<button class="catedit-icon-btn${ic===cat.icon?' selected':''}" title="${ic}" onclick="selectCatIcon(this,'${ic}')"><i data-lucide="${ic}"></i></button>`).join('')}
        </div>
      </div>
      <div class="catedit-row">
        <div class="catedit-label">Color</div>
        <div class="catedit-color-grid" id="catedit-color-grid">
          ${COLOR_PALETTE.map(c => `<div class="catedit-color-btn${c===cat.dot?' selected':''}" style="background:${c};" onclick="selectCatColor(this,'${c}')"></div>`).join('')}
        </div>
        <div class="catedit-hex-row">
          <div class="catedit-hex-swatch" id="catedit-hex-swatch" style="background:${cat.dot};"></div>
          <input class="catedit-hex-input" id="catedit-hex-input" maxlength="7" placeholder="#RRGGBB" value="${cat.dot}" oninput="syncHexInput(this)"/>
          <span class="catedit-hex-hint">or type any hex code</span>
        </div>
      </div>
      <div class="catedit-actions">
        <button class="action-modal-btn cancel" onclick="renderCatMgrList()"><i data-lucide="x" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>Cancel</button>
        <button class="action-modal-btn ok" onclick="saveCatEdit(${isNew ? 'null' : idx})"><i data-lucide="check" style="width:12px;height:12px;vertical-align:-2px;margin-right:4px;"></i>${isNew ? 'Add Category' : 'Save Changes'}</button>
      </div>
    </div>`;
  // store chosen values in form dataset
  body.querySelector('.catedit-form').dataset.icon  = cat.icon;
  body.querySelector('.catedit-form').dataset.color = cat.dot;
  lucide.createIcons({ nodes: [body] });
  // apply initial color to selected icon
  syncSelectedIconColor(cat.dot);
}

function selectCatIcon(btn, icon) {
  // reset inline styles on previously selected icon
  document.querySelectorAll('.catedit-icon-btn').forEach(b => {
    b.classList.remove('selected');
    b.style.borderColor = '';
    b.style.color = '';
    b.style.background = '';
  });
  btn.classList.add('selected');
  document.querySelector('.catedit-form').dataset.icon = icon;
  // apply current color to selected icon
  const currentColor = document.querySelector('.catedit-form').dataset.color;
  if (currentColor) syncSelectedIconColor(currentColor);
}

function selectCatColor(el, color) {
  document.querySelectorAll('.catedit-color-btn').forEach(b => b.classList.remove('selected'));
  el.classList.add('selected');
  document.querySelector('.catedit-form').dataset.color = color;
  // sync hex input + swatch
  const hexInput = document.getElementById('catedit-hex-input');
  const swatch   = document.getElementById('catedit-hex-swatch');
  if (hexInput) { hexInput.value = color.toUpperCase(); hexInput.classList.remove('invalid'); }
  if (swatch)   swatch.style.background = color;
  // sync selected icon color
  syncSelectedIconColor(color);
}

function syncSelectedIconColor(color) {
  const selectedIcon = document.querySelector('.catedit-icon-btn.selected');
  if (selectedIcon) {
    selectedIcon.style.borderColor = color;
    selectedIcon.style.color = color;
    selectedIcon.style.background = color + '33'; // 20% opacity
  }
}

function syncHexInput(input) {
  let val = input.value.trim();
  // auto-prepend # if user forgot it
  if (val && !val.startsWith('#')) val = '#' + val;
  const swatch = document.getElementById('catedit-hex-swatch');
  const isValid = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(val);
  input.classList.toggle('invalid', !!val && !isValid);
  if (isValid) {
    // normalise 3-digit to 6-digit
    const full = val.length === 4
      ? '#' + val[1]+val[1]+val[2]+val[2]+val[3]+val[3]
      : val;
    document.querySelector('.catedit-form').dataset.color = full;
    if (swatch) swatch.style.background = full;
    // deselect palette buttons if custom color
    const match = document.querySelector(`.catedit-color-btn[style*="${full.toLowerCase()}"], .catedit-color-btn[style*="${full.toUpperCase()}"]`);
    document.querySelectorAll('.catedit-color-btn').forEach(b => b.classList.remove('selected'));
    if (match) match.classList.add('selected');
    // sync selected icon color
    syncSelectedIconColor(full);
  }
}

async function saveCatEdit(idx) {
  const form   = document.querySelector('.catedit-form');
  const label  = document.getElementById('catedit-label').value.trim();
  if (!label) { document.getElementById('catedit-label').focus(); return; }
  const icon   = form.dataset.icon  || 'wrench';
  const dot    = form.dataset.color || '#4f8ef7';
  const color  = dot; // use same for text color; slightly lightened by CSS

  if (idx === null) {
    // new — generate a stable id from label
    const id = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g,'') + '_' + Date.now().toString(36);
    CATEGORIES.push({ id, label, icon, color, dot });
  } else {
    CATEGORIES[idx] = { ...CATEGORIES[idx], label, icon, color, dot };
  }
  await saveCategoryDefs();
  renderCatMgrList();
  // refresh the rest of the UI
  if (currentTab === 'categories') renderCategories();
  else renderContainers();
}

async function deleteCat(idx) {
  const cat = CATEGORIES[idx];
  if (!confirm(`Delete category "${cat.label}"? Containers assigned to it will become unassigned.`)) return;
  CATEGORIES.splice(idx, 1);
  // remove all assignments for this cat
  for (const name of Object.keys(containerAssignments)) {
    if (containerAssignments[name] === cat.id) delete containerAssignments[name];
  }
  await saveCategoryDefs();
  await fetch('/api/categories', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ purge: cat.id }) });
  renderCatMgrList();
  if (currentTab === 'categories') renderCategories();
  else renderContainers();
}

// containerAssignments: { containerName -> categoryId }  — loaded from server
let containerAssignments = {};
let _catDropdown = null;

// Load assignments from server on startup
async function loadAssignments() {
  await loadCategoryDefs();
  try {
    const res = await fetch('/api/categories');
    containerAssignments = await res.json();
  } catch { containerAssignments = {}; }
  render();
}

// Persist a single change to server (optimistic local update first)
async function saveAssignment(containerName, categoryId) {
  try {
    const res = await fetch('/api/categories', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ containerName, categoryId: categoryId ?? null }),
    });
    const data = await res.json();
    if (data.ok) {
      // Sync with server's authoritative state
      containerAssignments = data.assignments;
    }
  } catch (e) {
    console.error('Failed to save category assignment:', e);
  }
}
loadAssignments();

function getCatForContainer(name) {
  return containerAssignments[name] || null;
}

async function assignCategory(containerName, catId) {
  // Optimistic local update for instant UI response
  if (catId === null) {
    delete containerAssignments[containerName];
  } else {
    containerAssignments[containerName] = catId;
  }
  // Re-render immediately with optimistic state
  if (currentTab === 'containers') renderContainers();
  else if (currentTab === 'categories') renderCategories();
  // Then persist to server in background
  await saveAssignment(containerName, catId);
}

// ── Badge rendered inside container table ────────────────────────────────────
function renderCategoryBadge(containerId, containerName) {
  const catId = getCatForContainer(containerName);
  const cat = catId ? CATEGORIES.find(c => c.id === catId) : null;
  const cls = cat ? catCssClass(cat.id) : '';
  const inner = cat
    ? `<i data-lucide="${cat.icon}" style="width:12px;height:12px;flex-shrink:0;"></i>${cat.label}`
    : '＋ Assign';
  return `<button class="cat-badge-btn ${cls}"
    onclick="openCatDropdown(event,'${esc(containerId)}','${esc(containerName)}')"
    title="${cat ? 'Change category' : 'Assign to category'}">${inner}</button>`;
}

// ── Dropdown ────────────────────────────────────────────────────────────────
function openCatDropdown(evt, containerId, containerName) {
  evt.stopPropagation();
  closeCatDropdown();

  const currentCat = getCatForContainer(containerName);
  const btn = evt.currentTarget;
  const rect = btn.getBoundingClientRect();

  const dd = document.createElement('div');
  dd.className = 'cat-dropdown';
  dd.id = 'cat-dropdown';

  let inner = '';
  for (const cat of CATEGORIES) {
    const isActive = currentCat === cat.id;
    inner += `<div class="cat-dropdown-item${isActive?' active':''}"
      onclick="assignCategory('${esc(containerName)}','${cat.id}');closeCatDropdown()">
      <span class="cat-dot" style="background:${cat.dot}"></span>
      <i data-lucide="${cat.icon}" style="width:13px;height:13px;flex-shrink:0;"></i>${cat.label}
      ${isActive ? '<span style="margin-left:auto;color:var(--accent);">✓</span>' : ''}
    </div>`;
  }
  if (currentCat) {
    inner += `<div class="cat-dropdown-sep"></div>
      <div class="cat-dropdown-item" style="color:var(--red);"
        onclick="assignCategory('${esc(containerName)}',null);closeCatDropdown()">
        ✕ Remove category
      </div>`;
  }
  dd.innerHTML = inner;

  // Position below the button, flip up if too close to bottom
  const spaceBelow = window.innerHeight - rect.bottom;
  if (spaceBelow < 220) {
    dd.style.bottom = (window.innerHeight - rect.top + 4) + 'px';
  } else {
    dd.style.top = (rect.bottom + 4) + 'px';
  }
  dd.style.left = Math.min(rect.left, window.innerWidth - 180) + 'px';

  document.body.appendChild(dd);
  lucide.createIcons({ nodes: [dd] });
  _catDropdown = dd;

  setTimeout(() => {
    document.addEventListener('click', closeCatDropdown, { once: true });
  }, 0);
}

function closeCatDropdown() {
  if (_catDropdown) { _catDropdown.remove(); _catDropdown = null; }
}

// ── Categories tab renderer ──────────────────────────────────────────────────
const catCollapsed = new Set(); // tracks which cat ids are expanded; all start collapsed

function toggleCatSection(catId) {
  const el = document.getElementById('cat-sec-' + catId);
  if (!el) return;
  if (el.classList.contains('open')) {
    el.classList.remove('open');
    catCollapsed.delete(catId);
  } else {
    el.classList.add('open');
    catCollapsed.add(catId);
  }
}

function renderCategories() {
  const root = el('cat-root');
  if (!root) return;

  const containers = allData.containers.map(c => ({
    ...c,
    cpuNum: parseFloat(c.cpu) || 0,
    memNum: parseFloat(c.memPercent) || 0,
  }));

  // Separate assigned and unassigned
  const byCategory = {};
  CATEGORIES.forEach(cat => { byCategory[cat.id] = []; });
  const unassigned = [];

  containers.forEach(c => {
    const catId = getCatForContainer(c.name);
    if (catId && byCategory[catId]) byCategory[catId].push(c);
    else unassigned.push(c);
  });

  const badge = el('cat-unassigned-badge');
  if (badge) {
    if (unassigned.length > 0) {
      badge.textContent = `${unassigned.length} unassigned`;
      badge.style.display = '';
    } else {
      badge.style.display = 'none';
    }
  }

  function buildSection(catId, catDot, catColor, titleHtml, list, summaryExtra = '') {
    const isOpen = catCollapsed.has(catId);
    const totalCpu     = list.reduce((s, c) => s + c.cpuNum, 0);
    const totalMem     = list.reduce((s, c) => s + c.memNum, 0);
    const totalRx      = list.reduce((s, c) => s + (c.vethRxKBs || 0), 0);
    const totalTx      = list.reduce((s, c) => s + (c.vethTxKBs || 0), 0);
    const totalMemUsed = list.reduce((s, c) => s + parseMemUsage(c.memUsage), 0);
    const running      = list.filter(c => (c.state||'').toLowerCase() === 'running').length;
    const totalImg     = list.reduce((s, c) => s + parseImgSize(c.imageSize), 0);

    const tableRows = list.length === 0
      ? `<div class="cat-empty-drop">No containers — assign via the Category badge in Container Monitoring</div>`
      : `<table class="cat-table">
          <colgroup>
            <col class="col-dot"/>
            <col class="col-name"/>
            <col class="col-cpu"/>
            <col class="col-mem"/>
            <col class="col-memused"/>
            <col class="col-netin"/>
            <col class="col-netout"/>
            <col class="col-img"/>
            <col class="col-cat"/>
          </colgroup>
          <thead><tr>
            <th class="col-dot"></th>
            <th class="col-name">Name</th>
            <th class="col-cpu">%CPU</th>
            <th class="col-mem">%MEM</th>
            <th class="col-memused">Mem Used</th>
            <th class="col-netin">Net In</th>
            <th class="col-netout">Net Out</th>
            <th class="col-img">Image</th>
            <th class="col-cat">Category</th>
          </tr></thead>
          <tbody>
            ${list.map(c => {
              const stateClass = (c.state||'').toLowerCase();
              const rowClick = ` onclick="openCDetailModal('${c.id}','${esc(c.name)}','${stateClass}')"`;
              return `<tr${rowClick}>
                <td class="col-dot"><span class="status-dot ${stateClass}"></span></td>
                <td class="col-name" style="font-weight:600;color:var(--text);">${esc(c.name)}</td>
                <td class="col-cpu" style="color:${cpuHex(c.cpuNum)};">${c.cpu || '0%'}</td>
                <td class="col-mem" style="color:var(--accent);">${c.memPercent || '0%'}</td>
                <td class="col-memused" style="color:var(--green);">${c.memUsage || '–'}</td>
                <td class="col-netin" style="color:var(--green);">${c.vethRxKBs ? c.vethRxKBs.toFixed(2)+' KB/s' : '–'}</td>
                <td class="col-netout" style="color:var(--accent);">${c.vethTxKBs ? c.vethTxKBs.toFixed(2)+' KB/s' : '–'}</td>
                <td class="col-img" style="color:var(--text3);">${c.imageSize || '–'}</td>
                <td class="col-cat" onclick="event.stopPropagation()">${renderCategoryBadge(c.id, c.name)}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>`;

    return `<div class="cat-section${isOpen?' open':''}" id="cat-sec-${catId}">
      <div class="cat-header-row" onclick="toggleCatSection('${catId}')">
        <span class="cat-chevron">▶</span>
        <div class="cat-title-pill" style="background:${catDot}18;border-color:${catDot}44;color:${catColor};">
          ${titleHtml}
        </div>
        <div class="cat-summary-card">
          <div class="cat-summary-cell cat-sc-containers">
            <div class="cat-summary-label">Containers</div>
            <div class="cat-summary-value" style="color:${catColor};">${list.length} <span style="font-size:10px;font-weight:400;color:var(--text3);">${running} running</span></div>
          </div>
          <div class="cat-summary-cell cat-sc-cpu">
            <div class="cat-summary-label">CPU</div>
            <div class="cat-summary-value" style="color:${cpuHex(totalCpu)};">${totalCpu.toFixed(1)}%</div>
            <div class="cat-mini-bar"><div class="cat-mini-bar-fill" style="width:${Math.min(totalCpu,100)}%;background:${cpuHex(totalCpu)};"></div></div>
          </div>
          <div class="cat-summary-cell cat-sc-mem">
            <div class="cat-summary-label">Mem %</div>
            <div class="cat-summary-value" style="color:var(--green);">${totalMem.toFixed(1)}%</div>
          </div>
          <div class="cat-summary-cell cat-sc-netin">
            <div class="cat-summary-label">Net In</div>
            <div class="cat-summary-value" style="color:var(--green);">${totalRx.toFixed(1)} <span style="font-size:10px;font-weight:400;">KB/s</span></div>
          </div>
          <div class="cat-summary-cell cat-sc-netout">
            <div class="cat-summary-label">Net Out</div>
            <div class="cat-summary-value" style="color:var(--accent);">${totalTx.toFixed(1)} <span style="font-size:10px;font-weight:400;">KB/s</span></div>
          </div>
          <div class="cat-summary-cell cat-sc-memused">
            <div class="cat-summary-label">Mem Used</div>
            <div class="cat-summary-value" style="color:var(--orange);">${fmtBytes(totalMemUsed)}</div>
          </div>
          <div class="cat-summary-cell cat-sc-img">
            <div class="cat-summary-label">Img Size</div>
            <div class="cat-summary-value" style="color:var(--red);">${totalImg > 0 ? fmtBytes(totalImg) : '–'}</div>
          </div>
          ${summaryExtra}
        </div>
      </div>
      <div class="cat-body">${tableRows}</div>
    </div>`;
  }

  let html = '';
  for (const cat of CATEGORIES) {
    html += buildSection(cat.id, cat.dot, cat.color, `<i data-lucide="${cat.icon}" style="width:15px;height:15px;flex-shrink:0;"></i>${cat.label}`, byCategory[cat.id]);
  }

  if (unassigned.length > 0) {
    html += buildSection('__unassigned__', '#545b7a', 'var(--text3)', '❓ Unassigned', unassigned);
  }

  root.innerHTML = html;
  lucide.createIcons({ nodes: [root] });
}

// Parse memory usage string like "1.2GiB", "512MiB", "2GB" → bytes
