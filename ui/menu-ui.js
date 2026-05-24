// ═══════════════════════════════════════════════════════════════════════════
// menu.js — Sidebar and tab navigation logic for NAS Monitor
// ═══════════════════════════════════════════════════════════════════════════

const SIDEBAR_TAB_NAMES = ['containers', 'processes', 'disk', 'network', 'categories', 'settings'];

(function initSidebar() {
  document.querySelectorAll('.sidebar-item').forEach(b => {
    if (b.dataset.icon) {
      const span = document.createElement('span');
      span.className = 'sidebar-item-icon';
      const i = document.createElement('i');
      i.setAttribute('data-lucide', b.dataset.icon);
      span.appendChild(i);
      b.prepend(span);
      b.style.setProperty('--sidebar-active-color', b.dataset.activeColor);
      b.style.setProperty('--sidebar-idle-color', b.dataset.idleColor);
      b.style.setProperty('--sidebar-active-bg', hexToRgba(b.dataset.activeColor, 0.12));
      const label = b.querySelector('.sidebar-item-text')?.textContent;
      if (label) b.setAttribute('title', label);
    }
    if (b.dataset.tab) b.classList.toggle('active', b.dataset.tab === currentTab);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === 'tab-' + currentTab);
  });

  // Restore containers sub-menu open state (default: open)
  const submenuOpen = sessionStorage.getItem('containers-submenu-open') !== 'false';
  if (submenuOpen) {
    const parent = document.getElementById('containers-parent');
    if (parent) parent.classList.add('open');
  } else {
    const submenu = document.getElementById('containers-submenu');
    if (submenu) submenu.classList.add('closed');
  }

  // Mark containers parent active when containers tab is current
  if (currentTab === 'containers') {
    const parent = document.getElementById('containers-parent');
    if (parent) parent.querySelector('.sidebar-item')?.classList.add('active');
  }

  const sidebarExpanded = sessionStorage.getItem('sidebar-expanded') === 'true';
  if (sidebarExpanded) {
    document.body.classList.add('sidebar-expanded');
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.add('expanded');
  }

  updateSidebarToggleLabel();
  if (window.lucide) lucide.createIcons({ nodes: [document.getElementById('sidebar')] });
})();

function toggleContainersMenu() {
  const parent = document.getElementById('containers-parent');
  const submenu = document.getElementById('containers-submenu');
  if (!parent || !submenu) return;
  const isOpen = parent.classList.contains('open');
  parent.classList.toggle('open', !isOpen);
  submenu.classList.toggle('closed', isOpen);
  sessionStorage.setItem('containers-submenu-open', String(!isOpen));
  // Also switch to containers tab
  switchTab('containers');
}

function logout() {
  fetch('/logout', { method: 'GET', credentials: 'same-origin' })
    .finally(() => { window.location.href = '/login'; });
}

function switchTab(name) {
  currentTab = name;
  sessionStorage.setItem('nas-monitor-tab', name);
  document.querySelectorAll('.sidebar-item[data-tab]').forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === 'tab-' + name);
  });
  // Keep containers parent button highlighted when any sub-item tab is active
  const containersBtn = document.querySelector('#containers-parent > .sidebar-item');
  if (containersBtn) {
    const subTabs = ['containers', 'categories'];
    containersBtn.classList.toggle('active', subTabs.includes(name));
  }
  const filterInput = document.getElementById('filter-input');
  if (filterInput) filterInput.value = '';
  filterText = '';
  render();
}

function updateSidebarToggleLabel() {
  const label = document.getElementById('sidebar-toggle-label');
  if (!label) return;
  label.textContent = document.body.classList.contains('sidebar-expanded') ? '<<' : '>>';
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  document.body.classList.toggle('sidebar-expanded');
  if (sidebar) sidebar.classList.toggle('expanded');
  sessionStorage.setItem('sidebar-expanded', document.body.classList.contains('sidebar-expanded'));
  updateSidebarToggleLabel();
}

function closeSidebar() {
  const sidebar = document.getElementById('sidebar');
  document.body.classList.remove('sidebar-expanded');
  if (sidebar) sidebar.classList.remove('expanded');
  sessionStorage.setItem('sidebar-expanded', false);
  updateSidebarToggleLabel();
}

function switchTabFromSidebar(name) {
  switchTab(name);
}
