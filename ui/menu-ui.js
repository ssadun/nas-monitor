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
  // Sync mobile bottom-nav active state on load
  document.querySelectorAll('.mobile-bottom-nav-btn[data-tab]').forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === currentTab);
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

  // Restore network sub-menu open state (default: closed)
  const networkSubmenuOpen = sessionStorage.getItem('network-submenu-open') === 'true';
  if (networkSubmenuOpen) {
    const parent = document.getElementById('network-parent');
    const submenu = document.getElementById('network-submenu');
    if (parent) parent.classList.add('open');
    if (submenu) submenu.classList.remove('closed');
  }

  // Mark containers parent active when containers tab is current
  if (currentTab === 'containers') {
    const parent = document.getElementById('containers-parent');
    if (parent) parent.querySelector('.sidebar-item')?.classList.add('active');
  }
  // Mark network parent active when network tab is current
  if (currentTab === 'network') {
    const parent = document.getElementById('network-parent');
    if (parent) parent.querySelector('.sidebar-item')?.classList.add('active');
  }

  // On mobile the sidebar is an off-canvas drawer — always start closed,
  // ignoring any persisted desktop "expanded" rail state.
  const isMobileView = window.matchMedia('(max-width: 660px)').matches;
  const sidebarExpanded = !isMobileView && sessionStorage.getItem('sidebar-expanded') === 'true';
  if (sidebarExpanded) {
    document.body.classList.add('sidebar-expanded');
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.add('expanded');
  }

  updateSidebarToggleLabel();
  if (window.lucide) {
    lucide.createIcons({ nodes: [document.getElementById('sidebar')] });
    const bottomNav = document.getElementById('mobile-bottom-nav');
    if (bottomNav) lucide.createIcons({ nodes: [bottomNav] });
  }
})();

function toggleContainersMenu() {
  const parent = document.getElementById('containers-parent');
  const submenu = document.getElementById('containers-submenu');
  if (!parent || !submenu) return;
  const isOpen = parent.classList.contains('open');
  parent.classList.toggle('open', !isOpen);
  submenu.classList.toggle('closed', isOpen);
  sessionStorage.setItem('containers-submenu-open', String(!isOpen));
  // Collapse network menu when opening containers menu
  if (!isOpen) {
    const np = document.getElementById('network-parent');
    const ns = document.getElementById('network-submenu');
    if (np && ns) { np.classList.remove('open'); ns.classList.add('closed'); sessionStorage.setItem('network-submenu-open', 'false'); }
  }
  switchTab('containers');
}

function toggleNetworkMenu() {
  const parent = document.getElementById('network-parent');
  const submenu = document.getElementById('network-submenu');
  if (!parent || !submenu) return;
  const isOpen = parent.classList.contains('open');
  parent.classList.toggle('open', !isOpen);
  submenu.classList.toggle('closed', isOpen);
  sessionStorage.setItem('network-submenu-open', String(!isOpen));
  // Collapse containers menu when opening network menu
  if (!isOpen) {
    const cp = document.getElementById('containers-parent');
    const cs = document.getElementById('containers-submenu');
    if (cp && cs) { cp.classList.remove('open'); cs.classList.add('closed'); sessionStorage.setItem('containers-submenu-open', 'false'); }
  }
  switchTab('network');
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
  // Sync the mobile bottom nav: highlight the matching parent/tab
  document.querySelectorAll('.mobile-bottom-nav-btn[data-tab]').forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === name);
  });
  // Keep containers parent button highlighted when any sub-item tab is active
  const containersBtn = document.querySelector('#containers-parent > .sidebar-item');
  const subTabs = ['containers', 'categories'];
  if (containersBtn) {
    containersBtn.classList.toggle('active', subTabs.includes(name));
  }
  // Collapse Docker Management submenu when switching to a non-Docker tab
  if (!subTabs.includes(name)) {
    const parent = document.getElementById('containers-parent');
    const submenu = document.getElementById('containers-submenu');
    if (parent && submenu) {
      parent.classList.remove('open');
      submenu.classList.add('closed');
      sessionStorage.setItem('containers-submenu-open', 'false');
    }
  }
  // Collapse Network submenu when switching to a non-network tab
  if (name !== 'network') {
    const np = document.getElementById('network-parent');
    const ns = document.getElementById('network-submenu');
    if (np && ns) {
      np.classList.remove('open');
      ns.classList.add('closed');
      sessionStorage.setItem('network-submenu-open', 'false');
    }
  }
  const filterInput = document.getElementById('filter-input');
  if (filterInput) filterInput.value = '';
  filterText = '';
  // On mobile, the sidebar is an off-canvas drawer — auto-close after navigating
  if (window.matchMedia('(max-width: 660px)').matches) closeSidebar();
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

// ── Mobile bottom-nav popup submenus ─────────────────────────────────────────
// A parent tab (Docker / Network / More) reveals its sub-items as a floating
// popup above the bar; an invisible backdrop dismisses it. Only one open at a time.
function closeMobileNavPopups() {
  document.querySelectorAll('.mobile-nav-parent.open').forEach(p => p.classList.remove('open'));
  const backdrop = document.getElementById('mobile-sub-backdrop');
  if (backdrop) backdrop.classList.remove('show');
}

function openMobileNavPopup(which, evt, navTab) {
  if (evt) evt.stopPropagation();
  const parent = document.getElementById('mobnav-' + which + '-parent');
  if (!parent) return;
  const wasOpen = parent.classList.contains('open');
  closeMobileNavPopups();
  if (!wasOpen) {
    parent.classList.add('open');
    const backdrop = document.getElementById('mobile-sub-backdrop');
    if (backdrop) backdrop.classList.add('show');
    if (navTab) switchTab(navTab);
  }
}
