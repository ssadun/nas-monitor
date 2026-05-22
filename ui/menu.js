// ═══════════════════════════════════════════════════════════════════════════
// menu.js — Sidebar and tab navigation logic for NAS Monitor
// ═══════════════════════════════════════════════════════════════════════════

const SIDEBAR_TAB_NAMES = ['containers', 'processes', 'disk', 'network', 'categories', 'settings'];

(function initSidebar() {
  document.querySelectorAll('.sidebar-item[data-tab]').forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === currentTab);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === 'tab-' + currentTab);
  });

  const sidebarExpanded = sessionStorage.getItem('sidebar-expanded') === 'true';
  if (sidebarExpanded) {
    document.body.classList.add('sidebar-expanded');
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.add('expanded');
  }

  updateSidebarToggleLabel();
  if (window.lucide) lucide.createIcons();
})();

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
