// ─── Network Utilization ─────────────────────────────────────────────────────

// Ring-buffer history: iface → { rx: [], tx: [] }  (last 20 samples = ~60s)
const NET_HISTORY_LEN = 20;
const netHistory = {};          // { ifaceName: { rx: number[], tx: number[] } }
const expandedNetIfaces = new Set(); // ifaces with containers expanded (default: none = collapsed)
let netSort = { key: 'iface', dir: 1 };

function toggleNetContainers(iface) {
  if (expandedNetIfaces.has(iface)) expandedNetIfaces.delete(iface);
  else expandedNetIfaces.add(iface);
  renderNetworkLeft();
}

function setNetSort(key) {
  if (netSort.key === key) netSort.dir *= -1;
  else { netSort.key = key; netSort.dir = key === 'iface' ? 1 : -1; }
  const labels = { iface: 'NAME', rxKBs: 'IN', txKBs: 'OUT', totalKBs: 'TOTAL' };
  ['iface','rxKBs','txKBs','totalKBs'].forEach(k => {
    const btn = el('net-sort-' + k);
    if (!btn) return;
    const isActive = netSort.key === k;
    btn.classList.toggle('active', isActive);
    const arrow = isActive ? (netSort.dir === 1 ? ' ↑' : ' ↓') : ' ↕';
    btn.textContent = labels[k] + arrow;
  });
  renderNetworkLeft();
}

function renderNetwork() {
  renderNetworkLeft();
}

// ── Sparklines ────────────────────────────────────────────────────────────────
function renderNetworkLeft() {
  const s = allData.summary;
  let nets = [...(s.nets || [])];

  // Update ring buffers
  nets.forEach(n => {
    if (!netHistory[n.iface]) netHistory[n.iface] = { rx: [], tx: [] };
    const h = netHistory[n.iface];
    h.rx.push(n.rxKBs || 0);
    h.tx.push(n.txKBs || 0);
    if (h.rx.length > NET_HISTORY_LEN) h.rx.shift();
    if (h.tx.length > NET_HISTORY_LEN) h.tx.shift();
  });

  // Apply sort
  nets.sort((a, b) => {
    let av, bv;
    if (netSort.key === 'iface') {
      av = a.iface; bv = b.iface;
    } else if (netSort.key === 'totalKBs') {
      av = (a.rxKBs || 0) + (a.txKBs || 0);
      bv = (b.rxKBs || 0) + (b.txKBs || 0);
    } else {
      av = a[netSort.key] || 0;
      bv = b[netSort.key] || 0;
    }
    if (av < bv) return -netSort.dir;
    if (av > bv) return  netSort.dir;
    return 0;
  });

  el('net-total-info').textContent =
    '↓ ' + (s.netInKBs || 0).toFixed(2) + ' KB/s  ↑ ' + (s.netOutKBs || 0).toFixed(2) + ' KB/s';

  if (!nets.length) {
    el('net-ifaces').innerHTML = `<div class="empty-state" style="width:100%"><div class="emoji">🌐</div>No interfaces</div>`;
    return;
  }

  el('net-ifaces').innerHTML = nets.map(n => {
    const h = netHistory[n.iface] || { rx: [], tx: [] };
    const maxVal = Math.max(1, ...h.rx, ...h.tx);
    const rxKBs = (n.rxKBs || 0).toFixed(2);
    const txKBs = (n.txKBs || 0).toFixed(2);

    // ── Find containers attached to this host interface ──────────────────────
    // Match: container.networks[].hostIface === n.iface
    // Also catch docker0 / br-xxxx by checking if any network's hostIface matches
    const attachedContainers = (allData.containers || []).filter(c =>
      (c.state || '').toLowerCase() === 'running' &&
      (c.networks || []).some(net => net.hostIface === n.iface)
    );
    // For each attached container, find the specific network entry that matched
    const attachedRows = attachedContainers.map(c => {
      const matchedNet = (c.networks || []).find(net => net.hostIface === n.iface);
      return { container: c, net: matchedNet };
    });

    function sparkPoints(vals, W, H) {
      if (!vals.length) return '';
      const pts = vals.map((v, i) => {
        const x = (i / (NET_HISTORY_LEN - 1)) * W;
        const y = H - (v / maxVal) * (H - 2) - 1;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      });
      return pts.join(' ');
    }
    function sparkArea(vals, W, H, color) {
      if (vals.length < 2) return '';
      const pts = sparkPoints(vals, W, H);
      const lastX = ((vals.length - 1) / (NET_HISTORY_LEN - 1) * W).toFixed(1);
      return `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>
              <polygon points="0,${H} ${pts} ${lastX},${H}" fill="${color}" fill-opacity="0.15"/>`;
    }

    // Container rows HTML — collapsible, default collapsed
    const isExpanded = expandedNetIfaces.has(n.iface);
    const containerSection = attachedRows.length ? `
      <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:8px;">
        <div onclick="toggleNetContainers('${esc(n.iface)}')"
          style="display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none;padding:2px 0 6px 0;">
          <span style="font-size:10px;color:var(--text3);">${isExpanded ? '▼' : '▶'}</span>
          <span style="font-size:10px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--text3);font-family:var(--mono);">
            🐋 Containers (${attachedRows.length})
          </span>
        </div>
        ${isExpanded ? attachedRows.map(({ container: c, net }) => {
          const stateClass = (c.state||'').toLowerCase();
          const rxStr = c.netMode === 'host' ? '–' : (c.vethRxKBs||0).toFixed(2)+' KB/s';
          const txStr = c.netMode === 'host' ? '–' : (c.vethTxKBs||0).toFixed(2)+' KB/s';
          return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(42,47,74,.3);">
            <span class="status-dot ${stateClass}" style="flex-shrink:0;"></span>
            <span style="font-family:var(--mono);font-size:12px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
              title="${esc(c.name)}">${esc(c.name)}</span>
            ${net && net.ip ? `<span style="font-family:var(--mono);font-size:11px;color:var(--accent);">${esc(net.ip)}</span>` : ''}
            ${net && net.name ? `<span style="font-family:var(--mono);font-size:10px;color:var(--text3);padding:1px 5px;border:1px solid var(--border);border-radius:3px;">${esc(net.name)}</span>` : ''}
            <span class="green-text"  style="font-family:var(--mono);font-size:11px;">↓ ${esc(rxStr)}</span>
            <span class="cyan-text"   style="font-family:var(--mono);font-size:11px;">↑ ${esc(txStr)}</span>
          </div>`;
        }).join('') : ''}
      </div>` : `
      <div style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px;font-size:11px;color:var(--text3);font-family:var(--mono);">
        No containers attached
      </div>`;

    const W = 260, H = 44;
    return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);padding:12px 14px;min-width:380px;flex:1;max-width:560px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <div style="display:flex;align-items:baseline;gap:8px;">
          <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text)">${esc(n.iface)}</span>
          ${n.dockerNetName ? `<span style="font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:4px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.25);color:var(--lavender);">${esc(n.dockerNetName)}</span>` : ''}
        </div>
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">${fmtBytes(n.rxBytes)} rx · ${fmtBytes(n.txBytes)} tx</span>
      </div>
      <div style="display:flex;gap:16px;align-items:flex-start;">
        <!-- Sparkline -->
        <svg width="${W}" height="${H}" style="flex-shrink:0;overflow:visible;">
          <line x1="0" y1="${H/2}" x2="${W}" y2="${H/2}" stroke="var(--border)" stroke-width="0.5" stroke-dasharray="3,3"/>
          <line x1="0" y1="0" x2="${W}" y2="0" stroke="var(--border)" stroke-width="0.5"/>
          ${sparkArea(h.rx, W, H, 'var(--green)')}
          ${sparkArea(h.tx, W, H, 'var(--lavender)')}
        </svg>
        <!-- Current values -->
        <div style="display:flex;flex-direction:column;gap:8px;min-width:90px;">
          <div>
            <div style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:.8px;margin-bottom:2px;">↓ IN</div>
            <div style="font-family:var(--mono);font-size:16px;font-weight:700;color:var(--green);">${rxKBs}</div>
            <div style="font-size:10px;color:var(--text3);font-family:var(--mono);">KB/s</div>
          </div>
          <div>
            <div style="font-size:10px;color:var(--text3);font-family:var(--mono);letter-spacing:.8px;margin-bottom:2px;">↑ OUT</div>
            <div style="font-family:var(--mono);font-size:16px;font-weight:700;color:var(--lavender);">${txKBs}</div>
            <div style="font-size:10px;color:var(--text3);font-family:var(--mono);">KB/s</div>
          </div>
        </div>
      </div>
      <!-- Legend -->
      <div style="margin-top:6px;display:flex;gap:14px;">
        <span style="font-size:10px;color:var(--green);font-family:var(--mono);">── IN</span>
        <span style="font-size:10px;color:var(--lavender);font-family:var(--mono);">── OUT</span>
        <span style="font-size:10px;color:var(--text3);font-family:var(--mono);">60s window</span>
      </div>
      ${containerSection}
    </div>`;
  }).join('');
}

