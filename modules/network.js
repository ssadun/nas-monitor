'use strict';

const fs = require('fs');

// Per-interface host network snapshot: iface → { rxBytes, txBytes, ts }
const prevNetSnapshot = {};
// Per-container net namespace snapshot: fullId → { rxBytes, txBytes, ts }
const prevContainerNetSnapshot = {};
// Maps host bridge interface name to Docker network name: e.g. "docker-c5c36d39" → "nas"
const ifaceToDockerNet = {};

function readFile(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

// Read network stats from inside a container's net namespace via /proc/<pid>/net/dev.
// Each process's /proc/<pid>/net/dev shows the network interfaces visible from that
// process's network namespace — i.e. the container's own eth0/lo/etc., not the host's.
function readContainerNetDev(pid) {
  const raw = readFile(`/proc/${pid}/net/dev`);
  if (!raw) return null;
  let rxBytes = 0, txBytes = 0;
  const lines = raw.split('\n').slice(2).filter(Boolean);
  for (const l of lines) {
    const parts = l.trim().split(/\s+/);
    const iface = parts[0].replace(':', '');
    if (iface === 'lo') continue;
    rxBytes += parseInt(parts[1]) || 0;
    txBytes += parseInt(parts[9]) || 0;
  }
  return { rxBytes, txBytes };
}

// Reads /proc/net/dev, computes per-interface KB/s delta rates, returns enriched list + totals.
function collectNetRates() {
  const netLines = readFile('/proc/net/dev').split('\n').slice(2).filter(Boolean);
  const nets = netLines.map(l => {
    const parts = l.trim().split(/\s+/);
    const iface = parts[0].replace(':', '');
    return {
      iface,
      rxBytes: parseInt(parts[1]),
      txBytes: parseInt(parts[9]),
      dockerNetName: ifaceToDockerNet[iface] || '',
    };
  }).filter(n => n.iface !== 'lo');

  const now = Date.now();
  let totalRxKBs = 0;
  let totalTxKBs = 0;
  const netsWithRate = nets.map(n => {
    const prev = prevNetSnapshot[n.iface];
    let rxKBs = 0, txKBs = 0;
    if (prev && now > prev.ts) {
      const dtSec = (now - prev.ts) / 1000;
      rxKBs = Math.max(0, (n.rxBytes - prev.rxBytes) / 1024 / dtSec);
      txKBs = Math.max(0, (n.txBytes - prev.txBytes) / 1024 / dtSec);
    }
    prevNetSnapshot[n.iface] = { rxBytes: n.rxBytes, txBytes: n.txBytes, ts: now };
    totalRxKBs += rxKBs;
    totalTxKBs += txKBs;
    return { ...n, rxKBs: parseFloat(rxKBs.toFixed(2)), txKBs: parseFloat(txKBs.toFixed(2)) };
  });

  return {
    nets: netsWithRate,
    netInKBs: parseFloat(totalRxKBs.toFixed(2)),
    netOutKBs: parseFloat(totalTxKBs.toFixed(2)),
  };
}

module.exports = {
  prevContainerNetSnapshot,
  ifaceToDockerNet,
  readContainerNetDev,
  collectNetRates,
};
