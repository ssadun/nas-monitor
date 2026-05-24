'use strict';

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

let readFile = () => '';
let collectNetRates = () => ({ nets: [], netInKBs: 0, netOutKBs: 0 });

function setDependencies(deps = {}) {
  if (typeof deps.readFile === 'function') readFile = deps.readFile;
  if (typeof deps.collectNetRates === 'function') collectNetRates = deps.collectNetRates;
}

async function collectSystemSummary() {
  const meminfo = readFile('/proc/meminfo');
  const getMemVal = (key) => {
    const l = meminfo.split('\n').find(x => x.startsWith(key));
    return l ? parseInt(l.split(/\s+/)[1]) : 0;
  };

  const memTotal = getMemVal('MemTotal:');
  const memAvail = getMemVal('MemAvailable:');
  const memUsed = memTotal - memAvail;

  const statLines = readFile('/proc/stat').split('\n');
  const cpuLine = statLines[0].split(/\s+/).slice(1).map(Number);
  const idle = cpuLine[3] + (cpuLine[4] || 0);
  const total = cpuLine.reduce((a, b) => a + b, 0);

  const loadavg = readFile('/proc/loadavg').split(' ');
  const uptime = parseFloat(readFile('/proc/uptime').split(' ')[0]);

  let diskInfo = [];
  let diskTotalBytes = 0;
  let diskUsedBytes = 0;
  try {
    const { stdout } = await execAsync('df -k --output=source,size,used,avail,pcent,target 2>/dev/null | tail -n +2');
    diskInfo = stdout.trim().split('\n').map(l => {
      const [source, size, used, avail, pcent, target] = l.trim().split(/\s+/);
      return { source, size: parseInt(size), used: parseInt(used), avail: parseInt(avail), pcent, target };
    }).filter(d => d.target && !d.target.startsWith('/sys') && !d.target.startsWith('/proc') && !d.target.startsWith('/dev/shm'));

    // On Synology, /volume1 and all its sub-mounts share the same underlying device.
    // Only keep exact top-level /volumeN mount points to avoid overcounting.
    const volumeMounts = diskInfo.filter(d => /^\/volume\d+$/.test(d.target));

    if (volumeMounts.length > 0) {
      const seen = new Set();
      for (const d of volumeMounts) {
        if (seen.has(d.source)) continue;
        seen.add(d.source);
        diskTotalBytes += (d.size || 0) * 1024;
        diskUsedBytes  += (d.used || 0) * 1024;
      }
    } else {
      const real = diskInfo
        .filter(d => !d.target.startsWith('/dev') && d.size > 1024 * 1024)
        .sort((a, b) => b.size - a.size);
      const seen = new Set();
      for (const d of real) {
        if (seen.has(d.source)) continue;
        seen.add(d.source);
        diskTotalBytes += (d.size || 0) * 1024;
        diskUsedBytes  += (d.used || 0) * 1024;
      }
    }
  } catch {}

  const { nets: netsWithRate, netInKBs, netOutKBs } = collectNetRates();

  return {
    memTotal: memTotal * 1024,
    memUsed: memUsed * 1024,
    memAvail: memAvail * 1024,
    cpuIdle: idle,
    cpuTotal: total,
    load1: parseFloat(loadavg[0]),
    load5: parseFloat(loadavg[1]),
    load15: parseFloat(loadavg[2]),
    uptimeSeconds: uptime,
    disks: diskInfo,
    diskTotal: diskTotalBytes,
    diskUsed: diskUsedBytes,
    nets: netsWithRate,
    netInKBs,
    netOutKBs,
  };
}

module.exports = { setDependencies, collectSystemSummary };
