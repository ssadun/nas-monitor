'use strict';

const fs = require('fs');

// ─── /proc helpers ────────────────────────────────────────────────────────────

function readFile(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

function getTotalMemKB() {
  const line = readFile('/proc/meminfo').split('\n').find(l => l.startsWith('MemTotal:'));
  return line ? parseInt(line.split(/\s+/)[1]) : 1;
}

function getBootTime() {
  const line = readFile('/proc/stat').split('\n').find(l => l.startsWith('btime'));
  return line ? parseInt(line.split(' ')[1]) : 0;
}

const BOOT_TIME = getBootTime();
const TOTAL_MEM_KB = getTotalMemKB();
const CLK_TCK = 100; // Hz – standard Linux

function parseProcStat(pid) {
  try {
    const raw = readFile(`/proc/${pid}/stat`);
    if (!raw) return null;
    // comm is between first ( and last ) to handle spaces
    const commStart = raw.indexOf('(');
    const commEnd = raw.lastIndexOf(')');
    const comm = raw.slice(commStart + 1, commEnd);
    const rest = raw.slice(commEnd + 2).split(' ');
    return {
      state: rest[0],
      ppid: parseInt(rest[1]),
      utime: parseInt(rest[11]),
      stime: parseInt(rest[12]),
      starttime: parseInt(rest[19]),
      comm,
    };
  } catch { return null; }
}

function parseProcStatus(pid) {
  const lines = readFile(`/proc/${pid}/status`).split('\n');
  const get = (key) => {
    const l = lines.find(x => x.startsWith(key + ':'));
    return l ? l.split(':')[1].trim() : '';
  };
  return {
    name: get('Name'),
    uid: get('Uid').split('\t')[0],
    vmRSS: parseInt(get('VmRSS')) || 0,
    threads: parseInt(get('Threads')) || 1,
  };
}

function getOwner(uid) {
  try {
    const passwd = fs.readFileSync('/etc/passwd', 'utf8');
    const line = passwd.split('\n').find(l => l.split(':')[2] === String(uid));
    return line ? line.split(':')[0] : String(uid);
  } catch { return String(uid); }
}

function getCmdline(pid) {
  try {
    return readFile(`/proc/${pid}/cmdline`).replace(/\0/g, ' ').trim();
  } catch { return ''; }
}

function parseProcIO(pid) {
  // /proc/<pid>/io requires root on most kernels; returns null if unreadable
  try {
    const raw = readFile(`/proc/${pid}/io`);
    if (!raw) return null;
    const get = (key) => {
      const line = raw.split('\n').find(l => l.startsWith(key + ':'));
      return line ? parseInt(line.split(':')[1].trim()) : 0;
    };
    return {
      readBytes:  get('read_bytes'),
      writeBytes: get('write_bytes'),
    };
  } catch { return null; }
}

// CPU snapshots for delta calculations
let prevCpuSnapshot = {};
let prevSystemCpu = 0;
let prevDiskSnapshot = {}; // pid -> { readBytes, writeBytes, ts }

function getSystemCpuTotal() {
  const line = readFile('/proc/stat').split('\n')[0];
  const parts = line.split(/\s+/).slice(1).map(Number);
  return parts.reduce((a, b) => a + b, 0);
}

function getAllPids() {
  return fs.readdirSync('/proc')
    .filter(d => /^\d+$/.test(d))
    .map(Number);
}

async function collectProcesses() {
  const pids = getAllPids();
  const systemCpu = getSystemCpuTotal();
  const systemDelta = Math.max(systemCpu - prevSystemCpu, 1);
  const uptime = parseFloat(readFile('/proc/uptime').split(' ')[0]);
  const nowTs = Date.now();

  const processes = [];

  for (const pid of pids) {
    const stat = parseProcStat(pid);
    if (!stat) continue;
    const status = parseProcStatus(pid);

    const procCpu = stat.utime + stat.stime;
    const isFirstSnapshot = prevCpuSnapshot[pid] === undefined;
    const prevCpu = isFirstSnapshot ? procCpu : prevCpuSnapshot[pid];
    const cpuDelta = isFirstSnapshot ? 0 : Math.max(0, procCpu - prevCpu);
    const cpuPercent = parseFloat(((cpuDelta / systemDelta) * 100).toFixed(2));

    prevCpuSnapshot[pid] = procCpu;

    const memPercent = parseFloat(((status.vmRSS / TOTAL_MEM_KB) * 100).toFixed(2));
    const startEpoch = BOOT_TIME + (stat.starttime / CLK_TCK);
    const startDate = new Date(startEpoch * 1000).toISOString();

    const cmdline = getCmdline(pid);
    // Mark our own process (nas-monitor server.js) and its children
    const isSelf = pid === process.pid || stat.ppid === process.pid ||
      (cmdline.includes(process.cwd()) && cmdline.includes('server.js'));

    // Disk I/O rate from /proc/<pid>/io
    let diskReadKBs = 0, diskWriteKBs = 0;
    const io = parseProcIO(pid);
    if (io) {
      const prev = prevDiskSnapshot[pid];
      if (prev && nowTs > prev.ts) {
        const dtSec = (nowTs - prev.ts) / 1000;
        diskReadKBs  = parseFloat(Math.max(0, (io.readBytes  - prev.readBytes)  / 1024 / dtSec).toFixed(2));
        diskWriteKBs = parseFloat(Math.max(0, (io.writeBytes - prev.writeBytes) / 1024 / dtSec).toFixed(2));
      }
      prevDiskSnapshot[pid] = { readBytes: io.readBytes, writeBytes: io.writeBytes, ts: nowTs };
    }

    processes.push({
      pid,
      ppid: stat.ppid,
      name: status.name || stat.comm,
      owner: getOwner(status.uid),
      cpu: Math.max(0, cpuPercent),
      mem: memPercent,
      memKB: status.vmRSS,
      status: stat.state,
      start: startDate,
      cmdline,
      threads: status.threads,
      isSelf,
      diskReadKBs,
      diskWriteKBs,
    });
  }

  prevSystemCpu = systemCpu;

  return processes;
}

module.exports = {
  readFile,
  BOOT_TIME,
  TOTAL_MEM_KB,
  CLK_TCK,
  collectProcesses,
};
