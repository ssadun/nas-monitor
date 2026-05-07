const fs = require('fs');
const path = require('path');
const { exec, execFile, spawn } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

let appSettings = {};
let logError = () => {};
let logInfo = () => {};
let auditLog = () => {};
let readFile = () => '';
let formatBytes = (bytes) => (bytes === 0 ? '0B' : `${bytes}B`);
let getCache = () => ({ containers: [] });
let refreshCache = async () => {};
let ifaceToDockerNet = {};
let prevContainerNetSnapshot = {};

const DOCKER_PATHS = [
  '/usr/bin/docker',
  '/usr/local/bin/docker',
  '/bin/docker',
  '/usr/syno/bin/docker',
  '/var/packages/ContainerManager/target/usr/bin/docker',
  '/var/packages/Docker/target/usr/bin/docker',
];
const DOCKER_COMPOSE_PATHS = [
  '/usr/bin/docker-compose',
  '/usr/local/bin/docker-compose',
  '/bin/docker-compose',
];
const COMPOSE_BACKUP_ROOT = process.env.COMPOSE_BACKUP_ROOT || '/volume1/docker/_backups';
const COMPOSE_FILE_CANDIDATES = ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'];
const COMPOSE_DISCOVERY_TTL_MS = 30 * 1000;
const COMPOSE_BOOT_LOG_SECONDS = Math.max(5, Number(process.env.COMPOSE_BOOT_LOG_SECONDS || 20) || 20);
const NEW_COMPOSE_TEMPLATE_FILE = path.join(__dirname, 'compose-template.yaml');
const DEFAULT_NEW_COMPOSE_TEMPLATE = `services:\n  my-service:\n    container_name: my-service\n    hostname: my-service\n    environment:\n      TZ: Europe/Istanbul\n    volumes:\n      - ../../_data:/data\n    restart: unless-stopped\n    image: my-service:latest\n`;

let composeDiscoveryCache = { ts: 0, projects: [] };

function setDependencies(deps = {}) {
  appSettings = deps.appSettings || appSettings;
  logError = deps.logError || logError;
  logInfo = deps.logInfo || logInfo;
  auditLog = deps.auditLog || auditLog;
  readFile = deps.readFile || readFile;
  formatBytes = deps.formatBytes || formatBytes;
  getCache = deps.getCache || getCache;
  refreshCache = deps.refreshCache || refreshCache;
  ifaceToDockerNet = deps.ifaceToDockerNet || ifaceToDockerNet;
  prevContainerNetSnapshot = deps.prevContainerNetSnapshot || prevContainerNetSnapshot;
}

function findDocker() {
  for (const p of DOCKER_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return 'docker';
}

function getComposeConfigRoot() {
  return process.env.COMPOSE_CONFIG_ROOT || appSettings.dockerConfigFolder || '/volume1/docker/_config';
}

function getComposeRelativePath(projectDir = '') {
  const root = getComposeConfigRoot();
  const target = String(projectDir || '').trim();
  if (!target) return '';
  try {
    if (!isPathInsideRoot(target, root)) return path.basename(target);
    const rel = path.relative(root, target).split(path.sep).join('/');
    return rel || path.basename(target);
  } catch {
    return path.basename(target);
  }
}

function isPathInsideRoot(filePath, rootPath) {
  const resolvedFile = path.resolve(filePath);
  const resolvedRoot = path.resolve(rootPath);
  return resolvedFile === resolvedRoot || resolvedFile.startsWith(resolvedRoot + path.sep);
}

function pathsEqual(a, b) {
  try {
    return path.resolve(String(a || '')) === path.resolve(String(b || ''));
  } catch {
    return false;
  }
}

function stripInlineYamlComment(value) {
  return String(value || '').replace(/\s+#.*$/, '').trim();
}

function unquoteYamlScalar(value) {
  const cleaned = stripInlineYamlComment(value);
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
    return cleaned.slice(1, -1);
  }
  return cleaned;
}

function parseComposePortSpec(spec) {
  const cleaned = unquoteYamlScalar(spec);
  if (!cleaned) return null;
  const [portPart, protoRaw] = cleaned.split('/');
  const proto = (protoRaw || 'tcp').trim();
  const segments = portPart.split(':').map(s => s.trim()).filter(Boolean);
  if (!segments.length) return null;

  let host = '';
  let container = '';
  if (segments.length === 1) {
    host = segments[0];
    container = segments[0];
  } else if (segments.length === 2) {
    host = segments[0];
    container = segments[1];
  } else {
    host = segments[segments.length - 2];
    container = segments[segments.length - 1];
  }

  const hostMatch = host.match(/\d+(?:-\d+)?/);
  const containerMatch = container.match(/\d+(?:-\d+)?/);
  if (!hostMatch && !containerMatch) return null;

  return {
    host: hostMatch ? hostMatch[0] : '',
    container: containerMatch ? containerMatch[0] : '',
    proto,
  };
}

function parseComposeServices(raw) {
  const services = [];
  const lines = String(raw || '').replace(/\r/g, '').split('\n');
  let inServices = false;
  let servicesIndent = 0;
  let current = null;
  let currentIndent = 0;
  let inPorts = false;
  let portsIndent = 0;

  const flushCurrent = () => {
    if (!current) return;
    services.push({
      service: current.service,
      containerName: current.containerName || '',
      image: current.image || '',
      ports: current.ports || [],
      displayName: current.containerName || current.service,
    });
    current = null;
    inPorts = false;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = line.match(/^\s*/)[0].length;
    if (!inServices) {
      if (trimmed === 'services:' || trimmed.startsWith('services:')) {
        inServices = true;
        servicesIndent = indent;
      }
      continue;
    }

    if (indent <= servicesIndent && !trimmed.startsWith('-')) {
      flushCurrent();
      break;
    }

    if (indent === servicesIndent + 2 && /^[A-Za-z0-9_.-]+:\s*$/.test(trimmed)) {
      flushCurrent();
      current = { service: trimmed.slice(0, -1), ports: [] };
      currentIndent = indent;
      continue;
    }

    if (!current) continue;

    if (indent === currentIndent + 2) {
      const m = trimmed.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
      if (!m) continue;
      const [, key, value] = m;
      if (key === 'container_name') {
        current.containerName = unquoteYamlScalar(value);
      } else if (key === 'image') {
        current.image = unquoteYamlScalar(value);
      } else if (key === 'ports') {
        inPorts = true;
        portsIndent = indent;
      }
      continue;
    }

    if (inPorts && indent > portsIndent && trimmed.startsWith('- ')) {
      const parsed = parseComposePortSpec(trimmed.slice(2));
      if (parsed) current.ports.push(parsed);
    }
  }

  flushCurrent();
  return services;
}

function findComposeProjectDirectories(rootDir) {
  const found = [];
  const seen = new Set();
  const stack = [rootDir];

  while (stack.length) {
    const currentDir = stack.pop();
    if (!currentDir) continue;

    let realDir = '';
    try {
      realDir = fs.realpathSync(currentDir);
    } catch {
      continue;
    }

    if (seen.has(realDir)) continue;
    seen.add(realDir);

    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }

    const composeFileName = COMPOSE_FILE_CANDIDATES.find(name =>
      entries.some(entry => entry.isFile() && entry.name === name)
    );
    if (composeFileName) {
      found.push({
        projectDir: currentDir,
        composeFile: path.join(currentDir, composeFileName),
      });
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === '.' || entry.name === '..') continue;
      stack.push(path.join(currentDir, entry.name));
    }
  }

  found.sort((a, b) => a.projectDir.localeCompare(b.projectDir));
  return found;
}

function discoverComposeProjects(force = false) {
  const now = Date.now();
  if (!force && now - composeDiscoveryCache.ts < COMPOSE_DISCOVERY_TTL_MS) {
    return composeDiscoveryCache.projects;
  }

  const projects = [];
  const composeRoot = getComposeConfigRoot();
  try {
    const discoveredDirs = findComposeProjectDirectories(composeRoot);
    for (const discovered of discoveredDirs) {
      const { projectDir, composeFile } = discovered;
      let services = [];
      try {
        services = parseComposeServices(fs.readFileSync(composeFile, 'utf8'));
      } catch {}

      projects.push({
        project: path.basename(projectDir),
        pathLabel: getComposeRelativePath(projectDir),
        dir: projectDir,
        composeFile,
        services,
      });
    }
  } catch {}

  composeDiscoveryCache = { ts: now, projects };
  return projects;
}

function findComposeProject(projectName) {
  return discoverComposeProjects().find(p => p.project === projectName) || null;
}

function findComposeServiceTarget(projectName, serviceName) {
  const project = discoverComposeProjects().find(p => p.project === projectName);
  if (!project) return null;
  const service = project.services.find(s => s.service === serviceName);
  if (!service) return null;
  return { project, service };
}

function buildComposeSyntheticId(project, service) {
  return `compose:${project}:${service}`;
}

function parseComposeSyntheticId(id) {
  const raw = String(id || '');
  if (!raw.startsWith('compose:')) return null;
  const parts = raw.split(':');
  if (parts.length < 3) return null;
  return {
    project: parts[1],
    service: parts.slice(2).join(':'),
  };
}

function getContainerDataRoot() {
  return process.env.CONTAINER_DATA_ROOT || appSettings.dockerDataFolder || '/volume1/docker/_data';
}

function isValidContainerFolderName(name) {
  return /^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$/.test(String(name || ''));
}

function normalizeContainerSubPath(subPath = '') {
  const raw = String(subPath || '').trim().replace(/\\/g, '/');
  const cleaned = raw.replace(/^\/+/, '').replace(/\/+/g, '/');
  if (!cleaned) return '';
  const parts = cleaned.split('/').filter(Boolean);
  if (parts.some(seg => seg === '.' || seg === '..')) return null;
  return parts.join('/');
}

function resolveContainerDataPath(containerName, subPath = '') {
  if (!isValidContainerFolderName(containerName)) return null;
  const dataRoot = getContainerDataRoot();
  const basePath = path.join(dataRoot, containerName);
  if (!isPathInsideRoot(basePath, dataRoot)) return null;
  const normalizedSubPath = normalizeContainerSubPath(subPath);
  if (normalizedSubPath === null) return null;
  const targetPath = normalizedSubPath ? path.join(basePath, normalizedSubPath) : basePath;
  if (!isPathInsideRoot(targetPath, basePath)) return null;
  return { basePath, targetPath, subPath: normalizedSubPath || '' };
}

function getSafeComposeFilePath(projectName, explicitComposeFile = '') {
  const composeRoot = getComposeConfigRoot();
  const explicit = String(explicitComposeFile || '').trim();
  if (explicit && fs.existsSync(explicit) && isPathInsideRoot(explicit, composeRoot)) {
    return explicit;
  }

  const project = findComposeProject(projectName);
  if (!project || !project.composeFile) return '';
  if (!fs.existsSync(project.composeFile) || !isPathInsideRoot(project.composeFile, composeRoot)) return '';
  return project.composeFile;
}

function readComposeFilePayload(projectName, explicitComposeFile = '') {
  const composeFile = getSafeComposeFilePath(projectName, explicitComposeFile);
  if (!composeFile) return { ok: false, error: 'Compose file not found.' };
  try {
    return {
      ok: true,
      composeFile,
      composeFileName: path.basename(composeFile),
      composeFileContent: fs.readFileSync(composeFile, 'utf8'),
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function getComposeSyntheticDetail(id) {
  const synthetic = parseComposeSyntheticId(id);
  if (!synthetic) return null;
  const target = findComposeServiceTarget(synthetic.project, synthetic.service);
  if (!target) return { error: 'Compose service not found.' };
  const { project, service } = target;
  const composeFilePayload = readComposeFilePayload(project.project, project.composeFile);
  return {
    id: buildComposeSyntheticId(project.project, service.service),
    fullId: '',
    name: service.displayName,
    status: 'configured',
    running: false,
    created: '',
    startedAt: '',
    finishedAt: '',
    uptime: 'Defined in compose',
    restartCount: 0,
    restartPolicy: { name: 'compose', maximumRetryCount: 0 },
    image: service.image || '',
    imageId: '',
    imageHash: '',
    imageSize: '',
    cmd: `docker compose up -d ${service.service}`,
    entrypoint: '',
    memUsage: '',
    memPercent: '',
    cpu: '',
    blockIO: '',
    portConfig: (service.ports || []).map(p => ({
      containerPort: p.container ? `${p.container}/${p.proto || 'tcp'}` : '',
      hostIp: '0.0.0.0',
      hostPort: p.host || '',
    })),
    volumes: [],
    networks: [],
    env: [],
    labels: [
      { key: 'compose.project', value: project.project },
      { key: 'compose.service', value: service.service },
      { key: 'compose.file', value: project.composeFile },
    ],
    composeProject: project.project,
    composeService: service.service,
    composePath: '',
    composeManaged: true,
    composeOnly: true,
    composeFile: composeFilePayload.ok ? composeFilePayload.composeFile : project.composeFile,
    composeFileName: composeFilePayload.ok ? composeFilePayload.composeFileName : path.basename(project.composeFile),
    composeFileContent: composeFilePayload.ok ? composeFilePayload.composeFileContent : '',
    composeFileError: composeFilePayload.ok ? '' : composeFilePayload.error,
  };
}

function findDockerCompose() {
  for (const p of DOCKER_COMPOSE_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return findDocker();
}

function getComposeCommand(composeFile, args = []) {
  const composeBin = findDockerCompose();
  const composeName = path.basename(composeBin || 'docker');
  if (composeName === 'docker-compose') {
    return { exec: composeBin, args: ['-f', composeFile, ...args] };
  }
  return { exec: composeBin, args: ['compose', '-f', composeFile, ...args] };
}

function spawnComposeCommand(composeFile, args = [], spawnOptions = {}) {
  const command = getComposeCommand(composeFile, args);
  try {
    return spawn(command.exec, command.args, spawnOptions);
  } catch (e) {
    logError('Failed to spawn compose command', { composeFile, args, error: e.message });
    return null;
  }
}

async function runComposeProject(composeFile, args = [], timeoutMs = 60000) {
  const command = getComposeCommand(composeFile, args);
  try {
    return await execFileAsync(command.exec, command.args, { timeout: timeoutMs });
  } catch (e) {
    return { stdout: e.stdout || '', stderr: e.stderr || '', error: e.message || 'compose execution failed' };
  }
}

async function runComposeUpStream(composeFile, service, sendChunk, opts = {}) {
  const child = spawnComposeCommand(composeFile, ['up', '-d', service], { stdio: ['ignore', 'pipe', 'pipe'] });
  if (!child) return { ok: false, error: 'Failed to start compose process' };
  if (opts.onSpawn) opts.onSpawn(child);

  return new Promise(resolve => {
    let stdout = '';
    let stderr = '';
    const onData = (type, data) => {
      const text = String(data || '');
      if (type === 'stdout') stdout += text;
      else stderr += text;
      if (sendChunk) sendChunk(type, text);
    };

    child.stdout.on('data', data => onData('stdout', data));
    child.stderr.on('data', data => onData('stderr', data));
    child.on('error', err => {
      if (sendChunk) sendChunk('error', `[Error: ${err.message}]`);
      resolve({ ok: false, error: err.message || 'Compose spawn failed' });
    });
    child.on('close', code => {
      if (opts.isCancelled && opts.isCancelled()) {
        resolve({ ok: false, error: 'cancelled' });
        return;
      }
      if (code === 0) {
        resolve({ ok: true, stdout, stderr });
      } else {
        resolve({ ok: false, error: `Compose exited with code ${code}`, stdout, stderr });
      }
    });
  });
}

async function runComposeBootLogStream(composeFile, service, sendChunk, opts = {}) {
  const child = spawnComposeCommand(composeFile, ['logs', '--follow', '--timestamps', service], { stdio: ['ignore', 'pipe', 'pipe'] });
  if (!child) return { ok: false, error: 'Failed to start compose logs' };
  if (opts.onSpawn) opts.onSpawn(child);

  return new Promise(resolve => {
    let finished = false;
    const stop = (result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);
      try { child.kill(); } catch {}
      resolve(result);
    };

    const onData = (type, data) => {
      if (sendChunk) sendChunk(type, String(data || ''));
    };

    const onClose = (code) => {
      if (opts.isCancelled && opts.isCancelled()) {
        stop({ ok: false, error: 'cancelled' });
        return;
      }
      stop({ ok: true, code });
    };

    child.stdout.on('data', data => onData('stdout', data));
    child.stderr.on('data', data => onData('stderr', data));
    child.on('error', err => stop({ ok: false, error: err.message || 'Compose logs failed' }));
    child.on('close', onClose);

    const timeoutId = setTimeout(() => {
      stop({ ok: true });
    }, COMPOSE_BOOT_LOG_SECONDS * 1000);
  });
}

function readComposeTemplatePayload() {
  let content = DEFAULT_NEW_COMPOSE_TEMPLATE;
  try {
    if (fs.existsSync(NEW_COMPOSE_TEMPLATE_FILE)) {
      content = fs.readFileSync(NEW_COMPOSE_TEMPLATE_FILE, 'utf8');
    }
    return { ok: true, content, templateFile: NEW_COMPOSE_TEMPLATE_FILE };
  } catch (e) {
    return { ok: false, error: e.message || 'Failed to load compose template' };
  }
}

function saveComposeTemplatePayload(content) {
  try {
    fs.writeFileSync(NEW_COMPOSE_TEMPLATE_FILE, String(content || ''), 'utf8');
    return { ok: true, templateFile: NEW_COMPOSE_TEMPLATE_FILE };
  } catch (e) {
    return { ok: false, error: e.message || 'Failed to save compose template' };
  }
}

function findExistingContainerConflicts(services) {
  const existing = new Set(getCache().containers.map(c => String(c.name || '').trim()).filter(Boolean));
  const conflicts = [];
  for (const service of services || []) {
    const displayName = String(service.displayName || service.service || '').trim();
    if (displayName && existing.has(displayName)) {
      conflicts.push(displayName);
    }
  }
  return conflicts;
}

function shellQuote(v) {
  return `'${String(v ?? '').replace(/'/g, `'\\''`)}'`;
}

async function runDocker(args) {
  try {
    const { stdout } = await execAsync(`"${findDocker()}" ${args}`, { timeout: 8000 });
    return stdout.trim();
  } catch (e) {
    logError('Docker command failed', {
      args,
      error: e?.message || 'unknown error',
    });
    return '';
  }
}

function statAccessInfo(targetPath) {
  try {
    const st = fs.statSync(targetPath);
    const mode = (st.mode & 0o777).toString(8).padStart(3, '0');
    return {
      owner: `${st.uid}:${st.gid}`,
      mode,
      uid: st.uid,
      gid: st.gid,
    };
  } catch {
    return { owner: '', mode: '', uid: null, gid: null };
  }
}

async function buildVolumeUsageMap() {
  const usageMap = {};
  const psOut = await runDocker(`ps -a --format '{{json .}}'`);
  if (!psOut) return usageMap;

  const containers = psOut.split('\n').filter(Boolean).map(line => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);
  const ids = containers.map(c => c.ID).filter(Boolean);
  if (!ids.length) return usageMap;

  try {
    const { stdout } = await execAsync(`"${findDocker()}" inspect ${ids.map(shellQuote).join(' ')} --format '{{json .}}'`, { timeout: 25000 });
    const inspected = String(stdout || '').split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);

    for (const c of inspected) {
      const containerName = String(c.Name || '').replace(/^\//, '') || (c.Config && c.Config.Hostname) || '';
      const isRunning = Boolean(c.State && c.State.Running);
      for (const m of (c.Mounts || [])) {
        if (m && m.Type === 'volume' && m.Name) {
          if (!usageMap[m.Name]) usageMap[m.Name] = [];
          usageMap[m.Name].push({
            id: String(c.Id || '').slice(0, 12),
            name: containerName,
            status: isRunning ? 'running' : 'stopped',
            destination: m.Destination || '',
          });
        }
      }
    }
  } catch (e) {
    logError('Failed to inspect containers for volume usage', { error: e.message || 'unknown error' });
  }

  return usageMap;
}

async function collectDockerVolumes() {
  const usageMap = await buildVolumeUsageMap();
  const out = await runDocker(`volume ls --format '{{json .}}'`);
  if (!out) return [];

  const listed = out.split('\n').filter(Boolean).map(line => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);

  const names = listed.map(v => v.Name).filter(Boolean);
  if (!names.length) return [];

  let inspectArr = [];
  try {
    const { stdout } = await execAsync(`"${findDocker()}" volume inspect ${names.map(shellQuote).join(' ')}`, { timeout: 25000 });
    const parsed = JSON.parse(stdout || '[]');
    inspectArr = Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    logError('Failed to inspect docker volumes', { error: e.message || 'unknown error' });
  }

  const byName = Object.fromEntries(inspectArr.map(v => [v.Name, v]));
  return names.map(name => {
    const iv = byName[name] || {};
    const labels = iv.Labels || {};
    const stack = labels['com.docker.compose.project'] || labels['stack'] || '-';
    const mountpoint = iv.Mountpoint || '';
    const access = mountpoint ? statAccessInfo(mountpoint) : { owner: '', mode: '', uid: null, gid: null };
    const containers = usageMap[name] || [];
    const runningContainers = containers.filter(c => c.status === 'running').map(c => c.name).filter(Boolean);
    return {
      name,
      stack,
      driver: iv.Driver || '',
      mountpoint,
      ownership: access.owner || '-',
      mode: access.mode || '-',
      createdAt: iv.CreatedAt || '',
      createdDate: iv.CreatedAt ? new Date(iv.CreatedAt).toLocaleString() : '-',
      runningOn: runningContainers,
      labels,
      access,
      containers,
      options: iv.Options || {},
      scope: iv.Scope || '',
    };
  });
}

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

async function collectContainers() {
  const listJson = await runDocker(`ps --all --no-trunc --format '{{json .}}'`);
  if (!listJson) return [];

  const containers = listJson.split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);

  const statsJson = await runDocker(`stats --no-stream --no-trunc --format '{{json .}}'`);
  const statsMap = {};
  if (statsJson) {
    statsJson.split('\n').filter(Boolean).forEach(line => {
      try {
        const s = JSON.parse(line);
        statsMap[s.ID] = s;
      } catch {}
    });
  }

  const allIds = containers.map(c => c.ID).filter(Boolean);
  const networkDriverMap = {};
  try {
    const hostIfaces = new Set(
      readFile('/proc/net/dev').split('\n').slice(2).filter(Boolean)
        .map(l => l.trim().split(/\s+/)[0].replace(':', ''))
    );

    function resolveHostIface(networkId, explicitName) {
      if (explicitName && hostIfaces.has(explicitName)) return explicitName;
      if (explicitName) return explicitName;
      if (!networkId) return '';
      const candidates = [
        'docker-' + networkId.slice(0, 8),
        'br-' + networkId.slice(0, 12),
        'br-' + networkId.slice(0, 8),
        'docker' + networkId.slice(0, 7),
      ];
      for (const c of candidates) {
        if (hostIfaces.has(c)) return c;
      }
      const idPrefixes = [networkId.slice(0, 8), networkId.slice(0, 12)];
      for (const iface of hostIfaces) {
        for (const pfx of idPrefixes) {
          if (iface.includes(pfx)) return iface;
        }
      }
      return '';
    }

    const netLs = await runDocker(`network ls --format '{{json .}}'`);
    if (netLs) {
      const netIds = [];
      netLs.split('\n').filter(Boolean).forEach(line => {
        try {
          const n = JSON.parse(line);
          networkDriverMap[n.Name] = { driver: n.Driver || '', hostIface: '', id: n.ID || '' };
          if (n.ID) netIds.push(n.ID);
        } catch {}
      });

      if (netIds.length) {
        const netInspect = await runDocker(`network inspect ${netIds.join(' ')} --format '{{json .}}'`);
        if (netInspect) {
          netInspect.split('\n').filter(Boolean).forEach(line => {
            try {
              const ni = JSON.parse(line);
              const entry = Object.values(networkDriverMap).find(e => e.id === ni.Id || e.id === (ni.Id || '').slice(0, 12));
              if (!entry) return;
              if (ni.Driver === 'host') {
                entry.hostIface = 'host';
              } else if (ni.Driver === 'bridge' && ni.Id) {
                const explicit = (ni.Options && ni.Options['com.docker.network.bridge.name']) || '';
                entry.hostIface = resolveHostIface(ni.Id, explicit);
              }
            } catch {}
          });
        }
      }
    }
  } catch {}

  Object.keys(ifaceToDockerNet).forEach(key => delete ifaceToDockerNet[key]);
  Object.entries(networkDriverMap).forEach(([netName, entry]) => {
    if (entry.hostIface && entry.hostIface !== 'host') {
      ifaceToDockerNet[entry.hostIface] = netName;
    }
  });

  const inspectMetaMap = {};
  const netDefsMap = {};
  if (allIds.length) {
    try {
      const inspectOut = await runDocker(`inspect --format '{{json .}}' ${allIds.join(' ')}`);
      if (inspectOut) {
        inspectOut.split('\n').filter(Boolean).forEach(line => {
          try {
            const obj = JSON.parse(line);
            const fullId = obj.Id;
            const labels = obj.Config && obj.Config.Labels ? obj.Config.Labels : {};
            inspectMetaMap[fullId] = {
              composeProject: labels['com.docker.compose.project'] || '',
              composeService: labels['com.docker.compose.service'] || '',
              composeWorkingDir: labels['com.docker.compose.project.working_dir'] || '',
              composeConfigFiles: labels['com.docker.compose.project.config_files'] || '',
            };
            const nets = obj.NetworkSettings && obj.NetworkSettings.Networks ? obj.NetworkSettings.Networks : {};
            netDefsMap[fullId] = Object.entries(nets).map(([netName, n]) => {
              const meta = networkDriverMap[netName] || {};
              return {
                name: netName,
                driver: meta.driver || '',
                hostIface: meta.hostIface || '',
                ip: n.IPAddress || '',
                gateway: n.Gateway || '',
                macAddr: n.MacAddress || '',
              };
            });
          } catch {}
        });
      }
    } catch {}
  }

  const result = [];
  for (const c of containers) {
    const id = c.ID;
    const stats = statsMap[id] || {};
    const inspectMeta = inspectMetaMap[id] || {};

    let topOut = '';
    if (c.State === 'running') {
      topOut = await runDocker(`top ${id} -eo pid,ppid`);
    }
    const pids = [];
    if (topOut) {
      const lines = topOut.split('\n').slice(1);
      for (const l of lines) {
        const parts = l.trim().split(/\s+/);
        if (parts[0] && /^\d+$/.test(parts[0])) {
          pids.push(parseInt(parts[0]));
        }
      }
    }

    const memUsageRaw = stats.MemUsage || '0B / 0B';
    const netIO = stats.NetIO || '0B / 0B';
    const blockIO = stats.BlockIO || '0B / 0B';

    let imageSize = '';
    try {
      const imgOut = await runDocker(`inspect --format '{{.Config.Image}}' ${id}`);
      if (imgOut) {
        try {
          const { stdout } = await execAsync(`"${findDocker()}" image inspect --format '{{.Size}}' ${imgOut.trim()}`, { timeout: 8000 });
          if (stdout) {
            imageSize = formatBytes(parseInt(stdout.trim()));
          }
        } catch {}
      }
    } catch {}

    const portsRaw = c.Ports || '';
    const ports = [];
    if (portsRaw) {
      const seen = new Set();
      for (const part of portsRaw.split(',')) {
        const m = part.trim().match(/(?:[\d.]+:)?(\d+)->(\d+)\/(tcp|udp)/);
        if (m && !seen.has(m[1])) {
          seen.add(m[1]);
          ports.push({ host: m[1], container: m[2], proto: m[3] });
        }
      }
    }

    let vethRxKBs = 0, vethTxKBs = 0;
    let vethRxBytes = 0, vethTxBytes = 0;
    let netMode = 'veth';
    const netPid = pids[0];
    if (netPid) {
      const nsNet = readContainerNetDev(netPid);
      if (nsNet) {
        vethRxBytes = nsNet.rxBytes;
        vethTxBytes = nsNet.txBytes;
        const nowNet = Date.now();
        const prevCN = prevContainerNetSnapshot[id];
        if (prevCN && nowNet > prevCN.ts) {
          const dtSec = (nowNet - prevCN.ts) / 1000;
          vethRxKBs = parseFloat(Math.max(0, (nsNet.rxBytes - prevCN.rxBytes) / 1024 / dtSec).toFixed(2));
          vethTxKBs = parseFloat(Math.max(0, (nsNet.txBytes - prevCN.txBytes) / 1024 / dtSec).toFixed(2));
        }
        prevContainerNetSnapshot[id] = { rxBytes: nsNet.rxBytes, txBytes: nsNet.txBytes, ts: Date.now() };
      } else {
        netMode = 'host';
      }
    }

    result.push({
      name: (c.Names || c.Name || '').replace(/^\//, ''),
      id: id.slice(0, 12),
      fullId: id,
      image: c.Image || '',
      status: c.Status || '',
      state: c.State || '',
      cpu: stats.CPUPerc || '0%',
      memUsage: memUsageRaw.split('/')[0].trim(),
      memLimit: memUsageRaw.split('/')[1]?.trim() || '',
      memPercent: stats.MemPerc || '0%',
      netIn: netIO.split('/')[0].trim(),
      netOut: netIO.split('/')[1]?.trim() || '',
      blockIO,
      imageSize,
      ports,
      pids,
      processCount: stats.PIDs || pids.length,
      networks: netDefsMap[id] || [],
      vethRxKBs,
      vethTxKBs,
      vethRxBytes,
      vethTxBytes,
      netMode,
      composeProject: inspectMeta.composeProject || '',
      composeService: inspectMeta.composeService || '',
      composeDir: inspectMeta.composeWorkingDir || '',
      composePath: '',
      composeFile: (inspectMeta.composeConfigFiles || '').split(',').map(s => s.trim()).find(Boolean) || '',
      composeManaged: Boolean(
        inspectMeta.composeProject ||
        inspectMeta.composeService ||
        inspectMeta.composeWorkingDir ||
        inspectMeta.composeConfigFiles
      ),
      composeOnly: false,
    });
  }

  const composeProjects = discoverComposeProjects(true);
  const composeProjectMap = new Map();
  for (const project of composeProjects) {
    const group = composeProjectMap.get(project.project) || [];
    group.push(project);
    composeProjectMap.set(project.project, group);
  }
  const matchedComposeKeys = new Set();
  const matchedContainerNames = new Set(result.map(container => container.name));

  for (const container of result) {
    const candidates = container.composeProject ? (composeProjectMap.get(container.composeProject) || []) : [];
    if (!candidates.length) continue;
    const project = candidates.find(p => pathsEqual(p.dir, container.composeDir))
      || candidates.find(p => pathsEqual(p.composeFile, container.composeFile))
      || candidates[0];
    if (!project) continue;
    const service = project.services.find(s =>
      s.service === container.composeService ||
      s.containerName === container.name ||
      s.displayName === container.name
    );
    if (!service) continue;

    matchedComposeKeys.add(`${project.dir}/${service.service}`);
    container.composeProject = project.project;
    container.composeService = service.service;
    container.composePath = '';
    container.composeFile = container.composeFile || project.composeFile;
    container.composeDir = container.composeDir || project.dir;
    container.composeManaged = true;
    if ((!container.ports || !container.ports.length) && service.ports.length) {
      container.ports = service.ports;
    }
  }

  for (const project of composeProjects) {
    for (const service of project.services) {
      const composeKey = `${project.dir}/${service.service}`;
      if (matchedComposeKeys.has(composeKey) || matchedContainerNames.has(service.displayName)) continue;

      result.push({
        name: service.displayName,
        id: buildComposeSyntheticId(project.project, service.service),
        fullId: '',
        image: service.image || '',
        status: 'Defined in compose',
        state: 'configured',
        cpu: '–',
        memUsage: '–',
        memLimit: '',
        memPercent: '–',
        netIn: '–',
        netOut: '–',
        blockIO: '–',
        imageSize: '',
        ports: service.ports || [],
        pids: [],
        processCount: 0,
        networks: [],
        vethRxKBs: 0,
        vethTxKBs: 0,
        vethRxBytes: 0,
        vethTxBytes: 0,
        netMode: 'compose',
        composeProject: project.project,
        composeService: service.service,
        composeDir: project.dir,
        composePath: '',
        composeFile: project.composeFile,
        composeManaged: true,
        composeOnly: true,
      });
    }
  }

  return result;
}

function getHelperUrlValue(url, key) {
  return String(url.searchParams.get(key) || '').trim();
}

function writeJson(res, body, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(body));
}

function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

async function handleContainerLogStream(req, res, url) {
  if (!url.pathname.startsWith('/api/container/log/')) return false;
  const id = decodeURIComponent(url.pathname.split('/')[4] || '');
  if (!id) return false;

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  const tail = spawn(findDocker(), ['logs', '--tail', '200', '--follow', '--timestamps', id]);
  const send = data => {
    if (!res.writableEnded) {
      const lines = data.toString().split('\n').filter(Boolean);
      for (const line of lines) {
        res.write(`data: ${JSON.stringify(line)}\n\n`);
      }
    }
  };

  tail.stdout.on('data', send);
  tail.stderr.on('data', send);
  tail.on('error', e => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify('[Error: ' + e.message + ']')}\n\n`);
  });

  req.on('close', () => { try { tail.kill(); } catch {} });
  return true;
}

async function handleContainerDetail(req, res, url) {
  if (!url.pathname.startsWith('/api/container/detail/')) return false;
  const id = decodeURIComponent(url.pathname.split('/')[4] || '');
  if (!id) { writeJson(res, {}, 400); return true; }
  try {
    const syntheticDetail = getComposeSyntheticDetail(id);
    if (syntheticDetail) {
      writeJson(res, syntheticDetail);
      return true;
    }

    const raw = await runDocker(`inspect ${id}`);
    if (!raw) { writeJson(res, { error: 'Not found' }); return true; }
    const arr = JSON.parse(raw);
    const d = arr[0];
    if (!d) { writeJson(res, { error: 'Empty response' }); return true; }

    let imageHash = '';
    let imageSize = '';
    try {
      const imgRaw = await runDocker(`image inspect --format '{{json .}}' ${d.Image}`);
      if (imgRaw) {
        const img = JSON.parse(imgRaw);
        imageHash = img.Id ? img.Id.replace('sha256:', '').slice(0, 12) : '';
        imageSize = img.Size ? formatBytes(img.Size) : '';
      }
    } catch {}

    const portConfig = [];
    if (d.HostConfig && d.HostConfig.PortBindings) {
      Object.entries(d.HostConfig.PortBindings).forEach(([containerPort, bindings]) => {
        (bindings || []).forEach(b => {
          portConfig.push({ containerPort, hostIp: b.HostIp || '0.0.0.0', hostPort: b.HostPort || '' });
        });
      });
    }

    const volumes = [];
    if (d.Mounts) {
      for (const m of d.Mounts) {
        let sizeOnDisk = '';
        if (m.Source) {
          try {
            const { stdout } = await execAsync(`du -sh "${m.Source}" 2>/dev/null`, { timeout: 8000 });
            sizeOnDisk = stdout ? stdout.trim().split(/\s+/)[0] : '';
          } catch {}
        }
        volumes.push({ type: m.Type || '', source: m.Source || '', destination: m.Destination || '', mode: m.Mode || '', rw: m.RW, sizeOnDisk });
      }
    }

    const networks = [];
    if (d.NetworkSettings && d.NetworkSettings.Networks) {
      Object.entries(d.NetworkSettings.Networks).forEach(([name, n]) => {
        networks.push({ name, ip: n.IPAddress || '', gateway: n.Gateway || '', mac: n.MacAddress || '', subnet: (n.IPAMConfig && n.IPAMConfig.IPv4Address) || '' });
      });
    }

    const env = (d.Config && d.Config.Env || []).map(e => {
      const idx = e.indexOf('=');
      return idx >= 0 ? { key: e.slice(0, idx), value: e.slice(idx + 1) } : { key: e, value: '' };
    });

    const labels = Object.entries(d.Config && d.Config.Labels || {}).map(([k, v]) => ({ key: k, value: v }));
    const currentContainer = getCache().containers.find(c => c.id === id || c.fullId === id) || {};
    const composeProject = currentContainer.composeProject || (d.Config && d.Config.Labels && d.Config.Labels['com.docker.compose.project']) || '';
    const composeService = currentContainer.composeService || (d.Config && d.Config.Labels && d.Config.Labels['com.docker.compose.service']) || '';
    const composeFile = currentContainer.composeFile || '';
    const composeManaged = Boolean(currentContainer.composeManaged || composeProject || composeService || composeFile);
    const composeFilePayload = composeManaged ? readComposeFilePayload(composeProject, composeFile) : null;

    writeJson(res, {
      id: d.Id ? d.Id.slice(0, 12) : '',
      fullId: d.Id || '',
      name: (d.Name || '').replace(/^\//, ''),
      status: d.State ? d.State.Status : '',
      running: d.State ? d.State.Running : false,
      created: d.Created || '',
      startedAt: d.State ? d.State.StartedAt : '',
      finishedAt: d.State ? d.State.FinishedAt : '',
      uptime: d.State ? d.State.Status : '',
      restartCount: d.RestartCount || 0,
      restartPolicy: {
        name: (d.HostConfig && d.HostConfig.RestartPolicy && d.HostConfig.RestartPolicy.Name) || 'no',
        maximumRetryCount: (d.HostConfig && d.HostConfig.RestartPolicy && d.HostConfig.RestartPolicy.MaximumRetryCount) || 0,
      },
      image: d.Config ? d.Config.Image : '',
      imageId: d.Image || '',
      imageHash,
      imageSize,
      cmd: d.Config && d.Config.Cmd ? d.Config.Cmd.join(' ') : '',
      entrypoint: d.Config && d.Config.Entrypoint ? d.Config.Entrypoint.join(' ') : '',
      memUsage: currentContainer.memUsage || '',
      memPercent: currentContainer.memPercent || '',
      cpu: currentContainer.cpu || '',
      blockIO: currentContainer.blockIO || '',
      portConfig,
      volumes,
      networks,
      env,
      labels,
      composeProject,
      composeService,
      composeManaged,
      composeOnly: false,
      composeFile: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFile : composeFile,
      composeFileName: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFileName : (composeFile ? path.basename(composeFile) : ''),
      composeFileContent: composeFilePayload && composeFilePayload.ok ? composeFilePayload.composeFileContent : '',
      composeFileError: composeFilePayload && !composeFilePayload.ok ? composeFilePayload.error : '',
    });
  } catch (e) {
    writeJson(res, { error: e.message });
  }
  return true;
}

async function handleContainerRestartPolicy(req, res, url) {
  if (!url.pathname.startsWith('/api/container/restart-policy/') || req.method !== 'POST') return false;
  const id = url.pathname.split('/')[4];
  if (!id) { writeJson(res, { ok: false, error: 'Missing id' }, 400); return true; }
  const body = await getRequestBody(req);
  try {
    const { policy, maxRetries } = JSON.parse(body);
    const VALID = ['no', 'always', 'unless-stopped', 'on-failure'];
    if (!VALID.includes(policy)) {
      writeJson(res, { ok: false, error: `Invalid policy "${policy}". Must be one of: ${VALID.join(', ')}` });
      return true;
    }
    const restartFlag = (policy === 'on-failure' && maxRetries > 0)
      ? `on-failure:${parseInt(maxRetries)}`
      : policy;
    const { stdout, stderr } = await execAsync(`"${findDocker()}" update --restart=${restartFlag} ${id}`, { timeout: 10000 });
    writeJson(res, { ok: true, output: (stdout + stderr).trim(), policy, maxRetries: maxRetries || 0 });
  } catch (e) {
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleContainerFolders(req, res, url) {
  if (url.pathname !== '/api/container/folders') return false;
  if (req.method === 'GET') {
    const name = getHelperUrlValue(url, 'name');
    const subpath = getHelperUrlValue(url, 'subpath');
    const resolved = resolveContainerDataPath(name, subpath);
    if (!resolved) {
      writeJson(res, { ok: false, error: 'Invalid container name or path' }, 400);
      return true;
    }
    const exists = fs.existsSync(resolved.basePath);
    let entries = [];
    const currentExists = fs.existsSync(resolved.targetPath);
    if (exists && currentExists) {
      try {
        entries = fs.readdirSync(resolved.targetPath, { withFileTypes: true })
          .map(e => {
            const fullPath = path.join(resolved.targetPath, e.name);
            let sizeBytes = 0;
            let modifiedAt = '';
            try {
              const st = fs.statSync(fullPath);
              sizeBytes = st.size || 0;
              modifiedAt = st.mtime ? st.mtime.toISOString() : '';
            } catch {}
            return {
              name: e.name,
              type: e.isDirectory() ? 'dir' : 'file',
              sizeBytes,
              modifiedAt,
            };
          })
          .sort((a, b) => {
            if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
            return a.name.localeCompare(b.name);
          });
      } catch (e) {
        logError('Failed to browse container data folder', {
          name,
          subpath: resolved.subPath,
          path: resolved.targetPath,
          error: e.message,
        });
      }
    }
    writeJson(res, {
      ok: true,
      path: resolved.targetPath,
      basePath: resolved.basePath,
      subpath: resolved.subPath,
      exists,
      currentExists,
      entries,
    });
    return true;
  }

  if (req.method === 'POST') {
    const body = await getRequestBody(req);
    try {
      const { name, subfolders, parentPath } = JSON.parse(body || '{}');
      const resolvedBase = resolveContainerDataPath(name, '');
      const resolvedParent = resolveContainerDataPath(name, parentPath || '');
      if (!resolvedBase || !resolvedParent) {
        writeJson(res, { ok: false, error: 'Invalid container name or parent path' });
        return true;
      }
      const basePath = resolvedBase.basePath;
      const parentDir = resolvedParent.targetPath;
      const created = [];
      if (!fs.existsSync(basePath)) {
        fs.mkdirSync(basePath, { recursive: true });
        created.push(name);
      }
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }
      if (Array.isArray(subfolders)) {
        for (const sub of subfolders) {
          const subName = String(sub || '').trim();
          if (!subName || path.isAbsolute(subName)) continue;
          if (subName.split('/').some(seg => seg === '..' || seg === '.')) continue;
          if (!/^[a-zA-Z0-9_.\-][a-zA-Z0-9_.\-\/]*$/.test(subName)) continue;
          const subPath = path.join(parentDir, subName);
          if (!isPathInsideRoot(subPath, basePath)) continue;
          if (!fs.existsSync(subPath)) {
            fs.mkdirSync(subPath, { recursive: true });
            created.push(subName);
          }
        }
      }
      logError('Container data folder ensured', {
        container: name,
        createdCount: created.length,
        created,
      });
      writeJson(res, { ok: true, path: basePath, created });
    } catch (e) {
      logError('Failed to create container data folder', { error: e.message });
      writeJson(res, { ok: false, error: e.message });
    }
    return true;
  }

  return false;
}

async function handleContainerFoldersDownload(req, res, url) {
  if (url.pathname !== '/api/container/folders/download' || req.method !== 'GET') return false;
  const name = getHelperUrlValue(url, 'name');
  const filePath = getHelperUrlValue(url, 'filePath');
  const resolved = resolveContainerDataPath(name, filePath);
  if (!resolved) {
    writeJson(res, { ok: false, error: 'Invalid container name or file path' }, 400);
    return true;
  }

  let st = null;
  try { st = fs.statSync(resolved.targetPath); } catch {}
  if (!st) {
    writeJson(res, { ok: false, error: 'File not found' }, 404);
    return true;
  }
  if (!st.isFile()) {
    writeJson(res, { ok: false, error: 'Only files can be downloaded' }, 400);
    return true;
  }

  const filename = path.basename(resolved.targetPath);
  const encodedFilename = encodeURIComponent(filename);
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': st.size,
    'Content-Disposition': `attachment; filename="${filename.replace(/"/g, '')}"; filename*=UTF-8''${encodedFilename}`,
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });

  const stream = fs.createReadStream(resolved.targetPath);
  stream.on('error', e => {
    logError('Container file download stream failed', {
      container: name,
      filePath: resolved.subPath,
      error: e.message,
    });
    if (!res.writableEnded) {
      res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: 'Failed to read file' }));
    }
  });
  stream.pipe(res);
  return true;
}

async function handleContainerFoldersRename(req, res, url) {
  if (url.pathname !== '/api/container/folders/rename' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { name, folderPath, newName } = JSON.parse(body || '{}');
    const resolved = resolveContainerDataPath(name, folderPath || '');
    if (!resolved) {
      writeJson(res, { ok: false, error: 'Invalid container name or folder path' });
      return true;
    }
    const cleanNewName = String(newName || '').trim();
    if (!/^[a-zA-Z0-9_.\-]+$/.test(cleanNewName)) {
      writeJson(res, { ok: false, error: 'Invalid folder name' });
      return true;
    }
    const fromPath = resolved.targetPath;
    if (fromPath === resolved.basePath) {
      writeJson(res, { ok: false, error: 'Root folder cannot be renamed' });
      return true;
    }
    let fromStat = null;
    try { fromStat = fs.statSync(fromPath); } catch {}
    if (!fromStat || !fromStat.isDirectory()) {
      writeJson(res, { ok: false, error: 'Only folders can be renamed' });
      return true;
    }
    const toPath = path.join(path.dirname(fromPath), cleanNewName);
    if (!isPathInsideRoot(toPath, resolved.basePath)) {
      writeJson(res, { ok: false, error: 'Invalid target folder path' });
      return true;
    }
    if (fs.existsSync(toPath)) {
      writeJson(res, { ok: false, error: 'A file or folder with the target name already exists' });
      return true;
    }
    fs.renameSync(fromPath, toPath);
    logError('Container folder renamed', { container: name, from: resolved.subPath, to: cleanNewName });
    writeJson(res, { ok: true });
  } catch (e) {
    logError('Failed to rename container folder', { error: e.message });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleContainerFoldersDelete(req, res, url) {
  if (url.pathname !== '/api/container/folders/delete' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { name, folderPath } = JSON.parse(body || '{}');
    const resolved = resolveContainerDataPath(name, folderPath || '');
    if (!resolved) {
      writeJson(res, { ok: false, error: 'Invalid container name or folder path' });
      return true;
    }
    const targetPath = resolved.targetPath;
    if (targetPath === resolved.basePath) {
      writeJson(res, { ok: false, error: 'Root folder cannot be deleted' });
      return true;
    }
    let st = null;
    try { st = fs.statSync(targetPath); } catch {}
    if (!st || !st.isDirectory()) {
      writeJson(res, { ok: false, error: 'Only folders can be deleted' });
      return true;
    }
    fs.rmSync(targetPath, { recursive: true, force: false });
    logError('Container folder deleted', { container: name, folderPath: resolved.subPath });
    writeJson(res, { ok: true });
  } catch (e) {
    logError('Failed to delete container folder', { error: e.message });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function runContainerCommand(action, id) {
  const safeId = String(id || '').trim();
  if (!safeId) {
    return { ok: false, error: 'Container id is required' };
  }

  const commands = {
    start: ['start', safeId],
    stop: ['stop', safeId],
    restart: ['restart', safeId],
    delete: ['rm', '-f', safeId],
  };

  const cmdArgs = commands[action];
  if (!cmdArgs) {
    return { ok: false, error: `Unsupported action: ${action}` };
  }

  try {
    const { stdout, stderr } = await execFileAsync(findDocker(), cmdArgs, { timeout: 20000 });
    return { ok: true, output: `${stdout || ''}${stderr || ''}`.trim() };
  } catch (e) {
    const errorText = e.stderr ? String(e.stderr).trim() : e.message || 'Command failed';
    return { ok: false, error: errorText };
  }
}

async function handleContainerAction(req, res, url) {
  const supported = ['start', 'stop', 'restart', 'delete'];
  const action = url.pathname.split('/').pop();
  if (!supported.includes(action) || req.method !== 'GET') return false;
  const id = String(url.searchParams.get('id') || '').trim();
  const result = await runContainerCommand(action === 'delete' ? 'delete' : action, id);
  writeJson(res, result, result.ok ? 200 : 500);
  return true;
}

async function handleDockerVolumesList(req, res, url) {
  if (url.pathname !== '/api/docker/volumes/list' || req.method !== 'GET') return false;
  try {
    const volumes = await collectDockerVolumes();
    writeJson(res, { ok: true, volumes });
  } catch (e) {
    logError('Failed to list docker volumes', { error: e.message || 'unknown error' });
    writeJson(res, { ok: false, error: e.message, volumes: [] });
  }
  return true;
}

async function handleDockerVolumesDetail(req, res, url) {
  if (url.pathname !== '/api/docker/volumes/detail' || req.method !== 'GET') return false;
  const name = getHelperUrlValue(url, 'name');
  if (!name) { writeJson(res, { ok: false, error: 'name is required' }); return true; }
  try {
    const volumes = await collectDockerVolumes();
    const volume = volumes.find(v => v.name === name);
    if (!volume) {
      writeJson(res, { ok: false, error: 'Volume not found' });
      return true;
    }
    writeJson(res, { ok: true, volume });
  } catch (e) {
    logError('Failed to load docker volume detail', { name, error: e.message || 'unknown error' });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleDockerVolumesCreate(req, res, url) {
  if (url.pathname !== '/api/docker/volumes/create' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { name, driver, labels } = JSON.parse(body || '{}');
    const safeName = String(name || '').trim();
    if (!safeName) {
      writeJson(res, { ok: false, error: 'Volume name required' });
      return true;
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(safeName)) {
      writeJson(res, { ok: false, error: 'Invalid volume name format' });
      return true;
    }
    let cmd = `"${findDocker()}" volume create --driver ${shellQuote(driver || 'local')}`;
    if (labels && typeof labels === 'object') {
      for (const [k, v] of Object.entries(labels)) {
        if (!k) continue;
        cmd += ` --label ${shellQuote(`${k}=${String(v ?? '')}`)}`;
      }
    }
    cmd += ` ${shellQuote(safeName)}`;
    const { stdout } = await execAsync(cmd, { timeout: 15000 });
    writeJson(res, { ok: true, id: String(stdout || '').trim(), name: safeName });
  } catch (e) {
    logError('Failed to create docker volume', { error: e.message || 'unknown error' });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleDockerVolumesDelete(req, res, url) {
  if (url.pathname !== '/api/docker/volumes/delete' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { name } = JSON.parse(body || '{}');
    const safeName = String(name || '').trim();
    if (!safeName) {
      writeJson(res, { ok: false, error: 'Volume name required' });
      return true;
    }
    await execAsync(`"${findDocker()}" volume rm ${shellQuote(safeName)}`, { timeout: 15000 });
    writeJson(res, { ok: true });
  } catch (e) {
    logError('Failed to delete docker volume', { error: e.message || 'unknown error' });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeUp(req, res, url, reqUser) {
  if (url.pathname !== '/api/compose/up' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { project, service } = JSON.parse(body || '{}');
    if (!project || !service) {
      logError('Compose up rejected: missing project or service', { user: reqUser, project, service });
      writeJson(res, { ok: false, error: 'project and service are required' });
      return true;
    }

    const target = findComposeServiceTarget(project, service);
    if (!target) {
      logError('Compose up target not found', { user: reqUser, project, service });
      writeJson(res, { ok: false, error: 'Compose service not found under configured compose root.' });
      return true;
    }

    const result = await runComposeProject(target.project.composeFile, ['up', '-d', target.service.service], 60000);
    if (result.error) {
      logError('Compose up failed', { user: reqUser, project: target.project.project, service: target.service.service, error: result.error });
      writeJson(res, { ok: false, error: result.error });
      return true;
    }

    logInfo('Compose up completed', {
      user: reqUser,
      project: target.project.project,
      service: target.service.service,
    });
    writeJson(res, {
      ok: true,
      output: `${result.stdout || ''}${result.stderr || ''}`.trim(),
      project: target.project.project,
      service: target.service.service,
    });
  } catch (e) {
    logError('Compose up failed', { user: reqUser, error: e.message || 'unknown error' });
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeUpStream(req, res, url, reqUser) {
  if (url.pathname !== '/api/compose/up/stream' || req.method !== 'POST') return false;
  let activeChild = null;
  let clientClosed = false;
  const cancelActiveCompose = () => {
    clientClosed = true;
    if (activeChild && !activeChild.killed) {
      try { activeChild.kill('SIGTERM'); } catch {}
      setTimeout(() => {
        try {
          if (activeChild && !activeChild.killed) activeChild.kill('SIGKILL');
        } catch {}
      }, 1500);
    }
  };

  res.on('close', cancelActiveCompose);
  req.on('aborted', cancelActiveCompose);

  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  const send = payload => {
    if (!res.writableEnded && !res.destroyed) res.write(JSON.stringify(payload) + '\n');
  };
  const sendChunk = (type, text) => {
    const lines = String(text || '').replace(/\r/g, '').split('\n').filter(Boolean);
    for (const line of lines) send({ type, message: line });
  };

  try {
    const body = await getRequestBody(req);
    const { project, service } = JSON.parse(body || '{}');
    if (!project || !service) {
      logError('Compose stream rejected: missing project or service', { user: reqUser, project, service });
      send({ type: 'error', message: 'project and service are required' });
      send({ type: 'done', ok: false });
      res.end();
      return true;
    }

    const target = findComposeServiceTarget(project, service);
    if (!target) {
      logError('Compose stream failed: target not found', { user: reqUser, project, service });
      send({ type: 'error', message: 'Compose service not found under configured compose root.' });
      send({ type: 'done', ok: false });
      res.end();
      return true;
    }

    send({ type: 'status', message: 'Reading compose project…' });
    const result = await runComposeUpStream(target.project.composeFile, target.service.service, sendChunk, {
      onSpawn: child => { activeChild = child; },
      isCancelled: () => clientClosed,
    });

    if (clientClosed) {
      logInfo('Compose stream cancelled by client', { user: reqUser, project, service });
      if (!res.writableEnded && !res.destroyed) res.end();
      return true;
    }

    if (result.ok) {
      const bootLogs = await runComposeBootLogStream(target.project.composeFile, target.service.service, sendChunk, {
        onSpawn: child => { activeChild = child; },
        isCancelled: () => clientClosed,
      });
      if (clientClosed) {
        logInfo('Compose stream cancelled by client during startup logs', { user: reqUser, project, service });
        if (!res.writableEnded && !res.destroyed) res.end();
        return true;
      }
      if (!bootLogs.ok) {
        send({ type: 'status', message: `Startup log follow ended early: ${bootLogs.error || 'unknown reason'}` });
      }
      logInfo('Compose stream completed', { user: reqUser, project: target.project.project, service: target.service.service });
      send({ type: 'done', ok: true, message: 'Compose up completed successfully.' });
    } else {
      logError('Compose stream failed', {
        user: reqUser,
        project,
        service,
        error: result.error || 'compose up failed',
      });
      send({ type: 'error', message: result.error || 'compose up failed' });
      send({ type: 'done', ok: false });
    }
  } catch (e) {
    logError('Compose stream failed with unexpected error', { user: reqUser, error: e.message || 'Unexpected error' });
    send({ type: 'error', message: e.message || 'Unexpected error' });
    send({ type: 'done', ok: false });
  }

  if (!res.writableEnded && !res.destroyed) res.end();
  return true;
}

async function handleComposeTemplate(req, res, url, reqUser) {
  if (url.pathname !== '/api/compose/template') return false;
  if (req.method === 'GET') {
    writeJson(res, readComposeTemplatePayload());
    return true;
  }
  if (req.method === 'POST') {
    const body = await getRequestBody(req);
    try {
      const { content } = JSON.parse(body || '{}');
      const saved = saveComposeTemplatePayload(content);
      if (saved.ok) {
        logInfo('Compose template updated', { user: reqUser, templateFile: saved.templateFile });
      } else {
        logError('Compose template update failed', { user: reqUser, error: saved.error || 'unknown error' });
      }
      writeJson(res, saved);
    } catch (e) {
      logError('Compose template update failed', { user: reqUser, error: e.message || 'Unexpected error' });
      writeJson(res, { ok: false, error: e.message || 'Unexpected error' });
    }
    return true;
  }
  return false;
}

async function handleComposeCreate(req, res, url) {
  if (url.pathname !== '/api/compose/create' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { name, content } = JSON.parse(body || '{}');
    const parsedServices = parseComposeServices(content);

    if (!name || !/^[a-zA-Z0-9_-]+$/.test(name)) {
      writeJson(res, { ok: false, error: 'Invalid project name. Use only letters, numbers, hyphens and underscores.' });
      return true;
    }
    if (typeof content !== 'string' || !content.trim()) {
      writeJson(res, { ok: false, error: 'compose.yaml content is required.' });
      return true;
    }

    const containerConflicts = findExistingContainerConflicts(parsedServices);
    if (containerConflicts.length) {
      const quoted = containerConflicts.map(value => `"${value}"`).join(', ');
      writeJson(res, {
        ok: false,
        warning: true,
        error: `Container already exists: ${quoted}. Creation stopped; no files were changed.`,
      });
      return true;
    }

    const composeRoot = getComposeConfigRoot();
    const projectDir = path.join(composeRoot, name);
    const composeFile = path.join(projectDir, 'compose.yaml');

    if (!isPathInsideRoot(projectDir, composeRoot)) {
      writeJson(res, { ok: false, error: 'Invalid project path.' });
      return true;
    }
    if (fs.existsSync(projectDir)) {
      writeJson(res, { ok: false, error: `Project "${name}" already exists.` });
      return true;
    }

    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(composeFile, content, 'utf8');

    const firstService = parsedServices[0] || null;
    const openTarget = firstService ? {
      id: buildComposeSyntheticId(name, firstService.service),
      name: firstService.displayName || firstService.service,
      stateClass: 'configured',
    } : null;

    composeDiscoveryCache = { ts: 0, projects: [] };
    await refreshCache();
    auditLog('compose_create', { user: reqUser, details: name, status: 'success' }, req);
    writeJson(res, { ok: true, composeFile, openTarget });
  } catch (e) {
    auditLog('compose_create', { user: reqUser, details: body || '', status: 'failed', error: e.message }, req);
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeBackups(req, res, url) {
  if (url.pathname !== '/api/compose/backups' || req.method !== 'GET') return false;
  try {
    const result = [];
    if (fs.existsSync(COMPOSE_BACKUP_ROOT)) {
      const projects = fs.readdirSync(COMPOSE_BACKUP_ROOT).filter(e => {
        try { return fs.statSync(path.join(COMPOSE_BACKUP_ROOT, e)).isDirectory(); } catch { return false; }
      });
      for (const project of projects) {
        const dir = path.join(COMPOSE_BACKUP_ROOT, project);
        const files = fs.readdirSync(dir).map(f => {
          const fp = path.join(dir, f);
          let mtime = null;
          try { mtime = fs.statSync(fp).mtime.toISOString(); } catch {}
          return { name: f, mtime };
        }).sort((a, b) => (b.mtime || '').localeCompare(a.mtime || ''));
        result.push({ project, path: dir, files });
      }
      result.sort((a, b) => a.project.localeCompare(b.project));
    }
    writeJson(res, { ok: true, backups: result });
  } catch (e) {
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeArchive(req, res, url) {
  if (url.pathname !== '/api/compose/archive' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { project } = JSON.parse(body || '{}');
    if (!project || !/^[a-zA-Z0-9_-]+$/.test(project)) {
      writeJson(res, { ok: false, error: 'Invalid project name.' });
      return true;
    }

    const composeRoot = getComposeConfigRoot();
    const sourceDir = path.join(composeRoot, project);
    const backupDir = path.join(COMPOSE_BACKUP_ROOT, project);
    if (!isPathInsideRoot(sourceDir, composeRoot) || !isPathInsideRoot(backupDir, COMPOSE_BACKUP_ROOT)) {
      writeJson(res, { ok: false, error: 'Invalid project path.' });
      return true;
    }
    if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
      writeJson(res, { ok: false, error: 'Compose project folder not found.' });
      return true;
    }

    fs.mkdirSync(backupDir, { recursive: true });
    const moved = [];
    const entries = fs.readdirSync(sourceDir);
    for (const entry of entries) {
      const src = path.join(sourceDir, entry);
      let dst = path.join(backupDir, entry);
      if (fs.existsSync(dst)) {
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        dst = path.join(backupDir, `${entry}.${stamp}`);
      }
      fs.renameSync(src, dst);
      moved.push(path.basename(dst));
    }

    try {
      fs.rmdirSync(sourceDir);
    } catch {
      fs.rmSync(sourceDir, { recursive: true, force: true });
    }

    composeDiscoveryCache = { ts: 0, projects: [] };
    await refreshCache();
    writeJson(res, { ok: true, backupDir, moved });
  } catch (e) {
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeRestore(req, res, url) {
  if (url.pathname !== '/api/compose/restore' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { project } = JSON.parse(body || '{}');
    if (!project || !/^[a-zA-Z0-9_-]+$/.test(project)) {
      writeJson(res, { ok: false, error: 'Invalid project name.' });
      return true;
    }

    const backupDir = path.join(COMPOSE_BACKUP_ROOT, project);
    const composeRoot = getComposeConfigRoot();
    const targetDir = path.join(composeRoot, project);
    if (!isPathInsideRoot(backupDir, COMPOSE_BACKUP_ROOT) || !isPathInsideRoot(targetDir, composeRoot)) {
      writeJson(res, { ok: false, error: 'Invalid project path.' });
      return true;
    }
    if (!fs.existsSync(backupDir) || !fs.statSync(backupDir).isDirectory()) {
      writeJson(res, { ok: false, error: 'Backup project folder not found.' });
      return true;
    }

    fs.mkdirSync(targetDir, { recursive: true });
    const moved = [];
    const entries = fs.readdirSync(backupDir);
    for (const entry of entries) {
      const src = path.join(backupDir, entry);
      let dst = path.join(targetDir, entry);
      if (fs.existsSync(dst)) {
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        dst = path.join(targetDir, `${entry}.${stamp}`);
      }
      fs.renameSync(src, dst);
      moved.push(path.basename(dst));
    }

    const remaining = fs.readdirSync(backupDir);
    if (!remaining.length) {
      try {
        fs.rmdirSync(backupDir);
      } catch {
        fs.rmSync(backupDir, { recursive: true, force: true });
      }
    }

    composeDiscoveryCache = { ts: 0, projects: [] };
    await refreshCache();
    writeJson(res, { ok: true, targetDir, moved });
  } catch (e) {
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleComposeFileGet(req, res, url) {
  if (url.pathname !== '/api/compose/file' || req.method !== 'GET') return false;
  const project = url.searchParams.get('project') || '';
  const composeFile = url.searchParams.get('composeFile') || '';
  const payload = readComposeFilePayload(project, composeFile);
  writeJson(res, payload);
  return true;
}

async function handleComposeFilePost(req, res, url) {
  if (url.pathname !== '/api/compose/file' || req.method !== 'POST') return false;
  const body = await getRequestBody(req);
  try {
    const { project, composeFile, content } = JSON.parse(body || '{}');
    if (!project) {
      writeJson(res, { ok: false, error: 'project is required' });
      return true;
    }
    if (typeof content !== 'string') {
      writeJson(res, { ok: false, error: 'content must be a string' });
      return true;
    }

    const safeComposeFile = getSafeComposeFilePath(project, composeFile);
    if (!safeComposeFile) {
      writeJson(res, { ok: false, error: 'Compose file not found under configured compose root.' });
      return true;
    }

    fs.writeFileSync(safeComposeFile, content, 'utf8');
    composeDiscoveryCache = { ts: 0, projects: [] };
    await refreshCache();
    writeJson(res, { ok: true, composeFile: safeComposeFile });
  } catch (e) {
    writeJson(res, { ok: false, error: e.message });
  }
  return true;
}

async function handleApi(req, res, url, reqUser) {
  if (await handleContainerLogStream(req, res, url)) return true;
  if (await handleContainerDetail(req, res, url)) return true;
  if (await handleContainerRestartPolicy(req, res, url)) return true;
  if (await handleContainerFolders(req, res, url)) return true;
  if (await handleContainerFoldersDownload(req, res, url)) return true;
  if (await handleContainerFoldersRename(req, res, url)) return true;
  if (await handleContainerFoldersDelete(req, res, url)) return true;
  if (await handleContainerAction(req, res, url)) return true;
  if (await handleDockerVolumesList(req, res, url)) return true;
  if (await handleDockerVolumesDetail(req, res, url)) return true;
  if (await handleDockerVolumesCreate(req, res, url)) return true;
  if (await handleDockerVolumesDelete(req, res, url)) return true;
  if (await handleComposeUp(req, res, url, reqUser)) return true;
  if (await handleComposeUpStream(req, res, url, reqUser)) return true;
  if (await handleComposeTemplate(req, res, url, reqUser)) return true;
  if (await handleComposeCreate(req, res, url)) return true;
  if (await handleComposeBackups(req, res, url)) return true;
  if (await handleComposeArchive(req, res, url)) return true;
  if (await handleComposeRestore(req, res, url)) return true;
  if (await handleComposeFileGet(req, res, url)) return true;
  if (await handleComposeFilePost(req, res, url)) return true;
  return false;
}

module.exports = {
  setDependencies,
  collectContainers,
  collectDockerVolumes,
  getComposeSyntheticDetail,
  runDocker,
  handleApi,
  _test: {
    normalizeContainerSubPath,
    parseComposeServices,
    shellQuote,
    parseComposeSyntheticId,
    buildComposeSyntheticId,
    isPathInsideRoot,
    getSafeComposeFilePath,
    getComposeConfigRoot,
    getComposeRelativePath,
  },
};
