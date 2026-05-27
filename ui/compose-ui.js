// ─── Data Folder Management ───────────────────────────────────────────────────
const folderBrowserState = {};

function getFolderBrowserState(containerId) {
  if (!folderBrowserState[containerId]) {
    folderBrowserState[containerId] = { currentPath: '' };
  }
  return folderBrowserState[containerId];
}

function decodeFolderArg(value) {
  try { return decodeURIComponent(String(value || '')); } catch { return String(value || ''); }
}

function getFolderParentPath(subpath) {
  const parts = String(subpath || '').split('/').filter(Boolean);
  parts.pop();
  return parts.join('/');
}

function joinFolderPath(base, next) {
  const a = String(base || '').trim();
  const b = String(next || '').trim();
  if (!a) return b;
  if (!b) return a;
  return `${a}/${b}`;
}

async function loadFoldersTab(containerName, containerId, subpath = null) {
  const content = document.getElementById(`folders-content-${containerId}`);
  if (!content) return;
  const state = getFolderBrowserState(containerId);
  const wantedPath = subpath === null ? (state.currentPath || '') : String(subpath || '');
  state.currentPath = wantedPath;
  content.innerHTML = `<span style="font-family:var(--mono);font-size:13px;">⟳ Loading…</span>`;
  try {
    const params = new URLSearchParams({ name: containerName });
    if (wantedPath) params.set('subpath', wantedPath);
    const res = await fetch('/api/container/folders?' + params.toString());
    const data = await res.json();
    if (!data.ok) {
      content.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:13px;">⚠ ${esc(data.error)}</div>`;
      return;
    }
    state.currentPath = data.subpath || '';
    renderFoldersTab(containerName, containerId, data);
  } catch (e) {
    content.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:13px;">⚠ ${esc(e.message)}</div>`;
  }
}

async function loadConfigFolderTab(containerName, containerId) {
  const content = document.getElementById(`configfolder-content-${containerId}`);
  if (!content) return;
  content.innerHTML = `<span style="font-family:var(--mono);font-size:13px;">⟳ Loading…</span>`;
  try {
    const res = await fetch('/api/container/config-folders?' + new URLSearchParams({ name: containerName }).toString());
    const data = await res.json();
    renderConfigFolderTab(containerName, containerId, data);
  } catch (e) {
    content.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:13px;">⚠ ${esc(e.message)}</div>`;
  }
}

async function loadConfigFolderPath(containerName, containerId, subpath = '') {
  const content = document.getElementById(`configfolder-content-${containerId}`);
  if (!content) return;
  content.innerHTML = `<span style="font-family:var(--mono);font-size:13px;">⟳ Loading…</span>`;
  try {
    const params = new URLSearchParams({ name: containerName });
    if (subpath) params.set('subpath', subpath);
    const res = await fetch('/api/container/config-folders?' + params.toString());
    const data = await res.json();
    renderConfigFolderTab(containerName, containerId, data);
  } catch (e) {
    content.innerHTML = `<div style="color:var(--red);font-family:var(--mono);font-size:13px;">⚠ ${esc(e.message)}</div>`;
  }
}

function renderConfigFolderTab(containerName, containerId, data) {
  const content = document.getElementById(`configfolder-content-${containerId}`);
  if (!content) return;
  if (!data || !data.ok) {
    content.innerHTML = `<div style="color:var(--text3);font-family:var(--mono);font-size:13px;">No configuration folder configured for this container.</div>`;
    return;
  }
  const currentPath = String(data.subpath || '');
  const encodedName = encodeURIComponent(containerName);

  const parts = currentPath ? currentPath.split('/').filter(Boolean) : [];
  let breadcrumbBuild = '';
  const breadcrumbItems = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    breadcrumbBuild = breadcrumbBuild ? `${breadcrumbBuild}/${part}` : part;
    if (i > 0) breadcrumbItems.push(`<span style="color:var(--text3);">/</span>`);
    breadcrumbItems.push(`<a href="#" class="folder-breadcrumb-link" onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(breadcrumbBuild)}');return false;">${esc(part)}</a>`);
  }

  const pathRow = `
    <div style="margin-bottom:12px;">
      <div class="cdetail-key" style="margin-bottom:4px;">CONFIGURATION FOLDER BROWSER</div>
      <code style="font-family:var(--mono);font-size:11px;color:#505775;">${esc(data.path)}</code>
      <span class="status-dot ${data.exists ? 'running' : 'exited'}"
        style="width:8px;height:8px;margin-left:8px;vertical-align:middle;display:inline-block;"></span>
      <span style="font-family:var(--mono);font-size:11px;color:${data.exists ? 'var(--green)' : 'var(--red)'};">${data.exists ? 'exists' : 'missing'}</span>
      <div style="margin-top:8px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;color:var(--text2);">
        ${breadcrumbItems.length ? breadcrumbItems.join('') : '<span style="color:var(--text3);">/</span>'}
      </div>
    </div>`;

  if (!data.exists) {
    content.innerHTML = pathRow + `
      <div style="text-align:center;padding:16px 0;">
        <div style="color:var(--text3);font-family:var(--mono);font-size:12px;margin-bottom:14px;">
          No configuration folder found. Create it to store compose and container configuration files.
        </div>
        <button class="list-btn blue"
          onclick="createConfigFolderAt('${encodedName}','${containerId}','',[])"><i data-lucide="folder-plus" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Create Configuration Folder</button>
        <div id="configfolder-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>
      </div>`;
    lucide.createIcons({ nodes: [content] });
    return;
  }

  if (!data.currentExists) {
    const parentPath = getFolderParentPath(currentPath);
    content.innerHTML = pathRow + `
      <div style="padding:14px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;color:var(--text3);font-family:var(--mono);font-size:12px;">
        Current folder does not exist anymore.
        <div style="margin-top:8px;">
          <button class="list-btn blue" onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(parentPath)}')"><i data-lucide="arrow-up" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Up</button>
        </div>
      </div>
      <div id="configfolder-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>`;
    lucide.createIcons({ nodes: [content] });
    return;
  }

  const parentPath = getFolderParentPath(currentPath);
  const controls = `
    <div style="display:flex;align-items:center;gap:8px;margin:10px 0 12px;">
      <button class="list-btn blue" ${currentPath ? '' : 'disabled'} onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(parentPath)}')"><i data-lucide="arrow-up" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Up</button>
      <button class="list-btn blue" onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}')"><i data-lucide="refresh-cw" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Refresh</button>
      <input id="new-config-subfolder-${containerId}" class="filter-input" type="text" placeholder="new folder name"
        style="flex:1;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:6px;
               padding:6px 10px;font-family:var(--mono);font-size:12px;outline:none;"
        onkeydown="if(event.key==='Enter')createConfigFolderAt('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}',[this.value])"/>
      <button class="list-btn blue"
        onclick="createConfigFolderAt('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}',[document.getElementById('new-config-subfolder-${containerId}').value])"><i data-lucide="folder-plus" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Add Folder</button>
    </div>`;

  const rows = (data.entries || []).map(entry => {
    const isDir = entry.type === 'dir';
    const targetPath = joinFolderPath(currentPath, entry.name);
    const nameCellHtml = isDir
      ? `<button style="background:none;border:none;padding:0;margin:0;color:var(--text);font-family:var(--mono);font-size:12px;cursor:pointer;text-align:left;display:flex;align-items:center;gap:6px;" onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')" title="Open folder"><i data-lucide="folder" style="width:14px;height:14px;color:var(--text3);flex-shrink:0;"></i><span style="line-height:14px;">${esc(entry.name)}</span></button>`
      : `<span style="display:flex;align-items:center;gap:6px;"><i data-lucide="file" style="width:14px;height:14px;color:var(--text3);flex-shrink:0;"></i><span style="line-height:14px;">${esc(entry.name)}</span></span>`;
    const openBtn = isDir
      ? `<button class="list-btn blue" onclick="openConfigFolderPath('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="external-link" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Open</button>`
      : '';
    const renameBtn = isDir
      ? `<button class="list-btn blue" onclick="renameConfigFolder('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="pencil" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Rename</button>`
      : '';
    const deleteBtn = isDir
      ? `<button class="list-btn red" onclick="deleteConfigFolder('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="trash-2" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Delete</button>`
      : '';
    const downloadBtn = !isDir
      ? `<button class="list-btn green" onclick="downloadConfigFile('${encodedName}','${encodeURIComponent(targetPath)}')"><i data-lucide="download" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Download</button>`
      : '';
    return `<tr>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px;vertical-align:middle;">${nameCellHtml}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text3);vertical-align:middle;">${isDir ? 'Folder' : 'File'}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);vertical-align:middle;">${isDir ? '–' : fmtBytes(entry.sizeBytes || 0)}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text3);vertical-align:middle;">${entry.modifiedAt ? new Date(entry.modifiedAt).toLocaleString() : '–'}</td>
      <td style="white-space:nowrap;vertical-align:middle;"><div style="display:flex;gap:6px;justify-content:flex-end;align-items:center;">${openBtn}${renameBtn}${deleteBtn}${downloadBtn}</div></td>
    </tr>`;
  }).join('');

  const tableHtml = data.entries && data.entries.length
    ? `<table class="cdetail-table"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th style="text-align:right;">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:10px 0;">Folder is empty</div>`;

  content.innerHTML = pathRow
    + `<div style="color:var(--text3);font-family:var(--mono);font-size:11px;margin-bottom:6px;">Configuration folder browser. Create/Rename/Delete operations apply to folders only.</div>`
    + controls
    + tableHtml
    + `<div id="configfolder-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>`;
  lucide.createIcons({ nodes: [content] });
}

function openConfigFolderPath(encodedName, containerId, encodedSubpath) {
  loadConfigFolderPath(decodeFolderArg(encodedName), containerId, decodeFolderArg(encodedSubpath));
}

function downloadConfigFile(encodedName, encodedFilePath) {
  const containerName = decodeFolderArg(encodedName);
  const filePath = decodeFolderArg(encodedFilePath);
  const params = new URLSearchParams({ name: containerName, filePath });
  const a = document.createElement('a');
  a.href = '/api/container/config-folders/download?' + params.toString();
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function openFolderPath(encodedName, containerId, encodedSubpath) {
  loadFoldersTab(decodeFolderArg(encodedName), containerId, decodeFolderArg(encodedSubpath));
}

function downloadContainerFile(encodedName, encodedFilePath) {
  const containerName = decodeFolderArg(encodedName);
  const filePath = decodeFolderArg(encodedFilePath);
  const params = new URLSearchParams({ name: containerName, filePath });
  const a = document.createElement('a');
  a.href = '/api/container/folders/download?' + params.toString();
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function renderFoldersTab(containerName, containerId, data) {
  const content = document.getElementById(`folders-content-${containerId}`);
  if (!content) return;
  const state = getFolderBrowserState(containerId);
  const currentPath = String(data.subpath || '');
  state.currentPath = currentPath;
  const encodedName = encodeURIComponent(containerName);

  const parts = currentPath ? currentPath.split('/').filter(Boolean) : [];
  let breadcrumbBuild = '';
  const breadcrumbItems = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    breadcrumbBuild = breadcrumbBuild ? `${breadcrumbBuild}/${part}` : part;
    if (i > 0) breadcrumbItems.push(`<span style="color:var(--text3);">/</span>`);
    breadcrumbItems.push(`<a href="#" class="folder-breadcrumb-link" onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(breadcrumbBuild)}');return false;">${esc(part)}</a>`);
  }

  const pathRow = `
    <div style="margin-bottom:12px;">
      <div class="cdetail-key" style="margin-bottom:4px;">DATA FOLDER BROWSER</div>
      <code style="font-family:var(--mono);font-size:11px;color:#505775;">${esc(data.path)}</code>
      <span class="status-dot ${data.exists ? 'running' : 'exited'}"
        style="width:8px;height:8px;margin-left:8px;vertical-align:middle;display:inline-block;"></span>
      <span style="font-family:var(--mono);font-size:11px;color:${data.exists ? 'var(--green)' : 'var(--red)'};">${data.exists ? 'exists' : 'missing'}</span>
      <div style="margin-top:8px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-family:var(--mono);font-size:11px;color:var(--text2);">
        ${breadcrumbItems.length ? breadcrumbItems.join('') : '<span style="color:var(--text3);">/</span>'}
      </div>
    </div>`;

  if (!data.exists) {
    content.innerHTML = pathRow + `
      <div style="text-align:center;padding:16px 0;">
        <div style="color:var(--text3);font-family:var(--mono);font-size:12px;margin-bottom:14px;">
          No data folder found. Create it to resolve missing-volume errors during Compose Up.
        </div>
        <button class="list-btn blue"
          onclick="createDataFolderAt('${encodedName}','${containerId}','',[])"><i data-lucide="folder-plus" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Create Data Folder</button>
        <div id="folders-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>
      </div>`;
    lucide.createIcons({ nodes: [content] });
    return;
  }

  if (!data.currentExists) {
    const parentPath = getFolderParentPath(currentPath);
    content.innerHTML = pathRow + `
      <div style="padding:14px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;color:var(--text3);font-family:var(--mono);font-size:12px;">
        Current folder does not exist anymore.
        <div style="margin-top:8px;">
          <button class="list-btn blue" onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(parentPath)}')"><i data-lucide="arrow-up" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Up</button>
        </div>
      </div>
      <div id="folders-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>`;
    lucide.createIcons({ nodes: [content] });
    return;
  }

  const parentPath = getFolderParentPath(currentPath);
  const controls = `
    <div style="display:flex;align-items:center;gap:8px;margin:10px 0 12px;">
      <button class="list-btn blue" ${currentPath ? '' : 'disabled'} onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(parentPath)}')"><i data-lucide="arrow-up" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Up</button>
      <button class="list-btn blue" onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}')"><i data-lucide="refresh-cw" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Refresh</button>
                  <input id="new-subfolder-${containerId}" class="filter-input" type="text" placeholder="new folder name"
        style="flex:1;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:6px;
               padding:6px 10px;font-family:var(--mono);font-size:12px;outline:none;"
        onkeydown="if(event.key==='Enter')createDataFolderAt('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}',[this.value])"/>
      <button class="list-btn blue"
        onclick="createDataFolderAt('${encodedName}','${containerId}','${encodeURIComponent(currentPath)}',[document.getElementById('new-subfolder-${containerId}').value])"><i data-lucide="folder-plus" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Add Folder</button>
    </div>`;

  const rows = (data.entries || []).map(entry => {
    const isDir = entry.type === 'dir';
    const targetPath = joinFolderPath(currentPath, entry.name);
    const nameCellHtml = isDir
      ? `<button style="background:none;border:none;padding:0;margin:0;color:var(--text);font-family:var(--mono);font-size:12px;cursor:pointer;text-align:left;display:flex;align-items:center;gap:6px;" onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')" title="Open folder"><i data-lucide="folder" style="width:14px;height:14px;color:var(--text3);flex-shrink:0;"></i><span style="line-height:14px;">${esc(entry.name)}</span></button>`
      : `<span style="display:flex;align-items:center;gap:6px;"><i data-lucide="file" style="width:14px;height:14px;color:var(--text3);flex-shrink:0;"></i><span style="line-height:14px;">${esc(entry.name)}</span></span>`;
    const openBtn = isDir
      ? `<button class="list-btn blue" onclick="openFolderPath('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="external-link" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Open</button>`
      : '';
    const renameBtn = isDir
      ? `<button class="list-btn blue" onclick="renameDataFolder('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="pencil" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Rename</button>`
      : '';
    const deleteBtn = isDir
      ? `<button class="list-btn red" onclick="deleteDataFolder('${encodedName}','${containerId}','${encodeURIComponent(targetPath)}')"><i data-lucide="trash-2" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Delete</button>`
      : '';
    const downloadBtn = !isDir
      ? `<button class="list-btn green" onclick="downloadContainerFile('${encodedName}','${encodeURIComponent(targetPath)}')"><i data-lucide="download" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px;"></i>Download</button>`
      : '';
    return `<tr>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px;vertical-align:middle;">${nameCellHtml}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text3);vertical-align:middle;">${isDir ? 'Folder' : 'File'}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2);vertical-align:middle;">${isDir ? '–' : fmtBytes(entry.sizeBytes || 0)}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text3);vertical-align:middle;">${entry.modifiedAt ? new Date(entry.modifiedAt).toLocaleString() : '–'}</td>
      <td style="white-space:nowrap;vertical-align:middle;"><div style="display:flex;gap:6px;justify-content:flex-end;align-items:center;">${openBtn}${renameBtn}${deleteBtn}${downloadBtn}</div></td>
    </tr>`;
  }).join('');

  const tableHtml = data.entries && data.entries.length
    ? `<table class="cdetail-table"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th><th style="text-align:right;">Actions</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div style="color:var(--text3);font-family:var(--mono);font-size:12px;padding:10px 0;">Folder is empty</div>`;

  content.innerHTML = pathRow
    + `<div style="color:var(--text3);font-family:var(--mono);font-size:11px;margin-bottom:6px;">Read-only file browser. Create/Rename/Delete operations apply to folders only.</div>`
    + controls
    + tableHtml
    + `<div id="folders-status-${containerId}" style="font-family:var(--mono);font-size:12px;margin-top:8px;"></div>`;
  lucide.createIcons({ nodes: [content] });
}

async function createDataFolderAt(encodedName, containerId, encodedParentPath, subfolders) {
  const containerName = decodeFolderArg(encodedName);
  const parentPath = decodeFolderArg(encodedParentPath);
  const subNames = (subfolders || []).map(s => String(s || '').trim()).filter(Boolean);
  const statusEl = document.getElementById(`folders-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Creating…'; }
  try {
    const res = await fetch('/api/container/folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, parentPath, subfolders: subNames }),
    });
    const data = await res.json();
    if (data.ok) {
      const msg = data.created.length > 0 ? `✓ Created: ${data.created.join(', ')}` : '✓ Already exists';
      await loadFoldersTab(containerName, containerId, parentPath);
      const fresh = document.getElementById(`folders-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = msg; }
    } else {
      if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + (data.error || 'Failed'); }
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

async function renameDataFolder(encodedName, containerId, encodedFolderPath) {
  const containerName = decodeFolderArg(encodedName);
  const folderPath = decodeFolderArg(encodedFolderPath);
  const currentName = folderPath.split('/').filter(Boolean).pop() || '';
  const nextName = prompt('Rename folder to:', currentName);
  if (!nextName || String(nextName).trim() === currentName) return;
  const statusEl = document.getElementById(`folders-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Renaming…'; }
  try {
    const res = await fetch('/api/container/folders/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, folderPath, newName: String(nextName).trim() }),
    });
    const data = await res.json();
    if (data.ok) {
      const refreshPath = getFolderParentPath(folderPath);
      await loadFoldersTab(containerName, containerId, refreshPath);
      const fresh = document.getElementById(`folders-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = '✓ Folder renamed'; }
    } else if (statusEl) {
      statusEl.style.color = 'var(--red)';
      statusEl.textContent = '✗ ' + (data.error || 'Rename failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

async function deleteDataFolder(encodedName, containerId, encodedFolderPath) {
  const containerName = decodeFolderArg(encodedName);
  const folderPath = decodeFolderArg(encodedFolderPath);
  const folderName = folderPath.split('/').filter(Boolean).pop() || folderPath;
  if (!confirm(`Delete folder "${folderName}" and all nested content?`)) return;
  const statusEl = document.getElementById(`folders-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Deleting…'; }
  try {
    const res = await fetch('/api/container/folders/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, folderPath }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadFoldersTab(containerName, containerId, getFolderParentPath(folderPath));
      const fresh = document.getElementById(`folders-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = '✓ Folder deleted'; }
    } else if (statusEl) {
      statusEl.style.color = 'var(--red)';
      statusEl.textContent = '✗ ' + (data.error || 'Delete failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

async function createConfigFolderAt(encodedName, containerId, encodedParentPath, subfolders) {
  const containerName = decodeFolderArg(encodedName);
  const parentPath = decodeFolderArg(encodedParentPath);
  const subNames = (subfolders || []).map(s => String(s || '').trim()).filter(Boolean);
  const statusEl = document.getElementById(`configfolder-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Creating…'; }
  try {
    const res = await fetch('/api/container/config-folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, parentPath, subfolders: subNames }),
    });
    const data = await res.json();
    if (data.ok) {
      const msg = data.created.length > 0 ? `✓ Created: ${data.created.join(', ')}` : '✓ Already exists';
      await loadConfigFolderPath(containerName, containerId, parentPath);
      const fresh = document.getElementById(`configfolder-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = msg; }
    } else {
      if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + (data.error || 'Failed'); }
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

async function renameConfigFolder(encodedName, containerId, encodedFolderPath) {
  const containerName = decodeFolderArg(encodedName);
  const folderPath = decodeFolderArg(encodedFolderPath);
  const currentName = folderPath.split('/').filter(Boolean).pop() || '';
  const nextName = prompt('Rename folder to:', currentName);
  if (!nextName || String(nextName).trim() === currentName) return;
  const statusEl = document.getElementById(`configfolder-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Renaming…'; }
  try {
    const res = await fetch('/api/container/config-folders/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, folderPath, newName: String(nextName).trim() }),
    });
    const data = await res.json();
    if (data.ok) {
      const refreshPath = getFolderParentPath(folderPath);
      await loadConfigFolderPath(containerName, containerId, refreshPath);
      const fresh = document.getElementById(`configfolder-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = '✓ Folder renamed'; }
    } else if (statusEl) {
      statusEl.style.color = 'var(--red)';
      statusEl.textContent = '✗ ' + (data.error || 'Rename failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

async function deleteConfigFolder(encodedName, containerId, encodedFolderPath) {
  const containerName = decodeFolderArg(encodedName);
  const folderPath = decodeFolderArg(encodedFolderPath);
  const folderName = folderPath.split('/').filter(Boolean).pop() || folderPath;
  if (!confirm(`Delete folder "${folderName}" and all nested content?`)) return;
  const statusEl = document.getElementById(`configfolder-status-${containerId}`);
  if (statusEl) { statusEl.style.color = 'var(--text3)'; statusEl.textContent = 'Deleting…'; }
  try {
    const res = await fetch('/api/container/config-folders/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: containerName, folderPath }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadConfigFolderPath(containerName, containerId, getFolderParentPath(folderPath));
      const fresh = document.getElementById(`configfolder-status-${containerId}`);
      if (fresh) { fresh.style.color = 'var(--green)'; fresh.textContent = '✓ Folder deleted'; }
    } else if (statusEl) {
      statusEl.style.color = 'var(--red)';
      statusEl.textContent = '✗ ' + (data.error || 'Delete failed');
    }
  } catch (e) {
    if (statusEl) { statusEl.style.color = 'var(--red)'; statusEl.textContent = '✗ ' + e.message; }
  }
}

// ─── Restart Policy ───────────────────────────────────────────────────────────
function rpToggleRetries(containerId) {
  const sel     = el(`rp-select-${containerId}`);
  const retries = el(`rp-retries-${containerId}`);
  if (!sel || !retries) return;
  retries.style.display = sel.value === 'on-failure' ? 'block' : 'none';
  el(`rp-status-${containerId}`).textContent = '';
}

async function saveRestartPolicy(containerId) {
  const sel     = el(`rp-select-${containerId}`);
  const retries = el(`rp-retries-${containerId}`);
  const saveBtn = el(`rp-save-${containerId}`);
  const status  = el(`rp-status-${containerId}`);
  if (!sel || !saveBtn || !status) return;

  const policy     = sel.value;
  const maxRetries = policy === 'on-failure' ? (parseInt(retries && retries.value) || 0) : 0;

  saveBtn.disabled = true;
  saveBtn.innerHTML = '<span>…</span>';
  status.style.color = 'var(--text3)';
  status.textContent = 'Applying…';

  try {
    const res  = await fetch(`/api/container/restart-policy/${encodeURIComponent(containerId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy, maxRetries }),
    });
    const data = await res.json();
    if (data.ok) {
      status.style.color = 'var(--green)';
      status.textContent = '✓ Saved';
      setTimeout(() => { if (status) status.textContent = ''; }, 3000);
    } else {
      status.style.color = 'var(--red)';
      status.textContent = '✗ ' + (data.error || 'Failed');
    }
  } catch (e) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ ' + e.message;
  } finally {
    saveBtn.disabled = false;
    saveBtn.innerHTML = '<span>Apply</span>';
  }
}

async function switchCDetailTab(tab) {
  const activeTab = document.querySelector('.cdetail-tab.active')?.dataset?.tab || 'status';
  if (activeTab === 'compose' && tab !== 'compose' && !(await confirmDismissComposeChanges())) return;
  document.querySelectorAll('.cdetail-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.cdetail-tab-panel').forEach(p => {
    p.style.display = p.id === `cdetail-panel-${tab}` ? '' : 'none';
  });
}

async function saveComposeFile(project, composeFile, editorId, saveId, statusId) {
  const ta     = document.getElementById(editorId);
  const saveBtn= document.getElementById(saveId);
  const status = document.getElementById(statusId);
  if (!ta || !saveBtn || !status) return;

  saveBtn.disabled = true;
  saveBtn.innerHTML = '<i data-lucide="loader" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;"></i>Saving…';
  lucide.createIcons({ nodes: [saveBtn] });
  status.style.color = 'var(--text3)';
  status.textContent = '';

  try {
    const res  = await fetch('/api/compose/file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project, composeFile, content: ta.value }),
    });
    const data = await res.json();
    if (data.ok) {
      _composeEditorState.originalValue = ta.value;
      status.style.color = 'var(--green)';
      status.textContent = '✓ Saved';
      saveBtn.style.display = 'none';
      setTimeout(() => { if (status) status.textContent = ''; }, 3000);
    } else {
      status.style.color = 'var(--red)';
      status.textContent = '✗ ' + (data.error || 'Failed');
    }
  } catch (e) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ ' + e.message;
  } finally {
    saveBtn.disabled = false;
    saveBtn.innerHTML = '<i data-lucide="save" style="width:14px;height:14px;vertical-align:-2px;margin-right:4px;"></i>Save';
    lucide.createIcons({ nodes: [saveBtn] });
  }
}

// ─── Archive Browser Modal ────────────────────────────────────────────────────
async function openArchiveBrowserModal() {
  el('archivebrowser-modal').classList.add('open');
  el('archivebrowser-body').innerHTML = '<div class="archivebrowser-empty">Loading…</div>';
  try {
    const res = await fetch('/api/compose/backups');
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Failed to load');
    renderArchiveBrowser(data.backups);
  } catch (e) {
    el('archivebrowser-body').innerHTML = `<div class="archivebrowser-empty" style="color:var(--red)">✗ ${e.message}</div>`;
  }
}

function closeArchiveBrowserModal() {
  el('archivebrowser-modal').classList.remove('open');
}

let _archiveBackups = [];
let _archiveVisibleBackups = [];
let _archiveExpandedIndex = -1;
let _archiveRestoringProject = '';

function renderArchiveBrowser(backups) {
  _archiveBackups = backups || [];
  _archiveExpandedIndex = -1;
  el('archivebrowser-search').value = '';
  el('archivebrowser-count').textContent = `${_archiveBackups.length} project${_archiveBackups.length !== 1 ? 's' : ''}`;
  _renderArchiveList(_archiveBackups);
}

function filterArchiveBrowser(query) {
  const q = query.trim().toLowerCase();
  const filtered = q ? _archiveBackups.filter(p => p.project.toLowerCase().includes(q)) : _archiveBackups;
  el('archivebrowser-count').textContent = q
    ? `${filtered.length} / ${_archiveBackups.length}`
    : `${_archiveBackups.length} project${_archiveBackups.length !== 1 ? 's' : ''}`;
  _renderArchiveList(filtered);
}

function _renderArchiveList(backups) {
  _archiveVisibleBackups = backups || [];
  const body = el('archivebrowser-body');
  if (!_archiveVisibleBackups.length) {
    body.innerHTML = '<div class="archivebrowser-empty">No projects found.</div>';
    return;
  }
  const rows = _archiveVisibleBackups.map((proj, i) => {
    const files = Array.isArray(proj.files) ? proj.files : [];
    const isOpen = i === _archiveExpandedIndex;
    const isRestoring = _archiveRestoringProject === (proj.project || '');
    const dataFiles = Array.isArray(proj.dataFiles) ? proj.dataFiles : [];
    const detailRow = isOpen
      ? `<tr><td colspan="3" style="padding:0;">
          <div class="archivebrowser-file-list">
            <div class="archivebrowser-section-label">Configuration</div>
            ${files.length
              ? files.map(f => `<div class="archivebrowser-file-list-item"><span>📄 ${esc(f.name)}</span><span style="color:var(--text3);font-size:11px;">${f.mtime ? new Date(f.mtime).toLocaleString() : ''}</span></div>`).join('')
              : '<div class="archivebrowser-empty" style="padding:4px 0 8px;text-align:left;">No files</div>'}
            <div class="archivebrowser-section-label" style="margin-top:10px;">Data</div>
            ${dataFiles.length
              ? dataFiles.map(f => `<div class="archivebrowser-file-list-item"><span>${f.isDir ? '📁 ' : ''}${esc(f.name)}</span><span style="color:var(--text3);font-size:11px;">${f.mtime ? new Date(f.mtime).toLocaleString() : ''}</span></div>`).join('')
              : '<div class="archivebrowser-empty" style="padding:4px 0 8px;text-align:left;">No data folder found</div>'}
          </div>
        </td></tr>`
      : '';
    return `<tr>
      <td title="${esc(proj.project || '')}">${esc(proj.project || '(unnamed)')}</td>
      <td class="files-col">${files.length}</td>
      <td class="actions-col"><div class="archivebrowser-actions"><button class="archive-view-btn" onclick="toggleArchiveProject(${i})"><i data-lucide="${isOpen ? 'eye-off' : 'eye'}" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px"></i>${isOpen ? 'Hide' : 'View'}</button><button class="archive-restore-btn" onclick="restoreArchiveProject(${i})" ${isRestoring ? 'disabled' : ''}><i data-lucide="archive-restore" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px"></i>${isRestoring ? 'Restoring…' : 'Restore'}</button><button class="archive-delete-btn" onclick="openArchiveDeleteModal('${esc(proj.project || '')}','${esc(proj.dataPath || '')}')" ${isRestoring ? 'disabled' : ''}><i data-lucide="trash-2" style="width:12px;height:12px;vertical-align:-2px;margin-right:3px"></i>Delete</button></div></td>
    </tr>${detailRow}`;
  }).join('');

  body.innerHTML = `<table class="archivebrowser-table">
    <thead><tr><th>Project</th><th class="files-col">Files</th><th class="actions-col">Details</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
  lucide.createIcons({ nodes: [body] });
}

function toggleArchiveProject(i) {
  _archiveExpandedIndex = (_archiveExpandedIndex === i) ? -1 : i;
  _renderArchiveList(_archiveVisibleBackups);
}

let _archiveProjectToRestore = '';

function openRestoreConfirmModal(project) {
  _archiveProjectToRestore = project;
  el('restore-confirm-project').textContent = project;
  el('restore-confirm-desc').innerHTML = `Restore archive for <strong>${esc(project)}</strong>?<br><br>This moves files from <code style="color:var(--accent)">/volume1/docker/_backups/${esc(project)}/</code> to <code style="color:var(--accent)">/volume1/docker/_config/${esc(project)}/</code>.`;
  el('restore-confirm-modal').classList.add('open');
}

function closeRestoreConfirmModal() {
  el('restore-confirm-modal').classList.remove('open');
  _archiveProjectToRestore = '';
}

async function confirmRestoreProject() {
  const project = _archiveProjectToRestore;
  if (!project) return;
  
  el('restore-confirm-btn').disabled = true;
  el('restore-confirm-btn').textContent = 'Restoring…';
  
  try {
    const res = await fetch('/api/compose/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Restore failed');

    const listRes = await fetch('/api/compose/backups');
    const listData = await listRes.json();
    if (!listData.ok) throw new Error(listData.error || 'Failed to refresh archives');
    renderArchiveBrowser(listData.backups);
    if (typeof refreshContainerMonitoring === 'function') refreshContainerMonitoring();
    showToast(`Restored ${project} to /volume1/docker/_config/${project}/`, 'ok');
    closeRestoreConfirmModal();
  } catch (e) {
    showToast(`Restore failed: ${e.message}`, 'err', 3400);
    closeRestoreConfirmModal();
  }
}

async function restoreArchiveProject(i) {
  const proj = _archiveVisibleBackups[i];
  const project = proj && proj.project ? proj.project : '';
  if (!project) return;
  openRestoreConfirmModal(project);
}

let _archiveProjectToDelete = '';

function openArchiveDeleteModal(project, dataPath) {
  _archiveProjectToDelete = project;
  el('archive-delete-confirm-project').textContent = project;
  el('archive-delete-confirm-desc').innerHTML =
    `<span style="color:var(--red);font-weight:600;">⚠ This cannot be undone.</span><br><br>` +
    `The following will be permanently deleted:<br><br>` +
    `<code style="color:var(--accent);">_backups/${esc(project)}/</code> — archived configuration files<br>` +
    (dataPath ? `<code style="color:var(--accent);">_data/${esc(project)}/</code> — container data folder` : `<span style="color:var(--text3);">No data folder found</span>`);
  el('archive-delete-confirm-modal').classList.add('open');
}

function closeArchiveDeleteModal() {
  el('archive-delete-confirm-modal').classList.remove('open');
  _archiveProjectToDelete = '';
}

async function confirmArchiveDelete() {
  const project = _archiveProjectToDelete;
  if (!project) return;
  el('archive-delete-confirm-btn').disabled = true;
  el('archive-delete-confirm-btn').textContent = 'Deleting…';
  try {
    const res = await fetch('/api/compose/archive/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Delete failed');
    const listRes = await fetch('/api/compose/backups');
    const listData = await listRes.json();
    if (!listData.ok) throw new Error(listData.error || 'Failed to refresh archives');
    renderArchiveBrowser(listData.backups);
    showToast(`Deleted archive for ${project}`, 'ok');
    closeArchiveDeleteModal();
  } catch (e) {
    showToast(`Delete failed: ${e.message}`, 'err', 3400);
    el('archive-delete-confirm-btn').disabled = false;
    el('archive-delete-confirm-btn').textContent = 'Delete permanently';
  }
}

// ─── New Compose Modal ────────────────────────────────────────────────────────
function defaultComposeTemplate() {
  return `services:\n  my-service:\n    container_name: my-service\n    hostname: my-service\n    environment:\n      TZ: Europe/Istanbul\n    volumes:\n      - ../../_data:/data\n    restart: unless-stopped\n    image: my-service:latest\n`;
}

function leadingSpacesCount(line) {
  const m = String(line || '').match(/^ */);
  return m ? m[0].length : 0;
}

function quoteYamlScalar(value) {
  const raw = String(value ?? '');
  if (!raw.length) return '""';
  if (raw.trim() !== raw) return JSON.stringify(raw);
  if (/^(true|false|null|~)$/i.test(raw)) return JSON.stringify(raw);
  if (/^[\[{]|[\]}]$/.test(raw)) return JSON.stringify(raw);
  if (/^[-?:,@`!&*|>%#'"]/.test(raw)) return JSON.stringify(raw);
  if (/:\s/.test(raw) || /\s#/.test(raw) || /,/.test(raw)) return JSON.stringify(raw);
  return raw;
}

function quoteYamlFlowScalar(value) {
  return JSON.stringify(String(value ?? ''));
}

function stripInlineYamlComment(value) {
  return String(value || '').replace(/\s+#.*$/, '').trim();
}

function parseYamlScalar(value) {
  const cleaned = stripInlineYamlComment(value);
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
    return cleaned.slice(1, -1);
  }
  return cleaned;
}

function parseYamlInlineList(value) {
  const raw = stripInlineYamlComment(value);
  if (!raw.startsWith('[') || !raw.endsWith(']')) return [];
  const inner = raw.slice(1, -1).trim();
  if (!inner) return [];

  const items = [];
  let current = '';
  let quote = '';
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (quote) {
      if (ch === quote) {
        quote = '';
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ',') {
      items.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) items.push(current.trim());
  return items.map(item => parseYamlScalar(item)).filter(Boolean);
}

function normalizeComposeImportInput(raw) {
  return String(raw || '')
    .replace(/^```[A-Za-z0-9_-]*\s*/m, '')
    .replace(/\n```\s*$/m, '')
    .trim();
}

function normalizeDockerRunInput(raw) {
  return String(raw || '')
    .replace(/`#.*?`/g, ' ')
    .replace(/\\\r?\n/g, ' ')
    .replace(/[\r\n]+/g, ' ')
    .trim();
}

function tokenizeShellLike(input) {
  const tokens = [];
  let buf = '';
  let quote = '';

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const next = input[i + 1];

    if (quote) {
      if (ch === quote) {
        quote = '';
        continue;
      }
      if (ch === '\\' && quote === '"' && next) {
        buf += next;
        i++;
        continue;
      }
      buf += ch;
      continue;
    }

    if (ch === '\'' || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (buf) {
        tokens.push(buf);
        buf = '';
      }
      continue;
    }
    if (ch === '\\' && next) {
      buf += next;
      i++;
      continue;
    }
    buf += ch;
  }
  if (buf) tokens.push(buf);
  return tokens;
}

function parseDockerRunCommand(rawCommand) {
  const normalized = normalizeDockerRunInput(rawCommand);
  if (!normalized) return { ok: false, error: 'Docker run command is empty.' };

  const tokens = tokenizeShellLike(normalized);
  if (!tokens.length) return { ok: false, error: 'Docker run command is empty.' };

  let i = 0;
  if (tokens[i] === 'docker') i++;
  if (tokens[i] === 'container') i++;
  if (tokens[i] !== 'run') return { ok: false, error: 'Command must start with docker run.' };
  i++;

  const spec = {
    name: '',
    hostname: '',
    image: '',
    restart: '',
    shmSize: '',
    network: '',
    user: '',
    env: [],
    ports: [],
    volumes: [],
    capAdd: [],
    devices: [],
    dns: [],
    health: {
      disabled: false,
      cmd: '',
      interval: '',
      timeout: '',
      retries: '',
      startPeriod: '',
    },
  };

  const readOptionValue = (token, nextIndex) => {
    const eqPos = token.indexOf('=');
    if (eqPos >= 0) return { value: token.slice(eqPos + 1), nextIndex };
    if (nextIndex >= tokens.length) return { error: `Missing value for ${token}` };
    return { value: tokens[nextIndex], nextIndex: nextIndex + 1 };
  };

  while (i < tokens.length) {
    const token = tokens[i];
    if (!token.startsWith('-')) {
      spec.image = token;
      break;
    }

    if (token === '--') {
      i++;
      if (i < tokens.length) spec.image = tokens[i];
      break;
    }

    if (token === '-d' || token === '--detach' || token === '--rm' || token === '-it' || token === '-i' || token === '-t') {
      i++;
      continue;
    }

    if (token === '--name' || token.startsWith('--name=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.name = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--hostname' || token.startsWith('--hostname=') || token === '-h') {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.hostname = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--restart' || token.startsWith('--restart=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.restart = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--network' || token.startsWith('--network=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.network = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--user' || token.startsWith('--user=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.user = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--shm-size' || token.startsWith('--shm-size=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.shmSize = String(out.value || '').replace(/^"|"$/g, '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '-e' || token === '--env' || token.startsWith('--env=') || token.startsWith('-e')) {
      let value = '';
      if (token === '-e' || token === '--env' || token.startsWith('--env=')) {
        const out = readOptionValue(token, i + 1);
        if (out.error) return { ok: false, error: out.error };
        value = String(out.value || '').trim();
        i = out.nextIndex;
      } else {
        value = token.slice(2).trim();
        i++;
      }
      const eq = value.indexOf('=');
      if (eq > 0) {
        spec.env.push({ key: value.slice(0, eq).trim(), value: value.slice(eq + 1) });
      }
      continue;
    }

    if (token === '--cap-add' || token.startsWith('--cap-add=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      const value = String(out.value || '').trim();
      if (value) spec.capAdd.push(value);
      i = out.nextIndex;
      continue;
    }

    if (token === '--device' || token.startsWith('--device=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      const value = String(out.value || '').trim();
      if (value) spec.devices.push(value);
      i = out.nextIndex;
      continue;
    }

    if (token === '--dns' || token.startsWith('--dns=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      const value = String(out.value || '').trim();
      if (value) spec.dns.push(value);
      i = out.nextIndex;
      continue;
    }

    if (token === '-p' || token === '--publish' || token.startsWith('--publish=') || token.startsWith('-p')) {
      let value = '';
      if (token === '-p' || token === '--publish' || token.startsWith('--publish=')) {
        const out = readOptionValue(token, i + 1);
        if (out.error) return { ok: false, error: out.error };
        value = String(out.value || '').trim();
        i = out.nextIndex;
      } else {
        value = token.slice(2).trim();
        i++;
      }
      if (value) spec.ports.push(value);
      continue;
    }

    if (token === '-v' || token === '--volume' || token.startsWith('--volume=') || token.startsWith('-v')) {
      let value = '';
      if (token === '-v' || token === '--volume' || token.startsWith('--volume=')) {
        const out = readOptionValue(token, i + 1);
        if (out.error) return { ok: false, error: out.error };
        value = String(out.value || '').trim();
        i = out.nextIndex;
      } else {
        value = token.slice(2).trim();
        i++;
      }
      if (value) spec.volumes.push(value);
      continue;
    }

    if (token === '--no-healthcheck') {
      spec.health.disabled = true;
      i++;
      continue;
    }

    if (token === '--health-cmd' || token.startsWith('--health-cmd=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.health.cmd = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--health-interval' || token.startsWith('--health-interval=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.health.interval = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--health-timeout' || token.startsWith('--health-timeout=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.health.timeout = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--health-retries' || token.startsWith('--health-retries=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.health.retries = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    if (token === '--health-start-period' || token.startsWith('--health-start-period=')) {
      const out = readOptionValue(token, i + 1);
      if (out.error) return { ok: false, error: out.error };
      spec.health.startPeriod = String(out.value || '').trim();
      i = out.nextIndex;
      continue;
    }

    // Unknown flag: skip it and continue parsing recognized flags.
    i++;
  }

  if (!spec.image) {
    return { ok: false, error: 'Could not detect image name in docker run command.' };
  }

  return { ok: true, spec };
}

function parseComposeImport(rawCompose) {
  const normalized = normalizeComposeImportInput(rawCompose);
  if (!normalized) return { ok: false, error: 'Compose content is empty.' };

  const lines = normalized.split('\n');
  const servicesIdx = lines.findIndex(line => line.trim() === 'services:');
  if (servicesIdx === -1) return { ok: false, error: 'Could not find services: block.' };

  let serviceStart = -1;
  let serviceName = '';
  for (let i = servicesIdx + 1; i < lines.length; i++) {
    if (/^  [A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      serviceStart = i;
      serviceName = lines[i].trim().slice(0, -1);
      break;
    }
  }
  if (serviceStart === -1) return { ok: false, error: 'Could not find a service entry under services:.' };

  let serviceEnd = lines.length;
  for (let i = serviceStart + 1; i < lines.length; i++) {
    if (/^  [A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      serviceEnd = i;
      break;
    }
  }

  const spec = {
    serviceName,
    name: '',
    hostname: '',
    image: '',
    restart: '',
    shmSize: '',
    network: '',
    user: '',
    env: [],
    ports: [],
    volumes: [],
    capAdd: [],
    devices: [],
    dns: [],
    health: {
      disabled: false,
      cmd: '',
      interval: '',
      timeout: '',
      retries: '',
      startPeriod: '',
    },
  };

  let currentSection = '';
  for (let i = serviceStart + 1; i < serviceEnd; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const indent = leadingSpacesCount(line);
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (indent === 4) {
      currentSection = '';
      const match = trimmed.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
      if (!match) continue;
      const [, key, rawValue] = match;
      const value = parseYamlScalar(rawValue);

      if (key === 'image') spec.image = value;
      else if (key === 'container_name') spec.name = value;
      else if (key === 'hostname') spec.hostname = value;
      else if (key === 'restart') spec.restart = value;
      else if (key === 'shm_size') spec.shmSize = value;
      else if (key === 'network_mode') spec.network = value;
      else if (key === 'user') spec.user = value;
      else if (['environment', 'volumes', 'ports', 'cap_add', 'devices', 'dns', 'healthcheck'].includes(key)) {
        currentSection = key;
        if (rawValue.trim().startsWith('[')) {
          const inlineItems = parseYamlInlineList(rawValue);
          if (key === 'environment') {
            for (const item of inlineItems) {
              const eq = item.indexOf('=');
              if (eq > 0) spec.env.push({ key: item.slice(0, eq).trim(), value: item.slice(eq + 1) });
            }
          } else if (key === 'healthcheck') {
            // ignore inline object form for now
          } else {
            const targetKey = key === 'cap_add' ? 'capAdd' : key;
            if (Array.isArray(spec[targetKey])) spec[targetKey].push(...inlineItems);
          }
        }
      }
      continue;
    }

    if (indent <= 4 || !currentSection) continue;

    if (currentSection === 'environment') {
      if (trimmed.startsWith('- ')) {
        const item = parseYamlScalar(trimmed.slice(2));
        const eq = item.indexOf('=');
        if (eq > 0) spec.env.push({ key: item.slice(0, eq).trim(), value: item.slice(eq + 1) });
      } else {
        const match = trimmed.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
        if (match) spec.env.push({ key: match[1].trim(), value: parseYamlScalar(match[2]) });
      }
      continue;
    }

    if (currentSection === 'healthcheck') {
      const match = trimmed.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
      if (!match) continue;
      const [, key, rawValue] = match;
      if (key === 'test') {
        if (/NONE/.test(rawValue)) {
          spec.health.disabled = true;
        } else {
          const items = parseYamlInlineList(rawValue);
          if (items.length >= 2 && items[0] === 'CMD-SHELL') spec.health.cmd = items[1];
          else spec.health.cmd = parseYamlScalar(rawValue);
        }
      } else if (key === 'interval') {
        spec.health.interval = parseYamlScalar(rawValue);
      } else if (key === 'timeout') {
        spec.health.timeout = parseYamlScalar(rawValue);
      } else if (key === 'retries') {
        spec.health.retries = parseYamlScalar(rawValue);
      } else if (key === 'start_period') {
        spec.health.startPeriod = parseYamlScalar(rawValue);
      }
      continue;
    }

    if (trimmed.startsWith('- ')) {
      const item = parseYamlScalar(trimmed.slice(2));
      if (!item) continue;
      if (currentSection === 'volumes') spec.volumes.push(item);
      else if (currentSection === 'ports') spec.ports.push(item);
      else if (currentSection === 'cap_add') spec.capAdd.push(item);
      else if (currentSection === 'devices') spec.devices.push(item);
      else if (currentSection === 'dns') spec.dns.push(item);
    }
  }

  if (!spec.image && !spec.name && !spec.serviceName) {
    return { ok: false, error: 'Could not parse a usable service from the pasted compose content.' };
  }

  return { ok: true, spec };
}

function withPrimaryServiceLines(yaml, mutator) {
  const lines = String(yaml || '').split('\n');
  let servicesIdx = lines.findIndex(line => line.trim() === 'services:');
  if (servicesIdx === -1) {
    lines.unshift('services:', '  my-service:');
    servicesIdx = 0;
  }

  let start = -1;
  for (let i = servicesIdx + 1; i < lines.length; i++) {
    if (/^  [A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start === -1) {
    lines.splice(servicesIdx + 1, 0, '  my-service:');
    start = servicesIdx + 1;
  }

  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  [A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }

  mutator(lines, { start, end });
  return lines.join('\n');
}

function findServiceInsertIndex(lines, block) {
  const { start, end } = block;
  for (let i = start + 1; i < end; i++) {
    if (/^    (restart|image):/.test(lines[i])) return i;
  }
  return end;
}

function upsertServiceScalar(yaml, key, value) {
  if (value === undefined || value === null || String(value).trim() === '') return String(yaml || '');
  return withPrimaryServiceLines(yaml, (lines, block) => {
    const target = `    ${key}:`;
    for (let i = block.start + 1; i < block.end; i++) {
      if (lines[i].startsWith(target)) {
        lines[i] = `${target} ${quoteYamlScalar(String(value).trim())}`;
        return;
      }
    }
    const idx = findServiceInsertIndex(lines, block);
    lines.splice(idx, 0, `${target} ${quoteYamlScalar(String(value).trim())}`);
  });
}

function replaceServiceSection(yaml, sectionName, itemLines) {
  if (!Array.isArray(itemLines) || !itemLines.length) return String(yaml || '');
  return withPrimaryServiceLines(yaml, (lines, block) => {
    const header = `    ${sectionName}:`;
    let sectionStart = -1;
    for (let i = block.start + 1; i < block.end; i++) {
      if (lines[i].trim() === `${sectionName}:` && leadingSpacesCount(lines[i]) === 4) {
        sectionStart = i;
        break;
      }
    }

    if (sectionStart >= 0) {
      let sectionEnd = sectionStart + 1;
      while (sectionEnd < block.end) {
        const line = lines[sectionEnd];
        if (line.trim() && leadingSpacesCount(line) <= 4) break;
        sectionEnd++;
      }
      lines.splice(sectionStart, sectionEnd - sectionStart, header, ...itemLines);
      return;
    }

    const idx = findServiceInsertIndex(lines, block);
    lines.splice(idx, 0, header, ...itemLines);
  });
}

function applyDockerRunSpecToTemplate(template, spec, projectName = '') {
  const targetName = (spec.name || spec.serviceName || projectName || 'my-service').trim();
  let yaml = String(template || defaultComposeTemplate());

  yaml = withPrimaryServiceLines(yaml, (lines, block) => {
    lines[block.start] = `  ${targetName}:`;
  });

  yaml = upsertServiceScalar(yaml, 'container_name', spec.name || targetName);
  yaml = upsertServiceScalar(yaml, 'hostname', spec.hostname || spec.name || spec.serviceName || targetName);
  yaml = upsertServiceScalar(yaml, 'image', spec.image || '');
  yaml = upsertServiceScalar(yaml, 'restart', spec.restart || '');
  yaml = upsertServiceScalar(yaml, 'shm_size', spec.shmSize || '');
  yaml = upsertServiceScalar(yaml, 'network_mode', spec.network || '');
  yaml = upsertServiceScalar(yaml, 'user', spec.user || '');

  if (spec.env && spec.env.length) {
    const envMap = new Map();
    for (const item of spec.env) {
      const k = String(item && item.key || '').trim();
      if (!k) continue;
      envMap.set(k, String(item.value ?? ''));
    }
    const envLines = Array.from(envMap.entries()).map(([k, v]) => `      ${k}: ${quoteYamlScalar(v)}`);
    yaml = replaceServiceSection(yaml, 'environment', envLines);
  }

  if (spec.ports && spec.ports.length) {
    const portLines = spec.ports.map(p => `      - ${quoteYamlScalar(p)}`);
    yaml = replaceServiceSection(yaml, 'ports', portLines);
  }

  if (spec.volumes && spec.volumes.length) {
    const volumeLines = spec.volumes.map(v => `      - ${quoteYamlScalar(v)}`);
    yaml = replaceServiceSection(yaml, 'volumes', volumeLines);
  }

  if (spec.capAdd && spec.capAdd.length) {
    const capLines = Array.from(new Set(spec.capAdd)).map(v => `      - ${quoteYamlScalar(v)}`);
    yaml = replaceServiceSection(yaml, 'cap_add', capLines);
  }

  if (spec.devices && spec.devices.length) {
    const deviceLines = Array.from(new Set(spec.devices)).map(v => `      - ${quoteYamlScalar(v)}`);
    yaml = replaceServiceSection(yaml, 'devices', deviceLines);
  }

  if (spec.dns && spec.dns.length) {
    const dnsLines = Array.from(new Set(spec.dns)).map(v => `      - ${quoteYamlScalar(v)}`);
    yaml = replaceServiceSection(yaml, 'dns', dnsLines);
  }

  if (spec.health && (spec.health.disabled || spec.health.cmd || spec.health.interval || spec.health.timeout || spec.health.retries || spec.health.startPeriod)) {
    const healthLines = [];
    if (spec.health.disabled) {
      healthLines.push('      test: ["NONE"]');
    } else if (spec.health.cmd) {
      healthLines.push(`      test: ["CMD-SHELL", ${quoteYamlFlowScalar(spec.health.cmd)}]`);
    }
    if (spec.health.interval) healthLines.push(`      interval: ${quoteYamlScalar(spec.health.interval)}`);
    if (spec.health.timeout) healthLines.push(`      timeout: ${quoteYamlScalar(spec.health.timeout)}`);
    if (spec.health.retries) {
      const retries = String(spec.health.retries).trim();
      healthLines.push(`      retries: ${/^\d+$/.test(retries) ? retries : quoteYamlScalar(retries)}`);
    }
    if (spec.health.startPeriod) healthLines.push(`      start_period: ${quoteYamlScalar(spec.health.startPeriod)}`);
    if (healthLines.length) yaml = replaceServiceSection(yaml, 'healthcheck', healthLines);
  }

  return yaml;
}

function applyDockerRunToTemplate() {
  const runInput = el('newcompose-run');
  const editor = el('newcompose-editor');
  const nameInput = el('newcompose-name');
  const status = el('newcompose-status');

  const parsed = parseDockerRunCommand(runInput.value);
  if (!parsed.ok) {
    status.style.color = 'var(--red)';
    status.textContent = `✗ ${parsed.error}`;
    runInput.focus();
    return;
  }

  if (!nameInput.value.trim() && parsed.spec.name) {
    nameInput.value = parsed.spec.name;
    updateNewComposePath();
  }

  editor.value = applyDockerRunSpecToTemplate(editor.value, parsed.spec, nameInput.value.trim());
  status.style.color = 'var(--green)';
  status.textContent = '✓ Docker run values applied to template';
}

function applyComposeImportToTemplate() {
  const composeInput = el('newcompose-import');
  const editor = el('newcompose-editor');
  const nameInput = el('newcompose-name');
  const status = el('newcompose-status');

  const parsed = parseComposeImport(composeInput.value);
  if (!parsed.ok) {
    status.style.color = 'var(--red)';
    status.textContent = `✗ ${parsed.error}`;
    composeInput.focus();
    return;
  }

  if (!nameInput.value.trim()) {
    const derivedName = parsed.spec.name || parsed.spec.serviceName || '';
    if (derivedName) {
      nameInput.value = derivedName;
      updateNewComposePath();
    }
  }

  editor.value = applyDockerRunSpecToTemplate(editor.value, parsed.spec, nameInput.value.trim());
  status.style.color = 'var(--green)';
  status.textContent = '✓ Compose values applied to template';
}

async function openNewComposeModal() {
  const modal = el('newcompose-modal');
  el('newcompose-name').value = '';
  el('newcompose-run').value = '';
  el('newcompose-import').value = '';
  el('newcompose-editor').value = defaultComposeTemplate();
  el('newcompose-path-preview').textContent = '';
  el('newcompose-status').textContent = 'Loading template…';
  el('newcompose-status').style.color = 'var(--text3)';
  el('newcompose-save-btn').disabled = false;
  el('newcompose-template-btn').disabled = false;
  modal.classList.add('open');
  setTimeout(() => el('newcompose-name').focus(), 50);

  try {
    const res = await fetch('/api/compose/template');
    const data = await res.json();
    if (data.ok && typeof data.content === 'string') {
      el('newcompose-editor').value = data.content;
      el('newcompose-status').textContent = '';
    } else {
      el('newcompose-status').style.color = 'var(--red)';
      el('newcompose-status').textContent = '✗ ' + (data.error || 'Failed to load template');
    }
  } catch (e) {
    el('newcompose-status').style.color = 'var(--red)';
    el('newcompose-status').textContent = '✗ ' + e.message;
  }
}

function closeNewComposeModal() {
  el('newcompose-modal').classList.remove('open');
}

function updateNewComposePath() {
  const name = el('newcompose-name').value.trim();
  const preview = el('newcompose-path-preview');
  if (name) {
    preview.style.color = 'var(--text3)';
    preview.textContent = `/volume1/docker/_config/${name}/compose.yaml`;
  } else {
    preview.textContent = '';
  }
}

async function saveNewComposeTemplate() {
  const content = el('newcompose-editor').value;
  const btn = el('newcompose-template-btn');
  const status = el('newcompose-status');

  if (!content.trim()) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ Template cannot be empty.';
    return;
  }

  btn.disabled = true;
  status.style.color = 'var(--text3)';
  status.textContent = 'Saving template…';

  try {
    const res = await fetch('/api/compose/template', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    const data = await res.json();
    if (data.ok) {
      status.style.color = 'var(--green)';
      status.textContent = '✓ Template saved';
      setTimeout(() => {
        const s = el('newcompose-status');
        if (s && s.textContent === '✓ Template saved') s.textContent = '';
      }, 2500);
    } else {
      status.style.color = 'var(--red)';
      status.textContent = '✗ ' + (data.error || 'Failed');
    }
  } catch (e) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ ' + e.message;
  } finally {
    btn.disabled = false;
  }
}

async function saveNewCompose() {
  const name    = el('newcompose-name').value.trim();
  const content = el('newcompose-editor').value;
  const saveBtn = el('newcompose-save-btn');
  const status  = el('newcompose-status');

  if (!name) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ Project name is required.';
    el('newcompose-name').focus();
    return;
  }
  if (!content.trim()) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ compose.yaml content is required.';
    el('newcompose-editor').focus();
    return;
  }

  saveBtn.disabled = true;
  status.style.color = 'var(--text3)';
  status.textContent = 'Creating…';

  try {
    const res  = await fetch('/api/compose/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, content }),
    });
    const data = await res.json();
    if (data.ok) {
      closeNewComposeModal();
      if (data.openTarget && data.openTarget.id) {
        openCDetailModal(data.openTarget.id, data.openTarget.name || name, data.openTarget.stateClass || 'configured');
      } else if (typeof refreshContainerMonitoring === 'function') {
        refreshContainerMonitoring();
      }
    } else {
      status.style.color = data.warning ? 'var(--yellow)' : 'var(--red)';
      status.textContent = '✗ ' + (data.error || 'Failed');
      saveBtn.disabled = false;
    }
  } catch (e) {
    status.style.color = 'var(--red)';
    status.textContent = '✗ ' + e.message;
    saveBtn.disabled = false;
  }
}

async function closeCDetailModal() {
  if (!(await confirmDismissComposeChanges())) return;
  resetComposeEditorState();
  el('cdetail-modal').classList.remove('open');
  el('cdetail-actions').innerHTML = '';
}
