# Graph Report - /volume1/system/nas-monitor  (2026-06-29)

## Corpus Check
- 53 files · ~68,904 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 729 nodes · 1424 edges · 31 communities (27 shown, 4 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 165 edges (avg confidence: 0.8)
- Token cost: 93,394 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Docker Container Engine|Docker Container Engine]]
- [[_COMMUNITY_Container Detail & Archive UI|Container Detail & Archive UI]]
- [[_COMMUNITY_Compose Template & Folder UI|Compose Template & Folder UI]]
- [[_COMMUNITY_REST API Request Handlers|REST API Request Handlers]]
- [[_COMMUNITY_Network UI & Render Pipeline|Network UI & Render Pipeline]]
- [[_COMMUNITY_Server Entry & Module Wiring|Server Entry & Module Wiring]]
- [[_COMMUNITY_Sidebar Nav & Client State|Sidebar Nav & Client State]]
- [[_COMMUNITY_Authentication & Sessions|Authentication & Sessions]]
- [[_COMMUNITY_Category CRUD|Category CRUD]]
- [[_COMMUNITY_Image Update Checker|Image Update Checker]]
- [[_COMMUNITY_Process UI & Utilities|Process UI & Utilities]]
- [[_COMMUNITY_Project Docs & Architecture|Project Docs & Architecture]]
- [[_COMMUNITY_Dashboard Screenshot Elements|Dashboard Screenshot Elements]]
- [[_COMMUNITY_Docker Prune Scheduler|Docker Prune Scheduler]]
- [[_COMMUNITY_Structured Logging|Structured Logging]]
- [[_COMMUNITY_Process Collection (proc)|Process Collection (/proc)]]
- [[_COMMUNITY_Docker Volumes UI|Docker Volumes UI]]
- [[_COMMUNITY_Settings Panel UI|Settings Panel UI]]
- [[_COMMUNITY_Configuration Schema|Configuration Schema]]
- [[_COMMUNITY_Disk Scan & History|Disk Scan & History]]
- [[_COMMUNITY_Package Manifest|Package Manifest]]
- [[_COMMUNITY_Sidebar Menu UI|Sidebar Menu UI]]
- [[_COMMUNITY_Service Control Script|Service Control Script]]
- [[_COMMUNITY_Network Interface Stats|Network Interface Stats]]
- [[_COMMUNITY_System Summary Collector|System Summary Collector]]
- [[_COMMUNITY_Docker Module Tests|Docker Module Tests]]
- [[_COMMUNITY_HTTP Response Helpers|HTTP Response Helpers]]
- [[_COMMUNITY_PWA App Icon Assets|PWA App Icon Assets]]
- [[_COMMUNITY_Compose Templates|Compose Templates]]
- [[_COMMUNITY_Data Init Script|Data Init Script]]
- [[_COMMUNITY_Service Worker Caching|Service Worker Caching]]

## God Nodes (most connected - your core abstractions)
1. `el()` - 77 edges
2. `handleApi()` - 28 edges
3. `writeJson()` - 26 edges
4. `esc()` - 26 edges
5. `handleApi()` - 24 edges
6. `jsonOk()` - 21 edges
7. `logError()` - 18 edges
8. `getRequestBody()` - 18 edges
9. `renderContainers()` - 17 edges
10. `isPathInsideRoot()` - 14 edges

## Surprising Connections (you probably didn't know these)
- `Modules Compose Template` --semantically_similar_to--> `Root Compose Template`  [INFERRED] [semantically similar]
  modules/compose-template.yaml → compose-template.yaml
- `executeAction()` --calls--> `appendLog()`  [INFERRED]
  ui/render.js → modules/image-updates.js
- `Sidebar Menu Reference Page` --implements--> `Dark Dashboard Design System`  [INFERRED]
  preview/menu.html → CLAUDE.md
- `openNetworkEditForm()` --calls--> `esc()`  [INFERRED]
  ui/networks-ui.js → ui/utils.js
- `closeModal()` --calls--> `el()`  [INFERRED]
  ui/processes-ui.js → ui/utils.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Live Data Collection & Streaming Pipeline** — readme_proc_collection, readme_docker_cli, readme_sse_streaming, claude_md_data_flow [INFERRED 0.85]
- **Design System Reference Pages** — claude_md_design_system, preview_buttons_reference, preview_colors_reference, preview_menu_reference [INFERRED 0.85]

## Communities (31 total, 4 thin omitted)

### Community 0 - "Docker Container Engine"
Cohesion: 0.06
Nodes (92): appSettings, auditLog(), buildComposeSyntheticId(), buildVolumeUsageMap(), collectContainers(), collectDockerVolumes(), COMPOSE_BOOT_LOG_SECONDS, COMPOSE_FILE_CANDIDATES (+84 more)

### Community 1 - "Container Detail & Archive UI"
Cohesion: 0.05
Nodes (70): closeArchiveBrowserModal(), closeArchiveDeleteModal(), closeCDetailModal(), closeRestoreConfirmModal(), confirmArchiveDelete(), confirmRestoreProject(), filterArchiveBrowser(), openArchiveBrowserModal() (+62 more)

### Community 2 - "Compose Template & Folder UI"
Cohesion: 0.07
Nodes (53): applyComposeImportToTemplate(), applyDockerRunSpecToTemplate(), applyDockerRunToTemplate(), _archiveBackups, _archiveVisibleBackups, closeNewComposeModal(), createConfigFolderAt(), createDataFolderAt() (+45 more)

### Community 3 - "REST API Request Handlers"
Cohesion: 0.11
Nodes (49): _appSettings(), _auditLog(), checkDiskSpace(), _diskScanHistory(), { exec, spawn }, execAsync, _formatBytes(), fs (+41 more)

### Community 4 - "Network UI & Render Pipeline"
Cohesion: 0.06
Nodes (36): allNetworks, closeNetworkDeleteModal(), confirmDeleteNetwork(), openNetworkDeleteModal(), openNetworkEditForm(), openNetworkMgr(), renderNetworkMgrList(), saveNetwork() (+28 more)

### Community 5 - "Server Entry & Module Wiring"
Cohesion: 0.05
Nodes (34): api, appSettings, auth, cache, categories, crypto, disk, diskScanHistory (+26 more)

### Community 6 - "Sidebar Nav & Client State"
Cohesion: 0.07
Nodes (29): closeSidebar(), SIDEBAR_TAB_NAMES, switchTab(), switchTabFromSidebar(), toggleSidebar(), updateSidebarToggleLabel(), expandedNetIfaces, netHistory (+21 more)

### Community 7 - "Authentication & Sessions"
Cohesion: 0.11
Nodes (25): appSettings, checkCredentials(), createSession(), CREDENTIALS_FILE, crypto, deleteSession(), fs, getSessionId() (+17 more)

### Community 8 - "Category CRUD"
Cohesion: 0.09
Nodes (19): CAT_ASSIGNMENTS_FILE, CAT_DEFS_FILE, DEFAULT_CAT_DEFS, EMOJI_TO_LUCIDE, fs, loadCatAssignments(), loadCatDefs(), logError() (+11 more)

### Community 9 - "Image Update Checker"
Cohesion: 0.12
Nodes (22): appendLog(), checkImageUpdate(), { execFile, execFileSync }, execFileAsync, fs, getDockerHubToken(), getGhcrToken(), getLocalDigest() (+14 more)

### Community 10 - "Process UI & Utilities"
Cohesion: 0.13
Nodes (15): closeModal(), procRow(), renderProcesses(), setView(), showProcDetail(), showProcDetailFromAttr(), toggleProcCollapse(), getSorted() (+7 more)

### Community 11 - "Project Docs & Architecture"
Cohesion: 0.11
Nodes (22): Button Class Conventions, Cache Refresh + SSE Data Flow, Dependency Injection via setDependencies, Dark Dashboard Design System, Module Icon Mapping, NAS Monitor Project Guide (CLAUDE.md), NAS Monitor Docker Compose Deployment, CDN Dependencies (xterm, Prism, lucide) (+14 more)

### Community 12 - "Dashboard Screenshot Elements"
Cohesion: 0.12
Nodes (20): Per-Row Action Buttons (start/restart/stop/logs), Category Pills (System, Media, Performance, Networking, Utilities), Compose Project Grouping (nested children), Container List Table, Containers Metric (34 / 30 running), Avg CPU Metric with Load Average, Dark High-Contrast Theme, NAS Monitor Main Dashboard (+12 more)

### Community 13 - "Docker Prune Scheduler"
Cohesion: 0.16
Nodes (16): appendPruneLog(), { DEFAULT_SETTINGS }, { exec }, execAsync, fs, getPruneIntervalMs(), getSettings(), logError() (+8 more)

### Community 14 - "Structured Logging"
Cohesion: 0.19
Nodes (15): AUDIT_LOG, auditLog(), formatMeta(), fs, getClientIp(), getSettings(), { LOG_LEVELS }, logDebug() (+7 more)

### Community 15 - "Process Collection (/proc)"
Cohesion: 0.23
Nodes (16): BOOT_TIME, collectProcesses(), fs, getAllPids(), getBootTime(), getCmdline(), getOwner(), getSystemCpuTotal() (+8 more)

### Community 16 - "Docker Volumes UI"
Cohesion: 0.19
Nodes (14): showToast(), allDockerVolumes, createDockerVolume(), deleteDockerVolumeByName(), openDockerVolumeDetail(), openDockerVolumesModal(), refreshDockerVolumesList(), renderDockerVolumesList() (+6 more)

### Community 17 - "Settings Panel UI"
Cohesion: 0.35
Nodes (10): getElement(), hideSettingsMessage(), loadSettingsForm(), parseNumberField(), renderSettingsFolderList(), setSettingsInputValue(), _settingsConfigFolders, _settingsDataFolders (+2 more)

### Community 18 - "Configuration Schema"
Cohesion: 0.24
Nodes (9): DEFAULT_SETTINGS, fs, LEGACY_SETTINGS_FILE, loadSettings(), LOG_LEVELS, normalizeSettings(), path, saveSettingsFile() (+1 more)

### Community 19 - "Disk Scan & History"
Cohesion: 0.27
Nodes (7): collectFiles(), collectUsage(), countSize(), DISK_HISTORY_FILE, fs, path, walkTree()

### Community 20 - "Package Manifest"
Cohesion: 0.20
Nodes (9): author, description, keywords, license, main, name, scripts, test (+1 more)

### Community 21 - "Sidebar Menu UI"
Cohesion: 0.31
Nodes (8): closeSidebar(), SIDEBAR_TAB_NAMES, switchTab(), switchTabFromSidebar(), toggleContainersMenu(), toggleNetworkMenu(), toggleSidebar(), updateSidebarToggleLabel()

### Community 22 - "Service Control Script"
Cohesion: 0.42
Nodes (7): do_restart(), do_start(), do_status(), do_stop(), get_pid(), is_our_server_pid(), service.sh script

### Community 23 - "Network Interface Stats"
Cohesion: 0.32
Nodes (7): collectNetRates(), fs, ifaceToDockerNet, prevContainerNetSnapshot, prevNetSnapshot, readContainerNetDev(), readFile()

### Community 24 - "System Summary Collector"
Cohesion: 0.36
Nodes (6): collectNetRates(), collectSystemSummary(), { exec }, execAsync, { promisify }, readFile()

### Community 25 - "Docker Module Tests"
Cohesion: 0.25
Nodes (7): assert, DEFAULT_DEPS, { describe, test }, dockerModule, fs, os, path

### Community 27 - "PWA App Icon Assets"
Cohesion: 0.40
Nodes (5): PWA Icon 192px PNG, PWA Icon 512px PNG, NAS Monitor PWA App Icon, Dark Background with Blue Accent, Ship Glyph Branding

## Knowledge Gaps
- **180 isolated node(s):** `init-data.sh script`, `fs`, `path`, `{ exec, spawn }`, `{ promisify }` (+175 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `executeAction()` connect `Network UI & Render Pipeline` to `Docker Volumes UI`, `Image Update Checker`, `Container Detail & Archive UI`, `Sidebar Nav & Client State`?**
  _High betweenness centrality (0.406) - this node is a cross-community bridge._
- **Why does `appendLog()` connect `Image Update Checker` to `Network UI & Render Pipeline`?**
  _High betweenness centrality (0.399) - this node is a cross-community bridge._
- **Why does `el()` connect `Container Detail & Archive UI` to `Compose Template & Folder UI`, `Network UI & Render Pipeline`, `Sidebar Nav & Client State`, `Process UI & Utilities`, `Docker Volumes UI`?**
  _High betweenness centrality (0.242) - this node is a cross-community bridge._
- **Are the 75 inferred relationships involving `el()` (e.g. with `applyComposeImportToTemplate()` and `applyDockerRunToTemplate()`) actually correct?**
  _`el()` has 75 INFERRED edges - model-reasoned connections that need verification._
- **Are the 25 inferred relationships involving `esc()` (e.g. with `loadConfigFolderPath()` and `loadConfigFolderTab()`) actually correct?**
  _`esc()` has 25 INFERRED edges - model-reasoned connections that need verification._
- **What connects `init-data.sh script`, `fs`, `path` to the rest of the system?**
  _181 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Docker Container Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.06480117820324006 - nodes in this community are weakly interconnected._