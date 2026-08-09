# Graph Report - nas-monitor  (2026-06-29)

## Corpus Check
- 46 files · ~75,483 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1524 nodes · 3246 edges · 83 communities (68 shown, 15 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 174 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `91e69855`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

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
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 82|Community 82]]

## God Nodes (most connected - your core abstractions)
1. `E` - 109 edges
2. `el()` - 79 edges
3. `fire()` - 62 edges
4. `d` - 60 edges
5. `P` - 54 edges
6. `i()` - 43 edges
7. `constructor()` - 42 edges
8. `s()` - 39 edges
9. `c()` - 38 edges
10. `createRow()` - 32 edges

## Surprising Connections (you probably didn't know these)
- `Modules Compose Template` --semantically_similar_to--> `Root Compose Template`  [INFERRED] [semantically similar]
  modules/compose-template.yaml → compose-template.yaml
- `executeAction()` --calls--> `appendLog()`  [INFERRED]
  ui/render.js → modules/image-updates.js
- `index.html SPA Shell` --implements--> `Dark Dashboard Design System`  [INFERRED]
  index.html → CLAUDE.md
- `Sidebar Menu Reference Page` --implements--> `Dark Dashboard Design System`  [INFERRED]
  preview/menu.html → CLAUDE.md
- `openNetworkEditForm()` --calls--> `esc()`  [INFERRED]
  ui/networks-ui.js → ui/utils.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Live Data Collection & Streaming Pipeline** — readme_proc_collection, readme_docker_cli, readme_sse_streaming, claude_md_data_flow [INFERRED 0.85]
- **Design System Reference Pages** — claude_md_design_system, preview_buttons_reference, preview_colors_reference, preview_menu_reference [INFERRED 0.85]

## Communities (83 total, 15 thin omitted)

### Community 0 - "Docker Container Engine"
Cohesion: 0.06
Nodes (95): applyImageUpdate(), appSettings, auditLog(), buildComposeSyntheticId(), buildVolumeUsageMap(), collectContainers(), collectDockerVolumes(), COMPOSE_BOOT_LOG_SECONDS (+87 more)

### Community 1 - "Container Detail & Archive UI"
Cohesion: 0.11
Nodes (32): closeArchiveBrowserModal(), closeNewComposeModal(), rpToggleRetries(), saveComposeFile(), saveNewCompose(), saveNewComposeTemplate(), saveRestartPolicy(), closeConsoleModal() (+24 more)

### Community 2 - "Compose Template & Folder UI"
Cohesion: 0.08
Nodes (52): applyComposeImportToTemplate(), applyDockerRunSpecToTemplate(), applyDockerRunToTemplate(), _archiveBackups, _archiveVisibleBackups, closeArchiveDeleteModal(), closeRestoreConfirmModal(), confirmArchiveDelete() (+44 more)

### Community 3 - "REST API Request Handlers"
Cohesion: 0.11
Nodes (49): _appSettings(), _auditLog(), checkDiskSpace(), _diskScanHistory(), { exec, spawn }, execAsync, _formatBytes(), fs (+41 more)

### Community 4 - "Network UI & Render Pipeline"
Cohesion: 0.09
Nodes (27): openArchiveDeleteModal(), ACTION_META, appendLogLine(), buildDependsOnOrder(), clearLogs(), closeActionModal(), closeLogModal(), executeAction() (+19 more)

### Community 5 - "Server Entry & Module Wiring"
Cohesion: 0.05
Nodes (34): api, appSettings, auth, cache, categories, crypto, disk, diskScanHistory (+26 more)

### Community 6 - "Sidebar Nav & Client State"
Cohesion: 0.05
Nodes (47): closeSidebar(), SIDEBAR_TAB_NAMES, switchTab(), switchTabFromSidebar(), toggleSidebar(), closeSidebar(), SIDEBAR_TAB_NAMES, switchTab() (+39 more)

### Community 7 - "Authentication & Sessions"
Cohesion: 0.11
Nodes (25): appSettings, checkCredentials(), createSession(), CREDENTIALS_FILE, crypto, deleteSession(), fs, getSessionId() (+17 more)

### Community 8 - "Category CRUD"
Cohesion: 0.09
Nodes (19): CAT_ASSIGNMENTS_FILE, CAT_DEFS_FILE, DEFAULT_CAT_DEFS, EMOJI_TO_LUCIDE, fs, loadCatAssignments(), loadCatDefs(), logError() (+11 more)

### Community 9 - "Image Update Checker"
Cohesion: 0.12
Nodes (23): appendLog(), checkImageUpdate(), { execFile, execFileSync }, execFileAsync, fs, getBearerToken(), getDockerHubToken(), getGhcrToken() (+15 more)

### Community 10 - "Process UI & Utilities"
Cohesion: 0.13
Nodes (15): closeModal(), procRow(), renderProcesses(), setView(), showProcDetail(), showProcDetailFromAttr(), toggleProcCollapse(), getSorted() (+7 more)

### Community 11 - "Project Docs & Architecture"
Cohesion: 0.29
Nodes (8): Button Class Conventions, Dependency Injection via setDependencies, Dark Dashboard Design System, Module Icon Mapping, NAS Monitor Project Guide (CLAUDE.md), Button Class Reference Page, Color Variable Reference Page, Sidebar Menu Reference Page

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
Cohesion: 0.23
Nodes (11): allDockerVolumes, createDockerVolume(), openDockerVolumeDetail(), openDockerVolumesModal(), refreshDockerVolumesList(), renderDockerVolumesList(), updateVolBulkButtons(), updateVolSelectAllCheckbox() (+3 more)

### Community 17 - "Settings Panel UI"
Cohesion: 0.03
Nodes (40): activeProtocol(), activeVersion(), _announceCharacters(), b(), _clearLiveRegion(), clearTextureAtlas(), compositionupdate(), _createSelectionElement() (+32 more)

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
Cohesion: 0.10
Nodes (6): _createAccessibilityTreeNode(), _handleBoundaryFocus(), _handleResize(), _mergeRanges(), n(), _refreshRowElements()

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

### Community 31 - "Community 31"
Cohesion: 0.07
Nodes (5): E, markAllDirty(), nextStop(), setgCharset(), setgLevel()

### Community 32 - "Community 32"
Cohesion: 0.11
Nodes (9): clearAllMarkers(), debug(), fillViewportRows(), fire(), _fireOnCanvasResize(), insert(), modifyColors(), resize() (+1 more)

### Community 35 - "Community 35"
Cohesion: 0.12
Nodes (7): getJoinedCharacters(), h(), _reflow(), _reflowLarger(), _reflowLargerAdjustViewport(), _reflowSmaller(), scroll()

### Community 36 - "Community 36"
Cohesion: 0.17
Nodes (6): clearMarkers(), getBlankLine(), getCell(), getNullCell(), markDirty(), markRangeDirty()

### Community 37 - "Community 37"
Cohesion: 0.09
Nodes (3): P, shouldColumnSelect(), triggerDataEvent()

### Community 38 - "Community 38"
Cohesion: 0.13
Nodes (17): addEncoding(), addProtocol(), clear(), constructor(), _getCorrectBufferLength(), handleCharSizeChanged(), handleDevicePixelRatioChange(), _handleOptionsChanged() (+9 more)

### Community 40 - "Community 40"
Cohesion: 0.13
Nodes (3): c(), clearHandler(), registerHandler()

### Community 42 - "Community 42"
Cohesion: 0.10
Nodes (18): Architecture, Button conventions, Commands, Credential setup (first run), Data flow, Dependency injection pattern, Frontend (`ui/`, `index.html`, `styles.css`), graphify (+10 more)

### Community 43 - "Community 43"
Cohesion: 0.14
Nodes (18): closeCDetailModal(), switchCDetailTab(), buildCacheRows(), closeComposeDismissModal(), closePruneLogModal(), closePruneModal(), _composeEditorState, confirmDismissComposeChanges() (+10 more)

### Community 44 - "Community 44"
Cohesion: 0.10
Nodes (7): addRefreshCallback(), attachToDom(), L(), _queueRefresh(), register(), _registerDecorationListeners(), _registerDimensionChangeListeners()

### Community 45 - "Community 45"
Cohesion: 0.13
Nodes (13): clearSelection(), deregister(), disable(), _dragScroll(), _fireEventIfSelectionChanged(), _fireOnSelectionChange(), handleTrim(), _refreshRows() (+5 more)

### Community 46 - "Community 46"
Cohesion: 0.22
Nodes (15): deleteSelectedDiskScan(), diskCollapsed, diskFileSort, diskHistory, expandAllNodes(), loadHistoryScan(), renderDiskFiles(), renderDiskHistory() (+7 more)

### Community 47 - "Community 47"
Cohesion: 0.15
Nodes (15): _addMouseDownListeners(), _areCoordsInSelection(), _getMouseBufferCoords(), getWrappedRangeForLine(), _handleDoubleClick(), _handleIncrementalClick(), _handleMouseDown(), _handleSingleClick() (+7 more)

### Community 48 - "Community 48"
Cohesion: 0.15
Nodes (17): areSelectionValuesReversed(), _clearCurrentLink(), _createLinkUnderlineEvent(), finalSelectionEnd(), finalSelectionStart(), _fireUnderlineEvent(), getCoords(), _getMouseEventScrollAmount() (+9 more)

### Community 49 - "Community 49"
Cohesion: 0.11
Nodes (17): addLineToLink(), addMarker(), _askForLink(), _batchedMemoryCleanup(), _checkLinkProviderResult(), getBufferElements(), _getEntryIdKey(), getLinkData() (+9 more)

### Community 50 - "Community 50"
Cohesion: 0.13
Nodes (12): clearListeners(), delete(), dispose(), f(), forEachByKey(), getKeyIterator(), _handleBufferActivate(), _removeDecoration() (+4 more)

### Community 52 - "Community 52"
Cohesion: 0.12
Nodes (12): loadDockerfileTab(), renderDockerfileTab(), loadContainerImageUpdate(), openCDetailModal(), triggerContainerImageUpdate(), getContainerStateClass(), _dockerfileEditorState, initComposeHighlighting() (+4 more)

### Community 53 - "Community 53"
Cohesion: 0.15
Nodes (3): addOscHandler(), registerOscHandler(), setHandlerFallback()

### Community 54 - "Community 54"
Cohesion: 0.33
Nodes (6): error(), _evalLazyOptionalParams(), _getJoinedRanges(), info(), _log(), trace()

### Community 56 - "Community 56"
Cohesion: 0.15
Nodes (12): 🌐 API Reference, 🔒 Authentication, Changing credentials, 🛠️ Configuration Reference, Docker CLI via execFile, 📄 License, 🐋 NAS Monitor, PBKDF2-SHA512 Authentication (+4 more)

### Community 57 - "Community 57"
Cohesion: 0.23
Nodes (10): allNetworks, closeNetworkDeleteModal(), confirmDeleteNetwork(), openNetworkDeleteModal(), openNetworkEditForm(), openNetworkMgr(), renderNetworkMgrList(), saveNetwork() (+2 more)

### Community 58 - "Community 58"
Cohesion: 0.18
Nodes (11): addDecoration(), _addLineToZone(), _lineAdjacentToZone(), _lineIntersectsZone(), _refreshCanvasDimensions(), _refreshColorZonePadding(), _refreshDecorations(), _refreshDrawConstants() (+3 more)

### Community 59 - "Community 59"
Cohesion: 0.19
Nodes (8): clearRange(), decode(), end(), hook(), put(), reset(), _start(), unhook()

### Community 60 - "Community 60"
Cohesion: 0.14
Nodes (5): createInstance(), enable(), event(), hasRenderer(), setService()

### Community 62 - "Community 62"
Cohesion: 0.29
Nodes (10): _applyScrollModifier(), _bubbleScroll(), _clearSmoothScrollState(), getLinesScrolled(), _getPixelsScrolled(), handleTouchMove(), handleWheel(), scrollLines() (+2 more)

### Community 63 - "Community 63"
Cohesion: 0.22
Nodes (9): Categories, Container Monitoring (Main Tab), Disk Usage, Docker Compose Editor, Docker Networks, Docker Volumes, Network Utilisation, System Processes (+1 more)

### Community 64 - "Community 64"
Cohesion: 0.22
Nodes (3): addEscHandler(), registerEscHandler(), values()

### Community 65 - "Community 65"
Cohesion: 0.28
Nodes (3): a(), compositionstart(), handleFocus()

### Community 66 - "Community 66"
Cohesion: 0.20
Nodes (4): _cancelCallback(), r(), _requestCallback(), warn()

### Community 67 - "Community 67"
Cohesion: 0.20
Nodes (9): Context, CSS architecture, Current-state map (what each area needs), Decisions, Mobile View Support — Design & Implementation Plan, Phase 1 — Make it usable (minimal, CSS-mostly), Phase 2 — Full responsive polish (Home-Ledger parity), Risks / flags (+1 more)

### Community 68 - "Community 68"
Cohesion: 0.40
Nodes (6): Cache Refresh + SSE Data Flow, NAS Monitor Docker Compose Deployment, Container Net Namespace Read (/proc/<pid>/net/dev), /proc Filesystem Data Collection, Server-Sent Events Streaming, Pending Feature TODOs

### Community 69 - "Community 69"
Cohesion: 0.33
Nodes (6): Container Management, Core Monitoring, Docker Compose, Docker Infrastructure Management, ✨ Features, Security & UI

### Community 71 - "Community 71"
Cohesion: 0.40
Nodes (5): 1. Clone the repository, 2. Set up credentials, 3. Start the server, 4. (Optional) Run on a custom port, 🚀 Quick Start

### Community 72 - "Community 72"
Cohesion: 0.40
Nodes (5): Data Collection, Frontend Architecture, ⚙️ How It Works, Streaming, Terminal

### Community 74 - "Community 74"
Cohesion: 0.50
Nodes (4): _createElement(), _doRefreshDecorations(), _refreshXPosition(), _renderDecoration()

### Community 75 - "Community 75"
Cohesion: 0.50
Nodes (4): CDN Dependencies (xterm, Prism, lucide), index.html SPA Shell, PWA Support (manifest + service worker), WebSocket Container Terminal

### Community 78 - "Community 78"
Cohesion: 0.33
Nodes (4): _convertViewportColToCharacterIndex(), _getWordAt(), _isCharWordSeparator(), _stringRangesToCellRanges()

### Community 79 - "Community 79"
Cohesion: 0.40
Nodes (5): _addStyle(), _applyMinimumContrast(), getColor(), _getContrastCache(), setColor()

### Community 80 - "Community 80"
Cohesion: 0.50
Nodes (4): compositionend(), _finalizeComposition(), _handleAnyTextareaChanges(), keydown()

## Knowledge Gaps
- **233 isolated node(s):** `init-data.sh script`, `fs`, `path`, `{ exec, spawn }`, `{ promisify }` (+228 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **15 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `executeAction()` connect `Network UI & Render Pipeline` to `Container Detail & Archive UI`, `Sidebar Nav & Client State`, `Image Update Checker`, `Community 43`, `Community 52`, `Community 57`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `appendLog()` connect `Image Update Checker` to `Network UI & Render Pipeline`?**
  _High betweenness centrality (0.097) - this node is a cross-community bridge._
- **Why does `el()` connect `Container Detail & Archive UI` to `Compose Template & Folder UI`, `Network UI & Render Pipeline`, `Sidebar Nav & Client State`, `Process UI & Utilities`, `Community 43`, `Community 46`, `Community 52`, `Community 57`?**
  _High betweenness centrality (0.062) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `E` (e.g. with `modifyColors()` and `.forEach()`) actually correct?**
  _`E` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 77 inferred relationships involving `el()` (e.g. with `applyComposeImportToTemplate()` and `applyDockerRunToTemplate()`) actually correct?**
  _`el()` has 77 INFERRED edges - model-reasoned connections that need verification._
- **What connects `init-data.sh script`, `fs`, `path` to the rest of the system?**
  _234 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Docker Container Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.06297029702970297 - nodes in this community are weakly interconnected._