# 🚀 NAS Monitor Improvement Roadmap

> This file tracks future improvements to implement. Each item represents a deliberate enhancement to make the monitor more robust, secure, and feature-rich.

## Security & Reliability

- 🔴 **HTTPS Support**  
  Add optional HTTPS via environment variables (`HTTPS_KEY`, `HTTPS_CERT`) for encrypted access without reverse proxies

- 🔴 **Rate Limiting**  
  Protect `/login` against brute-force attempts with IP-based rate limiting (e.g. 5 attempts per 15 minutes, then lockout)

- ✅ **Audit Logging**  
  Implemented in `server.js` via `auditLog()` and writing user actions to `logs/audit.log`

- 🔴 **Log Rotation**  
  Implement automatic log rotation for `nas-monitor.log` to prevent disk space issues; compress old logs and keep 10 latest files

- 🔴 **HTTP Access Log (`http.log`)**  
  Dedicated HTTP request log written by the Node server with verbosity controlled by a `LOG_LEVEL` env var:
  - `INFO` — standard logging: method, path, status code, response time
  - `DEBUG` — all of INFO plus request headers, query params, and body size
  - `TRACE` — full access log: everything in DEBUG plus response headers and raw request/response details

## Features & Monitoring

- 🔴 **Historical Metrics**  
  Store time-series snapshots in `metrics-history.json` (24h at 5-min intervals) for trending and charts

- 🔴 **Alerting System**  
  Add configurable alerts for high CPU, low memory, disk full; expose at `/api/alerts` with status indicators

- 🔴 **Container Health Checks**  
  Display Docker health check status in the container table for services that report their own health

- 🔴 **Self-Monitoring Endpoint**  
  `/api/monitor/self` - expose the monitor's own CPU/memory/uptime metrics

- ✅ **Terminal into Containers**  
  WebSocket terminal implemented via xterm.js at `/ws/console/:id`

- 🟡 **Health Check Endpoint** (partial - started)  
  `/api/health` - check Docker availability, credential file existence, disk space, and memory usage

## Error Handling

- 🔴 **Graceful Shutdown**  
  Handle `SIGTERM` and `SIGINT` signals for clean shutdown (stop collection, close server, save state)

- 🔴 **Retry Logic for Docker Commands**  
  Add retry with backoff for Docker CLI operations that may fail transiently

## Code Organization

- ✅ **Extract Configuration**  
  Move configuration into a separate `config.js` file for better maintainability

- ✅ **Modularize server.js**  
  Split `server.js` into focused backend modules under `modules/`.

  | File | Status | Content |
  |---|---|---|
  | `auth.js` | ✅ | PBKDF2 password hashing, session create/validate/expiry, cookie management |
  | `config.js` | ✅ | PORT, DEFAULT_SETTINGS, normalizeSettings, loadSettings, saveSettingsFile |
  | `disk.js` | ✅ | Disk usage scan, history ring buffer, filesystem monitoring |
  | `network.js` | ✅ | Host interface rate tracking, container net namespace reads |
  | `docker.js` | ✅ | Container/volume/network operations, Compose project management |
  | `categories.js` | ✅ | Container category CRUD, route registration |
  | `header.js` | ✅ | HTTP response helpers (sendJavaScript, sendFile, sendNotFound) |
  | `monitor.js` | ✅ | `/proc`-based process collection, disk I/O tracking, `readFile` helper |
  | `process.js` | ✅ | `collectSystemSummary` — CPU, memory, load, uptime, disk, network from `/proc` |
  | `prune.js` | ✅ | scanUnused, runPrune, appendPruneLog, auto-prune scheduler |
  | `logger.js` | ✅ | writeLog, logDebug/Info/Warn/Error, auditLog, getClientIp |
  | `api.js` | ✅ | All HTTP route handlers: data, stream, disk, logs, prune, settings, credentials, networks, health |

- ✅ **Modularize index.html frontend**  
  Extract the inline `<script>` block into external files under `ui/`.

  | File | Status | Content |
  |---|---|---|
  | `utils.js` | ✅ | Formatting helpers, color utilities |
  | `state.js` | ✅ | State vars, SSE/polling, tab switching, sort, filter |
  | `menu-ui.js` | ✅ | Sidebar init, tab switching, toggle |
  | `categories.js` | ✅ | Category badge, dropdown, tab renderer, manager modal |
  | `setting.js` | ✅ | Settings modal |
  | `render.js` | ✅ | Summary bar, container table, sub-process table, main render |
  | `processes-ui.js` | ✅ | Process table (flat/tree), collapse toggle, process detail modal |
  | `disk-ui.js` | ✅ | Disk Usage tab renderer |
  | `network-ui.js` | ✅ | Network Utilization tab + sparklines |
  | `containers-ui.js` | ✅ | Container detail modal, container actions |
  | `compose-ui.js` | ✅ | New Compose modal, Archive Browser, Restart Policy |
  | `prune-ui.js` | ✅ | Prune modal |
  | `console-ui.js` | ✅ | Console modal (xterm.js) |
  | `credentials-ui.js` | ✅ | Credentials modal |
  | `volumes-ui.js` | ✅ | Docker Volumes Manager |
  | `networks-ui.js` | ✅ | Network Management tab |

  CSS (2,150 lines) and HTML modals (795 lines) could later be extracted to `styles.css` and
  partial templates, but require server assembly — lower priority than the JS split.

## Integrations

- 🔴 **Homepage Dashboard Widgets**  
  Expose a widget-compatible API endpoint for [Homepage](https://gethomepage.dev) integration — surface key metrics (CPU, memory, disk, running container count) as a custom widget consumable by Homepage's service widget format

## Documentation & Packaging

- 🔴 **API Versioning**  
  Add `/api/v1/` prefix to prevent breaking changes in future releases

- 🔴 **Docker Compose Example**  
  Create `docker-compose.yml` for those who prefer container-based deployment

- 🔴 **Synology Package Integration**  
  Create `package_info.json` for DSM Package Center

## User Experience

- 🔴 **YAML Syntax Highlighting for New Files**  
  Enable Prism.js YAML syntax highlighting in the New Compose modal (`newcompose-editor` textarea) using the same `initComposeHighlighting()` flow already implemented for the compose editor in container detail

- 🔴 **Button Standardization — Container Detail Folders Tab**  
  Audit and update all buttons in the container detail modal Folders tab to use the shared button classes (`action-modal-btn ok/cancel`, `folder-nav-btn`, etc.) per `preview/buttons.html` — no inline styles or one-off classes

- 🔴 **Standardize App Colors**  
  Audit `styles.css` to consolidate duplicate color values — same HEX used under different variable names or as inline values — into a single canonical CSS variable each. Also remove unused CSS variables and rules identified during the audit.

- 🔴 **Eliminate Unused HTML & JS Code**  
  Audit `index.html` and all `ui/*.js` modules to identify and remove dead code: unreferenced functions, orphaned HTML elements, unused event listeners, and unreachable code paths.

- 🔴 **Dark Mode Toggle**  
  Add light theme option with theme preference cookie

- 🔴 **Keyboard Shortcuts**  
  Add quick access shortcuts (e.g. `f` for filter, `r` for refresh, `l` for logout)

## Synology-Specific

- 🔴 **DSM Integration**  
  Read Synology temperature sensors from `/sys/class/thermal/` and display CPU temperature

- 🔴 **Package Center Support**  
  Create SPK package for easy installation via Synology UI

---

> **Status Legend**: 🔴 Not Started | 🟡 In Progress | ✅ Completed
