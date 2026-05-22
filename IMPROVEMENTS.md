# 🚀 NAS Monitor Improvement Roadmap

> This file tracks future improvements to implement. Each item represents a deliberate enhancement to make the monitor more robust, secure, and feature-rich.

## Security & Reliability

- **HTTPS Support**  
  Add optional HTTPS via environment variables (`HTTPS_KEY`, `HTTPS_CERT`) for encrypted access without reverse proxies

- **Rate Limiting**  
  Protect `/login` against brute-force attempts with IP-based rate limiting (e.g. 5 attempts per 15 minutes, then lockout)

- ✅ **Audit Logging**  
  Implemented in `server.js` via `auditLog()` and writing user actions to `logs/audit.log`

- **Log Rotation**  
  Implement automatic log rotation for `nas-monitor.log` to prevent disk space issues; compress old logs and keep 10 latest files

## Features & Monitoring

- **Historical Metrics**  
  Store time-series snapshots in `metrics-history.json` (24h at 5-min intervals) for trending and charts

- **Alerting System**  
  Add configurable alerts for high CPU, low memory, disk full; expose at `/api/alerts` with status indicators

- **Container Health Checks**  
  Display Docker health check status in the container table for services that report their own health

- **Self-Monitoring Endpoint**  
  `/api/monitor/self` - expose the monitor's own CPU/memory/uptime metrics

- **Terminal into Containers**  
  Re-enable WebSocket terminal for interactive container console access with xterm.js

- **Health Check Endpoint** (partial - started)  
  `/api/health` - check Docker availability, credential file existence, disk space, and memory usage

## Error Handling

- **Graceful Shutdown**  
  Handle `SIGTERM` and `SIGINT` signals for clean shutdown (stop collection, close server, save state)

- **Retry Logic for Docker Commands**  
  Add retry with backoff for Docker CLI operations that may fail transiently

## Code Organization

- **Extract Configuration**  
  Move configuration into a separate `config.js` file for better maintainability

- **Modularize server.js**  
  Split `server.js` into focused backend modules served from `modules/`:
  - `api.js` — API routing and REST endpoint handlers
  - `monitor.js` — `/proc`-based process and system statistics collection
  - `disk.js` — disk usage, history ring buffer, filesystem monitoring
  - `network.js` — interface/network statistics collection

  > `auth.js`, `docker.js`, `categories.js`, `header.js` already exist as modules.

- **Modularize index.html frontend (5,470-line inline script)**  
  Extract the inline `<script>` block into external files loaded via `<script src="/modules/...">`.  
  The server already serves `modules/menu.js` and `modules/setting.js` — same pattern.  
  Globals (`allData`, `el()`, `render()`, etc.) stay in `state.js`; modules load in dependency order.

  Proposed split (all in `modules/`):

  | File | ~Lines | Content |
  |---|---|---|
  | `state.js` | 80 | State vars, SSE/polling, tab switching, sort, filter |
  | `render.js` | 400 | Summary bar, container table, process table, main render, helpers |
  | `disk-ui.js` | 335 | Disk Usage tab renderer |
  | `network-ui.js` | 150 | Network Utilization tab + sparklines |
  | `containers-ui.js` | 600 | Container detail modal, depends_on grouping, container actions modal |
  | `compose-ui.js` | 870 | New Compose modal, Archive Browser, Data Folder, Restart Policy |
  | `prune-ui.js` | 290 | Prune modal |
  | `console-ui.js` | 115 | Console modal (xterm.js) |
  | `credentials-ui.js` | 160 | Credentials modal |
  | `volumes-ui.js` | 265 | Docker Volumes Manager tab |
  | `networks-ui.js` | 200 | Network Management tab |

  > `categories.js` already exists for category badge, dropdown, tab renderer, and manager modal.

  CSS (2,150 lines) and HTML modals (795 lines) could later be extracted to `styles.css` and
  partial templates, but require server assembly — lower priority than the JS split.

## Documentation & Packaging

- **API Versioning**  
  Add `/api/v1/` prefix to prevent breaking changes in future releases

- **Docker Compose Example**  
  Create `docker-compose.yml` for those who prefer container-based deployment

- **Synology Package Integration**  
  Create `package_info.json` for DSM Package Center

## User Experience

- **Dark Mode Toggle**  
  Add light theme option with theme preference cookie

- **Keyboard Shortcuts**  
  Add quick access shortcuts (e.g. `f` for filter, `r` for refresh, `l` for logout)

## Synology-Specific

- **DSM Integration**  
  Read Synology temperature sensors from `/sys/class/thermal/` and display CPU temperature

- **Package Center Support**  
  Create SPK package for easy installation via Synology UI

---

> **Status Legend**: 🟢 Not Started | 🟡 In Progress | ✅ Completed
