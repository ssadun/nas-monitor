# ⛵ NAS Monitor

A real-time system monitoring dashboard for **Synology NAS** (and other Linux-based systems running Docker). Built as a lightweight Node.js app with a fully modular backend — no frameworks, no build step, no Docker required to run it.

![Dashboard Preview](https://img.shields.io/badge/platform-Synology%20NAS-blue) ![Node.js](https://img.shields.io/badge/runtime-Node.js-green) ![License](https://img.shields.io/badge/license-MIT-brightgreen)

---

## ✨ Features

### Core Monitoring
- **Live system metrics** — CPU, memory, load average, uptime, disk usage, and network I/O, streamed via Server-Sent Events every 3 seconds
- **Container monitoring** — per-container CPU %, memory, network in/out, image size, ports, status, and sub-processes with sortable columns
- **System processes** — full process tree with flat/tree view toggle, sortable columns, and per-process detail modal (PID, PPID, user, CPU, memory, command, start time)
- **Disk usage** — mounted volume breakdown with used/free/total bars, expandable filesystem tree browser, and historical usage snapshots (20-snapshot ring buffer)
- **Network utilisation** — per-interface live rx/tx rates with sparkline charts showing Docker bridge networks and attached containers

### Container Management
- **Container actions** — start, stop, restart, delete containers; view live logs (last 200 lines); open interactive WebSocket terminal with xterm.js
- **Container categories** — organise containers into custom labelled groups with emoji icons and colours; collapsible accordion view with aggregated stats
- **Restart policies** — configure container restart policies (no, always, unless-stopped, on-failure)
- **Sub-process view** — expand containers to see child host processes with full process tree hierarchy

### Docker Infrastructure Management
- **Docker volumes** — full CRUD management with three-section detail view (volume details, access control, containers using volume); create volumes with custom labels
- **Docker networks** — manage networks with driver info, scope, subnets; view connected containers; create networks with custom drivers and subnets
- **Resource pruning** — scan and remove unused images, stopped containers, dangling volumes with confirmation and progress tracking; configurable auto-prune schedule

### Security & UI
- **Secure login** — session-based authentication with PBKDF2-SHA512 hashed credentials (100,000 iterations, 32-byte salt); 4-hour session expiry; sessions persisted across restarts
- **Credential management** — change username and password from within the UI with strength indicator and 8-character minimum
- **Audit logging** — all user actions (login, logout, container operations, settings changes) written to `logs/audit.log`
- **Dark UI** — polished dark theme with Inter font; fully responsive design; works on desktop and mobile
- **PWA support** — installable as a Progressive Web App with manifest and service worker

---

## 📋 Requirements

| Requirement | Version |
|---|---|
| Node.js | 16 or later |
| Docker CLI | Any (used via `execFile`) |
| OS | Linux (reads `/proc`); tested on Synology DSM 7 |

No npm packages required for core functionality. The server uses only Node.js built-in modules (`http`, `fs`, `path`, `crypto`, `child_process`).

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ssadun/nas-monitor.git
cd nas-monitor
```

### 2. Set up credentials

Run this once to create a hashed `data/credentials.json` file:

```bash
node -e "
const crypto = require('crypto');
const fs = require('fs');
const username = 'admin';        // change this
const password = 'yourpassword'; // change this
const salt = crypto.randomBytes(32).toString('hex');
const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
fs.writeFileSync('data/credentials.json', JSON.stringify({ username, passwordHash: hash, salt }, null, 2));
console.log('data/credentials.json created');
"
```

Alternatively, pass credentials via environment variables on first launch and they will be automatically migrated to `data/credentials.json`:

```bash
AUTH_USER=admin AUTH_PASS=yourpassword node server.js
```

### 3. Start the server

```bash
node server.js
```

The dashboard is available at **http://your-nas-ip:3232**

### 4. (Optional) Run on a custom port

```bash
PORT=8080 node server.js
```

---

## 🔄 Running as a Service (Synology)

To keep NAS Monitor running after reboots, create a scheduled task in **DSM → Control Panel → Task Scheduler**:

- **Task type:** Triggered task → Boot-up
- **Command:** `node /volume1/system/nas-monitor/server.js`
- **Run as:** root (required to read `/proc` and run Docker commands)

Or use the included service script:

```bash
bash service.sh start   # start the server
bash service.sh stop    # stop the server
bash service.sh status  # check if running
bash service.sh restart # restart the server
```

Or use `nohup` directly:

```bash
nohup node /volume1/system/nas-monitor/server.js > /volume1/system/nas-monitor/logs/nas-monitor.log 2>&1 &
```

---

## 📁 Project Structure

```
nas-monitor/
├── server.js                    # Entry point — HTTP routing, WebSocket console, cache refresh loop
├── modules/                     # Backend modules
│   ├── api.js                   # All HTTP API route handlers
│   ├── auth.js                  # PBKDF2 authentication, session management, login page
│   ├── categories.js            # Container category CRUD and route registration
│   ├── config.js                # PORT, default settings, loadSettings, saveSettings
│   ├── disk.js                  # Disk usage scan, history ring buffer, filesystem monitoring
│   ├── docker.js                # Container/volume/network operations, Compose management
│   ├── header.js                # HTTP response helpers (sendJavaScript, sendFile, sendNotFound)
│   ├── logger.js                # writeLog, logDebug/Info/Warn/Error, auditLog
│   ├── monitor.js               # /proc-based process collection, disk I/O tracking
│   ├── network.js               # Host interface rate tracking, container net namespace reads
│   ├── process.js               # collectSystemSummary — CPU, memory, load, uptime, network
│   └── prune.js                 # scanUnused, runPrune, auto-prune scheduler
├── ui/                          # Frontend JavaScript modules
│   ├── utils.js                 # Formatting helpers, color utilities
│   ├── state.js                 # State vars, SSE/polling, tab switching, sort, filter
│   ├── menu-ui.js               # Sidebar init, tab switching, toggle
│   ├── render.js                # Summary bar, container table, sub-process table, main render
│   ├── processes-ui.js          # Process table (flat/tree), collapse toggle, process detail modal
│   ├── containers-ui.js         # Container detail modal, container actions
│   ├── categories.js            # Category badge, dropdown, tab renderer, manager modal
│   ├── setting.js               # Settings modal
│   ├── disk-ui.js               # Disk Usage tab renderer
│   ├── network-ui.js            # Network Utilization tab + sparklines
│   ├── networks-ui.js           # Network Management tab
│   ├── volumes-ui.js            # Docker Volumes Manager
│   ├── compose-ui.js            # New Compose modal, Archive Browser, Restart Policy
│   ├── prune-ui.js              # Prune modal
│   ├── console-ui.js            # Console modal (xterm.js)
│   └── credentials-ui.js        # Credentials modal
├── index.html                   # Frontend SPA shell — HTML structure and modal templates
├── styles.css                   # All CSS (~2,150 lines) — dark theme, layout, components
├── pwa/                         # Progressive Web App assets
│   ├── manifest.webmanifest     # PWA manifest
│   ├── sw.js                    # Service worker
│   └── pwa-icon.svg             # App icon
├── data/                        # Runtime data (git-ignored)
│   ├── credentials.json         # Hashed login credentials
│   ├── sessions.json            # Persisted sessions (survive restarts)
│   ├── settings.json            # Runtime settings
│   ├── category-defs.json       # Custom container category definitions
│   ├── category-assignments.json# Container → category mappings
│   └── disk-history.json        # Historical disk usage snapshots (20-entry ring buffer)
└── logs/                        # Log files (git-ignored)
    ├── nas-monitor.log          # Server log
    └── audit.log                # User action audit log
```

---

## 🖥️ UI Tabs & Controls

### Container Monitoring (Main Tab)
The primary dashboard view showing all Docker containers as a real-time sortable table:

| Column | Description |
|---|---|
| **Name** | Container name with status indicator dot (green=running, yellow=restarting, red=stopped) |
| **%CPU** | Real-time CPU usage percentage (aggregate of all processes) |
| **%MEM** | Memory usage as percentage of total system RAM |
| **MEM USAGE** | Absolute memory used in bytes |
| **NET IN / OUT** | Per-container network rx/tx via `/proc/<pid>/net/dev` updated every 3s |
| **DISK R/W** | Container disk read/write activity in bytes |
| **IMG SIZE** | Docker image size on disk |
| **NETWORKS** | Docker bridge network(s) the container is attached to |
| **PORTS** | Exposed port mappings; hover or click to view; direct URL links if HTTP |
| **ACTIONS** | Start / Restart / Stop / Logs / Console / Delete buttons with modal dialogs |
| **SUB-PROCESSES** | Expand row to see child host processes with tree hierarchy |
| **CATEGORY** | Current category assignment; click to change |

### Categories
Organize containers into custom groups with aggregated statistics:
- **Custom groups** — Create categories with custom label, emoji icon, and hex color
- **Aggregated stats** — Each category shows aggregate CPU %, memory, network I/O, and total image size
- **Collapsible accordion** — Categories are collapsible; click to expand and see containers as a table
- **Persistence** — Definitions and assignments persist to `data/category-defs.json` and `data/category-assignments.json`

### System Processes
Complete host process monitoring with dual views:
- **Flat view** — Sortable table of all running processes (PID, PPID, User, CPU %, Memory %, Command, Start Time)
- **Tree view** — Parent/child process hierarchy with expandable/collapsible branches
- **Detail modal** — Click any row to open full process details
- **Search/filter** — Live search across process names and PIDs

### Disk Usage
Disk analysis and filesystem browser:
- **Mount list** — All mounted volumes with size bars showing used/free/total breakdown
- **Directory tree** — Expandable tree browser to drill down into directories (hidden until scan is run)
- **Largest files** — Sortable table of the largest files found in the scanned path (hidden until scan is run)
- **Scan history** — Click previous scans to view disk state at different points in time
- **Custom paths** — Configure scan path and depth (1–6 levels) for focused analysis

### Docker Volumes
Full CRUD volume management with three-section detail view:
- Volume details (ID, created date, mount path, driver, labels)
- Access control (ownership UID:GID)
- Containers using the volume (with mount paths and read-only status)

### Docker Networks
Network management with driver configuration:
- List with driver, scope, subnet, and container count
- Detail view with connected containers and their assigned IPs
- Create networks with custom driver, subnet, and gateway

### Network Utilisation
Per-interface network statistics:
- **Live rx/tx rates** — Real-time KB/s per interface with sparkline history charts
- **Attached containers** — Expandable list of containers per interface with their IP and network rates
- **Sort controls** — Sort by interface name, in, out, or total traffic

---

## 🔒 Authentication

Credentials are stored in `data/credentials.json` using **PBKDF2-SHA512** with 100,000 iterations and a 32-byte random salt — never in plain text.

```json
{
  "username": "admin",
  "passwordHash": "a3f8c2...",
  "salt": "e91b44..."
}
```

**Sessions** expire after **4 hours**, are persisted to `data/sessions.json` (survive restarts), and are cleared on logout. All login/logout events are written to `logs/audit.log`.

### Changing credentials

Use the **Credentials** button in the top bar to change username and password from within the UI. The form requires your current password and enforces a minimum 8-character length with a live strength indicator.

---

## 🌐 API Reference

All endpoints require a valid session cookie except `/login`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves `index.html` |
| `GET/POST` | `/login` | Login page and form handler |
| `GET` | `/logout` | Clears session and redirects to login |
| `GET` | `/api/stream` | SSE stream of live system + container data (every 3s) |
| `GET` | `/api/data` | One-shot JSON snapshot of all data |
| `GET` | `/api/disk` | Disk usage scan (directory tree + largest files) |
| `GET` | `/api/disk/history` | List all historical disk scan summaries |
| `GET` | `/api/disk/history/:id` | Fetch a specific historical scan by ID |
| `DELETE` | `/api/disk/history/:id` | Delete a historical disk scan |
| `GET` | `/api/logs/:id` | SSE stream of container logs (tail -f) |
| `GET` | `/api/container/detail/:id` | Full container inspect JSON |
| `POST` | `/api/container/start/:id` | Start a container |
| `POST` | `/api/container/stop/:id` | Stop a container |
| `POST` | `/api/container/restart/:id` | Restart a container |
| `DELETE` | `/api/container/delete/:id` | Remove a container |
| `POST` | `/api/container/restart-policy/:id` | Update restart policy |
| `GET` | `/api/prune/scan` | Scan for reclaimable Docker resources |
| `POST` | `/api/prune/run` | Execute docker system prune |
| `GET` | `/api/prune/log` | SSE stream of prune output |
| `GET` | `/api/settings` | Get current runtime settings |
| `POST` | `/api/settings` | Update runtime settings |
| `GET` | `/api/categories` | Get container → category assignments |
| `POST` | `/api/categories` | Update or purge a category assignment |
| `GET` | `/api/category-defs` | Get category definitions |
| `POST` | `/api/category-defs` | Save category definitions |
| `POST` | `/api/change-credentials` | Change username and password |
| `GET` | `/api/health` | Health check (Docker, credentials, disk, memory) |
| `GET` | `/api/docker/volumes/list` | List all Docker volumes with metadata |
| `GET` | `/api/docker/volumes/detail?name=` | Get detailed info for a specific volume |
| `POST` | `/api/docker/volumes/create` | Create a new Docker volume |
| `POST` | `/api/docker/volumes/delete` | Delete a Docker volume |
| `GET` | `/api/docker/networks/list` | List all Docker networks with metadata |
| `GET` | `/api/docker/networks/detail?name=` | Get detailed info for a specific network |
| `POST` | `/api/docker/networks/create` | Create a new Docker network |
| `POST` | `/api/docker/networks/delete` | Delete a Docker network |
| `WS` | `/ws/console/:id` | WebSocket for interactive container terminal |

---

## ⚙️ How It Works

### Data Collection
The backend collects metrics on every poll cycle (~3 seconds) from two sources:

1. **`/proc` filesystem** — CPU times, memory, load average, uptime, network interface stats, per-process stats (`stat`, `status`, `cmdline`, `io`, `net/dev`)
2. **Docker CLI** — `docker ps`, `docker inspect`, `docker network ls/inspect` via `execFile`

Container network I/O is read from `/proc/<container-pid>/net/dev` on the host, giving access to the container's network namespace without needing `docker stats`.

### Streaming
Live data is pushed to the browser using **Server-Sent Events (SSE)** on `/api/stream`. The frontend keeps a persistent `EventSource` connection and re-renders affected UI sections on each message.

### Terminal
The interactive container console uses **WebSockets** (`/ws/console/:id`), spawning `docker exec -i` with a shell. The frontend renders the terminal with **xterm.js**.

### Frontend Architecture
`index.html` is a lightweight SPA shell (~500 lines of HTML + modals). All JavaScript is split into 16 focused modules under `ui/`, served as separate files. No bundler, no framework — plain JavaScript with DOM manipulation. Lucide icons are loaded from CDN; xterm.js is loaded from cdnjs.

---

## 🛠️ Configuration Reference

| Environment Variable | Default | Description |
|---|---|---|
| `PORT` | `3232` | HTTP server port |
| `AUTH_USER` | *(none)* | Username for first-run credential migration |
| `AUTH_PASS` | *(none)* | Password for first-run credential migration |
| `COMPOSE_CONFIG_ROOT` | *(none)* | Root directory for Compose project discovery |
| `COMPOSE_BACKUP_ROOT` | *(none)* | Backup location for Compose projects |
| `COMPOSE_BOOT_LOG_SECONDS` | `20` | Boot log retention window (seconds) |

> After `data/credentials.json` is created, `AUTH_USER` / `AUTH_PASS` are no longer needed.

---

## 🔧 Troubleshooting

**Containers tab is empty**
- Ensure the process runs as a user with access to `/var/run/docker.sock`
- On Synology, Docker may be at `/var/packages/ContainerManager/target/usr/bin/docker` — the server probes several known paths automatically

**Login doesn't work with `set AUTH_USER=...`**
- `set` is csh/tcsh syntax. Use `export AUTH_USER=admin` in bash, or pass inline: `AUTH_USER=admin AUTH_PASS=pass node server.js`

**Port 3232 already in use**
```bash
PORT=8888 node server.js
```

**Disk tab shows no mounts**
- The server filters out `/sys`, `/proc`, `/dev/shm` mounts. Check `/proc/mounts` if your volumes are on unusual mount points.

**Directory Tree / Largest Files panels not visible**
- These panels are hidden until a disk scan is run. Click **Scan** in the Disk Usage tab to populate them.

---

## 📄 License

MIT — free to use, modify, and distribute.
