# 🐋 NAS Monitor

A real-time system monitoring dashboard for **Synology NAS** (and other Linux-based systems running Docker). Built as a single self-contained Node.js process — no frameworks, no build step, no Docker required to run it.

![Dashboard Preview](https://img.shields.io/badge/platform-Synology%20NAS-blue) ![Node.js](https://img.shields.io/badge/runtime-Node.js-green) ![License](https://img.shields.io/badge/license-MIT-brightgreen)

---

## ✨ Features

### Core Monitoring
- **Live system metrics** — CPU, memory, load average, uptime, disk usage, and network I/O, streamed via Server-Sent Events every 3 seconds
- **Container monitoring** — per-container CPU %, memory, network in/out, image size, ports, status, and sub-processes with sortable columns
- **System processes** — full process tree with flat/tree view toggle, sortable columns, and per-process detail modal (PID, PPID, user, CPU, memory, command, start time)
- **Disk usage** — mounted volume breakdown with used/free/total bars, expandable filesystem tree browser, and historical usage chart (20-snapshot history)
- **Network utilisation** — per-interface live rx/tx rates with sparkline charts showing Docker bridge networks

### Container Management
- **Container actions** — start, stop, restart, delete containers; view live logs (last 200 lines); open interactive WebSocket terminal with xterm.js
- **Container categories** — organise containers into custom labelled groups with emoji icons and colours; collapsible accordion view with aggregated stats
- **Restart policies** — configure container restart policies (no, always, unless-stopped, on-failure)
- **Sub-process view** — expand containers to see child host processes with full process tree hierarchy

### Docker Infrastructure Management
- **Docker volumes** — full CRUD management with three-section detail view (Volume details, Access control, Containers using volume); create volumes with custom labels; view container mount paths
- **Docker networks** — manage networks with driver info, scope, subnets; view connected containers; create networks with custom drivers and subnets
- **Resource pruning** — scan and remove unused images, stopped containers, dangling volumes with confirmation and progress tracking

### Security & UI
- **Secure login** — session-based authentication with PBKDF2-SHA512 hashed credentials (100,000 iterations, 32-byte salt); 4-hour session expiry; in-memory sessions
- **Credential management** — change username and password from within the UI with strength indicator and 8-character minimum
- **Dark UI** — polished dark theme using Space Grotesk font + JetBrains Mono monospace; fully responsive design; works on desktop and mobile

---

## 📋 Requirements

| Requirement | Version |
|---|---|
| Node.js | 16 or later |
| Docker CLI | Any (used via `execFile`) |
| OS | Linux (reads `/proc`); tested on Synology DSM 7 |

No npm packages are required. The server uses only Node.js built-in modules (`http`, `fs`, `path`, `crypto`, `child_process`).

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/youruser/nas-monitor.git
cd nas-monitor
```

### 2. Set up credentials

Run this once to create a hashed `credentials.json` file:

```bash
node -e "
const crypto = require('crypto');
const fs = require('fs');
const username = 'admin';      // change this
const password = 'yourpassword'; // change this
const salt = crypto.randomBytes(32).toString('hex');
const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
fs.writeFileSync('credentials.json', JSON.stringify({ username, passwordHash: hash, salt }, null, 2));
console.log('credentials.json created');
"
```

Alternatively, pass credentials via environment variables on first launch and they will be automatically migrated to `credentials.json`:

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

Or use a simple shell script with `nohup`:

```bash
nohup node /volume1/system/nas-monitor/server.js > /volume1/system/nas-monitor/nas-monitor.log 2>&1 &
```

---

## 📁 Project Structure

```
nas-monitor/
├── server.js                 # Single-file Node.js backend
├── index.html                # Single-file frontend (served by server.js)
├── credentials.json          # Hashed login credentials (auto-created)
├── category-defs.json        # Custom container category definitions
├── category-assignments.json # Container → category mappings
└── disk-history.json         # Historical disk usage snapshots
```

> All data files are created automatically on first run. You only need `server.js` and `index.html` to get started.

---

## 🖥️ UI Tabs & Controls

### 🐋 Container Monitoring (Main Tab)
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

**Toolbar controls:**
- **🐋 Container Monitoring** — Main monitoring tab (always active)
- **🗃️ Categories** — Switch to category view
- **⚙️ System Processes** — View host process tree
- **💾 Disk Usage** — Disk mounts and filesystem browser
- **🌐 Network Utilization** — Per-interface network stats
- **＋ New Compose** — Create a new docker-compose project
- **🗄 Archive** — View archived (stopped) compose projects
- **🧹 Prune** — Scan and remove unused Docker resources with confirmation modal
- **↻ Refresh** — Force immediate refresh of data (normally streams every 3s)
- **Filter…** — Live text filter across all visible container names

### 🗃️ Categories
Organize containers into custom groups with aggregated statistics:

**Features:**
- **Custom groups** — Create categories with custom label, emoji icon, and hex color (pick from palette or enter custom code)
- **Aggregated stats** — Each category shows aggregate CPU %, memory, network I/O, and total image size
- **Collapsible accordion** — Categories are collapsible; click to expand and see containers as a table
- **Assignment shortcuts** — Click container category badge in main tab to quickly change assignment
- **Persistence** — Category definitions and assignments persist to `category-defs.json` and `category-assignments.json`
- **Batch management** — Click **⚙ Manage Categories** to add, edit (label/icon/color), or delete categories

### ⚙️ System Processes
Complete host process monitoring with dual views:

**Features:**
- **Flat view** — Sortable table of all running processes with columns: PID, PPID, User, CPU %, Memory %, Memory (MB), Command, Start Time
- **Tree view** — Parent/child process hierarchy with expandable/collapsible branches showing process relationships
- **Detail modal** — Click any row to open full process details including environment variables, file descriptors, and I/O stats
- **Search/filter** — Live search across process names and PIDs
- **Sorting** — Click column headers to sort by any field (CPU, memory, start time, etc.)

### 💾 Disk Usage
Disk analysis and filesystem browser:

**Features:**
- **Mount list** — All mounted volumes with size bars showing used/free/total breakdown in GB/TB
- **Filesystem tree** — Expandable directory tree browser per mount point to drill down into directories
- **Size breakdown** — Visual percentage bar for each mount
- **Historical chart** — Line chart of disk usage over time (last 20 snapshots, updates every poll cycle)
- **Scan history** — Click previous scans in Scan History panel to view disk state at different times
- **Custom paths** — Configure scan path and depth (1-6 levels) for focused analysis

### 💽 Docker Volumes
Manage Docker volumes with full CRUD:

**List view:**
- **Columns** — Stack, Driver, Mount Point, Ownership (UID:GID), Created Date, Container Count
- **Actions** — Edit (detail view) or Delete buttons per volume
- **Create button** — Launch form to create new volumes

**Detail view (Three sections):**
- **📋 Volume details** — Volume ID, created date, mount path, driver type, and labels table with key-value pairs
- **👁 Access control** — Ownership information in UID:GID format
- **📦 Containers using volume** — Table showing all connected containers, their mount paths, and read-only status

**Operations:**
- **Create** — Form to create new volumes with name, driver selection, and optional custom labels
- **Delete** — Remove volumes with confirmation dialog
- **View metadata** — Full access to volume labels, driver options, and container relationships

### 🔌 Docker Networks
Manage Docker networks with driver configuration:

**List view:**
- **Columns** — Network name, Driver (bridge/overlay/host/macvlan), Scope (local/swarm), IPv4 Subnet, Container Count
- **Actions** — Edit (detail view) or Delete buttons per network
- **Create button** — Launch form to create new networks

**Detail view:**
- **Network metadata** — Name, driver type, scope (local/swarm)
- **Configuration** — Subnet CIDR, gateway, IPv6 support
- **Connected containers** — Table showing all containers attached to the network with their IP address

**Operations:**
- **Create** — Form to create networks with name, driver, optional subnet specification
- **Delete** — Remove networks (must be unused) with confirmation
- **Connection info** — View all attached containers and their assigned IPs

### 🌐 Network Utilisation
Per-interface network statistics:

**Features:**
- **Live rx/tx rates** — Real-time bytes/sec received and transmitted per interface
- **Sparkline charts** — Mini charts showing recent network activity trends
- **Interface list** — All physical + Docker bridge/overlay networks
- **Docker networks** — Displays both interface names and Docker network names

---

## 🔒 Authentication

Credentials are stored in `credentials.json` using **PBKDF2-SHA512** with 100,000 iterations and a 32-byte random salt — never in plain text.

```json
{
  "username": "admin",
  "passwordHash": "a3f8c2...",
  "salt": "e91b44..."
}
```

**Sessions** are in-memory, expire after **4 hours**, and are cleared on logout.

### Changing credentials

Use the **🔑 Credentials** button in the top bar to change your username and password from within the UI. The form requires your current password and enforces a minimum 8-character length for the new password, with a live strength indicator.

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
| `GET` | `/api/disk` | Disk mounts and filesystem tree |
| `GET` | `/api/disk/history` | Historical disk usage array |
| `GET` | `/api/disk/history/:mount` | History for a specific mount point |
| `GET` | `/api/container/detail/:id` | Full container inspect JSON |
| `POST` | `/api/container/start/:id` | Start a container |
| `POST` | `/api/container/stop/:id` | Stop a container |
| `POST` | `/api/container/restart/:id` | Restart a container |
| `DELETE` | `/api/container/delete/:id` | Remove a container |
| `GET` | `/api/logs/:id` | Tail container logs (last 200 lines) |
| `POST` | `/api/container/restart-policy/:id` | Update restart policy |
| `GET` | `/api/prune/scan` | Scan for reclaimable resources |
| `POST` | `/api/prune/run` | Execute docker system prune |
| `GET` | `/api/prune/log` | SSE stream of prune output |
| `GET` | `/api/categories` | Get container → category assignments |
| `POST` | `/api/categories` | Update or purge a category assignment |
| `GET` | `/api/category-defs` | Get category definitions |
| `POST` | `/api/category-defs` | Save category definitions |
| `POST` | `/api/change-credentials` | Change username and password |
| `GET` | `/api/docker/volumes/list` | List all Docker volumes with metadata |
| `GET` | `/api/docker/volumes/detail?name=<volume-name>` | Get detailed info for a specific volume |
| `POST` | `/api/docker/volumes/create` | Create a new Docker volume |
| `POST` | `/api/docker/volumes/delete` | Delete a Docker volume |
| `GET` | `/api/docker/networks/list` | List all Docker networks with metadata |
| `GET` | `/api/docker/networks/detail?name=<network-name>` | Get detailed info for a specific network |
| `POST` | `/api/docker/networks/create` | Create a new Docker network |
| `POST` | `/api/docker/networks/delete` | Delete a Docker network |
| `WS` | `/ws/console/:id` | WebSocket for interactive container terminal |

---

## ⚙️ How It Works

### Data Collection
The backend collects metrics on every poll cycle (~3 seconds) from two sources:

1. **`/proc` filesystem** — CPU times, memory, load average, uptime, network interface stats, per-process stats (stat, status, cmdline, io, net/dev)
2. **Docker CLI** — `docker ps`, `docker stats`, `docker top`, `docker inspect`, `docker network ls/inspect` via `execFile`

Container network I/O is read from `/proc/<container-pid>/net/dev` on the host, which gives access to the container's network namespace without needing `docker stats` for every container.

### Streaming
Live data is pushed to the browser using **Server-Sent Events (SSE)** on `/api/stream`. The frontend keeps a persistent `EventSource` connection and re-renders affected UI sections on each message.

### Terminal
The interactive container console uses **WebSockets** (`/ws/console/:id`) on the server, spawning `docker exec -it` via `node-pty`-style raw PTY. The frontend renders it with **xterm.js**.

### Frontend
`index.html` is a self-contained single-page app (~4000 lines). No bundler, no framework — plain JavaScript with DOM manipulation. Fonts are loaded from Google Fonts CDN; xterm.js is loaded from cdnjs.

---

## 🛠️ Configuration Reference

| Environment Variable | Default | Description |
|---|---|---|
| `PORT` | `3232` | HTTP server port |
| `AUTH_USER` | *(none)* | Username for first-run credential migration |
| `AUTH_PASS` | *(none)* | Password for first-run credential migration |

> After `credentials.json` is created, environment variables are no longer needed.

---

## � Recent Updates

### Latest Changes
- ✅ **Docker Volumes Manager** — Full CRUD with list and three-section detail view (volume details, access control, containers)
- ✅ **Docker Networks Manager** — Manage networks with driver info and container connections
- ✅ **Process Tree View** — Parent/child process hierarchy with expand/collapse functionality
- ✅ **Container Categories** — Group containers with custom labels, icons, and colors with aggregated stats
- ✅ **Disk History Chart** — 20-snapshot historical usage tracking with timeline selection
- ✅ **Real-time Metrics** — SSE stream of live CPU, memory, network, and disk data every 3 seconds
- ✅ **Interactive Terminal** — WebSocket-based xterm.js terminal for container console access

### Technology Stack
- **Backend** — Node.js (no external dependencies, built-in modules only)
- **Frontend** — Vanilla JavaScript, HTML5, CSS3 (no frameworks)
- **Data Transport** — Server-Sent Events (SSE) for live streaming, WebSockets for terminal
- **Storage** — JSON files for persistence (credentials, categories, disk history)
- **Authentication** — PBKDF2-SHA512 with 100K iterations and 32-byte salt

---

## �🔧 Troubleshooting

**Nothing shows up / containers tab is empty**
- Make sure the process runs as a user with access to the Docker socket (`/var/run/docker.sock`)
- On Synology, Docker may be at `/var/packages/ContainerManager/target/usr/bin/docker` — the server probes several known paths automatically

**Login doesn't work with `set AUTH_USER=...`**
- `set` is csh/tcsh syntax. Use `export AUTH_USER=admin` in bash, or pass inline: `AUTH_USER=admin AUTH_PASS=pass node server.js`

**Port 3232 already in use**
```bash
PORT=8888 node server.js
```

**Disk tab shows no mounts**
- The server filters out `/sys`, `/proc`, `/dev/shm` mounts. If your volumes are on unusual mount points, check `/proc/mounts` directly

---

## 📄 License

MIT — free to use, modify, and distribute.
