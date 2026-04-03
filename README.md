# 🐋 NAS Monitor

A real-time system monitoring dashboard for **Synology NAS** (and other Linux-based systems running Docker). Built as a single self-contained Node.js process — no frameworks, no build step, no Docker required to run it.

![Dashboard Preview](https://img.shields.io/badge/platform-Synology%20NAS-blue) ![Node.js](https://img.shields.io/badge/runtime-Node.js-green) ![License](https://img.shields.io/badge/license-MIT-brightgreen)

---

## ✨ Features

- **Live system metrics** — CPU, memory, load average, uptime, disk usage, and network I/O, streamed via Server-Sent Events every 3 seconds
- **Container monitoring** — per-container CPU %, memory, network in/out, image size, ports, status, and sub-processes
- **Container actions** — start, stop, restart, delete containers; view logs; open an interactive terminal (xterm.js)
- **Container categories** — organise containers into custom labelled groups with icons and colours; collapsible accordion view with aggregate stats
- **System processes** — full process tree with flat/tree view toggle, sortable columns, and per-process detail modal
- **Disk usage** — mounted volume breakdown with a history chart and filesystem tree browser
- **Network utilisation** — per-interface real-time rx/tx rates with a live sparkline chart
- **Secure login** — session-based authentication with PBKDF2-SHA512 hashed credentials stored in a local file
- **Dark UI** — polished dark theme using Space Grotesk + JetBrains Mono; fully responsive

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

## 🖥️ UI Tabs

### 🐋 Container Monitoring
The main view. Shows all Docker containers as a sortable table with live metrics:

| Column | Description |
|---|---|
| Name | Container name with status indicator dot |
| %CPU | Real-time CPU usage percentage |
| %MEM | Memory usage as % of total system RAM |
| MEM USAGE | Absolute memory used |
| NET IN / OUT | Per-container network rx/tx via `/proc/<pid>/net/dev` |
| DISK R/W | Container disk read/write activity |
| IMG SIZE | Docker image size on disk |
| NETWORKS | Docker network(s) the container is attached to |
| PORTS | Exposed port mappings (clickable links) |
| ACTIONS | Start / Restart / Stop / Logs / Console / Delete |
| SUB-PROCESSES | Expand to see host processes belonging to the container |
| CATEGORY | Assign or change the container's category |

**Toolbar controls:**
- **Expand All / Collapse All** — toggle sub-process rows for all containers
- **Prune** — scan for and remove unused images, stopped containers, and dangling volumes
- **Filter** — live text filter across container names

### 🗃️ Categories
Organise containers into custom groups. Each category shows aggregated CPU, memory, network, and image size stats. Sections are collapsible; containers appear as a table when expanded.

- Click **⚙ Manage Categories** to add, edit, or delete categories
- Each category has a custom label, emoji icon, and colour (choose from palette or enter any hex code)
- Assign containers via the category badge in the Container Monitoring tab
- Categories and assignments persist across restarts in `category-defs.json` and `category-assignments.json`

### ⚙️ System Processes
All running host processes with:
- **Flat view** — sortable table of all processes
- **Tree view** — parent/child hierarchy with collapsible branches
- Click any row for a full detail modal (PID, PPID, user, CPU, memory, command, start time, etc.)

### 💾 Disk Usage
- All mounted volumes with used/free/total breakdown and usage bar
- Expandable filesystem tree browser per mount point
- Historical usage chart (last 20 snapshots, sampled every poll cycle)

### 🌐 Network Utilisation
- Per-interface live rx/tx rates
- Sparkline chart for each interface
- Shows Docker bridge network names alongside host interface names

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

## 🔧 Troubleshooting

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
