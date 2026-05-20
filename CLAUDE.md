# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the server
node server.js

# Run tests (Node.js built-in test runner)
npm test
# or: node --test
```

No build step required. No linter configured. The only npm dependency is `node-pty`.

## Architecture

This is a single-file Node.js HTTP server that monitors a NAS/Docker host via `/proc` and the Docker CLI, serving a vanilla JS SPA with real-time updates.

**server.js** is the entry point and handles all HTTP routing, SSE streaming, and a 3-second data refresh loop. It reads system metrics directly from `/proc` (CPU, memory, processes, disk I/O, network I/O) rather than relying on external tools.

**modules/docker.js** wraps Docker CLI commands (`execFile`) for all container/volume/network operations and Docker Compose project management. It includes path safety validation to prevent traversal attacks, YAML parsing for compose files, and synthetic ID generation for compose services.

**modules/auth.js** handles PBKDF2-SHA512 password hashing (100K iterations), session creation/validation/expiry (4-hour TTL), cookie management, and periodic session cleanup. Sessions are persisted to `data/sessions.json` so they survive restarts.

**index.html** is the entire frontend — a ~8,000-line single file containing all HTML, CSS, and JavaScript. Vanilla JS only; no framework. It connects to `/api/stream` (SSE) for live metric updates every 3 seconds and `/ws/console/:id` (WebSocket + xterm.js) for interactive container terminals.

**modules/menu.js** and **modules/setting.js** are small frontend JS modules served at `/modules/*.js`.

**modules/header.js** contains HTTP response helpers for the server.

### Data flow

1. `setInterval(refreshCache, 3000)` runs every 3s in server.js, collecting process/container/system data in parallel
2. Data is held in an in-memory cache object `{ processes, containers, summary, lastUpdate }`
3. SSE clients connected to `/api/stream` receive the cache as a streamed JSON event
4. Write operations (container actions, settings, categories) go through individual REST endpoints, many of which trigger an immediate cache refresh

### Persistence

All state lives in `data/` as JSON files: `credentials.json`, `sessions.json`, `settings.json`, `category-defs.json`, `category-assignments.json`, `disk-history.json` (20-snapshot ring buffer). These are excluded from git.

### Docker path detection

The server searches 7 known paths to find the Docker binary, supporting both standard Linux and Synology DSM installs.

## Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3232` | HTTP listen port |
| `COMPOSE_CONFIG_ROOT` | — | Root directory for compose project discovery |
| `COMPOSE_BACKUP_ROOT` | — | Backup location for compose projects |
| `COMPOSE_BOOT_LOG_SECONDS` | `20` | Boot log retention window |

## Testing

`test/docker.test.js` uses `node:test` (built-in) and covers docker module helpers: path safety validation, YAML parsing, and synthetic ID generation. Tests are isolated unit tests with no Docker daemon required.

## UI Design

Dark, high-contrast theme. All colors are CSS variables defined in [styles.css](styles.css):

- Backgrounds: `--main-bg` (#0d0f14), `--menu-bg` (#141720), `--card-bg` (#1c2030), `--card-hover-bg` (#242840)
- Borders: `--border` (#2a2f4a), `--border2` (#353b5e)
- Accent: `--blue` (#4f8ef7), `--purple` (#7c3aed), `--green` (#22c55e), `--yellow` (#eab308), `--red` (#ef4444), `--orange` (#f97316), `--cyan` (#06b6d4), `--pink` (#ec4899)

Typography: `Inter` (Google Fonts) for UI, monospace for data. Base size 15px, labels at 10–12px. Icons via `lucide` (CDN). Terminal via `xterm.js` (CDN).

### Button conventions

Every modal and form must use these shared classes — no inline styles or one-off classes:

- **Green — positive** (save, restore, start, open, download): `class="action-modal-btn ok"` — green tint border/hover
- **Red — negative** (delete, cancel, dismiss): `class="action-modal-btn cancel"` — red tint border/hover
- **Blue — inform** (up, refresh, add folder, open, rename, compose up): `class="folder-nav-btn"` — blue (#477ed9) tint border/hover, matches `cdetail-action-btn apply`
- **Yellow — stop**: `class="cdetail-action-btn stop"` — yellow tint border/hover (container detail modal only)
- **Orange — restart**: `class="cdetail-action-btn restart"` — orange tint border/hover (container detail modal only)

## Planned improvements (IMPROVEMENTS.md)

Pending items to be aware of when working on related areas:

- **HTTPS**: optional via `HTTPS_KEY` / `HTTPS_CERT` env vars (not yet implemented)
- **Rate limiting**: brute-force protection on `/login` (not yet implemented)
- **Log rotation**: `nas-monitor.log` has no rotation yet
- **Historical metrics**: time-series snapshots in `metrics-history.json` (not yet implemented)
- **Alerting**: configurable high-CPU / low-memory / disk-full alerts at `/api/alerts` (not yet implemented)
- **Graceful shutdown**: `SIGTERM`/`SIGINT` handling not yet wired up
- **Config extraction**: configuration is inline in `server.js`, not in a separate `config.js`

## Credential setup (first run)

```bash
# Option A: env vars (auto-migrated to data/credentials.json on first start)
AUTH_USER=admin AUTH_PASS=yourpassword node server.js

# Option B: generate credentials.json manually
node -e "
const crypto = require('crypto');
const fs = require('fs');
const salt = crypto.randomBytes(32).toString('hex');
const hash = crypto.pbkdf2Sync('yourpassword', salt, 100000, 64, 'sha512').toString('hex');
fs.writeFileSync('data/credentials.json', JSON.stringify({ username: 'admin', passwordHash: hash, salt }, null, 2));
"
```

## Running as a service (Synology DSM)

In DSM → Control Panel → Task Scheduler, create a triggered task (Boot-up), run as root:

```bash
nohup node /volume1/system/nas-monitor/server.js > /volume1/system/nas-monitor/nas-monitor.log 2>&1 &
```

## Troubleshooting

- **Empty containers tab**: process must have access to `/var/run/docker.sock`; on Synology, Docker binary may be at `/var/packages/ContainerManager/target/usr/bin/docker` (server probes known paths automatically)
- **Disk tab shows no mounts**: `/sys`, `/proc`, `/dev/shm` mounts are filtered out by design; check `/proc/mounts` if volumes are on unusual mount points
- **Port conflict**: `PORT=8888 node server.js`
