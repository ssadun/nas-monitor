# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the server
node server.js

# Run all tests (Node.js built-in test runner)
npm test
# or: node --test

# Run a single test file
node --test test/docker.test.js

# Run tests matching a name pattern
node --test --test-name-pattern="path safety"
```

No build step required. No linter configured. The app has no runtime npm dependencies.

## Architecture

A Node.js HTTP server that monitors a NAS/Docker host via `/proc` and the Docker CLI, serving a vanilla JS SPA with real-time updates.

### Server-side modules (`modules/`)

**server.js** is the entry point: sets up the HTTP server, the 3-second (configurable) cache refresh loop, WebSocket console, and routes requests to the appropriate handler. It is thin — most logic lives in modules.

**modules/config.js** centralizes all configuration: `PORT`, file paths, `LOG_LEVELS`, settings schema/defaults (`logLevel`, `refreshIntervalSeconds`, `warnThresholdSeconds`), and `loadSettings()`/`saveSettingsFile()`. All other modules import from here.

**modules/api.js** handles the REST API via `handleApi()`. Routes: `/api/data`, `/api/data/refresh`, `/api/stream` (SSE), `/api/disk*`, `/api/logs/*`, `/api/prune/*`, `/api/image-updates/*`, `/api/settings`, `/api/change-credentials`, `/api/network/*`, `/api/health`.

**modules/docker.js** wraps Docker CLI (`execFile`) and handles container/compose routes via `handleApi()`. Routes: `/api/container/log/*`, `/api/container/detail/*`, `/api/container/restart-policy/*`, `/api/container/folders*`, `/api/container/config-folders*`, container action endpoints, `/api/docker/volumes/*`, `/api/compose/*`. Includes path safety validation, YAML parsing, and synthetic compose ID generation.

**modules/categories.js** handles category CRUD via `registerRoutes()`. Routes: `/api/category-defs`, `/api/categories`.

**modules/auth.js** handles PBKDF2-SHA512 password hashing (100K iterations), session creation/validation/expiry (4-hour TTL), and periodic cleanup. Sessions persist to `data/sessions.json`.

**modules/monitor.js** collects process list from `/proc`. **modules/process.js** collects system summary (CPU, memory, uptime). **modules/disk.js** handles disk scan and 20-snapshot ring-buffer history. **modules/network.js** handles network interface stats. **modules/prune.js** runs Docker prune with `scheduleAutoPrune()`. **modules/image-updates.js** checks/pulls image updates with `scheduleImageUpdateCheck()`.

**modules/logger.js** provides structured logging (`logDebug/Info/Warn/Error`, `auditLog`). Log level is runtime-configurable via settings. Audit log writes to `logs/audit.log`.

**modules/header.js** contains HTTP response helpers.

### Dependency injection pattern

All modules receive their dependencies via `setDependencies(deps)` rather than direct imports — this avoids circular dependencies between modules that need each other (e.g., `api.js` needs `disk`, `prune`, `auth`; `server.js` wires them all together).

### Frontend (`ui/`, `index.html`, `styles.css`)

**index.html** is the HTML shell (~934 lines). It loads CDN dependencies (xterm.js, Prism, lucide), then loads all `/ui/*.js` modules, then `/styles.css`. It is read from disk on every request — no restart needed for frontend changes, just refresh.

**styles.css** contains all CSS (~2400 lines). Edit this for styling.

**ui/*.js** contains all frontend JavaScript, split by concern:
- `utils.js` — shared utilities (loaded first, no imports)
- `state.js` — global client state
- `render.js` — data rendering / SSE update handler
- `*-ui.js` — per-feature UI: `processes-ui`, `disk-ui`, `network-ui`, `docker-ui`, `compose-ui`, `console-ui`, `credentials-ui`, `volumes-ui`, `networks-ui`, `image-updates-ui`, `prune-ui`
- `menu.js`, `menu-ui.js` — sidebar navigation
- `setting.js` — settings panel
- `syntax-highlight.js` — YAML/JSON highlighting

### Data flow

1. `setInterval(refreshCache, N * 1000)` runs every N seconds (default 3, configurable in settings), collecting data from `monitor`, `docker`, and `process` modules in parallel.
2. Cache is held in-memory as `{ processes, containers, summary, lastUpdate }`.
3. SSE clients at `/api/stream` receive the cache as a streamed JSON event.
4. Write operations go through REST endpoints; most trigger an immediate `refreshCache()`.

### Persistence

All state in `data/` as JSON (excluded from git): `credentials.json`, `sessions.json`, `settings.json`, `category-defs.json`, `category-assignments.json`, `disk-history.json`.

Logs in `logs/` (excluded from git): `nas-monitor.log`, `audit.log`, `image-updates.log`, `prune.log`.

## Key environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3232` | HTTP listen port |
| `COMPOSE_CONFIG_ROOT` | — | Root directory for compose project discovery |
| `COMPOSE_BACKUP_ROOT` | — | Backup location for compose projects |
| `COMPOSE_BOOT_LOG_SECONDS` | `20` | Boot log retention window |

## Testing

`test/docker.test.js` covers docker module helpers: path safety validation, YAML parsing, synthetic ID generation.  
`test/categories.test.js` covers category CRUD logic including file I/O, dependency injection, and route handlers.  
Both use `node:test` (built-in). No Docker daemon or running server required.

## UI Design

Dark, high-contrast theme. All colors are CSS variables defined in [styles.css](styles.css):

**Before using any color, read `preview/colors.html` to select the correct CSS variable.**

- Backgrounds: `--main-bg` (#0d0f14), `--menu-bg` (#141720), `--card-bg` (#1c2030), `--card-hover-bg` (#242840)
- Borders: `--border` (#2a2f4a), `--border2` (#353b5e)
- Accent: `--accent` (#4f8ef7), `--accent2` (#7c3aed), `--green` (#22c55e), `--yellow` (#eab308), `--red` (#ef4444), `--orange` (#f97316), `--cyan` (#06b6d4), `--pink` (#ec4899), `--lavender` (#8b5cf6), `--white` (#f2ffff)

Typography: `Inter` (Google Fonts) for UI, monospace for data. Base size 15px, labels at 10–12px. Icons via `lucide` (CDN). Terminal via `xterm.js` (CDN).

### Text case conventions

- **Default: Title Case** — all labels, form fields, sidebar items, modal titles, button text, tooltips, and captions
- **UPPER CASE** — page/tab headers and table column headers only

### Button conventions

**Before adding any button, read `preview/buttons.html` to select the correct class.**

Every modal and form must use these shared classes — no inline styles or one-off classes:

- **Green — positive** (save, restore, start, open, download): `class="action-modal-btn ok"` — green tint border/hover
- **Red — negative** (delete, cancel, dismiss): `class="action-modal-btn cancel"` — red tint border/hover
- **Blue — inform** (up, refresh, add folder, open, rename, compose up): `class="folder-nav-btn"` — blue (#477ed9) tint border/hover, matches `cdetail-action-btn apply`
- **Yellow — stop**: `class="cdetail-action-btn stop"` — yellow tint border/hover (container detail modal only)
- **Orange — restart**: `class="cdetail-action-btn restart"` — orange tint border/hover (container detail modal only)
- **Lavender**: `class="action-modal-btn lavender"` — #8b5cf6 tint border/hover
- **White**: `class="action-modal-btn white"` — #f2ffff tint border/hover

### Module icons

Each module has a designated lucide icon. **When changing a module's icon, update ALL occurrences**: sidebar item, modal title(s), and any related log modals.

| Module | Icon | Color | Locations |
|--------|------|-------|-----------|
| New Compose | `file-plus` | green | sidebar |
| Archive Browser | `archive` | orange | sidebar, modal title |
| Categories | `folder-open` | coral | sidebar, modal title |
| Volumes | `hard-drive` | yellow | sidebar, modal title |
| Image Updates | `arrow-up-circle` | lavender | sidebar, modal title, log modal |
| Prune | `archive-x` | red | sidebar, modal title, log modal |
| Networks | `cable` | coral | sidebar, modal title |

## Planned improvements (IMPROVEMENTS.md)

Pending items to be aware of when working on related areas:

- **HTTPS**: optional via `HTTPS_KEY` / `HTTPS_CERT` env vars (not yet implemented)
- **Rate limiting**: brute-force protection on `/login` (not yet implemented)
- **Log rotation**: `nas-monitor.log` has no rotation yet
- **Historical metrics**: time-series snapshots in `metrics-history.json` (not yet implemented)
- **Alerting**: configurable high-CPU / low-memory / disk-full alerts at `/api/alerts` (not yet implemented)
- **Graceful shutdown**: `SIGTERM`/`SIGINT` handling not yet wired up

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
nohup node /volume1/system/nas-monitor/server.js > /volume1/system/nas-monitor/logs/nas-monitor.log 2>&1 &
```

## Troubleshooting

- **Empty containers tab**: process must have access to `/var/run/docker.sock`; on Synology, Docker binary may be at `/var/packages/ContainerManager/target/usr/bin/docker` (server probes known paths automatically)
- **Disk tab shows no mounts**: `/sys`, `/proc`, `/dev/shm` mounts are filtered out by design; check `/proc/mounts` if volumes are on unusual mount points
- **Port conflict**: `PORT=8888 node server.js`
