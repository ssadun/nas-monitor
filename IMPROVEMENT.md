# 🚀 NAS Monitor Improvement Roadmap

> This file tracks future improvements to implement. Each item represents a deliberate enhancement to make the monitor more robust, secure, and feature-rich.

## Security & Reliability

- **HTTPS Support**  
  Add optional HTTPS via environment variables (`HTTPS_KEY`, `HTTPS_CERT`) for encrypted access without reverse proxies

- **Rate Limiting**  
  Protect `/login` against brute-force attempts with IP-based rate limiting (e.g. 5 attempts per 15 minutes, then lockout)

- **Audit Logging**  
  Track user actions (container start/stop, credential changes, prune operations) with timestamps and IP addresses in `audit.log`

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
  Re-enable WebSocket terminal for interactive container console access with xterm.js (currently partial implementation)

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

- **Modularize Codebase**  
  Split `server.js` into modules: `auth.js`, `docker.js`, `monitor.js`, `api.js`, `web.js`

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
