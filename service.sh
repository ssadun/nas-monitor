#!/bin/bash
# NAS Monitor - Service Manager
# Usage: bash service.sh {start|stop|status|restart}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${SCRIPT_DIR}/nas-monitor.pid"
LOG_FILE="${SCRIPT_DIR}/nas-monitor.log"

SERVICE_NAME="NAS Monitor"
SERVICE_ICON="🐋"

# Find Node.js on Synology
find_node() {
  local NODE_PATHS=(
    "/usr/local/bin/node"
    "/opt/bin/node"
    "/usr/bin/node"
    "/var/packages/Node.js_v18/target/bin/node"
    "/var/packages/Node.js_v20/target/bin/node"
    "/var/packages/Node.js_v22/target/bin/node"
  )

  for p in "${NODE_PATHS[@]}"; do
    if [ -x "$p" ]; then
      echo "$p"
      return
    fi
  done

  # Fallback to PATH
  local NODE=$(which node 2>/dev/null)
  if [ -n "$NODE" ]; then
    echo "$NODE"
    return
  fi

  echo ""
}

# Get the PID of the running service
get_pid() {
  local pid=""

  # Check PID file first
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      # Verify it's actually our server.js process
      if [ -f "/proc/$pid/cmdline" ]; then
        local cmdline
        cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
        if echo "$cmdline" | grep -q "server.js"; then
          # Additional check: verify cwd matches
          if [ -L "/proc/$pid/cwd" ]; then
            local cwd
            cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null)
            if [ "$cwd" = "$SCRIPT_DIR" ]; then
              echo "$pid"
              return
            fi
          fi
        fi
      fi
    fi
    # Stale PID file - remove it
    rm -f "$PID_FILE"
  fi

  # Search for running server.js process in this directory
  for pid in $(pgrep -f "node" 2>/dev/null); do
    if [ -L "/proc/$pid/cwd" ]; then
      local cwd
      cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null)
      if [ "$cwd" = "$SCRIPT_DIR" ]; then
        # Check if cmdline contains server.js
        if [ -f "/proc/$pid/cmdline" ]; then
          local cmdline
          cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
          if echo "$cmdline" | grep -q "server.js"; then
            # Found it - save PID for future
            echo "$pid" > "$PID_FILE"
            echo "$pid"
            return
          fi
        fi
      fi
    fi
  done

  # No NAS Monitor process found
  rm -f "$PID_FILE"
}

# Start the service
do_start() {
  local RUNNING_PID=$(get_pid)
  if [ -n "$RUNNING_PID" ]; then
    echo "⚠️  ${SERVICE_NAME} is already running (PID: $RUNNING_PID)"
    return 0
  fi

  echo "${SERVICE_ICON} ${SERVICE_NAME}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Find Node.js
  local NODE=$(find_node)
  if [ -z "$NODE" ]; then
    echo "❌ Node.js not found. Install it via Synology Package Center."
    return 1
  fi

  echo "✅ Node.js: $($NODE --version) at $NODE"
  echo "✅ Port: ${PORT:-3232}"
  echo ""

  # Start the server in background
  cd "$SCRIPT_DIR"
  nohup $NODE server.js >> "$LOG_FILE" 2>&1 &
  local SERVER_PID=$!
  echo $SERVER_PID > "$PID_FILE"

  # Wait briefly and check if it started
  sleep 1
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "✅ ${SERVICE_NAME} started (PID: $SERVER_PID)"
    echo "   Open: http://192.168.0.10:${PORT:-3232}"
    echo "   Log:  $LOG_FILE"
    echo ""
  else
    echo "❌ Failed to start ${SERVICE_NAME}. Check log: $LOG_FILE"
    return 1
  fi
}

# Stop the service
do_stop() {
  local PIDS=$(get_pid)
  if [ -z "$PIDS" ]; then
    echo "ℹ️  ${SERVICE_NAME} is not running."
    rm -f "$PID_FILE"
    return 0
  fi

  echo "${SERVICE_ICON} ${SERVICE_NAME}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "🔍 Found process(es): $PIDS"

  for PID in $PIDS; do
    kill "$PID" 2>/dev/null && echo "✅ Stopped PID $PID" || echo "❌ Failed to stop PID $PID"
  done

  # Verify they're gone
  sleep 1
  local STILL_RUNNING=$(pgrep -f "node.*server.js" 2>/dev/null)
  if [ -z "$STILL_RUNNING" ]; then
    rm -f "$PID_FILE"
    echo ""
    echo "✅ ${SERVICE_NAME} stopped."
  else
    echo ""
    echo "⚠️  Some processes still running: $STILL_RUNNING"
    echo "   Try: sudo kill -9 $STILL_RUNNING"
    return 1
  fi
}

# Show service status
do_status() {
  local RUNNING_PID=$(get_pid)
  if [ -z "$RUNNING_PID" ]; then
    echo "ℹ️  ${SERVICE_NAME} is not running."
    return 1
  fi

  echo "${SERVICE_ICON} ${SERVICE_NAME}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "✅ Status: Running"
  echo "   PID:  $RUNNING_PID"
  echo "   Port: ${PORT:-3232}"

  # Get uptime and memory from /proc
  if [ -f "/proc/$RUNNING_PID/stat" ]; then
    local UPTIME_SEC=$(awk '{print $3/100}' /proc/uptime)
    local MEM_KB=$(awk '/VmRSS/{print $2}' /proc/$RUNNING_PID/status 2>/dev/null)
    if [ -n "$MEM_KB" ]; then
      echo "   Mem:  $((MEM_KB / 1024))MB"
    fi

    # Calculate uptime from process starttime
    if [ -f "/proc/$RUNNING_PID/stat" ]; then
      local START_TICKS=$(awk '{print $22}' /proc/$RUNNING_PID/stat)
      local CLK_TCK=100
      local BOOT_TIME=$(awk '/btime/{print $2}' /proc/stat)
      local START_EPOCH=$((BOOT_TIME + START_TICKS / CLK_TCK))
      local UPTIME=$(( $(date +%s) - START_EPOCH ))

      local DAYS=$((UPTIME / 86400))
      local HOURS=$(( (UPTIME % 86400) / 3600 ))
      local MINS=$(( (UPTIME % 3600) / 60 ))
      echo "   Up:   ${DAYS}d ${HOURS}h ${MINS}m"
    fi
  fi

  # Show log file size if it exists
  if [ -f "$LOG_FILE" ]; then
    local LOG_SIZE=$(du -h "$LOG_FILE" 2>/dev/null | cut -f1)
    echo "   Log:  $LOG_FILE ($LOG_SIZE)"
  fi

  echo ""
  echo "   Open: http://192.168.0.10:${PORT:-3232}"
}

# Restart the service
do_restart() {
  echo "🔄 Restarting ${SERVICE_NAME}..."
  echo ""
  do_stop
  echo ""
  sleep 1
  do_start
}

# Main
case "${1}" in
  start)
    do_start
    ;;
  stop)
    do_stop
    ;;
  status)
    do_status
    ;;
  restart)
    do_restart
    ;;
  *)
    echo "${SERVICE_ICON} ${SERVICE_NAME} Service Manager"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Usage: bash service.sh {start|stop|status|restart}"
    echo ""
    echo "Commands:"
    echo "  start    - Start the NAS Monitor service"
    echo "  stop     - Stop the NAS Monitor service"
    echo "  status   - Show current service status"
    echo "  restart  - Restart the service"
    echo ""
    echo "Examples:"
    echo "  bash service.sh start"
    echo "  bash service.sh status"
    echo "  bash service.sh restart"
    echo ""
    return 1 2>/dev/null || exit 1
    ;;
esac
