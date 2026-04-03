#!/bin/bash
# NAS Monitor - Stop Script

echo "🐋 NAS Monitor"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Find PIDs — check PID file first, then fall back to pgrep
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="${SCRIPT_DIR}/nas-monitor.pid"
PIDS=""

if [ -f "$PID_FILE" ]; then
  FILE_PID=$(cat "$PID_FILE")
  if kill -0 "$FILE_PID" 2>/dev/null; then
    PIDS="$FILE_PID"
  else
    echo "ℹ️  PID file found but process $FILE_PID is no longer running."
    rm -f "$PID_FILE"
  fi
fi

# Fallback: search by process name
if [ -z "$PIDS" ]; then
  PIDS=$(pgrep -f "node.*${SCRIPT_DIR}/server.js" 2>/dev/null)
fi
if [ -z "$PIDS" ]; then
  PIDS=$(pgrep -f "node.*server.js" 2>/dev/null)
fi

if [ -z "$PIDS" ]; then
  echo "ℹ️  NAS Monitor is not running."
  exit 0
fi

echo "🔍 Found process(es): $PIDS"

for PID in $PIDS; do
  kill "$PID" 2>/dev/null && echo "✅ Stopped PID $PID" || echo "❌ Failed to stop PID $PID (try: sudo bash stop.sh)"
done

# Verify they're gone
sleep 1
STILL_RUNNING=$(pgrep -f "node.*server.js" 2>/dev/null)
if [ -z "$STILL_RUNNING" ]; then
  rm -f "$PID_FILE"
  echo ""
  echo "✅ NAS Monitor stopped."
else
  echo ""
  echo "⚠️  Some processes still running: $STILL_RUNNING"
  echo "   Try: sudo kill -9 $STILL_RUNNING"
  exit 1
fi
