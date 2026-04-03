#!/bin/bash
# NAS Monitor - Startup Script
# Run on Synology DS723+ directly (no Docker required)

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"

echo "🐋 NAS Monitor"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for root or admin privileges (required to read all /proc entries)
CURRENT_USER=$(whoami)
if [ "$EUID" -ne 0 ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "admin" ]; then
  echo "⚠️  Warning: running as '$CURRENT_USER' (not root/admin)."
  echo "   Some /proc entries and Docker stats may be inaccessible."
  echo "   Re-run with: sudo bash start.sh"
  echo ""
  read -r -p "   Continue anyway? [y/N] " REPLY
  case "$REPLY" in
    [yY][eE][sS]|[yY]) echo "" ;;
    *) echo "Aborted."; exit 1 ;;
  esac
else
  echo "✅ User: $CURRENT_USER"
fi

# Find Node.js on Synology
NODE_PATHS=(
  "/usr/local/bin/node"
  "/opt/bin/node"
  "/usr/bin/node"
  "/var/packages/Node.js_v18/target/bin/node"
  "/var/packages/Node.js_v20/target/bin/node"
  "/var/packages/Node.js_v22/target/bin/node"
)

NODE=""
for p in "${NODE_PATHS[@]}"; do
  if [ -x "$p" ]; then
    NODE="$p"
    break
  fi
done

# Fallback to PATH
if [ -z "$NODE" ]; then
  NODE=$(which node 2>/dev/null)
fi

if [ -z "$NODE" ]; then
  echo "❌ Node.js not found. Install it via Synology Package Center."
  exit 1
fi

echo "✅ Node.js: $($NODE --version) at $NODE"
echo "✅ Port: ${PORT:-3232}"
echo ""
echo "  Open: http://192.168.0.10:${PORT:-3232}"
echo ""

exec "$NODE" server.js &
SERVER_PID=$!
echo $SERVER_PID > "$SCRIPT_DIR/nas-monitor.pid"
echo "✅ PID: $SERVER_PID (saved to nas-monitor.pid)"
echo ""
wait $SERVER_PID
