#!/bin/bash

# Exit on any error
set -e

# ========== COMMAND LINE ARGUMENT HANDLING ==========
COMMAND="${1:-install}"
SERVER_DIR="$HOME/Library/Application Support/NodeServerStarter"

# Server management functions (available after installation)
check_server_running() {
    if command -v curl >/dev/null 2>&1; then
        curl -s "http://127.0.0.1:1337/health" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=2 "http://127.0.0.1:1337/health" -O /dev/null >/dev/null 2>&1
    else
        return 1
    fi
}

start_server() {
    echo "🚀 Starting FrogPost server..."
    
    if [ ! -d "$SERVER_DIR" ]; then
        echo "❌ FrogPost not installed. Please run: bash setup.sh"
        exit 1
    fi
    
    if check_server_running; then
        echo "✅ Server already running on port 1337"
        return 0
    fi
    
    cd "$SERVER_DIR"
    nohup node server.js >> frogpost-server.log 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > .frogpost-server.pid
    
    echo "⏳ Waiting for server to start..."
    for i in {1..10}; do
        sleep 1
        if check_server_running; then
            echo "✅ FrogPost server started successfully (PID: $SERVER_PID)"
            echo "📊 Server accessible at: http://127.0.0.1:1337"
            return 0
        fi
    done
    
    echo "❌ Server failed to start within 10 seconds"
    return 1
}

stop_server() {
    echo "🛑 Stopping FrogPost server..."
    
    if [ -f "$SERVER_DIR/.frogpost-server.pid" ]; then
        PID=$(cat "$SERVER_DIR/.frogpost-server.pid")
        if ps -p "$PID" >/dev/null 2>&1; then
            kill "$PID" 2>/dev/null
            sleep 2
            if ps -p "$PID" >/dev/null 2>&1; then
                kill -9 "$PID" 2>/dev/null
            fi
        fi
        rm -f "$SERVER_DIR/.frogpost-server.pid"
    fi
    
    pkill -f "node.*server" 2>/dev/null || true
    echo "✅ Server stopped"
}

server_status() {
    if check_server_running; then
        echo "Server status: ✅ Running"
        return 0
    else
        echo "Server status: ❌ Stopped"
        return 1
    fi
}

# Handle server management commands
case "$COMMAND" in
    start)
        start_server
        exit 0
        ;;
    stop)
        stop_server
        exit 0
        ;;
    status)
        server_status
        exit $?
        ;;
    restart)
        stop_server
        sleep 2
        start_server
        exit 0
        ;;
    install)
        # Continue with installation below
        ;;
    *)
        echo "Usage: $0 [install|start|stop|status|restart]"
        echo "  install - Install FrogPost (default)"
        echo "  start   - Start server in background"
        echo "  stop    - Stop background server"
        echo "  status  - Check server status"
        echo "  restart - Restart server"
        exit 1
        ;;
esac

cat << "EOF"
###############################################################################
#                                                                             #
#   ______                  _____           _                                 #
#  |  ____|                |  __ \         | |                                #
#  | |__ _ __ ___   __ _  | |__) |__  ___ | |_                                #
#  |  __| '__/ _ \ / _` | |  ___/ _ \/ __|| __|                               #
#  | |  | | | (_) | (_| | | |  | (_) \__ \| |_                                #
#  |_|  |_|  \___/ \__, | |_|   \___/|___/ \__|                               #
#                   __/ |                                                     #
#                  |___/                                                      #
#                                                                             #
#   🐸 FrogPost - postMessage Security Testing Tool                           #
#   Created by: thisis0xczar                                                  #
#                                                                             #
###############################################################################
EOF

echo "🐸 Starting FrogPost installation on macOS..."

# ========== AUTO CONFIGURATION ==========
FROGPOST_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📍 FrogPost repository detected at: $FROGPOST_REPO"

USER_NAME=$(whoami)
echo "👤 Installing for user: $USER_NAME"

echo ""
echo "🔑 Please enter your Chrome extension ID"
echo "   (You can find this at chrome://extensions after enabling Developer Mode)"
read -p "Extension ID: " EXTENSION_ID

# Validate extension ID format
while [[ ! $EXTENSION_ID =~ ^[a-z0-9]{32}$ ]]; do
  echo "❌ Invalid extension ID format. It should be 32 lowercase alphanumeric characters."
  read -p "Extension ID: " EXTENSION_ID
done

# Directory paths (SERVER_DIR already defined above)
NATIVE_HOST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"

# Source file paths (updated for new folder structure)
SERVER_JS_SRC="$FROGPOST_REPO/server/server.js"
START_SH_SRC="$FROGPOST_REPO/server/start_server.sh"
MANIFEST_SRC="$FROGPOST_REPO/server/com.nodeserver.starter.json"

# Target destination paths
SERVER_JS_DST="$SERVER_DIR/server.js"
START_SH_DST="$SERVER_DIR/start_server.sh"
MANIFEST_DST="$NATIVE_HOST_DIR/com.nodeserver.starter.json"

# ========== PRECHECK ==========
if ! command -v node >/dev/null || ! command -v npm >/dev/null; then
  echo "❌ Node.js and npm are required. Please install them first: https://nodejs.org/"
  exit 1
fi

# ========== STEP 1: Create Directories ==========
echo "📁 Creating required directories..."
mkdir -p "$SERVER_DIR"
mkdir -p "$NATIVE_HOST_DIR"
echo "✅ Directories ready."

# ========== STEP 2: Copy Files Before Modifying ==========
echo "📦 Copying files to destination directories..."
cp "$SERVER_JS_SRC" "$SERVER_JS_DST"
cp "$START_SH_SRC" "$START_SH_DST"
cp "$MANIFEST_SRC" "$MANIFEST_DST"
echo "✅ Files copied."

# ========== STEP 3: Update Manifest ==========
echo "🔧 Updating manifest..."
sed -i '' "s/abcdefghijklmnopabcdefghijklmnop/${EXTENSION_ID}/g" "$MANIFEST_DST"
sed -i '' "s/\[USER_NAME\]/${USER_NAME}/g" "$MANIFEST_DST"
echo "✅ Manifest updated at: $MANIFEST_DST"

# ========== STEP 4: Modify copied server.js ==========
echo "🛠 Updating copied server.js..."
FULL_REPO_PATH=$(cd "$FROGPOST_REPO" && pwd)
sed -i '' "s|const rootDir = .*|const rootDir = '${FULL_REPO_PATH}';|" "$SERVER_JS_DST"
echo "✅ rootDir set to: $FULL_REPO_PATH"

# ========== STEP 5: Modify copied start_server.sh ==========
echo "🛠 Updating copied start_server.sh..."
ESCAPED_PATH=$(echo "$SERVER_JS_DST" | sed 's/\//\\\//g')
sed -i '' "s|\[USER_NAME\]|${USER_NAME}|g" "$START_SH_DST"
sed -i '' "s|^SERVER_JS=.*|SERVER_JS=\"${SERVER_JS_DST}\" # Set by install script|" "$START_SH_DST"
chmod +x "$START_SH_DST"
echo "✅ start_server.sh updated."

# ========== STEP 6: Create log file ==========
LOG_FILE="$SERVER_DIR/node-finder.log"
echo "📝 Creating log file: $LOG_FILE"
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"
echo "✅ Log file ready."

# ========== STEP 7: Install Node.js dependencies ==========
echo "📦 Installing Node.js dependencies..."
cd "$SERVER_DIR"
cp "$FROGPOST_REPO/package.json" "$SERVER_DIR/package.json"
npm i
echo "✅ All dependencies installed from package.json."

# ========== ASK TO START SERVER ==========
echo ""
read -p "🤔 Would you like to start the FrogPost server now? (y/n): " START_NOW
if [[ $START_NOW =~ ^[Yy]$ ]]; then
    start_server
else
    echo "⏭️ Server not started. You can start it later with:"
    echo "   bash setup.sh start"
    echo "   OR directly: cd \"$SERVER_DIR\" && node server.js"
fi

# ========== COMPLETE ==========
echo ""
echo "🎉 FrogPost installation complete!"
echo ""
echo "📋 What was installed:"
echo "   ✅ Native messaging host for Chrome extension"
echo "   ✅ Server with all dependencies"
echo "   ✅ Server management through setup.sh"
echo ""
echo "🚀 Server Management Commands:"
echo "   bash setup.sh start     # Start server in background"
echo "   bash setup.sh status    # Check server status"
echo "   bash setup.sh stop      # Stop server"
echo "   bash setup.sh restart   # Restart server"
echo ""
echo "👉 Chrome Extension Setup:"
echo "   1. Go to chrome://extensions/"
echo "   2. Enable 'Developer Mode'"
echo "   3. Click 'Load unpacked' and select: $FROGPOST_REPO"
echo ""
echo "⚠️  Extension ID: $EXTENSION_ID"
echo "    (This ID is configured for native messaging)"
echo ""
echo "🎯 Ready to use! Server management is now integrated into setup.sh"
echo "💡 Happy Hacking with FrogPost 🐸"
