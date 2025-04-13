#!/bin/bash

# Exit on any error
set -e

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

# Directory paths
SERVER_DIR="$HOME/Library/Application Support/NodeServerStarter"
NATIVE_HOST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"

# Source file paths
SERVER_JS_SRC="$FROGPOST_REPO/server.js"
START_SH_SRC="$FROGPOST_REPO/start_server.sh"
MANIFEST_SRC="$FROGPOST_REPO/com.nodeserver.starter.json"

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
npm install express cors body-parser
echo "✅ Dependencies installed."

# ========== COMPLETE ==========
echo ""
echo "🎉 All done!"
echo "👉 Open Chrome and go to chrome://extensions/"
echo "   - Enable 'Developer Mode'"
echo "   - Click 'Load unpacked' and select the FrogPost directory"
echo ""
echo "⚠️ Extension ID: $EXTENSION_ID"
echo "   (This ID is also saved in extension_id.txt for your reference)"
echo ""
echo "🚀 To start the local server, run:"
echo "   bash \"$START_SH_DST\""
echo ""
echo "💡 Happy Hacking with FrogPost 🐸"
