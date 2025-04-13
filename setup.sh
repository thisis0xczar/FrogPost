#!/bin/bash

# Exit on any error
set -e

# Print the ASCII art at runtime
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
#          🐸 FrogPost - postMessage Security Testing Tool 🐸                #
#                                                                             #
###############################################################################
EOF

echo "🐸 Starting FrogPost installation on macOS..."

# ========== AUTO CONFIGURATION ==========
# Get the current directory as the FrogPost repo path
FROGPOST_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📍 FrogPost repository detected at: $FROGPOST_REPO"

# Get the current user's home directory and username
USER_NAME=$(whoami)
echo "👤 Installing for user: $USER_NAME"

# Prompt for extension ID
echo ""
echo "🔑 Please enter your Chrome extension ID"
echo "   (You can find this at chrome://extensions after enabling Developer Mode)"
read -p "Extension ID: " EXTENSION_ID

# Validate extension ID format (basic validation)
while [[ ! $EXTENSION_ID =~ ^[a-z0-9]{32}$ ]]; do
  echo "❌ Invalid extension ID format. It should be 32 lowercase alphanumeric characters."
  read -p "Extension ID: " EXTENSION_ID
done

# Directory paths
SERVER_DIR="$HOME/Library/Application Support/NodeServerStarter"
NATIVE_HOST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"

# Paths to files inside the repo
SERVER_JS_SRC="$FROGPOST_REPO/server.js"
START_SH_SRC="$FROGPOST_REPO/start_server.sh"
MANIFEST_SRC="$FROGPOST_REPO/com.nodeserver.starter.json"

# Target installation paths
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

# ========== STEP 2: Update manifest with extension ID and username ==========
echo "🔧 Updating manifest with Extension ID and username..."
cp "$MANIFEST_SRC" "$MANIFEST_DST"
sed -i '' "s/abcdefghijklmnopabcdefghijklmnop/${EXTENSION_ID}/g" "$MANIFEST_DST"
sed -i '' "s/\[USER_NAME\]/${USER_NAME}/g" "$MANIFEST_DST"
echo "✅ Manifest updated at: $MANIFEST_DST"

# ========== STEP 3: Update path in server.js ==========
echo "🛠  Updating rootDir in server.js..."
FULL_REPO_PATH=$(cd "$FROGPOST_REPO" && pwd)
sed -i '' "s|const rootDir = .*|const rootDir = '${FULL_REPO_PATH}';|" "$SERVER_JS_SRC"
echo "✅ rootDir set to: $FULL_REPO_PATH"

# ========== STEP 4: Update start_server.sh ==========
echo "🛠  Updating start_server.sh..."
# First, replace any [USER_NAME] placeholders in the start_server.sh source file
sed -i '' "s|\[USER_NAME\]|${USER_NAME}|g" "$START_SH_SRC"

# Then update the SERVER_JS path
ESCAPED_PATH=$(echo "$SERVER_JS_DST" | sed 's/\//\\\//g')
sed -i '' "s|^SERVER_JS=.*|SERVER_JS=\"${SERVER_JS_DST}\" # Set by install script|" "$START_SH_SRC"
echo "✅ start_server.sh updated."

# ========== STEP 5: Copy server files ==========
echo "📦 Copying server files to $SERVER_DIR..."
cp "$SERVER_JS_SRC" "$SERVER_JS_DST"
cp "$START_SH_SRC" "$START_SH_DST"

# Replace any remaining [USER_NAME] in the copied start_server.sh file
sed -i '' "s|\[USER_NAME\]|${USER_NAME}|g" "$START_SH_DST"

chmod +x "$START_SH_DST"
echo "✅ Server files installed."

# ========== STEP 6: Verify manifest ==========
echo "📋 Verifying manifest content:"
cat "$MANIFEST_DST" | grep -E 'path|allowed_origins'

# ========== STEP 7: Create log file directory if referenced ==========
LOG_DIR="$HOME/Library/Application Support/NodeServerStarter"
LOG_FILE="$LOG_DIR/node-finder.log"
echo "📝 Creating log file: $LOG_FILE"
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"
echo "✅ Log file ready."

# ========== STEP 8: Install Node.js dependencies ==========
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
