# Exit on any error
$ErrorActionPreference = "Stop"

Write-Host @"
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
"@

Write-Host "🐸 Starting FrogPost installation on Windows..."

# ========== AUTO CONFIGURATION ==========
$FROGPOST_REPO = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)
Write-Host "📍 FrogPost repository detected at: $FROGPOST_REPO"

$USER_NAME = $env:USERNAME
Write-Host "👤 Installing for user: $USER_NAME"

Write-Host ""
Write-Host "🔑 Please enter your Chrome extension ID"
Write-Host "   (You can find this at chrome://extensions after enabling Developer Mode)"
$EXTENSION_ID = Read-Host "Extension ID"

# Validate extension ID format
while ($EXTENSION_ID -notmatch "^[a-z0-9]{32}$") {
    Write-Host "❌ Invalid extension ID format. It should be 32 lowercase alphanumeric characters."
    $EXTENSION_ID = Read-Host "Extension ID"
}

# Directory paths
$SERVER_DIR = "$env:APPDATA\NodeServerStarter"
$NATIVE_HOST_DIR = "$env:APPDATA\Google\Chrome\NativeMessagingHosts"

# Source file paths (updated for correct folder structure)
$SERVER_JS_SRC = Join-Path $FROGPOST_REPO "server" "server.js"
$START_PS1_SRC = Join-Path $FROGPOST_REPO "Windows" "start_server.ps1"
$MANIFEST_SRC = Join-Path $FROGPOST_REPO "server" "com.nodeserver.starter.json"

# Target destination paths
$SERVER_JS_DST = Join-Path $SERVER_DIR "server.js"
$START_PS1_DST = Join-Path $SERVER_DIR "start_server.ps1"
$MANIFEST_DST = Join-Path $NATIVE_HOST_DIR "com.nodeserver.starter.json"

# ========== PRECHECK ==========
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Node.js and npm are required. Please install them first: https://nodejs.org/"
    exit 1
}

# ========== STEP 1: Create Directories ==========
Write-Host "📁 Creating required directories..."
New-Item -ItemType Directory -Force -Path $SERVER_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $NATIVE_HOST_DIR | Out-Null
Write-Host "✅ Directories ready."

# ========== STEP 2: Copy Files Before Modifying ==========
Write-Host "📦 Copying files to destination directories..."
Copy-Item -Path $SERVER_JS_SRC -Destination $SERVER_JS_DST -Force
Copy-Item -Path $START_PS1_SRC -Destination $START_PS1_DST -Force
Copy-Item -Path $MANIFEST_SRC -Destination $MANIFEST_DST -Force
Write-Host "✅ Files copied."

# ========== STEP 3: Update Manifest ==========
Write-Host "🔧 Updating manifest..."
(Get-Content $MANIFEST_DST) -replace "abcdefghijklmnopabcdefghijklmnop", $EXTENSION_ID -replace "\[USER_NAME\]", $USER_NAME | Set-Content $MANIFEST_DST
Write-Host "✅ Manifest updated at: $MANIFEST_DST"

# ========== STEP 4: Modify copied server.js ==========
Write-Host "🛠 Updating copied server.js..."
$FULL_REPO_PATH = $FROGPOST_REPO
(Get-Content $SERVER_JS_DST) -replace "const rootDir = .*", "const rootDir = '$($FULL_REPO_PATH.Replace('\', '\\'))';" | Set-Content $SERVER_JS_DST
Write-Host "✅ rootDir set to: $FULL_REPO_PATH"

# ========== STEP 5: Modify copied start_server.ps1 ==========
Write-Host "🛠 Updating copied start_server.ps1..."
(Get-Content $START_PS1_DST) `
    -replace "\[USER_NAME\]", $USER_NAME `
    -replace "^SERVER_JS=.*", "SERVER_JS=`"$SERVER_JS_DST`" # Set by install script" | Set-Content $START_PS1_DST
Set-ItemProperty -Path $START_PS1_DST -Name IsReadOnly -Value $false
Write-Host "✅ start_server.ps1 updated."

# ========== STEP 6: Create log file ==========
$LOG_FILE = Join-Path $SERVER_DIR "node-finder.log"
Write-Host "📝 Creating log file: $LOG_FILE"
New-Item -ItemType File -Force -Path $LOG_FILE | Out-Null
Set-ItemProperty -Path $LOG_FILE -Name IsReadOnly -Value $false
Write-Host "✅ Log file ready."

# ========== STEP 7: Install Node.js dependencies ==========
Write-Host "📦 Installing Node.js dependencies..."
$PACKAGE_JSON_SRC = Join-Path $FROGPOST_REPO "package.json"
$PACKAGE_JSON_DST = Join-Path $SERVER_DIR "package.json"
Copy-Item -Path $PACKAGE_JSON_SRC -Destination $PACKAGE_JSON_DST -Force
Push-Location $SERVER_DIR
npm install
Pop-Location
Write-Host "✅ All dependencies installed from package.json."

# ========== COMPLETE ==========
Write-Host ""
Write-Host "🎉 FrogPost installation complete!"
Write-Host ""
Write-Host "📋 What was installed:"
Write-Host "   ✅ Native messaging host for Chrome extension"
Write-Host "   ✅ Server with all dependencies"
Write-Host ""
Write-Host "👉 Chrome Extension Setup:"
Write-Host "   1. Go to chrome://extensions/"
Write-Host "   2. Enable 'Developer Mode'"
Write-Host "   3. Click 'Load unpacked' and select: $FROGPOST_REPO"
Write-Host ""
Write-Host "⚠️  Extension ID: $EXTENSION_ID"
Write-Host "    (This ID is configured for native messaging)"
Write-Host ""
Write-Host "🚀 To start the local server, run:"
Write-Host "   cd `"$SERVER_DIR`""
Write-Host "   node server.js"
Write-Host ""
Write-Host "💡 Happy Hacking with FrogPost 🐸"
