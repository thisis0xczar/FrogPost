# ========== COMMAND LINE ARGUMENT HANDLING ==========
param(
    [Parameter(Position=0)]
    [ValidateSet('install', 'start', 'stop', 'status', 'restart')]
    [string]$Command = 'install'
)

# Exit on any error
$ErrorActionPreference = "Stop"

$SERVER_DIR = "$env:APPDATA\NodeServerStarter"
$PID_FILE = "$SERVER_DIR\.frogpost-server.pid"
$PORT = 1337

# Server management functions
function Test-ServerRunning {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$PORT/health" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Start-Server {
    Write-Host "[*] Starting FrogPost server..."
    
    if (-not (Test-Path $SERVER_DIR)) {
        Write-Host "[!] FrogPost not installed. Please run: .\Windows\setup.ps1"
        exit 1
    }
    
    if (Test-ServerRunning) {
        Write-Host "[+] Server already running on port $PORT"
        return
    }
    
    $nodePath = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $nodePath) {
        Write-Host "[!] Node.js not found. Please install Node.js first."
        exit 1
    }
    
    $serverJs = Join-Path $SERVER_DIR "server.js"
    $logFile = Join-Path $SERVER_DIR "frogpost-server.log"
    
    # Start server in background
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $nodePath
    $processInfo.Arguments = "`"$serverJs`""
    $processInfo.WorkingDirectory = $SERVER_DIR
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null
    
    # Save PID
    $process.Id | Set-Content $PID_FILE
    
    Write-Host "[*] Waiting for server to start..."
    
    # Wait up to 10 seconds
    for ($i = 1; $i -le 10; $i++) {
        Start-Sleep -Seconds 1
        if (Test-ServerRunning) {
            Write-Host "[+] FrogPost server started successfully (PID: $($process.Id))"
            Write-Host "[*] Server accessible at: http://127.0.0.1:$PORT"
            return
        }
    }
    
    Write-Host "[!] Server failed to start within 10 seconds"
    Write-Host "    Check log file: $logFile"
    exit 1
}

function Stop-Server {
    Write-Host "[*] Stopping FrogPost server..."
    
    $stopped = $false
    
    # Try PID file first
    if (Test-Path $PID_FILE) {
        $pid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
        if ($pid) {
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                $stopped = $true
            }
        }
        Remove-Item $PID_FILE -ErrorAction SilentlyContinue
    }
    
    # Fallback: Kill node processes running server.js
    Get-Process -Name node -ErrorAction SilentlyContinue | ForEach-Object {
        $cmd = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
        if ($cmd -like "*server.js*") {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            $stopped = $true
        }
    }
    
    if ($stopped) {
        Write-Host "[+] Server stopped"
    } else {
        Write-Host "[*] No running server found"
    }
}

function Get-ServerStatus {
    if (Test-ServerRunning) {
        Write-Host "Server status: [+] Running on port $PORT"
        
        if (Test-Path $PID_FILE) {
            $pid = Get-Content $PID_FILE -ErrorAction SilentlyContinue
            if ($pid) {
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($process) {
                    Write-Host "Process ID: $pid"
                    Write-Host "Memory Usage: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
                }
            }
        }
        return 0
    } else {
        Write-Host "Server status: [!] Stopped"
        return 1
    }
}

# Handle server management commands
if ($Command -ne 'install') {
    switch ($Command) {
        'start' { Start-Server; exit 0 }
        'stop' { Stop-Server; exit 0 }
        'status' { exit (Get-ServerStatus) }
        'restart' { Stop-Server; Start-Sleep -Seconds 2; Start-Server; exit 0 }
    }
}

# Continue with installation if command is 'install'
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
#   FrogPost - postMessage Security Testing Tool                             #
#   Created by: thisis0xczar                                                  #
#                                                                             #
###############################################################################
"@

Write-Host "Starting FrogPost installation on Windows..."

# ========== AUTO CONFIGURATION ==========
$FROGPOST_REPO = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)
Write-Host "[*] FrogPost repository detected at: $FROGPOST_REPO"

$USER_NAME = $env:USERNAME
Write-Host "[*] Installing for user: $USER_NAME"

Write-Host ""
Write-Host "[*] Please enter your Chrome extension ID"
Write-Host "   (You can find this at chrome://extensions after enabling Developer Mode)"
$EXTENSION_ID = Read-Host "Extension ID"

# Validate extension ID format
while ($EXTENSION_ID -notmatch "^[a-z0-9]{32}$") {
    Write-Host "[!] Invalid extension ID format. It should be 32 lowercase alphanumeric characters."
    $EXTENSION_ID = Read-Host "Extension ID"
}

# Directory paths
$SERVER_DIR = "$env:APPDATA\NodeServerStarter"
$NATIVE_HOST_DIR = "$env:APPDATA\Google\Chrome\NativeMessagingHosts"

# Source file paths (updated for correct folder structure)
$SERVER_JS_SRC = Join-Path $FROGPOST_REPO "server\server.js"
$START_PS1_SRC = Join-Path $FROGPOST_REPO "Windows\start_server.ps1"
$MANIFEST_SRC = Join-Path $FROGPOST_REPO "server\com.nodeserver.starter.json"

# Target destination paths
$SERVER_JS_DST = Join-Path $SERVER_DIR "server.js"
$START_PS1_DST = Join-Path $SERVER_DIR "start_server.ps1"
$MANIFEST_DST = Join-Path $NATIVE_HOST_DIR "com.nodeserver.starter.json"

# ========== PRECHECK ==========
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Node.js not found. Attempting automatic installation..."
    
    # Try winget (Windows Package Manager)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "[*] Installing Node.js via winget..."
        try {
            winget install OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
            Write-Host "[+] Node.js installed successfully!"
            Write-Host "[*] Please close and reopen PowerShell, then run this script again."
            Write-Host "    (Required for PATH environment variable to refresh)"
            exit 0
        } catch {
            Write-Host "[!] Automatic installation failed."
        }
    } else {
        Write-Host "[!] winget not available (requires Windows 10 1809+ or Windows 11)"
    }
    
    # Fallback: Manual installation prompt
    Write-Host ""
    Write-Host "[!] Please install Node.js manually:"
    Write-Host "    1. Visit: https://nodejs.org/"
    Write-Host "    2. Download the LTS (Long Term Support) version"
    Write-Host "    3. Run the installer with default settings"
    Write-Host "    4. Restart PowerShell and run this script again"
    Write-Host ""
    exit 1
}

# ========== STEP 1: Create Directories ==========
Write-Host "[*] Creating required directories..."
New-Item -ItemType Directory -Force -Path $SERVER_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $NATIVE_HOST_DIR | Out-Null
Write-Host "[+] Directories ready."

# ========== STEP 2: Copy Files Before Modifying ==========
Write-Host "[*] Copying files to destination directories..."
Copy-Item -Path $SERVER_JS_SRC -Destination $SERVER_JS_DST -Force
Copy-Item -Path $START_PS1_SRC -Destination $START_PS1_DST -Force
Copy-Item -Path $MANIFEST_SRC -Destination $MANIFEST_DST -Force
Write-Host "[+] Files copied."

# ========== STEP 3: Update Manifest ==========
Write-Host "[*] Updating manifest..."
$manifestContent = Get-Content $MANIFEST_DST -Raw
$manifestContent = $manifestContent -replace "abcdefghijklmnopabcdefghijklmnop", $EXTENSION_ID
$manifestContent = $manifestContent -replace "\[USER_NAME\]", $USER_NAME
# Update path to Windows start_server.ps1 (convert forward slashes to escaped backslashes for JSON)
$windowsPath = $START_PS1_DST.Replace('\', '\\')
$manifestContent = $manifestContent -replace '".*/start_server\.(sh|ps1)"', "`"$windowsPath`""
$manifestContent | Set-Content $MANIFEST_DST
Write-Host "[+] Manifest updated at: $MANIFEST_DST"

# ========== STEP 4: Modify copied server.js ==========
Write-Host "[*] Updating copied server.js..."
$FULL_REPO_PATH = $FROGPOST_REPO
(Get-Content $SERVER_JS_DST) -replace "const rootDir = .*", "const rootDir = '$($FULL_REPO_PATH.Replace('\', '\\'))';" | Set-Content $SERVER_JS_DST
Write-Host "[+] rootDir set to: $FULL_REPO_PATH"

# ========== STEP 5: Modify copied start_server.ps1 ==========
Write-Host "[*] Updating copied start_server.ps1..."
(Get-Content $START_PS1_DST) `
    -replace "\[USER_NAME\]", $USER_NAME `
    -replace "^SERVER_JS=.*", "SERVER_JS=`"$SERVER_JS_DST`" # Set by install script" | Set-Content $START_PS1_DST
Set-ItemProperty -Path $START_PS1_DST -Name IsReadOnly -Value $false
Write-Host "[+] start_server.ps1 updated."

# ========== STEP 6: Create log file ==========
$LOG_FILE = Join-Path $SERVER_DIR "node-finder.log"
Write-Host "[*] Creating log file: $LOG_FILE"
New-Item -ItemType File -Force -Path $LOG_FILE | Out-Null
Set-ItemProperty -Path $LOG_FILE -Name IsReadOnly -Value $false
Write-Host "[+] Log file ready."

# ========== STEP 7: Install Node.js dependencies ==========
Write-Host "[*] Installing Node.js dependencies..."
$PACKAGE_JSON_SRC = Join-Path $FROGPOST_REPO "package.json"
$PACKAGE_JSON_DST = Join-Path $SERVER_DIR "package.json"
Copy-Item -Path $PACKAGE_JSON_SRC -Destination $PACKAGE_JSON_DST -Force
Push-Location $SERVER_DIR
npm install
Pop-Location
Write-Host "[+] All dependencies installed from package.json."

# ========== ASK TO START SERVER ==========
Write-Host ""
$START_NOW = Read-Host "[*] Would you like to start the FrogPost server now? (y/n)"

if ($START_NOW -match "^[Yy]$") {
    Start-Server
} else {
    Write-Host "[*] Server not started. You can start it later with:"
    Write-Host "    .\Windows\setup.ps1 start"
}

# ========== COMPLETE ==========
Write-Host ""
Write-Host "[+] FrogPost installation complete!"
Write-Host ""
Write-Host "What was installed:"
Write-Host "   [+] Native messaging host for Chrome extension"
Write-Host "   [+] Server with all dependencies"
Write-Host "   [+] Server management through setup.ps1"
Write-Host ""
Write-Host "Server Management Commands:"
Write-Host "   .\Windows\setup.ps1 start     # Start server in background"
Write-Host "   .\Windows\setup.ps1 status    # Check server status"
Write-Host "   .\Windows\setup.ps1 stop      # Stop server"
Write-Host "   .\Windows\setup.ps1 restart   # Restart server"
Write-Host ""
Write-Host "Chrome Extension Setup:"
Write-Host "   1. Go to chrome://extensions/"
Write-Host "   2. Enable 'Developer Mode'"
Write-Host "   3. Click 'Load unpacked' and select: $FROGPOST_REPO"
Write-Host ""
Write-Host "[!] Extension ID: $EXTENSION_ID"
Write-Host "    (This ID is configured for native messaging)"
Write-Host ""
Write-Host "[+] Ready to use! Server management is now integrated into setup.ps1"
Write-Host "Happy Hacking with FrogPost"
