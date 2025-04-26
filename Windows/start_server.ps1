# Script to find Node.js and run server.js

$SERVER_JS = "$env:APPDATA\NodeServerStarter\server.js" # Full Path to your server.js
$LOG_FILE = "$env:APPDATA\NodeServerStarter\node-finder.log" # log file path

# Start with a fresh log
"=== Node Finder Started: $(Get-Date) ===" | Set-Content $LOG_FILE

# List of common Node.js locations on Windows
$NODE_LOCATIONS = @(
    "$env:ProgramFiles\nodejs\node.exe",
    "$env:ProgramFiles(x86)\nodejs\node.exe",
    "$env:USERPROFILE\nvm\v*\node.exe",
    "$env:USERPROFILE\AppData\Roaming\npm\node.exe",
    "$env:USERPROFILE\scoop\apps\nodejs\current\node.exe",
    "$env:USERPROFILE\AppData\Local\Programs\nodejs\node.exe"
)

$found = $false

foreach ($node_path in $NODE_LOCATIONS) {
    # Expand wildcards for nvm
    $paths = Get-ChildItem -Path $node_path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    if (-not $paths) { $paths = @($node_path) }

    foreach ($path in $paths) {
        "Trying: $path" | Add-Content $LOG_FILE

        if (Test-Path $path) {
            "Found executable at: $path" | Add-Content $LOG_FILE

            # Try to run the server with this Node path using direct invocation and UTF-8 encoding for the log
            & $path $SERVER_JS 2>&1 | Out-File -FilePath $LOG_FILE -Encoding 'UTF8'
            if ($LASTEXITCODE -eq 0) {
                "Started server with $path" | Add-Content $LOG_FILE
                "Server running successfully with: $path" | Add-Content $LOG_FILE
                $found = $true
                exit 0
            } else {
                "Server failed to start with: $path" | Add-Content $LOG_FILE
            }
        } else {
            "Not found or not executable: $path" | Add-Content $LOG_FILE
        }
    }
}

if (-not $found) {
    "ERROR: Could not find a working Node.js installation" | Add-Content $LOG_FILE
    exit 1
}