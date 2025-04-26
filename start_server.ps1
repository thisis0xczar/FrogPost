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

            # Try to run the server with this Node path
            $tempErr = [System.IO.Path]::GetTempFileName()

            $process = Start-Process -FilePath $path `
                -ArgumentList "`"$SERVER_JS`"" `
                -PassThru `
                -RedirectStandardOutput $LOG_FILE `
                -RedirectStandardError $tempErr

            Start-Sleep -Seconds 1

            if (!$process.HasExited) {
                "Started server with PID: $($process.Id)" | Add-Content $LOG_FILE
                "Server running successfully with: $path" | Add-Content $LOG_FILE
                $found = $true
                $process.WaitForExit()
                # Append stderr to log
                Get-Content $tempErr | Add-Content $LOG_FILE
                Remove-Item $tempErr -ErrorAction SilentlyContinue
                exit 0
            } else {
                "Server failed to start with: $path" | Add-Content $LOG_FILE
                Get-Content $tempErr | Add-Content $LOG_FILE
                Remove-Item $tempErr -ErrorAction SilentlyContinue
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