#!/bin/bash

# Script to find Node.js and run server.js
SERVER_JS="~/Library/Application Support/NodeServerStarter/server.js" # Full Path to your server.js
LOG_FILE="~/Library/Application Support/NodeServerStarter/node-finder.log" # log file path

# Start with a fresh log
echo "=== Node Finder Started: $(date) ===" > "$LOG_FILE"

# List of common Node.js locations
NODE_LOCATIONS=(
    "/usr/local/bin/node"
    "/opt/homebrew/bin/node"
    "/usr/bin/node"
    "$HOME/.nvm/current/bin/node"
    "/opt/local/bin/node"
    "$HOME/.nodenv/shims/node"
    "/usr/local/opt/node/bin/node"
    "/opt/homebrew/opt/node/bin/node"
    "$HOME/n/bin/node"
)

# Try each Node location
for node_path in "${NODE_LOCATIONS[@]}"; do
    echo "Trying: $node_path" >> "$LOG_FILE"

    if [ -x "$node_path" ]; then
        echo "Found executable at: $node_path" >> "$LOG_FILE"

        # Try to run the server with this Node path
        "$node_path" "$SERVER_JS" >> "$LOG_FILE" 2>&1 &
        SERVER_PID=$!

        echo "Started server with PID: $SERVER_PID" >> "$LOG_FILE"

        # Wait a moment to see if it stays running
        sleep 1
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo "Server running successfully with: $node_path" >> "$LOG_FILE"
            # Keep the script running so the server stays alive
            wait $SERVER_PID
            exit 0
        else
            echo "Server failed to start with: $node_path" >> "$LOG_FILE"
        fi
    else
        echo "Not found or not executable: $node_path" >> "$LOG_FILE"
    fi
done

echo "ERROR: Could not find a working Node.js installation" >> "$LOG_FILE"
exit 1
