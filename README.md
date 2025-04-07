# FrogPost: postMessage Security Testing Tool

FrogPost is a powerful Chrome extension for testing and analyzing the security of postMessage communications between iframes. It helps developers and security professionals identify vulnerabilities in postMessage implementations.

<p align="center" width="100%">
    <img width="15%" src="frog-logo.png">
</p>

## Preview
<p align="center" width="100%">
    <img width="80%" src="FrogPost_hi.gif">
</p>

## Security Considerations

FrogPost is a security testing tool. Use it responsibly and only on applications you own or have permission to test.
Unauthorized testing of applications without permission may violate laws and regulations. Always follow ethical guidelines and obtain proper authorization before conducting security assessments.

## Features

* Monitor and intercept postMessage communications between frames

* Detect message handlers and analyze their security

* Generate targeted payloads for security testing

* Identify DOM XSS vulnerabilities in message handlers

* Check for missing origin validation

* Generate comprehensive security reports

* Launch fuzzing tests against vulnerable handlers

## Installation Guide for macOS

### Step 1: Install the Chrome Extension

1. Clone the repository:

   ```
   git clone https://github.com/thisis0xczar/FrogPost.git
   ```

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" by toggling the switch in the top right corner

4. Click "Load unpacked" and select the FrogPost directory

5. The FrogPost extension should now appear in your extensions list

### Step 2: Set Up the Native Messaging Host

For the fuzzing functionality, FrogPost requires a native messaging host to communicate with a local Node.js server:

1. Create the necessary directories:

   ```
   mkdir -p ~/Library/Application\ Support/NodeServerStarter
   mkdir -p ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
   ```

2. After loading the extension into Chrome, go to chrome://extensions and copy the Extension ID shown under FrogPost.

   Use the following sed command to replace the placeholder \[your_id_here\] in the manifest file:

   ```
   sed -i '' 's/\abcdefghijklmnopabcdefghijklmnop/<your-extension-id>/g' com.nodeserver.starter.json
   ```

3. Verify that the "allowed_origins" field now includes:

   ```
   "chrome-extension://<your-extension-id>/"
   ```

4. Change the following line to the path of your extension FULL path in server.js:

   ```
   const rootDir = '/Path/To/extension/folder';
   ```

5. Change the following line to the path of your extension path in start.sh:

   ```
   SERVER_JS="/Users/[USER_NAME]/Library/Application Support/NodeServerStarter/server.js" # Make sure to set the FULL path correctly to the server.js
   ```

6. Copy the server files to the NodeServerStarter directory:

   ```
   cp /path/to/FrogPost/server.js ~/Library/Application\ Support/NodeServerStarter/
   cp /path/to/FrogPost/start.sh ~/Library/Application\ Support/NodeServerStarter/
   cp /path/to/FrogPost/com.nodeserver.starter.json ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/
   ```

7. Make sure the paths in the manifest file are correct:

   ```
   cat ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.nodeserver.starter.json
   ```

   Verify that the "path" points to your start.sh script and "allowed_origins" includes your extension ID.

9. Install Node.js dependencies in the NodeServerStarter directory:

   ```
   cd ~/Library/Application\ Support/NodeServerStarter/
   npm install express cors body-parser
   ```

### Step 3: Verify Installation

1. Restart Chrome

2. Open the FrogPost extension by clicking on its icon in the extension bar

3. Navigate to a website that uses iframes and postMessage

4. The extension should show detected hosts and iframes in its dashboard

## Usage

1. **Monitor Messages**: Visit a page with postMessage communication between frames

2. **Analyze Handlers**: Click the "Play" button (▶) next to a frame to detect and analyze message handlers

3. **Generate Report**: Click the "Trace" button (✨) to generate a security report

4. **Launch Tests**: Click the "Launch" button (🚀) to start fuzzing tests against the target

## Dashboard Buttons Explained

Here's a breakdown of the primary buttons available in the FrogPost dashboard:

**Per-Iframe Buttons (in the Hosts Panel):**

* **Play (▶):**

    * Initiates the first stage of analysis for the selected iframe endpoint.

    * Checks if the target iframe can be embedded (verifying CSP `frame-ancestors` and `X-Frame-Options`).

    * Attempts to identify the primary JavaScript function responsible for handling incoming `postMessage` events (using runtime instrumentation first, then static analysis as fallback).

    * Saves a sample of captured messages related to this endpoint for later use.

    * On successful handler identification, it enables the "Trace" button.

* **Trace (✨):**

    * Performs a deeper static analysis on the message handler function identified by the "Play" step.

    * Identifies potential security sinks (like `.innerHTML`, `eval()`) where message data might be used unsafely.

    * Detects potential security issues (e.g., missing origin checks, weak data validation).

    * Attempts to map the flow of data from the message event (`event.data`) to identified sinks.

    * Calculates an overall security score based on findings.

    * Generates potential payload examples designed to test the identified sinks and data flows.

    * Saves the analysis results into a report.

    * On successful completion, it enables the "Report" (📋) and "Launch" (🚀) buttons. The "Play" button might visually change to the "Launch" icon if critical sinks are found.

* **Report (📋):**

    * Displays the detailed security analysis report generated by the "Trace" step.

    * Shows the security score, recommendations, a list of detected sinks and security issues, identified data flows, generated test payloads, and the code of the analyzed handler.

    * This button is only enabled after a successful "Trace" action.

* **Launch (🚀):**

    * Starts the interactive fuzzing environment in a new browser tab, targeting the analyzed endpoint.

    * Requires the Native Messaging Host and Node.js server to be set up correctly.

    * Uses the identified handler, sample messages, generated payloads, and sink information from the previous steps to automatically send crafted messages to the target iframe, attempting to trigger vulnerabilities.

    * Results of the fuzzing appear in the new tab and may optionally be sent to a configured callback URL.

    * This button is typically enabled after a successful "Trace" action.

**General Control Buttons (usually in the sidebar or top bar):**

* **Check All:**

    * Automatically triggers the "Play" (▶) action for all detected iframes in the Hosts Panel that haven't already been successfully analyzed (i.e., aren't showing Success, Launch, Warning, or Error states).

* **Clear Messages:**

    * Resets the extension's state entirely.

    * Clears all captured messages from the dashboard view and background storage.

    * Removes the list of detected hosts and iframes.

    * Resets the state (color/icon) of all per-iframe buttons.

    * Clears stored analysis results and reports.

* **Export Messages:**

    * Generates and downloads a JSON file containing the data for all currently captured postMessages displayed in the dashboard.

* **Refresh Messages:**

    * Manually requests the latest message data from the background script's buffer and updates the Messages Panel in the UI.

* **Debug Toggle:**

    * Switches verbose debugging logs on or off in the browser's developer console (F12). Useful for troubleshooting the extension itself.

**Message Detail Buttons (within the Messages Panel):**

* **→ Send to Origin:**

    * Takes the data from the selected message (allows editing the data in the panel first) and sends it back to the *original sender* of that message.

* **→ Send to Destination:**

    * Takes the data from the selected message (allows editing) and sends it to the *original receiver* (destination frame) of that message.

## Understanding the Dashboard

* **Hosts Panel**: Shows the main page and its iframe connections

* **Messages Panel**: Displays intercepted postMessages with details including:

    * Origin: Source of the message

    * Destination: Target of the message

    * Time: When the message was sent

    * Message Type: Format of the data (string, object, JSON string, etc.)

* **Security Report**: Highlights vulnerabilities like missing origin validation or DOM XSS sinks

## Troubleshooting macOS Installation

* **Could not connect to fuzzer server**: Double check the following files are having the right path inside them see Step 2:

  ```
  ~/Library/Application\ Support/NodeServerStarter/server.js
  ~/Library/Application\ Support/NodeServerStarter/start.sh
  ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.nodeserver.starter.json
  ```

* **Permissions Issues**: Make sure the directories have the correct permissions:

  ```
  chmod 755 ~/Library/Application\ Support/NodeServerStarter/server.js
  chmod 755 ~/Library/Application\ Support/NodeServerStarter/start.sh
  ```

* **Fuzzer Not Starting**: Check the Chrome console for errors. Verify the native messaging host is correctly set up:

  ```
  ls -la ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/
  ls -la ~/Library/Application\ Support/NodeServerStarter/
  ```

* **Node.js Not Found**: Make sure Node.js is installed and in your PATH:

  ```
  which node
  node --version
  ```

* **Extension Not Loading**: Check Chrome's extension page for any error messages. Try reloading the extension.

## Notes

1. This extension was tested on Brave and Chrome browsers.

## TODO

1. Setup Passive Listeners iframes (i.e Listeners that does not exchange any communication with the main page) ?

2. ~Fix Callback integration properly.~

3. Upload XSS Payloads file.

4. POC Build button.

## License

[MIT License](LICENSE)
