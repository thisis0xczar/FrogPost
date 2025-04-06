/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-03
 */
window.frogPostState = {
    frameConnections: new Map(),
    messages: [],
    activeEndpoint: null,
    activeUrl: null,
    loadedData: {
        urls: new Set()
    }
};

const log = {
    styles: {
        info: 'color: #0066cc; font-weight: bold',
        success: 'color: #00cc66; font-weight: bold',
        warning: 'color: #ff9900; font-weight: bold',
        error: 'color: #cc0000; font-weight: bold',
        handler: 'color: #6600cc; font-weight: bold',
        scan: 'color: #FFDC77; font-weight: bold',
        debug: 'color: #999999; font-style: italic'
    },
    info: (msg, details) => {
        console.log('%c ℹ️ ' + msg, log.styles.info);
        if (details && (debugMode || typeof details === 'string')) {
            console.log('%c    ' + details, 'color: #666666');
        }
    },
    success: (msg, details) => {
        console.log('%c ✅ ' + msg, log.styles.success);
        if (details && (debugMode || typeof details === 'string')) {
            console.log('%c    ' + details, 'color: #666666');
        }
    },
    warning: (msg, details) => {
        console.log('%c ⚠️ ' + msg, log.styles.warning);
        if (details && (debugMode || typeof details === 'string')) {
            console.log('%c    ' + details, 'color: #666666');
        }
    },
    error: (msg, details) => {
        console.error('%c ❌ ' + msg, log.styles.error);
        if (details) {
            console.error('%c    ' + details, 'color: #666666');
        }
    },
    handler: (msg, details) => {
        console.log('%c 🔍 ' + msg, log.styles.handler);
        if (details && debugMode) {
            console.log('%c    ' + details, 'color: #666666');
        }
    },
    scan: (msg, details) => {
        console.log('%c 🔄 ' + msg, log.styles.scan);
        if (details && debugMode) {
            console.log('%c    ' + details, 'color: #666666');
        }
    },
    debug: (msg, ...args) => {
        if (debugMode) {
            console.log('%c 🔧 ' + msg, log.styles.debug, ...args);
        }
    }
};

function printBanner() {
    console.log(`
  _____                ____           _
 |  ___| __ ___   __ _|  _ \\ ___  ___| |_
 | |_ | '__/ _ \\ / _\` | |_) / _ \\/ __| __|
 |  _|| | | (_) | (_| |  __/ (_) \\__ \\ |_
 |_|  |_|  \\___/ \\__, |_|   \\___/|___/\\__|
                 |___/
\n`);
    log.info('Initializing dashboard...');
    localStorage.clear();
    sessionStorage.clear();
    log.info('All Storage cleared!');
}

function toggleDebugMode() {
    debugMode = !debugMode;
    log.info(`Debug mode ${debugMode ? 'enabled' : 'disabled'}`);
    const debugButton = document.getElementById('debugToggle');
    if (debugButton) {
        debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF';
        debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off';
    }
    return debugMode;
}

let debugMode = false;
const messages = [];
let activeEndpoint = null;
const buttonStates = new Map();
const reportButtonStates = new Map();
const traceButtonStates = new Map();
let callbackUrl = null;
const CALLBACK_URL_STORAGE_KEY = 'callback_url';
let refreshInterval;
const modifiedEndpoints = new Map();
const launchInProgressEndpoints = new Set();
const connectionCache = new Map();

function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    const xssPatterns = [
        /<\s*script/i, /<\s*img[^>]+onerror/i, /javascript\s*:/i,
        /on\w+\s*=/i, /<\s*iframe/i, /<\s*svg[^>]+on\w+/i,
        /alert\s*\(/i, /console\.log\s*\(/i, /eval\s*\(/i,
        /Function\s*\(/i, /setTimeout\s*\(/i, /setInterval\s*\(/i,
        /document\.domain/i, /document\.location/i, /location\.href/i
    ];
    let containsXss = false;
    for (const pattern of xssPatterns) {
        if (pattern.test(str)) {
            containsXss = true;
            break;
        }
    }
    if (containsXss) {
        let sanitized = str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
        return `[SANITIZED PAYLOAD] ${sanitized}`;
    }
    return str;
}

function getBaseUrl(url) {
    try {
        const norm = normalizeEndpointUrl(url);
        return norm?.components ? norm.components.origin + norm.components.path : null;
    } catch (e) {
        log.debug(`[Get Base URL] Error getting base URL for: ${url}`, e.message);
        return null;
    }
}


function sanitizeMessageData(data) {
    if (!data) return data;
    if (typeof data === 'string') {
        try {
            const parsed = JSON.parse(data);
            return sanitizeMessageData(parsed);
        } catch (e) {
            return sanitizeString(data);
        }
    }
    if (Array.isArray(data)) {
        return data.map(item => sanitizeMessageData(item));
    }
    if (typeof data === 'object' && data !== null) {
        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            sanitized[key] = sanitizeMessageData(value);
        }
        return sanitized;
    }
    return data;
}

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function normalizeEndpointUrl(url) {
    try {
        if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) {
            return { normalized: url, components: null, key: url };
        }
        let absoluteUrlStr = url;
        if (!url.includes('://') && !url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }
        else if (url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }
        const urlObj = new URL(absoluteUrlStr);
        if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:', 'blob:', 'data:'].includes(urlObj.protocol)) {
            return { normalized: url, components: null, key: url };
        }
        const key = urlObj.origin + urlObj.pathname + urlObj.search;
        const normalized = key;
        return {
            normalized: normalized,
            components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash },
            key: key
        };
    } catch (e) {
        log.debug(`[Normalize URL] Error: ${e.message}`, url);
        return { normalized: url, components: null, key: url };
    }
}

function getStorageKeyForUrl(url) {
    return normalizeEndpointUrl(url)?.key || url;
}

function addFrameConnection(originUrl, destinationUrl, targetMap) {
    const originInfo = normalizeEndpointUrl(originUrl);
    const destInfo = normalizeEndpointUrl(destinationUrl);
    const originKey = originInfo?.key; // Use key
    const destKey = destInfo?.key; // Use key

    if (!originKey || !destKey || originKey === destKey || originKey === 'null' || destKey === 'null' || originKey === 'access-denied-or-invalid' || destKey === 'access-denied-or-invalid') {
        return false;
    }

    let addedNew = false;
    if (!targetMap.has(originKey)) {
        targetMap.set(originKey, new Set());
        addedNew = true;
    }
    const destSet = targetMap.get(originKey);
    if (!destSet.has(destKey)) {
        destSet.add(destKey);
        addedNew = true;
    }
    return addedNew;
}

function updateButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint'));
    if (endpointKey) {
        buttonStates.set(endpointKey, { state, options });
    }

    const states = {
        start: { text: '▶', title: 'Start checks', class: 'default' },
        csp: { text: '⏳', title: 'Checking CSP...', class: 'checking is-working' },
        analyze: { text: '⏳', title: 'Analyzing...', class: 'checking is-working' },
        launch: { text: '🚀', title: 'Launch Payload Testing', class: 'green' },
        success: { text: '✓', title: 'Check successful', class: 'success' },
        warning: { text: '⚠', title: 'No handler found', class: 'yellow' },
        error: { text: '✕', title: 'Check failed', class: 'red' }
    };
    let newState = states[state] || states.start;

    button.textContent = newState.text;
    button.title = newState.title;
    button.classList.remove('default', 'checking', 'is-working', 'green', 'success', 'yellow', 'red', 'has-critical-sinks', 'show-next-step-arrow', 'show-next-step-emoji');
    button.classList.add(...newState.class.split(' '));
    button.style.animation = '';

    if (newState.class.includes('is-working')) button.classList.add('is-working');
    if (state === 'launch' && options.hasCriticalSinks) {
        button.classList.add('has-critical-sinks');
        button.title += ' (Critical Sinks Found!)';
    }
    if (options.showArrow) button.classList.add('show-next-step-arrow');
    if (options.showEmoji) button.classList.add('show-next-step-emoji');
}


function updateTraceButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint'));
    if (endpointKey) {
        traceButtonStates.set(endpointKey, { state, options });
    }

    const states = {
        default: { text: '✨', title: 'Start message tracing', class: 'default' },
        disabled: { text: '✨', title: 'Start message tracing (disabled)', class: 'disabled' },
        checking: { text: '⏳', title: 'Tracing in progress...', class: 'checking is-working' },
        success: { text: '✨', title: 'Trace completed', class: 'green' },
        error: { text: '❌', title: 'Tracing failed', class: 'error' }
    };

    const newState = states[state] || states.disabled;
    button.textContent = newState.text;
    button.title = newState.title;

    const classesToRemove = ['default', 'disabled', 'checking', 'is-working', 'green', 'error', 'show-next-step-emoji', 'highlight-next-step'];
    button.classList.remove(...classesToRemove);
    button.classList.add('iframe-trace-button'); // Ensure base class remains
    button.classList.add(...newState.class.split(' ')); // Add new state classes

    button.style.animation = '';

    if (newState.class.includes('is-working')) {
        button.classList.add('is-working');
    }

    if (options?.showEmoji) {
        button.classList.add('show-next-step-emoji');
    }

    if (state === 'disabled') {
        button.setAttribute('disabled', 'true');
        button.classList.add('disabled');
    } else {
        button.removeAttribute('disabled');
    }
}

function updateReportButton(button, state, endpoint) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(endpoint);

    const states = {
        disabled: { text: '📋', title: 'Analysis Report (disabled)', className: 'iframe-report-button disabled' },
        default: { text: '📋', title: 'View Analysis Report', className: 'iframe-report-button default' },
        green: { text: '📋', title: 'View Analysis Report (Findings)', className: 'iframe-report-button green' }
    };
    const newState = states[state] || states.disabled;
    button.textContent = newState.text;
    button.title = newState.title;
    button.className = newState.className; // Use className directly for report button simpler states

    if (endpointKey) {
        reportButtonStates.set(endpointKey, state);
    }
}

function originMatchesSource(currentOrigin, source, endpointOrigin) {
    if (source === '*') {
        return true;
    }
    if (source === "'self'") {
        // 'self' requires the current origin to match the endpoint's origin
        return endpointOrigin !== null && currentOrigin === endpointOrigin;
    }
    if (source === "'none'") {
        return false;
    }
    const cleanCurrentOrigin = currentOrigin.endsWith('/') ? currentOrigin.slice(0, -1) : currentOrigin;
    const cleanSource = source.endsWith('/') ? source.slice(0, -1) : source;

    // Exact origin match (e.g., https://example.com)
    if (cleanCurrentOrigin === cleanSource) {
        return true;
    }
    if (cleanSource.startsWith('*.')) {
        const domainPart = cleanSource.substring(2); // Get 'domain.com'
        // Check if origin ends with '.domain.com' and is not just 'domain.com' itself
        // Ensure there's something before the matched part (e.g., 'www.' in 'www.domain.com')
        return cleanCurrentOrigin.endsWith('.' + domainPart) && cleanCurrentOrigin.length > (domainPart.length + 1);
    }

    return false;
}

async function performEmbeddingCheck(endpoint) {
    log.debug(`[Embedding Check] Starting for: ${endpoint}`); // Added debug log
    try {
        const response = await fetch(endpoint, { method: 'HEAD', cache: 'no-store' });
        log.debug(`[Embedding Check] HEAD request status: ${response.status}`); // Added debug log

        // --- Check X-Frame-Options ---
        const xFrameOptions = response.headers.get('X-Frame-Options');
        if (xFrameOptions) {
            log.debug(`[Embedding Check] Found X-Frame-Options: ${xFrameOptions}`); // Added debug log
            const xfoUpper = xFrameOptions.toUpperCase();
            if (xfoUpper === 'DENY') {
                const reason = `X-Frame-Options: ${xFrameOptions}`;
                log.warning(`[Embedding Check] Blocked by ${reason}`);
                return { status: reason, className: 'red', embeddable: false };
            }
            if (xfoUpper === 'SAMEORIGIN') {
                // Check if current origin matches the endpoint's origin
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try { endpointOrigin = new URL(endpoint).origin; } catch(e) { /* ignore */ }

                if (!endpointOrigin || currentOrigin !== endpointOrigin) {
                    const reason = `X-Frame-Options: ${xFrameOptions} (Origin mismatch: ${currentOrigin} vs ${endpointOrigin || 'invalid'})`;
                    log.warning(`[Embedding Check] Blocked by ${reason}`);
                    return { status: reason, className: 'red', embeddable: false };
                }
            }
        }

        const csp = response.headers.get('Content-Security-Policy');
        if (csp) {
            log.debug(`[Embedding Check] Found Content-Security-Policy header.`); // Added debug log
            const directives = csp.split(';').map(d => d.trim());
            const frameAncestors = directives.find(d => d.startsWith('frame-ancestors'));

            if (frameAncestors) {
                const sourcesString = frameAncestors.substring('frame-ancestors'.length).trim();
                const sources = sourcesString.split(/\s+/);
                log.debug(`[Embedding Check] Parsed frame-ancestors sources: [${sources.join(', ')}]`); // Added debug log

                if (sources.includes("'none'")) {
                    const reason = `CSP: frame-ancestors 'none'`;
                    log.warning(`[Embedding Check] Blocked by ${reason}`);
                    return { status: reason, className: 'red', embeddable: false };
                }
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try {
                    endpointOrigin = new URL(endpoint).origin;
                    log.debug(`[Embedding Check] Current Origin: ${currentOrigin}, Endpoint Origin: ${endpointOrigin}`);
                } catch(e) {
                    const reason = `Invalid endpoint URL for origin check: ${endpoint}`;
                    log.error(`[Embedding Check] Error: ${reason}`, e);
                    return { status: reason, className: 'red', embeddable: false };
                }

                let isAllowedByDirective = false;
                for (const source of sources) {
                    if (originMatchesSource(currentOrigin, source, endpointOrigin)) {
                        log.debug(`[Embedding Check] Origin ${currentOrigin} MATCHED source '${source}'`);
                        isAllowedByDirective = true;
                        break; // Found an allowing source, no need to check further
                    } else {
                        log.debug(`[Embedding Check] Origin ${currentOrigin} did NOT match source '${source}'`);
                    }
                }

                if (!isAllowedByDirective) {
                    const reason = `CSP: frame-ancestors does not allow ${currentOrigin}`;
                    log.warning(`[Embedding Check] Blocked by ${reason}. Allowed: [${sources.join(', ')}]`);
                    return { status: reason, className: 'red', embeddable: false };
                }
                // If loop finishes and isAllowedByDirective is true, embedding is permitted by CSP
                log.debug(`[Embedding Check] Origin ${currentOrigin} was allowed by frame-ancestors directive.`);
            } else {
                log.debug(`[Embedding Check] No frame-ancestors directive found in CSP.`);
            }
        } else {
            log.debug(`[Embedding Check] No Content-Security-Policy header found.`);
        }

        log.success(`[Embedding Check] Frame can be embedded for ${endpoint}`);
        return { status: 'Frame can be embedded', className: 'green', embeddable: true };

    } catch (error) {
        log.error(`[Embedding Check] Header check failed for ${endpoint}: ${error.message}`, error);
        return { status: `Header check failed: ${error.message}`, className: 'red', embeddable: false };
    }
}


function getMessageCount(endpointKey) {
    return messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === endpointKey || destKey === endpointKey;
    }).length;
}

function createHostElement(hostKey, iframesSet) {
    const hostElement = document.createElement("div");
    hostElement.className = "endpoint-host";

    const hostRow = document.createElement("div");
    hostRow.className = "host-row";

    const hostName = document.createElement("span");
    hostName.className = "host-name";
    const hostMessageCount = getMessageCount(hostKey);
    hostName.textContent = hostMessageCount > 0 ? `${hostKey} (${hostMessageCount})` : hostKey;

    hostRow.addEventListener("click", (e) => {
        e.stopPropagation();
        activeEndpoint = hostKey; // Set active endpoint to the key
        renderMessages();
        highlightActiveEndpoint();
    });

    hostRow.appendChild(hostName);
    hostElement.appendChild(hostRow);

    const iframeContainer = document.createElement("div");
    iframeContainer.className = "iframe-container";

    iframesSet.forEach((iframeKey) => {
        const iframeRow = document.createElement("div");
        iframeRow.className = "iframe-row";
        iframeRow.setAttribute("data-endpoint-key", iframeKey); // Store key

        const iframeName = document.createElement("span");
        iframeName.className = "iframe-name";
        const iframeMessageCount = getMessageCount(iframeKey);
        iframeName.textContent = iframeMessageCount > 0 ? `${iframeKey} (${iframeMessageCount})` : iframeKey;

        iframeRow.addEventListener("click", (e) => {
            e.stopPropagation();
            activeEndpoint = iframeKey;
            renderMessages();
            highlightActiveEndpoint();
        });

        const iframeButtonContainer = createActionButtonContainer(iframeKey); // Create buttons based on key
        iframeRow.appendChild(iframeName);
        iframeRow.appendChild(iframeButtonContainer);
        iframeContainer.appendChild(iframeRow);
    });

    if (iframesSet.size > 0) {
        hostElement.appendChild(iframeContainer);
    }
    return hostElement;
}

function createActionButtonContainer(endpointKey) {
    const buttonContainer = document.createElement("div");
    buttonContainer.className = "button-container";

    const playButton = document.createElement("button");
    playButton.className = "iframe-check-button default";
    playButton.setAttribute("data-endpoint", endpointKey); // Use the key
    playButton.textContent = '▶';
    playButton.title = 'Start checks';

    const traceButton = document.createElement("button");
    traceButton.className = "iframe-trace-button disabled";
    traceButton.setAttribute("data-endpoint", endpointKey); // Use the key
    traceButton.textContent = '✨'; // Using Sparkles emoji
    traceButton.title = 'Start message tracing (disabled)';
    traceButton.setAttribute('disabled', 'true');

    const reportButton = document.createElement("button");
    reportButton.className = "iframe-report-button disabled";
    reportButton.setAttribute("data-endpoint", endpointKey); // Use the key
    reportButton.textContent = '📋';
    reportButton.title = 'Analysis Report (disabled)';

    const savedPlayStateInfo = buttonStates.get(endpointKey);
    if (savedPlayStateInfo) {
        updateButton(playButton, savedPlayStateInfo.state, savedPlayStateInfo.options);
    } else {
        updateButton(playButton, 'start'); // Default state
    }

    const savedTraceStateInfo = traceButtonStates.get(endpointKey);
    if (savedTraceStateInfo) {
        updateTraceButton(traceButton, savedTraceStateInfo.state, savedTraceStateInfo.options);
    } else {
        if (playButton.classList.contains('success') || playButton.classList.contains('green')) {
            updateTraceButton(traceButton, 'default'); // Enable it
        } else {
            updateTraceButton(traceButton, 'disabled'); // Keep disabled otherwise
        }
    }

    const savedReportStateInfo = reportButtonStates.get(endpointKey);
    if (savedReportStateInfo) {
        updateReportButton(reportButton, savedReportStateInfo, endpointKey);
    } else {
        if (traceButton.classList.contains('green')) {
            updateReportButton(reportButton, 'default', endpointKey); // Enable it (no findings initially)
        } else {
            updateReportButton(reportButton, 'disabled', endpointKey); // Keep disabled
        }
    }

    playButton.addEventListener("click", async (e) => {
        e.stopPropagation();
        await handlePlayButton(endpointKey, playButton);
    });

    traceButton.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) {
            await handleTraceButton(endpointKey, traceButton);
        }
    });

    reportButton.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!reportButton.classList.contains('disabled')) {
            await handleReportButton(endpointKey);
        }
    });

    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(reportButton);
    return buttonContainer;
}


function renderEndpoints(filter = "") {
    const endpointsList = document.getElementById("endpointsList");
    if (!endpointsList) {
        return;
    }
    const currentFrameConnections = new Map();
    messages.forEach(msg => {
        if (msg.origin && msg.destinationUrl) {
            addFrameConnection(msg.origin, msg.destinationUrl, currentFrameConnections);
        }
    });

    if (currentFrameConnections.size === 0) {
        endpointsList.innerHTML = "<div class='no-endpoints'>No hosts or iframes detected or no communication captured yet.</div>";
        return;
    }

    endpointsList.innerHTML = "";
    let hostCount = 0;

    currentFrameConnections.forEach((iframesSet, hostKey) => {
        // Filter based on the key
        if (filter && !hostKey.toLowerCase().includes(filter.toLowerCase())) {
            return;
        }
        try {
            const hostElement = createHostElement(hostKey, iframesSet);
            if (hostElement) {
                endpointsList.appendChild(hostElement);
                hostCount++;
            }
        } catch (e) {
            // Log error internally if needed, but avoid console
        }
    });

    if (hostCount === 0 && filter) {
        endpointsList.innerHTML = `<div class='no-endpoints'>No endpoints match filter "${filter}".</div>`;
    } else if (hostCount === 0) {
        endpointsList.innerHTML = "<div class='no-endpoints'>Error: Connections found but failed to render hosts.</div>";
    }

    highlightActiveEndpoint();
}


async function sendMessageTo(targetKey, button) {
    // Sends message to the targetKey (which is the normalized URL key)
    try {
        const messageItem = button.closest('.message-item');
        if (!messageItem) return false;
        const messageDataElement = messageItem.querySelector('.message-data');
        if (!messageDataElement) return false;

        const messageContent = messageDataElement.textContent;
        let data;
        try { data = JSON.parse(messageContent); } catch (e) { data = messageContent; }

        if (targetKey.startsWith('chrome-extension://')) {
            // This case needs careful handling - targetKey might not be the full ext URL
            // Consider storing original full URL alongside the key if needed here
            // chrome.runtime.sendMessage({ action: "forwardPostMessage", data: data, targetUrl: targetKey });
            // Simplified for now, may need adjustment based on exact requirements
        } else {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
            iframe.src = targetKey; // Use the key directly as src - might need adjustment if hash was important

            await new Promise((resolve) => {
                iframe.onload = resolve;
                iframe.onerror = resolve; // Resolve on error too
                setTimeout(resolve, 3000); // Timeout
            });

            if (iframe.contentWindow) {
                iframe.contentWindow.postMessage(data, '*');
            } else {
                throw new Error("Iframe content window not accessible");
            }

            setTimeout(() => {
                if (document.body.contains(iframe)) {
                    document.body.removeChild(iframe);
                }
            }, 1000);
        }

        button.classList.add('success');
        setTimeout(() => button.classList.remove('success'), 1000);
        return true;
    } catch (error) {
        button.classList.add('error');
        setTimeout(() => button.classList.remove('error'), 1000);
        return false;
    }
}

function escapeHTML(str) {
    if (str === undefined || str === null) return '';
    str = String(str);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


function renderMessages() {
    const messagesList = document.getElementById("messagesList");
    if (!messagesList) return;
    messagesList.innerHTML = "";

    if (!activeEndpoint) {
        messagesList.innerHTML = "<div class='no-messages'>Select a host or iframe to view messages.</div>";
        return;
    }

    const relevantMessages = messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === activeEndpoint || destKey === activeEndpoint;
    });

    if (relevantMessages.length === 0) {
        messagesList.innerHTML = "<div class='no-messages'>No messages captured involving this endpoint.</div>";
        return;
    }

    const sortedMessages = [...relevantMessages].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    sortedMessages.forEach((msg) => {
        try {
            const messageItem = document.createElement("div");
            messageItem.className = "message-item";

            const sanitizedData = sanitizeMessageData(msg.data);
            let formattedData;
            try { formattedData = typeof sanitizedData === 'string' ? sanitizedData : JSON.stringify(sanitizedData, null, 2); }
            catch (e) { formattedData = String(sanitizedData); }

            const header = document.createElement("div");
            header.className = "message-header";
            // Use normalized display URLs, but store original for sending?
            const originDisplay = normalizeEndpointUrl(msg.origin)?.normalized || msg.origin || '?';
            const destDisplay = normalizeEndpointUrl(msg.destinationUrl)?.normalized || msg.destinationUrl || '?';
            header.innerHTML = `<strong>Origin:</strong> ${escapeHTML(originDisplay)}<br><strong>Destination:</strong> ${escapeHTML(destDisplay)}<br><strong>Time:</strong> ${new Date(msg.timestamp).toLocaleString()}<br><strong>Msg Type:</strong> <span class="message-type message-type-${(msg.messageType || 'unknown').replace(/\s+/g, '-').toLowerCase()}">${escapeHTML(msg.messageType || '?')}</span>`;

            const dataPre = document.createElement("pre");
            dataPre.className = "message-data";
            dataPre.textContent = formattedData;
            dataPre.contentEditable = "true";

            const controls = document.createElement("div");
            controls.className = "message-controls";

            const originBtn = document.createElement("button");
            originBtn.className = "send-origin";
            originBtn.textContent = "→ Send to Origin";
            const originKey = getStorageKeyForUrl(msg.origin); // Get key for sending
            originBtn.addEventListener('click', () => sendMessageTo(originKey, originBtn));

            const destBtn = document.createElement("button");
            destBtn.className = "send-destination";
            destBtn.textContent = "→ Send to Destination";
            const destKey = getStorageKeyForUrl(msg.destinationUrl); // Get key for sending
            destBtn.addEventListener('click', () => sendMessageTo(destKey, destBtn));

            controls.appendChild(originBtn);
            controls.appendChild(destBtn);
            messageItem.appendChild(header);
            messageItem.appendChild(dataPre);
            messageItem.appendChild(controls);
            messagesList.appendChild(messageItem);
        } catch (e) {
        }
    });
}


function highlightActiveEndpoint() {
    document.querySelectorAll('.endpoint-host, .iframe-row').forEach(el => {
        el.classList.remove('active');
    });
    if (activeEndpoint) { // activeEndpoint is the key
        document.querySelectorAll('.host-row, .iframe-row').forEach(el => {
            if (el.classList.contains('host-row')) {
                const hostNameSpan = el.querySelector('.host-name');
                const textContent = hostNameSpan?.textContent || '';
                const keyFromText = textContent.includes(' (') ? textContent.substring(0, textContent.lastIndexOf(' (')) : textContent;
                if(keyFromText === activeEndpoint) {
                    el.closest('.endpoint-host').classList.add('active'); // Highlight parent host div
                }
            } else if (el.classList.contains('iframe-row')) {
                if(el.getAttribute('data-endpoint-key') === activeEndpoint) {
                    el.classList.add('active');
                }
            }
        });
    }
}


function updateDashboardUI() {

    renderEndpoints(); // Rebuilds endpoint list, applies stored button states
    renderMessages(); // Re-renders messages for the active endpoint
    updateEndpointCounts(); // Update counts displayed
    highlightActiveEndpoint(); // Ensure active selection is visually correct
}

function startAutoRefresh() {
    // Placeholder for potential future auto-refresh logic if needed
    // For now, UI updates are driven by messages from background script
}

function updateEndpointCounts() {
    try {
        const endpointElements = document.querySelectorAll('.host-name, .iframe-name');
        endpointElements.forEach(el => {
            const fullText = el.textContent || '';
            const keyText = fullText.includes(' (') ? fullText.substring(0, fullText.lastIndexOf(' (')) : fullText;
            if (!keyText) return;

            const count = getMessageCount(keyText); // Use the key directly
            el.textContent = `${keyText} (${count})`;
        });
    } catch (e) {
        // Handle error silently
    }
}

function initializeMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message || !message.type) return false;

        let needsUiUpdate = false;

        try {
            if (message.type === "newPostMessage" && message.payload) {
                const newMsg = message.payload;
                const existingIndex = messages.findIndex(m => m.messageId === newMsg.messageId);
                if (existingIndex >= 0) { messages[existingIndex] = newMsg; } else { messages.push(newMsg); }
                needsUiUpdate = true;
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "newFrameConnection") {
                needsUiUpdate = true; // Need to redraw endpoints if connections change
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "updateMessages" && message.messages) {
                messages.length = 0; messages.push(...message.messages);
                needsUiUpdate = true;
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "forwardedPostMessage") {
                if (sendResponse) sendResponse({ success: true });
            }

            if (needsUiUpdate) {
                requestAnimationFrame(updateDashboardUI);
            }

        } catch (e) {
            if (sendResponse) try { sendResponse({ success: false, error: e.message }); } catch (respErr) {}
        }
        return false;
    });

    window.traceReportStorage.listAllReports().then(() => {
        chrome.runtime.sendMessage({ type: "fetchMessages" }, (response) => {
            if (chrome.runtime.lastError) { return; }
            if (response?.newMessages) {
                messages.length = 0;
                messages.push(...response.newMessages);
            }
            updateDashboardUI();
        });
    });
}


function setupCallbackUrl() {
    const urlInput = document.getElementById('callbackUrlInput');
    const saveButton = document.getElementById('saveCallbackUrl');
    const statusElement = document.getElementById('callback-status');

    if (!urlInput || !saveButton || !statusElement) {
        log.error("Callback URL UI elements not found.");
        return;
    }

    chrome.storage.local.get([CALLBACK_URL_STORAGE_KEY], (result) => {
        const storedUrl = result[CALLBACK_URL_STORAGE_KEY] || null;
        if (storedUrl) {
            urlInput.value = storedUrl;
            window.frogPostState.callbackUrl = storedUrl; // Update global state
            updateCallbackStatus(storedUrl);
            log.info(`[Callback URL] Loaded from storage: ${storedUrl}`);
        } else {
            window.frogPostState.callbackUrl = null;
            updateCallbackStatus(null); // Ensure status is clear if no URL
        }
    });

    saveButton.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url) {
            chrome.storage.local.remove(CALLBACK_URL_STORAGE_KEY, () => {
                if (chrome.runtime.lastError) {
                    updateCallbackStatus(null, `Error clearing URL: ${chrome.runtime.lastError.message}`);
                    log.error("[Callback URL] Error clearing:", chrome.runtime.lastError);
                } else {
                    window.frogPostState.callbackUrl = null;
                    updateCallbackStatus(null);
                    log.info(`[Callback URL] Cleared.`);
                }
            });
        } else if (isValidUrl(url)) {
            chrome.storage.local.set({
                [CALLBACK_URL_STORAGE_KEY]: url
            }, () => {
                if (chrome.runtime.lastError) {
                    updateCallbackStatus(window.frogPostState.callbackUrl, `Error saving URL: ${chrome.runtime.lastError.message}`);
                    log.error("[Callback URL] Error saving:", chrome.runtime.lastError);
                } else {
                    window.frogPostState.callbackUrl = url;
                    updateCallbackStatus(url);
                    log.info(`[Callback URL] Saved: ${url}`);
                }
            });
        } else {
            // Show error for invalid URL
            updateCallbackStatus(window.frogPostState.callbackUrl, 'Please enter a valid URL (e.g., https://...).');
        }
    });

    function updateCallbackStatus(url, errorMessage = null) {
        if (!statusElement) return;

        statusElement.innerHTML = '';
        statusElement.className = 'callback-status';
        if (errorMessage) {
            statusElement.innerHTML = `<div class="error-message">${escapeHTML(errorMessage)}</div>`;
            statusElement.classList.add('callback-status-error');

        } else if (url) {
            statusElement.innerHTML = `
                <div class="success-icon">✓</div>
                <div class="status-message">Active: <span class="url-value">${escapeHTML(url)}</span></div>
            `;
            statusElement.classList.add('callback-status-success');
        } else {
            statusElement.innerHTML = `<div class="info-message">No callback URL set.</div>`; // Indicate no URL is set
            statusElement.classList.add('callback-status-info'); // Optional class for neutral state
        }
    }
}

function setupUIControls() {
    const clearMessagesButton = document.getElementById("clearMessages");
    const exportMessagesButton = document.getElementById("exportMessages");
    const checkAllButton = document.getElementById("checkAll");
    const debugButton = document.getElementById("debugToggle");
    const refreshMessagesButton = document.getElementById("refreshMessages");

    if (refreshMessagesButton) {
        refreshMessagesButton.addEventListener("click", () => {
            chrome.runtime.sendMessage({ type: "fetchMessages" }, (response) => {
                if (response && response.newMessages) {
                    messages.length = 0;
                    messages.push(...response.newMessages);
                    renderEndpoints();
                    renderMessages();
                }
            });
        });
    }

    if (clearMessagesButton) {
        clearMessagesButton.addEventListener("click", () => {
            messages.length = 0;
            window.frogPostState.frameConnections.clear(); // Clear connections map too
            buttonStates.clear(); // Reset button states
            traceButtonStates.clear();
            reportButtonStates.clear();
            activeEndpoint = null; // Reset active endpoint
            chrome.runtime.sendMessage({ type: "resetState" }, () => {
                updateDashboardUI(); // Update UI after state reset
            });
        });
    }

    if (exportMessagesButton) {
        exportMessagesButton.addEventListener("click", () => {
            const sanitizedMessages = messages.map(msg => ({
                origin: msg.origin,
                destinationUrl: msg.destinationUrl,
                timestamp: msg.timestamp,
                data: sanitizeMessageData(msg.data),
                messageType: msg.messageType,
                messageId: msg.messageId
            }));
            const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "frogpost_messages.json";
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    if (checkAllButton) {
        checkAllButton.addEventListener("click", checkAllEndpoints);
    }

    if (debugButton) {
        debugButton.addEventListener("click", toggleDebugMode);
    }

    setupCallbackUrl();
}

async function launchFuzzerEnvironment(endpoint, testData) {
    try {
        console.log(`[Test Environment] Initializing fuzzer environment...`);
        let traceReport = null;
        const baseEndpoint = getBaseUrl(endpoint);
        const endpointKey = getStorageKeyForUrl(endpoint);

        try {
            traceReport = await window.traceReportStorage.getTraceReport(endpointKey);
            if (traceReport) {
                console.log(`[Test Environment] Found stored report using normalized key: ${endpointKey}`);
            } else {
                traceReport = await window.traceReportStorage.getTraceReport(endpoint);
                if (traceReport) {
                    console.log(`[Test Environment] Found stored report using exact URL: ${endpoint}`);
                } else {
                    const traceInfoKey = `trace-info-${endpointKey}`;
                    const traceInfo = await new Promise(resolve => {
                        chrome.storage.local.get([traceInfoKey], result => {
                            resolve(result[traceInfoKey]);
                        });
                    });

                    if (traceInfo?.analysisStorageKey) {
                        console.log(`[Test Environment] Trying to retrieve using analysis storage key from trace info: ${traceInfo.analysisStorageKey}`);
                        traceReport = await window.traceReportStorage.getTraceReport(traceInfo.analysisStorageKey);
                    }

                    if (!traceReport && traceInfo?.analyzedUrl) {
                        console.log(`[Test Environment] Trying to retrieve using analyzed URL from trace info: ${traceInfo.analyzedUrl}`);
                        traceReport = await window.traceReportStorage.getTraceReport(traceInfo.analyzedUrl);

                        if (!traceReport) {
                            const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                            console.log(`[Test Environment] Trying normalized analyzed URL: ${analyzedUrlKey}`);
                            traceReport = await window.traceReportStorage.getTraceReport(analyzedUrlKey);
                        }
                    }

                    if (!traceReport) {
                        const localReport = localStorage.getItem('traceReport');
                        if (localReport) {
                            traceReport = JSON.parse(localReport);
                            console.log(`[Test Environment] Found trace report in localStorage`);
                            await window.traceReportStorage.saveTraceReport(endpointKey, traceReport);
                        }
                    }
                }
            }
        } catch (e) { console.error('Error retrieving trace report:', e); }

        if (!traceReport) {
            throw new Error('No trace report found. Please run Play and Trace first.');
        }

        let handlerCode = '';
        if (testData && testData.handler) {
            handlerCode = testData.handler;
        } else if (traceReport && traceReport.bestHandler) {
            handlerCode = traceReport.bestHandler.handler || traceReport.bestHandler.code || '';
        } else if (traceReport && traceReport.analyzedHandler) {
            handlerCode = traceReport.analyzedHandler.code || '';
        } else {
            try {
                const bestHandlerKey = `best-handler-${endpointKey}`;
                const storedHandler = await new Promise(resolve => {
                    chrome.storage.local.get(bestHandlerKey, result => {
                        resolve(result[bestHandlerKey]);
                    });
                });

                if (storedHandler) {
                    handlerCode = storedHandler.handler || storedHandler.code || '';
                }

                if (!handlerCode) {
                    const traceInfoKey = `trace-info-${endpointKey}`;
                    const traceInfo = await new Promise(resolve => {
                        chrome.storage.local.get([traceInfoKey], result => {
                            resolve(result[traceInfoKey]);
                        });
                    });

                    if (traceInfo?.analysisStorageKey) {
                        const altHandlerKey = `best-handler-${traceInfo.analysisStorageKey}`;
                        const altHandler = await new Promise(resolve => {
                            chrome.storage.local.get(altHandlerKey, result => {
                                resolve(result[altHandlerKey]);
                            });
                        });
                        if (altHandler) {
                            handlerCode = altHandler.handler || altHandler.code || '';
                        }
                    }
                }
            } catch (e) { console.error('Error retrieving handler:', e); }
        }

        if (!handlerCode) {
            throw new Error('No handler code found. Please run Play first.');
        }

        let messages = [];
        if (testData && testData.originalMessages) {
            messages = testData.originalMessages;
        } else {
            messages = await retrieveMessagesWithFallbacks(endpointKey);
            if (messages.length === 0) {
                throw new Error('No messages found. Please run Play first to capture messages.');
            }
            console.log(`[Test Environment] Retrieved ${messages.length} messages after fallbacks`);
        }

        let payloads = [];
        if (testData && testData.payloads && testData.payloads.length > 0) {
            payloads = testData.payloads;
        } else if (traceReport && traceReport.details && traceReport.details.payloads && traceReport.details.payloads.length > 0) {
            payloads = traceReport.details.payloads;
        } else if (traceReport && traceReport.payloads && traceReport.payloads.length > 0) {
            payloads = traceReport.payloads;
        } else {
            try {
                payloads = await window.traceReportStorage.getReportPayloads(endpointKey);
                if (!payloads || payloads.length === 0) {
                    payloads = await window.traceReportStorage.getReportPayloads(endpoint);
                }

                if (!payloads || payloads.length === 0) {
                    const traceInfoKey = `trace-info-${endpointKey}`;
                    const traceInfo = await new Promise(resolve => {
                        chrome.storage.local.get([traceInfoKey], result => {
                            resolve(result[traceInfoKey]);
                        });
                    });

                    if (traceInfo?.analysisStorageKey) {
                        payloads = await window.traceReportStorage.getReportPayloads(traceInfo.analysisStorageKey);
                    }

                    if ((!payloads || payloads.length === 0) && traceInfo?.analyzedUrl) {
                        payloads = await window.traceReportStorage.getReportPayloads(traceInfo.analyzedUrl);

                        if (!payloads || payloads.length === 0) {
                            const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                            payloads = await window.traceReportStorage.getReportPayloads(analyzedUrlKey);
                        }
                    }
                }
            } catch (e) {
                console.error('Error retrieving payloads:', e);
            }

            if (!payloads || payloads.length === 0) {
                throw new Error('No payloads found in the trace report. Please run Trace again.');
            }
        }

        let vulnerabilities = [];
        if (traceReport && traceReport.details && traceReport.details.sinks) {
            vulnerabilities = traceReport.details.sinks;
        } else if (traceReport && traceReport.vulnerabilities) {
            vulnerabilities = traceReport.vulnerabilities;
        }

        const payloadSize = JSON.stringify(payloads).length;
        if (payloadSize > 5000000) {
            console.warn(`[Test Environment] Payload size (${payloadSize} bytes) is too large, reducing to first 100 payloads`);
            payloads = payloads.slice(0, 100);
        }

        console.log("Starting fuzzer server...");
        await chrome.runtime.sendMessage({ action: "startServer" });
        await new Promise(resolve => setTimeout(resolve, 2000));

        let serverStarted = false;
        let attempts = 0;
        const maxAttempts = 5;

        while (!serverStarted && attempts < maxAttempts) {
            attempts++;
            try {
                console.log(`Checking server health (attempt ${attempts}/${maxAttempts})...`);
                const health = await fetch('http://127.0.0.1:1337/health', {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
                    cache: 'no-store'
                });
                if (health.ok) {
                    serverStarted = true;
                    break;
                }
            } catch (e) {
                console.warn(`Server health check failed: ${e.message}`);
                await new Promise(r => setTimeout(r, 1000));
            }
        }

        if (!serverStarted) {
            throw new Error("Failed to start fuzzer server after multiple attempts");
        }

        const storageData = await chrome.storage.local.get(['callback_url', 'session_callback_url']);
        const currentCallbackUrl = storageData['callback_url'] || storageData['session_callback_url'] || null;

        if (currentCallbackUrl) {
            console.log(`Using callback URL: ${currentCallbackUrl}`);
        } else {
            console.log("No callback URL configured");
        }

        const config = {
            target: endpoint,
            messages: messages,
            handler: handlerCode,
            sinks: vulnerabilities,
            payloads: payloads,
            traceData: traceReport ? {
                vulnerabilities: traceReport.vulnerabilities || traceReport.details?.sinks || [],
                dataFlows: traceReport.details?.dataFlows || [],
                securityIssues: traceReport.securityIssues || traceReport.details?.securityIssues || [],
                payloads: payloads
            } : null,
            callbackUrl: currentCallbackUrl,
            fuzzerOptions: {
                skipInitialLoad: false,
                ignoreCSP: true,
                timeout: 10000,
                autoStart: true,
                useAdditionalPayloads: true,
                payloadTypes: {
                    xss: true,
                    dom: true,
                    postMessage: true,
                    prototype: true,
                    custom: true
                }
            }
        };

        console.log("Sending configuration to fuzzer server...:", config);
        const response = await fetch('http://127.0.0.1:1337/current-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config),
            signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
            throw new Error(`Config update failed: ${response.statusText}`);
        }

        console.log("Opening fuzzer in new tab...");
        const tab = await chrome.tabs.create({ url: 'http://127.0.0.1:1337/' });

        await new Promise(resolve => {
            let tabLoaded = false;
            chrome.tabs.onUpdated.addListener(function listener(tabId, info) {
                if (tabId === tab.id && info.status === 'complete') {
                    chrome.tabs.onUpdated.removeListener(listener);
                    tabLoaded = true;
                    chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        func: (callbackUrl) => {
                            window.postMessage({
                                type: "serverReady",
                                autoStart: true,
                                callbackUrl: callbackUrl
                            }, "*");
                        },
                        args: [currentCallbackUrl]
                    })
                        .then(() => {
                            console.log("Initialization script injected with callback URL");
                            resolve();
                        })
                        .catch(err => {
                            console.error("Script injection failed:", err);
                            resolve();
                        });
                }
            });

            setTimeout(() => {
                if (!tabLoaded) {
                    console.warn("Tab load timeout occurred, continuing anyway");
                    resolve();
                }
            }, 10000);
        });

        chrome.tabs.onRemoved.addListener(function cleanup(tabId) {
            if (tabId === tab.id) {
                console.log("Fuzzer tab closed, stopping server");
                chrome.runtime.sendMessage({ action: "stopServer" });
                chrome.tabs.onRemoved.removeListener(cleanup);
            }
        });

        return true;
    } catch (error) {
        console.error("Fuzzer launch failed:", error.message);
        alert(`Failed to launch fuzzer: ${error.message}\n\nPlease check if the fuzzer server component is installed and running.`);
        try {
            await chrome.runtime.sendMessage({ action: "stopServer" });
            console.log("Attempted to stop server after error");
        }
        catch (e) {
            console.error("Failed to stop server:", e.message);
        }
        return false;
    }
}

function showQueryModal(endpoint) {
    return new Promise((resolve) => {
        try {
            log.debug(`[Query Modal] Opening for endpoint: ${endpoint}`);
            const originalUrl = new URL(endpoint);
            const currentParams = new URLSearchParams(originalUrl.search);

            const modalContainer = document.getElementById('queryModalContainer');
            if (!modalContainer) {
                log.error("[Query Modal] Container element 'queryModalContainer' not found.");
                resolve({ url: endpoint, modified: false, cancelled: true }); // Cancel if container missing
                return;
            }
            modalContainer.innerHTML = ''; // Clear previous modal

            const modal = document.createElement('div');
            modal.className = 'query-modal';

            let modalContentHTML = `<h2 class="query-modal-title">Modify Query Parameters</h2><div class="query-modal-body">`;
            let paramCount = 0;

            currentParams.forEach((value, key) => {
                paramCount++;
                modalContentHTML += `<div class="query-param-row">
                                       <label class="query-param-label">${escapeHTML(key)}:</label>
                                       <input type="text" class="query-param-input" value="${escapeHTML(value)}" data-param="${escapeHTML(key)}">
                                    </div>`;
            });

            if (paramCount === 0) {
                modalContentHTML += '<p class="query-modal-no-params">No query parameters found in URL.</p>';
            }

            modalContentHTML += `</div><div class="query-modal-footer">
                                    <button id="cancelBtn" class="control-button secondary-button">Cancel</button>
                                    <button id="okBtn" class="control-button primary-button">OK</button>
                                </div>`;

            modal.innerHTML = modalContentHTML;

            const backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop';

            // Function to close modal
            const closeModal = (result) => {
                modal.remove();
                backdrop.remove();
                resolve(result);
            };


            modalContainer.appendChild(backdrop);
            modalContainer.appendChild(modal);

            modal.querySelector('#okBtn').addEventListener('click', () => {
                const inputs = modal.querySelectorAll('input.query-param-input');
                const modifiedUrl = new URL(endpoint);
                modifiedUrl.search = ''; // Clear existing params first

                inputs.forEach(input => {
                    const param = input.dataset.param;
                    const value = input.value; // Keep original value, don't trim yet
                    modifiedUrl.searchParams.set(param, value);
                });

                log.debug(`[Query Modal] OK clicked. Modified URL: ${modifiedUrl.toString()}`);
                closeModal({ url: modifiedUrl.toString(), modified: true, originalUrl: endpoint });
            });

            modal.querySelector('#cancelBtn').addEventListener('click', () => {
                log.debug(`[Query Modal] Cancel clicked.`);
                closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint });
            });

            backdrop.addEventListener('click', () => { // Close on backdrop click
                log.debug(`[Query Modal] Backdrop clicked.`);
                closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint });
            });


        } catch (error) {
            log.error('[Query Modal] Error:', error);
            resolve({ url: endpoint, modified: false, originalUrl: endpoint }); // Resolve with original on error
        }
    });
}


async function saveRandomPostMessages(endpointKey) {
    // Accepts the storage key directly
    const MAX_MESSAGES = 20;
    let relevantMessages = messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === endpointKey || destKey === endpointKey;
    });

    relevantMessages = relevantMessages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, MAX_MESSAGES);

    const processedMessages = relevantMessages.map(msg => {
        if (!msg.messageType) {
            let messageType = 'unknown';
            let data = msg.data;
            if (data === undefined || data === null) messageType = 'null_or_undefined';
            else if (typeof data === 'string') { try { JSON.parse(data); messageType = 'json_string'; } catch (e) { messageType = 'string'; } }
            else if (Array.isArray(data)) messageType = 'array';
            else if (typeof data === 'object') messageType = 'object';
            else messageType = typeof data;
            return {...msg, messageType: messageType};
        }
        return msg;
    });

    const storageKey = `saved-messages-${endpointKey}`;
    try {
        await chrome.storage.local.set({ [storageKey]: processedMessages });
        return processedMessages;
    } catch (error) {
        try { await chrome.storage.local.remove(storageKey); } catch (removeError) {}
        return [];
    }
}

async function retrieveMessagesWithFallbacks(endpointKey) {
    // Accepts the storage key directly
    const primaryStorageKey = `saved-messages-${endpointKey}`;
    try {
        const primaryResult = await new Promise(resolve => {
            chrome.storage.local.get([primaryStorageKey], result => {
                resolve(result[primaryStorageKey] || null);
            });
        });
        if (primaryResult?.length > 0) {
            return primaryResult;
        }
    } catch(e) { /* ignore storage errors */ }
    return [];
}

async function handlePlayButton(endpoint, button, skipCheck = false) {
    const originalFullEndpoint = endpoint;
    const endpointKey = getStorageKeyForUrl(originalFullEndpoint);

    const currentButtonContainer = button.closest('.button-container');
    const traceButton = currentButtonContainer?.querySelector('.iframe-trace-button');
    const reportButton = currentButtonContainer?.querySelector('.iframe-report-button');

    button.classList.remove('show-next-step-emoji', 'show-next-step-arrow');
    if (traceButton) traceButton.classList.remove('show-next-step-emoji');

    if (button.classList.contains('has-critical-sinks') || button.textContent === '🚀') {
        if (launchInProgressEndpoints.has(endpointKey)) {
            log.debug(`Launch already in progress for key: ${endpointKey}`);
            return;
        }
        launchInProgressEndpoints.add(endpointKey);
        log.scan(`Starting launch for endpoint represented by key: ${endpointKey}`);

        try {
            const traceInfoKey = `trace-info-${endpointKey}`;
            const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
            const traceInfo = traceInfoResult[traceInfoKey];

            if (!traceInfo?.success || !traceInfo?.analyzedUrl) {
                throw new Error(`Trace info/analyzedUrl not found for key ${traceInfoKey}. Run Trace again.`);
            }

            const endpointKeyForReport = traceInfo.analyzedUrl;
            log.debug(`[Launch] Using effective endpoint key from trace info for fetching report/payloads: ${endpointKeyForReport}`);

            const [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(endpointKeyForReport),
                window.traceReportStorage.getReportPayloads(endpointKeyForReport)
            ]);

            if (!reportData) {
                throw new Error(`No trace report found using key from trace info: ${endpointKeyForReport}.`);
            }
            log.debug(`[Launch] Retrieved report data and ${reportPayloads?.length || 0} payloads using key: ${endpointKeyForReport}`);

            const payloads = reportPayloads || [];
            const targetEndpointForLaunch = endpointKeyForReport;

            const details = reportData.details || {};
            const bestHandler = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler;
            let handlerCode = bestHandler ? (bestHandler.handler || bestHandler.code) : null;
            const sinks = details.sinks || reportData.vulnerabilities || [];

            let relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
            if (relevantMessages.length === 0 && details.uniqueStructures?.length > 0) {
                relevantMessages = details.uniqueStructures.flatMap(s => s.examples || []);
            }

            if (!handlerCode) {
                const analysisStorageKeyForHandler = getStorageKeyForUrl(endpointKeyForReport);
                const handlerStorageKey = `best-handler-${analysisStorageKeyForHandler}`;
                log.warning(`[Launch] Handler missing in report, attempting fetch from: ${handlerStorageKey}`);
                const handlerResult = await new Promise(resolve => chrome.storage.local.get(handlerStorageKey, resolve));
                handlerCode = handlerResult[handlerStorageKey]?.handler || handlerResult[handlerStorageKey]?.code;
                if (!handlerCode) throw new Error(`Handler code missing for launch. Key: ${handlerStorageKey}`);
            }

            const testData = { target: targetEndpointForLaunch, originalMessages: relevantMessages, handler: handlerCode, sinks: sinks, payloads: payloads };
            const success = await launchFuzzerEnvironment(targetEndpointForLaunch, testData);
            updateButton(button, success ? 'launch' : 'error', { hasCriticalSinks: button.classList.contains('has-critical-sinks') });
            if (traceButton) updateTraceButton(traceButton, success ? 'success' : 'default');

        } catch (error) {
            log.error('Launch error:', error?.message, error?.stack);
            alert(`Fuzzer launch failed: ${error.message}`);
            updateButton(button, 'error');
            if (traceButton) updateTraceButton(traceButton, 'disabled');
            try { await chrome.runtime.sendMessage({ action: "stopServer" }); } catch (e) { /* ignore */ }
        } finally {
            launchInProgressEndpoints.delete(endpointKey);
            log.debug(`Finished launch attempt for key ${endpointKey}`);
            updateDashboardUI()
        }
        return;
    }

    if (launchInProgressEndpoints.has(endpointKey)) {
        log.debug(`Play/Analysis already in progress for key: ${endpointKey}`);
        return;
    }
    launchInProgressEndpoints.add(endpointKey);
    try {
        await saveRandomPostMessages(endpointKey);
        const modalResult = await showQueryModal(originalFullEndpoint);
        log.debug('[Play Debug] Modal Result:', JSON.stringify(modalResult, null, 2));

        if (modalResult.cancelled) { updateButton(button, 'start'); throw new Error("User cancelled"); }
        const endpointUrlForAnalysis = modalResult.url;
        const analysisStorageKey = getStorageKeyForUrl(endpointUrlForAnalysis);
        const mappingKey = `analyzed-url-for-${endpointKey}`;

        if (modalResult.modified) {
            await chrome.storage.local.set({ [mappingKey]: endpointUrlForAnalysis });
            modifiedEndpoints.set(endpointKey, endpointUrlForAnalysis);
            await chrome.storage.local.set({ [`analysis-storage-key-for-${endpointKey}`]: analysisStorageKey });
            log.debug(`Stored analyzed URL mapping: ${mappingKey} -> ${endpointUrlForAnalysis}, storage key: ${analysisStorageKey}`);
        } else {
            await chrome.storage.local.remove(mappingKey);
            await chrome.storage.local.remove(`analysis-storage-key-for-${endpointKey}`);
            modifiedEndpoints.delete(endpointKey);
            log.debug(`Removed analyzed URL mapping for: ${mappingKey}`);
        }

        if (!skipCheck) {
            updateButton(button, 'csp');
            log.debug(`[Play Debug] Performing embedding check for URL: ${endpointUrlForAnalysis}`);
            const cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
            log.debug('[Play Debug] CSP Check Result Object:', JSON.stringify(cspResult, null, 2));

            if (!cspResult.embeddable) {
                log.debug('[Play Debug] CSP Check determined NOT embeddable. Throwing error...');
                throw new Error(`Embedding check failed: ${cspResult.status}`);
            } else {
                log.debug('[Play Debug] CSP Check determined embeddable (or check skipped). Proceeding to analyze.');
            }
        } else {
            log.debug('[Play Debug] Skipping CSP Check because skipCheck=true.');
        }
        updateButton(button, 'analyze');
        let foundHandlerObject = null;

        // Try runtime handler using ORIGINAL key
        const runtimeListenerKey = `runtime-listeners-${endpointKey}`;
        log.debug(`[Play] Attempting runtime listener retrieval using key: ${runtimeListenerKey}`);
        const runtimeResult = await new Promise((resolve, reject) => { chrome.storage.local.get([runtimeListenerKey], (result) => { if (chrome.runtime.lastError) reject(chrome.runtime.lastError); else resolve(result); }); });
        const runtimeListeners = runtimeResult ? runtimeResult[runtimeListenerKey] : null;
        if (runtimeListeners?.length > 0) {
            const validListeners = runtimeListeners.filter(l => l?.code && typeof l.code === 'string' && !l.code.includes('[native code]') && l.code.length > 25);
            if (validListeners.length > 0) {
                const scoringMessages = await retrieveMessagesWithFallbacks(endpointKey);
                if (scoringMessages.length > 0) {
                    const extractorForScoring = new HandlerExtractor();
                    extractorForScoring.initialize(endpointUrlForAnalysis, scoringMessages);
                    let bestListener = null, highestScore = -1;
                    validListeners.forEach(listener => { const score = extractorForScoring.scoreHandler(listener.code, 'runtime-captured', scoringMessages); if (score > highestScore) { highestScore = score; bestListener = listener; } });
                    if (bestListener) { foundHandlerObject = { handler: bestListener.code, category: 'runtime-captured-scored', score: highestScore, source: 'runtime-instrumentation', timestamp: bestListener.timestamp, stack: bestListener.stack, context: bestListener.context || 'unknown' }; log.success(`[Play] Selected best runtime handler via scoring (Score: ${highestScore})`); }
                } else { foundHandlerObject = { handler: validListeners[0].code, category: 'runtime-captured-unscored', score: 50, source: 'runtime-instrumentation', timestamp: validListeners[0].timestamp, stack: validListeners[0].stack, context: validListeners[0].context || 'unknown' }; log.warning(`[Play] No messages for scoring, selected first valid runtime handler.`); }
            }
        }
        // Fallback static extraction using analysis URL
        if (!foundHandlerObject) {
            log.warning(`[Play] No runtime handler. Using static extraction fallback for: ${endpointUrlForAnalysis}`);
            const extractor = new HandlerExtractor();
            const fallbackMessages = await retrieveMessagesWithFallbacks(endpointKey);
            extractor.initialize(endpointUrlForAnalysis, fallbackMessages);
            const extractedFallbackHandlers = await extractor.extract();
            if (extractedFallbackHandlers?.length > 0) {
                const bestFallbackHandler = extractor.getBestHandler(extractedFallbackHandlers);
                if (bestFallbackHandler) { foundHandlerObject = bestFallbackHandler; log.success(`[Play] Selected best handler via fallback (Score: ${foundHandlerObject.score?.toFixed(1)}, Cat: ${foundHandlerObject.category})`); }
                else { log.warning(`[Play] Fallback extraction ran but no best handler determined.`); }
            } else { log.warning(`[Play] Fallback extraction found no handlers.`); }
        }

        if (foundHandlerObject) {
            const finalBestHandlerKey = `best-handler-${analysisStorageKey}`;
            try {
                await chrome.storage.local.set({ [finalBestHandlerKey]: foundHandlerObject });
                log.success(`Saved best handler to storage key: ${finalBestHandlerKey}`);
            } catch (storageError) { log.error(`Failed to save best handler to storage (${finalBestHandlerKey}):`, storageError); }
            updateButton(button, 'success');
            if (traceButton) updateTraceButton(traceButton, 'default', { showEmoji: true });
            if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        } else {
            log.warning(`No handler found for ${endpointUrlForAnalysis} after all methods.`);
            updateButton(button, 'warning');
            if (traceButton) updateTraceButton(traceButton, 'disabled');
            if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        }
    } catch (error) {
        if (error.message !== "User cancelled") { log.error(`[Play Button Error] for ${originalFullEndpoint}:`, error.message, error.stack); updateButton(button, 'error'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        else { log.info("User cancelled Play action."); if (button.textContent === '▶' || button.classList.contains('checking') || button.classList.contains('default')) { updateButton(button, 'start'); } }
    } finally {
        launchInProgressEndpoints.delete(endpointKey);
        log.debug(`Finished checks for key ${endpointKey}. State deleted.`);
    }
}


function getRiskLevelAndColor(score) {
    if (score <= 20) return { riskLevel: 'Critical', riskColor: 'critical' };
    if (score <= 40) return { riskLevel: 'High', riskColor: 'high' };
    if (score <= 60) return { riskLevel: 'Medium', riskColor: 'medium' };
    if (score <= 80) return { riskLevel: 'Low', riskColor: 'low' };
    return { riskLevel: 'Good', riskColor: 'negligible' };
}

function getRecommendationText(score, reportData) {

    const hasCriticalSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'critical') || false;
    const hasHighSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'high') || false;
    const hasHighIssue = reportData?.details?.securityIssues?.some(s => s.severity?.toLowerCase() === 'high') || false;
    const mediumIssueCount = reportData?.details?.securityIssues?.filter(s => s.severity?.toLowerCase() === 'medium')?.length || 0;

    if (hasCriticalSink) {
        return 'Immediate attention required. Critical vulnerabilities present. Fix critical sinks (eval, innerHTML, etc.) and implement strict origin/data validation.';
    }

    if (score <= 20) {
        return 'Immediate attention required. Security posture is critically weak. Focus on fixing high-risk issues and implementing strict origin/data validation.';
    }

    if (hasHighSink || hasHighIssue || score <= 40) {
        return 'Significant risks identified. Implement strict origin checks and sanitize all inputs used in sinks. Consider a Content Security Policy (CSP).';
    }

    if (mediumIssueCount >= 3 || score <= 60) {
        return 'Potential vulnerabilities detected. Review security issues (e.g., origin checks, data validation) and ensure data flowing to sinks is safe.';
    }

    if (score <= 80) {
        return 'Low risk detected, but review identified issues and follow security best practices (origin/data validation).';
    }

    const hasFindings = (reportData?.details?.sinks?.length > 0) ||
        (reportData?.details?.securityIssues?.length > 0);

    if (hasFindings) {
        return 'Good score, but minor issues or informational findings detected. Review details and ensure best practices are followed.';
    }

    return 'Excellent score. Analysis found no major vulnerabilities. Continue to follow security best practices for postMessage handling.';
}

function renderStructureItem(structureData, index) {
    const exampleData = structureData.examples?.[0]?.data || structureData.examples?.[0] || {};
    let formattedExample = '';
    try { formattedExample = typeof exampleData === 'string' ? exampleData : JSON.stringify(exampleData, null, 2); }
    catch (e) { formattedExample = String(exampleData); }
    // const pathsString = structureData.pathsToFuzz?.map(p => `<code>${escapeHTML(p.path)} (${escapeHTML(p.type)})</code>`).join(', ') || 'N/A';

    return `
        <details class="report-details structure-item" data-structure-index="${index}">
            <summary class="report-summary-toggle">Structure ${index + 1} <span class="toggle-icon">▶</span></summary>
            <div class="structure-content">
                <p><strong>Example Message:</strong></p>
                <div class="report-code-block"><pre><code>${escapeHTML(formattedExample)}</code></pre></div>
            </div>
        </details>`;
}

function renderPayloadItem(p, index) {
    const safeType = escapeHTML(p.type || 'N/A');
    const safeTarget = escapeHTML(p.targetPath || p.targetFlow || p.description || 'N/A');
    let payloadString = '';
    try { payloadString = typeof p.payload === 'string' ? p.payload : JSON.stringify(p.payload, null, 2); }
    catch(e){ payloadString = String(p.payload); }
    const truncatedPayload = escapeHTML(payloadString.substring(0, 300) + (payloadString.length > 300 ? '...' : ''));

    return `
        <div class="payload-item" data-payload-index="${index}">
            <div class="payload-header">
                <strong>Type:</strong> <span class="payload-meta">${safeType}</span> |
                <strong>Target/Desc:</strong> <span class="payload-meta">${safeTarget}</span>
            </div>
            <pre class="report-code-block"><code>${truncatedPayload}</code></pre>
            <button class="control-button secondary-button view-full-payload-btn">View Full</button>
        </div>`;
}

function attachReportEventListeners(panel, reportData) {
    panel.querySelectorAll('details.report-details').forEach(detailsElement => {
        const iconElement = detailsElement.querySelector('.toggle-icon');
        if (detailsElement && iconElement) {
            detailsElement.addEventListener('toggle', () => {
                iconElement.textContent = detailsElement.open ? '▼' : '▶';
            });
        }
    });

    panel.querySelectorAll('.view-full-payload-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const item = e.target.closest('.payload-item');
            const index = parseInt(item?.getAttribute('data-payload-index'));
            const payloads = reportData?.details?.payloads || [];
            if (payloads[index] !== undefined) {
                showFullPayloadModal(payloads[index]);
            }
        });
    });

    const showAllPayloadsBtn = panel.querySelector('#showAllPayloadsBtn');
    if (showAllPayloadsBtn) {
        showAllPayloadsBtn.addEventListener('click', () => {
            const list = panel.querySelector('#payloads-list');
            const payloads = reportData?.details?.payloads || [];
            if (list && payloads.length > 0) {
                list.innerHTML = payloads.map((p, index) => renderPayloadItem(p, index)).join('');
                // Re-attach listeners for the newly rendered items
                attachReportEventListeners(panel, reportData);
            }
            showAllPayloadsBtn.remove();
        }, { once: true });
    }

    const showAllStructuresBtn = panel.querySelector('#showAllStructuresBtn');
    if (showAllStructuresBtn) {
        showAllStructuresBtn.addEventListener('click', () => {
            const list = panel.querySelector('.structures-list');
            const structures = reportData?.details?.uniqueStructures || [];
            if (list && structures.length > 0) {
                list.innerHTML = structures.map((s, index) => renderStructureItem(s, index)).join('');
                attachReportEventListeners(panel, reportData);
            }
            showAllStructuresBtn.remove();
        }, { once: true });
    }
}

function displayReport(reportData, panel) {
    panel.innerHTML = '';
    const header = document.createElement('div');
    header.className = 'trace-panel-header';
    header.innerHTML = `<h3>PostMessage Analysis Report</h3><button class="trace-panel-close">✕</button>`;
    panel.appendChild(header);
    header.querySelector('.trace-panel-close').onclick = () => {
        const backdrop = document.querySelector('.trace-panel-backdrop');
        if (backdrop) backdrop.remove();
        panel.remove();
    };
    const content = document.createElement('div');
    content.className = 'trace-results-content';
    panel.appendChild(content);
    if (!reportData || typeof reportData !== 'object') {
        content.innerHTML = '<p class="error-message">Error: Invalid or missing report data.</p>';
        return;
    }
    const details = reportData.details || {};
    const summary = reportData.summary || {};
    const bestHandler = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler;
    const vulnerabilities = [...(details.sinks || []), ...(reportData.vulnerabilities || [])];
    const securityIssues = [...(details.securityIssues || []), ...(reportData.securityIssues || [])];
    const dataFlows = details.dataFlows || [];
    const payloads = details.payloads || [];
    const structures = details.uniqueStructures || [];
    const uniqueVulns = vulnerabilities.filter((v, i, a) => a.findIndex(t => (t.type === v.type && t.context === v.context)) === i);
    const uniqueIssues = securityIssues.filter((v, i, a) => a.findIndex(t => (t.type === v.type && t.context === v.context)) === i);
    const score = reportData.securityScore ?? summary.securityScore ?? 100;
    const { riskLevel, riskColor } = getRiskLevelAndColor(score);
    const summarySection = document.createElement('div');
    summarySection.className = 'report-section report-summary';
    summarySection.innerHTML = `
        <h4 class="report-section-title">Analysis Summary</h4>
        <div class="summary-grid">
             <div class="security-score-container"><div class="security-score ${riskColor}"><div class="security-score-value">${score}</div><div class="security-score-label">${riskLevel}</div></div></div>
             <div class="summary-metrics">
                 <div class="metric"><span class="metric-label">Msgs Analyzed</span><span class="metric-value">${summary.messagesAnalyzed ?? 'N/A'}</span></div>
                 <div class="metric"><span class="metric-label">Msg Structures</span><span class="metric-value">${structures.length}</span></div>
                 <div class="metric"><span class="metric-label">Sinks Found</span><span class="metric-value">${uniqueVulns.length}</span></div>
                 <div class="metric"><span class="metric-label">Sec. Issues</span><span class="metric-value">${uniqueIssues.length}</span></div>
                 <div class="metric"><span class="metric-label">Payloads Gen.</span><span class="metric-value">${payloads.length}</span></div>
             </div>
        </div>
        <div class="recommendations"><h5 class="report-subsection-title">Recommendation</h5><p class="recommendation-text">${getRecommendationText(score, reportData)}</p></div>
    `;
    content.appendChild(summarySection);
    if (bestHandler?.handler) {
        const handlerSection = document.createElement('div');
        handlerSection.className = 'report-section report-handler';
        handlerSection.innerHTML = `<details class="report-details"><summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Category: ${escapeHTML(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▶</span></summary><div class="report-code-block handler-code"><pre><code>${escapeHTML(bestHandler.handler)}</code></pre></div></details>`;
        content.appendChild(handlerSection);
    }
    const findingsSection = document.createElement('div');
    findingsSection.className = 'report-section report-findings';
    let findingsHTML = '<h4 class="report-section-title">Findings</h4>';
    if (uniqueVulns.length > 0) {
        findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">DOM XSS Sinks Detected (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
        uniqueVulns.forEach(vuln => { findingsHTML += `<tr class="severity-row-${vuln.severity?.toLowerCase()}"><td>${escapeHTML(vuln.type||'?')}</td><td><span class="severity-badge severity-${vuln.severity?.toLowerCase()}">${escapeHTML(vuln.severity||'?')}</span></td><td><code class="context-snippet">${escapeHTML(vuln.context||'')}</code></td></tr>`; });
        findingsHTML += `</tbody></table></div>`;
    } else { findingsHTML += `<p class="no-findings-text">No direct DOM XSS sinks found.</p>`; }
    if (uniqueIssues.length > 0) {
        findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
        uniqueIssues.forEach(issue => { findingsHTML += `<tr class="severity-row-${issue.severity?.toLowerCase()}"><td>${escapeHTML(issue.type||'?')}</td><td><span class="severity-badge severity-${issue.severity?.toLowerCase()}">${escapeHTML(issue.severity||'?')}</span></td><td><code class="context-snippet">${escapeHTML(issue.context||'')}</code></td></tr>`; });
        findingsHTML += `</tbody></table></div>`;
    } else { findingsHTML += `<p class="no-findings-text">No other security issues found.</p>`; }
    findingsSection.innerHTML = findingsHTML;
    content.appendChild(findingsSection);
    if (dataFlows.length > 0) {
        const flowSection = document.createElement('div');
        flowSection.className = 'report-section report-dataflow';
        flowSection.innerHTML = `<h4 class="report-section-title">Data Flow (Message Data → Sink)</h4><table class="report-table dataflow-table"><thead><tr><th>Source Property</th><th>Sink Function</th><th>Context Snippet</th></tr></thead><tbody>`;
        dataFlows.forEach(flow => { flowSection.innerHTML += `<tr><td><code>event.data.${escapeHTML(flow.property)}</code></td><td>${escapeHTML(flow.sink)}</td><td><code class="context-snippet">${escapeHTML(flow.context)}</code></td></tr>`; });
        flowSection.innerHTML += `</tbody></table>`;
        content.appendChild(flowSection);
    }
    if (payloads.length > 0) {
        const payloadSection = document.createElement('div');
        payloadSection.className = 'report-section report-payloads';
        payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (${payloads.length})</h4><div id="payloads-list" class="payloads-list report-list">${payloads.slice(0, 10).map((p, index) => renderPayloadItem(p, index)).join('')}</div>${payloads.length > 10 ? `<button id="showAllPayloadsBtn" class="control-button secondary-button show-more-btn">Show All ${payloads.length} Payloads</button>` : ''}`;
        content.appendChild(payloadSection);
    } else {
        const payloadSection = document.createElement('div');
        payloadSection.className = 'report-section report-payloads';
        payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (0)</h4><p class="no-findings-text">No specific payloads were generated for this analysis.</p>`;
        content.appendChild(payloadSection);
    }
    const structureSection = document.createElement('div');
    structureSection.className = 'report-section report-structures';
    if (structures.length > 0) {
        let structuresHTML = `<h4 class="report-section-title">Unique Message Structures (${structures.length})</h4><div class="structures-list report-list">`;
        structures.slice(0, 3).forEach((s, index) => { structuresHTML += renderStructureItem(s, index); });
        structuresHTML += `</div>`;
        if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length} Structures</button>`; }
        structureSection.innerHTML = structuresHTML;
        content.appendChild(structureSection);
    } else {
        structureSection.innerHTML = `<h4 class="report-section-title">Unique Message Structures (0)</h4><p class="no-findings-text">No distinct message structures could be analyzed.</p>`;
        content.appendChild(structureSection);
    }
    attachReportEventListeners(panel, reportData); // Attach all listeners at the end
}

function showFullPayloadModal(payload) {
    const existingModal = document.querySelector('.payload-modal');
    if (existingModal) existingModal.remove();
    const existingBackdrop = document.querySelector('.payload-modal-backdrop');
    if (existingBackdrop) existingBackdrop.remove();

    const modal = document.createElement('div');
    modal.className = 'payload-modal';

    const modalContent = document.createElement('div');
    modalContent.className = 'payload-modal-content';

    const closeBtn = document.createElement('span');
    closeBtn.className = 'close-modal';
    closeBtn.innerHTML = '&times;';

    const backdrop = document.createElement('div');
    backdrop.className = 'payload-modal-backdrop';

    const closeModal = () => {
        modal.remove();
        backdrop.remove();
    };
    closeBtn.onclick = closeModal;
    backdrop.onclick = closeModal; // Close on backdrop click


    const heading = document.createElement('h4');
    heading.textContent = `Payload Details (Type: ${escapeHTML(payload.type)})`;

    const targetInfo = document.createElement('p');
    targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payload.targetPath || payload.targetFlow || payload.description || 'N/A')}`;
    targetInfo.style.marginBottom = '15px';
    targetInfo.style.fontSize = '13px';
    targetInfo.style.color = '#aaa';


    const payloadPre = document.createElement('pre');
    payloadPre.className = 'report-code-block'; // Use report style
    payloadPre.style.maxHeight = '50vh';
    payloadPre.style.overflowY = 'auto';

    const payloadCode = document.createElement('code');
    let formattedPayload = '';
    try {
        if(typeof payload.payload === 'object' && payload.payload !== null) {
            formattedPayload = JSON.stringify(payload.payload, null, 2);
        } else {
            formattedPayload = String(payload.payload);
        }
    } catch (e) { formattedPayload = String(payload.payload); }
    payloadCode.textContent = formattedPayload;
    payloadPre.appendChild(payloadCode);

    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy Payload';
    copyBtn.className = 'control-button';
    copyBtn.style.marginTop = '15px';
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(formattedPayload)
            .then(() => {
                copyBtn.textContent = 'Copied!';
                copyBtn.style.borderColor = 'var(--success-color)';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy Payload';
                    copyBtn.style.borderColor = '';
                }, 2000);
            })
            .catch(() => {
                copyBtn.textContent = 'Copy Failed';
                copyBtn.style.borderColor = 'var(--error-color)';
                setTimeout(() => { copyBtn.textContent = 'Copy Payload'; copyBtn.style.borderColor = '';}, 2000);
            });
    };

    modalContent.appendChild(closeBtn);
    modalContent.appendChild(heading);
    modalContent.appendChild(targetInfo);
    modalContent.appendChild(payloadPre);
    modalContent.appendChild(copyBtn);
    modal.appendChild(modalContent);

    document.body.appendChild(backdrop);
    document.body.appendChild(modal);
}

async function handleReportButton(endpoint) {
    const originalEndpoint = endpoint;
    const endpointKey = getStorageKeyForUrl(originalEndpoint);

    if (!endpointKey) {
        log.error('Could not determine key for report button:', originalEndpoint);
        alert('Internal error: Could not process endpoint URL for report.');
        return;
    }
    log.debug(`Report button clicked for key: ${endpointKey}`);

    try {
        const traceInfoKey = `trace-info-${endpointKey}`;
        const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
        const traceInfo = traceInfoResult[traceInfoKey];

        let endpointKeyForReport = endpointKey;
        let reportData = null;
        let reportPayloads = null;

        if (traceInfo) {
            if (traceInfo.analysisStorageKey) {
                endpointKeyForReport = traceInfo.analysisStorageKey;
                log.debug(`[Report] Using analysis storage key from trace info: ${endpointKeyForReport}`);

                [reportData, reportPayloads] = await Promise.all([
                    window.traceReportStorage.getTraceReport(endpointKeyForReport),
                    window.traceReportStorage.getReportPayloads(endpointKeyForReport)
                ]);
            }

            if (!reportData && traceInfo.analyzedUrl) {
                endpointKeyForReport = traceInfo.analyzedUrl;
                log.debug(`[Report] Using analyzed URL from trace info: ${endpointKeyForReport}`);

                [reportData, reportPayloads] = await Promise.all([
                    window.traceReportStorage.getTraceReport(endpointKeyForReport),
                    window.traceReportStorage.getReportPayloads(endpointKeyForReport)
                ]);

                if (!reportData) {
                    const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                    log.debug(`[Report] Trying with normalized analyzed URL key: ${analyzedUrlKey}`);

                    [reportData, reportPayloads] = await Promise.all([
                        window.traceReportStorage.getTraceReport(analyzedUrlKey),
                        window.traceReportStorage.getReportPayloads(analyzedUrlKey)
                    ]);

                    if (reportData) endpointKeyForReport = analyzedUrlKey;
                }
            }
        }

        if (!reportData) {
            log.debug(`[Report] No report from trace info. Trying original key: ${endpointKey}`);

            [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(endpointKey),
                window.traceReportStorage.getReportPayloads(endpointKey)
            ]);
        }

        if (!reportData) {
            log.debug(`[Report] No report with storage key. Trying with full URL: ${originalEndpoint}`);

            [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(originalEndpoint),
                window.traceReportStorage.getReportPayloads(originalEndpoint)
            ]);
        }

        if (!reportData) {
            throw new Error(`No report data found. Run Trace first.`);
        }

        if (typeof reportData !== 'object' || reportData === null) {
            throw new Error(`Invalid report data format retrieved`);
        }

        log.debug(`Retrieved report data. Payload count from separate storage: ${reportPayloads?.length || 0}`);

        if (!reportData.details) reportData.details = {};
        reportData.details.payloads = reportPayloads || [];
        if (!reportData.summary) reportData.summary = {};
        reportData.summary.payloadsGenerated = reportPayloads?.length || 0;

        const existingPanel = document.querySelector('.trace-results-panel');
        if (existingPanel) existingPanel.remove();
        const existingBackdrop = document.querySelector('.trace-panel-backdrop');
        if (existingBackdrop) existingBackdrop.remove();
        const tracePanel = document.createElement('div');
        tracePanel.className = 'trace-results-panel';
        const backdrop = document.createElement('div');
        backdrop.className = 'trace-panel-backdrop';
        backdrop.onclick = () => {
            try { if (tracePanel?.parentNode) tracePanel.remove(); } catch(e){}
            try { if (backdrop?.parentNode) backdrop.remove(); } catch(e){}
        };

        const reportContainer = document.getElementById('reportPanelContainer') || document.body;
        reportContainer.appendChild(backdrop);
        reportContainer.appendChild(tracePanel);
        displayReport(reportData, tracePanel);

    } catch (error) {
        log.error('Error retrieving or displaying report:', error?.message, error?.stack);
        alert(`Failed to retrieve or display report data: ${error?.message}`);
    }
}

async function checkAllEndpoints() {
    const endpointButtons = document.querySelectorAll('.iframe-row .iframe-check-button');
    for (const button of endpointButtons) {
        const endpointKey = button.getAttribute('data-endpoint'); // Key is stored here
        if (endpointKey && !button.classList.contains('green')) { // Only run if not already in launch state
            try {
                await handlePlayButton(endpointKey, button);
                await new Promise(resolve => setTimeout(resolve, 1000)); // Delay between checks
            } catch (e) {
                // Ignore errors during batch check to continue with others
            }
        }
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const clearStoredMessages = () => {
        chrome.runtime.sendMessage({ type: "resetState" });
        localStorage.removeItem('interceptedMessages'); // Clear potential old data
        messages.length = 0; // Clear in-memory messages
        window.frogPostState.frameConnections.clear();
        buttonStates.clear();
        reportButtonStates.clear();
        traceButtonStates.clear();
        activeEndpoint = null;
    };
    clearStoredMessages(); // Clear state on load

    const sidebarToggle = document.getElementById('sidebarToggle');
    const controlSidebar = document.getElementById('controlSidebar');

    if (sidebarToggle && controlSidebar) {
        // Initial animation state if closed
        if (!controlSidebar.classList.contains('open')) {
            sidebarToggle.classList.add('animate-toggle');
        }

        sidebarToggle.addEventListener('click', () => {
            controlSidebar.classList.toggle('open');
            // Add/Remove animation class based on sidebar state
            if (controlSidebar.classList.contains('open')) {
                sidebarToggle.classList.remove('animate-toggle');
            } else {
                sidebarToggle.classList.add('animate-toggle');
            }
        });
    } else {
        log.error("Sidebar toggle or container not found.");
    }
    printBanner();
    setupUIControls();
    initializeMessageHandling();
    startAutoRefresh();
    updateDashboardUI();
});
