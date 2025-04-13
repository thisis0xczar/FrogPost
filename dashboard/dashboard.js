/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
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

let debugMode = false;

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
    _log: (style, icon, msg, details) => {
        console.log(`%c ${icon} ${msg}`, style);
        if (details && (debugMode || typeof details === 'string')) {
            const detailStyle = style === log.styles.error ? 'color: #cc0000;' : 'color: #666666;';
            if (details instanceof Error) {
                console.error('%c    ' + details.message, detailStyle);
                if (details.stack && debugMode) {
                    console.error('%c    Stack Trace:', detailStyle, details.stack);
                }
            } else if (typeof details === 'object' && debugMode) {
                console.log('%c    Details:', detailStyle, details);
            } else {
                console.log('%c    ' + details, detailStyle);
            }
        }
    },
    info: (msg, details) => log._log(log.styles.info, 'ℹ️', msg, details),
    success: (msg, details) => log._log(log.styles.success, '✅', msg, details),
    warning: (msg, details) => log._log(log.styles.warning, '⚠️', msg, details),
    warn: (msg, details) => log.warning(msg, details),
    error: (msg, details) => log._log(log.styles.error, '❌', msg, details),
    handler: (msg, details) => log._log(log.styles.handler, '🔍', msg, details),
    scan: (msg, details) => log._log(log.styles.scan, '🔄', msg, details),
    debug: (msg, ...args) => {
        if (debugMode) {
            console.log('%c 🔧 ' + msg, log.styles.debug, ...args);
        }
    }
};
window.log = log;

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

const knownHandlerEndpoints = new Set();
const endpointsWithHandlers = new Set();
const messages = [];
let activeEndpoint = null;
const buttonStates = new Map();
const reportButtonStates = new Map();
const traceButtonStates = new Map();
let callbackUrl = null;
const CALLBACK_URL_STORAGE_KEY = 'callback_url';
const modifiedEndpoints = new Map();
const launchInProgressEndpoints = new Set();


function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    const xssPatterns = [
        /<\s*script/i, /<\s*img[^>]+onerror/i, /javascript\s*:/i,
        /on\w+\s*=/i, /<\s*iframe/i, /<\s*svg[^>]+on\w+/i,
        /alert\s*\(/i, /console\.log\s*\(/i, /eval\s*\(/i, // Simplified regex slightly
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
        log.handler(`[Get Base URL] Error getting base URL for: ${url}`, e.message);
        return null;
    }
}
window.getBaseUrl = getBaseUrl;


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
    // Simplified based on IntelliJ suggestion (original logic seemed correct but this is simpler if sufficient)
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
        return {
            normalized: key,
            components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash },
            key: key
        };
    } catch (e) {
        log.handler(`[Normalize URL] Error: ${e.message}`, url);
        return { normalized: url, components: null, key: url };
    }
}
window.normalizeEndpointUrl = normalizeEndpointUrl;

function getStorageKeyForUrl(url) {
    return normalizeEndpointUrl(url)?.key || url;
}
window.getStorageKeyForUrl = getStorageKeyForUrl;


function showToastNotification(message, type = 'error', duration = 5000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    const timeoutId = setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('fade-out');

        toast.addEventListener('transitionend', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, { once: true });

        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, duration + 600);

    }, duration);

    toast.addEventListener('click', () => {
        clearTimeout(timeoutId);
        toast.classList.remove('show');
        toast.classList.add('fade-out');
        toast.addEventListener('transitionend', () => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, { once: true });
        setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 600);
    });
}

function updateButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = window.getStorageKeyForUrl(button.getAttribute('data-endpoint'));
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
window.updateButton = updateButton;


function updateTraceButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = window.getStorageKeyForUrl(button.getAttribute('data-endpoint'));
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
    button.classList.add('iframe-trace-button');
    button.classList.add(...newState.class.split(' '));

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
window.updateTraceButton = updateTraceButton;

function updateReportButton(button, state, endpoint) {
    if (!button) return;
    const endpointKey = window.getStorageKeyForUrl(endpoint);

    const states = {
        disabled: { text: '📋', title: 'Analysis Report (disabled)', className: 'iframe-report-button disabled' },
        default: { text: '📋', title: 'View Analysis Report', className: 'iframe-report-button default' },
        green: { text: '📋', title: 'View Analysis Report (Findings)', className: 'iframe-report-button green' }
    };
    const newState = states[state] || states.disabled;
    button.textContent = newState.text;
    button.title = newState.title;
    button.className = newState.className;

    if (endpointKey) {
        reportButtonStates.set(endpointKey, state);
    }
}
window.updateReportButton = updateReportButton;

function originMatchesSource(currentOrigin, source, endpointOrigin) {
    if (source === '*') return true;
    if (source === "'self'") return endpointOrigin !== null && currentOrigin === endpointOrigin;
    if (source === "'none'") return false;

    const cleanCurrentOrigin = currentOrigin.endsWith('/') ? currentOrigin.slice(0, -1) : currentOrigin;
    const cleanSource = source.endsWith('/') ? source.slice(0, -1) : source;

    if (cleanCurrentOrigin === cleanSource) return true;
    if (cleanSource.startsWith('*.')) {
        const domainPart = cleanSource.substring(2);
        return cleanCurrentOrigin.endsWith('.' + domainPart) && cleanCurrentOrigin.length > (domainPart.length + 1);
    }
    return false;
}

async function performEmbeddingCheck(endpoint) {
    log.handler(`[Embedding Check] Starting for: ${endpoint}`);
    try {
        const response = await fetch(endpoint, { method: 'HEAD', cache: 'no-store' });
        log.handler(`[Embedding Check] HEAD request status: ${response.status}`);

        const xFrameOptions = response.headers.get('X-Frame-Options');
        if (xFrameOptions) {
            log.handler(`[Embedding Check] Found X-Frame-Options: ${xFrameOptions}`);
            const xfoUpper = xFrameOptions.toUpperCase();
            if (xfoUpper === 'DENY') {
                return { status: `X-Frame-Options: ${xFrameOptions}`, className: 'red', embeddable: false };
            }
            if (xfoUpper === 'SAMEORIGIN') {
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try { endpointOrigin = new URL(endpoint).origin; } catch(e) {}
                if (!endpointOrigin || currentOrigin !== endpointOrigin) {
                    return { status: `X-Frame-Options: ${xFrameOptions} (Origin mismatch)`, className: 'red', embeddable: false };
                }
            }
        }

        const csp = response.headers.get('Content-Security-Policy');
        if (csp) {
            log.handler(`[Embedding Check] Found Content-Security-Policy header.`);
            const directives = csp.split(';').map(d => d.trim());
            const frameAncestors = directives.find(d => d.startsWith('frame-ancestors'));
            if (frameAncestors) {
                const sourcesString = frameAncestors.substring('frame-ancestors'.length).trim();
                const sources = sourcesString.split(/\s+/);
                log.handler(`[Embedding Check] Parsed frame-ancestors sources: [${sources.join(', ')}]`);
                if (sources.includes("'none'")) {
                    return { status: `CSP: frame-ancestors 'none'`, className: 'red', embeddable: false };
                }
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try { endpointOrigin = new URL(endpoint).origin; } catch(e) { return { status: `Invalid endpoint URL`, className: 'red', embeddable: false }; }

                let isAllowedByDirective = false;
                for (const source of sources) {
                    if (originMatchesSource(currentOrigin, source, endpointOrigin)) {
                        isAllowedByDirective = true; break;
                    }
                }
                if (!isAllowedByDirective) {
                    return { status: `CSP: frame-ancestors does not allow ${currentOrigin}`, className: 'red', embeddable: false };
                }
            }
        }
        log.success(`[Embedding Check] Frame can be embedded for ${endpoint}`);
        return { status: 'Frame can be embedded', className: 'green', embeddable: true };
    } catch (error) {
        // Simplifying the throw/catch - just return error status
        log.error(`[Embedding Check] Header check failed for ${endpoint}: ${error.message}`, error);
        return { status: `Header check failed: ${error.message}`, className: 'red', embeddable: false };
    }
}

function getMessageCount(endpointKey) {
    return messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = window.getStorageKeyForUrl(msg.origin);
        const destKey = window.getStorageKeyForUrl(msg.destinationUrl);
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
    hostName.textContent = `${hostKey} (${getMessageCount(hostKey)})`;

    hostRow.addEventListener("click", (e) => {
        e.stopPropagation();
        activeEndpoint = hostKey;
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
        iframeRow.setAttribute("data-endpoint-key", iframeKey);

        const iframeName = document.createElement("span");
        iframeName.className = "iframe-name";
        iframeName.textContent = `${iframeKey} (${getMessageCount(iframeKey)})`;

        iframeRow.addEventListener("click", (e) => {
            e.stopPropagation();
            activeEndpoint = iframeKey;
            renderMessages();
            highlightActiveEndpoint();
        });

        const iframeButtonContainer = createActionButtonContainer(iframeKey);
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
    playButton.setAttribute("data-endpoint", endpointKey);

    const traceButton = document.createElement("button");
    traceButton.className = "iframe-trace-button disabled";
    traceButton.setAttribute("data-endpoint", endpointKey);
    traceButton.setAttribute('disabled', 'true');

    const reportButton = document.createElement("button");
    reportButton.className = "iframe-report-button disabled";
    reportButton.setAttribute("data-endpoint", endpointKey);

    const handlerButton = document.createElement("button");
    handlerButton.className = "iframe-handler-button";
    handlerButton.setAttribute("data-endpoint", endpointKey);
    handlerButton.textContent = '{ }';

    const hasHandler = endpointsWithHandlers.has(endpointKey);
    handlerButton.disabled = !hasHandler;
    handlerButton.title = hasHandler ? 'View Captured Listeners' : 'No Listeners Captured Yet';
    handlerButton.classList.toggle('green', hasHandler);
    handlerButton.classList.toggle('disabled', !hasHandler);
    if(hasHandler) handlerButton.style.backgroundColor = '#222';

    const savedPlayStateInfo = buttonStates.get(endpointKey);
    updateButton(playButton, savedPlayStateInfo?.state || 'start', savedPlayStateInfo?.options || {});

    const savedTraceStateInfo = traceButtonStates.get(endpointKey);
    const canTrace = playButton.classList.contains('success') || playButton.classList.contains('green');
    updateTraceButton(traceButton, savedTraceStateInfo?.state || (canTrace ? 'default' : 'disabled'), savedTraceStateInfo?.options || {});

    const savedReportStateInfo = reportButtonStates.get(endpointKey);
    const canReport = traceButton.classList.contains('green');
    updateReportButton(reportButton, savedReportStateInfo || (canReport ? 'default' : 'disabled'), endpointKey);


    playButton.addEventListener("click", async (e) => { e.stopPropagation(); await handlePlayButton(endpointKey, playButton); });
    traceButton.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) {
            await window.handleTraceButton(endpointKey, traceButton);
        }
    });

    reportButton.addEventListener("click", async (e) => { e.stopPropagation(); if (!reportButton.classList.contains('disabled')) { await handleReportButton(endpointKey); } });
    handlerButton.addEventListener("click", (e) => {
        e.stopPropagation();
        if (!handlerButton.disabled) {
            const key = handlerButton.getAttribute('data-endpoint');
            if (key) { showHandlerModal(key); }
        }
    });

    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(handlerButton);
    buttonContainer.appendChild(reportButton);
    return buttonContainer;
}


function renderEndpoints(filter = "") {
    const endpointsList = document.getElementById("endpointsList");
    if (!endpointsList) return;
    const currentFrameConnections = new Map();
    const messageKeys = new Set();
    messages.forEach(msg => {
        if (msg.origin && msg.destinationUrl) {
            const originKey = normalizeEndpointUrl(msg.origin)?.normalized;
            const destKey = normalizeEndpointUrl(msg.destinationUrl)?.normalized;
            if (originKey && destKey && originKey !== destKey && originKey !== 'null' && destKey !== 'null') {
                if (!currentFrameConnections.has(originKey)) {
                    currentFrameConnections.set(originKey, new Set());
                }
                currentFrameConnections.get(originKey).add(destKey);
                messageKeys.add(originKey);
                messageKeys.add(destKey);
            } else if (originKey && originKey !== 'null') {
                messageKeys.add(originKey);
            } else if (destKey && destKey !== 'null') {
                messageKeys.add(destKey);
            }
        }
    });
    const endpointHierarchy = new Map(currentFrameConnections);
    const allRenderedKeys = new Set(messageKeys);

    knownHandlerEndpoints.forEach(handlerKey => {
        if (handlerKey && !allRenderedKeys.has(handlerKey)) {
            try {
                if (handlerKey.startsWith('http:') || handlerKey.startsWith('https:')) {
                    const url = new URL(handlerKey);
                    const hostKey = url.origin;
                    if (endpointHierarchy.has(hostKey)) {
                        endpointHierarchy.get(hostKey).add(handlerKey);
                    } else {
                        endpointHierarchy.set(hostKey, new Set([handlerKey]));
                        allRenderedKeys.add(hostKey);
                    }
                    allRenderedKeys.add(handlerKey);
                } else {
                    if (!endpointHierarchy.has(handlerKey)) {
                        endpointHierarchy.set(handlerKey, new Set([handlerKey]));
                    }
                    allRenderedKeys.add(handlerKey);
                }
            } catch(e) {
                log.warn(`[RenderEndpoints] Error processing handler-only key: ${handlerKey}`, e);
                if (!endpointHierarchy.has(handlerKey)) {
                    endpointHierarchy.set(handlerKey, new Set([handlerKey]));
                }
                allRenderedKeys.add(handlerKey);
            }
        }
    });

    const finalHostKeys = Array.from(endpointHierarchy.keys());
    if (finalHostKeys.length === 0 && knownHandlerEndpoints.size === 0) {
        endpointsList.innerHTML = "<div class='no-endpoints'>No communication captured or listeners found.</div>";
        return;
    }

    endpointsList.innerHTML = "";
    let hostCount = 0;
    const sortedHostKeys = finalHostKeys.sort();

    sortedHostKeys.forEach(hostKey => {
        const iframesSet = endpointHierarchy.get(hostKey) || new Set();
        const hostMatches = !filter || hostKey.toLowerCase().includes(filter.toLowerCase());
        const anyIframeMatches = !filter || Array.from(iframesSet).some(iframeKey =>
            iframeKey.toLowerCase().includes(filter.toLowerCase())
        );

        if (!hostMatches && !anyIframeMatches) return;

        try {
            let displayedIframeSet = iframesSet;
            if (filter && !hostMatches && anyIframeMatches) {
                displayedIframeSet = new Set(Array.from(iframesSet).filter(iframeKey =>
                    iframeKey.toLowerCase().includes(filter.toLowerCase())
                ));
            }
            const hostElement = createHostElement(hostKey, displayedIframeSet);
            if (hostElement) {
                endpointsList.appendChild(hostElement);
                hostCount++;
            }
        } catch (e) {
            log.error(`[RenderEndpoints] Error processing host key: "${hostKey}".`, e);
        }
    });

    if (hostCount === 0 && filter) {
        endpointsList.innerHTML = `<div class='no-endpoints'>No endpoints match filter "${filter}".</div>`;
    } else if (hostCount === 0 && (finalHostKeys.length > 0 || knownHandlerEndpoints.size > 0)) {
        endpointsList.innerHTML = "<div class='no-endpoints'>Rendering error or no matching endpoints.</div>";
        log.handler("[RenderEndpoints] Rendered 0 hosts despite available keys.");
    }
    highlightActiveEndpoint();
}

async function sendMessageTo(targetKey, button) {
    let success = false;
    try {
        const messageItem = button.closest('.message-item');
        if (!messageItem) throw new Error("Message item not found");
        const messageDataElement = messageItem.querySelector('.message-data');
        if (!messageDataElement) throw new Error("Message data element not found");

        const messageContent = messageDataElement.textContent;
        let data;
        try { data = JSON.parse(messageContent); } catch (e) { data = messageContent; }

        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        iframe.src = targetKey;

        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("Iframe load timeout")), 3000);
            iframe.onload = () => { clearTimeout(timer); resolve(); };
            iframe.onerror = () => { clearTimeout(timer); reject(new Error("Iframe load error")); };
        });

        if (iframe.contentWindow) {
            iframe.contentWindow.postMessage(data, '*');
            success = true;
        } else {
            throw new Error("Iframe content window not accessible");
        }

        setTimeout(() => { if (document.body.contains(iframe)) document.body.removeChild(iframe); }, 500);

    } catch (error) {
        log.error("Error in sendMessageTo:", error);
        success = false;
    } finally {
        button.classList.toggle('success', success);
        button.classList.toggle('error', !success);
        setTimeout(() => button.classList.remove('success', 'error'), 1000);
    }
    return success;
}

function escapeHTML(str) {
    if (str === undefined || str === null) return '';
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
window.escapeHTML = escapeHTML;

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
        const originKey = window.getStorageKeyForUrl(msg.origin);
        const destKey = window.getStorageKeyForUrl(msg.destinationUrl);
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
            messageItem.setAttribute('data-message-id', msg.messageId);

            const sanitizedData = sanitizeMessageData(msg.data);
            let dataForDisplay;
            try {
                dataForDisplay = typeof sanitizedData === 'string' ? sanitizedData : JSON.stringify(sanitizedData, null, 2);
            } catch (e) {
                dataForDisplay = String(sanitizedData);
            }

            const header = document.createElement("div");
            header.className = "message-header";
            const originDisplay = normalizeEndpointUrl(msg.origin)?.normalized || msg.origin || '?';
            const destDisplay = normalizeEndpointUrl(msg.destinationUrl)?.normalized || msg.destinationUrl || '?';
            const messageTypeDisplay = (msg.messageType || 'unknown').replace(/\s+/g, '-').toLowerCase();
            header.innerHTML = `<strong>Origin:</strong> ${escapeHTML(originDisplay)}<br><strong>Destination:</strong> ${escapeHTML(destDisplay)}<br><strong>Time:</strong> ${new Date(msg.timestamp).toLocaleString()}<br><strong>Msg Type:</strong> <span class="message-type message-type-${messageTypeDisplay}">${escapeHTML(msg.messageType || '?')}</span>`;

            const dataPre = document.createElement("pre");
            dataPre.className = "message-data";
            dataPre.textContent = dataForDisplay;

            const controls = document.createElement("div");
            controls.className = "message-controls";

            const originBtn = document.createElement("button");
            originBtn.className = "send-origin";
            originBtn.textContent = "Resend to Origin";
            originBtn.addEventListener('click', () => sendMessageTo(window.getStorageKeyForUrl(msg.origin), originBtn));

            const destBtn = document.createElement("button");
            destBtn.className = "send-destination";
            destBtn.textContent = "Resend to Destination";
            destBtn.addEventListener('click', () => sendMessageTo(window.getStorageKeyForUrl(msg.destinationUrl), destBtn));

            const editBtn = document.createElement("button");
            editBtn.className = "edit-send";
            editBtn.textContent = "Edit & Send";
            editBtn.addEventListener('click', () => showEditModal(msg));

            controls.appendChild(originBtn);
            controls.appendChild(destBtn);
            controls.appendChild(editBtn);
            messageItem.appendChild(header);
            messageItem.appendChild(dataPre);
            messageItem.appendChild(controls);
            messagesList.appendChild(messageItem);
        } catch (e) {
            log.error("Error rendering message item:", e);
        }
    });
}

function showEditModal(messageObject) {
    const modalContainer = document.getElementById('editMessageModalContainer');
    if (!modalContainer) {
        console.error("Edit modal container not found");
        return;
    }
    modalContainer.innerHTML = '';

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    const modal = document.createElement('div');
    modal.className = 'edit-message-modal';

    let dataToEdit;
    try { dataToEdit = (typeof messageObject.data === 'string') ? messageObject.data : JSON.stringify(messageObject.data, null, 2); }
    catch (e) { dataToEdit = String(messageObject.data); }

    const originDisplay = escapeHTML(normalizeEndpointUrl(messageObject.origin)?.normalized || messageObject.origin);
    const destDisplay = escapeHTML(normalizeEndpointUrl(messageObject.destinationUrl)?.normalized || messageObject.destinationUrl);

    modal.innerHTML = `
        <div class="edit-modal-header"><h4>Edit Message</h4>
            <div class="message-info"><strong>Origin:</strong> ${originDisplay}<br><strong>Destination:</strong> ${destDisplay}<br><strong>Time:</strong> ${new Date(messageObject.timestamp).toLocaleString()}</div>
            <button class="close-modal-btn">&times;</button></div>
        <div class="edit-modal-body"><textarea id="messageEditTextarea">${escapeHTML(dataToEdit)}</textarea></div>
        <div class="edit-modal-footer"><button id="editCancelBtn" class="control-button secondary-button">Cancel</button><button id="editSendDestBtn" class="control-button">Send to Destination</button><button id="editSendOriginBtn" class="control-button">Send to Origin</button></div>`;

    modalContainer.appendChild(backdrop);
    modalContainer.appendChild(modal);

    const closeModal = () => { modalContainer.innerHTML = ''; };
    modal.querySelector('.close-modal-btn').addEventListener('click', closeModal);
    modal.querySelector('#editCancelBtn').addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);

    const textarea = modal.querySelector('#messageEditTextarea');
    const originKey = window.getStorageKeyForUrl(messageObject.origin);
    const destKey = window.getStorageKeyForUrl(messageObject.destinationUrl);

    modal.querySelector('#editSendOriginBtn').addEventListener('click', async () => {
        const success = await sendMessageFromModal(originKey, textarea.value, modal.querySelector('#editSendOriginBtn'), "Send to Origin");
        if (success) closeModal();
    });
    modal.querySelector('#editSendDestBtn').addEventListener('click', async () => {
        const success = await sendMessageFromModal(destKey, textarea.value, modal.querySelector('#editSendDestBtn'), "Send to Destination");
        if (success) closeModal();
    });
}

async function sendMessageFromModal(targetKey, editedDataString, buttonElement, originalButtonText) {
    if (!targetKey || !buttonElement) return false;
    let dataToSend;
    try { dataToSend = JSON.parse(editedDataString); } catch (e) { dataToSend = editedDataString; }

    buttonElement.textContent = 'Sending...'; buttonElement.disabled = true; buttonElement.classList.remove('success', 'error');
    let iframe = null;
    try {
        iframe = document.createElement('iframe'); iframe.style.display = 'none'; document.body.appendChild(iframe); iframe.src = targetKey;
        await new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => reject(new Error("Iframe load timeout")), 5000);
            iframe.onload = () => { clearTimeout(timeoutId); resolve(); };
            iframe.onerror = (err) => { clearTimeout(timeoutId); console.error("iframe load error", err); reject(new Error("Iframe load error")); };
        });

        if (iframe.contentWindow) {
            iframe.contentWindow.postMessage(dataToSend, '*');
            log.info(`Sent message from modal to ${targetKey}`, dataToSend);
            buttonElement.textContent = 'Sent ✓'; buttonElement.classList.add('success');
            await new Promise(res => setTimeout(res, 1000));
            return true;
        } else { throw new Error("Iframe content window not accessible"); }
    } catch (error) {
        log.error(`Error sending message from modal to ${targetKey}:`, error);
        buttonElement.textContent = 'Error ✕'; buttonElement.classList.add('error');
        await new Promise(res => setTimeout(res, 2000));
        return false;
    } finally {
        if (iframe && iframe.parentNode) iframe.parentNode.removeChild(iframe);
        if (buttonElement && !buttonElement.classList.contains('success')) {
            buttonElement.disabled = false;
            buttonElement.textContent = originalButtonText;
            buttonElement.classList.remove('error');
        }
    }
}

function highlightActiveEndpoint() {
    document.querySelectorAll('.endpoint-host, .iframe-row').forEach(el => el.classList.remove('active'));
    if (activeEndpoint) {
        document.querySelectorAll('.host-row, .iframe-row').forEach(el => {
            const key = el.classList.contains('host-row')
                ? (el.querySelector('.host-name')?.textContent || '').replace(/ \(\d+\)$/, '')
                : el.getAttribute('data-endpoint-key');
            if(key === activeEndpoint) {
                el.closest('.endpoint-host, .iframe-row').classList.add('active');
            }
        });
    }
}


function updateDashboardUI() {
    const filterInput = document.getElementById("endpointFilter");
    const filterValue = filterInput ? filterInput.value : "";
    renderEndpoints(filterValue);
    renderMessages();
    updateEndpointCounts();
    highlightActiveEndpoint();
}
window.updateDashboardUI = updateDashboardUI;

function updateEndpointCounts() {
    try {
        document.querySelectorAll('.host-name, .iframe-name').forEach(el => {
            const fullText = el.textContent || '';
            const keyText = fullText.replace(/ \(\d+\)$/, '');
            if (!keyText) return;
            const count = getMessageCount(keyText);
            el.textContent = `${keyText} (${count})`;
        });
    } catch { /* Ignore potential errors during UI update */ }
}

function initializeMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message?.type) return false;

        let needsUiUpdate = false;
        try {
            switch (message.type) {
                case "newPostMessage":
                    if (message.payload) {
                        const newMsg = message.payload;
                        const existingIndex = messages.findIndex(m => m.messageId === newMsg.messageId);
                        if (existingIndex >= 0) { messages[existingIndex] = newMsg; } else { messages.push(newMsg); }
                        needsUiUpdate = true;
                    }
                    break;
                case "newFrameConnection":
                    needsUiUpdate = true;
                    break;
                case "updateMessages":
                    if (message.messages) { messages.length = 0; messages.push(...message.messages); needsUiUpdate = true; }
                    break;
                case "handlerCapturedForEndpoint":
                case "handlerEndpointDetected":
                    if (message.payload?.endpointKey) {
                        const key = message.payload.endpointKey;
                        let addedNew = false;
                        if (!endpointsWithHandlers.has(key)) { endpointsWithHandlers.add(key); addedNew = true; }
                        if (!knownHandlerEndpoints.has(key)) { knownHandlerEndpoints.add(key); addedNew = true; }
                        if(addedNew) needsUiUpdate = true;
                    }
                    break;
                case "forwardedPostMessage":
                    // No UI update needed
                    break;
            }

            if (needsUiUpdate) {
                requestAnimationFrame(updateDashboardUI);
            }
            // Always send a response if callback exists, simplified logic
            if (sendResponse) sendResponse({ success: true });

        } catch (e) {
            console.error("[Dashboard Msg Handler] Error:", e);
            if (sendResponse) try { sendResponse({ success: false, error: e.message }); } catch(respErr){}
        }
        return true;
    });

    window.traceReportStorage.listAllReports().then(() => {
        chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => {
            if (chrome.runtime.lastError) { log.error("Error fetching initial state:", chrome.runtime.lastError); return; }
            if (response?.success) {
                if (response.messages) { messages.length = 0; messages.push(...response.messages); }
                if (response.handlerEndpointKeys) {
                    knownHandlerEndpoints.clear(); endpointsWithHandlers.clear();
                    response.handlerEndpointKeys.forEach(key => {
                        knownHandlerEndpoints.add(key);
                        endpointsWithHandlers.add(key);
                    });
                }
                updateDashboardUI();
            } else { log.error("Failed to fetch initial state:", response?.error); }
        });
    });
}


async function showHandlerModal(endpointKey) {
    const modalContainer = document.getElementById('handlerDisplayModalContainer');
    if (!modalContainer) return;
    modalContainer.innerHTML = '';

    const storageKey = `runtime-listeners-${endpointKey}`;
    log.handler(`[Show Handler] Fetching listeners for key: ${storageKey}`);
    modalContainer.innerHTML = '<div class="modal-backdrop"></div><div class="handler-display-modal"><div class="modal-loading">Loading listeners...</div></div>';
    const backdrop = modalContainer.querySelector('.modal-backdrop');
    const modal = modalContainer.querySelector('.handler-display-modal');
    const closeModal = () => { if (modalContainer) modalContainer.innerHTML = ''; };
    if(backdrop) backdrop.onclick = closeModal;

    chrome.storage.local.get([storageKey], (result) => {
        let content = '';
        if (chrome.runtime.lastError) {
            log.error(`[Show Handler] Error fetching listeners:`, chrome.runtime.lastError);
            content = `<p class="error-message">Failed to load listeners: ${chrome.runtime.lastError.message}</p>`;
        } else {
            const listeners = result[storageKey];
            log.handler(`[Show Handler] Found ${listeners?.length || 0} listeners for ${endpointKey}`);
            if (!listeners || listeners.length === 0) {
                content = `<p class="no-listeners-found">No runtime listeners captured for this endpoint.</p>`;
            } else {
                listeners.forEach((listener, index) => {
                    const captureContext = listener.context || 'unknown source';
                    const captureTime = listener.timestamp ? new Date(listener.timestamp).toLocaleString() : 'unknown time';
                    let codeContent = '[Code Unavailable]';
                    try { codeContent = listener.code.replace(/^ {8}/gm, '').replace(/\t/g, '  '); } catch{}

                    content += `<details class='listener-details' ${listeners.length === 1 ? 'open' : ''}>
                        <summary class='listener-summary'>Listener #${index + 1} (via <code>${escapeHTML(captureContext)}</code> at ${escapeHTML(captureTime)}) <span class="toggle-icon">${listeners.length === 1 ? '▼' : '▶'}</span></summary>
                        <div class='listener-content'><pre class='report-code-block listener-code'><code>${escapeHTML(codeContent)}</code></pre>`;
                    if (listener.stack) {
                        content += `<strong style='display: block; margin-top: 10px; font-size: 12px;'>Capture Stack Trace:</strong><pre class='report-code-block listener-stack' style='font-size: 11px; max-height: 150px; border-color: #555;'>${escapeHTML(listener.stack)}</pre>`;
                    }
                    content += `</div></details>`;
                });
            }
        }

        modal.innerHTML = `
            <div class="handler-modal-header"><h4>Captured Listeners</h4><div class="endpoint-info">For: ${escapeHTML(endpointKey)}</div><button class="close-modal-btn">&times;</button></div>
            <div class="handler-modal-body">${content}</div>`;
        modal.querySelector('.close-modal-btn').onclick = closeModal;
        modal.querySelectorAll('.listener-details').forEach(details => {
            details.addEventListener('toggle', () => {
                const icon = details.querySelector('.toggle-icon');
                if (icon) icon.textContent = details.open ? '▼' : '▶';
            });
        });
    });
}

function setupCallbackUrl() {
    const urlInput = document.getElementById('callbackUrlInput');
    const saveButton = document.getElementById('saveCallbackUrl');
    const statusElement = document.getElementById('callback-status');
    if (!urlInput || !saveButton || !statusElement) return;

    const updateCallbackStatus = (url, errorMessage = null) => {
        if (!statusElement) return; statusElement.innerHTML = ''; statusElement.className = 'callback-status';
        if (errorMessage) { statusElement.innerHTML = `<div class="error-message">${escapeHTML(errorMessage)}</div>`; statusElement.classList.add('callback-status-error'); }
        else if (url) { statusElement.innerHTML = `<div class="success-icon">✓</div><div class="status-message">Active (Session): <span class="url-value">${escapeHTML(url)}</span></div>`; statusElement.classList.add('callback-status-success'); }
        else { statusElement.innerHTML = `<div class="info-message">No callback URL set.</div>`; statusElement.classList.add('callback-status-info'); }
    };

    chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], (result) => {
        if (chrome.runtime.lastError) { log.error("[Callback URL] Error getting session storage:", chrome.runtime.lastError); updateCallbackStatus(null, `Error loading URL`); return; }
        const storedUrl = result[CALLBACK_URL_STORAGE_KEY] || null;
        if (storedUrl) { urlInput.value = storedUrl; window.frogPostState.callbackUrl = storedUrl; }
        updateCallbackStatus(storedUrl);
    });

    saveButton.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url) {
            chrome.storage.session.remove(CALLBACK_URL_STORAGE_KEY, () => {
                window.frogPostState.callbackUrl = null; updateCallbackStatus(null, chrome.runtime.lastError ? 'Error clearing URL' : null);
                if(!chrome.runtime.lastError) log.info(`[Callback URL] Cleared.`);
            });
        } else if (isValidUrl(url)) {
            chrome.storage.session.set({ [CALLBACK_URL_STORAGE_KEY]: url }, () => {
                window.frogPostState.callbackUrl = url; updateCallbackStatus(url, chrome.runtime.lastError ? 'Error saving URL' : null);
                if(!chrome.runtime.lastError) log.info(`[Callback URL] Saved: ${url}`);
            });
        } else { updateCallbackStatus(window.frogPostState.callbackUrl, 'Invalid URL format.'); }
    });
}

function setupUIControls() {
    document.getElementById("clearMessages")?.addEventListener("click", () => {
        log.info("Clearing dashboard state...");
        messages.length = 0; buttonStates.clear(); traceButtonStates.clear(); reportButtonStates.clear();
        activeEndpoint = null; endpointsWithHandlers.clear(); knownHandlerEndpoints.clear(); modifiedEndpoints.clear(); launchInProgressEndpoints.clear();
        chrome.storage.local.clear(() => log.info("Local storage cleared."));
        chrome.runtime.sendMessage({ type: "resetState" }, (response) => log.info("Background reset:", response));
        updateDashboardUI();
    });
    document.getElementById("exportMessages")?.addEventListener("click", () => {
        const sanitizedMessages = messages.map(msg => ({ origin: msg.origin, destinationUrl: msg.destinationUrl, timestamp: msg.timestamp, data: sanitizeMessageData(msg.data), messageType: msg.messageType, messageId: msg.messageId }));
        const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "frogpost_messages.json"; a.click(); URL.revokeObjectURL(url);
    });
    document.getElementById("checkAll")?.addEventListener("click", checkAllEndpoints);
    const debugButton = document.getElementById("debugToggle");
    if (debugButton) { debugButton.addEventListener("click", toggleDebugMode); debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF'; debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off'; }
    document.getElementById("refreshMessages")?.addEventListener("click", () => { chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => { if (response?.success) { if (response.messages) { messages.length = 0; messages.push(...response.messages); } if (response.handlerEndpointKeys) { knownHandlerEndpoints.clear(); endpointsWithHandlers.clear(); response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); }); } log.info("Dashboard refreshed."); updateDashboardUI(); } else { log.error("Failed refresh:", response?.error); } }); });
    const uploadPayloadsButton = document.getElementById("uploadCustomPayloadsBtn"); const payloadFileInput = document.getElementById("customPayloadsFile"); if(uploadPayloadsButton && payloadFileInput){ uploadPayloadsButton.addEventListener('click', () => payloadFileInput.click()); payloadFileInput.addEventListener('change', handlePayloadFileSelect); }
    document.getElementById("clearCustomPayloadsBtn")?.addEventListener('click', clearCustomPayloads);
    setupCallbackUrl(); updatePayloadStatus();
}

async function handlePayloadFileSelect(event) {
    const file = event.target.files[0];
    const statusElement = document.getElementById("customPayloadStatus");
    if (!file || !file.name.toLowerCase().endsWith('.txt')) { showToastNotification('Invalid file type (.txt only).', 'error'); if (statusElement) statusElement.textContent = 'Upload: Invalid file type.'; event.target.value = null; return; }
    const reader = new FileReader();
    reader.onload = (e) => { validateAndStorePayloads(e.target.result); event.target.value = null; };
    reader.onerror = () => { showToastNotification('Error reading file.', 'error'); if (statusElement) statusElement.textContent = 'Upload: Error reading file.'; event.target.value = null; };
    reader.readAsText(file);
}

function validateAndStorePayloads(content) {
    const lines = content.split('\n'); const payloads = lines.map(line => line.trim()).filter(line => line.length > 0);
    if (payloads.length === 0) { showToastNotification('No valid payloads found.', 'warning'); updatePayloadStatus(false, 0); return; }
    log.info(`[Custom Payloads] Loaded ${payloads.length} payloads.`);
    chrome.storage.session.set({ customXssPayloads: payloads }, () => {
        if (chrome.runtime.lastError) { showToastNotification(`Error saving payloads`, 'error'); updatePayloadStatus(false, 0); }
        else {
            try { localStorage.setItem('customXssPayloads', JSON.stringify(payloads)); } catch (e) {} // Optional backup
            if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...payloads]; }
            showToastNotification(`Stored ${payloads.length} custom payloads.`, 'success'); updatePayloadStatus(true, payloads.length);
            console.log("%c[🚀 Custom Payloads Active]", "color: #2ecc71; font-weight: bold; font-size: 14px", `${payloads.length} payloads active.`);
        }
    });
}

function updatePayloadStatus(isActive = null, count = 0) {
    const statusElement = document.getElementById("customPayloadStatus");
    const uploadButton = document.getElementById("uploadCustomPayloadsBtn");
    const clearButton = document.getElementById("clearCustomPayloadsBtn");
    const updateUI = (active, payloadCount) => {
        if (statusElement) { statusElement.textContent = active ? `Custom Payloads Active (${payloadCount})` : 'Using Default Payloads'; statusElement.style.color = active ? 'var(--accent-primary)' : 'var(--text-secondary)'; }
        if (uploadButton) uploadButton.textContent = active ? 'Update Payloads' : 'Upload Payloads';
        if (clearButton) clearButton.style.display = active ? 'inline-block' : 'none';
    };
    if (isActive !== null) { updateUI(isActive, count); }
    else { chrome.storage.session.get('customXssPayloads', (result) => { const storedPayloads = result.customXssPayloads; const active = storedPayloads && storedPayloads.length > 0; updateUI(active, active ? storedPayloads.length : 0); }); }
}

function clearCustomPayloads() {
    chrome.storage.session.remove('customXssPayloads', () => {
        if (chrome.runtime.lastError) { showToastNotification(`Error clearing payloads`, 'error'); }
        else {
            try { localStorage.removeItem('customXssPayloads'); } catch (e) {}
            if (window.FuzzingPayloads && window.FuzzingPayloads._originalXSS) { window.FuzzingPayloads.XSS = [...window.FuzzingPayloads._originalXSS]; }
            showToastNotification('Custom payloads cleared.', 'info'); updatePayloadStatus(false, 0);
        }
    });
}

async function launchFuzzerEnvironment(endpoint, testData) {
    try {
        let traceReport = null; const endpointKey = window.getStorageKeyForUrl(endpoint); let analysisKeyToUse = endpointKey;
        try { const traceInfoKey = `trace-info-${endpointKey}`; const traceInfo = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, result => resolve(result[traceInfoKey]))); if (traceInfo?.analysisStorageKey) analysisKeyToUse = traceInfo.analysisStorageKey; else if (traceInfo?.analyzedUrl) analysisKeyToUse = window.getStorageKeyForUrl(traceInfo.analyzedUrl); window.log.handler(`[Launch] Using analysis key: ${analysisKeyToUse}`); traceReport = await window.traceReportStorage.getTraceReport(analysisKeyToUse); } catch (e) {}
        if (!traceReport) { window.log.warning(`[Launch] Trace report not found for key ${analysisKeyToUse}, trying original key ${endpointKey}`); traceReport = await window.traceReportStorage.getTraceReport(endpointKey); if (traceReport) analysisKeyToUse = endpointKey; else throw new Error('No trace report found. Run Play & Trace first.'); }

        const handlerCode = traceReport?.analyzedHandler?.handler || traceReport?.analyzedHandler?.code || testData?.handler; if (!handlerCode) throw new Error('No handler code found. Run Play first.');
        let payloads = []; try { payloads = await window.traceReportStorage.getReportPayloads(analysisKeyToUse); } catch {} if (payloads.length === 0 && traceReport?.details?.payloads?.length > 0) payloads = traceReport.details.payloads; else if (payloads.length === 0 && traceReport?.payloads?.length > 0) payloads = traceReport.payloads; else if (payloads.length === 0 && testData?.payloads?.length > 0) payloads = testData.payloads; if (payloads.length === 0) window.log.warning('[Launch] No specific payloads found.');
        let messages = testData?.originalMessages || await window.retrieveMessagesWithFallbacks(endpointKey); if (messages.length === 0 && traceReport?.details?.uniqueStructures?.length > 0) messages = traceReport.details.uniqueStructures.flatMap(s => s.examples || []) || [];

        await chrome.runtime.sendMessage({ action: "startServer" }); await new Promise(resolve => setTimeout(resolve, 1500));
        let serverStarted = false; let attempts = 0; const maxAttempts = 3; while (!serverStarted && attempts < maxAttempts) { attempts++; try { const health = await fetch('http://127.0.0.1:1337/health', { method: 'GET', cache: 'no-store', signal: AbortSignal.timeout(800) }); if (health.ok) serverStarted = true; } catch { await new Promise(r => setTimeout(r, 700)); } } if (!serverStarted) throw new Error("Fuzzer server did not start.");
        const storageData = await chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY]); const currentCallbackUrl = storageData[CALLBACK_URL_STORAGE_KEY] || null; const customPayloadsResult = await new Promise(resolve => chrome.storage.session.get('customXssPayloads', result => resolve(result.customXssPayloads))); const useCustomPayloads = customPayloadsResult && customPayloadsResult.length > 0;

        const config = {
            target: traceReport.endpoint || endpoint, messages: messages, handler: handlerCode, payloads: payloads,
            traceData: {
                ...(traceReport || {}),
                details: {
                    ...(traceReport?.details || {}),
                    originValidationChecks: traceReport?.details?.originValidationChecks || []
                }
            },
            callbackUrl: currentCallbackUrl,
            fuzzerOptions: { autoStart: true, useCustomPayloads: useCustomPayloads, enableCallbackFuzzing: !!currentCallbackUrl, /* other defaults */ }
        };

        const response = await fetch('http://127.0.0.1:1337/current-config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config), signal: AbortSignal.timeout(5000) }); if (!response.ok) throw new Error(`Config update failed: ${response.statusText}`);
        const tab = await chrome.tabs.create({ url: 'http://127.0.0.1:1337/' }); const cleanupListener = (tabId) => { if (tabId === tab.id) { chrome.runtime.sendMessage({ action: "stopServer" }); chrome.tabs.onRemoved.removeListener(cleanupListener); } }; chrome.tabs.onRemoved.addListener(cleanupListener); return true;
    } catch (error) { alert(`Fuzzer Launch Failed: ${error.message}`); window.log.error("[Launch Fuzzer Env]", error); try { await chrome.runtime.sendMessage({ action: "stopServer" }); } catch {} return false; }
}


function showQueryModal(endpoint) {
    return new Promise((resolve) => {
        try {
            log.handler(`[Query Modal] Opening for: ${endpoint}`);
            const originalUrl = new URL(endpoint); const currentParams = new URLSearchParams(originalUrl.search);
            const modalContainer = document.getElementById('queryModalContainer');
            if (!modalContainer) throw new Error("Query modal container not found.");
            modalContainer.innerHTML = '';

            const modal = document.createElement('div'); modal.className = 'query-modal';
            let modalContentHTML = `<h2 class="query-modal-title">Modify Query Parameters</h2><div class="query-modal-body">`;
            let paramCount = 0;
            currentParams.forEach((value, key) => { paramCount++; modalContentHTML += `<div class="query-param-row"><label class="query-param-label">${escapeHTML(key)}:</label><input type="text" class="query-param-input" value="${escapeHTML(value)}" data-param="${escapeHTML(key)}"></div>`; });
            if (paramCount === 0) modalContentHTML += '<p class="query-modal-no-params">No query parameters found.</p>';
            modalContentHTML += `</div><div class="query-modal-footer"><button id="cancelBtn" class="control-button secondary-button">Cancel</button><button id="okBtn" class="control-button primary-button">OK</button></div>`;
            modal.innerHTML = modalContentHTML;

            const backdrop = document.createElement('div'); backdrop.className = 'modal-backdrop';
            const closeModal = (result) => { modalContainer.innerHTML = ''; resolve(result); };

            modalContainer.appendChild(backdrop); modalContainer.appendChild(modal);
            modal.querySelector('#okBtn').addEventListener('click', () => {
                const modifiedUrl = new URL(endpoint); modifiedUrl.search = '';
                modal.querySelectorAll('input.query-param-input').forEach(input => modifiedUrl.searchParams.set(input.dataset.param, input.value));
                log.handler(`[Query Modal] OK. Modified URL: ${modifiedUrl.toString()}`);
                closeModal({ url: modifiedUrl.toString(), modified: true, originalUrl: endpoint });
            });
            modal.querySelector('#cancelBtn').addEventListener('click', () => closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint }));
            backdrop.addEventListener('click', () => closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint }));
        } catch (error) {
            log.error('[Query Modal] Error:', error);
            resolve({ url: endpoint, modified: false, originalUrl: endpoint });
        }
    });
}


async function saveRandomPostMessages(endpointKey) {
    const MAX_MESSAGES = 20;
    let relevantMessages = messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = window.getStorageKeyForUrl(msg.origin);
        const destKey = window.getStorageKeyForUrl(msg.destinationUrl);
        return originKey === endpointKey || destKey === endpointKey;
    });

    relevantMessages = relevantMessages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, MAX_MESSAGES);

    const processedMessages = relevantMessages.map(msg => {
        if (!msg.messageType) {
            let messageType = 'unknown'; let data = msg.data;
            if (data === undefined || data === null) messageType = 'null_or_undefined';
            else if (typeof data === 'string') { try { JSON.parse(data); messageType = 'json_string'; } catch { messageType = 'string'; } }
            else if (Array.isArray(data)) messageType = 'array';
            else if (typeof data === 'object') messageType = 'object';
            else messageType = typeof data;
            return {...msg, messageType: messageType};
        }
        return msg;
    });

    const storageKey = `saved-messages-${endpointKey}`;
    try { await chrome.storage.local.set({ [storageKey]: processedMessages }); return processedMessages; }
    catch (error) { log.error("Failed to save messages:", error); try { await chrome.storage.local.remove(storageKey); } catch {} return []; }
}

async function retrieveMessagesWithFallbacks(endpointKey) {
    const primaryStorageKey = `saved-messages-${endpointKey}`;
    try { const primaryResult = await new Promise(resolve => chrome.storage.local.get(primaryStorageKey, result => resolve(result[primaryStorageKey] || null))); if (primaryResult?.length > 0) return primaryResult; }
    catch(e) {} return [];
}
window.retrieveMessagesWithFallbacks = retrieveMessagesWithFallbacks;


async function handlePlayButton(endpoint, button, skipCheck = false) {
    const endpointKey = button.getAttribute('data-endpoint');
    if (!endpointKey) { log.error("[Play Button] No endpoint key found."); updateButton(button, 'error'); return; }
    const originalFullEndpoint = endpoint;

    const currentButtonContainer = button.closest('.button-container');
    const traceButton = currentButtonContainer?.querySelector('.iframe-trace-button');
    const reportButton = currentButtonContainer?.querySelector('.iframe-report-button');

    button.classList.remove('show-next-step-emoji', 'show-next-step-arrow');
    if (traceButton) traceButton.classList.remove('show-next-step-emoji');

    if (button.classList.contains('has-critical-sinks') || button.textContent === '🚀') {
        if (launchInProgressEndpoints.has(endpointKey)) return;
        launchInProgressEndpoints.add(endpointKey);
        log.scan(`Starting launch for key: ${endpointKey}`);
        try {
            const traceInfoKey = `trace-info-${endpointKey}`;
            const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
            const traceInfo = traceInfoResult[traceInfoKey];
            let analysisKeyToUse = endpointKey;
            if (traceInfo?.analysisStorageKey) analysisKeyToUse = traceInfo.analysisStorageKey;
            else if (traceInfo?.analyzedUrl) analysisKeyToUse = window.getStorageKeyForUrl(traceInfo.analyzedUrl);

            const [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(analysisKeyToUse), window.traceReportStorage.getReportPayloads(analysisKeyToUse) ]);

            if (!reportData) throw new Error(`Trace report not found for analysis key ${analysisKeyToUse}. Run Play/Trace again.`);

            const handlerCode = reportData?.analyzedHandler?.handler || reportData?.analyzedHandler?.code;
            if (!handlerCode) throw new Error(`Handler code missing in report for launch. Key: ${analysisKeyToUse}`);

            let relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
            if (relevantMessages.length === 0 && reportData?.details?.uniqueStructures?.length > 0) { relevantMessages = reportData.details.uniqueStructures.flatMap(s => s.examples || []); }
            const payloads = reportPayloads || reportData?.details?.payloads || reportData?.payloads || [];
            const targetEndpointForLaunch = reportData.endpoint || endpointKey;
            const testData = { target: targetEndpointForLaunch, originalMessages: relevantMessages, handler: handlerCode, sinks: reportData.details?.sinks || reportData.vulnerabilities || [], payloads: payloads };
            const success = await launchFuzzerEnvironment(targetEndpointForLaunch, testData);
            updateButton(button, success ? 'launch' : 'error', { hasCriticalSinks: button.classList.contains('has-critical-sinks') });
            if (traceButton) updateTraceButton(traceButton, success ? 'success' : 'default');
        } catch (error) {
            log.error('[Launch Error]:', error?.message); alert(`Fuzzer launch failed: ${error.message}`); updateButton(button, 'error'); if (traceButton) updateTraceButton(traceButton, 'disabled'); try { await chrome.runtime.sendMessage({ action: "stopServer" }); } catch {}
        } finally { launchInProgressEndpoints.delete(endpointKey); setTimeout(() => requestAnimationFrame(updateDashboardUI), 100); }
        return;
    }

    if (launchInProgressEndpoints.has(endpointKey)) return;
    launchInProgressEndpoints.add(endpointKey);
    let analysisStorageKey = endpointKey; let endpointUrlForAnalysis = originalFullEndpoint; let handlerStateUpdated = false; let foundHandlerObject = null; let usingStaticFallback = false;

    try {
        await saveRandomPostMessages(endpointKey);
        const modalResult = await showQueryModal(originalFullEndpoint);
        if (modalResult.cancelled) { updateButton(button, 'start'); throw new Error("User cancelled"); }

        if (modalResult.modified) {
            endpointUrlForAnalysis = modalResult.url; analysisStorageKey = window.getStorageKeyForUrl(endpointUrlForAnalysis);
            const mappingKey = `analyzed-url-for-${endpointKey}`;
            await chrome.storage.local.set({ [mappingKey]: endpointUrlForAnalysis, [`analysis-storage-key-for-${endpointKey}`]: analysisStorageKey });
            modifiedEndpoints.set(endpointKey, endpointUrlForAnalysis);
        } else {
            analysisStorageKey = window.getStorageKeyForUrl(originalFullEndpoint); endpointUrlForAnalysis = originalFullEndpoint;
            await chrome.storage.local.remove([`analyzed-url-for-${endpointKey}`, `analysis-storage-key-for-${endpointKey}`]);
            modifiedEndpoints.delete(endpointKey);
        }
        log.handler(`Using URL for analysis: ${endpointUrlForAnalysis}, Storage key: ${analysisStorageKey}`);

        if (!skipCheck) {
            updateButton(button, 'csp'); const cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
            if (!cspResult.embeddable) throw new Error(`Embedding check failed: ${cspResult.status}`);
        }

        updateButton(button, 'analyze');
        const runtimeListenerKey = `runtime-listeners-${endpointKey}`;
        const runtimeResult = await new Promise(resolve => chrome.storage.local.get(runtimeListenerKey, resolve));
        const runtimeListeners = runtimeResult ? runtimeResult[runtimeListenerKey] : null;
        const validRuntimeListeners = runtimeListeners?.filter(l => l?.code && typeof l.code === 'string' && !l.code.includes('[native code]') && l.code.length > 25) || [];

        if (validRuntimeListeners.length > 0) {
            log.success(`[Play] Found ${validRuntimeListeners.length} valid runtime listener(s).`);
            if (validRuntimeListeners.length === 1) {
                const chosen = validRuntimeListeners[0];
                foundHandlerObject = { handler: chosen.code, category: 'runtime-captured-single', score: 50, source: 'runtime-instrumentation', timestamp: chosen.timestamp, stack: chosen.stack, context: chosen.context };
            } else {
                const scoringMessages = await retrieveMessagesWithFallbacks(endpointKey);
                if (scoringMessages.length > 0) {
                    try { const extractor = new HandlerExtractor().initialize(endpointUrlForAnalysis, scoringMessages); foundHandlerObject = extractor.getBestHandler(validRuntimeListeners.map(l => ({...l, handler: l.code, category: 'runtime-captured-scored'}))); } catch(e){ log.error("Error scoring runtime handlers:", e); }
                }
                if (!foundHandlerObject) { const chosen = validRuntimeListeners[0]; foundHandlerObject = { handler: chosen.code, category: 'runtime-captured-first', score: 50, source: 'runtime-instrumentation', timestamp: chosen.timestamp, stack: chosen.stack, context: chosen.context }; }
            }
        } else {
            log.warning(`[Play] No valid runtime listeners found. Trying static fallback.`);
            usingStaticFallback = true;
            try {
                const extractor = new HandlerExtractor().initialize(endpointUrlForAnalysis, await retrieveMessagesWithFallbacks(endpointKey));
                const extractedFallbackHandlers = await extractor.extract();
                foundHandlerObject = extractor.getBestHandler(extractedFallbackHandlers);
                if(foundHandlerObject) log.success(`[Play] Selected handler via static fallback (Score: ${foundHandlerObject.score?.toFixed(1)})`);
            } catch (extractionError) { log.error(`[Play] Static fallback failed:`, extractionError); }
        }

        if (foundHandlerObject?.handler) {
            const finalBestHandlerKey = `best-handler-${analysisStorageKey}`;
            try { await chrome.storage.local.set({ [finalBestHandlerKey]: foundHandlerObject }); log.success(`Saved best handler to: ${finalBestHandlerKey}`); const runtimeListKey = `runtime-listeners-${endpointKey}`; try { const res = await new Promise(resolve => chrome.storage.local.get(runtimeListKey, resolve)); let listeners = res[runtimeListKey] || []; if (!listeners.some(l => l.code === foundHandlerObject.handler)) { listeners.push({ code: foundHandlerObject.handler, context: `selected-by-play (${foundHandlerObject.category})`, timestamp: Date.now() }); if (listeners.length > 30) listeners = listeners.slice(-30); await chrome.storage.local.set({ [runtimeListKey]: listeners }); if (!endpointsWithHandlers.has(endpointKey)) { endpointsWithHandlers.add(endpointKey); handlerStateUpdated = true; } } } catch (e) { log.error("Failed updating runtime list", e); } updateButton(button, 'success'); if (traceButton) updateTraceButton(traceButton, 'default', { showEmoji: true }); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
            catch (storageError) { log.error(`Failed to save handler (${finalBestHandlerKey}):`, storageError); updateButton(button, 'error'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        } else { log.error(`[Play] No usable handler found.`); updateButton(button, 'warning'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        if (handlerStateUpdated) requestAnimationFrame(updateDashboardUI);
    } catch (error) {
        if (error.message === "User cancelled") { log.info(`Play cancelled for key ${endpointKey}.`); const currentState = buttonStates.get(endpointKey)?.state || 'start'; if (['start', 'csp', 'analyze', 'checking', 'default'].includes(currentState)) updateButton(button, 'start'); }
        else { log.error(`[Play Button Error] for key ${endpointKey}:`, error.message); showToastNotification(`Error: ${error.message.substring(0, 150)}`, 'error'); updateButton(button, 'error', { errorMessage: 'An error occurred' }); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
    } finally { launchInProgressEndpoints.delete(endpointKey); setTimeout(() => requestAnimationFrame(updateDashboardUI), 150); }
}

function getRiskLevelAndColor(score) {
    if (score <= 20) return { riskLevel: 'Critical', riskColor: 'critical' }; if (score <= 40) return { riskLevel: 'High', riskColor: 'high' }; if (score <= 60) return { riskLevel: 'Medium', riskColor: 'medium' }; if (score <= 80) return { riskLevel: 'Low', riskColor: 'low' }; return { riskLevel: 'Good', riskColor: 'negligible' };
}

function getRecommendationText(score, reportData) {
    const hasCriticalSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'critical') || false; const hasHighSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'high') || false; const hasHighIssue = reportData?.details?.securityIssues?.some(s => s.severity?.toLowerCase() === 'high') || false; const mediumIssueCount = reportData?.details?.securityIssues?.filter(s => s.severity?.toLowerCase() === 'medium')?.length || 0;
    if (hasCriticalSink) return 'Immediate attention required. Critical vulnerabilities present. Fix critical sinks (eval, innerHTML, etc.) and implement strict origin/data validation.';
    if (score <= 20) return 'Immediate attention required. Security posture is critically weak. Focus on fixing high-risk issues and implementing strict origin/data validation.';
    if (hasHighSink || hasHighIssue || score <= 40) return 'Significant risks identified. Implement strict origin checks and sanitize all inputs used in sinks. Consider a Content Security Policy (CSP).';
    if (mediumIssueCount >= 3 || score <= 60) return 'Potential vulnerabilities detected. Review security issues (e.g., origin checks, data validation) and ensure data flowing to sinks is safe.';
    if (score <= 80) return 'Low risk detected, but review identified issues and follow security best practices (origin/data validation).';
    const hasFindings = (reportData?.details?.sinks?.length > 0) || (reportData?.details?.securityIssues?.length > 0); if (hasFindings) return 'Good score, but minor issues or informational findings detected. Review details and ensure best practices are followed.';
    return 'Excellent score. Analysis found no major vulnerabilities. Continue to follow security best practices for postMessage handling.';
}

function renderStructureItem(structureData, index) {
    const exampleData = structureData.examples?.[0]?.data || structureData.examples?.[0] || {}; let formattedExample = ''; try { formattedExample = typeof exampleData === 'string' ? exampleData : JSON.stringify(exampleData, null, 2); } catch (e) { formattedExample = String(exampleData); }
    return `<details class="report-details structure-item" data-structure-index="${index}"><summary class="report-summary-toggle">Structure ${index + 1} <span class="toggle-icon">▶</span></summary><div class="structure-content"><p><strong>Example Message:</strong></p><div class="report-code-block"><pre><code>${escapeHTML(formattedExample)}</code></pre></div></div></details>`;
}

function renderPayloadItem(payloadItem, index) {
    let displayString = '(Error displaying payload)'; const maxDisplayLength = 150; const safeEscapeHTML = (str) => { try { return escapeHTML(str); } catch{ return '[Error]'; }};
    try { const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem; if (typeof actualPayloadData === 'object' && actualPayloadData !== null) { const payloadJson = JSON.stringify(actualPayloadData, null, 2); displayString = payloadJson.substring(0, maxDisplayLength) + (payloadJson.length > maxDisplayLength ? '...' : ''); } else { const payloadAsString = String(actualPayloadData); displayString = payloadAsString.substring(0, maxDisplayLength) + (payloadAsString.length > maxDisplayLength ? '...' : ''); } }
    catch (e) { console.error(`[renderPayloadItem] Error processing payload index ${index}:`, e); return `<div class="payload-item error">Error rendering payload ${index + 1}. See console.</div>`; }
    return `<div class="payload-item" data-payload-index="${index}"><pre><code>${safeEscapeHTML(displayString)}</code></pre></div>`;
}

function attachReportEventListeners(panel, reportData) {
    panel.querySelectorAll('details.report-details').forEach(detailsElement => { const iconElement = detailsElement.querySelector('.toggle-icon'); if (detailsElement && iconElement) { detailsElement.addEventListener('toggle', () => { iconElement.textContent = detailsElement.open ? '▼' : '▶'; }); } });
    panel.querySelectorAll('.view-full-payload-btn').forEach(btn => { btn.addEventListener('click', (e) => { const item = e.target.closest('.payload-item'); const index = parseInt(item?.getAttribute('data-payload-index')); const payloads = reportData?.details?.payloads || []; if (payloads[index] !== undefined) { showFullPayloadModal(payloads[index]); } }); });
    const showAllPayloadsBtn = panel.querySelector('#showAllPayloadsBtn'); if (showAllPayloadsBtn) { showAllPayloadsBtn.addEventListener('click', () => { const list = panel.querySelector('#payloads-list'); const payloads = reportData?.details?.payloads || []; if (list && payloads.length > 0) { list.innerHTML = payloads.map((p, index) => renderPayloadItem(p, index)).join(''); attachReportEventListeners(panel, reportData); } showAllPayloadsBtn.remove(); }, { once: true }); }
    const showAllStructuresBtn = panel.querySelector('#showAllStructuresBtn'); if (showAllStructuresBtn) { showAllStructuresBtn.addEventListener('click', () => { const list = panel.querySelector('.structures-list'); const structures = reportData?.details?.uniqueStructures || []; if (list && structures.length > 0) { list.innerHTML = structures.map((s, index) => renderStructureItem(s, index)).join(''); attachReportEventListeners(panel, reportData); } showAllStructuresBtn.remove(); }, { once: true }); }
}


function displayReport(reportData, panel) {
    try { panel.innerHTML = ''; } catch { panel.innerHTML = '<p class="error-message">Error clearing report panel.</p>'; return; }
    let content; try { content = document.createElement('div'); content.className = 'trace-results-content'; panel.appendChild(content); } catch { panel.innerHTML = '<p class="error-message">Error creating report content area.</p>'; return; }
    if (!reportData || typeof reportData !== 'object') { content.innerHTML = '<p class="error-message">Error: Invalid report data.</p>'; return; }
    try {
        const details = reportData.details || {}; const summary = reportData.summary || {}; const bestHandler = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler; const vulnerabilities = [...(details.sinks || []), ...(reportData.vulnerabilities || [])]; const securityIssues = [...(details.securityIssues || []), ...(reportData.securityIssues || [])]; const dataFlows = details.dataFlows || []; const payloads = details.payloads || []; const structures = details.uniqueStructures || []; const endpointDisplay = reportData.endpoint || reportData.originalEndpointKey || 'Unknown Endpoint'; const originChecks = details.originValidationChecks || [];
        const safeEscape = (str) => { try { return window.escapeHTML(String(str)); } catch{ return '[Error]'; }}; const safeGetRisk = (score) => { try { return getRiskLevelAndColor(score); } catch{ return { riskLevel: 'Error', riskColor: 'critical' }; }}; const safeGetRec = (score, data) => { try { return getRecommendationText(score, data); } catch{ return 'Error generating recommendation.'; }}; const safeRenderPayload = (p, i) => { try { return renderPayloadItem(p, i); } catch{ return '<p class="error-message">Error rendering payload item.</p>'; }}; const safeRenderStructure = (s, i) => { try { return renderStructureItem(s, i); } catch{ return '<p class="error-message">Error rendering structure item.</p>'; }};
        const uniqueVulns = vulnerabilities.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i); const uniqueIssues = securityIssues.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const score = reportData.securityScore ?? summary.securityScore ?? 100; const { riskLevel, riskColor } = safeGetRisk(score);
        const summarySection = document.createElement('div'); summarySection.className = 'report-section report-summary'; summarySection.innerHTML = `<h4 class="report-section-title">Analysis Summary - <span class="report-endpoint-title">${safeEscape(endpointDisplay)}</span></h4><div class="summary-grid"><div class="security-score-container"><h5 class="risk-score-title">Risk Score:</h5><div class="security-score ${riskColor}" title="Risk Score: ${score} (${riskLevel})"><div class="security-score-value">${score}</div><div class="security-score-label">${riskLevel}</div></div></div><div class="summary-metrics"><div class="metric"><span class="metric-label">Msgs Analyzed</span><span class="metric-value">${summary.messagesAnalyzed ?? 'N/A'}</span></div><div class="metric"><span class="metric-label">Msg Structures</span><span class="metric-value">${structures?.length ?? 0}</span></div><div class="metric"><span class="metric-label">Sinks Found</span><span class="metric-value">${uniqueVulns?.length ?? 0}</span></div><div class="metric"><span class="metric-label">Sec. Issues</span><span class="metric-value">${uniqueIssues?.length ?? 0}</span></div><div class="metric"><span class="metric-label">Payloads Gen.</span><span class="metric-value">${payloads?.length ?? 0}</span></div></div></div><div class="recommendations"><h5 class="report-subsection-title">Recommendation</h5><p class="recommendation-text">${safeEscape(safeGetRec(score, reportData))}</p></div>`; content.appendChild(summarySection);
        if (bestHandler?.handler) { const handlerSection = document.createElement('div'); handlerSection.className = 'report-section report-handler'; handlerSection.innerHTML = `<details class="report-details"><summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Cat: ${safeEscape(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▶</span></summary><div class="report-code-block handler-code"><pre><code>${safeEscape(bestHandler.handler)}</code></pre></div></details>`; content.appendChild(handlerSection); }
        const findingsSection = document.createElement('div'); findingsSection.className = 'report-section report-findings'; let findingsHTML = '<h4 class="report-section-title">Findings</h4>';
        if (originChecks.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Origin Validation (${originChecks.length})</h5><table class="report-table"><thead><tr><th>Check Type</th><th>Strength</th><th>Compared Value</th><th>Snippet</th></tr></thead><tbody>`;
            originChecks.forEach(check => {
                const type = check?.type || '?'; const strength = check?.strength || 'N/A'; const value = check?.value !== null && check?.value !== undefined ? String(check.value).substring(0, 100) : 'N/A'; const snippetHTML = check?.snippet ? `<code class="context-snippet">${safeEscape(check.snippet)}</code>` : 'N/A';
                let strengthClass = strength.toLowerCase(); if(strength === 'Missing') strengthClass = 'critical'; else if(strength === 'Weak') strengthClass = 'high'; else if(strength === 'Medium') strengthClass = 'medium'; else if(strength === 'Strong') strengthClass = 'negligible'; else strengthClass='low';
                findingsHTML += `<tr class="severity-row-${strengthClass}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${strengthClass}">${safeEscape(strength)}</span></td><td><code>${safeEscape(value)}</code></td><td>${snippetHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        } else { findingsHTML += `<p class="no-findings-text">No specific origin checks identified via static analysis.</p>`; }
        if (uniqueVulns.length > 0) { findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">DOM XSS Sinks Detected (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`; uniqueVulns.forEach(vuln => { const type = vuln?.type || '?'; const severity = vuln?.severity || 'N/A'; const contextHTML = vuln?.context || ''; findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscape(severity)}</span></td><td class="context-snippet-cell">${contextHTML}</td></tr>`; }); findingsHTML += `</tbody></table></div>`; } else { findingsHTML += `<p class="no-findings-text">No direct DOM XSS sinks found.</p>`; }
        if (uniqueIssues.length > 0) { findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Other Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`; uniqueIssues.forEach(issue => { const type = issue?.type || '?'; const severity = issue?.severity || 'N/A'; const contextHTML = issue?.context || ''; findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscape(severity)}</span></td><td class="context-snippet-cell">${contextHTML}</td></tr>`; }); findingsHTML += `</tbody></table></div>`; } else { findingsHTML += `<p class="no-findings-text">No other security issues found.</p>`; }
        findingsSection.innerHTML = findingsHTML; content.appendChild(findingsSection);
        if (dataFlows?.length > 0) { const flowSection = document.createElement('div'); flowSection.className = 'report-section report-dataflow'; flowSection.innerHTML = `<h4 class="report-section-title">Data Flow (Message Data → Sink)</h4><table class="report-table dataflow-table"><thead><tr><th>Source Property</th><th>Sink Function</th><th>Context Snippet</th></tr></thead><tbody>`; dataFlows.forEach(flow => { const prop = flow?.property || flow?.sourcePath || '?'; const sink = flow?.destinationContext || '?'; const context = flow?.fullCodeSnippet || flow?.taintedNodeSnippet || ''; flowSection.innerHTML += `<tr><td><code>event.data.${safeEscape(prop)}</code></td><td>${safeEscape(sink)}</td><td><code class="context-snippet">${safeEscape(context)}</code></td></tr>`; }); flowSection.innerHTML += `</tbody></table>`; content.appendChild(flowSection); }
        if (payloads?.length > 0) { const payloadSection = document.createElement('div'); payloadSection.className = 'report-section report-payloads'; payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (${payloads.length})</h4><div id="payloads-list" class="payloads-list report-list">${payloads.slice(0, 10).map((p, index) => safeRenderPayload(p, index)).join('')}</div>${payloads.length > 10 ? `<button id="showAllPayloadsBtn" class="control-button secondary-button show-more-btn">Show All ${payloads.length}</button>` : ''}`; content.appendChild(payloadSection); } else { const payloadSection = document.createElement('div'); payloadSection.className = 'report-section report-payloads'; payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (0)</h4><p class="no-findings-text">No specific payloads generated.</p>`; content.appendChild(payloadSection); }
        if (structures?.length > 0) { const structureSection = document.createElement('div'); structureSection.className = 'report-section report-structures'; let structuresHTML = `<h4 class="report-section-title">Unique Message Structures (${structures.length})</h4><div class="structures-list report-list">`; structures.slice(0, 3).forEach((s, index) => { structuresHTML += safeRenderStructure(s, index); }); structuresHTML += `</div>`; if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length}</button>`; } structureSection.innerHTML = structuresHTML; content.appendChild(structureSection); } else { const structureSection = document.createElement('div'); structureSection.className = 'report-section report-structures'; structureSection.innerHTML = `<h4 class="report-section-title">Unique Message Structures (0)</h4><p class="no-findings-text">No distinct message structures analyzed.</p>`; content.appendChild(structureSection); }
        const closeBtnInside = document.createElement('button'); closeBtnInside.textContent = 'Close Report'; closeBtnInside.className = 'control-button secondary-button'; closeBtnInside.style.marginTop = '20px'; closeBtnInside.style.display = 'block'; closeBtnInside.style.marginLeft = 'auto'; closeBtnInside.style.marginRight = 'auto'; closeBtnInside.onclick = () => { document.querySelector('.trace-panel-backdrop')?.remove(); panel.remove(); }; content.appendChild(closeBtnInside);
        attachReportEventListeners(panel, reportData);
    } catch (renderError) { content.innerHTML = `<p class="error-message">Error rendering report details: ${renderError.message}</p>`; window.log.error("Display Report Error", renderError); }
}


function showFullPayloadModal(payloadItem) {
    document.querySelector('.payload-modal')?.remove(); document.querySelector('.payload-modal-backdrop')?.remove();
    const modal = document.createElement('div'); modal.className = 'payload-modal'; const modalContent = document.createElement('div'); modalContent.className = 'payload-modal-content'; const closeBtn = document.createElement('span'); closeBtn.className = 'close-modal'; closeBtn.innerHTML = '&times;'; const backdrop = document.createElement('div'); backdrop.className = 'payload-modal-backdrop'; const closeModal = () => { modal.remove(); backdrop.remove(); }; closeBtn.onclick = closeModal; backdrop.onclick = closeModal;
    const heading = document.createElement('h4'); const targetInfo = document.createElement('p'); targetInfo.style.cssText = 'margin-bottom:15px;font-size:13px;color:#aaa;'; const payloadPre = document.createElement('pre'); payloadPre.className = 'report-code-block'; payloadPre.style.cssText = 'max-height:50vh;overflow-y:auto;'; const payloadCode = document.createElement('code');
    const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem;
    heading.textContent = `Payload Details (Type: ${escapeHTML(payloadItem?.type || 'unknown')})`; targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payloadItem?.targetPath || payloadItem?.targetFlow || payloadItem?.description || 'N/A')}`;
    let formattedPayload = ''; try { if (typeof actualPayloadData === 'object' && actualPayloadData !== null) { formattedPayload = JSON.stringify(actualPayloadData, null, 2); } else { formattedPayload = String(actualPayloadData); } } catch { formattedPayload = String(actualPayloadData); } payloadCode.textContent = formattedPayload;
    payloadPre.appendChild(payloadCode);
    const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy Payload'; copyBtn.className = 'control-button'; copyBtn.style.marginTop = '15px'; copyBtn.onclick = () => { navigator.clipboard.writeText(formattedPayload).then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }).catch(() => { copyBtn.textContent = 'Copy Failed'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }); };
    modalContent.appendChild(closeBtn); modalContent.appendChild(heading); modalContent.appendChild(targetInfo); modalContent.appendChild(payloadPre); modalContent.appendChild(copyBtn); modal.appendChild(modalContent); document.body.appendChild(backdrop); document.body.appendChild(modal);
}

async function handleReportButton(endpoint) {
    const endpointKey = window.getStorageKeyForUrl(endpoint);
    if (!endpointKey) { log.error('Report: Cannot get key for:', endpoint); return; }
    log.handler(`Report button clicked for key: ${endpointKey}`);
    let reportData = null; let reportPayloads = null; let keyUsed = endpointKey;
    try {
        const traceInfoKey = `trace-info-${endpointKey}`;
        const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
        const traceInfo = traceInfoResult[traceInfoKey];

        if (traceInfo?.analysisStorageKey) keyUsed = traceInfo.analysisStorageKey;
        else if (traceInfo?.analyzedUrl) keyUsed = window.getStorageKeyForUrl(traceInfo.analyzedUrl);
        log.handler(`[Report] Attempting fetch with key: ${keyUsed}`);
        [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]);

        if (!reportData && keyUsed !== endpointKey) { // Fallback to original key if analysis key failed
            log.warning(`[Report] Failed with analysis key, trying original key: ${endpointKey}`); keyUsed = endpointKey;
            [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]);
        }
        if (!reportData) throw new Error(`No report data found for key ${keyUsed}. Run Trace first.`);
        if (typeof reportData !== 'object' || reportData === null) throw new Error(`Invalid report data format`);

        if (!reportData.details) reportData.details = {}; reportData.details.payloads = reportPayloads || []; if (!reportData.summary) reportData.summary = {}; reportData.summary.payloadsGenerated = reportPayloads?.length || 0;

        document.querySelector('.trace-results-panel')?.remove(); document.querySelector('.trace-panel-backdrop')?.remove();
        const tracePanel = document.createElement('div'); tracePanel.className = 'trace-results-panel'; const backdrop = document.createElement('div'); backdrop.className = 'trace-panel-backdrop'; backdrop.onclick = () => { tracePanel.remove(); backdrop.remove(); };
        const reportContainer = document.getElementById('reportPanelContainer') || document.body; reportContainer.appendChild(backdrop); reportContainer.appendChild(tracePanel);
        addTraceReportStyles();
        displayReport(reportData, tracePanel);
    } catch (error) { log.error('Error handling report button:', error); alert(`Failed to display report: ${error?.message}`); }
}

async function checkAllEndpoints() {
    const endpointButtons = document.querySelectorAll('.iframe-row .iframe-check-button');
    for (const button of endpointButtons) {
        const endpointKey = button.getAttribute('data-endpoint');
        if (endpointKey && !button.classList.contains('green') && !button.classList.contains('success')) {
            try { await handlePlayButton(endpointKey, button); await new Promise(resolve => setTimeout(resolve, 500)); } catch {} // Ignore errors during bulk check
        }
    }
}

async function populateInitialHandlerStates() {
    log.debug("Populating initial handler states...");
    try {
        const allData = await chrome.storage.local.get(null);
        endpointsWithHandlers.clear();
        for (const key in allData) {
            if (key.startsWith('runtime-listeners-')) {
                if (Array.isArray(allData[key]) && allData[key].length > 0) {
                    endpointsWithHandlers.add(key.substring('runtime-listeners-'.length));
                }
            } else if (key.startsWith('best-handler-')) { // Also check for best handler existence
                endpointsWithHandlers.add(key.substring('best-handler-'.length));
            }
        }
        log.debug(`Initial handler states populated. Count: ${endpointsWithHandlers.size}`);
    } catch (error) { log.error("Error populating initial handler states:", error); }
    finally { updateDashboardUI(); }
}

const traceReportStyles = `
.trace-results-panel {
}
.trace-panel-backdrop {
}
.trace-panel-header {
}
.trace-panel-close {
}
.trace-results-content {
}
.report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; }
.report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); }
.report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; }
.report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; }
.security-score-container { display: flex; justify-content: center; }
.security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); }
.security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; }
.security-score div { position: relative; z-index: 2; }
.security-score-value { font-size: 28px; line-height: 1; }
.security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; }
.security-score.critical { border-color: #e74c3c; }
.security-score.high { border-color: #e67e22; }
.security-score.medium { border-color: #f39c12; }
.security-score.low { border-color: #3498db; }
.security-score.negligible { border-color: #2ecc71; }
.summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; }
.metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; }
.metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; }
.metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; }
.recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; }
.recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; }
.report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; }
.report-code-block pre { margin: 0; }
.report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; }
.report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; }
details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; }
summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; }
summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); }
details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; }
.toggle-icon { font-size: 1.2em; transition: transform 0.2s; }
details[open] .toggle-icon { transform: rotate(90deg); }
.report-details > div { padding: 15px; }
.report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; }
.report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; }
.report-table th { background-color: #2c313a; font-weight: bold; color: #fff; }
.report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; }
.report-table .context-snippet { max-width: 400px; white-space: pre-wrap; word-break: break-all; display: inline-block; vertical-align: middle; }
.severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
.severity-critical { background-color: #e74c3c; color: white; }
.severity-high { background-color: #e67e22; color: white; }
.severity-medium { background-color: #f39c12; color: #333; }
.severity-low { background-color: #3498db; color: white; }
.severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); }
.severity-row-high td { background-color: rgba(230, 126, 34, 0.15); }
.severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); }
.severity-row-low td { background-color: rgba(52, 152, 219, 0.1); }
.no-findings-text { color: #777; font-style: italic; padding: 10px 0; }
.dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; }
.report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; }
.payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; }
.payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; }
.payload-header strong { color: #fff; }
.payload-meta { color: #8be9fd; margin: 0 5px; }
.payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; }
.structure-content { padding: 15px; }
.structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; }
.structure-content strong { color: #00e1ff; }
.structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; }
.show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; }
.show-more-btn:hover { background-color: #4a5058; color: #fff; }
.control-button { }
.secondary-button { }
.error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; }

span.highlight-finding {
  background-color: rgba(255, 0, 0, 0.3);
  color: #ffdddd;
  font-weight: bold;
  padding: 1px 2px;
  border-radius: 2px;
  border: 1px solid rgba(255, 100, 100, 0.5);
}
`;

const progressStyles = `
.trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; }
.trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.phase-list { display: flex; flex-direction: column; gap: 10px; }
.phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; }
.phase .emoji { font-size: 20px; line-height: 1; }
.phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; }
.phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; }
.phase.active .label { color: #fff; font-weight: 600; }
.phase.active .emoji { animation: spin 1s linear infinite; }
.phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; }
.phase.completed .label { color: #50fa7b; }
.phase.completed .emoji::before { content: '✅'; }
.phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; }
.phase.error .label { color: #ff5555; font-weight: 600; }
.phase.error .emoji::before { content: '❌'; }
.phase[data-phase="finished"], .phase[data-phase="error"] { display: none; }
.phase[data-phase="finished"].completed, .phase[data-phase="error"].error { display: flex; }
@keyframes pulse-border {
  0% { border-color: #00e1ff; }
  50% { border-color: rgba(0, 225, 255, 0.5); }
  100% { border-color: #00e1ff; }
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
`;


function addTraceReportStyles() {
    if (!document.getElementById('frogpost-report-styles')) {
        const styleElement = document.createElement('style');
        styleElement.id = 'frogpost-report-styles';
        styleElement.textContent = traceReportStyles;
        document.head.appendChild(styleElement);
    }
}
window.addTraceReportStyles = addTraceReportStyles;

function addProgressStyles() {
    if (!document.getElementById('frogpost-progress-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'frogpost-progress-styles';
        styleEl.textContent = progressStyles;
        document.head.appendChild(styleEl);
    }
}

window.addProgressStyles = addProgressStyles;

window.addEventListener('DOMContentLoaded', () => {
    const clearStoredMessages = () => { chrome.runtime.sendMessage({ type: "resetState" }); localStorage.removeItem('interceptedMessages'); messages.length = 0; window.frogPostState.frameConnections.clear(); buttonStates.clear(); reportButtonStates.clear(); traceButtonStates.clear(); activeEndpoint = null; };
    clearStoredMessages();
    const sidebarToggle = document.getElementById('sidebarToggle'); const controlSidebar = document.getElementById('controlSidebar'); if (sidebarToggle && controlSidebar) { if (!controlSidebar.classList.contains('open')) sidebarToggle.classList.add('animate-toggle'); sidebarToggle.addEventListener('click', () => { controlSidebar.classList.toggle('open'); sidebarToggle.classList.toggle('animate-toggle', !controlSidebar.classList.contains('open')); }); }
    printBanner(); setupUIControls(); initializeMessageHandling(); populateInitialHandlerStates();
    addTraceReportStyles(); addProgressStyles();
    document.getElementById("endpointFilter")?.addEventListener("input", updateDashboardUI);
    updateDashboardUI();
    try { chrome.storage.session.get('customXssPayloads', (result) => { const storedPayloads = result.customXssPayloads; if (storedPayloads && storedPayloads.length > 0) { console.log(`[Init] Found ${storedPayloads.length} custom payloads in session.`); updatePayloadStatus(true, storedPayloads.length); if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...storedPayloads]; } } else { try { const localPayloads = localStorage.getItem('customXssPayloads'); if (localPayloads) { const parsed = JSON.parse(localPayloads); if (Array.isArray(parsed) && parsed.length > 0) { chrome.storage.session.set({ customXssPayloads: parsed }, () => { if (!chrome.runtime.lastError) { console.log(`[Init] Restored ${parsed.length} payloads from localStorage.`); updatePayloadStatus(true, parsed.length); if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...parsed]; } } }); } } } catch {} } }); } catch (e) {}
});
