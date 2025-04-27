/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-27
 */
window.frogPostState = {
    frameConnections: new Map(),
    messages: [],
    activeUrl: null,
    loadedData: { urls: new Set() },
    callbackUrl: null
};

let debugMode = false;

const log = {
    styles: { info: 'color: #0066cc; font-weight: bold', success: 'color: #00cc66; font-weight: bold', warning: 'color: #ff9900; font-weight: bold', error: 'color: #cc0000; font-weight: bold', handler: 'color: #6600cc; font-weight: bold', scan: 'color: #FFDC77; font-weight: bold', debug: 'color: #999999; font-style: italic' },
    _log: (style, icon, msg, details) => { console.log(`%c ${icon} ${msg}`, style); if (details && (debugMode || typeof details === 'string' || style === log.styles.error)) { const detailStyle = style === log.styles.error ? 'color: #cc0000;' : 'color: #666666;'; if (details instanceof Error) { console.error('%c    ' + details.message, detailStyle); if (details.stack && debugMode) console.error('%c    Stack Trace:', detailStyle, details.stack); } else if (typeof details === 'object' && debugMode) console.log('%c    Details:', detailStyle, details); else console.log('%c    ' + String(details), detailStyle); } },
    info: (msg, details) => log._log(log.styles.info, 'ℹ️', msg, details), success: (msg, details) => log._log(log.styles.success, '✅', msg, details), warning: (msg, details) => log._log(log.styles.warning, '⚠️', msg, details), warn: (msg, details) => log.warning(msg, details), error: (msg, details) => log._log(log.styles.error, '❌', msg, details), handler: (msg, details) => log._log(log.styles.handler, '🔍', msg, details), scan: (msg, details) => log._log(log.styles.scan, '🔄', msg, details),
    debug: (msg, ...args) => { if (debugMode) console.log('%c 🔧 ' + msg, log.styles.debug, ...args); }
};
window.log = log;

const knownHandlerEndpoints = new Set();
const endpointsWithHandlers = new Set();
const buttonStates = new Map();
const reportButtonStates = new Map();
const traceButtonStates = new Map();
const CALLBACK_URL_STORAGE_KEY = 'callback_url';
const launchInProgressEndpoints = new Set();
let uiUpdateTimer = null;
const DEBOUNCE_DELAY = 150;
let showOnlySilentIframes = false;
let hideSilentIframes = false;

function printBanner() {
    console.log(`%c
  _____                ____           _
 |  ___| __ ___   __ _|  _ \\ ___  ___| |_
 | |_ | '__/ _ \\ / _\` | |_) / _ \\/ __| __|
 |  _|| | | (_) | (_| |  __/ (_) \\__ \\ |_
 |_|  |_|  \\___/ \\__, |_|   \\___/|___/\\__|
                 |___/
`, 'color: #4dd051; font-weight: bold;');
    log.info('Initializing dashboard...');
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

function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    const xssPatterns = [ /<\s*script/i, /<\s*img[^>]+onerror/i, /javascript\s*:/i, /on\w+\s*=/i, /<\s*iframe/i, /<\s*svg[^>]+on\w+/i, /Function\s*\(/i, /setTimeout\s*\(/i, /setInterval\s*\(/i, /document\.domain/i, /document\.location/i, /location\.href/i ];
    let containsXss = false;
    for (const pattern of xssPatterns) { if (pattern.test(str)) { containsXss = true; break; } }
    if (containsXss) { let sanitized = str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); return `[SANITIZED PAYLOAD] ${sanitized}`; }
    return str;
}

function getBaseUrl(url) {
    try { const norm = normalizeEndpointUrl(url); return norm?.components ? norm.components.origin + norm.components.path : null; }
    catch (e) { log.handler(`[Get Base URL] Error getting base URL for: ${url}`, e.message); return null; }
}
window.getBaseUrl = getBaseUrl;

function sanitizeMessageData(data) {
    if (!data) return data;
    if (typeof data === 'string') { try { const parsed = JSON.parse(data); return sanitizeMessageData(parsed); } catch (e) { return sanitizeString(data); } }
    if (Array.isArray(data)) { return data.map(item => sanitizeMessageData(item)); }
    if (typeof data === 'object') { const sanitized = {}; for (const [key, value] of Object.entries(data)) sanitized[key] = sanitizeMessageData(value); return sanitized; }
    return data;
}

function isValidUrl(url) {
    try { new URL(url); return true; } catch { return false; }
}

function normalizeEndpointUrl(url) {
    let absUrl = url;
    try {
        if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) return { normalized: url, components: null, key: url };
        if (!url.includes('://') && !url.startsWith('//')) absUrl = 'https:' + url;
        else if (url.startsWith('//')) absUrl = 'https:' + url;
        const obj = new URL(absUrl);
        if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:', 'blob:', 'data:'].includes(obj.protocol)) return { normalized: url, components: null, key: url };
        const origin = obj.origin || ''; const pathname = obj.pathname || ''; const search = obj.search || ''; const key = origin + pathname + search;
        return { normalized: key, components: { origin: origin, path: pathname, query: search, hash: obj.hash || '' }, key: key };
    } catch (e) { log.error(`[Normalize URL] Error: "${e.message}".`, { originalInput: url, urlUsedInConstructor: absUrl }); return { normalized: url, components: null, key: url }; }
}
window.normalizeEndpointUrl = normalizeEndpointUrl;

function getStorageKeyForUrl(url) {
    return normalizeEndpointUrl(url)?.key || url;
}
window.getStorageKeyForUrl = getStorageKeyForUrl;

function showToastNotification(message, type = 'error', duration = 5000) {
    let container = document.getElementById('toast-container');
    if (!container) { container = document.createElement('div'); container.id = 'toast-container'; document.body.appendChild(container); }
    const toast = document.createElement('div'); toast.className = `toast toast-${type}`; toast.textContent = message; let removalTimeoutId = null; let removed = false;
    const removeToast = () => { if (removed || !toast.parentNode) return; removed = true; clearTimeout(removalTimeoutId); toast.classList.remove('show'); toast.classList.add('fade-out'); toast.addEventListener('transitionend', () => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, { once: true }); setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 600); };
    container.appendChild(toast); requestAnimationFrame(() => { toast.classList.add('show'); }); removalTimeoutId = setTimeout(removeToast, duration); toast.addEventListener('click', removeToast);
}


function updateButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint'));
    if (endpointKey) buttonStates.set(endpointKey, { state, options });

    const states = {
        start: { text: '▶', title: 'Start checks', class: 'default' },
        csp: { text: '⏳', title: 'Checking CSP...', class: 'checking is-working' },
        analyze: { text: '⏳', title: 'Analyzing...', class: 'checking is-working' },
        launch: { text: '🚀', title: 'Launch Payload Testing', class: 'green' },
        launching: { text: '🚀', title: 'Launching Fuzzer...', class: 'checking is-working launching' }, // <-- ADDED STATE
        success: { text: '✓', title: 'Check successful, handler found', class: 'success' },
        warning: { text: '⚠', title: options.errorMessage || 'Check completed with warnings', class: 'yellow' },
        error: { text: '✕', title: options.errorMessage || 'Check failed', class: 'red' }
    };

    let newState = states[state] || states.start;
    button.textContent = newState.text;
    button.title = newState.title;
    button.classList.remove(
        'default', 'checking', 'is-working', 'green', 'success', 'yellow', 'red',
        'has-critical-sinks', 'show-next-step-arrow', 'show-next-step-emoji',
        'launching' // <-- Add 'launching' here
    );
    button.classList.add(...newState.class.split(' '));
    button.style.animation = '';

    if (newState.class.includes('is-working')) button.classList.add('is-working');
    if (state === 'launch' && options.hasCriticalSinks) button.classList.add('has-critical-sinks');
    if (options.showArrow) button.classList.add('show-next-step-arrow');
    if (options.showEmoji) button.classList.add('show-next-step-emoji');
}
window.updateButton = updateButton;

function updateTraceButton(button, state, options = {}) {
    if (!button) return; const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint')); if (endpointKey) traceButtonStates.set(endpointKey, { state, options });
    const states = { default: { text: '✨', title: 'Start message tracing', class: 'default' }, disabled: { text: '✨', title: 'Start message tracing (disabled)', class: 'disabled' }, checking: { text: '⏳', title: 'Tracing in progress...', class: 'checking is-working' }, success: { text: '✨', title: 'Trace completed', class: 'green' }, error: { text: '❌', title: 'Tracing failed', class: 'error' } };
    const newState = states[state] || states.disabled; button.textContent = newState.text; button.title = newState.title; const classesToRemove = ['default', 'disabled', 'checking', 'is-working', 'green', 'error', 'show-next-step-emoji', 'highlight-next-step']; button.classList.remove(...classesToRemove); button.classList.add('iframe-trace-button'); button.classList.add(...newState.class.split(' ')); button.style.animation = '';
    if (newState.class.includes('is-working')) button.classList.add('is-working'); if (options?.showEmoji) button.classList.add('show-next-step-emoji');
    if (state === 'disabled') { button.setAttribute('disabled', 'true'); button.classList.add('disabled'); } else button.removeAttribute('disabled');
}
window.updateTraceButton = updateTraceButton;

function updateReportButton(button, state, endpoint) {
    if (!button) return; const endpointKey = getStorageKeyForUrl(endpoint);
    const states = { disabled: { text: '📋', title: 'Analysis Report (disabled)', className: 'iframe-report-button disabled' }, default: { text: '📋', title: 'View Analysis Report', className: 'iframe-report-button default' }, green: { text: '📋', title: 'View Analysis Report (Findings)', className: 'iframe-report-button green' } };
    const newState = states[state] || states.disabled; button.textContent = newState.text; button.title = newState.title; button.className = newState.className; if (endpointKey) reportButtonStates.set(endpointKey, state);
}
window.updateReportButton = updateReportButton;

function originMatchesSource(currentOrigin, source, endpointOrigin) {
    if (source === '*') return true; if (source === "'self'") return endpointOrigin !== null && currentOrigin === endpointOrigin; if (source === "'none'") return false;
    const cleanCurrentOrigin = currentOrigin.endsWith('/') ? currentOrigin.slice(0, -1) : currentOrigin; const cleanSource = source.endsWith('/') ? source.slice(0, -1) : source;
    if (cleanCurrentOrigin === cleanSource) return true; if (cleanSource.startsWith('*.')) { const domainPart = cleanSource.substring(2); return cleanCurrentOrigin.endsWith('.' + domainPart) && cleanCurrentOrigin.length > (domainPart.length + 1); } return false;
}

async function performEmbeddingCheck(endpoint) {
    log.handler(`[Embedding Check] Starting HEAD request for: ${endpoint}`);
    try {
        const response = await fetch(endpoint, { method: 'HEAD', cache: 'no-store', signal: AbortSignal.timeout(8000) });

        if (!response.ok) {
            log.warn(`[Embedding Check] Received non-OK status: ${response.status} for ${endpoint}`);
            return { status: `HTTP Error: ${response.status}`, className: 'red', embeddable: false };
        }

        log.handler(`[Embedding Check] HEAD request status OK: ${response.status}`);

        const xFrameOptions = response.headers.get('X-Frame-Options');
        if (xFrameOptions) {
            log.handler(`[Embedding Check] Found X-Frame-Options: ${xFrameOptions}`);
            const xfoUpper = xFrameOptions.toUpperCase();
            if (xfoUpper === 'DENY') return { status: `X-Frame-Options: DENY`, className: 'red', embeddable: false };
            if (xfoUpper === 'SAMEORIGIN') {
                const currentOrigin = window.location.origin; let endpointOrigin = null; try { endpointOrigin = new URL(endpoint).origin; } catch (e) {}
                if (!endpointOrigin || currentOrigin !== endpointOrigin) return { status: `X-Frame-Options: SAMEORIGIN (Origin mismatch)`, className: 'red', embeddable: false };
            }
        }

        const csp = response.headers.get('Content-Security-Policy');
        if (csp) {
            log.handler(`[Embedding Check] Found Content-Security-Policy header.`);
            const directives = csp.split(';').map(d => d.trim());
            const frameAncestors = directives.find(d => d.startsWith('frame-ancestors'));
            if (frameAncestors) {
                const sourcesString = frameAncestors.substring('frame-ancestors'.length).trim(); const sources = sourcesString.split(/\s+/);
                log.handler(`[Embedding Check] Parsed frame-ancestors sources: [${sources.join(', ')}]`);
                if (sources.includes("'none'")) return { status: `CSP: frame-ancestors 'none'`, className: 'red', embeddable: false };
                const currentOrigin = window.location.origin; let endpointOrigin = null; try { endpointOrigin = new URL(endpoint).origin; } catch (e) { return { status: `Invalid endpoint URL`, className: 'red', embeddable: false }; }
                let isAllowedByDirective = false;
                for (const source of sources) { if (originMatchesSource(currentOrigin, source, endpointOrigin)) { isAllowedByDirective = true; break; } }
                if (!isAllowedByDirective) return { status: `CSP: frame-ancestors does not allow ${currentOrigin}`, className: 'red', embeddable: false };
            }
        }
        log.success(`[Embedding Check] Frame can be embedded for ${endpoint}`);
        return { status: 'Frame can be embedded', className: 'green', embeddable: true };

    } catch (error) {
        log.error(`[Embedding Check] Network/Fetch error for ${endpoint}: ${error.message}`, error);
        return { status: `Header check failed: ${error.message}`, className: 'red', embeddable: false };
    }
}

function getMessageCount(endpointKey) {
    return window.frogPostState.messages.filter(msg => { if (!msg?.origin || !msg?.destinationUrl) return false; const originKey = getStorageKeyForUrl(msg.origin); const destKey = getStorageKeyForUrl(msg.destinationUrl); return originKey === endpointKey || destKey === endpointKey; }).length;
}

function escapeHTML(str) {
    if (str === undefined || str === null) return ''; return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
window.escapeHTML = escapeHTML;

async function sendMessageTo(targetKey, button) {
    let success = false; try { const messageItem = button.closest('.message-item'); if (!messageItem) throw new Error("Message item not found"); const messageDataElement = messageItem.querySelector('.message-data'); if (!messageDataElement) throw new Error("Message data element not found"); const messageContent = messageDataElement.textContent; let data; try { data = JSON.parse(messageContent); } catch (e) { data = messageContent; } const iframe = document.createElement('iframe'); iframe.style.display = 'none'; document.body.appendChild(iframe); iframe.src = targetKey; await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("Iframe load timeout")), 3000); iframe.onload = () => { clearTimeout(timer); resolve(); }; iframe.onerror = () => { clearTimeout(timer); reject(new Error("Iframe load error")); }; }); if (iframe.contentWindow) { iframe.contentWindow.postMessage(data, '*'); success = true; } else throw new Error("Iframe content window not accessible"); setTimeout(() => { if (document.body.contains(iframe)) document.body.removeChild(iframe); }, 500); } catch (error) { log.error("Error in sendMessageTo:", error); success = false; } finally { button.classList.toggle('success', success); button.classList.toggle('error', !success); setTimeout(() => button.classList.remove('success', 'error'), 1000); } return success;
}

async function sendMessageFromModal(targetKey, editedDataString, buttonElement, originalButtonText) {
    if (!targetKey || !buttonElement) return false; let dataToSend; try { dataToSend = JSON.parse(editedDataString); } catch (e) { dataToSend = editedDataString; } buttonElement.textContent = 'Sending...'; buttonElement.disabled = true; buttonElement.classList.remove('success', 'error'); let iframe = null;
    try { iframe = document.createElement('iframe'); iframe.style.display = 'none'; document.body.appendChild(iframe); iframe.src = targetKey; await new Promise((resolve, reject) => { const timeoutId = setTimeout(() => reject(new Error("Iframe load timeout")), 5000); iframe.onload = () => { clearTimeout(timeoutId); resolve(); }; iframe.onerror = (err) => { clearTimeout(timeoutId); reject(new Error("Iframe load error")); }; }); if (iframe.contentWindow) { iframe.contentWindow.postMessage(dataToSend, '*'); buttonElement.textContent = 'Sent ✓'; buttonElement.classList.add('success'); await new Promise(res => setTimeout(res, 1000)); return true; } else throw new Error("Iframe content window not accessible"); } catch (error) { log.error(`Error sending message from modal to ${targetKey}:`, error); buttonElement.textContent = 'Error ✕'; buttonElement.classList.add('error'); await new Promise(res => setTimeout(res, 2000)); return false; } finally { if (iframe && iframe.parentNode) iframe.parentNode.removeChild(iframe); if (buttonElement && !buttonElement.classList.contains('success')) { buttonElement.disabled = false; buttonElement.textContent = originalButtonText; buttonElement.classList.remove('error'); } }
}

function showEditModal(messageObject) {
    const modalContainer = document.getElementById('editMessageModalContainer'); if (!modalContainer) return; modalContainer.innerHTML = ''; const backdrop = document.createElement('div'); backdrop.className = 'modal-backdrop'; const modal = document.createElement('div'); modal.className = 'edit-message-modal'; let dataToEdit; try { dataToEdit = (typeof messageObject.data === 'string') ? messageObject.data : JSON.stringify(messageObject.data, null, 2); } catch (e) { dataToEdit = String(messageObject.data); } const originDisplay = escapeHTML(normalizeEndpointUrl(messageObject.origin)?.normalized || messageObject.origin); const destDisplay = escapeHTML(normalizeEndpointUrl(messageObject.destinationUrl)?.normalized || messageObject.destinationUrl);
    modal.innerHTML = `<div class="edit-modal-header"><h4>Edit Message</h4><div class="message-info"><strong>Origin:</strong> ${originDisplay}<br><strong>Destination:</strong> ${destDisplay}<br><strong>Time:</strong> ${new Date(messageObject.timestamp).toLocaleString()}</div><button class="close-modal-btn">&times;</button></div><div class="edit-modal-body"><textarea id="messageEditTextarea">${escapeHTML(dataToEdit)}</textarea></div><div class="edit-modal-footer"><button id="editCancelBtn" class="control-button secondary-button">Cancel</button><button id="editSendDestBtn" class="control-button">Send to Destination</button><button id="editSendOriginBtn" class="control-button">Send to Origin</button></div>`;
    modalContainer.appendChild(backdrop); modalContainer.appendChild(modal); const closeModal = () => { modalContainer.innerHTML = ''; }; modal.querySelector('.close-modal-btn').addEventListener('click', closeModal); modal.querySelector('#editCancelBtn').addEventListener('click', closeModal); backdrop.addEventListener('click', closeModal); const textarea = modal.querySelector('#messageEditTextarea'); const originKey = getStorageKeyForUrl(messageObject.origin); const destKey = getStorageKeyForUrl(messageObject.destinationUrl);
    modal.querySelector('#editSendOriginBtn').addEventListener('click', async () => { const success = await sendMessageFromModal(originKey, textarea.value, modal.querySelector('#editSendOriginBtn'), "Send to Origin"); if (success) closeModal(); }); modal.querySelector('#editSendDestBtn').addEventListener('click', async () => { const success = await sendMessageFromModal(destKey, textarea.value, modal.querySelector('#editSendDestBtn'), "Send to Destination"); if (success) closeModal(); });
}

function createMessageElement(msg) {
    const item = document.createElement('div'); item.classList.add('message-item'); item.setAttribute('data-message-id', msg.messageId); const source = msg?.origin || 'Unknown Source'; const target = msg?.destinationUrl || 'Unknown Target'; const type = msg?.messageType || 'Unknown Type'; const sanitizedData = sanitizeMessageData(msg.data); let dataForDisplay; try { dataForDisplay = typeof sanitizedData === 'string' ? sanitizedData : JSON.stringify(sanitizedData, null, 2); } catch (e) { dataForDisplay = String(sanitizedData); }
    const header = document.createElement("div"); header.className = "message-header"; const originDisplay = normalizeEndpointUrl(source)?.normalized || source; const destDisplay = normalizeEndpointUrl(target)?.normalized || target; const messageTypeDisplay = type.replace(/\s+/g, '-').toLowerCase(); header.innerHTML = `<strong>Origin:</strong> ${escapeHTML(originDisplay)}<br><strong>Destination:</strong> ${escapeHTML(destDisplay)}<br><strong>Time:</strong> ${new Date(msg.timestamp).toLocaleString()}<br><strong>Msg Type:</strong> <span class="message-type message-type-${messageTypeDisplay}">${escapeHTML(type)}</span>`;
    const dataPre = document.createElement("pre"); dataPre.className = "message-data"; dataPre.textContent = dataForDisplay; const controls = document.createElement("div"); controls.className = "message-controls"; const originBtn = document.createElement("button"); originBtn.className = "send-origin"; originBtn.textContent = "Resend to Origin"; originBtn.addEventListener('click', () => sendMessageTo(getStorageKeyForUrl(source), originBtn)); const destBtn = document.createElement("button"); destBtn.className = "send-destination"; destBtn.textContent = "Resend to Destination"; destBtn.addEventListener('click', () => sendMessageTo(getStorageKeyForUrl(target), destBtn)); const editBtn = document.createElement("button"); editBtn.className = "edit-send"; editBtn.textContent = "Edit & Send"; editBtn.addEventListener('click', () => showEditModal(msg)); controls.appendChild(originBtn); controls.appendChild(destBtn); controls.appendChild(editBtn); item.appendChild(header); item.appendChild(dataPre); item.appendChild(controls); return item;
}

function updateMessageListForUrl(url) {
    const messageList = document.getElementById('messagesList'); if (!messageList) return; const noMessagesDiv = messageList.querySelector('.no-messages'); messageList.querySelectorAll('.message-item').forEach(item => item.remove());
    if (!url) { if (noMessagesDiv) { noMessagesDiv.style.display = 'block'; noMessagesDiv.textContent = 'Select an endpoint to view messages.'; } return; }
    const normalizedUrlKey = getStorageKeyForUrl(url); const filteredMessages = window.frogPostState.messages.filter(msg => { if (!msg) return false; const originKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null; const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null; return originKey === normalizedUrlKey || destKey === normalizedUrlKey; });
    if (filteredMessages.length === 0) { if (noMessagesDiv) { noMessagesDiv.style.display = 'block'; noMessagesDiv.textContent = `No messages found involving endpoint: ${url}`; } }
    else { if (noMessagesDiv) noMessagesDiv.style.display = 'none'; const sortedMessages = [...filteredMessages].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)); sortedMessages.forEach(msg => { const messageElement = createMessageElement(msg); if (messageElement) messageList.appendChild(messageElement); }); }
}

function setActiveUrl(url) {
    if (window.frogPostState.activeUrl !== url) {
        window.frogPostState.activeUrl = url;
        log.info(`Selected endpoint: ${url}`);
        requestUiUpdate();
    }
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
    const savedPlayStateInfo = buttonStates.get(endpointKey);
    const savedTraceStateInfo = traceButtonStates.get(endpointKey);
    const savedReportStateInfo = reportButtonStates.get(endpointKey);
    updateButton(playButton, savedPlayStateInfo?.state || 'start', savedPlayStateInfo?.options || {});
    const canTrace = playButton.classList.contains('success') || playButton.classList.contains('green') || playButton.classList.contains('launch');
    updateTraceButton(traceButton, savedTraceStateInfo?.state || (canTrace ? 'default' : 'disabled'), savedTraceStateInfo?.options || {});
    const canReport = traceButton.classList.contains('green') || traceButton.classList.contains('success');
    updateReportButton(reportButton, savedReportStateInfo || (canReport ? 'default' : 'disabled'), endpointKey);
    playButton.addEventListener("click", (e) => { e.stopPropagation(); handlePlayButton(endpointKey, playButton); });
    traceButton.addEventListener("click", (e) => { e.stopPropagation(); if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) window.handleTraceButton(endpointKey, traceButton); });
    reportButton.addEventListener("click", (e) => { e.stopPropagation(); if (!reportButton.classList.contains('disabled')) handleReportButton(endpointKey); });
    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(reportButton);
    return buttonContainer;
}

function createHostElement(hostOriginKey, iframeKeysSet) {
    const hostElement = document.createElement("div");
    hostElement.className = "endpoint-host";
    const hostRow = document.createElement("div");
    hostRow.className = "host-row";
    hostRow.dataset.url = hostOriginKey;
    if (hostOriginKey === window.frogPostState.activeUrl) {
        hostRow.classList.add('active');
    }
    const hostName = document.createElement("span");
    hostName.className = "host-name";
    hostName.textContent = hostOriginKey;
    hostName.title = hostOriginKey;
    hostRow.addEventListener("click", (e) => {
        e.stopPropagation();
        setActiveUrl(hostOriginKey);
    });
    hostRow.appendChild(hostName);
    hostElement.appendChild(hostRow);

    const iframeContainer = document.createElement("div");
    iframeContainer.className = "iframe-container";
    const sortedIframeKeys = Array.from(iframeKeysSet).sort();
    let iframeCount = 0;
    sortedIframeKeys.forEach((iframeFullKey) => { // Declared here
        if (iframeFullKey === hostOriginKey) return;

        const iframeRow = document.createElement("div");
        iframeRow.className = "iframe-row";
        iframeRow.setAttribute("data-endpoint-key", iframeFullKey);
        iframeRow.dataset.url = iframeFullKey;
        if (iframeFullKey === window.frogPostState.activeUrl) { // Used here
            iframeRow.classList.add('active');
        }
        const iframeName = document.createElement("span");
        iframeName.className = "iframe-name";
        iframeName.textContent = iframeFullKey;
        iframeName.title = iframeFullKey;
        iframeRow.addEventListener("click", (e) => {
            e.stopPropagation();
            setActiveUrl(iframeFullKey);
        });
        const iframeButtonContainer = createActionButtonContainer(iframeFullKey);
        iframeRow.appendChild(iframeName);
        iframeRow.appendChild(iframeButtonContainer);
        iframeContainer.appendChild(iframeRow);
        iframeCount++;
    });

    if (iframeCount > 0) {
        hostElement.appendChild(iframeContainer);
    }
    return hostElement;
}

function updateDashboardUI() {
    const endpointsList = document.getElementById('endpointsList');
    if (!endpointsList) { log.error("Cannot find endpointsList element"); return; }

    const filterInput = document.getElementById('endpointFilterInput');
    const filterText = filterInput ? filterInput.value.toLowerCase().trim() : '';
    const filterContainer = endpointsList.querySelector('.endpoint-filter-container');

    endpointsList.querySelectorAll('.endpoint-host, .no-endpoints').forEach(el => el.remove());

    const endpointHierarchy = new Map();
    const allUrls = new Set();
    window.frogPostState.messages.forEach(msg => { if (msg?.origin) allUrls.add(msg.origin); if (msg?.destinationUrl) allUrls.add(msg.destinationUrl); });
    window.frogPostState.loadedData.urls.forEach(url => allUrls.add(url));
    knownHandlerEndpoints.forEach(url => allUrls.add(url));

    allUrls.forEach(url => {
        const normResult = normalizeEndpointUrl(url);
        const normKey = normResult?.key;
        const hostOriginKey = normResult?.components?.origin;
        if (!normKey || normKey === 'null' || !hostOriginKey) return;
        if (!endpointHierarchy.has(hostOriginKey)) endpointHierarchy.set(hostOriginKey, new Set());
        endpointHierarchy.get(hostOriginKey).add(normKey);
    });

    const fragment = document.createDocumentFragment();
    let hostCount = 0;
    const sortedHostKeys = Array.from(endpointHierarchy.keys()).sort();

    sortedHostKeys.forEach(hostOriginKey => {
        const fullUrlKeysSet = endpointHierarchy.get(hostOriginKey) || new Set();
        const hostMatchesTextFilter = !filterText || hostOriginKey.toLowerCase().includes(filterText);

        let visibleIframesSet = new Set();
        let hasAnyVisibleChildren = false;

        fullUrlKeysSet.forEach(iframeFullKey => {
            if (iframeFullKey === hostOriginKey) return;

            const iframeMatchesTextFilter = !filterText || iframeFullKey.toLowerCase().includes(filterText);
            const isIframeSilent = getMessageCount(iframeFullKey) === 0;

            const shouldShowThisIframe = iframeMatchesTextFilter && (!showOnlySilentIframes || isIframeSilent);

            if (shouldShowThisIframe) {
                visibleIframesSet.add(iframeFullKey);
                hasAnyVisibleChildren = true;
            }
        });

        const showHost = (!showOnlySilentIframes && hostMatchesTextFilter) || hasAnyVisibleChildren;

        if (showHost) {
            const hostElement = createHostElement(hostOriginKey, visibleIframesSet);
            if (hostElement) {
                fragment.appendChild(hostElement);
                hostCount++;
            }
        }
    });

    let noEndpointsDiv = endpointsList.querySelector('.no-endpoints');
    if (!noEndpointsDiv) { noEndpointsDiv = document.createElement('div'); noEndpointsDiv.className = 'no-endpoints'; if(filterContainer && filterContainer.nextSibling) endpointsList.insertBefore(noEndpointsDiv, filterContainer.nextSibling); else endpointsList.appendChild(noEndpointsDiv); }

    if (hostCount > 0) { endpointsList.appendChild(fragment); noEndpointsDiv.style.display = 'none'; }
    else { noEndpointsDiv.style.display = 'block'; const hasAnyEndpoints = sortedHostKeys.length > 0 || knownHandlerEndpoints.size > 0; if (filterText || showOnlySilentIframes) { noEndpointsDiv.textContent = `No endpoints match active filters.`; } else if (hasAnyEndpoints) { noEndpointsDiv.textContent = "No endpoints to display."; } else { noEndpointsDiv.textContent = "No endpoints captured or listeners found."; } }

    updateMessageListForUrl(window.frogPostState.activeUrl);
    updateEndpointCounts();
}
window.updateDashboardUI = updateDashboardUI;

function requestUiUpdate() {
    clearTimeout(uiUpdateTimer);
    uiUpdateTimer = setTimeout(updateDashboardUI, DEBOUNCE_DELAY);
}
window.requestUiUpdate = requestUiUpdate;

function updateEndpointCounts() {
    try {
        document.querySelectorAll('#endpointsList .endpoint-host .host-name, #endpointsList .endpoint-host .iframe-name').forEach(el => {
            const url = el.textContent?.replace(/ \(\d+\)$/, '') || '';
            if (!url) return;
            const count = getMessageCount(url);
            el.textContent = `${url} (${count})`;
        });
    } catch(e) {
        log.error("Error updating endpoint counts", e);
    }
}

function initializeMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message?.type) return false; let needsUiUpdate = false;
        try {
            switch (message.type) {
                case "newPostMessage": if (message.payload) { const newMsg = message.payload; const existingIndex = window.frogPostState.messages.findIndex(m => m.messageId === newMsg.messageId); if (existingIndex >= 0) window.frogPostState.messages[existingIndex] = newMsg; else window.frogPostState.messages.push(newMsg); needsUiUpdate = true; } break;
                case "newFrameConnection": needsUiUpdate = true; break;
                case "updateMessages": if (message.messages) { window.frogPostState.messages.length = 0; window.frogPostState.messages.push(...message.messages); needsUiUpdate = true; } break;
                case "handlerCapturedForEndpoint": case "handlerEndpointDetected": if (message.payload?.endpointKey) { const key = message.payload.endpointKey; let addedNew = false; if (!endpointsWithHandlers.has(key)) { endpointsWithHandlers.add(key); addedNew = true; } if (!knownHandlerEndpoints.has(key)) { knownHandlerEndpoints.add(key); addedNew = true; } if(addedNew) needsUiUpdate = true; } break;
            } if (needsUiUpdate) requestUiUpdate(); if (sendResponse) sendResponse({ success: true });
        } catch (e) { log.error("[Dashboard Msg Handler] Error:", e); if (sendResponse) try { sendResponse({ success: false, error: e.message }); } catch(respErr){} } return true;
    });
    window.traceReportStorage.listAllReports().then(() => {
        chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => {
            if (chrome.runtime.lastError) { log.error("[MsgListener] Error receiving fetchInitialState response:", chrome.runtime.lastError.message); requestUiUpdate(); return; }
            if (response?.success) { if (response.messages) { window.frogPostState.messages.length = 0; window.frogPostState.messages.push(...response.messages); } if (response.handlerEndpointKeys) { knownHandlerEndpoints.clear(); endpointsWithHandlers.clear(); response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); }); } requestUiUpdate(); }
            else { log.error("Failed to fetch initial state:", response?.error); requestUiUpdate(); }
        });
    });
}

function setupCallbackUrl() {
    const urlInput = document.getElementById('callbackUrlInput'); const saveButton = document.getElementById('saveCallbackUrl'); const statusElement = document.getElementById('callback-status'); if (!urlInput || !saveButton || !statusElement) return;
    const updateCallbackStatus = (url, errorMessage = null) => { if (!statusElement) return; statusElement.innerHTML = ''; statusElement.className = 'callback-status'; if (errorMessage) { statusElement.innerHTML = `<div class="error-message">${escapeHTML(errorMessage)}</div>`; statusElement.classList.add('callback-status-error'); } else if (url) { statusElement.innerHTML = `<div class="success-icon">✓</div><div class="status-message">Active (Session): <span class="url-value">${escapeHTML(url)}</span></div>`; statusElement.classList.add('callback-status-success'); } else { statusElement.innerHTML = `<div class="info-message">No callback URL set.</div>`; statusElement.classList.add('callback-status-info'); } };
    chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], (result) => { if (chrome.runtime.lastError) { updateCallbackStatus(null, `Error loading URL`); return; } const storedUrl = result[CALLBACK_URL_STORAGE_KEY] || null; if (storedUrl) { urlInput.value = storedUrl; window.frogPostState.callbackUrl = storedUrl; } updateCallbackStatus(storedUrl); });
    saveButton.addEventListener('click', () => { const url = urlInput.value.trim(); if (!url) { chrome.storage.session.remove(CALLBACK_URL_STORAGE_KEY, () => { window.frogPostState.callbackUrl = null; updateCallbackStatus(null, chrome.runtime.lastError ? 'Error clearing URL' : null); }); } else if (isValidUrl(url)) { chrome.storage.session.set({ [CALLBACK_URL_STORAGE_KEY]: url }, () => { window.frogPostState.callbackUrl = url; updateCallbackStatus(url, chrome.runtime.lastError ? 'Error saving URL' : null); }); } else updateCallbackStatus(window.frogPostState.callbackUrl, 'Invalid URL format.'); });
}

function setupUIControls() {
    document.getElementById("clearMessages")?.addEventListener("click", () => { log.info("Clearing dashboard state..."); window.frogPostState.messages.length = 0; window.frogPostState.activeUrl = null; buttonStates.clear(); traceButtonStates.clear(); reportButtonStates.clear(); endpointsWithHandlers.clear(); knownHandlerEndpoints.clear(); launchInProgressEndpoints.clear(); chrome.storage.local.clear(() => log.info("Local storage cleared.")); chrome.runtime.sendMessage({ type: "resetState" }, (response) => log.info("Background reset:", response)); requestUiUpdate(); });
    document.getElementById("exportMessages")?.addEventListener("click", () => { const sanitizedMessages = window.frogPostState.messages.map(msg => ({ origin: msg.origin, destinationUrl: msg.destinationUrl, timestamp: msg.timestamp, data: sanitizeMessageData(msg.data), messageType: msg.messageType, messageId: msg.messageId })); const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "frogpost_messages.json"; a.click(); URL.revokeObjectURL(url); });
    document.getElementById("checkAll")?.addEventListener("click", checkAllEndpoints); const debugButton = document.getElementById("debugToggle"); if (debugButton) { debugButton.addEventListener("click", toggleDebugMode); debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF'; debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off'; }
    document.getElementById("refreshMessages")?.addEventListener("click", () => { chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => { if (response?.success) { if (response.messages) { window.frogPostState.messages.length = 0; window.frogPostState.messages.push(...response.messages); } if (response.handlerEndpointKeys) { knownHandlerEndpoints.clear(); endpointsWithHandlers.clear(); response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); }); } log.info("Dashboard refreshed."); requestUiUpdate(); } else log.error("Failed refresh:", response?.error); }); });
    const uploadPayloadsButton = document.getElementById("uploadCustomPayloadsBtn"); const payloadFileInput = document.getElementById("customPayloadsFile"); if(uploadPayloadsButton && payloadFileInput){ uploadPayloadsButton.addEventListener('click', () => payloadFileInput.click()); payloadFileInput.addEventListener('change', handlePayloadFileSelect); }
    document.getElementById("clearCustomPayloadsBtn")?.addEventListener('click', clearCustomPayloads); setupCallbackUrl(); updatePayloadStatus();
    document.getElementById("openOptionsBtn")?.addEventListener("click", () => { if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage(); else window.open(chrome.runtime.getURL("../options/options.html")); });
}

async function handlePayloadFileSelect(event) {
    const file = event.target.files[0]; const statusElement = document.getElementById("customPayloadStatus"); if (!file || !file.name.toLowerCase().endsWith('.txt')) { showToastNotification('Invalid file type (.txt only).', 'error'); if (statusElement) statusElement.textContent = 'Upload: Invalid file type.'; event.target.value = null; return; }
    const reader = new FileReader(); reader.onload = (e) => { validateAndStorePayloads(e.target.result); event.target.value = null; }; reader.onerror = () => { showToastNotification('Error reading file.', 'error'); if (statusElement) statusElement.textContent = 'Upload: Error reading file.'; event.target.value = null; }; reader.readAsText(file);
}

function validateAndStorePayloads(content) {
    const lines = content.split('\n'); const payloads = lines.map(line => line.trim()).filter(line => line.length > 0); if (payloads.length === 0) { showToastNotification('No valid payloads found.', 'warning'); updatePayloadStatus(false, 0); return; }
    chrome.storage.session.set({ customXssPayloads: payloads }, () => { if (chrome.runtime.lastError) { showToastNotification(`Error saving payloads`, 'error'); updatePayloadStatus(false, 0); } else { try { localStorage.setItem('customXssPayloads', JSON.stringify(payloads)); } catch (e) {} if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...payloads]; } showToastNotification(`Stored ${payloads.length} custom payloads.`, 'success'); updatePayloadStatus(true, payloads.length); } });
}

function updatePayloadStatus(isActive = null, count = 0) {
    const statusElement = document.getElementById("customPayloadStatus"); const uploadButton = document.getElementById("uploadCustomPayloadsBtn"); const clearButton = document.getElementById("clearCustomPayloadsBtn");
    const updateUI = (active, payloadCount) => { if (statusElement) { statusElement.textContent = active ? `Custom Payloads Active (${payloadCount})` : 'Using Default Payloads'; statusElement.style.color = active ? 'var(--accent-primary)' : 'var(--text-secondary)'; } if (uploadButton) uploadButton.textContent = active ? 'Update Payloads' : 'Upload Payloads'; if (clearButton) clearButton.style.display = active ? 'inline-block' : 'none'; };
    if (isActive !== null) updateUI(isActive, count); else chrome.storage.session.get('customXssPayloads', (result) => { const storedPayloads = result.customXssPayloads; const active = storedPayloads && storedPayloads.length > 0; updateUI(active, active ? storedPayloads.length : 0); });
}

function clearCustomPayloads() {
    chrome.storage.session.remove('customXssPayloads', () => { if (chrome.runtime.lastError) showToastNotification(`Error clearing payloads`, 'error'); else { try { localStorage.removeItem('customXssPayloads'); } catch (e) {} if (window.FuzzingPayloads && window.FuzzingPayloads._originalXSS) window.FuzzingPayloads.XSS = [...window.FuzzingPayloads._originalXSS]; showToastNotification('Custom payloads cleared.', 'info'); updatePayloadStatus(false, 0); } });
}

async function launchFuzzerEnvironment(targetUrl, handlerCode, messages, payloads, traceReportData, fuzzerOptions, analysisKeyForReport) {
    let serverStarted = false;
    try {
        if (!analysisKeyForReport) throw new Error("Internal error: Missing analysis key for launching fuzzer.");
        if (!traceReportData) throw new Error(`Internal error: Trace report data missing.`);
        if (!targetUrl || !handlerCode || !messages || !payloads || !fuzzerOptions) throw new Error("Internal error: Missing data for launching fuzzer.");

        await chrome.runtime.sendMessage({ type: "startServer" });
        await new Promise(resolve => setTimeout(resolve, 1500));
        let attempts = 0;
        while (!serverStarted && attempts < 3) {
            attempts++;
            try { const health = await fetch('http://127.0.0.1:1337/health', { method: 'GET', cache: 'no-store', signal: AbortSignal.timeout(800) }); if (health.ok) serverStarted = true; else await new Promise(r => setTimeout(r, 700)); } catch(err) { await new Promise(r => setTimeout(r, 700)); }
        }
        if (!serverStarted) throw new Error("Fuzzer server did not start.");

        const config = {
            target: targetUrl,
            messages: messages, // Assuming messages are already simple objects/strings
            handler: handlerCode,
            payloads: payloads, // Assuming payloads are simple objects/strings
            traceData: {
                endpoint: traceReportData.endpoint,
                originalEndpointKey: traceReportData.originalEndpointKey,
                analysisStorageKey: traceReportData.analysisStorageKey,
                timestamp: traceReportData.timestamp,
                securityScore: traceReportData.securityScore,
                details: {
                    payloadsGeneratedCount: traceReportData.details?.payloadsGeneratedCount,
                    uniqueStructures: traceReportData.details?.uniqueStructures, // Might need sanitization if examples contain complex objects
                    staticAnalysisUsed: traceReportData.details?.staticAnalysisUsed,
                    messagesAvailable: traceReportData.details?.messagesAvailable,
                },
                summary: traceReportData.summary // Summary should be safe
            },
            callbackUrl: fuzzerOptions.callbackUrl,
            fuzzerOptions: {
                autoStart: fuzzerOptions.autoStart,
                useCustomPayloads: fuzzerOptions.useCustomPayloads,
                enableCallbackFuzzing: fuzzerOptions.enableCallbackFuzzing
            }
        };

        log.debug("[Launch Fuzzer Env] Sending sanitized config:", config);

        const response = await fetch('http://127.0.0.1:1337/current-config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config), signal: AbortSignal.timeout(5000) }); // Stringify the sanitized config
        if (!response.ok) { const errorText = await response.text(); throw new Error(`Config update failed: ${response.statusText} - ${errorText}`); }

        const tab = await chrome.tabs.create({ url: 'http://127.0.0.1:1337/' });
        const cleanupListener = (tabId, removeInfo) => { if (tabId === tab.id) { chrome.runtime.sendMessage({ type: "stopServer" }).catch(e => {}); chrome.tabs.onRemoved.removeListener(cleanupListener); } };
        chrome.tabs.onRemoved.addListener(cleanupListener);
        return true;
    } catch (error) {
        log.error("[Launch Fuzzer Env] Caught error:", error);
        alert(`Fuzzer Launch Failed: ${error.message}`);
        if (serverStarted === false) try { await chrome.runtime.sendMessage({ type: "stopServer" }); } catch {}
        return false;
    }
}

async function saveRandomPostMessages(endpointKey, messagesToSave = null) {
    const MAX_MESSAGES = 20; let relevantMessages = [];
    if (messagesToSave && Array.isArray(messagesToSave)) relevantMessages = messagesToSave; else relevantMessages = window.frogPostState.messages.filter(msg => { if (!msg?.origin || !msg?.destinationUrl) return false; const originKey = getStorageKeyForUrl(msg.origin); const destKey = getStorageKeyForUrl(msg.destinationUrl); return originKey === endpointKey || destKey === endpointKey; });
    relevantMessages = relevantMessages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, MAX_MESSAGES); const processedMessages = relevantMessages.map(msg => { if (!msg.messageType) { let messageType = 'unknown'; let data = msg.data; if (data === undefined || data === null) messageType = 'null_or_undefined'; else if (typeof data === 'string') { try { JSON.parse(data); messageType = 'json_string'; } catch { messageType = 'string'; } } else if (Array.isArray(data)) messageType = 'array'; else if (typeof data === 'object') messageType = 'object'; else messageType = typeof data; return {...msg, messageType: messageType}; } return msg; });
    const storageKey = `saved-messages-${endpointKey}`; try { if (processedMessages.length > 0) await chrome.storage.local.set({ [storageKey]: processedMessages }); else await chrome.storage.local.remove(storageKey); return processedMessages; } catch (error) { log.error("Failed to save messages:", error); try { await chrome.storage.local.remove(storageKey); } catch {} return []; }
}

async function retrieveMessagesWithFallbacks(endpointKey) {
    const primaryStorageKey = `saved-messages-${endpointKey}`; try { const result = await new Promise((resolve, reject) => { chrome.storage.local.get(primaryStorageKey, (storageResult) => { if (chrome.runtime.lastError) reject(chrome.runtime.lastError); else resolve(storageResult?.[primaryStorageKey] || null); }); }); if (result && Array.isArray(result) && result.length > 0) return result; else return []; } catch (e) { log.error(`[RetrieveMessages] Error for key ${primaryStorageKey}:`, e); return []; }
}
window.retrieveMessagesWithFallbacks = retrieveMessagesWithFallbacks;

async function showUrlModificationModal(originalUrl, failureReason) {
    return new Promise((resolve) => { const modalContainer = document.getElementById('urlModificationModalContainer'); if (!modalContainer) { resolve({ action: 'cancel', modifiedUrl: null }); return; } modalContainer.innerHTML = ''; const backdrop = document.createElement('div'); backdrop.className = 'modal-backdrop'; const modal = document.createElement('div'); modal.className = 'url-modification-modal'; let currentUrl = new URL(originalUrl); const params = new URLSearchParams(currentUrl.search); let paramInputs = {}; let paramsHTML = ''; if (Array.from(params.keys()).length > 0) { params.forEach((value, key) => { const inputId = `param-input-${key}`; paramsHTML += `<div class="url-param-row"><label for="${inputId}" class="url-param-label">${escapeHTML(key)}:</label><input type="text" id="${inputId}" class="url-param-input" value="${escapeHTML(value)}"></div>`; paramInputs[key] = inputId; }); } else paramsHTML = '<p class="url-modal-no-params">No query parameters found.</p>'; modal.innerHTML = `<div class="url-modal-header"><h4>Embedding Check Failed - Modify URL?</h4><button class="close-modal-btn">&times;</button></div><div class="url-modal-body"><p class="url-modal-reason"><strong>Reason:</strong> ${escapeHTML(failureReason)}</p><p class="url-modal-original"><strong>Original URL:</strong> <span class="url-display">${escapeHTML(originalUrl)}</span></p><hr><h5 class="url-modal-params-title">Edit Query Parameters:</h5><div class="url-params-editor">${paramsHTML}</div></div><div class="url-modal-footer"><button id="urlCancelBtn" class="control-button secondary-button">Cancel Analysis</button><button id="urlContinueBtn" class="control-button secondary-button orange-button">Analyze Original Anyway</button><button id="urlRetryBtn" class="control-button primary-button">Modify & Retry Analysis</button></div>`; modalContainer.appendChild(backdrop); modalContainer.appendChild(modal); const closeModal = (result) => { modalContainer.innerHTML = ''; resolve(result); }; modal.querySelector('.close-modal-btn').addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); backdrop.addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); modal.querySelector('#urlCancelBtn').addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); modal.querySelector('#urlContinueBtn').addEventListener('click', () => closeModal({ action: 'continue', modifiedUrl: originalUrl })); modal.querySelector('#urlRetryBtn').addEventListener('click', () => { const newParams = new URLSearchParams(); let changed = false; params.forEach((originalValue, key) => { const inputElement = document.getElementById(paramInputs[key]); const newValue = inputElement ? inputElement.value : originalValue; newParams.set(key, newValue); if (newValue !== originalValue) changed = true; }); if (!changed) { showToastNotification("No parameters were changed.", "info", 3000); return; } currentUrl.search = newParams.toString(); const modifiedUrlString = currentUrl.toString(); if (!isValidUrl(modifiedUrlString)) { showToastNotification("Modified URL is invalid.", "error", 4000); return; } closeModal({ action: 'retry', modifiedUrl: modifiedUrlString }); }); });
}


async function handlePlayButton(endpoint, button, skipCheck = false) {
    const endpointKey = button.getAttribute('data-endpoint');
    if (!endpointKey) { log.error("[Play Button] No endpoint key found."); updateButton(button, 'error'); return; }

    const originalFullEndpoint = endpoint;
    const currentStateInfo = buttonStates.get(endpointKey);

    if (currentStateInfo?.state === 'launch') {
        if (launchInProgressEndpoints.has(endpointKey)) {
            log.debug(`[Play Button] Launch already in progress for ${endpointKey}`);
            return;
        }
        launchInProgressEndpoints.add(endpointKey);
        const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button');
        let launchSuccess = false;

        try {
            updateButton(button, 'launching', currentStateInfo.options);
            showToastNotification("Preparing Fuzzer Environment...", "info", 3000);

            const successfulUrlStorageKey = `successful-url-${endpointKey}`;
            const successfulUrlResult = await new Promise(resolve => chrome.storage.local.get(successfulUrlStorageKey, resolve));
            const successfulUrl = successfulUrlResult[successfulUrlStorageKey] || originalFullEndpoint;
            const analysisKeyToUse = getStorageKeyForUrl(successfulUrl);

            const [traceReport, storedPayloads, storedMessages] = await Promise.all([
                window.traceReportStorage.getTraceReport(analysisKeyToUse),
                window.traceReportStorage.getReportPayloads(analysisKeyToUse),
                retrieveMessagesWithFallbacks(endpointKey) // Get messages associated with original endpoint key
            ]);

            if (!traceReport) throw new Error(`No trace report found for ${analysisKeyToUse}. Run Play & Trace again.`);
            const handlerCode = traceReport?.analyzedHandler?.handler || traceReport?.analyzedHandler?.code;
            if (!handlerCode) throw new Error('Handler code missing in trace report.');

            const payloads = storedPayloads || traceReport?.details?.payloads || traceReport?.payloads || [];
            let messagesForFuzzer = [];
            if (Array.isArray(storedMessages) && storedMessages.length > 0) {
                messagesForFuzzer = storedMessages;
            } else if (traceReport?.details?.uniqueStructures) {
                messagesForFuzzer = traceReport.details.uniqueStructures.flatMap(s => s.examples || []);
            }

            const callbackStorageData = await new Promise(resolve => chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], resolve));
            const currentCallbackUrl = callbackStorageData[CALLBACK_URL_STORAGE_KEY] || null;
            const customPayloadsResult = await new Promise(resolve => chrome.storage.session.get('customXssPayloads', result => resolve(result.customXssPayloads)));
            const useCustomPayloads = customPayloadsResult && customPayloadsResult.length > 0;

            const fuzzerOptions = {
                autoStart: true, // Can be configured if needed
                useCustomPayloads: useCustomPayloads,
                enableCallbackFuzzing: !!currentCallbackUrl,
                callbackUrl: currentCallbackUrl
            };

            launchSuccess = await launchFuzzerEnvironment(successfulUrl, handlerCode, messagesForFuzzer, payloads, traceReport, fuzzerOptions, analysisKeyToUse);

        } catch (error) {
            log.error('[Launch Error]:', error?.message);
            alert(`Fuzzer launch failed: ${error.message}`);
            launchSuccess = false;
            try { await chrome.runtime.sendMessage({ type: "stopServer" }); } catch {} // Use type for clarity
        } finally {
            updateButton(button, launchSuccess ? 'launch' : 'error', { // Restore to launch on success, error on failure
                ...currentStateInfo.options, // Keep original options like hasCriticalSinks
                errorMessage: launchSuccess ? undefined : 'Fuzzer launch failed'
            });

            launchInProgressEndpoints.delete(endpointKey);
            setTimeout(requestUiUpdate, 100);
        }
        return;
    }

    if (launchInProgressEndpoints.has(endpointKey)) return;
    launchInProgressEndpoints.add(endpointKey);

    const reportButton = button.closest('.button-container')?.querySelector('.iframe-report-button');
    let endpointUrlForAnalysis = originalFullEndpoint;
    let analysisStorageKey = endpointKey;
    let successfullyAnalyzedUrl = null;
    let handlerStateUpdated = false;
    let foundHandlerObject = null;
    let originalMessages = [];

    try {
        originalMessages = window.frogPostState.messages.filter(msg => { if (!msg?.origin || !msg?.destinationUrl) return false; const originKey = getStorageKeyForUrl(msg.origin); const destKey = getStorageKeyForUrl(msg.destinationUrl); return originKey === endpointKey || destKey === endpointKey; }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 50);

        if (!skipCheck) {
            updateButton(button, 'csp');
            let cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
            if (!cspResult.embeddable) {
                log.warn(`[Play] Embedding check failed for ${endpointUrlForAnalysis}: ${cspResult.status}`);
                const isCspOrXfoError = cspResult.status.includes('X-Frame-Options') || cspResult.status.includes('CSP');
                showToastNotification(`Embedding check failed: ${cspResult.status}`, 'error');
                if (isCspOrXfoError) {
                    const modalResult = await showUrlModificationModal(endpointUrlForAnalysis, cspResult.status);
                    if (modalResult.action === 'cancel') { updateButton(button, 'start'); throw new Error("User cancelled analysis"); }
                    else if (modalResult.action === 'continue') { successfullyAnalyzedUrl = endpointUrlForAnalysis; updateButton(button, 'warning', { errorMessage: 'Proceeding despite embedding failure' }); throw new Error("Proceeding despite embedding failure (analysis skipped)"); }
                    else if (modalResult.action === 'retry') {
                        endpointUrlForAnalysis = modalResult.modifiedUrl; analysisStorageKey = getStorageKeyForUrl(endpointUrlForAnalysis);
                        updateButton(button, 'csp');
                        cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
                        if (!cspResult.embeddable) { updateButton(button, 'error', { errorMessage: `Modified URL failed check: ${cspResult.status}` }); throw new Error("Modified URL failed embedding check"); }
                        successfullyAnalyzedUrl = endpointUrlForAnalysis;
                    } else { updateButton(button, 'start'); throw new Error("Embedding check failed - Unknown modal action"); }
                } else { updateButton(button, 'error', { errorMessage: cspResult.status }); launchInProgressEndpoints.delete(endpointKey); setTimeout(requestUiUpdate, 50); return; }
            } else { successfullyAnalyzedUrl = endpointUrlForAnalysis; }
        } else { successfullyAnalyzedUrl = endpointUrlForAnalysis; }

        updateButton(button, 'analyze');
        analysisStorageKey = getStorageKeyForUrl(successfullyAnalyzedUrl);
        await saveRandomPostMessages(endpointKey, originalMessages);
        const successfulUrlStorageKey = `successful-url-${endpointKey}`;
        await chrome.storage.local.set({ [successfulUrlStorageKey]: successfullyAnalyzedUrl });

        const runtimeListenerKey = `runtime-listeners-${endpointKey}`;
        const runtimeResult = await new Promise(resolve => chrome.storage.local.get(runtimeListenerKey, resolve));
        const runtimeListeners = runtimeResult ? runtimeResult[runtimeListenerKey] : null;
        const validRuntimeListeners = runtimeListeners?.filter(l => l?.code && typeof l.code === 'string' && !l.code.includes('[native code]') && l.code.length > 25) || [];
        const scoringMessages = originalMessages;

        if (validRuntimeListeners.length > 0) {
            const scorer = new HandlerExtractor().initialize(successfullyAnalyzedUrl, scoringMessages);
            let bestScore = -1; let bestListener = null;
            validRuntimeListeners.forEach(listener => {
                let handlerInfo = { handler: listener.code, category: listener.category || 'runtime-captured', source: listener.source || 'runtime', handlerNode: null, fullScriptContent: listener.code };
                const score = scorer.scoreHandler(handlerInfo);
                if (score > bestScore) { bestScore = score; bestListener = listener; } });
            if (bestListener) foundHandlerObject = { handler: bestListener.code, category: bestListener.category || 'runtime-best-scored', score: bestScore, source: `runtime: ${bestListener.context || bestListener.source || 'unknown'}`, timestamp: bestListener.timestamp, stack: bestListener.stack, context: bestListener.context };
            else foundHandlerObject = null;
        }

        if (!foundHandlerObject) {
            try {
                const extractor = new HandlerExtractor().initialize(successfullyAnalyzedUrl, scoringMessages);
                showToastNotification('Attaching debugger to analyze scripts...', 'info', 10000);
                const dynamicHandlers = await extractor.extractDynamicallyViaDebugger(successfullyAnalyzedUrl);
                if (dynamicHandlers && dynamicHandlers.length > 0) {
                    foundHandlerObject = extractor.getBestHandler(dynamicHandlers);
                    if (foundHandlerObject) foundHandlerObject.category = foundHandlerObject.category ? `debugger-${foundHandlerObject.category}` : 'debugger-extracted';
                    else foundHandlerObject = null;
                } else foundHandlerObject = null;
            } catch (extractionError) { log.error(`[Play] Debugger extraction failed:`, extractionError); foundHandlerObject = null; }
        }

        if (foundHandlerObject?.handler) {
            const finalBestHandlerKey = `best-handler-${analysisStorageKey}`;
            try {
                if (typeof window.analyzeHandlerStatically === 'function') {
                    const quickAnalysis = window.analyzeHandlerStatically(foundHandlerObject.handler);
                    if(quickAnalysis?.analysis?.identifiedEventParam) {
                        foundHandlerObject.eventParamName = quickAnalysis.analysis.identifiedEventParam;
                    }
                }
                await chrome.storage.local.set({ [finalBestHandlerKey]: foundHandlerObject });
                const runtimeListKeyForUpdate = `runtime-listeners-${endpointKey}`;
                try { const res = await new Promise(resolve => chrome.storage.local.get(runtimeListKeyForUpdate, resolve)); let listeners = res[runtimeListKeyForUpdate] || []; if (!listeners.some(l => l.code === foundHandlerObject.handler)) { listeners.push({ code: foundHandlerObject.handler, context: `selected-by-play (${foundHandlerObject.category})`, timestamp: Date.now(), source: foundHandlerObject.source }); if (listeners.length > 30) listeners = listeners.slice(-30); await chrome.storage.local.set({ [runtimeListKeyForUpdate]: listeners }); } if (!endpointsWithHandlers.has(endpointKey)) { endpointsWithHandlers.add(endpointKey); handlerStateUpdated = true; } } catch (e) { log.error("Failed updating runtime list after selection", e); }
                updateButton(button, 'success');
                const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button');
                if (traceButton) updateTraceButton(traceButton, 'default', { showEmoji: true });
                if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
            } catch (storageError) { log.error(`Failed to save handler (${finalBestHandlerKey}):`, storageError); updateButton(button, 'error', {errorMessage: 'Failed to save handler'}); const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        } else { const failureMessage = `No usable handler found for ${endpointUrlForAnalysis}.`; updateButton(button, 'warning', { errorMessage: "No handler function found" }); const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        if (handlerStateUpdated) requestUiUpdate();

    } catch (error) {
        if (error.message === "Proceeding despite embedding failure (analysis skipped)") { log.info(`[Play] Process stopped for ${endpointKey}: ${error.message}`); showToastNotification('Analysis skipped due to embedding restrictions. Button set to warning.', 'warning', 6000); const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        else if (["User cancelled analysis", "Modified URL failed embedding check"].includes(error.message) || error.message?.startsWith('Embedding check failed:')) { log.info(`[Play] Process stopped for ${endpointKey}: ${error.message}`); const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
        else { log.error(`[Play Button Error] Unexpected error for key ${endpointKey}:`, error.message); if(!button.classList.contains('error') && !button.classList.contains('warning')) { updateButton(button, 'error', { errorMessage: 'Analysis error occurred' }); } showToastNotification(`Analysis Error: ${error.message.substring(0, 100)}`, 'error'); const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button'); if (traceButton) updateTraceButton(traceButton, 'disabled'); if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint); }
    } finally {
        launchInProgressEndpoints.delete(endpointKey);
        setTimeout(requestUiUpdate, 150);
    }
}

function getRiskLevelAndColor(score) { if (score <= 20) return { riskLevel: 'Critical', riskColor: 'critical' }; if (score <= 40) return { riskLevel: 'High', riskColor: 'high' }; if (score <= 60) return { riskLevel: 'Medium', riskColor: 'medium' }; if (score <= 80) return { riskLevel: 'Low', riskColor: 'low' }; return { riskLevel: 'Good', riskColor: 'negligible' }; }

function getRecommendationText(score, reportData) { const hasCriticalSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'critical') || false; const hasHighSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'high') || false; const hasHighIssue = reportData?.details?.securityIssues?.some(s => s.severity?.toLowerCase() === 'high') || false; const mediumIssueCount = reportData?.details?.securityIssues?.filter(s => s.severity?.toLowerCase() === 'medium')?.length || 0; if (hasCriticalSink) return 'Immediate attention required. Critical vulnerabilities present. Fix critical sinks (eval, innerHTML, etc.) and implement strict origin/data validation.'; if (score <= 20) return 'Immediate attention required. Security posture is critically weak. Focus on fixing high-risk issues and implementing strict origin/data validation.'; if (hasHighSink || hasHighIssue || score <= 40) return 'Significant risks identified. Implement strict origin checks and sanitize all inputs used in sinks. Consider a Content Security Policy (CSP).'; if (mediumIssueCount >= 3 || score <= 60) return 'Potential vulnerabilities detected. Review security issues (e.g., origin checks, data validation) and ensure data flowing to sinks is safe.'; if (score <= 80) return 'Low risk detected, but review identified issues and follow security best practices (origin/data validation).'; const hasFindings = (reportData?.details?.sinks?.length > 0) || (reportData?.details?.securityIssues?.length > 0); if (hasFindings) return 'Good score, but minor issues or informational findings detected. Review details and ensure best practices are followed.'; return 'Excellent score. Analysis found no major vulnerabilities. Continue to follow security best practices for postMessage handling.'; }

function renderStructureItem(structureData, index) { const exampleData = structureData.examples?.[0]?.data || structureData.examples?.[0] || {}; let formattedExample = ''; try { formattedExample = typeof exampleData === 'string' ? exampleData : JSON.stringify(exampleData, null, 2); } catch (e) { formattedExample = String(exampleData); } return `<details class="report-details structure-item" data-structure-index="${index}"><summary class="report-summary-toggle">Structure ${index + 1} <span class="toggle-icon">▶</span></summary><div class="structure-content"><p><strong>Example Message:</strong></p><div class="report-code-block"><pre><code>${escapeHTML(formattedExample)}</code></pre></div></div></details>`; }

function renderPayloadItem(payloadItem, index) { let displayString = '(Error displaying payload)'; const maxDisplayLength = 150; const safeEscapeHTML = (str) => { try { return escapeHTML(str); } catch{ return '[Error]'; }}; try { const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem; if (typeof actualPayloadData === 'object' && actualPayloadData !== null) { const payloadJson = JSON.stringify(actualPayloadData, null, 2); displayString = payloadJson.substring(0, maxDisplayLength) + (payloadJson.length > maxDisplayLength ? '...' : ''); } else { const payloadAsString = String(actualPayloadData); displayString = payloadAsString.substring(0, maxDisplayLength) + (payloadAsString.length > maxDisplayLength ? '...' : ''); } } catch (e) { return `<div class="payload-item error">Error rendering payload ${index + 1}.</div>`; } return `<div class="payload-item" data-payload-index="${index}"><pre><code>${safeEscapeHTML(displayString)}</code></pre></div>`; }

function attachReportEventListeners(panel, reportData) { panel.querySelectorAll('details.report-details').forEach(detailsElement => { const iconElement = detailsElement.querySelector('.toggle-icon'); if (detailsElement && iconElement) { detailsElement.addEventListener('toggle', () => { iconElement.textContent = detailsElement.open ? '▼' : '▶'; }); } }); panel.querySelectorAll('.view-full-payload-btn').forEach(btn => { btn.addEventListener('click', (e) => { const item = e.target.closest('.payload-item'); const index = parseInt(item?.getAttribute('data-payload-index')); const payloads = reportData?.details?.payloads || []; if (payloads[index] !== undefined) showFullPayloadModal(payloads[index]); }); }); const showAllPayloadsBtn = panel.querySelector('#showAllPayloadsBtn'); if (showAllPayloadsBtn) { showAllPayloadsBtn.addEventListener('click', () => { const list = panel.querySelector('#payloads-list'); const payloads = reportData?.details?.payloads || []; if (list && payloads.length > 0) { list.innerHTML = payloads.map((p, index) => renderPayloadItem(p, index)).join(''); attachReportEventListeners(panel, reportData); } showAllPayloadsBtn.remove(); }, { once: true }); } const showAllStructuresBtn = panel.querySelector('#showAllStructuresBtn'); if (showAllStructuresBtn) { showAllStructuresBtn.addEventListener('click', () => { const list = panel.querySelector('.structures-list'); const structures = reportData?.details?.uniqueStructures || []; if (list && structures.length > 0) { list.innerHTML = structures.map((s, index) => renderStructureItem(s, index)).join(''); attachReportEventListeners(panel, reportData); } showAllStructuresBtn.remove(); }, { once: true }); } }

function displayReport(reportData, panel) {
    try {
        panel.innerHTML = '';
    } catch (clearError) {
        panel.innerHTML = '<p class="error-message">Internal error clearing report panel.</p>';
        return;
    }
    let content;
    try {
        content = document.createElement('div');
        content.className = 'trace-results-content';
        panel.appendChild(content);
    } catch (contentError) {
        panel.innerHTML = '<p class="error-message">Internal error creating report content area.</p>';
        return;
    }
    if (!reportData || typeof reportData !== 'object') {
        content.innerHTML = '<p class="error-message">Error: Invalid or missing report data.</p>';
        return;
    }
    try {
        const details = reportData.details || {};
        const summary = reportData.summary || {};
        const bestHandler = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler;
        const vulnerabilities = [...(details.sinks || []), ...(reportData.vulnerabilities || [])];
        const securityIssues = [...(details.securityIssues || []), ...(reportData.securityIssues || [])];
        const dataFlows = details.dataFlows || [];
        const payloads = details.payloads || [];
        const structures = details.uniqueStructures || [];
        const endpointDisplay = reportData.endpoint || reportData.originalEndpointKey || 'Unknown';
        const analysisStorageKey = reportData.analysisStorageKey || 'report';
        const originChecks = details.originValidationChecks || [];
        const safeEscape = (str) => { try { return window.escapeHTML(String(str ?? '')); } catch(e){ return '[Error]'; }};
        const safeGetRisk = (score) => { try { return getRiskLevelAndColor(score); } catch(e){ return { riskLevel: 'Error', riskColor: 'critical' }; }};
        const safeGetRec = (score, data) => { try { return getRecommendationText(score, data); } catch(e){ return 'Error generating recommendation.'; }};
        const safeRenderPayload = (p, i) => { try { return renderPayloadItem(p, i); } catch(e){ return '<p class="error-message">Error rendering payload item.</p>'; }};
        const safeRenderStructure = (s, i) => { try { return renderStructureItem(s, i); } catch(e){ return '<p class="error-message">Error rendering structure item.</p>'; }};
        const uniqueVulns = vulnerabilities.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const uniqueIssues = securityIssues.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const score = reportData.securityScore ?? summary.securityScore ?? 100;
        const { riskLevel, riskColor } = safeGetRisk(score);

        const summarySection = document.createElement('div');
        summarySection.className = 'report-section report-summary';
        summarySection.innerHTML = `
            <h4 class="report-section-title">Analysis Summary - <span class="report-endpoint-title">${safeEscape(endpointDisplay)}</span></h4>
            <div class="summary-grid">
                <div class="security-score-container">
                    <h5 class="risk-score-title">Risk Score:</h5>
                    <div class="security-score ${riskColor}" title="Score: ${score} (${riskLevel})">
                        <div class="security-score-value">${score}</div>
                        <div class="security-score-label">${riskLevel}</div>
                    </div>
                </div>
                <div class="summary-metrics">
                    <div class="metric"><span class="metric-label">Msgs</span><span class="metric-value">${summary.messagesAnalyzed ?? 'N/A'}</span></div>
                    <div class="metric"><span class="metric-label">Structs</span><span class="metric-value">${structures?.length ?? 0}</span></div>
                    <div class="metric"><span class="metric-label">Sinks</span><span class="metric-value">${uniqueVulns?.length ?? 0}</span></div>
                    <div class="metric"><span class="metric-label">Issues</span><span class="metric-value">${uniqueIssues?.length ?? 0}</span></div>
                    <div class="metric"><span class="metric-label">Payloads</span><span class="metric-value">${payloads?.length ?? 0}</span></div>
                </div>
            </div>
            <div class="recommendations">
                <h5 class="report-subsection-title">Recommendation</h5>
                <p class="recommendation-text">${safeEscape(safeGetRec(score, reportData))}</p>
            </div>`;
        content.appendChild(summarySection);

        if (bestHandler?.handler) {
            const handlerSection = document.createElement('div');
            handlerSection.className = 'report-section report-handler';
            handlerSection.innerHTML = `
                <details class="report-details">
                    <summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Cat: ${safeEscape(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▶</span></summary>
                    <div class="report-code-block handler-code"><pre><code>${safeEscape(bestHandler.handler)}</code></pre></div>
                </details>`;
            content.appendChild(handlerSection);
        }

        const findingsSection = document.createElement('div');
        findingsSection.className = 'report-section report-findings';
        let findingsHTML = '<h4 class="report-section-title">Findings</h4>';

        if (originChecks.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Origin Validation (${originChecks.length})</h5><table class="report-table"><thead><tr><th>Check Type</th><th>Strength</th><th>Compared Value</th><th>Snippet</th></tr></thead><tbody>`;
            originChecks.forEach(check => {
                const type = check?.type || '?';
                const strength = check?.strength || 'N/A';
                const value = check?.comparedValue !== null && check?.comparedValue !== undefined ? String(check.comparedValue).substring(0, 100) : 'N/A';
                const snippetHTML = check?.rawSnippet ? `<code class="context-snippet">${safeEscape(check.rawSnippet)}</code>` : 'N/A';
                let strengthClass = strength.toLowerCase();
                if(strength === 'Missing') strengthClass = 'critical'; else if(strength === 'Weak') strengthClass = 'high'; else if(strength === 'Medium') strengthClass = 'medium'; else if(strength === 'Strong') strengthClass = 'negligible'; else strengthClass='low';
                findingsHTML += `<tr class="severity-row-${strengthClass}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${strengthClass}">${safeEscape(strength)}</span></td><td><code>${safeEscape(value)}</code></td><td>${snippetHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueVulns.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">DOM XSS Sinks Detected (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueVulns.forEach(vuln => {
                const type = vuln?.type || '?'; const severity = vuln?.severity || 'N/A'; const contextHTML = vuln?.context || '';
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscape(severity)}</span></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueIssues.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Other Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueIssues.forEach(issue => {
                const type = issue?.type || '?'; const severity = issue?.severity || 'N/A'; const contextHTML = issue?.context || '';
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscape(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscape(severity)}</span></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (!originChecks.length && !uniqueVulns.length && !uniqueIssues.length) { findingsHTML += '<p class="no-findings-text">No significant findings detected.</p>'; }
        findingsSection.innerHTML = findingsHTML;
        content.appendChild(findingsSection);

        if (dataFlows?.length > 0) {
            const flowSection = document.createElement('div');
            flowSection.className = 'report-section report-dataflow';
            flowSection.innerHTML = ` <h4 class="report-section-title">Data Flow</h4> <table class="report-table dataflow-table"> <thead> <tr> <th>Source Property</th> <th>Sink / Target</th> <th>Conditions</th> <th>Code Snippet</th> </tr> </thead> <tbody> </tbody> </table>`;
            const tbody = flowSection.querySelector('tbody');
            if (tbody) {
                dataFlows.forEach(flow => {
                    const prop = flow?.sourcePath || '?'; const sink = flow?.destinationContext || '?'; const context = flow?.fullCodeSnippet || flow?.taintedNodeSnippet || ''; const displayProp = prop === '(root)' ? '(root data)' : `event.data.${safeEscape(prop)}`; const conditions = flow?.requiredConditionsForFlow || [];
                    let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = safeEscape(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${safeEscape(c.path)} ${safeEscape(c.op)} ${valStr}</code>`; }).join('<br>'); }
                    const rowHtml = ` <tr> <td><code>${displayProp}</code></td> <td>${safeEscape(sink)}</td> <td>${conditionsHtml}</td> <td><code class="context-snippet">${safeEscape(context)}</code></td> </tr>`; tbody.insertAdjacentHTML('beforeend', rowHtml);
                });
            } else { flowSection.innerHTML += '<p class="error-message">Error rendering data flow table body.</p>'; }
            content.appendChild(flowSection);
        }

        if (payloads?.length > 0) {
            const payloadSection = document.createElement('div');
            payloadSection.className = 'report-section report-payloads';
            payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (${payloads.length})</h4><div id="payloads-list" class="payloads-list report-list">${payloads.slice(0, 10).map((p, i) => safeRenderPayload(p, i)).join('')}</div>${payloads.length > 10 ? `<button id="showAllPayloadsBtn" class="control-button secondary-button show-more-btn">Show All ${payloads.length}</button>` : ''}`;
            content.appendChild(payloadSection);
        }

        if (structures?.length > 0) {
            const structureSection = document.createElement('div');
            structureSection.className = 'report-section report-structures';
            let structuresHTML = `<h4 class="report-section-title">Unique Msg Structures (${structures.length})</h4><div class="structures-list report-list">`;
            structures.slice(0, 3).forEach((s, i) => { structuresHTML += safeRenderStructure(s, i); }); structuresHTML += `</div>`;
            if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length}</button>`; }
            structureSection.innerHTML = structuresHTML;
            content.appendChild(structureSection);
        }

        const buttonContainer = document.createElement('div'); buttonContainer.style.cssText = 'margin-top:20px; display: flex; justify-content: center; gap: 15px;'; const exportJsonBtn = document.createElement('button'); exportJsonBtn.textContent = 'Export JSON'; exportJsonBtn.className = 'control-button secondary-button'; exportJsonBtn.addEventListener('click', (e) => { e.stopPropagation(); try { const jsonData = JSON.stringify(reportData, null, 2); const blob = new Blob([jsonData], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); const safeFilename = (analysisStorageKey || 'frogpost_report').replace(/[^a-z0-9_\-.]/gi, '_'); a.href = url; a.download = `${safeFilename}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); } catch (exportError) { alert("Failed to export report as JSON."); } }); const closeBtnInside = document.createElement('button'); closeBtnInside.textContent = 'Close Report'; closeBtnInside.className = 'control-button secondary-button'; closeBtnInside.onclick = () => { document.querySelector('.trace-panel-backdrop')?.remove(); panel.remove(); }; buttonContainer.appendChild(exportJsonBtn); buttonContainer.appendChild(closeBtnInside); content.appendChild(buttonContainer);
        attachReportEventListeners(panel, reportData);

    } catch (renderError) {
        content.innerHTML = `<p class="error-message">Error rendering report details: ${renderError.message}</p>`;
        console.error("Error rendering report:", renderError);
    }
}

function showFullPayloadModal(payloadItem) {
    document.querySelector('.payload-modal')?.remove(); document.querySelector('.payload-modal-backdrop')?.remove(); const modal = document.createElement('div'); modal.className = 'payload-modal'; const modalContent = document.createElement('div'); modalContent.className = 'payload-modal-content'; const closeBtn = document.createElement('span'); closeBtn.className = 'close-modal'; closeBtn.innerHTML = '&times;'; const backdrop = document.createElement('div'); backdrop.className = 'payload-modal-backdrop'; const closeModal = () => { modal.remove(); backdrop.remove(); }; closeBtn.onclick = closeModal; backdrop.onclick = closeModal; const heading = document.createElement('h4'); const targetInfo = document.createElement('p'); targetInfo.style.cssText = 'margin-bottom:15px;font-size:13px;color:#aaa;'; const payloadPre = document.createElement('pre'); payloadPre.className = 'report-code-block'; payloadPre.style.cssText = 'max-height:50vh;overflow-y:auto;'; const payloadCode = document.createElement('code'); const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem; heading.textContent = `Payload Details (Type: ${escapeHTML(payloadItem?.type || 'unknown')})`; targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payloadItem?.targetPath || payloadItem?.targetFlow || payloadItem?.description || 'N/A')}`; let formattedPayload = ''; try { if (typeof actualPayloadData === 'object' && actualPayloadData !== null) formattedPayload = JSON.stringify(actualPayloadData, null, 2); else formattedPayload = String(actualPayloadData); } catch { formattedPayload = String(actualPayloadData); } payloadCode.textContent = formattedPayload; payloadPre.appendChild(payloadCode); const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy Payload'; copyBtn.className = 'control-button'; copyBtn.style.marginTop = '15px'; copyBtn.onclick = () => { navigator.clipboard.writeText(formattedPayload).then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }).catch(() => { copyBtn.textContent = 'Copy Failed'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }); }; modalContent.appendChild(closeBtn); modalContent.appendChild(heading); modalContent.appendChild(targetInfo); modalContent.appendChild(payloadPre); modalContent.appendChild(copyBtn); modal.appendChild(modalContent); document.body.appendChild(backdrop); document.body.appendChild(modal);
}

async function handleReportButton(endpoint) {
    const endpointKey = getStorageKeyForUrl(endpoint); if (!endpointKey) return; let reportData = null; let reportPayloads = null; let keyUsed = endpointKey;
    try { const traceInfoKey = `trace-info-${endpointKey}`; const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve)); const traceInfo = traceInfoResult[traceInfoKey]; if (traceInfo?.analysisStorageKey) keyUsed = traceInfo.analysisStorageKey; else if (traceInfo?.analyzedUrl) keyUsed = getStorageKeyForUrl(traceInfo.analyzedUrl); [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]); if (!reportData && keyUsed !== endpointKey) { keyUsed = endpointKey; [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]); } if (!reportData || typeof reportData !== 'object') throw new Error(`No report data found for key ${keyUsed}. Run Trace first.`); if (!reportData.details) reportData.details = {}; reportData.details.payloads = reportPayloads || []; if (!reportData.summary) reportData.summary = {}; reportData.summary.payloadsGenerated = reportPayloads?.length || 0; document.querySelector('.trace-results-panel')?.remove(); document.querySelector('.trace-panel-backdrop')?.remove(); const tracePanel = document.createElement('div'); tracePanel.className = 'trace-results-panel'; const backdrop = document.createElement('div'); backdrop.className = 'trace-panel-backdrop'; backdrop.onclick = () => { tracePanel.remove(); backdrop.remove(); }; const reportContainer = document.getElementById('reportPanelContainer') || document.body; reportContainer.appendChild(backdrop); reportContainer.appendChild(tracePanel); addTraceReportStyles(); displayReport(reportData, tracePanel); }
    catch (error) { log.error('Error handling report button:', error); alert(`Failed to display report: ${error?.message}`); }
}

async function checkAllEndpoints() { const endpointButtons = document.querySelectorAll('.iframe-row .iframe-check-button'); for (const button of endpointButtons) { const endpointKey = button.getAttribute('data-endpoint'); if (endpointKey && !button.classList.contains('green') && !button.classList.contains('success')) { try { await handlePlayButton(endpointKey, button); await new Promise(resolve => setTimeout(resolve, 500)); } catch {} } } }

async function populateInitialHandlerStates() {
    try { const allData = await chrome.storage.local.get(null); endpointsWithHandlers.clear(); for (const key in allData) { if (key.startsWith('best-handler-')) { const handlerKey = key.substring('best-handler-'.length); if(handlerKey) endpointsWithHandlers.add(handlerKey); } } }
    catch (error) { log.error("Error populating initial handler states:", error); }
    finally { requestUiUpdate(); }
}

const traceReportStyles = `.trace-results-panel {} .trace-panel-backdrop {} .trace-panel-header {} .trace-panel-close {} .trace-results-content {} .report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; } .report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); } .report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; } .report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; } .security-score-container { display: flex; justify-content: center; } .security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); } .security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; } .security-score div { position: relative; z-index: 2; } .security-score-value { font-size: 28px; line-height: 1; } .security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; } .security-score.critical { border-color: #e74c3c; } .security-score.high { border-color: #e67e22; } .security-score.medium { border-color: #f39c12; } .security-score.low { border-color: #3498db; } .security-score.negligible { border-color: #2ecc71; } .summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; } .metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; } .metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; } .metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; } .recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; } .recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; } .report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; } .report-code-block pre { margin: 0; } .report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; } .report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; } details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; } summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; } summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); } details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; } .toggle-icon { font-size: 1.2em; transition: transform 0.2s; } details[open] .toggle-icon { transform: rotate(90deg); } .report-details > div { padding: 15px; } .report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; } .report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; } .report-table th { background-color: #2c313a; font-weight: bold; color: #fff; } .report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; } .report-table .context-snippet { max-width: 400px; white-space: pre-wrap; word-break: break-all; display: inline-block; vertical-align: middle; } .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; } .severity-critical { background-color: #e74c3c; color: white; } .severity-high { background-color: #e67e22; color: white; } .severity-medium { background-color: #f39c12; color: #333; } .severity-low { background-color: #3498db; color: white; } .severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); } .severity-row-high td { background-color: rgba(230, 126, 34, 0.15); } .severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); } .severity-row-low td { background-color: rgba(52, 152, 219, 0.1); } .no-findings-text { color: #777; font-style: italic; padding: 10px 0; } .dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; } .report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; } .payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; } .payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; } .payload-header strong { color: #fff; } .payload-meta { color: #8be9fd; margin: 0 5px; } .payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; } .structure-content { padding: 15px; } .structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; } .structure-content strong { color: #00e1ff; } .structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; } .show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; } .show-more-btn:hover { background-color: #4a5058; color: #fff; } .control-button {} .secondary-button {} .error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; } span.highlight-finding { background-color: rgba(255, 0, 0, 0.3); color: #ffdddd; font-weight: bold; padding: 1px 2px; border-radius: 2px; border: 1px solid rgba(255, 100, 100, 0.5); }`;

const progressStyles = `.trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; } .trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; } .phase-list { display: flex; flex-direction: column; gap: 10px; } .phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; } .phase .emoji { font-size: 20px; line-height: 1; } .phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; } .phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; } .phase.active .label { color: #fff; font-weight: 600; } .phase.active .emoji { animation: spin 1s linear infinite; } .phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; } .phase.completed .label { color: #50fa7b; } .phase.completed .emoji::before { content: '✅'; } .phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; } .phase.error .label { color: #ff5555; font-weight: 600; } .phase.error .emoji::before { content: '❌'; } .phase[data-phase="finished"], .phase[data-phase="error"] { display: none; } .phase[data-phase="finished"].completed, .phase[data-phase="error"].error { display: flex; } @keyframes pulse-border { 0% { border-color: #00e1ff; } 50% { border-color: rgba(0, 225, 255, 0.5); } 100% { border-color: #00e1ff; } } @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`;

function addTraceReportStyles() { if (!document.getElementById('frogpost-report-styles')) { const styleElement = document.createElement('style'); styleElement.id = 'frogpost-report-styles'; styleElement.textContent = traceReportStyles; document.head.appendChild(styleElement); } }
window.addTraceReportStyles = addTraceReportStyles;

function addProgressStyles() { if (!document.getElementById('frogpost-progress-styles')) { const styleEl = document.createElement('style'); styleEl.id = 'frogpost-progress-styles'; styleEl.textContent = progressStyles; document.head.appendChild(styleEl); } }
window.addProgressStyles = addProgressStyles;

window.addEventListener('DOMContentLoaded', () => {
    const clearStoredMessages = () => { chrome.runtime.sendMessage({ type: "resetState" }); localStorage.removeItem('interceptedMessages'); window.frogPostState.messages.length = 0; window.frogPostState.frameConnections.clear(); buttonStates.clear(); reportButtonStates.clear(); traceButtonStates.clear(); window.frogPostState.activeUrl = null; };
    clearStoredMessages();
    const sidebarToggle = document.getElementById('sidebarToggle'); const controlSidebar = document.getElementById('controlSidebar'); if (sidebarToggle && controlSidebar) { if (!controlSidebar.classList.contains('open')) sidebarToggle.classList.add('animate-toggle'); sidebarToggle.addEventListener('click', () => { controlSidebar.classList.toggle('open'); sidebarToggle.classList.toggle('animate-toggle', !controlSidebar.classList.contains('open')); }); }
    printBanner(); setupUIControls(); initializeMessageHandling(); populateInitialHandlerStates(); addTraceReportStyles(); addProgressStyles();

    const filterInput = document.getElementById('endpointFilterInput');
    if (filterInput) {
        filterInput.addEventListener('input', requestUiUpdate);
    } else {
        log.error("Could not find endpoint filter input element (#endpointFilterInput)");
    }

    const silentFilterToggle = document.getElementById('silentFilterToggle');
    if (silentFilterToggle) {
        const textSpan = silentFilterToggle.querySelector('.button-text');
        if (textSpan) textSpan.textContent = showOnlySilentIframes ? 'Silent Listeners On' : 'Silent Listeners Off';
        silentFilterToggle.classList.toggle('active', showOnlySilentIframes);

        silentFilterToggle.addEventListener('click', () => {
            showOnlySilentIframes = !showOnlySilentIframes;
            silentFilterToggle.classList.toggle('active', showOnlySilentIframes);
            const textSpan = silentFilterToggle.querySelector('.button-text');
            if (textSpan) textSpan.textContent = showOnlySilentIframes ? 'Silent Listeners On' : 'Silent Listeners Off';
            log.info(`Silent iframe filter ${showOnlySilentIframes ? 'ON (Showing ONLY Silent)' : 'OFF (Showing All)'}.`);
            requestUiUpdate();
        });
    } else {
        log.error("Could not find silent filter toggle button (#silentFilterToggle)");
    }

    requestUiUpdate();

    try { chrome.storage.session.get('customXssPayloads', (result) => { const storedPayloads = result.customXssPayloads; if (storedPayloads && storedPayloads.length > 0) { updatePayloadStatus(true, storedPayloads.length); if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...storedPayloads]; } } else { try { const localPayloads = localStorage.getItem('customXssPayloads'); if (localPayloads) { const parsed = JSON.parse(localPayloads); if (Array.isArray(parsed) && parsed.length > 0) { chrome.storage.session.set({ customXssPayloads: parsed }, () => { if (!chrome.runtime.lastError) { updatePayloadStatus(true, parsed.length); if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...parsed]; } } }); } } } catch {} } }); } catch (e) {}
});
