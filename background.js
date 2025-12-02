/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-10-22
 * Updated: 2025-11-15 - Handler detection & performance optimizations
 */

// TELEMETRY-FIRST: No AST parsing needed
try {
    importScripts(
        './static/handler-extractor.js'
    );
} catch (e) {
    console.error("Background.js: Failed to import handler-extractor.js", e);
}

let debugMode = false; // Flag to control debug logging - Loaded from storage, false by default
const DEBUG_MODE_STORAGE_KEY = 'frogpostDebugMode';

// Load debug mode from storage on startup
(async () => {
    try {
        const result = await chrome.storage.local.get([DEBUG_MODE_STORAGE_KEY]);
        debugMode = result[DEBUG_MODE_STORAGE_KEY] || false;
    } catch (error) {
        debugMode = false;
    }
})();

const log = {
    debug: (...args) => { if (debugMode) console.debug("BG:", ...args); },
    info: (...args) => { if (debugMode) console.info("BG:", ...args); },
    warn: (...args) => { console.warn("BG:", ...args); }, // Always show warnings
    error: (...args) => { console.error("BG:", ...args); }, // Always show errors
    handler: (...args) => { if (debugMode) console.log("BG HANDLER:", ...args); },
    scan: (...args) => { if (debugMode) console.log("BG SCAN:", ...args); },
};
/**
 * BoundedMap - Prevents memory leaks by limiting Map size
 * Automatically removes oldest entries when limit is reached
 */
class BoundedMap extends Map {
    constructor(maxSize = 100) {
        super();
        this.maxSize = maxSize;
    }
    
    set(key, value) {
        // If we're at capacity, remove the oldest entry
        if (this.size >= this.maxSize && !this.has(key)) {
            const firstKey = this.keys().next().value;
            this.delete(firstKey);
        }
        return super.set(key, value);
    }
}

/**
 * BoundedSet - Prevents memory leaks by limiting Set size
 */
class BoundedSet extends Set {
    constructor(maxSize = 100) {
        super();
        this.maxSize = maxSize;
    }
    
    add(value) {
        // If we're at capacity, remove the first entry
        if (this.size >= this.maxSize && !this.has(value)) {
            const firstValue = this.values().next().value;
            this.delete(firstValue);
        }
        return super.add(value);
    }
}

/**
 * LRUCache - Least Recently Used cache implementation
 * Efficiently tracks access order and evicts least recently used entries
 */
class LRUCache extends Map {
    constructor(maxSize = 100) {
        super();
        this.maxSize = maxSize;
        this.accessOrder = []; // Track access order (most recent at end)
    }
    
    get(key) {
        if (super.has(key)) {
            // Move to end (most recently used)
            this._updateAccess(key);
            return super.get(key);
        }
        return undefined;
    }
    
    set(key, value) {
        if (super.has(key)) {
            // Update existing entry and move to end
            super.set(key, value);
            this._updateAccess(key);
        } else {
            // Add new entry
            if (this.size >= this.maxSize) {
                // Evict least recently used (first in accessOrder)
                const lruKey = this.accessOrder.shift();
                if (lruKey !== undefined) {
                    super.delete(lruKey);
                }
            }
            super.set(key, value);
            this.accessOrder.push(key);
        }
        return this;
    }
    
    delete(key) {
        if (super.has(key)) {
            super.delete(key);
            const index = this.accessOrder.indexOf(key);
            if (index !== -1) {
                this.accessOrder.splice(index, 1);
            }
        }
        return super.has(key);
    }
    
    clear() {
        super.clear();
        this.accessOrder = [];
    }
    
    _updateAccess(key) {
        const index = this.accessOrder.indexOf(key);
        if (index !== -1) {
            // Move to end (most recently used)
            this.accessOrder.splice(index, 1);
            this.accessOrder.push(key);
        }
    }
}

/**
 * In-Memory Handler Cache for Real-Time Capture
 * Stores handlers immediately when detected by DOM agent
 * Uses LRU eviction to keep most recently accessed handlers
 */
const MAX_CACHE_SIZE = 500;
const MAX_HANDLERS_PER_URL = 10;
const handlerCache = new LRUCache(MAX_CACHE_SIZE);

/**
 * OPTIMIZATION: Fast hash function for handler deduplication
 * 5-10x faster than full string comparison for long handlers
 */
function fastHashHandler(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash; // Convert to 32-bit integer
    }
    return hash;
}

/**
 * RELIABILITY FIX: Generate URL variants for fuzzy matching
 * Handles cases where URL has query params, hash, trailing slash variations
 */
function generateUrlVariants(url) {
    try {
        const urlObj = new URL(url);
        const variants = new Set();
        
        // Variant 1: Full URL (primary key - CRITICAL for backward compatibility)
        variants.add(url);
        
        // Variant 2: Origin + pathname + search (no hash)
        variants.add(urlObj.origin + urlObj.pathname + urlObj.search);
        
        // Variant 3: Origin + pathname (no query/hash)
        variants.add(urlObj.origin + urlObj.pathname);
        
        // Variant 4: With trailing slash
        const pathWithSlash = urlObj.pathname.endsWith('/') ? urlObj.pathname : urlObj.pathname + '/';
        variants.add(urlObj.origin + pathWithSlash);
        
        // Variant 5: Without trailing slash
        const pathWithoutSlash = urlObj.pathname.endsWith('/') ? urlObj.pathname.slice(0, -1) : urlObj.pathname;
        if (pathWithoutSlash) {
            variants.add(urlObj.origin + pathWithoutSlash);
        }
        
        return Array.from(variants);
    } catch {
        // Invalid URL - return as-is
        return [url];
    }
}

let frameConnections = new BoundedMap(50); // Limit to 50 frame connections
let messageBuffer;
const injectedFramesAgents = new BoundedMap(20); // Limit to 20 injected agents

/**
 * StorageBatcher - Batches storage writes to reduce I/O operations
 * Accumulates writes over 100ms window and merges writes to same key
 */
class StorageBatcher {
    constructor(flushInterval = 100, maxQueueSize = 10) {
        this.queue = new Map(); // key -> value
        this.flushInterval = flushInterval;
        this.maxQueueSize = maxQueueSize;
        this.flushTimer = null;
        this.flushing = false;
    }

    set(keyValuePairs, options = {}) {
        const immediate = options.immediate || false;
        
        // Add to queue (merge if key already exists)
        for (const [key, value] of Object.entries(keyValuePairs)) {
            this.queue.set(key, value);
        }

        // Flush immediately if requested or queue is full
        if (immediate || this.queue.size >= this.maxQueueSize) {
            this.flush();
        } else {
            // Schedule flush if not already scheduled
            if (!this.flushTimer) {
                this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
            }
        }
    }

    async flush() {
        if (this.flushing || this.queue.size === 0) return;
        
        this.flushing = true;
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }

        try {
            const toWrite = Object.fromEntries(this.queue);
            this.queue.clear();
            
            await chrome.storage.local.set(toWrite);
            log.debug(`[StorageBatcher] Flushed ${Object.keys(toWrite).length} items`);
        } catch (error) {
            log.error('[StorageBatcher] Flush error:', error);
            // Re-queue failed writes
            for (const [key, value] of Object.entries(toWrite)) {
                this.queue.set(key, value);
            }
        } finally {
            this.flushing = false;
        }
    }

    // Force immediate flush (for critical operations)
    async forceFlush() {
        if (this.flushTimer) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }
        await this.flush();
    }
}

// Global storage batcher instance
const storageBatcher = new StorageBatcher(100, 10);

// Server management
let serverCheckInterval = null;
const SERVER_PORT = 1337;
const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}`;

/**
 * Check if local FrogPost server is running
 */
async function isServerRunning() {
    try {
        const response = await fetch(`${SERVER_URL}/health`, { 
            method: 'GET',
            signal: AbortSignal.timeout(2000)
        });
        return response.ok;
    } catch {
        return false;
    }
}

/**
 * Attempt to start the local server (requires native messaging or user action)
 */
async function ensureServerRunning() {
    if (await isServerRunning()) {
        log.debug("Server already running");
        return true;
    }
    
    log.warn("Server not running. LLM features will be limited.");
    
    // Show notification to user about starting server
    try {
        await chrome.notifications.create('frogpost-server-needed', {
            type: 'basic',
            iconUrl: 'icons/frog-logo48.png',
            title: 'FrogPost Server Needed',
            message: 'Start the server with "node server.js" for AI analysis features.'
        });
    } catch (e) {
        log.debug("Could not show notification:", e);
    }
    
    return false;
}

/**
 * Auto-check server status periodically when extension is active
 */
function startServerMonitoring() {
    if (serverCheckInterval) return;
    
    serverCheckInterval = setInterval(async () => {
        const running = await isServerRunning();
        chrome.storage.session.set({ 'server-running': running });
        
        if (!running) {
            log.debug("Server stopped - LLM features disabled");
        }
    }, 30000); // Check every 30 seconds
}
const HANDLER_ENDPOINT_KEYS_STORAGE_KEY = 'handler_endpoint_keys';
let endpointsWithDetectedHandlers = new BoundedSet(30); // Limit to 30 endpoints
let nativePort = null;
const NATIVE_HOST_NAME = "com.nodeserver.starter";
let consoleSuccessIndices = [];
let activeDebugSessions = new BoundedMap(10); // Limit to 10 debug sessions
const autoAttachInProgress = new BoundedSet(5); // Limit to 5 concurrent attachments
const processedUrlsInSession = new BoundedSet(100); // Limit to 100 processed URLs
let isDebuggerApiModeGloballyEnabled = false;
const DEBUGGER_MODE_STORAGE_KEY = 'debuggerApiModeEnabled';

// PERFORMANCE: Debugger session limiting to prevent browser lag
const MAX_CONCURRENT_DEBUGGER_SESSIONS = 3;
let activeDebuggerCount = 0;
const debuggerQueue = [];

function canAttachDebugger() {
    return activeDebuggerCount < MAX_CONCURRENT_DEBUGGER_SESSIONS;
}

function incrementDebuggerCount() {
    activeDebuggerCount++;
    log.debug(`[Debugger Limit] Active sessions: ${activeDebuggerCount}/${MAX_CONCURRENT_DEBUGGER_SESSIONS}`);
}

function decrementDebuggerCount() {
    activeDebuggerCount = Math.max(0, activeDebuggerCount - 1);
    log.debug(`[Debugger Limit] Active sessions: ${activeDebuggerCount}/${MAX_CONCURRENT_DEBUGGER_SESSIONS}`);
    processDebuggerQueue();
}

function processDebuggerQueue() {
    if (debuggerQueue.length > 0 && canAttachDebugger()) {
        const nextTask = debuggerQueue.shift();
        if (nextTask) {
            log.debug(`[Debugger Limit] Processing queued task (${debuggerQueue.length} remaining)`);
            nextTask();
        }
    }
}

(async () => {
    try {
        const result = await chrome.storage.local.get([DEBUGGER_MODE_STORAGE_KEY]);
        isDebuggerApiModeGloballyEnabled = result[DEBUGGER_MODE_STORAGE_KEY] || false;
    } catch (error) {
        log.error("Error loading initial debugger mode state:", error);
        isDebuggerApiModeGloballyEnabled = false;
    }
})();
// Helper: Fetch response headers via debugger network interception to reliably read X-Frame-Options/CSP
async function fetchHeadersViaDebugger(targetUrl) {
    let tabId = null;
    let attached = false;
    let headers = {};
    let status = 0;
    let reason = '';
    let finalUrl = targetUrl; // Track final URL after redirects
    let redirectChain = []; // Track redirect chain
    try {
        const tab = await chrome.tabs.create({ url: targetUrl, active: false });
        tabId = tab.id;
        await chrome.debugger.attach({ tabId }, '1.3');
        attached = true;
        await chrome.debugger.sendCommand({ tabId }, 'Network.enable');
        await chrome.debugger.sendCommand({ tabId }, 'Page.enable');

        let resolveOnce;
        const done = new Promise(res => { resolveOnce = res; });
        const onEvent = (src, method, params) => {
            if (src.tabId !== tabId) return;
            
            // Track redirects by monitoring request chains
            if (method === 'Network.requestWillBeSent' && params?.type === 'Document') {
                const request = params.request || {};
                const requestUrl = request.url;
                const redirectResponse = params.redirectResponse;
                
                if (redirectResponse && redirectResponse.status >= 300 && redirectResponse.status < 400) {
                    // This is a redirect!
                    try {
                        const location = redirectResponse.headers?.Location || redirectResponse.headers?.location;
                        redirectChain.push({ from: finalUrl, to: requestUrl, status: redirectResponse.status });
                        finalUrl = requestUrl;
                        log.info(`[Debugger] Redirect detected: ${redirectResponse.status} ${finalUrl} → ${requestUrl}`);
                    } catch (e) {
                        log.warn(`[Debugger] Failed to track redirect: ${e.message}`);
                    }
                }
            }
            
            if (method === 'Network.responseReceived' && params?.type === 'Document') {
                try {
                    const resp = params.response || {};
                    status = resp.status || 0;
                    const hs = resp.headers || {};
                    const map = {};
                    for (const k in hs) { map[k] = hs[k]; map[k.toLowerCase()] = hs[k]; }
                    
                    if (status >= 200 && status < 300) {
                        // Final response - use these headers
                        headers = map;
                        
                        // CRITICAL: Check if final URL differs from original (indicates redirect)
                        if (resp.url && resp.url !== targetUrl) {
                            if (redirectChain.length === 0) {
                                // Redirect happened but we didn't catch it in requestWillBeSent
                                log.warn(`[Debugger] Redirect detected via final URL: ${targetUrl} → ${resp.url}`);
                                redirectChain.push({ from: targetUrl, to: resp.url, status: 'unknown' });
                            }
                            finalUrl = resp.url;
                        }
                        
                        resolveOnce();
                    }
                } catch (_) { resolveOnce(); }
            } else if (method === 'Page.loadEventFired') {
                resolveOnce();
            }
        };
        chrome.debugger.onEvent.addListener(onEvent);

        // Navigate explicitly to trigger response
        await chrome.debugger.sendCommand({ tabId }, 'Page.navigate', { url: targetUrl });
        await Promise.race([done, new Promise(res => setTimeout(res, 6000))]);
        chrome.debugger.onEvent.removeListener(onEvent);
        reason = 'ok';
        
        if (redirectChain.length > 0) {
            log.info(`[Debugger] Redirect chain: ${targetUrl} → ${redirectChain.map(r => r.to).join(' → ')}`);
        }
    } catch (e) {
        reason = e?.message || 'debugger error';
    } finally {
        try { if (attached && tabId) await chrome.debugger.detach({ tabId }); } catch {}
        try { if (tabId) await chrome.tabs.remove(tabId); } catch {}
    }
    return { status, headers, reason, finalUrl, redirectChain };
}


class CircularMessageBuffer {
    constructor(maxSize = 100) { this.maxSize = maxSize; this.buffer = new Array(this.maxSize); this.head = 0; this.size = 0; }
    push(message) { message.messageId = message.messageId || `${message.timestamp || Date.now()}-${Math.random().toString(16).slice(2)}`; const existingIndex = this.findIndex(m => m.messageId === message.messageId); if (existingIndex !== -1) { this.buffer[existingIndex] = message; } else { this.buffer[this.head] = message; this.head = (this.head + 1) % this.maxSize; if (this.size < this.maxSize) { this.size++; } } }
    findIndex(predicate) { for (let i = 0; i < this.size; i++) { const index = (this.head - this.size + i + this.maxSize) % this.maxSize; if (this.buffer[index] !== undefined && predicate(this.buffer[index])) { return index; } } return -1; }
    getMessages() { const messages = []; for (let i = 0; i < this.size; i++) { const index = (this.head - this.size + i + this.maxSize) % this.maxSize; if (this.buffer[index] !== undefined) { messages.push(this.buffer[index]); } } return messages; }
    clear() { this.buffer = new Array(this.maxSize); this.head = 0; this.size = 0; }
}
messageBuffer = new CircularMessageBuffer(100);

// Deep JSON sanitizer: caps total keys across nested structure and array lengths (defense-in-depth)
// CRITICAL: Does NOT add any markers to the output - clean truncation only
function sanitizeJsonDeep(value, options = {}) {
    const maxKeysTotal = typeof options.maxKeysTotal === 'number' ? options.maxKeysTotal : 50;
    const maxArrayLength = typeof options.maxArrayLength === 'number' ? options.maxArrayLength : 50;
    const maxDepth = typeof options.maxDepth === 'number' ? options.maxDepth : 8;
    let remainingKeys = maxKeysTotal;

    function walk(val, depth) {
        if (depth > maxDepth) return '[truncated: max depth]';
        if (!val || typeof val !== 'object') return val;
        if (Array.isArray(val)) {
            const out = [];
            const len = Math.min(val.length, maxArrayLength);
            for (let i = 0; i < len; i++) {
                if (remainingKeys <= 0) break;
                out.push(walk(val[i], depth + 1));
            }
            // Silent truncation - no marker objects added
            return out;
        }

        const out = {};
        const keys = Object.keys(val);
        for (let i = 0; i < keys.length; i++) {
            if (remainingKeys <= 0) break;
            const k = keys[i];
            remainingKeys--;
            out[k] = walk(val[k], depth + 1);
        }
        // Silent truncation - no marker keys added
        return out;
    }

    return walk(value, 0);
}

function normalizeEndpointUrl(url) { try { if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) { return { normalized: url, components: null }; } let absoluteUrlStr = url; if (!url.includes('://') && !url.startsWith('//')) { absoluteUrlStr = 'https:' + url; } else if (url.startsWith('//')) { absoluteUrlStr = 'https:' + url; } const urlObj = new URL(absoluteUrlStr); if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:', 'blob:', 'data:'].includes(urlObj.protocol)) { const normalized = url; return { normalized: normalized, components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash } }; } const normalized = urlObj.origin + urlObj.pathname + urlObj.search; return { normalized: normalized, components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash } }; } catch (e) { return { normalized: url, components: null }; } }
function addFrameConnection(origin, destinationUrl) { let addedNew = false; try { const normalizedOrigin = normalizeEndpointUrl(origin)?.normalized; const normalizedDestination = normalizeEndpointUrl(destinationUrl)?.normalized; if (!normalizedOrigin || !normalizedDestination || normalizedOrigin === 'null' || normalizedDestination === 'null' || normalizedOrigin === 'access-denied-or-invalid' || normalizedDestination === 'access-denied-or-invalid' || normalizedOrigin === normalizedDestination ) { return false; } if (!frameConnections.has(normalizedOrigin)) { frameConnections.set(normalizedOrigin, new Set()); addedNew = true; } const destSet = frameConnections.get(normalizedOrigin); if (!destSet.has(normalizedDestination)) { destSet.add(normalizedDestination); addedNew = true; } } catch (e) {} return addedNew; }
async function isDashboardOpen() { try { const dashboardUrl = chrome.runtime.getURL("dashboard/dashboard.html"); const tabs = await chrome.tabs.query({ url: dashboardUrl }); return tabs.length > 0; } catch (e) { return false; } }
async function notifyDashboard(type, payload) { if (!(await isDashboardOpen())) return; try { let serializablePayload; try { JSON.stringify(payload); serializablePayload = payload; } catch (e) { if (payload instanceof Map) serializablePayload = Object.fromEntries(payload); else if (payload instanceof Set) serializablePayload = Array.from(payload); else serializablePayload = { error: "Payload not serializable", type: payload?.constructor?.name }; } if (chrome?.runtime?.id) { await chrome.runtime.sendMessage({ type: type, payload: serializablePayload }); } } catch (error) { if (!error.message?.includes("Receiving end does not exist") && !error.message?.includes("Could not establish connection")) {} } }
/**
 * RELIABILITY FIX: Inject DOM agent with retry logic
 * Handles transient failures like "Frame with ID 0 was removed"
 */
async function injectDOMAgent(tabId, frameId = 0, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tabId, frameIds: [frameId] },
                files: ['dom_injection_agent.js'],
                world: 'MAIN'
            });
            
            if (results?.[0]?.error) {
                throw new Error(results[0].error);
            }
            
            if (attempt > 1) {
                log.info(`[DOM Agent] Successfully injected into tab ${tabId}, frame ${frameId} (attempt ${attempt}/${maxRetries})`);
            } else {
                log.info(`[DOM Agent] Successfully injected into tab ${tabId}, frame ${frameId}`);
            }
            return true;
            
        } catch (error) {
            const isLastAttempt = (attempt === maxRetries);
            const isTransientError = error.message?.includes('Frame with ID') || 
                                   error.message?.includes('was removed') ||
                                   error.message?.includes('No frame with id');
            
            if (!isLastAttempt && isTransientError) {
                // Retry with exponential backoff for transient errors
                const delay = Math.min(50 * Math.pow(2, attempt - 1), 500); // 50ms, 100ms, 200ms (max 500ms)
                log.warn(`[DOM Agent] Transient injection error (attempt ${attempt}/${maxRetries}), retrying in ${delay}ms: ${error.message}`);
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                // Log error and fail
                if (isLastAttempt) {
                    log.error(`[DOM Agent] All ${maxRetries} injection attempts failed for tab ${tabId}, frame ${frameId}:`, error.message);
                } else {
                    log.error(`[DOM Agent] Non-transient injection error:`, error.message);
                }
                return false;
            }
        }
    }
    return false;
}

function agentFunctionToInject() { const AGENT_VERSION = 'v11_postMsg_inline'; const agentFlag = `__frogPostAgentInjected_${AGENT_VERSION}`; if (window[agentFlag]) return { success: true, alreadyInjected: true, message: `Agent ${AGENT_VERSION} already present.` }; window[agentFlag] = true; let errors = []; const MAX_LISTENER_CODE_LENGTH = 15000; const originalWindowAddEventListener = window.addEventListener; const capturedListenerSources = new Set(); const safeToString = (func) => { try { return func.toString(); } catch (e) { return `[Error converting function: ${e?.message}]`; } }; const sendListenerToForwarder = (listenerCode, contextInfo, destinationUrl) => { try { const codeStr = typeof listenerCode === 'string' ? listenerCode : safeToString(listenerCode); if (!codeStr || codeStr.includes('[native code]') || codeStr.length < 25) { return; } const fingerprint = codeStr.replace(/\s+/g, '').substring(0, 250); if (capturedListenerSources.has(fingerprint)) { return; } capturedListenerSources.add(fingerprint); let stack = ''; try { throw new Error('CaptureStack'); } catch (e) { stack = e.stack || ''; } const payload = { listenerCode: codeStr.substring(0, MAX_LISTENER_CODE_LENGTH), stackTrace: stack, destinationUrl: destinationUrl || window.location.href, context: contextInfo }; window.postMessage({ type: 'frogPostAgent->ForwardToBackground', payload: payload }, window.location.origin || '*'); } catch (e) { errors.push(`sendListener Error (${contextInfo}): ${e.message}`); } }; try { window.addEventListener = function (type, listener, options) { if (type === 'message' && typeof listener === 'function') { sendListenerToForwarder(listener, 'window.addEventListener', window.location.href); } return originalWindowAddEventListener.apply(this, arguments); }; } catch (e) { errors.push(`addEventListener hook failed: ${e.message}`); window.addEventListener = originalWindowAddEventListener; } try { if (window.EventTarget && window.EventTarget.prototype) { const originalProtoAddEventListener = window.EventTarget.prototype.addEventListener; window.EventTarget.prototype.addEventListener = function(type, listener, options) { try { const isWindowLike = this === window || this === self || (typeof Window !== 'undefined' && this instanceof Window); const isMessagePort = typeof MessagePort !== 'undefined' && this instanceof MessagePort; if ((isWindowLike || isMessagePort) && type === 'message' && typeof listener === 'function') { sendListenerToForwarder(listener, isMessagePort ? 'EventTarget(MessagePort).addEventListener' : 'EventTarget(Window).addEventListener', window.location.href); } } catch(e) { errors.push(`EventTarget.prototype.addEventListener hook inner failed: ${e.message}`); } return originalProtoAddEventListener.apply(this, arguments); }; } } catch(e) { errors.push(`EventTarget.prototype.addEventListener hook failed: ${e.message}`); }
 let _currentWindowOnmessage = window.onmessage; try { Object.defineProperty(window, 'onmessage', { set: function (listener) { _currentWindowOnmessage = listener; if (typeof listener === 'function') { sendListenerToForwarder(listener, 'window.onmessage_set', window.location.href); } }, get: function () { return _currentWindowOnmessage; }, configurable: true, enumerable: true }); if (typeof _currentWindowOnmessage === 'function') { sendListenerToForwarder(_currentWindowOnmessage, 'window.onmessage_initial', window.location.href); } } catch (e) { errors.push(`onmessage hook failed: ${e.message}`); } try { const originalPortAddEventListener = MessagePort.prototype.addEventListener; MessagePort.prototype.addEventListener = function (type, listener, options) { try { if (type === 'message' && typeof listener === 'function') { sendListenerToForwarder(listener, 'port.addEventListener', window.location.href); } } catch(e) { errors.push(`port.addEventListener inner: ${e.message}`); } return originalPortAddEventListener.apply(this, arguments); }; const portOnMessageDescriptor = Object.getOwnPropertyDescriptor(MessagePort.prototype, 'onmessage'); const originalPortSetter = portOnMessageDescriptor?.set; const originalPortGetter = portOnMessageDescriptor?.get; const portOnmessageTracker = new WeakMap(); Object.defineProperty(MessagePort.prototype, 'onmessage', { set: function(listener) { try { portOnmessageTracker.set(this, listener); if (typeof listener === 'function') { sendListenerToForwarder(listener, 'port.onmessage_set', window.location.href); } if (originalPortSetter) originalPortSetter.call(this, listener); } catch(e) { errors.push(`port.onmessage set inner: ${e.message}`); } }, get: function() { try { let value = portOnmessageTracker.get(this); if (value === undefined && originalPortGetter) value = originalPortGetter.call(this); return value; } catch(e) { errors.push(`port.onmessage get inner: ${e.message}`); return undefined; } }, configurable: true, enumerable: true }); } catch (e) { errors.push(`MessagePort hook failed: ${e.message}`); } return { success: errors.length === 0, alreadyInjected: false, errors: errors, logsAdded: true }; }
async function loadHandlerEndpoints() { try { const result = await chrome.storage.session.get([HANDLER_ENDPOINT_KEYS_STORAGE_KEY]); if (result[HANDLER_ENDPOINT_KEYS_STORAGE_KEY]) { endpointsWithDetectedHandlers = new Set(result[HANDLER_ENDPOINT_KEYS_STORAGE_KEY]); } else { endpointsWithDetectedHandlers = new Set(); } } catch (e) { endpointsWithDetectedHandlers = new Set(); } }
async function saveHandlerEndpoints() { 
    try { 
        const data = { [HANDLER_ENDPOINT_KEYS_STORAGE_KEY]: Array.from(endpointsWithDetectedHandlers) }; 
        // Use batched storage - will flush within 100ms or when queue is full
        // This reduces I/O overhead while still maintaining reasonable freshness
        storageBatcher.set(data);
    } catch (e) {} 
}
function disconnectNativeHost() { if (nativePort) { nativePort.disconnect(); nativePort = null; } }
async function detachDebugger(debuggee) { const sessionKey = `${debuggee.tabId}:${debuggee.frameId || 0}`; if (activeDebugSessions.has(sessionKey)) { try { await new Promise((resolve, reject) => { chrome.debugger.detach(debuggee, () => { if (chrome.runtime.lastError) reject(chrome.runtime.lastError); else resolve(); }); }); log.debug(`Debugger detached from ${sessionKey}`); } catch (error) { log.warn(`Error detaching debugger from ${sessionKey}:`, error.message); } finally { activeDebugSessions.delete(sessionKey); } } }
async function analyzeHandlerDynamically(details, sendResponse) { const { targetTabId, targetFrameId = 0, handlerSnippet, pointsOfInterest = [] } = details; if (!targetTabId) { sendResponse({ success: false, error: "Missing targetTabId" }); return; } const debuggee = { tabId: targetTabId }; if (targetFrameId !== 0) { debuggee.frameId = targetFrameId; } const sessionKey = `${debuggee.tabId}:${debuggee.frameId || 0}`; if (activeDebugSessions.has(sessionKey)) { sendResponse({ success: false, error: "Debugger session already active for this target" }); return; } let results = { variableStates: {}, errors: [] }; let breakpointId = null; try { await new Promise((resolve, reject) => { chrome.debugger.attach(debuggee, "1.3", () => { if (chrome.runtime.lastError) reject(new Error(`Attach failed: ${chrome.runtime.lastError.message}`)); else resolve(); }); }); activeDebugSessions.set(sessionKey, { target: debuggee, status: 'attached' }); log.debug(`Debugger attached to ${sessionKey}`); await new Promise((resolve, reject) => { chrome.debugger.sendCommand(debuggee, "Debugger.enable", {}, () => { if (chrome.runtime.lastError) reject(new Error(`Debugger.enable failed: ${chrome.runtime.lastError.message}`)); else resolve(); }); }); const scriptSource = await new Promise((resolve, reject) => { chrome.debugger.sendCommand(debuggee, "Debugger.getScriptSource", { scriptId: "SOME_SCRIPT_ID_PLACEHOLDER" }, (result) => { if (chrome.runtime.lastError) reject(new Error(`getScriptSource failed: ${chrome.runtime.lastError.message}`)); else resolve(result?.scriptSource); }); }); const location = { scriptId: "SOME_SCRIPT_ID_PLACEHOLDER", lineNumber: 0, columnNumber: 0 }; breakpointId = await new Promise((resolve, reject) => { chrome.debugger.sendCommand(debuggee, "Debugger.setBreakpoint", { location: location }, (result) => { if (chrome.runtime.lastError) reject(new Error(`setBreakpoint failed: ${chrome.runtime.lastError.message}`)); else resolve(result?.breakpointId); }); }); if (!breakpointId) throw new Error("Failed to set breakpoint."); log.debug(`Breakpoint set for ${sessionKey} at simplified location`); const eventListener = (source, method, params) => { if (source.tabId === debuggee.tabId && (!debuggee.frameId || source.frameId === debuggee.frameId)) { if (method === "Debugger.paused" && params.hitBreakpoints?.includes(breakpointId)) { log.debug(`Breakpoint hit for ${sessionKey}`); const callFrameId = params.callFrames[0].callFrameId; Promise.all(pointsOfInterest.map(varName => new Promise((resolve) => { chrome.debugger.sendCommand(debuggee, "Debugger.evaluateOnCallFrame", { callFrameId: callFrameId, expression: varName, objectGroup: "tempInspect", returnByValue: false, generatePreview: true }, (evalResult) => { if (chrome.runtime.lastError) { results.errors.push(`Eval error for ${varName}: ${chrome.runtime.lastError.message}`); resolve(); } else { results.variableStates[varName] = evalResult?.result; resolve(); } }); }))).then(async () => { chrome.debugger.sendCommand(debuggee, "Debugger.resume", {}, () => { if (chrome.runtime.lastError) log.warn(`Resume failed: ${chrome.runtime.lastError.message}`); }); await new Promise(resolve => setTimeout(resolve, 500)); chrome.debugger.onEvent.removeListener(eventListener); await detachDebugger(debuggee); sendResponse({ success: true, results: results }); }).catch(async (evalErr) => { results.errors.push(`Evaluation error: ${evalErr.message}`); chrome.debugger.onEvent.removeListener(eventListener); await detachDebugger(debuggee); sendResponse({ success: false, results: results }); }); } else if (method === "Debugger.resumed") {} } }; chrome.debugger.onEvent.addListener(eventListener); log.debug(`Debugger setup complete for ${sessionKey}. Waiting for breakpoint...`); } catch (error) { log.error(`Dynamic analysis error for ${sessionKey}:`, error); results.errors.push(error.message); if (breakpointId) { try { await new Promise(r => chrome.debugger.sendCommand(debuggee, "Debugger.removeBreakpoint", { breakpointId }, r)); } catch {} } await detachDebugger(debuggee); sendResponse({ success: false, results: results }); } }
chrome.debugger.onDetach.addListener((source, reason) => { const sessionKey = `${source.tabId}:${source.frameId || 0}`; log.warn(`Debugger detached from ${sessionKey}. Reason: ${reason}`); activeDebugSessions.delete(sessionKey); });

async function handleExtensionPageLoad(tabId, targetUrl) {
    const extensionOrigin = new URL(targetUrl).origin;
    log.debug(`[AutoAttach] Checking extension page: ${targetUrl}`);
    if (processedUrlsInSession.has(targetUrl)) { log.debug(`[AutoAttach] URL ${targetUrl} already processed in this session.`); return; }
    if (autoAttachInProgress.has(tabId)) { log.debug(`[AutoAttach] Debugger attach already in progress for tab ${tabId}, skipping.`); return; }
    
    // Check if real-time detection is active - if so, delay debugger attachment
    try {
        const results = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => window.__frogPostRealTimeDetector_v1 ? true : false
        });
        if (results?.[0]?.result) {
            log.info(`[AutoAttach] Real-time detection active for ${targetUrl}, delaying debugger attachment`);
            // Delay debugger attachment by 2 seconds to let real-time detection work first
            setTimeout(() => {
                if (!autoAttachInProgress.has(tabId)) {
                    handleExtensionPageLoad(tabId, targetUrl);
                }
            }, 2000);
            return;
        }
    } catch (error) {
        log.debug("Could not check real-time detection status:", error.message);
    }
    
    // PERFORMANCE: Queue if at debugger limit
    if (!canAttachDebugger()) {
        log.info(`[AutoAttach] Debugger limit reached, queuing ${targetUrl}`);
        debuggerQueue.push(() => handleExtensionPageLoad(tabId, targetUrl));
        return;
    }
    
    autoAttachInProgress.add(tabId);
    processedUrlsInSession.add(targetUrl);
    incrementDebuggerCount();
    let attached = false; let extractor = null; let analysisTimeout = null;
    try {
        log.debug(`[AutoAttach] Attaching debugger to: ${targetUrl} (Tab ID: ${tabId})`);
        await chrome.debugger.attach({ tabId: tabId }, "1.3"); attached = true; log.debug(`[AutoAttach] Attached successfully.`);
        if (typeof HandlerExtractor === 'undefined') { log.warn("[AutoAttach] HandlerExtractor class not available. Cannot analyze scripts."); await chrome.debugger.detach({ tabId: tabId }); attached = false; return; }
        extractor = new HandlerExtractor(); extractor.initialize(targetUrl, []);
        let analysisCompleteResolve; const analysisCompletionPromise = new Promise(resolve => { analysisCompleteResolve = resolve; }); analysisTimeout = setTimeout(() => { log.warn(`[AutoAttach] Analysis timeout reached for ${targetUrl}. Detaching.`); analysisCompleteResolve(); }, 6000); // OPTIMIZED: Reduced from 12s to 6s
        const onEvent = async (source, method, params) => {
            if (source.tabId !== tabId) return;
            if (method === 'Debugger.scriptParsed') {
                const { scriptId, url } = params; const sourceUrl = url || `tab_${tabId}_script_${scriptId}`;
                if (url && url.startsWith(extensionOrigin) && url.endsWith('.js') && url.length < 1500000) {
                    log.debug(`[AutoAttach] Relevant script parsed: ${url}`);
                    try {
                        const { scriptSource } = await chrome.debugger.sendCommand({ tabId: tabId }, "Debugger.getScriptSource", { scriptId: scriptId });
                        if (scriptSource) {
                            log.debug(`[AutoAttach] Analyzing source for ${url} (Length: ${scriptSource.length})`); const foundHandlers = extractor.analyzeScriptContent(scriptSource, url); log.debug(`[AutoAttach] Found ${foundHandlers.length} potential handlers in ${url}`);
                            if (foundHandlers.length > 0) {
                                const bestHandlerInfo = extractor.getBestHandler(foundHandlers);
                                if (bestHandlerInfo && bestHandlerInfo.handler) {
                                    const endpointKey = normalizeEndpointUrl(targetUrl)?.normalized || targetUrl; log.debug(`[AutoAttach] Best handler found for ${endpointKey} from script ${url}:`, bestHandlerInfo.category);
                                    if (!endpointsWithDetectedHandlers.has(endpointKey)) { endpointsWithDetectedHandlers.add(endpointKey); await saveHandlerEndpoints(); }
                                    notifyDashboard("handlerCapturedForEndpoint", { endpointKey: endpointKey, handlerInfo: { category: bestHandlerInfo.category, source: bestHandlerInfo.source, functionName: bestHandlerInfo.functionName, score: bestHandlerInfo.score } });
                                    const bestHandlerStorageKey = `best-handler-${endpointKey}`; 
                                    storageBatcher.set({ [bestHandlerStorageKey]: bestHandlerInfo }); 
                                    log.debug(`[AutoAttach] Saved best handler for ${endpointKey} to storage.`);
                                }
                            }
                        }
                    } catch (e) { log.warn(`[AutoAttach] Failed to fetch/analyze source for ${scriptId} (${url}):`, e.message); }
                } else { log.debug(`[AutoAttach] Skipping script (not target origin or not .js or too long): ${sourceUrl}`); }
            } else if (method === 'Page.loadEventFired') { log.debug("[AutoAttach] Page load event fired. Resetting timeout."); clearTimeout(analysisTimeout); analysisTimeout = setTimeout(() => { log.warn(`[AutoAttach] Analysis timeout reached after load for ${targetUrl}. Detaching.`); analysisCompleteResolve(); }, 8000); }
        };
        const onDetach = (source, reason) => { if (source.tabId === tabId) { log.warn(`[AutoAttach] Detached from tab ${tabId}. Reason: ${reason}`); attached = false; try{chrome.debugger.onEvent.removeListener(onEvent);}catch(e){} try{chrome.debugger.onDetach.removeListener(onDetach);}catch(e){} clearTimeout(analysisTimeout); analysisCompleteResolve(); } };
        chrome.debugger.onEvent.addListener(onEvent); chrome.debugger.onDetach.addListener(onDetach);
        await Promise.all([ chrome.debugger.sendCommand({ tabId: tabId }, "Page.enable"), chrome.debugger.sendCommand({ tabId: tabId }, "Runtime.enable"), chrome.debugger.sendCommand({ tabId: tabId }, "Debugger.enable") ]); log.debug(`[AutoAttach] Domains enabled.`);
        log.debug("[AutoAttach] Waiting for analysis timeout or detach..."); await analysisCompletionPromise;
    } catch (err) { log.error(`[AutoAttach] Error processing extension tab ${tabId}:`, err.message);
    } finally { clearTimeout(analysisTimeout); try { chrome.debugger.onEvent.removeListener(onEvent); } catch(e) {} try { chrome.debugger.onDetach.removeListener(onDetach); } catch(e) {} if (attached) { try { await chrome.debugger.detach({ tabId: tabId }); log.debug(`[AutoAttach] Detached in finally block for tab ${tabId}`); } catch (e) { log.warn(`[AutoAttach] Error detaching in finally for tab ${tabId}: ${e.message}`) } } autoAttachInProgress.delete(tabId); decrementDebuggerCount(); } // PERFORMANCE: Decrement counter to allow queued tasks
}

async function handleWebPageLoadForDebug(tabId, targetUrl) {
    // Skip handler extraction tabs (check both URL parameter and storage flag)
    if (targetUrl.includes('frogpost_handler_extraction=true')) {
        log.debug(`[Debug Mode] Skipping handler extraction tab: ${targetUrl} (Tab ID: ${tabId})`);
        return;
    }
    
    const isHandlerExtractionTab = await chrome.storage.local.get(`handler-extraction-tab-${tabId}`);
    if (isHandlerExtractionTab[`handler-extraction-tab-${tabId}`]) {
        log.debug(`[Debug Mode] Skipping handler extraction tab: ${targetUrl} (Tab ID: ${tabId})`);
        return;
    }
    
    log.debug(`[Debug Mode] Checking web page: ${targetUrl} (Tab ID: ${tabId})`);
    if (autoAttachInProgress.has(tabId)) { log.debug(`[Debug Mode] Debugger attach already in progress for tab ${tabId}, skipping web page check.`); return; }
    
    // PERFORMANCE: Queue if at debugger limit
    if (!canAttachDebugger()) {
        log.info(`[Debug Mode] Debugger limit reached, queuing ${targetUrl}`);
        debuggerQueue.push(() => handleWebPageLoadForDebug(tabId, targetUrl));
        return;
    }
    
    autoAttachInProgress.add(tabId);
    incrementDebuggerCount();
    let attached = false; let extractor = null; let analysisTimeout = null;
    try {
        log.debug(`[Debug Mode] Attaching debugger to: ${targetUrl} (Tab ID: ${tabId})`);
        await chrome.debugger.attach({ tabId: tabId }, "1.3"); attached = true; log.debug(`[Debug Mode] Attached successfully.`);
        if (typeof HandlerExtractor === 'undefined') { log.warn("[Debug Mode] HandlerExtractor class not available. Cannot analyze scripts."); await chrome.debugger.detach({ tabId: tabId }); attached = false; return; }
        extractor = new HandlerExtractor(); extractor.initialize(targetUrl, []);
        let analysisCompleteResolve; const analysisCompletionPromise = new Promise(resolve => { analysisCompleteResolve = resolve; }); analysisTimeout = setTimeout(() => { log.warn(`[Debug Mode] Analysis timeout for ${targetUrl}. Detaching.`); analysisCompleteResolve(); }, 8000); // OPTIMIZED: Reduced from 15s to 8s
        
        let lastScriptParsedAt = Date.now();
        let idleTimer = null;
        const refreshIdleTimer = () => {
            lastScriptParsedAt = Date.now();
            if (idleTimer) clearTimeout(idleTimer);
            // Detach if idle for 8s with no new scripts
            idleTimer = setTimeout(() => { 
                if (analysisCompleteResolve) analysisCompleteResolve(); 
            }, 8000);
        };
        
        const tryDetach = async (tabId) => {
            try {
                if (attached) {
                    await chrome.debugger.detach({ tabId });
                    attached = false;
                    log.debug(`[Debug Mode] Auto-detached from tab ${tabId} due to idle timeout.`);
                }
            } catch (e) {
                log.warn(`[Debug Mode] Error during auto-detach from tab ${tabId}:`, e.message);
            }
        };
        
        const onEvent = async (source, method, params) => {
            if (source.tabId !== tabId) return;
            if (method === "Debugger.scriptParsed") refreshIdleTimer();
            if (method === "Debugger.paused" && params?.reason === "EventListener") {
                try {
                    const frame = params.callFrames?.[0];
                    const scriptId = frame?.location?.scriptId;
                    if (scriptId) {
                        const { scriptSource } = await chrome.debugger.sendCommand({ tabId }, "Debugger.getScriptSource", { scriptId });
                        const found = extractor.analyzeScriptContent(scriptSource, `paused_${scriptId}`);
                        if (found?.length) {
                            const best = extractor.getBestHandler(found);
                            if (best?.handler) {
                                const endpointKey = normalizeEndpointUrl(targetUrl)?.normalized || targetUrl;
                                storageBatcher.set({ [`best-handler-${endpointKey}`]: best });
                                notifyDashboard("handlerCaptured", { endpoint: targetUrl, bestHandler: { fn: best.functionName, score: best.score } });
                            }
                        }
                    }
                } catch (e) { log.warn("[Debug Mode] paused handler capture error:", e?.message); }
                try { await chrome.debugger.sendCommand({ tabId }, "Debugger.resume"); } catch {}
                return;
            }
            if (method === 'Debugger.scriptParsed') {
                const { scriptId, url } = params; const sourceUrl = url || `tab_${tabId}_script_${scriptId}`;
                const urlStr = url || '';
                const baseUrl = urlStr.split(/[?#]/)[0];
                const isLikelyJs = urlStr.startsWith('blob:') || urlStr.startsWith('data:') || urlStr.startsWith('webpack-internal:') || baseUrl.endsWith('.js') || baseUrl.endsWith('.mjs') || baseUrl.endsWith('.cjs');
                if (urlStr && !urlStr.startsWith('chrome-extension://') && isLikelyJs && urlStr.length < 1500000) {
                    log.debug(`[Debug Mode] Relevant script parsed: ${url}`);
                    try {
                        const { scriptSource } = await chrome.debugger.sendCommand({ tabId: tabId }, "Debugger.getScriptSource", { scriptId: scriptId });
                        if (scriptSource) {
                            log.debug(`[Debug Mode] Analyzing source for ${url} (Length: ${scriptSource.length})`); const foundHandlers = extractor.analyzeScriptContent(scriptSource, url); log.debug(`[Debug Mode] Found ${foundHandlers.length} potential handlers in ${url}`);
                            if (foundHandlers.length > 0) {
                                const bestHandlerInfo = extractor.getBestHandler(foundHandlers);
                                if (bestHandlerInfo && bestHandlerInfo.handler) {
                                    const endpointKey = normalizeEndpointUrl(targetUrl)?.normalized || targetUrl; log.debug(`[Debug Mode] Best handler found for ${endpointKey} from script ${url}:`, bestHandlerInfo.category);
                                    if (!endpointsWithDetectedHandlers.has(endpointKey)) { endpointsWithDetectedHandlers.add(endpointKey); await saveHandlerEndpoints(); }
                                    notifyDashboard("handlerCapturedForEndpoint", { endpointKey: endpointKey, handlerInfo: { category: bestHandlerInfo.category, source: bestHandlerInfo.source, functionName: bestHandlerInfo.functionName, score: bestHandlerInfo.score } });
                                    const bestHandlerStorageKey = `best-handler-${endpointKey}`; 
                                    storageBatcher.set({ [bestHandlerStorageKey]: bestHandlerInfo }); 
                                    log.debug(`[Debug Mode] Saved best handler for ${endpointKey} to storage.`);
                                }
                            }
                        }
                    } catch (e) { log.warn(`[Debug Mode] Failed to fetch/analyze source for ${scriptId} (${url}):`, e.message); }
                } else { log.debug(`[Debug Mode] Skipping script: ${sourceUrl}`); }
            } else if (method === 'Page.loadEventFired') { log.debug("[Debug Mode] Page load event fired. Resetting timeout."); clearTimeout(analysisTimeout); analysisTimeout = setTimeout(() => { log.warn(`[Debug Mode] Analysis timeout after load for ${targetUrl}. Detaching.`); analysisCompleteResolve(); }, 5000); }
        };
        const onDetach = (source, reason) => { if (source.tabId === tabId) { log.warn(`[Debug Mode] Detached from tab ${tabId}. Reason: ${reason}`); attached = false; try{chrome.debugger.onEvent.removeListener(onEvent);}catch(e){} try{chrome.debugger.onDetach.removeListener(onDetach);}catch(e){} clearTimeout(analysisTimeout); analysisCompleteResolve(); } };
        chrome.debugger.onEvent.addListener(onEvent); chrome.debugger.onDetach.addListener(onDetach);
        await Promise.all([ chrome.debugger.sendCommand({ tabId: tabId }, "Page.enable"), chrome.debugger.sendCommand({ tabId: tabId }, "Runtime.enable"), chrome.debugger.sendCommand({ tabId: tabId }, "Debugger.enable") ]); log.debug(`[Debug Mode] Domains enabled.`);
        // Workers discovery & auto-attach
        await chrome.debugger.sendCommand({ tabId }, "Target.setDiscoverTargets", { discover: true });
        await chrome.debugger.sendCommand({ tabId }, "Target.setAutoAttach", {
            autoAttach: true, waitForDebuggerOnStart: false, flatten: true
        });
        // Break on message listener registration (ignore duplicate)
        try {
            await chrome.debugger.sendCommand({ tabId }, "DOMDebugger.setEventListenerBreakpoint", { eventName: "message" });
        } catch (e) {
            if (e && (e.code === -32000 || /already exists/i.test(e.message||''))) {
                log.info("[Debug Mode] EventListenerBreakpoint('message') already set; continuing.");
            } else {
                log.warn("[Debug Mode] DOMDebugger.setEventListenerBreakpoint failed:", e?.message);
            }
        }
        log.debug("[Debug Mode] Waiting for analysis timeout or detach..."); await analysisCompletionPromise;
    } catch (err) { log.error(`[Debug Mode] Error processing web page tab ${tabId}:`, err.message);
    } finally { clearTimeout(analysisTimeout); try { chrome.debugger.onEvent.removeListener(onEvent); } catch(e) {} try { chrome.debugger.onDetach.removeListener(onDetach); } catch(e) {} if (attached) { try { await chrome.debugger.detach({ tabId: tabId }); log.debug(`[Debug Mode] Detached in finally block for tab ${tabId}`); } catch (e) { log.warn(`[Debug Mode] Error detaching in finally for tab ${tabId}: ${e.message}`) } } autoAttachInProgress.delete(tabId); decrementDebuggerCount(); } // PERFORMANCE: Decrement counter to allow queued tasks
}

async function fetchLatestReleaseInfo(repoOwner, repoName) {
    const releasesUrl = `https://github.com/${repoOwner}/${repoName}/releases/`;
    if(typeof log !== 'undefined') 

    try {
        const response = await fetch(releasesUrl, {
            method: 'GET',
            cache: 'no-cache'
        });

        if (!response.ok) {
            throw new Error(`GitHub releases page request failed: ${response.status} ${response.statusText}`);
        }

        const htmlText = await response.text();

        const regex = /href=["']\/thisis0xczar\/FrogPost\/releases\/tag\/([^"']+)["']/i;
        const match = htmlText.match(regex);

        let tagNameFromHtml = null;
        let releaseUrl = releasesUrl;

        if (match && match[1]) {
            tagNameFromHtml = match[1];
            try {
                releaseUrl = new URL(match[0].match(/href=["'](.*?)["']/i)[1], releasesUrl).href;
            } catch {} // Ignore URL construction errors
            if(typeof log !== 'undefined') log.debug("BG: Found latest release tag:", tagNameFromHtml);
        } else {
            if(typeof log !== 'undefined') log.error("BG: Could not find the latest release tag link using regex on the releases page.");
            throw new Error("Could not parse latest release tag from GitHub page HTML using regex.");
        }

        return {
            success: true,
            tagName: tagNameFromHtml,
            url: releaseUrl
        };

    } catch (error) {
        if(typeof log !== 'undefined') log.error("BG: Error fetching/parsing GitHub releases page:", error);
        throw error;
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "checkVersion") { // Use a more specific message type
        const repoOwner = "thisis0xczar";
        const repoName = "FrogPost";
        if(typeof log !== 'undefined') 

        fetchLatestReleaseInfo(repoOwner, repoName)
            .then(releaseInfo => {
                if(typeof log !== 'undefined') log.debug("BG: Sending release info response:", releaseInfo);
                sendResponse(releaseInfo);
            })
            .catch(error => {
                if(typeof log !== 'undefined') log.error("BG: Version check failed in listener:", error);
                sendResponse({ success: false, error: error.message || 'Unknown version check error' });
            });
        return true;

    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab?.url) {
        handleTabUpdated(tabId, changeInfo, tab);
    }
});

async function handleTabUpdated(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab?.url) {
        try {
            const result = await chrome.storage.local.get([DEBUGGER_MODE_STORAGE_KEY]);
            const debuggerModeEnabled = result[DEBUGGER_MODE_STORAGE_KEY] || false;
            isDebuggerApiModeGloballyEnabled = debuggerModeEnabled;
            if (!debuggerModeEnabled) {
                return;
            }
            if (tab.url.startsWith('chrome-extension://') && tab.url !== chrome.runtime.getURL("dashboard/dashboard.html")) { 
                handleExtensionPageLoad(tabId, tab.url); 
            } else if (tab.url.startsWith('http:') || tab.url.startsWith('https://')) { 
                handleWebPageLoadForDebug(tabId, tab.url); 
            }
        } catch (error) { 
            log.error(`[onUpdated] Error checking debugger mode or processing tab ${tabId}:`, error); 
        }
    } else if (changeInfo.status === 'loading' && tabId) {
        injectedFramesAgents.delete(tabId);
        detachDebugger({ tabId: tabId }).catch(()=>{});
    }
}

chrome.tabs.onRemoved.addListener(tabId => { injectedFramesAgents.delete(tabId); detachDebugger({ tabId: tabId }).catch(()=>{}); });
// Also inject when tab becomes active (user switches tabs)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (!tab?.url) return;
        if (!tab.url.startsWith('http') && !tab.url.startsWith('https')) return;
        
        // Skip handler extraction tabs (check both URL parameter and storage flag)
        if (tab.url.includes('frogpost_handler_extraction=true')) {
            log.debug(`[Tab Activation] Skipping handler extraction tab: ${tab.url}`);
            return;
        }
        
        const isHandlerExtractionTab = await chrome.storage.local.get(`handler-extraction-tab-${activeInfo.tabId}`);
        if (isHandlerExtractionTab[`handler-extraction-tab-${activeInfo.tabId}`]) {
            log.debug(`[Tab Activation] Skipping handler extraction tab: ${tab.url}`);
            return;
        }
        
        await injectDOMAgent(activeInfo.tabId, 0);
    } catch {}
});
chrome.webNavigation.onCommitted.addListener((details) => {
    if (!details.url || details.transitionType === 'server_redirect') { return; }
    handleWebNavigationCommitted(details);
});

async function handleWebNavigationCommitted(details) {
    // Only inject into http/https pages
    const urlStr = details?.url || '';
    if (!/^https?:\/\//i.test(urlStr)) {
        return;
    }
    
    // Skip handler extraction tabs (check both URL parameter and storage flag)
    if (urlStr.includes('frogpost_handler_extraction=true')) {
        log.debug(`[Navigation] Skipping handler extraction tab: ${urlStr}`);
        return;
    }
    
    const isHandlerExtractionTab = await chrome.storage.local.get(`handler-extraction-tab-${details.tabId}`);
    if (isHandlerExtractionTab[`handler-extraction-tab-${details.tabId}`]) {
        log.debug(`[Navigation] Skipping handler extraction tab: ${urlStr}`);
        return;
    }
    const tabFrames = injectedFramesAgents.get(details.tabId);
    if (tabFrames?.has(details.frameId)) { return; }
    
    // Try DOM agent injection first
    const domAgentSuccess = await injectDOMAgent(details.tabId, details.frameId);
    
    if (domAgentSuccess) {
        if (!injectedFramesAgents.has(details.tabId)) { 
            injectedFramesAgents.set(details.tabId, new Set()); 
        } 
        injectedFramesAgents.get(details.tabId).add(details.frameId);
        return;
    }
    
    // Fallback to original agent injection
    try {
        const results = await chrome.scripting.executeScript({ target: { tabId: details.tabId, frameIds: [details.frameId] }, func: agentFunctionToInject, injectImmediately: true, world: 'MAIN' });
        let injectionStatus = { success: false, alreadyInjected: false, errors: ["No result from executeScript"] };
        if (results?.[0]?.result) { injectionStatus = results[0].result; } else if (results?.[0]?.error) { injectionStatus.errors = [`executeScript framework error: ${results[0].error.message || results[0].error}`]; }
        if (injectionStatus.success || injectionStatus.alreadyInjected) { if (!injectedFramesAgents.has(details.tabId)) { injectedFramesAgents.set(details.tabId, new Set()); } injectedFramesAgents.get(details.tabId).add(details.frameId); }
    } catch (error) {
        if (!error.message?.includes("Cannot access") && !error.message?.includes("No frame with id") && !error.message?.includes("target frame detached") && !error.message?.includes("The frame was removed") && !error.message?.includes("Could not establish connection") && !error.message?.includes("No tab with id")) {}
        const tf = injectedFramesAgents.get(details.tabId);
        if (tf) { tf.delete(details.frameId); }
    }
}

/**
 * Store handler from DOM agent telemetry
 * Enhanced to support both old and new telemetry formats
 */
async function storeRealTimeHandler(payload) {
    try {
        const location = payload.location;
        if (!location) return;

        // Normalize URL to match Play button expectations
        const normalized = normalizeEndpointUrl(location);
        const storageKey = `real-time-handlers-${normalized?.normalized || location}`;
        
        const existingResult = await chrome.storage.local.get(storageKey);
        const existingHandlers = existingResult[storageKey] || [];
        
        // Add new handler if not already present
        const handlerExists = existingHandlers.some(h => h.id === payload.id);
        if (!handlerExists) {
            existingHandlers.push(payload);
            // Keep only last 10 handlers per URL
            if (existingHandlers.length > 10) {
                existingHandlers.splice(0, existingHandlers.length - 10);
            }
            // Use batched storage (non-critical)
            storageBatcher.set({ [storageKey]: existingHandlers });
            
            // Mark endpoint as having detected handlers
            if (normalized?.normalized) {
                endpointsWithDetectedHandlers.add(normalized.normalized);
                await saveHandlerEndpoints(); // Immediate flush for tracking
            }
        }
    } catch (error) {
        log.error("Error in storeRealTimeHandler:", error);
    }
}

/**
 * Store periodic telemetry from enhanced DOM agent
 * This is the primary handler storage mechanism
 */
async function storeHandlerTelemetry(payload) {
    try {
        const { windowId, location, handlers, timestamp, isIframe, handlerCount } = payload;
        if (!location || !handlers) return;

        // Normalize URL
        const normalized = normalizeEndpointUrl(location);
        const endpointKey = normalized?.normalized || location;
        const storageKey = `dom-agent-telemetry-${endpointKey}`;
        
        // Store telemetry with frame metadata
        const telemetryData = {
            windowId: windowId,
            location: location,
            handlers: handlers, // Array of {code, length, name}
            timestamp: timestamp,
            isIframe: isIframe,
            handlerCount: handlerCount,
            endpointKey: endpointKey
        };
        
        // Use batched storage (non-critical, can wait 100ms)
        storageBatcher.set({ [storageKey]: telemetryData });
        
        // If handlers found, mark endpoint
        if (handlers && handlers.length > 0) {
            if (!endpointsWithDetectedHandlers.has(endpointKey)) {
                endpointsWithDetectedHandlers.add(endpointKey);
                await saveHandlerEndpoints(); // This one needs immediate flush
                notifyDashboard("handlerEndpointDetected", { endpointKey: endpointKey });
            }
        }
        
        log.debug(`[Telemetry] Queued ${handlers.length} handlers for ${endpointKey}`);
    } catch (error) {
        log.error("Error in storeHandlerTelemetry:", error);
    }
}

/**
 * Retrieve best pre-extracted handler - REAL-TIME FIRST, then old telemetry fallback
 * This is what the Play button calls first (primary method)
 */
async function getPreExtractedHandler(endpointKey) {
    try {
        if (debugMode) {
            console.log(`[FROGPOST-BG] getPreExtractedHandler called with key: ${endpointKey}`);
            console.log(`[FROGPOST-BG] Cache has ${handlerCache.size} entries`);
            if (handlerCache.size <= 10) {
                console.log(`[FROGPOST-BG] Cache keys:`, Array.from(handlerCache.keys()));
            }
        }
        
        // PRIORITY 1: Check in-memory real-time cache (NEW SYSTEM)
        // Try exact match first
        if (handlerCache.has(endpointKey)) {
            const cacheEntry = handlerCache.get(endpointKey);
            if (cacheEntry.handlers && cacheEntry.handlers.length > 0) {
                const handler = cacheEntry.handlers[cacheEntry.handlers.length - 1];
                if (debugMode) console.log(`[FROGPOST-BG] ✅ Found handler in real-time cache: ${handler.code.length} chars, ${cacheEntry.handlers.length} total handlers for URL`);
                return { 
                    handler: handler.code,
                    name: handler.name, 
                    source: 'realtime-cache',
                    category: 'realtime-capture',
                    score: 1000
                };
            }
        }
        
        // RELIABILITY FIX: Try all URL variants (fuzzy matching)
        const normalized = normalizeEndpointUrl(endpointKey);
        const searchKey = normalized?.normalized || endpointKey;
        const allVariants = generateUrlVariants(searchKey);
        
        if (debugMode) {
            console.log(`[FROGPOST-BG] Searching for handler with ${allVariants.length} URL variant(s)`);
        }
        
        // Try each variant in order (most specific first)
        for (const variant of allVariants) {
            if (handlerCache.has(variant)) {
                const cacheEntry = handlerCache.get(variant);
                if (cacheEntry.handlers && cacheEntry.handlers.length > 0) {
                    const handler = cacheEntry.handlers[cacheEntry.handlers.length - 1];
                    if (debugMode) {
                        console.log(`[FROGPOST-BG] ✅ Found handler via URL variant: ${variant}`);
                        console.log(`[FROGPOST-BG]    Search key: ${searchKey}`);
                        console.log(`[FROGPOST-BG]    Match type: ${variant === searchKey ? 'exact' : 'fuzzy'}`);
                    }
                    return { 
                        handler: handler.code,
                        name: handler.name, 
                        source: 'realtime-cache',
                        category: 'realtime-capture',
                        score: 1000,
                        matchedVariant: variant
                    };
                }
            }
        }
        
        // Try origin-only matching (last resort)
        try {
            const endpointUrl = new URL(endpointKey);
            const originOnly = endpointUrl.origin;
            
            // Check all cache entries for matching origin
            for (const [cachedUrl, cacheEntry] of handlerCache.entries()) {
                try {
                    const cachedUrlObj = new URL(cachedUrl);
                    if (cachedUrlObj.origin === originOnly && cacheEntry.handlers && cacheEntry.handlers.length > 0) {
                        const handler = cacheEntry.handlers[cacheEntry.handlers.length - 1];
                        if (debugMode) console.log(`[FROGPOST-BG] ✅ Found handler in cache via origin match: ${cachedUrl}`);
                        return { 
                            handler: handler.code,
                            name: handler.name, 
                            source: 'realtime-cache',
                            category: 'realtime-capture',
                            score: 1000
                        };
                    }
                } catch (e) {
                    // Skip invalid URLs
                }
            }
        } catch (e) {
            // endpointKey might not be a valid URL
        }
        
        if (debugMode) console.log(`[FROGPOST-BG] No handler in real-time cache, falling back to old telemetry...`);
        
        // FALLBACK: Check old telemetry system (DEPRECATED)
        const storageKey = `dom-agent-telemetry-${endpointKey}`;
        if (debugMode) console.log(`[FROGPOST-BG] Storage key: ${storageKey}`);
        log.debug(`[Telemetry Retrieval] Looking for key: ${storageKey}`);
        
        let result = await chrome.storage.local.get(storageKey);
        let telemetry = result[storageKey];
        if (debugMode) console.log(`[FROGPOST-BG] Exact match result:`, telemetry ? 'FOUND' : 'NOT_FOUND');
        
        if (telemetry) {
            if (debugMode) console.log(`[FROGPOST-BG] Telemetry object:`, {
                hasHandlers: !!telemetry.handlers,
                handlerCount: telemetry.handlers?.length || 0,
                timestamp: telemetry.timestamp,
                timestampAge: `${Math.floor((Date.now() - telemetry.timestamp) / 1000)}s ago`,
                location: telemetry.location,
                windowId: telemetry.windowId
            });
            if (telemetry.handlers && telemetry.handlers.length > 0) {
                if (debugMode) console.log(`[FROGPOST-BG] First handler:`, {
                    codeLength: telemetry.handlers[0].code?.length || 0,
                    name: telemetry.handlers[0].name,
                    hasCode: !!telemetry.handlers[0].code
                });
            } else {
                // Empty handlers - treat as invalid and try fallback
                if (debugMode) console.warn(`[FROGPOST-BG] Exact match found but has EMPTY handlers - will try fallback`);
                telemetry = null;  // Force fallback matching
            }
        }
        
        // DEBUG: If not found OR empty, check what keys DO exist and try fuzzy matching
        if (!telemetry || !telemetry.handlers || telemetry.handlers.length === 0) {
            if (debugMode) console.log(`[FROGPOST-BG] Telemetry empty or invalid. Checking reason:`, {
                exists: !!result[storageKey],
                exactMatchHandlerCount: result[storageKey]?.handlers?.length || 0,
                willTryFallback: true
            });
            const allStorage = await chrome.storage.local.get(null);
            const allTelemetryKeys = Object.keys(allStorage).filter(k => k.startsWith('dom-agent-telemetry-'));
            log.warn(`[Telemetry Retrieval] ❌ Exact match not found`);
            log.info(`[Telemetry Retrieval] Looking for: ${endpointKey}`);
            log.info(`[Telemetry Retrieval] Storage key: ${storageKey}`);
            log.info(`[Telemetry Retrieval] Total telemetry entries: ${allTelemetryKeys.length}`);
            
            // FALLBACK: Try aggressive fuzzy matching
            // Strategy 1: Match origin + pathname (ignore query params)
            // Strategy 2: Match origin only
            try {
                const endpointUrl = new URL(endpointKey);
                const endpointOrigin = endpointUrl.origin;
                const endpointPath = endpointUrl.pathname;
                const endpointOriginPath = endpointOrigin + endpointPath;
                
                log.info(`[Telemetry Retrieval] Attempting fallback matches:`);
                log.info(`  - Origin: ${endpointOrigin}`);
                log.info(`  - Origin+Path: ${endpointOriginPath}`);
                
                // Strategy 1: Match origin + pathname (best match)
                log.info(`[Telemetry Retrieval] Strategy 1: Matching origin+path = ${endpointOriginPath}`);
                let originPathMatches = allTelemetryKeys.filter(k => {
                    const telemetryUrl = k.replace('dom-agent-telemetry-', '');
                    try {
                        const telUrl = new URL(telemetryUrl);
                        const telOriginPath = telUrl.origin + telUrl.pathname;
                        const matches = telOriginPath === endpointOriginPath;
                        if (matches) {
                            log.info(`  ✅ Match found: ${telemetryUrl}`);
                        }
                        return matches;
                    } catch {
                        return false;
                    }
                });
                
                // Strategy 2: Match origin only (broader fallback)
                if (originPathMatches.length === 0) {
                    log.info(`[Telemetry Retrieval] Strategy 2: Matching origin = ${endpointOrigin}`);
                    var originMatches = allTelemetryKeys.filter(k => {
                        const telemetryUrl = k.replace('dom-agent-telemetry-', '');
                        try {
                            const telUrl = new URL(telemetryUrl);
                            const matches = telUrl.origin === endpointOrigin;
                            if (matches) {
                                log.info(`  ✅ Match found: ${telemetryUrl}`);
                            }
                            return matches;
                        } catch {
                            return false;
                        }
                    });
                } else {
                    var originMatches = [];
                }
                
                // Try Strategy 1 first (origin+path), then Strategy 2 (origin)
                let matchingKeys = originPathMatches.length > 0 ? originPathMatches : originMatches;
                
                log.info(`[Telemetry Retrieval] Found ${matchingKeys.length} potential matches`);
                
                if (matchingKeys.length > 0) {
                    log.success(`[Telemetry Retrieval] Found ${matchingKeys.length} fallback matches`);
                    if (originPathMatches.length > 0) {
                        log.info(`  ✅ Using Strategy 1: origin+path match`);
                    } else {
                        log.info(`  ⚠️  Using Strategy 2: origin-only match`);
                    }
                    
                    // Use the most recent one (by timestamp)
                    let bestMatch = null;
                    let bestTimestamp = 0;
                    let bestKey = null;
                    
                    for (const key of matchingKeys) {
                        const tel = allStorage[key];
                        if (tel?.handlers && tel.handlers.length > 0) {
                            const ts = tel.timestamp || 0;
                            if (ts > bestTimestamp) {
                                bestTimestamp = ts;
                                bestMatch = tel;
                                bestKey = key.replace('dom-agent-telemetry-', '');
                            }
                        }
                    }
                    
                    if (bestMatch) {
                        log.success(`[Telemetry Retrieval] ✅ Using fallback telemetry:`);
                        log.info(`  - Original key: ${bestKey}`);
                        log.info(`  - Timestamp: ${new Date(bestTimestamp).toISOString()}`);
                        log.info(`  - Handlers: ${bestMatch.handlers.length}`);
                        telemetry = bestMatch;
                    }
                } else {
                    log.warn(`[Telemetry Retrieval] No fallback matches found for origin ${endpointOrigin}`);
                }
            } catch (e) {
                log.debug(`[Telemetry Retrieval] Fallback matching failed:`, e);
            }
            
            // Still no match
            if (!telemetry || !telemetry.handlers || telemetry.handlers.length === 0) {
                return null;
            }
        }
        
        // CRITICAL: Get the best handler (longest/most complete)
        if (debugMode) console.log(`[FROGPOST-BG] Selecting best handler from ${telemetry.handlers.length} handlers`);
        telemetry.handlers.forEach((h, i) => {
            if (debugMode) console.log(`[FROGPOST-BG]   Handler ${i+1}: ${(h.code || '').length} chars, name: ${h.name}`);
        });
        
        const bestHandler = telemetry.handlers.reduce((best, current) => {
            const currentLen = (current.code || '').length;
            const bestLen = (best.code || '').length;
            return currentLen > bestLen ? current : best;
        }, telemetry.handlers[0]);
        
        if (debugMode) console.log(`[FROGPOST-BG] Selected handler: ${(bestHandler.code || '').length} chars, name: ${bestHandler.name}`);
        
        // CRITICAL: Ensure full code is returned, not truncated
        const fullHandlerCode = bestHandler.code || '';
        
        // Note: Removed length check - real handlers can be short (e.g., e=>{this.messageReceived(e)})
        
        log.debug(`[Handler Retrieval] Retrieved handler for ${endpointKey}: ${fullHandlerCode.length} chars`);
        
        // Return in format expected by Play button
        return {
            handler: fullHandlerCode,  // Full code
            code: fullHandlerCode,     // Full code
            category: "dom-agent-telemetry",
            method: "FrogPost runtime interception",
            score: 100, // High confidence from runtime interception
            windowId: telemetry.windowId,
            location: telemetry.location,
            timestamp: telemetry.timestamp,
            source: "DOM Agent Telemetry",
            length: bestHandler.length,
            name: bestHandler.name
        };
    } catch (error) {
        log.error("Error in getPreExtractedHandler:", error);
        return null;
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    let isAsync = false; let responseFunction = sendResponse;
    try {
        const messageType = message?.type; const payload = message?.payload; const detail = message?.detail; const payloadIndex = message?.payloadIndex; const senderTabId = sender?.tab?.id;
        if (message.type === "performSearch" && message.query) {
            performGoogleSearch(message.query) // Assume this function calls the Google Search tool
                .then(results => {
                    sendResponse({ success: true, results: results });
                })
                .catch(error => {
                    sendResponse({ success: false, error: error.message || 'Unknown search error' });
                });
            return true;
        }
        switch (messageType) {
            case 'fetchResponseHeaders':
                (async () => {
                    try {
                        const targetUrl = message?.url;
                        if (!targetUrl) { sendResponse({ success: false, error: 'Missing url' }); return; }
                        const result = await fetchHeadersViaDebugger(targetUrl);
                        sendResponse({ success: true, ...result });
                    } catch (e) {
                        sendResponse({ success: false, error: e?.message || 'Unknown error' });
                    }
                })();
                return true;
            case "runtimeListenerCaptured":
                if (payload) {
                    const { listenerCode, stackTrace, destinationUrl, context } = payload;
                    const normalizedInfo = normalizeEndpointUrl(destinationUrl);
                    const storageIdentifier = normalizedInfo?.normalized;
                    // Drop our own agent-captured meta messages
                    if (context && typeof context === 'string' && context.startsWith('frogPost')) {
                        if (responseFunction) responseFunction({ success: true, action: "ignored-extension-context" });
                        return true;
                    }
                    if (listenerCode && storageIdentifier && typeof storageIdentifier === 'string') {
                        const storageKey = `runtime-listeners-${storageIdentifier}`;
                        const isValidListenerCode = code => code && typeof code === 'string' && !code.includes('[native code]') && code.length > 25;
                        isAsync = true;
                        (async () => {
                            let responseSent = false;
                            let response = { success: false, error: "Storage operation did not complete" };
                            try {
                                const result = await chrome.storage.local.get([storageKey]);
                                let listeners = result[storageKey] || [];
                                const existingIndex = listeners.findIndex(l => l.code === listenerCode);
                                const newListenerData = { code: listenerCode, stack: stackTrace, timestamp: Date.now(), context: context };
                                let needsEndpointNotification = false;
                                let needsHandlerUpdateNotification = false;
                                if (existingIndex === -1) {
                                    listeners.push(newListenerData);
                                    if (listeners.length > 30) listeners = listeners.slice(-30);
                                    storageBatcher.set({ [storageKey]: listeners });
                                    response = { success: true, action: "saved" };
                                    if (isValidListenerCode(listenerCode)) { needsHandlerUpdateNotification = true; }
                                } else {
                                    response = { success: true, action: "duplicate" };
                                    if (isValidListenerCode(listenerCode)) { needsHandlerUpdateNotification = true; }
                                }
                                if (isValidListenerCode(listenerCode)) {
                                    if (!endpointsWithDetectedHandlers.has(storageIdentifier)) { endpointsWithDetectedHandlers.add(storageIdentifier); await saveHandlerEndpoints(); needsEndpointNotification = true; }
                                }
                                if (needsEndpointNotification) { notifyDashboard("handlerEndpointDetected", { endpointKey: storageIdentifier }); }
                                if (needsHandlerUpdateNotification) { notifyDashboard("handlerCapturedForEndpoint", { endpointKey: storageIdentifier }); }
                            } catch (error) {
                                response = { success: false, error: error.message };
                            } finally {
                                if (responseFunction && !responseSent) { try { responseFunction(response); responseSent = true; } catch (e) {} }
                            }
                        })();
                        return true;
                    } else {
                        if (responseFunction) responseFunction({ success: false, error: "Missing listenerCode or invalid destinationUrl" });
                        return false;
                    }
                }
                break;
            case "postMessageCaptured":
                if (payload) {
                    const { origin, destinationUrl, data, timestamp } = payload;
                    let finalData = data;
                    let processedData = data;
                    let calculatedMessageType = 'unknown';

                    if (processedData === undefined) {
                        calculatedMessageType = "undefined";
                    } else if (processedData === null) {
                        calculatedMessageType = "null";
                    } else if (Array.isArray(processedData)) {
                        calculatedMessageType = "array";
                    } else if (typeof processedData === 'object' && processedData !== null) {
                        calculatedMessageType = processedData.constructor === Object ? "object" : "special_object";
                    } else if (typeof processedData === 'string') {
                        const trimmedData = processedData.trim();
                        if ((trimmedData.startsWith('{') && trimmedData.endsWith('}')) || (trimmedData.startsWith('[') && trimmedData.endsWith(']'))) {
                            try {
                                const parsed = JSON.parse(trimmedData);
                                processedData = parsed;
                                calculatedMessageType = Array.isArray(parsed) ? "array" : "object";
                            } catch (e) {
                                calculatedMessageType = "string";
                            }
                        } else {
                            calculatedMessageType = "string";
                        }
                    } else {
                        calculatedMessageType = typeof processedData;
                    }


                    const destUrlStr = typeof destinationUrl === 'string' ? destinationUrl : 'unknown_frame_url';
                    const topLevelUrlRaw = sender?.tab?.url || null;

                    const safeData = sanitizeJsonDeep(processedData, { maxKeysTotal: 50, maxArrayLength: 50, maxDepth: 8 });

                    const messageData = {
                        origin: origin || sender.origin || 'unknown',
                        destinationUrl: destUrlStr,
                        data: safeData, // Send the potentially parsed data with top-level key cap
                        messageType: calculatedMessageType, // Send the refined type
                        timestamp: timestamp || new Date().toISOString(),
                        messageId: `${timestamp || Date.now()}-${Math.random().toString(16).slice(2)}`,
                        topLevelUrl: topLevelUrlRaw
                    };

                    // Filter out extension-generated messages so analysis relies on site messages only
                    const dataType = typeof processedData === 'object' && processedData ? processedData.type : null;
                    const isExtensionMsg = (typeof processedData === 'string' && processedData === 'FrogPost::BreakpointTest') || (typeof dataType === 'string' && (
                        dataType.startsWith('frogPost') ||
                        dataType.startsWith('FROGPOST_') ||
                        dataType === 'realTimeDetectorReady' ||
                        dataType === 'realTimeHandlerDetected' ||
                        dataType === 'realTimeMessageSent'));
                    
                    if (!isExtensionMsg) {
                        messageBuffer.push(messageData);
                        notifyDashboard('newPostMessage', messageData);
                    }

                    const newConnection = addFrameConnection(messageData.origin, messageData.destinationUrl);
                    if (newConnection) {
                        const connectionsPayload = {};
                        frameConnections.forEach((v, k) => { connectionsPayload[k] = Array.from(v); });
                        notifyDashboard('newFrameConnection', connectionsPayload);
                    }
                }
                if (responseFunction) responseFunction({ success: true });
                return false;
            case "FROGPOST_MUTATION": notifyDashboard("domMutationDetected", { detail: detail, location: message.location, payloadIndex: payloadIndex }); return false;
            case "FROGPOST_CONSOLE_SUCCESS": if (payloadIndex !== undefined && payloadIndex !== -1) { if (!consoleSuccessIndices.includes(payloadIndex)) { consoleSuccessIndices.push(payloadIndex); } } notifyDashboard("consoleSuccessDetected", { detail: detail, location: message.location, payloadIndex: payloadIndex }); return false;
            case "getConsoleSuccessIndices": const indicesToSend = [...consoleSuccessIndices]; consoleSuccessIndices = []; responseFunction({ success: true, indices: indicesToSend }); return true;
            case "fetchInitialState": isAsync = true; (async () => { const messages = messageBuffer.getMessages(); const handlerKeys = Array.from(endpointsWithDetectedHandlers); if (responseFunction) { try { responseFunction({ success: true, messages: messages, handlerEndpointKeys: handlerKeys }); } catch (e) {} } })(); return true;
            case "resetState": messageBuffer.clear(); frameConnections.clear(); injectedFramesAgents.clear(); endpointsWithDetectedHandlers.clear(); consoleSuccessIndices = []; isAsync = true; (async () => { let response = { success: true, message: "State reset" }; try { const allData = await chrome.storage.local.get(null); const keysToRemove = Object.keys(allData).filter(key => key.startsWith('runtime-listeners-') || key.startsWith('best-handler-') || key.startsWith('saved-messages-') || key.startsWith('trace-info-') || key.startsWith('analyzed-url-for-') || key.startsWith('analysis-storage-key-for-')); if (keysToRemove.length > 0) { await chrome.storage.local.remove(keysToRemove); } await chrome.storage.session.remove(HANDLER_ENDPOINT_KEYS_STORAGE_KEY); if (self.traceReportStorage && typeof self.traceReportStorage.clearAllReports === 'function') { await self.traceReportStorage.clearAllReports(); } } catch(storageError) { response = { success: false, message: "Error clearing storage", error: storageError.message }; } finally { if (responseFunction) { try { responseFunction(response); } catch(e) {} } } })(); notifyDashboard('stateReset', {}); return true;
            case 'startServer': isAsync = true; chrome.runtime.sendNativeMessage( NATIVE_HOST_NAME, { action: 'startServer', data: JSON.stringify(message.data), options: { port: 1337, maxRetries: 3, timeout: 5000 } }, (response) => { if (chrome.runtime.lastError) { if (responseFunction) try { responseFunction({success: false, error: chrome.runtime.lastError.message}); } catch(e){} } else if (response?.success) { setTimeout(() => { if (responseFunction) try { responseFunction({success: true}); } catch(e){} }, 2000); } else { if (responseFunction) try { responseFunction({success: false, error: response?.error || "Failed to start server"}); } catch(e){} } } ); return true;
            case 'stopServer': isAsync = true; chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: 'stopServer' }, (response) => { if (responseFunction) { try { responseFunction({ success: !chrome.runtime.lastError && response?.success, error: chrome.runtime.lastError?.message || response?.error }); } catch(e){} } }); disconnectNativeHost(); return true;
            case 'analyzeHandlerDynamically': isAsync = true; analyzeHandlerDynamically(payload, responseFunction); return true;
            case "setDebuggerMode": if (typeof payload?.enabled === 'boolean') { isDebuggerApiModeGloballyEnabled = payload.enabled; log.info(`Background Debugger API Mode set to: ${isDebuggerApiModeGloballyEnabled}`); if (responseFunction) responseFunction({ success: true }); } else { if (responseFunction) responseFunction({ success: false, error: "Invalid payload for setDebuggerMode" }); } return false;
            case "setDebugMode": 
                isAsync = true;
                (async () => {
                    if (typeof payload?.enabled === 'boolean') { 
                        debugMode = payload.enabled;
                        try {
                            await chrome.storage.local.set({ [DEBUG_MODE_STORAGE_KEY]: debugMode });
                            log.info(`Debug mode ${debugMode ? 'enabled' : 'disabled'}`);
                            if (responseFunction) responseFunction({ success: true });
                            
                            // Broadcast debug mode change to all tabs so DOM agents can update
                            try {
                                const tabs = await chrome.tabs.query({});
                                for (const tab of tabs) {
                                    if (tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
                                        chrome.tabs.sendMessage(tab.id, {
                                            type: '__FROGPOST_SET_DEBUG_MODE__',
                                            enabled: debugMode
                                        }).catch(() => {}); // Ignore errors for tabs that don't have content script
                                    }
                                }
                            } catch (e) {
                                // Ignore broadcast errors
                            }
                        } catch (error) {
                            log.error("Error saving debug mode:", error);
                            if (responseFunction) responseFunction({ success: false, error: error.message });
                        }
                    } else {
                        if (responseFunction) responseFunction({ success: false, error: "Invalid payload for setDebugMode" });
                    }
                })();
                return true;
            case "zombieDebuggerScan":
                isAsync = true;
                (async () => {
                    try {
                        const { url, endpointKey } = payload || {};
                        if (!url) {
                            if (responseFunction) responseFunction({ success: false, error: 'Missing url' });
                            return;
                        }
                        
                        log.info(`[Zombie Debugger] Starting debugger scan for ${url}`);
                        
                        // Check if debugger mode is enabled
                        const debuggerModeResult = await chrome.storage.local.get(['debuggerApiModeEnabled']);
                        if (!debuggerModeResult?.debuggerApiModeEnabled) {
                            if (responseFunction) responseFunction({ success: false, error: 'Debugger API mode not enabled' });
                            return;
                        }
                        
                        // Queue if at debugger limit
                        if (!canAttachDebugger()) {
                            log.warn(`[Zombie Debugger] Debugger limit reached, queuing ${url}`);
                            debuggerQueue.push(() => {
                                chrome.runtime.sendMessage({
                                    type: 'zombieDebuggerScan',
                                    payload: payload
                                }, responseFunction);
                            });
                            if (responseFunction) responseFunction({ success: false, error: 'Debugger queue full, will retry' });
                            return;
                        }
                        
                        incrementDebuggerCount();
                        let tabId = null;
                        let attached = false;
                        let handlerFound = null;
                        
                        try {
                            // Create tab
                            const tab = await chrome.tabs.create({ url: url, active: false });
                            tabId = tab.id;
                            
                            // Wait for page to load
                            await new Promise(resolve => setTimeout(resolve, 2000));
                            
                            // Attach debugger
                            await chrome.debugger.attach({ tabId }, '1.3');
                            attached = true;
                            log.debug(`[Zombie Debugger] Attached to tab ${tabId}`);
                            
                            // Enable domains
                            await Promise.all([
                                chrome.debugger.sendCommand({ tabId }, 'Page.enable'),
                                chrome.debugger.sendCommand({ tabId }, 'Runtime.enable'),
                                chrome.debugger.sendCommand({ tabId }, 'Debugger.enable')
                            ]);
                            
                            // Set breakpoint on message listener registration
                            try {
                                await chrome.debugger.sendCommand({ tabId }, 'DOMDebugger.setEventListenerBreakpoint', { eventName: 'message' });
                            } catch (e) {
                                // Ignore if already set
                            }
                            
                            // Set up event listener
                            const eventListener = async (source, method, params) => {
                                if (source.tabId !== tabId) return;
                                
                                if (method === 'Debugger.paused' && params?.reason === 'EventListener') {
                                    try {
                                        const frame = params.callFrames?.[0];
                                        const scriptId = frame?.location?.scriptId;
                                        if (scriptId && typeof HandlerExtractor !== 'undefined') {
                                            const { scriptSource } = await chrome.debugger.sendCommand({ tabId }, 'Debugger.getScriptSource', { scriptId });
                                            if (scriptSource) {
                                                const extractor = new HandlerExtractor();
                                                const foundHandlers = extractor.analyzeScriptContent(scriptSource, `zombie_${scriptId}`);
                                                if (foundHandlers && foundHandlers.length > 0) {
                                                    const bestHandler = extractor.getBestHandler(foundHandlers);
                                                    if (bestHandler && bestHandler.handler) {
                                                        handlerFound = bestHandler;
                                                        log.success(`[Zombie Debugger] Found handler via breakpoint`);
                                                    }
                                                }
                                            }
                                        }
                                    } catch (e) {
                                        log.warn(`[Zombie Debugger] Error processing breakpoint:`, e);
                                    }
                                    
                                    // Resume execution
                                    try {
                                        await chrome.debugger.sendCommand({ tabId }, 'Debugger.resume');
                                    } catch {}
                                }
                                
                                // Also check script parsing (external AND inline scripts)
                                if (method === 'Debugger.scriptParsed') {
                                    const { scriptId, url: scriptUrl } = params || {};
                                    // CRITICAL FIX: Process scripts with URLs AND scripts without URLs (inline scripts)
                                    // Inline scripts may have no URL, empty URL, or data: URLs
                                    const isInlineScript = !scriptUrl || scriptUrl === '' || scriptUrl.startsWith('data:') || scriptUrl.startsWith('about:');
                                    if (typeof HandlerExtractor !== 'undefined') {
                                        try {
                                            const { scriptSource } = await chrome.debugger.sendCommand({ tabId }, 'Debugger.getScriptSource', { scriptId });
                                            if (scriptSource && scriptSource.length < 1500000) {
                                                const extractor = new HandlerExtractor();
                                                // Use appropriate source identifier for inline vs external scripts
                                                const sourceIdentifier = isInlineScript 
                                                    ? `zombie_inline_${scriptId}` 
                                                    : scriptUrl;
                                                const foundHandlers = extractor.analyzeScriptContent(scriptSource, sourceIdentifier);
                                                if (foundHandlers && foundHandlers.length > 0) {
                                                    const bestHandler = extractor.getBestHandler(foundHandlers);
                                                    if (bestHandler && bestHandler.handler && !handlerFound) {
                                                        handlerFound = bestHandler;
                                                        log.success(`[Zombie Debugger] Found handler via script parsing (${isInlineScript ? 'inline' : 'external'})`);
                                                    }
                                                }
                                            }
                                        } catch (e) {
                                            // Ignore errors
                                        }
                                    }
                                }
                            };
                            
                            chrome.debugger.onEvent.addListener(eventListener);
                            
                            // CRITICAL FIX: Also extract inline scripts from HTML after page load
                            // This catches inline <script> tags that may not trigger Debugger.scriptParsed
                            const extractInlineScriptsFromHTML = async () => {
                                try {
                                    if (typeof HandlerExtractor === 'undefined') return;
                                    
                                    // Get the page HTML via debugger
                                    const { result } = await chrome.debugger.sendCommand({ tabId }, 'Runtime.evaluate', {
                                        expression: 'document.documentElement.outerHTML',
                                        returnByValue: true
                                    });
                                    
                                    if (result?.value && typeof result.value === 'string') {
                                        const html = result.value;
                                        const extractor = new HandlerExtractor();
                                        
                                        // Extract inline scripts using same pattern as extractStaticallyWithContext
                                        const inlineRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
                                        let match;
                                        let inlineIndex = 0;
                                        
                                        while ((match = inlineRegex.exec(html)) !== null && !handlerFound) {
                                            const content = match[1] || '';
                                            if (content.trim().length < 20) {
                                                inlineIndex++;
                                                continue;
                                            }
                                            
                                            const sourceId = `${url}/inline_${inlineIndex}.js`;
                                            const foundHandlers = extractor.analyzeScriptContent(content, sourceId);
                                            
                                            if (foundHandlers && foundHandlers.length > 0) {
                                                const bestHandler = extractor.getBestHandler(foundHandlers);
                                                if (bestHandler && bestHandler.handler && !handlerFound) {
                                                    handlerFound = bestHandler;
                                                    log.success(`[Zombie Debugger] Found handler in inline script #${inlineIndex}`);
                                                }
                                            }
                                            
                                            inlineIndex++;
                                        }
                                        
                                        if (inlineIndex > 0) {
                                            log.debug(`[Zombie Debugger] Scanned ${inlineIndex} inline script(s) from HTML`);
                                        }
                                    }
                                } catch (e) {
                                    log.debug(`[Zombie Debugger] Inline script extraction error: ${e.message}`);
                                }
                            };
                            
                            // Wait for page to fully load, then extract inline scripts
                            setTimeout(async () => {
                                await extractInlineScriptsFromHTML();
                            }, 3000);
                            
                            // Wait for handler discovery (max 8 seconds)
                            await new Promise(resolve => setTimeout(resolve, 8000));
                            
                            chrome.debugger.onEvent.removeListener(eventListener);
                            
                            if (handlerFound) {
                                if (responseFunction) responseFunction({ 
                                    success: true, 
                                    handler: handlerFound 
                                });
                            } else {
                                if (responseFunction) responseFunction({ 
                                    success: false, 
                                    error: 'No handler found within timeout' 
                                });
                            }
                            
                        } catch (error) {
                            log.error(`[Zombie Debugger] Error:`, error);
                            if (responseFunction) responseFunction({ 
                                success: false, 
                                error: error.message || 'Unknown error' 
                            });
                        } finally {
                            if (attached && tabId) {
                                try {
                                    await chrome.debugger.detach({ tabId });
                                } catch {}
                            }
                            if (tabId) {
                                try {
                                    await chrome.tabs.remove(tabId);
                                } catch {}
                            }
                            decrementDebuggerCount();
                        }
                        
                    } catch (error) {
                        log.error(`[Zombie Debugger] Top-level error:`, error);
                        if (responseFunction) responseFunction({ 
                            success: false, 
                            error: error.message || 'Unknown error' 
                        });
                    }
                })();
                return true;
            case "contentScriptReady":
                try {
                    const tabId = sender?.tab?.id;
                    const frameId = sender?.frameId ?? 0;
                    const tabUrl = sender?.tab?.url;
                    
                    // Skip handler extraction tabs
                    if (tabUrl && tabUrl.includes('frogpost_handler_extraction=true')) {
                        log.debug(`[Content Script Ready] Skipping handler extraction tab: ${tabUrl}`);
                        break;
                    }
                    
                    if (tabId != null) {
                        const already = injectedFramesAgents.get(tabId)?.has(frameId);
                        if (!already) {
                            chrome.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, func: agentFunctionToInject, injectImmediately: true, world: 'MAIN' })
                                .then(results => {
                                    const ok = results?.[0]?.result?.success || results?.[0]?.result?.alreadyInjected;
                                    if (ok) {
                                        if (!injectedFramesAgents.has(tabId)) injectedFramesAgents.set(tabId, new Set());
                                        injectedFramesAgents.get(tabId).add(frameId);
                                    }
                                }).catch(()=>{});
                        }
                    }
                } catch(e) {}
                break;
            case "realTimeDetectorReady":
                // Skip handler extraction tabs
                if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                    log.debug(`[Real-time Detector Ready] Skipping handler extraction tab: ${payload.location}`);
                    break;
                }
                log.info("Real-time detector ready on:", payload?.location);
                notifyDashboard('realTimeDetectorReady', payload);
                break;
        case "realTimeHandlerDetected":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                log.debug(`[Real-time Handler Detected] Skipping handler extraction tab: ${payload.location}`);
                break;
            }
            log.handler("Real-time handler detected:", payload);
            notifyDashboard('realTimeHandlerDetected', payload);

            // Store real-time handler for Play button to use
            storeRealTimeHandler(payload).catch(error => {
                log.error("Error storing real-time handler:", error);
            });
            break;

        case "frogPostDOMAgentHandler":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                log.debug(`[DOM Agent Handler] Skipping handler extraction tab: ${payload.location}`);
                break;
            }
            log.handler("DOM Agent handler detected:", payload);
            notifyDashboard('realTimeHandlerDetected', payload);

            // Store DOM agent handler for Play button to use
            storeRealTimeHandler(payload).catch(error => {
                log.error("Error storing DOM agent handler:", error);
            });
            break;

        case "frogPostDOMAgentMessage":
            try {
                const d = payload?.data;
                // Drop our breakpoint probes entirely
                if ((typeof d === 'string' && d === 'FrogPost::BreakpointTest') ||
                    (d && typeof d === 'object' && d.FrogPost === 'BreakpointTest')) {
                    break;
                }
                
                // Filter out DOM agent internal messages - these should not be displayed to user
                if (payload?.id && payload.id.startsWith('dom_agent_')) {
                    log.debug("DOM Agent internal message filtered out:", payload.id);
                    break;
                }
            } catch {}
            log.info("DOM Agent message detected:", payload);
            notifyDashboard('realTimeMessageSent', payload);
            break;

        case "frogPostDOMAgentReady":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                log.debug(`[DOM Agent Ready] Skipping handler extraction tab: ${payload.location}`);
                break;
            }
            log.info("DOM Agent ready on:", payload.location);
            notifyDashboard('realTimeDetectorReady', payload);
            break;

        // NEW: Enhanced telemetry handlers
        case "agent-ready":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                log.debug(`[Agent Ready] Skipping handler extraction tab: ${payload.location}`);
                break;
            }
            log.info(`[FrogPost Agent] Ready on ${payload.location} (windowId: ${payload.windowId})`);
            notifyDashboard('realTimeDetectorReady', payload);
            break;

        case "handlers-telemetry":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                break;
            }
            // Store periodic telemetry (THE KEY to 95%+ accuracy)
            storeHandlerTelemetry(payload).catch(error => {
                log.error("Error storing handler telemetry:", error);
            });
            // Forward to dashboard for real-time display
            notifyDashboard('handlersUpdated', {
                location: payload.location,
                handlerCount: payload.handlerCount,
                windowId: payload.windowId
            });
            break;

        case "handler-added":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                break;
            }
            log.handler(`[FrogPost] Handler added via ${payload.method} on ${payload.location}`);
            notifyDashboard('realTimeHandlerDetected', payload);
            break;

        case "handler-detected":
            // Real-time handler capture - add to in-memory cache
            if (debugMode) console.log(`[FROGPOST-BG] 🎯 handler-detected received!`, {
                hasPayload: !!payload,
                hasLocation: !!payload?.location,
                hasHandler: !!payload?.handler,
                location: payload?.location,
                handlerType: typeof payload?.handler
            });
            
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                if (debugMode) console.log(`[FROGPOST-BG] Skipping extraction tab`);
                break;
            }
            if (payload?.location && payload?.handler) {
                const url = payload.location;
                // CRITICAL FIX: Normalize URL when storing in cache for consistent lookup
                const normalizedUrl = normalizeEndpointUrl(url)?.normalized || url;
                
                // RELIABILITY FIX: Generate URL variants for fuzzy matching
                const urlVariants = generateUrlVariants(normalizedUrl);
                
                if (debugMode) {
                    console.log(`[FROGPOST-BG] 📥 Storing handler for: ${url}`);
                    console.log(`[FROGPOST-BG]    Original URL: ${url}`);
                    console.log(`[FROGPOST-BG]    Normalized key: ${normalizedUrl}`);
                    console.log(`[FROGPOST-BG]    URL variants (${urlVariants.length}): ${urlVariants.slice(0, 3).join(', ')}...`);
                    console.log(`[FROGPOST-BG]    Handler length: ${payload.handler.code?.length || 0} chars`);
                }
                
                const handlerData = {
                    code: payload.handler.code || payload.handler,
                    name: payload.handler.name || 'anonymous',
                    timestamp: payload.handler.timestamp || Date.now(),
                    source: 'dom-agent-realtime'
                };
                
                // RELIABILITY FIX: Store under ALL URL variants for maximum findability
                // This ensures handlers can be found even with URL variations (query params, trailing slashes, etc.)
                const handlerHash = fastHashHandler(handlerData.code);
                let storedCount = 0;
                
                for (const variant of urlVariants) {
                    // Get or create cache entry for this variant
                    if (!handlerCache.has(variant)) {
                        handlerCache.set(variant, { handlers: [], handlerHashes: new Set(), lastUpdate: Date.now() });
                    }
                    
                    const cacheEntry = handlerCache.get(variant);
                    
                    // OPTIMIZATION: Hash-based deduplication (5-10x faster than string comparison)
                    if (cacheEntry.handlerHashes.has(handlerHash)) {
                        // Already stored under this variant - skip
                        continue;
                    }
                    
                    // Add new handler
                    cacheEntry.handlerHashes.add(handlerHash);
                    cacheEntry.handlers.push(handlerData);
                    cacheEntry.lastUpdate = Date.now();
                    storedCount++;
                    
                    // Limit handlers per URL
                    if (cacheEntry.handlers.length > MAX_HANDLERS_PER_URL) {
                        const removed = cacheEntry.handlers.shift(); // Remove oldest
                        // Also remove its hash
                        if (removed?.code) {
                            const removedHash = fastHashHandler(removed.code);
                            cacheEntry.handlerHashes.delete(removedHash);
                        }
                    }
                }
                    
                if (debugMode) {
                    console.log(`[FROGPOST-BG] Handler cached under ${storedCount} URL variant(s): ${handlerData.code.substring(0, 80)}...`);
                    console.log(`[FROGPOST-BG] Primary cache key now has ${handlerCache.get(normalizedUrl)?.handlers.length || 0} handler(s)`);
                }
                // LRU cache automatically handles eviction when size exceeds MAX_CACHE_SIZE
                
                // CRITICAL FIX: Notify dashboard about the new endpoint with handler
                // This ensures zombie endpoints (handlers without messages) appear in the endpoint list
                notifyDashboard('handlerDetectedForEndpoint', {
                    endpointKey: normalizedUrl,
                    location: url,
                    handler: {
                        code: handlerData.code,
                        name: handlerData.name,
                        source: handlerData.source,
                        timestamp: handlerData.timestamp
                    },
                    isZombie: true // Mark as zombie endpoint (handler detected, no messages yet)
                });
                
                log.info(`[handler-detected] Handler cached for zombie endpoint: ${normalizedUrl}`);
            }
            break;

        case "received-message":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                break;
            }
            // Track incoming postMessage
            try {
                const messageData = {
                    origin: payload.origin,
                    destinationUrl: payload.location,
                    data: sanitizeJsonDeep(payload.data, { maxKeysTotal: 50, maxArrayLength: 50, maxDepth: 8 }),
                    messageType: typeof payload.data,
                    timestamp: new Date(payload.timestamp).toISOString(),
                    messageId: payload.messageId,
                    windowId: payload.windowId
                };
                messageBuffer.push(messageData);
                notifyDashboard('newPostMessage', messageData);
            } catch (e) {
                log.debug("Error processing received-message:", e);
            }
            break;

        case "outgoing-message":
            // Skip handler extraction tabs
            if (payload?.location && payload.location.includes('frogpost_handler_extraction=true')) {
                break;
            }
            log.debug(`[FrogPost] Outgoing postMessage from ${payload.location}`);
            break;

        case "getPreExtractedHandler":
            // NEW: Retrieve handler from telemetry (called by Play button)
            console.log('[FROGPOST-BG] ========================================');
            console.log('[FROGPOST-BG] getPreExtractedHandler message received');
            console.log('[FROGPOST-BG] Payload:', payload);
            isAsync = true;
            (async () => {
                try {
                    const endpointKey = payload?.endpointKey;
                    if (!endpointKey) {
                        console.error('[FROGPOST-BG] Missing endpointKey in payload');
                        log.error('[getPreExtractedHandler] Missing endpointKey in payload');
                        sendResponse({ success: false, error: 'Missing endpointKey' });
                        return;
                    }
                    if (debugMode) console.log(`[FROGPOST-BG] Looking up telemetry for: ${endpointKey}`);
                    log.info(`[getPreExtractedHandler] Looking up telemetry for: ${endpointKey}`);
                    const handler = await getPreExtractedHandler(endpointKey);
                    if (debugMode) console.log(`[FROGPOST-BG] getPreExtractedHandler returned:`, handler ? 'FOUND' : 'NULL');
                    if (handler) {
                        if (debugMode) console.log(`[FROGPOST-BG] ✅ Handler found! Length: ${handler.handler?.length || handler.code?.length}`);
                        log.info(`[getPreExtractedHandler] ✅ Found handler for ${endpointKey}`);
                        sendResponse({ success: true, handler: handler });
                    } else {
                        if (debugMode) console.warn(`[FROGPOST-BG] ❌ No handler found`);
                        log.warn(`[getPreExtractedHandler] ❌ No handler found for ${endpointKey}`);
                        sendResponse({ success: false, error: 'No pre-extracted handler found' });
                    }
                } catch (e) {
                    console.error('[FROGPOST-BG] Exception:', e);
                    sendResponse({ success: false, error: e?.message || 'Unknown error' });
                }
            })();
            break;
            case "realTimeMessageSent":
                log.debug("Real-time message sent:", payload);
                notifyDashboard('realTimeMessageSent', payload);
                break;
            case "getRealTimeHandlersForUrl":
                (async () => {
                    try {
                        const url = payload?.url;
                        if (!url) { sendResponse({ success: false, error: 'Missing url' }); return; }
                        const storageKey = `real-time-handlers-${url}`;
                        const result = await chrome.storage.local.get(storageKey);
                        const handlers = result[storageKey] || [];
                        sendResponse({ success: true, handlers });
                    } catch (e) {
                        sendResponse({ success: false, error: e?.message || 'Unknown error' });
                    }
                })();
                isAsync = true;
                break;
            case "realTimeExistingListeners":
                log.info("Real-time existing listeners found on:", payload?.location);
                notifyDashboard('realTimeExistingListeners', payload);
                break;
            case "realTimeCrossOriginIframe":
                log.info("Real-time cross-origin iframe detected:", payload?.src);
                notifyDashboard('realTimeCrossOriginIframe', payload);
                break;
            case "realTimeIframeHandler":
                log.handler("Real-time iframe handler detected:", payload);
                notifyDashboard('realTimeIframeHandler', payload);
                break;
            default: break;
        }
    } catch (error) { log.error("Top-level error processing message:", error, message); if (responseFunction) try { responseFunction({ success: false, error: "Handler error" }); } catch (e) {} }
    return isAsync;
});

chrome.action.onClicked.addListener((tab) => { chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/dashboard.html") }); });
chrome.runtime.onInstalled.addListener(details => { 
    if (details.reason === 'install' || details.reason === 'update') { 
        chrome.storage.session.remove(HANDLER_ENDPOINT_KEYS_STORAGE_KEY); 
        chrome.storage.local.remove('debuggerApiModeEnabled'); 
    } 
    messageBuffer = new CircularMessageBuffer(100); 
    // Start server monitoring for LLM features
    startServerMonitoring();
    log.info("Extension initialized - server monitoring started");
});
loadHandlerEndpoints().catch(error => {
    log.error("Error loading handler endpoints:", error);
});
if (!messageBuffer) { messageBuffer = new CircularMessageBuffer(100); }
// Periodic cleanup to prevent memory accumulation
function performPeriodicCleanup() {
    try {
        // Clear old processed URLs (keep only recent ones)
        if (processedUrlsInSession.size > 50) {
            const urls = Array.from(processedUrlsInSession);
            processedUrlsInSession.clear();
            // Keep only the most recent 25 URLs
            urls.slice(-25).forEach(url => processedUrlsInSession.add(url));
        }
        
        // Clear old console success indices
        if (consoleSuccessIndices.length > 20) {
            consoleSuccessIndices = consoleSuccessIndices.slice(-10);
        }
        
        log.debug("Periodic cleanup completed");
    } catch (error) {
        log.error("Error during periodic cleanup:", error);
    }
}

// Run cleanup every 5 minutes
setInterval(performPeriodicCleanup, 300000);
