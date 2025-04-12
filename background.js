/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
let frameConnections = new Map();
let messageBuffer;
const injectedFramesAgents = new Map();
const HANDLER_ENDPOINT_KEYS_STORAGE_KEY = 'handler_endpoint_keys';
let endpointsWithDetectedHandlers = new Set();

class CircularMessageBuffer {
    constructor(maxSize = 1000) {
        this.maxSize = maxSize;
        this.buffer = new Array(this.maxSize);
        this.head = 0;
        this.size = 0;
    }

    push(message) {
        message.messageId = message.messageId || `${message.timestamp || Date.now()}-${Math.random().toString(16).slice(2)}`;
        const existingIndex = this.findIndex(m => m.messageId === message.messageId);
        if (existingIndex !== -1) {
            this.buffer[existingIndex] = message;
        } else {
            this.buffer[this.head] = message;
            this.head = (this.head + 1) % this.maxSize;
            if (this.size < this.maxSize) {
                this.size++;
            }
        }
    }

    findIndex(predicate) {
        for (let i = 0; i < this.size; i++) {
            const index = (this.head - this.size + i + this.maxSize) % this.maxSize;
            if (this.buffer[index] !== undefined && predicate(this.buffer[index])) {
                return index;
            }
        }
        return -1;
    }

    getMessages() {
        const messages = [];
        for (let i = 0; i < this.size; i++) {
            const index = (this.head - this.size + i + this.maxSize) % this.maxSize;
            if (this.buffer[index] !== undefined) {
                messages.push(this.buffer[index]);
            }
        }
        return messages;
    }

    clear() {
        this.buffer = new Array(this.maxSize);
        this.head = 0;
        this.size = 0;
    }
}

messageBuffer = new CircularMessageBuffer(1000);

function normalizeEndpointUrl(url) {
    try {
        if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) {
            return { normalized: url, components: null };
        }
        let absoluteUrlStr = url;
        if (!url.includes('://') && !url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }
        else if (url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }

        const urlObj = new URL(absoluteUrlStr);
        if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:', 'blob:', 'data:'].includes(urlObj.protocol)) {
            return { normalized: url, components: null };
        }
        const normalized = urlObj.origin + urlObj.pathname + urlObj.search;
        return {
            normalized: normalized,
            components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash }
        };
    } catch (e) {
        return { normalized: url, components: null };
    }
}

function getBaseUrl(url) {
    try {
        const norm = normalizeEndpointUrl(url);
        return norm?.components ? norm.components.origin + norm.components.path : null;
    } catch (e) { return null; }
}

function addFrameConnection(origin, destinationUrl) {
    let addedNew = false;
    try {
        const normalizedOrigin = normalizeEndpointUrl(origin)?.normalized;
        const normalizedDestination = normalizeEndpointUrl(destinationUrl)?.normalized;

        if (!normalizedOrigin || !normalizedDestination ||
            normalizedOrigin === 'null' || normalizedDestination === 'null' ||
            normalizedOrigin === 'access-denied-or-invalid' || normalizedDestination === 'access-denied-or-invalid' ||
            normalizedOrigin === normalizedDestination ) {
            return false;
        }

        if (!frameConnections.has(normalizedOrigin)) {
            frameConnections.set(normalizedOrigin, new Set());
            addedNew = true;
        }
        const destSet = frameConnections.get(normalizedOrigin);
        if (!destSet.has(normalizedDestination)) {
            destSet.add(normalizedDestination);
            addedNew = true;
        }
    } catch (e) { /* Ignore */ }
    return addedNew;
}

async function isDashboardOpen() {
    try {
        const dashboardUrl = chrome.runtime.getURL("dashboard/dashboard.html");
        const tabs = await chrome.tabs.query({ url: dashboardUrl });
        return tabs.length > 0;
    } catch (e) { return false; }
}

async function notifyDashboard(type, payload) {
    if (!(await isDashboardOpen())) return;

    try {
        let serializablePayload;
        try {
            JSON.stringify(payload);
            serializablePayload = payload;
        } catch (e) {
            if (payload instanceof Map) serializablePayload = Object.fromEntries(payload);
            else if (payload instanceof Set) serializablePayload = Array.from(payload);
            else serializablePayload = { error: "Payload not serializable", type: payload?.constructor?.name };
        }

        if (chrome?.runtime?.id) {
            await chrome.runtime.sendMessage({ type: type, payload: serializablePayload });
        }
    } catch (error) {
        if (!error.message?.includes("Receiving end does not exist") &&
            !error.message?.includes("Could not establish connection")) {
            console.warn(`[notifyDashboard] Error sending message type ${type}:`, error.message);
        }
    }
}

function agentFunctionToInject() {
    const AGENT_VERSION = 'v10_postMsg_inline';
    const agentFlag = `__frogPostAgentInjected_${AGENT_VERSION}`;
    if (window[agentFlag]) return { success: true, alreadyInjected: true, message: `Agent ${AGENT_VERSION} already present.` };
    window[agentFlag] = true;
    console.log(`[FrogPost Agent ${AGENT_VERSION}] EXECUTE in:`, window.location.href);

    let errors = [];
    const MAX_LISTENER_CODE_LENGTH = 15000;
    const originalWindowAddEventListener = window.addEventListener;
    const capturedListenerSources = new Set();

    const safeToString = (func) => {
        try { return func.toString(); } catch (e) { return `[Error converting function: ${e?.message}]`; }
    };

    const sendListenerToForwarder = (listenerCode, contextInfo, destinationUrl) => {
        try {
            const codeStr = typeof listenerCode === 'string' ? listenerCode : safeToString(listenerCode);
            if (!codeStr || codeStr.includes('[native code]') || codeStr.length < 25) { return; }

            const fingerprint = codeStr.replace(/\s+/g, '').substring(0, 250);
            if (capturedListenerSources.has(fingerprint)) { return; }
            capturedListenerSources.add(fingerprint);

            let stack = ''; try { throw new Error('CaptureStack'); } catch (e) { stack = e.stack || ''; }

            const payload = {
                listenerCode: codeStr.substring(0, MAX_LISTENER_CODE_LENGTH),
                stackTrace: stack,
                destinationUrl: destinationUrl || window.location.href,
                context: contextInfo
            };
            window.postMessage({ type: 'frogPostAgent->ForwardToBackground', payload: payload }, window.location.origin || '*');
        } catch (e) { errors.push(`sendListener Error (${contextInfo}): ${e.message}`); }
    };

    try {
        window.addEventListener = function (type, listener, options) {
            if (type === 'message' && typeof listener === 'function') {
                sendListenerToForwarder(listener, 'window.addEventListener', window.location.href);
            }
            return originalWindowAddEventListener.apply(this, arguments);
        };
    } catch (e) { errors.push(`addEventListener hook failed: ${e.message}`); window.addEventListener = originalWindowAddEventListener; }

    let _currentWindowOnmessage = window.onmessage;
    try {
        Object.defineProperty(window, 'onmessage', {
            set: function (listener) {
                _currentWindowOnmessage = listener;
                if (typeof listener === 'function') {
                    sendListenerToForwarder(listener, 'window.onmessage_set', window.location.href);
                }
            },
            get: function () { return _currentWindowOnmessage; },
            configurable: true, enumerable: true
        });
        if (typeof _currentWindowOnmessage === 'function') {
            sendListenerToForwarder(_currentWindowOnmessage, 'window.onmessage_initial', window.location.href);
        }
    } catch (e) { errors.push(`onmessage hook failed: ${e.message}`); }

    try {
        const originalPortAddEventListener = MessagePort.prototype.addEventListener;
        MessagePort.prototype.addEventListener = function (type, listener, options) {
            try { if (type === 'message' && typeof listener === 'function') { sendListenerToForwarder(listener, 'port.addEventListener', window.location.href); } } catch(e) { errors.push(`port.addEventListener inner: ${e.message}`); }
            return originalPortAddEventListener.apply(this, arguments);
        };
        const portOnMessageDescriptor = Object.getOwnPropertyDescriptor(MessagePort.prototype, 'onmessage');
        const originalPortSetter = portOnMessageDescriptor?.set;
        const originalPortGetter = portOnMessageDescriptor?.get;
        const portOnmessageTracker = new WeakMap();
        Object.defineProperty(MessagePort.prototype, 'onmessage', {
            set: function(listener) {
                try { portOnmessageTracker.set(this, listener); if (typeof listener === 'function') { sendListenerToForwarder(listener, 'port.onmessage_set', window.location.href); } if (originalPortSetter) originalPortSetter.call(this, listener); } catch(e) { errors.push(`port.onmessage set inner: ${e.message}`); }
            },
            get: function() {
                try { let value = portOnmessageTracker.get(this); if (value === undefined && originalPortGetter) value = originalPortGetter.call(this); return value; } catch(e) { errors.push(`port.onmessage get inner: ${e.message}`); return undefined; }
            },
            configurable: true, enumerable: true
        });
    } catch (e) { errors.push(`MessagePort hook failed: ${e.message}`); }

    return { success: errors.length === 0, alreadyInjected: false, errors: errors, logsAdded: true };
}

async function loadHandlerEndpoints() {
    try {
        const result = await chrome.storage.session.get([HANDLER_ENDPOINT_KEYS_STORAGE_KEY]);
        if (result[HANDLER_ENDPOINT_KEYS_STORAGE_KEY]) {
            endpointsWithDetectedHandlers = new Set(result[HANDLER_ENDPOINT_KEYS_STORAGE_KEY]);
        } else {
            endpointsWithDetectedHandlers = new Set();
        }
    } catch (e) {
        console.error('[BG] Error loading handler endpoints:', e);
        endpointsWithDetectedHandlers = new Set();
    }
}

async function saveHandlerEndpoints() {
    try {
        await chrome.storage.session.set({
            [HANDLER_ENDPOINT_KEYS_STORAGE_KEY]: Array.from(endpointsWithDetectedHandlers)
        });
    } catch (e) {
        console.error('[BG] Error saving handler endpoints:', e);
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tabId) {
        injectedFramesAgents.delete(tabId);
    }
});

chrome.tabs.onRemoved.addListener(tabId => {
    injectedFramesAgents.delete(tabId);
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (!details.url || (!details.url.startsWith('http:') && !details.url.startsWith('https://')) || details.transitionType === 'server_redirect') {
        return;
    }
    const tabFrames = injectedFramesAgents.get(details.tabId);
    if (tabFrames?.has(details.frameId)) {
        return;
    }

    try {
        const results = await chrome.scripting.executeScript({
            target: { tabId: details.tabId, frameIds: [details.frameId] },
            func: agentFunctionToInject,
            injectImmediately: true,
            world: 'MAIN'
        });

        let injectionStatus = { success: false, alreadyInjected: false, errors: ["No result from executeScript"] };
        if (results?.[0]?.result) {
            injectionStatus = results[0].result;
        } else if (results?.[0]?.error) {
            injectionStatus.errors = [`executeScript framework error: ${results[0].error.message || results[0].error}`];
        }

        if (injectionStatus.success || injectionStatus.alreadyInjected) {
            if (!injectedFramesAgents.has(details.tabId)) {
                injectedFramesAgents.set(details.tabId, new Set());
            }
            injectedFramesAgents.get(details.tabId).add(details.frameId);
        }

    } catch (error) {
        if (!error.message?.includes("Cannot access") &&
            !error.message?.includes("No frame with id") &&
            !error.message?.includes("target frame detached") &&
            !error.message?.includes("The frame was removed") &&
            !error.message?.includes("Could not establish connection") &&
            !error.message?.includes("No tab with id")) {
            console.warn(`[BG WebNav] executeScript error T:${details.tabId}/F:${details.frameId}:`, error.message);
        }
        const tf = injectedFramesAgents.get(details.tabId);
        if (tf) { tf.delete(details.frameId); }
    }
}, { url: [{ schemes: ["http", "https"] }] });


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    let isAsync = false;
    let responseFunction = sendResponse;

    try {
        if (message.type === "runtimeListenerCaptured" && message.payload) {
            const { listenerCode, stackTrace, destinationUrl, context } = message.payload;
            const normalizedInfo = normalizeEndpointUrl(destinationUrl);
            const storageIdentifier = normalizedInfo?.normalized;

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
                            await chrome.storage.local.set({ [storageKey]: listeners });
                            response = { success: true, action: "saved" };
                            if (isValidListenerCode(listenerCode)) {
                                needsHandlerUpdateNotification = true;
                            }
                        } else {
                            response = { success: true, action: "duplicate" };
                            if (isValidListenerCode(listenerCode)) {
                                needsHandlerUpdateNotification = true;
                            }
                        }

                        if (isValidListenerCode(listenerCode)) {
                            if (!endpointsWithDetectedHandlers.has(storageIdentifier)) {
                                endpointsWithDetectedHandlers.add(storageIdentifier);
                                await saveHandlerEndpoints();
                                needsEndpointNotification = true;
                            }
                        }

                        if (needsEndpointNotification) {
                            notifyDashboard("handlerEndpointDetected", { endpointKey: storageIdentifier });
                        }
                        if (needsHandlerUpdateNotification) {
                            notifyDashboard("handlerCapturedForEndpoint", { endpointKey: storageIdentifier });
                        }

                    } catch (error) {
                        response = { success: false, error: error.message };
                        console.error(`[BG Save Err] Storage operation failed for ${storageKey}:`, error);
                    } finally {
                        if (responseFunction && !responseSent) {
                            try { responseFunction(response); responseSent = true; } catch (e) { /* Ignore */ }
                        }
                    }
                })();
                return true;
            } else {
                if (responseFunction) responseFunction({ success: false, error: "Missing listenerCode or invalid destinationUrl" });
                return false;
            }
        } else if (message.type === "postMessageCaptured") {
            const {origin, destinationUrl, data, messageType, timestamp} = message.payload;
            const destUrlStr = typeof destinationUrl === 'string' ? destinationUrl : 'unknown_frame_url';
            const messageData = {
                origin: origin || sender.origin || sender.tab?.url || 'unknown',
                destinationUrl: destUrlStr,
                data: data,
                messageType: messageType,
                timestamp: timestamp || new Date().toISOString(),
                messageId: `${timestamp || Date.now()}-${Math.random().toString(16).slice(2)}`
            };
            messageBuffer.push(messageData);
            const newConnection = addFrameConnection(messageData.origin, messageData.destinationUrl);
            notifyDashboard('newPostMessage', messageData);
            if (newConnection) {
                const connectionsPayload = {};
                frameConnections.forEach((v, k) => { connectionsPayload[k] = Array.from(v); });
                notifyDashboard('newFrameConnection', connectionsPayload);
            }
            if (responseFunction) responseFunction({success: true});
            return false;

        } else if (message.type === "fetchInitialState") {
            isAsync = true;
            (async () => {
                const messages = messageBuffer.getMessages();
                const handlerKeys = Array.from(endpointsWithDetectedHandlers);
                if (responseFunction) {
                    try {
                        responseFunction({ success: true, messages: messages, handlerEndpointKeys: handlerKeys });
                    } catch (e) { /* ignore */ }
                }
            })();
            return true;

        } else if (message.type === "resetState") {
            messageBuffer.clear();
            frameConnections.clear();
            injectedFramesAgents.clear();
            endpointsWithDetectedHandlers.clear();
            isAsync = true;
            (async () => {
                let response = { success: true, message: "State reset" };
                try {
                    const allData = await chrome.storage.local.get(null);
                    const keysToRemove = Object.keys(allData).filter(key => key.startsWith('runtime-listeners-') || key.startsWith('best-handler-') || key.startsWith('saved-messages-') || key.startsWith('trace-info-') || key.startsWith('analyzed-url-for-') || key.startsWith('analysis-storage-key-for-'));
                    if (keysToRemove.length > 0) {
                        await chrome.storage.local.remove(keysToRemove);
                    }
                    await chrome.storage.session.remove(HANDLER_ENDPOINT_KEYS_STORAGE_KEY);
                    if (self.traceReportStorage && typeof self.traceReportStorage.clearAllReports === 'function') {
                        await self.traceReportStorage.clearAllReports();
                    }
                } catch(storageError) {
                    console.error("[BG Reset] Error clearing storage:", storageError);
                    response = { success: false, message: "Error clearing storage", error: storageError.message };
                } finally {
                    if (responseFunction) {
                        try { responseFunction(response); } catch(e) {}
                    }
                }
            })();
            return true;
        } else if (message.action === "startServer") {
            isAsync = true;
            chrome.runtime.sendNativeMessage(
                'com.nodeserver.starter',
                { action: 'startServer', data: JSON.stringify(message.data), options: { port: 1337, maxRetries: 3, timeout: 5000 } },
                (response) => {
                    if (chrome.runtime.lastError) {
                        if (responseFunction) try { responseFunction({success: false, error: chrome.runtime.lastError.message}); } catch(e){}
                    } else if (response?.success) {
                        setTimeout(() => {
                            if (responseFunction) try { responseFunction({success: true}); } catch(e){}
                        }, 2000);
                    } else {
                        if (responseFunction) try { responseFunction({success: false, error: response?.error || "Failed to start server"}); } catch(e){}
                    }
                }
            );
            return true;
        } else if (message.action === "stopServer") {
            isAsync = true;
            chrome.runtime.sendNativeMessage('com.nodeserver.starter', { action: 'stopServer' }, (response) => {
                if (responseFunction) {
                    try { responseFunction({ success: !chrome.runtime.lastError && response?.success, error: chrome.runtime.lastError?.message || response?.error }); } catch(e){}
                }
            });
            return true;
        }

    } catch (error) {
        console.error("[Background] Top-level error processing message:", error, message);
        if (responseFunction) try { responseFunction({ success: false, error: "Handler error" }); } catch (e) {}
    }

    return isAsync;
});


chrome.action.onClicked.addListener((tab) => {
    chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/dashboard.html") });
});

chrome.runtime.onInstalled.addListener(details => {
    if (details.reason === 'install' || details.reason === 'update') {
        chrome.storage.session.remove(HANDLER_ENDPOINT_KEYS_STORAGE_KEY);
    }
    messageBuffer = new CircularMessageBuffer(1000);
    loadHandlerEndpoints();
});

loadHandlerEndpoints();

if (!messageBuffer) {
    messageBuffer = new CircularMessageBuffer(1000);
}
