/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-03
 */
let frameConnections = new Map();
let messageBuffer;
const injectedFramesAgents = new Map();

class CircularMessageBuffer {
    constructor(maxSize = 1000) { this.maxSize = maxSize; this.buffer = new Array(this.maxSize); this.head = 0; this.size = 0; }
    push(message) { message.messageId = message.messageId || `${message.timestamp || Date.now()}-${Math.random().toString(16).slice(2)}`; const existingIndex = this.findIndex(m => m.messageId === message.messageId); if (existingIndex !== -1) this.buffer[existingIndex] = message; else { this.buffer[this.head] = message; this.head = (this.head + 1) % this.maxSize; if (this.size < this.maxSize) this.size++; } }
    findIndex(predicate) { for (let i = 0; i < this.size; i++) { const index = (this.head - this.size + i + this.maxSize) % this.maxSize; if (this.buffer[index] !== undefined && predicate(this.buffer[index])) return index; } return -1; }
    getMessages() { const messages = []; for (let i = 0; i < this.size; i++) { const index = (this.head - this.size + i + this.maxSize) % this.maxSize; if (this.buffer[index] !== undefined) messages.push(this.buffer[index]); } return messages; }
    clear() { this.buffer = new Array(this.maxSize); this.head = 0; this.size = 0; }
}
messageBuffer = new CircularMessageBuffer(1000);

function normalizeEndpointUrl(url) {
    try {
        if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) return { normalized: url, components: null };
        let absoluteUrlStr = url;
        if (!url.includes('://') && !url.startsWith('//')) absoluteUrlStr = 'https:' + url;
        else if (url.startsWith('//')) absoluteUrlStr = 'https:' + url;
        const urlObj = new URL(absoluteUrlStr);
        if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:'].includes(urlObj.protocol)) return { normalized: url, components: null };
        const normalized = urlObj.origin + urlObj.pathname + urlObj.search;
        return {
            normalized: normalized,
            components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash }
        };
    } catch (e) {
        return { normalized: url, components: null };
    }
}

function getBaseUrl(url) { try { const norm = normalizeEndpointUrl(url); return norm?.components ? norm.components.origin + norm.components.path : null; } catch (e) { return null; } }
function addFrameConnection(origin, destinationUrl) { let addedNew = false; try { const normalizedOrigin = normalizeEndpointUrl(origin)?.normalized; const normalizedDestination = normalizeEndpointUrl(destinationUrl)?.normalized; if (!normalizedOrigin || !normalizedDestination || normalizedOrigin === 'null' || normalizedDestination === 'access-denied-or-invalid' || normalizedOrigin === normalizedDestination ) return false; if (!frameConnections.has(normalizedOrigin)) { frameConnections.set(normalizedOrigin, new Set()); addedNew = true; } const destSet = frameConnections.get(normalizedOrigin); if (!destSet.has(normalizedDestination)) { destSet.add(normalizedDestination); addedNew = true; } } catch (e) { } return addedNew; }
async function isDashboardOpen() { try { const dashboardUrl = chrome.runtime.getURL("dashboard/dashboard.html"); const tabs = await chrome.tabs.query({ url: dashboardUrl }); return tabs.length > 0; } catch (e) { return false; } }
async function notifyDashboard(type, payload) { if (!(await isDashboardOpen())) return; try { let serializablePayload; try { JSON.stringify(payload); serializablePayload = payload; } catch (e) { if (payload instanceof Map) serializablePayload = Object.fromEntries(payload); else if (payload instanceof Set) serializablePayload = Array.from(payload); else serializablePayload = { error: "Payload not serializable", type: payload?.constructor?.name }; } if (chrome?.runtime?.id) await chrome.runtime.sendMessage({ type: type, payload: serializablePayload }); } catch (error) { if (!error.message?.includes("Receiving end does not exist") && !error.message?.includes("Could not establish connection")) {} } }

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
    const safeToString = (func) => { try { return func.toString(); } catch (e) { return `[Error converting function: ${e?.message}]`; } };
    const sendListenerToForwarder = (listenerCode, contextInfo, destinationUrl) => {
        try {
            const codeStr = typeof listenerCode === 'string' ? listenerCode : safeToString(listenerCode);
            console.log(`[FrogPost Agent ${AGENT_VERSION}] Attempt Cap (${contextInfo}): Code length ${codeStr?.length}, Native: ${codeStr?.includes('[native code]')}`);
            if (!codeStr || codeStr.includes('[native code]') || codeStr.length < 25) { console.log(`[FrogPost Agent ${AGENT_VERSION}] Filtered out (${contextInfo})`); return; }
            const fingerprint = codeStr.replace(/\s+/g, '').substring(0, 250);
            if (capturedListenerSources.has(fingerprint)) { console.log(`[FrogPost Agent ${AGENT_VERSION}] Duplicate fingerprint (${contextInfo})`); return; }
            capturedListenerSources.add(fingerprint);
            let stack = ''; try { throw new Error('CaptureStack'); } catch (e) { stack = e.stack || ''; }
            const payload = { listenerCode: codeStr.substring(0, MAX_LISTENER_CODE_LENGTH), stackTrace: stack, destinationUrl: destinationUrl || window.location.href, context: contextInfo };
            console.log(`[FrogPost Agent ${AGENT_VERSION}] Posting to window (${contextInfo}) from:`, payload.destinationUrl);
            window.postMessage({ type: 'frogPostAgent->ForwardToBackground', payload: payload }, window.location.origin || '*');
        } catch (e) { console.error(`[FrogPost Agent ${AGENT_VERSION}] PostMessage ERROR (${contextInfo}): ${e.message}`, destinationUrl); errors.push(`sendListener Error (${contextInfo}): ${e.message}`); }
    };
    try {
        window.addEventListener = function (type, listener, options) {
            if (type === 'message' && typeof listener === 'function') { console.log(`[FrogPost Agent ${AGENT_VERSION}] HOOK: addEventListener('message') triggered.`); sendListenerToForwarder(listener, 'window.addEventListener', window.location.href); }
            return originalWindowAddEventListener.apply(this, arguments);
        };
    } catch (e) { errors.push(`addEventListener hook failed: ${e.message}`); window.addEventListener = originalWindowAddEventListener; }
    let _currentWindowOnmessage = window.onmessage;
    try {
        Object.defineProperty(window, 'onmessage', {
            set: function (listener) { console.log(`[FrogPost Agent ${AGENT_VERSION}] HOOK: window.onmessage = ... triggered.`); _currentWindowOnmessage = listener; if (typeof listener === 'function') { sendListenerToForwarder(listener, 'window.onmessage_set', window.location.href); } },
            get: function () { return _currentWindowOnmessage; },
            configurable: true, enumerable: true
        });
        if (typeof _currentWindowOnmessage === 'function') { console.log(`[FrogPost Agent ${AGENT_VERSION}] HOOK: Initial window.onmessage found.`); sendListenerToForwarder(_currentWindowOnmessage, 'window.onmessage_initial', window.location.href); }
    } catch (e) { errors.push(`onmessage hook failed: ${e.message}`); }
    try {
        const originalPortAddEventListener = MessagePort.prototype.addEventListener;
        MessagePort.prototype.addEventListener = function (type, listener, options) { try { if (type === 'message' && typeof listener === 'function') { console.log(`[FrogPost Agent ${AGENT_VERSION}] HOOK: port.addEventListener('message') triggered.`); sendListenerToForwarder(listener, 'port.addEventListener', window.location.href); } } catch(e) { errors.push(`port.addEventListener inner: ${e.message}`); } return originalPortAddEventListener.apply(this, arguments); };
        const portOnMessageDescriptor = Object.getOwnPropertyDescriptor(MessagePort.prototype, 'onmessage'); const originalPortSetter = portOnMessageDescriptor?.set; const originalPortGetter = portOnMessageDescriptor?.get; const portOnmessageTracker = new WeakMap();
        Object.defineProperty(MessagePort.prototype, 'onmessage', {
            set: function(listener) { try { console.log(`[FrogPost Agent ${AGENT_VERSION}] HOOK: port.onmessage = ... triggered.`); portOnmessageTracker.set(this, listener); if (typeof listener === 'function') { sendListenerToForwarder(listener, 'port.onmessage_set', window.location.href); } if (originalPortSetter) originalPortSetter.call(this, listener); } catch(e) { errors.push(`port.onmessage set inner: ${e.message}`); } },
            get: function() { try { let value = portOnmessageTracker.get(this); if (value === undefined && originalPortGetter) value = originalPortGetter.call(this); return value; } catch(e) { errors.push(`port.onmessage get inner: ${e.message}`); return undefined; } },
            configurable: true, enumerable: true
        });
    } catch (e) { errors.push(`MessagePort hook failed: ${e.message}`); }
    console.log(`[FrogPost Agent ${AGENT_VERSION}] Injection finished. Errors: ${errors.length}`);
    return { success: errors.length === 0, alreadyInjected: false, errors: errors, logsAdded: true };
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => { if (changeInfo.status === 'loading' && tabId) { injectedFramesAgents.delete(tabId); } });
chrome.tabs.onRemoved.addListener(tabId => { injectedFramesAgents.delete(tabId); });

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (!details.url || (!details.url.startsWith('http:') && !details.url.startsWith('https://')) || details.transitionType === 'server_redirect') { return; }
    const tabFrames = injectedFramesAgents.get(details.tabId);
    if (tabFrames?.has(details.frameId)) { return; }
    try {
        const results = await chrome.scripting.executeScript({
            target: { tabId: details.tabId, frameIds: [details.frameId] },
            injectImmediately: true,
            world: 'MAIN'
        });
        let injectionStatus = { success: false, alreadyInjected: false, errors: ["No result from executeScript"] };
        if (results?.[0]?.result) {
            injectionStatus = results[0].result;
        } else if (results?.[0]?.error) {
            injectionStatus.errors = [`executeScript framework error: ${results[0].error.message || results[0].error}`];
        } else {
            console.warn(`[BG WebNav] Injection Result UNKNOWN for T:${details.tabId}/F:${details.frameId}. Results:`, results);
        }
        if (injectionStatus.success || injectionStatus.alreadyInjected) { if (!injectedFramesAgents.has(details.tabId)) injectedFramesAgents.set(details.tabId, new Set()); injectedFramesAgents.get(details.tabId).add(details.frameId); }
    } catch (error) {
        if (!error.message?.includes("Cannot access") && !error.message?.includes("No frame with id") && !error.message?.includes("target frame detached") && !error.message?.includes("The frame was removed") && !error.message?.includes("Could not establish connection")){}
        const tf = injectedFramesAgents.get(details.tabId); if (tf) tf.delete(details.frameId);
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
                isAsync = true;
                (async () => {
                    let responseSent = false; let response = { success: false, error: "Storage operation did not complete" };
                    try {
                        console.log(`[BG onMessage] Getting existing listeners for key: ${storageKey}`);
                        const result = await chrome.storage.local.get([storageKey]);
                        let listeners = result[storageKey] || [];
                        const existingIndex = listeners.findIndex(l => l.code === listenerCode);
                        const newListenerData = { code: listenerCode, stack: stackTrace, timestamp: Date.now(), context: context };
                        if (existingIndex === -1) {
                            listeners.push(newListenerData);
                            if (listeners.length > 30) listeners = listeners.slice(-30);
                            console.log(`[BG onMessage] Saving NEW listener for key: ${storageKey}`);
                            await chrome.storage.local.set({ [storageKey]: listeners });
                            console.log(`[BG Save OK] Successfully saved listener data for ${storageKey}`);
                            response = { success: true, action: "saved" };
                        } else {
                            console.log(`[BG onMessage] Duplicate listener found for key: ${storageKey}`);
                            response = { success: true, action: "duplicate" };
                        }
                    } catch (error) { response = { success: false, error: error.message }; console.error(`[BG Save Err] Storage operation failed for ${storageKey}:`, error); }
                    finally { if (responseFunction && !responseSent) { try { responseFunction(response); responseSent = true; } catch (e) {} } }
                })();
                return true;
            } else { console.warn(`[BG onMessage] Invalid data for listener storage: Code: ${!!listenerCode}, URL: ${destinationUrl}, Identifier: ${storageIdentifier}`); if (responseFunction) responseFunction({ success: false, error: "Missing listenerCode or invalid destinationUrl" }); return false; }
        } else if (message.type === "postMessageCaptured") {
            const {origin, destinationUrl, data, messageType, timestamp} = message.payload; const destUrlStr = typeof destinationUrl === 'string' ? destinationUrl : 'unknown_frame_url'; const messageData = { origin: origin || sender.origin || sender.tab?.url || 'unknown', destinationUrl: destUrlStr, data: data, messageType: messageType, timestamp: timestamp || new Date().toISOString(), messageId: `${timestamp || Date.now()}-${Math.random().toString(16).slice(2)}` }; messageBuffer.push(messageData); const newConnection = addFrameConnection(messageData.origin, messageData.destinationUrl); notifyDashboard('newPostMessage', messageData); if (newConnection) { const connectionsPayload = {}; frameConnections.forEach((v, k) => { connectionsPayload[k] = Array.from(v); }); notifyDashboard('newFrameConnection', connectionsPayload); } if (responseFunction) responseFunction({success: true}); return false;
        } else if (message.type === "fetchMessages") {
            if (responseFunction) responseFunction({newMessages: messageBuffer.getMessages()}); return false;
        } else if (message.type === "resetState") {
            messageBuffer.clear(); frameConnections.clear(); injectedFramesAgents.clear(); isAsync = true; chrome.storage.local.clear(() => { const success = !chrome.runtime.lastError; if (responseFunction) responseFunction({ status: success ? "State reset" : "Error resetting", error: chrome.runtime.lastError?.message }); }); return true;
        }         else if (message.action === "startServer") {
            chrome.runtime.sendNativeMessage(
                'com.nodeserver.starter',
                {
                    action: 'startServer',
                    data: JSON.stringify(message.data),
                    options: {
                        port: 1337,
                        maxRetries: 3,
                        timeout: 5000
                    }
                },
                (response) => {
                    if (chrome.runtime.lastError) {
                        sendResponse({success: false, error: chrome.runtime.lastError.message});
                    } else if (response?.success) {
                        setTimeout(() => sendResponse({success: true}), 2000);
                    } else {
                        sendResponse({success: false, error: response?.error || "Failed to start server"});
                    }
                })
        } else if (message.action === "stopServer") {
            isAsync = true; chrome.runtime.sendNativeMessage('com.nodeserver.starter', { action: 'stopServer' }, (response) => { if (responseFunction) responseFunction({ success: !chrome.runtime.lastError && response?.success, error: chrome.runtime.lastError?.message || response?.error }); }); return true;
        }
    } catch (error) { console.error("[Background] Top-level error processing message:", error, message); if (responseFunction) try { responseFunction({ success: false, error: "Handler error" }); } catch (e) {} return false; }
    return isAsync;
});

chrome.action.onClicked.addListener((tab) => { chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/dashboard.html") }); });
chrome.runtime.onInstalled.addListener(details => { messageBuffer = new CircularMessageBuffer(1000); });
if (!messageBuffer) messageBuffer = new CircularMessageBuffer(1000);
