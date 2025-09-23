/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor
 * Refined on: 2025-09-17
 */

// ============================================================================
// CONTENT FORWARDER
// ============================================================================
(() => {
    const FORWARDER_FLAG = '__frogPostForwarderInjected_v2';
    if (window[FORWARDER_FLAG]) return;
    window[FORWARDER_FLAG] = true;

    function safeGetLocation(win) {
        try {
            if (win?.location?.href) return win.location.href;
        } catch (e) {}
        return 'access-denied-or-invalid';
    }

    // Handle messages from extension to send to iframe
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        console.log('Content script received message:', request);
        if (request.action === 'sendPostMessageToIframe') {
            try {
                console.log('Looking for iframe on page...');
                const iframe = document.querySelector('iframe');
                console.log('Found iframe:', iframe);

                if (iframe && iframe.contentWindow) {
                    console.log('Sending postMessage to iframe:', request.message);
                    iframe.contentWindow.postMessage(request.message, '*');
                    console.log('Content script sent message to iframe:', request.message);
                    sendResponse({ success: true });
                } else {
                    console.log('No iframe found to send message to');
                    sendResponse({ success: false, error: 'No iframe found' });
                }
            } catch (error) {
                console.error('Error sending message to iframe:', error);
                sendResponse({ success: false, error: error.message });
            }
            return true; // Keep message channel open for async response
        }
    });

    window.addEventListener('message', (event) => {
        if (event.source === window && event.data?.type === 'frogPostAgent->ForwardToBackground') {
            if (chrome?.runtime?.id && chrome.runtime.sendMessage) {
                try {
                    chrome.runtime.sendMessage({ type: "runtimeListenerCaptured", payload: event.data.payload }, (response) => { if (chrome.runtime.lastError) {} else {} });
                } catch (e) {}
            }
        } else if (event.data && event.data.type === '__FROGPOST_SET_INDEX__') {
            return;
        } else if (event.data && event.data.type && event.data.type.startsWith('frogPostDOMAgent')) {
            // Check if this is a message from our DOM agent
            try {
                // Forward to background script (only if chrome.runtime is available)
                if (chrome?.runtime?.sendMessage) {
                    chrome.runtime.sendMessage({
                        type: event.data.type,
                        payload: event.data.data
                    }).catch(error => {
                        console.error('FrogPost DOM Agent Forwarder: Error sending message to background:', error);
                    });
                } else {
                    console.warn('FrogPost DOM Agent Forwarder: chrome.runtime not available, skipping message forwarding');
                }
            } catch (error) {
                console.error('FrogPost DOM Agent Forwarder: Error processing message:', error);
            }
            return;
        } else {
            const messageInternalType = event.data?.type;
            if (typeof messageInternalType === 'string' && (messageInternalType.startsWith('frogPostAgent') || messageInternalType.startsWith('frogPostDOMAgent'))) {
                return;
            }
            if (!event.source) return;

            try {
                let messageType = 'unknown';
                const data = event.data;
                if (data === undefined) messageType = "undefined";
                else if (data === null) messageType = "null";
                else if (Array.isArray(data)) messageType = "array";
                else if (typeof data === 'object') messageType = data.constructor === Object ? "object" : "special_object";
                else if (typeof data === 'string') messageType = (data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']')) ? "potential_json_string" : "string";
                else messageType = typeof data;
                const destination = safeGetLocation(window);
                if (chrome?.runtime?.id) {
                    // Filter out extension-generated messages by common markers
                    if (typeof data === 'object' && data && typeof data.type === 'string') {
                        const t = data.type;
                        if (t.startsWith('frogPost') || t.startsWith('FROGPOST_') || t === 'realTimeDetectorReady' || t === 'realTimeHandlerDetected' || t === 'realTimeMessageSent') {
                            return;
                        }
                    }
                    // Filter the special breakpoint probe messages
                    if (typeof data === 'string' && data === 'FrogPost::BreakpointTest') {
                        return;
                    }
                    if (typeof data === 'object' && data !== null && data.FrogPost === 'BreakpointTest') {
                        return;
                    }
                    chrome.runtime.sendMessage({
                        type: "postMessageCaptured",
                        payload: { origin: event.origin || 'unknown-origin', destinationUrl: destination, data: data, messageType: messageType, timestamp: new Date().toISOString(), }
                    }).catch(error => {});
                }
            } catch (e) { }
        }
    }, true);

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === "forwardedPostMessage") {
            window.postMessage(message.data, '*');
            if (sendResponse) sendResponse({ success: true });
            return false;
        }
        return false;
    });

    if(chrome?.runtime?.id) {
        chrome.runtime.sendMessage({ type: "contentScriptReady", url: window.location.href }).catch(error => {});
    }
})();

// ============================================================================
// CONTENT MONITOR
// ============================================================================
(() => {
    const MONITOR_FLAG = '__frogPostMonitorInjected_v3';
    const CONSOLE_FLAG = '__frogPostConsoleHooked_v2';
    if (window[MONITOR_FLAG]) {
        return;
    }
    window[MONITOR_FLAG] = true;

    const CONSOLE_MARKER = "FROGPWNED_CONSOLE_XSS";
    let lastKnownPayloadIndexFromFuzzer = -1;

    try {
        window.addEventListener('message', (event) => {
            if (event.source === window.parent && event.data && event.data.type === '__FROGPOST_SET_INDEX__' && typeof event.data.index === 'number') {
                lastKnownPayloadIndexFromFuzzer = event.data.index;
            }
        }, false);
    } catch(e) {
        console.error("FrogPost Monitor: Failed to add index listener", e);
    }

    if (!window[CONSOLE_FLAG]) {
        try {
            const originalConsoleLog = window.console.log;
            window.console.log = function(...args) {
                let markerFound = false;
                let detectedPayloadIndex = lastKnownPayloadIndexFromFuzzer;
                try {
                    if (args.some(arg => typeof arg === 'string' && arg.includes(CONSOLE_MARKER))) {
                        markerFound = true;
                        if (chrome?.runtime?.id) {
                            chrome.runtime.sendMessage({
                                type: "FROGPOST_CONSOLE_SUCCESS",
                                detail: { markerFound: true, firstArg: String(args[0]).substring(0, 100), timestamp: new Date().toISOString() },
                                location: window.location.href,
                                payloadIndex: detectedPayloadIndex
                            }).catch(e => {});
                        }
                    }
                } catch (e) {
                    console.warn("FrogPost Monitor: Error processing console log hook", e);
                }
                originalConsoleLog.apply(console, args);
            };
            window[CONSOLE_FLAG] = true;
        } catch (e) {
            console.error("FrogPost Monitor: Failed to hook console.log", e);
        }
    }

    const SUSPICIOUS_TAGS = new Set(['SCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'APPLET', 'VIDEO', 'AUDIO', 'LINK', 'FORM', 'DETAILS', 'MARQUEE', 'SVG', 'MATH', 'BUTTON']);
    const SUSPICIOUS_ATTRS = new Set(['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onpageshow', 'onwheel', 'ontoggle', 'onbegin', 'formaction', 'srcdoc', 'background', 'style']);
    const SUSPICIOUS_ATTR_VALUES = /^(javascript:|vbscript:|data:)/i;
    const SUSPICIOUS_SRC_HREF_ATTRS = new Set(['src', 'href', 'action', 'formaction', 'background', 'data']);

    function getElementDescription(node) { if (!node || node.nodeType !== Node.ELEMENT_NODE) return 'NonElementNode'; let desc = `<${node.nodeName.toLowerCase()}`; for (const attr of node.attributes) { desc += ` ${attr.name}="${String(attr.value || '').substring(0, 20)}..."`; } return desc.substring(0, 100) + (desc.length > 100 ? '>...' : '>'); }

    function isSuspiciousMutation(mutation) { try { if (mutation.type === 'childList') { for (const node of mutation.addedNodes) { if (node.nodeType === Node.ELEMENT_NODE) { const nodeName = node.nodeName.toUpperCase(); if (SUSPICIOUS_TAGS.has(nodeName)) { return { reason: `Added suspicious tag: <${nodeName}>`, nodeInfo: node.outerHTML?.substring(0, 150) }; } if (node.matches && node.matches('[onerror], [onload], [onclick], [onmouseover], [onfocus]')) { return { reason: `Added node with suspicious event handler`, nodeInfo: node.outerHTML.substring(0, 100) }; } const suspiciousAttr = node.getAttributeNames().find(attr => SUSPICIOUS_ATTRS.has(attr.toLowerCase())); if(suspiciousAttr) { return { reason: `Added node with suspicious attribute: ${suspiciousAttr}`, nodeInfo: getElementDescription(node), attributeValue: node.getAttribute(suspiciousAttr)?.substring(0, 50) }; } for(const attrName of node.getAttributeNames()) { const lowerAttrName = attrName.toLowerCase(); if (SUSPICIOUS_SRC_HREF_ATTRS.has(lowerAttrName)) { const value = node.getAttribute(attrName); if(value && SUSPICIOUS_ATTR_VALUES.test(value)) { return { reason: `Added node with suspicious protocol in attribute: ${lowerAttrName}`, nodeInfo: getElementDescription(node), attributeValue: value.substring(0, 50) }; } } } if (nodeName === 'SCRIPT' && node.innerHTML?.length > 0) { return { reason: `Added script tag with content`, nodeInfo: node.outerHTML?.substring(0, 150) }; } } } } else if (mutation.type === 'attributes') { const attrName = mutation.attributeName?.toLowerCase(); const targetNode = mutation.target; if (targetNode?.nodeType !== Node.ELEMENT_NODE) return null; const targetDesc = getElementDescription(targetNode); if (SUSPICIOUS_ATTRS.has(attrName)) { const value = targetNode.getAttribute(mutation.attributeName); return { reason: `Suspicious attribute modified/added: ${attrName}`, target: targetNode.nodeName, value: value?.substring(0, 100), nodeInfo: targetDesc }; } if (SUSPICIOUS_SRC_HREF_ATTRS.has(attrName)) { const value = targetNode.getAttribute(mutation.attributeName); if(value && SUSPICIOUS_ATTR_VALUES.test(value)) { return { reason: `Suspicious protocol set for attribute: ${attrName}`, target: targetNode.nodeName, value: value.substring(0, 100), nodeInfo: targetDesc }; } } } } catch(e) { console.warn("FrogPost Monitor: Error checking mutation", e); } return null; }

    // Throttle mutation processing to prevent performance issues
    let mutationThrottleTimeout = null;
    const mutationQueue = [];

    const processMutations = () => {
        if (mutationQueue.length === 0) return;

        let currentPayloadIndex = lastKnownPayloadIndexFromFuzzer;
        const mutationsToProcess = mutationQueue.splice(0, 10); // Process max 10 mutations at a time

        for (const mutation of mutationsToProcess) {
            const suspiciousDetail = isSuspiciousMutation(mutation);
            if (suspiciousDetail) {
                try {
                    suspiciousDetail.timestamp = new Date().toISOString();
                    if (chrome?.runtime?.id) {
                        chrome.runtime.sendMessage({ type: "FROGPOST_MUTATION", detail: suspiciousDetail, location: window.location.href, payloadIndex: currentPayloadIndex }).catch(e => {});
                    } else { observer.disconnect(); break; }
                } catch (e) { console.warn("FrogPost Monitor: Failed to send mutation message", e); }
            }
        }

        // Continue processing if there are more mutations
        if (mutationQueue.length > 0) {
            mutationThrottleTimeout = setTimeout(processMutations, 50);
        }
    };

    const observerCallback = (mutationsList, observer) => {
        // Add mutations to queue
        mutationQueue.push(...mutationsList);

        // Throttle processing to prevent excessive CPU usage
        if (!mutationThrottleTimeout) {
            mutationThrottleTimeout = setTimeout(processMutations, 100);
        }
    };

    const observer = new MutationObserver(observerCallback);
    // Optimized config: reduced scope and added throttling
    const config = {
        attributes: true,
        childList: true,
        subtree: false, // Only observe direct children, not entire subtree
        attributeOldValue: false,
        attributeFilter: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onpageshow', 'onwheel', 'ontoggle', 'onbegin', 'formaction', 'srcdoc', 'background', 'style'] // Only watch specific attributes
    };

    const startObserving = () => {
        const initialTarget = document.documentElement;
        let bodyObserverActive = false;
        const observeBody = () => { if (document.body && !bodyObserverActive) { try { observer.disconnect(); } catch(e){} try { observer.observe(document.body, config); bodyObserverActive = true; } catch(e) { console.error("FrogPost Monitor: Failed to observe document.body", e); } } };
        try { observer.observe(initialTarget, { childList: true, subtree: true }); } catch(e) { console.error("FrogPost Monitor: Failed to observe documentElement", e); return; }
        if (document.body) { observeBody(); }
        else { const bodyWaitObserver = new MutationObserver(() => { if (document.body) { bodyWaitObserver.disconnect(); observeBody(); } }); try { bodyWaitObserver.observe(document.documentElement, { childList: true }); } catch(e) { console.error("FrogPost Monitor: Failed to observe documentElement for body wait", e); if(document.body) observeBody(); } }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startObserving, { once: true });
    } else {
        startObserving();
    }
})();

// ============================================================================
// REAL TIME DETECTOR
// ============================================================================
(() => {
    const DETECTOR_FLAG = '__frogPostRealTimeDetector_v1';
    if (window[DETECTOR_FLAG]) return;
    window[DETECTOR_FLAG] = true;

    class RealTimeHandlerDetector {
        constructor() {
            this.detectedHandlers = new Map();
            this.messageEvents = new Map();
            this.iframeHandlers = new Map();
            this.originalMethods = {};
            this.isMonitoring = true;

            this.initialize();
        }

        initialize() {
            try {
                this.overrideAddEventListener();
                this.overridePostMessage();
                this.monitorExistingListeners();
                this.setupIframeMonitoring();
                this.reportInitialState();
            } catch (error) {
                console.error('FrogPost RealTimeDetector: Initialization failed', error);
            }
        }

        /**
         * Override addEventListener to catch message handlers as they're registered
         */
        overrideAddEventListener() {
            const self = this;
            this.originalMethods.addEventListener = EventTarget.prototype.addEventListener;

            EventTarget.prototype.addEventListener = function(type, listener, options) {
                if (type === 'message' && self.isMonitoring) {
                    self.detectMessageHandler(this, listener, options);
                }
                return self.originalMethods.addEventListener.call(this, type, listener, options);
            };
        }

        /**
         * Override postMessage to log all outgoing messages
         */
        overridePostMessage() {
            const self = this;
            this.originalMethods.postMessage = window.postMessage;

            window.postMessage = function(message, targetOrigin, transfer) {
                if (self.isMonitoring) {
                    self.logPostMessage(message, targetOrigin, transfer);
                }
                return self.originalMethods.postMessage.call(this, message, targetOrigin, transfer);
            };
        }

        /**
         * Detect and analyze message event handlers
         */
        detectMessageHandler(target, listener, options) {
            try {
                // Filter out extension-injected handlers
                if (this.isExtensionHandler(listener)) {
                    console.log('FrogPost: Filtered out extension handler:', listener.toString().substring(0, 100));
                    return; // Skip extension handlers
                }

                const handlerInfo = {
                    id: this.generateHandlerId(),
                    target: this.getTargetInfo(target),
                    listener: this.analyzeListener(listener),
                    options: options,
                    timestamp: new Date().toISOString(),
                    location: window.location.href,
                    frameType: this.getFrameType()
                };

                this.detectedHandlers.set(handlerInfo.id, handlerInfo);
                this.reportHandlerDetection(handlerInfo);

                console.log('FrogPost: Real-time handler detected', handlerInfo);
            } catch (error) {
                console.error('FrogPost: Error detecting handler', error);
            }
        }

        /**
         * Log postMessage calls for analysis
         */
        logPostMessage(message, targetOrigin, transfer) {
            try {
                // Filter out extension messages
                if (this.isExtensionMessage(message)) {
                    console.log('FrogPost: Filtered out extension message:', JSON.stringify(message).substring(0, 100));
                    return; // Skip extension messages
                }

                const messageInfo = {
                    id: this.generateMessageId(),
                    data: message,
                    targetOrigin: targetOrigin,
                    transfer: transfer,
                    timestamp: new Date().toISOString(),
                    source: window.location.href,
                    frameType: this.getFrameType()
                };

                this.messageEvents.set(messageInfo.id, messageInfo);
                this.reportMessageSent(messageInfo);
                console.log('FrogPost: Real-time message logged', messageInfo);
            } catch (error) {
                console.error('FrogPost: Error logging postMessage', error);
            }
        }

        /**
         * Monitor existing event listeners on page load
         */
        monitorExistingListeners() {
            try {
                // Check if window already has message listeners
                const hasMessageListeners = this.checkExistingListeners(window);
                if (hasMessageListeners) {
                    this.reportExistingListeners();
                }

                // Also check for onmessage handlers
                if (window.onmessage && typeof window.onmessage === 'function') {
                    console.log('FrogPost: Found existing onmessage handler');
                    this.detectMessageHandler(window, window.onmessage, null);
                }

                // Check for any existing addEventListener calls we might have missed
                setTimeout(() => {
                    this.scanForExistingHandlers();
                }, 1000);
            } catch (error) {
                console.error('FrogPost: Error monitoring existing listeners', error);
            }
        }

        /**
         * Scan for existing handlers that might have been added before our detector
         */
        scanForExistingHandlers() {
            try {
                // This is a simplified scan - we can't easily detect all existing listeners
                // but we can check for common patterns
                console.log('FrogPost: Scanning for existing message handlers...');

                // Check if there are any message event listeners on common targets
                const targets = [window, document];
                targets.forEach(target => {
                    if (target.onmessage && typeof target.onmessage === 'function') {
                        console.log('FrogPost: Found onmessage handler on', target.constructor.name);
                        this.detectMessageHandler(target, target.onmessage, null);
                    }
                });
            } catch (error) {
                console.error('FrogPost: Error scanning for existing handlers', error);
            }
        }

        /**
         * Setup monitoring for dynamically created iframes
         */
        setupIframeMonitoring() {
            const self = this;

            // Monitor for new iframes
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.tagName === 'IFRAME') {
                            self.monitorNewIframe(node);
                        }
                    });
                });
            });

            observer.observe(document.body || document.documentElement, {
                childList: true,
                subtree: true
            });
        }

        /**
         * Monitor newly created iframe
         */
        monitorNewIframe(iframe) {
            try {
                iframe.addEventListener('load', () => {
                    try {
                        // Try to access iframe content (may fail due to CORS)
                        const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
                        if (iframeDoc) {
                            this.injectDetectorIntoIframe(iframeDoc);
                        }
                    } catch (error) {
                        // CORS restriction - iframe is cross-origin
                        this.reportCrossOriginIframe(iframe);
                    }
                });
            } catch (error) {
                console.error('FrogPost: Error monitoring iframe', error);
            }
        }

        /**
         * Inject detector into iframe content
         */
        injectDetectorIntoIframe(iframeDoc) {
            try {
                const script = iframeDoc.createElement('script');
                script.src = chrome.runtime.getURL('static/iframe-detector.js');
                script.onload = () => script.remove();
                iframeDoc.head.appendChild(script);
            } catch (error) {
                console.error('FrogPost: Error injecting into iframe', error);
            }
        }

        /**
         * Check if a handler is from the extension (should be filtered out)
         */
        isExtensionHandler(listener) {
            try {
                if (typeof listener !== 'function') {
                    return false;
                }

                const source = listener.toString();

                // Check for FrogPost extension patterns (more specific to avoid false positives)
                const extensionPatterns = [
                    'frogPostIframeHandler',
                    'frogPostAgent->ForwardToBackground',
                    '__FROGPOST_SET_INDEX__',
                    'chrome.runtime.sendMessage',
                    'chrome?.runtime?.id',
                    '__frogPostRealTimeDetector'
                ];

                // Only filter if we find very specific extension patterns
                return extensionPatterns.some(pattern => source.includes(pattern));
            } catch (error) {
                return false; // If we can't analyze, assume it's not an extension handler
            }
        }

        /**
         * Check if a message is from the extension (should be filtered out)
         */
        isExtensionMessage(message) {
            try {
                if (!message || typeof message !== 'object') {
                    return false;
                }

                // Check for specific extension message types
                if (message.type) {
                    const extensionTypes = [
                        'frogPostIframeHandler',
                        'frogPostAgent->ForwardToBackground',
                        '__FROGPOST_SET_INDEX__',
                        'realTimeHandlerDetected',
                        'realTimeMessageSent',
                        'realTimeDetectorReady'
                    ];

                    if (extensionTypes.includes(message.type)) {
                        return true;
                    }
                }

                // Check message content for extension patterns
                const messageStr = JSON.stringify(message);
                const extensionPatterns = [
                    'frogPostIframeHandler',
                    'frogPostAgent->ForwardToBackground',
                    '__FROGPOST_SET_INDEX__',
                    'chrome.runtime.sendMessage',
                    'chrome?.runtime?.id'
                ];

                return extensionPatterns.some(pattern => messageStr.includes(pattern));
            } catch (error) {
                return false; // If we can't analyze, assume it's not an extension message
            }
        }

        /**
         * Analyze listener function to extract useful information
         */
        analyzeListener(listener) {
            try {
                return {
                    type: typeof listener,
                    isFunction: typeof listener === 'function',
                    isObject: typeof listener === 'object' && listener !== null,
                    hasHandleEvent: typeof listener === 'object' && typeof listener.handleEvent === 'function',
                    source: listener.toString ? listener.toString().substring(0, 200) : 'unknown'
                };
            } catch (error) {
                return { type: 'unknown', error: error.message };
            }
        }

        /**
         * Get information about the event target
         */
        getTargetInfo(target) {
            try {
                if (target === window) {
                    return { type: 'window', url: window.location.href };
                } else if (target === document) {
                    return { type: 'document', url: window.location.href };
                } else if (target.nodeType) {
                    return {
                        type: 'element',
                        tagName: target.tagName,
                        id: target.id,
                        className: target.className
                    };
                } else {
                    return { type: 'unknown', target: target };
                }
            } catch (error) {
                return { type: 'error', error: error.message };
            }
        }

        /**
         * Determine frame type
         */
        getFrameType() {
            try {
                if (window === window.top) {
                    return 'top';
                } else if (window.parent !== window.top) {
                    return 'nested';
                } else {
                    return 'iframe';
                }
            } catch (error) {
                return 'unknown';
            }
        }

        /**
         * Check for existing message listeners
         */
        checkExistingListeners(target) {
            try {
                // This is a simplified check - full detection requires debugger
                return target.onmessage !== null ||
                    (target._listeners && target._listeners.message) ||
                    false;
            } catch (error) {
                return false;
            }
        }

        /**
         * Generate unique handler ID
         */
        generateHandlerId() {
            return `handler_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

        /**
         * Generate unique message ID
         */
        generateMessageId() {
            return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

        /**
         * Report handler detection to background script
         */
        reportHandlerDetection(handlerInfo) {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeHandlerDetected',
                    payload: handlerInfo
                }).catch(error => {
                    console.error('FrogPost: Error reporting handler detection', error);
                });
            }
        }

        /**
         * Report message sent to background script
         */
        reportMessageSent(messageInfo) {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeMessageSent',
                    payload: messageInfo
                }).catch(error => {
                    console.error('FrogPost: Error reporting message sent', error);
                });
            }
        }

        /**
         * Report existing listeners
         */
        reportExistingListeners() {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeExistingListeners',
                    payload: {
                        location: window.location.href,
                        timestamp: new Date().toISOString(),
                        frameType: this.getFrameType()
                    }
                }).catch(error => {
                    console.error('FrogPost: Error reporting existing listeners', error);
                });
            }
        }

        /**
         * Report cross-origin iframe
         */
        reportCrossOriginIframe(iframe) {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeCrossOriginIframe',
                    payload: {
                        src: iframe.src,
                        timestamp: new Date().toISOString(),
                        parentLocation: window.location.href
                    }
                }).catch(error => {
                    console.error('FrogPost: Error reporting cross-origin iframe', error);
                });
            }
        }

        /**
         * Report initial state
         */
        reportInitialState() {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeDetectorReady',
                    payload: {
                        location: window.location.href,
                        timestamp: new Date().toISOString(),
                        frameType: this.getFrameType(),
                        userAgent: navigator.userAgent
                    }
                }).catch(error => {
                    console.error('FrogPost: Error reporting initial state', error);
                });
            }
        }

        /**
         * Get detection statistics
         */
        getStats() {
            return {
                handlersDetected: this.detectedHandlers.size,
                messagesLogged: this.messageEvents.size,
                isMonitoring: this.isMonitoring
            };
        }

        /**
         * Stop monitoring (cleanup)
         */
        stop() {
            this.isMonitoring = false;

            // Restore original methods
            if (this.originalMethods.addEventListener) {
                EventTarget.prototype.addEventListener = this.originalMethods.addEventListener;
            }
            if (this.originalMethods.postMessage) {
                window.postMessage = this.originalMethods.postMessage;
            }
        }
    }

    // Initialize the real-time detector
    const detector = new RealTimeHandlerDetector();

    // Listen for iframe handler reports
    window.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'frogPostIframeHandler') {
            if (chrome?.runtime?.id) {
                chrome.runtime.sendMessage({
                    type: 'realTimeIframeHandler',
                    payload: event.data.data
                }).catch(error => {
                    console.error('FrogPost: Error reporting iframe handler', error);
                });
            }
        }
    });

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        detector.stop();
    });

    console.log('FrogPost: Real-time handler detector initialized');
})();
