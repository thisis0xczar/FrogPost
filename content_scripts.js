/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor
 * Refined on: 2025-10-22
 */

// ============================================================================
// INJECT DOM AGENT INTO MAIN WORLD (CRITICAL!)
// ============================================================================
// The DOM agent MUST run in the MAIN world to intercept page's addEventListener
(async () => {
    try {
        // Inject the DOM agent script into MAIN world
        const script = document.createElement('script');
        script.src = chrome.runtime.getURL('dom_injection_agent.js');
        script.onload = () => script.remove();
        (document.head || document.documentElement).appendChild(script);
    } catch (e) {
        console.error('FrogPost: Failed to inject DOM agent into MAIN world:', e);
    }
})();

// ============================================================================
// CONTENT FORWARDER (ISOLATED WORLD)
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
        // console.log('Content script received message:', request);
        if (request.action === 'sendPostMessageToIframe') {
            // Use async to allow waiting for iframes to load
            (async () => {
                try {
                    const targetUrl = request.targetUrl;
                    let iframe = null;
                    
                    // Wait for iframes to load (Azure Portal loads them dynamically)
                    let allIframes = document.querySelectorAll('iframe');
                    let retries = 0;
                    const maxRetries = 10; // Wait up to 1 second
                    
                    while (allIframes.length === 0 && retries < maxRetries) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                        allIframes = document.querySelectorAll('iframe');
                        retries++;
                    }
                    
                    console.log('[FrogPost Content] Received send request for:', targetUrl);
                    console.log('[FrogPost Content] Total iframes on page:', allIframes.length, `(after ${retries * 100}ms wait)`);
                    
                    // Log all iframe sources for debugging
                    allIframes.forEach((frame, index) => {
                        console.log(`[FrogPost Content] Iframe ${index}:`, {
                            src: frame.src || '(no src)',
                            id: frame.id || '(no id)',
                            name: frame.name || '(no name)'
                        });
                    });

                    // Try to find iframe matching the target URL
                    if (targetUrl) {
                        try {
                            const targetUrlObj = new URL(targetUrl);
                            console.log('[FrogPost Content] Looking for:', targetUrlObj.hostname, targetUrlObj.pathname);
                            
                            // Try exact src match first
                            iframe = document.querySelector(`iframe[src="${targetUrl}"]`);
                            if (iframe) console.log('[FrogPost Content] Found by exact match');
                            
                            // Try partial match (hostname + pathname)
                            if (!iframe) {
                                for (const frame of allIframes) {
                                    if (frame.src) {
                                        try {
                                            const frameSrc = new URL(frame.src);
                                            // Match if hostname and pathname match
                                            if (frameSrc.hostname === targetUrlObj.hostname && 
                                                frameSrc.pathname === targetUrlObj.pathname) {
                                                iframe = frame;
                                                console.log('[FrogPost Content] Found by hostname+path match');
                                                break;
                                            }
                                        } catch (e) {
                                            // Invalid frame src, skip
                                        }
                                    }
                                }
                            }
                            
                            // If still not found, try matching just hostname
                            if (!iframe) {
                                for (const frame of allIframes) {
                                    if (frame.src) {
                                        try {
                                            const frameSrc = new URL(frame.src);
                                            if (frameSrc.hostname === targetUrlObj.hostname) {
                                                iframe = frame;
                                                console.log('[FrogPost Content] Found by hostname match');
                                                break;
                                            }
                                        } catch (e) {
                                            // Invalid frame src, skip
                                        }
                                    }
                                }
                            }
                        } catch (e) {
                            console.log('[FrogPost Content] URL parsing error:', e.message);
                        }
                    }
                    
                    // Final fallback: use first iframe if no match found
                    if (!iframe && allIframes.length > 0) {
                        iframe = allIframes[0];
                        console.log('[FrogPost Content] Using first available iframe as fallback');
                    }

                    if (iframe && iframe.contentWindow) {
                        iframe.contentWindow.postMessage(request.message, '*');
                        console.log('[FrogPost Content] ✓ Message sent to iframe');
                        sendResponse({ 
                            success: true, 
                            targetMatched: !!targetUrl,
                            debug: `Sent to iframe (${allIframes.length} total on page)`
                        });
                    } else {
                        console.warn('[FrogPost Content] ✗ No iframe found or no contentWindow');
                        const iframeList = Array.from(allIframes).map((f, i) => `${i}: ${f.src || '(no src)'}`).join(', ');
                        sendResponse({ 
                            success: false, 
                            error: allIframes.length === 0 ? 'No iframes on this page (waited 1s)' : `Found ${allIframes.length} iframes but none matched. Iframes: ${iframeList}` 
                        });
                    }
                } catch (error) {
                    console.error('[FrogPost Content] Error:', error);
                    sendResponse({ success: false, error: error.message });
                }
            })();
            
            return true; // Keep message channel open for async response
        }
    });

    window.addEventListener('message', (event) => {
        // NEW: Enhanced message forwarding
        if (event.source === window && event.data?.type === 'frogPostAgent->ForwardToBackground') {
            if (chrome?.runtime?.id && chrome.runtime.sendMessage) {
                try {
                    const payload = event.data.payload;
                    const topic = payload?.topic;
                    
                    // Forward with proper topic-based type
                    // Map topics to message types that background script expects
                    let messageType;
                    switch(topic) {
                        case 'handler-detected':  // Real-time handler capture (NEW)
                        case 'handlers-telemetry': // Old telemetry (DEPRECATED)
                        case 'handler-added':
                        case 'received-message':
                        case 'outgoing-message':
                        case 'agent-ready':
                            messageType = topic;
                            break;
                        default:
                            // Skip unknown topics (they're likely internal)
                            return;
                    }
                    
                    // Logging disabled to prevent flood
                    // console.log(`%c[FrogPost Forwarder]`, 'color: #ff6600; font-weight: bold', '🔄 Forwarding:', messageType);
                    
                    chrome.runtime.sendMessage({ 
                        type: messageType, 
                        payload: payload 
                    }, (response) => { 
                        if (chrome.runtime.lastError) {
                            // Silently ignore
                        }
                    });
                } catch (e) {
                    // Silently ignore
                }
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
                        // console.error('FrogPost DOM Agent Forwarder: Error sending message to background:', error);
                    });
                } else {
                    // console.warn('FrogPost DOM Agent Forwarder: chrome.runtime not available, skipping message forwarding');
                }
            } catch (error) {
                // console.error('FrogPost DOM Agent Forwarder: Error processing message:', error);
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
        // console.error("FrogPost Monitor: Failed to add index listener", e);
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
                    // console.warn("FrogPost Monitor: Error processing console log hook", e);
                }
                originalConsoleLog.apply(console, args);
            };
            window[CONSOLE_FLAG] = true;
        } catch (e) {
            // console.error("FrogPost Monitor: Failed to hook console.log", e);
        }
    }

    const SUSPICIOUS_TAGS = new Set(['SCRIPT', 'IFRAME', 'OBJECT', 'EMBED', 'APPLET', 'VIDEO', 'AUDIO', 'LINK', 'FORM', 'DETAILS', 'MARQUEE', 'SVG', 'MATH', 'BUTTON']);
    const SUSPICIOUS_ATTRS = new Set(['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onpageshow', 'onwheel', 'ontoggle', 'onbegin', 'formaction', 'srcdoc', 'background', 'style']);
    const SUSPICIOUS_ATTR_VALUES = /^(javascript:|vbscript:|data:)/i;
    const SUSPICIOUS_SRC_HREF_ATTRS = new Set(['src', 'href', 'action', 'formaction', 'background', 'data']);

    function getElementDescription(node) { if (!node || node.nodeType !== Node.ELEMENT_NODE) return 'NonElementNode'; let desc = `<${node.nodeName.toLowerCase()}`; for (const attr of node.attributes) { desc += ` ${attr.name}="${String(attr.value || '').substring(0, 20)}..."`; } return desc.substring(0, 100) + (desc.length > 100 ? '>...' : '>'); }

    function isSuspiciousMutation(mutation) { try { if (mutation.type === 'childList') { for (const node of mutation.addedNodes) { if (node.nodeType === Node.ELEMENT_NODE) { const nodeName = node.nodeName.toUpperCase(); if (SUSPICIOUS_TAGS.has(nodeName)) { return { reason: `Added suspicious tag: <${nodeName}>`, nodeInfo: node.outerHTML?.substring(0, 150) }; } if (node.matches && node.matches('[onerror], [onload], [onclick], [onmouseover], [onfocus]')) { return { reason: `Added node with suspicious event handler`, nodeInfo: node.outerHTML.substring(0, 100) }; } const suspiciousAttr = node.getAttributeNames().find(attr => SUSPICIOUS_ATTRS.has(attr.toLowerCase())); if(suspiciousAttr) { return { reason: `Added node with suspicious attribute: ${suspiciousAttr}`, nodeInfo: getElementDescription(node), attributeValue: node.getAttribute(suspiciousAttr)?.substring(0, 50) }; } for(const attrName of node.getAttributeNames()) { const lowerAttrName = attrName.toLowerCase(); if (SUSPICIOUS_SRC_HREF_ATTRS.has(lowerAttrName)) { const value = node.getAttribute(attrName); if(value && SUSPICIOUS_ATTR_VALUES.test(value)) { return { reason: `Added node with suspicious protocol in attribute: ${lowerAttrName}`, nodeInfo: getElementDescription(node), attributeValue: value.substring(0, 50) }; } } } if (nodeName === 'SCRIPT' && node.innerHTML?.length > 0) { return { reason: `Added script tag with content`, nodeInfo: node.outerHTML?.substring(0, 150) }; } } } } else if (mutation.type === 'attributes') { const attrName = mutation.attributeName?.toLowerCase(); const targetNode = mutation.target; if (targetNode?.nodeType !== Node.ELEMENT_NODE) return null; const targetDesc = getElementDescription(targetNode); if (SUSPICIOUS_ATTRS.has(attrName)) { const value = targetNode.getAttribute(mutation.attributeName); return { reason: `Suspicious attribute modified/added: ${attrName}`, target: targetNode.nodeName, value: value?.substring(0, 100), nodeInfo: targetDesc }; } if (SUSPICIOUS_SRC_HREF_ATTRS.has(attrName)) { const value = targetNode.getAttribute(mutation.attributeName); if(value && SUSPICIOUS_ATTR_VALUES.test(value)) { return { reason: `Suspicious protocol set for attribute: ${attrName}`, target: targetNode.nodeName, value: value.substring(0, 100), nodeInfo: targetDesc }; } } } } catch(e) { /* console.warn("FrogPost Monitor: Error checking mutation", e); */ } return null; }

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
                } catch (e) { /* console.warn("FrogPost Monitor: Failed to send mutation message", e); */ }
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
        const observeBody = () => { if (document.body && !bodyObserverActive) { try { observer.disconnect(); } catch(e){} try { observer.observe(document.body, config); bodyObserverActive = true; } catch(e) { /* console.error("FrogPost Monitor: Failed to observe document.body", e); */ } } };
        try { observer.observe(initialTarget, { childList: true, subtree: true }); } catch(e) { /* console.error("FrogPost Monitor: Failed to observe documentElement", e); */ return; }
        if (document.body) { observeBody(); }
        else { const bodyWaitObserver = new MutationObserver(() => { if (document.body) { bodyWaitObserver.disconnect(); observeBody(); } }); try { bodyWaitObserver.observe(document.documentElement, { childList: true }); } catch(e) { /* console.error("FrogPost Monitor: Failed to observe documentElement for body wait", e); */ if(document.body) observeBody(); } }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startObserving, { once: true });
    } else {
        startObserving();
    }
})();

// ============================================================================
// REAL TIME DETECTOR (DEPRECATED - REPLACED BY ADVANCED DOM AGENT)
// ============================================================================
// The old RealTimeHandlerDetector has been REMOVED and replaced by the new
// FrogPost DOM agent in dom_injection_agent.js which provides 95%+ accuracy.
// Code removed to prevent conflicts and reduce extension size.
