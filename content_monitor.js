/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-27
 */
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

    const observerCallback = (mutationsList, observer) => {
        let currentPayloadIndex = lastKnownPayloadIndexFromFuzzer;
        for (const mutation of mutationsList) {
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
    };

    const observer = new MutationObserver(observerCallback);
    const config = { attributes: true, childList: true, subtree: true, attributeOldValue: false };

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
