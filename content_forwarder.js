/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-15
 */
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

    window.addEventListener('message', (event) => {
        if (event.source === window && event.data?.type === 'frogPostAgent->ForwardToBackground') {
            if (chrome?.runtime?.id && chrome.runtime.sendMessage) {
                try {
                    chrome.runtime.sendMessage({ type: "runtimeListenerCaptured", payload: event.data.payload }, (response) => { if (chrome.runtime.lastError) {} else {} });
                } catch (e) {}
            }
        } else if (event.data && event.data.type === '__FROGPOST_SET_INDEX__') {
            return;
        } else {
            const messageInternalType = event.data?.type;
            if (typeof messageInternalType === 'string' && messageInternalType.startsWith('frogPostAgent')) {
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
