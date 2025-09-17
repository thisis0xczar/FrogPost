/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-09-17
 */

(() => {
    try {
        if (window.__frogPostDOMChildAgent) return;
        window.__frogPostDOMChildAgent = true;
        
        // Get parent agent ID from the script tag's data attribute or use a default
        const PARENT_AGENT_ID = window.__frogPostAgentId || 'unknown';
        
        const originalAdd = EventTarget.prototype.addEventListener;
        const safeToString = (fn) => { 
            try { 
                return fn.toString(); 
            } catch (e) { 
                return '[toString failed]'; 
            } 
        };
        
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            try {
                if (type === 'message' && typeof listener === 'function') {
                    const payload = {
                        id: 'child_' + Date.now() + '_' + Math.random().toString(36).slice(2),
                        agentId: PARENT_AGENT_ID,
                        target: { type: 'window', url: window.location.href },
                        listener: { 
                            type: typeof listener, 
                            isFunction: true, 
                            source: safeToString(listener).substring(0, 2000), 
                            length: listener.length || 0 
                        },
                        options: options,
                        timestamp: Date.now(),
                        location: window.location.href,
                        method: 'iframe.addEventListener',
                        isIframe: true
                    };
                    parent.postMessage({ type: 'frogPostDOMAgentHandler', data: payload }, '*');
                }
            } catch {}
            return originalAdd.apply(this, arguments);
        };
        
        // Override onmessage property
        let _onmsg = window.onmessage;
        Object.defineProperty(window, 'onmessage', { 
            configurable: true, 
            enumerable: true, 
            get: function(){ 
                return _onmsg; 
            }, 
            set: function(v){ 
                _onmsg = v; 
                try { 
                    if (typeof v === 'function') { 
                        const payload = { 
                            id: 'child_' + Date.now() + '_' + Math.random().toString(36).slice(2), 
                            agentId: PARENT_AGENT_ID, 
                            target: { type: 'window', url: window.location.href }, 
                            listener: { 
                                type: typeof v, 
                                isFunction: true, 
                                source: safeToString(v).substring(0, 2000), 
                                length: v.length || 0 
                            }, 
                            options: null, 
                            timestamp: Date.now(), 
                            location: window.location.href, 
                            method: 'iframe.onmessage_set', 
                            isIframe: true 
                        }; 
                        parent.postMessage({ type: 'frogPostDOMAgentHandler', data: payload }, '*'); 
                    } 
                } catch {} 
            } 
        });
    } catch (e) { 
        parent.postMessage({ 
            type: 'frogPostDOMAgentMessage', 
            data: { 
                agentId: PARENT_AGENT_ID, 
                error: 'Child agent init failed: ' + (e && e.message), 
                timestamp: Date.now(), 
                location: window.location.href, 
                isIframe: true 
            } 
        }, '*'); 
    }
})();
