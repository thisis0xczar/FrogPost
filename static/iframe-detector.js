/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-09-17
 */

(() => {
    if (window.__frogPostRealTimeDetector_v1) return;
    window.__frogPostRealTimeDetector_v1 = true;
    
    // Inject simplified detector for iframe
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'message') {
            parent.postMessage({
                type: 'frogPostIframeHandler',
                data: {
                    target: this.tagName || 'window',
                    timestamp: new Date().toISOString(),
                    location: window.location.href
                }
            }, '*');
        }
        return originalAddEventListener.call(this, type, listener, options);
    };
})();
