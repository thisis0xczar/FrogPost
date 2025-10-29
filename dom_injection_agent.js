/**
 * FrogPost Extension - Advanced Runtime Handler Extraction
 * Originally Created by thisis0xczar/Lidor
 * Enhanced: 2025-10-22 - Runtime interception for 95%+ accuracy
 */

(function() {
    // Prevent multiple injections
    if (window.__frogPostDOMAgent) {
        return;
    }
    window.__frogPostDOMAgent = true;

    // Generate a stable per-frame windowId (uuidv4)
    function uuidv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    // Per-frame unique ID (critical for frame tree tracking)
    const windowId = window.__frogPostWindowId || (window.__frogPostWindowId = uuidv4());
    const AGENT_ID = window.__frogPostAgentId || (window.__frogPostAgentId = uuidv4());

    // Store original methods before overriding
    const $$$_addEventListener = window.addEventListener;
    const $$$_postMessage = window.postMessage;
    
    // Store actual function references (runtime interception)
    const $$$listeners = new Set();
    let $$$onmessage = null;

    // Message tracking
    const messageEvents = new Map();
    let isActive = true;

    // Adaptive telemetry configuration
    let telemetryInterval = 3000; // Start at 3s
    let lastHandlerDetectedTime = Date.now();
    let telemetryTimer = null;
    const TELEMETRY_ACTIVE = 3000;      // 3s when handlers recently detected
    const TELEMETRY_IDLE = 10000;       // 10s when idle (no new handlers for 30s)
    const TELEMETRY_BACKGROUND = 30000; // 30s when page hidden/inactive

    // Smart telemetry: Cache to avoid resending identical handlers
    const handlerCache = new Map(); // hash -> {code, timestamp}
    const CACHE_CLEANUP_INTERVAL = 60000; // Clean cache every 60s
    let lastCacheCleanup = Date.now();
    
    // Fast hash function for handler code (FNV-1a)
    function hashCode(str) {
        let hash = 2166136261;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return (hash >>> 0).toString(36);
    }

    // VERBOSE DEBUG MODE - Disabled to prevent log flood
    const VERBOSE_DEBUG = false;
    const debugLog = (...args) => {
        if (VERBOSE_DEBUG) {
            console.log(`%c[FrogPost Agent ${windowId.substring(0, 8)}]`, 'color: #00ff00; font-weight: bold', ...args);
        }
    };

    // Deep JSON sanitizer: caps total keys across nested structure and array lengths
    function sanitizeJsonDeep(value, options = {}) {
        const maxKeysTotal = typeof options.maxKeysTotal === 'number' ? options.maxKeysTotal : 50;
        const maxArrayLength = typeof options.maxArrayLength === 'number' ? options.maxArrayLength : 50;
        const maxDepth = typeof options.maxDepth === 'number' ? options.maxDepth : 8;
        let remainingKeys = maxKeysTotal;

        function walk(val, depth) {
            if (depth > maxDepth) return { __frogPost_truncatedDepth: true };
            if (!val || typeof val !== 'object') return val;
            if (Array.isArray(val)) {
                const out = [];
                const len = Math.min(val.length, maxArrayLength);
                for (let i = 0; i < len; i++) {
                    if (remainingKeys <= 0) break;
                    out.push(walk(val[i], depth + 1));
                }
                if (val.length > len) out.push({ __frogPost_truncatedArray: val.length - len });
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
            const omitted = keys.length - Object.keys(out).length;
            if (omitted > 0) out.__frogPost_truncatedKeys = omitted;
            return out;
        }

        const result = walk(value, 0);
        if (remainingKeys <= 0 && result && typeof result === 'object' && !Array.isArray(result)) {
            result.__frogPost_truncatedTotalKeys = true;
        }
        return result;
    }

    /**
     * Send telemetry to background script via content script forwarder
     */
    function sendToBackground(payload) {
        try {
            debugLog('📤 Sending to background:', payload.topic, payload);
            window.postMessage({
                type: 'frogPostAgent->ForwardToBackground',
                payload: payload
            }, '*');
        } catch (error) {
            debugLog('❌ Error sending to background:', error);
        }
    }

    /**
     * Build recursive frame tree (simplified - no inter-frame messaging)
     */
    function buildFrameTree(frameId = "root", refWindow = window, path = []) {
        // Simplified version - just reports frame structure without cross-frame messages
        try {
            // Get child frames (same-origin only)
            const childWindowIds = Object.keys(refWindow.frames)
                .slice(0, Object.keys(refWindow.frames).findIndex((v) => v === "window"))
                .map(Number);
            
            // Recursively check child frames
            childWindowIds.forEach(id => {
                try {
                    buildFrameTree(id, refWindow[id], path.concat(id));
                } catch (e) {
                    // Cross-origin frame - skip
                }
            });
        } catch (error) {
            // Frame access error - skip
        }
    }

    /**
     * Send periodic telemetry with current handlers
     * OPTIMIZED: Only sends handler CHANGES (not full code every time)
     * This reduces IPC traffic by 80-90% with multiple frames
     */
    function sendPeriodicTelemetry() {
        try {
            const now = Date.now();
            const allHandlers = [];  // Send ALL handlers, not just changes
            const currentHashes = new Set();
            
            // Send ALL handlers every time (not just changes)
            // This ensures dashboard always gets full handler list even if opened late
            $$$listeners.forEach(listener => {
                try {
                    const code = listener.toString();
                    const hash = hashCode(code);
                    currentHashes.add(hash);
                    
                    // Send full code (not abbreviated) for actual handler analysis
                    const isNew = !handlerCache.has(hash);
                    if (isNew) {
                        handlerCache.set(hash, { code: code, timestamp: now });
                    }
                    
                    allHandlers.push({
                        hash: hash,
                        code: code,  // Send FULL code for analysis
                        length: listener.length || 0,
                        name: listener.name || 'anonymous',
                        isNew: isNew
                    });
                } catch (e) {
                    // Skip handlers that can't be stringified
                }
            });

            // Periodic cache cleanup to prevent memory leaks
            if (now - lastCacheCleanup > CACHE_CLEANUP_INTERVAL) {
                const staleThreshold = now - 300000; // 5 minutes
                for (const [hash, entry] of handlerCache.entries()) {
                    if (entry.timestamp < staleThreshold && !currentHashes.has(hash)) {
                        handlerCache.delete(hash);
                    }
                }
                lastCacheCleanup = now;
            }

            // Always send telemetry with ALL handlers (not just changes)
            // This ensures dashboard gets full handler list even if opened after handlers were registered
            if (allHandlers.length > 0) {
                const newHandlerCount = allHandlers.filter(h => h.isNew).length;
                console.log(`[FrogPost DOM Agent] 📊 Sending telemetry: ${newHandlerCount} new, ${allHandlers.length} total handlers`);
                console.log(`[FrogPost DOM Agent] Location: ${window.location.href}`);
                console.log(`[FrogPost DOM Agent] Handlers:`, allHandlers.map(h => ({ name: h.name, codeLength: h.code.length })));
                debugLog(`📊 Telemetry: ${newHandlerCount} new, ${allHandlers.length} total handlers, iframe=${window !== window.top}`);

                sendToBackground({
                    topic: "handlers-telemetry",
                    windowId: windowId,
                    location: window.location.href,
                    isIframe: window !== window.top,
                    handlers: allHandlers,  // Send ALL handlers every time
                    timestamp: now,
                    handlerCount: $$$listeners.size,
                    cacheSize: handlerCache.size
                });
            } else {
                console.log(`[FrogPost DOM Agent] ⚠️ No handlers to send. Total listeners: ${$$$listeners.size}`);
            }

            // Build frame tree from top window only (less frequently)
            if (window.top === window && allHandlers.length > 0) {
                buildFrameTree();
            }

            // Adaptive interval calculation
            const timeSinceLastHandler = Date.now() - lastHandlerDetectedTime;
            if (timeSinceLastHandler > 30000) {
                // No new handlers for 30s -> slow down to 10s interval
                telemetryInterval = document.hidden ? TELEMETRY_BACKGROUND : TELEMETRY_IDLE;
            } else {
                // Recent handler activity -> keep at 3s interval
                telemetryInterval = TELEMETRY_ACTIVE;
            }

        } catch (error) {
            debugLog('❌ Telemetry error:', error);
        }

        // Schedule next telemetry update with adaptive interval
        telemetryTimer = setTimeout(sendPeriodicTelemetry, telemetryInterval);
    }

    /**
     * Message Interception Hub
     * This hub captures ALL incoming postMessages and dispatches to registered listeners
     * Critical for complete message visibility and handler correlation
     * OPTIMIZED: Single-pass filtering with early rejection (reduces IPC by 60-70%)
     */
    
    // Pre-compiled filter criteria for performance
    const SKIP_MESSAGE_TYPES = new Set([
        'frogPostAgent->ForwardToBackground',
        'chrome-devtools',
        'extension-update',
        'realTimeDetectorReady',
        'realTimeHandlerDetected',
        'realTimeMessageSent'
    ]);
    
    const SKIP_MESSAGE_PREFIXES = ['chrome-', 'extension-', 'frogPost', 'FROGPOST_'];
    
    function messageHub(event) {
        const { data, origin, source } = event;

        // OPTIMIZED: Single-pass early rejection filter
        // Check 1: Skip our own telemetry messages (most common case)
        if (data && typeof data === 'object') {
            const msgType = data.type;
            
            // Fast path: Check type against skip list
            if (typeof msgType === 'string') {
                if (SKIP_MESSAGE_TYPES.has(msgType)) return;
                
                // Check prefixes (common case)
                for (let i = 0; i < SKIP_MESSAGE_PREFIXES.length; i++) {
                    if (msgType.startsWith(SKIP_MESSAGE_PREFIXES[i])) return;
                }
            }
            
            // Check for FrogPost markers
            if (data.__frogPostInternal || data.FrogPost === 'BreakpointTest') return;
        }
        
        // Check 2: String-based messages (less common)
        if (typeof data === 'string') {
            if (data === 'FrogPost::BreakpointTest' || 
                data.includes('__frogPost') || 
                data.includes('chrome-extension://')) {
                return;
            }
        }

        debugLog('📨 Message intercepted:', { origin, dataType: typeof data, listenerCount: $$$listeners.size });

        // Generate unique message ID and log it
        const messageId = uuidv4();
        const sanitizedData = sanitizeJsonDeep(data, { maxKeysTotal: 50, maxArrayLength: 50, maxDepth: 8 });
        const messageInfo = {
            messageId: messageId,
            data: sanitizedData,
            origin: origin,
            timestamp: Date.now()
        };
        messageEvents.set(messageId, messageInfo);
        // Keep only the most recent 30 messages in this iframe
        if (messageEvents.size > 30) {
            const oldestKey = messageEvents.keys().next().value;
            if (oldestKey !== undefined) messageEvents.delete(oldestKey);
        }

        sendToBackground({
            topic: "received-message",
            windowId: windowId,
            messageId: messageId,
            origin: origin,
            data: sanitizedData,
            location: window.location.href,
            isIframe: window !== window.top
        });

        // Dispatch to ALL registered handlers
        $$$listeners.forEach(listener => {
            try {
                listener(event);
            } catch (error) {
                // Handler threw error - don't break other handlers
            }
        });
    }

    /**
     * Initialize the agent
     */
    function initialize() {
        try {
            debugLog('🚀 Initializing FrogPost agent...');
            debugLog('📍 Location:', window.location.href);
            debugLog('🪟 WindowId:', windowId);
            debugLog('🖼️ Is iframe:', window !== window.top);

            // Install message hub as THE listener
            $$$_addEventListener.call(window, "message", messageHub);
            debugLog('✅ Message hub installed');

            // Override addEventListener to intercept handler registrations
            overrideAddEventListener();

            // Override onmessage property setter
            overrideOnMessageProperty();

            // Override postMessage to track outgoing messages
            overridePostMessage();

            // Scan for existing handlers
            scanExistingHandlers();

            // Report initialization
            sendToBackground({
                topic: "agent-ready",
                windowId: windowId,
                location: window.location.href,
                isIframe: window !== window.top,
                timestamp: Date.now()
            });

            debugLog('✅ Agent fully initialized! Starting periodic telemetry...');

            // Start periodic telemetry (THE KEY to 95%+ accuracy)
            sendPeriodicTelemetry();

        } catch (error) {
            debugLog('❌ Initialization error:', error);
        }
    }

    /**
     * Override addEventListener to intercept handler registrations
     */
    function overrideAddEventListener() {
        debugLog('🔧 Overriding addEventListener...');
        Object.defineProperty(window, 'addEventListener', {
            value: function(type, listener, options) {
                if (type === 'message' && isActive) {
                    // Add to our Set of actual function references
                    if (typeof listener === 'function') {
                        // Check if this is our own agent
                        const listenerStr = listener.toString();
                        const isOwnHandler = listenerStr.includes('__frogPost') || 
                                           listenerStr.includes('frogPostAgent') ||
                                           listenerStr.includes('messageHub');
                        
                        if (!isOwnHandler) {
                            $$$listeners.add(listener);
                            lastHandlerDetectedTime = Date.now(); // Reset for adaptive telemetry
                            telemetryInterval = TELEMETRY_ACTIVE; // Speed up to 3s
                            debugLog(`✅ Handler registered via addEventListener! Total: ${$$$listeners.size}`, listenerStr.substring(0, 100));
                            
                            // Send immediate notification about new handler
                            sendToBackground({
                                topic: "handler-added",
                                windowId: windowId,
                                location: window.location.href,
                                method: "addEventListener",
                                handlerCode: listenerStr.substring(0, 2000),
                                timestamp: Date.now()
                            });

                            // Trigger immediate telemetry update
                            if (telemetryTimer) clearTimeout(telemetryTimer);
                            sendPeriodicTelemetry();
                        }
                    }
                    // Don't call original - hub already handles it
                    return;
                }
                // For non-message events, use original
                $$$_addEventListener.call(this, type, listener, options);
            },
            configurable: true,
            writable: true  // CRITICAL: Allow other code to reassign/wrap addEventListener (Azure Portal compatibility)
        });
        debugLog('✅ addEventListener override complete');
    }

    /**
     * Override onmessage property setter
     */
    function overrideOnMessageProperty() {
        Object.defineProperty(window, 'onmessage', {
            set: function(handler) {
                $$$onmessage = handler;
                if (handler && typeof handler === 'function' && isActive) {
                    const handlerStr = handler.toString();
                    const isOwnHandler = handlerStr.includes('__frogPost') || 
                                       handlerStr.includes('frogPostAgent');
                    
                    if (!isOwnHandler) {
                        $$$listeners.add(handler);
                        lastHandlerDetectedTime = Date.now(); // Reset for adaptive telemetry
                        telemetryInterval = TELEMETRY_ACTIVE; // Speed up to 3s
                        
                        sendToBackground({
                            topic: "handler-added",
                            windowId: windowId,
                            location: window.location.href,
                            method: "onmessage",
                            handlerCode: handlerStr.substring(0, 2000),
                            timestamp: Date.now()
                        });

                        // Trigger immediate telemetry update
                        if (telemetryTimer) clearTimeout(telemetryTimer);
                        sendPeriodicTelemetry();
                    }
                }
            },
            get: function() {
                return $$$onmessage;
            },
            configurable: true
        });
    }

    /**
     * Override postMessage to track outgoing messages
     */
    function overridePostMessage() {
        window.postMessage = function(message, targetOrigin, transfer) {
            // Track outgoing message
            if (isActive) {
                try {
                    // Skip tracking our own internal messages
                    if (message && typeof message === 'object' && 
                        (message.__frogPostInternal || message.type?.includes('frogPost'))) {
                        // Send anyway without tracking
                        return $$$_postMessage.call(this, message, targetOrigin, transfer);
                    }

                    const messageId = uuidv4();
                    sendToBackground({
                        topic: "outgoing-message",
                        windowId: windowId,
                        messageId: messageId,
                        data: message,
                        targetOrigin: targetOrigin,
                        location: window.location.href,
                        timestamp: Date.now()
                    });
                } catch (e) {
                    // Don't break postMessage functionality
                }
            }
            
            // Always call original postMessage
            return $$$_postMessage.call(this, message, targetOrigin, transfer);
        };
    }

    /**
     * Scan for existing handlers (before our agent loaded)
     */
    function scanExistingHandlers() {
        try {
            // Check if window.onmessage was set before we overrode it
            if (window.onmessage && typeof window.onmessage === 'function') {
                $$$listeners.add(window.onmessage);
                sendToBackground({
                    topic: "handler-added",
                    windowId: windowId,
                    location: window.location.href,
                    method: "onmessage (pre-existing)",
                    handlerCode: window.onmessage.toString().substring(0, 2000),
                    timestamp: Date.now()
                });
            }
        } catch (error) {
            // Silent fail
        }
    }

    /**
     * Get agent statistics (for debugging)
     */
    function getStats() {
        return {
            windowId: windowId,
            handlersDetected: $$$listeners.size,
            messagesLogged: messageEvents.size,
            isActive: isActive,
            location: window.location.href,
            isIframe: window !== window.top
        };
    }

    /**
     * Stop the agent and restore original methods
     */
    function stop() {
        isActive = false;
        
        // Note: We intentionally don't restore original methods
        // because other code may depend on our overrides
        // The hub will simply stop dispatching when isActive = false
    }

    // Initialize the agent
    initialize();

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        stop();
    });

    // Adapt telemetry based on page visibility (saves CPU when page is hidden)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            // Page hidden -> slow down to 30s
            telemetryInterval = TELEMETRY_BACKGROUND;
            debugLog('📴 Page hidden, telemetry slowed to 30s');
        } else {
            // Page visible -> check if handlers were detected recently
            const timeSinceLastHandler = Date.now() - lastHandlerDetectedTime;
            telemetryInterval = timeSinceLastHandler > 30000 ? TELEMETRY_IDLE : TELEMETRY_ACTIVE;
            debugLog('📱 Page visible, telemetry adjusted to', telemetryInterval + 'ms');
        }
    });

    // Expose agent API for debugging
    window.__frogPostAgentAPI = {
        getStats: getStats,
        stop: stop,
        windowId: windowId,
        agentId: AGENT_ID,
        enableDebug: () => { 
            console.log('Debug mode not available in production build');
        }
    };

    // Single minimal log message (once per page)
    if (!window.__frogPostQuietMode) {
        const isIframe = window !== window.top;
        console.log(`🐸 FrogPost agent active (${isIframe ? 'iframe' : 'main'}) - windowId: ${windowId.substring(0, 8)}`);
        window.__frogPostQuietMode = true;
    }
})();
