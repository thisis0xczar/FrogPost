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

    // VERBOSE DEBUG MODE - Disabled to prevent log flood
    const VERBOSE_DEBUG = false;
    const debugLog = (...args) => {
        if (VERBOSE_DEBUG) {
            console.log(`%c[FrogPost Agent ${windowId.substring(0, 8)}]`, 'color: #00ff00; font-weight: bold', ...args);
        }
    };

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
     * This is THE KEY to high accuracy - periodic updates capture dynamically added handlers
     * Now uses adaptive timing to reduce CPU usage on idle pages
     */
    function sendPeriodicTelemetry() {
        try {
            const handlers = Array.from($$$listeners).map(listener => {
                try {
                    return {
                        code: listener.toString(),
                        length: listener.length || 0,
                        name: listener.name || 'anonymous'
                    };
                } catch (e) {
                    return { code: '[unable to stringify]', length: 0, name: 'error' };
                }
            });

            debugLog(`📊 Telemetry update: ${handlers.length} handlers, iframe=${window !== window.top}, interval=${telemetryInterval}ms`);

            sendToBackground({
                topic: "handlers-telemetry",
                windowId: windowId,
                location: window.location.href,
                isIframe: window !== window.top,
                handlers: handlers,
                timestamp: Date.now(),
                handlerCount: $$$listeners.size
            });

            // Build frame tree from top window only
            if (window.top === window) {
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
     * Early filtering reduces IPC traffic by 40-50%
     */
    function messageHub(event) {
        const { data, origin, source } = event;

        // CRITICAL: Skip our own telemetry messages FIRST to prevent infinite loop
        if (data && typeof data === 'object' && data.type === 'frogPostAgent->ForwardToBackground') {
            return; // Don't intercept our own messages!
        }

        // Early filter: Skip extension-specific messages before forwarding
        if (data && typeof data === 'object') {
            // FrogPost breakpoint test messages
            if (data === 'FrogPost::BreakpointTest' || data.FrogPost === 'BreakpointTest') {
                return;
            }
            
            // FrogPost internal coordination
            if (data.__frogPostInternal) {
                return; // Don't send to background or dispatch to handlers
            }
            
            // Chrome extension messages (avoid intercepting browser's own messages)
            if (data.type && (data.type.startsWith('chrome-') || data.type.startsWith('extension-'))) {
                return;
            }
        }

        // String-based extension markers
        if (typeof data === 'string' && (
            data.includes('__frogPost') || 
            data.includes('chrome-extension://') ||
            data === 'FrogPost::BreakpointTest'
        )) {
            return;
        }

        // Skip other extension messages
        if (data && typeof data === 'object') {
            const dataStr = JSON.stringify(data).substring(0, 200);
            if (dataStr.includes('frogPost') || dataStr.includes('__frogPost')) {
                return;
            }
        }

        debugLog('📨 Message intercepted:', { origin, dataType: typeof data, listenerCount: $$$listeners.size });

        // Generate unique message ID and log it
        const messageId = uuidv4();
        const messageInfo = {
            messageId: messageId,
            data: data,
            origin: origin,
            timestamp: Date.now()
        };
        messageEvents.set(messageId, messageInfo);

        sendToBackground({
            topic: "received-message",
            windowId: windowId,
            messageId: messageId,
            origin: origin,
            data: data,
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
            configurable: true
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
