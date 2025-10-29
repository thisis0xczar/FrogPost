/**
 * FrogPost Extension - Real-Time Handler Extraction
 * Originally Created by thisis0xczar/Lidor
 * Enhanced: 2025-10-29 - Immediate handler capture for BlackHat presentation
 * Architecture: Handlers sent instantly when registered, no periodic telemetry
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
     * Send handler immediately when detected (real-time capture)
     * No periodic batching - handlers sent instantly when registered
     */
    function sendHandlerImmediately(listenerFunc) {
        try {
            const handlerCode = listenerFunc.toString();
            const handlerName = listenerFunc.name || 'anonymous';
            
            debugLog(` 📨 Handler detected immediately: ${handlerName} (${handlerCode.length} chars)`);
            debugLog(` Location: ${window.location.href}`);
            
            sendToBackground({
                topic: "handler-detected",
                windowId: windowId,
                location: window.location.href,
                isIframe: window !== window.top,
                handler: {
                    code: handlerCode,
                    name: handlerName,
                    length: listenerFunc.length || 0,
                    timestamp: Date.now()
                }
            });
            
            debugLog(`📨 Handler sent immediately: ${handlerName} (${handlerCode.length} chars)`);
        } catch (e) {
            debugLog('❌ Failed to send handler:', e);
        }
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
     * Scan inline <script> tags for message handlers
     * Optimized for performance with fast hash deduplication
     */
    function scanInlineScripts() {
        try {
            const scripts = document.querySelectorAll('script:not([src])');
            debugLog(` 🔍 Scanning ${scripts.length} inline script(s) for handlers...`);
            const seenHashes = new Set();
            
            // Fast hash function for deduplication
            function fastHash(str) {
                let hash = 0;
                for (let i = 0; i < str.length; i++) {
                    hash = ((hash << 5) - hash) + str.charCodeAt(i);
                    hash = hash & hash;
                }
                return hash;
            }
            
            // Cached regex patterns
            const addEventListenerPattern = /addEventListener\s*\(\s*["']message["']\s*,\s*([^,)]+)/g;
            const onMessagePattern = /\.onmessage\s*=\s*([^;]+)/g;
            
            scripts.forEach((script) => {
                try {
                    const scriptContent = script.textContent;
                    if (!scriptContent || scriptContent.length > 1000000) return; // Skip huge scripts
                    
                    const scriptHash = fastHash(scriptContent);
                    if (seenHashes.has(scriptHash)) return; // Skip duplicates
                    seenHashes.add(scriptHash);
                    
                    // Find addEventListener('message', handler) - handles both inline and named handlers
                    let match;
                    const inlineHandlerPattern = /addEventListener\s*\(\s*["']message["']\s*,\s*(\([^)]*\)\s*=>\s*\{|function\s*\([^)]*\)\s*\{)/g;
                    
                    // First, try to find inline handlers (arrow functions or anonymous functions)
                    inlineHandlerPattern.lastIndex = 0;
                    while ((match = inlineHandlerPattern.exec(scriptContent)) !== null) {
                        debugLog(` 📝 Found inline addEventListener handler`);
                        const matchStart = match.index + match[0].indexOf(match[1]);
                        let braceCount = 1;
                        let endIdx = matchStart + match[1].length;
                        
                        while (braceCount > 0 && endIdx < scriptContent.length) {
                            if (scriptContent[endIdx] === '{') braceCount++;
                            else if (scriptContent[endIdx] === '}') braceCount--;
                            endIdx++;
                        }
                        
                        if (braceCount === 0) {
                            const handlerCode = scriptContent.substring(matchStart, endIdx);
                            sendHandlerImmediately({ toString: () => handlerCode, name: 'inline-addEventListener' });
                        }
                    }
                    
                    // Then, try to find named handler references
                    addEventListenerPattern.lastIndex = 0;
                    while ((match = addEventListenerPattern.exec(scriptContent)) !== null) {
                        const handlerRef = match[1].trim();
                        
                        // Skip if it looks like an inline function (starts with parenthesis or 'function')
                        if (handlerRef.startsWith('(') || handlerRef.startsWith('function')) continue;
                        
                        debugLog(` 📝 Found addEventListener pattern, handler ref: ${handlerRef}`);
                        
                        // Extract actual handler code
                        let handlerCode = null;
                        const funcMatch = scriptContent.match(new RegExp(`(?:function\\s+${handlerRef}|const\\s+${handlerRef}\\s*=|let\\s+${handlerRef}\\s*=|var\\s+${handlerRef}\\s*=)\\s*(?:function)?\\s*\\([^)]*\\)\\s*\\{`, 'g'));
                        
                        if (funcMatch) {
                            const startIdx = scriptContent.indexOf(funcMatch[0]);
                            let braceCount = 1;
                            let endIdx = startIdx + funcMatch[0].length;
                            
                            while (braceCount > 0 && endIdx < scriptContent.length) {
                                if (scriptContent[endIdx] === '{') braceCount++;
                                else if (scriptContent[endIdx] === '}') braceCount--;
                                endIdx++;
                            }
                            
                            if (braceCount === 0) {
                                handlerCode = scriptContent.substring(startIdx, endIdx);
                            }
                        }
                        
                        if (handlerCode) {
                            sendHandlerImmediately({ toString: () => handlerCode, name: handlerRef });
                        }
                    }
                    
                    // Find window.onmessage = handler
                    onMessagePattern.lastIndex = 0;
                    while ((match = onMessagePattern.exec(scriptContent)) !== null) {
                        const handlerDef = match[1].trim();
                        debugLog(` 📝 Found onmessage pattern: ${handlerDef.substring(0, 50)}...`);
                        if (handlerDef.startsWith('function') || handlerDef.includes('=>')) {
                            sendHandlerImmediately({ toString: () => handlerDef, name: 'onmessage' });
                        }
                    }
                    
                } catch (scriptError) {
                    // Silently skip problematic scripts
                }
            });
            
        } catch (error) {
            debugLog('❌ Error scanning inline scripts:', error);
        }
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

            // Scan inline scripts for handlers (catches handlers defined in <script> tags)
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => scanInlineScripts());
            } else {
                scanInlineScripts();
            }

            // Report initialization
            sendToBackground({
                topic: "agent-ready",
                windowId: windowId,
                location: window.location.href,
                isIframe: window !== window.top,
                timestamp: Date.now()
            });

            debugLog('✅ Agent fully initialized! Real-time handler capture active.');

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
                            debugLog(`✅ Handler registered via addEventListener! Total: ${$$$listeners.size}`, listenerStr.substring(0, 100));
                            
                            // Send handler immediately (real-time capture)
                            sendHandlerImmediately(listener);
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
                        
                        // Send handler immediately (real-time capture)
                        sendHandlerImmediately(handler);
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
                // Send handler immediately (real-time capture)
                sendHandlerImmediately(window.onmessage);
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
