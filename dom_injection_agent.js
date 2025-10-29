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
     * OPTIMIZED: Minimal logging to prevent main thread blocking
     */
    function sendHandlerImmediately(listenerFunc) {
        try {
            const handlerCode = listenerFunc.toString();
            const handlerName = listenerFunc.name || 'anonymous';
            
            // Production: Only log if VERBOSE_DEBUG is enabled
            debugLog(`📨 Handler: ${handlerName} (${handlerCode.length} chars) @ ${window.location.href}`);
            
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
        } catch (e) {
            // Silent fail in production
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

            // Scan inline scripts for handlers (after DOM is ready)
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', scanInlineScripts, { once: true });
            } else {
                // DOM already loaded, scan immediately
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
     * Fast hash function for handler deduplication
     * Uses FNV-1a algorithm for speed (faster than SHA-256)
     */
    function fastHash(str) {
        let hash = 2166136261; // FNV offset basis
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return hash >>> 0; // Convert to unsigned 32-bit
    }

    /**
     * Scan inline <script> tags for addEventListener('message', ...) handlers
     * OPTIMIZED: Size limits, cached regexes, fast hash dedup, minimal logging
     */
    function scanInlineScripts() {
        try {
            const scripts = document.querySelectorAll('script:not([src])');
            debugLog(`🔍 Scanning ${scripts.length} inline script(s) for message handlers...`);
            
            // Cache compiled regexes OUTSIDE loop for performance
            const cachedUsageRegexes = new Map();
            function getUsageRegex(varName) {
                if (!cachedUsageRegexes.has(varName)) {
                    cachedUsageRegexes.set(varName, 
                        new RegExp(`addEventListener\\s*\\(\\s*['"]message['"]\\s*,\\s*${varName}\\s*[,\\)]`)
                    );
                }
                return cachedUsageRegexes.get(varName);
            }
            
            const foundHandlerHashes = new Set(); // Fast hash-based dedup
            let scannedCount = 0;
            let skippedLarge = 0;
            
            for (const script of scripts) {
                const code = script.textContent || script.innerText || '';
                if (!code.trim()) continue;
                
                // OPTIMIZATION: Skip extremely large scripts (>1MB minified bundles)
                if (code.length > 1000000) {
                    skippedLarge++;
                    debugLog(`⏭️  Skipping large script (${(code.length/1024).toFixed(0)}KB)`);
                    continue;
                }
                
                scannedCount++;
                
                // Helper to extract balanced braces starting from a position
                function extractHandler(startPos) {
                    let depth = 0;
                    let inString = false;
                    let stringChar = null;
                    let escaped = false;
                    
                    for (let i = startPos; i < code.length; i++) {
                        const char = code[i];
                        
                        if (escaped) {
                            escaped = false;
                            continue;
                        }
                        
                        if (char === '\\') {
                            escaped = true;
                            continue;
                        }
                        
                        if ((char === '"' || char === "'" || char === '`') && !inString) {
                            inString = true;
                            stringChar = char;
                        } else if (char === stringChar && inString) {
                            inString = false;
                            stringChar = null;
                        }
                        
                        if (!inString) {
                            if (char === '{') depth++;
                            if (char === '}') {
                                depth--;
                                if (depth === 0) {
                                    return code.substring(startPos, i + 1);
                                }
                            }
                        }
                    }
                    return null;
                }
                
                // Pattern 1: Direct inline handlers
                const directRegex = /addEventListener\s*\(\s*['"]message['"]\s*,\s*/g;
                let match;
                
                while ((match = directRegex.exec(code)) !== null) {
                    const afterMatch = match.index + match[0].length;
                    const handlerCode = extractHandler(afterMatch);
                    
                    if (handlerCode && handlerCode.length > 10) {
                        const hash = fastHash(handlerCode);
                        if (!foundHandlerHashes.has(hash)) {
                            foundHandlerHashes.add(hash);
                            debugLog(`📨 Handler [direct]: ${handlerCode.length} chars`);
                            
                            sendHandlerImmediately({
                                toString: () => handlerCode,
                                name: 'inline-addEventListener',
                                length: 1
                            });
                        }
                    }
                }
                
                // Pattern 2: Separate declaration + addEventListener (OPTIMIZED with cached regex)
                const separatePattern = /(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?(\w+|\([^)]*\))\s*=>\s*\{/g;
                
                while ((match = separatePattern.exec(code)) !== null) {
                    const varName = match[1];
                    const startPos = match.index + match[0].length - 1;
                    const handlerCode = extractHandler(startPos);
                    
                    if (handlerCode && handlerCode.length > 50) {
                        // OPTIMIZED: Use cached regex
                        if (getUsageRegex(varName).test(code)) {
                            const params = match[3];
                            const fullHandler = `${match[2] || ''}${params} => ${handlerCode}`;
                            
                            const hash = fastHash(fullHandler);
                            if (!foundHandlerHashes.has(hash)) {
                                foundHandlerHashes.add(hash);
                                debugLog(`📨 Handler [separate-var]: ${fullHandler.length} chars`);
                                
                                sendHandlerImmediately({
                                    toString: () => fullHandler,
                                    name: `inline-${varName}`,
                                    length: 1
                                });
                            }
                        }
                    }
                }
                
                // Pattern 3: React useEffect with addEventListener
                const useEffectPattern = /useEffect\s*\)\s*\(\s*\(\s*\(\s*\)\s*=>\s*\{/g;
                
                while ((match = useEffectPattern.exec(code)) !== null) {
                    const startPos = match.index + match[0].length - 1;
                    const effectBody = extractHandler(startPos);
                    
                    if (effectBody && effectBody.includes("addEventListener") && effectBody.includes("message")) {
                        const innerPattern = /(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?(\w+|\([^)]*\))\s*=>\s*\{/g;
                        let innerMatch;
                        
                        while ((innerMatch = innerPattern.exec(effectBody)) !== null) {
                            const varName = innerMatch[1];
                            const innerStartPos = innerMatch.index + innerMatch[0].length - 1;
                            const innerHandler = extractHandler(innerStartPos);
                            
                            if (innerHandler && innerHandler.length > 50) {
                                if (getUsageRegex(varName).test(effectBody)) {
                                    const params = innerMatch[3];
                                    const fullHandler = `${innerMatch[2] || ''}${params} => ${innerHandler}`;
                                    
                                    const hash = fastHash(fullHandler);
                                    if (!foundHandlerHashes.has(hash)) {
                                        foundHandlerHashes.add(hash);
                                        debugLog(`📨 Handler [useEffect]: ${fullHandler.length} chars`);
                                        
                                        sendHandlerImmediately({
                                            toString: () => fullHandler,
                                            name: `inline-useEffect-${varName}`,
                                            length: 1
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            debugLog(`✅ Scanned ${scannedCount}/${scripts.length} scripts, skipped ${skippedLarge} large, found ${foundHandlerHashes.size} unique handlers`);
        } catch (error) {
            debugLog('❌ Error scanning inline scripts:', error);
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
