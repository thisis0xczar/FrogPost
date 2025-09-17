/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-09-17
 */

(function() {
    // Prevent multiple injections
    if (window.__frogPostDOMAgent) {
        return;
    }
    window.__frogPostDOMAgent = true;

    // Generate a stable per-page agent id (uuidv4)
    function uuidv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    const AGENT_ID = window.__frogPostAgentId || (window.__frogPostAgentId = uuidv4());

    console.log('FrogPost DOM Agent: Initializing in MAIN world');

    class DOMInjectionAgent {
        constructor() {
            this.detectedHandlers = new Map();
            this.messageEvents = new Map();
            this.originalMethods = {};
            this.isActive = true;
            
            this.initialize();
        }

        initialize() {
            try {
                // Override addEventListener to catch message handlers
                this.overrideAddEventListener();
                
                // Override postMessage to log outgoing messages
                this.overridePostMessage();
                
                // Override onmessage property
                this.overrideOnMessage();
                
                // Scan for existing handlers
                this.scanExistingHandlers();

                // Watch and instrument iframes (same-origin only)
                this.setupIframeMonitoring();
                
                // Report initialization
                this.reportInitialization();
                
                console.log('FrogPost DOM Agent: Successfully initialized');
            } catch (error) {
                console.error('FrogPost DOM Agent: Initialization failed', error);
            }
        }

        /**
         * Override addEventListener to intercept message event registrations
         */
        overrideAddEventListener() {
            const self = this;
            this.originalMethods.addEventListener = EventTarget.prototype.addEventListener;
            
            EventTarget.prototype.addEventListener = function(type, listener, options) {
                if (type === 'message' && self.isActive) {
                    self.handleMessageListenerAdded(this, listener, options);
                }
                return self.originalMethods.addEventListener.call(this, type, listener, options);
            };
        }

        /**
         * Override postMessage to intercept outgoing messages
         */
        overridePostMessage() {
            const self = this;
            this.originalMethods.postMessage = window.postMessage;
            
            window.postMessage = function() {
                try {
                    if (self.isActive) {
                        const args = Array.from(arguments);
                        const msg = args[0];
                        const second = args[1];
                        const transfer = args[2];
                        const targetOrigin = typeof second === 'string' ? second : (second && typeof second === 'object' ? second.targetOrigin : undefined);
                        self.handlePostMessage(msg, targetOrigin, transfer);
                    }
                } catch {}
                // Preserve exact call signature to avoid behavior changes
                return self.originalMethods.postMessage.apply(this, arguments);
            };
        }

        /**
         * Override onmessage property to catch direct assignments
         */
        overrideOnMessage() {
            const self = this;
            
            // Override onmessage for window
            Object.defineProperty(window, 'onmessage', {
                get: function() {
                    return this._frogPostOnMessage;
                },
                set: function(handler) {
                    this._frogPostOnMessage = handler;
                    if (self.isActive && typeof handler === 'function') {
                        self.handleMessageListenerAdded(this, handler, null);
                    }
                },
                configurable: true
            });
        }

        /**
         * Handle when a message listener is added
         */
        handleMessageListenerAdded(target, listener, options) {
            try {
                // Skip if this is our own agent
                if (this.isOwnAgent(listener)) {
                    return;
                }

                const handlerInfo = {
                    id: this.generateId(),
                    agentId: AGENT_ID,
                    target: this.getTargetInfo(target),
                    listener: this.analyzeListener(listener),
                    options: options,
                    timestamp: Date.now(),
                    location: window.location.href,
                    method: 'addEventListener',
                    isIframe: window !== window.top
                };

                this.detectedHandlers.set(handlerInfo.id, handlerInfo);
                this.reportHandler(handlerInfo);
                
                console.log('FrogPost DOM Agent: Handler detected', handlerInfo);
            } catch (error) {
                console.error('FrogPost DOM Agent: Error handling listener', error);
            }
        }

        /**
         * Handle postMessage calls
         */
        handlePostMessage(message, targetOrigin, transfer) {
            try {
                // Skip if this is our own message
                if (this.isOwnMessage(message)) {
                    return;
                }

                const messageInfo = {
                    id: this.generateId(),
                    agentId: AGENT_ID,
                    data: message,
                    targetOrigin: targetOrigin,
                    transfer: transfer,
                    timestamp: Date.now(),
                    source: window.location.href,
                    isIframe: window !== window.top
                };

                this.messageEvents.set(messageInfo.id, messageInfo);
                this.reportMessage(messageInfo);
                
                console.log('FrogPost DOM Agent: Message sent', messageInfo);
            } catch (error) {
                console.error('FrogPost DOM Agent: Error handling message', error);
            }
        }

        /**
         * Scan for existing handlers that were added before our agent
         */
        scanExistingHandlers() {
            try {
                // Check window.onmessage
                if (window._frogPostOnMessage && typeof window._frogPostOnMessage === 'function') {
                    this.handleMessageListenerAdded(window, window._frogPostOnMessage, null);
                }

                // Check document.onmessage
                if (document.onmessage && typeof document.onmessage === 'function') {
                    this.handleMessageListenerAdded(document, document.onmessage, null);
                }

                // Try to detect other existing listeners (limited by browser security)
                this.attemptListenerDetection();
            } catch (error) {
                console.error('FrogPost DOM Agent: Error scanning existing handlers', error);
            }
        }

        /**
         * Attempt to detect existing listeners (limited approach)
         */
        attemptListenerDetection() {
            try {
                // This is a simplified approach - we can't easily detect all existing listeners
                // but we can check for common patterns
                console.log('FrogPost DOM Agent: Scanning for existing listeners...');
                
                // Check if there are any message-related properties
                const targets = [window, document];
                targets.forEach(target => {
                    if (target.onmessage && typeof target.onmessage === 'function') {
                        console.log('FrogPost DOM Agent: Found existing onmessage on', target.constructor.name);
                    }
                });
            } catch (error) {
                console.error('FrogPost DOM Agent: Error in listener detection', error);
            }
        }

        /**
         * Check if a listener belongs to our own agent
         */
        isOwnAgent(listener) {
            try {
                if (typeof listener !== 'function') {
                    return false;
                }

                const source = listener.toString();
                const patterns = [
                    '__frogPost',
                    'FrogPost DOM Agent',
                    'frogPostDOMAgent',
                    'frogPostAgent->ForwardToBackground',
                    '__FROGPOST_SET_INDEX__',
                    'FROGPWNED_CONSOLE_XSS',
                    'FROGPOST_MUTATION',
                    'contentScriptReady',
                    'realTimeDetectorReady',
                    'realTimeHandlerDetected',
                    'realTimeMessageSent',
                    'chrome.runtime.sendMessage'
                ];
                return patterns.some(p => source.includes(p));
            } catch (error) {
                return false;
            }
        }

        /**
         * Check if a message is from our own agent
         */
        isOwnMessage(message) {
            try {
                if (!message || typeof message !== 'object') {
                    return false;
                }

                const messageStr = JSON.stringify(message);
                return messageStr.includes('__frogPost') || 
                       messageStr.includes('FrogPost DOM Agent') ||
                       messageStr.includes('frogPostDOMAgent');
            } catch (error) {
                return false;
            }
        }

        /**
         * Analyze listener function
         */
        analyzeListener(listener) {
            try {
                return {
                    type: typeof listener,
                    isFunction: typeof listener === 'function',
                    source: listener.toString ? listener.toString().substring(0, 2000) : 'unknown',
                    length: listener.length || 0
                };
            } catch (error) {
                return { type: 'unknown', error: error.message };
            }
        }

        /**
         * Get target information
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
                    return { type: 'unknown', constructor: target.constructor.name };
                }
            } catch (error) {
                return { type: 'error', error: error.message };
            }
        }

        /**
         * Generate unique ID
         */
        generateId() {
            return `dom_agent_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

        /**
         * Report handler detection to extension
         */
        reportHandler(handlerInfo) {
            try {
                // Send to extension via postMessage
                window.postMessage({
                    type: 'frogPostDOMAgentHandler',
                    data: handlerInfo
                }, '*');
            } catch (error) {
                console.error('FrogPost DOM Agent: Error reporting handler', error);
            }
        }

        /**
         * Report message to extension
         */
        reportMessage(messageInfo) {
            try {
                // Send to extension via postMessage
                window.postMessage({
                    type: 'frogPostDOMAgentMessage',
                    data: messageInfo
                }, '*');
            } catch (error) {
                console.error('FrogPost DOM Agent: Error reporting message', error);
            }
        }

        /**
         * Report initialization
         */
        reportInitialization() {
            try {
                window.postMessage({
                    type: 'frogPostDOMAgentReady',
                    data: {
                        agentId: AGENT_ID,
                        location: window.location.href,
                        timestamp: Date.now(),
                        userAgent: navigator.userAgent
                    }
                }, '*');
            } catch (error) {
                console.error('FrogPost DOM Agent: Error reporting initialization', error);
            }
        }

        /**
         * Monitor and instrument newly added iframes (same-origin only)
         */
        setupIframeMonitoring() {
            try {
                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        mutation.addedNodes.forEach((node) => {
                            if (node && node.tagName === 'IFRAME') {
                                this.monitorNewIframe(node);
                            }
                        });
                    });
                });
                observer.observe(document.documentElement || document.body, { childList: true, subtree: true });

                // Also handle any existing iframes
                const existingIframes = document.getElementsByTagName('iframe');
                Array.from(existingIframes).forEach(iframe => this.monitorNewIframe(iframe));
            } catch (e) {
                console.error('FrogPost DOM Agent: Error setting up iframe monitoring', e);
            }
        }

        monitorNewIframe(iframe) {
            try {
                iframe.addEventListener('load', () => {
                    try {
                        const doc = iframe.contentDocument || iframe.contentWindow?.document;
                        if (doc) {
                            this.injectAgentIntoIframe(doc);
                        } else {
                            // Cross-origin - cannot inject
                            window.postMessage({
                                type: 'frogPostDOMAgentMessage',
                                data: {
                                    id: this.generateId(),
                                    agentId: AGENT_ID,
                                    note: 'Cross-origin iframe - injection skipped',
                                    iframeSrc: iframe.src,
                                    timestamp: Date.now(),
                                    source: window.location.href,
                                    isIframe: window !== window.top
                                }
                            }, '*');
                        }
                    } catch (err) {
                        // Cross-origin access error
                        window.postMessage({
                            type: 'frogPostDOMAgentMessage',
                            data: {
                                id: this.generateId(),
                                agentId: AGENT_ID,
                                note: 'Iframe access error - likely cross-origin',
                                iframeSrc: iframe.src,
                                error: err?.message,
                                timestamp: Date.now(),
                                source: window.location.href,
                                isIframe: window !== window.top
                            }
                        }, '*');
                    }
                });
            } catch (e) {
                console.error('FrogPost DOM Agent: Error monitoring iframe', e);
            }
        }

        injectAgentIntoIframe(iframeDoc) {
            try {
                const script = iframeDoc.createElement('script');
                if (chrome?.runtime?.getURL) {
                    script.src = chrome.runtime.getURL('static/iframe-dom-agent.js');
                } else {
                    // Fallback: inject inline script if chrome.runtime is not available
                    script.textContent = `
                        (() => {
                            try {
                                if (window.__frogPostDOMChildAgent) return;
                                window.__frogPostDOMChildAgent = true;
                                const PARENT_AGENT_ID = '${AGENT_ID}';
                                const originalAdd = EventTarget.prototype.addEventListener;
                                EventTarget.prototype.addEventListener = function(type, listener, options) {
                                    if (type === 'message' && typeof listener === 'function') {
                                        parent.postMessage({ type: 'frogPostDOMAgentHandler', data: { id: 'child_' + Date.now(), agentId: PARENT_AGENT_ID, target: { type: 'window', url: window.location.href }, listener: { type: typeof listener, isFunction: true, source: listener.toString().substring(0, 2000), length: listener.length || 0 }, options: options, timestamp: Date.now(), location: window.location.href, method: 'iframe.addEventListener', isIframe: true } }, '*');
                                    }
                                    return originalAdd.apply(this, arguments);
                                };
                            } catch (e) { parent.postMessage({ type: 'frogPostDOMAgentMessage', data: { agentId: '${AGENT_ID}', error: 'Child agent init failed: ' + (e && e.message), timestamp: Date.now(), location: window.location.href, isIframe: true } }, '*'); }
                        })();
                    `;
                }
                script.onload = () => script.remove();
                iframeDoc.head.appendChild(script);
            } catch (e) {
                console.error('FrogPost DOM Agent: Error injecting agent into iframe', e);
            }
        }

        /**
         * Get statistics
         */
        getStats() {
            return {
                handlersDetected: this.detectedHandlers.size,
                messagesLogged: this.messageEvents.size,
                isActive: this.isActive
            };
        }

        /**
         * Stop the agent
         */
        stop() {
            this.isActive = false;
            
            // Restore original methods
            if (this.originalMethods.addEventListener) {
                EventTarget.prototype.addEventListener = this.originalMethods.addEventListener;
            }
            if (this.originalMethods.postMessage) {
                window.postMessage = this.originalMethods.postMessage;
            }
        }
    }

    // Initialize the DOM injection agent
    const agent = new DOMInjectionAgent();
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        agent.stop();
    });

    // Expose agent for debugging
    window.frogPostDOMAgent = agent;

    console.log('FrogPost DOM Agent: Ready');
})();

/**
 * DOM Agent Forwarder
 * Listens for messages from the DOM injection agent and forwards them to the background script
 */
(function() {
    // Prevent multiple initializations
    if (window.__frogPostDOMAgentForwarder) {
        return;
    }
    window.__frogPostDOMAgentForwarder = true;

    console.log('FrogPost DOM Agent Forwarder: Initializing');

    // Listen for messages from the DOM injection agent
    window.addEventListener('message', (event) => {
        // Only process messages from the same origin
        if (event.source !== window) {
            return;
        }

        // Check if this is a message from our DOM agent
        if (event.data && event.data.type && event.data.type.startsWith('frogPostDOMAgent')) {
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
        }

        // Explicitly ignore upstream agent-forwarded meta messages
        if (event.data && event.data.type === 'frogPostAgent->ForwardToBackground') {
            return;
        }
    });

    console.log('FrogPost DOM Agent Forwarder: Ready');
})();
