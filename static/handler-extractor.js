/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
class HandlerExtractor {
    constructor() {
        this.handlers = [];
        this.messages = [];
        this.endpoint = null;
        this.baseEndpoint = null;
        this.scriptSources = new Set();
        this.processedScripts = new Set();
        this.dynamicScriptQueue = [];

        // Adjusted Weights: Reduce generic, increase specific postMessage terms
        this.scoreWeights = {
            'event.data': 8, 'e.data': 8, 'message.data': 8, 'msg.data': 8, // Slightly higher
            '.data': 3, // Lower score for generic .data access
            'event.origin': 10, 'e.origin': 10, 'message.origin': 10, // Higher for origin
            'origin': 2, // Lower for just 'origin'
            'event.source': 6, 'e.source': 6, 'message.source': 6, // Slightly higher
            'postMessage(': 15, // Much higher for calling postMessage
            'targetOrigin': 8, // Higher for targetOrigin usage
            'origin ===': 15, '.origin ===': 15,
            'trustedOrigins': 12, 'allowedOrigins': 12, 'parentOrigin': 10, 'checkOrigin': 10, 'validateOrigin': 10, // Higher for validation terms
            'JSON.parse': 3, 'JSON.stringify': 2, // Keep low
            'typeof': 3, 'instanceof': 2, // Keep low
            'try': 1, 'catch': 1, // Keep low
            'switch': 5, 'case': 4, // Slightly higher for logic flow
            'messageType': 10, 'data.type': 9, 'message.type': 9, 'event.data.type': 9, // Higher for type checking
            'action': 9, 'data.action': 9, 'kind': 9, 'data.kind': 9, // Higher for common action keys
            'window.addEventListener("message"': 20, // High score for direct listener
            'addEventListener("message"': 15, // High score for direct listener (non-window)
            'onmessage': 8, // Lower score for onmessage assignment
            'window.parent': 5, // Keep moderate
            'response': 2, 'callback': 2, 'resolve': 1, 'send': 1, // Lower utility keywords
            'WORKER_ID': -15, 'self.onmessage': -20, 'importScripts': -20, // Penalties for worker code
            'ajax': -5, 'fetch': -5, '$': -2, 'jQuery': -3, // Penalties for non-postMessage code
        };

        this.extractionPatterns = {
            directListeners: [
                { pattern: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener-window', score: 20 },
                { pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener', score: 10 },
                { pattern: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow-window', score: 19, process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
                { pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow', score: 9, process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
                { pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*([^{].*?)(?:\s*,|\s*\))/g, category: 'direct-listener-arrow-expression', score: 8, process: (match) => `function(${match[1] || 'event'}) { return ${match[2] || ''}; }` }
            ],
            functionReferences: [
                { pattern: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference-window', score: 12, needsResolving: true },
                { pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference', score: 7, needsResolving: true },
                { pattern: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:this\.)?([a-zA-Z0-9_$]+)\.([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'method-reference', score: 6, needsResolving: true }
            ],
            onMessageAssignments: [
                { pattern: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g, category: 'onmessage-assignment', score: 9 },
                { pattern: /(?:window\.)?onmessage\s*=\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/g, category: 'onmessage-arrow', score: 8, process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
                { pattern: /(?:window\.)?onmessage\s*=\s*([a-zA-Z0-9_$]+)\s*;/g, category: 'onmessage-reference', score: 7, needsResolving: true }
            ],
            frameCommunication: [
                { pattern: /window\.addEventListener\("message",\s*\(([^)]+)\s*=>\s*\{\s*this\.([a-zA-Z0-9_$]+)\(.*?\)\s*\}\s*\)/g, category: 'frame-communication-delegate', score: 25, isDelegator: true, getDetails: (match) => ({ delegateParam: match[1], delegateMethodName: match[2] }) },
                { pattern: /(\w+)\s*[:=]?\s*(?:function)?\s*\(([^)]*)\)\s*(?:=>)?\s*\{([\s\S]*?)\}(?=[;\n\s]*[}\),])/g, category: 'frame-communication-impl', score: 5, isImplementation: true },
                { pattern: /window\.parent\.postMessage\(\{\s*kind:.*?signature: this\.frameSignature[\s\S]*?\}\)/g, category: 'frame-parent-communication', score: 20 }
            ],
            messageHandlingFunctions: [
                { pattern: /function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{([\s\S]*?(?:event|e|msg|message)\.data[\s\S]*?)\}/g, category: 'event-data-function', score: 6 },
                { pattern: /function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{([\s\S]*?(?:event|e|msg|message)\.origin[\s\S]*?)\}/g, category: 'origin-check-function', score: 7 },
                { pattern: /function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{([\s\S]*?postMessage\s*\([\s\S]*?)\}/g, category: 'postmessage-function', score: 5 }
            ],
            messageHandlers: [
                { pattern: /(?:class|var|let|const)\s+([a-zA-Z0-9_$]+)(?:[\s\S]*?)handleMessage\s*\(([^)]*)\)\s*\{([\s\S]*?)\}/g, category: 'handler-class-method', score: 8 },
                { pattern: /messageHandler\s*[:=]\s*\{([\s\S]*?)handleMessage\s*:\s*function\s*\(([^)]*)\)\s*\{([\s\S]*?)\}/g, category: 'handler-object', score: 7 }
            ],
            minifiedPatterns: [
                { pattern: /([a-zA-Z0-9_$]{1,3})\.addEventListener\(["']message["'],([a-zA-Z0-9_$]{1,3})\)/g, category: 'minified-listener', score: 3, needsResolving: true },
                { pattern: /window\[["']onmessage["']\]=([a-zA-Z0-9_$]{1,3})/g, category: 'minified-onmessage', score: 3, needsResolving: true }
            ]
        };
    }

    /**
     * Initialize the extractor with an endpoint and any captured messages
     * @param {string} endpoint - The URL to extract handlers from
     * @param {Array} messages - Any postMessage events that have been captured
     * @returns {HandlerExtractor} - Returns this for chaining
     */
    initialize(endpoint, messages = []) {
        this.endpoint = endpoint;
        this.messages = Array.isArray(messages) ? messages : [];
        try { if (typeof endpoint === 'string') { this.baseEndpoint = this.getBaseUrl(endpoint); } } catch (error) { console.error('[HandlerExtractor] Error initializing with endpoint:', error); }
        this.handlers = [];
        console.log(`[HandlerExtractor] Initialized for ${this.baseEndpoint}. Using ${this.messages.length} provided messages.`);
        return this;
    }

    async extractFromStorage() {
        if (!this.baseEndpoint) return [];
        const storageKey = `runtime-listeners-${this.baseEndpoint}`;
        try {
            const result = await chrome.storage.local.get([storageKey]);
            const storedListeners = result[storageKey] || [];
            console.log(`[HandlerExtractor] Found ${storedListeners.length} listeners in storage for ${this.baseEndpoint}`);
            return storedListeners.map(listener => ({
                handler: listener.code,
                score: this.scoreHandler(listener.code, 'runtime-captured', []), // Score initially without context
                category: 'runtime-captured',
                source: 'runtime-instrumentation',
                timestamp: listener.timestamp,
                stack: listener.stack
            }));
        } catch (error) {
            console.error(`[HandlerExtractor] Error fetching from storage key ${storageKey}:`, error);
            return [];
        }
    }

    /**
     * Get base URL without query params or hash
     * @param {string} url - The URL to normalize
     * @returns {string} - Normalized URL
     */
    getBaseUrl(url) {
        try {
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                url = 'https://' + url;
            }
            const urlObj = new URL(url);
            urlObj.hash = '';
            return urlObj.toString();
        } catch (e) {
            console.warn('[HandlerExtractor] Invalid URL:', url);
            return url;
        }
    }

    resolveScriptUrl(src, baseUrl) {
        try {
            if (src.startsWith('http://') || src.startsWith('https://')) {
                return src;
            }

            if (src.startsWith('//')) {
                const baseUrlProtocol = baseUrl.split('://')[0];
                return `${baseUrlProtocol}:${src}`;
            }

            const baseUrlObj = new URL(baseUrl);

            if (src.startsWith('/')) {
                return `${baseUrlObj.origin}${src}`;
            }

            let basePath = baseUrlObj.pathname;
            const lastSlashIndex = basePath.lastIndexOf('/');
            if (lastSlashIndex !== -1) {
                const lastPart = basePath.substring(lastSlashIndex + 1);
                if (lastPart.includes('.')) {
                    basePath = basePath.substring(0, lastSlashIndex);
                }
            }

            if (basePath.endsWith('/')) {
                basePath = basePath.substring(0, basePath.length - 1);
            }

            const baseSegments = basePath.split('/').filter(segment => segment.length > 0);
            const srcSegments = src.split('/').filter(segment => segment.length > 0);
            const filename = srcSegments[srcSegments.length - 1];
            const srcDirSegments = srcSegments.slice(0, -1);
            let pathDuplication = false;
            if (srcDirSegments.length > 0 && baseSegments.length >= srcDirSegments.length) {
                const baseEndSegments = baseSegments.slice(-srcDirSegments.length);
                pathDuplication = srcDirSegments.every((segment, index) =>
                    segment === baseEndSegments[index]);
            }

            let resolvedUrl;

            if (pathDuplication) {
                resolvedUrl = `${baseUrlObj.origin}${basePath}/${filename}`;
                console.log(`[HandlerExtractor] Found path duplication. Using: ${resolvedUrl}`);
            } else {
                resolvedUrl = `${baseUrlObj.origin}${basePath}/${src}`;
            }

            return resolvedUrl;
        } catch (error) {
            console.warn(`[HandlerExtractor] Error resolving script URL:`, error);
            return src;
        }
    }

    /**
     * Find matching tabs for the current endpoint
     * @returns {Promise<Array>} - Array of matching tabs
     */
    async findMatchingTabs() {
        return new Promise((resolve) => {
            chrome.tabs.query({}, (tabs) => {
                if (!this.endpoint) {
                    resolve([]);
                    return;
                }

                try {
                    const endpointUrl = new URL(this.endpoint);
                    const matchingTabs = tabs.filter(tab => {
                        if (!tab.url) return false;
                        try {
                            return tab.url.includes(endpointUrl.hostname);
                        } catch (e) {
                            return false;
                        }
                    });

                    resolve(matchingTabs);
                } catch (error) {
                    console.error('[HandlerExtractor] Error finding matching tabs:', error);
                    resolve([]);
                }
            });
        });
    }

    /**
     * Extract handlers using all available strategies
     * @returns {Promise<Array>} - Array of extracted handlers
     */
    async extract() {
        this.handlers = [];
        const savedMessages = await this.getSavedMessages();
        const allRelevantMessages = [...this.messages, ...savedMessages];
        const strategies = [
            // 'storage' strategy removed - handled by Play button logic first
            { name: 'messages', method: this.extractFromMessages.bind(this) },
            { name: 'direct', method: this.extractDirectly.bind(this) },
            { name: 'scripts', method: this.extractFromExternalScripts.bind(this) },
            // { name: 'tabs', method: this.extractFromTabs.bind(this) } // Keep commented unless needed
        ];

        for (const strategy of strategies) {
            try {
                const extractedHandlers = await strategy.method();
                if (extractedHandlers && extractedHandlers.length > 0) {
                    console.log(`[HandlerExtractor - Fallback] Found ${extractedHandlers.length} potential handlers via ${strategy.name}.`);
                    extractedHandlers.forEach(h => {
                        if (h.handler && typeof h.handler === 'string' && typeof h.score !== 'number') {
                            h.score = this.scoreHandler(h.handler, h.category, []); // Initial score without context
                        } else if (typeof h.score !== 'number') {
                            h.score = -1; // Mark as invalid if no handler or score
                        }
                    });
                    extractedHandlers.forEach(h => {
                        if (!this.handlers.some(existing => existing.handler === h.handler)) {
                            if (h.score >= 0) {
                                this.handlers.push(h);
                            }
                        }
                    });
                }
            } catch (error) { console.error(`[HandlerExtractor - Fallback] Error in ${strategy.name} extraction:`, error); }
        }

        if (allRelevantMessages.length > 0 && this.handlers.length > 0) {
            console.log(`[HandlerExtractor - Fallback] Enhancing scores using ${allRelevantMessages.length} total messages.`);
            this.enhanceScores(allRelevantMessages); // Score handlers found by fallback
        }

        const uniqueHandlers = this.deduplicateHandlers(); // Deduplicates this.handlers
        if (uniqueHandlers.length === 0) {
            console.log(`[HandlerExtractor - Fallback] No handlers found, generating synthetic.`);
            const syntheticHandler = this.generateSyntheticHandler(allRelevantMessages);
            syntheticHandler.score = this.scoreHandler(syntheticHandler.handler, syntheticHandler.category, allRelevantMessages);
            uniqueHandlers.push(syntheticHandler);
        }

        if (uniqueHandlers.length > 0) {
            const bestHandler = this.getBestHandler(uniqueHandlers);
            if (bestHandler) {
                console.log(`[HandlerExtractor - Fallback] Best handler determined (Score: ${bestHandler.score?.toFixed(1)}, Cat: ${bestHandler.category}, Src: ${bestHandler.source})`);
            } else { console.log("[HandlerExtractor - Fallback] Could not select a best handler."); }
        } else {
            console.log("[HandlerExtractor - Fallback] No handlers found or generated.");
        }

        return uniqueHandlers;
    }

    /**
     * Extract handlers from captured messages
     * @returns {Promise<Array>} - Extracted handlers
     */
    async extractFromMessages() {
        if (!this.messages || this.messages.length === 0) {
            return [];
        }

        console.log(`[HandlerExtractor] Extracting handlers from ${this.messages.length} messages`);
        const extractedHandlers = [];
        const handlerRegex = /function\s*\([^)]*\)\s*\{[\s\S]*?\}/g;

        this.messages.forEach(message => {
            try {
                let msgData = message.data;

                if (typeof msgData === 'string') {
                    try {
                        msgData = JSON.parse(msgData);
                    } catch (e) {
                        const stringMatches = msgData.match(handlerRegex);
                        if (stringMatches) {
                            stringMatches.forEach(match => {
                                if (this.isLikelyHandler(match)) {
                                    extractedHandlers.push({
                                        handler: match,
                                        score: this.scoreHandler(match),
                                        category: 'message-string',
                                        source: 'message'
                                    });
                                }
                            });
                        }
                        return;
                    }
                }

                if (typeof msgData === 'object' && msgData !== null) {
                    const objString = JSON.stringify(msgData);
                    const objMatches = objString.match(handlerRegex);

                    if (objMatches) {
                        objMatches.forEach(match => {
                            if (this.isLikelyHandler(match)) {
                                extractedHandlers.push({
                                    handler: match,
                                    score: this.scoreHandler(match),
                                    category: 'message-object',
                                    source: 'message'
                                });
                            }
                        });
                    }

                    Object.entries(msgData).forEach(([key, value]) => {
                        if (typeof value === 'string' &&
                            (key.includes('handler') || key.includes('callback') || key.includes('function'))) {
                            if (this.isLikelyHandler(value)) {
                                extractedHandlers.push({
                                    handler: value,
                                    score: this.scoreHandler(value),
                                    category: 'message-property',
                                    source: `message-property-${key}`
                                });
                            }
                        }
                    });
                }
            } catch (error) {
                console.warn(`[HandlerExtractor] Error processing message:`, error);
            }
        });

        return extractedHandlers;
    }

    /**
     * Extract handlers directly using Chrome's scripting API
     * @returns {Promise<Array>} - Extracted handlers
     */
    async extractDirectly() {
        try {
            const matchingTabs = await this.findMatchingTabs();
            if (matchingTabs.length === 0) {
                console.log(`[HandlerExtractor] No matching tabs found for ${this.endpoint}`);
                return [];
            }

            const targetTab = matchingTabs[0];
            console.log(`[HandlerExtractor] Extracting from tab ${targetTab.id}`);

            const results = await chrome.scripting.executeScript({
                target: { tabId: targetTab.id, allFrames: true },
                func: () => {
                    const extractedHandlers = [];
                    const handlerFunctions = new Map();

                    if (window.onmessage && typeof window.onmessage === 'function') {
                        extractedHandlers.push({
                            handler: window.onmessage.toString(),
                            category: 'onmessage-property',
                            source: 'window.onmessage'
                        });
                    }

                    try {
                        for (const sym of Object.getOwnPropertySymbols(window)) {
                            if (sym.toString().includes('EventListeners')) {
                                const listeners = window[sym];
                                if (listeners && listeners.message) {
                                    for (const listener of listeners.message) {
                                        if (listener && typeof listener.listener === 'function') {
                                            extractedHandlers.push({
                                                handler: listener.listener.toString(),
                                                category: 'symbol-listener',
                                                source: 'event-listener-symbol'
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        console.warn("Error accessing event listeners via symbol:", e);
                    }

                    let allScriptContent = '';
                    document.querySelectorAll('script').forEach(script => {
                        if (script.textContent) {
                            allScriptContent += script.textContent + '\n';
                        }
                    });

                    function shouldIgnoreHandler(code) {
                        return code.includes('chrome.runtime.sendMessage') ||
                            code.includes('[PostMessage Monitor]') ||
                            code.includes('handlePostMessageCapture');
                    }

                    const patterns = [
                        {
                            regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g,
                            category: 'addEventListener-function'
                        },
                        {
                            regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g,
                            category: 'addEventListener-arrow',
                            process: (match) => {
                                const params = match[1] || 'event';
                                const body = match[2] || '';
                                return `function(${params}) { ${body} }`;
                            }
                        },
                        {
                            regex: /addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g,
                            category: 'addEventListener-reference',
                            lookupFunction: true
                        },
                        {
                            regex: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g,
                            category: 'onmessage-assignment'
                        },
                        {
                            regex: /(?:window\.)?onmessage\s*=\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/g,
                            category: 'onmessage-arrow',
                            process: (match) => {
                                const params = match[1] || 'event';
                                const body = match[2] || '';
                                return `function(${params}) { ${body} }`;
                            }
                        },
                        {
                            regex: /(?:window\.)?onmessage\s*=\s*([a-zA-Z0-9_$]+)\s*;/g,
                            category: 'onmessage-reference',
                            lookupFunction: true
                        }
                    ];


                    const functionDefRegex = /function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{[\s\S]*?\}/g;
                    let funcMatch;
                    while ((funcMatch = functionDefRegex.exec(allScriptContent)) !== null) {
                        const funcName = funcMatch[1];
                        const funcCode = funcMatch[0];
                        handlerFunctions.set(funcName, funcCode);
                    }

                    patterns.forEach(pattern => {
                        let match;
                        while ((match = pattern.regex.exec(allScriptContent)) !== null) {
                            try {
                                let handlerCode;

                                if (pattern.lookupFunction) {
                                    const funcName = match[1];
                                    if (handlerFunctions.has(funcName)) {
                                        handlerCode = handlerFunctions.get(funcName);
                                    } else {
                                        continue;
                                    }
                                } else if (pattern.process) {
                                    handlerCode = pattern.process(match);
                                } else {
                                    handlerCode = match[1];
                                }

                                if (handlerCode && !shouldIgnoreHandler(handlerCode)) {
                                    extractedHandlers.push({
                                        handler: handlerCode,
                                        category: pattern.category,
                                        source: 'inline-script'
                                    });
                                }
                            } catch (e) {
                                console.warn('Error processing pattern match:', e);
                            }
                        }
                    });

                    function isLikelyHandler(funcBody) {
                        const indicators = [
                            'event.data', 'e.data', 'message.data', 'msg.data',
                            'event.origin', 'e.origin',
                            'postMessage(',
                            'JSON.parse(', 'JSON.stringify('
                        ];
                        return indicators.some(indicator => funcBody.includes(indicator));
                    }

                    handlerFunctions.forEach((funcBody, funcName) => {
                        if (isLikelyHandler(funcBody) && !shouldIgnoreHandler(funcBody)) {
                            const isDuplicate = extractedHandlers.some(h => h.handler === funcBody);
                            if (!isDuplicate) {
                                extractedHandlers.push({
                                    handler: funcBody,
                                    category: 'likely-handler-function',
                                    source: `function-${funcName}`
                                });
                            }
                        }
                    });

                    return extractedHandlers;
                }
            });

            const allHandlers = [];

            for (const result of results) {
                if (result.result && Array.isArray(result.result)) {
                    const frameHandlers = result.result.map(handler => ({
                        ...handler,
                        score: this.scoreHandler(handler.handler)
                    }));

                    allHandlers.push(...frameHandlers);
                }
            }

            return allHandlers;

        } catch (error) {
            console.error(`[HandlerExtractor] Error in direct extraction:`, error);
            return [];
        }
    }

    injectDynamicScriptMonitor(iframe) {
        try {
            if (!iframe || !iframe.contentWindow) {
                console.warn('[HandlerExtractor] Invalid iframe for script monitoring');
                return;
            }

            let iframeDocument;
            try {
                iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                if (!iframeDocument) {
                    console.warn('[HandlerExtractor] Cannot access iframe document (possible cross-origin restriction)');
                    return;
                }
            } catch (e) {
                console.warn('[HandlerExtractor] Cross-origin restriction prevents script monitoring:', e);
                return;
            }

            const self = this;

            const messageListener = function(event) {
                if (event.data && event.data.type === 'dynamicScriptDetected') {
                    const scriptUrl = event.data.url;
                    if (scriptUrl && !self.processedScripts.has(scriptUrl)) {
                        console.log(`[HandlerExtractor] Detected dynamic script: ${scriptUrl}`);
                        self.dynamicScriptQueue.push(scriptUrl);
                        self.processedScripts.add(scriptUrl);
                    }
                }
            };

            window.addEventListener('message', messageListener);

            this._messageListener = messageListener;

            const scriptMonitor = `
            (function() {
                try {
                    const originalCreateElement = document.createElement;
                    document.createElement = function(tagName) {
                        const element = originalCreateElement.call(document, tagName);
                        if (tagName.toLowerCase() === 'script') {
                            const originalSetAttribute = element.setAttribute;
                            element.setAttribute = function(name, value) {
                                if (name === 'src' && value) {
                                    try {
                                        window.parent.postMessage({
                                            type: 'dynamicScriptDetected',
                                            url: value
                                        }, '*');
                                    } catch(e) {
                                        console.warn("Error sending script detection message:", e);
                                    }
                                }
                                return originalSetAttribute.call(this, name, value);
                            };
                            
                            try {
                                const originalSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
                                Object.defineProperty(element, 'src', {
                                    set: function(value) {
                                        if (value) {
                                            try {
                                                window.parent.postMessage({
                                                    type: 'dynamicScriptDetected',
                                                    url: value
                                                }, '*');
                                            } catch(e) {}
                                        }
                                        return originalSrcDescriptor.set.call(this, value);
                                    },
                                    get: function() {
                                        return originalSrcDescriptor.get.call(this);
                                    }
                                });
                            } catch(e) {}
                        }
                        return element;
                    };
                    
                    try {
                        const observer = new MutationObserver(mutations => {
                            for (const mutation of mutations) {
                                if (mutation.type === 'childList') {
                                    for (const node of mutation.addedNodes) {
                                        if (node.tagName === 'SCRIPT' && node.src) {
                                            try {
                                                window.parent.postMessage({
                                                    type: 'dynamicScriptDetected',
                                                    url: node.src
                                                }, '*');
                                            } catch(e) {}
                                        }
                                    }
                                }
                            }
                        });
                        
                        observer.observe(document.documentElement, { childList: true, subtree: true });
                    } catch(e) {}
                    
                    try {
                        const originalAppendChild = Node.prototype.appendChild;
                        Node.prototype.appendChild = function(node) {
                            if (node && node.tagName === 'SCRIPT' && node.src) {
                                try {
                                    window.parent.postMessage({
                                        type: 'dynamicScriptDetected',
                                        url: node.src
                                    }, '*');
                                } catch(e) {}
                            }
                            return originalAppendChild.call(this, node);
                        };
                    } catch(e) {}
                    
                    try {
                        const originalInsertBefore = Node.prototype.insertBefore;
                        Node.prototype.insertBefore = function(newNode, referenceNode) {
                            if (newNode && newNode.tagName === 'SCRIPT' && newNode.src) {
                                try {
                                    window.parent.postMessage({
                                        type: 'dynamicScriptDetected',
                                        url: newNode.src
                                    }, '*');
                                } catch(e) {}
                            }
                            return originalInsertBefore.call(this, newNode, referenceNode);
                        };
                    } catch(e) {}
                    
                    try {
                        const originalFetch = window.fetch;
                        window.fetch = function(resource, options) {
                            const url = resource instanceof Request ? resource.url : resource;
                            if (typeof url === 'string' && url.endsWith('.js')) {
                                try {
                                    window.parent.postMessage({
                                        type: 'dynamicScriptDetected',
                                        url: url
                                    }, '*');
                                } catch(e) {}
                            }
                            return originalFetch.apply(this, arguments);
                        };
                    } catch(e) {}
                    
                    try {
                        const originalXHROpen = XMLHttpRequest.prototype.open;
                        XMLHttpRequest.prototype.open = function(method, url) {
                            if (typeof url === 'string' && url.endsWith('.js')) {
                                try {
                                    window.parent.postMessage({
                                        type: 'dynamicScriptDetected',
                                        url: url
                                    }, '*');
                                } catch(e) {}
                            }
                            return originalXHROpen.apply(this, arguments);
                        };
                    } catch(e) {}
                    
                    console.log("[HandlerExtractor] Dynamic script monitoring initialized");
                } catch(e) {
                    console.error("[HandlerExtractor] Error initializing script monitor:", e);
                }
            })();
        `;

            try {
                if (iframeDocument.readyState === 'loading') {
                    iframe.contentWindow.addEventListener('DOMContentLoaded', () => {
                        try {
                            const scriptEl = iframeDocument.createElement('script');
                            scriptEl.textContent = scriptMonitor;
                            iframeDocument.head.appendChild(scriptEl);
                        } catch (error) {
                            console.warn('[HandlerExtractor] Failed to inject monitor after DOM ready:', error);
                        }
                    });
                } else {
                    if (iframeDocument.head) {
                        const scriptEl = iframeDocument.createElement('script');
                        scriptEl.textContent = scriptMonitor;
                        iframeDocument.head.appendChild(scriptEl);
                    } else if (iframeDocument.body) {
                        const scriptEl = iframeDocument.createElement('script');
                        scriptEl.textContent = scriptMonitor;
                        iframeDocument.body.appendChild(scriptEl);
                    } else {
                        const scriptEl = iframeDocument.createElement('script');
                        scriptEl.textContent = scriptMonitor;
                        iframeDocument.appendChild(scriptEl);
                    }
                }

                console.log('[HandlerExtractor] Script monitor injected successfully');
            } catch (error) {
                try {
                    console.warn('[HandlerExtractor] Trying alternative script injection method');

                    this._checkForScriptsInterval = setInterval(() => {
                        try {
                            const scripts = iframeDocument.querySelectorAll('script[src]');
                            scripts.forEach(script => {
                                const src = script.getAttribute('src');
                                if (src && !this.processedScripts.has(src)) {
                                    this.dynamicScriptQueue.push(src);
                                    this.processedScripts.add(src);
                                    console.log(`[HandlerExtractor] Detected script via polling: ${src}`);
                                }
                            });
                        } catch (e) {
                            clearInterval(this._checkForScriptsInterval);
                        }
                    }, 500);

                    setTimeout(() => {
                        if (this._checkForScriptsInterval) {
                            clearInterval(this._checkForScriptsInterval);
                            this._checkForScriptsInterval = null;
                        }
                    }, 8000);
                } catch (fallbackError) {
                    console.warn('[HandlerExtractor] Alternative method also failed:', fallbackError);
                }

                console.error('[HandlerExtractor] Failed to inject script monitor:', error);
            }
        } catch (error) {
            console.error("[HandlerExtractor] Error in script monitor setup:", error);
        }
    }

    async getAllLoadedScripts(tabId) {
        return new Promise((resolve, reject) => {
            try {
                if (!chrome || !chrome.debugger) {
                    console.warn('[HandlerExtractor] Chrome debugger API not available');
                    resolve([]);
                    return;
                }

                if (!tabId) {
                    console.warn('[HandlerExtractor] Invalid tabId provided to getAllLoadedScripts');
                    resolve([]);
                    return;
                }

                const onAttach = () => {
                    if (chrome.runtime.lastError) {
                        console.warn('[HandlerExtractor] Error attaching debugger:', chrome.runtime.lastError.message);
                        resolve([]);
                        return;
                    }

                    chrome.debugger.sendCommand({tabId}, "Runtime.evaluate", {
                        expression: `
                        Array.from(document.scripts)
                            .filter(s => s.src)
                            .map(s => s.src);
                    `
                    }, (response) => {
                        try {
                            chrome.debugger.detach({tabId});
                        } catch (detachError) {
                            console.warn('[HandlerExtractor] Error detaching debugger:', detachError);
                        }

                        if (chrome.runtime.lastError) {
                            console.warn('[HandlerExtractor] Error in sendCommand:', chrome.runtime.lastError.message);
                            resolve([]);
                            return;
                        }

                        let scriptUrls = [];
                        try {
                            scriptUrls = response && response.result && response.result.value ? response.result.value : [];
                        } catch (parseError) {
                            console.warn('[HandlerExtractor] Error parsing script URLs:', parseError);
                        }

                        resolve(scriptUrls);
                    });
                };

                chrome.debugger.attach({tabId}, "1.3", onAttach);
            } catch (error) {
                console.error("[HandlerExtractor] Error getting loaded scripts:", error);
                resolve([]);
            }
        });
    }

    async extractFromExternalScripts() {
        try {
            const scriptUrls = new Set();
            const processedUrls = new Set();
            const extractedHandlers = [];

            const urlObj = new URL(this.endpoint);
            const tabs = await chrome.tabs.query({});
            const matchingTabs = tabs.filter(tab => tab.url && tab.url.includes(urlObj.hostname));

            let tabId;
            if (matchingTabs.length > 0) {
                tabId = matchingTabs[0].id;
                console.log(`[HandlerExtractor] Found matching tab ID: ${tabId}`);
            } else {
                const newTab = await chrome.tabs.create({ url: this.endpoint, active: false });
                tabId = newTab.id;
                console.log(`[HandlerExtractor] Created new tab with ID: ${tabId}`);

                await new Promise(resolve => {
                    const listener = (changedTabId, changeInfo) => {
                        if (changedTabId === tabId && changeInfo.status === 'complete') {
                            chrome.tabs.onUpdated.removeListener(listener);
                            resolve();
                        }
                    };
                    chrome.tabs.onUpdated.addListener(listener);
                    setTimeout(resolve, 3000);
                });
            }

            try {
                const performanceResults = await chrome.scripting.executeScript({
                    target: { tabId },
                    func: () => {
                        const resources = performance.getEntriesByType("resource");
                        return resources
                            .filter(entry => entry.name.endsWith('.js') ||
                                entry.initiatorType === 'script' ||
                                entry.name.includes('remoteEntry'))
                            .map(entry => entry.name);
                    }
                });

                if (performanceResults?.[0]?.result) {
                    performanceResults[0].result.forEach(url => scriptUrls.add(url));
                    console.log(`[HandlerExtractor] Performance API found ${performanceResults[0].result.length} scripts`);
                }
            } catch (error) {
                console.warn(`[HandlerExtractor] Performance API failed:`, error);
            }

            try {
                const scriptTagResults = await chrome.scripting.executeScript({
                    target: { tabId },
                    func: () => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
                });

                if (scriptTagResults?.[0]?.result) {
                    scriptTagResults[0].result.forEach(url => scriptUrls.add(url));
                    console.log(`[HandlerExtractor] Script tags found ${scriptTagResults[0].result.length} scripts`);
                }
            } catch (error) {
                console.warn(`[HandlerExtractor] Script tag extraction failed:`, error);
            }

            try {
                await chrome.scripting.executeScript({
                    target: { tabId },
                    func: () => {
                        if (!window._injected) {
                            window._injected = true;
                            window._scriptUrls = new Set();

                            const report = (url) => {
                                if (!url) return;
                                window._scriptUrls.add(url);
                                const marker = document.createElement('div');
                                marker.className = 'script-detection-marker';
                                marker.dataset.url = url;
                                marker.style.display = 'none';
                                document.body.appendChild(marker);
                            };

                            if (window.__webpack_require__ && window.__webpack_require__.l) {
                                const original = window.__webpack_require__.l;
                                window.__webpack_require__.l = function(url, ...args) {
                                    report(url);
                                    return original.apply(this, arguments);
                                };
                            }

                            for (const key in window) {
                                try {
                                    if (typeof window[key] === 'object' && window[key] &&
                                        typeof window[key].l === 'function') {
                                        const original = window[key].l;
                                        window[key].l = function(url, ...args) {
                                            report(url);
                                            return original.apply(this, arguments);
                                        };
                                    }
                                } catch (e) {}
                            }

                            const originalCreateElement = document.createElement;
                            document.createElement = function(tagName) {
                                const element = originalCreateElement.call(document, tagName);
                                if (tagName.toLowerCase() === 'script') {
                                    const originalSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
                                    Object.defineProperty(element, 'src', {
                                        set: function(value) {
                                            if (value) report(value);
                                            return originalSrcDescriptor.set.call(this, value);
                                        },
                                        get: function() {
                                            return originalSrcDescriptor.get.call(this);
                                        }
                                    });
                                }
                                return element;
                            };
                        }
                        return Array.from(window._scriptUrls || []);
                    }
                });
            } catch (error) {
                console.warn(`[HandlerExtractor] Webpack hook failed:`, error);
            }

            try {
                await chrome.tabs.reload(tabId);

                for (let i = 0; i < 5; i++) {
                    await new Promise(resolve => setTimeout(resolve, 500));

                    const markerResults = await chrome.scripting.executeScript({
                        target: { tabId },
                        func: () => {
                            const markers = document.querySelectorAll('.script-detection-marker');
                            const urls = [];
                            markers.forEach(marker => {
                                const url = marker.dataset.url;
                                if (url) urls.push(url);
                                marker.remove();
                            });
                            return urls;
                        }
                    });

                    if (markerResults?.[0]?.result) {
                        markerResults[0].result.forEach(url => scriptUrls.add(url));
                    }

                    const storedResults = await chrome.scripting.executeScript({
                        target: { tabId },
                        func: () => Array.from(window._scriptUrls || [])
                    });

                    if (storedResults?.[0]?.result) {
                        storedResults[0].result.forEach(url => scriptUrls.add(url));
                    }

                }
            } catch (error) {
                console.warn(`[HandlerExtractor] Polling failed:`, error);
            }

            console.log(`[HandlerExtractor] Processing ${scriptUrls.size} scripts`);
            for (const url of Array.from(scriptUrls)) {
                if (processedUrls.has(url)) continue;
                processedUrls.add(url);

                try {
                    console.log(`[HandlerExtractor] Fetching: ${url}`);
                    const response = await fetch(url, {
                        credentials: 'omit',
                        cache: 'no-store'
                    });

                    if (!response.ok) {
                        console.warn(`[HandlerExtractor] Failed to fetch ${url}: ${response.status}`);
                        continue;
                    }

                    const content = await response.text();

                    const handlers = this.extractFromJavaScriptContent(content);
                    if (handlers.length > 0) {
                        handlers.forEach(handler => {
                            extractedHandlers.push({...handler, source: url});
                        });
                        console.log(`[HandlerExtractor] Found ${handlers.length} handlers in ${url}`);
                    }

                    else if (content.includes('addEventListener') &&
                        content.includes('message') &&
                        (content.includes('event.data') || content.includes('e.data'))) {

                        const patterns = [
                            /addEventListener\s*\(\s*['"]message['"]\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/,
                            /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/
                        ];

                        let handlerCode = null;
                        for (const pattern of patterns) {
                            const match = content.match(pattern);
                            if (match) {
                                if (pattern.toString().includes('=>')) {
                                    const params = match[1] || 'event';
                                    const body = match[2];
                                    handlerCode = `function(${params}) { ${body} }`;
                                } else {
                                    handlerCode = match[1];
                                }
                                break;
                            }
                        }

                        if (handlerCode) {
                            extractedHandlers.push({
                                handler: handlerCode,
                                score: 7,
                                category: 'extracted-handler',
                                source: url
                            });
                            console.log(`[HandlerExtractor] Extracted handler from ${url}`);
                        }
                    }

                    const chunkPattern = /__webpack_require__\.l\s*\(\s*["']([^"']+)["']/g;
                    let match;
                    while ((match = chunkPattern.exec(content)) !== null) {
                        try {
                            const chunkUrl = match[1];
                            const fullUrl = this.resolveScriptUrl(chunkUrl, url);
                            if (!scriptUrls.has(fullUrl) && !processedUrls.has(fullUrl)) {
                                scriptUrls.add(fullUrl);
                                console.log(`[HandlerExtractor] Found webpack chunk: ${chunkUrl} → ${fullUrl}`);
                            }
                        } catch (error) {
                            console.warn(`[HandlerExtractor] Error resolving chunk URL:`, error);
                        }
                    }
                } catch (error) {
                    console.warn(`[HandlerExtractor] Error processing ${url}:`, error);
                }
            }

            if (matchingTabs.length === 0) {
                try {
                    await chrome.tabs.remove(tabId);
                    console.log(`[HandlerExtractor] Closed tab ${tabId}`);
                } catch (error) {
                    console.warn(`[HandlerExtractor] Error closing tab:`, error);
                }
            }

            console.log(`[HandlerExtractor] Found ${extractedHandlers.length} handlers from ${scriptUrls.size} scripts`);
            return extractedHandlers;
        } catch (error) {
            console.error(`[HandlerExtractor] Fatal error:`, error);
            return [];
        }
    }

    /**
     * Inject a content script to help detect scripts in cross-origin iframes
     */
    async injectContentScriptForScriptDetection() {
        try {
            const url = new URL(this.endpoint);
            const pattern = `*://${url.hostname}/*`;

            console.log(`[HandlerExtractor] Looking for tabs matching pattern: ${pattern}`);
            const matchingTabs = await chrome.tabs.query({url: pattern});

            if (matchingTabs.length === 0) {
                console.log(`[HandlerExtractor] No matching tabs found for content script injection`);
                return false;
            }

            const tabId = matchingTabs[0].id;
            console.log(`[HandlerExtractor] Found matching tab with ID: ${tabId}`);

            const scriptDetectorCode = `
            console.log("[HandlerExtractor] Script detector running in tab");
            
            const existingScripts = Array.from(document.querySelectorAll('script[src]'))
                .map(script => script.src);
                
            console.log("[HandlerExtractor] Found " + existingScripts.length + " existing script tags");
                
            existingScripts.forEach(url => {
                window.top.postMessage({
                    type: 'scriptDetected',
                    url: url
                }, '*');
            });
            
            const observer = new MutationObserver(mutations => {
                for (const mutation of mutations) {
                    if (mutation.type === 'childList') {
                        for (const node of mutation.addedNodes) {
                            if (node.tagName === 'SCRIPT' && node.src) {
                                console.log("[HandlerExtractor] Detected new script: " + node.src);
                                window.top.postMessage({
                                    type: 'scriptDetected',
                                    url: node.src
                                }, '*');
                            }
                        }
                    }
                }
            });
            
            observer.observe(document.documentElement, { 
                childList: true, 
                subtree: true 
            });
            
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(document, tagName);
                if (tagName.toLowerCase() === 'script') {
                    console.log("[HandlerExtractor] Script element created");
                    const originalSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
                    Object.defineProperty(element, 'src', {
                        set: function(value) {
                            if (value) {
                                console.log("[HandlerExtractor] Script src set: " + value);
                                window.top.postMessage({
                                    type: 'scriptDetected',
                                    url: value
                                }, '*');
                            }
                            return originalSrcDescriptor.set.call(this, value);
                        },
                        get: function() {
                            return originalSrcDescriptor.get.call(this);
                        }
                    });
                }
                return element;
            };
            
            setTimeout(() => {
                console.log("[HandlerExtractor] Script detector completed initial scan");
            }, 1000);
        `;

            await chrome.scripting.executeScript({
                target: { tabId: tabId, allFrames: true },
                func: new Function(scriptDetectorCode),
            });

            console.log(`[HandlerExtractor] Injected script detector into tab ${tabId}`);
            return true;
        } catch (error) {
            console.warn(`[HandlerExtractor] Error injecting content script: ${error}`);
            return false;
        }
    }


    extractFromJavaScriptContent(jsContent) {
        if (!jsContent || typeof jsContent !== 'string') return [];
        const foundHandlers = [];
        const functionDefinitions = new Map();
        const methodDefinitions = new Map();

        const functionDefRegex = /function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{[\s\S]*?\}/g;
        let funcMatch;
        while ((funcMatch = functionDefRegex.exec(jsContent)) !== null) {
            functionDefinitions.set(funcMatch[1], funcMatch[0]);
        }

        const methodDefRegex = /(\w+)\s*[:(]?\s*(?:function)?\s*\(([^)]*)\)\s*(?:=>)?\s*\{([\s\S]*?)\}(?=[;\n\s]*[}\),])/g;
        let methodMatch;
        while ((methodMatch = methodDefRegex.exec(jsContent)) !== null) {
            const methodName = methodMatch[1];
            const methodBody = methodMatch[0];
            if (methodName && !functionDefinitions.has(methodName)) {
                methodDefinitions.set(methodName, methodBody);
            }
        }
        functionDefinitions.forEach((body, name) => {
            if (!methodDefinitions.has(name)) {
                methodDefinitions.set(name, body);
            }
        });

        const listenerPatterns = [
            { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener-window', score: 20, type: 'inline' },
            { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener', score: 10, type: 'inline' },
            { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow-window', score: 19, type: 'arrow', process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
            { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow', score: 9, type: 'arrow', process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
            { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference-window', score: 12, type: 'reference' },
            { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference', score: 7, type: 'reference' },
            { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:this\.|[a-zA-Z0-9_$]+\.)([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'method-reference', score: 15, type: 'method_reference' },
            { regex: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g, category: 'onmessage-assignment', score: 9, type: 'inline' },
            { regex: /(?:window\.)?onmessage\s*=\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/g, category: 'onmessage-arrow', score: 8, type: 'arrow', process: (match) => `function(${match[1] || 'event'}) { ${match[2] || ''} }` },
            { regex: /(?:window\.)?onmessage\s*=\s*([a-zA-Z0-9_$]+)\s*;/g, category: 'onmessage-reference', score: 7, type: 'reference' },
            { regex: /window\.addEventListener\("message",\s*\(([^)]*)\s*=>\s*\{\s*this\.([a-zA-Z0-9_$]+)\(.*?\)\s*\}\s*\)/g, category: 'frame-communication-delegate', score: 25, type: 'delegator', getDetails: (match) => ({ delegateParam: match[1], delegateMethodName: match[2] }) }
        ];

        listenerPatterns.forEach(patternObj => {
            const { regex, category, score = 0, type, process, getDetails } = patternObj;
            regex.lastIndex = 0;
            let match;
            while ((match = regex.exec(jsContent)) !== null) {
                try {
                    let handlerCode;
                    let handlerKey = '';
                    let details = getDetails ? getDetails(match) : {};

                    switch (type) {
                        case 'inline':
                            handlerCode = match[1];
                            break;
                        case 'arrow':
                            handlerCode = process(match);
                            break;
                        case 'reference':
                            handlerKey = match[1];
                            handlerCode = functionDefinitions.get(handlerKey);
                            break;
                        case 'method_reference':
                            handlerKey = match[1];
                            handlerCode = methodDefinitions.get(handlerKey);
                            break;
                        case 'delegator':
                            handlerKey = details.delegateMethodName;
                            handlerCode = match[0];
                            break;
                        default:
                            handlerCode = null;
                    }

                    if (!handlerCode) continue;
                    if (handlerCode.length < 20) continue;

                    foundHandlers.push({
                        handler: handlerCode,
                        category,
                        score: this.scoreHandler(handlerCode, category) + score,
                        sourceText: jsContent,
                        isDelegator: (type === 'delegator'),
                        details: details
                    });

                } catch (error) { console.warn(`[HandlerExtractor] Error processing listener pattern match:`, error); }
            }
        });

        return foundHandlers;
    }

    combineDelegatedHandlers(handlers) {
        const combined = [];
        const implementations = handlers.filter(h => h.category === 'frame-communication-impl' || h.category === 'delegated-method');
        const delegators = handlers.filter(h => h.isDelegator);
        const others = handlers.filter(h => !h.isDelegator && h.category !== 'frame-communication-impl' && h.category !== 'delegated-method');

        delegators.forEach(del => {
            const methodName = del.details?.delegateMethodName;
            if (methodName) {
                const matchingImpl = implementations
                    .filter(impl => impl.methodName === methodName || impl.handler.startsWith(methodName + '(') || impl.handler.startsWith(methodName + ':'))
                    .sort((a, b) => b.handler.length - a.handler.length)[0];
                if (matchingImpl) {
                    combined.push({
                        ...del,
                        handler: `${del.handler}\n\n// Implementation for ${methodName}:\n${matchingImpl.handler}`,
                        score: del.score + 5,
                        category: 'combined-delegate-impl',
                        combined: true
                    });
                    matchingImpl.usedInCombination = true;
                } else { combined.push(del); }
            } else { combined.push(del); }
        });
        combined.push(...others);
        return combined;
    }

    /**
     * Extract handlers using the tabs API (most comprehensive but slower)
     * @returns {Promise<Array>} - Extracted handlers
     */
    async extractFromTabs() {
        try {
            const matchingTabs = await this.findMatchingTabs();
            if (!matchingTabs.length) {
                return [];
            }

            const targetTab = matchingTabs[0];
            const scriptUrls = new Set();

            if (matchingTabs.length > 0) {
                const runtimeScripts = await this.getAllLoadedScripts(matchingTabs[0].id);
                console.log(`[HandlerExtractor] Found ${runtimeScripts.length} runtime scripts`);
                runtimeScripts.forEach(url => scriptUrls.add(url));
            }

            const results = await chrome.scripting.executeScript({
                target: { tabId: targetTab.id, allFrames: true },
                func: () => {
                    return new Promise(async (resolve) => {
                        const foundHandlers = [];
                        const baseUrl = document.baseURI || window.location.href;

                        function resolveUrl(relativeUrl) {
                            try {
                                if (relativeUrl.startsWith('http')) return relativeUrl;
                                if (relativeUrl.startsWith('//')) return 'https:' + relativeUrl;

                                const urlObj = new URL(relativeUrl, baseUrl);
                                return urlObj.href;
                            } catch (e) {
                                console.warn('Error resolving URL:', e);
                                return relativeUrl;
                            }
                        }

                        const scriptUrls = new Set();
                        let inlineContent = '';

                        document.querySelectorAll('script').forEach(script => {
                            if (script.src) {
                                scriptUrls.add(resolveUrl(script.src));
                            } else if (script.textContent) {
                                inlineContent += script.textContent + '\n';
                            }
                        });

                        const scriptLoaderRegex = /(?:document\.createElement\s*\(\s*['"]script['"]\s*\)[^;]*?\.src\s*=\s*['"]([^'"]+)['"])|(?:loadScript\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
                        let loaderMatch;

                        while ((loaderMatch = scriptLoaderRegex.exec(inlineContent)) !== null) {
                            const scriptUrl = loaderMatch[1] || loaderMatch[2];
                            if (scriptUrl) {
                                scriptUrls.add(resolveUrl(scriptUrl));
                            }
                        }

                        const fetchedScripts = [];

                        async function fetchScript(url) {
                            try {
                                const response = await fetch(url, {
                                    credentials: 'same-origin',
                                    referrerPolicy: 'no-referrer-when-downgrade',
                                    cache: 'no-store'
                                });

                                if (response.ok) {
                                    const text = await response.text();
                                    return { url, content: text, success: true };
                                }
                            } catch (e) {
                            }
                            return { url, content: '', success: false };
                        }

                        const fetchPromises = Array.from(scriptUrls).map(url => {
                            return Promise.race([
                                fetchScript(url),
                                new Promise(r => setTimeout(() => r({ url, content: '', success: false }), 2000))
                            ]);
                        });

                        const results = await Promise.all(fetchPromises);
                        results.forEach(result => {
                            if (result.success) {
                                fetchedScripts.push(result.content);
                            }
                        });

                        const allScriptContent = inlineContent + '\n' + fetchedScripts.join('\n');

                        function processPatterns(content) {
                            const handlerPatterns = [
                                {
                                    regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g,
                                    category: 'addEventListener-function'
                                },
                                {
                                    regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g,
                                    category: 'addEventListener-arrow',
                                    process: (match) => {
                                        const params = match[1] || 'event';
                                        const body = match[2] || '';
                                        return `function(${params}) { ${body} }`;
                                    }
                                },
                                {
                                    regex: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g,
                                    category: 'onmessage-assignment'
                                },
                                {
                                    regex: /function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{([\s\S]*?(?:event|e|msg|message)\.data[\s\S]*?)\}/g,
                                    category: 'event-data-function'
                                }
                            ];

                            const handlerResults = [];

                            const functionDefs = new Map();
                            const functionDefRegex = /function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{[\s\S]*?\}/g;
                            let funcDef;

                            while ((funcDef = functionDefRegex.exec(content)) !== null) {
                                functionDefs.set(funcDef[1], funcDef[0]);
                            }

                            handlerPatterns.forEach(pattern => {
                                let match;
                                while ((match = pattern.regex.exec(content)) !== null) {
                                    try {
                                        let handler;

                                        if (pattern.process) {
                                            handler = pattern.process(match);
                                        } else {
                                            handler = match[0];
                                        }

                                        if (handler && handler.length > 30) {
                                            handlerResults.push({
                                                handler,
                                                category: pattern.category
                                            });
                                        }
                                    } catch (e) {
                                    }
                                }
                            });

                            return handlerResults;
                        }

                        const handlers = processPatterns(allScriptContent);

                        if (window.onmessage && typeof window.onmessage === 'function') {
                            handlers.push({
                                handler: window.onmessage.toString(),
                                category: 'active-onmessage'
                            });
                        }

                        resolve(handlers);
                    });
                }
            });

            const allHandlers = [];

            for (const result of results) {
                if (result.result && Array.isArray(result.result)) {
                    const frameHandlers = result.result.map(handler => ({
                        ...handler,
                        score: this.scoreHandler(handler.handler),
                        source: 'comprehensive-tab-scan'
                    }));

                    allHandlers.push(...frameHandlers);
                }
            }

            return allHandlers;

        } catch (error) {
            console.error(`[HandlerExtractor] Error in tab extraction:`, error);
            return [];
        }
    }

    /**
     * Get saved messages from storage for better scoring
     * @returns {Promise<Array>} - Saved messages
     */
    async getSavedMessages() {
        if (!this.baseEndpoint) return [];
        const storageKey = `saved-messages-${this.baseEndpoint}`;
        try {
            return new Promise(resolve => {
                chrome.storage.local.get([storageKey], result => {
                    const saved = result[storageKey] || [];
                    console.log(`[HandlerExtractor] Retrieved ${saved.length} saved messages from storage key ${storageKey}`);
                    resolve(saved);
                });
            });
        } catch (error) {
            console.error(`[HandlerExtractor] Error getting saved messages (${storageKey}):`, error);
            return [];
        }
    }

    /**
     * Enhance scoring using saved messages
     * @param {Array} savedMessages - Additional messages to use for scoring
     */
    enhanceScores(savedMessages) {
        if (!savedMessages || savedMessages.length === 0) return;
        console.log(`[HandlerExtractor] Re-scoring ${this.handlers.length} handlers using ${savedMessages.length} messages.`);
        this.handlers.forEach(handler => {
            handler.score = this.scoreHandler(handler.handler, handler.category, savedMessages);
        });
        // Re-sort based on new scores
        this.handlers.sort((a, b) => b.score - a.score);
    }

    /**
     * Generate a synthetic handler when no real handlers are found
     * @param {Array} messages - Messages to use for handler generation
     * @returns {Object} - Synthetic handler
     */
    generateSyntheticHandler(messages = []) {
        let template = `function(event) {
      if (!event || !event.data) return;
      
      
      console.log('Received message:', event.data);
      
      try {
        const data = typeof event.data === 'string' 
          ? JSON.parse(event.data) 
          : event.data;
    `;

        const messageTypes = new Set();
        const messageProperties = new Set();

        const allMessages = [...messages, ...this.messages];

        allMessages.forEach(message => {
            try {
                let msgData = message.data;
                if (typeof msgData === 'string') {
                    try {
                        msgData = JSON.parse(msgData);
                    } catch (e) {
                        return;
                    }
                }

                if (typeof msgData === 'object' && msgData !== null) {
                    if (msgData.type) messageTypes.add(msgData.type);
                    if (msgData.action) messageTypes.add(msgData.action);
                    if (msgData.messageType) messageTypes.add(msgData.messageType);
                    if (msgData.kind) messageTypes.add(msgData.kind);

                    Object.keys(msgData).forEach(key => {
                        if (!['type', 'action', 'messageType', 'kind'].includes(key)) {
                            messageProperties.add(key);
                        }
                    });
                }
            } catch (e) {
            }
        });

        if (messageTypes.size > 0) {
            template += `
        const messageType = data.type || data.action || data.messageType || data.kind;
        
        switch (messageType) {
      `;

            messageTypes.forEach(type => {
                template += `          case '${type}':
            console.log('Processing ${type} message');
            break;
            
        `;
            });

            template += `          default:
            console.log('Unknown message type:', messageType);
            break;
        }
      `;
        } else if (messageProperties.size > 0) {
            template += `        
      `;

            const commonProps = Array.from(messageProperties).slice(0, 5);
            commonProps.forEach(prop => {
                template += `        if (data.${prop} !== undefined) {
          console.log('Processing ${prop}:', data.${prop});
        }
        
      `;
            });
        }

        template += `        
        if (event.source && typeof event.source.postMessage === 'function') {
          event.source.postMessage({
            type: 'response',
            status: 'received',
            receivedData: data
          }, event.origin);
        }
      } catch (error) {
        console.error('Error processing message:', error);
      }
    }`;

        return {
            handler: template,
            score: 5,
            category: 'synthetic',
            source: 'generated'
        };
    }

    /**
     * Check if a string is likely a message handler
     * @param {string} handlerStr - String to check
     * @returns {boolean} - True if likely a handler
     */
    isLikelyHandler(handlerStr) {
        if (!handlerStr || typeof handlerStr !== 'string') return false;

        return (handlerStr.includes('function') || handlerStr.includes('=>')) &&
            (handlerStr.includes('event') ||
                handlerStr.includes('message') ||
                handlerStr.includes('data') ||
                handlerStr.includes('e.') ||
        handlerStr.includes('message') ||
        handlerStr.includes('data') ||
        handlerStr.includes('e.') ||
        handlerStr.includes('msg'));
    }

    /**
     * Score a handler based on its contents
     * @param {string} handlerStr - Handler code to score
     * @returns {number} - Score value
     */
    scoreHandler(handlerStr, category = '', relevantMessages = []) {
        if (!handlerStr || typeof handlerStr !== 'string') return 0;
        let score = 0;
        let scoreDetails = { base: 0, keywordHits: {}, messageMatchBonus: 0, categoryBonus: 0, lengthPenalty: 0, miscPenalty: 0 };

        Object.entries(this.scoreWeights).forEach(([feature, weight]) => {
            let regex;
            if (feature.match(/^[a-zA-Z0-9_$.]+$/) && !feature.includes('(') && !feature.includes('"')) {
                regex = new RegExp(`\\b${feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
            } else {
                regex = new RegExp(feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
            }
            try {
                const matches = handlerStr.match(regex);
                if (matches) {
                    const count = matches.length;
                    score += weight * count;
                    scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + (weight * count);
                }
            } catch (e) {
                if (handlerStr.includes(feature)) {
                    score += weight;
                    scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + weight;
                }
            }
        });
        scoreDetails.base = score;

        let messageBonus = 0;
        const MAX_MESSAGE_BONUS = 25;
        if (relevantMessages.length > 0) {
            const messageKeys = new Set();
            const messageStringValues = new Set();
            relevantMessages.forEach(message => {
                try {
                    let data = message.data;
                    if (typeof data === 'string') { try { data = JSON.parse(data); } catch (e) { messageStringValues.add(data); return; } }
                    if (typeof data === 'object' && data !== null) {
                        Object.keys(data).forEach(key => messageKeys.add(key));
                        Object.entries(data).forEach(([key, value]) => { if (typeof value === 'string') messageStringValues.add(value); });
                    } else if (typeof data === 'string') {
                        messageStringValues.add(data);
                    }
                } catch (e) {}
            });

            messageKeys.forEach(key => {
                const keyRegex = new RegExp(`[.\\s\\[]['"]${key}['"]\\]?`, 'g');
                if (keyRegex.test(handlerStr)) { messageBonus += 3; }
            });

            messageStringValues.forEach(value => {
                if (value && value.length > 3 && value.length < 50) {
                    const valueRegex = new RegExp(`['"\`]${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`);
                    if (valueRegex.test(handlerStr)) {
                        messageBonus += 8;
                        if (handlerStr.toLowerCase().includes('messagetype') || handlerStr.toLowerCase().includes('switch') || handlerStr.toLowerCase().includes('.type') || handlerStr.toLowerCase().includes('.action')) {
                            messageBonus += 5;
                        }
                    }
                }
            });
            messageBonus = Math.min(messageBonus, MAX_MESSAGE_BONUS);
            score += messageBonus;
            scoreDetails.messageMatchBonus = messageBonus;
        }

        if (category.includes('window') || category.includes('direct-listener')) scoreDetails.categoryBonus += 8;
        if (category.includes('onmessage')) scoreDetails.categoryBonus -= 5; // Penalize onmessage slightly
        if (category.includes('runtime')) scoreDetails.categoryBonus += 15; // Bonus if captured at runtime
        if (category.includes('delegate') || category.includes('frame')) scoreDetails.categoryBonus += 10;
        if (category.includes('worker') || category.includes('synthetic')) scoreDetails.miscPenalty -= 15;
        score += scoreDetails.categoryBonus;

        const length = handlerStr.length;
        if (length < 100 && !category.includes('runtime') && !category.includes('delegate')) { scoreDetails.lengthPenalty -= 10; }
        else if (length < 50 && !category.includes('runtime') && !category.includes('delegate')) { scoreDetails.lengthPenalty -= 20; }
        score += scoreDetails.lengthPenalty;

        const finalScore = Math.max(0, Math.round(score));
        return finalScore;
    }


    /**
     * Check if we have high-quality handlers
     * @returns {boolean} - True if we have high-quality handlers
     */
    hasHighQualityWindowHandlers() {
        return this.handlers.some(handler =>
            handler.score >= 20 &&
            (handler.category?.includes('window') || handler.category?.includes('direct-listener') || handler.category?.includes('delegate') || handler.category?.includes('frame')) &&
            (handler.handler.includes('event.data') || handler.handler.includes('e.data') || handler.handler.includes('message.data'))
        );
    }

    deduplicateHandlers() {
        const unique = []; const seen = new Set();
        const categoryPriority = [ 'combined-delegate-impl', 'frame-communication-delegate', 'direct-listener-window', 'function-reference-window', 'frame-parent-communication', 'direct-listener', 'onmessage-assignment', 'onmessage-arrow', 'event-data-function', 'other', 'synthetic', 'worker' ];
        const getPriority = (cat) => { const index = categoryPriority.findIndex(p => cat?.includes(p)); return index === -1 ? 99 : index; };
        const sorted = [...this.handlers].sort((a, b) => { if (b.score !== a.score) return b.score - a.score; return getPriority(a.category) - getPriority(b.category); });
        for (const handler of sorted) {
            const fingerprint = handler.handler.split('\n').map(line => line.replace(/\s+/g, '').replace(/\/\*.*?\*\//g, '').replace(/\/\/.*$/, '').trim()).filter(line => line.length > 5 && !line.startsWith('//') && !line.startsWith('/*')).slice(0, 20).join('');
            if (!fingerprint) continue;
            if (!seen.has(fingerprint)) { seen.add(fingerprint); unique.push(handler); }
        }
        return unique;
    }

    getBestHandler(uniqueHandlers = null) {
        const handlersToConsider = uniqueHandlers || this.deduplicateHandlers();
        if (handlersToConsider.length === 0) return null;
        const priority1 = handlersToConsider.filter(h => h.score >= 25 && (h.category?.includes('combined') || h.category?.includes('delegate') || h.category?.includes('direct-listener-window')));
        if (priority1.length > 0) return priority1[0];
        const priority2 = handlersToConsider.filter(h => h.score >= 20 && h.category?.includes('frame'));
        if (priority2.length > 0) return priority2[0];
        const priority3 = handlersToConsider.filter(h => h.score >= 18 && (h.category?.includes('window') || h.category?.includes('direct-listener')));
        if (priority3.length > 0) return priority3[0];
        return handlersToConsider[0];
    }
    /**
     * Group handlers by category
     * @returns {Object} - Handlers grouped by category
     */
    groupHandlersByCategory() {
        const groups = {};

        this.handlers.forEach(handler => {
            const category = handler.category || 'unknown';
            if (!groups[category]) {
                groups[category] = [];
            }
            groups[category].push(handler);
        });

        return groups;
    }


    /**
     * Analyze vulnerabilities in handler code
     * @param {string} handlerCode - Handler code to analyze
     * @returns {Array} - Found vulnerabilities
     */
    analyzeVulnerabilities(handlerCode) {
        if (!handlerCode) return [];

        const vulnerabilities = [];
        const patterns = [
            { regex: /eval\s*\(/g, type: 'eval', severity: 'critical', details: 'Uses eval() which can lead to code injection' },
            { regex: /\.innerHTML\s*=/g, type: 'innerHTML', severity: 'high', details: 'Uses innerHTML which can lead to XSS' },
            { regex: /document\.write/g, type: 'document_write', severity: 'high', details: 'Uses document.write which can lead to XSS' },
            { regex: /setTimeout\s*\(\s*['"`]/g, type: 'setTimeout', severity: 'high', details: 'Uses setTimeout with string argument' },
            { regex: /setInterval\s*\(\s*['"`]/g, type: 'setInterval', severity: 'high', details: 'Uses setInterval with string argument' },
            { regex: /new\s+Function\s*\(/g, type: 'Function', severity: 'critical', details: 'Uses Function constructor which is similar to eval' },
            { regex: /location\s*=/g, type: 'location', severity: 'medium', details: 'Modifies location object' },
            { regex: /\.src\s*=/g, type: 'src', severity: 'medium', details: 'Sets src attribute which can lead to script injection' }
        ];

        patterns.forEach(({regex, type, severity, details}) => {
            const matches = handlerCode.match(regex);
            if (matches) {
                vulnerabilities.push({
                    type,
                    severity,
                    details,
                    count: matches.length
                });
            }
        });

        if (!handlerCode.match(/(?:event|e|msg|message)\.origin/)) {
            vulnerabilities.push({
                type: 'Missing Origin Check',
                severity: 'high',
                details: 'Handler does not validate message origin, which can lead to cross-origin attacks',
                remediation: 'Add origin validation like: if (event.origin !== "https://trusted-domain.com") return;'
            });
        } else if (handlerCode.match(/(?:event|e|msg|message)\.origin\s*==\s*['"`][^'"`]+['"`]/)) {
            vulnerabilities.push({
                type: 'Weak Origin Check',
                severity: 'medium',
                details: 'Handler uses weak origin comparison (== instead of ===)',
                remediation: 'Use strict equality (===) when comparing origins'
            });
        }

        if (!handlerCode.match(/typeof\s+(?:event|e|msg|message)\.data/)) {
            vulnerabilities.push({
                type: 'Missing Data Type Check',
                severity: 'medium',
                details: 'Handler does not validate message data type',
                remediation: 'Add type checking like: if (typeof event.data !== "object") return;'
            });
        }

        return vulnerabilities;
    }

    /**
     * Get line number from character index
     * @param {string} text - Text to analyze
     * @param {number} index - Character index
     * @returns {number} - Line number
     */
    getLineNumber(text, index) {
        return (text.substring(0, index).match(/\n/g) || []).length + 1;
    }

    /**
     * Save extracted handlers to storage
     * @returns {Promise<boolean>} - Success status
     */
    async saveToStorage() {
        if (!this.baseEndpoint) return false;

        try {
            const handlers = this.deduplicateHandlers();
            const bestHandler = this.getBestHandler();

            return new Promise(resolve => {
                chrome.storage.local.set({
                    [`handlers-${this.baseEndpoint}`]: handlers,
                    [`best-handler-${this.baseEndpoint}`]: bestHandler
                }, () => {
                    console.log(`[HandlerExtractor] Saved ${handlers.length} handlers for ${this.baseEndpoint}`);
                    resolve(true);
                });
            });
        } catch (error) {
            console.error(`[HandlerExtractor] Error saving to storage:`, error);
            return false;
        }
    }
}

window.HandlerExtractor = HandlerExtractor;
