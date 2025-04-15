/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-15 - Implemented AST-based Handler Extraction
 */

if (typeof acorn === 'undefined' || typeof acorn.parse !== 'function' || typeof acorn.walk?.ancestor !== 'function') {
    console.error("Acorn library not available to HandlerExtractor. Extraction will be limited.");
}

class HandlerExtractor {
    constructor() {
        this.handlers = [];
        this.messages = [];
        this.endpoint = null;
        this.baseEndpoint = null;
        this.scoreWeights = {
            'event.data': 8, 'e.data': 8, 'message.data': 8, 'msg.data': 8,
            '.data': 3,
            'event.origin': 10, 'e.origin': 10, 'message.origin': 10,
            'origin': 2,
            'event.source': 6, 'e.source': 6, 'message.source': 6,
            'postMessage(': 15,
            'targetOrigin': 8,
            'origin ===': 15, '.origin ===': 15,
            'trustedOrigins': 12, 'allowedOrigins': 12, 'parentOrigin': 10, 'checkOrigin': 10, 'validateOrigin': 10,
            'JSON.parse': 3, 'JSON.stringify': 2,
            'typeof': 3, 'instanceof': 2,
            'try': 1, 'catch': 1,
            'switch': 5, 'case': 4,
            'messageType': 10, 'data.type': 9, 'message.type': 9, 'event.data.type': 9,
            'action': 9, 'data.action': 9, 'kind': 9, 'data.kind': 9,
            'window.addEventListener("message"': 20,
            'addEventListener("message"': 15,
            'onmessage': 8,
            'window.parent': 5,
            'response': 2, 'callback': 2, 'resolve': 1, 'send': 1,
            'WORKER_ID': -15, 'self.onmessage': -20, 'importScripts': -20,
            'ajax': -5, 'fetch': -5, '$': -2, 'jQuery': -3,
        };
    }

    initialize(endpoint, messages = []) {
        this.endpoint = endpoint;
        this.messages = Array.isArray(messages) ? messages : [];
        try {
            if (typeof endpoint === 'string') {
                this.baseEndpoint = this.getBaseUrl(endpoint);
            }
        } catch (error) {
            console.error('[HandlerExtractor] Error initializing with endpoint:', error);
        }
        this.handlers = [];
        console.log(`[HandlerExtractor] Initialized for ${this.baseEndpoint}. Using ${this.messages.length} provided messages.`);
        return this;
    }

    getBaseUrl(url) {
        try {
            if (!url?.startsWith('http://') && !url?.startsWith('https://')) {
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

    async findMatchingTabs() {
        return new Promise((resolve) => {
            chrome.tabs.query({}, (tabs) => {
                if (!this.endpoint) { resolve([]); return; }
                try {
                    const endpointUrl = new URL(this.endpoint);
                    const matchingTabs = tabs.filter(tab => { if (!tab.url) return false; try { return tab.url.includes(endpointUrl.hostname); } catch (e) { return false; } });
                    resolve(matchingTabs);
                } catch (error) { console.error('[HandlerExtractor] Error finding matching tabs:', error); resolve([]); }
            });
        });
    }

    async extract() {
        this.handlers = [];
        const savedMessages = await this.getSavedMessages();
        const allRelevantMessages = [...this.messages, ...savedMessages];
        const strategies = [
            { name: 'scripts', method: this.extractFromExternalScriptsAST.bind(this) },
            { name: 'direct', method: this.extractDirectlyAST.bind(this) }, // Attempt AST on inline too
            // { name: 'messages', method: this.extractFromMessages.bind(this) },
        ];
        const uniqueHandlerStrings = new Set();

        for (const strategy of strategies) {
            try {
                const extractedHandlers = await strategy.method();
                if (extractedHandlers && extractedHandlers.length > 0) {
                    extractedHandlers.forEach(h => {
                        if (h.handler && typeof h.handler === 'string' && !uniqueHandlerStrings.has(h.handler)) {
                            if (typeof h.score !== 'number') {
                                h.score = this.scoreHandler(h.handler, h.category, []);
                            }
                            if (h.score >= 0) { // Basic score check
                                this.handlers.push(h);
                                uniqueHandlerStrings.add(h.handler);
                            }
                        }
                    });
                }
            } catch (error) {
                console.error(`[HandlerExtractor] Error in ${strategy.name} extraction:`, error);
            }
        }

        if (allRelevantMessages.length > 0 && this.handlers.length > 0) {
            this.enhanceScores(allRelevantMessages);
        }

        const uniqueHandlers = this.deduplicateHandlers(); // Deduplicate again after scoring if needed

        if (uniqueHandlers.length > 0) {
            this.getBestHandler(uniqueHandlers);
        } else {
            console.log("[HandlerExtractor] No valid handlers found via AST or other methods.");
            if (allRelevantMessages.length > 0) {
                const syntheticHandler = this.generateSyntheticHandler(allRelevantMessages);
                syntheticHandler.score = this.scoreHandler(syntheticHandler.handler, syntheticHandler.category, allRelevantMessages);
                uniqueHandlers.push(syntheticHandler);
                console.log("[HandlerExtractor] Generated synthetic handler as fallback.");
            }
        }

        return uniqueHandlers;
    }

    async extractFromExternalScriptsAST() {
        if (typeof acorn === 'undefined') return [];

        let scriptContents = new Map();
        try {
            const scriptUrls = new Set();
            const processedUrls = new Set();
            const urlObj = new URL(this.endpoint);
            const tabs = await chrome.tabs.query({});
            const matchingTabs = tabs.filter(tab => tab.url && tab.url.includes(urlObj.hostname));
            let tabId;

            if (matchingTabs.length > 0) { tabId = matchingTabs[0].id; }
            else { return []; }

            try { const perfResults = await chrome.scripting.executeScript({ target: { tabId }, func: () => performance.getEntriesByType("resource").filter(e => e.initiatorType === 'script' && e.name.endsWith('.js')).map(e => e.name) }); if (perfResults?.[0]?.result) perfResults[0].result.forEach(url => scriptUrls.add(url)); } catch (error) {}
            try { const tagResults = await chrome.scripting.executeScript({ target: { tabId }, func: () => Array.from(document.querySelectorAll('script[src]')).map(s => s.src) }); if (tagResults?.[0]?.result) tagResults[0].result.forEach(url => scriptUrls.add(url)); } catch (error) {}


            for (const url of Array.from(scriptUrls)) {
                if (!url || !url.startsWith('http') || processedUrls.has(url)) continue;
                processedUrls.add(url);
                try {
                    const response = await fetch(url, { credentials: 'omit', cache: 'force-cache' });
                    if (!response.ok) continue;
                    const content = await response.text();
                    if (content && content.length > 10 && (content.includes('addEventListener') || content.includes('onmessage'))) { // Basic filter
                        scriptContents.set(url, content);
                    }
                } catch (fetchError) { console.warn(`[HandlerExtractor] Failed to fetch script ${url}:`, fetchError); }
            }
        } catch (setupError) { console.error(`[HandlerExtractor] Error fetching script URLs:`, setupError); return []; }

        const allFoundHandlers = [];
        for (const [url, content] of scriptContents) {
            try {
                const handlersFromScript = this.extractHandlersFromAST(content, url);
                allFoundHandlers.push(...handlersFromScript);
            } catch (parseError) {
                console.warn(`[HandlerExtractor] Failed to parse script ${url} with Acorn:`, parseError.message);
            }
        }
        return allFoundHandlers;
    }

    async extractDirectlyAST() {
        if (typeof acorn === 'undefined') return [];
        let inlineHandlers = [];
        try {
            const matchingTabs = await this.findMatchingTabs();
            if (matchingTabs.length === 0) return [];
            const targetTab = matchingTabs[0];

            const results = await chrome.scripting.executeScript({
                target: { tabId: targetTab.id, allFrames: true },
                func: () => {
                    let scriptsContent = '';
                    document.querySelectorAll('script:not([src])').forEach(script => {
                        if(script.textContent) scriptsContent += script.textContent + ';\n'; // Add semicolon
                    });
                    let onMessageHandler = null;
                    if(window.onmessage && typeof window.onmessage === 'function') {
                        onMessageHandler = { handler: window.onmessage.toString(), category: 'onmessage-property', source: 'window.onmessage-direct' };
                    }
                    return { inlineScriptContent: scriptsContent, onMessageHandler: onMessageHandler };
                }
            });

            for (const frameResult of results) {
                if (frameResult.result) {
                    const { inlineScriptContent, onMessageHandler } = frameResult.result;
                    if (onMessageHandler) {
                        inlineHandlers.push(onMessageHandler);
                    }
                    if (inlineScriptContent) {
                        try {
                            const handlersFromInline = this.extractHandlersFromAST(inlineScriptContent, 'inline-script');
                            inlineHandlers.push(...handlersFromInline);
                        } catch (parseError) {
                            console.warn(`[HandlerExtractor] Failed to parse inline script content:`, parseError.message);
                        }
                    }
                }
            }
        } catch (error) { console.error(`[HandlerExtractor] Error in extractDirectlyAST:`, error); }
        return inlineHandlers;
    }

    extractHandlersFromAST(scriptContent, sourceUrl) {
        if (typeof acorn === 'undefined') return [];
        const foundHandlers = [];
        const ast = acorn.parse(scriptContent, {
            ecmaVersion: 'latest',
            locations: true, ranges: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true,
            tolerant: true // Use tolerant mode
        });

        const functionDeclarations = new Map();
        const functionExpressions = new Map(); // For var x = function()...
        acorn.walk.simple(ast, {
            FunctionDeclaration(node) {
                if (node.id?.name) {
                    functionDeclarations.set(node.id.name, node);
                }
            },
            VariableDeclarator(node) {
                if (node.id?.name && node.init && (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')) {
                    functionExpressions.set(node.id.name, node.init);
                }
            },
            AssignmentExpression(node) { // Handle assignments like handler = function() {}
                if(node.left.type === 'Identifier' && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
                    functionExpressions.set(node.left.name, node.right);
                } else if (node.left.type === 'MemberExpression' && node.left.property.type === 'Identifier' && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
                }
            },
            Property(node) {
                if (node.key.type === 'Identifier' && (node.value.type === 'FunctionExpression' || node.value.type === 'ArrowFunctionExpression')) {
                    functionExpressions.set(node.key.name, node.value);
                }
            }
        });


        acorn.walk.ancestor(ast, {
            CallExpression: (node, ancestors) => {
                let isAddEventListener = false;
                if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier' && node.callee.property.name === 'addEventListener') {
                    isAddEventListener = true;
                }
                // Add checks for other potential listener registration functions if needed

                if (isAddEventListener && node.arguments.length >= 2) {
                    const eventNameNode = node.arguments[0];
                    const handlerNode = node.arguments[1];

                    if (eventNameNode.type === 'Literal' && eventNameNode.value === 'message') {
                        let handlerCode = null;
                        let category = 'unknown-ast';
                        let resolvedFrom = null;

                        if (handlerNode.type === 'FunctionExpression' || handlerNode.type === 'ArrowFunctionExpression') {
                            handlerCode = scriptContent.substring(handlerNode.range[0], handlerNode.range[1]);
                            category = handlerNode.type === 'ArrowFunctionExpression' ? 'ast-direct-arrow' : 'ast-direct-function';
                        } else if (handlerNode.type === 'Identifier') {
                            resolvedFrom = handlerNode.name;
                            const funcDefNode = functionDeclarations.get(resolvedFrom) || functionExpressions.get(resolvedFrom);
                            if (funcDefNode) {
                                handlerCode = scriptContent.substring(funcDefNode.range[0], funcDefNode.range[1]);
                                category = 'ast-reference';
                            }
                        } else if (handlerNode.type === 'CallExpression' && handlerNode.callee.type === 'MemberExpression' && handlerNode.callee.property.name === 'bind') {
                            const boundFuncNode = handlerNode.callee.object;
                            if (boundFuncNode.type === 'Identifier') {
                                resolvedFrom = boundFuncNode.name;
                                const funcDefNode = functionDeclarations.get(resolvedFrom) || functionExpressions.get(resolvedFrom);
                                if (funcDefNode) {
                                    handlerCode = scriptContent.substring(funcDefNode.range[0], funcDefNode.range[1]);
                                    category = 'ast-bind-reference';
                                }
                            } else if (boundFuncNode.type === 'FunctionExpression' || boundFuncNode.type === 'ArrowFunctionExpression') {
                                handlerCode = scriptContent.substring(boundFuncNode.range[0], boundFuncNode.range[1]);
                                category = 'ast-bind-inline';
                            }
                        }

                        if (handlerCode && handlerCode.length > 20) {
                            if (!handlerCode.includes('chrome.runtime.sendMessage') && !handlerCode.includes('[PostMessage Monitor]') && !handlerCode.includes('handlePostMessageCapture')) {
                                foundHandlers.push({ handler: handlerCode, category, score: 15, source: sourceUrl, resolvedFrom });
                            }
                        }
                    }
                }
            },
            AssignmentExpression: (node, ancestors) => {
                if(node.left.type === 'MemberExpression' && node.left.property.name === 'onmessage') {
                    const handlerNode = node.right;
                    let handlerCode = null;
                    let category = 'unknown-ast-onmessage';
                    let resolvedFrom = null;

                    if (handlerNode.type === 'FunctionExpression' || handlerNode.type === 'ArrowFunctionExpression') {
                        handlerCode = scriptContent.substring(handlerNode.range[0], handlerNode.range[1]);
                        category = 'ast-onmessage-inline';
                    } else if (handlerNode.type === 'Identifier') {
                        resolvedFrom = handlerNode.name;
                        const funcDefNode = functionDeclarations.get(resolvedFrom) || functionExpressions.get(resolvedFrom);
                        if (funcDefNode) {
                            handlerCode = scriptContent.substring(funcDefNode.range[0], funcDefNode.range[1]);
                            category = 'ast-onmessage-reference';
                        }
                    } else if (handlerNode.type === 'Literal' && handlerNode.value === null) {
                        // Explicitly assigned null, ignore
                    }

                    if (handlerCode && handlerCode.length > 20) {
                        if (!handlerCode.includes('chrome.runtime.sendMessage') && !handlerCode.includes('[PostMessage Monitor]') && !handlerCode.includes('handlePostMessageCapture')) {
                            foundHandlers.push({ handler: handlerCode, category, score: 10, source: sourceUrl, resolvedFrom });
                        }
                    }
                }
            }
        });

        return foundHandlers;
    }

    async getSavedMessages() {
        if (!this.baseEndpoint) return [];
        const storageKey = `saved-messages-${this.baseEndpoint}`;
        try {
            return new Promise(resolve => {
                chrome.storage.local.get([storageKey], result => resolve(result[storageKey] || []));
            });
        } catch (error) { return []; }
    }

    enhanceScores(savedMessages) {
        if (!savedMessages || savedMessages.length === 0) return;
        this.handlers.forEach(handler => { handler.score = this.scoreHandler(handler.handler, handler.category, savedMessages); });
        this.handlers.sort((a, b) => b.score - a.score);
    }

    generateSyntheticHandler(messages = []) {
        let template = `function(event){if(!event||!event.data)return;console.log('Received:',event.data);try{const data=typeof event.data==='string'?JSON.parse(event.data):event.data;`;
        const types = new Set(); const props = new Set(); const all = [...messages, ...this.messages];
        all.forEach(m => { try { let d = m.data; if(typeof d==='string') try{d=JSON.parse(d);}catch{return;} if(typeof d==='object'&&d!==null){if(d.type)types.add(d.type);if(d.action)types.add(d.action);if(d.messageType)types.add(d.messageType);if(d.kind)types.add(d.kind);Object.keys(d).forEach(k=>{if(!['type','action','messageType','kind'].includes(k))props.add(k);});}} catch {} });
        if (types.size > 0) { template += `const type=data.type||data.action||data.messageType||data.kind;switch(type){`; types.forEach(t => template += `case'${t}':console.log('Processing ${t}');break;`); template += `default:console.log('Unknown type:',type);break;}}`; }
        else if (props.size > 0) { template += ``; Array.from(props).slice(0, 5).forEach(p => template += `if(data.${p}!==undefined)console.log('Processing ${p}:',data.${p});`); }
        template += `if(event.source&&typeof event.source.postMessage==='function')event.source.postMessage({type:'response',status:'received',receivedData:data},event.origin);}catch(e){console.error('Error:',e);}}`;
        return { handler: template, score: 5, category: 'synthetic', source: 'generated' };
    }


    scoreHandler(handlerStr, category = '', relevantMessages = []) {
        if (!handlerStr || typeof handlerStr !== 'string') return 0;
        let score = 0; const scoreDetails = { base: 0, keywordHits: {}, messageMatchBonus: 0, categoryBonus: 0, lengthPenalty: 0, miscPenalty: 0 };
        Object.entries(this.scoreWeights).forEach(([feature, weight]) => { let regex; if (feature.match(/^[a-zA-Z0-9_$.]+$/) && !feature.includes('(') && !feature.includes('"')) regex = new RegExp(`\\b${feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g'); else regex = new RegExp(feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'); try { const m = handlerStr.match(regex); if (m) { score += weight * m.length; scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + (weight * m.length); } } catch (e) { if (handlerStr.includes(feature)) { score += weight; scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + weight; } } });
        scoreDetails.base = score; let msgBonus = 0; const MAX_BONUS = 25; if (relevantMessages.length > 0) { const keys = new Set(); const strings = new Set(); relevantMessages.forEach(m => { try { let d = m.data; if(typeof d==='string')try{d=JSON.parse(d);}catch{strings.add(d);return;} if(typeof d==='object'&&d!==null){Object.keys(d).forEach(k=>keys.add(k));Object.entries(d).forEach(([k,v])=>{if(typeof v==='string')strings.add(v);});} else if(typeof d==='string')strings.add(d); } catch {} }); keys.forEach(k => { if (new RegExp(`[.\\s\\[]['"]?${k}['"]?\\]?`, 'g').test(handlerStr)) msgBonus += 3; }); strings.forEach(v => { if (v && v.length>3 && v.length<50 && new RegExp(`['"\`]${v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}['"\`]`).test(handlerStr)) { msgBonus += 8; if (handlerStr.toLowerCase().includes('messagetype')||handlerStr.toLowerCase().includes('switch')||handlerStr.toLowerCase().includes('.type')||handlerStr.toLowerCase().includes('.action')) msgBonus += 5; } }); msgBonus = Math.min(msgBonus, MAX_BONUS); score += msgBonus; scoreDetails.messageMatchBonus = msgBonus; }
        if (category.includes('window')||category.includes('direct-listener')) scoreDetails.categoryBonus += 8; if (category.includes('onmessage')) scoreDetails.categoryBonus -= 5; if (category.includes('runtime')) scoreDetails.categoryBonus += 15; if (category.includes('delegate')||category.includes('frame')) scoreDetails.categoryBonus += 10; if (category.includes('worker')||category.includes('synthetic')) scoreDetails.miscPenalty -= 15; score += scoreDetails.categoryBonus;
        const len = handlerStr.length; if (len<100&&!category.includes('runtime')&&!category.includes('delegate')) scoreDetails.lengthPenalty -= 10; else if (len<50&&!category.includes('runtime')&&!category.includes('delegate')) scoreDetails.lengthPenalty -= 20; score += scoreDetails.lengthPenalty;
        return Math.max(0, Math.round(score));
    }

    deduplicateHandlers() {
        const unique = []; const seen = new Set();
        const categoryPriority = [ 'runtime', 'ast-direct-function', 'ast-direct-arrow', 'ast-reference', 'ast-bind-reference', 'ast-onmessage-inline', 'ast-onmessage-reference', 'direct-listener-window', 'function-reference-window', 'direct-listener', 'onmessage-assignment', 'framework-heuristic', 'other', 'synthetic', 'worker' ];
        const getPriority = (cat = '') => { const index = categoryPriority.findIndex(p => cat.includes(p)); return index === -1 ? 99 : index; };
        const sorted = [...this.handlers].sort((a, b) => { if (b.score !== a.score) return b.score - a.score; return getPriority(a.category) - getPriority(b.category); });
        for (const handler of sorted) {
            const fingerprint = handler.handler.replace(/\s+/g, '').substring(0, 1000);
            if (!fingerprint) continue;
            if (!seen.has(fingerprint)) { seen.add(fingerprint); unique.push(handler); }
            else { console.log(`[HandlerExtractor] Deduplicating handler starting with: ${fingerprint.substring(0,50)}...`);}
        }
        return unique;
    }

    getBestHandler(uniqueHandlers = null) {
        const handlersToConsider = uniqueHandlers || this.deduplicateHandlers();
        if (handlersToConsider.length === 0) { return null; }
        handlersToConsider.sort((a, b) => b.score - a.score);
        return handlersToConsider[0];
    }
}
window.HandlerExtractor = HandlerExtractor;
