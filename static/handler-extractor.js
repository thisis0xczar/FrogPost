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
                pathDuplication = srcDirSegments.every((segment, index) => segment === baseEndSegments[index]);
            }
            let resolvedUrl;
            if (pathDuplication) {
                resolvedUrl = `${baseUrlObj.origin}${basePath}/${filename}`;
            } else {
                resolvedUrl = `${baseUrlObj.origin}${basePath}/${src}`;
            }
            return resolvedUrl;
        } catch (error) {
            console.warn(`[HandlerExtractor] Error resolving script URL:`, error);
            return src;
        }
    }

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

    async extract() {
        this.handlers = [];
        const savedMessages = await this.getSavedMessages();
        const allRelevantMessages = [...this.messages, ...savedMessages];
        const strategies = [
            { name: 'messages', method: this.extractFromMessages.bind(this) },
            { name: 'direct', method: this.extractDirectly.bind(this) },
            { name: 'scripts', method: this.extractFromExternalScripts.bind(this) },
        ];

        for (const strategy of strategies) {
            try {
                const extractedHandlers = await strategy.method();
                if (extractedHandlers && extractedHandlers.length > 0) {
                    extractedHandlers.forEach(h => {
                        if (h.handler && typeof h.handler === 'string' && typeof h.score !== 'number') {
                            h.score = this.scoreHandler(h.handler, h.category, []);
                        } else if (typeof h.score !== 'number') {
                            h.score = -1;
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
            } catch (error) {
                console.error(`[HandlerExtractor - Fallback] Error in ${strategy.name} extraction:`, error);
            }
        }

        if (allRelevantMessages.length > 0 && this.handlers.length > 0) {
            this.enhanceScores(allRelevantMessages);
        }

        const uniqueHandlers = this.deduplicateHandlers();
        if (uniqueHandlers.length === 0) {
            const syntheticHandler = this.generateSyntheticHandler(allRelevantMessages);
            syntheticHandler.score = this.scoreHandler(syntheticHandler.handler, syntheticHandler.category, allRelevantMessages);
            uniqueHandlers.push(syntheticHandler);
        }

        if (uniqueHandlers.length > 0) {
            this.getBestHandler(uniqueHandlers); // Log happens internally now
        } else {
            console.log("[HandlerExtractor - Fallback] No handlers found or generated.");
        }

        return uniqueHandlers;
    }

    async extractFromMessages() {
        if (!this.messages || this.messages.length === 0) {
            return [];
        }
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
                        if (typeof value === 'string' && (key.includes('handler') || key.includes('callback') || key.includes('function'))) {
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

    async extractDirectly() {
        try {
            const matchingTabs = await this.findMatchingTabs();
            if (matchingTabs.length === 0) {
                return [];
            }
            const targetTab = matchingTabs[0];
            const results = await chrome.scripting.executeScript({
                target: { tabId: targetTab.id, allFrames: true },
                func: () => {
                    const extractedHandlers = [];
                    const handlerFunctions = new Map();
                    if (window.onmessage && typeof window.onmessage === 'function') {
                        extractedHandlers.push({ handler: window.onmessage.toString(), category: 'onmessage-property', source: 'window.onmessage' });
                    }
                    try {
                        for (const sym of Object.getOwnPropertySymbols(window)) {
                            if (sym.toString().includes('EventListeners')) {
                                const listeners = window[sym];
                                if (listeners?.message) {
                                    for (const listener of listeners.message) {
                                        if (listener?.listener === 'function') {
                                            extractedHandlers.push({ handler: listener.listener.toString(), category: 'symbol-listener', source: 'event-listener-symbol' });
                                        }
                                    }
                                }
                            }
                        }
                    } catch (e) {}
                    let allScriptContent = '';
                    document.querySelectorAll('script').forEach(script => { if (script.textContent) { allScriptContent += script.textContent + '\n'; }});
                    function shouldIgnoreHandler(code) { return code.includes('chrome.runtime.sendMessage') || code.includes('[PostMessage Monitor]') || code.includes('handlePostMessageCapture'); }
                    const patterns = [ { regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g, category: 'addEventListener-function' }, { regex: /addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'addEventListener-arrow', process: (m) => `function(${m[1]||'event'}) { ${m[2]||''} }` }, { regex: /addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'addEventListener-reference', lookupFunction: true }, { regex: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g, category: 'onmessage-assignment' }, { regex: /(?:window\.)?onmessage\s*=\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/g, category: 'onmessage-arrow', process: (m) => `function(${m[1]||'event'}) { ${m[2]||''} }` }, { regex: /(?:window\.)?onmessage\s*=\s*([a-zA-Z0-9_$]+)\s*;/g, category: 'onmessage-reference', lookupFunction: true } ];
                    const funcDefRegex = /function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{[\s\S]*?\}/g;
                    let funcMatch; while ((funcMatch = funcDefRegex.exec(allScriptContent)) !== null) { handlerFunctions.set(funcMatch[1], funcMatch[0]); }
                    patterns.forEach(p => { let m; while ((m = p.regex.exec(allScriptContent)) !== null) { try { let code; if (p.lookupFunction) { code = handlerFunctions.get(m[1]); if (!code) continue; } else if (p.process) { code = p.process(m); } else { code = m[1]; } if (code && !shouldIgnoreHandler(code)) extractedHandlers.push({ handler: code, category: p.category, source: 'inline-script' }); } catch (e) {} } });
                    function isLikelyHandler(body) { const ind = ['event.data', 'e.data', 'message.data', 'msg.data', 'event.origin', 'e.origin', 'postMessage(', 'JSON.parse(', 'JSON.stringify(']; return ind.some(i => body.includes(i)); }
                    handlerFunctions.forEach((body, name) => { if (isLikelyHandler(body) && !shouldIgnoreHandler(body) && !extractedHandlers.some(h => h.handler === body)) extractedHandlers.push({ handler: body, category: 'likely-handler-function', source: `function-${name}` }); });
                    return extractedHandlers;
                }
            });
            const allHandlers = [];
            for (const result of results) { if (result.result && Array.isArray(result.result)) { const frameHandlers = result.result.map(h => ({ ...h, score: this.scoreHandler(h.handler) })); allHandlers.push(...frameHandlers); } }
            return allHandlers;
        } catch (error) { console.error(`[HandlerExtractor] Error in direct extraction:`, error); return []; }
    }

    async extractFromExternalScripts() {
        try {
            const scriptUrls = new Set(); const processedUrls = new Set(); const extractedHandlers = [];
            const urlObj = new URL(this.endpoint); const tabs = await chrome.tabs.query({}); const matchingTabs = tabs.filter(tab => tab.url && tab.url.includes(urlObj.hostname)); let tabId;
            if (matchingTabs.length > 0) { tabId = matchingTabs[0].id; }
            else { const newTab = await chrome.tabs.create({ url: this.endpoint, active: false }); tabId = newTab.id; await new Promise(resolve => { const listener = (tid, info) => { if (tid === tabId && info.status === 'complete') { chrome.tabs.onUpdated.removeListener(listener); resolve(); } }; chrome.tabs.onUpdated.addListener(listener); setTimeout(resolve, 3000); }); }

            try { const perfResults = await chrome.scripting.executeScript({ target: { tabId }, func: () => performance.getEntriesByType("resource").filter(e => e.name.endsWith('.js') || e.initiatorType === 'script' || e.name.includes('remoteEntry')).map(e => e.name) }); if (perfResults?.[0]?.result) perfResults[0].result.forEach(url => scriptUrls.add(url)); } catch (error) {}
            try { const tagResults = await chrome.scripting.executeScript({ target: { tabId }, func: () => Array.from(document.querySelectorAll('script[src]')).map(s => s.src) }); if (tagResults?.[0]?.result) tagResults[0].result.forEach(url => scriptUrls.add(url)); } catch (error) {}
            try { await chrome.scripting.executeScript({ target: { tabId }, func: () => { if (!window._injected) { window._injected=true; window._scriptUrls=new Set(); const report=(url)=>{if(!url)return; window._scriptUrls.add(url); const m=document.createElement('div'); m.className='script-detection-marker'; m.dataset.url=url; m.style.display='none'; document.body.appendChild(m);}; if(window.__webpack_require__?.l){const o=window.__webpack_require__.l; window.__webpack_require__.l = function(u,...a){report(u);return o.apply(this,arguments);};} for(const k in window){try{if(typeof window[k]==='object'&&window[k]?.l==='function'){const o=window[k].l;window[k].l=function(u,...a){report(u);return o.apply(this,arguments);};}}catch{}} const oCE=document.createElement; document.createElement=function(t){const e=oCE.call(document,t); if(t.toLowerCase()==='script'){const d=Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype,'src'); Object.defineProperty(e,'src',{set:function(v){if(v)report(v);return d.set.call(this,v);},get:function(){return d.get.call(this);}}); } return e;}; } return Array.from(window._scriptUrls||[]); } }); } catch (error) {}
            try { await chrome.tabs.reload(tabId); for (let i = 0; i < 5; i++) { await new Promise(resolve => setTimeout(resolve, 500)); const markerResults = await chrome.scripting.executeScript({ target: { tabId }, func: ()=>{const m=document.querySelectorAll('.script-detection-marker');const u=[];m.forEach(mk=>{const url=mk.dataset.url;if(url)u.push(url);mk.remove();});return u;} }); if(markerResults?.[0]?.result) markerResults[0].result.forEach(url => scriptUrls.add(url)); const storedResults = await chrome.scripting.executeScript({ target: { tabId }, func: () => Array.from(window._scriptUrls||[]) }); if(storedResults?.[0]?.result) storedResults[0].result.forEach(url => scriptUrls.add(url)); } } catch (error) {}

            for (const url of Array.from(scriptUrls)) {
                if (processedUrls.has(url)) continue; processedUrls.add(url);
                try {
                    const response = await fetch(url, { credentials: 'omit', cache: 'no-store' }); if (!response.ok) continue;
                    const content = await response.text(); const handlers = this.extractFromJavaScriptContent(content);
                    if (handlers.length > 0) { handlers.forEach(h => extractedHandlers.push({...h, source: url})); }
                    else if (content.includes('addEventListener') && content.includes('message') && (content.includes('event.data') || content.includes('e.data'))) { const patterns = [ /addEventListener\s*\(\s*['"]message['"]\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/, /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/ ]; let code = null; for (const p of patterns) { const m=content.match(p); if (m) { if (p.toString().includes('=>')) code = `function(${m[1]||'event'}) { ${m[2]} }`; else code = m[1]; break; } } if (code) extractedHandlers.push({ handler: code, score: 7, category: 'extracted-handler', source: url }); }
                    const chunkPattern = /__webpack_require__\.l\s*\(\s*["']([^"']+)["']/g; let match; while ((match = chunkPattern.exec(content)) !== null) { try { const chunkUrl = match[1]; const fullUrl = this.resolveScriptUrl(chunkUrl, url); if (!scriptUrls.has(fullUrl) && !processedUrls.has(fullUrl)) scriptUrls.add(fullUrl); } catch {} }
                } catch (error) {}
            }
            if (matchingTabs.length === 0) { try { await chrome.tabs.remove(tabId); } catch {} }
            return extractedHandlers;
        } catch (error) { console.error(`[HandlerExtractor] Fatal error:`, error); return []; }
    }

    extractFromJavaScriptContent(jsContent) {
        if (!jsContent || typeof jsContent !== 'string') return [];
        const foundHandlers = []; const functionDefinitions = new Map(); const methodDefinitions = new Map();
        const funcDefRegex = /function\s+([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{[\s\S]*?\}/g; let funcMatch; while ((funcMatch = funcDefRegex.exec(jsContent)) !== null) functionDefinitions.set(funcMatch[1], funcMatch[0]);
        const methodDefRegex = /(\w+)\s*[:(]?\s*(?:function)?\s*\(([^)]*)\)\s*(?:=>)?\s*\{([\s\S]*?)\}(?=[;\n\s]*[}\),])/g; let methodMatch; while ((methodMatch = methodDefRegex.exec(jsContent)) !== null) { const name = methodMatch[1]; const body = methodMatch[0]; if (name && !functionDefinitions.has(name)) methodDefinitions.set(name, body); } functionDefinitions.forEach((body, name) => { if (!methodDefinitions.has(name)) methodDefinitions.set(name, body); });
        const listenerPatterns = [ { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener-window', score: 20, type: 'inline' }, { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})\s*,?/g, category: 'direct-listener', score: 10, type: 'inline' }, { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow-window', score: 19, type: 'arrow', process: (m) => `function(${m[1]||'event'}) { ${m[2]||''} }` }, { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}(?:\s*,|\s*\))/g, category: 'direct-listener-arrow', score: 9, type: 'arrow', process: (m) => `function(${m[1]||'event'}) { ${m[2]||''} }` }, { regex: /window\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference-window', score: 12, type: 'reference' }, { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'function-reference', score: 7, type: 'reference' }, { regex: /\.addEventListener\s*\(\s*["']message["']\s*,\s*(?:this\.|[a-zA-Z0-9_$]+\.)([a-zA-Z0-9_$]+)(?:\.bind\s*\([^)]*\)|[^,)]*)/g, category: 'method-reference', score: 15, type: 'method_reference' }, { regex: /(?:window\.)?onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\})/g, category: 'onmessage-assignment', score: 9, type: 'inline' }, { regex: /(?:window\.)?onmessage\s*=\s*(?:\()?([^)]*?)(?:\))?\s*=>\s*\{([\s\S]*?)\}/g, category: 'onmessage-arrow', score: 8, type: 'arrow', process: (m) => `function(${m[1]||'event'}) { ${m[2]||''} }` }, { regex: /(?:window\.)?onmessage\s*=\s*([a-zA-Z0-9_$]+)\s*;/g, category: 'onmessage-reference', score: 7, type: 'reference' }, { regex: /window\.addEventListener\("message",\s*\(([^)]*)\s*=>\s*\{\s*this\.([a-zA-Z0-9_$]+)\(.*?\)\s*\}\s*\)/g, category: 'frame-communication-delegate', score: 25, type: 'delegator', getDetails: (m) => ({ delegateParam: m[1], delegateMethodName: m[2] }) } ];
        listenerPatterns.forEach(p => { const { regex, category, score = 0, type, process, getDetails } = p; regex.lastIndex = 0; let match; while ((match = regex.exec(jsContent)) !== null) { try { let code; let key = ''; let details = getDetails ? getDetails(match) : {}; switch (type) { case 'inline': code = match[1]; break; case 'arrow': code = process(match); break; case 'reference': key = match[1]; code = functionDefinitions.get(key); break; case 'method_reference': key = match[1]; code = methodDefinitions.get(key); break; case 'delegator': key = details.delegateMethodName; code = match[0]; break; default: code = null; } if (!code || code.length < 20) continue; foundHandlers.push({ handler: code, category, score: this.scoreHandler(code, category) + score, sourceText: jsContent, isDelegator: (type === 'delegator'), details: details }); } catch (error) {} } });
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

    isLikelyHandler(handlerStr) {
        if (!handlerStr || typeof handlerStr !== 'string') return false;
        return (handlerStr.includes('function') || handlerStr.includes('=>')) && (handlerStr.includes('event') || handlerStr.includes('message') || handlerStr.includes('data') || handlerStr.includes('e.') || handlerStr.includes('msg'));
    }

    scoreHandler(handlerStr, category = '', relevantMessages = []) {
        if (!handlerStr || typeof handlerStr !== 'string') return 0;
        let score = 0; const scoreDetails = { base: 0, keywordHits: {}, messageMatchBonus: 0, categoryBonus: 0, lengthPenalty: 0, miscPenalty: 0 };
        Object.entries(this.scoreWeights).forEach(([feature, weight]) => { let regex; if (feature.match(/^[a-zA-Z0-9_$.]+$/) && !feature.includes('(') && !feature.includes('"')) regex = new RegExp(`\\b${feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g'); else regex = new RegExp(feature.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'); try { const m = handlerStr.match(regex); if (m) { score += weight * m.length; scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + (weight * m.length); } } catch (e) { if (handlerStr.includes(feature)) { score += weight; scoreDetails.keywordHits[feature] = (scoreDetails.keywordHits[feature] || 0) + weight; } } });
        scoreDetails.base = score; let msgBonus = 0; const MAX_BONUS = 25; if (relevantMessages.length > 0) { const keys = new Set(); const strings = new Set(); relevantMessages.forEach(m => { try { let d = m.data; if(typeof d==='string')try{d=JSON.parse(d);}catch{strings.add(d);return;} if(typeof d==='object'&&d!==null){Object.keys(d).forEach(k=>keys.add(k));Object.entries(d).forEach(([k,v])=>{if(typeof v==='string')strings.add(v);});} else if(typeof d==='string')strings.add(d); } catch {} }); keys.forEach(k => { if (new RegExp(`[.\\s\\[]['"]${k}['"]\\]?`, 'g').test(handlerStr)) msgBonus += 3; }); strings.forEach(v => { if (v && v.length>3 && v.length<50 && new RegExp(`['"\`]${v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}['"\`]`).test(handlerStr)) { msgBonus += 8; if (handlerStr.toLowerCase().includes('messagetype')||handlerStr.toLowerCase().includes('switch')||handlerStr.toLowerCase().includes('.type')||handlerStr.toLowerCase().includes('.action')) msgBonus += 5; } }); msgBonus = Math.min(msgBonus, MAX_BONUS); score += msgBonus; scoreDetails.messageMatchBonus = msgBonus; }
        if (category.includes('window')||category.includes('direct-listener')) scoreDetails.categoryBonus += 8; if (category.includes('onmessage')) scoreDetails.categoryBonus -= 5; if (category.includes('runtime')) scoreDetails.categoryBonus += 15; if (category.includes('delegate')||category.includes('frame')) scoreDetails.categoryBonus += 10; if (category.includes('worker')||category.includes('synthetic')) scoreDetails.miscPenalty -= 15; score += scoreDetails.categoryBonus;
        const len = handlerStr.length; if (len<100&&!category.includes('runtime')&&!category.includes('delegate')) scoreDetails.lengthPenalty -= 10; else if (len<50&&!category.includes('runtime')&&!category.includes('delegate')) scoreDetails.lengthPenalty -= 20; score += scoreDetails.lengthPenalty;
        return Math.max(0, Math.round(score));
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
        if (handlersToConsider.length === 0) {
            return null;
        }
        const priority1 = handlersToConsider.filter(h => h.score >= 25 && (h.category?.includes('combined') || h.category?.includes('delegate') || h.category?.includes('direct-listener-window')));
        if (priority1.length > 0) return priority1[0];
        const priority2 = handlersToConsider.filter(h => h.score >= 20 && h.category?.includes('frame'));
        if (priority2.length > 0) return priority2[0];
        const priority3 = handlersToConsider.filter(h => h.score >= 18 && (h.category?.includes('window') || h.category?.includes('direct-listener')));
        if (priority3.length > 0) return priority3[0];
        return handlersToConsider[0];
    }
}
window.HandlerExtractor = HandlerExtractor;
