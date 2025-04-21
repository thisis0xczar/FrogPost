/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-21
 */
class HandlerExtractor {
    constructor() {
        this.endpoint = null;
        this.messages = [];
        this.messageKeys = new Set();
        this.messageTypes = new Set();
        this.functionDefinitions = new Map();
        this.scriptContentCache = new Map();
        this.fetchInProgress = new Map();
    }

    initialize(endpoint, messages = []) {
        this.endpoint = endpoint;
        this.messages = messages || [];
        this.messageKeys = this._extractKeysFromMessages(this.messages);
        this.messageTypes = this._extractMessageTypes(this.messages);
        this.functionDefinitions.clear();
        log.debug(`[Extractor Init] Initialized for ${endpoint}. Message count: ${this.messages.length}, Keys: ${this.messageKeys.size}, Types: ${this.messageTypes.size}`);
        return this;
    }

    _extractKeysFromMessages(messages) {
        const keys = new Set();
        (messages || []).forEach(msg => {
            if (typeof msg.data === 'object' && msg.data !== null) {
                Object.keys(msg.data).forEach(key => keys.add(key));
                if (typeof msg.data.data === 'object' && msg.data.data !== null) {
                    Object.keys(msg.data.data).forEach(key => keys.add(key));
                }
            }
        });
        log.debug(`[Extractor Scoring Context] Extracted message keys:`, Array.from(keys));
        return keys;
    }

    _extractMessageTypes(messages) {
        const types = new Set();
        (messages || []).forEach(msg => {
            const kind = msg.data?.kind || msg.data?.messageType || msg.data?.type || msg.data?.action;
            if (typeof kind === 'string') {
                types.add(kind);
            }
        });
        log.debug(`[Extractor Scoring Context] Extracted message types/kinds:`, Array.from(types));
        return types;
    }

    async fetchScriptContent(url) {
        if (this.scriptContentCache.has(url)) return this.scriptContentCache.get(url);
        if (this.fetchInProgress.has(url)) return this.fetchInProgress.get(url);
        log.debug(`[Extractor] Fetching script content for: ${url}`);
        const promise = fetch(url)
            .then(response => { if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`); return response.text(); })
            .then(content => { this.scriptContentCache.set(url, content); this.fetchInProgress.delete(url); return content; })
            .catch(error => { log.error(`[Extractor] Failed to fetch script ${url}:`, error); this.fetchInProgress.delete(url); this.scriptContentCache.set(url, null); return null; });
        this.fetchInProgress.set(url, promise);
        return promise;
    }

    analyzeScriptContent(content, sourceIdentifier) {
        const handlers = [];
        if (!content || typeof content !== 'string' || content.length < 50) return handlers;
        this.functionDefinitions.clear();
        let ast;
        try {
            if (typeof acorn === 'undefined') throw new Error("Acorn not loaded");
            log.debug(`[Extractor] Attempting AST parse for: ${sourceIdentifier}`);
            ast = acorn.parse(content, { ecmaVersion: 'latest', silent: true, locations: true, sourceType: 'script' });
            log.debug(`[Extractor] AST parsing SUCCESS for: ${sourceIdentifier}`);
            this._mapFunctionDeclarations(ast);
            this._mapPrototypeMethods(ast);
            handlers.push(...this.analyzeAst(ast, content, sourceIdentifier));
        } catch (e) {
            log.warn(`[Extractor] AST parsing FAILED for ${sourceIdentifier}: ${e.message}. Falling back to regex.`);
            handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
        }
        log.debug(`[Extractor] Found ${handlers.length} potential structures in ${sourceIdentifier} (before scoring).`);
        return handlers;
    }

    _mapFunctionDeclarations(ast) {
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return;
        try {
            acorn.walk.simple(ast, {
                FunctionDeclaration: (node) => {
                    if (node.id?.name) {
                        this.functionDefinitions.set(node.id.name, { node: node, type: 'declaration' });
                    }
                },
                VariableDeclarator: (node) => {
                    if (node.id?.name && (node.init?.type === 'FunctionExpression' || node.init?.type === 'ArrowFunctionExpression')) {
                        this.functionDefinitions.set(node.id.name, { node: node.init, type: 'expression-variable' });
                    }
                }
            });
        } catch (e) { log.error("[Extractor] Error mapping function declarations:", e); }
    }

    _mapPrototypeMethods(ast) {
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return;
        try {
            acorn.walk.simple(ast, {
                AssignmentExpression: (node) => {
                    if (node.operator === '=' &&
                        node.left.type === 'MemberExpression' &&
                        node.left.object.type === 'MemberExpression' &&
                        node.left.object.property.name === 'prototype' &&
                        node.left.object.object.type === 'Identifier' &&
                        (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression'))
                    {
                        const className = node.left.object.object.name;
                        const methodName = node.left.property.name;
                        const functionNode = node.right;
                        const prototypeKey = `${className}.prototype.${methodName}`;
                        this.functionDefinitions.set(prototypeKey, { node: functionNode, className: className, methodName: methodName, type: 'prototype' });
                        log.debug(`[Extractor] Mapped prototype method: ${prototypeKey}`);
                    }
                    else if (node.operator === '=' &&
                        node.left.type === 'MemberExpression' &&
                        node.left.property?.name &&
                        node.left.object?.type === 'Identifier' &&
                        (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression'))
                    {
                        const functionName = node.left.property.name;
                        const objectName = node.left.object.name;
                        const key = `${objectName}.${functionName}`;


                        if (!this.functionDefinitions.has(key) && !this.functionDefinitions.has(functionName)) {
                            this.functionDefinitions.set(key, { node: node.right, className: objectName, methodName: functionName, type: 'object-method' });
                            log.debug(`[Extractor] Mapped object method: ${key}`);
                        }
                    }
                }
            });
        } catch (e) {
            log.error("[Extractor] Error mapping prototype/object methods:", e);


            console.error("Stack Trace:", e.stack);
        }
    }

    analyzeAst(ast, scriptContent, sourceUrl) {
        const foundHandlers = [];
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return foundHandlers;
        try {
            acorn.walk.simple(ast, {
                AssignmentExpression: (node) => {
                    if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.property.name === 'onmessage') {
                        let funcNode = null; let category = 'ast-onmessage-assignment'; let functionName = null;
                        if (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression') funcNode = node.right;
                        else if (node.right.type === 'Identifier') { functionName = node.right.name; funcNode = this.functionDefinitions.get(functionName); if(funcNode) category += '-identifier'; }
                        if (funcNode) {
                            const codePreview = scriptContent.substring(funcNode.start, Math.min(funcNode.end, funcNode.start + 100));
                            log.debug(`[Extractor AST Found] Category: ${category}, Source: ${sourceUrl}, FuncName: ${functionName || 'N/A'}, Preview: ${codePreview}...`);
                            foundHandlers.push({ category, source: sourceUrl, functionName, handlerNode: funcNode, fullScriptContent: scriptContent });
                        }
                    }
                },
                CallExpression: (node) => {
                    if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'addEventListener' && node.arguments.length >= 2 && node.arguments[0].type === 'Literal' && node.arguments[0].value === 'message') {
                        const handlerArg = node.arguments[1];
                        let funcDef = null;
                        let category = 'ast-event-listener';
                        let functionName = null;
                        let resolvedIdentifier = false;

                        if (handlerArg.type === 'FunctionExpression' || handlerArg.type === 'ArrowFunctionExpression') {
                            funcDef = { node: handlerArg };
                        } else if (handlerArg.type === 'Identifier') {
                            functionName = handlerArg.name;
                            funcDef = this.functionDefinitions.get(functionName);
                            if (funcDef) {
                                category += '-identifier';
                                resolvedIdentifier = true;
                            }
                        } else if (handlerArg.type === 'MemberExpression') {
                            const objName = handlerArg.object?.name;
                            const methodName = handlerArg.property?.name;

                            if (methodName) {
                                functionName = methodName;


                                const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${methodName}`));
                                if (protoKey) {
                                    funcDef = this.functionDefinitions.get(protoKey);
                                    category += '-prototype-lookup';
                                    resolvedIdentifier = true;
                                    log.debug(`[Extractor AST] Found prototype method ref ${protoKey} for addEventListener via MemberExpression.`);
                                } else {
                                    const objMethodKey = `${objName}.${methodName}`;
                                    if (this.functionDefinitions.has(objMethodKey)) {
                                        funcDef = this.functionDefinitions.get(objMethodKey);
                                        category += '-objectMethod-lookup';
                                        resolvedIdentifier = true;
                                        log.debug(`[Extractor AST] Found object method ref ${objMethodKey} for addEventListener via MemberExpression.`);
                                    }
                                }
                            }
                            if(!resolvedIdentifier && handlerArg.object?.type === 'ThisExpression' && handlerArg.property?.name) {
                                functionName = handlerArg.property.name;
                                const thisProtoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${functionName}`) && this.functionDefinitions.get(key)?.type === 'prototype');
                                if(thisProtoKey) {
                                    funcDef = this.functionDefinitions.get(thisProtoKey);
                                    category += '-this-prototype-lookup';
                                    resolvedIdentifier = true;
                                    log.debug(`[Extractor AST] Found this.prototype method ref ${thisProtoKey} for addEventListener.`);
                                }
                            }
                        } else if (handlerArg.type === 'CallExpression' && handlerArg.callee.type === 'MemberExpression' && handlerArg.callee.property.name === 'bind') {
                            let boundFuncIdentifier = null;
                            let boundFuncNode = null;


                            if (handlerArg.callee.object.type === 'Identifier') {
                                boundFuncIdentifier = handlerArg.callee.object.name;
                                boundFuncNode = this.functionDefinitions.get(boundFuncIdentifier);
                            } else if (handlerArg.callee.object.type === 'MemberExpression' && handlerArg.callee.object.property?.name) {

                                const objName = handlerArg.callee.object.object?.name;
                                const methodName = handlerArg.callee.object.property.name;
                                boundFuncIdentifier = methodName;

                                const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${methodName}`) && (!objName || key.startsWith(objName)));
                                if (protoKey) {
                                    boundFuncNode = this.functionDefinitions.get(protoKey);
                                    category += '-bind-prototype';
                                    log.debug(`[Extractor AST] Found bound prototype method ref ${protoKey} for addEventListener.`);
                                } else {
                                    const objMethodKey = `${objName}.${methodName}`;
                                    if(this.functionDefinitions.has(objMethodKey)) {
                                        boundFuncNode = this.functionDefinitions.get(objMethodKey);
                                        category += '-bind-objectMethod';
                                        log.debug(`[Extractor AST] Found bound object method ref ${objMethodKey} for addEventListener.`);
                                    }
                                }

                            } else if (handlerArg.callee.object.type === 'FunctionExpression') {
                                boundFuncNode = { node: handlerArg.callee.object };
                                category += '-bind-inline';
                            }

                            if (boundFuncNode) {
                                funcDef = boundFuncNode;
                                functionName = boundFuncIdentifier || funcDef.methodName;
                                resolvedIdentifier = true;
                                category += boundFuncIdentifier ? '-identifier' : '';
                            }
                        }

                        if (funcDef && funcDef.node) {
                            const codePreview = scriptContent.substring(funcDef.node.start, Math.min(funcDef.node.end, funcDef.node.start + 100));
                            log.debug(`[Extractor AST Found] Category: ${category}, Source: ${sourceUrl}, FuncName: ${functionName || 'N/A'}, Preview: ${codePreview}...`);
                            foundHandlers.push({ category, source: sourceUrl, functionName: functionName || funcDef.methodName, handlerNode: funcDef.node, fullScriptContent: scriptContent });
                        } else if (handlerArg.type === 'Identifier' && !resolvedIdentifier) {
                            log.debug(`[Extractor AST] Could not resolve identifier "${handlerArg.name}" used in addEventListener.`);
                        }
                    }
                }
            });
        } catch (e) { log.error(`[Extractor] Error walking AST for ${sourceUrl}:`, e); }
        return foundHandlers;
    }

    analyzeWithRegex(content, sourceUrl) {
        const handlers = [];
        const onMessageRegex = /\bonmessage\s*=\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})/gi;
        const addEventListenerRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})\s*,?/gi;
        const addEventListenerIdentifierRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)\s*,?/gi;
        let match;
        while ((match = onMessageRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-onmessage', source: sourceUrl });
        while ((match = addEventListenerRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-event-listener-inline', source: sourceUrl });
        while ((match = addEventListenerIdentifierRegex.exec(content)) !== null) {
            const functionName = match[1]; const funcDefRegex = new RegExp(`(?:function\\s+${functionName}\\s*\\(|(?:var|let|const)\\s+${functionName}\\s*=\\s*function\\s*\\()(\\s*\\(.*?\\)\\s*\\{[\\s\\S]*?\\})`, 'i'); const funcMatch = content.match(funcDefRegex);
            if (funcMatch?.[0]) { const firstParenIndex = funcMatch[0].indexOf('('); const functionSignatureAndBody = funcMatch[0].substring(firstParenIndex); const fullHandlerText = `function${functionSignatureAndBody}`; handlers.push({ handler: fullHandlerText, category: 'regex-event-listener-identifier', source: sourceUrl, functionName: functionName }); }
        }
        return handlers.map(h => ({ ...h, handlerNode: null, fullScriptContent: h.handler }));
    }

    analyzeInlineHandlers(doc) {
        const handlers = [];
        const elements = doc.querySelectorAll('[onmessage]');
        elements.forEach(el => { const handlerCode = el.getAttribute('onmessage'); if (handlerCode) handlers.push({ handler: `function(event){ ${handlerCode} }`, category: 'inline-onmessage-attribute', source: this.endpoint + ' (inline attribute)', handlerNode: null, fullScriptContent: `function(event){ ${handlerCode} }` }); });
        return handlers;
    }

    scoreHandler(handlerInfo) {
        const { handlerNode, category, source, fullScriptContent, functionName } = handlerInfo;
        const handlerCode = handlerInfo.handler;
        let score = 0;
        const MIN_CODE_LENGTH_ESTIMATE = 40;
        const MAX_CODE_LENGTH_ESTIMATE = 15000;
        let handlerCodeLength = 0;

        if (handlerNode?.end && handlerNode?.start) handlerCodeLength = handlerNode.end - handlerNode.start;
        else if (handlerCode) handlerCodeLength = handlerCode.length;
        if (handlerCodeLength < MIN_CODE_LENGTH_ESTIMATE) return 0;

        log.debug(`[Scoring Handler] Category: ${category}, Source: ${source?.substring(0, 100)}`);
        log.debug(`[Scoring Handler] Using Context - Keys:`, Array.from(this.messageKeys));
        log.debug(`[Scoring Handler] Using Context - Types/Kinds:`, Array.from(this.messageTypes));

        let basicScore = 10;
        score += basicScore;
        let astScore = 0;

        if (handlerNode && typeof acorn !== 'undefined' && typeof acorn.walk !== 'undefined') {
            try {
                const foundGenericKeys = new Set(); const foundSpecificKeys = new Set(); const foundSpecificTypes = new Set();
                let usesPostMessageCall = false; let referencesEventData = false; let referencesEventOrigin = false;
                let hasOriginCheck = false; let usesJsonParse = false; let usesSwitchOnKind = false;
                let eventParamName = null;
                if (handlerNode.params?.[0]?.type === 'Identifier') eventParamName = handlerNode.params[0].name;

                acorn.walk.simple(handlerNode, {
                    MemberExpression: (node) => {
                        let propName = null; if (node.property?.type === 'Identifier') propName = node.property.name; else if (node.property?.type === 'Literal') propName = node.property.value;
                        let baseObjectName = null; if (node.object?.type === 'Identifier') baseObjectName = node.object.name;
                        if (propName) {
                            if (eventParamName && baseObjectName === eventParamName && ['data', 'origin', 'source'].includes(propName)) { foundGenericKeys.add(propName); if (propName === 'data') referencesEventData = true; if (propName === 'origin') referencesEventOrigin = true; }
                            if (eventParamName && node.object?.type === 'MemberExpression' && node.object.object?.name === eventParamName && node.object.property?.name === 'data') { if (this.messageKeys.has(propName)) { log.debug(`[Scoring AST Walk] Found Specific Key: ${propName}`); foundSpecificKeys.add(propName); } }
                            if(eventParamName && propName === 'rawData' && node.object?.type === 'MemberExpression' && node.object.property?.name === 'data' && node.object.object?.type === 'MemberExpression' && node.object.object.property?.name === 'data' && node.object.object.object?.name === eventParamName){ if(this.messageKeys.has(propName)) foundSpecificKeys.add(propName); }
                            if (propName === 'postMessage') usesPostMessageCall = true;
                            if (propName === 'origin' && node.parent?.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.parent.operator)) { hasOriginCheck = true; }
                        }
                    },
                    Literal: (node) => { if (typeof node.value === 'string') { log.debug(`[Scoring AST Walk] Visiting Literal: "${node.value}"`); if (this.messageTypes.has(node.value)) { log.debug(`[Scoring AST Walk] Matched Specific Type/Kind: "${node.value}"`); foundSpecificTypes.add(node.value); } } },
                    CallExpression: (node) => { if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'postMessage') usesPostMessageCall = true; if (node.callee.type === 'MemberExpression' && node.callee.object?.name === 'JSON' && node.callee.property?.name === 'parse') usesJsonParse = true; },
                    SwitchStatement: (node) => { if (node.discriminant?.type === 'MemberExpression' && node.discriminant.property?.name && ['kind', 'messageType', 'type', 'action'].includes(node.discriminant.property.name)) { if (node.discriminant.object?.type === 'MemberExpression' && node.discriminant.object.property?.name === 'data') { usesSwitchOnKind = true; } } }
                });
                astScore += foundSpecificKeys.size * 150; astScore += foundSpecificTypes.size * 100;
                if (referencesEventData) astScore += 20; if (referencesEventOrigin) astScore += 20; if (usesPostMessageCall) astScore += 10;
                if (hasOriginCheck) astScore += 75; if (usesJsonParse) astScore += 40; if (usesSwitchOnKind) astScore += 50;
                if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE && astScore < 200) astScore -= 100; else if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE) astScore -= 20;
                log.debug(`[Scoring AST Node SUCCEEDED] Handler (Cat: ${category}, EstLen: ${handlerCodeLength}) - AST Score: ${astScore}, Specific Keys Found: ${foundSpecificKeys.size}, Patterns: OriginCheck=${hasOriginCheck}, JSONParse=${usesJsonParse}, Switch=${usesSwitchOnKind}`);
            } catch (e) {
                log.warn(`[Scoring AST Node] Failed walking node for category ${category}: ${e.message}.`);
                astScore = 0;
            }
        } else if (handlerCode) {
            if (handlerCode.includes('.data') || handlerCode.includes('["data"]')) astScore += 5; if (handlerCode.includes('.origin') || handlerCode.includes('["origin"]')) astScore += 5; if (handlerCode.includes('.source') || handlerCode.includes('["source"]')) astScore += 3; if (handlerCode.includes('postMessage')) astScore += 3; if (handlerCode.includes('messageType') || handlerCode.includes('["messageType"]')) astScore += 10; if (handlerCode.includes('JSON.parse')) astScore += 5; if (handlerCode.includes('switch')) astScore += 5;
            log.debug(`[Scoring Basic String] Handler (Cat: ${category}, Len: ${handlerCodeLength}) - Basic Score Contribution: ${astScore}`);
        }
        score += astScore;

        if (category?.includes('ast-event-listener') || category?.includes('ast-onmessage')) score += 50;
        else if (category?.includes('runtime')) score += 150;
        else if (category?.includes('debugger')) score += 5;
        else if (category?.includes('inline-onmessage-attribute')) score += 5;
        else if (category?.includes('regex')) score += 1;

        return Math.max(0, score);
    }

    getBestHandler(handlersInfo) {
        if (!handlersInfo || handlersInfo.length === 0) return null;
        const scoredHandlers = handlersInfo
            .map(handlerInfo => {
                const score = this.scoreHandler(handlerInfo);
                let boostedScore = score;

                if (handlerInfo.category?.includes('prototype') || handlerInfo.category?.includes('objectMethod') || handlerInfo.category?.includes('indirect')) {
                    boostedScore += 10;
                } else if (handlerInfo.category?.includes('ast-event-listener-identifier') || handlerInfo.category?.includes('ast-onmessage-assignment-identifier')) {
                    boostedScore += 5;
                }
                return { ...handlerInfo, score: boostedScore };
            })
            .filter(h => h.score > 0);

        if (scoredHandlers.length === 0) { log.debug("[getBestHandler] No candidates scored above 0."); return null; }
        log.debug("[getBestHandler] Scored Candidates (Pre-sort):", JSON.stringify(scoredHandlers.map(h => ({ score: h.score, category: h.category, source: h.source?.substring(0,100), hasNode: !!h.handlerNode, name: h.functionName || 'N/A' })), null, 2));

        const categoryPriority = {
            'runtime': 1,
            'ast-event-listener': 2, 'ast-onmessage': 3,
            'debugger': 4,
            'regex': 6, 'inline-onmessage-attribute': 7
        };


        scoredHandlers.sort((a, b) => {
            if (b.score !== a.score) return b.score - a.score;
            const priorityA = categoryPriority[a.category?.split('-')[0]] || 99;
            const priorityB = categoryPriority[b.category?.split('-')[0]] || 99;
            if (priorityA !== priorityB) return priorityA - priorityB;
            const lenA = a.handlerNode ? a.handlerNode.end - a.handlerNode.start : (a.handler?.length || a.fullScriptContent?.length || 0);
            const lenB = b.handlerNode ? b.handlerNode.end - b.handlerNode.start : (b.handler?.length || b.fullScriptContent?.length || 0);
            if (lenA !== lenB) return lenB - lenA;
            return (a.source || '').localeCompare(b.source || '');
        });

        const bestHandlerInfo = scoredHandlers[0];
        let finalHandlerCode = bestHandlerInfo.handler || '';
        if (!finalHandlerCode && bestHandlerInfo.handlerNode && bestHandlerInfo.fullScriptContent) {
            try {
                finalHandlerCode = bestHandlerInfo.fullScriptContent.substring(bestHandlerInfo.handlerNode.start, bestHandlerInfo.handlerNode.end);
            } catch (e) {
                log.error("Failed to extract final handler code string from node!", e);
                finalHandlerCode = "[Error extracting code string]";
            }
        }
        else if (!finalHandlerCode && bestHandlerInfo.fullScriptContent) {
            finalHandlerCode = bestHandlerInfo.fullScriptContent;
        }

        const bestLen = bestHandlerInfo.handlerNode ? bestHandlerInfo.handlerNode.end - bestHandlerInfo.handlerNode.start : finalHandlerCode.length;
        log.debug(`[getBestHandler] Selected Handler: Score=${bestHandlerInfo.score}, Category=${bestHandlerInfo.category}, Source=${bestHandlerInfo.source}, EstLen=${bestLen}, Name=${bestHandlerInfo.functionName || 'N/A'}`);
        return { handler: finalHandlerCode, category: bestHandlerInfo.category, score: bestHandlerInfo.score, source: bestHandlerInfo.source, functionName: bestHandlerInfo.functionName };
    }

    async extractDynamicallyViaDebugger(targetUrl) {
        const handlers = new Set();
        let tabId = null; let attached = false; let detachReason = null;
        const collectedScripts = new Map(); let analysisTimer = null;
        const ANALYSIS_TIMEOUT = 10000; const SETTLE_TIME = 1500; const LOAD_EXTRA_TIME = 2000;
        let resolveAnalysis; const analysisPromise = new Promise(res => { resolveAnalysis = res; }); let analysisResolved = false;
        const onDebuggerEvent = (source, method, params) => { if (!tabId || source.tabId !== tabId) return; if (method === 'Debugger.scriptParsed') { const { scriptId, url } = params; if (url && !url.startsWith('chrome-extension://') && url !== 'about:blank') { log.debug(`[Debugger Tab] Script parsed: ID=${scriptId}, URL=${url.substring(0,100)}`); collectedScripts.set(scriptId, { url: url, scriptId: scriptId }); clearTimeout(analysisTimer); analysisTimer = setTimeout(() => { if (!analysisResolved) { log.debug('[Debugger Tab] Script parsing settled.'); analysisResolved = true; resolveAnalysis(); } }, SETTLE_TIME); } } else if (method === 'Page.loadEventFired') { log.debug('[Debugger Tab] Page load event fired.'); clearTimeout(analysisTimer); analysisTimer = setTimeout(() => { if (!analysisResolved) { log.debug('[Debugger Tab] Page loaded + settle time.'); analysisResolved = true; resolveAnalysis(); } }, LOAD_EXTRA_TIME); } else if (method === 'Runtime.exceptionThrown') { log.warn('[Debugger Tab] Exception in target:', params.exceptionDetails?.exception?.description || 'Unknown error'); } };
        const onDebuggerDetach = (source, reason) => { if (source.tabId === tabId) { log.warn(`[Debugger Tab] Detached unexpectedly from tab ${tabId}. Reason: ${reason}`); attached = false; detachReason = reason; if (chrome?.debugger) { try { chrome.debugger.onEvent.removeListener(onDebuggerEvent); } catch(e){} try { chrome.debugger.onDetach.removeListener(onDebuggerDetach); } catch(e){} } if (!analysisResolved) { analysisResolved = true; resolveAnalysis(); } } };
        try {
            log.debug('[Debugger Tab] Creating temporary background tab for:', targetUrl);
            const tab = await chrome.tabs.create({ url: targetUrl, active: false }); tabId = tab.id; if (!tabId) throw new Error("Failed to create target tab."); log.debug(`[Debugger Tab] Created target tab ID: ${tabId}`); await new Promise(res => setTimeout(res, 1500));
            await chrome.debugger.attach({ tabId }, "1.3"); attached = true; log.debug(`[Debugger Tab] Attached to target tab: ${tabId}`);
            chrome.debugger.onEvent.addListener(onDebuggerEvent); chrome.debugger.onDetach.addListener(onDebuggerDetach);
            await Promise.all([ chrome.debugger.sendCommand({ tabId }, "Page.enable"), chrome.debugger.sendCommand({ tabId }, "Runtime.enable"), chrome.debugger.sendCommand({ tabId }, "Debugger.enable") ]); log.debug(`[Debugger Tab] Enabled domains.`);
            const overallTimeout = setTimeout(() => { if (!analysisResolved) { log.warn(`[Debugger Tab] Overall analysis timeout reached.`); analysisResolved = true; resolveAnalysis(); } }, ANALYSIS_TIMEOUT);
            log.debug('[Debugger Tab] Waiting for script parsing to settle...'); await analysisPromise; clearTimeout(overallTimeout);
            if (!attached) throw new Error(`Debugger detached unexpectedly. Reason: ${detachReason || 'Unknown'}`); log.debug(`[Debugger Tab] Proceeding to fetch ${collectedScripts.size} script sources.`);
            const sourcePromises = Array.from(collectedScripts.keys()).map(scriptId => chrome.debugger.sendCommand({ tabId }, "Debugger.getScriptSource", { scriptId }).then(result => ({ scriptId, source: result.scriptSource })).catch(err => { log.warn(`[Debugger Tab] Failed to get source for scriptId ${scriptId}:`, err?.message || err); return { scriptId, source: null }; }));
            const sources = await Promise.all(sourcePromises);
            log.debug(`[Debugger Tab] Analyzing ${sources.filter(s => s.source).length} fetched script sources.`);
            for (const { scriptId, source } of sources) { if (source) { const scriptInfo = collectedScripts.get(scriptId); const sourceUrl = scriptInfo?.url || `tab_${tabId}_scriptId_${scriptId}`; const scriptHandlers = this.analyzeScriptContent(source, sourceUrl); scriptHandlers.forEach(handlerInfo => handlers.add(handlerInfo)); } }
        } catch (error) { log.error('[Debugger Tab] Error during dynamic extraction process:', error); throw new Error(`Debugger analysis failed: ${error.message}`); }
        finally {
            log.debug('[Debugger Tab] Entering finally block for cleanup.'); clearTimeout(analysisTimer);
            if (attached && tabId) { log.debug(`[Debugger Tab] Attempting to detach from tab: ${tabId}`); try { if (chrome?.debugger) { if (chrome.debugger.onEvent?.removeListener) chrome.debugger.onEvent.removeListener(onDebuggerEvent); if (chrome.debugger.onDetach?.removeListener) chrome.debugger.onDetach.removeListener(onDebuggerDetach); if (chrome.debugger.detach) await chrome.debugger.detach({ tabId }); log.debug(`[Debugger Tab] Detached successfully from tab: ${tabId}`); } else { log.warn('[Debugger Tab] chrome.debugger API unavailable for detach.'); } } catch (detachError) { log.error('[Debugger Tab] Error detaching:', detachError?.message || detachError); } }
            else { log.debug('[Debugger Tab] Skipping detach (not attached or no tabId).'); }
            if (tabId) { log.debug(`[Debugger Tab] Attempting to remove temporary tab: ${tabId}`); try { await chrome.tabs.remove(tabId); log.debug(`[Debugger Tab] Removed temporary tab: ${tabId}`); } catch (removeError) { log.error(`[Debugger Tab] Error removing temporary tab ${tabId}:`, removeError); } }
        }
        log.success(`[Debugger Tab] Dynamic extraction finished. Found ${handlers.size} potential handler structures.`);
        return Array.from(handlers);
    }
}

window.HandlerExtractor = HandlerExtractor;
