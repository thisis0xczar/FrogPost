/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor
 * Refined on: 2025-09-17
 */

class HandlerExtractor {
    constructor() {
        this.endpoint = null;
        this.messages = [];
        this.messageKeys = new Set();
        this.messageTypes = new Set();
        this.messageValues = new Set();
        this.functionDefinitions = new Map();
        this.debugLevel = this._resolveDebugLevel(); // 0:none,1:basic,2:verbose,3:trace
    }

    _is(n, t) { return !!n && n.type === t; }
    _prop(o, k) { return (o && Object.prototype.hasOwnProperty.call(o, k)) ? o[k] : undefined; }
    _safeLog(...args) { try { console.debug(...args); } catch {} }

    _resolveDebugLevel() {
        try {
            if (typeof HandlerExtractor.globalDebugLevel === 'number') return HandlerExtractor.globalDebugLevel;
            if (typeof localStorage !== 'undefined') {
                const raw = localStorage.getItem('frogpost_debug_level');
                if (!raw) return 1;
                const norm = String(raw).toLowerCase();
                if (norm === 'off' || norm === '0') return 0;
                if (norm === 'basic' || norm === '1') return 1;
                if (norm === 'verbose' || norm === '2') return 2;
                if (norm === 'trace' || norm === '3') return 3;
            }
        } catch (_) {}
        return 1;
    }

    setDebugLevel(level) {
        const n = Number(level);
        this.debugLevel = Number.isFinite(n) ? Math.max(0, Math.min(3, n)) : this.debugLevel;
        try { if (typeof localStorage !== 'undefined') localStorage.setItem('frogpost_debug_level', String(this.debugLevel)); } catch(_){}
    }

    static setGlobalDebugLevel(level) {
        const n = Number(level);
        HandlerExtractor.globalDebugLevel = Number.isFinite(n) ? Math.max(0, Math.min(3, n)) : 1;
    }

    _log(level, method, ...args) {
        if (this.debugLevel < level) return;
        try {
            if (typeof log !== 'undefined' && typeof log[method] === 'function') return log[method](...args);
        } catch(_) {}
        try { console[method === 'success' ? 'log' : (method || 'log')](...args); } catch(_) {}
    }

    _isNonPostMessageHandler(handlerCode, handlerFlags) {
        if (!handlerCode || typeof handlerCode !== 'string') return false;

        // Check for common non-postMessage handler patterns
        const nonPostMessagePatterns = [
            // Positioning/UI related functions
            /positioning|offset|placement|floating|platform|isRTL/i,
            // Scheduler/async related
            /scheduler|async.*fn|unstable_now|MessageChannel/i,
            // Generic utility functions
            /utility|helper|util|common|shared/i,
            // Event handling without message focus
            /addEventListener.*(?!message)|removeEventListener/i,
            // Function that doesn't access event.data
            /function.*\{[^}]*\}(?!.*event\.data)/i
        ];

        // Check if handler code matches non-postMessage patterns
        for (const pattern of nonPostMessagePatterns) {
            if (pattern.test(handlerCode)) return true;
        }

        // Check if handler doesn't access event.data at all
        if (!handlerCode.includes('event.data') && !handlerCode.includes('evt.data')) {
            return true;
        }

        // Check if handler doesn't have any DOM manipulation or postMessage processing
        const domPatterns = [/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function|createElement|appendChild|setAttribute|style\.|classList\./i];
        const processingPatterns = [/JSON\.parse|JSON\.stringify|switch.*case|if.*event\.data|\.type|\.action|\.command/i];
        const hasDOMManipulation = domPatterns.some(pattern => pattern.test(handlerCode));
        const hasProcessingLogic = processingPatterns.some(pattern => pattern.test(handlerCode));

        // If no DOM manipulation AND no processing logic, likely not a postMessage handler
        if (!hasDOMManipulation && !hasProcessingLogic) return true;

        // Check if handler is too complex for a simple postMessage handler
        if (handlerCode.length > 1000 && !handlerFlags.accessesEventDataConditionally) {
            return true;
        }

        return false;
    }

    _resolveStringLiteral(node) {
        if (!node) return null;
        const lit = (n) => (n && n.type === 'Literal' && typeof n.value === 'string') ? n.value : null;
        const tmpl = (n) => {
            if (!n || n.type !== 'TemplateLiteral' || (n.expressions && n.expressions.length)) return null;
            return n.quasis.map(q => (q.value.cooked ?? q.value.raw ?? '')).join('');
        };
        const bin = (n) => {
            if (!n || n.type !== 'BinaryExpression' || n.operator !== '+') return null;
            const l = this._resolveStringLiteral(n.left);
            const r = this._resolveStringLiteral(n.right);
            return (typeof l === 'string' && typeof r === 'string') ? (l + r) : null;
        };
        const id = (n) => {
            if (!n || n.type !== 'Identifier' || !this._constStringEnv) return null;
            return this._constStringEnv.get(n.name) || null;
        };
        return lit(node) ?? tmpl(node) ?? bin(node) ?? id(node) ?? null;
    }

    _seedConstStringEnv(ast) {
        this._constStringEnv = new Map();
        acorn.walk.simple(ast, {
            VariableDeclarator: (n) => {
                try {
                    if (n?.id?.name && n.init) {
                        const v = this._resolveStringLiteral(n.init);
                        if (typeof v === 'string') this._constStringEnv.set(n.id.name, v);
                    }
                } catch (e) { this._safeLog('[ConstSeed] var error:', e?.message); }
            },
            AssignmentExpression: (n) => {
                try {
                    if (n?.operator === '=' && n.left?.type === 'Identifier') {
                        const v = this._resolveStringLiteral(n.right);
                        if (typeof v === 'string') this._constStringEnv.set(n.left.name, v);
                    }
                } catch (e) { this._safeLog('[ConstSeed] assign error:', e?.message); }
            }
        });
    }

    initialize(endpoint, messages = []) {
        this.endpoint = endpoint;
        this.messages = messages || [];
        this.debugLevel = this._resolveDebugLevel();
        this.messageKeys = this._extractKeysFromMessages(this.messages);
        this.messageTypes = this._extractMessageTypes(this.messages);
        this.messageValues = this._extractMessageValues(this.messages);
        this.functionDefinitions.clear();
        this._log(1, 'debug', `[Extractor Init] Initialized for ${endpoint}. Message count: ${this.messages.length}, Keys: ${this.messageKeys.size}, Types: ${this.messageTypes.size}, DebugLevel: ${this.debugLevel}`);
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
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message keys:`, Array.from(keys));
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
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message types/kinds:`, Array.from(types));
        return types;
    }

    _extractMessageValues(messages) {
        const values = new Set();
        const collectValues = (obj) => {
            if (!obj) return;
            try {
                Object.values(obj).forEach(v => {
                    if (typeof v === 'string') values.add(v);
                    else if (v && typeof v === 'object') {
                        // Only go one level deeper to avoid heavy recursion
                        Object.values(v).forEach(nv => { if (typeof nv === 'string') values.add(nv); });
                    }
                });
            } catch (_) {}
        };
        (messages || []).forEach(msg => {
            if (typeof msg?.data === 'string') values.add(msg.data);
            else if (msg?.data && typeof msg.data === 'object') {
                collectValues(msg.data);
                if (msg.data.data && typeof msg.data.data === 'object') collectValues(msg.data.data);
            }
        });
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message values (sample):`, Array.from(values).slice(0, 10));
        return values;
    }

    analyzeScriptContent(content, sourceIdentifier) {
        const handlers = [];
        if (!content || typeof content !== 'string' || content.length < 50) return handlers;
        this.functionDefinitions.clear();
        let ast;
        let parseError = null;

        try {
            if (typeof acorn === 'undefined') throw new Error("Acorn not loaded");
            this._log(3, 'debug', `[Extractor] Attempting AST parse (module) for: ${sourceIdentifier}`);
            ast = acorn.parse(content, {
                ecmaVersion: 'latest',
                silent: true, // Keep silent to allow fallback
                locations: true,
                sourceType: 'module' // Attempt module parse
            });
            this._log(3, 'debug', `[Extractor] AST parsing as MODULE SUCCESS for: ${sourceIdentifier}`);

        } catch (moduleError) {
            this._log(2, 'warn', `[Extractor] AST module parse failed for ${sourceIdentifier}: ${moduleError.message}. Trying as script...`);
            try {
                ast = acorn.parse(content, {
                    ecmaVersion: 'latest',
                    silent: true,
                    locations: true,
                    sourceType: 'script' // Fallback to script parse
                });
                this._log(3, 'debug', `[Extractor] AST parsing as SCRIPT SUCCESS for: ${sourceIdentifier}`);
            } catch (scriptError) {
                parseError = scriptError;
                this._log(1, 'error', `[Extractor] AST parsing FAILED for ${sourceIdentifier} (both module & script): ${scriptError.message}. Falling back to regex.`);
                ast = null;
            }
        }

        if (ast) {
            this._seedConstStringEnv(ast);
            try {
                this._mapFunctionDeclarations(ast);
                this._mapPrototypeMethods(ast);
                handlers.push(...this.analyzeAst(ast, content, sourceIdentifier));
            } catch(walkError) {
                this._log(1, 'error', `[Extractor] Error during AST walk for ${sourceIdentifier}:`, walkError);
                handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
            }
        } else {
            handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
        }

        this._log(2, 'debug', `[Extractor] Found ${handlers.length} potential structures in ${sourceIdentifier} (before scoring).`);
        return handlers;
    }

    _mapFunctionDeclarations(ast) {
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return;
        try {
            acorn.walk.simple(ast, {
                FunctionDeclaration: (node) => { if (node.id?.name) { this.functionDefinitions.set(node.id.name, { node: node, type: 'declaration' }); } },
                VariableDeclarator: (node) => { if (node.id?.name && (node.init?.type === 'FunctionExpression' || node.init?.type === 'ArrowFunctionExpression')) { this.functionDefinitions.set(node.id.name, { node: node.init, type: 'expression-variable' }); } }
            });
        } catch (e) { if(typeof log !== 'undefined') log.error("[Extractor] Error mapping function declarations:", e); }
    }

    _mapPrototypeMethods(ast) {
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return;
        try {
            acorn.walk.simple(ast, {
                AssignmentExpression: (node) => {
                    if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.object.type === 'MemberExpression' && node.left.object.property.name === 'prototype' && node.left.object.object.type === 'Identifier' && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
                        const className = node.left.object.object.name; const methodName = node.left.property.name; const functionNode = node.right; const prototypeKey = `${className}.prototype.${methodName}`; this.functionDefinitions.set(prototypeKey, { node: functionNode, className: className, methodName: methodName, type: 'prototype' }); if(typeof log !== 'undefined') log.debug(`[Extractor] Mapped prototype method: ${prototypeKey}`);
                    } else if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.property?.name && node.left.object?.type === 'Identifier' && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
                        const functionName = node.left.property.name; const objectName = node.left.object.name; const key = `${objectName}.${functionName}`;
                        if (!this.functionDefinitions.has(key) && !this.functionDefinitions.has(functionName)) { this.functionDefinitions.set(key, { node: node.right, className: objectName, methodName: functionName, type: 'object-method' }); if(typeof log !== 'undefined') log.debug(`[Extractor] Mapped object method: ${key}`); }
                    }
                }
            });
        } catch (e) { if(typeof log !== 'undefined') { log.error("[Extractor] Error mapping prototype/object methods:", e); console.error("Stack Trace:", e.stack); } }
    }


    analyzeAst(ast, scriptContent, sourceUrl) {
        const foundHandlers = [];
        if (!ast || typeof acorn === 'undefined' || typeof acorn.walk === 'undefined') return foundHandlers;

        const SCHEDULER_KEYWORDS = ['unstable_now', 'MessageChannel', 'requestAnimationFrame', 'setImmediate', 'setTimeout', 'setInterval'];
        const VERIFIER_KEYWORDS = /verify|validate|check|authenticate/i;
        const CALLBACK_MAP_KEYWORDS = /callback|handler|listener/i;
        const COMMON_DATA_FIELDS = new Set(['type', 'action', 'kind', 'msgType', 'message', 'payload', 'data', 'id', 'command', 'event']);
        const MAX_RECURSION_DEPTH = 4;

        const quickScanForPatternsRecursive = (node, eventParamName, currentDepth, visitedNodes = new Set()) => {
            let flags = {
                callsVerifier: false, usesCallbackMap: false, accessesEventDataConditionally: false,
                accessesEventOriginConditionally: false, looksLikeScheduler: false, mentionsPostMessageNull: false,
                usesSwitchOnEventData: false, accessesCommonDataFields: 0, accessesAnyDataField: false,
                accessesOriginField: false, hasStrongSignal: false
            };

            if (!node || !node.body || currentDepth > MAX_RECURSION_DEPTH || visitedNodes.has(node)) {
                return flags;
            }
            visitedNodes.add(node);
            this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}, Scanning node type ${node.type}`);


            try {
                if (!node || !node.body) {
                    return flags;
                }
                acorn.walk.simple(node.body, {
                    CallExpression: (callNode) => {
                        try {
                            if (!callNode) return;
                            let calleeName = null;
                            let resolvedCalleeDef = null;
                            const args = this._prop(callNode, 'arguments') || [];
                            const callee = this._prop(callNode, 'callee');

                            let isPassedEventArg = Array.isArray(args) && args.some(arg => arg?.type === 'Identifier' && arg?.name === eventParamName);

                            if (callee?.type === 'Identifier') {
                                calleeName = this._prop(callee, 'name');
                                if (calleeName) {
                                    resolvedCalleeDef = this.functionDefinitions.get(calleeName);
                                    if (resolvedCalleeDef) this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Found direct call to '${calleeName}', Definition found: ${!!resolvedCalleeDef.node}`);
                                }
                            } else if (callee?.type === 'MemberExpression') {
                                const calleeProp = this._prop(callee, 'property');
                                if (calleeProp?.type === 'Identifier') {
                                    calleeName = this._prop(calleeProp, 'name');
                                    const objExpr = this._prop(callee, 'object');
                                    let objName = null;

                                    if(objExpr?.type === 'ThisExpression') objName = 'this';
                                    else if (objExpr?.type === 'Identifier') objName = this._prop(objExpr, 'name');

                                    if (objName && calleeName) {
                                        const lookupKey = `${objName}.${calleeName}`;
                                        resolvedCalleeDef = this.functionDefinitions.get(lookupKey);
                                        this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Found method call '${lookupKey}', Definition found: ${!!resolvedCalleeDef?.node}`);

                                        if (!resolvedCalleeDef) {
                                            const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${calleeName}`) && this.functionDefinitions.get(key)?.type === 'prototype');
                                            if(protoKey) {
                                                resolvedCalleeDef = this.functionDefinitions.get(protoKey);
                                                this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Found potential prototype method '${calleeName}' via key '${protoKey}', Definition found: ${!!resolvedCalleeDef?.node}`);
                                            }
                                        }
                                    } else {
                                        this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Method call '${calleeName || 'unknown'}' on complex object type '${objExpr?.type || 'unknown'}', skipping lookup.`);
                                    }
                                }
                            }

                            if (calleeName) {
                                if (VERIFIER_KEYWORDS.test(calleeName)) flags.callsVerifier = true;
                                if (SCHEDULER_KEYWORDS.includes(calleeName)) flags.looksLikeScheduler = true;
                                if (calleeName === 'postMessage' && args.length > 0 && args[0]?.type === 'Literal' && args[0]?.value === null) flags.mentionsPostMessageNull = true;
                            }

                            if (resolvedCalleeDef?.node && isPassedEventArg) {
                                this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Recursing into '${calleeName || 'callee'}' because event param '${eventParamName}' was passed.`);
                                const nestedFlags = quickScanForPatternsRecursive(resolvedCalleeDef.node, eventParamName, currentDepth + 1, new Set(visitedNodes));
                                this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Flags from recursive call to '${calleeName || 'callee'}':`, nestedFlags);
                                for(const key in nestedFlags) {
                                    if (typeof flags[key] === 'boolean') flags[key] = flags[key] || nestedFlags[key];
                                    else if (typeof flags[key] === 'number') flags[key] += nestedFlags[key];
                                }
                            } else if (resolvedCalleeDef?.node && !isPassedEventArg) {
                                this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}: Found call to '${calleeName || 'callee'}' but event param '${eventParamName}' not passed, not recursing.`);
                            }
                        } catch (e) {
                            this._safeLog('[quickScanRec] CallExpression error:', e?.message);
                        }
                    },
                    MemberExpression: (memNode) => {
                        try {
                            if (!memNode) return;
                            const obj = this._prop(memNode, 'object');
                            const prop = this._prop(memNode, 'property');

                            let baseObjectIsEvent = obj?.type === 'Identifier' && obj?.name === eventParamName;
                            let baseObjectIsDeeperEventData = obj?.type === 'MemberExpression' &&
                                this._prop(obj, 'object')?.type === 'Identifier' &&
                                this._prop(obj, 'object')?.name === eventParamName &&
                                this._prop(obj, 'property')?.name === 'data';

                            if (obj?.type === 'ThisExpression' || obj?.type === 'Identifier') {
                                if (prop?.type === 'Identifier' && CALLBACK_MAP_KEYWORDS.test(prop?.name || '')) {
                                    const parent = this._prop(memNode, 'parent');
                                    let parentCall = parent?.type === 'CallExpression' ? parent : null;
                                    let grandParentMember = parentCall && this._prop(parentCall, 'parent')?.type === 'MemberExpression' ? this._prop(parentCall, 'parent') : null;
                                    if (parentCall && parentCall.callee === memNode && grandParentMember && this._prop(grandParentMember, 'property')?.name === 'find') flags.usesCallbackMap = true;
                                    else if (parent?.type === 'MemberExpression' && parent.object === memNode && this._prop(parent, 'property')?.type !== 'Identifier') flags.usesCallbackMap = true;
                                }
                            }

                            if (baseObjectIsEvent && prop?.name === 'origin') {
                                flags.accessesOriginField = true;
                                let current = this._prop(memNode, 'parent'); let depth = 0;
                                while (current && depth < 5) {
                                    const currentType = current?.type;
                                    if (currentType === 'IfStatement' || currentType === 'BinaryExpression' || currentType === 'ConditionalExpression' || currentType === 'LogicalExpression') {
                                        flags.accessesEventOriginConditionally = true; break;
                                    }
                                    if (currentType === 'FunctionExpression' || currentType === 'FunctionDeclaration' || currentType === 'ArrowFunctionExpression') break;
                                    current = this._prop(current, 'parent'); depth++;
                                }
                            }

                            if (baseObjectIsDeeperEventData && prop?.type === 'Identifier') {
                                flags.accessesAnyDataField = true;
                                if(COMMON_DATA_FIELDS.has(prop?.name || '')) flags.accessesCommonDataFields++;
                                let current = this._prop(memNode, 'parent'); let depth = 0;
                                while(current && depth < 5) {
                                    const currentType = current?.type;
                                    if(currentType === 'IfStatement' || currentType === 'SwitchCase' || currentType === 'ConditionalExpression' || currentType === 'LogicalExpression' || currentType === 'BinaryExpression') {
                                        flags.accessesEventDataConditionally = true; break;
                                    }
                                    if(currentType === 'FunctionExpression' || currentType === 'FunctionDeclaration' || currentType === 'ArrowFunctionExpression') break;
                                    current = this._prop(current, 'parent'); depth++;
                                }
                            }
                        } catch (e) {
                            this._safeLog('[quickScanRec] MemberExpression error:', e?.message);
                        }
                    },
                    SwitchStatement: (switchNode) => {
                        try {
                            if (!switchNode) return;
                            let discriminantChecksEventData = false;
                            const discriminant = this._prop(switchNode, 'discriminant');
                            if (discriminant?.type === 'MemberExpression') {
                                const discObj = this._prop(discriminant, 'object');
                                const discProp = this._prop(discriminant, 'property');
                                if (discObj?.type === 'MemberExpression' &&
                                    this._prop(discObj, 'object')?.name === eventParamName &&
                                    this._prop(discObj, 'property')?.name === 'data') {
                                    discriminantChecksEventData = true;
                                } else if (discObj?.type === 'Identifier') {
                                    if (COMMON_DATA_FIELDS.has(discProp?.name || '')) discriminantChecksEventData = true;
                                }
                            }
                            if (discriminantChecksEventData) flags.usesSwitchOnEventData = true;
                        } catch (e) {
                            this._safeLog('[quickScanRec] SwitchStatement error:', e?.message);
                        }
                    },
                    Identifier: (idNode) => {
                        try {
                            if (!idNode) return;
                            const nodeName = this._prop(idNode, 'name');
                            if (nodeName && SCHEDULER_KEYWORDS.includes(nodeName)) flags.looksLikeScheduler = true;
                        } catch (e) {
                            this._safeLog('[quickScanRec] Identifier error:', e?.message);
                        }
                    }
                });
            } catch (e) {
                this._log(2, 'warn', `[Extractor AST Pattern Scan] Error during scan depth ${currentDepth}: ${e?.message || String(e)}`);
            }

            flags.hasStrongSignal = flags.callsVerifier || flags.usesCallbackMap || flags.accessesEventOriginConditionally || flags.usesSwitchOnEventData || flags.accessesEventDataConditionally;
            this._log(3, 'debug', `[quickScanRec] Depth ${currentDepth}, Node type ${node.type}. Final flags:`, flags);
            return flags;
        };

        try {
            acorn.walk.simple(ast, {
                AssignmentExpression: (node) => {
                    try {
                        if (!this._is(node, 'AssignmentExpression')) return;
                        const left = this._prop(node, 'left');
                        if (!this._is(left, 'MemberExpression')) return;
                        const prop = this._prop(left, 'property');
                        if (prop?.name !== 'onmessage') return;
                        let funcNode = null; let category = 'ast-onmessage-assignment'; let functionName = null;
                        let handlerFlags = {}; let eventParamName = 'event';

                        if (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression') {
                            funcNode = node.right;
                            if(funcNode.params?.[0]?.type === 'Identifier') eventParamName = funcNode.params[0].name;
                            else if (funcNode.params?.length > 0) eventParamName = 'param0';
                            handlerFlags = quickScanForPatternsRecursive(funcNode, eventParamName, 0);
                        } else if (node.right.type === 'Identifier') {
                            functionName = node.right.name;
                            let funcDef = this.functionDefinitions.get(functionName);
                            funcNode = funcDef?.node || null;
                            if (funcNode) {
                                category += '-identifier';
                                if(funcNode.params?.[0]?.type === 'Identifier') eventParamName = funcDef.node.params[0].name;
                                else if (funcNode.params?.length > 0) eventParamName = 'param0';
                                handlerFlags = quickScanForPatternsRecursive(funcNode, eventParamName, 0);
                            }
                        }
                        if (funcNode) {
                            foundHandlers.push({ category, source: sourceUrl, functionName, handlerNode: funcNode, fullScriptContent: scriptContent, handlerFlags, eventParamName });
                            this._log(2, 'debug', `[AST Detect] onmessage assignment candidate in ${sourceUrl} (${category}). Function: ${functionName || 'anonymous'}`);
                        }
                    } catch (e) {
                        this._safeLog('[Extractor AST Pattern Scan] swallowed assign error:', e?.message);
                    }
                },
                CallExpression: (node) => {
                    try {
                        if (!this._is(node, 'CallExpression')) return;
                        const callee = this._prop(node, 'callee');
                        if (!this._is(callee, 'MemberExpression')) return;
                        const prop = this._prop(callee, 'property');
                        if (prop?.name !== 'addEventListener') return;
                        const args = Array.isArray(node.arguments) ? node.arguments : [];
                        const evtArg = args[0];
                        const evtName = this._resolveStringLiteral(evtArg);
                        if (evtName !== 'message') return;
                        const handlerArg = args[1];
                        let funcDef = null; let category = 'ast-event-listener'; let functionName = null;
                        let handlerFlags = {}; let eventParamName = 'event';

                        if (handlerArg.type === 'FunctionExpression' || handlerArg.type === 'ArrowFunctionExpression') {
                            funcDef = { node: handlerArg };
                            if(handlerArg.params?.[0]?.type === 'Identifier') eventParamName = handlerArg.params[0].name;
                            else if (handlerArg.params?.length > 0) eventParamName = 'param0';
                            handlerFlags = quickScanForPatternsRecursive(handlerArg, eventParamName, 0);
                        } else if (handlerArg.type === 'Identifier') {
                            functionName = handlerArg.name;
                            funcDef = this.functionDefinitions.get(functionName);
                            if (funcDef?.node) {
                                category += '-identifier';
                                if(funcDef.node.params?.[0]?.type === 'Identifier') eventParamName = funcDef.node.params[0].name;
                                else if (funcDef.node.params?.length > 0) eventParamName = 'param0';
                                handlerFlags = quickScanForPatternsRecursive(funcDef.node, eventParamName, 0);
                            } else funcDef = null;
                        } else if (handlerArg.type === 'MemberExpression') {
                            functionName = handlerArg.property?.name || functionName;
                            const objExpr = handlerArg.object;
                            let objName = null;
                            if(objExpr?.type === 'ThisExpression') objName = 'this';
                            else if(objExpr?.type === 'Identifier') objName = objExpr.name;
                            if (objName && functionName) {
                                const potentialKey = `${objName}.${functionName}`;
                                funcDef = this.functionDefinitions.get(potentialKey);
                                if (!funcDef) { const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${functionName}`) && this.functionDefinitions.get(key)?.type === 'prototype'); if(protoKey) funcDef = this.functionDefinitions.get(protoKey); }
                            }
                            if (funcDef?.node) {
                                category += '-method-lookup';
                                if(funcDef.node.params?.[0]?.type === 'Identifier') eventParamName = funcDef.node.params[0].name;
                                else if (funcDef.node.params?.length > 0) eventParamName = 'param0';
                                handlerFlags = quickScanForPatternsRecursive(funcDef.node, eventParamName, 0);
                            } else funcDef = null;
                        } else if (handlerArg.type === 'CallExpression' && handlerArg.callee.type === 'MemberExpression' && handlerArg.callee.property.name === 'bind') {
                            let baseFuncDef = null;
                            let potentialFuncName = null;
                            const calleeObject = handlerArg.callee.object;
                            if (calleeObject.type === 'Identifier') { potentialFuncName = calleeObject.name; baseFuncDef = this.functionDefinitions.get(potentialFuncName); }
                            else if (calleeObject.type === 'MemberExpression') {
                                potentialFuncName = calleeObject.property?.name;
                                const objExpr = calleeObject.object; let objName = null;
                                if(objExpr?.type === 'ThisExpression') objName = 'this'; else if(objExpr?.type === 'Identifier') objName = objExpr.name;
                                if(objName && potentialFuncName) baseFuncDef = this.functionDefinitions.get(`${objName}.${potentialFuncName}`);
                                if(!baseFuncDef && potentialFuncName) { const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${potentialFuncName}`) && this.functionDefinitions.get(key)?.type === 'prototype'); if(protoKey) baseFuncDef = this.functionDefinitions.get(protoKey); }
                            } else if (calleeObject.type === 'FunctionExpression') { baseFuncDef = { node: calleeObject }; }
                            if (baseFuncDef?.node) {
                                funcDef = baseFuncDef;
                                functionName = potentialFuncName || funcDef.methodName;
                                category += '-bind';
                                if(funcDef.node.params?.[0]?.type === 'Identifier') eventParamName = funcDef.node.params[0].name;
                                else if (funcDef.node.params?.length > 0) eventParamName = 'param0';
                                handlerFlags = quickScanForPatternsRecursive(funcDef.node, eventParamName, 0);
                            } else funcDef = null;
                        }

                        if (funcDef && funcDef.node) {
                            foundHandlers.push({ category, source: sourceUrl, functionName: functionName || funcDef.methodName, handlerNode: funcDef.node, fullScriptContent: scriptContent, handlerFlags, eventParamName });
                            this._log(2, 'debug', `[AST Detect] addEventListener('message', ...) candidate in ${sourceUrl} (${category}). Function: ${functionName || funcDef.methodName || 'anonymous'}`);
                        }
                    } catch (e) {
                        this._safeLog('[Extractor AST Pattern Scan] swallowed node error:', e?.message);
                    }
                }
            });
        } catch (e) {
            this._log(1, 'error', `[Extractor] Error walking AST for ${sourceUrl}:`, e);
        }
        return foundHandlers;
    }


    scoreHandler(handlerInfo) {
        const { handlerNode, category, source, fullScriptContent, functionName, handlerFlags = {}, eventParamName } = handlerInfo;
        const handlerCode = handlerInfo.handler || fullScriptContent;
        let score = 0;
        const dbg = this.debugLevel >= 3 ? { contributions: [], notes: [] } : null;
        const MIN_CODE_LENGTH_ESTIMATE = 25;
        const MAX_CODE_LENGTH_ESTIMATE = 30000;
        const MIN_COMPLEXITY_LENGTH = 65;

        const SCHEDULER_PENALTY = -250;
        const POSTMESSAGE_NULL_PENALTY = -75;
        const SIMPLICITY_PENALTY = -50;
        const NON_POSTMESSAGE_PENALTY = -200; // Heavy penalty for non-postMessage handlers

        const VERIFIER_BONUS = 120;
        const CALLBACK_MAP_BONUS = 110;
        const CONDITIONAL_ORIGIN_ACCESS_BONUS = 125;
        const SWITCH_BONUS = 140;
        const CONDITIONAL_DATA_ACCESS_BONUS = 75;
        const ORIGIN_CHECK_STRUCTURE_BONUS = 90;

        // New bonuses for better handler detection
        const POSTMESSAGE_HANDLER_BONUS = 200;  // Strong indicator
        const DOM_SINK_BONUS = 150;             // Has DOM manipulation
        const JSON_PROCESSING_BONUS = 100;       // Processes JSON data
        const TYPE_CHECKING_BONUS = 80;          // Checks message type/action

        const COMMON_DATA_FIELD_BONUS = 30;
        const ANY_DATA_FIELD_BONUS = 5;
        const ORIGIN_FIELD_BONUS = 10;
        const SPECIFIC_KEY_MATCH_BONUS = 150;
        const SPECIFIC_TYPE_MATCH_BONUS = 100;
        const JSON_PARSE_BONUS = 40;
        const POSTMESSAGE_CALL_BONUS = 5;

        let handlerCodeLength = handlerNode?.end && handlerNode?.start ? handlerNode.end - handlerNode.start : (handlerCode?.length || 0);
        if (handlerCodeLength < MIN_CODE_LENGTH_ESTIMATE) return 0;

        let baseScore = 5; score += baseScore; if (dbg) dbg.contributions.push({rule:'BASE', delta:baseScore});
        let featureScore = 0;
        let hasStrongSignal = handlerFlags.hasStrongSignal || false;

        if (handlerFlags.looksLikeScheduler) { featureScore += SCHEDULER_PENALTY; if (dbg) dbg.contributions.push({rule:'SCHEDULER_PENALTY', delta:SCHEDULER_PENALTY}); }
        if (handlerFlags.mentionsPostMessageNull) { featureScore += POSTMESSAGE_NULL_PENALTY; if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_NULL_PENALTY', delta:POSTMESSAGE_NULL_PENALTY}); }

        // Check if this looks like a non-postMessage handler
        const isNonPostMessageHandler = this._isNonPostMessageHandler(handlerCode, handlerFlags);
        if (isNonPostMessageHandler) { featureScore += NON_POSTMESSAGE_PENALTY; if (dbg) dbg.contributions.push({rule:'NON_POSTMESSAGE_PENALTY', delta:NON_POSTMESSAGE_PENALTY}); }

        if (handlerFlags.callsVerifier) { featureScore += VERIFIER_BONUS; if (dbg) dbg.contributions.push({rule:'VERIFIER_BONUS', delta:VERIFIER_BONUS}); }
        if (handlerFlags.usesCallbackMap) { featureScore += CALLBACK_MAP_BONUS; if (dbg) dbg.contributions.push({rule:'CALLBACK_MAP_BONUS', delta:CALLBACK_MAP_BONUS}); }
        if (handlerFlags.accessesEventOriginConditionally) { featureScore += CONDITIONAL_ORIGIN_ACCESS_BONUS; if (dbg) dbg.contributions.push({rule:'CONDITIONAL_ORIGIN_ACCESS_BONUS', delta:CONDITIONAL_ORIGIN_ACCESS_BONUS}); }
        if (handlerFlags.usesSwitchOnEventData) { featureScore += SWITCH_BONUS; if (dbg) dbg.contributions.push({rule:'SWITCH_BONUS', delta:SWITCH_BONUS}); }
        if (handlerFlags.accessesEventDataConditionally) { featureScore += CONDITIONAL_DATA_ACCESS_BONUS; if (dbg) dbg.contributions.push({rule:'CONDITIONAL_DATA_ACCESS_BONUS', delta:CONDITIONAL_DATA_ACCESS_BONUS}); }

        if (handlerFlags.accessesCommonDataFields > 0) { const d = (handlerFlags.accessesCommonDataFields * COMMON_DATA_FIELD_BONUS); featureScore += d; if (dbg) dbg.contributions.push({rule:'COMMON_DATA_FIELDS', delta:d}); }
        if (handlerFlags.accessesAnyDataField && !handlerFlags.accessesEventDataConditionally && handlerFlags.accessesCommonDataFields === 0) { featureScore += ANY_DATA_FIELD_BONUS; if (dbg) dbg.contributions.push({rule:'ANY_DATA_FIELD_BONUS', delta:ANY_DATA_FIELD_BONUS}); }
        if (handlerFlags.accessesOriginField && !handlerFlags.accessesEventOriginConditionally) { featureScore += ORIGIN_FIELD_BONUS; if (dbg) dbg.contributions.push({rule:'ORIGIN_FIELD_BONUS', delta:ORIGIN_FIELD_BONUS}); }

        // Apply new pattern-based bonuses
        if (/addEventListener.*message|window\.onmessage|message.*event/i.test(handlerCode)) { featureScore += POSTMESSAGE_HANDLER_BONUS; if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_HANDLER_BONUS', delta:POSTMESSAGE_HANDLER_BONUS}); }
        if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|createElement/i.test(handlerCode)) { featureScore += DOM_SINK_BONUS; if (dbg) dbg.contributions.push({rule:'DOM_SINK_BONUS', delta:DOM_SINK_BONUS}); }
        if (/JSON\.parse|JSON\.stringify/i.test(handlerCode)) { featureScore += JSON_PROCESSING_BONUS; if (dbg) dbg.contributions.push({rule:'JSON_PROCESSING_BONUS', delta:JSON_PROCESSING_BONUS}); }
        if (/\.type|\.action|\.command|switch.*case|if.*event\.data\./i.test(handlerCode)) { featureScore += TYPE_CHECKING_BONUS; if (dbg) dbg.contributions.push({rule:'TYPE_CHECKING_BONUS', delta:TYPE_CHECKING_BONUS}); }

        if (handlerNode && typeof acorn !== 'undefined' && typeof acorn.walk !== 'undefined') {
            try {
                const foundSpecificKeys = new Set(); const foundSpecificTypes = new Set();
                let usesPostMessageCall = false; let hasOriginCheckStructure = false; let usesJsonParse = false;
                const effectiveEventParamName = eventParamName || 'event';

                acorn.walk.simple(handlerNode, {
                    MemberExpression: (node) => {
                        if (node.property?.name === 'origin' && node.object?.name === effectiveEventParamName) {
                            if (node.parent?.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.parent.operator)) hasOriginCheckStructure = true;
                            else if (node.parent?.type === 'CallExpression' && node.parent.callee?.type === 'MemberExpression' && ['startsWith', 'endsWith', 'includes', 'indexOf'].includes(node.parent.callee.property?.name)) hasOriginCheckStructure = true;
                        }
                        if (node.object?.type === 'MemberExpression' && node.object.object?.name === effectiveEventParamName && node.object.property?.name === 'data') {
                            if (node.property?.type === 'Identifier' && this.messageKeys.has(node.property.name)) foundSpecificKeys.add(node.property.name);
                        }
                    },
                    Literal: (node) => {
                        if (typeof node.value === 'string' && node.parent.type === 'BinaryExpression' && node.parent.operator === '===' && node.parent.left?.type === 'MemberExpression') {
                            if (node.parent.left.object?.type === 'MemberExpression' && node.parent.left.object.object?.name === effectiveEventParamName && node.parent.left.object.property?.name === 'data') { if(this.messageTypes.has(node.value)) foundSpecificTypes.add(node.value); }
                        } else if (typeof node.value === 'string' && node.parent.type === 'SwitchCase' && node.parent.test === node) { if(this.messageTypes.has(node.value)) foundSpecificTypes.add(node.value); }
                    },
                    CallExpression: (node) => {
                        if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'postMessage') usesPostMessageCall = true;
                        if (node.callee.type === 'MemberExpression' && node.callee.object?.name === 'JSON' && node.callee.property?.name === 'parse') usesJsonParse = true;
                        if(node.callee.type === 'MemberExpression' && node.callee.property?.name === 'test' && node.arguments.length > 0 && node.arguments[0].object?.name === effectiveEventParamName && node.arguments[0].property?.name === 'origin') hasOriginCheckStructure = true;
                    }
                });

                const keysDelta = foundSpecificKeys.size * SPECIFIC_KEY_MATCH_BONUS;
                const typesDelta = foundSpecificTypes.size * SPECIFIC_TYPE_MATCH_BONUS;
                featureScore += keysDelta; if (dbg && keysDelta) dbg.contributions.push({rule:'SPECIFIC_KEY_MATCH_BONUS', delta:keysDelta, details:Array.from(foundSpecificKeys)});
                featureScore += typesDelta; if (dbg && typesDelta) dbg.contributions.push({rule:'SPECIFIC_TYPE_MATCH_BONUS', delta:typesDelta, details:Array.from(foundSpecificTypes)});
                if (usesPostMessageCall && !handlerFlags.mentionsPostMessageNull) { featureScore += POSTMESSAGE_CALL_BONUS; if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_CALL_BONUS', delta:POSTMESSAGE_CALL_BONUS}); }
                if (hasOriginCheckStructure) { featureScore += ORIGIN_CHECK_STRUCTURE_BONUS; hasStrongSignal = true; if (dbg) dbg.contributions.push({rule:'ORIGIN_CHECK_STRUCTURE_BONUS', delta:ORIGIN_CHECK_STRUCTURE_BONUS}); }
                if (usesJsonParse) { featureScore += JSON_PARSE_BONUS; if (dbg) dbg.contributions.push({rule:'JSON_PARSE_BONUS', delta:JSON_PARSE_BONUS}); }

            } catch (e) { }
        }

        if(!hasStrongSignal && handlerFlags.hasStrongSignal !== undefined) {
            hasStrongSignal = handlerFlags.hasStrongSignal;
        }

        if (handlerCodeLength < MIN_COMPLEXITY_LENGTH && !hasStrongSignal && featureScore < (VERIFIER_BONUS / 2)) {
            featureScore += SIMPLICITY_PENALTY; if (dbg) dbg.contributions.push({rule:'SIMPLICITY_PENALTY', delta:SIMPLICITY_PENALTY});
        }

        if (!handlerNode && handlerCode) {
            if (!hasStrongSignal) {
                if (handlerCode.match(/(event|msg|message|e)\.data\.(type|action|kind|msgType|payload|message)/)) featureScore += 15;
                else if (handlerCode.match(/(event|msg|message|e)\.data\.\w+/)) featureScore += 5;
                if (handlerCode.match(/(event|msg|message|e)\.origin/)) featureScore += 10;
                if (handlerCode.match(/\.origin\s*(===|!==|==|!=)/)) featureScore += 20;
                else if (handlerCode.match(/\.origin\.(startsWith|endsWith|includes|indexOf|test)\(/)) featureScore += 20;
                if (handlerCode.match(/switch\s*\([^)]*?\.data\.\w+\)/)) featureScore += 30;
                if (handlerCode.includes('JSON.parse')) featureScore += 10;
            }
            if (handlerCode.includes('postMessage') && !handlerCode.match(/postMessage\s*\(\s*null\s*\)/)) featureScore += POSTMESSAGE_CALL_BONUS;
            if (handlerCode.match(/unstable_now|MessageChannel/)) featureScore += SCHEDULER_PENALTY / 2;
        }

        if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE && featureScore < 200) { featureScore -= 150; if (dbg) dbg.contributions.push({rule:'OVERSIZE_CODE_PENALTY_HEAVY', delta:-150}); }
        else if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE) { featureScore -= 50; if (dbg) dbg.contributions.push({rule:'OVERSIZE_CODE_PENALTY_LIGHT', delta:-50}); }

        score += featureScore;

        if (category?.includes('runtime')) { score += 150; if (dbg) dbg.contributions.push({rule:'CATEGORY_RUNTIME', delta:150}); }
        else if (category?.includes('debugger') || category?.includes('breakpoint')) { score += 75; if (dbg) dbg.contributions.push({rule:'CATEGORY_DEBUGGER', delta:75}); }
        else if (category?.includes('ast-event-listener') || category?.includes('ast-onmessage')) { score += 50; if (dbg) dbg.contributions.push({rule:'CATEGORY_AST', delta:50}); }
        else if (category?.includes('inline-onmessage-attribute')) { score += 5; if (dbg) dbg.contributions.push({rule:'CATEGORY_INLINE', delta:5}); }
        else if (category?.includes('regex')) { score += 1; if (dbg) dbg.contributions.push({rule:'CATEGORY_REGEX', delta:1}); }
        const finalScore = Math.max(0, score);
        if (dbg) this._log(3, 'debug', `[Score] ${source || 'inline'} (${category}) => ${finalScore}`, { functionName, flags: handlerFlags, breakdown: dbg.contributions });
        return finalScore;
    }


    getBestHandler(handlersInfo) {
        if (!handlersInfo || handlersInfo.length === 0) return null;

        const calculateHeuristicBoost = (handlerInfo) => {
            let boost = 0;
            const source = handlerInfo.source || '';
            const category = handlerInfo.category || '';
            const filename = source.substring(source.lastIndexOf('/') + 1);
            let reason = "No boost applied";

            if (category.includes('breakpoint') || category.includes('ast')) {
                if (filename.match(/app\.js|main\.js|index\.js/i)) {
                    boost = 50;
                    reason = "App-like name";
                } else if (filename.match(/^(npm|vendor|chunk|bundle|poly|webpack)/i) || filename.match(/^\d+\.js$/)) {
                    // Penalize only if there are other non-chunk candidates
                    boost = (handlersInfo.some(h => {
                        const f = (h.source||'').split('/').pop()||'';
                        return !/^(npm|vendor|chunk|bundle|poly|webpack)/i.test(f) && !/^\d+\.js$/.test(f);
                    })) ? -15 : 0;
                    reason = "Lib/Chunk-like name";
                } else if (filename.length > 20 && filename.endsWith('.js')) { // Boost longer JS names slightly more
                    boost = 15;
                    reason = "Longer/specific name";
                } else {
                    reason = "Filename pattern mismatch";
                }
            } else {
                reason = "Category not eligible for boost";
            }
            if(typeof log !== 'undefined') log.debug(`[getBestHandler Boost Calc] File: ${filename}, Category: ${category}, Calculated Boost: ${boost} (Reason: ${reason})`);
            return boost;
        };

        // Early exit for extremely high confidence handlers (saves processing time)
        const HIGH_CONFIDENCE_THRESHOLD = 800;
        for (const handlerInfo of handlersInfo) {
            if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
            }
            if (handlerInfo.handler) {
                const quickScore = this.scoreHandler(handlerInfo);
                if (quickScore >= HIGH_CONFIDENCE_THRESHOLD) {
                    if(typeof log !== 'undefined') log.success(`[getBestHandler] Early exit - found high confidence handler (score: ${quickScore})`);
                    return { ...handlerInfo, score: quickScore };
                }
            }
        }

        const scoredHandlers = handlersInfo.map((handlerInfo, index) => {
            let originalScore = 0;
            let boostedScore = 0;
            const handlerCodePresent = !!handlerInfo.handler || (handlerInfo.fullScriptContent && handlerInfo.handlerNode);

            if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
            }

            if (!handlerInfo.handler) {
                if(typeof log !== 'undefined') log.warn(`[getBestHandler Map] Handler candidate ${index} missing handler code. Assigning score 0.`);
                originalScore = 0;
                boostedScore = 0;
            } else {
                originalScore = this.scoreHandler(handlerInfo);
                boostedScore = originalScore;

                if (handlerInfo.category?.includes('prototype') || handlerInfo.category?.includes('objectMethod') || handlerInfo.category?.includes('indirect')) boostedScore += 10;
                else if (handlerInfo.category?.includes('ast-event-listener-identifier') || handlerInfo.category?.includes('ast-onmessage-assignment-identifier')) boostedScore += 5;
                else if (handlerInfo.category?.includes('breakpoint')) boostedScore += 20;

                boostedScore += calculateHeuristicBoost(handlerInfo);
                boostedScore = Math.max(0, boostedScore);
            }

            this._log(2, 'debug', `[getBestHandler Map] Candidate ${index}: Source=${handlerInfo.source?.substring(handlerInfo.source?.lastIndexOf('/')+1)}, BaseScore=${originalScore}, FinalScore=${boostedScore}`);
            return { ...handlerInfo, score: boostedScore };
        }).filter(h => h.score > 0);

        if (scoredHandlers.length === 0) {
            if(typeof log !== 'undefined') log.debug("[getBestHandler] No candidates scored above 0 after boosting/filtering.");
            return null;
        }

        this._log(2, 'debug', "[getBestHandler] Scored Candidates (After Boost, Pre-sort):", JSON.stringify(scoredHandlers.map(h => ({ score: h.score, category: h.category, source: h.source?.substring(h.source?.lastIndexOf('/')+1), name: h.functionName || 'N/A', flags: h.handlerFlags })), null, 2));

        const categoryPriority = { 'runtime': 1, 'debugger': 2, 'breakpoint': 3, 'ast-event-listener': 4, 'ast-onmessage': 5, 'regex': 7, 'inline-onmessage-attribute': 8 };

        scoredHandlers.sort((a, b) => {
            if (b.score !== a.score) return b.score - a.score;
            const priorityA = categoryPriority[a.category?.split('-')[0]] || 99;
            const priorityB = categoryPriority[b.category?.split('-')[0]] || 99;
            if (priorityA !== priorityB) return priorityA - priorityB;
            const lenA = a.handlerNode ? a.handlerNode.end - a.handlerNode.start : (a.handler?.length || 0);
            const lenB = b.handlerNode ? b.handlerNode.end - b.handlerNode.start : (b.handler?.length || 0);
            if (lenA !== lenB) return lenB - lenA;
            return (a.source || '').localeCompare(b.source || '');
        });

        let bestHandlerInfo = scoredHandlers[0];

        if (scoredHandlers.length > 1) {
            const flags = bestHandlerInfo.handlerFlags || {};
            const isLikelyScheduler = flags.looksLikeScheduler || flags.mentionsPostMessageNull;
            const hasStrongSignals = flags.hasStrongSignal || flags.callsVerifier || flags.usesCallbackMap || flags.accessesEventOriginConditionally || flags.usesSwitchOnEventData || flags.accessesEventDataConditionally || bestHandlerInfo.score > 200;
            const handlerLen = bestHandlerInfo.handlerNode ? bestHandlerInfo.handlerNode.end - bestHandlerInfo.handlerNode.start : (bestHandlerInfo.handler?.length || 0);
            const isTooSimple = handlerLen > 0 && handlerLen < 65;

            if ((isLikelyScheduler || (isTooSimple && !hasStrongSignals)) && bestHandlerInfo.score > 0) {
                for (let i = 1; i < scoredHandlers.length; i++) {
                    const alternative = scoredHandlers[i];
                    const altFlags = alternative.handlerFlags || {};
                    const altIsLikelyScheduler = altFlags.looksLikeScheduler || altFlags.mentionsPostMessageNull;
                    const altHasStrongSignals = altFlags.hasStrongSignal || altFlags.callsVerifier || altFlags.usesCallbackMap || altFlags.accessesEventOriginConditionally || altFlags.usesSwitchOnEventData || altFlags.accessesEventDataConditionally || alternative.score > 150;
                    const altHandlerLen = alternative.handlerNode ? alternative.handlerNode.end - alternative.handlerNode.start : (alternative.handler?.length || 0);
                    const altIsTooSimple = altHandlerLen > 0 && altHandlerLen < 65;

                    if (!altIsLikelyScheduler && (altHasStrongSignals || !altIsTooSimple)) {
                        const scoreDifference = bestHandlerInfo.score - alternative.score;
                        if (alternative.score > 100 || scoreDifference < 150 ) {
                            if(typeof log !== 'undefined') log.debug(`[getBestHandler] Top handler (${bestHandlerInfo.score}) rejected (Scheduler/Too Simple: ${isLikelyScheduler}/${isTooSimple}, StrongSignals: ${hasStrongSignals}). Promoting alternative (${alternative.score}, StrongSignals: ${altHasStrongSignals}, Simple: ${altIsTooSimple}).`);
                            bestHandlerInfo = alternative;
                            break;
                        }
                    }
                }
            }
        }

        let finalHandlerCode = bestHandlerInfo.handler || '';
        if (!finalHandlerCode && bestHandlerInfo.fullScriptContent && bestHandlerInfo.handlerNode) {
            try { finalHandlerCode = bestHandlerInfo.fullScriptContent.substring(bestHandlerInfo.handlerNode.start, bestHandlerInfo.handlerNode.end); }
            catch (e) { finalHandlerCode = "[Error extracting code string]"; }
        } else if (!finalHandlerCode && bestHandlerInfo.fullScriptContent) {
            finalHandlerCode = bestHandlerInfo.fullScriptContent;
        }
        if (!bestHandlerInfo.handler && finalHandlerCode !== "[Error extracting code string]") {
            bestHandlerInfo.handler = finalHandlerCode;
        }

        const bestLen = bestHandlerInfo.handlerNode ? bestHandlerInfo.handlerNode.end - bestHandlerInfo.handlerNode.start : finalHandlerCode.length;
        this._log(1, 'debug', `[getBestHandler] Selected Handler: Score=${bestHandlerInfo.score}, Category=${bestHandlerInfo.category}, Source=${bestHandlerInfo.source}, EstLen=${bestLen}, Name=${bestHandlerInfo.functionName || 'N/A'}, Flags=${JSON.stringify(bestHandlerInfo.handlerFlags)}`);

        return bestHandlerInfo;
    }

    analyzeWithRegex(content, sourceUrl) {
        const handlers = []; const onMessageRegex = /\bonmessage\s*=\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})/gi; const addEventListenerRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})\s*,?/gi; const addEventListenerIdentifierRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)\s*,?/gi; let match;
        while ((match = onMessageRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-onmessage', source: sourceUrl });
        while ((match = addEventListenerRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-event-listener-inline', source: sourceUrl });
        while ((match = addEventListenerIdentifierRegex.exec(content)) !== null) { const functionName = match[1]; const funcDefRegex = new RegExp(`(?:function\\s+${functionName}\\s*\\(|(?:var|let|const)\\s+${functionName}\\s*=\\s*function\\s*\\()(\\s*\\(.*?\\)\\s*\\{[\\s\\S]*?\\})`, 'i'); const funcMatch = content.match(funcDefRegex); if (funcMatch?.[0]) { const firstParenIndex = funcMatch[0].indexOf('('); const functionSignatureAndBody = funcMatch[0].substring(firstParenIndex); const fullHandlerText = `function${functionSignatureAndBody}`; handlers.push({ handler: fullHandlerText, category: 'regex-event-listener-identifier', source: sourceUrl, functionName: functionName }); } }
        return handlers.map(h => ({ ...h, handlerNode: null, fullScriptContent: h.handler }));
    }

    async extractDynamicallyViaDebugger(targetUrl) {
        const handlers = new Set();
        let tabId = null;
        let attached = false;
        let detachReason = null;
        const collectedScripts = new Map();
        let analysisTimer = null;
        const ANALYSIS_TIMEOUT = 15000;  // Increased for better handler detection
        const SETTLE_TIME = 2000;        // Increased for script parsing to complete
        const LOAD_EXTRA_TIME = 3000;    // Increased for page load completion
        let resolveAnalysis;
        const analysisPromise = new Promise(res => { resolveAnalysis = res; });
        let analysisResolved = false;
        let eventListener = null;
        let detachListener = null;
        let listenerAttached = false;
        let detachListenerAttached = false;

        eventListener = (source, method, params) => {
            if (!tabId || source.tabId !== tabId) return;
            if (method === 'Debugger.scriptParsed') {
                const { scriptId, url } = params;
                if (url && !url.startsWith('chrome-extension://') && url !== 'about:blank' && url.startsWith('http')) { // Ensure URL is valid http/https
                    if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Script parsed: ID=${scriptId}, URL=${url.substring(0,100)}`);
                    collectedScripts.set(scriptId, { url: url, scriptId: scriptId });
                    clearTimeout(analysisTimer);
                    analysisTimer = setTimeout(() => {
                        if (!analysisResolved) {
                            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Script parsing settled.');
                            analysisResolved = true;
                            resolveAnalysis();
                        }
                    }, SETTLE_TIME);
                }
            } else if (method === 'Page.loadEventFired') {
                if(typeof log !== 'undefined') log.debug('[Debugger Tab] Page load event fired.');
                clearTimeout(analysisTimer);
                analysisTimer = setTimeout(() => {
                    if (!analysisResolved) {
                        if(typeof log !== 'undefined') log.debug('[Debugger Tab] Page loaded + settle time.');
                        analysisResolved = true;
                        resolveAnalysis();
                    }
                }, LOAD_EXTRA_TIME);
            } else if (method === 'Runtime.exceptionThrown') {
                if(typeof log !== 'undefined') log.warn('[Debugger Tab] Exception in target:', params.exceptionDetails?.exception?.description || 'Unknown error');
            }
        };

        detachListener = (source, reason) => {
            if (source.tabId === tabId) {
                detachReason = reason;
                if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Detached unexpectedly from tab ${tabId}. Reason: ${reason}`);
                attached = false;
                if (eventListener && chrome?.debugger?.onEvent) try {chrome.debugger.onEvent.removeListener(eventListener); listenerAttached = false;} catch(e){}
                if (detachListener && chrome?.debugger?.onDetach) try {chrome.debugger.onDetach.removeListener(detachListener); detachListenerAttached = false;} catch(e){}
                if (!analysisResolved) {
                    analysisResolved = true;
                    resolveAnalysis();
                }
            }
        };

        try {
            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Creating temporary background tab for:', targetUrl);

            // Create tab with special parameter to mark it as handler extraction
            const analysisUrl = targetUrl + (targetUrl.includes('?') ? '&' : '?') + 'frogpost_handler_extraction=true';
            const tab = await chrome.tabs.create({ url: analysisUrl, active: false });
            tabId = tab.id;
            if (!tabId) throw new Error("Failed to create target tab.");
            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Created target tab ID: ${tabId}`);

            // Mark this tab as a handler extraction tab
            await chrome.storage.local.set({ [`handler-extraction-tab-${tabId}`]: true });

            await new Promise(res => setTimeout(res, 2000)); // Increased for better page load

            await chrome.debugger.attach({ tabId }, "1.3");
            attached = true;
            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attached to target tab: ${tabId}`);

            chrome.debugger.onEvent.addListener(eventListener); listenerAttached = true;
            chrome.debugger.onDetach.addListener(detachListener); detachListenerAttached = true;

            await Promise.all([
                chrome.debugger.sendCommand({ tabId }, "Page.enable"),
                chrome.debugger.sendCommand({ tabId }, "Runtime.enable"),
                chrome.debugger.sendCommand({ tabId }, "Debugger.enable")
            ]);
            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Enabled domains.`);

            const overallTimeout = setTimeout(() => {
                if (!analysisResolved) {
                    if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Overall analysis timeout reached.`);
                    analysisResolved = true;
                    resolveAnalysis();
                }
            }, ANALYSIS_TIMEOUT);

            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Waiting for script parsing to settle...');
            await analysisPromise;
            clearTimeout(overallTimeout);

            if (!attached) throw new Error(`Debugger detached unexpectedly. Reason: ${detachReason || 'Unknown'}`);
            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Proceeding to fetch ${collectedScripts.size} script sources.`);

            const sourcePromises = Array.from(collectedScripts.keys()).map(scriptId =>
                chrome.debugger.sendCommand({ tabId }, "Debugger.getScriptSource", { scriptId })
                    .then(result => ({ scriptId, source: result.scriptSource }))
                    .catch(err => {
                        if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Failed to get source for scriptId ${scriptId}:`, err?.message || err);
                        return { scriptId, source: null };
                    })
            );
            const sources = await Promise.all(sourcePromises);

            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Analyzing ${sources.filter(s => s.source).length} fetched script sources.`);
            for (const { scriptId, source } of sources) {
                if (source) {
                    const scriptInfo = collectedScripts.get(scriptId);
                    const sourceUrl = scriptInfo?.url || `tab_${tabId}_scriptId_${scriptId}`;
                    const scriptHandlers = this.analyzeScriptContent(source, sourceUrl);
                    scriptHandlers.forEach(handlerInfo => handlers.add(handlerInfo));
                }
            }
        } catch (error) {
            if(typeof log !== 'undefined') log.error('[Debugger Tab] Error during dynamic extraction process:', error);
            handlers.clear();
        } finally {
            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Entering finally block for cleanup.');
            clearTimeout(analysisTimer);
            if (attached && tabId) {
                if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attempting to detach from tab: ${tabId}`);
                try {
                    if (listenerAttached && eventListener && chrome?.debugger?.onEvent) chrome.debugger.onEvent.removeListener(eventListener);
                    if (detachListenerAttached && detachListener && chrome?.debugger?.onDetach) chrome.debugger.onDetach.removeListener(detachListener);
                    await chrome.debugger.sendCommand({ tabId }, "Debugger.disable").catch(e => {});
                    await chrome.debugger.detach({ tabId });
                    if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Detached successfully from tab: ${tabId}`);
                } catch (detachError) {
                    if(typeof log !== 'undefined') log.error('[Debugger Tab] Error detaching:', detachError?.message || detachError);
                }
            }
            else { if(typeof log !== 'undefined') log.debug('[Debugger Tab] Skipping detach (not attached or no tabId).'); }

            if (tabId) {
                if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attempting to remove temporary tab: ${tabId}`);
                try {
                    // Clean up the handler extraction flag
                    await chrome.storage.local.remove(`handler-extraction-tab-${tabId}`);

                    await chrome.tabs.remove(tabId);
                }
                catch (removeError) { if(typeof log !== 'undefined') log.error(`[Debugger Tab] Error removing temporary tab ${tabId}:`, removeError); }
            }
        }
        if(typeof log !== 'undefined') log.success(`[Debugger Tab] Dynamic extraction finished. Found ${handlers.size} potential handler structures.`);
        return Array.from(handlers);
    }

    async confirmHandlerViaBreakpointExecution(targetUrl, potentialHandlers, testMessageData = {"FrogPost": "BreakpointTest"}) {
        if (!potentialHandlers || potentialHandlers.length === 0) {
            if(typeof log !== 'undefined') log.warn('[Breakpoint Exec] No potential handlers provided.');
            return null;
        }

        let tabId = null;
        let attached = false;
        let confirmedHandler = null;
        const breakpointMap = new Map();
        let targetOrigin = '*';

        const onDebuggerEvent = (source, method, params) => {
            if (!tabId || source.tabId !== tabId) return;

            if (method === 'Debugger.paused' && params.hitBreakpoints && params.hitBreakpoints.length > 0) {
                if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Debugger paused. Hit Breakpoints: ${params.hitBreakpoints.join(', ')}`);
                for (const bpId of params.hitBreakpoints) {
                    if (breakpointMap.has(bpId)) {
                        confirmedHandler = breakpointMap.get(bpId);
                        if(typeof log !== 'undefined') log.success(`[Breakpoint Exec] Confirmed handler via breakpoint ${bpId}. Handler category: ${confirmedHandler.category}`);
                        break;
                    }
                }
                chrome.debugger.sendCommand({ tabId }, "Debugger.resume").catch(e => log.warn("[Breakpoint Exec] Error resuming debugger:", e.message));
            } else if (method === 'Debugger.scriptParsed') {
            } else if (method === 'Runtime.exceptionThrown') {
                if(typeof log !== 'undefined') log.warn('[Breakpoint Exec Tab] Exception in target:', params.exceptionDetails?.exception?.description || 'Unknown error');
            }
        };

        const onDebuggerDetach = (source, reason) => {
            if (source.tabId === tabId) {
                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec Tab] Detached from tab ${tabId}. Reason: ${reason}`);
                attached = false;
            }
        };

        try {
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Creating temp tab for: ${targetUrl}`);
            // Create the temporary tab with a special marker so the extension ignores it
            const analysisUrl = targetUrl + (targetUrl.includes('?') ? '&' : '?') + 'frogpost_handler_extraction=true';
            const tab = await chrome.tabs.create({ url: analysisUrl, active: false });
            tabId = tab.id;
            if (!tabId) throw new Error("Failed to create target tab.");
            // Mark this tab in storage as a handler-extraction tab for extra safety
            try { await chrome.storage.local.set({ [`handler-extraction-tab-${tabId}`]: true }); } catch {}
            // Wait for page to be ready - need enough time for scripts to load
            await new Promise(resolve => setTimeout(resolve, 1000)); // Reduced from 1500

            targetOrigin = new URL(targetUrl).origin;

            await chrome.debugger.attach({ tabId }, "1.3");
            attached = true;
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Attached to target tab: ${tabId}`);

            chrome.debugger.onEvent.addListener(onDebuggerEvent);
            chrome.debugger.onDetach.addListener(onDebuggerDetach);

            await Promise.all([
                chrome.debugger.sendCommand({ tabId }, "Page.enable"),
                chrome.debugger.sendCommand({ tabId }, "Runtime.enable"),
                chrome.debugger.sendCommand({ tabId }, "Debugger.enable")
            ]);
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Enabled debugger domains.`);

            let breakpointPromises = [];
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Attempting to set breakpoints for ${potentialHandlers.length} potential handlers.`);
            for (const handlerInfo of potentialHandlers) {
                if (handlerInfo.handlerNode?.loc?.start) {
                    const location = {
                        scriptId: '', // This needs to be determined, major challenge!
                        lineNumber: handlerInfo.handlerNode.loc.start.line - 1, // Acorn lines are 1-based, debugger is 0-based
                        columnNumber: handlerInfo.handlerNode.loc.start.column
                    };

                    if (handlerInfo.source && handlerInfo.source.startsWith('http')) {
                        const bpPromise = chrome.debugger.sendCommand({ tabId }, "Debugger.setBreakpointByUrl", {
                            url: handlerInfo.source, // Or regex if needed
                            lineNumber: location.lineNumber,
                            columnNumber: location.columnNumber
                        }).then(result => {
                            if (result && result.breakpointId) {
                                breakpointMap.set(result.breakpointId, handlerInfo);
                                if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Set breakpoint ${result.breakpointId} for handler at ${handlerInfo.source}:${location.lineNumber}`);
                            } else {
                                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Failed to set breakpoint for handler at ${handlerInfo.source}:${location.lineNumber}`);
                            }
                            return result;
                        }).catch(err => {
                            // Handle "already exists" errors gracefully
                            if (err && (err.code === -32000 || /already exists/i.test(err.message||''))) {
                                if(typeof log !== 'undefined') log.info(`[Breakpoint Exec] Breakpoint already exists at ${handlerInfo.source}:${location.lineNumber} - continuing.`);
                            } else {
                                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Error setting breakpoint for handler at ${handlerInfo.source}:${location.lineNumber}: ${err.message}`);
                            }
                            return null;
                        });
                        breakpointPromises.push(bpPromise);
                    } else {
                        if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Cannot set breakpoint for handler candidate without source URL or scriptId mapping.`);
                    }

                } else {
                    if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Skipping handler candidate, no location info: ${handlerInfo.category}`);
                }
            }
            await Promise.all(breakpointPromises);
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Finished attempting to set ${breakpointMap.size} breakpoints.`);

            if (breakpointMap.size === 0) {
                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] No breakpoints could be set. Potential handlers:`, potentialHandlers.map(h => ({
                    category: h.category,
                    source: h.source?.substring(h.source?.lastIndexOf('/')+1),
                    hasLocation: !!h.handlerNode?.loc?.start
                })));
                throw new Error("Could not set any breakpoints for potential handlers.");
            }

            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Injecting postMessage probes with targetOrigin: ${targetOrigin}`);

            // Send both probes in parallel for faster execution
            const jsonProbe = JSON.stringify(testMessageData || { "FrogPost": "BreakpointTest" });
            const strProbe = 'FrogPost::BreakpointTest';

            const probePromises = [
                chrome.debugger.sendCommand({ tabId }, "Runtime.evaluate", {
                    expression: `window.postMessage(${jsonProbe}, '${targetOrigin}');`
                }),
                chrome.debugger.sendCommand({ tabId }, "Runtime.evaluate", {
                    expression: `window.postMessage('${strProbe}', '${targetOrigin}');`
                })
            ];

            // Adaptive delay based on number of breakpoints set
            const breakpointDelay = Math.min(200 + (breakpointMap.size * 50), 500);
            await new Promise(resolve => setTimeout(resolve, breakpointDelay));

            await Promise.all(probePromises);
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Both probes sent in parallel.`);

            // Wait for handler confirmation with early exit capability
            const maxWaitTime = 2000; // Reduced from 3000
            const checkInterval = 50;  // Reduced from 100 for faster checking
            let waitedTime = 0;

            while (waitedTime < maxWaitTime && !confirmedHandler) {
                await new Promise(resolve => setTimeout(resolve, checkInterval));
                waitedTime += checkInterval;
            }

            if (confirmedHandler) {
                if(typeof log !== 'undefined') log.success(`[Breakpoint Exec] Confirmed handler via execution (${waitedTime}ms):`, confirmedHandler);
                confirmedHandler.category = `breakpoint-${confirmedHandler.category || 'confirmed'}`;
            } else {
                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] No breakpoint hit confirmed within ${maxWaitTime}ms timeout.`);
            }

        } catch (error) {
            if(typeof log !== 'undefined') log.error('[Breakpoint Exec] Error during process:', error);
            confirmedHandler = null;
        } finally {
            if (attached && tabId) {
                if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Cleaning up debugger for tab ${tabId}`);
                try {
                    chrome.debugger.onEvent.removeListener(onDebuggerEvent);
                    chrome.debugger.onDetach.removeListener(onDebuggerDetach);
                    await chrome.debugger.sendCommand({ tabId }, "Debugger.disable");
                    await chrome.debugger.detach({ tabId });
                } catch (detachError) {
                    if(typeof log !== 'undefined') log.error('[Breakpoint Exec] Error during cleanup:', detachError?.message || detachError);
                }
            }
            if (tabId) {
                try {
                    // Clean up the handler extraction flag
                    await chrome.storage.local.remove(`handler-extraction-tab-${tabId}`);

                    await chrome.tabs.remove(tabId);
                }
                catch (removeError) { if(typeof log !== 'undefined') log.error(`[Breakpoint Exec] Error removing temp tab ${tabId}:`, removeError); }
            }
        }
        return confirmedHandler;
    }

}

// New methods added to support dashboard calls
HandlerExtractor.prototype.extractStaticallyWithContext = async function(targetUrl, messageKeys, messageTypes, messageValues) {
    const handlers = new Set();
    try {
        this._log(1, 'debug', `[Static Context] Fetching HTML for: ${targetUrl}`);
        const res = await fetch(targetUrl, { credentials: 'omit', cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const html = await res.text();

        // Extract external script src URLs
        const srcRegex = /<script[^>]*\bsrc=["']([^"']+)["'][^>]*><\/script>/gi;
        const srcs = new Set();
        let m;
        while ((m = srcRegex.exec(html)) !== null) {
            try {
                const absolute = new URL(m[1], targetUrl).href;
                // Skip extension and data URLs
                if (!absolute.startsWith('chrome-extension://') && !absolute.startsWith('data:')) srcs.add(absolute);
            } catch (_) {}
        }

        // Extract inline scripts
        const inlineRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
        let im;
        let inlineIndex = 0;
        while ((im = inlineRegex.exec(html)) !== null) {
            const content = im[1] || '';
            if (content.trim().length < 20) { inlineIndex++; continue; }
            const sourceId = `${new URL(targetUrl).origin}/inline_${inlineIndex}.js`;
            const found = this.analyzeScriptContent(content, sourceId);
            found.forEach(h => handlers.add(h));
            inlineIndex++;
        }

        this._log(1, 'debug', `[Static Context] Found ${srcs.size} external script(s). Fetching...`, Array.from(srcs).slice(0, 30));
        const fetchLimit = 40; // Avoid fetching too many scripts
        let fetchedCount = 0;
        for (const src of srcs) {
            if (fetchedCount >= fetchLimit) break;
            try {
                const sres = await fetch(src, { credentials: 'omit', cache: 'no-store' });
                if (!sres.ok) { fetchedCount++; continue; }
                const js = await sres.text();
                const found = this.analyzeScriptContent(js, src);
                found.forEach(h => handlers.add(h));
                this._log(2, 'debug', `[Static Context] Analyzed ${src}. Found ${found.length} candidate(s).`);
            } catch (_) { /* ignore individual script failures */ }
            fetchedCount++;
        }
        this._log(1, 'success', `[Static Context] Extraction complete. Candidates: ${handlers.size}`);
    } catch (e) {
        this._log(1, 'error', `[Static Context] Error: ${e?.message || e}`);
    }
    return Array.from(handlers);
};

HandlerExtractor.prototype.extractWithStrictIframe = async function(targetUrl, messageKeys, messageTypes, messageValues) {
    // Minimal strict mode: leverage debugger-based dynamic extraction to approximate iframe monitoring
    try {
        this._log(1, 'debug', `[Strict Iframe] Starting dynamic extraction for: ${targetUrl}`);
        const dynamicHandlers = await this.extractDynamicallyViaDebugger(targetUrl);
        if (Array.isArray(dynamicHandlers) && dynamicHandlers.length > 0) {
            this._log(1, 'success', `[Strict Iframe] Dynamic extraction returned ${dynamicHandlers.length} candidate(s).`);
            return dynamicHandlers;
        }
        this._log(1, 'warn', `[Strict Iframe] No dynamic candidates found. Returning empty set.`);
        return [];
    } catch (e) {
        this._log(1, 'error', `[Strict Iframe] Error: ${e?.message || e}`);
        return [];
    }
};
