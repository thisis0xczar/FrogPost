/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-05-01
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
        if(typeof log !== 'undefined') log.debug(`[Extractor Init] Initialized for ${endpoint}. Message count: ${this.messages.length}, Keys: ${this.messageKeys.size}, Types: ${this.messageTypes.size}`);
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
        if(typeof log !== 'undefined') log.debug(`[Extractor Scoring Context] Extracted message keys:`, Array.from(keys));
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
        if(typeof log !== 'undefined') log.debug(`[Extractor Scoring Context] Extracted message types/kinds:`, Array.from(types));
        return types;
    }

    analyzeScriptContent(content, sourceIdentifier) {
        const handlers = [];
        if (!content || typeof content !== 'string' || content.length < 50) return handlers;
        this.functionDefinitions.clear();
        let ast;
        let parseError = null;

        try {
            if (typeof acorn === 'undefined') throw new Error("Acorn not loaded");
            if(typeof log !== 'undefined') log.debug(`[Extractor] Attempting AST parse (module) for: ${sourceIdentifier}`);
            ast = acorn.parse(content, {
                ecmaVersion: 'latest',
                silent: true, // Keep silent to allow fallback
                locations: true,
                sourceType: 'module' // Attempt module parse
            });
            if(typeof log !== 'undefined') log.debug(`[Extractor] AST parsing as MODULE SUCCESS for: ${sourceIdentifier}`);

        } catch (moduleError) {
            if(typeof log !== 'undefined') log.warn(`[Extractor] AST module parse failed for ${sourceIdentifier}: ${moduleError.message}. Trying as script...`);
            try {
                ast = acorn.parse(content, {
                    ecmaVersion: 'latest',
                    silent: true,
                    locations: true,
                    sourceType: 'script' // Fallback to script parse
                });
                if(typeof log !== 'undefined') log.debug(`[Extractor] AST parsing as SCRIPT SUCCESS for: ${sourceIdentifier}`);
            } catch (scriptError) {
                parseError = scriptError;
                if(typeof log !== 'undefined') log.error(`[Extractor] AST parsing FAILED for ${sourceIdentifier} (both module & script): ${scriptError.message}. Falling back to regex.`);
                ast = null;
            }
        }

        if (ast) {
            try {
                this._mapFunctionDeclarations(ast);
                this._mapPrototypeMethods(ast);
                handlers.push(...this.analyzeAst(ast, content, sourceIdentifier));
            } catch(walkError) {
                if(typeof log !== 'undefined') log.error(`[Extractor] Error during AST walk for ${sourceIdentifier}:`, walkError);
                handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
            }
        } else {
            handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
        }

        if(typeof log !== 'undefined') log.debug(`[Extractor] Found ${handlers.length} potential structures in ${sourceIdentifier} (before scoring).`);
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
            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}, Scanning node type ${node.type}`);


            try {
                acorn.walk.simple(node.body, {
                    CallExpression: (callNode) => {
                        let calleeName = null;
                        let resolvedCalleeDef = null;
                        let isPassedEventArg = callNode.arguments.some(arg => arg.type === 'Identifier' && arg.name === eventParamName);

                        if (callNode.callee.type === 'Identifier') {
                            calleeName = callNode.callee.name;
                            resolvedCalleeDef = this.functionDefinitions.get(calleeName);
                            if(typeof log !== 'undefined' && resolvedCalleeDef) log.debug(`[quickScanRec] Depth ${currentDepth}: Found direct call to '${calleeName}', Definition found: ${!!resolvedCalleeDef.node}`);
                        } else if (callNode.callee.type === 'MemberExpression') {
                            if (callNode.callee.property.type === 'Identifier') {
                                calleeName = callNode.callee.property.name;
                                const objExpr = callNode.callee.object;
                                let objName = null;
                                let lookupKey = null;

                                if(objExpr.type === 'ThisExpression') objName = 'this';
                                else if (objExpr.type === 'Identifier') objName = objExpr.name;

                                if (objName) {
                                    lookupKey = `${objName}.${calleeName}`;
                                    resolvedCalleeDef = this.functionDefinitions.get(lookupKey);
                                    if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Found method call '${lookupKey}', Definition found: ${!!resolvedCalleeDef?.node}`);

                                    if (!resolvedCalleeDef) {
                                        const protoKey = Array.from(this.functionDefinitions.keys()).find(key => key.endsWith(`.${calleeName}`) && this.functionDefinitions.get(key)?.type === 'prototype');
                                        if(protoKey) {
                                            resolvedCalleeDef = this.functionDefinitions.get(protoKey);
                                            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Found potential prototype method '${calleeName}' via key '${protoKey}', Definition found: ${!!resolvedCalleeDef?.node}`);
                                        }
                                    }
                                } else {
                                    if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Method call '${calleeName}' on complex object type '${objExpr.type}', skipping lookup.`);
                                }
                            }
                        }

                        if (calleeName) {
                            if (VERIFIER_KEYWORDS.test(calleeName)) flags.callsVerifier = true;
                            if (SCHEDULER_KEYWORDS.includes(calleeName)) flags.looksLikeScheduler = true;
                            if (calleeName === 'postMessage' && callNode.arguments.length > 0 && callNode.arguments[0].type === 'Literal' && callNode.arguments[0].value === null) flags.mentionsPostMessageNull = true;
                        }

                        if (resolvedCalleeDef?.node && isPassedEventArg) {
                            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Recursing into '${calleeName || 'callee'}' because event param '${eventParamName}' was passed.`);
                            const nestedFlags = quickScanForPatternsRecursive(resolvedCalleeDef.node, eventParamName, currentDepth + 1, new Set(visitedNodes));
                            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Flags from recursive call to '${calleeName || 'callee'}':`, nestedFlags);
                            for(const key in nestedFlags) {
                                if (typeof flags[key] === 'boolean') flags[key] = flags[key] || nestedFlags[key];
                                else if (typeof flags[key] === 'number') flags[key] += nestedFlags[key];
                            }
                        } else if (resolvedCalleeDef?.node && !isPassedEventArg) {
                            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}: Found call to '${calleeName || 'callee'}' but event param '${eventParamName}' not passed, not recursing.`);
                        }
                    },
                    MemberExpression: (memNode) => {
                        let baseObjectIsEvent = memNode.object?.type === 'Identifier' && memNode.object.name === eventParamName;
                        let baseObjectIsDeeperEventData = memNode.object?.type === 'MemberExpression' && memNode.object.object?.type === 'Identifier' && memNode.object.object.name === eventParamName && memNode.object.property?.name === 'data';

                        if (memNode.object.type === 'ThisExpression' || memNode.object.type === 'Identifier') {
                            if (memNode.property.type === 'Identifier' && CALLBACK_MAP_KEYWORDS.test(memNode.property.name)) {
                                let parentCall = memNode.parent.type === 'CallExpression' ? memNode.parent : null;
                                let grandParentMember = parentCall?.parent.type === 'MemberExpression' ? parentCall.parent : null;
                                if (parentCall && parentCall.callee === memNode && grandParentMember && grandParentMember.property.name === 'find') flags.usesCallbackMap = true;
                                else if (memNode.parent.type === 'MemberExpression' && memNode.parent.object === memNode && memNode.parent.property.type !== 'Identifier') flags.usesCallbackMap = true;
                            }
                        }

                        if (baseObjectIsEvent && memNode.property?.name === 'origin') {
                            flags.accessesOriginField = true;
                            let current = memNode.parent; let depth = 0;
                            while (current && depth < 5) {
                                if (current.type === 'IfStatement' || current.type === 'BinaryExpression' || current.type === 'ConditionalExpression' || current.type === 'LogicalExpression') { flags.accessesEventOriginConditionally = true; break; }
                                if (current.type === 'FunctionExpression' || current.type === 'FunctionDeclaration' || current.type === 'ArrowFunctionExpression') break;
                                current = current.parent; depth++;
                            }
                        }

                        if (baseObjectIsDeeperEventData && memNode.property?.type === 'Identifier') {
                            flags.accessesAnyDataField = true;
                            if(COMMON_DATA_FIELDS.has(memNode.property.name)) flags.accessesCommonDataFields++;
                            let current = memNode.parent; let depth = 0;
                            while(current && depth < 5) {
                                if(current.type === 'IfStatement' || current.type === 'SwitchCase' || current.type === 'ConditionalExpression' || current.type === 'LogicalExpression' || current.type === 'BinaryExpression') { flags.accessesEventDataConditionally = true; break; }
                                if(current.type === 'FunctionExpression' || current.type === 'FunctionDeclaration' || current.type === 'ArrowFunctionExpression') break;
                                current = current.parent; depth++;
                            }
                        }
                    },
                    SwitchStatement: (switchNode) => {
                        let discriminantChecksEventData = false;
                        if (switchNode.discriminant?.type === 'MemberExpression') {
                            const disc = switchNode.discriminant;
                            if (disc.object?.type === 'MemberExpression' && disc.object.object?.name === eventParamName && disc.object.property?.name === 'data') {
                                discriminantChecksEventData = true;
                            } else if (disc.object?.type === 'Identifier') {
                                if (COMMON_DATA_FIELDS.has(disc.property?.name)) discriminantChecksEventData = true;
                            }
                        }
                        if (discriminantChecksEventData) flags.usesSwitchOnEventData = true;
                    },
                    Identifier: (idNode) => {
                        if (SCHEDULER_KEYWORDS.includes(idNode.name)) flags.looksLikeScheduler = true;
                    }
                });
            } catch (e) {
                if(typeof log !== 'undefined') log.warn(`[Extractor AST Pattern Scan] Error during scan depth ${currentDepth}: ${e.message}`);
            }

            flags.hasStrongSignal = flags.callsVerifier || flags.usesCallbackMap || flags.accessesEventOriginConditionally || flags.usesSwitchOnEventData || flags.accessesEventDataConditionally;
            if(typeof log !== 'undefined') log.debug(`[quickScanRec] Depth ${currentDepth}, Node type ${node.type}. Final flags:`, flags);
            return flags;
        };

        try {
            acorn.walk.simple(ast, {
                AssignmentExpression: (node) => {
                    if (node.operator === '=' && node.left.type === 'MemberExpression' && node.left.property.name === 'onmessage') {
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
                                if(funcNode.params?.[0]?.type === 'Identifier') eventParamName = funcNode.params[0].name;
                                else if (funcNode.params?.length > 0) eventParamName = 'param0';
                                handlerFlags = quickScanForPatternsRecursive(funcNode, eventParamName, 0);
                            }
                        }
                        if (funcNode) foundHandlers.push({ category, source: sourceUrl, functionName, handlerNode: funcNode, fullScriptContent: scriptContent, handlerFlags, eventParamName });
                    }
                },
                CallExpression: (node) => {
                    if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'addEventListener' && node.arguments.length >= 2 && node.arguments[0].type === 'Literal' && node.arguments[0].value === 'message') {
                        const handlerArg = node.arguments[1];
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
                        }
                    }
                }
            });
        } catch (e) {
            if(typeof log !== 'undefined') log.error(`[Extractor] Error walking AST for ${sourceUrl}:`, e);
        }
        return foundHandlers;
    }


    scoreHandler(handlerInfo) {
        const { handlerNode, category, source, fullScriptContent, functionName, handlerFlags = {}, eventParamName } = handlerInfo;
        const handlerCode = handlerInfo.handler || fullScriptContent;
        let score = 0;
        const MIN_CODE_LENGTH_ESTIMATE = 25;
        const MAX_CODE_LENGTH_ESTIMATE = 30000;
        const MIN_COMPLEXITY_LENGTH = 65;

        const SCHEDULER_PENALTY = -250;
        const POSTMESSAGE_NULL_PENALTY = -75;
        const SIMPLICITY_PENALTY = -50;

        const VERIFIER_BONUS = 120;
        const CALLBACK_MAP_BONUS = 110;
        const CONDITIONAL_ORIGIN_ACCESS_BONUS = 125;
        const SWITCH_BONUS = 140;
        const CONDITIONAL_DATA_ACCESS_BONUS = 75;
        const ORIGIN_CHECK_STRUCTURE_BONUS = 90;

        const COMMON_DATA_FIELD_BONUS = 30;
        const ANY_DATA_FIELD_BONUS = 5;
        const ORIGIN_FIELD_BONUS = 10;
        const SPECIFIC_KEY_MATCH_BONUS = 150;
        const SPECIFIC_TYPE_MATCH_BONUS = 100;
        const JSON_PARSE_BONUS = 40;
        const POSTMESSAGE_CALL_BONUS = 5;

        let handlerCodeLength = handlerNode?.end && handlerNode?.start ? handlerNode.end - handlerNode.start : (handlerCode?.length || 0);
        if (handlerCodeLength < MIN_CODE_LENGTH_ESTIMATE) return 0;

        let baseScore = 5; score += baseScore;
        let featureScore = 0;
        let hasStrongSignal = handlerFlags.hasStrongSignal || false;

        if (handlerFlags.looksLikeScheduler) featureScore += SCHEDULER_PENALTY;
        if (handlerFlags.mentionsPostMessageNull) featureScore += POSTMESSAGE_NULL_PENALTY;

        if (handlerFlags.callsVerifier) featureScore += VERIFIER_BONUS;
        if (handlerFlags.usesCallbackMap) featureScore += CALLBACK_MAP_BONUS;
        if (handlerFlags.accessesEventOriginConditionally) featureScore += CONDITIONAL_ORIGIN_ACCESS_BONUS;
        if (handlerFlags.usesSwitchOnEventData) featureScore += SWITCH_BONUS;
        if (handlerFlags.accessesEventDataConditionally) featureScore += CONDITIONAL_DATA_ACCESS_BONUS;

        if (handlerFlags.accessesCommonDataFields > 0) featureScore += (handlerFlags.accessesCommonDataFields * COMMON_DATA_FIELD_BONUS);
        if (handlerFlags.accessesAnyDataField && !handlerFlags.accessesEventDataConditionally && handlerFlags.accessesCommonDataFields === 0) featureScore += ANY_DATA_FIELD_BONUS;
        if (handlerFlags.accessesOriginField && !handlerFlags.accessesEventOriginConditionally) featureScore += ORIGIN_FIELD_BONUS;

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

                featureScore += foundSpecificKeys.size * SPECIFIC_KEY_MATCH_BONUS;
                featureScore += foundSpecificTypes.size * SPECIFIC_TYPE_MATCH_BONUS;
                if (usesPostMessageCall && !handlerFlags.mentionsPostMessageNull) featureScore += POSTMESSAGE_CALL_BONUS;
                if (hasOriginCheckStructure) { featureScore += ORIGIN_CHECK_STRUCTURE_BONUS; hasStrongSignal = true; }
                if (usesJsonParse) featureScore += JSON_PARSE_BONUS;

            } catch (e) { }
        }

        if(!hasStrongSignal && handlerFlags.hasStrongSignal !== undefined) {
            hasStrongSignal = handlerFlags.hasStrongSignal;
        }

        if (handlerCodeLength < MIN_COMPLEXITY_LENGTH && !hasStrongSignal && featureScore < (VERIFIER_BONUS / 2)) {
            featureScore += SIMPLICITY_PENALTY;
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

        if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE && featureScore < 200) featureScore -= 150;
        else if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE) featureScore -= 50;

        score += featureScore;

        if (category?.includes('runtime')) score += 150;
        else if (category?.includes('debugger') || category?.includes('breakpoint')) score += 75;
        else if (category?.includes('ast-event-listener') || category?.includes('ast-onmessage')) score += 50;
        else if (category?.includes('inline-onmessage-attribute')) score += 5;
        else if (category?.includes('regex')) score += 1;

        return Math.max(0, score);
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
                    boost = -25;
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

            if(typeof log !== 'undefined') log.debug(`[getBestHandler Map] Candidate ${index}: Source=${handlerInfo.source?.substring(handlerInfo.source?.lastIndexOf('/')+1)}, BaseScore=${originalScore}, FinalScore=${boostedScore}`);
            return { ...handlerInfo, score: boostedScore };
        }).filter(h => h.score > 0);

        if (scoredHandlers.length === 0) {
            if(typeof log !== 'undefined') log.debug("[getBestHandler] No candidates scored above 0 after boosting/filtering.");
            return null;
        }

        if(typeof log !== 'undefined') log.debug("[getBestHandler] Scored Candidates (After Boost, Pre-sort):", JSON.stringify(scoredHandlers.map(h => ({ score: h.score, category: h.category, source: h.source?.substring(h.source?.lastIndexOf('/')+1), name: h.functionName || 'N/A', flags: h.handlerFlags })), null, 2));

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
        if(typeof log !== 'undefined') log.debug(`[getBestHandler] Selected Handler: Score=${bestHandlerInfo.score}, Category=${bestHandlerInfo.category}, Source=${bestHandlerInfo.source}, EstLen=${bestLen}, Name=${bestHandlerInfo.functionName || 'N/A'}, Flags=${JSON.stringify(bestHandlerInfo.handlerFlags)}`);

        return bestHandlerInfo;
    }

    analyzeWithRegex(content, sourceUrl) {
        const handlers = []; const onMessageRegex = /\bonmessage\s*=\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})/gi; const addEventListenerRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\(.*?\)\s*\{[\s\S]*?\})\s*,?/gi; const addEventListenerIdentifierRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)\s*,?/gi; let match;
        while ((match = onMessageRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-onmessage', source: sourceUrl });
        while ((match = addEventListenerRegex.exec(content)) !== null) handlers.push({ handler: match[1], category: 'regex-event-listener-inline', source: sourceUrl });
        while ((match = addEventListenerIdentifierRegex.exec(content)) !== null) { const functionName = match[1]; const funcDefRegex = new RegExp(`(?:function\\s+${functionName}\\s*\\(|(?:var|let|const)\\s+${functionName}\\s*=\\s*function\\s*\\()(\\s*\\(.*?\\)\\s*\\{[\\s\\S]*?\\})`, 'i'); const funcMatch = content.match(funcDefRegex); if (funcMatch?.[0]) { const firstParenIndex = funcMatch[0].indexOf('('); const functionSignatureAndBody = funcMatch[0].substring(firstParenIndex); const fullHandlerText = `function${functionSignatureAndBody}`; handlers.push({ handler: fullHandlerText, category: 'regex-event-listener-identifier', source: sourceUrl, functionName: functionName }); } }
        return handlers.map(h => ({ ...h, handlerNode: null, fullScriptContent: h.handler }));
    }

    async confirmHandlerViaBreakpointExecution(targetUrl, potentialHandlers, testMessageData = {"FrogPost": "BreakpointTest"}) {
        if (!potentialHandlers || potentialHandlers.length === 0) {
            if(typeof log !== 'undefined') log.warn('[Breakpoint Exec] No potential handlers provided.');
            return null;
        }

        let tabId = null;
        let attached = false;
        let confirmedHandler = null;
        const hitHandlerInfos = [];
        const breakpointMap = new Map();
        let targetOrigin = '*';
        let detachReason = null;
        let eventListener = null;
        let detachListener = null;
        const confirmedBreakpointIds = new Set();

        if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Starting confirmation for ${targetUrl}`);

        eventListener = (source, method, params) => {
            if (!tabId || source.tabId !== tabId) return;

            if (method === 'Debugger.paused' && params.hitBreakpoints && params.hitBreakpoints.length > 0) {
                if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Event: Debugger.paused. Hit Breakpoint IDs: [${params.hitBreakpoints.join(', ')}]`);
                let resumed = false;
                for (const bpId of params.hitBreakpoints) {
                    if (breakpointMap.has(bpId) && !confirmedBreakpointIds.has(bpId)) {
                        const handlerInfo = breakpointMap.get(bpId);
                        if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                            try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
                        }
                        if(handlerInfo.handler){
                            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Match found for hit breakpoint ${bpId}. Recording handler:`, {category: handlerInfo?.category, source: handlerInfo?.source, name: handlerInfo?.functionName});
                            hitHandlerInfos.push(handlerInfo);
                            confirmedBreakpointIds.add(bpId);
                        } else {
                            if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Breakpoint ${bpId} hit, but associated handler code missing.`);
                        }
                    } else if (breakpointMap.has(bpId) && confirmedBreakpointIds.has(bpId)) {
                        if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Breakpoint ${bpId} hit again, already recorded.`);
                    } else {
                        if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Paused on unknown breakpoint ID: ${bpId}`);
                    }
                }
                chrome.debugger.sendCommand({ tabId }, "Debugger.resume").catch(e => log.warn("[Breakpoint Exec] Error resuming debugger:", e.message));
            } else if (method === 'Runtime.exceptionThrown') {
                if(typeof log !== 'undefined') log.warn('[Breakpoint Exec Tab] Exception in target:', params.exceptionDetails?.exception?.description || 'Unknown error');
            } else if (method === 'Debugger.resumed') {
                if(typeof log !== 'undefined') log.debug('[Breakpoint Exec] Event: Debugger.resumed');
            }
        };

        detachListener = (source, reason) => {
            if (source.tabId === tabId) {
                detachReason = reason;
                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec Tab] Detached from tab ${tabId}. Reason: ${reason}`);
                attached = false;
                if (eventListener && chrome?.debugger?.onEvent) try { chrome.debugger.onEvent.removeListener(eventListener); } catch(e){}
                if (detachListener && chrome?.debugger?.onDetach) try { chrome.debugger.onDetach.removeListener(detachListener); } catch(e){}
            }
        };

        try {
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Creating temp tab for: ${targetUrl}`);
            const tab = await chrome.tabs.create({ url: targetUrl, active: false });
            tabId = tab.id;
            if (!tabId) throw new Error("Failed to create target tab.");
            await new Promise(resolve => setTimeout(resolve, 2500));

            try { targetOrigin = new URL(targetUrl).origin; } catch { targetOrigin = '*'; }
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Target origin for postMessage set to: ${targetOrigin}`);

            await chrome.debugger.attach({ tabId }, "1.3");
            attached = true;
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Attached to target tab: ${tabId}`);

            chrome.debugger.onEvent.addListener(eventListener);
            chrome.debugger.onDetach.addListener(detachListener);

            await Promise.all([
                chrome.debugger.sendCommand({ tabId }, "Page.enable"),
                chrome.debugger.sendCommand({ tabId }, "Runtime.enable"),
                chrome.debugger.sendCommand({ tabId }, "Debugger.enable")
            ]);
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Enabled debugger domains.`);

            let breakpointPromises = [];
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Potential handler candidates for breakpoint setting:`, potentialHandlers.map(h => ({ src: h.source, line: h.handlerNode?.loc?.start?.line, col: h.handlerNode?.loc?.start?.column, category: h.category, name: h.functionName })));

            for (const handlerInfo of potentialHandlers) {
                if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                    try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
                }
                if (!handlerInfo.handler) {
                    if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Skipping candidate for BP, missing handler code string: ${handlerInfo.category} from ${handlerInfo.source}`);
                    continue;
                }
                if (handlerInfo.handlerNode?.loc?.start) {
                    const location = { lineNumber: handlerInfo.handlerNode.loc.start.line - 1, columnNumber: handlerInfo.handlerNode.loc.start.column };
                    if (handlerInfo.source && handlerInfo.source.startsWith('http')) {
                        const urlForBp = handlerInfo.source;
                        if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Attempting to set BP for candidate: ${handlerInfo.category} at ${urlForBp}:${location.lineNumber}:${location.columnNumber}`);
                        const bpPromise = chrome.debugger.sendCommand({ tabId }, "Debugger.setBreakpointByUrl", { url: urlForBp, lineNumber: location.lineNumber, columnNumber: location.columnNumber })
                            .then(result => {
                                if (result && result.breakpointId) {
                                    breakpointMap.set(result.breakpointId, handlerInfo);
                                    if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Successfully set breakpoint ${result.breakpointId} for ${urlForBp}:${location.lineNumber}`);
                                } else {
                                    if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Failed to set BP for ${urlForBp}:${location.lineNumber}. Result:`, result);
                                }
                                return result;
                            }).catch(err => {
                                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Error setting BP for ${urlForBp}:${location.lineNumber}: ${err.message}`);
                                return null;
                            });
                        breakpointPromises.push(bpPromise);
                    } else { if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] Cannot set BP for handler candidate without source URL starting with http: ${handlerInfo.source}`); }
                } else { if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Skipping candidate, no location info: ${handlerInfo.category}`); }
            }
            await Promise.all(breakpointPromises);
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Finished attempting to set breakpoints. ${breakpointMap.size} breakpoints mapped.`);

            if (breakpointMap.size === 0) { throw new Error("Could not set any valid breakpoints for potential handlers."); }

            const messageDataStr = JSON.stringify(testMessageData);
            const escapedMessageDataStr = messageDataStr.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
            const expression = `setTimeout(() => { try { console.log('FrogPost DEBUG: Sending test message:', JSON.parse('${escapedMessageDataStr}'), 'to target', '${targetOrigin}'); window.postMessage(JSON.parse('${escapedMessageDataStr}'), '${targetOrigin}'); console.log('FrogPost DEBUG: Test message sent via setTimeout'); } catch(e) { console.error('FrogPost DEBUG: Error sending test message:', e); } }, 100);`;

            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Scheduling postMessage injection. TargetOrigin: ${targetOrigin}. Message: ${messageDataStr.substring(0,100)}... Expression: ${expression.substring(0,200)}...`);
            await chrome.debugger.sendCommand({ tabId }, "Runtime.evaluate", { expression: expression, awaitPromise: false, returnByValue: false });
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] postMessage injection scheduled.`);

            const waitTimeout = 8000;
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Waiting ${waitTimeout / 1000} seconds for breakpoint hits...`);
            await new Promise(resolve => setTimeout(resolve, waitTimeout));
            if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Timeout reached. Collected ${hitHandlerInfos.length} handlers that hit breakpoints.`);
            if (hitHandlerInfos.length > 0 && typeof log !== 'undefined') {
                log.debug(`[Breakpoint Exec] Details of hit handlers:`, hitHandlerInfos.map(h => ({
                    category: h.category,
                    source: h.source,
                    name: h.functionName,
                    line: h.handlerNode?.loc?.start?.line,
                    code: h.handler,
                })));
            }

            let finalConfirmedHandler = null;
            if (hitHandlerInfos.length === 1) {
                finalConfirmedHandler = hitHandlerInfos[0];
                if(typeof log !== 'undefined') log.success(`[Breakpoint Exec] Only one handler hit breakpoint. Selecting it: ${finalConfirmedHandler?.category} from ${finalConfirmedHandler?.source}`);
            } else if (hitHandlerInfos.length > 1) {
                if(typeof log !== 'undefined') log.info(`[Breakpoint Exec] Multiple handlers hit (${hitHandlerInfos.length}). Scoring them to select the best...`);
                hitHandlerInfos.forEach(h => { if (!h.handlerFlags) h.handlerFlags = {}; });
                finalConfirmedHandler = this.getBestHandler(hitHandlerInfos);
                if(finalConfirmedHandler && typeof log !== 'undefined') {
                    log.success(`[Breakpoint Exec] Selected best handler from ${hitHandlerInfos.length} hits based on score: ${finalConfirmedHandler?.category} from ${finalConfirmedHandler?.source} with score ${finalConfirmedHandler?.score}`);
                } else if (typeof log !== 'undefined') {
                    log.warn('[Breakpoint Exec] getBestHandler failed to select a handler from the hits.');
                }
            } else {
                if(typeof log !== 'undefined') log.warn(`[Breakpoint Exec] No handlers hit any set breakpoints within timeout.`);
            }

            if (finalConfirmedHandler) {
                if (!finalConfirmedHandler.handler && finalConfirmedHandler.fullScriptContent && finalConfirmedHandler.handlerNode) {
                    try { finalConfirmedHandler.handler = finalConfirmedHandler.fullScriptContent.substring(finalConfirmedHandler.handlerNode.start, finalConfirmedHandler.handlerNode.end); } catch {}
                }
                if (!finalConfirmedHandler.handler) {
                    if(typeof log !== 'undefined') log.error("[Breakpoint Exec] Final selected handler object missing handler code string! Invalidating selection.");
                    finalConfirmedHandler = null;
                } else {
                    finalConfirmedHandler.category = `breakpoint-scored-${finalConfirmedHandler.category || 'confirmed'}`;
                }
            }

            confirmedHandler = finalConfirmedHandler;

        } catch (error) {
            if(typeof log !== 'undefined') log.error('[Breakpoint Exec] Error during process:', error);
            confirmedHandler = null;
        } finally {
            if (tabId) {
                if (attached) {
                    if(typeof log !== 'undefined') log.debug(`[Breakpoint Exec] Cleaning up debugger for tab ${tabId}`);
                    try {
                        if (eventListener && chrome?.debugger?.onEvent) chrome.debugger.onEvent.removeListener(eventListener);
                        if (detachListener && chrome?.debugger?.onDetach) chrome.debugger.onDetach.removeListener(detachListener);
                        await chrome.debugger.sendCommand({ tabId }, "Debugger.disable").catch(e => log.warn('Error disabling debugger:', e.message));
                        await chrome.debugger.detach({ tabId });
                    } catch (detachError) { if(typeof log !== 'undefined') log.error('[Breakpoint Exec] Error during cleanup:', detachError?.message || detachError); }
                }
                try { await chrome.tabs.remove(tabId); }
                catch (removeError) { if(typeof log !== 'undefined') log.error(`[Breakpoint Exec] Error removing temp tab ${tabId}:`, removeError); }
            }
        }
        if(typeof log !== 'undefined') log.debug("[Breakpoint Exec] Returning from function. Final handler:", confirmedHandler ? {category: confirmedHandler.category, source: confirmedHandler.source, hasHandlerProp: !!confirmedHandler.handler, score: confirmedHandler.score} : null);
        return confirmedHandler;
    }

    async extractDynamicallyViaDebugger(targetUrl) {
        const handlers = new Set(); let tabId = null; let attached = false; let detachReason = null; const collectedScripts = new Map(); let analysisTimer = null; const ANALYSIS_TIMEOUT = 10000; const SETTLE_TIME = 1500; const LOAD_EXTRA_TIME = 2000; let resolveAnalysis; const analysisPromise = new Promise(res => { resolveAnalysis = res; }); let analysisResolved = false;
        const onDebuggerEvent = (source, method, params) => { if (!tabId || source.tabId !== tabId) return; if (method === 'Debugger.scriptParsed') { const { scriptId, url } = params; if (url && !url.startsWith('chrome-extension://') && url !== 'about:blank') { if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Script parsed: ID=${scriptId}, URL=${url.substring(0,100)}`); collectedScripts.set(scriptId, { url: url, scriptId: scriptId }); clearTimeout(analysisTimer); analysisTimer = setTimeout(() => { if (!analysisResolved) { if(typeof log !== 'undefined') log.debug('[Debugger Tab] Script parsing settled.'); analysisResolved = true; resolveAnalysis(); } }, SETTLE_TIME); } } else if (method === 'Page.loadEventFired') { if(typeof log !== 'undefined') log.debug('[Debugger Tab] Page load event fired.'); clearTimeout(analysisTimer); analysisTimer = setTimeout(() => { if (!analysisResolved) { if(typeof log !== 'undefined') log.debug('[Debugger Tab] Page loaded + settle time.'); analysisResolved = true; resolveAnalysis(); } }, LOAD_EXTRA_TIME); } else if (method === 'Runtime.exceptionThrown') { if(typeof log !== 'undefined') log.warn('[Debugger Tab] Exception in target:', params.exceptionDetails?.exception?.description || 'Unknown error'); } };
        const onDebuggerDetach = (source, reason) => { if (source.tabId === tabId) { if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Detached unexpectedly from tab ${tabId}. Reason: ${reason}`); attached = false; detachReason = reason; if (chrome?.debugger) { try { chrome.debugger.onEvent.removeListener(onDebuggerEvent); } catch(e){} try { chrome.debugger.onDetach.removeListener(onDebuggerDetach); } catch(e){} } if (!analysisResolved) { analysisResolved = true; resolveAnalysis(); } } };
        try {
            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Creating temporary background tab for:', targetUrl);
            const tab = await chrome.tabs.create({ url: targetUrl, active: false }); tabId = tab.id; if (!tabId) throw new Error("Failed to create target tab."); if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Created target tab ID: ${tabId}`); await new Promise(res => setTimeout(res, 1500));
            await chrome.debugger.attach({ tabId }, "1.3"); attached = true; if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attached to target tab: ${tabId}`);
            chrome.debugger.onEvent.addListener(onDebuggerEvent); chrome.debugger.onDetach.addListener(onDebuggerDetach);
            await Promise.all([ chrome.debugger.sendCommand({ tabId }, "Page.enable"), chrome.debugger.sendCommand({ tabId }, "Runtime.enable"), chrome.debugger.sendCommand({ tabId }, "Debugger.enable") ]); if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Enabled domains.`);
            const overallTimeout = setTimeout(() => { if (!analysisResolved) { if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Overall analysis timeout reached.`); analysisResolved = true; resolveAnalysis(); } }, ANALYSIS_TIMEOUT);
            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Waiting for script parsing to settle...'); await analysisPromise; clearTimeout(overallTimeout);
            if (!attached) throw new Error(`Debugger detached unexpectedly. Reason: ${detachReason || 'Unknown'}`); if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Proceeding to fetch ${collectedScripts.size} script sources.`);
            const sourcePromises = Array.from(collectedScripts.keys()).map(scriptId => chrome.debugger.sendCommand({ tabId }, "Debugger.getScriptSource", { scriptId }).then(result => ({ scriptId, source: result.scriptSource })).catch(err => { if(typeof log !== 'undefined') log.warn(`[Debugger Tab] Failed to get source for scriptId ${scriptId}:`, err?.message || err); return { scriptId, source: null }; }));
            const sources = await Promise.all(sourcePromises);
            if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Analyzing ${sources.filter(s => s.source).length} fetched script sources.`);
            for (const { scriptId, source } of sources) { if (source) { const scriptInfo = collectedScripts.get(scriptId); const sourceUrl = scriptInfo?.url || `tab_${tabId}_scriptId_${scriptId}`; const scriptHandlers = this.analyzeScriptContent(source, sourceUrl); scriptHandlers.forEach(handlerInfo => handlers.add(handlerInfo)); } }
        } catch (error) { if(typeof log !== 'undefined') log.error('[Debugger Tab] Error during dynamic extraction process:', error); throw new Error(`Debugger analysis failed: ${error.message}`); }
        finally {
            if(typeof log !== 'undefined') log.debug('[Debugger Tab] Entering finally block for cleanup.'); clearTimeout(analysisTimer);
            if (attached && tabId) { if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attempting to detach from tab: ${tabId}`); try { if (chrome?.debugger) { if (chrome.debugger.onEvent?.removeListener) chrome.debugger.onEvent.removeListener(onDebuggerEvent); if (chrome.debugger.onDetach?.removeListener) chrome.debugger.onDetach.removeListener(onDebuggerDetach); if (chrome.debugger.detach) await chrome.debugger.detach({ tabId }); if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Detached successfully from tab: ${tabId}`); } else { if(typeof log !== 'undefined') log.warn('[Debugger Tab] chrome.debugger API unavailable for detach.'); } } catch (detachError) { if(typeof log !== 'undefined') log.error('[Debugger Tab] Error detaching:', detachError?.message || detachError); } }
            else { if(typeof log !== 'undefined') log.debug('[Debugger Tab] Skipping detach (not attached or no tabId).'); }
            if (tabId) { if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Attempting to remove temporary tab: ${tabId}`); try { await chrome.tabs.remove(tabId); if(typeof log !== 'undefined') log.debug(`[Debugger Tab] Removed temporary tab: ${tabId}`); } catch (removeError) { if(typeof log !== 'undefined') log.error(`[Debugger Tab] Error removing temporary tab ${tabId}:`, removeError); } }
        }
        if(typeof log !== 'undefined') log.success(`[Debugger Tab] Dynamic extraction finished. Found ${handlers.size} potential handler structures.`);
        return Array.from(handlers);
    }
}

