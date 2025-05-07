/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-05-07
 */
(function(global) {

    if (typeof global.acorn === 'undefined' ||
        typeof global.acorn.parse !== 'function' ||
        typeof global.acorn.walk?.ancestor !== 'function' ||
        !global.acorn.walk.base) {
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn or Acorn-walk variant not fully found/initialized.', analysis: null });
        return;
    }

    const getSafeAcornWalkBase = () => {
        const originalBase = global.acorn.walk.base || {};
        const patchedBase = Object.create(originalBase);
        let knownMissingTypesLogged = new Set();

        const ensureVisitor = (typeName, visitorFunc) => {
            if (!(typeName in originalBase)) {
                patchedBase[typeName] = visitorFunc;
                if (typeof log !== 'undefined' && log.debug) {
                    log.debug(`[SafeWalkBase] Added explicit stub for potentially missing base visitor: ${typeName}`);
                }
            }
        };

        ensureVisitor("PropertyDefinition", (node, st, c) => {
            if (node.key) c(node.key, st);
            if (node.value) c(node.value, st);
        });
        ensureVisitor("PrivateIdentifier", (node, st, c) => {});
        ensureVisitor("StaticBlock", (node, st, c) => {
            for (const stmt of node.body) c(stmt, st, "Statement");
        });
        ensureVisitor("ChainExpression", (node, st, c) => { c(node.expression, st); });
        ensureVisitor("ImportExpression", (node, st, c) => {
            c(node.source, st);
            if (node.options) c(node.options, st);
        });
        ensureVisitor("Super", (node, st, c) => {});
        ensureVisitor("MetaProperty", (node, st, c) => {});

        return new Proxy(patchedBase, {
            get: (target, typeName, receiver) => {
                if (typeName in target) {
                    return target[typeName];
                }
                if (typeof typeName === 'string' && /^[A-Z]/.test(typeName)) {
                    if (!knownMissingTypesLogged.has(typeName)) {
                        if (typeof log !== 'undefined' && log.warn) {
                            log.warn(`[SafeWalkBase] Dynamically providing NOP base visitor for unknown AST node type: "${String(typeName)}". Analysis for this node structure might be incomplete.`);
                        }
                        knownMissingTypesLogged.add(typeName);
                    }
                    return (node, st, c) => {};
                }
                return Reflect.get(target, typeName, receiver);
            }
        });
    };

    let safeWalkBaseInstance = null;
    try {
        safeWalkBaseInstance = getSafeAcornWalkBase();
    } catch (e) {
        if (typeof log !== 'undefined' && log.error) {
            log.error("[Static Analyzer] Critical error creating safe walk base:", e);
        }
        safeWalkBaseInstance = global.acorn.walk.base;
    }

    const STANDARD_EVENT_NAMES = /^(event|e|msg|message|evt|data|payload|p|d|m|evtData|msgData)$/;
    const ORIGIN_PROP = 'origin';
    const DATA_PROP = 'data';
    const SOURCE_PROP = 'source';
    const WEAK_ORIGIN_METHODS = ['indexOf', 'includes', 'startsWith', 'endsWith', 'match', 'search', 'test'];
    const WRAPPER_PREFIX = 'const __dummyFunc = ';

    function getCodeSnippet(node, originalSourceWithWrapper) {
        if (!node || !node.range || typeof originalSourceWithWrapper !== 'string') return '[Snippet Error: Invalid Input]';
        try {
            const startOffset = WRAPPER_PREFIX.length;
            let start = node.range[0]; let end = node.range[1];
            start = Math.max(start, startOffset); end = Math.min(end, originalSourceWithWrapper.length); start = Math.min(start, end);
            const snippet = originalSourceWithWrapper.substring(start, end);
            const displaySnippet = snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
            return displaySnippet || '[Snippet Error: Empty Result]';
        } catch (e) { return '[Snippet Error: Exception]'; }
    }

    function getFullAccessPath(node) {
        let current = node; const path = []; let depth = 0;
        while (current && depth < 20) {
            depth++;
            if (current.type === 'MemberExpression') { if (current.property.type === 'Identifier') path.unshift(current.property.name); else if (current.property.type === 'Literal') path.unshift(String(current.property.value)); else if (current.property.type === 'ThisExpression') path.unshift('this'); else if (current.property.type === 'CallExpression') path.unshift('[call()]'); else path.unshift(`[${current.property.type}]`); current = current.object; }
            else if (current.type === 'Identifier') { path.unshift(current.name); current = null; }
            else if (current.type === 'ThisExpression') { path.unshift('this'); current = null; }
            else if (current.type === 'CallExpression') { if (current.callee.type === 'Identifier') path.unshift(current.callee.name + '()'); else if (current.callee.type === 'MemberExpression') path.unshift(getFullAccessPath(current.callee) + '()'); else path.unshift('[call()]'); current = null; }
            else { path.unshift(`[${current.type}]`); current = null; }
        }
        return path.join('.');
    }

    function isDirectEventPropertyAccess(node, propertyName, eventParamName) {
        if (!eventParamName || !node) return false;
        return node.type === 'MemberExpression' && node.object.type === 'Identifier' && node.object.name === eventParamName && node.property.type === 'Identifier' && node.property.name === propertyName;
    }

    function deriveRelativePath(fullPath, eventParamName, aliasMap) {
        if (!fullPath || !eventParamName) return null;
        const eventDataPrefix = `${eventParamName}.${DATA_PROP}.`;
        const eventPrefix = `${eventParamName}.`;
        if (fullPath === `${eventParamName}.${DATA_PROP}`) { return '(root_data)'; }
        else if (fullPath.startsWith(eventDataPrefix)) { const rel = fullPath.substring(eventDataPrefix.length); return rel || '(root_data)'; }
        else if (fullPath.startsWith(eventPrefix)) { return null; }
        else {
            const parts = fullPath.split('.'); const baseName = parts[0];
            if (baseName) {
                const aliasSource = aliasMap.get(baseName);
                if (aliasSource === `${eventParamName}.${DATA_PROP}`) { const rel = parts.slice(1).join('.'); return rel || '(root_data)'; }
                else if (aliasSource?.startsWith('JSON.parse')) { const rel = parts.slice(1).join('.'); return rel || '(parsed_root)'; }
                else if (aliasSource === eventParamName) { return null; }
            }
        }
        return null;
    }

    function isEventDataAccess(node, eventParamName, aliasMap, taintMap, depth = 0) {
        const MAX_RECURSION_DEPTH = 10;
        if (depth > MAX_RECURSION_DEPTH) { return { tainted: false, path: null, relativePath: null, source: null }; }
        if (!node || !eventParamName) return { tainted: false, path: null, relativePath: null, source: null };
        const fullPath = getFullAccessPath(node);
        if (depth === 0 && typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Start] Check: ${fullPath} (Type: ${node.type}, Param: ${eventParamName})`);
        if(taintMap.has(fullPath)) { const directTaint = taintMap.get(fullPath); if(directTaint.tainted) { const result = { ...directTaint, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Direct Taint Found: ${fullPath}`, result); return result; } }
        if (node.type === 'Identifier') { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] Identifier: ${node.name}`); if (node.name === eventParamName) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Matched Param`); return { tainted: true, path: fullPath, relativePath: null, source: eventParamName }; } const aliasSource = aliasMap.get(node.name); if (aliasSource === `${eventParamName}.${DATA_PROP}`) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Matched Alias(event.data)`); return { tainted: true, path: fullPath, relativePath: '(root_data)', source: aliasSource }; } if (aliasSource === eventParamName) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Matched Alias(event)`); return { tainted: true, path: fullPath, relativePath: null, source: aliasSource }; } if (aliasSource && aliasSource.startsWith('JSON.parse')) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Matched Alias(JSON.parse)`); return { tainted: true, path: fullPath, relativePath: '(parsed_root)', source: aliasSource }; } if (taintMap.has(node.name)) { const taintInfo = taintMap.get(node.name); if (taintInfo.tainted) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Matched TaintMap`); const relPathFromTaint = deriveRelativePath(fullPath, eventParamName, aliasMap); return { tainted: true, path: fullPath, relativePath: relPathFromTaint, source: taintInfo.path }; } } if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> Identifier Untainted`); return { tainted: false, path: fullPath, relativePath: null, source: null }; }
        if (node.type === 'MemberExpression') { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] MemberExpr: ${fullPath}. Checking object...`); const objCheck = isEventDataAccess(node.object, eventParamName, aliasMap, taintMap, depth + 1); if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] MemberExpr object check result for ${fullPath}:`, objCheck); if (objCheck.tainted) { const propertyName = node.property.type === 'Identifier' ? node.property.name : (node.property.type === 'Literal' ? String(node.property.value) : null); let derivedRelPath = null; if (propertyName !== null) { const isObjectEventData = (node.object.type === 'MemberExpression' && node.object.object?.name === eventParamName && node.object.property?.name === DATA_PROP) || (node.object.type === 'Identifier' && aliasMap.get(node.object.name) === `${eventParamName}.${DATA_PROP}`); if (isObjectEventData || objCheck.relativePath === '(root_data)') { derivedRelPath = propertyName; } else if (objCheck.relativePath && objCheck.relativePath !== '(parsed_root)' && objCheck.relativePath !== null) { derivedRelPath = `${objCheck.relativePath}.${propertyName}`; } else if (objCheck.relativePath === '(parsed_root)') { derivedRelPath = propertyName; } } if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> MemberExpr TAINTED. Path: ${fullPath}, RelPath: ${derivedRelPath}, Source: ${objCheck.path}`); return { tainted: true, path: fullPath, relativePath: derivedRelPath, source: objCheck.path }; } }
        else if (node.type === 'CallExpression') { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] Checking CallExpr: ${fullPath}`); const calleeCheck = isEventDataAccess(node.callee, eventParamName, aliasMap, taintMap, depth + 1); if (calleeCheck.tainted) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> CallExpr Callee TAINTED`); return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap), source: calleeCheck.path }; } if (node.arguments) { for (const arg of node.arguments) { const argCheck = isEventDataAccess(arg, eventParamName, aliasMap, taintMap, depth + 1); if (argCheck.tainted) { if(typeof log !== 'undefined' && log.debug) log.debug(`[isEDA Depth ${depth}] -> CallExpr Argument TAINTED`); return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap), source: argCheck.path }; } } } }
        if (depth === 0 && typeof log !== 'undefined' && log.debug) log.debug(`[isEDA End] No taint found for ${fullPath}`); return { tainted: false, path: fullPath, relativePath: null, source: null };
    }

    function analyzeOriginCheck(node, eventParamName, aliasMap, originalSourceWithWrapper) { const checkInfo = { isCheck: false, type: 'unknown', comparedValue: null, comparedValueType: 'unknown', methodName: null, strength: 'None', negated: false, rawSnippet: null, node: node }; const getStrength = (value, methodName = null, operator = null) => { if (methodName && WEAK_ORIGIN_METHODS.includes(methodName)) return 'Weak'; if (typeof value === 'string') { if (value === '*' || value === 'null') return 'Weak'; try { const url = new URL(value); if (url.protocol === 'http:' || url.protocol === 'https:') return 'Strong'; } catch(e) {} return 'Medium'; } if (operator === '==' || operator === '!=') return 'Medium'; if (value !== null && value !== undefined) return 'Medium'; return 'Weak'; }; const isNodeEventOrigin = (n) => { if (!n) return false; if (eventParamName) { if (isDirectEventPropertyAccess(n, ORIGIN_PROP, eventParamName)) return true; if (n?.type === 'Identifier' && aliasMap.get(n.name) === `${eventParamName}.${ORIGIN_PROP}`) return true; if (n?.type === 'MemberExpression' && n.property?.name === ORIGIN_PROP && n.object?.type === 'Identifier' && aliasMap.get(n.object.name) === eventParamName) return true; } if (n.type === 'MemberExpression' && n.object.type === 'Identifier' && n.object.name === 'event' && n.property.type === 'Identifier' && n.property.name === ORIGIN_PROP) return true; return false; }; let checkNode = node; let topLevelNodeForSnippet = node; let isNegatedExplicitly = false; if (node.type === 'UnaryExpression' && node.operator === '!') { isNegatedExplicitly = true; checkNode = node.argument; topLevelNodeForSnippet = node; } else if (node.type === 'IfStatement' || node.type === 'ConditionalExpression') { return analyzeOriginCheck(node.test, eventParamName, aliasMap, originalSourceWithWrapper); } else if (node.type === 'LogicalExpression') { const leftCheck = analyzeOriginCheck(node.left, eventParamName, aliasMap, originalSourceWithWrapper); if (leftCheck.isCheck) return leftCheck; const rightCheck = analyzeOriginCheck(node.right, eventParamName, aliasMap, originalSourceWithWrapper); if (rightCheck.isCheck) return rightCheck; return checkInfo; } checkInfo.negated = isNegatedExplicitly; checkInfo.rawSnippet = getCodeSnippet(topLevelNodeForSnippet, originalSourceWithWrapper); if (checkNode.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(checkNode.operator)) { let originNode = null; let otherNode = null; if (isNodeEventOrigin(checkNode.left)) { originNode = checkNode.left; otherNode = checkNode.right; } else if (isNodeEventOrigin(checkNode.right)) { originNode = checkNode.right; otherNode = checkNode.left; } if (originNode) { checkInfo.isCheck = true; checkInfo.type = (checkNode.operator === '===' || checkNode.operator === '!==') ? 'Strict Equality' : 'Loose Equality'; checkInfo.negated = checkInfo.negated || checkNode.operator === '!==' || checkNode.operator === '!='; checkInfo.comparedValueType = otherNode.type; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); if (otherNode.type === 'Literal') { checkInfo.comparedValue = otherNode.value; checkInfo.strength = getStrength(otherNode.value, null, checkNode.operator); } else if (otherNode.type === 'Identifier') { checkInfo.comparedValue = otherNode.name; checkInfo.strength = 'Medium'; } else { checkInfo.comparedValue = getCodeSnippet(otherNode, originalSourceWithWrapper); checkInfo.strength = 'Medium'; } return checkInfo; } } else if (checkNode.type === 'CallExpression') { const callee = checkNode.callee; if (callee.type === 'MemberExpression') { if (isNodeEventOrigin(callee.object)) { checkInfo.methodName = callee.property.name; if (WEAK_ORIGIN_METHODS.includes(checkInfo.methodName) && checkNode.arguments.length > 0) { checkInfo.isCheck = true; checkInfo.type = `Method Call (${checkInfo.methodName})`; checkInfo.strength = 'Weak'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); const argNode = checkNode.arguments[0]; checkInfo.comparedValueType = argNode.type; if (argNode.type === 'Literal') { checkInfo.comparedValue = argNode.value; } else if (argNode.type === 'Identifier') { checkInfo.comparedValue = argNode.name; } else { checkInfo.comparedValue = getCodeSnippet(argNode, originalSourceWithWrapper); } return checkInfo; } } else if (checkNode.arguments.some(arg => isNodeEventOrigin(arg))) { if (callee.type === 'MemberExpression' && callee.property.name === 'test' && callee.object.type === 'Literal' && callee.object.regex) { checkInfo.isCheck = true; checkInfo.type = 'Regex Test'; checkInfo.methodName = 'test'; checkInfo.comparedValue = callee.object.regex.pattern; checkInfo.comparedValueType = 'RegExp'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); const pattern = callee.object.regex.pattern; if (!pattern.startsWith('^') || !pattern.endsWith('$') || pattern.includes('.*') || pattern.includes('.+')) checkInfo.strength = 'Medium'; else if (pattern.includes('http')) checkInfo.strength = 'Strong'; else checkInfo.strength = 'Medium'; return checkInfo; } else { checkInfo.isCheck = true; checkInfo.type = 'Function Call'; checkInfo.methodName = getFullAccessPath(callee); checkInfo.strength = 'Unknown'; checkInfo.comparedValue = `Args: ${checkNode.arguments.length}`; checkInfo.comparedValueType = 'Arguments'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); return checkInfo; } } } } else if (isNodeEventOrigin(checkNode)) { checkInfo.isCheck = true; checkInfo.type = 'Existence Check'; checkInfo.strength = 'Weak'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); return checkInfo; } return checkInfo; }
    function findConditionsForNode(testNode, eventParamName, aliasMap, taintMap) { const conditions = []; const MAX_DEPTH = 5; function extract(node, depth) { if (!node || depth >= MAX_DEPTH) return; if (node.type === 'LogicalExpression' && node.operator === '&&') { extract(node.left, depth + 1); extract(node.right, depth + 1); } else if (node.type === 'BinaryExpression' && ['===', '=='].includes(node.operator)) { let dataAccessNode = null; let literalNode = null; let dataCheckLeft = isEventDataAccess(node.left, eventParamName, aliasMap, taintMap); let dataCheckRight = isEventDataAccess(node.right, eventParamName, aliasMap, taintMap); if (dataCheckLeft.tainted && dataCheckLeft.relativePath && node.right.type === 'Literal') { dataAccessNode = node.left; literalNode = node.right; } else if (dataCheckRight.tainted && dataCheckRight.relativePath && node.left.type === 'Literal') { dataAccessNode = node.right; literalNode = node.left; } if (dataAccessNode && literalNode && (typeof literalNode.value === 'string' || typeof literalNode.value === 'number' || typeof literalNode.value === 'boolean')) { const { relativePath } = isEventDataAccess(dataAccessNode, eventParamName, aliasMap, taintMap); if (relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { conditions.push({ path: relativePath, op: node.operator, value: literalNode.value }); } } } else if (node.type === 'MemberExpression' || node.type === 'Identifier') { const { tainted, relativePath } = isEventDataAccess(node, eventParamName, aliasMap, taintMap); if (tainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { conditions.push({ path: relativePath, op: 'truthy', value: true }); } } } extract(testNode, 0); return conditions; }

    function isLocallyDefined(identifierName, ancestorsArg) { // Changed parameter name
        if (!ancestorsArg) return false;
        for (let i = ancestorsArg.length - 1; i >= 0; i--) {
            const scopeNode = ancestorsArg[i];
            if (scopeNode.type === 'FunctionExpression' || scopeNode.type === 'FunctionDeclaration' || scopeNode.type === 'ArrowFunctionExpression') {
                if (scopeNode.id && scopeNode.id.type === 'Identifier' && scopeNode.id.name === identifierName) return true;
                if (scopeNode.params.some(p => {
                    if (p.type === 'Identifier') return p.name === identifierName;
                    if (p.type === 'AssignmentPattern' && p.left.type === 'Identifier') return p.left.name === identifierName;
                    if (p.type === 'RestElement' && p.argument.type === 'Identifier') return p.argument.name === identifierName;
                    return false;
                })) return true;
            }
            if (scopeNode.type === 'BlockStatement' || scopeNode.type === 'StaticBlock') {
                if (scopeNode.body) {
                    for (const stmt of scopeNode.body) {
                        if (stmt.type === 'VariableDeclaration') {
                            if (stmt.declarations.some(d => d.id.type === 'Identifier' && d.id.name === identifierName)) return true;
                        } else if (stmt.type === 'FunctionDeclaration' && stmt.id && stmt.id.name === identifierName) {
                            return true;
                        } else if (stmt.type === 'ClassDeclaration' && stmt.id && stmt.id.name === identifierName) {
                            return true;
                        }
                    }
                }
            }
            if (scopeNode.type === 'ForStatement' || scopeNode.type === 'ForInStatement' || scopeNode.type === 'ForOfStatement') {
                if (scopeNode.init && scopeNode.init.type === 'VariableDeclaration') {
                    if (scopeNode.init.declarations.some(d => d.id.type === 'Identifier' && d.id.name === identifierName)) return true;
                }
            }
            if (scopeNode.type === 'CatchClause' && scopeNode.param && scopeNode.param.type === 'Identifier' && scopeNode.param.name === identifierName) {
                return true;
            }
        }
        return false;
    }

    function recordSink(sinkDefinition, sinkNode, ancestorsArg, taintedInput, stateArg, collectedSinks) { // Changed parameter names
        log.debug(`[recordSink] Called for sink '${sinkDefinition.name}' with input path '${taintedInput.path}' (full node type: ${sinkNode.type})`);
        const { path: fullInputPath, relativePath } = taintedInput;
        let actualRelativePath = relativePath;
        if(relativePath === '(root_data)' || relativePath === '(parsed_root)') {
            actualRelativePath = '(root)';
        } else if (!relativePath) {
            actualRelativePath = '(Tainted non-data property)';
        }

        let conditions = [];
        let ifStmtNode = null;

        if (ancestorsArg && ancestorsArg.length > 1) {
            const parentChainTypes = [];
            for (let i = ancestorsArg.length - 2; i >= 0; i--) { // Corrected loop for ancestorsArg
                const ancestorNode = ancestorsArg[i];
                parentChainTypes.push(ancestorNode.type);
                if (ancestorNode.type === 'IfStatement') {
                    ifStmtNode = ancestorNode;
                    log.debug(`[recordSink] Found IfStatement ancestor for sink '${sinkDefinition.name}'. Chain: ${parentChainTypes.join(' -> ')}`);
                    break;
                }
                if (ancestorNode.type === 'FunctionExpression' || ancestorNode.type === 'FunctionDeclaration' || ancestorNode.type === 'ArrowFunctionExpression') {
                    log.debug(`[recordSink] Hit function boundary in ancestors before finding IfStatement for sink '${sinkDefinition.name}'. Chain: ${parentChainTypes.join(' -> ')}`);
                    break;
                }
            }
            if(!ifStmtNode && typeof log !== 'undefined' && log.debug) log.debug(`[recordSink] No IfStatement found in ancestors. Chain searched: ${parentChainTypes.join(' -> ')}`);
        } else {
            log.warn(`[recordSink] No or insufficient ancestors provided for sink '${sinkDefinition.name}'. Cannot find IfStatement for conditions.`);
        }

        const tempSnippetForLog = getCodeSnippet(sinkNode, stateArg.originalSource);

        if(ifStmtNode && ifStmtNode.test) {
            if(typeof log !== 'undefined' && log.debug) log.debug(`[recordSink] Analyzing conditions for IfStatement (test type: ${ifStmtNode.test?.type}) for sink '${sinkDefinition.name}' (snippet: "${tempSnippetForLog}")`);
            conditions = findConditionsForNode(ifStmtNode.test, stateArg.eventParamName, stateArg.aliasMap, stateArg.taintMap);
            if(typeof log !== 'undefined' && log.debug) log.debug(`[recordSink] Conditions extracted:`, JSON.stringify(conditions));
        } else {
            if(typeof log !== 'undefined' && log.debug) log.debug(`[recordSink] No IfStatement parent found/used or no test node for sink '${sinkDefinition.name}' (snippet: "${tempSnippetForLog}")`);
        }

        const sinkNodeForEntry = {type: sinkNode.type, start: sinkNode.start, end: sinkNode.end };
        if (sinkNode.loc) sinkNodeForEntry.loc = sinkNode.loc;
        if (sinkNode.range) sinkNodeForEntry.range = sinkNode.range;


        const sinkEntry = {
            name: sinkDefinition.name,
            severity: sinkDefinition.severity,
            category: sinkDefinition.category,
            node: sinkNodeForEntry,
            snippet: tempSnippetForLog,
            fullInputPath: fullInputPath,
            sourcePath: actualRelativePath,
            conditions: conditions
        };

        try {
            const jsonSinkEntryForLog = JSON.stringify(sinkEntry);
            log.debug(`[recordSink] >>> Adding sink entry to collectedSinks:`, jsonSinkEntryForLog);
        } catch (e) {
            log.error(`[recordSink] Error stringifying sinkEntry for logging: ${e.message}. Entry name: ${sinkEntry.name}`);
            log.debug(`[recordSink] Adding sink entry (omitting node for log):`, { ...sinkEntry, node: `[Node type: ${sinkNode.type}, Range: ${sinkNode.start}-${sinkNode.end}]`});
        }

        collectedSinks.push(sinkEntry);
        log.debug(`[recordSink] collectedSinks length after push: ${collectedSinks.length}`);

        if (actualRelativePath && actualRelativePath !== '(Tainted non-data property)' && actualRelativePath !== '(root)') {
            log.debug(`[recordSink] Recording path/conditions for relative path: ${actualRelativePath}`);
            if (!stateArg.analysis.requiredConditions[actualRelativePath]) {
                stateArg.analysis.requiredConditions[actualRelativePath] = { conditions: [], sinks: [] };
            }
            const reqCondEntry = stateArg.analysis.requiredConditions[actualRelativePath];
            conditions.forEach(cond => {
                if (!reqCondEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(cond))) {
                    reqCondEntry.conditions.push(cond);
                }
            });
            if (!reqCondEntry.sinks.includes(sinkDefinition.name)) {
                reqCondEntry.sinks.push(sinkDefinition.name);
            }
            stateArg.analysis.accessedEventDataPaths.add(actualRelativePath);
            conditions.forEach(cond => stateArg.analysis.accessedEventDataPaths.add(cond.path));
        } else {
            log.debug(`[recordSink] Skipping path/condition recording for non-specific or root path: ${actualRelativePath}`);
        }
    }

    global.analyzeHandlerStatically = function(handlerCode, endpoint = '', sinkPatterns = [], context = {}) {
        const analysis = { identifiedEventParam: null, potentialSinks: [], originChecks: [], securityIssues: [], accessedEventDataPaths: new Set(), requiredConditions: {}, externalStateAccesses: [], indirectCalls: [] };
        let ast = null; const sourceCodeWithWrapper = WRAPPER_PREFIX + handlerCode; const sourceCodeWithoutWrapper = handlerCode; const allOriginChecksFound = [];
        const usedSinkPatterns = Array.isArray(sinkPatterns) ? sinkPatterns : [];
        const collectedSinksDuringWalk = [];

        if(typeof log === 'undefined') { global.log = { debug: console.debug, info: console.info, warn: console.warn, error: console.error }; }
        if(typeof log !== 'undefined' && log.debug) log.debug("[Static Analyzer] Using sink patterns:", usedSinkPatterns.map(s => s.name));

        try {
            ast = global.acorn.parse(sourceCodeWithWrapper, { ecmaVersion: 2022, locations: true, ranges: true, allowReturnOutsideFunction: true });
            if (typeof log !== 'undefined' && log.debug) log.debug("[Static Analyzer] Successfully parsed with ecmaVersion: 2022");
        } catch (e) {
            log.warn(`[Static Analyzer] AST Parsing with ecmaVersion 2022 failed: ${e.message}. Falling back to 'latest'.`);
            try {
                ast = global.acorn.parse(sourceCodeWithWrapper, { ecmaVersion: 'latest', locations: true, ranges: true, allowReturnOutsideFunction: true });
                if (typeof log !== 'undefined' && log.debug) log.debug("[Static Analyzer] Successfully parsed with ecmaVersion: 'latest' after 2022 failed.");
            } catch (e2) {
                log.error(`[Static Analyzer] AST Parsing Error (tried 2022 and latest): ${e2.message}`, e2);
                return { success: false, error: `AST Parsing Error (tried 2022 and latest): ${e2.message}`, analysis: null };
            }
        }

        let identifiedParams = []; let paramUsageCounts = {}; const topLevelFuncNode = ast.body[0]?.declarations[0]?.init;
        if (topLevelFuncNode && (topLevelFuncNode.type === 'FunctionExpression' || topLevelFuncNode.type === 'ArrowFunctionExpression')) { identifiedParams = topLevelFuncNode.params.filter(p => p.type === 'Identifier').map(p => p.name); identifiedParams.forEach(p => paramUsageCounts[p] = { data: 0, origin: 0, source: 0, total: 0 }); try { global.acorn.walk.simple(topLevelFuncNode.body, { MemberExpression(node) { if (node.object.type === 'Identifier' && identifiedParams.includes(node.object.name)) { paramUsageCounts[node.object.name].total++; if (node.property.type === 'Identifier') { if (node.property.name === DATA_PROP) paramUsageCounts[node.object.name].data++; else if (node.property.name === ORIGIN_PROP) paramUsageCounts[node.object.name].origin++; else if (node.property.name === SOURCE_PROP) paramUsageCounts[node.object.name].source++; } } } }); } catch(walkError){} }
        let localEventParamName = null; if (identifiedParams.length > 0) { let bestParam = identifiedParams[0]; let maxScore = -1; identifiedParams.forEach(p => { let score = (paramUsageCounts[p].data * 3) + (paramUsageCounts[p].origin * 2) + (paramUsageCounts[p].source * 1) + (paramUsageCounts[p].total * 0.1); if (STANDARD_EVENT_NAMES.test(p)) score += 5; if (score > maxScore) { maxScore = score; bestParam = p; } }); localEventParamName = bestParam; } else { localEventParamName = 'event';}
        analysis.identifiedEventParam = localEventParamName;
        const initialTaintMap = new Map([[localEventParamName, { tainted: true, path: localEventParamName }]]);

        const stateObj = { // Renamed from 'state' to 'stateObj' to avoid conflict with visitor param
            eventParamName: localEventParamName,
            aliasMap: new Map(),
            taintMap: initialTaintMap,
            analysis: analysis,
            handlerCode: sourceCodeWithoutWrapper,
            originalSource: sourceCodeWithWrapper,
            funcBodyAstNode: null
        };

        try {
            const funcBody = ast.body[0]?.declarations[0]?.init?.body;
            if (!funcBody) throw new Error("Could not find function body in AST");
            stateObj.funcBodyAstNode = funcBody;

            const analysisVisitors = {
                VariableDeclarator: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA VariableDeclarator] state or state.analysis is undefined!"); return; }
                    if (node.init) {
                        const varName = node.id.name; let isJsonParseAlias = false;
                        if (isDirectEventPropertyAccess(node.init, ORIGIN_PROP, state.eventParamName)) state.aliasMap.set(varName, `${state.eventParamName}.${ORIGIN_PROP}`);
                        else if (isDirectEventPropertyAccess(node.init, DATA_PROP, state.eventParamName)) state.aliasMap.set(varName, `${state.eventParamName}.${DATA_PROP}`);
                        else if (node.init.type === 'Identifier' && node.init.name === state.eventParamName) state.aliasMap.set(varName, state.eventParamName);
                        else if (node.init.type === 'CallExpression' && node.init.callee.type === 'MemberExpression' && node.init.callee.object?.name === 'JSON' && node.init.callee.property?.name === 'parse' && node.init.arguments?.length > 0) {
                            const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.init.arguments[0], state.eventParamName, state.aliasMap, state.taintMap);
                            if (inputTainted) { state.aliasMap.set(varName, `JSON.parse(...)`); state.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.init.arguments[0])})` }); state.analysis.accessedEventDataPaths.add('(parsed_root)'); isJsonParseAlias = true; }
                        }
                        const { tainted: rhsTainted, path: rhsPath, source: rhsSource } = isEventDataAccess(node.init, state.eventParamName, state.aliasMap, state.taintMap);
                        if (rhsTainted && !isJsonParseAlias) { state.taintMap.set(varName, { tainted: true, path: rhsPath || getFullAccessPath(node.init), source: rhsSource }); }
                        else if (!isJsonParseAlias) { state.taintMap.set(varName, { tainted: false, path: null, source: null }); }
                    }
                },
                AssignmentExpression: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA AssignmentExpression] state or state.analysis is undefined!"); return; }
                    let isJsonParseAlias = false;
                    if (node.left?.type === 'Identifier' && node.right) {
                        const varName = node.left.name;
                        if (isDirectEventPropertyAccess(node.right, ORIGIN_PROP, state.eventParamName)) state.aliasMap.set(varName, `${state.eventParamName}.${ORIGIN_PROP}`);
                        else if (isDirectEventPropertyAccess(node.right, DATA_PROP, state.eventParamName)) state.aliasMap.set(varName, `${state.eventParamName}.${DATA_PROP}`);
                        else if (node.right.type === 'Identifier' && node.right.name === state.eventParamName) state.aliasMap.set(varName, state.eventParamName);
                        else if (node.right.type === 'CallExpression' && node.right.callee.type === 'MemberExpression' && node.right.callee.object?.name === 'JSON' && node.right.callee.property?.name === 'parse' && node.right.arguments?.length > 0) {
                            const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.right.arguments[0], state.eventParamName, state.aliasMap, state.taintMap);
                            if (inputTainted) { isJsonParseAlias = true; state.aliasMap.set(varName, `JSON.parse(...)`); state.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.right.arguments[0])})` }); state.analysis.accessedEventDataPaths.add('(parsed_root)'); }
                        }
                    }
                    const { tainted: rhsTainted, path: rhsPath, source: rhsSource } = isEventDataAccess(node.right, state.eventParamName, state.aliasMap, state.taintMap);
                    if (node.left.type === 'Identifier') {
                        const varName = node.left.name;
                        if (rhsTainted && !isJsonParseAlias) { state.taintMap.set(varName, { tainted: true, path: rhsPath || getFullAccessPath(node.right), source: rhsSource }); }
                        else if (!isJsonParseAlias) { const existing = state.taintMap.get(varName); if(!existing || !existing.tainted) state.taintMap.set(varName, { tainted: false, path: null, source: null }); }
                    } else if (node.left.type === 'MemberExpression') {
                        const matchedSink = usedSinkPatterns.find(sink => sink.type === 'property' && node.left.property.type === 'Identifier' && node.left.property.name === sink.identifier && (!sink.base || (node.left.object.type === 'Identifier' && node.left.object.name === sink.base)) && (!sink.basePattern || (node.left.object.type === 'Identifier' && sink.basePattern.test(node.left.object.name))) );
                        if (matchedSink && rhsTainted) { recordSink(matchedSink, node, ancestorsArr, { tainted: rhsTainted, path: rhsPath, source: rhsSource, relativePath: deriveRelativePath(rhsPath, state.eventParamName, state.aliasMap) }, state, collectedSinksDuringWalk); }
                    }
                },
                Identifier: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA Identifier] state or state.analysis is undefined!", {node_name: node.name, state_defined: !!state}); return; }
                    const name = node.name;
                    const { tainted: pathTainted, path: accessedPath, relativePath } = isEventDataAccess(node, state.eventParamName, state.aliasMap, state.taintMap);
                    if (pathTainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { log.debug(`[Walker] Adding accessed path from Identifier: ${relativePath} from ${accessedPath}`); state.analysis.accessedEventDataPaths.add(relativePath); }
                    const knownGlobals = ['window', 'document', 'console', 'Math', 'JSON', 'Object', 'Array','String', 'Number', 'Boolean', 'Date', 'RegExp', 'Error','setTimeout', 'setInterval', 'clearTimeout', 'clearInterval','encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI','btoa', 'atob', 'navigator', 'location', 'history', 'screen','performance', 'localStorage', 'sessionStorage', '$', 'jQuery', 'eval', 'alert', 'confirm', 'prompt'];
                    if (name !== state.eventParamName && !knownGlobals.includes(name) && !isLocallyDefined(name, ancestorsArr)) {
                        if (!state.analysis.externalStateAccesses.some(e => e.base === name && !e.property)) {
                            state.analysis.externalStateAccesses.push({ base: name, property: undefined, node: {type: node.type, start: node.start, end: node.end }, snippet: getCodeSnippet(node, state.originalSource) });
                        }
                    }
                },
                MemberExpression: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA MemberExpression] state or state.analysis is undefined!", {node_path: getFullAccessPath(node), state_defined: !!state}); return; }
                    const { tainted: pathTainted, path: accessedPath, relativePath } = isEventDataAccess(node, state.eventParamName, state.aliasMap, state.taintMap);
                    if (pathTainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { log.debug(`[Walker] Adding accessed path from MemberExpression: ${relativePath} from ${accessedPath}`); state.analysis.accessedEventDataPaths.add(relativePath); }
                    if (node.object.type === 'Identifier' && !isLocallyDefined(node.object.name, ancestorsArr) && node.object.name !== state.eventParamName && !state.aliasMap.has(node.object.name)) {
                        const base = node.object.name;
                        const property = node.property.type === 'Identifier' ? node.property.name : (node.property.type === 'Literal' ? node.property.value : '[computed]');
                        if (!state.analysis.externalStateAccesses.some(e => e.base === base && e.property === property)) {
                            state.analysis.externalStateAccesses.push({ base: base, property: property, node: {type: node.type, start: node.start, end: node.end }, snippet: getCodeSnippet(node, state.originalSource) });
                        }
                    }
                },
                CallExpression: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA CallExpression] state (state) or state.analysis is undefined!"); return; } // Renamed st to state
                    const check = analyzeOriginCheck(node, state.eventParamName, state.aliasMap, state.originalSource); if (check.isCheck) { allOriginChecksFound.push(check); }
                    let matchedSink = null; let sinkInputNode = null; let sinkArgIndex = 0;
                    if (node.callee.type === 'Identifier') { matchedSink = usedSinkPatterns.find(sink => sink.type === 'function' && node.callee.name === sink.identifier); if (matchedSink) sinkArgIndex = matchedSink.argIndex ?? 0; }
                    else if (node.callee.type === 'MemberExpression' && node.callee.property.type === 'Identifier') { const methodName = node.callee.property.name; const baseNameNode = node.callee.object; let baseIdentifier = null; if (baseNameNode.type === 'Identifier') { baseIdentifier = baseNameNode.name; } else if (baseNameNode.type === 'ThisExpression') { baseIdentifier = 'this';} else { baseIdentifier = getFullAccessPath(baseNameNode); } matchedSink = usedSinkPatterns.find(sink => sink.type === 'method' && methodName === sink.identifier && (!sink.base || sink.base === baseIdentifier || (sink.basePattern instanceof RegExp && sink.basePattern.test(baseIdentifier))) ); if (matchedSink) sinkArgIndex = matchedSink.argIndex ?? 0; }

                    if (matchedSink && node.arguments.length > sinkArgIndex) {
                        sinkInputNode = node.arguments[sinkArgIndex];
                        log.debug(`[Sink Check CallExpr] Found potential sink call '${matchedSink.name}'. Checking arg node type ${sinkInputNode.type} at index ${sinkArgIndex}`);
                        if (!matchedSink.check || matchedSink.check(node, sinkInputNode, state)) {
                            const taintedInput = isEventDataAccess(sinkInputNode, state.eventParamName, state.aliasMap, state.taintMap);
                            log.debug(`[Sink Check CallExpr] Taint result for sink '${matchedSink.name}' arg ${sinkArgIndex}:`, JSON.stringify(taintedInput));
                            if (taintedInput.tainted) {
                                log.debug(`[Sink Check CallExpr] >>> Tainted input confirmed for sink '${matchedSink.name}'. Calling recordSink.`);
                                recordSink(matchedSink, node, ancestorsArr, taintedInput, state, collectedSinksDuringWalk);
                            } else { log.debug(`[Sink Check CallExpr] Input not tainted for sink '${matchedSink.name}'.`); }
                        } else { log.debug(`[Sink Check CallExpr] Sink '${matchedSink.name}' failed custom check function.`); }
                    }
                },
                NewExpression: (node, state, ancestorsArr) => { // Corrected signature
                    if (!state || !state.analysis) { log.error("[SA NewExpression] state (state) or state.analysis is undefined!"); return; } // Renamed st to state
                    let matchedSink = null; let sinkInputNode = null; let sinkArgIndex = 0;
                    if (node.callee.type === 'Identifier') {
                        matchedSink = usedSinkPatterns.find(sink => sink.type === 'constructor' && node.callee.name === sink.identifier);
                        if (matchedSink) sinkArgIndex = matchedSink.argIndex ?? 0;
                    }
                    if (matchedSink && node.arguments.length > sinkArgIndex) {
                        sinkInputNode = node.arguments[sinkArgIndex];
                        log.debug(`[Sink Check NewExpr] Found potential constructor sink call '${matchedSink.name}'. Checking arg node type ${sinkInputNode.type} at index ${sinkArgIndex}`);
                        if (!matchedSink.check || matchedSink.check(node, sinkInputNode, state)) {
                            const taintedInput = isEventDataAccess(sinkInputNode, state.eventParamName, state.aliasMap, state.taintMap);
                            log.debug(`[Sink Check NewExpr] Taint result for sink '${matchedSink.name}' arg ${sinkArgIndex}:`, JSON.stringify(taintedInput));
                            if (taintedInput.tainted) {
                                log.debug(`[Sink Check NewExpr] >>> Tainted input confirmed for constructor sink '${matchedSink.name}'. Calling recordSink.`);
                                recordSink(matchedSink, node, ancestorsArr, taintedInput, state, collectedSinksDuringWalk);
                            } else { log.debug(`[Sink Check NewExpr] Input not tainted for constructor sink '${matchedSink.name}'.`); }
                        } else { log.debug(`[Sink Check NewExpr] Constructor sink '${matchedSink.name}' failed custom check function.`); }
                    }
                },
                IfStatement: (node, state, ancestorsArr) => { if (!state || !state.analysis) {return;} const check = analyzeOriginCheck(node.test, state.eventParamName, state.aliasMap, state.originalSource); if (check.isCheck) { allOriginChecksFound.push(check); } findConditionsForNode(node.test, state.eventParamName, state.aliasMap, state.taintMap).forEach(cond => { state.analysis.accessedEventDataPaths.add(cond.path); }); },
                BinaryExpression: (node, state, ancestorsArr) => { if (!state) {return;} const check = analyzeOriginCheck(node, state.eventParamName, state.aliasMap, state.originalSource); if (check.isCheck) { allOriginChecksFound.push(check); } },
                LogicalExpression: (node, state, ancestorsArr) => { if (!state) {return;} const checkLeft = analyzeOriginCheck(node.left, state.eventParamName, state.aliasMap, state.originalSource); if (checkLeft.isCheck) { allOriginChecksFound.push(checkLeft); } const checkRight = analyzeOriginCheck(node.right, state.eventParamName, state.aliasMap, state.originalSource); if (checkRight.isCheck) { allOriginChecksFound.push(checkRight); } },
                UnaryExpression: (node, state, ancestorsArr) => { if (!state) {return;} const check = analyzeOriginCheck(node, state.eventParamName, state.aliasMap, state.originalSource); if (check.isCheck) { allOriginChecksFound.push(check); } },
                ConditionalExpression: (node, state, ancestorsArr) => { if (!state || !state.analysis) {return;} const check = analyzeOriginCheck(node.test, state.eventParamName, state.aliasMap, state.originalSource); if (check.isCheck) { allOriginChecksFound.push(check); } findConditionsForNode(node.test, state.eventParamName, state.aliasMap, state.taintMap).forEach(cond => { state.analysis.accessedEventDataPaths.add(cond.path); }); }
            };

            global.acorn.walk.ancestor(funcBody, analysisVisitors, safeWalkBaseInstance, stateObj);

            analysis.potentialSinks = [...collectedSinksDuringWalk];
            log.debug("[Finalizing] Potential sinks BEFORE filtering:", JSON.stringify(analysis.potentialSinks.map(s=>({name:s.name, path: s.sourcePath, conditions: s.conditions }))));

            if (allOriginChecksFound.length === 0) { analysis.originChecks.push({ isCheck: false, type: 'Missing', strength: 'Missing', rawSnippet: '[No origin check found]', node: null }); }
            else { const uniqueChecksMap = new Map(); allOriginChecksFound.forEach(check => { const key = `${check.type}-${check.strength}-${check.rawSnippet}`; if (!uniqueChecksMap.has(key)) { uniqueChecksMap.set(key, check); } }); analysis.originChecks = Array.from(uniqueChecksMap.values()); }

            analysis.accessedEventDataPaths = Array.from(analysis.accessedEventDataPaths);

            const uniqueSinkKeys = new Set();
            const uniqueSinks = [];
            for (const sink of analysis.potentialSinks) {
                const key = `${sink.name}|${sink.sourcePath}|${sink.snippet}`;
                if (!uniqueSinkKeys.has(key)) {
                    uniqueSinkKeys.add(key);
                    uniqueSinks.push(sink);
                } else {
                    log.debug(`[Finalizing] Filtering out duplicate sink: ${key}`);
                }
            }
            analysis.potentialSinks = uniqueSinks;
            log.debug("[Finalizing] Potential sinks AFTER filtering:", JSON.stringify(analysis.potentialSinks.map(s=>({name:s.name, path: s.sourcePath, conditions: s.conditions }))));

            return { success: true, analysis: analysis };

        } catch (e) {
            console.error("[Static Analyzer] Walk Error:", e, e.stack);
            return { success: false, error: `Static Analysis Walk Error: ${e.message} (Stack: ${e.stack ? e.stack.substring(0,300) : 'N/A'})`, analysis: null };
        }
    };

})(typeof window !== 'undefined' ? window : global);
