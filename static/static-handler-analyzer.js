(function(global) {

    if (typeof global.acorn === 'undefined' || typeof global.acorn.parse !== 'function' || typeof global.acorn.walk?.recursive !== 'function') {
        console.error("Acorn/Acorn Recursive Walk library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn library not found.', analysis: null });
        return;
    }

    let currentSourceMap = '';
    const STANDARD_EVENT_NAMES = /^(event|e|msg|message|evt|data|payload|p|d|m|evtData|msgData)$/; // Expanded common names
    const ORIGIN_PROP = 'origin';
    const DATA_PROP = 'data';
    const SOURCE_PROP = 'source';
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
        } catch (e) { console.error("[getCodeSnippet] Error generating snippet:", e, node, originalSourceWithWrapper.length); return '[Snippet Error: Exception]'; }
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
        const eventDataPrefix = `${eventParamName}.${DATA_PROP}.`; const eventPrefix = `${eventParamName}.`;
        if (fullPath === `${eventParamName}.${DATA_PROP}`) { return '(root_data)'; }
        else if (fullPath.startsWith(eventDataPrefix)) { const rel = fullPath.substring(eventDataPrefix.length); return rel || null; }
        else if (fullPath.startsWith(eventPrefix)) { return null; }
        else {
            const parts = fullPath.split('.'); const baseName = parts[0];
            if (baseName) {
                const aliasSource = aliasMap.get(baseName);
                if (aliasSource === `${eventParamName}.${DATA_PROP}`) { const rel = parts.slice(1).join('.'); return rel || '(root_data)'; }
                else if (aliasSource?.startsWith('JSON.parse')) { const rel = parts.slice(1).join('.'); return rel || '(parsed_root)'; }
                else if (aliasSource === eventParamName) { return null; } // Alias points to event, not event.data
            }
        }
        return null;
    }

    function isEventDataAccess(node, eventParamName, aliasMap, taintMap) {
        if (!node || !eventParamName) return { tainted: false, path: null, relativePath: null };
        let current = node; let depth = 0; const fullPath = getFullAccessPath(node);
        while (current && depth < 30) {
            depth++;
            if (current.type === 'Identifier') {
                if (current.name === eventParamName) { return { tainted: true, path: fullPath, relativePath: null }; }
                const aliasSource = aliasMap.get(current.name);
                if (aliasSource === `${eventParamName}.${DATA_PROP}`) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(root_data)'}; }
                if (aliasSource === eventParamName) { return { tainted: true, path: fullPath, relativePath: null }; }
                if (aliasSource && aliasSource.startsWith('JSON.parse')) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(parsed_root)' }; }
                if (taintMap.has(current.name)) { const taintInfo = taintMap.get(current.name); if (taintInfo.tainted) { const relPathFromTaint = deriveRelativePath(fullPath, eventParamName, aliasMap); return { tainted: true, path: fullPath, relativePath: relPathFromTaint }; } }
                break;
            }
            if (current.type === 'MemberExpression') {
                if (current.object.type === 'Identifier' && current.object.name === eventParamName && current.property.type === 'Identifier') { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; }
                const aliasSourceObj = aliasMap.get(current.object?.name);
                if (current.property?.name === DATA_PROP && aliasSourceObj === eventParamName) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(root_data)' }; }
                const objCheck = isEventDataAccess(current.object, eventParamName, aliasMap, taintMap);
                if(objCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; }
                current = current.object;
            } else if (current.type === 'CallExpression') {
                const calleeCheck = isEventDataAccess(current.callee, eventParamName, aliasMap, taintMap);
                if (calleeCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; }
                if (current.arguments) { for (const arg of current.arguments) { const argCheck = isEventDataAccess(arg, eventParamName, aliasMap, taintMap); if (argCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; } } }
                break;
            } else if (current.type === 'ThisExpression') { break; }
            else { break; }
        }
        return { tainted: false, path: null, relativePath: null };
    }

    function analyzeOriginCheck(node, eventParamName, aliasMap, sourceCode, originalSourceWithWrapper) {
        const checkInfo = { isCheck: false, type: 'unknown', comparedValue: null, comparedValueType: 'unknown', methodName: null, strength: 'none', negated: false, rawSnippet: null, node: node };
        const getStrength = (value) => { if (typeof value === 'string') { if (value === '*' || value === 'null') return 'weak'; if (value.startsWith('http://') || value.startsWith('https://')) return 'strong'; } return 'medium'; };
        const isNodeEventOrigin = (n) => {
            if (!n) return false;
            if (eventParamName) { if (isDirectEventPropertyAccess(n, ORIGIN_PROP, eventParamName)) return true; if (n?.type === 'Identifier' && aliasMap.get(n.name) === `${eventParamName}.${ORIGIN_PROP}`) return true; if (n?.type === 'MemberExpression' && n.property?.name === ORIGIN_PROP && n.object?.type === 'Identifier' && aliasMap.get(n.object.name) === eventParamName) return true; }
            if (n.type === 'MemberExpression' && n.object.type === 'Identifier' && n.object.name === 'event' && n.property.type === 'Identifier' && n.property.name === ORIGIN_PROP) { if(typeof log !== 'undefined' && log.debug) log.debug("[Static Analyzer/OriginCheck] Heuristic match for literal 'event.origin'"); return true; }
            return false;
        };
        let checkNode = node; let topLevelNodeForSnippet = node; let isNegatedExplicitly = false;
        if (node.type === 'UnaryExpression' && node.operator === '!') { isNegatedExplicitly = true; checkNode = node.argument; topLevelNodeForSnippet = node; }
        else if (node.type === 'IfStatement') { checkNode = node.test; topLevelNodeForSnippet = node.test; }
        else if (node.type === 'LogicalExpression') { let leftCheck = analyzeOriginCheck(node.left, eventParamName, aliasMap, sourceCode, originalSourceWithWrapper); if (leftCheck.isCheck) { return leftCheck; } let rightCheck = analyzeOriginCheck(node.right, eventParamName, aliasMap, sourceCode, originalSourceWithWrapper); if (rightCheck.isCheck) { return rightCheck; } return checkInfo; }
        else { checkNode = node; topLevelNodeForSnippet = node; }
        checkInfo.negated = isNegatedExplicitly;
        checkInfo.rawSnippet = getCodeSnippet(topLevelNodeForSnippet, originalSourceWithWrapper);
        if (checkNode.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(checkNode.operator)) {
            let originNode = null; let otherNode = null;
            if (isNodeEventOrigin(checkNode.left)) { originNode = checkNode.left; otherNode = checkNode.right; }
            else if (isNodeEventOrigin(checkNode.right)) { originNode = checkNode.right; otherNode = checkNode.left; }
            if (originNode) {
                checkInfo.isCheck = true; checkInfo.type = (checkNode.operator === '===' || checkNode.operator === '!==') ? 'Strict Equality' : 'Loose Equality';
                checkInfo.negated = checkInfo.negated || checkNode.operator === '!==' || checkNode.operator === '!='; checkInfo.comparedValueType = otherNode.type;
                checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper);
                if (otherNode.type === 'Literal') { checkInfo.comparedValue = otherNode.value; checkInfo.strength = getStrength(otherNode.value); }
                else if (otherNode.type === 'Identifier') { checkInfo.comparedValue = otherNode.name; checkInfo.strength = 'medium'; }
                else { checkInfo.comparedValue = getCodeSnippet(otherNode, originalSourceWithWrapper); checkInfo.strength = 'medium'; }
                return checkInfo;
            }
        } else if (checkNode.type === 'CallExpression') {
            const callee = checkNode.callee; if (callee.type === 'MemberExpression') { if (isNodeEventOrigin(callee.object)) { checkInfo.methodName = callee.property.name; if (['startsWith', 'endsWith', 'includes', 'indexOf'].includes(checkInfo.methodName) && checkNode.arguments.length > 0) { checkInfo.isCheck = true; checkInfo.type = 'Method Call'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); const argNode = checkNode.arguments[0]; checkInfo.comparedValueType = argNode.type; if (argNode.type === 'Literal') { checkInfo.comparedValue = argNode.value; checkInfo.strength = getStrength(argNode.value); } else if (argNode.type === 'Identifier') { checkInfo.comparedValue = argNode.name; checkInfo.strength = 'medium';} else { checkInfo.comparedValue = getCodeSnippet(argNode, originalSourceWithWrapper); checkInfo.strength = 'medium'; } if (checkInfo.methodName === 'indexOf' && checkInfo.strength !== 'weak') { checkInfo.strength = 'medium'; } else if (checkInfo.methodName === 'includes' && checkInfo.strength === 'strong') { checkInfo.strength = 'medium'; } return checkInfo; } } else if (checkNode.arguments.some(arg => isNodeEventOrigin(arg))) { if (callee.type === 'MemberExpression' && callee.property.name === 'test' && callee.object.type === 'Literal' && callee.object.regex) { checkInfo.isCheck = true; checkInfo.type = 'Regex Test'; checkInfo.methodName = 'test'; checkInfo.comparedValue = callee.object.regex.pattern; checkInfo.comparedValueType = 'RegExp'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); const pattern = callee.object.regex.pattern; if (!pattern.startsWith('^') || !pattern.endsWith('$') || pattern.includes('.*') || pattern.includes('.+')) checkInfo.strength = 'medium'; else if (pattern.includes('http')) checkInfo.strength = 'strong'; else checkInfo.strength = 'medium'; return checkInfo; } else { checkInfo.isCheck = true; checkInfo.type = 'Function Call'; checkInfo.methodName = getFullAccessPath(callee); checkInfo.strength = 'unknown'; checkInfo.comparedValue = `Args: ${checkNode.arguments.length}`; checkInfo.comparedValueType = 'Arguments'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper); return checkInfo; } } }
        } else if (isNodeEventOrigin(checkNode)) {
            checkInfo.isCheck = true; checkInfo.type = 'Existence Check'; checkInfo.strength = 'weak'; checkInfo.rawSnippet = getCodeSnippet(checkNode, originalSourceWithWrapper);
            return checkInfo;
        }
        return checkInfo;
    }

    function findConditionsForNode(testNode, eventParamName, aliasMap, taintMap) {
        const conditions = []; const MAX_DEPTH = 5;
        function extract(node, depth) {
            if (!node || depth >= MAX_DEPTH) return;
            if (node.type === 'LogicalExpression' && node.operator === '&&') { extract(node.left, depth + 1); extract(node.right, depth + 1); }
            else if (node.type === 'BinaryExpression' && ['===', '=='].includes(node.operator)) {
                let dataAccessNode = null; let literalNode = null;
                let dataCheckLeft = isEventDataAccess(node.left, eventParamName, aliasMap, taintMap);
                let dataCheckRight = isEventDataAccess(node.right, eventParamName, aliasMap, taintMap);
                if (dataCheckLeft.tainted && dataCheckLeft.relativePath && node.right.type === 'Literal') { dataAccessNode = node.left; literalNode = node.right; }
                else if (dataCheckRight.tainted && dataCheckRight.relativePath && node.left.type === 'Literal') { dataAccessNode = node.right; literalNode = node.left; }
                if (dataAccessNode && literalNode && (typeof literalNode.value === 'string' || typeof literalNode.value === 'number' || typeof literalNode.value === 'boolean')) {
                    const { relativePath } = isEventDataAccess(dataAccessNode, eventParamName, aliasMap, taintMap);
                    if (relativePath && relativePath.length > 0 && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { conditions.push({ path: relativePath, op: node.operator, value: literalNode.value }); }
                }
            } else if (node.type === 'MemberExpression' || node.type === 'Identifier') {
                const { tainted, relativePath } = isEventDataAccess(node, eventParamName, aliasMap, taintMap);
                if (tainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { conditions.push({ path: relativePath, op: 'truthy', value: true }); }
            }
        }
        extract(testNode, 0);
        return conditions;
    }

    function isLocallyDefined(identifierName, scopeStack) {
        for (let i = scopeStack.length - 1; i >= 0; i--) { if (scopeStack[i].has(identifierName)) { return true; } } return false;
    }

    function findParentNodeOfType(node, type, maxDepth = 10) {
        let current = node?.parent; let depth = 0;
        while(current && depth < maxDepth) {
            if (current.type === type) { return current; }
            if (current.type === 'FunctionExpression' || current.type === 'FunctionDeclaration' || current.type === 'ArrowFunctionExpression') { return null; }
            current = current.parent; depth++;
        }
        return null;
    }

    global.analyzeHandlerStatically = function(handlerCode, endpoint = '', sinkPatterns = [], context = {}) {
        analysisLog = [];
        const analysis = { identifiedEventParam: null, potentialSinks: [], originChecks: [], securityIssues: [], accessedEventDataPaths: new Set(), requiredConditions: {}, externalStateAccesses: [], indirectCalls: [] };
        let ast = null;
        const sourceCodeWithWrapper = WRAPPER_PREFIX + handlerCode;
        const sourceCodeWithoutWrapper = handlerCode;

        try {
            if (typeof log === 'undefined') { global.log = { debug: console.debug, info: console.info, warn: console.warn, error: console.error }; }
            log.debug("[Static Analyzer] Starting parsing");
            ast = global.acorn.parse(sourceCodeWithWrapper, { ecmaVersion: 'latest', locations: true, ranges: true, allowReturnOutsideFunction: true });
            let ancestors = [];
            acorn.walk.full(ast, (node, state, type) => { node.parent = ancestors.length > 0 ? ancestors[ancestors.length-1] : null; ancestors.push(node); }, acorn.walk.base);
            ancestors = [];
            acorn.walk.full(ast, (node, state, type) => { ancestors.pop(); }, acorn.walk.base);
        } catch (e) { log.error("[Static Analyzer] Acorn parsing failed:", e); return { success: false, error: `AST Parsing Error: ${e.message}`, analysis: null }; }

        let identifiedParams = [];
        let paramUsageCounts = {};
        const topLevelFuncNode = ast.body[0]?.declarations[0]?.init;

        if (topLevelFuncNode && (topLevelFuncNode.type === 'FunctionExpression' || topLevelFuncNode.type === 'ArrowFunctionExpression')) {
            identifiedParams = topLevelFuncNode.params.filter(p => p.type === 'Identifier').map(p => p.name);
            identifiedParams.forEach(p => paramUsageCounts[p] = { data: 0, origin: 0, source: 0, total: 0 });
            try {
                acorn.walk.simple(topLevelFuncNode.body, {
                    MemberExpression(node) {
                        if (node.object.type === 'Identifier' && identifiedParams.includes(node.object.name)) {
                            paramUsageCounts[node.object.name].total++;
                            if (node.property.type === 'Identifier') {
                                if (node.property.name === DATA_PROP) paramUsageCounts[node.object.name].data++;
                                else if (node.property.name === ORIGIN_PROP) paramUsageCounts[node.object.name].origin++;
                                else if (node.property.name === SOURCE_PROP) paramUsageCounts[node.object.name].source++;
                            }
                        }
                    }
                });
            } catch(walkError){ log.warn("[Static Analyzer] Error during param usage walk:", walkError); }
        }

        let localEventParamName = null;
        if (identifiedParams.length > 0) {
            let bestParam = identifiedParams[0];
            let maxScore = -1;
            identifiedParams.forEach(p => {
                let score = (paramUsageCounts[p].data * 3) + (paramUsageCounts[p].origin * 2) + (paramUsageCounts[p].source * 1) + (paramUsageCounts[p].total * 0.1);
                if (STANDARD_EVENT_NAMES.test(p)) score += 5;
                if (score > maxScore) { maxScore = score; bestParam = p; }
            });
            localEventParamName = bestParam;
            log.debug(`[Static Analyzer] Identified event parameter as '${localEventParamName}' based on usage scores:`, paramUsageCounts);
        } else { localEventParamName = 'event'; log.debug("[Static Analyzer] Could not identify params, defaulting event param name to 'event'");}

        analysis.identifiedEventParam = localEventParamName;
        const initialTaintMap = new Map([[localEventParamName, { tainted: true, path: localEventParamName }]]);
        const state = { scopeStack: [new Set([localEventParamName])], eventParamName: localEventParamName, aliasMap: new Map(), taintMap: initialTaintMap, analysis: analysis, handlerCode: sourceCodeWithoutWrapper, originalSource: sourceCodeWithWrapper };

        try {
            log.debug("[Static Analyzer] Running recursive walk (main analysis)");
            const funcBody = ast.body[0]?.declarations[0]?.init?.body;
            if (!funcBody) throw new Error("Could not find function body in AST");

            acorn.walk.recursive(funcBody, state, {
                Function(node, st, c) { const currentScope = new Set(); node.params?.forEach(param => { if (param.type === 'Identifier') currentScope.add(param.name); }); if (node.id?.type === 'Identifier') currentScope.add(node.id.name); st.scopeStack.push(currentScope); if(node.body) c(node.body, st, "BlockStatement"); st.scopeStack.pop(); },
                BlockStatement(node, st, c) { const currentScope = new Set(); node.body.forEach(stmt => { if (stmt.type === 'VariableDeclaration') { stmt.declarations.forEach(decl => { if (decl.id.type === 'Identifier') currentScope.add(decl.id.name); }); } else if (stmt.type === 'FunctionDeclaration' && stmt.id) { currentScope.add(stmt.id.name); } }); st.scopeStack.push(currentScope); node.body.forEach(stmt => c(stmt, st)); st.scopeStack.pop(); },
                VariableDeclarator(node, st, c) { if (node.id.type === 'Identifier' && st.scopeStack.length > 0) { const currentTopScope = st.scopeStack[st.scopeStack.length - 1]; if (currentTopScope) currentTopScope.add(node.id.name); } if (node.init) { c(node.init, st, "Expression"); const varName = node.id.name; if (isDirectEventPropertyAccess(node.init, ORIGIN_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${ORIGIN_PROP}`); else if (isDirectEventPropertyAccess(node.init, DATA_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${DATA_PROP}`); else if (node.init.type === 'Identifier' && node.init.name === st.eventParamName) st.aliasMap.set(varName, st.eventParamName); else if (node.init.type === 'CallExpression' && node.init.callee.type === 'MemberExpression' && node.init.callee.object?.name === 'JSON' && node.init.callee.property?.name === 'parse' && node.init.arguments?.length > 0) { const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.init.arguments[0], st.eventParamName, st.aliasMap, st.taintMap); if (inputTainted) { st.aliasMap.set(varName, `JSON.parse(...)`); st.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.init.arguments[0])})` }); st.analysis.accessedEventDataPaths.add('(parsed_root)'); } } const { tainted: rhsTainted, path: rhsPath } = isEventDataAccess(node.init, st.eventParamName, st.aliasMap, st.taintMap); if (rhsTainted) { st.taintMap.set(varName, { tainted: rhsTainted, path: rhsPath || getFullAccessPath(node.init) }); } else { st.taintMap.set(varName, { tainted: false, path: null }); } } },
                AssignmentExpression(node, st, c) { let isJsonParseAlias = false; if (node.left?.type === 'Identifier' && node.right) { const varName = node.left.name; if (isDirectEventPropertyAccess(node.right, ORIGIN_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${ORIGIN_PROP}`); else if (isDirectEventPropertyAccess(node.right, DATA_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${DATA_PROP}`); else if (node.right.type === 'Identifier' && node.right.name === st.eventParamName) st.aliasMap.set(varName, st.eventParamName); else if (node.right.type === 'CallExpression' && node.right.callee.type === 'MemberExpression' && node.right.callee.object?.name === 'JSON' && node.right.callee.property?.name === 'parse' && node.right.arguments?.length > 0) { const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.right.arguments[0], st.eventParamName, st.aliasMap, st.taintMap); if (inputTainted) { isJsonParseAlias = true; st.aliasMap.set(varName, `JSON.parse(...)`); st.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.right.arguments[0])})` }); st.analysis.accessedEventDataPaths.add('(parsed_root)'); } } } const { tainted: rhsTainted, path: rhsPath } = isEventDataAccess(node.right, st.eventParamName, st.aliasMap, st.taintMap); if (node.left.type === 'Identifier') { if (rhsTainted && !isJsonParseAlias) { st.taintMap.set(node.left.name, { tainted: rhsTainted, path: rhsPath || getFullAccessPath(node.right) }); } else if (!isJsonParseAlias) { const existing = st.taintMap.get(node.left.name); if(!existing || !existing.tainted) st.taintMap.set(node.left.name, { tainted: false, path: null }); } } c(node.left, st, "Expression"); c(node.right, st, "Expression"); },
                Identifier(node, st, c) { const name = node.name; const knownGlobals = ['window', 'document', 'console', 'Math', 'JSON', 'Object', 'Array','String', 'Number', 'Boolean', 'Date', 'RegExp', 'Error','setTimeout', 'setInterval', 'clearTimeout', 'clearInterval','encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI','btoa', 'atob', 'navigator', 'location', 'history', 'screen','performance', 'localStorage', 'sessionStorage', '$', 'jQuery', 'eval', 'alert', 'confirm', 'prompt']; if (name !== st.eventParamName && !knownGlobals.includes(name) && !isLocallyDefined(name, st.scopeStack)) { if (!st.analysis.externalStateAccesses.some(e => e.base === name && !e.property)) { st.analysis.externalStateAccesses.push({ base: name, property: undefined, node: node, snippet: getCodeSnippet(node, st.originalSource) }); } } },
                MemberExpression(node, st, c) { const { tainted: pathTainted, path: accessedPath, relativePath } = isEventDataAccess(node, st.eventParamName, st.aliasMap, st.taintMap); if (pathTainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { st.analysis.accessedEventDataPaths.add(relativePath); } if (node.object.type === 'Identifier' && !isLocallyDefined(node.object.name, st.scopeStack) && node.object.name !== st.eventParamName && !state.aliasMap.has(node.object.name)) { const base = node.object.name; const property = node.property.type === 'Identifier' ? node.property.name : (node.property.type === 'Literal' ? node.property.value : '[computed]'); if (!st.analysis.externalStateAccesses.some(e => e.base === base && e.property === property)) { st.analysis.externalStateAccesses.push({ base: base, property: property, node: node, snippet: getCodeSnippet(node, st.originalSource) }); } } c(node.object, st, "Expression"); c(node.property, st, "Expression"); },
                CallExpression(node, st, c) {
                    const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode, st.originalSource); if (check.isCheck) { st.analysis.originChecks.push(check); }
                    let sinkName = null; let sinkInputNode = null; let sinkSeverity = 'Medium'; let sinkCategory = 'generic';
                    if (node.callee.type === 'Identifier' && node.callee.name === 'eval' && node.arguments.length > 0) { sinkName = 'eval'; sinkInputNode = node.arguments[0]; sinkSeverity = 'Critical'; sinkCategory = 'eval'; }
                    if (sinkName && sinkInputNode) {
                        const { tainted, path: fullInputPath, relativePath } = isEventDataAccess(sinkInputNode, st.eventParamName, st.aliasMap, st.taintMap);
                        if (tainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') {
                            let conditions = []; const ifStmt = findParentNodeOfType(node, 'IfStatement');
                            if(ifStmt) { conditions = findConditionsForNode(ifStmt.test, st.eventParamName, st.aliasMap, st.taintMap); }
                            const sinkEntry = { name: sinkName, severity: sinkSeverity, category: sinkCategory, node: node, snippet: getCodeSnippet(node, st.originalSource), fullInputPath: fullInputPath, sourcePath: relativePath, conditions: conditions };
                            st.analysis.potentialSinks.push(sinkEntry);
                            if (!st.analysis.requiredConditions[relativePath]) { st.analysis.requiredConditions[relativePath] = { conditions: [], sinks: [] }; }
                            const reqCondEntry = st.analysis.requiredConditions[relativePath];
                            conditions.forEach(cond => { if (!reqCondEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(cond))) { reqCondEntry.conditions.push(cond); }});
                            if (!reqCondEntry.sinks.includes(sinkName)) { reqCondEntry.sinks.push(sinkName); }
                            st.analysis.accessedEventDataPaths.add(relativePath);
                            conditions.forEach(cond => st.analysis.accessedEventDataPaths.add(cond.path));
                        } else if(tainted) { st.analysis.potentialSinks.push({ name: sinkName, severity: sinkSeverity, category: sinkCategory, node: node, snippet: getCodeSnippet(node, st.originalSource), fullInputPath: fullInputPath, sourcePath: null, conditions: [] }); }
                    }
                    c(node.callee, st, "Expression"); node.arguments.forEach(arg => c(arg, st, "Expression"));
                },
                IfStatement(node, st, c) {
                    findConditionsForNode(node.test, st.eventParamName, st.aliasMap, st.taintMap).forEach(cond => { st.analysis.accessedEventDataPaths.add(cond.path); });
                    c(node.test, st, "Expression"); c(node.consequent, st, "Statement"); if (node.alternate) { c(node.alternate, st, "Statement"); }
                },
                BinaryExpression(node, st, c) { const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode, st.originalSource); if (check.isCheck) { st.analysis.originChecks.push(check); } c(node.left, st, "Expression"); c(node.right, st, "Expression"); },
                LogicalExpression(node, st, c) { const checkLeft = analyzeOriginCheck(node.left, st.eventParamName, st.aliasMap, st.handlerCode, st.originalSource); if (checkLeft.isCheck) { st.analysis.originChecks.push(checkLeft); } const checkRight = analyzeOriginCheck(node.right, st.eventParamName, st.aliasMap, st.handlerCode, st.originalSource); if (checkRight.isCheck) { st.analysis.originChecks.push(checkRight); } c(node.left, st, "Expression"); c(node.right, st, "Expression"); },
                UnaryExpression(node, st, c) { const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode, st.originalSource); if (check.isCheck) { st.analysis.originChecks.push(check); } c(node.argument, st, "Expression"); }
            }, acorn.walk.base);

            analysis.accessedEventDataPaths = Array.from(analysis.accessedEventDataPaths);
            return { success: true, analysis: analysis };

        } catch (e) {
            log.error("[Static Analyzer] Caught Error during analysis walk:", e);
            return { success: false, error: `Static Analysis Walk Error: ${e.message}`, analysis: null };
        }
    };

})(typeof window !== 'undefined' ? window : global);
