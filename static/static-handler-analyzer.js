/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-27
 */
(function(global) {

    if (typeof global.acorn === 'undefined' || typeof global.acorn.parse !== 'function' || typeof global.acorn.walk?.recursive !== 'function') {
        console.error("Acorn/Acorn Recursive Walk library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn library not found.', analysis: null });
        return;
    }

    let currentSourceMap = '';
    const STANDARD_EVENT_NAMES = /^(event|e|msg|message|evt)$/;
    const ORIGIN_PROP = 'origin';
    const DATA_PROP = 'data';
    let analysisLog = [];

    function getCodeSnippet(node, source) {
        if (!node || !node.range || typeof source !== 'string') return '';
        try {
            const snippet = source.substring(node.range[0], node.range[1]);
            return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
        } catch (e) { return '[snippet error]'; }
    }

    function getFullAccessPath(node) {
        let current = node; const path = []; let depth = 0;
        while (current && depth < 20) {
            depth++;
            if (current.type === 'MemberExpression') {
                if (current.property.type === 'Identifier') path.unshift(current.property.name);
                else if (current.property.type === 'Literal') path.unshift(String(current.property.value));
                else if (current.property.type === 'ThisExpression') path.unshift('this');
                else if (current.property.type === 'CallExpression') path.unshift('[call()]');
                else path.unshift(`[${current.property.type}]`);
                current = current.object;
            } else if (current.type === 'Identifier') { path.unshift(current.name); current = null; }
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
        else if (fullPath.startsWith(eventDataPrefix)) { const rel = fullPath.substring(eventDataPrefix.length); return rel || null; } // Return null if empty
        else if (fullPath.startsWith(eventPrefix)) { return null; }
        else {
            const parts = fullPath.split('.'); const baseName = parts[0];
            if (baseName) {
                const aliasSource = aliasMap.get(baseName);
                if (aliasSource === `${eventParamName}.${DATA_PROP}`) { const rel = parts.slice(1).join('.'); return rel || '(root_data)'; } // Alias for event.data
                else if (aliasSource?.startsWith('JSON.parse')) { const rel = parts.slice(1).join('.'); return rel || '(parsed_root)'; } // Alias for parsed data
            }
        }
        return null;
    }

    function isEventDataAccess(node, eventParamName, aliasMap, taintMap) {
        if (!node || !eventParamName) return { tainted: false, path: null, relativePath: null };
        let current = node; let depth = 0; const fullPath = getFullAccessPath(node);
        while (current && depth < 20) {
            depth++;
            if (current.type === 'Identifier') {
                if (current.name === eventParamName) { return { tainted: true, path: fullPath, relativePath: null }; }
                const aliasSource = aliasMap.get(current.name);
                if (aliasSource === `${eventParamName}.${DATA_PROP}`) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(root_data)'}; } // Handle root alias
                if (aliasSource === eventParamName) { return { tainted: true, path: fullPath, relativePath: null }; }
                if (aliasSource && aliasSource.startsWith('JSON.parse')) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(parsed_root)' }; }
                if (taintMap.has(current.name)) { const taintInfo = taintMap.get(current.name); if (taintInfo.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; } }
                break;
            }
            if (current.type === 'MemberExpression') {
                if (current.object.type === 'Identifier' && current.object.name === eventParamName && current.property.type === 'Identifier') { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; } // Direct access like event.data or event.origin
                const aliasSourceObj = aliasMap.get(current.object?.name);
                if (current.property?.name === DATA_PROP && aliasSourceObj === eventParamName) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) ?? '(root_data)' }; } // Alias usage like alias.data
                const objCheck = isEventDataAccess(current.object, eventParamName, aliasMap, taintMap);
                if(objCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; }
                current = current.object;
            } else if (current.type === 'CallExpression') {
                const calleeCheck = isEventDataAccess(current.callee, eventParamName, aliasMap, taintMap);
                if (calleeCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; }
                if (current.arguments) { for (const arg of current.arguments) { const argCheck = isEventDataAccess(arg, eventParamName, aliasMap, taintMap); if (argCheck.tainted) { return { tainted: true, path: fullPath, relativePath: deriveRelativePath(fullPath, eventParamName, aliasMap) }; } } }
                break;
            } else { break; }
        }
        return { tainted: false, path: null, relativePath: null };
    }

    function analyzeOriginCheck(node, eventParamName, aliasMap, sourceCode) {
        const checkInfo = { isCheck: false, type: 'unknown', comparedValue: null, comparedValueType: 'unknown', methodName: null, strength: 'none', negated: false, rawSnippet: getCodeSnippet(node, sourceCode), node: node };
        const getStrength = (value) => { if (typeof value === 'string') { if (value === '*' || value === 'null') return 'weak'; if (value.startsWith('http://') || value.startsWith('https://')) return 'strong'; } return 'medium'; };
        const isEventOriginAccessSimple = (n) => { if (!eventParamName) return false; if (isDirectEventPropertyAccess(n, ORIGIN_PROP, eventParamName)) return true; if (n?.type === 'Identifier' && aliasMap.get(n.name) === `${eventParamName}.${ORIGIN_PROP}`) return true; if (n?.type === 'Identifier' && aliasMap.get(n.name) === eventParamName) return false; if (n?.type === 'MemberExpression' && n.property?.name === ORIGIN_PROP && n.object?.type === 'Identifier' && aliasMap.get(n.object.name) === eventParamName) return true; return false; };
        let currentNode = node; if (node.type === 'UnaryExpression' && node.operator === '!') { checkInfo.negated = true; currentNode = node.argument; }
        if (currentNode.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(currentNode.operator)) { let originNode = null; let otherNode = null; if (isEventOriginAccessSimple(currentNode.left)) { originNode = currentNode.left; otherNode = currentNode.right; } else if (isEventOriginAccessSimple(currentNode.right)) { originNode = currentNode.right; otherNode = currentNode.left; } if (originNode) { checkInfo.isCheck = true; checkInfo.type = (currentNode.operator === '===' || currentNode.operator === '!==') ? 'Strict Equality' : 'Loose Equality'; checkInfo.comparedValueType = otherNode.type; checkInfo.negated = checkInfo.negated || currentNode.operator === '!==' || currentNode.operator === '!='; if (otherNode.type === 'Literal') { checkInfo.comparedValue = otherNode.value; checkInfo.strength = getStrength(otherNode.value); } else if (otherNode.type === 'Identifier') { checkInfo.comparedValue = otherNode.name; checkInfo.strength = 'medium'; } else { checkInfo.comparedValue = getCodeSnippet(otherNode, sourceCode); checkInfo.strength = 'medium'; } return checkInfo; }
        } else if (currentNode.type === 'CallExpression') { const callee = currentNode.callee; if (callee.type === 'MemberExpression') { if (isEventOriginAccessSimple(callee.object)) { checkInfo.methodName = callee.property.name; if (['startsWith', 'endsWith', 'includes', 'indexOf'].includes(checkInfo.methodName) && currentNode.arguments.length > 0) { checkInfo.isCheck = true; checkInfo.type = 'Method Call'; const argNode = currentNode.arguments[0]; checkInfo.comparedValueType = argNode.type; if (argNode.type === 'Literal') { checkInfo.comparedValue = argNode.value; checkInfo.strength = getStrength(argNode.value); } else { checkInfo.comparedValue = getCodeSnippet(argNode, sourceCode); checkInfo.strength = 'medium'; } if (checkInfo.methodName === 'indexOf' && checkInfo.strength !== 'weak') { checkInfo.strength = 'medium'; } else if (checkInfo.methodName === 'includes' && checkInfo.strength === 'strong') { checkInfo.strength = 'medium'; } return checkInfo; } } else if (currentNode.arguments.some(arg => isEventOriginAccessSimple(arg))) { if (callee.type === 'MemberExpression' && callee.property.name === 'test' && callee.object.type === 'Literal' && callee.object.regex) { checkInfo.isCheck = true; checkInfo.type = 'Regex Test'; checkInfo.methodName = 'test'; checkInfo.comparedValue = callee.object.regex.pattern; checkInfo.comparedValueType = 'RegExp'; const pattern = callee.object.regex.pattern; if (!pattern.startsWith('^') || !pattern.endsWith('$') || pattern.includes('.*') || pattern.includes('.+')) checkInfo.strength = 'medium'; else if (pattern.includes('http')) checkInfo.strength = 'strong'; else checkInfo.strength = 'medium'; return checkInfo; } else { checkInfo.isCheck = true; checkInfo.type = 'Function Call'; checkInfo.methodName = getFullAccessPath(callee); checkInfo.strength = 'unknown'; checkInfo.comparedValue = `Args: ${currentNode.arguments.length}`; checkInfo.comparedValueType = 'Arguments'; return checkInfo; } } }
        } else if (isEventOriginAccessSimple(currentNode)) { checkInfo.isCheck = true; checkInfo.type = 'Existence Check'; checkInfo.strength = 'weak'; return checkInfo; }
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
                if (dataCheckLeft.tainted && node.right.type === 'Literal') { dataAccessNode = node.left; literalNode = node.right; }
                else if (dataCheckRight.tainted && node.left.type === 'Literal') { dataAccessNode = node.right; literalNode = node.left; }
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
        const analysis = {
            identifiedEventParam: null,
            potentialSinks: [],
            originChecks: [],
            securityIssues: [],
            accessedEventDataPaths: new Set(),
            requiredConditions: {},
            externalStateAccesses: [],
            indirectCalls: []
        };
        let ast = null;
        let sourceCodeToUse = 'const __dummyFunc = ' + handlerCode;
        const sourceCodeWithoutWrapper = handlerCode;

        try {
            if (typeof log === 'undefined') { global.log = console; }
            log.debug("[Static Analyzer] Starting parsing");
            ast = global.acorn.parse(sourceCodeToUse, { ecmaVersion: 'latest', locations: true, ranges: true, allowReturnOutsideFunction: true });
            let ancestors = [];
            acorn.walk.full(ast, (node, state, type) => { node.parent = ancestors.length > 0 ? ancestors[ancestors.length-1] : null; ancestors.push(node); }, acorn.walk.base);
            acorn.walk.full(ast, (node, state, type) => { ancestors.pop(); }, acorn.walk.base);
        } catch (e) { log.error("[Static Analyzer] Acorn parsing failed:", e); return { success: false, error: `AST Parsing Error: ${e.message}`, analysis: null }; }

        let localEventParamName = context.eventParamName || null;
        if (!localEventParamName) {
            log.debug("[Static Analyzer] Running simple walker for event param detection");
            try { acorn.walk.simple(ast.body[0]?.declarations[0]?.init, { Function(node) { if (!localEventParamName && node.params?.length > 0) { const param = node.params[0]; if (param?.type === 'Identifier' && STANDARD_EVENT_NAMES.test(param.name)) { localEventParamName = param.name; } } } }); }
            catch (e) { log.warn("[Static Analyzer] Error during event param detection:", e.message); }
        }
        if (!localEventParamName) { localEventParamName = 'event'; }
        analysis.identifiedEventParam = localEventParamName;

        const state = { scopeStack: [new Set([localEventParamName])], eventParamName: localEventParamName, aliasMap: new Map(), taintMap: new Map([[localEventParamName, { tainted: true, path: localEventParamName }]]), analysis: analysis, handlerCode: sourceCodeWithoutWrapper };

        try {
            log.debug("[Static Analyzer] Running recursive walk (main analysis)");
            acorn.walk.recursive(ast.body[0]?.declarations[0]?.init?.body, state, {
                Function(node, st, c) {
                    const currentScope = new Set(); node.params?.forEach(param => { if (param.type === 'Identifier') currentScope.add(param.name); }); if (node.id?.type === 'Identifier') currentScope.add(node.id.name); st.scopeStack.push(currentScope); if(node.body) c(node.body, st, "BlockStatement"); st.scopeStack.pop();
                },
                BlockStatement(node, st, c) {
                    const currentScope = new Set(); node.body.forEach(stmt => { if (stmt.type === 'VariableDeclaration') { stmt.declarations.forEach(decl => { if (decl.id.type === 'Identifier') currentScope.add(decl.id.name); }); } else if (stmt.type === 'FunctionDeclaration' && stmt.id) { currentScope.add(stmt.id.name); } }); st.scopeStack.push(currentScope); node.body.forEach(stmt => c(stmt, st)); st.scopeStack.pop();
                },
                VariableDeclarator(node, st, c) {
                    if (node.id.type === 'Identifier' && st.scopeStack.length > 0) { const currentTopScope = st.scopeStack[st.scopeStack.length - 1]; if (currentTopScope) currentTopScope.add(node.id.name); }
                    if (node.init) {
                        c(node.init, st, "Expression"); const varName = node.id.name;
                        if (isDirectEventPropertyAccess(node.init, ORIGIN_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${ORIGIN_PROP}`);
                        else if (isDirectEventPropertyAccess(node.init, DATA_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${DATA_PROP}`);
                        else if (node.init.type === 'Identifier' && node.init.name === st.eventParamName) st.aliasMap.set(varName, st.eventParamName);
                        else if (node.init.type === 'CallExpression' && node.init.callee.type === 'MemberExpression' && node.init.callee.object?.name === 'JSON' && node.init.callee.property?.name === 'parse' && node.init.arguments?.length > 0) { const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.init.arguments[0], st.eventParamName, st.aliasMap, st.taintMap); if (inputTainted) { st.aliasMap.set(varName, `JSON.parse(...)`); st.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.init.arguments[0])})` }); st.analysis.accessedEventDataPaths.add('(parsed_root)'); } }
                        const { tainted: rhsTainted, path: rhsPath } = isEventDataAccess(node.init, st.eventParamName, st.aliasMap, st.taintMap);
                        if (rhsTainted) { st.taintMap.set(varName, { tainted: rhsTainted, path: rhsPath || getFullAccessPath(node.init) }); } else { st.taintMap.set(varName, { tainted: false, path: null }); }
                    }
                },
                AssignmentExpression(node, st, c) {
                    let isJsonParseAlias = false;
                    if (node.left?.type === 'Identifier' && node.right) {
                        const varName = node.left.name;
                        if (isDirectEventPropertyAccess(node.right, ORIGIN_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${ORIGIN_PROP}`);
                        else if (isDirectEventPropertyAccess(node.right, DATA_PROP, st.eventParamName)) st.aliasMap.set(varName, `${st.eventParamName}.${DATA_PROP}`);
                        else if (node.right.type === 'Identifier' && node.right.name === st.eventParamName) st.aliasMap.set(varName, st.eventParamName);
                        else if (node.right.type === 'CallExpression' && node.right.callee.type === 'MemberExpression' && node.right.callee.object?.name === 'JSON' && node.right.callee.property?.name === 'parse' && node.right.arguments?.length > 0) { const { tainted: inputTainted, path: inputPath } = isEventDataAccess(node.right.arguments[0], st.eventParamName, st.aliasMap, st.taintMap); if (inputTainted) { isJsonParseAlias = true; st.aliasMap.set(varName, `JSON.parse(...)`); st.taintMap.set(varName, { tainted: true, path: `JSON.parse(${inputPath || getFullAccessPath(node.right.arguments[0])})` }); st.analysis.accessedEventDataPaths.add('(parsed_root)'); } }
                    }
                    const { tainted: rhsTainted, path: rhsPath } = isEventDataAccess(node.right, st.eventParamName, st.aliasMap, st.taintMap);
                    if (node.left.type === 'Identifier') { if (rhsTainted && !isJsonParseAlias) { st.taintMap.set(node.left.name, { tainted: rhsTainted, path: rhsPath || getFullAccessPath(node.right) }); } else if (!isJsonParseAlias) { const existing = st.taintMap.get(node.left.name); if(!existing || !existing.tainted) st.taintMap.set(node.left.name, { tainted: false, path: null }); } }
                    c(node.left, st, "Expression"); c(node.right, st, "Expression");
                },
                Identifier(node, st, c) {
                    const name = node.name; const knownGlobals = ['window', 'document', 'console', 'Math', 'JSON', 'Object', 'Array','String', 'Number', 'Boolean', 'Date', 'RegExp', 'Error','setTimeout', 'setInterval', 'clearTimeout', 'clearInterval','encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI','btoa', 'atob', 'navigator', 'location', 'history', 'screen','performance', 'localStorage', 'sessionStorage', '$', 'jQuery', 'eval', 'alert', 'confirm', 'prompt'];
                    if (name !== st.eventParamName && !knownGlobals.includes(name) && !isLocallyDefined(name, st.scopeStack)) { if (!st.analysis.externalStateAccesses.some(e => e.base === name && !e.property)) { st.analysis.externalStateAccesses.push({ base: name, property: undefined, node: node, snippet: getCodeSnippet(node, st.handlerCode) }); } }
                },
                MemberExpression(node, st, c) {
                    const { tainted: pathTainted, path: accessedPath, relativePath } = isEventDataAccess(node, st.eventParamName, st.aliasMap, st.taintMap);
                    if (pathTainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') { st.analysis.accessedEventDataPaths.add(relativePath); }
                    if (node.object.type === 'Identifier' && !isLocallyDefined(node.object.name, st.scopeStack) && node.object.name !== st.eventParamName && !state.aliasMap.has(node.object.name)) { const base = node.object.name; const property = node.property.type === 'Identifier' ? node.property.name : (node.property.type === 'Literal' ? node.property.value : '[computed]'); if (!st.analysis.externalStateAccesses.some(e => e.base === base && e.property === property)) { st.analysis.externalStateAccesses.push({ base: base, property: property, node: node, snippet: getCodeSnippet(node, st.handlerCode) }); } }
                    c(node.object, st, "Expression"); c(node.property, st, "Expression");
                },
                CallExpression(node, st, c) {
                    const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode); if (check.isCheck) { st.analysis.originChecks.push(check); }
                    let sinkName = null; let sinkInputNode = null; let sinkSeverity = 'Medium'; let sinkCategory = 'generic';
                    if (node.callee.type === 'Identifier' && node.callee.name === 'eval' && node.arguments.length > 0) { sinkName = 'eval'; sinkInputNode = node.arguments[0]; sinkSeverity = 'Critical'; sinkCategory = 'eval'; }
                    if (sinkName && sinkInputNode) {
                        const { tainted, path: fullInputPath, relativePath } = isEventDataAccess(sinkInputNode, st.eventParamName, st.aliasMap, st.taintMap);
                        if (tainted && relativePath && relativePath !== '(root_data)' && relativePath !== '(parsed_root)') {
                            let conditions = []; const ifStmt = findParentNodeOfType(node, 'IfStatement');
                            if(ifStmt) { conditions = findConditionsForNode(ifStmt.test, st.eventParamName, st.aliasMap, st.taintMap); }
                            const sinkEntry = { name: sinkName, severity: sinkSeverity, category: sinkCategory, node: node, snippet: getCodeSnippet(node, st.handlerCode), fullInputPath: fullInputPath, sourcePath: relativePath, conditions: conditions };
                            st.analysis.potentialSinks.push(sinkEntry);
                            if (!st.analysis.requiredConditions[relativePath]) { st.analysis.requiredConditions[relativePath] = { conditions: [], sinks: [] }; }
                            const reqCondEntry = st.analysis.requiredConditions[relativePath];
                            conditions.forEach(cond => { if (!reqCondEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(cond))) { reqCondEntry.conditions.push(cond); }});
                            if (!reqCondEntry.sinks.includes(sinkName)) { reqCondEntry.sinks.push(sinkName); }
                            st.analysis.accessedEventDataPaths.add(relativePath);
                            conditions.forEach(cond => st.analysis.accessedEventDataPaths.add(cond.path));
                        } else if(tainted) { st.analysis.potentialSinks.push({ name: sinkName, severity: sinkSeverity, category: sinkCategory, node: node, snippet: getCodeSnippet(node, st.handlerCode), fullInputPath: fullInputPath, sourcePath: null, conditions: [] }); }
                    }
                    c(node.callee, st, "Expression"); node.arguments.forEach(arg => c(arg, st, "Expression"));
                },
                IfStatement(node, st, c) {
                    findConditionsForNode(node.test, st.eventParamName, st.aliasMap, st.taintMap).forEach(cond => {
                        st.analysis.accessedEventDataPaths.add(cond.path);
                        if (!st.analysis.requiredConditions[cond.path]) st.analysis.requiredConditions[cond.path] = { conditions: [], sinks: []};
                        if (!st.analysis.requiredConditions[cond.path].conditions.some(c => JSON.stringify(c) === JSON.stringify(cond))) { st.analysis.requiredConditions[cond.path].conditions.push(cond); }
                    });
                    c(node.test, st, "Expression"); c(node.consequent, st, "Statement"); if (node.alternate) { c(node.alternate, st, "Statement"); }
                },
                BinaryExpression(node, st, c) {
                    const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode); if (check.isCheck) { st.analysis.originChecks.push(check); }
                    c(node.left, st, "Expression"); c(node.right, st, "Expression");
                },
                LogicalExpression(node, st, c) {
                    const checkLeft = analyzeOriginCheck(node.left, st.eventParamName, st.aliasMap, st.handlerCode); if (checkLeft.isCheck) { st.analysis.originChecks.push(checkLeft); }
                    const checkRight = analyzeOriginCheck(node.right, st.eventParamName, st.aliasMap, st.handlerCode); if (checkRight.isCheck) { st.analysis.originChecks.push(checkRight); }
                    c(node.left, st, "Expression"); c(node.right, st, "Expression");
                },
                UnaryExpression(node, st, c) {
                    const check = analyzeOriginCheck(node, st.eventParamName, st.aliasMap, st.handlerCode); if (check.isCheck) { st.analysis.originChecks.push(check); }
                    c(node.argument, st, "Expression");
                }
            }, acorn.walk.base);

            analysis.accessedEventDataPaths = Array.from(analysis.accessedEventDataPaths);
            return { success: true, analysis: analysis };

        } catch (e) {
            log.error("[Static Analyzer] Caught Error during analysis walk:", e);
            return { success: false, error: `Static Analysis Walk Error: ${e.message}`, analysis: null };
        }
    };

})(typeof window !== 'undefined' ? window : global);
