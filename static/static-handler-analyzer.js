/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-21
 */
(function(global) {

    if (typeof global.acorn === 'undefined' || typeof global.acorn.parse !== 'function' || typeof global.acorn?.walk?.simple !== 'function' || typeof global.acorn?.walk?.ancestor !== 'function') {
        console.error("Acorn/Acorn Walk library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn library not found.', analysis: null });
        return;
    }

    let currentSourceMap = '';
    let identifiedEventParamName = null;
    const STANDARD_EVENT_NAMES = /^(event|e|msg|message|evt)$/;
    const ORIGIN_PROP = 'origin';
    const DATA_PROP = 'data';

    function getCodeSnippet(node) {
        if (!node || !node.range || !currentSourceMap) return '';
        try {
            const startOffset = 'const __dummyFunc = '.length;
            const snippet = currentSourceMap.substring(node.range[0] - startOffset, node.range[1] - startOffset);
            return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
        } catch (e) { return '[snippet error]'; }
    }

    function getFullAccessPath(node) {
        let current = node; const path = [];
        while (current) {
            if (current.type === 'MemberExpression') {
                if (current.property.type === 'Identifier') path.unshift(current.property.name);
                else if (current.property.type === 'Literal') path.unshift(String(current.property.value));
                else if (current.property.type === 'ThisExpression') path.unshift('this');
                else if (current.property.type === 'CallExpression') path.unshift('[call()]');
                else path.unshift(`[${current.property.type}]`);
                current = current.object;
            } else if (current.type === 'Identifier') {
                path.unshift(current.name);
                current = null;
            } else if (current.type === 'ThisExpression') {
                path.unshift('this');
                current = null;
            } else if (current.type === 'CallExpression') {
                if (current.callee.type === 'Identifier') path.unshift(current.callee.name + '()');
                else if (current.callee.type === 'MemberExpression') path.unshift(getFullAccessPath(current.callee) + '()');
                else path.unshift('[call()]');
                current = null;
            }
            else {
                path.unshift(`[${current.type}]`);
                current = null;
            }
        }
        return path.join('.');
    }

    function isDirectEventPropertyAccess(node, propertyName, eventParamName) {
        if (!eventParamName || !node) return false;
        return node.type === 'MemberExpression' &&
            node.object.type === 'Identifier' &&
            node.object.name === eventParamName &&
            node.property.type === 'Identifier' &&
            node.property.name === propertyName;
    }

    function checkAliasMap(node, targetSource, aliasMap) {
        if (node?.type === 'Identifier' && aliasMap?.has(node.name)) {
            const source = aliasMap.get(node.name);
            if (source === targetSource || (source === identifiedEventParamName && targetSource.startsWith(identifiedEventParamName + '.'))) {
                return true;
            }
            if (targetSource.startsWith(source + '.')) {
                return true;
            }
        }
        return false;
    }


    function isEventOriginAccess(node, eventParamName, aliasMap) {
        if (isDirectEventPropertyAccess(node, ORIGIN_PROP, eventParamName)) return 'direct';
        if (checkAliasMap(node, `${eventParamName}.${ORIGIN_PROP}`, aliasMap)) return 'alias';
        if (node?.type === 'MemberExpression' && node.property?.name === ORIGIN_PROP) {
            if (checkAliasMap(node.object, eventParamName, aliasMap)) return 'alias';
        }
        if (node?.type === 'MemberExpression' && node.object?.type === 'Identifier') {
            if (checkAliasMap(node.object, `${eventParamName}.${ORIGIN_PROP}`, aliasMap)) {
                return 'alias';
            }
            if (aliasMap.has(node.object.name) && aliasMap.get(node.object.name) === eventParamName && node.property?.name === ORIGIN_PROP) {
                return 'alias';
            }
        }
        return false;
    }


    function isEventDataAccess(node, eventParamName, aliasMap) {
        if (!node || !eventParamName) return false;
        let current = node;
        while (current) {
            if (isDirectEventPropertyAccess(current, DATA_PROP, eventParamName)) return true;
            if (current.type === 'Identifier' && current.name === eventParamName) {
                if (aliasMap.has(current.name) && aliasMap.get(current.name) === identifiedEventParamName) return true;
                break;
            }
            if (checkAliasMap(current, `${eventParamName}.${DATA_PROP}`, aliasMap)) return true;
            if (checkAliasMap(current, eventParamName, aliasMap)) return true;
            if (current.type === 'Identifier' && aliasMap.has(current.name) && aliasMap.get(current.name).startsWith('JSON.parse')) return true;

            if (current.type === 'MemberExpression') {
                if (current.property?.name === DATA_PROP && checkAliasMap(current.object, eventParamName, aliasMap)) return true;
                current = current.object;
            } else if (current.type === 'Identifier') {
                if (aliasMap.has(current.name)) {
                    const aliasSource = aliasMap.get(current.name);
                    if(aliasSource === identifiedEventParamName || aliasSource === `${eventParamName}.${DATA_PROP}` || aliasSource.startsWith('JSON.parse')) return true;
                }
                break;
            }
            else {
                break;
            }
        }
        return false;
    }


    function analyzeOriginCheck(node, eventParamName, aliasMap) {
        const checkInfo = {
            isCheck: false, type: 'unknown', comparedValue: null, comparedValueType: 'unknown',
            methodName: null, strength: 'none', negated: false, rawSnippet: getCodeSnippet(node)
        };
        const getStrength = (value) => {
            if (typeof value === 'string') { if (value === '*' || value === 'null') return 'weak'; if (value.startsWith('http://') || value.startsWith('https://')) return 'strong'; } return 'medium';
        };

        if (node.type === 'UnaryExpression' && node.operator === '!') { checkInfo.negated = true; node = node.argument; }

        if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.operator)) {
            let originAccessType = false; let otherNode = null;
            originAccessType = isEventOriginAccess(node.left, eventParamName, aliasMap);
            if (originAccessType) { otherNode = node.right; }
            else { originAccessType = isEventOriginAccess(node.right, eventParamName, aliasMap); if (originAccessType) { otherNode = node.left; } }

            if (originAccessType) {
                checkInfo.isCheck = true; checkInfo.type = 'comparison'; checkInfo.comparedValueType = otherNode.type; checkInfo.negated = checkInfo.negated || node.operator === '!==' || node.operator === '!=';
                if (otherNode.type === 'Literal') { checkInfo.comparedValue = otherNode.value; checkInfo.strength = getStrength(otherNode.value); if(node.operator === '===' || node.operator === '!==') { if(checkInfo.strength === 'medium') checkInfo.strength = 'strong'; } else { if(checkInfo.strength === 'strong') checkInfo.strength = 'medium'; } }
                else if (otherNode.type === 'Identifier') { checkInfo.comparedValue = otherNode.name; checkInfo.strength = 'medium'; }
                else { checkInfo.comparedValue = getCodeSnippet(otherNode); checkInfo.strength = 'medium'; }
                return checkInfo;
            }
        }
        if (node.type === 'CallExpression') {
            const callee = node.callee;
            if (callee.type === 'MemberExpression') {
                const originAccessType = isEventOriginAccess(callee.object, eventParamName, aliasMap);
                if(originAccessType) {
                    checkInfo.methodName = callee.property.name;
                    if (['startsWith', 'endsWith', 'includes', 'indexOf'].includes(checkInfo.methodName) && node.arguments.length > 0) {
                        checkInfo.isCheck = true; checkInfo.type = 'method_call'; checkInfo.comparedValueType = node.arguments[0].type;
                        if (node.arguments[0].type === 'Literal') { checkInfo.comparedValue = node.arguments[0].value; checkInfo.strength = getStrength(node.arguments[0].value); }
                        else { checkInfo.comparedValue = getCodeSnippet(node.arguments[0]); checkInfo.strength = 'medium'; }
                        if (checkInfo.methodName === 'indexOf' && checkInfo.comparedValue === -1) checkInfo.strength = 'weak'; else if (checkInfo.methodName === 'indexOf') checkInfo.strength = 'medium';
                        return checkInfo;
                    }
                }
                else if (node.arguments.length > 0) {
                    const argOriginAccessType = isEventOriginAccess(node.arguments[0], eventParamName, aliasMap);
                    if (argOriginAccessType) {
                        const methodName = callee.property.name;
                        if (methodName === 'includes' || methodName === 'test') {
                            checkInfo.isCheck = true; checkInfo.type = methodName === 'includes' ? 'method_call' : 'regex_test'; checkInfo.methodName = methodName;
                            checkInfo.comparedValue = getCodeSnippet(callee.object); checkInfo.comparedValueType = callee.object.type; checkInfo.strength = 'medium';
                            if(methodName === 'test' && callee.object.type === 'Literal' && callee.object.regex) { if (callee.object.regex.pattern === '^\\*$' || callee.object.regex.pattern === '.*') { checkInfo.strength = 'weak'; } else if (callee.object.regex.pattern.includes('http')) { checkInfo.strength = 'strong'; } }
                            return checkInfo;
                        }
                    }
                }
            }
            if (callee.type === 'Identifier' || callee.type === 'MemberExpression') {
                let originArgFound = false;
                for (const arg of node.arguments) { if (isEventOriginAccess(arg, eventParamName, aliasMap)) { originArgFound = true; break; } }
                if (originArgFound) {
                    checkInfo.isCheck = true; checkInfo.type = 'function_call'; checkInfo.methodName = (callee.type === 'Identifier') ? callee.name : getCodeSnippet(callee);
                    checkInfo.strength = 'medium'; checkInfo.comparedValue = `Arguments: ${node.arguments.length}`; checkInfo.comparedValueType = 'FunctionCallArguments';
                    return checkInfo;
                }
            }
        }
        if (isEventOriginAccess(node, eventParamName, aliasMap)) {
            checkInfo.isCheck = true; checkInfo.type = 'existence'; checkInfo.strength = 'weak'; return checkInfo;
        }
        return checkInfo;
    }

    function findConditionsForNode(testNode, identifiedEventParamName, dataAliases) {
        const conditions = [];
        const MAX_DEPTH = 5;

        function extract(node, depth) {
            if (!node || depth >= MAX_DEPTH) {
                return;
            }

            if (node.type === 'LogicalExpression' && node.operator === '&&') {
                extract(node.left, depth + 1);
                extract(node.right, depth + 1);
            } else if (node.type === 'BinaryExpression' && ['===', '=='].includes(node.operator)) {
                let dataAccessNode = null;
                let literalNode = null;

                if (node.left.type === 'MemberExpression' && isEventDataAccess(node.left, identifiedEventParamName, dataAliases) && node.right.type === 'Literal') {
                    dataAccessNode = node.left;
                    literalNode = node.right;
                }
                else if (node.right.type === 'MemberExpression' && isEventDataAccess(node.right, identifiedEventParamName, dataAliases) && node.left.type === 'Literal') {
                    dataAccessNode = node.right;
                    literalNode = node.left;
                }

                if (dataAccessNode && literalNode && (typeof literalNode.value === 'string' || typeof literalNode.value === 'number' || typeof literalNode.value === 'boolean')) {
                    const fullPath = getFullAccessPath(dataAccessNode);
                    let relativePath = null;
                    if (fullPath && fullPath.startsWith(`${identifiedEventParamName}.${DATA_PROP}.`)) {
                        relativePath = fullPath.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                    } else if (fullPath && dataAccessNode.object?.type === 'Identifier' && dataAliases.has(dataAccessNode.object.name)) {
                        const aliasSource = dataAliases.get(dataAccessNode.object.name);
                        if (aliasSource.startsWith('JSON.parse')) {
                            relativePath = fullPath.substring(dataAccessNode.object.name.length + 1);
                        } else if (aliasSource === `${identifiedEventParamName}.${DATA_PROP}`){
                            relativePath = fullPath.substring(dataAccessNode.object.name.length + 1);
                        }
                    }

                    if (relativePath && relativePath.length > 0) {
                        conditions.push({ path: relativePath, op: node.operator, value: literalNode.value });
                    }
                }
            }
        }

        extract(testNode, 0);
        return conditions;
    }

    global.analyzeHandlerStatically = function(handlerCode, endpoint = '', sinkPatterns = [], context = {}) {
        const analysis = {
            success: false, error: null, identifiedEventParam: null, potentialSinks: [],
            originChecks: [], dataStructure: {}, securityIssues: [], flow: [],
            accessedEventDataPaths: new Set(),
            requiredConditionsForSink: {}
        };
        const originAliases = new Map();
        const dataAliases = new Map();

        identifiedEventParamName = null;
        currentSourceMap = 'const __dummyFunc = ' + handlerCode;

        try {
            const ast = global.acorn.parse(currentSourceMap, { ecmaVersion: 'latest', locations: true, ranges: true });

            acorn.walk.simple(ast, { Function(node) { if (node.params && node.params.length > 0) { for (const param of node.params) { if (param.type === 'Identifier') { if (STANDARD_EVENT_NAMES.test(param.name)) { identifiedEventParamName = param.name; break; } } } } } });
            if (!identifiedEventParamName && context.eventParamName) identifiedEventParamName = context.eventParamName;
            if (!identifiedEventParamName) identifiedEventParamName = 'event';
            analysis.identifiedEventParam = identifiedEventParamName;

            const guards = []; const sinks = [];
            let walkSucceeded = false;

            try {
                console.debug("[Static Analyzer] Starting AST walk...");
                acorn.walk.ancestor(ast, {
                    VariableDeclarator(node, ancestors) {
                        if (node.id?.type === 'Identifier' && node.init) {
                            const varName = node.id.name;
                            if (isDirectEventPropertyAccess(node.init, ORIGIN_PROP, identifiedEventParamName)) { originAliases.set(varName, `${identifiedEventParamName}.${ORIGIN_PROP}`); }
                            else if (isDirectEventPropertyAccess(node.init, DATA_PROP, identifiedEventParamName)) { dataAliases.set(varName, `${identifiedEventParamName}.${DATA_PROP}`); analysis.accessedEventDataPaths.add('(root)'); }
                            else if (node.init.type === 'Identifier' && node.init.name === identifiedEventParamName) { originAliases.set(varName, identifiedEventParamName); dataAliases.set(varName, identifiedEventParamName); }
                            else if (node.init.type === 'MemberExpression' && isEventDataAccess(node.init, identifiedEventParamName, dataAliases)) {
                                const path = getFullAccessPath(node.init);
                                let baseNode = node.init;
                                while(baseNode.type === 'MemberExpression') baseNode = baseNode.object;
                                const baseAlias = baseNode.type === 'Identifier' ? dataAliases.get(baseNode.name) : null;

                                if (path.startsWith(`${identifiedEventParamName}.${DATA_PROP}`)) {
                                    dataAliases.set(varName, path);
                                    const relPath = path.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                    if (relPath) analysis.accessedEventDataPaths.add(relPath); else analysis.accessedEventDataPaths.add('(root)');
                                } else if (baseAlias === `${identifiedEventParamName}.${DATA_PROP}`) {
                                    dataAliases.set(varName, path);
                                    const relativePath = path.startsWith(baseNode.name + '.') ? path.substring(baseNode.name.length + 1) : path;
                                    if (relativePath) analysis.accessedEventDataPaths.add(relativePath);
                                } else if (baseAlias === identifiedEventParamName && path.startsWith(`${baseNode.name}.${DATA_PROP}`)) {
                                    dataAliases.set(varName, path);
                                    const relPath = path.substring(`${baseNode.name}.${DATA_PROP}.`.length);
                                    if(relPath) analysis.accessedEventDataPaths.add(relPath); else analysis.accessedEventDataPaths.add('(root)');
                                }
                            }
                            else if (node.init.type === 'CallExpression' && node.init.callee.type === 'MemberExpression' && node.init.callee.object?.name === 'JSON' && node.init.callee.property?.name === 'parse' && node.init.arguments?.length > 0) {
                                if(isEventDataAccess(node.init.arguments[0], identifiedEventParamName, dataAliases)) {
                                    const sourcePath = getFullAccessPath(node.init.arguments[0]);
                                    dataAliases.set(varName, `JSON.parse(${sourcePath})`); analysis.accessedEventDataPaths.add('(parsed_root)');
                                    let argNode = node.init.arguments[0];
                                    if (argNode.type === 'MemberExpression' && argNode.object?.object?.name === identifiedEventParamName && argNode.object?.property?.name === DATA_PROP){
                                        const parsedPath = getFullAccessPath(argNode).substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                        if(parsedPath) analysis.accessedEventDataPaths.add(`(parsed ${parsedPath})`);
                                    }
                                }
                            }
                        }
                    },
                    AssignmentExpression(node, ancestors) {
                        if (node.left?.type === 'Identifier' && node.right) {
                            const varName = node.left.name;
                            if (isDirectEventPropertyAccess(node.right, ORIGIN_PROP, identifiedEventParamName)) { originAliases.set(varName, `${identifiedEventParamName}.${ORIGIN_PROP}`); }
                            else if (isDirectEventPropertyAccess(node.right, DATA_PROP, identifiedEventParamName)) { dataAliases.set(varName, `${identifiedEventParamName}.${DATA_PROP}`); analysis.accessedEventDataPaths.add('(root)'); }
                            else if (node.right.type === 'Identifier' && node.right.name === identifiedEventParamName) { originAliases.set(varName, identifiedEventParamName); dataAliases.set(varName, identifiedEventParamName); }
                            else if (node.right.type === 'MemberExpression' && isEventDataAccess(node.right, identifiedEventParamName, dataAliases)) {
                                const path = getFullAccessPath(node.right);
                                let baseNode = node.right;
                                while(baseNode.type === 'MemberExpression') baseNode = baseNode.object;
                                const baseAlias = baseNode.type === 'Identifier' ? dataAliases.get(baseNode.name) : null;

                                if (path.startsWith(`${identifiedEventParamName}.${DATA_PROP}`)) {
                                    dataAliases.set(varName, path);
                                    const relPath = path.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                    if (relPath) analysis.accessedEventDataPaths.add(relPath); else analysis.accessedEventDataPaths.add('(root)');
                                } else if (baseAlias === `${identifiedEventParamName}.${DATA_PROP}`) {
                                    dataAliases.set(varName, path);
                                    const relativePath = path.startsWith(baseNode.name + '.') ? path.substring(baseNode.name.length + 1) : path;
                                    if(relativePath) analysis.accessedEventDataPaths.add(relativePath);
                                } else if (baseAlias === identifiedEventParamName && path.startsWith(`${baseNode.name}.${DATA_PROP}`)) {
                                    dataAliases.set(varName, path);
                                    const relPath = path.substring(`${baseNode.name}.${DATA_PROP}.`.length);
                                    if(relPath) analysis.accessedEventDataPaths.add(relPath); else analysis.accessedEventDataPaths.add('(root)');
                                }
                            }
                            else if (node.right.type === 'CallExpression' && node.right.callee.type === 'MemberExpression' && node.right.callee.object?.name === 'JSON' && node.right.callee.property?.name === 'parse' && node.right.arguments?.length > 0) {
                                if(isEventDataAccess(node.right.arguments[0], identifiedEventParamName, dataAliases)) {
                                    const sourcePath = getFullAccessPath(node.right.arguments[0]);
                                    dataAliases.set(varName, `JSON.parse(${sourcePath})`); analysis.accessedEventDataPaths.add('(parsed_root)');
                                    let argNode = node.right.arguments[0];
                                    if (argNode.type === 'MemberExpression' && argNode.object?.object?.name === identifiedEventParamName && argNode.object?.property?.name === DATA_PROP){
                                        const parsedPath = getFullAccessPath(argNode).substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                        if(parsedPath) analysis.accessedEventDataPaths.add(`(parsed ${parsedPath})`);
                                    }
                                }
                            }
                            else if (originAliases.has(varName) && node.right.type === 'CallExpression' && node.right.callee.type === 'MemberExpression' && node.right.callee.object.type === 'Identifier' && node.right.callee.object.name === varName && node.right.callee.property.name === 'toLowerCase') {}
                            else if (originAliases.has(varName)) {}
                        }
                    },
                    MemberExpression(node, ancestors) {
                        if (isEventDataAccess(node, identifiedEventParamName, dataAliases)) {
                            const fullPath = getFullAccessPath(node);
                            let relativePath = null;
                            if (fullPath) {
                                if (fullPath.startsWith(`${identifiedEventParamName}.${DATA_PROP}.`)) {
                                    relativePath = fullPath.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                } else {
                                    let base = node;
                                    while(base && (base.type === 'MemberExpression' || base.type === 'CallExpression')) {
                                        if(base.type === 'MemberExpression') base = base.object;
                                        else if (base.type === 'CallExpression') base = base.callee;
                                        else break;
                                    }
                                    if(base && base.type === 'Identifier') {
                                        const aliasSource = dataAliases.get(base.name);
                                        if(aliasSource === identifiedEventParamName && node.object.type === 'MemberExpression' && node.object.property?.name === DATA_PROP) {
                                            relativePath = getFullAccessPath(node).substring(`${base.name}.${DATA_PROP}.`.length);
                                        } else if (aliasSource === `${identifiedEventParamName}.${DATA_PROP}`) {
                                            relativePath = getFullAccessPath(node).substring(`${base.name}.`.length);
                                        } else if (aliasSource && aliasSource.startsWith(`${identifiedEventParamName}.${DATA_PROP}`)) {
                                            const aliasBasePath = aliasSource.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                            const pathFromAlias = getFullAccessPath(node).substring(`${base.name}.`.length);
                                            relativePath = aliasBasePath ? `${aliasBasePath}.${pathFromAlias}` : pathFromAlias;
                                        } else if (aliasSource && aliasSource.startsWith('JSON.parse')) {
                                            relativePath = getFullAccessPath(node).substring(`${base.name}.`.length);
                                            if(relativePath) analysis.accessedEventDataPaths.add(`(from_parsed ${relativePath})`);
                                        }
                                    }
                                }
                            }

                            if (relativePath && relativePath.length > 0 && relativePath !== 'hasOwnProperty') {
                                analysis.accessedEventDataPaths.add(relativePath);
                            }
                            else if (fullPath === `${identifiedEventParamName}.${DATA_PROP}`) {
                                analysis.accessedEventDataPaths.add('(root)');
                            }

                            const snippet = getCodeSnippet(node);
                            for (const sinkPattern of sinkPatterns) {
                                if (sinkPattern.methods?.includes('ast') || !sinkPattern.methods) {
                                    if (sinkPattern.category === 'innerHTML' && node.property.name === 'innerHTML') {
                                        const parent = ancestors[ancestors.length - 2];
                                        if (parent.type === 'AssignmentExpression' && parent.left === node) {
                                            sinks.push({ node: parent, type: 'sink', name: sinkPattern.name, severity: sinkPattern.severity, snippet: getCodeSnippet(parent), isGuarded: 'unknown', sinkPattern });
                                            analysis.flow.push({ type: 'sink', node: parent, name: sinkPattern.name, targetPath: relativePath || '(root)' });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Identifier(node, ancestors) {
                        if (checkAliasMap(node, `${identifiedEventParamName}.${DATA_PROP}`, dataAliases)) { analysis.accessedEventDataPaths.add('(root)'); }
                        else if (dataAliases.has(node.name) && dataAliases.get(node.name).startsWith('JSON.parse')) { analysis.accessedEventDataPaths.add('(parsed_root)');}
                        else if (dataAliases.has(node.name) && dataAliases.get(node.name) === identifiedEventParamName) {
                        }
                    },
                    BinaryExpression(node, ancestors) { const check = analyzeOriginCheck(node, identifiedEventParamName, originAliases); if (check.isCheck) { guards.push({ node, ...check }); analysis.flow.push({ type: 'check', node, strength: check.strength }); } },
                    CallExpression(node, ancestors) {
                        const check = analyzeOriginCheck(node, identifiedEventParamName, originAliases); if (check.isCheck) { guards.push({ node, ...check }); analysis.flow.push({ type: 'check', node, strength: check.strength }); }

                        let sinkTargetPath = null;

                        for (const sinkPattern of sinkPatterns) {
                            let isSinkMatch = false; let sinkArgNode = null;
                            if (sinkPattern.methods?.includes('ast') && node.callee.type === 'MemberExpression' && typeof sinkPattern.pattern?.test === 'function' && sinkPattern.pattern.test(node.callee.property.name)) {
                                if (node.arguments.length > (sinkPattern.argIndex ?? 0)) {
                                    sinkArgNode = node.arguments[sinkPattern.argIndex ?? 0];
                                    isSinkMatch = isEventDataAccess(sinkArgNode, identifiedEventParamName, dataAliases);
                                }
                            }
                            else if(sinkPattern.name === 'eval' && node.callee.type === 'Identifier' && node.callee.name === 'eval' && node.arguments.length > 0) {
                                sinkArgNode = node.arguments[0];
                                isSinkMatch = isEventDataAccess(sinkArgNode, identifiedEventParamName, dataAliases);
                            }
                            else if(sinkPattern.name === 'JSON.parse' && node.callee.type === 'MemberExpression' && node.callee.object?.name === 'JSON' && node.callee.property?.name === 'parse' && node.arguments.length > 0) {
                                sinkArgNode = node.arguments[0];
                                if (isEventDataAccess(sinkArgNode, identifiedEventParamName, dataAliases)) {
                                    analysis.accessedEventDataPaths.add('(parsed_root)');
                                    let argNode = sinkArgNode;
                                    if (argNode.type === 'MemberExpression' && argNode.object?.object?.name === identifiedEventParamName && argNode.object?.property?.name === DATA_PROP){
                                        const parsedPath = getFullAccessPath(argNode).substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                        if(parsedPath) analysis.accessedEventDataPaths.add(`(parsed ${parsedPath})`);
                                    }
                                }
                            }
                            else if (sinkPattern.methods?.includes('ast') && sinkPattern.nodeType && node.type === sinkPattern.nodeType && typeof sinkPattern.pattern?.test === 'function' && sinkPattern.pattern.test(node.callee?.name) && node.arguments.length > (sinkPattern.argIndex ?? 0) ) {
                                sinkArgNode = node.arguments[sinkPattern.argIndex ?? 0];
                                isSinkMatch = isEventDataAccess(sinkArgNode, identifiedEventParamName, dataAliases);
                            }


                            if(isSinkMatch && sinkArgNode) {
                                const argPath = getFullAccessPath(sinkArgNode);
                                let relativePath = null;
                                if (argPath) {
                                    if (argPath.startsWith(`${identifiedEventParamName}.${DATA_PROP}.`)) {
                                        relativePath = argPath.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                    } else {
                                        let base = sinkArgNode;
                                        let depth = 0;
                                        while(base && (base.type === 'MemberExpression' || base.type === 'CallExpression') && depth < 10) {
                                            if(base.type === 'MemberExpression') base = base.object;
                                            else if (base.type === 'CallExpression') base = base.callee;
                                            else break;
                                            depth++;
                                        }
                                        if(base && base.type === 'Identifier') {
                                            const aliasSource = dataAliases.get(base.name);
                                            if(aliasSource === identifiedEventParamName && sinkArgNode.type === 'MemberExpression' && sinkArgNode.object?.type === 'MemberExpression' && sinkArgNode.object.property?.name === DATA_PROP) {
                                                relativePath = getFullAccessPath(sinkArgNode).substring(`${base.name}.${DATA_PROP}.`.length);
                                            } else if (aliasSource === `${identifiedEventParamName}.${DATA_PROP}`) {
                                                relativePath = getFullAccessPath(sinkArgNode).substring(`${base.name}.`.length);
                                            } else if (aliasSource && aliasSource.startsWith(`${identifiedEventParamName}.${DATA_PROP}`)) {
                                                const aliasBasePath = aliasSource.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                                const pathFromAlias = getFullAccessPath(sinkArgNode).substring(`${base.name}.`.length);
                                                relativePath = aliasBasePath ? `${aliasBasePath}.${pathFromAlias}` : pathFromAlias;
                                            } else if (aliasSource && aliasSource.startsWith('JSON.parse')) {
                                                relativePath = getFullAccessPath(sinkArgNode).substring(`${base.name}.`.length);
                                                if(relativePath) analysis.accessedEventDataPaths.add(`(from_parsed ${relativePath})`);
                                            }
                                        }
                                    }
                                }

                                sinkTargetPath = relativePath || (checkAliasMap(sinkArgNode, `${identifiedEventParamName}.${DATA_PROP}`, dataAliases) ? '(root)' : null);
                                if (sinkTargetPath === null && checkAliasMap(sinkArgNode, `JSON.parse`, dataAliases)) {
                                    sinkTargetPath = '(parsed_root)';
                                }

                                if (sinkTargetPath && sinkTargetPath !== 'hasOwnProperty') {
                                    analysis.accessedEventDataPaths.add(sinkTargetPath);
                                } else if (argPath === identifiedEventParamName) {
                                } else if (!sinkTargetPath){
                                    analysis.accessedEventDataPaths.add('(unknown_expression)');
                                }


                                sinks.push({ node: node, type: 'sink', name: sinkPattern.name, severity: sinkPattern.severity, snippet: getCodeSnippet(node), isGuarded: 'unknown', sinkPattern, targetPath: sinkTargetPath });
                                analysis.flow.push({ type: 'sink', node: node, name: sinkPattern.name, targetPath: sinkTargetPath });
                                break;
                            }
                        }
                    },
                    UnaryExpression(node, ancestors) { const check = analyzeOriginCheck(node, identifiedEventParamName, originAliases); if (check.isCheck) { guards.push({ node, ...check }); analysis.flow.push({ type: 'check', node, strength: check.strength }); } },
                    IfStatement(node, ancestors) {
                        analysis.flow.push({ type: 'control', node, control: 'if' });
                        const testConditions = findConditionsForNode(node.test, identifiedEventParamName, dataAliases);

                        if (testConditions.length > 0) {
                            const consequentSinks = new Map();
                            acorn.walk.simple(node.consequent, {
                                CallExpression(sinkNode) {
                                    if(sinkNode.callee?.name === 'eval' && sinkNode.arguments?.length > 0) {
                                        if(isEventDataAccess(sinkNode.arguments[0], identifiedEventParamName, dataAliases)) {
                                            const argPath = getFullAccessPath(sinkNode.arguments[0]);
                                            let targetPath = null;
                                            if (argPath && argPath.startsWith(`${identifiedEventParamName}.${DATA_PROP}.`)) {
                                                targetPath = argPath.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                            } else if (argPath && sinkNode.arguments[0].type === 'Identifier' && dataAliases.has(sinkNode.arguments[0].name)){
                                                const aliasSource = dataAliases.get(sinkNode.arguments[0].name);
                                                if(aliasSource === `${identifiedEventParamName}.${DATA_PROP}`) {
                                                    targetPath = '(root)';
                                                } else if (aliasSource.startsWith(`${identifiedEventParamName}.${DATA_PROP}`)) {
                                                    targetPath = aliasSource.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                                    if (!targetPath) targetPath = '(root)';
                                                } else if (aliasSource.startsWith('JSON.parse')) {
                                                    targetPath = `(parsed_root_alias)`;
                                                }
                                            }
                                            if (targetPath && targetPath.length > 0) consequentSinks.set(targetPath, sinkNode);
                                        }
                                    }
                                },
                                AssignmentExpression(assignNode){
                                    if (assignNode.left.type === 'MemberExpression' && assignNode.left.property.name === 'innerHTML') {
                                        if (isEventDataAccess(assignNode.right, identifiedEventParamName, dataAliases)) {
                                            const argPath = getFullAccessPath(assignNode.right);
                                            let targetPath = null;
                                            if (argPath && argPath.startsWith(`${identifiedEventParamName}.${DATA_PROP}.`)) {
                                                targetPath = argPath.substring(`${identifiedEventParamName}.${DATA_PROP}.`.length);
                                            }
                                            if (targetPath && targetPath.length > 0) consequentSinks.set(targetPath, assignNode);
                                        }
                                    }
                                }
                            });

                            consequentSinks.forEach((sinkNode, sinkPath) => {
                                if (!analysis.requiredConditionsForSink[sinkPath]) {
                                    analysis.requiredConditionsForSink[sinkPath] = [];
                                }
                                testConditions.forEach(newCond => {
                                    if (!analysis.requiredConditionsForSink[sinkPath].some(existing => JSON.stringify(existing) === JSON.stringify(newCond))) {
                                        analysis.requiredConditionsForSink[sinkPath].push(newCond);
                                    }
                                });
                            });
                        }
                    },
                    LogicalExpression(node, ancestors) {
                        if (node.operator === '&&' || node.operator === '||') {
                            const checkLeft = analyzeOriginCheck(node.left, identifiedEventParamName, originAliases);
                            if (checkLeft.isCheck && !guards.some(g => g.node === node.left)) {
                                guards.push({ node: node.left, ...checkLeft });
                                analysis.flow.push({ type: 'check', node: node.left, strength: checkLeft.strength });
                            }
                            const leftDataConditions = findConditionsForNode(node.left, identifiedEventParamName, dataAliases);
                            if (leftDataConditions.length > 0) {
                            }

                            const checkRight = analyzeOriginCheck(node.right, identifiedEventParamName, originAliases);
                            if (checkRight.isCheck && !guards.some(g => g.node === node.right)) {
                                guards.push({ node: node.right, ...checkRight });
                                analysis.flow.push({ type: 'check', node: node.right, strength: checkRight.strength });
                            }
                            const rightDataConditions = findConditionsForNode(node.right, identifiedEventParamName, dataAliases);
                            if (rightDataConditions.length > 0) {
                            }
                        }
                    },
                    ReturnStatement(node, ancestors) { analysis.flow.push({ type: 'control', node, control: 'return' }); }
                });
                console.debug("[Static Analyzer] AST walk completed successfully.");
                walkSucceeded = true;
            } catch (walkError) {
                analysis.success = false;
                analysis.error = `AST Walk Error: ${walkError.message}. Check console for details.`;
                console.error("[Static Analyzer] AST Walk Error:", walkError);
                console.error("[Static Analyzer] Error occurred near:", walkError.loc ? currentSourceMap.substring(Math.max(0, walkError.pos - 50), Math.min(currentSourceMap.length, walkError.pos + 50)) : "N/A");
                return analysis;
            }

            if(walkSucceeded) {
                analysis.originChecks = guards; analysis.potentialSinks = sinks; analysis.success = true;
                try {
                    console.debug("[Static Analyzer] Starting Sink/Guard Correlation... Current success state:", analysis.success);
                    for(const sink of analysis.potentialSinks) {
                        let isGuarded = false;
                        let nearestGuardStrength = 'none';
                        let guardType = 'none';
                        let contributingGuards = [];

                        try {
                            let currentAncestors = [];
                            acorn.walk.ancestor(ast, {
                                Conditional(guardNode, ancestors) {
                                    if(guardNode.type === 'IfStatement' || guardNode.type === 'ConditionalExpression') {
                                        if(nodeContains(guardNode, sink.node)) {
                                            const originCheck = analysis.originChecks.find(oc => oc.node === guardNode.test || (oc.node.type === 'LogicalExpression' && nodeContains(guardNode.test, oc.node)));
                                            if(originCheck) {
                                                isGuarded = true;
                                                if (!contributingGuards.find(g => g.node === originCheck.node)) contributingGuards.push(originCheck);
                                            }
                                        }
                                    }
                                },
                                IfStatement(guardNode, ancestors) {
                                    if (nodeContains(guardNode.consequent, sink.node)) {
                                        const originCheck = analysis.originChecks.find(oc => oc.node === guardNode.test);
                                        if (originCheck) {
                                            isGuarded = true;
                                            if (!contributingGuards.find(g => g.node === originCheck.node)) contributingGuards.push(originCheck);
                                        }
                                    }
                                },
                                LogicalExpression(guardNode, ancestors) {
                                    if (guardNode.end < sink.node.start) {
                                        const originCheckLeft = analysis.originChecks.find(oc => oc.node === guardNode.left);
                                        if (originCheckLeft) { if (!contributingGuards.find(g => g.node === originCheckLeft.node)) contributingGuards.push(originCheckLeft); isGuarded = true; }
                                        const originCheckRight = analysis.originChecks.find(oc => oc.node === guardNode.right);
                                        if (originCheckRight) { if (!contributingGuards.find(g => g.node === originCheckRight.node)) contributingGuards.push(originCheckRight); isGuarded = true; }
                                    }
                                }
                            }, null, ast);

                            if (isGuarded && contributingGuards.length > 0) {
                                const strengths = contributingGuards.map(g => g.strength);
                                if (strengths.includes('strong')) nearestGuardStrength = 'strong';
                                else if (strengths.includes('medium')) nearestGuardStrength = 'medium';
                                else if (strengths.includes('weak')) nearestGuardStrength = 'weak';
                                guardType = contributingGuards.map(g => g.type).filter((v,i,a)=>a.indexOf(v)===i).join(', ');
                            }

                        } catch(correlationWalkError) {
                            console.error(`[Static Analyzer] Error during correlation walk for sink ${sink.name}:`, correlationWalkError);
                        }

                        if (isGuarded && ['strong', 'medium'].includes(nearestGuardStrength)) {
                            sink.isGuarded = 'yes';
                        } else if (analysis.originChecks.length > 0 || contributingGuards.length > 0) {
                            sink.isGuarded = nearestGuardStrength === 'weak' ? 'weak_guard' : 'partial';
                        } else {
                            sink.isGuarded = 'no';
                        }

                        if (sink.isGuarded !== 'yes') {
                            const existingIssueIndex = analysis.securityIssues.findIndex(iss => iss.sinkSnippet === sink.snippet);
                            if (existingIssueIndex === -1) {
                                analysis.securityIssues.push({
                                    type: 'Origin Validation Issue',
                                    severity: sink.severity || 'Medium',
                                    description: `Potential sink '${sink.name}' using event.data (target: ${sink.targetPath || 'N/A'}) might be executed without strong origin validation. Guard status: ${sink.isGuarded}.`,
                                    guardStatus: sink.isGuarded,
                                    guardType: guardType,
                                    sinkSnippet: sink.snippet,
                                    checksFound: analysis.originChecks.length,
                                    targetPath: sink.targetPath
                                });
                            } else {
                            }
                        }
                    }
                    console.debug("[Static Analyzer] Sink/Guard Correlation finished. Current success state:", analysis.success);
                } catch(correlationError) {
                    analysis.success = false;
                    analysis.error = `Sink/Guard Correlation Error: ${correlationError.message}`;
                    console.error("[Static Analyzer] Sink/Guard Correlation Error:", correlationError);
                }

                if (analysis.success) {
                    try {
                        console.debug("[Static Analyzer] Starting Regex Sink Detection... Current success state:", analysis.success);
                        const currentSinkLocations = new Set(analysis.potentialSinks.filter(s=>s.node).map(s=>`${s.node.range[0]}-${s.node.range[1]}`));

                        for (const sinkPattern of sinkPatterns) {
                            if (sinkPattern.methods?.includes('regex')) {
                                let regex;
                                try { regex = new RegExp(sinkPattern.pattern, 'g'); }
                                catch (e) { console.warn(`Invalid regex pattern skipped: ${sinkPattern.pattern}`); continue; }
                                let match;
                                while ((match = regex.exec(handlerCode)) !== null) {
                                    const matchStartOffset = match.index + 'const __dummyFunc = '.length;
                                    const matchEndOffset = matchStartOffset + match[0].length;
                                    const snippet = handlerCode.substring(Math.max(0, match.index - 30), Math.min(handlerCode.length, match.index + match[0].length + 30));

                                    const alreadyCovered = analysis.potentialSinks.some(astSink =>
                                        astSink.node &&
                                        astSink.node.range &&
                                        astSink.node.range[0] <= matchStartOffset &&
                                        astSink.node.range[1] >= matchEndOffset &&
                                        astSink.name === sinkPattern.name
                                    );

                                    if (!alreadyCovered) {
                                        const existingRegexSink = analysis.potentialSinks.find(regSink =>
                                            regSink.type === 'sink-regex' &&
                                            regSink.name === sinkPattern.name &&
                                            regSink.matchIndex !== undefined && // Ensure matchIndex exists
                                            Math.abs(regSink.matchIndex - match.index) < 10
                                        );

                                        if (!existingRegexSink) {
                                            analysis.potentialSinks.push({
                                                node: null,
                                                type: 'sink-regex',
                                                name: sinkPattern.name,
                                                severity: sinkPattern.severity,
                                                snippet: snippet,
                                                isGuarded: 'unknown',
                                                sinkPattern: sinkPattern,
                                                targetPath: '(regex-detected)',
                                                matchIndex: match.index
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        console.debug("[Static Analyzer] Regex Sink Detection finished. Current success state:", analysis.success);
                    } catch(regexError) {
                        analysis.success = false;
                        analysis.error = `Regex Sink Detection Error: ${regexError.message}`;
                        console.error("[Static Analyzer] Regex Sink Detection Error:", regexError);
                    }
                } else {
                    console.warn("[Static Analyzer] Skipping Regex phase due to previous errors.");
                }

                if(analysis.success) {
                    console.debug("[Static Analyzer] Analysis completed successfully overall.");
                    analysis.error = null;
                } else {
                    console.warn("[Static Analyzer] Analysis marked as failed due to errors during post-walk analysis.");
                    if (!analysis.error) {
                        analysis.error = "Post-walk analysis failed for unknown reason (error message missing).";
                        console.error(analysis.error);
                    }
                }
            } else {
                if (!analysis.error) {
                    analysis.error = "AST walk failed unexpectedly.";
                }
                analysis.success = false;
                console.error("[Static Analyzer] AST walk did not complete successfully.");
            }
        } catch (e) {
            analysis.success = false;
            analysis.error = `Parsing Error: ${e.message}. Check console for details.`;
            console.error("[Static Analyzer] Parsing Error:", e);
            if (e.loc) {
                console.error("[Static Analyzer] Error occurred at Line:", e.loc.line, "Column:", e.loc.column);
                console.error("[Static Analyzer] Code near error:", currentSourceMap.substring(Math.max(0, e.pos - 50), Math.min(currentSourceMap.length, e.pos + 50)));
            }
            analysis.potentialSinks = [];
            analysis.originChecks = [];
            analysis.flow = [];
            analysis.securityIssues = [];
            analysis.accessedEventDataPaths = new Set();
            analysis.requiredConditionsForSink = {};
        }

        const finalAnalysis = {...analysis};
        finalAnalysis.requiredConditions = finalAnalysis.requiredConditionsForSink;

        delete finalAnalysis.originAliases;
        delete finalAnalysis.dataAliases;
        delete finalAnalysis.requiredConditionsForSink;

        console.debug('[Static Analyzer] Returning analysis object:', JSON.stringify(finalAnalysis, (key, value) => {
            if (key === 'node' && value && typeof value === 'object' && value.type) return `[AST Node ${value.type}]`;
            if (key === 'sinkPattern' && value && value.pattern) return {...value, pattern: value.pattern.toString()};
            if (value instanceof Set) return Array.from(value);
            return value;
        }, 2));
        return finalAnalysis;
    };

    global.buildDataStructure = function(handlerCode, eventParamName) {
        const structure = {};
        if (!eventParamName) return { properties: {}, accessCount: 0 };

        try {
            const ast = global.acorn.parse('const __dummyFunc = ' + handlerCode, { ecmaVersion: 'latest', locations: true });
            const dataAliases = new Map();

            acorn.walk.simple(ast, {
                VariableDeclarator(node) {
                    if (node.id?.type === 'Identifier' && node.init) {
                        const varName = node.id.name;
                        if (isDirectEventPropertyAccess(node.init, DATA_PROP, eventParamName)) {
                            dataAliases.set(varName, `${eventParamName}.${DATA_PROP}`);
                        } else if (node.init.type === 'CallExpression' && node.init.callee.type === 'MemberExpression' && node.init.callee.object?.name === 'JSON' && node.init.callee.property?.name === 'parse' && node.init.arguments?.length > 0) {
                            if(isEventDataAccess(node.init.arguments[0], eventParamName, dataAliases)) {
                                dataAliases.set(varName, 'JSON.parse(...)');
                            }
                        }
                    }
                },
                AssignmentExpression(node) {
                    if (node.left?.type === 'Identifier' && node.right) {
                        const varName = node.left.name;
                        if (isDirectEventPropertyAccess(node.right, DATA_PROP, eventParamName)) {
                            dataAliases.set(varName, `${eventParamName}.${DATA_PROP}`);
                        }
                    }
                }
            });

            acorn.walk.ancestor(ast, {
                MemberExpression(node, ancestors) {
                    let baseObjectNode = node.object;
                    let isDirectData = false;
                    let isAliasData = false;
                    let aliasName = null;

                    if (baseObjectNode.type === 'Identifier' && baseObjectNode.name === eventParamName) {
                        if (node.property?.name === DATA_PROP) isDirectData = true;
                    } else if (baseObjectNode.type === 'MemberExpression' && baseObjectNode.object?.type === 'Identifier' && baseObjectNode.object.name === eventParamName && baseObjectNode.property?.name === DATA_PROP) {
                        isDirectData = true;
                        baseObjectNode = node;
                    } else if (baseObjectNode.type === 'Identifier' && dataAliases.has(baseObjectNode.name)) {
                        const aliasSource = dataAliases.get(baseObjectNode.name);
                        if (aliasSource === `${eventParamName}.${DATA_PROP}` || aliasSource.startsWith('JSON.parse')) {
                            isAliasData = true;
                            aliasName = baseObjectNode.name;
                            baseObjectNode = node;
                        }
                    }

                    if (isDirectData || isAliasData) {
                        const fullPath = getFullAccessPath(baseObjectNode);
                        if (fullPath) {
                            let pathParts = [];
                            if (isDirectData && fullPath.startsWith(`${eventParamName}.${DATA_PROP}.`)) {
                                pathParts = fullPath.split('.').slice(2);
                            } else if (isAliasData && fullPath.startsWith(`${aliasName}.`)) {
                                pathParts = fullPath.split('.').slice(1);
                            } else if (isDirectData && baseObjectNode.type === 'MemberExpression' && baseObjectNode.object.name === eventParamName && baseObjectNode.property.name === DATA_PROP && ancestors.length > 1) {
                            }

                            if (pathParts.length >= 0) {
                                updateStructure(structure, pathParts, node, handlerCode, ancestors);
                            }
                        }
                    }
                }
            });
        } catch (e) { console.error("Error building data structure:", e); }
        if (!structure.properties) structure.properties = {};
        if (structure.accessCount === undefined) structure.accessCount = 0;

        return structure;
    }

    function updateStructure(obj, pathParts, node, source, ancestors) {
        let current = obj;
        if (!current.properties) { current.properties = {}; }
        if (current.accessCount === undefined) { current.accessCount = 0;}
        current.accessCount++;

        let currentLevel = current.properties;

        for (let i = 0; i < pathParts.length; i++) {
            const part = pathParts[i];
            const isLastPart = i === pathParts.length - 1;

            let currentPart = part;
            if(part.startsWith('[') && part.endsWith(']')) {
                currentPart = part.substring(1, part.length -1);
                if((currentPart.startsWith("'") && currentPart.endsWith("'")) || (currentPart.startsWith('"') && currentPart.endsWith('"'))) {
                    currentPart = currentPart.substring(1, currentPart.length -1);
                }
            }

            if (!currentLevel[currentPart]) {
                currentLevel[currentPart] = { name: currentPart, accessCount: 0, expectedType: 'unknown', properties: {}, sampleValues: new Set(), defaultValue: undefined, isArrayItem: /^\d+$/.test(currentPart), itemDetails: null };
            }
            currentLevel[currentPart].accessCount++;

            if (isLastPart) {
                const update = { expectedType: 'unknown', sampleValue: undefined, defaultValue: undefined };
                const parentNode = ancestors[ancestors.length - 2];

                if (parentNode) {
                    if (parentNode.type === 'BinaryExpression') {
                        if (['+', '-', '*', '/'].includes(parentNode.operator)) update.expectedType = 'number';
                        else if (parentNode.operator === '+') update.expectedType = 'string_or_number';
                        else if (['===', '!==', '==', '!='].includes(parentNode.operator)){
                            const otherNode = parentNode.left === node ? parentNode.right : parentNode.left;
                            if(otherNode.type === 'Literal') update.expectedType = typeof otherNode.value;
                            else update.expectedType = 'primitive';
                        }
                    }
                    else if (parentNode.type === 'CallExpression') {
                        if (parentNode.callee?.type === 'MemberExpression') {
                            if (['startsWith', 'endsWith', 'includes', 'toLowerCase', 'toUpperCase', 'slice', 'substring'].includes(parentNode.callee.property?.name)) update.expectedType = 'string';
                        }
                    }
                    else if (parentNode.type === 'AssignmentExpression' && parentNode.right.type === 'Literal') update.sampleValue = parentNode.right.value;
                    else if (parentNode.type === 'IfStatement' || parentNode.type === 'WhileStatement' || parentNode.type === 'LogicalExpression' || parentNode.type === 'UnaryExpression' && parentNode.operator === '!') update.expectedType = 'boolean';
                    else if (parentNode.type === 'MemberExpression' && parentNode.object === node) {
                        if (currentLevel[currentPart].expectedType === 'unknown') {
                            const nextPart = parentNode.property?.name || parentNode.property?.value;
                            if(nextPart && /^\d+$/.test(String(nextPart))) currentLevel[currentPart].expectedType = 'array';
                            else currentLevel[currentPart].expectedType = 'object';
                        }
                    }
                }

                if(update.expectedType && update.expectedType !== 'unknown' && update.expectedType !== 'primitive' && currentLevel[currentPart].expectedType === 'unknown') currentLevel[currentPart].expectedType = update.expectedType;
                if(update.sampleValue !== undefined) {
                    try { currentLevel[currentPart].sampleValues.add(JSON.stringify(update.sampleValue)); } catch (e) { currentLevel[currentPart].sampleValues.add(String(update.sampleValue)); }
                }
                if(update.defaultValue !== undefined && currentLevel[currentPart].defaultValue === undefined) currentLevel[currentPart].defaultValue = update.defaultValue;
            } else {
                if (currentLevel[currentPart].expectedType === 'unknown') {
                    const nextPart = pathParts[i + 1];
                    const isNextArrayIndex = /^\d+$/.test(String(nextPart));
                    currentLevel[currentPart].expectedType = isNextArrayIndex ? 'array' : 'object';
                }

                if (currentLevel[currentPart].expectedType === 'array') {
                    if (!currentLevel[currentPart].itemDetails) {
                        currentLevel[currentPart].itemDetails = { expectedType: 'unknown', properties: {}, accessCount: 0, sampleValues: new Set() };
                    }
                    current = currentLevel[currentPart].itemDetails;
                    currentLevel = current.properties;
                } else if (currentLevel[currentPart].expectedType === 'object') {
                    if (!currentLevel[currentPart].properties) currentLevel[currentPart].properties = {};
                    current = currentLevel[currentPart];
                    currentLevel = current.properties;
                } else {
                    return;
                }
            }
        }
    }

    function nodeContains(outerNode, innerNode) {
        if (!outerNode || !innerNode || !outerNode.range || !innerNode.range) {
            return false;
        }
        return outerNode.range[0] <= innerNode.range[0] && outerNode.range[1] >= innerNode.range[1];
    }

})(typeof window !== 'undefined' ? window : global);
