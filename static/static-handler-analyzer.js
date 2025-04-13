/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
(function(global) {
    if (typeof global.acorn === 'undefined' || typeof global.acorn.parse !== 'function' || typeof global.acorn?.walk?.simple !== 'function' || typeof global.acorn?.walk?.ancestor !== 'function') {
        console.error("Acorn/Acorn Walk library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn library not found.', analysis: null });
        return;
    }

    let currentSourceMap = '';
    const EVENT_NAMES = /^(event|e|msg|message|evt)$/;
    const ORIGIN_PROP = 'origin';
    const DATA_PROP = 'data';

    function getCodeSnippet(node) {
        if (!node || !node.range || !currentSourceMap) return '';
        try {
            const startOffset = 'var __dummyFunc = '.length;
            const snippet = currentSourceMap.substring(node.range[0] - startOffset, node.range[1] - startOffset);
            return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
        } catch (e) { return '[snippet error]'; }
    }

    function getFullAccessPath(node) {
        let current = node; const path = [];
        while (current) {
            if (current.type === 'MemberExpression') {
                if (current.property.type === 'Identifier' && !current.computed) path.unshift(current.property.name);
                else if (current.property.type === 'Literal' && current.computed) {
                    if (typeof current.property.value === 'string' && /^[a-zA-Z_$][0-9a-zA-Z_$]*$/.test(current.property.value)) path.unshift(current.property.value);
                    else path.unshift(`[${current.property.raw}]`);
                } else path.unshift('[computed]');
                current = current.object;
            } else if (current.type === 'Identifier') { path.unshift(current.name); break; }
            else if (current.type === 'ThisExpression') { path.unshift('this'); break; }
            else if (current.type === 'CallExpression') { path.unshift('()'); current = current.callee; }
            else return null;
        }
        return path.join('.');
    }

    function isEventOriginAccess(node) {
        if (!node || node.type !== 'MemberExpression') return false;
        return node.property?.name === ORIGIN_PROP && node.object?.type === 'Identifier' && EVENT_NAMES.test(node.object.name);
    }

    function isEventDataAccess(node) {
        if (!node || node.type !== 'MemberExpression') return false;
        return node.property?.name === DATA_PROP && node.object?.type === 'Identifier' && EVENT_NAMES.test(node.object.name);
    }

    function findEventDataSourceNode(node) {
        let current = node;
        while (current && current.type === 'MemberExpression') {
            if (isEventDataAccess(current.object)) {
                return node;
            }
            current = current.object;
        }
        if (isEventDataAccess(node)) {
            return node;
        }
        return null;
    }

    function analyzeOriginCheck(node) {
        if (!node) return null;
        let originNode = null; let comparisonValue = null; let checkType = 'Unknown'; let strength = 'Weak'; let comparedValueType = 'Unknown';
        if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.operator)) {
            if (isEventOriginAccess(node.left)) { originNode = node.left; comparisonValue = node.right; }
            else if (isEventOriginAccess(node.right)) { originNode = node.right; comparisonValue = node.left; }
            if (originNode && comparisonValue) { checkType = node.operator === '===' || node.operator === '!==' ? 'Strict Equality' : 'Loose Equality'; strength = node.operator === '===' || node.operator === '!==' ? 'Strong' : 'Medium'; if (comparisonValue.type === 'Literal') { comparedValueType = typeof comparisonValue.value; comparisonValue = comparisonValue.value; } else { comparedValueType = 'Variable/Expression'; comparisonValue = getCodeSnippet(comparisonValue); } }
        } else if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
            const method = node.callee.property.name;
            if (['includes', 'startsWith', 'endsWith', 'indexOf', 'test', 'match'].includes(method)) {
                let targetObject = node.callee.object; let argumentValue = node.arguments.length > 0 ? node.arguments[0] : null;
                if (isEventOriginAccess(targetObject)) { originNode = targetObject; comparisonValue = argumentValue; checkType = `Method Call (.${method})`; strength = 'Weak'; }
                else if (argumentValue && isEventOriginAccess(argumentValue) && targetObject.type === 'Identifier') { originNode = argumentValue; comparisonValue = targetObject; checkType = `Lookup (.${method} on ${targetObject.name})`; strength = 'Medium'; }
                else if (argumentValue && isEventOriginAccess(argumentValue) && method === 'test' && targetObject.type === 'Literal' && targetObject.regex) { originNode = argumentValue; comparisonValue = targetObject.regex.pattern; checkType = `Regex Test`; strength = 'Medium'; comparedValueType = 'RegExp'; }
                if (originNode && comparisonValue && comparisonValue.type === 'Literal') { comparedValueType = typeof comparisonValue.value; comparisonValue = comparisonValue.value; }
                else if (originNode && comparisonValue) { comparedValueType = 'Variable/Expression'; comparisonValue = getCodeSnippet(comparisonValue); }
            }
        }
        if (originNode) { return { type: checkType, strength: strength, value: comparisonValue, valueType: comparedValueType, snippet: getCodeSnippet(node) }; }
        return null;
    }

    function analyzeConditionNode(node) {
        if (!node) return null;
        if (node.type === 'BinaryExpression' && ['===', '!==', '==', '!='].includes(node.operator)) {
            let eventDataSourceNode = findEventDataSourceNode(node.left) || findEventDataSourceNode(node.right);
            let otherNode = null;
            if (eventDataSourceNode === node.left) otherNode = node.right;
            else if (eventDataSourceNode === node.right) otherNode = node.left;

            if (eventDataSourceNode && otherNode) {
                const fullPath = getFullAccessPath(eventDataSourceNode);
                const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                const relativePath = relativePathMatch ? (relativePathMatch[1] || '(root)') : null;
                if (relativePath !== null) {
                    let conditionValue;
                    if (otherNode.type === 'Literal') conditionValue = otherNode.value;
                    else conditionValue = `[EXPRESSION:${getCodeSnippet(otherNode)}]`;
                    return { path: relativePath, op: node.operator, value: conditionValue, conditionSnippet: getCodeSnippet(node) };
                }
            }
            if (node.left.type === 'UnaryExpression' && node.left.operator === 'typeof' && findEventDataSourceNode(node.left.argument) && node.right.type === 'Literal') { const fullPath = getFullAccessPath(node.left.argument); const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/); const relativePath = relativePathMatch?(relativePathMatch[1]||'(root)'):null; if (relativePath!==null) return { path: relativePath, op: 'typeof', value: node.right.value, conditionSnippet: getCodeSnippet(node) }; }
            if (node.right.type === 'UnaryExpression' && node.right.operator === 'typeof' && findEventDataSourceNode(node.right.argument) && node.left.type === 'Literal') { const fullPath = getFullAccessPath(node.right.argument); const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/); const relativePath = relativePathMatch?(relativePathMatch[1]||'(root)'):null; if (relativePath!==null) return { path: relativePath, op: 'typeof', value: node.left.value, conditionSnippet: getCodeSnippet(node) }; }
        } else if (node.type === 'MemberExpression' && findEventDataSourceNode(node)) {
            const fullPath = getFullAccessPath(node);
            const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
            const relativePath = relativePathMatch?.[1];
            if (relativePath) return { path: relativePath, op: 'truthy', conditionSnippet: getCodeSnippet(node) };
        } else if (node.type === 'LogicalExpression' && node.operator === '&&') {
            const leftCond = analyzeConditionNode(node.left); const rightCond = analyzeConditionNode(node.right);
            const conditions = []; if (leftCond) conditions.push(...(Array.isArray(leftCond) ? leftCond : [leftCond])); if (rightCond) conditions.push(...(Array.isArray(rightCond) ? rightCond : [rightCond]));
            return conditions.length > 0 ? conditions : null;
        } else if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
            const calleeObj = node.callee.object;
            const eventDataSourceNode = findEventDataSourceNode(calleeObj);
            if (eventDataSourceNode) {
                const fullPath = getFullAccessPath(eventDataSourceNode);
                const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                const relativePath = relativePathMatch?.[1];
                if (relativePath) {
                    const method = node.callee.property.name;
                    let argValue = '[complex argument]';
                    if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
                        argValue = node.arguments[0].value;
                    }
                    return { path: relativePath, op: `.${method}()`, value: argValue, conditionSnippet: getCodeSnippet(node) };
                }
            }
        }
        return null;
    }

    function extractGuardingConditionsForNode(ancestors) {
        const conditions = [];
        for (let i = ancestors.length - 2; i >= 0; i--) {
            const ancestor = ancestors[i];
            if (['FunctionExpression', 'FunctionDeclaration', 'ArrowFunctionExpression', 'MethodDefinition', 'Program'].includes(ancestor.type)) {
                break;
            }
            if (ancestor.type === 'IfStatement') {
                const conditionData = analyzeConditionNode(ancestor.test);
                if (conditionData) conditions.push(...(Array.isArray(conditionData) ? conditionData : [conditionData]));
            } else if (ancestor.type === 'SwitchCase') {
                if (ancestor.test) {
                    const switchStmt = ancestors[i+1];
                    if (switchStmt?.type === 'SwitchStatement') {
                        const discriminantNode = findEventDataSourceNode(switchStmt.discriminant);
                        if (discriminantNode) {
                            const fullPath = getFullAccessPath(discriminantNode);
                            const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                            const relativePath = relativePathMatch ? (relativePathMatch[1] || '(root)') : null;
                            if (relativePath !== null) {
                                let caseValue;
                                if (ancestor.test.type === 'Literal') caseValue = ancestor.test.value;
                                else caseValue = `[EXPRESSION:${getCodeSnippet(ancestor.test)}]`;
                                conditions.push({ path: relativePath, op: '===', value: caseValue, conditionSnippet: getCodeSnippet(ancestor.test) });
                            }
                        }
                    }
                }
            }
        }
        return conditions.filter((cond, index, self) => cond && index === self.findIndex(c => c && c.path === cond.path && c.op === cond.op && c.value === cond.value && c.conditionSnippet === cond.conditionSnippet));
    }

    global.analyzeHandlerStatically = function(handlerCode) {
        if (!handlerCode || typeof handlerCode !== 'string') {
            return { success: false, error: 'Invalid handler code provided.', analysis: null };
        }
        let ast;
        currentSourceMap = handlerCode;
        try {
            ast = global.acorn.parse(`var __dummyFunc = ${handlerCode}`, { ecmaVersion: 'latest', locations: true, allowReturnOutsideFunction: true, ranges: true });
        } catch (e) {
            currentSourceMap = '';
            return { success: false, error: `Acorn parsing failed: ${e.message}`, analysis: null };
        }

        const analysisResults = {
            accessedEventDataPaths: new Set(),
            dataFlows: [],
            requiredConditions: {},
            originValidationChecks: [],
            hasListener: false
        };
        let foundOriginCheck = false;

        try {
            global.acorn.walk.ancestor(ast, {
                MemberExpression(node, ancestors) {
                    const fullPath = getFullAccessPath(node);
                    const dataMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                    if (dataMatch) {
                        analysisResults.accessedEventDataPaths.add(dataMatch[1] || '(root)');
                    }
                    if (isEventOriginAccess(node)) {
                        analysisResults.hasListener = true;
                        const parent = ancestors[ancestors.length - 2];
                        const originCheckResult = analyzeOriginCheck(parent);
                        if (originCheckResult && !analysisResults.originValidationChecks.some(c => c.snippet === originCheckResult.snippet)) {
                            analysisResults.originValidationChecks.push(originCheckResult);
                            foundOriginCheck = true;
                        }
                    }
                },
                IfStatement(node, ancestors) {
                    analysisResults.hasListener = true;
                    const originCheckResult = analyzeOriginCheck(node.test);
                    if (originCheckResult && !analysisResults.originValidationChecks.some(c => c.snippet === originCheckResult.snippet)) {
                        analysisResults.originValidationChecks.push(originCheckResult);
                        foundOriginCheck = true;
                    }
                },
                CallExpression(node, ancestors) {
                    analysisResults.hasListener = true;
                    const originCheckResult = analyzeOriginCheck(node);
                    if (originCheckResult && !analysisResults.originValidationChecks.some(c => c.snippet === originCheckResult.snippet)) {
                        analysisResults.originValidationChecks.push(originCheckResult);
                        foundOriginCheck = true;
                    }
                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                            const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                            if (sourcePath !== null) {
                                let destinationContext = '(complex callee)';
                                if (node.callee.type === 'Identifier') {
                                    destinationContext = node.callee.name;
                                } else if (node.callee.type === 'MemberExpression') {
                                    destinationContext = getFullAccessPath(node.callee);
                                }
                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath, destinationType: 'CallExpressionArgument', destinationContext: destinationContext,
                                    argIndex: index, requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors),
                                    taintedNodeSnippet: getCodeSnippet(argNode), fullCodeSnippet: getCodeSnippet(node), nodeType: node.type
                                });
                            }
                        }
                    });
                },
                AssignmentExpression(node, ancestors) {
                    analysisResults.hasListener = true;
                    const eventDataSourceNode = findEventDataSourceNode(node.right);
                    if (eventDataSourceNode) {
                        const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                        const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                        const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                        if (sourcePath !== null) {
                            let destinationContext = '(complex assignment target)';
                            if (node.left.type === 'MemberExpression') {
                                destinationContext = getFullAccessPath(node.left);
                            } else if (node.left.type === 'Identifier') {
                                destinationContext = node.left.name;
                            }
                            analysisResults.dataFlows.push({
                                sourcePath: sourcePath, destinationType: 'Assignment', destinationContext: destinationContext,
                                requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors),
                                taintedNodeSnippet: getCodeSnippet(node.right), fullCodeSnippet: getCodeSnippet(node), nodeType: node.type
                            });
                        }
                    }
                },
                NewExpression(node, ancestors) {
                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                            const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                            if (sourcePath !== null) {
                                let destinationContext = '(complex constructor)';
                                if (node.callee.type === 'Identifier') {
                                    destinationContext = `new ${node.callee.name}`;
                                }
                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath, destinationType: 'NewExpressionArgument', destinationContext: destinationContext,
                                    argIndex: index, requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors),
                                    taintedNodeSnippet: getCodeSnippet(argNode), fullCodeSnippet: getCodeSnippet(node), nodeType: node.type
                                });
                            }
                        }
                    });
                }
            });
        } catch (walkError) {
            currentSourceMap = '';
            console.error("Error during AST walk:", walkError);
            return { success: false, error: `AST walk failed: ${walkError.message}`, analysis: null };
        }

        if (analysisResults.hasListener && !foundOriginCheck) {
            analysisResults.originValidationChecks.push({ type: 'Missing', strength: 'Missing', value: null, valueType: 'N/A', snippet: 'No origin check detected in handler.' });
        }
        analysisResults.originValidationChecks = analysisResults.originValidationChecks.filter((c, i, self) => c && i === self.findIndex(ch => ch && ch.type === c.type && ch.value === c.value && ch.strength === c.strength && ch.snippet === c.snippet));
        analysisResults.dataFlows = analysisResults.dataFlows.filter((flow, index, self) => index === self.findIndex(f => f.sourcePath === flow.sourcePath && f.destinationType === flow.destinationType && f.destinationContext === flow.destinationContext && f.argIndex === flow.argIndex && f.fullCodeSnippet === flow.fullCodeSnippet));
        const allEqualityConditions = analysisResults.dataFlows.flatMap(flow => flow.requiredConditionsForFlow || []).filter(cond => cond && (cond.op === '===' || cond.op === '==') && cond.path !== '(root)' && cond.value !== undefined && !String(cond.value).startsWith('[EXPRESSION:'));
        analysisResults.requiredConditions = allEqualityConditions.reduce((acc, cond) => { acc[cond.path] = cond.value; return acc; }, {});
        currentSourceMap = '';
        return { success: true, analysis: analysisResults };
    };

})(typeof window !== 'undefined' ? window : global);
