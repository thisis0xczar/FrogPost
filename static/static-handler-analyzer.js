/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-15 - Simplified Acorn wrapper
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

    function isEventObject(objectNode) {
        if (!objectNode || objectNode.type !== 'Identifier') return false;
        return objectNode.name === identifiedEventParamName || STANDARD_EVENT_NAMES.test(objectNode.name);
    }

    function isSpecificPropertyAccess(node, propName) {
        if (!node || node.type !== 'MemberExpression') return false;
        if (node.property?.name === propName && !node.computed && isEventObject(node.object)) {
            return true;
        }
        if (node.property?.type === 'Literal' && node.property.value === propName && node.computed && isEventObject(node.object)) {
            return true;
        }
        return false;
    }

    function isEventOriginAccess(node) {
        return isSpecificPropertyAccess(node, ORIGIN_PROP);
    }

    function isEventDataAccess(node) {
        return isSpecificPropertyAccess(node, DATA_PROP);
    }

    function findEventDataSourceNode(node) {
        let current = node;
        while (current) {
            if (isEventDataAccess(current)) {
                return current;
            }
            if (current.type === 'MemberExpression') {
                if(isEventDataAccess(current.object)) {
                    return node;
                }
                current = current.object;
            } else if (current.type === 'Identifier') {
                break;
            } else {
                break;
            }
        }
        return null;
    }

    function analyzeOriginCheck(checkNode) {
        if (!checkNode) return null;
        let originNode = null; let comparisonValue = null; let checkType = 'Unknown'; let strength = 'Weak'; let comparedValueType = 'Unknown';
        const node = checkNode;

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
                if (originNode && comparisonValue && comparisonValue?.type === 'Literal') { comparedValueType = typeof comparisonValue.value; comparisonValue = comparisonValue.value; }
                else if (originNode && comparisonValue) { comparedValueType = 'Variable/Expression'; comparisonValue = getCodeSnippet(comparisonValue); }
            }
        }
        if (originNode) {
            return {
                type: checkType, strength: strength, value: comparisonValue, valueType: comparedValueType,
                snippet: getCodeSnippet(node), range: node.range
            };
        }
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
                const eventVarName = identifiedEventParamName || 'event';
                const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                const relativePathMatch = fullPath?.match(pathRegex);
                const relativePath = relativePathMatch ? (relativePathMatch[1] || '(root)') : null;
                if (relativePath !== null) {
                    let conditionValue;
                    if (otherNode.type === 'Literal') conditionValue = otherNode.value;
                    else conditionValue = `[EXPRESSION:${getCodeSnippet(otherNode)}]`;
                    return { path: relativePath, op: node.operator, value: conditionValue, conditionSnippet: getCodeSnippet(node) };
                }
            }
            const typeofArgLeft = node.left.type === 'UnaryExpression' && node.left.operator === 'typeof' ? node.left.argument : null;
            const typeofArgRight = node.right.type === 'UnaryExpression' && node.right.operator === 'typeof' ? node.right.argument : null;

            if (typeofArgLeft && findEventDataSourceNode(typeofArgLeft) && node.right.type === 'Literal') {
                const fullPath = getFullAccessPath(typeofArgLeft);
                const eventVarName = identifiedEventParamName || 'event';
                const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                const relativePathMatch = fullPath?.match(pathRegex);
                const relativePath = relativePathMatch ? (relativePathMatch[1] || '(root)') : null;
                if (relativePath !== null) return { path: relativePath, op: 'typeof', value: node.right.value, conditionSnippet: getCodeSnippet(node) };
            }
            if (typeofArgRight && findEventDataSourceNode(typeofArgRight) && node.left.type === 'Literal') {
                const fullPath = getFullAccessPath(typeofArgRight);
                const eventVarName = identifiedEventParamName || 'event';
                const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                const relativePathMatch = fullPath?.match(pathRegex);
                const relativePath = relativePathMatch ? (relativePathMatch[1] || '(root)') : null;
                if (relativePath !== null) return { path: relativePath, op: 'typeof', value: node.left.value, conditionSnippet: getCodeSnippet(node) };
            }
        } else if (node.type === 'MemberExpression' && findEventDataSourceNode(node)) {
            const fullPath = getFullAccessPath(node);
            const eventVarName = identifiedEventParamName || 'event';
            const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)`);
            const relativePathMatch = fullPath?.match(pathRegex);
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
                const eventVarName = identifiedEventParamName || 'event';
                const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)`);
                const relativePathMatch = fullPath?.match(pathRegex);
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

    function isNodeInsideBlock(targetNode, blockNode) {
        if (!targetNode || !blockNode || !targetNode.range || !blockNode.range) return false;
        return blockNode.range[0] <= targetNode.range[0] && targetNode.range[1] <= blockNode.range[1];
    }

    function extractGuardingConditionsForNode(ancestors, targetNode) {
        const conditions = [];
        for (let i = ancestors.length - 2; i >= 0; i--) {
            const ancestor = ancestors[i];
            const parent = ancestors[i + 1];

            if (['FunctionExpression', 'FunctionDeclaration', 'ArrowFunctionExpression', 'MethodDefinition', 'Program'].includes(ancestor.type)) {
                break;
            }

            if (ancestor.type === 'IfStatement') {
                if (ancestor.consequent && isNodeInsideBlock(targetNode, ancestor.consequent)) {
                    const conditionData = analyzeConditionNode(ancestor.test);
                    if (conditionData) conditions.push(...(Array.isArray(conditionData) ? conditionData : [conditionData]));
                }
            } else if (ancestor.type === 'ConditionalExpression') {
                if (ancestor.consequent && isNodeInsideBlock(targetNode, ancestor.consequent)) {
                    const conditionData = analyzeConditionNode(ancestor.test);
                    if (conditionData) conditions.push(...(Array.isArray(conditionData) ? conditionData : [conditionData]));
                }
            } else if (ancestor.type === 'SwitchCase' && parent?.type === 'SwitchStatement') {
                let caseContainsTarget = false;
                for(const stmt of ancestor.consequent) {
                    if(isNodeInsideBlock(targetNode, stmt)) {
                        caseContainsTarget = true;
                        break;
                    }
                }
                if (caseContainsTarget && ancestor.test) {
                    const switchStmt = parent;
                    const discriminantNode = findEventDataSourceNode(switchStmt.discriminant);
                    if (discriminantNode) {
                        const fullPath = getFullAccessPath(discriminantNode);
                        const eventVarName = identifiedEventParamName || 'event';
                        const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                        const relativePathMatch = fullPath?.match(pathRegex);
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
        return conditions.filter((cond, index, self) =>
                cond && index === self.findIndex(c =>
                    c && c.path === cond.path && c.op === cond.op && c.value === cond.value && c.conditionSnippet === c.conditionSnippet
                )
        );
    }

    global.analyzeHandlerStatically = function(handlerCode) {
        if (!handlerCode || typeof handlerCode !== 'string') {
            return { success: false, error: 'Invalid handler code provided.', analysis: null };
        }
        let ast;
        identifiedEventParamName = null;
        let topLevelFunctionNode = null;

        const codeToParse = `const __dummyFunc = ${handlerCode};`;
        currentSourceMap = handlerCode;

        try {
            ast = global.acorn.parse(codeToParse, {
                ecmaVersion: 'latest',
                locations: true,
                ranges: true,
                allowReturnOutsideFunction: true,
                tolerant: true
            });

            if (ast.body?.[0]?.declarations?.[0]?.init &&
                (ast.body[0].declarations[0].init.type === 'FunctionExpression' ||
                    ast.body[0].declarations[0].init.type === 'ArrowFunctionExpression')) {
                topLevelFunctionNode = ast.body[0].declarations[0].init;
                if (topLevelFunctionNode.params?.[0]?.type === 'Identifier') {
                    identifiedEventParamName = topLevelFunctionNode.params[0].name;
                    log.debug(`[Static Analyzer] Identified event param name: ${identifiedEventParamName}`);
                }
            } else {
                console.warn("[Static Analyzer] Could not find top-level function node using simple wrapper.");
            }

        } catch (e) {
            currentSourceMap = '';
            identifiedEventParamName = null;
            return { success: false, error: `Acorn parsing failed: ${e.message}`, analysis: null };
        }

        const analysisResults = {
            accessedEventDataPaths: new Set(),
            dataFlows: [],
            originValidationChecks: [],
            hasListener: false,
            firstDataAccessRangeStart: null,
            rawOriginChecks: []
        };
        const simpleTaint = new Map();

        try {
            global.acorn.walk.ancestor(ast, {
                Identifier(node, ancestors) {
                    if(simpleTaint.has(node.name)) {
                        const taintSource = simpleTaint.get(node.name);
                        const parent = ancestors[ancestors.length-2];
                        let destinationContext = null;
                        let destinationType = null;
                        let argIndex = undefined;
                        let flowNode = parent;

                        if(parent.type === 'CallExpression' && parent.arguments.includes(node)) {
                            destinationType = 'CallExpressionArgument';
                            if (parent.callee.type === 'Identifier') destinationContext = parent.callee.name;
                            else if (parent.callee.type === 'MemberExpression') destinationContext = getFullAccessPath(parent.callee);
                            else destinationContext = '[complex callee]';
                            argIndex = parent.arguments.indexOf(node);
                        } else if (parent.type === 'NewExpression' && parent.arguments.includes(node)) {
                            destinationType = 'NewExpressionArgument';
                            if (parent.callee.type === 'Identifier') destinationContext = `new ${parent.callee.name}`;
                            else destinationContext = '[complex constructor]';
                            argIndex = parent.arguments.indexOf(node);
                            flowNode = parent;
                        }

                        if (destinationType && destinationContext) {
                            const conditions = extractGuardingConditionsForNode(ancestors, flowNode);
                            analysisResults.dataFlows.push({
                                sourcePath: taintSource.sourcePath, viaVariable: node.name, destinationType: destinationType,
                                destinationContext: destinationContext, argIndex: argIndex, requiredConditionsForFlow: conditions,
                                taintedNodeSnippet: getCodeSnippet(node), fullCodeSnippet: getCodeSnippet(flowNode), nodeType: parent.type
                            });
                        }
                    }
                },
                MemberExpression(node, ancestors) {
                    const fullPath = getFullAccessPath(node);
                    const eventVarName = identifiedEventParamName || 'event';
                    const dataPathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                    const dataMatch = fullPath?.match(dataPathRegex);

                    if (dataMatch) {
                        analysisResults.hasListener = true;
                        analysisResults.accessedEventDataPaths.add(dataMatch[1] || '(root)');
                        if(analysisResults.firstDataAccessRangeStart === null && node.range) {
                            analysisResults.firstDataAccessRangeStart = node.range[0];
                        }
                    }
                    if (isEventOriginAccess(node)) {
                        analysisResults.hasListener = true;
                        const parent = ancestors[ancestors.length - 2];
                        const originCheckResult = analyzeOriginCheck(parent);
                        if (originCheckResult && !analysisResults.rawOriginChecks.some(c => c.snippet === originCheckResult.snippet)) {
                            analysisResults.rawOriginChecks.push(originCheckResult);
                        }
                    }
                },
                IfStatement(node, ancestors) {
                    analysisResults.hasListener = true;
                    const originCheckResult = analyzeOriginCheck(node.test);
                    if (originCheckResult && !analysisResults.rawOriginChecks.some(c => c.snippet === originCheckResult.snippet)) {
                        analysisResults.rawOriginChecks.push(originCheckResult);
                    }
                },
                ConditionalExpression(node, ancestors) {
                    analysisResults.hasListener = true;
                    const originCheckResult = analyzeOriginCheck(node.test);
                    if (originCheckResult && !analysisResults.rawOriginChecks.some(c => c.snippet === originCheckResult.snippet)) {
                        analysisResults.rawOriginChecks.push(originCheckResult);
                    }
                },
                CallExpression(node, ancestors) {
                    analysisResults.hasListener = true;
                    const originCheckResult = analyzeOriginCheck(node);
                    if (originCheckResult && !analysisResults.rawOriginChecks.some(c => c.snippet === originCheckResult.snippet)) {
                        analysisResults.rawOriginChecks.push(originCheckResult);
                    }

                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const eventVarName = identifiedEventParamName || 'event';
                            const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                            const sourcePathMatch = fullSourcePath?.match(pathRegex);
                            const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                            if (sourcePath !== null) {
                                let destinationContext = '[complex callee]';
                                if (node.callee.type === 'Identifier') destinationContext = node.callee.name;
                                else if (node.callee.type === 'MemberExpression') destinationContext = getFullAccessPath(node.callee);

                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath, destinationType: 'CallExpressionArgument', destinationContext: destinationContext,
                                    argIndex: index, requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors, node),
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
                        const eventVarName = identifiedEventParamName || 'event';
                        const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                        const sourcePathMatch = fullSourcePath?.match(pathRegex);
                        const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                        if (sourcePath !== null) {
                            let destinationContext = '[complex assignment target]';
                            if (node.left.type === 'MemberExpression') destinationContext = getFullAccessPath(node.left);
                            else if (node.left.type === 'Identifier') destinationContext = node.left.name;

                            analysisResults.dataFlows.push({
                                sourcePath: sourcePath, destinationType: 'Assignment', destinationContext: destinationContext,
                                requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors, node),
                                taintedNodeSnippet: getCodeSnippet(node.right), fullCodeSnippet: getCodeSnippet(node), nodeType: node.type
                            });

                            if(node.left.type === 'Identifier') {
                                simpleTaint.set(node.left.name, { sourcePath: sourcePath, assignmentNode: node });
                            }
                        }
                    } else if (node.left.type === 'Identifier' && simpleTaint.has(node.left.name)) {
                        simpleTaint.delete(node.left.name);
                    }
                },
                VariableDeclarator(node, ancestors) {
                    if (node.id.type === 'Identifier' && node.init) {
                        const eventDataSourceNode = findEventDataSourceNode(node.init);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const eventVarName = identifiedEventParamName || 'event';
                            const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                            const sourcePathMatch = fullSourcePath?.match(pathRegex);
                            const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                            if (sourcePath !== null) {
                                simpleTaint.set(node.id.name, { sourcePath: sourcePath, assignmentNode: node });
                                analysisResults.hasListener = true;
                            }
                        } else {
                            simpleTaint.delete(node.id.name);
                        }
                    }
                },
                NewExpression(node, ancestors) {
                    analysisResults.hasListener = true;
                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const eventVarName = identifiedEventParamName || 'event';
                            const pathRegex = new RegExp(`^${eventVarName}\\.data\\.?(.+)?`);
                            const sourcePathMatch = fullSourcePath?.match(pathRegex);
                            const sourcePath = sourcePathMatch ? (sourcePathMatch[1] || '(root)') : null;
                            if (sourcePath !== null) {
                                let destinationContext = '[complex constructor]';
                                if (node.callee.type === 'Identifier') destinationContext = `new ${node.callee.name}`;

                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath, destinationType: 'NewExpressionArgument', destinationContext: destinationContext,
                                    argIndex: index, requiredConditionsForFlow: extractGuardingConditionsForNode(ancestors, node),
                                    taintedNodeSnippet: getCodeSnippet(argNode), fullCodeSnippet: getCodeSnippet(node), nodeType: node.type
                                });
                            }
                        }
                    });
                }
            });
        } catch (walkError) {
            currentSourceMap = '';
            identifiedEventParamName = null;
            console.error("Error during AST walk:", walkError);
            return { success: false, error: `AST walk failed: ${walkError.message}`, analysis: null };
        }

        const firstDataPos = analysisResults.firstDataAccessRangeStart ?? Infinity;
        analysisResults.rawOriginChecks.forEach(check => {
            const isBefore = check.range && (check.range[0] < firstDataPos);
            analysisResults.originValidationChecks.push({ ...check, isBeforeDataAccess: isBefore });
        });

        if (analysisResults.hasListener && analysisResults.originValidationChecks.length === 0) {
            analysisResults.originValidationChecks.push({ type: 'Missing', strength: 'Missing', value: null, valueType: 'N/A', snippet: 'No origin check detected in handler.', isBeforeDataAccess: false, range: null });
        }

        analysisResults.dataFlows = analysisResults.dataFlows.filter((flow, index, self) =>
                index === self.findIndex(f =>
                    f.sourcePath === flow.sourcePath &&
                    f.destinationType === flow.destinationType &&
                    f.destinationContext === flow.destinationContext &&
                    f.argIndex === flow.argIndex &&
                    f.fullCodeSnippet === flow.fullCodeSnippet
                )
        );

        const allEqualityConditions = analysisResults.dataFlows
            .flatMap(flow => flow.requiredConditionsForFlow || [])
            .filter(cond => cond && (cond.op === '===' || cond.op === '==') && cond.path !== '(root)' && cond.value !== undefined && !String(cond.value).startsWith('[EXPRESSION:'));
        analysisResults.requiredConditions = allEqualityConditions.reduce((acc, cond) => {
            acc[cond.path] = cond.value;
            return acc;
        }, {});

        delete analysisResults.firstDataAccessRangeStart;
        delete analysisResults.rawOriginChecks;

        currentSourceMap = '';
        identifiedEventParamName = null;
        return { success: true, analysis: analysisResults };
    };

})(typeof window !== 'undefined' ? window : global);
