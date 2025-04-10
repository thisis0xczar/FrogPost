/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-09
 */
(function(global) {
    if (typeof global.acorn === 'undefined' || typeof global.acorn.parse !== 'function') {
        console.error("Acorn library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn library not found.', analysis: null });
        return;
    }
    if (typeof global.acorn?.walk?.simple !== 'function' || typeof global.acorn?.walk?.ancestor !== 'function') {
        console.error("Acorn Walk library not loaded. Static analysis unavailable.");
        global.analyzeHandlerStatically = () => ({ success: false, error: 'Acorn Walk library not found.', analysis: null });
        return;
    }

    let currentSourceMap = '';

    function getCodeSnippet(node) {
        if (node && node.range && currentSourceMap) {
            try {
                const startOffset = 'var __dummyFunc = '.length;
                const snippet = currentSourceMap.substring(node.range[0] - startOffset, node.range[1] - startOffset);
                return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
            } catch (e) {
                return '[snippet error]';
            }
        }
        return '';
    }

    function getFullAccessPath(node) {
        let current = node;
        const path = [];
        while (current) {
            if (current.type === 'MemberExpression') {
                if (current.property.type === 'Identifier' && !current.computed) {
                    path.unshift(current.property.name);
                } else if (current.property.type === 'Literal' && current.computed) {
                    if (typeof current.property.value === 'string') {
                        if (/^[a-zA-Z_$][0-9a-zA-Z_$]*$/.test(current.property.value)) {
                            path.unshift(current.property.value);
                        } else {
                            path.unshift(`[${current.property.raw}]`);
                        }
                    } else {
                        path.unshift(`[${current.property.raw}]`);
                    }
                } else {
                    path.unshift('[computed]');
                }
                current = current.object;
            } else if (current.type === 'Identifier') {
                if (current.name === '__dummyFunc' || /^(event|e|msg|message|evt)$/.test(current.name)) {
                    path.unshift(current.name);
                    break;
                }
                path.unshift(current.name);
                break;
            } else if (current.type === 'ThisExpression') {
                path.unshift('this');
                break;
            } else if (current.type === 'CallExpression') {
                path.unshift('()');
                current = current.callee;
            } else {
                return null;
            }
        }
        return path.join('.');
    }


    function findEventDataSourceNode(node) {
        let foundNode = null;
        if (!node) return null;
        const eventVarNames = /^(event|e|msg|message|evt)$/;

        try {
            global.acorn.walk.simple(node, {
                MemberExpression(childNode) {
                    const obj = childNode.object;
                    if (obj?.type === 'MemberExpression' && obj?.property?.name === 'data' && obj?.object?.type === 'Identifier' && eventVarNames.test(obj.object.name)) {
                        foundNode = childNode;
                        throw 'found';
                    }
                },
            }, undefined, { node: node }); // Pass initial node state if needed by walkers
        } catch (e) {
            if (e !== 'found') console.error("Error during AST walk for event data:", e);
        }

        if (!foundNode && node.type === 'MemberExpression') {
            const fullPath = getFullAccessPath(node);
            if (fullPath?.match(/^(?:event|e|msg|message|evt)\.data/)) {
                foundNode = node;
            }
        }
        return foundNode;
    }

    function analyzeConditionNode(node) {
        if (!node) return null;

        if (node.type === 'BinaryExpression' && (node.operator === '===' || node.operator === '==')) {
            let eventDataSourceNode = findEventDataSourceNode(node.left) || findEventDataSourceNode(node.right);
            let literalNode = null;
            if (eventDataSourceNode === node.left && node.right.type === 'Literal') literalNode = node.right;
            else if (eventDataSourceNode === node.right && node.left.type === 'Literal') literalNode = node.left;

            if (eventDataSourceNode && literalNode) {
                const fullPath = getFullAccessPath(eventDataSourceNode);
                const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                const relativePath = relativePathMatch?.[1] || (fullPath?.endsWith('.data') ? '(root)' : null);

                if (relativePath && relativePath !== '(root)') {
                    return { path: relativePath, op: node.operator, value: literalNode.value, conditionSnippet: getCodeSnippet(node) };
                }
            }

            if (node.left.type === 'UnaryExpression' && node.left.operator === 'typeof' && findEventDataSourceNode(node.left.argument) && node.right.type === 'Literal') {
                const fullPath = getFullAccessPath(node.left.argument);
                const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                const relativePath = relativePathMatch?.[1] || (fullPath?.endsWith('.data') ? '(root)' : null);
                if (relativePath && relativePath !== '(root)') {
                    return { path: relativePath, op: 'typeof', value: node.right.value, conditionSnippet: getCodeSnippet(node) };
                }
            }
            if (node.right.type === 'UnaryExpression' && node.right.operator === 'typeof' && findEventDataSourceNode(node.right.argument) && node.left.type === 'Literal') {
                const fullPath = getFullAccessPath(node.right.argument);
                const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                const relativePath = relativePathMatch?.[1] || (fullPath?.endsWith('.data') ? '(root)' : null);
                if (relativePath && relativePath !== '(root)') {
                    return { path: relativePath, op: 'typeof', value: node.left.value, conditionSnippet: getCodeSnippet(node) };
                }
            }

        } else if (node.type === 'MemberExpression' && getFullAccessPath(node)?.startsWith('event.data')) {
            const fullPath = getFullAccessPath(node);
            const relativePathMatch = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
            const relativePath = relativePathMatch?.[1];
            if (relativePath){
                return { path: relativePath, op: 'truthy', conditionSnippet: getCodeSnippet(node) };
            }

        } else if (node.type === 'LogicalExpression' && node.operator === '&&') {
            const leftCond = analyzeConditionNode(node.left);
            const rightCond = analyzeConditionNode(node.right);
            const conditions = [];
            if (leftCond) conditions.push(...(Array.isArray(leftCond) ? leftCond : [leftCond]));
            if (rightCond) conditions.push(...(Array.isArray(rightCond) ? rightCond : [rightCond]));
            return conditions.length > 0 ? conditions : null;
        }

        return null;
    }


    function extractGuardingConditions(ancestors) {
        const conditions = [];
        for (let i = ancestors.length - 2; i >= 0; i--) {
            const ancestor = ancestors[i];

            if (['FunctionExpression', 'FunctionDeclaration', 'ArrowFunctionExpression', 'MethodDefinition'].includes(ancestor.type)) {
                break;
            }

            if (ancestor.type === 'IfStatement') {
                const conditionData = analyzeConditionNode(ancestor.test);
                if (conditionData) {
                    if (Array.isArray(conditionData)) {
                        conditions.push(...conditionData);
                    } else {
                        conditions.push(conditionData);
                    }
                }
            }
        }

        const uniqueConditions = conditions.filter((cond, index, self) =>
            cond && index === self.findIndex(c => c && c.path === cond.path && c.op === cond.op && c.value === cond.value)
        );
        return uniqueConditions;
    }

    global.analyzeHandlerStatically = function(handlerCode) {
        if (!handlerCode || typeof handlerCode !== 'string') {
            return { success: false, error: 'Invalid handler code provided.', analysis: null };
        }

        let ast;
        currentSourceMap = handlerCode;
        try {
            const parsableCode = `var __dummyFunc = ${handlerCode}`;
            ast = global.acorn.parse(parsableCode, {
                ecmaVersion: 'latest', locations: true, allowReturnOutsideFunction: true, ranges: true
            });
        } catch (e) {
            currentSourceMap = '';
            return { success: false, error: `Acorn parsing failed: ${e.message}`, analysis: null };
        }

        const analysisResults = {
            accessedEventDataPaths: new Set(),
            dataFlows: [],
            requiredConditions: {}
        };

        try {
            global.acorn.walk.ancestor(ast, {
                MemberExpression(node, ancestors) {
                    const fullPath = getFullAccessPath(node);
                    const match = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                    if (match) {
                        const pathToAdd = match[1] || '(root)';
                        analysisResults.accessedEventDataPaths.add(pathToAdd);
                    }
                },

                AssignmentExpression(node, ancestors) {
                    const eventDataSourceNode = findEventDataSourceNode(node.right);
                    if (eventDataSourceNode) {
                        const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                        const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                        const sourcePath = sourcePathMatch?.[1] || (fullSourcePath?.endsWith('.data') ? '(root)' : null);

                        if (sourcePath !== null) {
                            let destinationContext = '(complex assignment target)';
                            if (node.left.type === 'MemberExpression') {
                                destinationContext = getFullAccessPath(node.left);
                            } else if (node.left.type === 'Identifier') {
                                destinationContext = node.left.name;
                            }

                            analysisResults.dataFlows.push({
                                sourcePath: sourcePath,
                                destinationType: 'Assignment',
                                destinationContext: destinationContext,
                                guardingConditions: extractGuardingConditions(ancestors),
                                taintedNodeSnippet: getCodeSnippet(node.right),
                                fullCodeSnippet: getCodeSnippet(node),
                                nodeType: node.type
                            });
                        }
                    }
                },

                CallExpression(node, ancestors) {
                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                            const sourcePath = sourcePathMatch?.[1] || (fullSourcePath?.endsWith('.data') ? '(root)' : null);

                            if (sourcePath !== null) {
                                let destinationContext = '(complex callee)';
                                if (node.callee.type === 'Identifier') {
                                    destinationContext = node.callee.name;
                                } else if (node.callee.type === 'MemberExpression') {
                                    destinationContext = getFullAccessPath(node.callee);
                                }

                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath,
                                    destinationType: 'CallExpressionArgument',
                                    destinationContext: destinationContext,
                                    argIndex: index,
                                    guardingConditions: extractGuardingConditions(ancestors),
                                    taintedNodeSnippet: getCodeSnippet(argNode),
                                    fullCodeSnippet: getCodeSnippet(node),
                                    nodeType: node.type
                                });
                            }
                        }
                    });
                },

                NewExpression(node, ancestors) {
                    node.arguments.forEach((argNode, index) => {
                        const eventDataSourceNode = findEventDataSourceNode(argNode);
                        if (eventDataSourceNode) {
                            const fullSourcePath = getFullAccessPath(eventDataSourceNode);
                            const sourcePathMatch = fullSourcePath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
                            const sourcePath = sourcePathMatch?.[1] || (fullSourcePath?.endsWith('.data') ? '(root)' : null);

                            if (sourcePath !== null) {
                                let destinationContext = '(complex constructor)';
                                if (node.callee.type === 'Identifier') {
                                    destinationContext = `new ${node.callee.name}`;
                                }

                                analysisResults.dataFlows.push({
                                    sourcePath: sourcePath,
                                    destinationType: 'NewExpressionArgument',
                                    destinationContext: destinationContext,
                                    argIndex: index,
                                    guardingConditions: extractGuardingConditions(ancestors),
                                    taintedNodeSnippet: getCodeSnippet(argNode),
                                    fullCodeSnippet: getCodeSnippet(node),
                                    nodeType: node.type
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


        const uniqueDataFlows = analysisResults.dataFlows.filter((flow, index, self) =>
                index === self.findIndex(f =>
                    f.sourcePath === flow.sourcePath &&
                    f.destinationType === flow.destinationType &&
                    f.destinationContext === flow.destinationContext &&
                    f.argIndex === flow.argIndex &&
                    f.fullCodeSnippet === flow.fullCodeSnippet
                )
        );
        analysisResults.dataFlows = uniqueDataFlows;

        const allEqualityConditions = uniqueDataFlows
            .flatMap(flow => flow.guardingConditions || [])
            .filter(cond => cond && (cond.op === '===' || cond.op === '==') && cond.path !== '(root)' && cond.value !== undefined);


        analysisResults.requiredConditions = allEqualityConditions.reduce((acc, cond) => {
            acc[cond.path] = cond.value;
            return acc;
        }, {});

        currentSourceMap = '';
        return {
            success: true,
            analysis: analysisResults
        };
    };

})(typeof window !== 'undefined' ? window : global);
