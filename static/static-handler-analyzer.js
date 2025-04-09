/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-09
 */
window.analyzeHandlerStatically = function(handlerCode) {
    if (typeof window.acorn === 'undefined' || typeof window.acorn.parse !== 'function') {
        return { success: false, error: 'Acorn library not found or invalid.', analysis: null };
    }
    if (typeof window.acorn?.walk?.simple !== 'function' || typeof window.acorn?.walk?.ancestor !== 'function') {
        return { success: false, error: 'Acorn Walk library (simple/ancestor) not found or invalid.', analysis: null };
    }
    if (!handlerCode || typeof handlerCode !== 'string') {
        return { success: false, error: 'Invalid handler code provided.', analysis: null };
    }

    let ast;
    try {
        const parsableCode = `var __dummyFunc = ${handlerCode}`;
        ast = window.acorn.parse(parsableCode, {
            ecmaVersion: 'latest', locations: true, allowReturnOutsideFunction: true, ranges: true
        });
    } catch (e) {
        return { success: false, error: `Acorn parsing failed: ${e.message}`, analysis: null };
    }

    const analysisResults = {
        accessedEventDataPaths: new Set(),
        dataFlows: [],
        requiredConditions: []
    };
    // Assuming handlerCode itself can be used as the source map here for snippets
    const sourceMap = handlerCode;

    function getCodeSnippet(node) {
        if (node && node.range && sourceMap) {
            // Adjust ranges because we parsed `var __dummyFunc = ${handlerCode}`
            const startOffset = 'var __dummyFunc = '.length;
            const snippet = sourceMap.substring(node.range[0] - startOffset, node.range[1] - startOffset);
            return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : '');
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
                // Stop if we hit the dummy function name or the event parameter
                if (current.name === '__dummyFunc' || /^(event|e|msg|message|evt)$/.test(current.name)) {
                    path.unshift(current.name); // Include the event name for context
                    break;
                }
                path.unshift(current.name);
                break; // Should break here unless it's part of a deeper structure like window.x.y
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

        try {
            window.acorn.walk.simple(node, {
                MemberExpression(childNode) {
                    const fullPath = getFullAccessPath(childNode);
                    const match = fullPath?.match(/^(?:event|e|msg|message|evt)\.data(?:\.(.*))?$/);
                    if (match) {
                        foundNode = childNode;
                        throw 'found';
                    }
                }
            });
        } catch (e) {
            if (e !== 'found') throw e;
        }
        if (!foundNode && node.type === 'MemberExpression') {
            const fullPath = getFullAccessPath(node);
            const match = fullPath?.match(/^(?:event|e|msg|message|evt)\.data(?:\.(.*))?$/);
            if (match) {
                foundNode = node;
            }
        }
        return foundNode;
    }

    function extractGuardingConditions(ancestors) {
        const conditions = [];
        for (let i = ancestors.length - 2; i >= 0; i--) {
            const ancestor = ancestors[i];

            if (ancestor.type === 'FunctionExpression' || ancestor.type === 'FunctionDeclaration' || ancestor.type === 'ArrowFunctionExpression' || ancestor.type === 'MethodDefinition') {
                break;
            }

            if (ancestor.type === 'IfStatement') {
                const test = ancestor.test;
                let conditionData = null;

                if (test.type === 'BinaryExpression') {
                    let eventDataSourceNode = findEventDataSourceNode(test.left) || findEventDataSourceNode(test.right);
                    let otherNode = null;
                    if (eventDataSourceNode) {
                        otherNode = (findEventDataSourceNode(test.left)) ? test.right : test.left;
                        const fullPath = getFullAccessPath(eventDataSourceNode);
                        const relativePath = fullPath?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';

                        if (otherNode.type === 'Literal') {
                            conditionData = { path: relativePath, op: test.operator, value: otherNode.value };
                        }
                        else if (test.operator === '===' || test.operator === '==' || test.operator === '!==' || test.operator === '!=') {
                            if (test.left.type === 'UnaryExpression' && test.left.operator === 'typeof' && findEventDataSourceNode(test.left.argument) && test.right.type === 'Literal') {
                                const typeofPath = getFullAccessPath(test.left.argument)?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
                                conditionData = { path: typeofPath, op: 'typeof', value: test.right.value, originalOp: test.operator };
                            } else if (test.right.type === 'UnaryExpression' && test.right.operator === 'typeof' && findEventDataSourceNode(test.right.argument) && test.left.type === 'Literal') {
                                const typeofPath = getFullAccessPath(test.right.argument)?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
                                conditionData = { path: typeofPath, op: 'typeof', value: test.left.value, originalOp: test.operator };
                            }
                        }
                    }
                }
                else if (test.type === 'UnaryExpression' && test.operator === '!') {
                    let eventDataSourceNode = findEventDataSourceNode(test.argument);
                    if (eventDataSourceNode) {
                        const fullPath = getFullAccessPath(eventDataSourceNode);
                        const relativePath = fullPath?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
                        conditionData = { path: relativePath, op: 'falsy' };
                    }
                }
                else if (test.type === 'MemberExpression' || test.type === 'Identifier') {
                    let eventDataSourceNode = findEventDataSourceNode(test);
                    if (eventDataSourceNode) {
                        const fullPath = getFullAccessPath(eventDataSourceNode);
                        const relativePath = fullPath?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
                        conditionData = { path: relativePath, op: 'truthy' };
                    }
                }

                if (conditionData) {
                    conditionData.conditionSnippet = getCodeSnippet(test);
                    conditions.push(conditionData);
                }
            }
        }
        return conditions.reverse();
    }

    window.acorn.walk.ancestor(ast, {
        MemberExpression(node, ancestors) {
            const fullPath = getFullAccessPath(node);
            const match = fullPath?.match(/^(?:event|e|msg|message|evt)\.data\.?(.*)/);
            if (match) {
                analysisResults.accessedEventDataPaths.add(match[1] || '(root)');
            }
        },

        AssignmentExpression(node, ancestors) {
            const eventDataSourceNode = findEventDataSourceNode(node.right);
            if (eventDataSourceNode) {
                const sourcePath = getFullAccessPath(eventDataSourceNode)?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
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
        },

        CallExpression(node, ancestors) {
            node.arguments.forEach((argNode, index) => {
                const eventDataSourceNode = findEventDataSourceNode(argNode);
                if (eventDataSourceNode) {
                    const sourcePath = getFullAccessPath(eventDataSourceNode)?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
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
            });
        },

        NewExpression(node, ancestors) {
            node.arguments.forEach((argNode, index) => {
                const eventDataSourceNode = findEventDataSourceNode(argNode);
                if (eventDataSourceNode) {
                    const sourcePath = getFullAccessPath(eventDataSourceNode)?.replace(/^(?:event|e|msg|message|evt)\.data\.?/, '') || '(root)';
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
            });
        }
    });

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

    analysisResults.requiredConditions = analysisResults.dataFlows
        .flatMap(flow => flow.guardingConditions)
        .filter(cond => cond && (cond.op === '===' || cond.op === '==') && typeof cond.value === 'string')
        .reduce((acc, cond) => {
            if (cond.path !== '(root)') {
                acc[cond.path] = cond.value;
            }
            return acc;
        }, {});


    return {
        success: true,
        analysis: analysisResults // Return the results nested under 'analysis'
    };
};
