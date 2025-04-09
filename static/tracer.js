/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-09
 */
class HandlerTracer {
    constructor() {
        // Single source of truth for sink patterns
        this.domXssSinks = [
            // Critical Sinks
            { name: "eval", pattern: /\beval\s*\(/, severity: "Critical", methods: ['regex'] }, // Regex more reliable here
            { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical", methods: ['regex'] },
            { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex'] },
            { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex'] },
            { name: "document.write", pattern: /document\.write/, severity: "Critical", methods: ['regex', 'ast'] }, // Match ending paren optional for regex
            { name: "document.writeln", pattern: /document\.writeln/, severity: "Critical", methods: ['regex', 'ast'] }, // Match ending paren optional for regex
            { name: "window.execScript", pattern: /window\.execScript\s*\(/, severity: "Critical", methods: ['regex'] },
            { name: "DOM_XSS_innerHTML", pattern: /\.innerHTML$/, severity: 'Critical', methods: ['ast'] }, // AST specific pattern
            { name: "DOM_XSS_outerHTML", pattern: /\.outerHTML$/, severity: 'Critical', methods: ['ast'] }, // AST specific pattern
            { name: "EvalInjection_Function_AST", pattern: /^Function$/, severity: 'Critical', methods: ['ast'], nodeType: 'NewExpression' }, // AST specific

            // High Severity Sinks
            { name: "innerHTML assign", pattern: /\.innerHTML\s*[\+\-]?=/, severity: "High", methods: ['regex'] }, // Regex version
            { name: "outerHTML assign", pattern: /\.outerHTML\s*[\+\-]?=/, severity: "High", methods: ['regex'] }, // Regex version
            { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High", methods: ['regex', 'ast'], argIndex: 1 },
            { name: "DOM_XSS_DOMParser", pattern: /DOMParser\.parseFromString$/, severity: 'High', methods: ['ast'], argIndex: 0 },
            { name: "DOMParser innerHTML Regex", pattern: /DOMParser.*innerHTML/, severity: "High", methods: ['regex'] },
            { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High", methods: ['regex'] },
            { name: "OpenRedirect_location_AST", pattern: /\.location$/, severity: 'High', methods: ['ast'] },
            { name: "OpenRedirect_href_AST", pattern: /\.location\.href$/, severity: 'High', methods: ['ast'] },
            { name: "OpenRedirect_assign_AST", pattern: /\.location\.assign$/, severity: 'High', methods: ['ast'] },
            { name: "OpenRedirect_replace_AST", pattern: /\.location\.replace$/, severity: 'High', methods: ['ast'] },
            { name: "location.href assign", pattern: /\.location\.href\s*=/, severity: "High", methods: ['regex'] },
            { name: "CookieManipulation_AST", pattern: /document\.cookie$/, severity: 'High', methods: ['ast'] }, // Assignment check best via AST
            { name: "document.createElement('script')", pattern: /document\.createElement\s*\(\s*['"]script['"]/, severity: "High", methods: ['regex'] },
            { name: "jQuery html", pattern: /\$\(.*\)\.html\s*\(|\$\.[a-zA-Z0-9_]+\.html\s*\(/, severity: "High", methods: ['regex'] },
            { name: "iframe.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'] },
            { name: "script.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'] },
            { name: "srcdoc assignment", pattern: /\.srcdoc\s*=/, severity: "High", methods: ['regex'] },
            { name: "EvalInjection_setTimeout_AST", pattern: /^(?:window\.|self\.|top\.)?setTimeout$/, severity: 'High', methods: ['ast'], argIndex: 0 },
            { name: "EvalInjection_setInterval_AST", pattern: /^(?:window\.|self\.|top\.)?setInterval$/, severity: 'High', methods: ['ast'], argIndex: 0 },

            // Medium Severity Sinks
            { name: "open", pattern: /\.open\s*\(/, severity: "Medium", methods: ['regex'] }, // Simple regex version
            { name: "OpenRedirect_window_open_AST", pattern: /^(?:window\.|self\.|top\.)?open$/, severity: 'Medium', methods: ['ast'], argIndex: 0 }, // AST Version
            { name: "jQuery attr href", pattern: /\$.*?\.attr\s*\(\s*['"]href['"]/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery prop href", pattern: /\$.*?\.prop\s*\(\s*['"]href['"]/, severity: "Medium", methods: ['regex'] },
            { name: "document.domain assignment", pattern: /document\.domain\s*=/, severity: "Medium", methods: ['regex'] },
            { name: "document.cookie assignment", pattern: /document\.cookie\s*=/, severity: "Medium", methods: ['regex'] },
            { name: "createContextualFragment", pattern: /createContextualFragment\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery append", pattern: /\$.*?\.append\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery prepend", pattern: /\$.*?\.prepend\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery after", pattern: /\$.*?\.after\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery before", pattern: /\$.*?\.before\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "element.appendChild", pattern: /\.appendChild\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "element.insertBefore", pattern: /\.insertBefore\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "setAttribute dangerous", pattern: /\.setAttribute\s*\(\s*['"](?:src|href|onclick|onerror|onload|on\w+)['"]/, severity: "Medium", methods: ['regex'] },
            { name: "unsafe template literal", pattern: /`.*?\${(?![^{}]*?encodeURIComponent)(?![^{}]*?escape)/m, severity: "Medium", methods: ['regex'] },
            { name: "Handlebars.compile", pattern: /Handlebars\.compile\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "Vue $compile", pattern: /\$compile\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "Web Worker Regex", pattern: /new\s+Worker\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "Blob URL creation", pattern: /URL\.createObjectURL\s*\(/, severity: "Medium", methods: ['regex'] },
            { name: "Blob constructor", pattern: /new\s+Blob\s*\(\s*\[/, severity: "Medium", methods: ['regex'] },
            { name: "WebSocket URL Regex", pattern: /new\s+WebSocket\s*\((?![^)]*['"]wss?:\/\/)/, severity: "Medium", methods: ['regex'] },
            { name: "JSON.parse", pattern: /JSON\.parse\s*\(/, severity: "Medium", methods: ['regex'] }, // Often safe, but can be entry point
            { name: "element.on* assign", pattern: /\.on(?:error|load|click|mouseover|keydown|submit)\s*=/, severity: "Medium", methods: ['regex'] },
            { name: "jQuery selector XSS", pattern: /\$\s*\(\s*[^"'`]*?(?!\$|jQuery)/, severity: "Medium", methods: ['regex'] }, // Potential if input controls selector
            { name: "URLManipulation_pushState_AST", pattern: /history\.pushState$/, severity: 'Medium', methods: ['ast'], argIndex: 2},
            { name: "URLManipulation_replaceState_AST", pattern: /history\.replaceState$/, severity: 'Medium', methods: ['ast'], argIndex: 2},
            { name: "StorageManipulation_localStorage_AST", pattern: /localStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1 },
            { name: "StorageManipulation_sessionStorage_AST", pattern: /sessionStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1 },

            // Low Severity Sinks
            { name: "localStorage Regex", pattern: /localStorage\.setItem\s*\(|localStorage\[\s*/, severity: "Low", methods: ['regex'] },
            { name: "sessionStorage Regex", pattern: /sessionStorage\.setItem\s*\(|sessionStorage\[\s*/, severity: "Low", methods: ['regex'] },
            { name: "addEventListener other", pattern: /\.addEventListener\s*\(\s*['"](?!message)/, severity: "Low", methods: ['regex'] },
            { name: "URL constructor", pattern: /new\s+URL\s*\(/, severity: "Low", methods: ['regex'] },
            { name: "URL prop manipulation", pattern: /\.(?:searchParams|pathname|hash|search)\s*=/, severity: "Low", methods: ['regex'] },
            { name: "history manipulation Regex", pattern: /history\.(?:pushState|replaceState)\s*\(/, severity: "Low", methods: ['regex'] },
            { name: "WebSocketCreation_AST", pattern: /WebSocket$/, severity: 'Low', methods: ['ast'], nodeType: 'NewExpression', argIndex: 0},
            { name: "PotentialReMessaging_AST", pattern: /postMessage$/, severity: 'Low', methods: ['ast', 'regex']} // Check both ways
        ];

        this.securityChecks = [
            { name: "Missing origin check", pattern: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function|\([^)]*\)\s*=>|[a-zA-Z0-9_$]+)\s*(?:\([^)]*\))?\s*\{(?![^{}]*?(?:\.origin|origin\s*===|origin\s*==|origin\s*!==|origin\s*!=|allowedOrigins|checkOrigin|verifyOrigin))[^{}]*?\}/ms, severity: "High" },
            { name: "Loose origin check", pattern: /\.origin\.(?:indexOf|includes|startsWith|search|match)\s*\(/, severity: "Medium" },
            { name: "Weak origin comparison", pattern: /\.origin\s*(?:==|!=)\s*['"]/, severity: "Medium" },
            { name: "Wildcard origin in postMessage", pattern: /postMessage\s*\([^,]+,\s*['"][\*]['"]\s*\)/, severity: "Medium" },
            { name: "Using window.parent without origin check", pattern: /window\.parent\.postMessage\s*\((?![^)]*origin)/, severity: "Medium" },
            { name: "No message type check", pattern: /addEventListener\s*\(\s*['"]message['"](?![^{]*?\.(?:type|messageType|kind|action))/ms, severity: "Low" },
            { name: "Unsafe object assignment", pattern: /(?:Object\.assign|\.\.\.)[^;]*event\.data/, severity: "Medium" },
            { name: "Unchecked JSON parsing", pattern: /JSON\.parse\s*\([^)]*?\)\s*(?!\.(?:hasOwnProperty|propertyIsEnumerable))/, severity: "Medium" },
            { name: "Dynamic property access", pattern: /\[[^\]]*?\.data\.[^\]]*?\]/, severity: "Medium" },
            { name: "Sensitive information leak", pattern: /postMessage\s*\(\s*(?:document\.cookie|localStorage|sessionStorage)/, severity: "High" },
            { name: "Potential XSS in postMessage", pattern: /postMessage\s*\(\s*['"][^"']*?<[^"']*?(?:script|img|svg|iframe)[^"']*?>[^"']*?['"]/, severity: "High" },
            { name: "Potential prototype pollution", pattern: /(?:Object\.assign\s*\(\s*[^,]+,|Object\.setPrototypeOf|__proto__)/, severity: "Medium" },
            { name: "Dynamic function execution", pattern: /\[['"]\w+['"]\]\s*\([^)]*event\.data/, severity: "High" },
            { name: "this[prop] function call", pattern: /this\s*\[[^\]]+\]\s*\(/, severity: "Medium" }
        ];
        this.handlersMap = new Map();
    }

    isPlainObject(obj) {
        if (typeof obj !== 'object' || obj === null) return false;
        let proto = Object.getPrototypeOf(obj); if (proto === null) return true;
        let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) baseProto = Object.getPrototypeOf(baseProto);
        return proto === baseProto;
    }

    analyzeJsonStructures(messages) {
        const structureMap = new Map(); if (!messages || messages.length === 0) return [];
        for (const message of messages) {
            if (!message) continue;
            try {
                let data = message.data; let dataType = typeof data;
                if (dataType === 'string') { if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) { try { data = JSON.parse(data); dataType = typeof data; } catch (e) {} } }
                if (this.isPlainObject(data)) {
                    const structure = this.getJsonStructure(data); const hash = this.hashJsonStructure(structure);
                    if (!structureMap.has(hash)) { const paths = this.identifyPathsToFuzz(structure); structureMap.set(hash, { structure: structure, examples: [message], pathsToFuzz: paths }); }
                    else { const entry = structureMap.get(hash); if (entry.examples.length < 3) entry.examples.push(message); }
                }
            } catch (error) {}
        }
        return Array.from(structureMap.values());
    }

    getJsonStructure(obj, path = '') {
        if (obj === null || obj === undefined) return { type: 'null', path }; const type = typeof obj; if (type !== 'object') return { type: type, path };
        if (Array.isArray(obj)) { const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` }; return { type: 'array', path, items: itemStructure }; }
        const structure = { type: 'object', path, properties: {} }; const keys = Object.keys(obj).sort();
        for (const key of keys) { const newPath = path ? `${path}.${key}` : key; structure.properties[key] = this.getJsonStructure(obj[key], newPath); }
        return structure;
    }

    hashJsonStructure(structure) {
        if (!structure || !structure.type) return 'invalid'; if (structure.type === 'array') return `array[${this.hashJsonStructure(structure.items)}]`; if (structure.type !== 'object') return structure.type;
        const keys = Object.keys(structure.properties || {}).sort(); return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(',');
    }

    identifyPathsToFuzz(structure, currentPath = '', paths = []) {
        if (!structure) return paths; const nodePath = structure.path || currentPath;
        if (structure.type !== 'object' && structure.type !== 'array') { if (nodePath) paths.push({ path: nodePath, type: structure.type }); return paths; }
        if (structure.type === 'array' && structure.items) { this.identifyPathsToFuzz(structure.items, '', paths); }
        else if (structure.type === 'object' && structure.properties) { for (const key of Object.keys(structure.properties)) this.identifyPathsToFuzz(structure.properties[key], '', paths); }
        const uniquePaths = []; const seenPaths = new Set();
        for (const p of paths) { if (p.path && !seenPaths.has(p.path)) { seenPaths.add(p.path); uniquePaths.push(p); } }
        return uniquePaths;
    }

    checkOriginValidation(handlerCode) {
        if (!handlerCode) return false;
        const originCheckPatterns = [
            /\.origin\s*===?\s*['"][^'"]*['"]/, /\.origin\s*!==?\s*['"][^'"]*['"]/,
            /\.origin\.(?:indexOf|includes|startsWith|endsWith|match)\s*\(/,
            /(?:checkOrigin|validateOrigin|isValidOrigin|verifyOrigin)\s*\(/i,
            /origin(?:Validation|Validator|Check|Checking)\s*\(/i,
            /(?:allowed|trusted|valid)Origin/i, /if\s*\([^)]*\.origin\s*[!=]==/,
            /\btrustedOrigins\b[.\[].*\.(?:includes|indexOf)\(/
        ];
        return originCheckPatterns.some(pattern => pattern.test(handlerCode));
    }

    analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData = null) {
        const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] };
        const foundSinks = new Map(); // type#context -> sinkObject to avoid duplicates

        if (!handlerCode) return vulnerabilities;

        // Regex-based sinks
        this.domXssSinks.filter(p => p.methods.includes('regex')).forEach(sink => {
            let match;
            const regex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || ''));
            while ((match = regex.exec(handlerCode)) !== null) {
                const context = this.extractContext(handlerCode, match.index, match[0].length);
                const key = `${sink.type}#${context}`;
                if (!foundSinks.has(key)) {
                    const sinkData = { type: sink.type, severity: sink.severity, context: context, method: 'regex' };
                    foundSinks.set(key, sinkData);
                }
            }
        });

        // AST-based sinks
        if (staticAnalysisData?.dataFlows) {
            vulnerabilities.dataFlows = staticAnalysisData.dataFlows; // Store flows
            (staticAnalysisData.dataFlows || []).forEach(flow => {
                this.domXssSinks.filter(p => p.methods.includes('ast')).forEach(sinkPattern => {
                    let isMatch = false;
                    if (sinkPattern.nodeType && sinkPattern.nodeType !== flow.nodeType) return;
                    if (sinkPattern.argIndex !== undefined && sinkPattern.argIndex !== flow.argIndex) return;
                    if (sinkPattern.pattern instanceof RegExp) {
                        if (sinkPattern.pattern.test(flow.destinationContext)) isMatch = true;
                    } else if (typeof sinkPattern.pattern === 'string') {
                        if (flow.destinationContext === sinkPattern.pattern) isMatch = true;
                    }
                    if (isMatch) {
                        const context = flow.fullCodeSnippet || flow.taintedNodeSnippet || '';
                        const key = `${sinkPattern.type}#${context}`;
                        if (!foundSinks.has(key)) {
                            const sinkData = {
                                type: sinkPattern.type, severity: sinkPattern.severity,
                                path: flow.sourcePath || '(root)', conditions: flow.guardingConditions || [],
                                context: context, method: 'ast'
                            };
                            foundSinks.set(key, sinkData);
                        }
                        // Only match first pattern for this flow? Maybe not, allow multiple sink types per flow
                        // break; // Re-evaluate if break is needed
                    }
                });
            });
        }

        vulnerabilities.sinks = Array.from(foundSinks.values());

        // Security Issues (Regex based)
        const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]/i.test(handlerCode) ||
            /onmessage\s*=\s*function/i.test(handlerCode) ||
            /function\s*\([^)]*(?:event|e|msg|message|evt)[^)]*\)\s*{.*?\.data/ms.test(handlerCode);
        if (hasMessageListener && !this.checkOriginValidation(handlerCode)) {
            if (!vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) {
                vulnerabilities.securityIssues.push({ type: "Missing origin check", severity: "High", context: "No explicit origin validation found." });
            }
        }
        for (const check of this.securityChecks) {
            if (check.name === "Missing origin check" && vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) continue;
            let match;
            try {
                const flags = [...new Set(['g', 'm', 's', ...(check.pattern.flags?.split('') || [])])].join('');
                const regex = new RegExp(check.pattern.source, flags);
                while ((match = regex.exec(handlerCode)) !== null) {
                    const context = this.extractContext(handlerCode, match.index, match[0].length);
                    if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context === context)) {
                        vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: context });
                    }
                    if (!regex.global) break;
                }
            } catch (e) {}
        }

        return vulnerabilities;
    }

    analyzeDataFlowEnhanced(handlerCode) {
        const dataFlows = []; if (!handlerCode || typeof handlerCode !== 'string') return dataFlows;
        const codeToAnalyze = handlerCode.length > 50000 ? handlerCode.substring(0, 50000) : handlerCode;
        const dataProperties = new Set();
        const assignmentPattern = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:event|e|msg|message|evt)\.data(?:\.([a-zA-Z0-9_$]+)|\[['"`](.+?)['"`]\])?/g;
        let assignmentMatch; while ((assignmentMatch = assignmentPattern.exec(codeToAnalyze)) !== null) { const varName = assignmentMatch[1]; const directProp = assignmentMatch[2]; const bracketProp = assignmentMatch[3]; if (directProp) dataProperties.add({ identifier: varName, sourcePath: `event.data.${directProp}` }); else if (bracketProp) dataProperties.add({ identifier: varName, sourcePath: `event.data.${bracketProp}` }); else dataProperties.add({ identifier: varName, sourcePath: 'event.data' }); }
        const directAccessPattern = /(?:event|e|msg|message|evt)\.data\.([a-zA-Z0-9_$]+(?:(?:\.[a-zA-Z0-9_$]+)|(?:\[.+?\]))?)/g;
        let directMatch; while ((directMatch = directAccessPattern.exec(codeToAnalyze)) !== null) { dataProperties.add({ identifier: `event.data.${directMatch[1]}`, sourcePath: `event.data.${directMatch[1]}` }); }
        if (/(?<!\.)\b(?:event|e|msg|message|evt)\.data\b(?![\.\['])/.test(codeToAnalyze)) { dataProperties.add({ identifier: 'event.data', sourcePath: 'event.data'}); }
        if (dataProperties.size === 0) return dataFlows;
        for (const sink of this.domXssSinks.filter(p=>p.methods.includes('regex'))) { // Check regex sinks here
            const sinkRegex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || '')); let sinkMatch;
            while ((sinkMatch = sinkRegex.exec(codeToAnalyze)) !== null) {
                const sinkContext = this.extractContext(codeToAnalyze, sinkMatch.index, sinkMatch[0].length);
                for (const prop of dataProperties) {
                    const escapedIdentifier = prop.identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    const propUsagePattern = new RegExp(`\\b${escapedIdentifier}\\b`);
                    if (propUsagePattern.test(sinkContext)) {
                        const propertyName = prop.sourcePath.startsWith('event.data.') ? prop.sourcePath.substring('event.data.'.length) : prop.sourcePath;
                        if (!dataFlows.some(df => df.property === propertyName && df.sink === sink.type)) { dataFlows.push({ property: propertyName, sink: sink.type, severity: sink.severity, context: sinkContext }); }
                    }
                }
            }
        }
        return dataFlows;
    }

    extractContext(codeToSearchIn, index, length) {
        const before = Math.max(0, index - 50); const after = Math.min(codeToSearchIn.length, index + length + 50);
        let context = codeToSearchIn.substring(before, after); context = context.replace(/\n|\r/g, "↵").trim();
        if (context.length > 150) context = context.substring(0, 70) + "..." + context.substring(context.length - 70); return context;
    }

    generateFuzzingPayloads(uniqueStructures, vulnerabilities, originalMessages = []) {
        const generatedPayloads = [];
        const MAX_PAYLOADS_TOTAL = 10000;
        const MAX_PAYLOADS_PER_SINK_PATH = 30;
        const MAX_PAYLOADS_PER_DUMB_FIELD = 20;
        const MAX_DUMB_FIELDS_TO_TARGET = 50;
        const handledPaths = new Set();

        if (!Array.isArray(uniqueStructures)) uniqueStructures = [];
        const hasStringMessages = originalMessages.some(msg => typeof msg?.data === 'string');

        const allXssPayloads = window.FuzzingPayloads?.XSS || ['<script>alert("FP_XSS")</script>'];
        const genericXssPayloads = [...allXssPayloads].sort(() => 0.5 - Math.random()).slice(0, 100);

        const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };
        const staticSinks = (vulnerabilities?.sinks || []).filter(s => s.method === 'ast' && s.path && s.path !== '(root)');

        if (uniqueStructures.length === 0 && !hasStringMessages) {
            genericXssPayloads.slice(0, 10).forEach(p => {
                if (generatedPayloads.length < MAX_PAYLOADS_TOTAL)
                    generatedPayloads.push({ type: 'dumb-generic', payload: p, targetFlow: 'generic string', description: 'Generic payload (no structure)' });
            });
            log.debug(`[Payload Gen] No structures/strings, returning ${generatedPayloads.length} generic payloads.`);
            return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
        }

        structureLoop: for (const structure of uniqueStructures) {
            handledPaths.clear();
            const isStaticStructure = structure.source === 'static-analysis';
            const exampleData = structure.examples?.[0]?.data;
            let baseMsgData = exampleData !== undefined ? exampleData : structure.original;

            if (baseMsgData === undefined) continue;
            if (typeof baseMsgData === 'string' && (baseMsgData.startsWith('{') || baseMsgData.startsWith('['))) {
                try { baseMsgData = JSON.parse(baseMsgData); } catch (e) { continue; }
            }

            if (this.isPlainObject(baseMsgData)) {
                const structurePaths = structure.pathsToFuzz || [];
                const sinkPathsForThisStructure = staticSinks
                    .filter(sink => structurePaths.some(p => p.path === sink.path || sink.path.startsWith(p.path + '.') || sink.path.startsWith(p.path + '[')))
                    .sort((a, b) => (severityOrder[b.severity?.toLowerCase()] ?? -1) - (severityOrder[a.severity?.toLowerCase()] ?? -1));

                for (const sink of sinkPathsForThisStructure) {
                    const path = sink.path;
                    if (handledPaths.has(path) || generatedPayloads.length >= MAX_PAYLOADS_TOTAL) continue;

                    let simpleSinkType = sink.type.toLowerCase();
                    if (simpleSinkType.includes('eval') || simpleSinkType.includes('function') || simpleSinkType.includes('script')) simpleSinkType = 'eval';
                    else if (simpleSinkType.includes('innerhtml')) simpleSinkType = 'innerHTML';
                    else if (simpleSinkType.includes('document.write') || simpleSinkType.includes('document.writeln')) simpleSinkType = 'document_write';
                    else if (simpleSinkType.includes('settimeout')) simpleSinkType = 'setTimeout';
                    else if (simpleSinkType.includes('setinterval')) simpleSinkType = 'setInterval';
                    else if (simpleSinkType.includes('location') || simpleSinkType.includes('href')) simpleSinkType = 'location_href';

                    let payloadsToUse = genericXssPayloads;
                    if (simpleSinkType && window.FuzzingPayloads?.SINK_SPECIFIC?.[simpleSinkType]) {
                        payloadsToUse = window.FuzzingPayloads.SINK_SPECIFIC[simpleSinkType];
                        log.handler(`[Payload Gen] Using ${payloadsToUse.length} sink-specific payloads for type "${simpleSinkType}" on path "${path}".`);
                    } else {
                        log.handler(`[Payload Gen] Using generic XSS payloads for sink type "${sink.type}" on path "${path}".`);
                    }

                    const selectedPayloads = [...payloadsToUse].sort(() => 0.5 - Math.random()).slice(0, MAX_PAYLOADS_PER_SINK_PATH);

                    for (const payload of selectedPayloads) {
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                        try {
                            const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                            this.setValueAtPath(modifiedMsg, path, payload);
                            generatedPayloads.push({
                                type: isStaticStructure ? 'smart-static' : 'smart-message',
                                payload: modifiedMsg, targetPath: path, sinkType: sink.type,
                                description: `Targeted payload for ${sink.type} sink via path: ${path}`
                            });
                        } catch (e) { log.debug(`Error generating smart payload for path ${path}:`, e); }
                    }
                    handledPaths.add(path);
                }

                const allStringFields = structurePaths.filter(p => p.type === 'string').map(p => p.path) || [];
                const remainingStringFields = allStringFields.filter(path => !handledPaths.has(path));

                if (remainingStringFields.length > 0) {
                    log.handler(`[Payload Gen] Applying dumb fuzzing to ${remainingStringFields.length} remaining string fields.`);
                    const fieldsToTarget = remainingStringFields.sort(() => 0.5 - Math.random()).slice(0, MAX_DUMB_FIELDS_TO_TARGET);
                    for (const field of fieldsToTarget) {
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                        const selectedPayloads = genericXssPayloads.slice(0, MAX_PAYLOADS_PER_DUMB_FIELD);
                        for (const payload of selectedPayloads) {
                            if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                            try {
                                const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                this.setValueAtPath(modifiedMsg, field, payload);
                                generatedPayloads.push({
                                    type: 'dumb-json', payload: modifiedMsg,
                                    targetFlow: `JSON Field: ${field}`, description: `Dumb XSS targeting string field ${field}`
                                });
                                handledPaths.add(field);
                            } catch (e) { log.debug(`Error generating dumb-json payload for field ${field}:`, e); }
                        }
                    }
                }

            } else if (typeof baseMsgData === 'string') {
                log.handler(`[Payload Gen] Applying dumb string fuzzing.`);
                const originalString = baseMsgData;
                const looksLikeHtml = originalString.includes('<') && originalString.includes('>');
                const payloadsForString = genericXssPayloads.slice(0, looksLikeHtml ? 5 : 15);
                for (const payload of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                    generatedPayloads.push({ type: 'dumb-string-replace', payload: payload, targetFlow: 'string replacement', description: `Dumb XSS replacing original string`, original: originalString });
                    if (!looksLikeHtml && generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: 'dumb-string-append', payload: originalString + payload, targetFlow: 'string append', description: `Dumb XSS appending`, original: originalString });
                    }
                    if (!looksLikeHtml && generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: 'dumb-string-prepend', payload: payload + originalString, targetFlow: 'string prepend', description: `Dumb XSS prepending`, original: originalString });
                    }
                }
            }
        }

        log.debug(`[generateFuzzingPayloads] Final generated payload count: ${generatedPayloads.length}`);
        return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
    }

    setValueAtPath(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) { if (typeof obj === 'string') return value; return; }
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
        let current = obj;
        for (let i = 0; i < parts.length - 1; i++) {
            let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
            const nextPartStr = parts[i + 1]; let nextPartNormalized = nextPartStr;
            if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, '');
            const isNextPartIndex = /^\d+$/.test(nextPartNormalized);
            if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') { current[part] = isNextPartIndex ? [] : {}; }
            current = current[part];
            if (typeof current !== 'object' || current === null) return;
        }
        let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
        if (typeof current === 'object' && current !== null) {
            const isIndex = /^\d+$/.test(lastPart);
            if (Array.isArray(current) && isIndex) current[parseInt(lastPart)] = value;
            else if (!Array.isArray(current)) current[lastPart] = value;
        }
    }

    calculateRiskScore(analysisResults) {
        let penaltyScore = 0; const MAX_PENALTY = 100;
        if (!analysisResults) return 100;
        const sinks = analysisResults.sinks || []; const issues = analysisResults.securityIssues || []; const dataFlows = analysisResults.dataFlows || [];
        let hasCriticalSink = false; let hasHighSink = false;
        sinks.forEach(sink => {
            switch (sink.severity?.toLowerCase()) {
                case 'critical': hasCriticalSink = true; penaltyScore += 35; break;
                case 'high': hasHighSink = true; penaltyScore += 20; break;
                case 'medium': penaltyScore += 8; break;
                case 'low': penaltyScore += 2; break;
                default: penaltyScore += 1; break;
            }
        });
        let hasHighIssue = false; let mediumIssueCount = 0;
        issues.forEach(issue => {
            switch (issue.severity?.toLowerCase()) {
                case 'high': hasHighIssue = true; penaltyScore += 15; break;
                case 'medium': mediumIssueCount++; penaltyScore += 5 + Math.min(mediumIssueCount, 4); break;
                case 'low': penaltyScore += 3; break;
                default: penaltyScore += 1; break;
            }
        });
        if (dataFlows.length > 0) {
            let flowPenalty = 0;
            dataFlows.forEach(flow => {
                switch (flow.severity?.toLowerCase()) {
                    case 'critical': flowPenalty += 5; break; case 'high': flowPenalty += 3; break;
                    case 'medium': flowPenalty += 1; break; default: flowPenalty += 0.5; break;
                }
            });
            penaltyScore += Math.min(flowPenalty, 25);
        }
        if (issues.some(issue => issue.type.toLowerCase().includes('window.parent') && issue.type.toLowerCase().includes('origin check'))) {
            penaltyScore += 10;
        }
        penaltyScore = Math.min(penaltyScore, MAX_PENALTY);
        let finalScore = Math.max(0, 100 - penaltyScore);
        return Math.round(finalScore);
    }
}

if (typeof window !== 'undefined') {
    window.HandlerTracer = HandlerTracer;
}

const traceReportStyles = `
.trace-results-panel {
}
.trace-panel-backdrop {
}
.trace-panel-header {
}
.trace-panel-close {
}
.trace-results-content {
}
.report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; }
.report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); }
.report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; }
.report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; }
.security-score-container { display: flex; justify-content: center; }
.security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); }
.security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; }
.security-score div { position: relative; z-index: 2; }
.security-score-value { font-size: 28px; line-height: 1; }
.security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; }
.security-score.critical { border-color: #e74c3c; }
.security-score.high { border-color: #e67e22; }
.security-score.medium { border-color: #f39c12; }
.security-score.low { border-color: #3498db; }
.security-score.negligible { border-color: #2ecc71; }
.summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; }
.metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; }
.metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; }
.metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; }
.recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; }
.recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; }
.report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; }
.report-code-block pre { margin: 0; }
.report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; }
.report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; }
details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; }
summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; }
summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); }
details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; }
.toggle-icon { font-size: 1.2em; transition: transform 0.2s; }
details[open] .toggle-icon { transform: rotate(90deg); }
.report-details > div { padding: 15px; }
.report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; }
.report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; }
.report-table th { background-color: #2c313a; font-weight: bold; color: #fff; }
.report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px;}
.report-table .context-snippet { max-width: 400px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; }
.severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
.severity-critical { background-color: #e74c3c; color: white; }
.severity-high { background-color: #e67e22; color: white; }
.severity-medium { background-color: #f39c12; color: #333; }
.severity-low { background-color: #3498db; color: white; }
.severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); }
.severity-row-high td { background-color: rgba(230, 126, 34, 0.15); }
.severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); }
.severity-row-low td { background-color: rgba(52, 152, 219, 0.1); }
.no-findings-text { color: #777; font-style: italic; padding: 10px 0; }
.dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; }
.report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; }
.payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; }
.payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; }
.payload-header strong { color: #fff; }
.payload-meta { color: #8be9fd; margin: 0 5px; }
.payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; }
.structure-content { padding: 15px; }
.structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; }
.structure-content strong { color: #00e1ff; }
.structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; }
.show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; }
.show-more-btn:hover { background-color: #4a5058; color: #fff; }
.control-button { }
.secondary-button { }
.error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; }
`;

const progressStyles = `
.trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; }
.trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.phase-list { display: flex; flex-direction: column; gap: 10px; }
.phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; }
.phase .emoji { font-size: 20px; line-height: 1; }
.phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; }
.phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; }
.phase.active .label { color: #fff; font-weight: 600; }
.phase.active .emoji { animation: spin 1s linear infinite; }
.phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; }
.phase.completed .label { color: #50fa7b; }
.phase.completed .emoji::before { content: '✅'; }
.phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; }
.phase.error .label { color: #ff5555; font-weight: 600; }
.phase.error .emoji::before { content: '❌'; }
.phase[data-phase="finished"], .phase[data-phase="error"] { display: none; }
.phase[data-phase="finished"].completed, .phase[data-phase="error"].error { display: flex; }
@keyframes pulse-border {
  0% { border-color: #00e1ff; }
  50% { border-color: rgba(0, 225, 255, 0.5); }
  100% { border-color: #00e1ff; }
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
`;


function addProgressStyles() {
    if (!document.getElementById('frogpost-progress-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'frogpost-progress-styles';
        styleEl.textContent = progressStyles;
        document.head.appendChild(styleEl);
    }
}

function addTraceReportStyles() {
    if (!document.getElementById('frogpost-report-styles')) {
        const styleElement = document.createElement('style');
        styleElement.id = 'frogpost-report-styles';
        styleElement.textContent = traceReportStyles;
        document.head.appendChild(styleElement);
    }
}


async function handleTraceButton(endpoint, traceButton) {
    const originalFullEndpoint = endpoint;
    const endpointKey = getStorageKeyForUrl(originalFullEndpoint);

    traceButton.classList.remove('show-next-step-emoji');
    traceButton.style.animation = '';
    log.handler(`Trace: Starting for original key ${endpointKey}`);

    if (!endpointKey) {
        log.error("Trace: Cannot determine endpoint key", originalFullEndpoint);
        updateTraceButton(traceButton, 'error');
        return;
    }

    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) {
        log.handler(`Trace already in progress for key: ${endpointKey}`);
        return;
    }
    sessionStorage.setItem(traceInProgressKey, 'true');
    log.scan(`Starting message trace for endpoint key: ${endpointKey}`);
    updateTraceButton(traceButton, 'checking');

    const buttonContainer = traceButton.closest('.button-container');
    const playButton = buttonContainer?.querySelector('.iframe-check-button');
    const reportButton = buttonContainer?.querySelector('.iframe-report-button');
    if (playButton) playButton.classList.remove('show-next-step-emoji');

    let progressContainer = document.querySelector('.trace-progress-container');
    if (!progressContainer) {
        addProgressStyles();
        progressContainer = document.createElement('div');
        progressContainer.className = 'trace-progress-container';
        document.body.appendChild(progressContainer);
    }
    progressContainer.innerHTML = `<h4>Trace Analysis Progress</h4><div class="phase-list"><div class="phase" data-phase="collection"><span class="emoji">📦</span><span class="label">Collecting Data</span></div><div class="phase" data-phase="analysis"><span class="emoji">🔬</span><span class="label">Analyzing Handler</span></div><div class="phase" data-phase="structure"><span class="emoji">🧱</span><span class="label">Analyzing Structures</span></div><div class="phase" data-phase="generation"><span class="emoji">⚙️</span><span class="label">Generating Payloads</span></div><div class="phase" data-phase="saving"><span class="emoji">💾</span><span class="label">Saving Report</span></div><div class="phase" data-phase="finished" style="display: none;"><span class="emoji">✅</span><span class="label">Completed</span></div><div class="phase" data-phase="error" style="display: none;"><span class="emoji">❌</span><span class="label">Error Occurred</span></div></div>`;

    const updatePhase = (phase, status = 'active') => {
        const phaseElement = progressContainer?.querySelector(`.phase[data-phase="${phase}"]`);
        if (!phaseElement) return;
        progressContainer?.querySelectorAll('.phase').forEach(el => el.classList.remove('active', 'completed', 'error'));
        phaseElement.classList.add(status);
        if (status === 'error' || status === 'completed') {
            const finalPhase = status === 'error' ? 'error' : 'finished';
            const finalElement = progressContainer?.querySelector(`.phase[data-phase="${finalPhase}"]`);
            if (finalElement) {
                finalElement.style.display = 'flex';
                finalElement.classList.add(status);
            }
        } else {
            progressContainer?.querySelectorAll('.phase[data-phase="finished"], .phase[data-phase="error"]').forEach(el => el.style.display = 'none');
        }
    };

    let hasCriticalSinks = false;
    let endpointUrlUsedForAnalysis = originalFullEndpoint;
    let handlerCode = null;
    let bestHandler = null;
    let analysisStorageKey = endpointKey;
    let report = {};
    let payloads = [];
    let vulnAnalysis = {
        sinks: [],
        securityIssues: [],
        dataFlows: [],
    };
    let uniqueStructures = [];
    let usedStaticAnalysis = false;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) window.handlerTracer = new HandlerTracer();

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;
        analysisStorageKey = getStorageKeyForUrl(endpointUrlUsedForAnalysis);

        log.handler(`[Trace] Effective endpoint URL for analysis/saving report: ${endpointUrlUsedForAnalysis}`);
        log.handler(`[Trace] Storage key derived from analysis URL (for handler/report): ${analysisStorageKey}`);

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;

        if (!handlerCode) throw new Error(`No handler code found in storage (${bestHandlerStorageKey}). Run Play first.`);

        const relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
        log.handler(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));
        vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));
        uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));
        payloads = window.handlerTracer.generateFuzzingPayloads(uniqueStructures, vulnAnalysis, relevantMessages);

        updatePhase('saving');
        const securityScore = window.handlerTracer.calculateRiskScore(vulnAnalysis);

        report = {
            endpoint: endpointUrlUsedForAnalysis,
            originalEndpointKey: endpointKey,
            analysisStorageKey: analysisStorageKey,
            timestamp: new Date().toISOString(),
            analyzedHandler: {
                code: handlerCode,
                category: bestHandler?.category,
                score: bestHandler?.score,
                context: bestHandler?.context
            },
            vulnerabilities: vulnAnalysis.sinks || [],
            securityIssues: vulnAnalysis.securityIssues || [],
            securityScore: securityScore,
            details: {
                analyzedHandler: { code: handlerCode, category: bestHandler?.category, score: bestHandler?.score, context: bestHandler?.context },
                sinks: vulnAnalysis.sinks || [],
                securityIssues: vulnAnalysis.securityIssues || [],
                dataFlows: vulnAnalysis.dataFlows || [],
                payloadsGeneratedCount: payloads.length,
                uniqueStructures: uniqueStructures || []
            },
            summary: {
                messagesAnalyzed: relevantMessages.length,
                patternsIdentified: uniqueStructures.length,
                sinksFound: vulnAnalysis.sinks?.length || 0,
                issuesFound: vulnAnalysis.securityIssues?.length || 0,
                payloadsGenerated: payloads.length,
                securityScore: securityScore
            }
        };

        log.info(`[Trace] Saving report and payloads using storage key: ${analysisStorageKey}`);
        const reportStorageKey = analysisStorageKey;

        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);

        if (!reportSaved || !payloadsSaved) throw new Error("Failed to save trace report or payloads.");
        log.success(`Trace report & ${payloads.length} payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: { success: true, criticalSinks: hasCriticalSinks, analyzedUrl: endpointUrlUsedForAnalysis, analysisStorageKey: analysisStorageKey }
        });
        log.handler(`Saved trace status for UI key ${traceInfoKey}: success=true, criticalSinks=${hasCriticalSinks}, analyzedUrl=${endpointUrlUsedForAnalysis}, storageKey=${analysisStorageKey}`);

        updateTraceButton(traceButton, 'success');
        if (playButton) updateButton(playButton, 'launch', { hasCriticalSinks: hasCriticalSinks, showEmoji: true });
        if (reportButton) {
            const reportState = hasCriticalSinks || report.securityIssues?.length > 0 ? 'green' : 'default';
            updateReportButton(reportButton, reportState, originalFullEndpoint);
        }

        log.info("[Trace] Analysis completed successfully");
        updatePhase('saving', 'completed');

    } catch (error) {
        log.error(`[Trace] Error for ${originalFullEndpoint}:`, error.message, error.stack);
        updateTraceButton(traceButton, 'error');
        const traceInfoKey = `trace-info-${endpointKey}`;
        try {
            await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false } });
        } catch(e) {}

        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
    } finally {
        setTimeout(() => {
            if (progressContainer?.parentNode) progressContainer.parentNode.removeChild(progressContainer);
        }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        log.handler(`[Trace] Finished trace attempt for key ${endpointKey}`);
        setTimeout(() => requestAnimationFrame(updateDashboardUI), 100);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    addTraceReportStyles();
    addProgressStyles();
    if (!window.handlerTracer) {
        window.handlerTracer = new HandlerTracer();
    }
});
window.handleTraceButton = handleTraceButton;
