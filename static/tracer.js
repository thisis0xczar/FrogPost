/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
class HandlerTracer {
    constructor() {
        this.domXssSinks = [
            { name: "eval", pattern: /\beval\s*\(/, severity: "Critical", methods: ['regex'], category: 'eval' },
            { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical", methods: ['regex'], category: 'eval' },
            { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex'], category: 'setTimeout' },
            { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex'], category: 'setInterval' },
            { name: "window.execScript", pattern: /window\.execScript\s*\(/, severity: "Critical", methods: ['regex'], category: 'eval' },
            { name: "element.innerHTML assignment", pattern: /\.innerHTML\s*=/, severity: "High", methods: ['regex'], category: 'innerHTML' },
            { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High", methods: ['regex', 'ast'], argIndex: 1, category: 'innerHTML' },
            { name: "DOM_XSS_DOMParser", pattern: /DOMParser\.parseFromString$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'innerHTML' },
            { name: "DOMParser innerHTML Regex", pattern: /DOMParser.*innerHTML/, severity: "High", methods: ['regex'], category: 'innerHTML' },
            { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High", methods: ['regex'], category: 'location_href' },
            { name: "OpenRedirect_location_AST", pattern: /\.location$/, severity: 'High', methods: ['ast'], category: 'location_href' },
            { name: "OpenRedirect_href_AST", pattern: /\.location\.href$/, severity: 'High', methods: ['ast'], category: 'location_href' },
            { name: "OpenRedirect_assign_AST", pattern: /\.location\.assign$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href' },
            { name: "OpenRedirect_replace_AST", pattern: /\.location\.replace$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href' },
            { name: "location.href assign", pattern: /\.location\.href\s*=/, severity: "High", methods: ['regex'], category: 'location_href' },
            { name: "document.createElement('script')", pattern: /document\.createElement\s*\(\s*['"]script['"]\)/, severity: "High", methods: ['regex'], category: 'script_manipulation' },
            { name: "jQuery html", pattern: /\$\(.*\)\.html\s*\(|\$\.[a-zA-Z0-9_]+\.html\s*\(/, severity: "High", methods: ['regex'], category: 'innerHTML' },
            { name: "iframe.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'], category: 'src_manipulation' },
            { name: "script.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'], category: 'script_manipulation' },
            { name: "srcdoc assignment", pattern: /\.srcdoc\s*=/, severity: "High", methods: ['regex'], category: 'innerHTML' },
            { name: "EvalInjection_setTimeout_AST", pattern: /^(?:window\.|self\.|top\.)?setTimeout$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setTimeout' },
            { name: "EvalInjection_setInterval_AST", pattern: /^(?:window\.|self\.|top\.)?setInterval$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setInterval' },
            { name: "jQuery attr href", pattern: /\$.*?\.attr\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex'], category: 'location_href' },
            { name: "jQuery prop href", pattern: /\$.*?\.prop\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex'], category: 'location_href' },
            { name: "document.domain assignment", pattern: /document\.domain\s*=/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "document.cookie assignment", pattern: /document\.cookie\s*=/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "createContextualFragment", pattern: /createContextualFragment\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' },
            { name: "jQuery append", pattern: /\$.*?\.append\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' },
            { name: "jQuery prepend", pattern: /\$.*?\.prepend\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' },
            { name: "jQuery after", pattern: /\$.*?\.after\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' },
            { name: "jQuery before", pattern: /\$.*?\.before\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' },
            { name: "element.appendChild", pattern: /\.appendChild\s*\(/, severity: "Medium", methods: ['regex'], category: 'dom_manipulation' },
            { name: "element.insertBefore", pattern: /\.insertBefore\s*\(/, severity: "Medium", methods: ['regex'], category: 'dom_manipulation' },
            { name: "setAttribute dangerous", pattern: /\.setAttribute\s*\(\s*['"](?:src|href|onclick|onerror|onload|on\w+)['"]\)/, severity: "Medium", methods: ['regex'], category: 'src_manipulation' },
            { name: "unsafe template literal", pattern: /`.*?\${(?![^{}]*?encodeURIComponent)(?![^{}]*?escape)/m, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Handlebars.compile", pattern: /Handlebars\.compile\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Vue $compile", pattern: /\$compile\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Web Worker Regex", pattern: /new\s+Worker\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Blob URL creation", pattern: /URL\.createObjectURL\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Blob constructor", pattern: /new\s+Blob\s*\(\s*\[/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "WebSocket URL Regex", pattern: /new\s+WebSocket\s*\((?![^)]*['"]wss?:\/\/)/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "element.on* assign", pattern: /\.on(?:error|load|click|mouseover|keydown|submit)\s*=/, severity: "Medium", methods: ['regex'], category: 'event_handler' },
            { name: "URLManipulation_pushState_AST", pattern: /history\.pushState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href'},
            { name: "URLManipulation_replaceState_AST", pattern: /history\.replaceState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href'},
            { name: "StorageManipulation_localStorage_AST", pattern: /localStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic' },
            { name: "StorageManipulation_sessionStorage_AST", pattern: /sessionStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic' },
            { name: "localStorage Regex", pattern: /localStorage\.setItem\s*\(|localStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "sessionStorage Regex", pattern: /sessionStorage\.setItem\s*\(|sessionStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "addEventListener other", pattern: /\.addEventListener\s*\(\s*['"](?!message)/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "URL constructor", pattern: /new\s+URL\s*\(/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "URL prop manipulation", pattern: /\.(?:searchParams|pathname|hash|search)\s*=/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "history manipulation Regex", pattern: /history\.(?:pushState|replaceState)\s*\(/, severity: "Low", methods: ['regex'], category: 'location_href' },
            { name: "WebSocketCreation_AST", pattern: /WebSocket$/, severity: 'Low', methods: ['ast'], nodeType: 'NewExpression', argIndex: 0, category: 'generic'},
            { name: "console.log", pattern: /console\.log\s*\(/, severity: "Low", methods: ['regex', 'ast'], category: 'generic', argIndex: 0},
        ];
        this.securityChecks = [
            { name: "Missing origin check", pattern: null, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Missing') },
            { name: "Loose origin check", pattern: /\.origin\.(?:indexOf|includes|startsWith|endsWith|search|match)\s*\(/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Weak' && c.type?.includes('Method Call')) },
            { name: "Weak origin comparison", pattern: /\.origin\s*(?:==|!=)\s*['"]/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Medium' && c.type?.includes('Equality')) },
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
    }


    isPlainObject(obj) {
        if (typeof obj !== 'object' || obj === null) return false;
        let proto = Object.getPrototypeOf(obj); if (proto === null) return true;
        let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) baseProto = Object.getPrototypeOf(baseProto);
        return proto === baseProto;
    }

    analyzeJsonStructures(messages) {
        const structureMap = new Map();
        if (!messages || messages.length === 0) return [];
        for (const message of messages) {
            if (!message) continue;
            try {
                let data = message.data; let dataType = typeof data;
                if (dataType === 'string') { if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) { try { data = JSON.parse(data); dataType = typeof data; } catch {} } }
                if (this.isPlainObject(data)) { const structure = this.getJsonStructure(data); const hash = this.hashJsonStructure(structure); if (!structureMap.has(hash)) { const paths = this.identifyPathsToFuzz(structure); structureMap.set(hash, { structure: structure, examples: [message], pathsToFuzz: paths }); } else { const entry = structureMap.get(hash); if (entry.examples.length < 3) entry.examples.push(message); } }
            } catch {}
        }
        return Array.from(structureMap.values());
    }

    getJsonStructure(obj, path = '') {
        if (obj === null || obj === undefined) return { type: 'null', path }; const type = typeof obj; if (type !== 'object') return { type: type, path };
        if (Array.isArray(obj)) { const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` }; return { type: 'array', path, items: itemStructure }; }
        const structure = { type: 'object', path, properties: {} }; const keys = Object.keys(obj).sort(); for (const key of keys) { const newPath = path ? `${path}.${key}` : key; structure.properties[key] = this.getJsonStructure(obj[key], newPath); } return structure;
    }

    hashJsonStructure(structure) {
        if (!structure || !structure.type) return 'invalid'; if (structure.type === 'array') return `array[${this.hashJsonStructure(structure.items)}]`; if (structure.type !== 'object') return structure.type;
        const keys = Object.keys(structure.properties || {}).sort(); return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(',');
    }

    identifyPathsToFuzz(structure, currentPath = '', paths = []) {
        if (!structure) return paths; const nodePath = structure.path || currentPath; if (structure.type !== 'object' && structure.type !== 'array') { if (nodePath) paths.push({ path: nodePath, type: structure.type }); return paths; }
        if (structure.type === 'array' && structure.items) this.identifyPathsToFuzz(structure.items, '', paths); else if (structure.type === 'object' && structure.properties) for (const key of Object.keys(structure.properties)) this.identifyPathsToFuzz(structure.properties[key], '', paths);
        const uniquePaths = []; const seenPaths = new Set(); for (const p of paths) if (p.path && !seenPaths.has(p.path)) { seenPaths.add(p.path); uniquePaths.push(p); } return uniquePaths;
    }

    analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData = null) {
        const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] };
        const foundSinks = new Map();
        if (!handlerCode) {
            return vulnerabilities;
        }
        const escapeHTML = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        this.domXssSinks.forEach(sink => {
            if (sink.methods.includes('regex')) {
                let match;
                const regex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || ''));
                while ((match = regex.exec(handlerCode)) !== null) {
                    const exactMatchSnippet = match[0];
                    const key = `${sink.name || sink.type}#${exactMatchSnippet}`;
                    if (!foundSinks.has(key)) {
                        const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length);
                        let highlightedContextHTML = escapeHTML(rawContext);
                        let highlightStartIndex = -1;
                        let highlightEndIndex = -1;
                        const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet);
                        if (matchIndexInRawContext !== -1) {
                            highlightStartIndex = matchIndexInRawContext;
                            highlightEndIndex = highlightStartIndex + exactMatchSnippet.length;
                            const partBefore = rawContext.substring(0, highlightStartIndex);
                            const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex);
                            const partAfter = rawContext.substring(highlightEndIndex);
                            highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter;
                        }
                        foundSinks.set(key, { type: sink.name || sink.type, severity: sink.severity, context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex, method: 'regex', path: '', category: sink.category || 'generic' });
                    }
                }
            }
        });

        if (staticAnalysisData?.dataFlows) {
            vulnerabilities.dataFlows = staticAnalysisData.dataFlows;
            (staticAnalysisData.dataFlows || []).forEach(flow => {
                this.domXssSinks.filter(p => p.methods.includes('ast')).forEach(sinkPattern => {
                    let isMatch = false;
                    if (sinkPattern.nodeType && sinkPattern.nodeType !== flow.nodeType) return;
                    if (sinkPattern.argIndex !== undefined && sinkPattern.argIndex !== flow.argIndex) return;
                    let contextToMatch = flow.destinationContext || "";
                    if(sinkPattern.pattern instanceof RegExp){
                        const testRegex = new RegExp(sinkPattern.pattern.source, sinkPattern.pattern.flags.replace('g', ''));
                        isMatch = testRegex.test(contextToMatch);
                    } else if(typeof sinkPattern.pattern === 'string'){
                        isMatch = contextToMatch.includes(sinkPattern.pattern);
                    }
                    if (isMatch) {
                        const context = flow.fullCodeSnippet || flow.taintedNodeSnippet || '';
                        const key = `${sinkPattern.name || sinkPattern.type}#${context}`;
                        if (!foundSinks.has(key)) {
                            foundSinks.set(key, { type: sinkPattern.name || sinkPattern.type, severity: sinkPattern.severity, path: flow.sourcePath || '(root)', conditions: flow.requiredConditionsForFlow || [], context: escapeHTML(context), highlightStart: -1, highlightEnd: -1, method: 'ast', category: sinkPattern.category || 'generic' });
                        }
                    }
                });
            });
        }
        vulnerabilities.sinks = Array.from(foundSinks.values());

        const originChecks = staticAnalysisData?.originValidationChecks || [];
        const hasListener = staticAnalysisData?.hasListener || /addEventListener\s*\(\s*['"]message['"]/i.test(handlerCode) || /onmessage\s*=/i.test(handlerCode);
        let originCheckCoveredByStatic = false;

        if (hasListener && originChecks.length > 0) {
            originChecks.forEach(check => {
                const severity = check.strength === 'Missing' || check.strength === 'Weak' ? 'Medium' : (check.strength === 'Medium' ? 'Medium' : 'Low');
                const issueType = check.strength === 'Missing' ? 'Missing origin check' : `${check.strength} Origin Check`;
                const existing = vulnerabilities.securityIssues.find(iss => iss.type === issueType && iss.details === check.type);
                if (!existing) {
                    vulnerabilities.securityIssues.push({ type: issueType, severity: severity, context: check.snippet || `Detected origin check type: ${check.type || 'Unknown'}`, details: check.type || 'N/A', strength: check.strength, highlightStart: -1, highlightEnd: -1 });
                }
            });
            originCheckCoveredByStatic = true;
        }

        for (const check of this.securityChecks) {
            if (check.name.toLowerCase().includes('origin') && originCheckCoveredByStatic) {
                continue;
            }
            if (check.checkFunc && staticAnalysisData) {
                if (check.checkFunc(handlerCode, staticAnalysisData)) {
                    if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name)) {
                        vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: `${check.name} condition met (via static analysis).`, highlightStart: -1, highlightEnd: -1 });
                    }
                }
            } else if (check.pattern) {
                let match;
                try {
                    const flags = [...new Set(['g', 'm', 's', ...(check.pattern.flags?.split('') || [])])].join('');
                    const regex = new RegExp(check.pattern.source, flags);
                    while ((match = regex.exec(handlerCode)) !== null) {
                        const exactMatchSnippet = match[0];
                        const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length);
                        let highlightedContextHTML = escapeHTML(rawContext);
                        let highlightStartIndex = -1;
                        let highlightEndIndex = -1;
                        const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet);
                        if (matchIndexInRawContext !== -1) {
                            highlightStartIndex = matchIndexInRawContext;
                            highlightEndIndex = highlightStartIndex + exactMatchSnippet.length;
                            const partBefore = rawContext.substring(0, highlightStartIndex);
                            const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex);
                            const partAfter = rawContext.substring(highlightEndIndex);
                            highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter;
                        }
                        if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context.includes(escapeHTML(exactMatchSnippet)))) {
                            vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex });
                        }
                        if (!regex.global) break;
                    }
                } catch {}
            }
        }

        if (originCheckCoveredByStatic) {
            vulnerabilities.securityIssues = vulnerabilities.securityIssues.filter(issue => {
                const isStaticOriginIssue = issue.strength && issue.type.toLowerCase().includes('origin check');
                const isOldRegexOriginIssue = !issue.strength && issue.type.toLowerCase().includes('origin check');
                return isStaticOriginIssue || !isOldRegexOriginIssue;
            });
        }
        return vulnerabilities;
    }

    extractContext(codeToSearchIn, index, length) {
        const before = Math.max(0, index - 50);
        const after = Math.min(codeToSearchIn.length, index + length + 50);
        let context = codeToSearchIn.substring(before, after);
        context = context.replace(/\n|\r/g, "↵").trim();
        return context;
    }

    async generateFuzzingPayloads(uniqueStructures, vulnerabilities, originalMessages = []) {
        const generatedPayloads = [];
        const MAX_PAYLOADS_TOTAL = 10000;
        const MAX_PAYLOADS_PER_SINK_PATH = 30;
        const MAX_PAYLOADS_PER_DUMB_FIELD = 20;
        const MAX_DUMB_FIELDS_TO_TARGET = 50;

        if (!Array.isArray(uniqueStructures)) {
            uniqueStructures = [];
        }
        let customXssPayloads = [];
        let customPayloadsActive = false;
        try {
            const storedPayloadsString = sessionStorage.getItem('customXssPayloads');
            if (storedPayloadsString) {
                const parsed = JSON.parse(storedPayloadsString);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    customXssPayloads = parsed;
                    customPayloadsActive = true;
                }
            }
        } catch (e) {}

        const allXssPayloads = customPayloadsActive ? customXssPayloads : (window.FuzzingPayloads?.XSS || []);
        let callbackUrl = null;
        let processedCallbackPayloads = [];
        try {
            const storageData = await new Promise(resolve => chrome.storage.session.get('callback_url', resolve));
            callbackUrl = storageData['callback_url'];
            if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) {
                processedCallbackPayloads = window.FuzzingPayloads.CALLBACK_URL.map(template => template.replace(/%%CALLBACK_URL%%/g, callbackUrl));
            }
        } catch(e) {}

        const combinedPayloadStrings = [...allXssPayloads, ...processedCallbackPayloads];
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());
        const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };
        const sinksWithPath = (vulnerabilities?.sinks || []).filter(s => s.path && s.path !== '(root)');

        structureLoop: for (const structure of uniqueStructures) {
            const handledPaths = new Set();
            const isStaticStructure = structure.source === 'static-analysis';
            const exampleData = structure.examples?.[0]?.data;
            let baseMsgData = exampleData !== undefined ? exampleData : structure.original;
            if (baseMsgData === undefined) {
                continue;
            }
            if (typeof baseMsgData === 'string' && (baseMsgData.startsWith('{') || baseMsgData.startsWith('['))) {
                try { baseMsgData = JSON.parse(baseMsgData); } catch (e) {}
            }

            if (this.isPlainObject(baseMsgData)) {
                const structurePaths = structure.pathsToFuzz || [];
                const sinkPathsForThisStructure = sinksWithPath
                    .filter(sink => structurePaths.some(p => p.path === sink.path || sink.path.startsWith(p.path + '.') || sink.path.startsWith(p.path + '[')))
                    .sort((a, b) => (severityOrder[b.severity?.toLowerCase()] ?? -1) - (severityOrder[a.severity?.toLowerCase()] ?? -1));

                for (const sink of sinkPathsForThisStructure) {
                    const path = sink.path;
                    if (handledPaths.has(path) || generatedPayloads.length >= MAX_PAYLOADS_TOTAL) {
                        continue;
                    }
                    const payloadsToInject = shuffleArray(combinedPayloadStrings).slice(0, MAX_PAYLOADS_PER_SINK_PATH);
                    for (const payloadString of payloadsToInject) {
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) {
                            break structureLoop;
                        }
                        try {
                            const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                            this.setValueAtPath(modifiedMsg, path, payloadString);
                            const isCallback = processedCallbackPayloads.includes(payloadString);
                            let payloadType = isStaticStructure ? 'smart-static' : 'smart-message';
                            if(isCallback) payloadType = isStaticStructure ? 'smart-static-callback' : 'smart-message-callback';
                            if (customPayloadsActive && !isCallback) payloadType = isStaticStructure ? 'custom-smart-static' : 'custom-smart-message';
                            generatedPayloads.push({ type: payloadType, payload: modifiedMsg, targetPath: path, sinkType: sink.type, description: `${isCallback?'Callback':'XSS'} for ${sink.type} via ${path}` });
                        } catch (e) {}
                    }
                    handledPaths.add(path);
                }

                const allStringFields = structurePaths.filter(p => p.type === 'string').map(p => p.path) || [];
                const remainingStringFields = allStringFields.filter(path => !handledPaths.has(path));
                if (remainingStringFields.length > 0) {
                    const fieldsToTarget = shuffleArray(remainingStringFields).slice(0, MAX_DUMB_FIELDS_TO_TARGET);
                    for (const field of fieldsToTarget) {
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                        const selectedPayloads = shuffleArray(combinedPayloadStrings).slice(0, MAX_PAYLOADS_PER_DUMB_FIELD);
                        for (const payloadString of selectedPayloads) {
                            if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                            try {
                                const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                this.setValueAtPath(modifiedMsg, field, payloadString);
                                const isCallback = processedCallbackPayloads.includes(payloadString);
                                let payloadType = 'dumb-json';
                                if(isCallback) payloadType = 'dumb-json-callback';
                                if (customPayloadsActive && !isCallback) payloadType = 'custom-dumb-json';
                                generatedPayloads.push({ type: payloadType, payload: modifiedMsg, targetFlow: `JSON Field: ${field}`, description: `Dumb ${isCallback?'Callback':'XSS'} for ${field}` });
                                handledPaths.add(field);
                            } catch (e) {}
                        }
                    }
                }
            } else if (typeof baseMsgData === 'string') {
                const originalString = baseMsgData;
                const payloadsForString = shuffleArray(combinedPayloadStrings).slice(0, 15);
                let payloadTypeBase = 'dumb-string';
                if(customPayloadsActive) payloadTypeBase = 'custom-dumb-string';
                stringLoop: for (const payloadString of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break stringLoop;
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    const currentTypeBase = isCallback ? 'dumb-string-callback' : payloadTypeBase;
                    generatedPayloads.push({ type: `${currentTypeBase}-replace`, payload: payloadString, targetFlow: 'string replacement', description: `Dumb ${isCallback?'Callback':'XSS'} replace`, original: originalString });
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) generatedPayloads.push({ type: `${currentTypeBase}-append`, payload: originalString + payloadString, targetFlow: 'string append', description: `Dumb ${isCallback?'Callback':'XSS'} append`, original: originalString });
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) generatedPayloads.push({ type: `${currentTypeBase}-prepend`, payload: payloadString + originalString, targetFlow: 'string prepend', description: `Dumb ${isCallback?'Callback':'XSS'} prepend`, original: originalString });
                }
            }
        }

        if (generatedPayloads.length === 0 && uniqueStructures.length === 0) {
            const stringMessages = originalMessages.filter(msg => typeof msg?.data === 'string');
            if (stringMessages.length > 0) {
                const originalString = stringMessages[0].data;
                const payloadsForString = shuffleArray(combinedPayloadStrings).slice(0, 15);
                let payloadTypeBase = 'dumb-string';
                if(customPayloadsActive) payloadTypeBase = 'custom-dumb-string';
                stringLoopFallback: for (const payloadString of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break stringLoopFallback;
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    const currentTypeBase = isCallback ? 'dumb-string-callback' : payloadTypeBase;
                    generatedPayloads.push({ type: `${currentTypeBase}-replace`, payload: payloadString, targetFlow: 'string replace fallback', description: `Dumb ${isCallback?'Callback':'XSS'} replace`, original: originalString });
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) generatedPayloads.push({ type: `${currentTypeBase}-append`, payload: originalString + payloadString, targetFlow: 'string append fallback', description: `Dumb ${isCallback?'Callback':'XSS'} append`, original: originalString });
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) generatedPayloads.push({ type: `${currentTypeBase}-prepend`, payload: payloadString + originalString, targetFlow: 'string prepend fallback', description: `Dumb ${isCallback?'Callback':'XSS'} prepend`, original: originalString });
                }
            } else {
                let payloadType = 'dumb-generic';
                if(customPayloadsActive) payloadType = 'custom-dumb-generic';
                shuffleArray(combinedPayloadStrings).slice(0, 10).forEach(p => {
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        const isCallback = processedCallbackPayloads.includes(p);
                        const currentType = isCallback ? 'dumb-generic-callback' : payloadType;
                        generatedPayloads.push({ type: currentType, payload: p, targetFlow: 'generic string', description: `Generic ${isCallback?'Callback':'XSS'} (no structure)` });
                    }
                });
            }
        }
        return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
    }

    setValueAtPath(obj, path, value) {
        return this.setNestedValue(obj, path, value);
    }

    calculateRiskScore(analysisResults) {
        let penaltyScore = 0;
        const MAX_PENALTY = 100;
        if (!analysisResults) return 100;
        const sinks = analysisResults.sinks || [];
        const issues = analysisResults.securityIssues || [];
        const dataFlows = analysisResults.dataFlows || [];

        sinks.forEach(sink => { switch (sink.severity?.toLowerCase()) { case 'critical': penaltyScore += 35; break; case 'high': penaltyScore += 20; break; case 'medium': penaltyScore += 8; break; case 'low': penaltyScore += 2; break; default: penaltyScore += 1; break; } });
        let mediumIssueCount = 0;
        issues.forEach(issue => { if (issue.type.toLowerCase().includes('origin check')) { switch (issue.strength?.toLowerCase()) { case 'missing': penaltyScore += 15; break; case 'weak': penaltyScore += 15; break; case 'medium': penaltyScore += 5; break; case 'strong': penaltyScore += 0; break; default: penaltyScore += 5; break; } } else { switch (issue.severity?.toLowerCase()) { case 'high': penaltyScore += 15; break; case 'medium': mediumIssueCount++; penaltyScore += 5 + Math.min(mediumIssueCount, 4); break; case 'low': penaltyScore += 3; break; default: penaltyScore += 1; break; } } });
        if (dataFlows.length > 0) { let flowPenalty = 0; dataFlows.forEach(flow => { switch (flow.severity?.toLowerCase()) { case 'critical': flowPenalty += 5; break; case 'high': flowPenalty += 3; break; case 'medium': flowPenalty += 1; break; default: flowPenalty += 0.5; break; } }); penaltyScore += Math.min(flowPenalty, 25); }
        if (issues.some(issue => issue.type.toLowerCase().includes('window.parent') && issue.type.toLowerCase().includes('origin check'))) penaltyScore += 10;

        penaltyScore = Math.min(penaltyScore, MAX_PENALTY);
        let finalScore = Math.max(0, 100 - penaltyScore);
        return Math.round(finalScore);
    }

    createSyntheticStructureFromPaths(pathsSet) {
        const structure = {};
        function setPathValue(obj, pathParts, value) { let current=obj; for(let i=0;i<pathParts.length-1;i++){const part=pathParts[i];if(!current[part]||typeof current[part]!=='object'){const next=/^\d+$/.test(pathParts[i+1])?[]:{};current[part]=next;}current=current[part];} const last=pathParts[pathParts.length-1]; if(typeof current==='object'&&current!==null&&current[last]===undefined)current[last]=value; }
        const getDefaultValue = (p)=>{const l=p.toLowerCase(); return l.includes('url')||l.includes('src')||l.includes('href')?'https://e.com':l.includes('id')||l.includes('count')||l.includes('index')?0:l.includes('enabled')||l.includes('isvalid')||l.includes('success')?true:l.includes('name')||l.includes('title')?'P Name':l.includes('type')||l.includes('action')||l.includes('cmd')||l.includes('kind')||l.includes('messageType')?'message':l.includes('desc')||l.includes('text')||l.includes('content')?'P text.':'p_val';};
        const sortedPaths = Array.from(pathsSet).sort((a, b) => a.split(/[\.\[]/).length - b.split(/[\.\[]/).length);
        sortedPaths.forEach(path => { const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g)?.map(p => p.startsWith('[') ? p.substring(1, p.length - 1).replace(/['"`]/g, '') : p) || []; if (parts.length > 0 && path !== '(root)') setPathValue(structure, parts, getDefaultValue(path)); });
        if (pathsSet.has('(root)') && Object.keys(structure).length === 0) return [{ type: 'raw_value', original: getDefaultValue('(root)'), fields: [], fieldTypes: {}, pathsToFuzz: [{path: '(root)', type: 'string'}], source: 'static-analysis' }];
        if (Object.keys(structure).length === 0 && !pathsSet.has('(root)')) return [];
        const fieldTypes = this.getFieldTypesFromObject(structure); const fields = this.extractAllFieldsFromObject(structure); const typeFields = fields.filter(f => ['type', 'action', 'messagetype', 'kind', 'cmd'].includes(f.toLowerCase())); const structureVariants = [];
        if (typeFields.length > 0) { const commonTypes = ['message', 'request', 'response', 'config', 'init', 'load', 'save']; const base = JSON.parse(JSON.stringify(structure)); commonTypes.forEach(typeValue => { const variant = JSON.parse(JSON.stringify(base)); typeFields.forEach(field => this.setValueAtPath(variant, field, typeValue)); structureVariants.push({ type: 'object', original: variant, pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })), examples: [{ data: JSON.parse(JSON.stringify(variant)) }], source: 'static-analysis-variant' }); }); if (structureVariants.length > 0) return structureVariants; }
        return [{ type: 'object', original: JSON.parse(JSON.stringify(structure)), pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })), examples: [{ data: JSON.parse(JSON.stringify(structure)) }], source: 'static-analysis' }];
    }

    matchSinkPattern(destContext) {
        if (!destContext) return null;
        for (const sink of this.domXssSinks) { if (!sink.pattern) continue; let isMatch=false; if (sink.pattern instanceof RegExp){const testRegex=new RegExp(sink.pattern.source,sink.pattern.flags.replace('g',''));isMatch=testRegex.test(destContext);}else if(typeof sink.pattern==='string')isMatch=destContext.includes(sink.pattern); if(isMatch)return {name:sink.name,severity:sink.severity,category:sink.category||'generic'}; }
        return null;
    }

    async generateAstBasedPayloads(staticAnalysisData, vulnerabilityAnalysis) {
        const generatedPayloads = [];
        const MAX_PAYLOADS_TOTAL = 5000;
        const MAX_PAYLOADS_PER_SINK_PATH = 30;
        const MAX_PAYLOADS_PER_COMMON_PATH = 15;

        if (!staticAnalysisData || !vulnerabilityAnalysis) {
            return [];
        }
        let customXssPayloads = [];
        let customPayloadsActive = false;
        try {
            const storedPayloadsString = sessionStorage.getItem('customXssPayloads');
            if (storedPayloadsString) {
                const parsed = JSON.parse(storedPayloadsString);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    customXssPayloads = parsed;
                    customPayloadsActive = true;
                }
            }
        } catch (e) {}

        const allXssPayloads = customPayloadsActive ? customXssPayloads : (window.FuzzingPayloads?.XSS || []);
        let callbackUrl = null;
        let processedCallbackPayloads = [];
        try {
            const storageData = await new Promise(resolve => chrome.storage.session.get('callback_url', resolve));
            callbackUrl = storageData['callback_url'];
            if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) {
                processedCallbackPayloads = window.FuzzingPayloads.CALLBACK_URL.map(template => template.replace(/%%CALLBACK_URL%%/g, callbackUrl));
            }
        } catch(e) {}

        const combinedPayloadStrings = [...allXssPayloads, ...processedCallbackPayloads];
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());
        const accessedPaths = new Set();

        if (staticAnalysisData.accessedEventDataPaths) {
            const pathsToAdd = staticAnalysisData.accessedEventDataPaths instanceof Set ? Array.from(staticAnalysisData.accessedEventDataPaths) : (typeof staticAnalysisData.accessedEventDataPaths === 'object' ? Object.keys(staticAnalysisData.accessedEventDataPaths) : []);
            pathsToAdd.forEach(path => accessedPaths.add(path));
        }

        const dataFlows = staticAnalysisData.dataFlows || [];
        if (dataFlows.length > 0) {
            dataFlows.forEach(flow => {
                if (flow.sourcePath) { accessedPaths.add(flow.sourcePath); }
                if (flow.requiredConditionsForFlow) {
                    flow.requiredConditionsForFlow.forEach(cond => { if(cond.path) accessedPaths.add(cond.path); });
                }
                if (flow.taintedNodeSnippet) {
                    const matches = flow.taintedNodeSnippet.match(/event\.data\.([\w.[\]'"`]+)/g);
                    if (matches) {
                        matches.forEach(match => { let path = match.replace('event.data.', '').replace(/\[['"`]?([^\]'"`]+)['"`]?\]/g, '.$1'); if (path) { accessedPaths.add(path); } });
                    }
                }
            });
        }

        const syntheticStructures = this.createSyntheticStructureFromPaths(accessedPaths);
        const typeFields = Array.from(accessedPaths).filter(path => ['type', 'action', 'messagetype', 'kind', 'cmd'].includes(path.toLowerCase()));
        const pathToSinkMap = new Map();
        const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };

        dataFlows.forEach(flow => {
            let path = flow.sourcePath;
            if (path === '(root)' && flow.taintedNodeSnippet) { const match = flow.taintedNodeSnippet.match(/^(?:event|e|msg|message)\.data\.([\w.[\]'"`]+)/); if (match && match[1]) path = match[1].replace(/\[['"`]?([^\]'"`]+)['"`]?\]/g, '.$1'); }
            if (path && path !== '(root)') {
                const sinkInfo = this.matchSinkPattern(flow.destinationContext);
                const existingSink = pathToSinkMap.get(path);
                const newSeverityScore = severityOrder[sinkInfo?.severity?.toLowerCase()] || 0;
                const existingSeverityScore = severityOrder[existingSink?.severity?.toLowerCase()] || 0;
                if (sinkInfo && (!existingSink || newSeverityScore > existingSeverityScore)) {
                    pathToSinkMap.set(path, { ...sinkInfo, flowConditions: flow.requiredConditionsForFlow || [] });
                } else if (!sinkInfo && !existingSink) {
                    pathToSinkMap.set(path, { name: 'unknown', severity: 'Low', category: 'generic', flowConditions: flow.requiredConditionsForFlow || [] });
                }
            }
        });
        (vulnerabilityAnalysis.sinks || []).forEach(sink => {
            let path = sink.path;
            if (path && path !== '(root)' && !pathToSinkMap.has(path)) { const category = this.domXssSinks.find(s => s.name === sink.type)?.category || 'generic'; pathToSinkMap.set(path, { name: sink.type || 'unknown', severity: sink.severity || 'Medium', category: category, flowConditions: sink.conditions || [] }); }
        });

        const requiredConditions = staticAnalysisData.requiredConditions || {};

        structureLoop: for (const structure of syntheticStructures) {
            if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL || !structure.type || structure.type !== 'object' || !structure.original) { continue; }
            let generalBaseMessageObject = JSON.parse(JSON.stringify(structure.original));
            Object.entries(requiredConditions).forEach(([path, value]) => { this.setValueAtPath(generalBaseMessageObject, path, value); });
            const pathsInStructure = structure.pathsToFuzz?.map(p => p.path) || [];

            for (const path of pathsInStructure) {
                if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) { break structureLoop; }
                if (typeFields.includes(path)) { continue; }

                const sinkInfo = pathToSinkMap.get(path);
                // --- FIX: Define specificFlowConditions HERE ---
                const specificFlowConditions = sinkInfo?.flowConditions || [];
                let baseForThisPath = JSON.parse(JSON.stringify(generalBaseMessageObject));

                // Now use the defined specificFlowConditions variable
                specificFlowConditions.forEach(cond => {
                    if (cond.path && cond.value !== undefined && !String(cond.value).startsWith('[EXPRESSION:') && (cond.op === '===' || cond.op === '==') && cond.path !== path) {
                        this.setValueAtPath(baseForThisPath, cond.path, cond.value);
                    }
                });

                let currentValAtPath = undefined;
                try { let current=baseForThisPath; const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g)||[]; for(let i=0;i<parts.length-1;i++){let p=parts[i]; if(p.startsWith('['))p=p.substring(1,p.length-1).replace(/['"`]/g,''); current=current?.[p];} let last=parts[parts.length-1]; if(last.startsWith('['))last=last.substring(1,last.length-1).replace(/['"`]/g,''); currentValAtPath=current?.[last]; } catch(e){}
                if (currentValAtPath === undefined) { const synthPath=structure.pathsToFuzz?.find(p=>p.path===path); const phVal=synthPath?(synthPath.type==='string'?'placeholder':(synthPath.type==='number'?0:true)):'placeholder_value'; this.setValueAtPath(baseForThisPath, path, phVal); }

                const useSmartLimit = sinkInfo && sinkInfo.name !== 'unknown';
                const limit = useSmartLimit ? MAX_PAYLOADS_PER_SINK_PATH : MAX_PAYLOADS_PER_COMMON_PATH;
                const payloadsToInject = shuffleArray(combinedPayloadStrings).slice(0, limit);
                let payloadType = 'ast-smart'; const sinkSeverity = sinkInfo?.severity?.toLowerCase();
                if (!sinkInfo || sinkInfo.name === 'unknown' || sinkSeverity === 'low') payloadType = 'dumb-json';
                if (customPayloadsActive) payloadType = useSmartLimit ? 'custom-ast-smart' : 'custom-ast-dumb';

                for (const payloadString of payloadsToInject) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                    try {
                        const modifiedMessage = JSON.parse(JSON.stringify(baseForThisPath));
                        this.setValueAtPath(modifiedMessage, path, payloadString);
                        const isCallback = processedCallbackPayloads.includes(payloadString);
                        let currentPayloadType = payloadType;
                        if(isCallback) currentPayloadType = payloadType.startsWith('custom-') ? (useSmartLimit ? 'custom-ast-smart-callback' : 'custom-ast-dumb-callback') : (useSmartLimit ? 'ast-smart-callback' : 'dumb-json-callback');
                        generatedPayloads.push({ type: currentPayloadType, payload: modifiedMessage, targetPath: path, sinkType: sinkInfo?.name||'unknown', sinkSeverity: sinkInfo?.severity||'Low', description: `AST ${isCallback?'Cb':'XSS'} for ${path}${sinkInfo?` -> ${sinkInfo.name}`:' (generic)'}` });
                    } catch (e) {}
                }
            }
        }

        if (accessedPaths.has('(root)') && generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
            const rootFlow = dataFlows.find(f => f.sourcePath === '(root)'); const rootSinkInfo = rootFlow ? this.matchSinkPattern(rootFlow.destinationContext) : null; const rootPayloadsToUse = shuffleArray(combinedPayloadStrings).slice(0, 20);
            rootPayloadsToUse.forEach(payloadString => {
                if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                    const isCallback = processedCallbackPayloads.includes(payloadString); let payloadType = customPayloadsActive ? 'custom-ast-raw' : 'ast-raw'; if(isCallback) payloadType = 'callback_url_raw';
                    generatedPayloads.push({ type: payloadType, payload: payloadString, targetPath: '(root)', sinkType: rootSinkInfo?.name||'unknown', sinkSeverity: rootSinkInfo?.severity||'Low', description: `AST raw ${isCallback?'Cb':'XSS'} for root${rootSinkInfo?` -> ${rootSinkInfo.name}`:''}` });
                }
            });
        }

        if (generatedPayloads.length === 0) {
            shuffleArray(combinedPayloadStrings).slice(0, 30).forEach(payloadString => {
                if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                    const isCallback = processedCallbackPayloads.includes(payloadString); let payloadType = customPayloadsActive ? 'custom-ast-fallback' : 'ast-fallback'; if(isCallback) payloadType = 'callback_url_raw';
                    generatedPayloads.push({ type: payloadType, payload: payloadString, targetPath: 'fallback', sinkType: 'unknown', sinkSeverity: 'Low', description: `AST fallback ${isCallback?'Cb':'XSS'}` });
                }
            });
        }
        return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
    }

    getFieldTypesFromObject(obj, prefix = '', types = {}) {
        if (!obj || typeof obj !== 'object') return types;
        for (const key in obj) { if (Object.hasOwnProperty.call(obj, key)) { const fieldPath = prefix ? `${prefix}.${key}` : key; types[fieldPath] = Array.isArray(obj[key]) ? 'array' : typeof obj[key]; if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) this.getFieldTypesFromObject(obj[key], fieldPath, types); else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') this.getFieldTypesFromObject(obj[key][0], `${fieldPath}[0]`, types); } } return types;
    }

    extractAllFieldsFromObject(obj, prefix = '', fields = []) {
        if (!obj || typeof obj !== 'object') return fields;
        for (const key in obj) { if (Object.hasOwnProperty.call(obj, key)) { const fieldPath = prefix ? `${prefix}.${key}` : key; fields.push(fieldPath); if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) this.extractAllFieldsFromObject(obj[key], fieldPath, fields); else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') this.extractAllFieldsFromObject(obj[key][0], `${fieldPath}[0]`, fields); } } return [...new Set(fields)];
    }

    setNestedValue(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) { if (typeof obj === 'string') return value; return; }
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || []; let current = obj;
        for (let i = 0; i < parts.length - 1; i++) { let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, ''); const nextPartStr = parts[i + 1]; let nextPartNormalized = nextPartStr; if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, ''); const isNextPartIndex = /^\d+$/.test(nextPartNormalized); if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') current[part] = isNextPartIndex ? [] : {}; current = current[part]; if (typeof current !== 'object' || current === null) return; }
        let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
        if (typeof current === 'object' && current !== null) { const isIndex = /^\d+$/.test(lastPart); if (Array.isArray(current) && isIndex) current[parseInt(lastPart, 10)] = value; else if (!Array.isArray(current)) current[lastPart] = value; }
    }
}
window.HandlerTracer = HandlerTracer;

async function handleTraceButton(endpoint, traceButton) {
    const originalFullEndpoint = endpoint;
    const endpointKey = window.getStorageKeyForUrl(originalFullEndpoint);

    window.updateTraceButton(traceButton, 'default');
    traceButton.classList.remove('show-next-step-emoji');
    traceButton.style.animation = '';

    if (!endpointKey) {
        window.log.error("Trace: Cannot determine endpoint key", originalFullEndpoint);
        window.updateTraceButton(traceButton, 'error');
        return;
    }

    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) {
        window.log.handler(`Trace already in progress for key: ${endpointKey}`);
        return;
    }
    sessionStorage.setItem(traceInProgressKey, 'true');
    window.log.scan(`Starting message trace for endpoint key: ${endpointKey}`);
    window.updateTraceButton(traceButton, 'checking');

    const buttonContainer = traceButton.closest('.button-container');
    const playButton = buttonContainer?.querySelector('.iframe-check-button');
    const reportButton = buttonContainer?.querySelector('.iframe-report-button');
    if (playButton) {
        playButton.classList.remove('show-next-step-emoji');
    }

    let progressContainer = document.querySelector('.trace-progress-container');
    if (!progressContainer) {
        window.addProgressStyles();
        progressContainer = document.createElement('div');
        progressContainer.className = 'trace-progress-container';
        document.body.appendChild(progressContainer);
    }
    progressContainer.innerHTML = `<h4>Trace Progress</h4><div class="phase-list"><div class="phase" data-phase="collection"><span class="emoji">📦</span><span class="label">Data</span></div><div class="phase" data-phase="analysis"><span class="emoji">🔬</span><span class="label">Analyze</span></div><div class="phase" data-phase="structure"><span class="emoji">🧱</span><span class="label">Structure</span></div><div class="phase" data-phase="generation"><span class="emoji">⚙️</span><span class="label">Payloads</span></div><div class="phase" data-phase="saving"><span class="emoji">💾</span><span class="label">Saving</span></div><div class="phase" data-phase="finished" style="display: none;"><span class="emoji">✅</span><span class="label">Done</span></div><div class="phase" data-phase="error" style="display: none;"><span class="emoji">❌</span><span class="label">Error</span></div></div>`;

    const updatePhase = (phase, status = 'active') => {
        const phaseElement = progressContainer?.querySelector(`.phase[data-phase="${phase}"]`);
        if (!phaseElement) {
            return;
        }
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
    let vulnAnalysis = { sinks: [], securityIssues: [], dataFlows: [], originValidationChecks: [] };
    let uniqueStructures = [];
    let usedAstGenerator = false;
    let staticAnalyzer = null;
    let staticAnalysisData = null;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) {
            window.handlerTracer = new HandlerTracer();
        }
        if (typeof window.analyzeHandlerStatically === 'function') {
            staticAnalyzer = window.analyzeHandlerStatically;
        } else {
            window.log.warn("Static analyzer not found.");
        }

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;
        analysisStorageKey = window.getStorageKeyForUrl(endpointUrlUsedForAnalysis);

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;
        if (!handlerCode) {
            throw new Error(`No handler code found in storage (${bestHandlerStorageKey}). Run Play first.`);
        }

        const relevantMessages = await window.retrieveMessagesWithFallbacks(endpointKey);
        window.log.handler(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));

        if (staticAnalyzer && handlerCode) {
            try {
                const staticResults = staticAnalyzer(handlerCode);
                if (staticResults?.success && staticResults.analysis) {
                    staticAnalysisData = staticResults.analysis;
                    window.log.handler(`[Trace] Static analysis successful.`);
                } else {
                    window.log.warn(`[Trace] Static analysis failed: ${staticResults?.error}. Continuing without AST data.`);
                    staticAnalysisData = null;
                }
            } catch (e) {
                window.log.error("Error executing static analyzer:", e);
                staticAnalysisData = null;
            }
        }

        vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));
        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));

        if (relevantMessages.length > 0) {
            window.log.handler("[Trace] Messages found. Using message-based payload generation.");
            uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);
            payloads = await window.handlerTracer.generateFuzzingPayloads(uniqueStructures, vulnAnalysis, relevantMessages);
        } else {
            window.log.handler("[Trace] No messages. Attempting AST-based payload generation.");
            if (staticAnalysisData && (staticAnalysisData.accessedEventDataPaths?.size > 0 || staticAnalysisData.dataFlows?.length > 0)) {
                payloads = await window.handlerTracer.generateAstBasedPayloads(staticAnalysisData, vulnAnalysis);
                usedAstGenerator = true;
                window.log.handler(`[Trace] AST generator created ${payloads.length} payloads.`);
            } else {
                const reason = staticAnalysisData === null ? "Static analysis failed or unavailable" : "Insufficient AST data";
                window.log.warn(`[Trace] ${reason}. Skipping AST payload generation.`);
                payloads = [];
            }
        }

        updatePhase('saving');
        const securityScore = window.handlerTracer.calculateRiskScore(vulnAnalysis);

        report = {
            endpoint: endpointUrlUsedForAnalysis,
            originalEndpointKey: endpointKey,
            analysisStorageKey: analysisStorageKey,
            timestamp: new Date().toISOString(),
            analyzedHandler: bestHandler,
            vulnerabilities: vulnAnalysis.sinks || [],
            securityIssues: vulnAnalysis.securityIssues || [],
            securityScore: securityScore,
            details: {
                analyzedHandler: bestHandler,
                sinks: vulnAnalysis.sinks || [],
                securityIssues: vulnAnalysis.securityIssues || [],
                dataFlows: vulnAnalysis.dataFlows || [],
                originValidationChecks: staticAnalysisData?.originValidationChecks || [],
                payloadsGeneratedCount: payloads.length,
                uniqueStructures: uniqueStructures || [],
                staticAnalysisUsed: usedAstGenerator,
                messagesAvailable: relevantMessages.length > 0,
                requiredConditions: staticAnalysisData?.requiredConditions || {}
            },
            summary: {
                messagesAnalyzed: relevantMessages.length,
                patternsIdentified: uniqueStructures.length,
                sinksFound: vulnAnalysis.sinks?.length || 0,
                issuesFound: vulnAnalysis.securityIssues?.length || 0,
                payloadsGenerated: payloads.length,
                securityScore: securityScore,
                staticAnalysisUsed: usedAstGenerator
            }
        };

        window.log.info(`[Trace] Saving report. Payloads: ${payloads.length}. AST Used: ${usedAstGenerator}`);
        const reportStorageKey = analysisStorageKey;
        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);
        if (!reportSaved || !payloadsSaved) {
            throw new Error("Failed to save trace report or payloads.");
        }
        window.log.success(`Report & ${payloads.length} payloads saved: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true, criticalSinks: hasCriticalSinks, analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey, timestamp: Date.now(), payloadCount: payloads.length,
                sinkCount: vulnAnalysis.sinks?.length || 0, usedStaticAnalysis: usedAstGenerator
            }
        });

        window.updateTraceButton(traceButton, 'success');
        if (playButton) {
            window.updateButton(playButton, 'launch', { hasCriticalSinks: hasCriticalSinks, showEmoji: true });
        }
        if (reportButton) {
            const reportState = hasCriticalSinks || (vulnAnalysis.securityIssues?.length || 0) > 0 ? 'green' : 'default';
            window.updateReportButton(reportButton, reportState, originalFullEndpoint);
        }
        updatePhase('saving', 'completed');

    } catch (error) {
        console.error(`[Trace] Error for ${originalFullEndpoint}:`, error);
        window.log.error(`[Trace] Error:`, error.message);
        window.updateTraceButton(traceButton, 'error');
        const traceInfoKey = `trace-info-${endpointKey}`;
        try {
            await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false, error: error.message } });
        } catch (e) {}
        if (reportButton) {
            window.updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        }
        updatePhase('error', 'error');
        const errorLabel = progressContainer?.querySelector('.phase[data-phase="error"] .label');
        if(errorLabel) {
            errorLabel.textContent = `Error: ${error.message.substring(0, 50)}...`;
        }
    } finally {
        setTimeout(() => {
            progressContainer?.remove();
        }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        window.log.handler(`[Trace] Finished attempt: ${endpointKey}`);
        setTimeout(() => requestAnimationFrame(window.updateDashboardUI), 100);
    }
}
window.handleTraceButton = handleTraceButton;

document.addEventListener('DOMContentLoaded', () => { if (!window.handlerTracer) window.handlerTracer = new HandlerTracer(); });
