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
            { name: "element.innerHTML assignment", pattern: /\.innerHTML\s*=/, severity: "High", methods: ['regex'], category: 'innerHTML' }, // <<< ADDED THIS LINE
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
        const foundSinks = new Map();

        if (!handlerCode) return vulnerabilities;

        const eventDataAccessPaths = new Set();
        const dataAccessRegex = /(?:event|e|msg|message|evt)\.data(?:\.([\w.[\]'"`]+)|(\[\s*['"`]([^\]'"`]+)['"`]\s*\]))?/g;
        let dataMatch;
        while ((dataMatch = dataAccessRegex.exec(handlerCode)) !== null) {
            let pathSegment = dataMatch[1] || dataMatch[3];
            eventDataAccessPaths.add(pathSegment || '(root)');
        }
        const sortedPaths = Array.from(eventDataAccessPaths).sort((a, b) => b.length - a.length);

        function findDataPathForSink(context) {
            for (const path of sortedPaths) {
                if (path === '(root)') continue;
                const escapedPath = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const pathRegex = new RegExp(`(?:event|e|msg|message|evt)\\.data\\.${escapedPath}`, 'i');
                if (pathRegex.test(context)) return path;
                const bracketPath = path.includes('.')
                    ? path.split('.').map(p => `['${p.replace(/'/g, "\\'")}']`).join('')
                    : `['${path.replace(/'/g, "\\'")}']`;
                const bracketRegex = new RegExp(`(?:event|e|msg|message|evt)\\.data${bracketPath}`, 'i');
                if (bracketRegex.test(context)) return path;
            }
            if (/(?:event|e|msg|message|evt)\.data/.test(context)) return '(root)';
            return '';
        }

        const escapeHTML = (str) => String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); // Ensure input is string

        // Process Regex Sinks
        this.domXssSinks.filter(p => p.methods.includes('regex')).forEach(sink => {
            let match;
            const regex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || ''));
            while ((match = regex.exec(handlerCode)) !== null) {
                const rawContext = this.extractContext(handlerCode, match.index, match[0].length);
                const sinkPath = findDataPathForSink(rawContext);
                const exactMatchSnippet = match[0];
                const key = `${sink.name || sink.type}#${exactMatchSnippet}`;

                if (!foundSinks.has(key)) {
                    let highlightedContextHTML = escapeHTML(rawContext); // Default to escaped version if match fails
                    let highlightStartIndex = -1;
                    let highlightEndIndex = -1;

                    const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet);

                    if (matchIndexInRawContext !== -1) {
                        highlightStartIndex = matchIndexInRawContext;
                        highlightEndIndex = highlightStartIndex + exactMatchSnippet.length;
                        const partBefore = rawContext.substring(0, highlightStartIndex);
                        const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex);
                        const partAfter = rawContext.substring(highlightEndIndex);

                        highlightedContextHTML = partBefore +
                            '<span class="highlight-finding">' +
                            escapeHTML(partMatch) +
                            '</span>' +
                            partAfter;
                    }

                    const sinkData = {
                        type: sink.name || sink.type,
                        severity: sink.severity,
                        context: highlightedContextHTML, // Store the HTML string
                        highlightStart: highlightStartIndex,
                        highlightEnd: highlightEndIndex,
                        method: 'regex',
                        path: sinkPath || '',
                        category: sink.category || 'generic'
                    };
                    foundSinks.set(key, sinkData);
                }
            }
        });

        // Process AST Sinks (No highlighting applied here currently)
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
                            const sinkData = {
                                type: sinkPattern.name || sinkPattern.type,
                                severity: sinkPattern.severity,
                                path: flow.sourcePath || '(root)',
                                conditions: flow.guardingConditions || [],
                                context: escapeHTML(context), // Escape AST context for safety
                                highlightStart: -1,
                                highlightEnd: -1,
                                method: 'ast',
                                category: sinkPattern.category || 'generic'
                            };
                            foundSinks.set(key, sinkData);
                        }
                    }
                });
            });
        }

        vulnerabilities.sinks = Array.from(foundSinks.values());

        // Process Security Checks
        const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]/i.test(handlerCode) ||
            /onmessage\s*=\s*function/i.test(handlerCode) ||
            /window\.onmessage/i.test(handlerCode) ||
            /function\s*\([^)]*(?:event|e|msg|message|evt)[^)]*\)\s*{.*?\.data/ms.test(handlerCode);

        if (hasMessageListener && !this.checkOriginValidation(handlerCode)) {
            if (!vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) {
                vulnerabilities.securityIssues.push({ type: "Missing origin check", severity: "High", context: "No explicit origin validation found.", highlightStart: -1, highlightEnd: -1 });
            }
        }
        const hasTypeCheck = /\.(?:type|action|messageType|kind|command)\s*===?\s*['"`]/i.test(handlerCode) ||
            /switch\s*\(\s*(?:event|e|msg|message|evt)\.data(?:\.(?:type|action|messageType|kind|command))?\s*\)/i.test(handlerCode);
        if (hasMessageListener && !hasTypeCheck) {
            if (!vulnerabilities.securityIssues.some(iss => iss.type === "No message type validation")) {
                vulnerabilities.securityIssues.push({ type: "No message type validation", severity: "Medium", context: "Handler does not appear to validate message type/action/kind.", highlightStart: -1, highlightEnd: -1 });
            }
        }

        for (const check of this.securityChecks) {
            if (check.name === "Missing origin check" && vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) continue;
            if (check.name === "No message type validation" && vulnerabilities.securityIssues.some(iss => iss.type === "No message type validation")) continue;

            let match;
            try {
                const flags = [...new Set(['g', 'm', 's', ...(check.pattern.flags?.split('') || [])])].join('');
                const regex = new RegExp(check.pattern.source, flags);
                while ((match = regex.exec(handlerCode)) !== null) {
                    const exactMatchSnippet = match[0];
                    const rawContext = this.extractContext(handlerCode, match.index, match[0].length);
                    let highlightedContextHTML = escapeHTML(rawContext); // Default
                    let highlightStartIndex = -1;
                    let highlightEndIndex = -1;

                    const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet);

                    if (matchIndexInRawContext !== -1) {
                        highlightStartIndex = matchIndexInRawContext;
                        highlightEndIndex = highlightStartIndex + exactMatchSnippet.length;
                        const partBefore = rawContext.substring(0, highlightStartIndex);
                        const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex);
                        const partAfter = rawContext.substring(highlightEndIndex);
                        // *** CORRECTED LOGIC ***
                        highlightedContextHTML = partBefore + // Raw before
                            '<span class="highlight-finding">' +
                            escapeHTML(partMatch) + // Escape only match
                            '</span>' +
                            partAfter; // Raw after
                        // *** END CORRECTION ***
                    }

                    const findingKey = `${check.name}#${exactMatchSnippet}`;
                    // Deduplicate based on finding type and raw match snippet
                    if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context.includes(escapeHTML(exactMatchSnippet)))) {
                        vulnerabilities.securityIssues.push({
                            type: check.name,
                            severity: check.severity,
                            context: highlightedContextHTML, // Store HTML string
                            highlightStart: highlightStartIndex,
                            highlightEnd: highlightEndIndex
                        });
                    }
                    if (!regex.global) break;
                }
            } catch (e) {}
        }

        return vulnerabilities;
    }

    extractContext(codeToSearchIn, index, length) {
        const before = Math.max(0, index - 50); // Use 50 padding again
        const after = Math.min(codeToSearchIn.length, index + length + 50);
        let context = codeToSearchIn.substring(before, after);
        context = context.replace(/\n|\r/g, "↵").trim();
        return context;
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
        log.debug(`[generateFuzzingPayloads] Starting. Structures: ${uniqueStructures?.length}, Sinks: ${vulnerabilities?.sinks?.length}`);


        if (!Array.isArray(uniqueStructures)) uniqueStructures = [];

        let customXssPayloads = [];
        let customPayloadsActive = false;
        try {
            const storedPayloadsString = sessionStorage.getItem('customXssPayloads');
            if (storedPayloadsString) {
                const parsed = JSON.parse(storedPayloadsString);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    customXssPayloads = parsed;
                    customPayloadsActive = true;
                    log.debug(`[generateFuzzingPayloads] Using ${customXssPayloads.length} custom payloads.`);
                }
            }
        } catch (e) {
            console.error("Error accessing/parsing custom payloads from session storage:", e);
        }

        const allXssPayloads = customPayloadsActive
            ? customXssPayloads
            : (window.FuzzingPayloads?.XSS || ['<script>alert("FP_XSS_Default")</script>']);
        log.debug(`[generateFuzzingPayloads] Using base payload list size: ${allXssPayloads.length}`);

        let callbackUrl = null;
        let processedCallbackPayloads = [];
        try {
            const storageData = await new Promise(resolve => chrome.storage.session.get('callback_url', resolve));
            callbackUrl = storageData['callback_url'];
            if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) {
                const callbackTemplates = window.FuzzingPayloads.CALLBACK_URL;
                processedCallbackPayloads = callbackTemplates.map(template =>
                    template.replace(/%%CALLBACK_URL%%/g, callbackUrl)
                );
                log.debug(`[generateFuzzingPayloads] Prepared ${processedCallbackPayloads.length} callback payload strings.`);
            }
        } catch(e) {
            console.error("Error getting callback URL for payload generation:", e);
        }

        const combinedPayloadStrings = [...allXssPayloads, ...processedCallbackPayloads];
        log.debug(`[generateFuzzingPayloads] Combined injectable strings count: ${combinedPayloadStrings.length}`);
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());

        const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };
        const sinksWithPath = (vulnerabilities?.sinks || [])
            .filter(s => s.path && s.path !== '(root)');
        log.debug(`[generateFuzzingPayloads] Found ${sinksWithPath.length} sinks with specific paths.`);

        structureLoop: for (const structure of uniqueStructures) {
            log.debug(`[generateFuzzingPayloads] Processing structure type: ${structure.type}`);
            const handledPaths = new Set();
            const isStaticStructure = structure.source === 'static-analysis';
            const exampleData = structure.examples?.[0]?.data;
            let baseMsgData = exampleData !== undefined ? exampleData : structure.original;

            if (baseMsgData === undefined){
                log.debug(`[generateFuzzingPayloads] Skipping structure - baseMsgData is undefined.`);
                continue;
            }

            if (typeof baseMsgData === 'string' && (baseMsgData.startsWith('{') || baseMsgData.startsWith('['))) {
                try { baseMsgData = JSON.parse(baseMsgData); } catch (e) {}
            }
            log.debug(`[generateFuzzingPayloads] Using base message data:`, JSON.stringify(baseMsgData).substring(0, 200));

            if (this.isPlainObject(baseMsgData)) {
                const structurePaths = structure.pathsToFuzz || [];
                log.debug(`[generateFuzzingPayloads] Structure paths to fuzz:`, structurePaths.map(p=>p.path));

                const sinkPathsForThisStructure = sinksWithPath
                    .filter(sink => {
                        const found = structurePaths.some(p => p.path === sink.path || sink.path.startsWith(p.path + '.') || sink.path.startsWith(p.path + '['));
                        log.debug(`[generateFuzzingPayloads] Sink path "${sink.path}" ${found ? 'matches' : 'does NOT match'} structure paths.`);
                        return found;
                    })
                    .sort((a, b) => (severityOrder[b.severity?.toLowerCase()] ?? -1) - (severityOrder[a.severity?.toLowerCase()] ?? -1));
                log.debug(`[generateFuzzingPayloads] Applicable sink paths for this structure:`, sinkPathsForThisStructure.map(s=>s.path));

                for (const sink of sinkPathsForThisStructure) {
                    const path = sink.path;
                    log.debug(`[generateFuzzingPayloads] SMART loop - Target path: "${path}" for sink: ${sink.type}`);
                    if (handledPaths.has(path) || generatedPayloads.length >= MAX_PAYLOADS_TOTAL) continue;

                    const payloadsToInject = shuffleArray(combinedPayloadStrings).slice(0, MAX_PAYLOADS_PER_SINK_PATH);

                    for (const payloadString of payloadsToInject) {
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                        try {
                            const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                            this.setValueAtPath(modifiedMsg, path, payloadString);
                            log.debug(`[generateFuzzingPayloads] SMART Inject: Path="${path}", PayloadString="${payloadString.substring(0,50)}...", ResultingMsg:`, JSON.stringify(modifiedMsg));
                            const isCallback = processedCallbackPayloads.includes(payloadString);
                            let payloadType = isStaticStructure ? 'smart-static' : 'smart-message';
                            if(isCallback) payloadType = isStaticStructure ? 'smart-static-callback' : 'smart-message-callback';
                            if (customPayloadsActive && !isCallback) payloadType = isStaticStructure ? 'custom-smart-static' : 'custom-smart-message';

                            generatedPayloads.push({
                                type: payloadType,
                                payload: modifiedMsg, targetPath: path, sinkType: sink.type,
                                description: `${isCallback ? 'Callback' : 'XSS'} payload for ${sink.type} sink via path: ${path}`
                            });
                        } catch (e) {
                            log.error(`[generateFuzzingPayloads] SMART Error setting path "${path}":`, e);
                        }
                    }
                    handledPaths.add(path);
                }

                const allStringFields = structurePaths.filter(p => p.type === 'string').map(p => p.path) || [];
                const remainingStringFields = allStringFields.filter(path => !handledPaths.has(path));
                log.debug(`[generateFuzzingPayloads] Remaining string fields for DUMB fuzzing:`, remainingStringFields);

                if (remainingStringFields.length > 0) {
                    const fieldsToTarget = shuffleArray(remainingStringFields).slice(0, MAX_DUMB_FIELDS_TO_TARGET);
                    for (const field of fieldsToTarget) {
                        log.debug(`[generateFuzzingPayloads] DUMB loop - Target field: "${field}"`);
                        if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                        const selectedPayloads = shuffleArray(combinedPayloadStrings).slice(0, MAX_PAYLOADS_PER_DUMB_FIELD);
                        for (const payloadString of selectedPayloads) {
                            if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                            try {
                                const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                this.setValueAtPath(modifiedMsg, field, payloadString);
                                log.debug(`[generateFuzzingPayloads] DUMB Inject: Field="${field}", PayloadString="${payloadString.substring(0,50)}...", ResultingMsg:`, JSON.stringify(modifiedMsg));
                                const isCallback = processedCallbackPayloads.includes(payloadString);
                                let payloadType = 'dumb-json';
                                if(isCallback) payloadType = 'dumb-json-callback';
                                if (customPayloadsActive && !isCallback) payloadType = 'custom-dumb-json';

                                generatedPayloads.push({
                                    type: payloadType, payload: modifiedMsg,
                                    targetFlow: `JSON Field: ${field}`, description: `Dumb ${isCallback ? 'Callback' : 'XSS'} targeting string field ${field}`
                                });
                                handledPaths.add(field);
                            } catch (e) {
                                log.error(`[generateFuzzingPayloads] DUMB Error setting field "${field}":`, e);
                            }
                        }
                    }
                }
            }
            else if (typeof baseMsgData === 'string') {
                log.debug(`[generateFuzzingPayloads] Processing raw string base message.`);
                const originalString = baseMsgData;
                const payloadsForString = shuffleArray(combinedPayloadStrings).slice(0, 15);
                let payloadTypeBase = 'dumb-string';
                if(customPayloadsActive) payloadTypeBase = 'custom-dumb-string';

                stringLoop: for (const payloadString of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break stringLoop;
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    const currentTypeBase = isCallback ? 'dumb-string-callback' : payloadTypeBase;
                    log.debug(`[generateFuzzingPayloads] RAW String Inject: TypeBase="${currentTypeBase}", PayloadString="${payloadString.substring(0,50)}..."`);

                    generatedPayloads.push({ type: `${currentTypeBase}-replace`, payload: payloadString, targetFlow: 'string replacement', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} replacing original string`, original: originalString });

                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: `${currentTypeBase}-append`, payload: originalString + payloadString, targetFlow: 'string append', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} appending`, original: originalString });
                    }
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: `${currentTypeBase}-prepend`, payload: payloadString + originalString, targetFlow: 'string prepend', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} prepending`, original: originalString });
                    }
                }
            } else {
                log.debug(`[generateFuzzingPayloads] Base message data is not a plain object or processable string.`);
            }
        }

        if (generatedPayloads.length === 0 && uniqueStructures.length === 0) {
            log.debug(`[generateFuzzingPayloads] No structures found, attempting fallback generation.`);
            const stringMessages = originalMessages.filter(msg => typeof msg?.data === 'string');
            if (stringMessages.length > 0) {
                log.debug(`[generateFuzzingPayloads] Fallback using first raw string message.`);
                const originalString = stringMessages[0].data;
                const payloadsForString = shuffleArray(combinedPayloadStrings).slice(0, 15);
                let payloadTypeBase = 'dumb-string';
                if(customPayloadsActive) payloadTypeBase = 'custom-dumb-string';
                stringLoopFallback: for (const payloadString of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break stringLoopFallback;
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    const currentTypeBase = isCallback ? 'dumb-string-callback' : payloadTypeBase;
                    log.debug(`[generateFuzzingPayloads] Fallback RAW String Inject: TypeBase="${currentTypeBase}", PayloadString="${payloadString.substring(0,50)}..."`);

                    generatedPayloads.push({ type: `${currentTypeBase}-replace`, payload: payloadString, targetFlow: 'string replacement fallback', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} replacing original string`, original: originalString });
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: `${currentTypeBase}-append`, payload: originalString + payloadString, targetFlow: 'string append fallback', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} appending`, original: originalString });
                    }
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        generatedPayloads.push({ type: `${currentTypeBase}-prepend`, payload: payloadString + originalString, targetFlow: 'string prepend fallback', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} prepending`, original: originalString });
                    }
                }
            } else {
                log.debug(`[generateFuzzingPayloads] Fallback using generic payloads.`);
                let payloadType = 'dumb-generic';
                if(customPayloadsActive) payloadType = 'custom-dumb-generic';
                shuffleArray(combinedPayloadStrings).slice(0, 10).forEach(p => {
                    if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                        const isCallback = processedCallbackPayloads.includes(p);
                        const currentType = isCallback ? 'dumb-generic-callback' : payloadType;
                        log.debug(`[generateFuzzingPayloads] Fallback Generic Inject: Type="${currentType}", PayloadString="${p.substring(0,50)}..."`);
                        generatedPayloads.push({ type: currentType, payload: p, targetFlow: 'generic string', description: `Generic ${isCallback ? 'Callback' : 'XSS'} payload (no structure/string)` });
                    }
                });
            }
        }

        log.debug(`[generateFuzzingPayloads] Finished generation. Total payloads: ${generatedPayloads.length}`);
        return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
    }

    setValueAtPath(obj, path, value) {
        return this.setNestedValue(obj, path, value);
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

    createSyntheticStructureFromPaths(pathsSet) {
        const structure = {};

        function setPathValue(obj, pathParts, value) {
            let current = obj;
            for (let i = 0; i < pathParts.length - 1; i++) {
                const part = pathParts[i];
                if (!current[part] || typeof current[part] !== 'object') {
                    const nextPart = pathParts[i + 1];
                    current[part] = /^\d+$/.test(nextPart) ? [] : {};
                }
                current = current[part];
            }
            const lastPart = pathParts[pathParts.length - 1];
            if (typeof current === 'object' && current !== null) {
                if (current[lastPart] === undefined) {
                    current[lastPart] = value;
                }
            }
        }

        const getDefaultValue = (path) => {
            const lowerPath = path.toLowerCase();
            if (lowerPath.includes('url') || lowerPath.includes('src') || lowerPath.includes('href')) return "https://example.com";
            if (lowerPath.includes('id') || lowerPath.includes('count') || lowerPath.includes('index')) return 0;
            if (lowerPath.includes('enabled') || lowerPath.includes('isvalid') || lowerPath.includes('success')) return true;
            if (lowerPath.includes('name') || lowerPath.includes('title')) return "Placeholder Name";
            if (lowerPath.includes('type') || lowerPath.includes('action') || lowerPath.includes('cmd') || lowerPath.includes('kind') || lowerPath.includes('messageType')) return "message";
            if (lowerPath.includes('description') || lowerPath.includes('text') || lowerPath.includes('content')) return "Placeholder text content.";
            return "placeholder_value";
        };
        const sortedPaths = Array.from(pathsSet).sort((a, b) => a.split(/[\.\[]/).length - b.split(/[\.\[]/).length);

        sortedPaths.forEach(path => {
            const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g)
                ?.map(part => part.startsWith('[') ? part.substring(1, part.length - 1).replace(/['"`]/g, '') : part) || [];

            if (parts.length > 0 && path !== '(root)') {
                setPathValue(structure, parts, getDefaultValue(path));
            }
        });

        if (pathsSet.has('(root)') && Object.keys(structure).length === 0) {
            return [{
                type: 'raw_value',
                original: getDefaultValue('(root)'),
                fields: [],
                fieldTypes: {},
                pathsToFuzz: [{path: '(root)', type: 'string'}],
                source: 'static-analysis'
            }];
        }

        if (Object.keys(structure).length === 0 && !pathsSet.has('(root)')) {
            return [];
        }


        const fieldTypes = this.getFieldTypesFromObject(structure);
        const fields = this.extractAllFieldsFromObject(structure);
        const typeFields = fields.filter(f => {
            const lowerF = f.toLowerCase();
            return lowerF === 'type' || lowerF === 'action' || lowerF === 'messagetype' ||
                lowerF === 'kind' || lowerF === 'cmd';
        });
        const structureVariants = [];

        if (typeFields.length > 0) {
            const commonTypeValues = ['message', 'notification', 'request', 'response', 'command', 'action', 'init', 'load', 'save', 'config'];
            const baseStructure = JSON.parse(JSON.stringify(structure));

            commonTypeValues.forEach(typeValue => {
                const variant = JSON.parse(JSON.stringify(baseStructure));
                typeFields.forEach(field => {
                    this.setValueAtPath(variant, field, typeValue);
                });

                structureVariants.push({
                    type: 'object',
                    original: variant,
                    pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })),
                    examples: [{ data: JSON.parse(JSON.stringify(variant)) }],
                    source: 'static-analysis-variant'
                });
            });

            if (structureVariants.length > 0) {
                return structureVariants;
            }
        }

        return [{
            type: 'object',
            original: JSON.parse(JSON.stringify(structure)),
            pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })),
            examples: [{ data: JSON.parse(JSON.stringify(structure)) }],
            source: 'static-analysis'
        }];
    }

    matchSinkPattern(destContext) {
        if (!destContext) return null;
        for (const sink of this.domXssSinks) {
            if (!sink.pattern) continue;
            let isMatch = false;
            if (sink.pattern instanceof RegExp) {
                const testRegex = new RegExp(sink.pattern.source, sink.pattern.flags.replace('g', ''));
                isMatch = testRegex.test(destContext);
            } else if (typeof sink.pattern === 'string') {
                isMatch = destContext.includes(sink.pattern);
            }
            if (isMatch) {
                return {
                    name: sink.name,
                    severity: sink.severity,
                    category: sink.category || 'generic'
                };
            }
        }
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
                    log.debug(`[AST Payload Gen] Using ${customXssPayloads.length} custom payloads from session storage.`);
                }
            }
        } catch (e) {
            log.error("[AST Payload Gen] Error accessing/parsing custom payloads from session storage:", e);
        }

        const allXssPayloads = customPayloadsActive
            ? customXssPayloads
            : (window.FuzzingPayloads?.XSS || ['<script>alert("FP_XSS_AST_Default")</script>']);

        let callbackUrl = null;
        let processedCallbackPayloads = [];
        try {
            const storageData = await new Promise(resolve => chrome.storage.session.get('callback_url', resolve));
            callbackUrl = storageData['callback_url'];
            if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) {
                const callbackTemplates = window.FuzzingPayloads.CALLBACK_URL;
                processedCallbackPayloads = callbackTemplates.map(template =>
                    template.replace(/%%CALLBACK_URL%%/g, callbackUrl)
                );
                console.log(`[AST Payload Gen] Prepared ${processedCallbackPayloads.length} callback payload strings.`);
            }
        } catch(e) {
            console.error("Error getting callback URL for AST payload generation:", e);
        }

        const combinedPayloadStrings = [...allXssPayloads, ...processedCallbackPayloads];
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());

        const accessedPaths = new Set();
        if (staticAnalysisData.accessedEventDataPaths) {
            const pathsToAdd = staticAnalysisData.accessedEventDataPaths instanceof Set
                ? Array.from(staticAnalysisData.accessedEventDataPaths)
                : (typeof staticAnalysisData.accessedEventDataPaths === 'object' ? Object.keys(staticAnalysisData.accessedEventDataPaths) : []);
            pathsToAdd.forEach(path => accessedPaths.add(path));
        }

        const dataFlows = staticAnalysisData.dataFlows || [];
        if (dataFlows.length > 0) {
            dataFlows.forEach(flow => {
                if (flow.sourcePath) { accessedPaths.add(flow.sourcePath); }
                if (flow.guardingConditions) {
                    flow.guardingConditions.forEach(cond => { if(cond.path) accessedPaths.add(cond.path); });
                }
                if (flow.taintedNodeSnippet) {
                    const matches = flow.taintedNodeSnippet.match(/event\.data\.([\w.[\]'"`]+)/g);
                    if (matches) {
                        matches.forEach(match => {
                            let path = match.replace('event.data.', '');
                            path = path.replace(/\[['"`]?([^\]'"`]+)['"`]?\]/g, '.$1');
                            if (path && path !== '') { accessedPaths.add(path); }
                        });
                    }
                }
            });
        }

        const syntheticStructures = this.createSyntheticStructureFromPaths(accessedPaths);

        const typeFields = Array.from(accessedPaths).filter(path => {
            const lowerPath = path.toLowerCase();
            return ['type', 'action', 'messagetype', 'kind', 'cmd'].includes(lowerPath);
        });

        const pathToSinkMap = new Map();
        const severityOrder = { 'critical': 3, 'high': 2, 'medium': 1, 'low': 0 };


        dataFlows.forEach(flow => {
            let path = flow.sourcePath;
            if (path === '(root)' && flow.taintedNodeSnippet) {
                const match = flow.taintedNodeSnippet.match(/^(?:event|e|msg|message)\.data\.([\w.[\]'"`]+)/);
                if (match && match[1]) path = match[1].replace(/\[['"`]?([^\]'"`]+)['"`]?\]/g, '.$1');
            }
            if (path && path !== '(root)') {
                const sinkInfo = this.matchSinkPattern(flow.destinationContext);
                if (sinkInfo && (!pathToSinkMap.has(path) || (severityOrder[sinkInfo.severity.toLowerCase()] || 0) > (severityOrder[pathToSinkMap.get(path)?.severity?.toLowerCase()] || 0))) {
                    pathToSinkMap.set(path, { ...sinkInfo, flowConditions: flow.guardingConditions || [] });
                } else if (!sinkInfo && !pathToSinkMap.has(path)) {
                    pathToSinkMap.set(path, { name: 'unknown', severity: 'Low', category: 'generic', flowConditions: flow.guardingConditions || [] });
                }
            }
        });
        (vulnerabilityAnalysis.sinks || []).forEach(sink => {
            let path = sink.path;
            if (path && path !== '(root)' && !pathToSinkMap.has(path)) {
                const category = this.domXssSinks.find(s => s.name === sink.type)?.category || 'generic';
                pathToSinkMap.set(path, { name: sink.type || 'unknown', severity: sink.severity || 'Medium', category: category, flowConditions: sink.conditions || [] });
            }
        });

        const requiredConditions = staticAnalysisData.requiredConditions || {};

        structureLoop: for (const structure of syntheticStructures) {
            if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break;
            if (!structure.type || structure.type !== 'object' || !structure.original) continue;

            let generalBaseMessageObject = JSON.parse(JSON.stringify(structure.original));
            Object.entries(requiredConditions).forEach(([path, value]) => {
                this.setValueAtPath(generalBaseMessageObject, path, value);
            });

            const pathsInStructure = structure.pathsToFuzz?.map(p => p.path) || [];

            for (const path of pathsInStructure) {
                if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                if (typeFields.includes(path)) continue;

                const sinkInfo = pathToSinkMap.get(path);
                const specificFlowConditions = sinkInfo?.flowConditions || [];

                let baseForThisPath = JSON.parse(JSON.stringify(generalBaseMessageObject));
                specificFlowConditions.forEach(cond => {
                    if (cond.path && cond.value !== undefined && (cond.op === '===' || cond.op === '==') && cond.path !== path) {
                        this.setValueAtPath(baseForThisPath, cond.path, cond.value);
                    }
                });

                let currentValAtPath = undefined;
                try {
                    let current = baseForThisPath;
                    const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
                    for(let i=0; i<parts.length -1; i++) { let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, ''); current = current?.[part]; }
                    let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
                    currentValAtPath = current?.[lastPart];
                } catch(e){}

                if (currentValAtPath === undefined) {
                    const syntheticStructPath = structure.pathsToFuzz?.find(p=>p.path === path);
                    const placeholderValue = syntheticStructPath ? (syntheticStructPath.type === 'string' ? 'placeholder' : (syntheticStructPath.type === 'number' ? 0 : true) ) : 'placeholder_value';
                    this.setValueAtPath(baseForThisPath, path, placeholderValue);
                }

                const useSmartLimit = sinkInfo && sinkInfo.name !== 'unknown';
                const limit = useSmartLimit ? MAX_PAYLOADS_PER_SINK_PATH : MAX_PAYLOADS_PER_COMMON_PATH;

                const payloadsToInject = shuffleArray(combinedPayloadStrings).slice(0, limit);

                let payloadType = 'ast-smart';
                const sinkSeverity = sinkInfo?.severity?.toLowerCase();
                if (!sinkInfo || sinkInfo.name === 'unknown' || sinkSeverity === 'low') {
                    payloadType = 'dumb-json';
                }
                if (customPayloadsActive) {
                    payloadType = useSmartLimit ? 'custom-ast-smart' : 'custom-ast-dumb';
                }


                for (const payloadString of payloadsToInject) {
                    if (generatedPayloads.length >= MAX_PAYLOADS_TOTAL) break structureLoop;
                    try {
                        const modifiedMessage = JSON.parse(JSON.stringify(baseForThisPath));
                        this.setValueAtPath(modifiedMessage, path, payloadString);
                        const isCallback = processedCallbackPayloads.includes(payloadString);
                        let currentPayloadType = payloadType;
                        if(isCallback) {
                            currentPayloadType = payloadType.startsWith('custom-')
                                ? (useSmartLimit ? 'custom-ast-smart-callback' : 'custom-ast-dumb-callback')
                                : (useSmartLimit ? 'ast-smart-callback' : 'dumb-json-callback');
                        }

                        generatedPayloads.push({
                            type: currentPayloadType,
                            payload: modifiedMessage,
                            targetPath: path,
                            sinkType: sinkInfo ? sinkInfo.name : 'unknown',
                            sinkSeverity: sinkInfo ? sinkInfo.severity : 'Low',
                            description: `AST ${isCallback ? 'Callback' : 'XSS'} payload for path: ${path}${sinkInfo ? ` -> ${sinkInfo.name}` : ' (generic target)'}`
                        });
                    } catch (e) {
                        log.error(`[AST Payload Gen] Error creating payload for path ${path}:`, e);
                    }
                }
            }
        }

        if (accessedPaths.has('(root)') && generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
            const rootFlow = dataFlows.find(f => f.sourcePath === '(root)');
            const rootSinkInfo = rootFlow ? this.matchSinkPattern(rootFlow.destinationContext) : null;
            const rootPayloadsToUse = shuffleArray(combinedPayloadStrings).slice(0, 20);

            rootPayloadsToUse.forEach(payloadString => {
                if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    let payloadType = customPayloadsActive ? 'custom-ast-raw' : 'ast-raw';
                    if(isCallback) payloadType = 'callback_url_raw';

                    generatedPayloads.push({
                        type: payloadType,
                        payload: payloadString,
                        targetPath: '(root)',
                        sinkType: rootSinkInfo?.name || 'unknown',
                        sinkSeverity: rootSinkInfo?.severity || 'Low',
                        description: `AST raw ${isCallback ? 'Callback' : 'XSS'} payload for root access${rootSinkInfo ? ` -> ${rootSinkInfo.name}` : ''}`
                    });
                }
            });
        }

        if (generatedPayloads.length === 0) {
            log.debug("[AST Payload Gen] No targeted payloads generated, creating final fallback payloads");
            shuffleArray(combinedPayloadStrings).slice(0, 30).forEach(payloadString => {
                if (generatedPayloads.length < MAX_PAYLOADS_TOTAL) {
                    const isCallback = processedCallbackPayloads.includes(payloadString);
                    let payloadType = customPayloadsActive ? 'custom-ast-fallback' : 'ast-fallback';
                    if(isCallback) payloadType = 'callback_url_raw';

                    generatedPayloads.push({
                        type: payloadType,
                        payload: payloadString,
                        targetPath: 'fallback',
                        sinkType: 'unknown',
                        sinkSeverity: 'Low',
                        description: `AST fallback ${isCallback ? 'Callback' : 'XSS'} payload` });
                }
            });
        }

        log.debug("[AST Payload Gen] Final generated payload count:", generatedPayloads.length);
        return generatedPayloads.slice(0, MAX_PAYLOADS_TOTAL);
    }

    getFieldTypesFromObject(obj, prefix = '', types = {}) {
        if (!obj || typeof obj !== 'object') return types;
        for (const key in obj) {
            if (Object.hasOwnProperty.call(obj, key)) {
                const fieldPath = prefix ? `${prefix}.${key}` : key;
                types[fieldPath] = Array.isArray(obj[key]) ? 'array' : typeof obj[key];
                if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                    this.getFieldTypesFromObject(obj[key], fieldPath, types);
                } else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') {
                    this.getFieldTypesFromObject(obj[key][0], `${fieldPath}[0]`, types);
                }
            }
        }
        return types;
    }

    extractAllFieldsFromObject(obj, prefix = '', fields = []) {
        if (!obj || typeof obj !== 'object') return fields;
        for (const key in obj) {
            if (Object.hasOwnProperty.call(obj, key)) {
                const fieldPath = prefix ? `${prefix}.${key}` : key;
                fields.push(fieldPath);
                if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                    this.extractAllFieldsFromObject(obj[key], fieldPath, fields);
                } else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') {
                    this.extractAllFieldsFromObject(obj[key][0], `${fieldPath}[0]`, fields);
                }
            }
        }
        return [...new Set(fields)];
    }

    setNestedValue(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) {
            if (typeof obj === 'string') return value;
            return;
        }
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
        let current = obj;
        for (let i = 0; i < parts.length - 1; i++) {
            let part = parts[i];
            if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
            const nextPartStr = parts[i + 1];
            let nextPartNormalized = nextPartStr;
            if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, '');
            const isNextPartIndex = /^\d+$/.test(nextPartNormalized);
            if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') {
                current[part] = isNextPartIndex ? [] : {};
            }
            current = current[part];
            if (typeof current !== 'object' || current === null) {
                return;
            }
        }
        let lastPart = parts[parts.length - 1];
        if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
        if (typeof current === 'object' && current !== null) {
            const isIndex = /^\d+$/.test(lastPart);
            if (Array.isArray(current) && isIndex) {
                const index = parseInt(lastPart, 10);
                current[index] = value;
            } else if (!Array.isArray(current)) {
                current[lastPart] = value;
            }
        }
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
.report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; }
.report-table .context-snippet { max-width: 400px; white-space: pre-wrap; word-break: break-all; display: inline-block; vertical-align: middle; }
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

span.highlight-finding {
  background-color: rgba(255, 0, 0, 0.3);
  color: #ffdddd;
  font-weight: bold;
  padding: 1px 2px;
  border-radius: 2px;
  border: 1px solid rgba(255, 100, 100, 0.5);
}
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

    if (!endpointKey) {
        window.log.error("Trace: Cannot determine endpoint key", originalFullEndpoint);
        updateTraceButton(traceButton, 'error');
        return;
    }

    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) {
        window.log.handler(`Trace already in progress for key: ${endpointKey}`);
        return;
    }
    sessionStorage.setItem(traceInProgressKey, 'true');
    window.log.scan(`Starting message trace for endpoint key: ${endpointKey}`);
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
    let vulnAnalysis = { sinks: [], securityIssues: [], dataFlows: [] };
    let uniqueStructures = [];
    let usedAstGenerator = false;
    let staticAnalyzer = null;
    let staticAnalysisData = null;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) window.handlerTracer = new HandlerTracer();
        if (typeof window.analyzeHandlerStatically === 'function') {
            staticAnalyzer = window.analyzeHandlerStatically;
        } else {
            window.log.warn("Static analyzer (analyzeHandlerStatically) not found on window object.");
        }

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;
        analysisStorageKey = getStorageKeyForUrl(endpointUrlUsedForAnalysis);

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;

        if (!handlerCode) throw new Error(`No handler code found in storage (${bestHandlerStorageKey}). Run Play first.`);

        const relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
        window.log.handler(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));

        if (staticAnalyzer && handlerCode) {
            try {
                const staticAnalysisResults = staticAnalyzer(handlerCode);
                if (staticAnalysisResults?.success && staticAnalysisResults.analysis) {
                    staticAnalysisData = staticAnalysisResults.analysis;
                    window.log.handler(`[Trace] Static analysis successful. Paths: ${staticAnalysisData.accessedEventDataPaths?.size || 0}, Flows: ${staticAnalysisData.dataFlows?.length || 0}, Conditions: ${Object.keys(staticAnalysisData.requiredConditions || {}).length}`);
                } else {
                    window.log.warn(`[Trace] Static analysis failed or returned no/invalid analysis object: ${staticAnalysisResults?.error}.`);
                }
            } catch(e) {
                window.log.error("Error executing static analyzer:", e);
            }
        }

        vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;


        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));

        if (relevantMessages.length > 0) {
            window.log.handler("[Trace] Messages found. Using standard message-based payload generation.");
            uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);
            window.log.handler(`[Trace] Found ${uniqueStructures.length} unique structures from messages.`);
            payloads = await window.handlerTracer.generateFuzzingPayloads(
                uniqueStructures,
                vulnAnalysis,
                relevantMessages
            );
        } else {
            window.log.handler("[Trace] No messages found (Silent Listener). Attempting AST-based payload generation.");
            if (staticAnalysisData && (staticAnalysisData.accessedEventDataPaths?.size > 0 || staticAnalysisData.dataFlows?.length > 0)) {
                payloads = await window.handlerTracer.generateAstBasedPayloads(
                    staticAnalysisData,
                    vulnAnalysis
                );
                usedAstGenerator = true;
                window.log.handler(`[Trace] AST-based generator created ${payloads.length} payloads.`);
            } else {
                window.log.warn("[Trace] No messages and insufficient AST data. Payload generation skipped.");
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

        window.log.info(`[Trace] Proceeding to save report. Payload count: ${payloads.length}. Used AST Generator: ${usedAstGenerator}`);
        const reportStorageKey = analysisStorageKey;

        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);

        if (!reportSaved || !payloadsSaved) {
            throw new Error("Failed to save trace report or payloads.");
        }
        window.log.success(`Trace report & ${payloads.length} payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true,
                criticalSinks: hasCriticalSinks,
                analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey,
                timestamp: Date.now(),
                payloadCount: payloads.length,
                sinkCount: vulnAnalysis.sinks?.length || 0,
                usedStaticAnalysis: usedAstGenerator
            }
        });
        window.log.handler(`Saved trace status for UI key ${traceInfoKey}: success=true, criticalSinks=${hasCriticalSinks}, payloadCount=${payloads.length}, usedStatic=${usedAstGenerator}...`);

        updateTraceButton(traceButton, 'success');
        if (playButton) updateButton(playButton, 'launch', { hasCriticalSinks: hasCriticalSinks, showEmoji: true });
        if (reportButton) {
            const reportState = hasCriticalSinks || (vulnAnalysis.securityIssues?.length || 0) > 0 ? 'green' : 'default';
            updateReportButton(reportButton, reportState, originalFullEndpoint);
        }

        window.log.info("[Trace] Analysis completed successfully");
        updatePhase('saving', 'completed');

    } catch (error) {
        console.error(`[Trace] Error during trace for ${originalFullEndpoint}:`, error);
        window.log.error(`[Trace] Error for ${originalFullEndpoint}:`, error.message);
        updateTraceButton(traceButton, 'error');
        const traceInfoKey = `trace-info-${endpointKey}`;
        try {
            await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false, error: error.message } });
        } catch (e) { console.error("Failed to save error state:", e); }

        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
        const errorPhaseLabel = progressContainer?.querySelector('.phase[data-phase="error"] .label');
        if(errorPhaseLabel) errorPhaseLabel.textContent = `Error: ${error.message.substring(0, 50)}...`;

    } finally {
        setTimeout(() => { if (progressContainer?.parentNode) progressContainer.parentNode.removeChild(progressContainer); }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        window.log.handler(`[Trace] Finished trace attempt for key ${endpointKey}`);
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
