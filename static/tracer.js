/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-05-07
 */
const DATA_PROP = 'data';

if (typeof window.analyzeHandlerStatically === 'undefined') {
    console.error("Static Handler Analyzer not loaded. Payload generation will be limited.");
    window.analyzeHandlerStatically = () => ({ success: false, error: 'Analyzer not loaded.', analysis: null });
}

class HandlerTracer {
    constructor() {
        this.domXssSinks = [
            { name: "eval", pattern: /\beval\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval', type: 'function', identifier: 'eval', argIndex: 0 },
            { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval', type: 'constructor', identifier: 'Function', argIndex: 0 },
            { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setTimeout', argIndex: 0, type: 'function', identifier: 'setTimeout' },
            { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setInterval', argIndex: 0, type: 'function', identifier: 'setInterval' },
            { name: "element.innerHTML assignment", pattern: /\.innerHTML\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'innerHTML', type: 'property', identifier: 'innerHTML' },
            { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High", methods: ['regex', 'ast'], argIndex: 1, category: 'innerHTML', type: 'method', identifier: 'insertAdjacentHTML' },
            { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'location_href', type: 'property', identifier: 'location', basePattern: /^(window|document|self|top|parent)$/ },
            { name: "OpenRedirect_assign_AST", pattern: /\.location\.assign$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href', type: 'method', identifier: 'assign', base: 'location' },
            { name: "OpenRedirect_replace_AST", pattern: /\.location\.replace$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href', type: 'method', identifier: 'replace', base: 'location' },
            { name: "location.href assign", pattern: /\.location\.href\s*=/, severity: "High", methods: ['regex'], category: 'location_href' },
            { name: "document.createElement('script')", pattern: /document\.createElement\s*\(\s*['"]script['"]\)/, severity: "High", methods: ['regex'], category: 'script_manipulation' },
            { name: "jQuery html", pattern: /\$\(.*\)\.html\s*\(|\$\.[a-zA-Z0-9_]+\.html\s*\(/, severity: "High", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'html', basePattern: /^\$/, argIndex: 0},
            { name: "iframe.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex', 'ast'], category: 'src_manipulation', type: 'property', identifier: 'src' },
            { name: "script.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex', 'ast'], category: 'script_manipulation', type: 'property', identifier: 'src' },
            { name: "srcdoc assignment", pattern: /\.srcdoc\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'innerHTML', type: 'property', identifier: 'srcdoc' },
            { name: "EvalInjection_setTimeout_AST", pattern: /^(?:window\.|self\.|top\.)?setTimeout$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setTimeout', type: 'function', identifier: 'setTimeout' },
            { name: "EvalInjection_setInterval_AST", pattern: /^(?:window\.|self\.|top\.)?setInterval$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setInterval', type: 'function', identifier: 'setInterval' },
            { name: "jQuery attr href", pattern: /\$.*?\.attr\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex', 'ast'], category: 'location_href', type: 'method', identifier: 'attr', basePattern: /^\$/, argIndex: 1 },
            { name: "jQuery prop href", pattern: /\$.*?\.prop\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex', 'ast'], category: 'location_href', type: 'method', identifier: 'prop', basePattern: /^\$/, argIndex: 1 },
            { name: "document.domain assignment", pattern: /document\.domain\s*=/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'property', identifier: 'domain', base: 'document' },
            { name: "document.cookie assignment", pattern: /document\.cookie\s*=/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'property', identifier: 'cookie', base: 'document' },
            { name: "createContextualFragment", pattern: /createContextualFragment\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'createContextualFragment', argIndex: 0 },
            { name: "jQuery append", pattern: /\$.*?\.append\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'append', basePattern: /^\$/, argIndex: 0 },
            { name: "jQuery prepend", pattern: /\$.*?\.prepend\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'prepend', basePattern: /^\$/, argIndex: 0 },
            { name: "jQuery after", pattern: /\$.*?\.after\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'after', basePattern: /^\$/, argIndex: 0 },
            { name: "jQuery before", pattern: /\$.*?\.before\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'innerHTML', type: 'method', identifier: 'before', basePattern: /^\$/, argIndex: 0 },
            { name: "element.appendChild", pattern: /\.appendChild\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'dom_manipulation', type: 'method', identifier: 'appendChild', argIndex: 0 },
            { name: "element.insertBefore", pattern: /\.insertBefore\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'dom_manipulation', type: 'method', identifier: 'insertBefore', argIndex: 0 },
            { name: "setAttribute dangerous", pattern: /\.setAttribute\s*\(\s*['"](?:src|href|onclick|onerror|onload|on\w+)['"]\)/, severity: "Medium", methods: ['regex', 'ast'], category: 'src_manipulation', type: 'method', identifier: 'setAttribute', argIndex: 1 },
            { name: "unsafe template literal", pattern: /`.*?\${(?![^{}]*?encodeURIComponent)(?![^{}]*?escape)/m, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "Handlebars.compile", pattern: /Handlebars\.compile\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'method', identifier: 'compile', base: 'Handlebars', argIndex: 0 },
            { name: "Vue $compile", pattern: /\$compile\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'method', identifier: '$compile', argIndex: 0 },
            { name: "Web Worker Regex", pattern: /new\s+Worker\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'constructor', identifier: 'Worker', argIndex: 0},
            { name: "Blob URL creation", pattern: /URL\.createObjectURL\s*\(/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'method', identifier: 'createObjectURL', base: 'URL', argIndex: 0 },
            { name: "Blob constructor", pattern: /new\s+Blob\s*\(\s*\[/, severity: "Medium", methods: ['regex', 'ast'], category: 'generic', type: 'constructor', identifier: 'Blob', argIndex: 0 },
            { name: "WebSocket URL Regex", pattern: /new\s+WebSocket\s*\((?![^)]*['"]wss?:\/\/)/, severity: "Medium", methods: ['regex'], category: 'generic' },
            { name: "element.on* assign", pattern: /\.on(?:error|load|click|mouseover|keydown|submit)\s*=/, severity: "Medium", methods: ['regex', 'ast'], category: 'event_handler', type: 'property', identifierPattern: /^on(?:error|load|click|mouseover|keydown|submit)$/ },
            { name: "URLManipulation_pushState_AST", pattern: /history\.pushState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href', type: 'method', identifier: 'pushState', base: 'history'},
            { name: "URLManipulation_replaceState_AST", pattern: /history\.replaceState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href', type: 'method', identifier: 'replaceState', base: 'history'},
            { name: "StorageManipulation_localStorage_AST", pattern: /localStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic', type: 'method', identifier: 'setItem', base: 'localStorage' },
            { name: "StorageManipulation_sessionStorage_AST", pattern: /sessionStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic', type: 'method', identifier: 'setItem', base: 'sessionStorage' },
            { name: "localStorage Regex", pattern: /localStorage\.setItem\s*\(|localStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "sessionStorage Regex", pattern: /sessionStorage\.setItem\s*\(|sessionStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "addEventListener other", pattern: /\.addEventListener\s*\(\s*['"](?!message)/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "URL constructor", pattern: /new\s+URL\s*\(/, severity: "Low", methods: ['regex', 'ast'], category: 'generic', type: 'constructor', identifier: 'URL', argIndex: 0 },
            { name: "URL prop manipulation", pattern: /\.(?:searchParams|pathname|hash|search)\s*=/, severity: "Low", methods: ['regex'], category: 'generic' },
            { name: "history manipulation Regex", pattern: /history\.(?:pushState|replaceState)\s*\(/, severity: "Low", methods: ['regex'], category: 'location_href' },
            { name: "WebSocketCreation_AST", pattern: /WebSocket$/, severity: 'Low', methods: ['ast'], nodeType: 'NewExpression', argIndex: 0, category: 'generic', type: 'constructor', identifier: 'WebSocket'},
            { name: "console.log", pattern: /console\.log\s*\(/, severity: "Low", methods: ['regex', 'ast'], category: 'generic', argIndex: 0, type: 'method', identifier: 'log', base: 'console'},
        ];
        this.securityChecks = [ { name: "Missing origin check", pattern: null, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Missing') }, { name: "Loose origin check", pattern: /\.origin\.(?:indexOf|includes|startsWith|endsWith|search|match)\s*\(/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Weak' && c.type?.includes('Method Call')) }, { name: "Weak origin comparison", pattern: /\.origin\s*(?:==|!=)\s*['"]/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Medium' && c.type?.includes('Equality')) }, { name: "Wildcard origin in postMessage", pattern: /postMessage\s*\([^,]+,\s*['"][\*]['"]\s*\)/, severity: "Medium" }, { name: "Using window.parent without origin check", pattern: /window\.parent\.postMessage\s*\((?![^)]*origin)/, severity: "Medium" }, { name: "No message type check", pattern: /addEventListener\s*\(\s*['"]message['"](?![^{]*?\.(?:type|messageType|kind|action))/ms, severity: "Low" }, { name: "Unsafe object assignment", pattern: /(?:Object\.assign|\.\.\.)[^;]*event\.data/, severity: "Medium" }, { name: "Unchecked JSON parsing", pattern: /JSON\.parse\s*\([^)]*?\)\s*(?!\.(?:hasOwnProperty|propertyIsEnumerable))/, severity: "Medium" }, { name: "Dynamic property access", pattern: /\[[^\]]*?\.data\.[^\]]*?\]/, severity: "Medium" }, { name: "Sensitive information leak", pattern: /postMessage\s*\(\s*(?:document\.cookie|localStorage|sessionStorage)/, severity: "High" }, { name: "Potential XSS in postMessage", pattern: /postMessage\s*\(\s*['"][^"']*?<[^"']*?(?:script|img|svg|iframe)[^"']*?>[^"']*?['"]/, severity: "High" }, { name: "Potential prototype pollution", pattern: /(?:Object\.assign\s*\(\s*[^,]+,|Object\.setPrototypeOf|__proto__)/, severity: "Medium" }, { name: "Dynamic function execution", pattern: /\[['"]\w+['"]\]\s*\([^)]*event\.data/, severity: "High" }, { name: "this[prop] function call", pattern: /this\s*\[[^\]]+\]\s*\(/, severity: "Medium" } ];
        this.severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0 };
        this.MAX_PAYLOADS_TOTAL = 5000;
        this.MAX_PAYLOADS_PER_DUMB_FIELD = 10;
        this.MAX_PAYLOADS_PER_SINK_PATH = 35;
        this.loadedCustomSinks = []; this.loadedCustomChecks = []; this.traceReport = null;
        this.DATA_PROP = DATA_PROP;
    }

    isPlainObject(obj) { if (typeof obj !== 'object' || obj === null) return false; let proto = Object.getPrototypeOf(obj); if (proto === null) return true; let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) { baseProto = Object.getPrototypeOf(baseProto); } return proto === baseProto; }
    analyzeJsonStructures(messages) { const structureMap = new Map(); if (!messages || messages.length === 0) return []; for (const message of messages) { if (!message) continue; try { let data = message.data; let dataType = typeof data; if (dataType === 'string') { if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) { try { data = JSON.parse(data); dataType = typeof data; } catch {} } } if (this.isPlainObject(data)) { const structure = this.getJsonStructure(data); const hash = this.hashJsonStructure(structure); if (!structureMap.has(hash)) { const paths = this.identifyPathsToFuzz(structure); structureMap.set(hash, { structure: structure, examples: [message], pathsToFuzz: paths, source: message.source || 'unknown_message_source' }); } else { const entry = structureMap.get(hash); if (entry.examples.length < 3) { entry.examples.push(message); } } } } catch {} } return Array.from(structureMap.values()); }
    getJsonStructure(obj, path = '') { if (obj === null || obj === undefined) return { type: 'null', path }; const type = typeof obj; if (type !== 'object') return { type: type, path }; if (Array.isArray(obj)) { const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` }; return { type: 'array', path, items: itemStructure }; } const structure = { type: 'object', path, properties: {} }; const keys = Object.keys(obj).sort(); for (const key of keys) { const newPath = path ? `${path}.${key}` : key; structure.properties[key] = this.getJsonStructure(obj[key], newPath); } return structure; }
    hashJsonStructure(structure) { if (!structure || !structure.type) return 'invalid'; if (structure.type === 'array') return `array[${this.hashJsonStructure(structure.items)}]`; if (structure.type !== 'object') return structure.type; const keys = Object.keys(structure.properties || {}).sort(); return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(','); }
    identifyPathsToFuzz(structure, currentPath = '', paths = []) { if (!structure) return paths; const nodePath = structure.path || currentPath; if (structure.type !== 'object' && structure.type !== 'array') { if (nodePath) paths.push({ path: nodePath, type: structure.type }); return paths; } if (structure.type === 'array' && structure.items) { this.identifyPathsToFuzz(structure.items, '', paths); } else if (structure.type === 'object' && structure.properties) { for (const key of Object.keys(structure.properties)) { this.identifyPathsToFuzz(structure.properties[key], '', paths); } } const uniquePaths = []; const seenPaths = new Set(); for (const p of paths) { if (p.path && !seenPaths.has(p.path)) { seenPaths.add(p.path); uniquePaths.push(p); } } return uniquePaths; }
    async _loadCustomDefinitions() { try { const data = await chrome.storage.sync.get(['customSinks', 'customChecks']); this.loadedCustomSinks = data.customSinks || []; this.loadedCustomChecks = data.customChecks || []; } catch (e) { this.loadedCustomSinks = []; this.loadedCustomChecks = []; } }
    async analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData = null) { await this._loadCustomDefinitions(); const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] }; const foundSinks = new Map(); if (!handlerCode) { return vulnerabilities; } const escapeHTML = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); const allSinks = [...this.domXssSinks, ...this.loadedCustomSinks]; allSinks.forEach(sink => { if (!sink.methods || sink.methods.includes('regex')) { let regex; try { regex = new RegExp(sink.pattern, 'g'); } catch (e) { return; } let match; while ((match = regex.exec(handlerCode)) !== null) { const exactMatchSnippet = match[0]; const sinkType = sink.name || sink.type || 'custom-sink'; const key = `${sinkType}#${exactMatchSnippet}`; if (!foundSinks.has(key)) { const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length); let highlightedContextHTML = escapeHTML(rawContext); let highlightStartIndex = -1; let highlightEndIndex = -1; const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet); if (matchIndexInRawContext !== -1) { highlightStartIndex = matchIndexInRawContext; highlightEndIndex = highlightStartIndex + exactMatchSnippet.length; const partBefore = rawContext.substring(0, highlightStartIndex); const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex); const partAfter = rawContext.substring(highlightEndIndex); highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter; } foundSinks.set(key, { type: sinkType, severity: sink.severity || 'Medium', context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex, method: 'regex', path: '', category: sink.category || 'custom' }); } } } });
        if(staticAnalysisData?.potentialSinks) {
            if (staticAnalysisData.dataFlows && Array.isArray(staticAnalysisData.dataFlows)) { vulnerabilities.dataFlows = staticAnalysisData.dataFlows; }
            staticAnalysisData.potentialSinks.forEach(staticSink => {
                const getCodeSnippetFromNode = (node) => {
                    if (!node || !node.range || typeof handlerCode !== 'string') return '[AST Node Snippet Unavailable]';
                    try { const startOffset = 0; const snippet = handlerCode.substring(node.range[0] - startOffset, node.range[1] - startOffset); return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : ''); } catch (e) { return '[snippet error]'; }
                };
                const sinkType = staticSink.name || staticSink.sinkPattern?.name || 'ast-sink';
                const context = staticSink.snippet || getCodeSnippetFromNode(staticSink.node);
                const key = `${sinkType}#${context}`;
                if (!foundSinks.has(key)) {
                    foundSinks.set(key, {
                        type: sinkType,
                        severity: staticSink.severity || staticSink.sinkPattern?.severity || 'Medium',
                        path: staticSink.path || staticSink.sourcePath || '(unknown path)',
                        conditions: staticSink.conditions || [],
                        context: escapeHTML(context),
                        highlightStart: -1,
                        highlightEnd: -1,
                        method: 'ast',
                        category: staticSink.category || staticSink.sinkPattern?.category || 'generic',
                        isGuarded: staticSink.isGuarded || 'unknown',
                        sourcePath: staticSink.sourcePath
                    });
                }
            });
        }
        vulnerabilities.sinks = Array.from(foundSinks.values()); const originChecks = staticAnalysisData?.originChecks || []; const securityIssuesFromStatic = staticAnalysisData?.securityIssues || []; vulnerabilities.securityIssues.push(...securityIssuesFromStatic); let originCheckCoveredByStatic = originChecks.length > 0 || securityIssuesFromStatic.some(iss => iss.type.toLowerCase().includes('origin check') || iss.type.toLowerCase().includes('origin validation')); const patternBasedChecks = this.securityChecks.filter(c => c.pattern); const allPatternChecks = [...patternBasedChecks, ...this.loadedCustomChecks]; for (const check of allPatternChecks) { if (check.name.toLowerCase().includes('origin check') && originCheckCoveredByStatic) { continue; } if (check.pattern) { let regex; try { const flags = [...new Set(['g', 'm', 's', ...(check.pattern.flags?.split('') || [])])].join(''); regex = new RegExp(check.pattern, flags); } catch (e) { continue; } let match; while ((match = regex.exec(handlerCode)) !== null) { const exactMatchSnippet = match[0]; const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length); let highlightedContextHTML = escapeHTML(rawContext); let highlightStartIndex = -1; let highlightEndIndex = -1; const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet); if (matchIndexInRawContext !== -1) { highlightStartIndex = matchIndexInRawContext; highlightEndIndex = highlightStartIndex + exactMatchSnippet.length; const partBefore = rawContext.substring(0, highlightStartIndex); const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex); const partAfter = rawContext.substring(highlightEndIndex); highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter; } if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context.includes(escapeHTML(exactMatchSnippet)))) { vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex }); } if (!regex.global) break; } } } const uniqueIssues = new Map(); vulnerabilities.securityIssues.forEach(issue => { const key = `${issue.type}#${issue.context}`; if (!uniqueIssues.has(key)) { uniqueIssues.set(key, issue); } }); vulnerabilities.securityIssues = Array.from(uniqueIssues.values()); return vulnerabilities; }
    extractContext(codeToSearchIn, index, length) { const before = Math.max(0, index - 50); const after = Math.min(codeToSearchIn.length, index + length + 50); let context = codeToSearchIn.substring(before, after); context = context.replace(/\n|\r/g, "↵").trim(); return context; }

    calculateRiskScore(analysisResults) {
        let penaltyScore = 0;
        const MAX_PENALTY = 100;
        const STRONG_CHECK_REWARD = 25;
        const MEDIUM_CHECK_REWARD = 10;
        const WEAK_CHECK_PENALTY = 3;
        const MISSING_CHECK_PENALTY = 20;


        if (!analysisResults) return 0;

        const sinks = analysisResults.sinks || [];
        const issues = analysisResults.securityIssues || [];
        const dataFlows = analysisResults.dataFlows || [];
        const originChecks = analysisResults.originChecks || [];

        let hasStrongOriginCheck = false;
        let hasMediumOriginCheck = false;
        let hasWeakOriginCheck = false;
        let explicitOriginChecksFound = originChecks.length > 0 && !originChecks.some(c => c.strength === 'Missing');

        originChecks.forEach(check => {
            switch (check.strength?.toLowerCase()) {
                case 'strong':
                    penaltyScore -= STRONG_CHECK_REWARD;
                    hasStrongOriginCheck = true;
                    break;
                case 'medium':
                    penaltyScore -= MEDIUM_CHECK_REWARD;
                    hasMediumOriginCheck = true;
                    break;
                case 'weak':
                    penaltyScore += WEAK_CHECK_PENALTY;
                    hasWeakOriginCheck = true;
                    break;
                case 'missing':
                    penaltyScore += MISSING_CHECK_PENALTY;
                    break;
            }
        });

        sinks.forEach(sink => {
            switch (sink.severity?.toLowerCase()) {
                case 'critical': penaltyScore += 35; break;
                case 'high': penaltyScore += 20; break;
                case 'medium': penaltyScore += 8; break;
                case 'low': penaltyScore += 2; break;
                default: penaltyScore += 1; break;
            }
        });

        let mediumIssueCount = 0;
        issues.forEach(issue => {
            if (issue.type.toLowerCase().includes('origin check') || issue.type.toLowerCase().includes('origin validation issue')) { return; }
            switch (issue.severity?.toLowerCase()) {
                case 'high': penaltyScore += 15; break;
                case 'medium': mediumIssueCount++; penaltyScore += 5 + Math.min(mediumIssueCount, 4); break;
                case 'low': penaltyScore += 3; break;
                default: penaltyScore += 1; break;
            }
        });

        const flowsToConsider = analysisResults.dataFlows || [];
        if (flowsToConsider.length > 0) {
            let flowPenalty = 0;
            flowsToConsider.forEach(flow => {
                const severity = flow.severity || analysisResults.sinks?.find(s => s.name === flow.sink)?.severity || 'Medium';
                switch (severity.toLowerCase()) {
                    case 'critical': flowPenalty += 5; break;
                    case 'high': flowPenalty += 3; break;
                    case 'medium': flowPenalty += 1; break;
                    default: flowPenalty += 0.5; break;
                }
            });
            penaltyScore += Math.min(flowPenalty, 25);
        }

        if (issues.some(issue => issue.type.toLowerCase().includes('window.parent') && issue.type.toLowerCase().includes('origin check'))) { penaltyScore += 10; }

        penaltyScore = Math.max(0, penaltyScore);
        penaltyScore = Math.min(penaltyScore, MAX_PENALTY);
        let finalScore = Math.max(0, 100 - penaltyScore);
        return Math.round(finalScore);
    }

    createStructureFromStaticAnalysis(staticAnalysisData) {
        if (!staticAnalysisData || typeof staticAnalysisData !== 'object') {
            log.warn("[Payload Gen] createStructureFromStaticAnalysis: Invalid staticAnalysisData received.");
            return null;
        }
        log.debug("[Payload Gen] createStructureFromStaticAnalysis: Input staticAnalysisData:", staticAnalysisData);

        const structure = {
            type: 'synthesized_object',
            example: {},
            processedData: {},
            fields: new Set(),
            keySignature: 'synthesized:object:'
        };

        let accessedPaths = staticAnalysisData?.accessedEventDataPaths || [];
        if (!Array.isArray(accessedPaths)) {
            accessedPaths = accessedPaths instanceof Set ? Array.from(accessedPaths) : [];
        }
        const pathsSet = new Set(accessedPaths);
        log.debug("[Payload Gen] createStructureFromStaticAnalysis: Using accessed paths:", pathsSet);

        if (pathsSet.size === 0 || (pathsSet.size === 1 && (pathsSet.has('(root)') || pathsSet.has('(parsed_root)') || pathsSet.has('(root_data)') || pathsSet.has('(Tainted non-data property)')))) {
            log.warn("[Payload Gen] createStructureFromStaticAnalysis: No usable paths found for synthesis.");
            return null;
        }

        try {
            pathsSet.forEach(path => {
                if (path && typeof path === 'string' && path !== '(root)' && path !== '(root_data)' && path !== '(parsed_root)' && path !== '(Tainted non-data property)' && !path.startsWith('(parsed ') && !path.startsWith('(from_parsed ') && path !== '(unknown_expression)') {
                    const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
                    const cleanedParts = parts.map(p => p.startsWith('[') ? p.substring(1, p.length - 1).replace(/['"`]/g, '') : p);

                    if (cleanedParts.length > 0 && cleanedParts[0]) {
                        let currentLevelInExample = structure.example;
                        for (let i = 0; i < cleanedParts.length; i++) {
                            const partKey = cleanedParts[i];
                            if (i === cleanedParts.length - 1) {
                                currentLevelInExample[partKey] = "default_value";
                            } else {
                                if (!currentLevelInExample[partKey] || typeof currentLevelInExample[partKey] !== 'object') {
                                    currentLevelInExample[partKey] = {};
                                }
                                currentLevelInExample = currentLevelInExample[partKey];
                            }
                        }
                        structure.fields.add(path);
                        structure.processedData[path] = "default_value";
                    } else {
                        log.warn(`[Payload Gen] Synthesis: Skipping invalid path format after cleaning: ${path}`);
                    }
                } else {
                    log.debug(`[Payload Gen] Synthesis: Skipping generic/ignored path: ${path}`);
                }
            });

            if (structure.fields.size > 0) {
                log.debug("[Payload Gen] createStructureFromStaticAnalysis: Successfully synthesized structure:", structure);
                return structure;
            } else {
                log.warn("[Payload Gen] createStructureFromStaticAnalysis: No fields added to synthesized structure.");
                return null;
            }
        } catch (e) {
            log.error("[Payload Gen] Synthesis Error Stack:", e.stack);
            return null;
        }
    }

    setNestedValue(obj, path, value) {
        if (!obj || !path) { return; }
        if (path === 'raw' && typeof obj !== 'object') { throw new Error("Cannot set raw value on non-object/array"); }
        if (path === 'raw') {
            log.warn("setNestedValue raw path handling is ambiguous. Ignoring.");
            return;
        }

        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
        let current = obj;

        for (let i = 0; i < parts.length - 1; i++) {
            let part = parts[i];
            let isIndex = false;
            if (part.startsWith('[')) {
                part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
                isIndex = /^\d+$/.test(part);
                if(isIndex) part = parseInt(part, 10);
            }

            const nextPartStr = parts[i + 1];
            let nextPartNormalized = nextPartStr;
            if (nextPartNormalized.startsWith('[')) {
                nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, '');
            }
            const isNextPartIndex = /^\d+$/.test(nextPartNormalized);

            if (current[part] === undefined || current[part] === null) {
                current[part] = isNextPartIndex ? [] : {};
            } else if (typeof current[part] !== 'object') {
                current[part] = isNextPartIndex ? [] : {};
            }

            current = current[part];
            if (typeof current !== 'object' || current === null) {
                log.warn(`Cannot traverse deeper into path "${path}" at part "${part}". Current level is not an object/array.`);
                return;
            }
        }

        let lastPart = parts[parts.length - 1];
        let lastIsIndex = false;
        if (lastPart.startsWith('[')) {
            lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
            lastIsIndex = /^\d+$/.test(lastPart);
            if(lastIsIndex) lastPart = parseInt(lastPart, 10);
        }

        if (typeof current === 'object' && current !== null) {
            if (Array.isArray(current) && lastIsIndex) {
                current[lastPart] = value;
            } else if (!Array.isArray(current)) {
                current[lastPart] = value;
            } else {
                log.warn(`Type mismatch trying to set property "${lastPart}" on an array.`);
            }
        } else {
            log.warn(`Cannot set value for path "${path}". Penultimate level is not an object/array.`);
        }
    }


    _deepCopy(obj) { try { if (obj === null || typeof obj !== 'object') { return obj; } return JSON.parse(JSON.stringify(obj)); } catch (e) { const copy = Array.isArray(obj) ? [] : {}; for(const key in obj){ if(Object.prototype.hasOwnProperty.call(obj, key)) { try { copy[key] = this._deepCopy(obj[key]); } catch { copy[key] = '[Uncopyable]'; }}} return copy; } }

    async _getPayloadLists() { let customXssPayloads = []; let customPayloadsActive = false; let callbackUrl = null; let processedCallbackPayloads = []; try { const results = await new Promise(resolve => chrome.storage.session.get(['customXssPayloads', 'callback_url'], resolve)); customXssPayloads = results.customXssPayloads || []; callbackUrl = results.callback_url; customPayloadsActive = customXssPayloads.length > 0; if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) { processedCallbackPayloads = window.FuzzingPayloads.CALLBACK_URL.map(template => String(template).replace(/%%CALLBACK_URL%%/g, callbackUrl)); } } catch (e) {} const baseFuzzingPayloads = window.FuzzingPayloads || { XSS: [], SINK_SPECIFIC: {}, TYPE_FUZZ: [], PROTOTYPE_POLLUTION: [], ENCODING: [] }; const activeXssPayloads = customPayloadsActive ? customXssPayloads : (baseFuzzingPayloads.XSS || []); const encodingPayloads = baseFuzzingPayloads.ENCODING || []; const typeFuzzPayloads = baseFuzzingPayloads.TYPE_FUZZ || [null, true, false, 0, -1, 1.23, 9999999999999999, [], {}]; const combinedXss = [...new Set([...activeXssPayloads, ...encodingPayloads])].map(p => String(p)); const sinkCategoryToPayloadMap = { 'eval': baseFuzzingPayloads.SINK_SPECIFIC?.eval || combinedXss, 'setTimeout': baseFuzzingPayloads.SINK_SPECIFIC?.setTimeout || combinedXss, 'setInterval': baseFuzzingPayloads.SINK_SPECIFIC?.setInterval || combinedXss, 'innerHTML': baseFuzzingPayloads.SINK_SPECIFIC?.innerHTML || combinedXss, 'script_manipulation': combinedXss, 'src_manipulation': [...combinedXss, ...processedCallbackPayloads], 'location_href': baseFuzzingPayloads.SINK_SPECIFIC?.location_href || [...combinedXss, ...processedCallbackPayloads], 'event_handler': combinedXss, 'dom_manipulation': combinedXss, 'generic': [...combinedXss, ...processedCallbackPayloads], 'default': [...combinedXss, ...processedCallbackPayloads] }; for (const key in sinkCategoryToPayloadMap) { if (!Array.isArray(sinkCategoryToPayloadMap[key])) { sinkCategoryToPayloadMap[key] = [...combinedXss, ...processedCallbackPayloads].map(p => String(p)); } else { sinkCategoryToPayloadMap[key] = sinkCategoryToPayloadMap[key].map(p => String(p)); } } return { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads: processedCallbackPayloads, typeFuzzPayloads }; }

    _satisfyConditions(baseObject, conditions) {
        log.debug("[Payload Gen - _satisfyConditions] Initial baseObject:", JSON.stringify(baseObject), "Conditions to satisfy:", JSON.stringify(conditions));
        if (!conditions || conditions.length === 0 || !baseObject || typeof baseObject !== 'object') {
            return this._deepCopy(baseObject);
        }
        const modifiedBase = this._deepCopy(baseObject);
        for (const cond of conditions) {
            if (!cond || !cond.path || cond.value === undefined) {
                log.debug(`[Payload Gen - _satisfyConditions] Skipping invalid or incomplete condition:`, JSON.stringify(cond));
                continue;
            }
            if (String(cond.value).startsWith('[EXPRESSION:')) {
                log.debug(`[Payload Gen - _satisfyConditions] Skipping expression-based condition:`, JSON.stringify(cond));
                continue;
            }

            try {
                if ((cond.op === '===' || cond.op === '==') && cond.value !== null) {
                    log.debug(`[Payload Gen - _satisfyConditions] Attempting to apply equality condition: path='${cond.path}', op='${cond.op}', value='${cond.value}'`);
                    this.setNestedValue(modifiedBase, cond.path, cond.value);
                    log.debug(`[Payload Gen - _satisfyConditions] Applied condition. Path '${cond.path}' SET to '${cond.value}'. Current base:`, JSON.stringify(modifiedBase));
                } else if (cond.op === 'truthy' && cond.value === true) {
                    log.debug(`[Payload Gen - _satisfyConditions] Attempting to apply truthy condition: path='${cond.path}'`);
                    try {
                        let existingValue = null;
                        let current = modifiedBase;
                        const parts = cond.path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
                        let pathExists = true;
                        for (let i = 0; i < parts.length - 1; i++) {
                            let part = parts[i];
                            if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
                            if (current[part] === undefined || current[part] === null) { pathExists = false; break; }
                            current = current[part];
                        }
                        if (pathExists) {
                            let lastPart = parts[parts.length - 1];
                            if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
                            existingValue = current?.[lastPart];
                        } else {
                            existingValue = undefined;
                        }

                        if (existingValue === false || existingValue === null || existingValue === 0 || existingValue === '') {
                            this.setNestedValue(modifiedBase, cond.path, true);
                            log.debug(`[Payload Gen - _satisfyConditions] Applied truthy. Path '${cond.path}' set to true (was falsy). Base:`, JSON.stringify(modifiedBase));
                        } else if (existingValue === undefined && cond.path !== '(root_data)' && cond.path !== '(parsed_root)') { // only set if not a generic root path
                            this.setNestedValue(modifiedBase, cond.path, true);
                            log.debug(`[Payload Gen - _satisfyConditions] Applied truthy. Path '${cond.path}' set to true (was undefined). Base:`, JSON.stringify(modifiedBase));
                        } else {
                            log.debug(`[Payload Gen - _satisfyConditions] Truthy condition for '${cond.path}' already met or path is root. Value: ${existingValue}. Base:`, JSON.stringify(modifiedBase));
                        }
                    } catch (e) {
                        log.error(`[Payload Gen - _satisfyConditions] Error applying truthy for path '${cond.path}', setting to true as fallback. Error: ${e.message}`);
                        if (cond.path !== '(root_data)' && cond.path !== '(parsed_root)') {
                            this.setNestedValue(modifiedBase, cond.path, true);
                        }
                    }
                } else if (cond.op === 'typeof' && typeof cond.value === 'string') {
                    let sampleValue;
                    switch (cond.value) {
                        case 'string': sampleValue = 'frog_generated_string'; break;
                        case 'number': sampleValue = 1337; break;
                        case 'boolean': sampleValue = true; break;
                        case 'object': sampleValue = { frog_generated_object: true }; break;
                        default: continue;
                    }
                    log.debug(`[Payload Gen - _satisfyConditions] Applying typeof condition: path='${cond.path}', type='${cond.value}', setting value:`, sampleValue);
                    this.setNestedValue(modifiedBase, cond.path, sampleValue);
                    log.debug(`[Payload Gen - _satisfyConditions] Applied typeof. Base:`, JSON.stringify(modifiedBase));
                } else {
                    log.debug(`[Payload Gen - _satisfyConditions] Skipping condition with unhandled op '${cond.op}' or null value for path '${cond.path}'`);
                }
            } catch (e) {
                log.error(`[Payload Gen - _satisfyConditions] Error processing condition for path '${cond.path}'`, e, JSON.stringify(cond));
            }
        }
        log.debug("[Payload Gen - _satisfyConditions] Final modifiedBase:", JSON.stringify(modifiedBase));
        return modifiedBase;
    }


    async generateDefaultPayloads(context) {
        const { uniqueStructures = [], originalMessages = [] } = context;
        const generatedPayloads = [];
        const handledPathValuePairs = new Set();

        const { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads, typeFuzzPayloads } = await this._getPayloadLists();
        const defaultPayloadList = [...new Set([...(sinkCategoryToPayloadMap['default'] || []), ...typeFuzzPayloads])];
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());

        const objectStructures = uniqueStructures.filter(s => s.structure.type === 'object' && s.examples && s.examples.length > 0 && typeof s.examples[0].data === 'object');
        const rawStringStructures = uniqueStructures.filter(s => s.structure.type !== 'object' && s.examples && s.examples.length > 0 && typeof s.examples[0].data === 'string');

        if (originalMessages && originalMessages.length > 0) {
            originalMessages.forEach(msg => {
                const msgData = msg?.data;
                const msgSource = msg?.source || 'original_message';
                if (typeof msgData === 'string') {
                    if (!rawStringStructures.some(rs => rs.baseObject === msgData)) {
                        let isPotentialJson = false; try { if ((msgData.startsWith('{') && msgData.endsWith('}')) || (msgData.startsWith('[') && msgData.endsWith(']'))) { JSON.parse(msgData); isPotentialJson = true; } } catch {}
                        if (!isPotentialJson) {
                            rawStringStructures.push({ source: msgSource, baseObject: msgData, type: 'raw-string', examples: [{data: msgData, source: msgSource}] });
                        }
                    }
                } else if (typeof msgData === 'object' && msgData !== null) {
                    if (!objectStructures.some(os => JSON.stringify(os.examples[0].data) === JSON.stringify(msgData))) {
                        objectStructures.push({ source: msgSource, baseObject: msgData, type: 'object', structure: {type: 'object', keySignature: 'original_message_object'}, examples: [{data: msgData, source: msgSource}] });
                    }
                }
            });
        }

        log.info(`[Payload Gen - Default] Starting. Object Structures: ${objectStructures.length}, Raw Strings: ${rawStringStructures.length}`);

        if (objectStructures.length > 0) {
            const limitedDefaultPayloads = shuffleArray(defaultPayloadList).slice(0, this.MAX_PAYLOADS_PER_DUMB_FIELD);

            for (const baseStructInfo of objectStructures) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const baseObject = (baseStructInfo.baseObject && typeof baseStructInfo.baseObject === 'object' && !Array.isArray(baseStructInfo.baseObject)) ? baseStructInfo.baseObject : baseStructInfo.examples?.[0]?.data;
                const sourceName = baseStructInfo.examples?.[0]?.source || baseStructInfo.source || 'unknown_object_source';
                if (!baseObject || typeof baseObject !== 'object' || baseObject === null) {
                    log.warn(`[Payload Gen - Default] Skipping structure from ${sourceName} due to invalid/null base object.`);
                    continue;
                }

                const pathsToFuzz = [];
                const getAllPaths = (obj, prefix = '') => {
                    if (obj === null || typeof obj !== 'object') return;
                    Object.keys(obj).forEach(key => {
                        const currentPath = prefix ? `${prefix}.${key}` : key;
                        pathsToFuzz.push(currentPath);
                        if (typeof obj[key] === 'object' && obj[key] !== null) {
                            if (Array.isArray(obj[key])) {
                                obj[key].forEach((item, index) => {
                                    const arrayIndexPath = `${currentPath}[${index}]`;
                                    pathsToFuzz.push(arrayIndexPath);
                                    if (typeof item === 'object' && item !== null) { getAllPaths(item, arrayIndexPath); }
                                });
                            } else { getAllPaths(obj[key], currentPath); }
                        }
                    });
                };

                try { getAllPaths(baseObject, ''); } catch(e) { log.error(`Error extracting paths from base object for ${sourceName}`, e); continue; }
                const uniquePaths = [...new Set(pathsToFuzz)];

                if (uniquePaths.length === 0) { log.warn(`[Payload Gen - Default] No paths found to fuzz for structure from ${sourceName}`); continue; }
                log.debug(`[Payload Gen - Default] Fuzzing ${uniquePaths.length} unique paths for structure from ${sourceName}`);

                for (const targetPath of uniquePaths) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    for (const payload of limitedDefaultPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        try {
                            const finalMessage = this._deepCopy(baseObject);
                            this.setNestedValue(finalMessage, targetPath, payload);
                            const payloadKey = JSON.stringify(finalMessage);
                            if (handledPathValuePairs.has(payloadKey)) continue;

                            const isCallback = allCallbackPayloads.includes(payload);
                            const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload);
                            const isTypeFuzz = typeFuzzPayloads.includes(payload);
                            let pType = customPayloadsActive ? 'custom-default-dumb' : 'default-dumb';
                            if (isCallback) pType += '-callback'; else if(isEncoding) pType += '-encoding'; else if(isTypeFuzz) pType += '-type'; else pType += '-xss';

                            generatedPayloads.push({
                                type: pType, payload: finalMessage, targetPath: targetPath, sinkType: 'N/A (Default Fuzz)', sinkSeverity: 'Low',
                                description: `Default ${isCallback ? 'Callback' : (isEncoding ? 'Encoding' : (isTypeFuzz ? `Type (${typeof payload})` : 'XSS'))} for field ${targetPath}`,
                                baseSource: sourceName
                            });
                            handledPathValuePairs.add(payloadKey);
                        } catch (e) { log.error(`Error setting value for default path ${targetPath}`, e); }
                    }
                }
            }
        }

        if (rawStringStructures.length > 0) {
            log.info(`[Payload Gen - Default] Processing ${rawStringStructures.length} raw string messages.`);
            const limitedPayloads = shuffleArray(defaultPayloadList).slice(0, this.MAX_PAYLOADS_PER_DUMB_FIELD * 2);

            for (const baseStructInfo of rawStringStructures) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const originalString = String(baseStructInfo.baseObject ?? baseStructInfo.examples?.[0]?.data ?? '');
                const sourceName = baseStructInfo.examples?.[0]?.source || baseStructInfo.source || 'unknown_raw_source';

                log.debug(`[Payload Gen - Default] Generating raw string payloads based on: "${originalString.substring(0, 50)}..." from ${sourceName}`);
                for (const payload of limitedPayloads) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const isCallback = allCallbackPayloads.includes(payload); const isTypeFuzz = typeFuzzPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload);
                    let pTypeBase = customPayloadsActive ? 'custom-default-raw' : 'default-raw';
                    if (isCallback) pTypeBase += '-callback'; else if (isTypeFuzz) pTypeBase += '-type'; else if (isEncoding) pTypeBase += '-encoding'; else pTypeBase += '-xss';

                    const replacePayload = { type: `${pTypeBase}-replace`, payload: payload, targetPath: 'raw', sinkType: 'unknown', description: `Default Raw Replace (${typeof payload})`, baseSource: sourceName, original: originalString };
                    let replaceKey; try {replaceKey = JSON.stringify(replacePayload.payload);} catch{replaceKey = String(replacePayload.payload);}
                    if (!handledPathValuePairs.has(replaceKey + '-replace')) { generatedPayloads.push(replacePayload); handledPathValuePairs.add(replaceKey + '-replace');}
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;

                    if(typeof payload === 'string' && originalString.length > 0) {
                        const appendPayload = { type: `${pTypeBase}-append`, payload: originalString + payload, targetPath: 'raw', sinkType: 'unknown', description: `Default Raw Append`, baseSource: sourceName, original: originalString };
                        let appendKey; try {appendKey = JSON.stringify(appendPayload.payload);} catch{appendKey = String(appendPayload.payload);}
                        if (!handledPathValuePairs.has(appendKey + '-append')) { generatedPayloads.push(appendPayload); handledPathValuePairs.add(appendKey + '-append');}
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;

                        const prependPayload = { type: `${pTypeBase}-prepend`, payload: payload + originalString, targetPath: 'raw', sinkType: 'unknown', description: `Default Raw Prepend`, baseSource: sourceName, original: originalString };
                        let prependKey; try {prependKey = JSON.stringify(prependPayload.payload);} catch{prependKey = String(prependPayload.payload);}
                        if (!handledPathValuePairs.has(prependKey + '-prepend')) { generatedPayloads.push(prependPayload); handledPathValuePairs.add(prependKey + '-prepend'); }
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    }
                }
            }
        }

        if (generatedPayloads.length === 0 && defaultPayloadList.length > 0) {
            log.warn("[Payload Gen - Default] No payloads generated from structures. Adding basic raw fallback.");
            const limitedFallbackPayloads = shuffleArray(defaultPayloadList).slice(0, 15);
            limitedFallbackPayloads.forEach(p => {
                if (generatedPayloads.length < this.MAX_PAYLOADS_TOTAL) {
                    const isCallback = allCallbackPayloads.includes(p); const isTypeFuzz = typeFuzzPayloads.includes(p); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(p);
                    let pTypeBase = customPayloadsActive ? 'custom-raw-fallback' : 'raw-fallback';
                    if (isCallback) pTypeBase += '-callback'; else if (isTypeFuzz) pTypeBase += '-type'; else if (isEncoding) pTypeBase += '-encoding'; else pTypeBase += '-xss';
                    const fallbackPayload = { type: pTypeBase, payload: p, targetPath: 'raw', sinkType: 'unknown', description: `Raw Fallback Payload (${typeof p})`, baseSource: 'fallback' };
                    let fbKey; try { fbKey = JSON.stringify(fallbackPayload.payload); } catch { fbKey = String(fallbackPayload.payload); }
                    if (!handledPathValuePairs.has(fbKey + '-fallback')) { generatedPayloads.push(fallbackPayload); handledPathValuePairs.add(fbKey + '-fallback');}
                }
            });
        }

        log.info(`[Payload Gen - Default] Final default payload count: ${generatedPayloads.length}`);
        return generatedPayloads.slice(0, this.MAX_PAYLOADS_TOTAL);
    }

    async generateSmartPayloads(context) {
        const { uniqueStructures = [], vulnerabilities = { sinks: [], securityIssues: [] }, staticAnalysisData = null, originalMessages = [], dynamicAnalysisResults = null } = context;
        const safeStaticData = staticAnalysisData || {};
        const potentialSinks = safeStaticData.potentialSinks || [];
        const requiredConditions = safeStaticData.requiredConditions || {};
        const analysisSucceeded = !!staticAnalysisData;

        const generatedPayloads = [];
        const handledSmartPayloadKeys = new Set();
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());
        const { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads, typeFuzzPayloads } = await this._getPayloadLists();

        let synthesizedBaseStructure = null;
        if (analysisSucceeded && staticAnalysisData) {
            try {
                synthesizedBaseStructure = this.createStructureFromStaticAnalysis(staticAnalysisData);
                log.debug("[Payload Gen - Smart] Synthesized base structure example:", synthesizedBaseStructure ? JSON.stringify(synthesizedBaseStructure.example) : "null");
            } catch(e) {
                log.error("[Payload Gen - Smart] Error creating synthesized base structure:", e);
                synthesizedBaseStructure = null;
            }
        }

        const objectStructuresFromMessages = uniqueStructures
            .filter(s => s.structure.type === 'object' && s.examples && s.examples.length > 0 && typeof s.examples[0].data === 'object' && s.examples[0].data !== null)
            .map(s => ({
                base: s.examples[0].data,
                sourceName: s.examples?.[0]?.source || s.source || 'message_observed',
                id: (s.examples?.[0]?.source || s.source || 'message_observed') + '|' + (s.structure?.keySignature || s.hash || 'no-sig')
            }));

        const rawStringExamples = uniqueStructures
            .filter(s => s.structure.type !== 'object' && s.examples && s.examples.length > 0 && typeof s.examples[0].data === 'string')
            .map(s => ({
                base: s.examples[0].data,
                sourceName: s.examples?.[0]?.source || s.source || 'raw_string_observed',
                id: (s.examples?.[0]?.source || s.source || 'raw_string_observed') + '|' + (s.hash || 'no-sig')
            }));

        if (originalMessages && originalMessages.length > 0) {
            originalMessages.forEach(msg => {
                const msgData = msg?.data;
                const msgSource = msg?.source || 'original_message';
                if (typeof msgData === 'string') {
                    if (!rawStringExamples.some(rs => rs.base === msgData && rs.sourceName === msgSource )) {
                        let isPotentialJson = false; try { if ((msgData.startsWith('{') && msgData.endsWith('}')) || (msgData.startsWith('[') && msgData.endsWith(']'))) { JSON.parse(msgData); isPotentialJson = true; } } catch {}
                        if (!isPotentialJson) { rawStringExamples.push({ base: msgData, sourceName: msgSource, id: `${msgSource}|${msgData.substring(0,50)}`}); }
                    }
                } else if (typeof msgData === 'object' && msgData !== null) {
                    if (!objectStructuresFromMessages.some(os => os.sourceName === msgSource && JSON.stringify(os.base) === JSON.stringify(msgData))) {
                        objectStructuresFromMessages.push({ base: msgData, sourceName: msgSource, id: `${msgSource}|object`});
                    }
                }
            });
        }


        if (!analysisSucceeded || potentialSinks.length === 0) {
            log.warn("[Payload Gen - Smart] No sinks identified by static analysis or analysis failed. Cannot generate smart payloads based on sinks.");
            return [];
        }

        log.debug("[Payload Gen - Smart] Full Potential Sinks from Static Analysis for Smart Gen:", JSON.stringify(potentialSinks));

        const sinkPathsToFuzz = potentialSinks
            .filter(sink => sink.sourcePath && sink.sourcePath !== '(Tainted non-data property)' && sink.sourcePath !== '(root)' && sink.sourcePath !== '(parsed_root)')
            .sort((a, b) => (this.severityOrder[b.severity?.toLowerCase()] || 0) - (this.severityOrder[a.severity?.toLowerCase()] || 0));

        let baseStructuresForFuzzing = [];
        if (objectStructuresFromMessages.length > 0) {
            baseStructuresForFuzzing.push(...objectStructuresFromMessages);
            log.info(`[Payload Gen - Smart] Prioritizing ${objectStructuresFromMessages.length} observed object structures for smart fuzzing.`);
        } else if (synthesizedBaseStructure && synthesizedBaseStructure.example && Object.keys(synthesizedBaseStructure.example).length > 0) {
            log.info("[Payload Gen - Smart] No observed object messages, using synthesized structure as base.");
            baseStructuresForFuzzing.push({
                base: synthesizedBaseStructure.example,
                sourceName: 'synthesized',
                id: 'synthesized|' + (synthesizedBaseStructure.keySignature || 'synthesized:object:')
            });
        } else {
            log.warn("[Payload Gen - Smart] No suitable object base (observed or synthesized with content) for smart fuzzing of specific paths.");
        }


        if (sinkPathsToFuzz.length > 0 && baseStructuresForFuzzing.length > 0) {
            log.info(`[Payload Gen - Smart] Processing ${sinkPathsToFuzz.length} specific sink paths against ${baseStructuresForFuzzing.length} base object structures.`);
            for (const baseStruct of baseStructuresForFuzzing) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;

                const baseObject = baseStruct.base;
                const sourceName = baseStruct.sourceName;

                for (const sink of sinkPathsToFuzz) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const targetPath = sink.sourcePath;
                    if (!targetPath) continue;

                    const conditions = sink.conditions || requiredConditions[targetPath]?.conditions || [];
                    log.debug(`[Payload Gen - Smart] For sink ${sink.name} (targetPath: ${targetPath}), base obj BEFORE conditions:`, JSON.stringify(baseObject));
                    log.debug(`[Payload Gen - Smart] Conditions to satisfy for ${targetPath}:`, JSON.stringify(conditions));

                    const sinkCategory = sink.category || 'generic';
                    const sinkSeverity = sink.severity || 'Low';
                    const payloadList = sinkCategoryToPayloadMap[sinkCategory] || sinkCategoryToPayloadMap['default'];
                    const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);

                    let baseForPath;
                    try {
                        baseForPath = this._deepCopy(baseObject);
                        if (baseForPath === undefined && baseObject !== undefined) {
                            log.warn(`[Payload Gen - Smart] _deepCopy resulted in undefined. Base:`, baseObject);
                            baseForPath = {};
                        } else if (baseForPath === undefined && baseObject === undefined) {
                            log.warn(`[Payload Gen - Smart] Base object was undefined for path ${targetPath} from ${sourceName}.`);
                            baseForPath = {};
                        }
                        if (conditions && conditions.length > 0) {
                            baseForPath = this._satisfyConditions(baseForPath, conditions);
                        }
                        log.debug(`[Payload Gen - Smart] Base obj AFTER conditions for ${targetPath} (Sink: ${sink.name}):`, JSON.stringify(baseForPath));
                    } catch (e) { log.error(`[Payload Gen - Smart] Error preparing base for path ${targetPath} from ${sourceName}`, e); baseForPath = {}; }

                    log.debug(`[Payload Gen - Smart] Generating ${limitedPayloads.length} payloads for sink path: ${targetPath} (Sink: ${sink.name}) using base from ${sourceName} (after conditions)`);

                    for (const pValue of limitedPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        try {
                            let finalMessage = this._deepCopy(baseForPath);
                            if (typeof finalMessage !== 'object' || finalMessage === null) {
                                log.warn(`[Payload Gen - Smart] Base for path ${targetPath} is not an object after copy/conditions. Forcing to empty object. Original baseForPath:`, baseForPath);
                                finalMessage = {};
                            }
                            this.setNestedValue(finalMessage, targetPath, pValue);

                            const payloadKey = `${targetPath}|${JSON.stringify(finalMessage)}|${sourceName}`;
                            if (handledSmartPayloadKeys.has(payloadKey)) continue;

                            const isCallback = allCallbackPayloads.includes(pValue);
                            const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(pValue);
                            const payloadBaseType = 'smart-sink';
                            let pType = customPayloadsActive ? `custom-${payloadBaseType}` : payloadBaseType;
                            if (isCallback) pType += '-callback'; else if (isEncoding) pType += '-encoding'; else pType += '-xss';

                            generatedPayloads.push({
                                type: pType,
                                payload: finalMessage,
                                targetPath: targetPath,
                                sinkType: sink.name || 'N/A (Flow Target)',
                                sinkSeverity: sinkSeverity,
                                description: `Targeted ${isCallback ? 'Callback' : (isEncoding ? 'Encoding/Bypass' : 'XSS')} for ${targetPath} -> ${sink.name || 'Flow'}`,
                                baseSource: sourceName
                            });
                            handledSmartPayloadKeys.add(payloadKey);
                        } catch (e) { log.error(`Error setting value for smart path ${targetPath} with payload ${pValue}`, e); }
                    }
                }
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
            }
        }

        const rootSinks = potentialSinks.filter(sink => sink.sourcePath && (sink.sourcePath === '(root)' || sink.sourcePath === '(root_data)' || sink.sourcePath === '(parsed_root)'));
        if (rootSinks.length > 0 && rawStringExamples.length > 0) {
            log.info(`[Payload Gen - Smart] Processing ${rootSinks.length} root sinks for ${rawStringExamples.length} raw string examples.`);
            for (const rawExample of rawStringExamples) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const baseString = String(rawExample.base);
                const sourceName = rawExample.sourceName;

                for (const sink of rootSinks) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const sinkCategory = sink.category || 'generic';
                    const sinkSeverity = sink.severity || 'Low';
                    const payloadList = sinkCategoryToPayloadMap[sinkCategory] || sinkCategoryToPayloadMap['default'];
                    const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);

                    log.debug(`[Payload Gen - Smart] Generating ${limitedPayloads.length} targeted raw string payloads for root sink ${sink.name} using base: "${baseString.substring(0,30)}..." from ${sourceName}`);
                    for (const pValue of limitedPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        if (typeof pValue !== 'string' && pValue !== null && typeof pValue !== 'boolean' && typeof pValue !== 'number') continue;

                        const payloadKey = `raw_root|${String(pValue)}|${sink.name}|${sourceName}`;
                        if (handledSmartPayloadKeys.has(payloadKey)) continue;

                        const isCallback = allCallbackPayloads.includes(pValue);
                        const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(pValue);
                        let pType = customPayloadsActive ? 'custom-smart-string-root' : 'smart-string-root';
                        if(isCallback) pType += '-callback'; else if(isEncoding) pType += '-encoding'; else pType += '-xss';

                        generatedPayloads.push({
                            type: pType,
                            payload: pValue,
                            targetPath: 'raw',
                            sinkType: sink.name,
                            sinkSeverity: sinkSeverity,
                            description: `Smart string (root) for sink ${sink.name}`,
                            baseSource: sourceName,
                            original: baseString
                        });
                        handledSmartPayloadKeys.add(payloadKey);
                    }
                }
            }
        }


        const uniquePayloads = [];
        const seenPayloadContent = new Set();
        for(const p of generatedPayloads) {
            let key;
            try { key = typeof p.payload === 'object' && p.payload !== null ? JSON.stringify(p.payload) : String(p.payload); } catch { key = String(p.payload); }
            if(!seenPayloadContent.has(key)){
                uniquePayloads.push(p);
                seenPayloadContent.add(key);
            }
        }
        log.info(`[Payload Gen - Smart] Final unique payload count: ${uniquePayloads.length} (Total generated before dedupe: ${generatedPayloads.length})`);
        return uniquePayloads.slice(0, this.MAX_PAYLOADS_TOTAL);
    }

}

async function handleTraceButton(endpoint, traceButton) {
    const originalFullEndpoint = endpoint;
    const endpointKey = window.getStorageKeyForUrl(originalFullEndpoint);
    log.debug(`[Trace Button START] Processing endpoint key: ${endpointKey}`);
    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) { log.debug(`[Trace Button] Trace already in progress for ${endpointKey}. Aborting.`); return; }
    sessionStorage.setItem(traceInProgressKey, 'true');
    window.log.scan(`Starting message trace for endpoint key: ${endpointKey}`);
    window.updateTraceButton(traceButton, 'checking');
    const buttonContainer = traceButton.closest('.button-container');
    const playButton = buttonContainer?.querySelector('.iframe-check-button');
    const reportButton = buttonContainer?.querySelector('.iframe-report-button');
    if (playButton) playButton.classList.remove('show-next-step-emoji');
    let progressContainer = document.querySelector('.trace-progress-container');
    if (!progressContainer) { window.addProgressStyles(); progressContainer = document.createElement('div'); progressContainer.className = 'trace-progress-container'; document.body.appendChild(progressContainer); }
    progressContainer.innerHTML = `<h4>Trace Progress</h4><div class="phase-list"><div class="phase" data-phase="collection"><span class="emoji">📦</span><span class="label">Data</span></div><div class="phase" data-phase="analysis"><span class="emoji">🔬</span><span class="label">Analyze</span></div><div class="phase" data-phase="dynamic" style="display:none;"><span class="emoji">🩺</span><span class="label">Runtime</span></div><div class="phase" data-phase="structure"><span class="emoji">🧱</span><span class="label">Structure</span></div><div class="phase" data-phase="generation"><span class="emoji">⚙️</span><span class="label">Payloads</span></div><div class="phase" data-phase="saving"><span class="emoji">💾</span><span class="label">Saving</span></div><div class="phase" data-phase="finished" style="display: none;"><span class="emoji">✅</span><span class="label">Done</span></div><div class="phase" data-phase="error" style="display: none;"><span class="emoji">❌</span><span class="label">Error</span></div></div>`;
    const updatePhase = (phase, status = 'active') => { const phaseElement = progressContainer?.querySelector(`.phase[data-phase="${phase}"]`); if (!phaseElement) return; progressContainer?.querySelectorAll('.phase').forEach(el => { el.classList.remove('active', 'completed', 'error'); if(el.dataset.phase === 'dynamic' && status !== 'active') el.style.display = 'none'; }); phaseElement.classList.add(status); if (phase === 'dynamic') phaseElement.style.display = 'flex'; if (status === 'error' || status === 'completed') { const finalPhase = status === 'error' ? 'error' : 'finished'; const finalElement = progressContainer?.querySelector(`.phase[data-phase="${finalPhase}"]`); if (finalElement) { finalElement.style.display = 'flex'; finalElement.classList.add(status); } } else { progressContainer?.querySelectorAll('.phase[data-phase="finished"], .phase[data-phase="error"]').forEach(el => el.style.display = 'none'); } };

    let handlerCode = null;
    let bestHandler = null;
    let analysisStorageKey = endpointKey;
    let endpointUrlUsedForAnalysis = originalFullEndpoint;
    let report = {};
    let payloads = [];
    let vulnAnalysis = { sinks: [], securityIssues: [], dataFlows: [], originValidationChecks: [] };
    let uniqueStructures = [];
    let staticAnalysisData = null;
    let staticAnalysisResult = null;
    let dynamicAnalysisResults = null;
    let hasCriticalSinks = false;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) { window.handlerTracer = new HandlerTracer(); }

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        if (mappingResult && mappingResult[mappingKey]) {
            analysisStorageKey = mappingResult[mappingKey];
            log.debug(`[Trace Button] Found mapping. Using analysis key: ${analysisStorageKey}`);
            const successfulUrlStorageKey = `successful-url-${analysisStorageKey}`;
            const successfulUrlResult = await new Promise(resolve => chrome.storage.local.get(successfulUrlStorageKey, resolve));
            endpointUrlUsedForAnalysis = successfulUrlResult[successfulUrlStorageKey] || analysisStorageKey;
            log.debug(`[Trace Button] Associated analyzed URL: ${endpointUrlUsedForAnalysis}`);
        } else {
            log.debug(`[Trace Button] No mapping found. Using original key: ${analysisStorageKey}`);
            endpointUrlUsedForAnalysis = originalFullEndpoint;
        }

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        log.debug(`[Trace Button] Attempting to retrieve handler from storage key: ${bestHandlerStorageKey}`);
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;
        log.debug("[Trace Button] Retrieved Handler Code:", handlerCode ? handlerCode.substring(0, 300) + '...' : '[No Handler Code Found]');

        if (!handlerCode) {
            throw new Error(`No handler code found (Storage Key: ${bestHandlerStorageKey}). Run Play first.`);
        }

        const relevantMessages = await window.retrieveMessagesWithFallbacks(analysisStorageKey, endpointKey);
        const messagesAvailable = relevantMessages.length > 0;
        log.debug(`[Trace Button] Retrieved ${relevantMessages.length} relevant messages for original key ${endpointKey} (using analysis key ${analysisStorageKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));

        staticAnalysisResult = { success: false, error: 'Static analyzer not available or prerequisites failed', analysis: null };
        if (window.analyzeHandlerStatically && handlerCode) {
            let isParsable = false; let preliminaryParseError = null;
            if (handlerCode && typeof handlerCode === 'string' && handlerCode.trim() !== '') {
                try { const checkCode = 'const __dummyFunc = ' + handlerCode; window.acorn.parse(checkCode, { ecmaVersion: 'latest', allowReturnOutsideFunction: true }); isParsable = true; }
                catch (parseError) { isParsable = false; preliminaryParseError = parseError; }
            } else { preliminaryParseError = new Error('Invalid or empty handler code provided'); isParsable = false; }

            if (isParsable) {
                log.debug("Code is parsable, proceeding with static analysis.");
                try {
                    staticAnalysisResult = window.analyzeHandlerStatically( handlerCode, analysisStorageKey, window.handlerTracer.domXssSinks, { eventParamName: bestHandler?.eventParamName });
                    log.debug("staticAnalysisResult", staticAnalysisResult);
                    if (staticAnalysisResult?.success && staticAnalysisResult?.analysis) {
                        staticAnalysisData = staticAnalysisResult.analysis;
                        log.success("[Trace Button] Static analysis succeeded.");
                        log.debug(`[Static Analysis Results] Sinks: ${staticAnalysisData.potentialSinks?.length || 0}, Origin Checks: ${staticAnalysisData.originChecks?.length || 0}, Accessed Paths: ${staticAnalysisData.accessedEventDataPaths?.size || Array.isArray(staticAnalysisData.accessedEventDataPaths) ? staticAnalysisData.accessedEventDataPaths.length : 0}`);
                        if(staticAnalysisData.potentialSinks?.length > 0) { log.warn("[Static Analysis Results] Potential Sinks Found:", staticAnalysisData.potentialSinks); }
                        if(staticAnalysisData.originChecks?.some(c => c.strength === 'Missing' || c.strength === 'Weak')) { log.warn("[Static Analysis Results] Weak/Missing Origin Checks Found:", staticAnalysisData.originChecks); }
                    } else {
                        staticAnalysisData = null;
                        if (!staticAnalysisResult) staticAnalysisResult = { success: false, error: 'Analysis returned undefined/null result', analysis: null };
                        log.warn(`[Trace Button] Static analysis failed or returned no success/analysis data: ${staticAnalysisResult?.error}.`);
                    }
                } catch (e) {
                    staticAnalysisData = null; staticAnalysisResult = { success: false, error: `Execution Error: ${e.message}`, analysis: null };
                    log.error("[Trace Button] Error executing static analyzer:", e);
                }
            } else {
                staticAnalysisData = null; staticAnalysisResult = { success: false, error: `Static analysis skipped: Preliminary parse failed - ${preliminaryParseError?.message || 'Unknown parse error'}`, analysis: null };
                log.warn(`[Trace Button] ${staticAnalysisResult.error}`);
            }
        }

        vulnAnalysis = await window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData);
        vulnAnalysis.originChecks = staticAnalysisData?.originChecks || [];
        vulnAnalysis.dataFlows = staticAnalysisData?.dataFlows || [];

        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        const isStateDependent = staticAnalysisData?.externalStateAccesses?.length > 0 || staticAnalysisData?.indirectCalls?.length > 0;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));
        if (messagesAvailable) { uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages); }
        log.debug(`[Trace Button] Unique structures identified from messages: ${uniqueStructures.length}`);

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));
        const isStaticAnalysisAvailable = !!(staticAnalysisResult?.success && staticAnalysisData);

        const defaultContext = { uniqueStructures, originalMessages: relevantMessages, staticAnalysisData };
        payloads = await window.handlerTracer.generateDefaultPayloads(defaultContext);
        log.info(`[Trace Button] Default (initial) payload generation completed. Count: ${payloads.length}`);

        const payloadMode = payloads.length > 0 ? 'default' : 'none';

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
                staticAnalysisRawOutput: staticAnalysisResult,
                accessedEventDataPaths: staticAnalysisData?.accessedEventDataPaths instanceof Set ? Array.from(staticAnalysisData.accessedEventDataPaths) : staticAnalysisData?.accessedEventDataPaths,
                requiredConditions: staticAnalysisData?.requiredConditions || {},
                analyzedHandler: bestHandler,
                sinks: vulnAnalysis.sinks || [],
                securityIssues: vulnAnalysis.securityIssues || [],
                dataFlows: staticAnalysisData?.dataFlows || [],
                originValidationChecks: staticAnalysisData?.originChecks || [],
                externalStateAccesses: staticAnalysisData?.externalStateAccesses || [],
                indirectCalls: staticAnalysisData?.indirectCalls || [],
                dynamicAnalysisResults: dynamicAnalysisResults,
                payloadsGeneratedCount: payloads.length,
                uniqueStructures: uniqueStructures || [],
                staticAnalysisUsed: isStaticAnalysisAvailable,
                messagesAvailable: messagesAvailable,
                payloadMode: payloadMode
            },
            summary: {
                messagesAnalyzed: relevantMessages.length,
                patternsIdentified: uniqueStructures.length,
                sinksFound: vulnAnalysis.sinks?.length || 0,
                issuesFound: vulnAnalysis.securityIssues?.length || 0,
                payloadsGenerated: payloads.length,
                securityScore: securityScore,
                staticAnalysisUsed: isStaticAnalysisAvailable
            }
        };

        const reportStorageKey = analysisStorageKey;
        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);
        if (!reportSaved || !payloadsSaved) { throw new Error("Failed to save trace report or initial payloads."); }
        log.success(`Report & ${payloads.length} initial default payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true,
                criticalSinks: hasCriticalSinks,
                sinksFound: vulnAnalysis.sinks?.length > 0,
                analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey,
                timestamp: Date.now(),
                payloadCount: payloads.length,
                sinkCount: vulnAnalysis.sinks?.length || 0,
                usedStaticAnalysis: isStaticAnalysisAvailable,
                payloadMode: payloadMode
            }
        });

        window.updateTraceButton(traceButton, 'success');
        if (playButton) { window.updateButton(playButton, 'launch', { hasCriticalSinks: hasCriticalSinks, showEmoji: true }); }
        if (reportButton) { const reportState = hasCriticalSinks || (vulnAnalysis.securityIssues?.length || 0) > 0 ? 'green' : 'default'; window.updateReportButton(reportButton, reportState, originalFullEndpoint); }
        updatePhase('saving', 'completed');

    } catch (error) {
        console.error(`[Trace Button ERROR] for ${originalFullEndpoint}:`, error);
        window.log.error(`[Trace Button ERROR] Error:`, error.message);
        window.updateTraceButton(traceButton, 'error');
        const traceInfoKey = `trace-info-${endpointKey}`;
        try { await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false, error: error.message, timestamp: Date.now() } }); } catch (e) {}
        if (reportButton) window.updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
        const errorLabel = progressContainer?.querySelector('.phase[data-phase="error"] .label');
        if(errorLabel) errorLabel.textContent = `Error: ${error.message.substring(0, 50)}...`;
    } finally {
        setTimeout(() => { progressContainer?.remove(); }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        setTimeout(window.requestUiUpdate, 100);
    }
}
window.handleTraceButton = handleTraceButton;

document.addEventListener('DOMContentLoaded', () => {
    if (!window.handlerTracer) {
        window.handlerTracer = new HandlerTracer();
    }
});

if (typeof window.analyzeHandlerStatically === 'undefined') {
    console.error("Static Handler Analyzer not loaded. Payload generation will be limited.");
    window.analyzeHandlerStatically = () => ({ success: false, error: 'Analyzer not loaded.', analysis: null });
}
