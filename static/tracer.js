/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-05-02
 */

const DATA_PROP = 'data';

if (typeof window.analyzeHandlerStatically === 'undefined') {
    console.error("Static Handler Analyzer not loaded. Payload generation will be limited.");
    window.analyzeHandlerStatically = () => ({ success: false, error: 'Analyzer not loaded.', analysis: null });
}

class HandlerTracer {
    constructor() {
        this.domXssSinks = [ { name: "eval", pattern: /\beval\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval' }, { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval' }, { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setTimeout', argIndex: 0 }, { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setInterval', argIndex: 0 }, { name: "element.innerHTML assignment", pattern: /\.innerHTML\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'innerHTML' }, { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High", methods: ['regex', 'ast'], argIndex: 1, category: 'innerHTML' }, { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'location_href' }, { name: "OpenRedirect_assign_AST", pattern: /\.location\.assign$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href' }, { name: "OpenRedirect_replace_AST", pattern: /\.location\.replace$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'location_href' }, { name: "location.href assign", pattern: /\.location\.href\s*=/, severity: "High", methods: ['regex'], category: 'location_href' }, { name: "document.createElement('script')", pattern: /document\.createElement\s*\(\s*['"]script['"]\)/, severity: "High", methods: ['regex'], category: 'script_manipulation' }, { name: "jQuery html", pattern: /\$\(.*\)\.html\s*\(|\$\.[a-zA-Z0-9_]+\.html\s*\(/, severity: "High", methods: ['regex'], category: 'innerHTML' }, { name: "iframe.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'], category: 'src_manipulation' }, { name: "script.src JS", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High", methods: ['regex'], category: 'script_manipulation' }, { name: "srcdoc assignment", pattern: /\.srcdoc\s*=/, severity: "High", methods: ['regex'], category: 'innerHTML' }, { name: "EvalInjection_setTimeout_AST", pattern: /^(?:window\.|self\.|top\.)?setTimeout$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setTimeout' }, { name: "EvalInjection_setInterval_AST", pattern: /^(?:window\.|self\.|top\.)?setInterval$/, severity: 'High', methods: ['ast'], argIndex: 0, category: 'setInterval' }, { name: "jQuery attr href", pattern: /\$.*?\.attr\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex'], category: 'location_href' }, { name: "jQuery prop href", pattern: /\$.*?\.prop\s*\(\s*['"]href['"]\)/, severity: "Medium", methods: ['regex'], category: 'location_href' }, { name: "document.domain assignment", pattern: /document\.domain\s*=/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "document.cookie assignment", pattern: /document\.cookie\s*=/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "createContextualFragment", pattern: /createContextualFragment\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' }, { name: "jQuery append", pattern: /\$.*?\.append\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' }, { name: "jQuery prepend", pattern: /\$.*?\.prepend\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' }, { name: "jQuery after", pattern: /\$.*?\.after\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' }, { name: "jQuery before", pattern: /\$.*?\.before\s*\(/, severity: "Medium", methods: ['regex'], category: 'innerHTML' }, { name: "element.appendChild", pattern: /\.appendChild\s*\(/, severity: "Medium", methods: ['regex'], category: 'dom_manipulation' }, { name: "element.insertBefore", pattern: /\.insertBefore\s*\(/, severity: "Medium", methods: ['regex'], category: 'dom_manipulation' }, { name: "setAttribute dangerous", pattern: /\.setAttribute\s*\(\s*['"](?:src|href|onclick|onerror|onload|on\w+)['"]\)/, severity: "Medium", methods: ['regex'], category: 'src_manipulation' }, { name: "unsafe template literal", pattern: /`.*?\${(?![^{}]*?encodeURIComponent)(?![^{}]*?escape)/m, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "Handlebars.compile", pattern: /Handlebars\.compile\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "Vue $compile", pattern: /\$compile\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "Web Worker Regex", pattern: /new\s+Worker\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "Blob URL creation", pattern: /URL\.createObjectURL\s*\(/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "Blob constructor", pattern: /new\s+Blob\s*\(\s*\[/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "WebSocket URL Regex", pattern: /new\s+WebSocket\s*\((?![^)]*['"]wss?:\/\/)/, severity: "Medium", methods: ['regex'], category: 'generic' }, { name: "element.on* assign", pattern: /\.on(?:error|load|click|mouseover|keydown|submit)\s*=/, severity: "Medium", methods: ['regex'], category: 'event_handler' }, { name: "URLManipulation_pushState_AST", pattern: /history\.pushState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href'}, { name: "URLManipulation_replaceState_AST", pattern: /history\.replaceState$/, severity: 'Medium', methods: ['ast'], argIndex: 2, category: 'location_href'}, { name: "StorageManipulation_localStorage_AST", pattern: /localStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic' }, { name: "StorageManipulation_sessionStorage_AST", pattern: /sessionStorage\.setItem$/, severity: 'Medium', methods: ['ast'], argIndex: 1, category: 'generic' }, { name: "localStorage Regex", pattern: /localStorage\.setItem\s*\(|localStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' }, { name: "sessionStorage Regex", pattern: /sessionStorage\.setItem\s*\(|sessionStorage\[\s*/, severity: "Low", methods: ['regex'], category: 'generic' }, { name: "addEventListener other", pattern: /\.addEventListener\s*\(\s*['"](?!message)/, severity: "Low", methods: ['regex'], category: 'generic' }, { name: "URL constructor", pattern: /new\s+URL\s*\(/, severity: "Low", methods: ['regex'], category: 'generic' }, { name: "URL prop manipulation", pattern: /\.(?:searchParams|pathname|hash|search)\s*=/, severity: "Low", methods: ['regex'], category: 'generic' }, { name: "history manipulation Regex", pattern: /history\.(?:pushState|replaceState)\s*\(/, severity: "Low", methods: ['regex'], category: 'location_href' }, { name: "WebSocketCreation_AST", pattern: /WebSocket$/, severity: 'Low', methods: ['ast'], nodeType: 'NewExpression', argIndex: 0, category: 'generic'}, { name: "console.log", pattern: /console\.log\s*\(/, severity: "Low", methods: ['regex', 'ast'], category: 'generic', argIndex: 0}, ];
        this.securityChecks = [ { name: "Missing origin check", pattern: null, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Missing') }, { name: "Loose origin check", pattern: /\.origin\.(?:indexOf|includes|startsWith|endsWith|search|match)\s*\(/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Weak' && c.type?.includes('Method Call')) }, { name: "Weak origin comparison", pattern: /\.origin\s*(?:==|!=)\s*['"]/, severity: "Medium", checkFunc: (code, analysis) => analysis?.originValidationChecks?.some(c => c.strength === 'Medium' && c.type?.includes('Equality')) }, { name: "Wildcard origin in postMessage", pattern: /postMessage\s*\([^,]+,\s*['"][\*]['"]\s*\)/, severity: "Medium" }, { name: "Using window.parent without origin check", pattern: /window\.parent\.postMessage\s*\((?![^)]*origin)/, severity: "Medium" }, { name: "No message type check", pattern: /addEventListener\s*\(\s*['"]message['"](?![^{]*?\.(?:type|messageType|kind|action))/ms, severity: "Low" }, { name: "Unsafe object assignment", pattern: /(?:Object\.assign|\.\.\.)[^;]*event\.data/, severity: "Medium" }, { name: "Unchecked JSON parsing", pattern: /JSON\.parse\s*\([^)]*?\)\s*(?!\.(?:hasOwnProperty|propertyIsEnumerable))/, severity: "Medium" }, { name: "Dynamic property access", pattern: /\[[^\]]*?\.data\.[^\]]*?\]/, severity: "Medium" }, { name: "Sensitive information leak", pattern: /postMessage\s*\(\s*(?:document\.cookie|localStorage|sessionStorage)/, severity: "High" }, { name: "Potential XSS in postMessage", pattern: /postMessage\s*\(\s*['"][^"']*?<[^"']*?(?:script|img|svg|iframe)[^"']*?>[^"']*?['"]/, severity: "High" }, { name: "Potential prototype pollution", pattern: /(?:Object\.assign\s*\(\s*[^,]+,|Object\.setPrototypeOf|__proto__)/, severity: "Medium" }, { name: "Dynamic function execution", pattern: /\[['"]\w+['"]\]\s*\([^)]*event\.data/, severity: "High" }, { name: "this[prop] function call", pattern: /this\s*\[[^\]]+\]\s*\(/, severity: "Medium" } ];
        this.severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0 };
        this.MAX_PAYLOADS_TOTAL = 5000; this.MAX_PAYLOADS_PER_SINK_PATH = 30; this.MAX_PAYLOADS_PER_DUMB_FIELD = 15; this.MAX_PAYLOADS_PER_TYPE_FIELD = 5; this.MAX_DUMB_FIELDS_TO_TARGET = 30; this.MAX_TYPE_FIELDS_TO_TARGET = 50;
        this.loadedCustomSinks = []; this.loadedCustomChecks = []; this.traceReport = null;
        this.DATA_PROP = DATA_PROP;
    }

    isPlainObject(obj) { if (typeof obj !== 'object' || obj === null) return false; let proto = Object.getPrototypeOf(obj); if (proto === null) return true; let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) { baseProto = Object.getPrototypeOf(baseProto); } return proto === baseProto; }
    analyzeJsonStructures(messages) { const structureMap = new Map(); if (!messages || messages.length === 0) return []; for (const message of messages) { if (!message) continue; try { let data = message.data; let dataType = typeof data; if (dataType === 'string') { if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) { try { data = JSON.parse(data); dataType = typeof data; } catch {} } } if (this.isPlainObject(data)) { const structure = this.getJsonStructure(data); const hash = this.hashJsonStructure(structure); if (!structureMap.has(hash)) { const paths = this.identifyPathsToFuzz(structure); structureMap.set(hash, { structure: structure, examples: [message], pathsToFuzz: paths }); } else { const entry = structureMap.get(hash); if (entry.examples.length < 3) { entry.examples.push(message); } } } } catch {} } return Array.from(structureMap.values()); }
    getJsonStructure(obj, path = '') { if (obj === null || obj === undefined) return { type: 'null', path }; const type = typeof obj; if (type !== 'object') return { type: type, path }; if (Array.isArray(obj)) { const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` }; return { type: 'array', path, items: itemStructure }; } const structure = { type: 'object', path, properties: {} }; const keys = Object.keys(obj).sort(); for (const key of keys) { const newPath = path ? `${path}.${key}` : key; structure.properties[key] = this.getJsonStructure(obj[key], newPath); } return structure; }
    hashJsonStructure(structure) { if (!structure || !structure.type) return 'invalid'; if (structure.type === 'array') return `array[${this.hashJsonStructure(structure.items)}]`; if (structure.type !== 'object') return structure.type; const keys = Object.keys(structure.properties || {}).sort(); return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(','); }
    identifyPathsToFuzz(structure, currentPath = '', paths = []) { if (!structure) return paths; const nodePath = structure.path || currentPath; if (structure.type !== 'object' && structure.type !== 'array') { if (nodePath) paths.push({ path: nodePath, type: structure.type }); return paths; } if (structure.type === 'array' && structure.items) { this.identifyPathsToFuzz(structure.items, '', paths); } else if (structure.type === 'object' && structure.properties) { for (const key of Object.keys(structure.properties)) { this.identifyPathsToFuzz(structure.properties[key], '', paths); } } const uniquePaths = []; const seenPaths = new Set(); for (const p of paths) { if (p.path && !seenPaths.has(p.path)) { seenPaths.add(p.path); uniquePaths.push(p); } } return uniquePaths; }
    async _loadCustomDefinitions() { try { const data = await chrome.storage.sync.get(['customSinks', 'customChecks']); this.loadedCustomSinks = data.customSinks || []; this.loadedCustomChecks = data.customChecks || []; } catch (e) { this.loadedCustomSinks = []; this.loadedCustomChecks = []; } }
    async analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData = null) { await this._loadCustomDefinitions(); const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] }; const foundSinks = new Map(); if (!handlerCode) { return vulnerabilities; } const escapeHTML = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); const allSinks = [...this.domXssSinks, ...this.loadedCustomSinks]; allSinks.forEach(sink => { if (!sink.methods || sink.methods.includes('regex')) { let regex; try { regex = new RegExp(sink.pattern, 'g'); } catch (e) { return; } let match; while ((match = regex.exec(handlerCode)) !== null) { const exactMatchSnippet = match[0]; const sinkType = sink.name || sink.type || 'custom-sink'; const key = `${sinkType}#${exactMatchSnippet}`; if (!foundSinks.has(key)) { const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length); let highlightedContextHTML = escapeHTML(rawContext); let highlightStartIndex = -1; let highlightEndIndex = -1; const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet); if (matchIndexInRawContext !== -1) { highlightStartIndex = matchIndexInRawContext; highlightEndIndex = highlightStartIndex + exactMatchSnippet.length; const partBefore = rawContext.substring(0, highlightStartIndex); const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex); const partAfter = rawContext.substring(highlightEndIndex); highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter; } foundSinks.set(key, { type: sinkType, severity: sink.severity || 'Medium', context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex, method: 'regex', path: '', category: sink.category || 'custom' }); } } } });
        if(staticAnalysisData?.potentialSinks) {
            vulnerabilities.dataFlows = staticAnalysisData.dataFlows || [];
            staticAnalysisData.potentialSinks.forEach(staticSink => {
                const getCodeSnippetFromNode = (node) => {
                    if (!node || !node.range || typeof handlerCode !== 'string') return '[AST Node Snippet Unavailable]';
                    try { const startOffset = 0; const snippet = handlerCode.substring(node.range[0] - startOffset, node.range[1] - startOffset); return snippet.substring(0, 150) + (snippet.length > 150 ? '...' : ''); } catch (e) { return '[snippet error]'; }
                };
                const sinkType = staticSink.name || staticSink.sinkPattern?.name || 'ast-sink'; const context = staticSink.snippet || getCodeSnippetFromNode(staticSink.node); const key = `${sinkType}#${context}`;
                if (!foundSinks.has(key)) {
                    foundSinks.set(key, { type: sinkType, severity: staticSink.severity || staticSink.sinkPattern?.severity || 'Medium', path: staticSink.path || staticSink.sourcePath || '(unknown path)', conditions: staticSink.conditions || [], context: escapeHTML(context), highlightStart: -1, highlightEnd: -1, method: 'ast', category: staticSink.category || staticSink.sinkPattern?.category || 'generic', isGuarded: staticSink.isGuarded || 'unknown', sourcePath: staticSink.sourcePath });
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
        const originChecks = analysisResults.details?.originValidationChecks || analysisResults.originChecks || [];

        let hasStrongOriginCheck = false;
        let hasMediumOriginCheck = false;
        let hasWeakOriginCheck = false;
        let explicitOriginChecksFound = originChecks.length > 0;

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
            }
        });

        if (!explicitOriginChecksFound) {
            const hasAnyOriginIssue = issues.some(issue => issue.type.toLowerCase().includes('origin check') || issue.type.toLowerCase().includes('origin validation issue'));
            if (!hasAnyOriginIssue) {
                penaltyScore += MISSING_CHECK_PENALTY;
            } else {
                issues.forEach(issue => { // Check regex-based issues if no static checks found
                    if (issue.type.toLowerCase().includes('origin check') || issue.type.toLowerCase().includes('origin validation issue')) {
                        switch (issue.severity?.toLowerCase()) {
                            case 'critical': case 'high': penaltyScore += MISSING_CHECK_PENALTY; break;
                            case 'medium': penaltyScore += WEAK_CHECK_PENALTY; break;
                        }
                    }
                });
            }
        }

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
            if (issue.type.toLowerCase().includes('origin check') || issue.type.toLowerCase().includes('origin validation issue')) { return; } // Skip ones handled above
            switch (issue.severity?.toLowerCase()) {
                case 'high': penaltyScore += 15; break;
                case 'medium': mediumIssueCount++; penaltyScore += 5 + Math.min(mediumIssueCount, 4); break;
                case 'low': penaltyScore += 3; break;
                default: penaltyScore += 1; break;
            }
        });

        if (dataFlows.length > 0) {
            let flowPenalty = 0; dataFlows.forEach(flow => { switch (flow.severity?.toLowerCase()) { case 'critical': flowPenalty += 5; break; case 'high': flowPenalty += 3; break; case 'medium': flowPenalty += 1; break; default: flowPenalty += 0.5; break; } }); penaltyScore += Math.min(flowPenalty, 25);
        }

        if (issues.some(issue => issue.type.toLowerCase().includes('window.parent') && issue.type.toLowerCase().includes('origin check'))) { penaltyScore += 10; }

        penaltyScore = Math.max(0, penaltyScore);
        penaltyScore = Math.min(penaltyScore, MAX_PENALTY);
        let finalScore = Math.max(0, 100 - penaltyScore);
        return Math.round(finalScore);
    }


    createStructureFromStaticAnalysis(staticAnalysisData) {
        log.debug("[Payload Gen] createStructureFromStaticAnalysis: Input staticAnalysisData:", staticAnalysisData);
        const structure = { type: 'synthesized_object', example: {}, processedData: {}, fields: new Set(), keySignature: 'synthesized:object:', properties: {} };
        let accessedPaths = staticAnalysisData?.accessedEventDataPaths || [];
        if (!Array.isArray(accessedPaths)) { accessedPaths = accessedPaths instanceof Set ? Array.from(accessedPaths) : []; }
        const pathsSet = new Set(accessedPaths);
        log.debug("[Payload Gen] createStructureFromStaticAnalysis: Using accessed paths:", pathsSet);
        if (pathsSet.size === 0 || (pathsSet.size === 1 && (pathsSet.has('(root)') || pathsSet.has('(parsed_root)') || pathsSet.has('(root_data)') ) ) ) { log.warn("[Payload Gen] createStructureFromStaticAnalysis: No usable paths found for synthesis."); return null; }
        const buildNestedStructure = (obj, pathParts) => {
            let currentLevel = obj;
            for (let i = 0; i < pathParts.length; i++) {
                const part = pathParts[i]; if (!part || part.trim() === '') continue;
                const isLast = i === pathParts.length - 1; if (!currentLevel.properties) currentLevel.properties = {};
                if (!currentLevel.properties[part]) { currentLevel.properties[part] = { name: part, expectedType: isLast ? 'string' : 'object', accessCount: 0, properties: {}, sampleValues: [] }; } currentLevel.properties[part].accessCount++;
                if (!isLast) { if (!currentLevel.properties[part].properties) { currentLevel.properties[part].properties = {}; } currentLevel = currentLevel.properties[part]; if (currentLevel.expectedType !== 'object' && currentLevel.expectedType !== 'unknown') { log.debug(`[Payload Gen] Synthesis: Changing type of ${part} to object.`); currentLevel.expectedType = 'object'; }
                } else {
                    const potentialSinks = Array.isArray(staticAnalysisData?.potentialSinks) ? staticAnalysisData.potentialSinks : []; const fullPathJoined = pathParts.join('.'); const sink = potentialSinks.find(s => s.sourcePath === fullPathJoined);
                    if (sink?.category === 'innerHTML' || sink?.category === 'dom_manipulation') { currentLevel.properties[part].expectedType = 'string'; } else if (sink?.category === 'eval' || sink?.category === 'setTimeout' || sink?.category === 'setInterval') { currentLevel.properties[part].expectedType = 'string'; } else if (sink?.category === 'location_href' || sink?.category === 'src_manipulation') { currentLevel.properties[part].expectedType = 'string'; }
                    if (!Array.isArray(currentLevel.properties[part].sampleValues) || currentLevel.properties[part].sampleValues.length === 0) { currentLevel.properties[part].sampleValues = ["default_value"]; }
                    const topLevelKey = pathParts[0]; if (topLevelKey && !structure.example.hasOwnProperty(topLevelKey)) { structure.example[topLevelKey] = "default_value"; } structure.processedData[fullPathJoined] = "default_value"; structure.fields.add(fullPathJoined);
                }
            }
        };
        try {
            pathsSet.forEach(path => { if (path && typeof path === 'string' && path !== '(root)' && path !== '(root_data)' && path !== '(parsed_root)' && !path.startsWith('(parsed ') && !path.startsWith('(from_parsed ') && path !== '(unknown_expression)') { const parts = path.split('.'); if (parts.length > 0 && parts[0]) { log.debug(`[Payload Gen] Synthesis: Building structure for path: ${path}`); buildNestedStructure(structure, parts); } else { log.warn(`[Payload Gen] Synthesis: Skipping invalid path format: ${path}`); } } else { log.debug(`[Payload Gen] Synthesis: Skipping generic/ignored path: ${path}`); } });
            structure.keySignature += Array.from(structure.fields).sort().join(','); if (structure.fields.size > 0) { log.debug("[Payload Gen] createStructureFromStaticAnalysis: Successfully synthesized structure:", structure); return structure; } else { log.warn("[Payload Gen] createStructureFromStaticAnalysis: No fields added to synthesized structure."); return null; }
        } catch (e) { log.error("[Payload Gen] Synthesis Error Stack:", e.stack); return null; }
    }

    setNestedValue(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) { if(typeof obj === 'string' && path === 'raw') return value; return; }
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
        let current = obj;
        for (let i = 0; i < parts.length - 1; i++) {
            let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
            const nextPartStr = parts[i + 1]; let nextPartNormalized = nextPartStr; if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, ''); const isNextPartIndex = /^\d+$/.test(nextPartNormalized);
            if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') { current[part] = isNextPartIndex ? [] : {}; }
            current = current[part]; if (typeof current !== 'object' || current === null) return;
        }
        let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
        if (typeof current === 'object' && current !== null) { const isIndex = /^\d+$/.test(lastPart); if (Array.isArray(current) && isIndex) current[parseInt(lastPart, 10)] = value; else if (!Array.isArray(current)) current[lastPart] = value; }
    }

    _deepCopy(obj) { try { if (obj === null || typeof obj !== 'object') { return obj; } return JSON.parse(JSON.stringify(obj)); } catch (e) { const copy = Array.isArray(obj) ? [] : {}; for(const key in obj){ if(Object.prototype.hasOwnProperty.call(obj, key)) { try { copy[key] = this._deepCopy(obj[key]); } catch { copy[key] = '[Uncopyable]'; }}} return copy; } }

    async _getPayloadLists() { let customXssPayloads = []; let customPayloadsActive = false; let callbackUrl = null; let processedCallbackPayloads = []; try { const results = await new Promise(resolve => chrome.storage.session.get(['customXssPayloads', 'callback_url'], resolve)); customXssPayloads = results.customXssPayloads || []; callbackUrl = results.callback_url; customPayloadsActive = customXssPayloads.length > 0; if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) { processedCallbackPayloads = window.FuzzingPayloads.CALLBACK_URL.map(template => String(template).replace(/%%CALLBACK_URL%%/g, callbackUrl)); } } catch (e) {} const baseFuzzingPayloads = window.FuzzingPayloads || { XSS: [], SINK_SPECIFIC: {}, TYPE_FUZZ: [], PROTOTYPE_POLLUTION: [], ENCODING: [] }; const activeXssPayloads = customPayloadsActive ? customXssPayloads : (baseFuzzingPayloads.XSS || []); const encodingPayloads = baseFuzzingPayloads.ENCODING || []; const typeFuzzPayloads = baseFuzzingPayloads.TYPE_FUZZ || [null, true, false, 0, -1, 1.23, 9999999999999999, [], {}]; const combinedXss = [...new Set([...activeXssPayloads, ...encodingPayloads])].map(p => String(p)); const sinkCategoryToPayloadMap = { 'eval': baseFuzzingPayloads.SINK_SPECIFIC?.eval || combinedXss, 'setTimeout': baseFuzzingPayloads.SINK_SPECIFIC?.setTimeout || combinedXss, 'setInterval': baseFuzzingPayloads.SINK_SPECIFIC?.setInterval || combinedXss, 'innerHTML': baseFuzzingPayloads.SINK_SPECIFIC?.innerHTML || combinedXss, 'script_manipulation': combinedXss, 'src_manipulation': [...combinedXss, ...processedCallbackPayloads], 'location_href': baseFuzzingPayloads.SINK_SPECIFIC?.location_href || [...combinedXss, ...processedCallbackPayloads], 'event_handler': combinedXss, 'dom_manipulation': combinedXss, 'generic': [...combinedXss, ...processedCallbackPayloads], 'default': [...combinedXss, ...processedCallbackPayloads] }; for (const key in sinkCategoryToPayloadMap) { if (!Array.isArray(sinkCategoryToPayloadMap[key])) { sinkCategoryToPayloadMap[key] = [...combinedXss, ...processedCallbackPayloads].map(p => String(p)); } else { sinkCategoryToPayloadMap[key] = sinkCategoryToPayloadMap[key].map(p => String(p)); } } return { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads: processedCallbackPayloads, typeFuzzPayloads }; }

    _satisfyConditions(baseObject, conditions) {
        log.debug("[Payload Gen] _satisfyConditions: Input baseObject:", JSON.stringify(baseObject), "Conditions:", conditions);
        if (!conditions || conditions.length === 0 || !baseObject || typeof baseObject !== 'object') { return this._deepCopy(baseObject); }
        const modifiedBase = this._deepCopy(baseObject);
        for (const cond of conditions) {
            if (!cond || !cond.path || cond.value === undefined) continue; if (String(cond.value).startsWith('[EXPRESSION:')) continue;
            try {
                if ((cond.op === '===' || cond.op === '==') && cond.value !== null) { log.debug(`[Payload Gen] _satisfyConditions: Setting path '${cond.path}' to value:`, cond.value); this.setNestedValue(modifiedBase, cond.path, cond.value); }
                else if (cond.op === 'typeof' && typeof cond.value === 'string') { let sampleValue; switch (cond.value) { case 'string': sampleValue = 'frog_generated_string'; break; case 'number': sampleValue = 1337; break; case 'boolean': sampleValue = true; break; case 'object': sampleValue = { frog_generated_object: true }; break; default: continue; } log.debug(`[Payload Gen] _satisfyConditions: Setting path '${cond.path}' for typeof to value:`, sampleValue); this.setNestedValue(modifiedBase, cond.path, sampleValue); }
                else { log.debug(`[Payload Gen] _satisfyConditions: Skipping condition with op '${cond.op}'`); }
            } catch (e) { log.error(`[Payload Gen] _satisfyConditions: Error processing condition for path '${cond.path}'`, e); }
        }
        log.debug("[Payload Gen] _satisfyConditions: Output modifiedBase:", JSON.stringify(modifiedBase));
        return modifiedBase;
    }

    async generateContextAwarePayloads(context) {
        const { uniqueStructures = [], vulnerabilities = { sinks: [], securityIssues: [] }, staticAnalysisData = null, originalMessages = [], dynamicAnalysisResults = null } = context;
        const safeStaticData = staticAnalysisData || {};
        let accessedEventDataPathsSet = safeStaticData.accessedEventDataPaths instanceof Set ? safeStaticData.accessedEventDataPaths : new Set(Array.isArray(safeStaticData.accessedEventDataPaths) ? safeStaticData.accessedEventDataPaths : []);
        const requiredConditionsForSinkPath = safeStaticData.requiredConditions || {};
        const externalStateAccesses = safeStaticData.externalStateAccesses || [];
        const indirectCalls = safeStaticData.indirectCalls || [];
        const isStateDependentHandler = externalStateAccesses.length > 0 || indirectCalls.length > 0;
        const analysisSucceeded = !!staticAnalysisData;

        const generatedPayloads = [];
        const handledSmartObjectPaths = new Set();
        const handledDumbObjectPaths = new Set();
        const handledTypePaths = new Set();
        const handledStructureGuessPaths = new Set();
        const handledRawStringSmart = new Set();
        const handledRawStringDumb = new Set();

        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());
        const { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads, typeFuzzPayloads } = await this._getPayloadLists();
        let synthesizedBase = null;

        const objectStructuresFromMessages = uniqueStructures.filter(s => s.structure.type === 'object').map(s => ({ source: 'message', structure: s.structure, baseObject: s.examples?.[0]?.data !== undefined ? s.examples[0].data : s.original, paths: s.pathsToFuzz || [] }));
        const rawStringStructures = uniqueStructures.filter(s => s.structure.type !== 'object').map(s => ({ source: 'message', baseObject: s.examples?.[0]?.data !== undefined ? s.examples[0].data : s.original, type: 'raw-string' }));
        if (originalMessages && originalMessages.length > 0) {
            originalMessages.forEach(msg => {
                if (typeof msg?.data === 'string' && !rawStringStructures.some(rs => rs.baseObject === msg.data) && !objectStructuresFromMessages.some(os => JSON.stringify(os.baseObject) === JSON.stringify(msg.data))) {
                    rawStringStructures.push({ source: 'raw-string', baseObject: msg.data, type: 'raw-string' });
                }
            });
        }

        if (analysisSucceeded && staticAnalysisData) {
            try {
                const synthesizedStructureObject = this.createStructureFromStaticAnalysis(staticAnalysisData);
                if (synthesizedStructureObject && typeof synthesizedStructureObject === 'object' && synthesizedStructureObject.fields?.size > 0) {
                    let synthesizedPaths = [];
                    try {
                        if (synthesizedStructureObject.properties) {
                            const extractPaths = (props, currentPrefix = '') => {
                                Object.entries(props).forEach(([key, details]) => {
                                    if (!details || typeof details !== 'object') return;
                                    const newPath = currentPrefix ? `${currentPrefix}.${key}` : key;
                                    synthesizedPaths.push({ path: newPath, type: details.expectedType || 'unknown' });
                                    if (details.properties && Object.keys(details.properties).length > 0) extractPaths(details.properties, newPath);
                                    else if (details.itemDetails?.properties && Object.keys(details.itemDetails.properties).length > 0) extractPaths(details.itemDetails.properties, `${newPath}[*]`);
                                });
                            };
                            extractPaths(synthesizedStructureObject.properties);
                        } else if (synthesizedStructureObject.fields) {
                            synthesizedPaths.push(...Array.from(synthesizedStructureObject.fields).map(f => ({ path: f, type: 'unknown' })));
                        }
                    } catch (extractError) { synthesizedPaths = []; }

                    if (synthesizedPaths.length > 0) {
                        synthesizedBase = {
                            source: 'static-analysis',
                            structure: synthesizedStructureObject,
                            baseObject: synthesizedStructureObject.example || {},
                            paths: synthesizedPaths
                        };
                    } else { synthesizedBase = null; }
                } else { synthesizedBase = null; }
            } catch(e) { synthesizedBase = null; }
        }

        const hasObservedObjects = objectStructuresFromMessages.length > 0;
        const hasObservedStrings = rawStringStructures.length > 0;
        const hasSynthesized = !!synthesizedBase;
        const baseStructureAvailable = hasObservedObjects || hasSynthesized;

        if (!hasObservedObjects && !hasObservedStrings && !hasSynthesized) {
            const fallbackPayloadList = shuffleArray(sinkCategoryToPayloadMap['default'] || []).slice(0, 50);
            fallbackPayloadList.forEach(p => { if (generatedPayloads.length < this.MAX_PAYLOADS_TOTAL && typeof p === 'string') { const isCallback = allCallbackPayloads.includes(p); const pType = isCallback ? 'callback-raw-fallback' : (customPayloadsActive ? 'custom-raw-fallback' : 'xss-raw-fallback'); generatedPayloads.push({ type: pType, payload: p, targetPath: 'raw', sinkType: 'unknown', description: `Raw payload (no base structure found)`, baseSource: 'fallback' }); } });
            const uniquePayloads = []; const seenPayloads = new Set(); for(const p of generatedPayloads) { let key = typeof p.payload === 'object' && p.payload !== null ? JSON.stringify(p.payload) : String(p.payload); if(!seenPayloads.has(key)){ uniquePayloads.push(p); seenPayloads.add(key); } } return uniquePayloads.slice(0, this.MAX_PAYLOADS_TOTAL);
        }

        const pathToAnalysisInfoMap = new Map();
        const allPathsFromStatic = new Set(accessedEventDataPathsSet);
        (vulnerabilities.sinks || []).forEach(sink => { const relativePath = sink.sourcePath || sink.path; if (relativePath && relativePath !== '(root)' && relativePath !== '(root_data)' && relativePath !== '(parsed_root)' && !relativePath.startsWith('(parsed ')) { allPathsFromStatic.add(relativePath); const sinkSeverity = this.severityOrder[sink.severity?.toLowerCase()] || 0; const conditionsFromStatic = requiredConditionsForSinkPath[relativePath]?.conditions || sink.conditions || []; const existingEntry = pathToAnalysisInfoMap.get(relativePath); if (!existingEntry || sinkSeverity > (existingEntry.severity || 0)) { pathToAnalysisInfoMap.set(relativePath, { sink: sink, conditions: [...conditionsFromStatic], severity: sinkSeverity }); } else { conditionsFromStatic.forEach(newCond => { if (!existingEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(newCond))) { existingEntry.conditions.push(newCond); }}); if (sinkSeverity > existingEntry.severity) { existingEntry.severity = sinkSeverity; existingEntry.sink = sink; } } } });
        if (analysisSucceeded && requiredConditionsForSinkPath) { Object.entries(requiredConditionsForSinkPath).forEach(([relativePath, conditionInfo]) => { if (relativePath && Array.isArray(conditionInfo?.conditions) && conditionInfo.conditions.length > 0) { allPathsFromStatic.add(relativePath); const conditions = conditionInfo.conditions; if (!pathToAnalysisInfoMap.has(relativePath)) { pathToAnalysisInfoMap.set(relativePath, { sink: null, conditions: [...conditions], severity: 0 }); } else { const existingEntry = pathToAnalysisInfoMap.get(relativePath); conditions.forEach(newCond => { if (!existingEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(newCond))) { existingEntry.conditions.push(newCond); } }); } } }); }

        const prioritizedPaths = Array.from(allPathsFromStatic).filter(p => p && p !== '(root)' && p !== '(root_data)' && p !== '(parsed_root)' && !p.startsWith('(parsed '));
        const sinkPathsToFuzz = prioritizedPaths.filter(path => pathToAnalysisInfoMap.get(path)?.sink).sort((a, b) => (pathToAnalysisInfoMap.get(b)?.severity || 0) - (pathToAnalysisInfoMap.get(a)?.severity || 0));
        let smartPayloadsGenerated = 0;


        if (sinkPathsToFuzz.length > 0 && baseStructureAvailable) {
            const structuresToFuzz = hasSynthesized ? [synthesizedBase] : objectStructuresFromMessages;
            for (const baseStructInfo of structuresToFuzz) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const baseObject = baseStructInfo.baseObject;
                const structurePaths = new Set((baseStructInfo.paths || []).map(p => p.path));
                const baseIdentifier = baseStructInfo.source + '|' + (baseStructInfo.structure.keySignature || 'no-sig');

                for (const targetPath of sinkPathsToFuzz) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const handledKey = targetPath + '|' + baseIdentifier; if (handledSmartObjectPaths.has(handledKey)) continue;

                    const analysisInfo = pathToAnalysisInfoMap.get(targetPath);
                    if (!analysisInfo || !analysisInfo.sink) continue;

                    const pathMightExist = structurePaths.has(targetPath) || targetPath.includes('__proto__') || Array.from(structurePaths).some(sp => targetPath.startsWith(sp + '.') || targetPath.startsWith(sp + '['));
                    if (!pathMightExist) continue;

                    const { sink, conditions } = analysisInfo;
                    const sinkCategory = sink?.category || 'generic';
                    const sinkSeverity = sink?.severity || 'Low';
                    const payloadList = sinkCategoryToPayloadMap[sinkCategory] || sinkCategoryToPayloadMap['default'];
                    const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);
                    let baseForPath; try { baseForPath = this._deepCopy(baseObject); if (conditions && conditions.length > 0) baseForPath = this._satisfyConditions(baseForPath, conditions); } catch (e) { continue; }

                    for (const payload of limitedPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        try {
                            const finalMessage = this._deepCopy(baseForPath);
                            const relativeTargetPath = sink?.sourcePath || targetPath;
                            this.setNestedValue(finalMessage, relativeTargetPath, payload);
                            const isCallback = allCallbackPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload); const payloadBaseType = 'smart-sink'; let pType = customPayloadsActive ? `custom-${payloadBaseType}` : payloadBaseType; if (isCallback) pType += '-callback'; else if (isEncoding) pType += '-encoding'; else pType += '-xss';
                            generatedPayloads.push({ type: pType, payload: finalMessage, targetPath: relativeTargetPath, sinkType: sink?.name || 'N/A (Flow Target)', sinkSeverity: sinkSeverity, description: `Targeted ${isCallback ? 'Callback' : (isEncoding ? 'Encoding/Bypass' : 'XSS')} for ${relativeTargetPath} -> ${sink?.name || 'Flow'}`, baseSource: baseStructInfo.source });
                            smartPayloadsGenerated++;
                        } catch (e) {}
                    }
                    handledSmartObjectPaths.add(handledKey);
                }
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
            }
        }

        if (sinkPathsToFuzz.length > 0 && hasObservedStrings) {
            for (const baseStructInfo of rawStringStructures) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const baseString = String(baseStructInfo.baseObject);
                const baseIdentifier = `${baseStructInfo.source}|${baseString.substring(0,50)}`; if(handledRawStringSmart.has(baseIdentifier)) continue;
                for (const targetPath of sinkPathsToFuzz) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const analysisInfo = pathToAnalysisInfoMap.get(targetPath); if (!analysisInfo || !analysisInfo.sink) continue;
                    const sourcePath = analysisInfo.sink.sourcePath || analysisInfo.sink.path;
                    const isDirectDataSource = sourcePath === '(root_data)' || sourcePath === null || sourcePath === undefined;
                    if (isDirectDataSource) {
                        const { sink } = analysisInfo; const sinkCategory = sink?.category || 'generic'; const sinkSeverity = sink?.severity || 'Low'; const payloadList = sinkCategoryToPayloadMap[sinkCategory] || sinkCategoryToPayloadMap['default']; const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);
                        for (const payload of limitedPayloads) {
                            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break; if (typeof payload !== 'string') continue;
                            try { const isCallback = allCallbackPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload); let pType = customPayloadsActive ? 'custom-smart-string' : 'smart-string'; if(isCallback) pType += '-callback'; else if(isEncoding) pType += '-encoding'; else pType += '-xss'; generatedPayloads.push({ type: pType, payload: payload, targetPath: 'raw', sinkType: sink.name, sinkSeverity: sinkSeverity, description: `Smart string replace for sink ${sink.name}`, baseSource: baseStructInfo.source, original: baseString }); smartPayloadsGenerated++; } catch (e) {}
                        }
                        handledRawStringSmart.add(baseIdentifier);
                        break;
                    }
                }
            }
        }


        const runFallbackBlock = smartPayloadsGenerated < 5 || baseStructureAvailable || hasObservedStrings;

        if (runFallbackBlock) {
            let dumbFuzzedCount = 0;
            let typeFuzzedCount = 0;

            const fallbackTargetPaths = new Set(prioritizedPaths);
            const structuresForFallback = [];
            if(hasSynthesized) structuresForFallback.push(synthesizedBase);
            objectStructuresFromMessages.forEach(obs => {
                structuresForFallback.push(obs);
                if(obs.paths) obs.paths.forEach(p => fallbackTargetPaths.add(p.path));
            });

            const dumbPathsToTarget = shuffleArray(Array.from(fallbackTargetPaths)).slice(0, this.MAX_DUMB_FIELDS_TO_TARGET);
            const typePathsToTarget = shuffleArray(Array.from(fallbackTargetPaths)).slice(0, this.MAX_TYPE_FIELDS_TO_TARGET);
            const dumbPayloadsPerField = isStateDependentHandler ? Math.min(this.MAX_PAYLOADS_PER_DUMB_FIELD + 5, 25) : this.MAX_PAYLOADS_PER_DUMB_FIELD;

            if (dumbPathsToTarget.length > 0 && structuresForFallback.length > 0) {
                for (const baseStructInfo of structuresForFallback) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const baseObject = baseStructInfo.baseObject;
                    const baseIdentifier = baseStructInfo.source + '|' + (baseStructInfo.structure.keySignature || 'no-sig');
                    let baseCopy; try { baseCopy = this._deepCopy(baseObject); } catch(e) { continue; }

                    for (const targetPath of dumbPathsToTarget) {
                        const handledKey = targetPath + '|' + baseIdentifier + '|dumb';
                        if (handledDumbObjectPaths.has(handledKey) || handledSmartObjectPaths.has(targetPath + '|' + baseIdentifier)) continue;
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;

                        const pathMightExist = baseStructInfo.paths.some(p => p.path === targetPath || targetPath.startsWith(p.path + '.') || targetPath.startsWith(p.path + '['));
                        if (!pathMightExist && baseStructInfo.source !== 'static-analysis') continue;

                        const payloadList = sinkCategoryToPayloadMap['generic'] || sinkCategoryToPayloadMap['default'];
                        const limitedPayloads = shuffleArray(payloadList).slice(0, dumbPayloadsPerField);
                        for (const payload of limitedPayloads) {
                            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                            try {
                                const finalMessage = this._deepCopy(baseCopy);
                                this.setNestedValue(finalMessage, targetPath, payload);
                                const isCallback = allCallbackPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload); let pType = customPayloadsActive ? 'custom-dumb' : 'dumb'; if (isCallback) pType += '-callback'; else if(isEncoding) pType += '-encoding'; else pType += '-xss';
                                generatedPayloads.push({ type: pType, payload: finalMessage, targetPath: targetPath, sinkType: 'N/A (Dumb Fuzz)', sinkSeverity: 'Low', description: `Dumb ${isCallback ? 'Callback' : (isEncoding ? 'Encoding' : 'XSS')} for field ${targetPath}`, baseSource: baseStructInfo.source });
                                dumbFuzzedCount++;
                            } catch (e) {}
                        }
                        handledDumbObjectPaths.add(handledKey);
                    }
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                }
            }

            if (typePathsToTarget.length > 0 && structuresForFallback.length > 0 && typeFuzzPayloads.length > 0) {
                for (const baseStructInfo of structuresForFallback) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const baseObject = baseStructInfo.baseObject;
                    const baseIdentifier = baseStructInfo.source + '|' + (baseStructInfo.structure.keySignature || 'no-sig');
                    let baseCopy; try { baseCopy = this._deepCopy(baseObject); } catch(e) { continue; }

                    for (const targetPath of typePathsToTarget) {
                        const handledKey = targetPath + '|' + baseIdentifier + '|type';
                        if (handledTypePaths.has(handledKey) || handledSmartObjectPaths.has(targetPath + '|' + baseIdentifier)) continue;
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;

                        const pathMightExist = baseStructInfo.paths.some(p => p.path === targetPath || targetPath.startsWith(p.path + '.') || targetPath.startsWith(p.path + '['));
                        if (!pathMightExist && baseStructInfo.source !== 'static-analysis') continue;

                        const limitedPayloads = typeFuzzPayloads.slice(0, this.MAX_PAYLOADS_PER_TYPE_FIELD);
                        for (const payload of limitedPayloads) {
                            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                            try {
                                const finalMessage = this._deepCopy(baseCopy);
                                this.setNestedValue(finalMessage, targetPath, payload);
                                generatedPayloads.push({ type: 'type-fuzz', payload: finalMessage, targetPath: targetPath, sinkType: 'N/A (Type Fuzz)', sinkSeverity: 'Low', description: `Type fuzz (${typeof payload}) for field ${targetPath}`, baseSource: baseStructInfo.source });
                                typeFuzzedCount++;
                            } catch(e) {}
                        }
                        handledTypePaths.add(handledKey);
                    }
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                }
            }

            const runStructureGuess = isStateDependentHandler && !baseStructureAvailable;
            if (runStructureGuess) {
                let structureGuessCount = 0;
                const guessedStructures = new Map();
                externalStateAccesses.forEach(access => { if (access.base && access.property && access.property !== '[computed]') { if (!guessedStructures.has(access.base)) { guessedStructures.set(access.base, new Set()); } guessedStructures.get(access.base).add(access.property); } });
                indirectCalls.forEach(call => { const parts = call.source?.split('.'); if (parts && parts.length === 2 && parts[0] && parts[1]) { const base = parts[0]; const prop = parts[1]; if (!guessedStructures.has(base)) guessedStructures.set(base, new Set()); guessedStructures.get(base).add(prop); } });
                let dynamicState = dynamicAnalysisResults?.variableStates || null;

                if (guessedStructures.size > 0) {
                    const guessPayloadList = [...new Set([...(sinkCategoryToPayloadMap['generic'] || []), ...typeFuzzPayloads])];
                    const jsPayloads = sinkCategoryToPayloadMap['eval'] || [];
                    guessedStructures.forEach((propertiesSet, baseVar) => {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) return;
                        const properties = Array.from(propertiesSet); if (properties.length === 0) return;
                        let template = {}; properties.forEach(prop => { template[prop] = 'PLACEHOLDER'; });
                        if(dynamicState && dynamicState[baseVar]?.preview?.properties) { try { const previewProps = dynamicState[baseVar].preview.properties; if(Array.isArray(previewProps)) { template = {}; previewProps.forEach(p => { template[p.name] = p.value || 'PLACEHOLDER'; }); properties.forEach(p => { if(!(p in template)) template[p] = 'PLACEHOLDER'; }); } } catch (e) {} }

                        properties.forEach(propToFuzz => {
                            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) return;
                            const handledKey = `${baseVar}.${propToFuzz}|structure-guess`; if (handledStructureGuessPaths.has(handledKey)) return;
                            let payloadsToUse = shuffleArray(guessPayloadList); if (indirectCalls.some(ic => ic.source === `${baseVar}.${propToFuzz}`)) payloadsToUse = [...new Set([...payloadsToUse, ...jsPayloads])];
                            payloadsToUse = payloadsToUse.slice(0, this.MAX_PAYLOADS_PER_DUMB_FIELD);
                            for (const payload of payloadsToUse) {
                                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                                try { const guessedPayload = this._deepCopy(template); guessedPayload[propToFuzz] = payload; const isCallback = allCallbackPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload); const isType = typeFuzzPayloads.includes(payload); let pSubType = '-xss'; if(isCallback) pSubType = '-callback'; else if(isEncoding) pSubType = '-encoding'; else if(isType) pSubType = '-type'; else if(jsPayloads.includes(payload)) pSubType = '-js';
                                    generatedPayloads.push({ type: `structure-guess${pSubType}`, payload: guessedPayload, targetPath: `${baseVar}.${propToFuzz}`, sinkType: 'N/A (Structure Guess)', sinkSeverity: 'Medium', description: `Structure guess fuzzing for ${baseVar}.${propToFuzz}`, baseSource: 'static-analysis-guess' }); structureGuessCount++; } catch (e) {}
                            }
                            handledStructureGuessPaths.add(handledKey);
                        });
                    });
                }
            }

            if (hasObservedStrings) {
                let rawFuzzedCount = 0;
                const payloadList = [...new Set([...(sinkCategoryToPayloadMap['default'] || []), ...allCallbackPayloads, ...typeFuzzPayloads])];
                const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);
                for (const baseStructInfo of rawStringStructures) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const originalString = String(baseStructInfo.baseObject);
                    const baseIdentifier = `${baseStructInfo.source}|${originalString.substring(0,50)}`;
                    if(handledRawStringSmart.has(baseIdentifier) || handledRawStringDumb.has(baseIdentifier)) continue;
                    for (const payload of limitedPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        const isCallback = allCallbackPayloads.includes(payload); const isTypeFuzz = typeFuzzPayloads.includes(payload); const isEncoding = (window.FuzzingPayloads?.ENCODING || []).includes(payload); let pTypeBase = customPayloadsActive ? 'custom-raw' : 'raw'; if (isCallback) pTypeBase += '-callback'; else if (isTypeFuzz) pTypeBase += '-type'; else if (isEncoding) pTypeBase += '-encoding'; else pTypeBase += '-xss';
                        generatedPayloads.push({ type: `${pTypeBase}-replace`, payload: payload, targetPath: 'raw', sinkType: 'unknown', description: `Dumb Raw Replace (${typeof payload})`, baseSource: 'raw-string', original: originalString }); rawFuzzedCount++;
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        if(typeof payload === 'string') { generatedPayloads.push({ type: `${pTypeBase}-append`, payload: originalString + payload, targetPath: 'raw', sinkType: 'unknown', description: `Dumb Raw Append`, baseSource: 'raw-string', original: originalString }); rawFuzzedCount++; if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break; generatedPayloads.push({ type: `${pTypeBase}-prepend`, payload: payload + originalString, targetPath: 'raw', sinkType: 'unknown', description: `Dumb Raw Prepend`, baseSource: 'raw-string', original: originalString }); rawFuzzedCount++; }
                    }
                    handledRawStringDumb.add(baseIdentifier);
                }
            }
        } // End Fallback Block

        const uniquePayloads = []; const seenPayloads = new Set();
        for(const p of generatedPayloads) { let key; try { key = typeof p.payload === 'object' && p.payload !== null ? JSON.stringify(p.payload) : String(p.payload); } catch { key = String(p.payload); } if(!seenPayloads.has(key)){ uniquePayloads.push(p); seenPayloads.add(key); } }
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
                try {
                    staticAnalysisResult = window.analyzeHandlerStatically( handlerCode, analysisStorageKey, window.handlerTracer.domXssSinks, { eventParamName: bestHandler?.eventParamName });
                    if (staticAnalysisResult?.success && staticAnalysisResult?.analysis) {
                        staticAnalysisData = staticAnalysisResult.analysis;
                        log.success("[Trace Button] Static analysis succeeded.");
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
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        const isStateDependent = staticAnalysisData?.externalStateAccesses?.length > 0 || staticAnalysisData?.indirectCalls?.length > 0;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));
        if (messagesAvailable) { uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages); }
        log.debug(`[Trace Button] Unique structures identified from messages: ${uniqueStructures.length}`);

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));
        const isStaticAnalysisAvailable = !!(staticAnalysisResult?.success && staticAnalysisData);
        const generationContext = { uniqueStructures, vulnerabilities: vulnAnalysis, staticAnalysisData: staticAnalysisData, originalMessages: relevantMessages, dynamicAnalysisResults: null };
        payloads = await window.handlerTracer.generateContextAwarePayloads(generationContext);
        log.info(`[Trace Button] Payload generation completed. Count: ${payloads.length}`);

        updatePhase('saving');
        const securityScore = window.handlerTracer.calculateRiskScore(vulnAnalysis);
        report = {
            endpoint: endpointUrlUsedForAnalysis, // The URL that was successfully analyzed
            originalEndpointKey: endpointKey, // The key from the UI
            analysisStorageKey: analysisStorageKey, // The key under which data is stored
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
        if (!reportSaved || !payloadsSaved) { throw new Error("Failed to save trace report or payloads."); }
        log.success(`Report & ${payloads.length} payloads saved for key: ${reportStorageKey}`);

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
                usedStaticAnalysis: isStaticAnalysisAvailable
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
