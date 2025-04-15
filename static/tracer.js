/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-14
 * Enhanced with Context-Aware Payload Generation & Debugging
 */

if (typeof window.analyzeHandlerStatically === 'undefined') {
    console.error("Static Handler Analyzer not loaded. Payload generation will be limited.");
    window.analyzeHandlerStatically = () => ({ success: false, error: 'Analyzer not loaded.', analysis: null });
}

class HandlerTracer {
    constructor() {
        this.domXssSinks = [
            { name: "eval", pattern: /\beval\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval' },
            { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical", methods: ['regex', 'ast'], category: 'eval' },
            { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setTimeout', argIndex: 0 },
            { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical", methods: ['regex', 'ast'], category: 'setInterval', argIndex: 0 },
            { name: "element.innerHTML assignment", pattern: /\.innerHTML\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'innerHTML' },
            { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High", methods: ['regex', 'ast'], argIndex: 1, category: 'innerHTML' },
            { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High", methods: ['regex', 'ast'], category: 'location_href' },
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
        this.severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0 };
        this.MAX_PAYLOADS_TOTAL = 5000;
        this.MAX_PAYLOADS_PER_SINK_PATH = 30;
        this.MAX_PAYLOADS_PER_DUMB_FIELD = 15;
        this.MAX_DUMB_FIELDS_TO_TARGET = 30;
    }

    isPlainObject(obj) {
        if (typeof obj !== 'object' || obj === null) return false; let proto = Object.getPrototypeOf(obj); if (proto === null) return true; let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) baseProto = Object.getPrototypeOf(baseProto); return proto === baseProto;
    }
    analyzeJsonStructures(messages) {
        const structureMap = new Map(); if (!messages || messages.length === 0) return [];
        for (const message of messages) { if (!message) continue; try { let data = message.data; let dataType = typeof data; if (dataType === 'string') { if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) { try { data = JSON.parse(data); dataType = typeof data; } catch {} } } if (this.isPlainObject(data)) { const structure = this.getJsonStructure(data); const hash = this.hashJsonStructure(structure); if (!structureMap.has(hash)) { const paths = this.identifyPathsToFuzz(structure); structureMap.set(hash, { structure: structure, examples: [message], pathsToFuzz: paths }); } else { const entry = structureMap.get(hash); if (entry.examples.length < 3) entry.examples.push(message); } } } catch {} } return Array.from(structureMap.values());
    }
    getJsonStructure(obj, path = '') {
        if (obj === null || obj === undefined) return { type: 'null', path }; const type = typeof obj; if (type !== 'object') return { type: type, path }; if (Array.isArray(obj)) { const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` }; return { type: 'array', path, items: itemStructure }; } const structure = { type: 'object', path, properties: {} }; const keys = Object.keys(obj).sort(); for (const key of keys) { const newPath = path ? `${path}.${key}` : key; structure.properties[key] = this.getJsonStructure(obj[key], newPath); } return structure;
    }
    hashJsonStructure(structure) {
        if (!structure || !structure.type) return 'invalid'; if (structure.type === 'array') return `array[${this.hashJsonStructure(structure.items)}]`; if (structure.type !== 'object') return structure.type; const keys = Object.keys(structure.properties || {}).sort(); return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(',');
    }
    identifyPathsToFuzz(structure, currentPath = '', paths = []) {
        if (!structure) return paths; const nodePath = structure.path || currentPath; if (structure.type !== 'object' && structure.type !== 'array') { if (nodePath) paths.push({ path: nodePath, type: structure.type }); return paths; } if (structure.type === 'array' && structure.items) this.identifyPathsToFuzz(structure.items, '', paths); else if (structure.type === 'object' && structure.properties) for (const key of Object.keys(structure.properties)) this.identifyPathsToFuzz(structure.properties[key], '', paths); const uniquePaths = []; const seenPaths = new Set(); for (const p of paths) if (p.path && !seenPaths.has(p.path)) { seenPaths.add(p.path); uniquePaths.push(p); } return uniquePaths;
    }
    analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData = null) {
        const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] }; const foundSinks = new Map(); if (!handlerCode) { return vulnerabilities; } const escapeHTML = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        this.domXssSinks.forEach(sink => { if (sink.methods.includes('regex')) { let match; const regex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || '')); while ((match = regex.exec(handlerCode)) !== null) { const exactMatchSnippet = match[0]; const key = `${sink.name || sink.type}#${exactMatchSnippet}`; if (!foundSinks.has(key)) { const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length); let highlightedContextHTML = escapeHTML(rawContext); let highlightStartIndex = -1; let highlightEndIndex = -1; const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet); if (matchIndexInRawContext !== -1) { highlightStartIndex = matchIndexInRawContext; highlightEndIndex = highlightStartIndex + exactMatchSnippet.length; const partBefore = rawContext.substring(0, highlightStartIndex); const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex); const partAfter = rawContext.substring(highlightEndIndex); highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter; } foundSinks.set(key, { type: sink.name || sink.type, severity: sink.severity, context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex, method: 'regex', path: '', category: sink.category || 'generic' }); } } } });
        if (staticAnalysisData?.dataFlows) { vulnerabilities.dataFlows = staticAnalysisData.dataFlows; (staticAnalysisData.dataFlows || []).forEach(flow => { this.domXssSinks.filter(p => p.methods.includes('ast')).forEach(sinkPattern => { let isMatch = false; if (sinkPattern.nodeType && sinkPattern.nodeType !== flow.nodeType) return; if (sinkPattern.argIndex !== undefined && sinkPattern.argIndex !== flow.argIndex) return; let contextToMatch = flow.destinationContext || ""; if(sinkPattern.pattern instanceof RegExp){ const testRegex = new RegExp(sinkPattern.pattern.source, sinkPattern.pattern.flags.replace('g', '')); isMatch = testRegex.test(contextToMatch); } else if(typeof sinkPattern.pattern === 'string'){ isMatch = contextToMatch.includes(sinkPattern.pattern); } if (isMatch) { const context = flow.fullCodeSnippet || flow.taintedNodeSnippet || ''; const key = `${sinkPattern.name || sinkPattern.type}#${context}`; if (!foundSinks.has(key)) { foundSinks.set(key, { type: sinkPattern.name || sinkPattern.type, severity: sinkPattern.severity, path: flow.sourcePath || '(root)', conditions: flow.requiredConditionsForFlow || [], context: escapeHTML(context), highlightStart: -1, highlightEnd: -1, method: 'ast', category: sinkPattern.category || 'generic' }); } } }); }); } vulnerabilities.sinks = Array.from(foundSinks.values());
        const originChecks = staticAnalysisData?.originValidationChecks || []; const hasListener = staticAnalysisData?.hasListener || /addEventListener\s*\(\s*['"]message['"]/i.test(handlerCode) || /onmessage\s*=/i.test(handlerCode); let originCheckCoveredByStatic = false;
        if (hasListener && originChecks.length > 0) { originChecks.forEach(check => { const severity = check.strength === 'Missing' || check.strength === 'Weak' ? 'Medium' : (check.strength === 'Medium' ? 'Medium' : 'Low'); const issueType = check.strength === 'Missing' ? 'Missing origin check' : `${check.strength} Origin Check`; const existing = vulnerabilities.securityIssues.find(iss => iss.type === issueType && iss.details === check.type); if (!existing) { vulnerabilities.securityIssues.push({ type: issueType, severity: severity, context: check.snippet || `Detected origin check type: ${check.type || 'Unknown'}`, details: check.type || 'N/A', strength: check.strength, highlightStart: -1, highlightEnd: -1 }); } }); originCheckCoveredByStatic = true; }
        for (const check of this.securityChecks) { if (check.name.toLowerCase().includes('origin') && originCheckCoveredByStatic) { continue; } if (check.checkFunc && staticAnalysisData) { if (check.checkFunc(handlerCode, staticAnalysisData)) { if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name)) { vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: `${check.name} condition met (via static analysis).`, highlightStart: -1, highlightEnd: -1 }); } } } else if (check.pattern) { let match; try { const flags = [...new Set(['g', 'm', 's', ...(check.pattern.flags?.split('') || [])])].join(''); const regex = new RegExp(check.pattern.source, flags); while ((match = regex.exec(handlerCode)) !== null) { const exactMatchSnippet = match[0]; const rawContext = this.extractContext(handlerCode, match.index, exactMatchSnippet.length); let highlightedContextHTML = escapeHTML(rawContext); let highlightStartIndex = -1; let highlightEndIndex = -1; const matchIndexInRawContext = rawContext.indexOf(exactMatchSnippet); if (matchIndexInRawContext !== -1) { highlightStartIndex = matchIndexInRawContext; highlightEndIndex = highlightStartIndex + exactMatchSnippet.length; const partBefore = rawContext.substring(0, highlightStartIndex); const partMatch = rawContext.substring(highlightStartIndex, highlightEndIndex); const partAfter = rawContext.substring(highlightEndIndex); highlightedContextHTML = partBefore + '<span class="highlight-finding">' + escapeHTML(partMatch) + '</span>' + partAfter; } if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context.includes(escapeHTML(exactMatchSnippet)))) { vulnerabilities.securityIssues.push({ type: check.name, severity: check.severity, context: highlightedContextHTML, highlightStart: highlightStartIndex, highlightEnd: highlightEndIndex }); } if (!regex.global) break; } } catch {} } }
        if (originCheckCoveredByStatic) { vulnerabilities.securityIssues = vulnerabilities.securityIssues.filter(issue => { const isStaticOriginIssue = issue.strength && issue.type.toLowerCase().includes('origin check'); const isOldRegexOriginIssue = !issue.strength && issue.type.toLowerCase().includes('origin check'); return isStaticOriginIssue || !isOldRegexOriginIssue; }); }
        return vulnerabilities;
    }
    extractContext(codeToSearchIn, index, length) {
        const before = Math.max(0, index - 50); const after = Math.min(codeToSearchIn.length, index + length + 50); let context = codeToSearchIn.substring(before, after); context = context.replace(/\n|\r/g, "↵").trim(); return context;
    }
    setValueAtPath(obj, path, value) {
        return this.setNestedValue(obj, path, value);
    }
    calculateRiskScore(analysisResults) {
        let penaltyScore = 0; const MAX_PENALTY = 100; if (!analysisResults) return 100; const sinks = analysisResults.sinks || []; const issues = analysisResults.securityIssues || []; const dataFlows = analysisResults.dataFlows || []; sinks.forEach(sink => { switch (sink.severity?.toLowerCase()) { case 'critical': penaltyScore += 35; break; case 'high': penaltyScore += 20; break; case 'medium': penaltyScore += 8; break; case 'low': penaltyScore += 2; break; default: penaltyScore += 1; break; } }); let mediumIssueCount = 0; issues.forEach(issue => { if (issue.type.toLowerCase().includes('origin check')) { switch (issue.strength?.toLowerCase()) { case 'missing': penaltyScore += 15; break; case 'weak': penaltyScore += 15; break; case 'medium': penaltyScore += 5; break; case 'strong': penaltyScore += 0; break; default: penaltyScore += 5; break; } } else { switch (issue.severity?.toLowerCase()) { case 'high': penaltyScore += 15; break; case 'medium': mediumIssueCount++; penaltyScore += 5 + Math.min(mediumIssueCount, 4); break; case 'low': penaltyScore += 3; break; default: penaltyScore += 1; break; } } }); if (dataFlows.length > 0) { let flowPenalty = 0; dataFlows.forEach(flow => { switch (flow.severity?.toLowerCase()) { case 'critical': flowPenalty += 5; break; case 'high': flowPenalty += 3; break; case 'medium': flowPenalty += 1; break; default: flowPenalty += 0.5; break; } }); penaltyScore += Math.min(flowPenalty, 25); } if (issues.some(issue => issue.type.toLowerCase().includes('window.parent') && issue.type.toLowerCase().includes('origin check'))) penaltyScore += 10; penaltyScore = Math.min(penaltyScore, MAX_PENALTY); let finalScore = Math.max(0, 100 - penaltyScore); return Math.round(finalScore);
    }
    createSyntheticStructureFromPaths(pathsSet) {
        const structure = {}; function setPathValue(obj, pathParts, value) { let current=obj; for(let i=0;i<pathParts.length-1;i++){const part=pathParts[i];if(!current[part]||typeof current[part]!=='object'){const next=/^\d+$/.test(pathParts[i+1])?[]:{};current[part]=next;}current=current[part];} const last=pathParts[pathParts.length-1]; if(typeof current==='object'&&current!==null&&current[last]===undefined)current[last]=value; } const getDefaultValue = (p)=>{const l=p.toLowerCase(); return l.includes('url')||l.includes('src')||l.includes('href')?'https://e.com':l.includes('id')||l.includes('count')||l.includes('index')?0:l.includes('enabled')||l.includes('isvalid')||l.includes('success')?true:l.includes('name')||l.includes('title')?'P Name':l.includes('type')||l.includes('action')||l.includes('cmd')||l.includes('kind')||l.includes('messageType')?'message':l.includes('desc')||l.includes('text')||l.includes('content')?'P text.':'p_val';}; const sortedPaths = Array.from(pathsSet).sort((a, b) => a.split(/[\.\[]/).length - b.split(/[\.\[]/).length); sortedPaths.forEach(path => { const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g)?.map(p => p.startsWith('[') ? p.substring(1, p.length - 1).replace(/['"`]/g, '') : p) || []; if (parts.length > 0 && path !== '(root)') setPathValue(structure, parts, getDefaultValue(path)); }); if (pathsSet.has('(root)') && Object.keys(structure).length === 0) return [{ type: 'raw_value', original: getDefaultValue('(root)'), fields: [], fieldTypes: {}, pathsToFuzz: [{path: '(root)', type: 'string'}], source: 'static-analysis' }]; if (Object.keys(structure).length === 0 && !pathsSet.has('(root)')) return []; const fieldTypes = this.getFieldTypesFromObject(structure); const fields = this.extractAllFieldsFromObject(structure); const typeFields = fields.filter(f => ['type', 'action', 'messagetype', 'kind', 'cmd'].includes(f.toLowerCase())); const structureVariants = []; if (typeFields.length > 0) { const commonTypes = ['message', 'request', 'response', 'config', 'init', 'load', 'save']; const base = JSON.parse(JSON.stringify(structure)); commonTypes.forEach(typeValue => { const variant = JSON.parse(JSON.stringify(base)); typeFields.forEach(field => this.setValueAtPath(variant, field, typeValue)); structureVariants.push({ type: 'object', original: variant, pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })), examples: [{ data: JSON.parse(JSON.stringify(variant)) }], source: 'static-analysis-variant' }); }); if (structureVariants.length > 0) return structureVariants; } return [{ type: 'object', original: JSON.parse(JSON.stringify(structure)), pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || 'unknown' })), examples: [{ data: JSON.parse(JSON.stringify(structure)) }], source: 'static-analysis' }];
    }
    matchSinkPattern(destContext) {
        if (!destContext) return null; for (const sink of this.domXssSinks) { if (!sink.pattern) continue; let isMatch=false; if (sink.pattern instanceof RegExp){const testRegex=new RegExp(sink.pattern.source,sink.pattern.flags.replace('g',''));isMatch=testRegex.test(destContext);}else if(typeof sink.pattern==='string')isMatch=destContext.includes(sink.pattern); if(isMatch)return {name:sink.name,severity:sink.severity,category:sink.category||'generic'}; } return null;
    }
    getFieldTypesFromObject(obj, prefix = '', types = {}) {
        if (!obj || typeof obj !== 'object') return types; for (const key in obj) { if (Object.hasOwnProperty.call(obj, key)) { const fieldPath = prefix ? `${prefix}.${key}` : key; types[fieldPath] = Array.isArray(obj[key]) ? 'array' : typeof obj[key]; if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) this.getFieldTypesFromObject(obj[key], fieldPath, types); else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') this.getFieldTypesFromObject(obj[key][0], `${fieldPath}[0]`, types); } } return types;
    }
    extractAllFieldsFromObject(obj, prefix = '', fields = []) {
        if (!obj || typeof obj !== 'object') return fields; for (const key in obj) { if (Object.hasOwnProperty.call(obj, key)) { const fieldPath = prefix ? `${prefix}.${key}` : key; fields.push(fieldPath); if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) this.extractAllFieldsFromObject(obj[key], fieldPath, fields); else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') this.extractAllFieldsFromObject(obj[key][0], `${fieldPath}[0]`, fields); } } return [...new Set(fields)];
    }
    setNestedValue(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) { if(typeof obj === 'string') return value; return; } const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || []; let current = obj; for (let i = 0; i < parts.length - 1; i++) { let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, ''); const nextPartStr = parts[i + 1]; let nextPartNormalized = nextPartStr; if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, ''); const isNextPartIndex = /^\d+$/.test(nextPartNormalized); if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') current[part] = isNextPartIndex ? [] : {}; current = current[part]; if (typeof current !== 'object' || current === null) return; } let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, ''); if (typeof current === 'object' && current !== null) { const isIndex = /^\d+$/.test(lastPart); if (Array.isArray(current) && isIndex) current[parseInt(lastPart, 10)] = value; else if (!Array.isArray(current)) current[lastPart] = value; }
    }

    _deepCopy(obj) {
        try {
            if (obj === null || typeof obj !== 'object') {
                return obj;
            }
            return JSON.parse(JSON.stringify(obj));
        } catch (e) {
            console.error("[PayloadGen] Deep copy failed:", e);
            return { ...obj };
        }
    }

    _satisfyConditions(baseObject, conditions) {
        if (!conditions || conditions.length === 0 || !baseObject || typeof baseObject !== 'object') {
            return this._deepCopy(baseObject);
        }
        const modifiedBase = this._deepCopy(baseObject);
        for (const cond of conditions) {
            if (!cond || !cond.path || cond.path === '(root)' || cond.value === undefined) continue;
            if (String(cond.value).startsWith('[EXPRESSION:')) continue;
            try {
                if ((cond.op === '===' || cond.op === '==') && cond.value !== null) {
                    this.setNestedValue(modifiedBase, cond.path, cond.value);
                } else if (cond.op === 'typeof' && typeof cond.value === 'string') {
                    let sampleValue;
                    switch (cond.value) {
                        case 'string': sampleValue = 'frog_generated_string'; break;
                        case 'number': sampleValue = 1337; break;
                        case 'boolean': sampleValue = true; break;
                        case 'object': sampleValue = { frog_generated_object: true }; break;
                        default: continue;
                    }
                    this.setNestedValue(modifiedBase, cond.path, sampleValue);
                }
            } catch (e) {
                window.log.debug(`[PayloadGen] Error satisfying condition for path ${cond.path}: ${e.message}`);
            }
        }
        return modifiedBase;
    }

    async _getPayloadLists() {
        let customXssPayloads = [];
        let customPayloadsActive = false;
        let callbackUrl = null;
        let processedCallbackPayloads = [];
        try {
            const results = await new Promise(resolve => chrome.storage.session.get(['customXssPayloads', 'callback_url'], resolve));
            customXssPayloads = results.customXssPayloads || [];
            callbackUrl = results.callback_url;
            customPayloadsActive = customXssPayloads.length > 0;
            if (callbackUrl && window.FuzzingPayloads?.CALLBACK_URL) {
                processedCallbackPayloads = window.FuzzingPayloads.CALLBACK_URL
                    .map(template => String(template).replace(/%%CALLBACK_URL%%/g, callbackUrl));
            }
        } catch (e) {
            console.error("[PayloadGen] Error fetching session storage for payloads/callback:", e);
        }
        const baseFuzzingPayloads = window.FuzzingPayloads || { XSS: [], SINK_SPECIFIC: {} };
        const activeXssPayloads = customPayloadsActive ? customXssPayloads : (baseFuzzingPayloads.XSS || []);
        const sinkCategoryToPayloadMap = {
            'eval': baseFuzzingPayloads.SINK_SPECIFIC?.eval || activeXssPayloads,
            'setTimeout': baseFuzzingPayloads.SINK_SPECIFIC?.setTimeout || activeXssPayloads,
            'setInterval': baseFuzzingPayloads.SINK_SPECIFIC?.setInterval || activeXssPayloads,
            'innerHTML': baseFuzzingPayloads.SINK_SPECIFIC?.innerHTML || activeXssPayloads,
            'script_manipulation': activeXssPayloads,
            'src_manipulation': [...activeXssPayloads, ...processedCallbackPayloads],
            'location_href': baseFuzzingPayloads.SINK_SPECIFIC?.location_href || [...activeXssPayloads, ...processedCallbackPayloads],
            'event_handler': activeXssPayloads,
            'dom_manipulation': activeXssPayloads,
            'generic': [...activeXssPayloads, ...processedCallbackPayloads],
            'default': [...activeXssPayloads, ...processedCallbackPayloads]
        };
        for (const key in sinkCategoryToPayloadMap) {
            if (Array.isArray(sinkCategoryToPayloadMap[key])) {
                sinkCategoryToPayloadMap[key] = sinkCategoryToPayloadMap[key].map(p => String(p));
            } else {
                sinkCategoryToPayloadMap[key] = [...activeXssPayloads, ...processedCallbackPayloads].map(p => String(p));
            }
        }
        window.log.debug(`[PayloadGen] Loaded payload lists. Custom Active: ${customPayloadsActive}. XSS Count: ${activeXssPayloads.length}. Callback Count: ${processedCallbackPayloads.length}`);
        return { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads: processedCallbackPayloads };
    }

    async generateContextAwarePayloads(context) {
        const {
            uniqueStructures = [],
            vulnerabilities = { sinks: [], securityIssues: [] },
            staticAnalysisData = null,
            originalMessages = []
        } = context;

        const safeStaticData = staticAnalysisData || {};
        const dataFlows = safeStaticData.dataFlows || [];
        const accessedEventDataPaths = safeStaticData.accessedEventDataPaths instanceof Set
            ? safeStaticData.accessedEventDataPaths
            : new Set();
        const originValidationChecks = safeStaticData.originValidationChecks || [];
        const requiredConditions = safeStaticData.requiredConditions || {};

        window.log.debug("[PayloadGen] Starting generation. Context received. Static Analysis available:", !!staticAnalysisData);

        const generatedPayloads = [];
        const handledSinkPaths = new Set();
        const handledDumbPaths = new Set();
        const shuffleArray = arr => [...arr].sort(() => 0.5 - Math.random());

        const { sinkCategoryToPayloadMap, customPayloadsActive, allCallbackPayloads } = await this._getPayloadLists();

        let baseMessageStructures = [];
        let objectStructures = [];
        if (uniqueStructures && uniqueStructures.length > 0) {
            objectStructures = uniqueStructures.map(s => ({
                source: 'message', structure: s, baseObject: s.examples?.[0]?.data !== undefined ? s.examples[0].data : s.original,
                paths: s.pathsToFuzz || []
            })).filter(s => s.baseObject !== undefined && typeof s.baseObject === 'object');
            window.log.debug(`[PayloadGen] Found ${objectStructures.length} object structures from messages.`);
            baseMessageStructures.push(...objectStructures);
        }

        let rawStringMessages = [];
        if (originalMessages && originalMessages.length > 0) {
            rawStringMessages = originalMessages.filter(msg => typeof msg?.data === 'string' && !objectStructures.some(os => os.baseObject === msg.data));
            if (rawStringMessages.length > 0) window.log.debug(`[PayloadGen] Found ${rawStringMessages.length} potential raw string messages.`);
        }

        if (baseMessageStructures.length === 0 && staticAnalysisData && accessedEventDataPaths.size > 0) {
            try {
                const syntheticStructures = this.createSyntheticStructureFromPaths(accessedEventDataPaths);
                baseMessageStructures = syntheticStructures.map(s => ({
                    source: 'static-analysis', structure: s, baseObject: s.original, paths: s.pathsToFuzz || []
                })).filter(s => s.baseObject !== undefined && typeof s.baseObject === 'object');
                if(baseMessageStructures.length > 0) window.log.debug(`[PayloadGen] Using ${baseMessageStructures.length} structures synthesized from static analysis.`);
            } catch(e) { console.error("[PayloadGen] Error creating synthetic structures:", e); }
        }

        let addedRawStringBases = false;
        if (baseMessageStructures.length === 0 && rawStringMessages.length > 0) {
            rawStringMessages.slice(0, 50).forEach(msg => {
                baseMessageStructures.push({ source: 'raw-string', structure: null, baseObject: msg.data, paths: [] });
            });
            if (baseMessageStructures.length > 0) {
                window.log.debug(`[PayloadGen] Using ${baseMessageStructures.length} raw string bases as primary.`);
                addedRawStringBases = true;
            }
        }

        if (baseMessageStructures.length === 0) {
            window.log.warn("[PayloadGen] No base message structures found. Fuzzing will be very limited.");
            const fallbackPayloadList = shuffleArray(sinkCategoryToPayloadMap['default'] || []).slice(0, 50);
            fallbackPayloadList.forEach(p => {
                if (generatedPayloads.length < this.MAX_PAYLOADS_TOTAL) {
                    const isCallback = allCallbackPayloads.includes(p);
                    const pType = isCallback ? 'callback-raw-fallback' : (customPayloadsActive ? 'custom-raw-fallback' : 'xss-raw-fallback');
                    generatedPayloads.push({ type: pType, payload: p, targetPath: 'raw', sinkType: 'unknown', description: `Raw payload (no base structure)` });
                }
            });
            window.log.debug(`[PayloadGen] Returning ${generatedPayloads.length} raw fallback payloads.`);
            return generatedPayloads;
        }
        window.log.debug(`[PayloadGen] Determined ${baseMessageStructures.length} base structures. Sources: ${[...new Set(baseMessageStructures.map(b=>b.source))].join(', ')}`);

        const pathToAnalysisInfoMap = new Map();
        const allPathsFromFlows = new Set(accessedEventDataPaths);
        dataFlows.forEach(flow => {
            const path = flow.sourcePath || '(root)';
            if (path !== '(root)') allPathsFromFlows.add(path);
            const conditions = flow.requiredConditionsForFlow || [];
            if (!pathToAnalysisInfoMap.has(path)) {
                pathToAnalysisInfoMap.set(path, { sink: null, conditions: [] });
            }
            const existingEntry = pathToAnalysisInfoMap.get(path);
            conditions.forEach(newCond => {
                if (!existingEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(newCond))) {
                    existingEntry.conditions.push(newCond);
                }
            });
        });
        (vulnerabilities.sinks || []).forEach(sink => {
            const path = sink.path || '(root)';
            if (path === '(root)') return;
            allPathsFromFlows.add(path);
            const sinkSeverity = this.severityOrder[sink.severity?.toLowerCase()] || 0;
            const existingEntry = pathToAnalysisInfoMap.get(path);
            if (!existingEntry) {
                pathToAnalysisInfoMap.set(path, { sink: sink, conditions: sink.conditions || [] });
            } else {
                const currentSeverity = this.severityOrder[existingEntry.sink?.severity?.toLowerCase()] || -1;
                if (sinkSeverity > currentSeverity) {
                    existingEntry.sink = sink;
                    (sink.conditions || []).forEach(newCond => {
                        if (!existingEntry.conditions.some(c => JSON.stringify(c) === JSON.stringify(newCond))) {
                            existingEntry.conditions.push(newCond);
                        }
                    });
                }
            }
        });
        window.log.debug(`[PayloadGen] Built path analysis map. Size: ${pathToAnalysisInfoMap.size}. Keys: ${Array.from(pathToAnalysisInfoMap.keys()).join(', ')}`);

        const prioritizedPaths = Array.from(allPathsFromFlows)
            .filter(p => p !== '(root)')
            .sort((a, b) => {
                const severityA = this.severityOrder[pathToAnalysisInfoMap.get(a)?.sink?.severity?.toLowerCase()] || 0;
                const severityB = this.severityOrder[pathToAnalysisInfoMap.get(b)?.sink?.severity?.toLowerCase()] || 0;
                return severityB - severityA;
            });
        window.log.debug(`[PayloadGen] Prioritized paths for smart fuzzing: ${prioritizedPaths.join(', ')}`);

        for (const baseStructInfo of baseMessageStructures) {
            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
            if (baseStructInfo.source === 'raw-string') continue;

            const baseObject = baseStructInfo.baseObject;
            if(typeof baseObject !== 'object' || baseObject === null) continue;

            const structurePaths = new Set((baseStructInfo.paths || []).map(p => p.path));
            window.log.debug(`[PayloadGen] Processing base structure. Source: ${baseStructInfo.source}. Paths in structure: ${structurePaths.size}`);

            for (const targetPath of prioritizedPaths) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                if (!structurePaths.has(targetPath) && !Array.from(structurePaths).some(sp => targetPath.startsWith(sp + '.') || targetPath.startsWith(sp + '['))) {
                    if (baseStructInfo.source !== 'static-analysis' && !targetPath.includes('__proto__')) {
                        window.log.debug(`[PayloadGen] Skipping path ${targetPath} for base structure from ${baseStructInfo.source} as it does not seem relevant.`);
                        continue;
                    } else {
                        window.log.debug(`[PayloadGen] Path ${targetPath} not directly in structure, but proceeding for static-analysis base or __proto__.`);
                    }
                }
                if (handledSinkPaths.has(targetPath)) continue;

                const analysisInfo = pathToAnalysisInfoMap.get(targetPath);
                if (!analysisInfo) continue;

                window.log.debug(`[PayloadGen] Targeting path: ${targetPath}. Analysis Info:`, analysisInfo);

                const { sink, conditions } = analysisInfo;
                const sinkCategory = sink?.category || 'generic';
                const sinkSeverity = sink?.severity || 'Low';
                const payloadList = sinkCategoryToPayloadMap[sinkCategory] || sinkCategoryToPayloadMap['default'];
                const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);
                window.log.debug(`[PayloadGen] Path: ${targetPath}. Sink Category: ${sinkCategory}. Selected ${limitedPayloads.length} payloads.`);

                let conditionSatisfiedBase;
                try {
                    conditionSatisfiedBase = this._satisfyConditions(baseObject, conditions);
                    window.log.debug(`[PayloadGen] Path: ${targetPath}. Condition satisfied base:`, this._deepCopy(conditionSatisfiedBase));
                } catch (e) {
                    window.log.error(`[PayloadGen] Failed to satisfy conditions for path ${targetPath}: ${e.message}`);
                    conditionSatisfiedBase = this._deepCopy(baseObject);
                }

                for (const payload of limitedPayloads) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    try {
                        const finalMessage = this._deepCopy(conditionSatisfiedBase);
                        this.setNestedValue(finalMessage, targetPath, payload);
                        const isCallback = allCallbackPayloads.includes(payload);
                        const payloadBaseType = sink ? 'smart-sink' : 'smart-flow';
                        let pType = customPayloadsActive ? `custom-${payloadBaseType}` : payloadBaseType;
                        if (isCallback) pType += '-callback';
                        generatedPayloads.push({
                            type: pType, payload: finalMessage, targetPath: targetPath, sinkType: sink?.name || 'N/A (Flow Target)',
                            sinkSeverity: sinkSeverity, description: `Targeted ${isCallback ? 'Callback' : 'XSS'} for ${targetPath} -> ${sink?.name || 'Flow'}`, baseSource: baseStructInfo.source
                        });
                        window.log.debug(`[PayloadGen] Added ${pType} payload for path ${targetPath}. Total: ${generatedPayloads.length}`);
                    } catch (e) {
                        window.log.warn(`[PayloadGen] Error injecting payload for ${targetPath}: ${e.message}`);
                    }
                }
                handledSinkPaths.add(targetPath);
            }
            if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
        }

        let dumbFuzzedCount = 0;
        const potentialDumbPaths = new Set();
        baseMessageStructures.forEach(bs => {
            if (bs.source !== 'raw-string' && bs.paths) {
                bs.paths.forEach(p => {
                    if (p.type === 'string' && !handledSinkPaths.has(p.path) && !handledDumbPaths.has(p.path)) {
                        potentialDumbPaths.add(p.path);
                    }
                });
            }
        });
        const dumbPathsToTarget = shuffleArray(Array.from(potentialDumbPaths)).slice(0, this.MAX_DUMB_FIELDS_TO_TARGET);
        window.log.debug(`[PayloadGen] Identified ${potentialDumbPaths.size} potential paths for dumb fuzzing. Targeting ${dumbPathsToTarget.length}.`);

        if (dumbPathsToTarget.length > 0) {
            for (const baseStructInfo of baseMessageStructures) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                if (baseStructInfo.source === 'raw-string') continue;
                const baseObject = baseStructInfo.baseObject;
                if(typeof baseObject !== 'object' || baseObject === null) continue;

                for (const targetPath of dumbPathsToTarget) {
                    if (!baseStructInfo.paths?.some(p => p.path === targetPath) || handledSinkPaths.has(targetPath) || handledDumbPaths.has(targetPath)) {
                        continue;
                    }
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const payloadList = sinkCategoryToPayloadMap['generic'] || sinkCategoryToPayloadMap['default'];
                    const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_DUMB_FIELD);
                    const baseCopy = this._deepCopy(baseObject);
                    window.log.debug(`[PayloadGen] Dumb fuzzing path: ${targetPath} with ${limitedPayloads.length} payloads.`);

                    for (const payload of limitedPayloads) {
                        if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                        try {
                            const finalMessage = this._deepCopy(baseCopy);
                            this.setNestedValue(finalMessage, targetPath, payload);
                            const isCallback = allCallbackPayloads.includes(payload);
                            let pType = customPayloadsActive ? 'custom-dumb' : 'dumb';
                            if (isCallback) pType += '-callback';
                            generatedPayloads.push({
                                type: pType, payload: finalMessage, targetPath: targetPath, sinkType: 'N/A (Dumb Fuzz)',
                                sinkSeverity: 'Low', description: `Dumb ${isCallback ? 'Callback' : 'XSS'} for field ${targetPath}`, baseSource: baseStructInfo.source
                            });
                            dumbFuzzedCount++;
                        } catch (e) {
                            window.log.warn(`[PayloadGen] Error injecting dumb payload for ${targetPath}: ${e.message}`);
                        }
                    }
                    handledDumbPaths.add(targetPath);
                }
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
            }
        }
        if (dumbFuzzedCount > 0) window.log.debug(`[PayloadGen] Added ${dumbFuzzedCount} dumb fuzzing payloads.`);

        const rawStringBases = baseMessageStructures.filter(b => b.source === 'raw-string');
        if (!addedRawStringBases && rawStringMessages.length > 0) {
            rawStringMessages.slice(0, 50).forEach(msg => {
                if (!rawStringBases.some(rsb => rsb.baseObject === msg.data)) {
                    rawStringBases.push({ source: 'raw-string', structure: null, baseObject: msg.data, paths: [] });
                }
            });
            if (rawStringBases.length > 0) window.log.debug(`[PayloadGen] Added ${rawStringBases.length} raw string bases for final processing.`);
        }
        if (rawStringBases.length > 0) {
            const payloadList = sinkCategoryToPayloadMap['default'] || [];
            const limitedPayloads = shuffleArray(payloadList).slice(0, this.MAX_PAYLOADS_PER_SINK_PATH);
            window.log.debug(`[PayloadGen] Processing ${rawStringBases.length} raw string bases with ${limitedPayloads.length} payloads each.`);

            for (const baseStructInfo of rawStringBases) {
                if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                const originalString = String(baseStructInfo.baseObject);

                for (const payload of limitedPayloads) {
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    const isCallback = allCallbackPayloads.includes(payload);
                    let pTypeBase = customPayloadsActive ? 'custom-raw' : 'raw';
                    if (isCallback) pTypeBase += '-callback';
                    generatedPayloads.push({
                        type: `${pTypeBase}-replace`, payload: payload, targetPath: 'raw', sinkType: 'unknown',
                        description: `Raw Replace ${isCallback ? 'Callback' : 'XSS'}`, baseSource: 'raw-string', original: originalString
                    });
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    generatedPayloads.push({
                        type: `${pTypeBase}-append`, payload: originalString + payload, targetPath: 'raw', sinkType: 'unknown',
                        description: `Raw Append ${isCallback ? 'Callback' : 'XSS'}`, baseSource: 'raw-string', original: originalString
                    });
                    if (generatedPayloads.length >= this.MAX_PAYLOADS_TOTAL) break;
                    generatedPayloads.push({
                        type: `${pTypeBase}-prepend`, payload: payload + originalString, targetPath: 'raw', sinkType: 'unknown',
                        description: `Raw Prepend ${isCallback ? 'Callback' : 'XSS'}`, baseSource: 'raw-string', original: originalString
                    });
                }
            }
        }

        window.log.success(`[PayloadGen] Finished generation. Total: ${generatedPayloads.length}.`);
        return generatedPayloads.slice(0, this.MAX_PAYLOADS_TOTAL);
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
        const phaseElement = progressContainer?.querySelector(`.phase[data-phase="${phase}"]`); if (!phaseElement) { return; } progressContainer?.querySelectorAll('.phase').forEach(el => el.classList.remove('active', 'completed', 'error')); phaseElement.classList.add(status); if (status === 'error' || status === 'completed') { const finalPhase = status === 'error' ? 'error' : 'finished'; const finalElement = progressContainer?.querySelector(`.phase[data-phase="${finalPhase}"]`); if (finalElement) { finalElement.style.display = 'flex'; finalElement.classList.add(status); } } else { progressContainer?.querySelectorAll('.phase[data-phase="finished"], .phase[data-phase="error"]').forEach(el => el.style.display = 'none'); }
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
    let staticAnalysisData = null;
    let messagesAvailable = false;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) {
            window.handlerTracer = new HandlerTracer();
        }

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;
        analysisStorageKey = window.getStorageKeyForUrl(endpointUrlUsedForAnalysis);
        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;
        if (!handlerCode) throw new Error(`No handler code found (Storage Key: ${bestHandlerStorageKey}). Run Play first.`);
        const relevantMessages = await window.retrieveMessagesWithFallbacks(endpointKey);
        messagesAvailable = relevantMessages.length > 0;
        window.log.handler(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));

        if (window.analyzeHandlerStatically && handlerCode) {
            try {
                log.debug(handlerCode)
                const staticResults = window.analyzeHandlerStatically(handlerCode);
                if (staticResults?.success && staticResults.analysis) {
                    staticAnalysisData = staticResults.analysis;
                    window.log.handler(`[Trace] Static analysis successful.`);
                } else {
                    window.log.warn(`[Trace] Static analysis failed: ${staticResults?.error}. Proceeding without AST data.`);
                    staticAnalysisData = null;
                }
            } catch (e) {
                window.log.error("Error executing static analyzer:", e);
                staticAnalysisData = null;
            }
        } else {
            window.log.warn("[Trace] Static analyzer not available or no handler code.");
            staticAnalysisData = null;
        }

        vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));

        if (messagesAvailable) {
            uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);
        }

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));

        const generationContext = {
            uniqueStructures,
            vulnerabilities: vulnAnalysis,
            staticAnalysisData,
            originalMessages: relevantMessages
        };
        payloads = await window.handlerTracer.generateContextAwarePayloads(generationContext);

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
                dataFlows: staticAnalysisData?.dataFlows || [],
                originValidationChecks: staticAnalysisData?.originValidationChecks || [],
                payloadsGeneratedCount: payloads.length,
                uniqueStructures: uniqueStructures || [],
                staticAnalysisUsed: !!staticAnalysisData,
                messagesAvailable: messagesAvailable,
                requiredConditions: staticAnalysisData?.requiredConditions || {}
            },
            summary: {
                messagesAnalyzed: relevantMessages.length,
                patternsIdentified: uniqueStructures.length,
                sinksFound: vulnAnalysis.sinks?.length || 0,
                issuesFound: vulnAnalysis.securityIssues?.length || 0,
                payloadsGenerated: payloads.length,
                securityScore: securityScore,
                staticAnalysisUsed: !!staticAnalysisData
            }
        };

        window.log.info(`[Trace] Saving report. Payloads: ${payloads.length}. AST Used: ${!!staticAnalysisData}`);
        const reportStorageKey = analysisStorageKey;
        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);
        if (!reportSaved || !payloadsSaved) {
            throw new Error("Failed to save trace report or payloads.");
        }
        window.log.success(`Report & ${payloads.length} payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true, criticalSinks: hasCriticalSinks, analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey, timestamp: Date.now(), payloadCount: payloads.length,
                sinkCount: vulnAnalysis.sinks?.length || 0, usedStaticAnalysis: !!staticAnalysisData
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
        try { await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false, error: error.message, timestamp: Date.now() } }); } catch (e) { console.error("Failed to save error state", e); }
        if (reportButton) window.updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
        const errorLabel = progressContainer?.querySelector('.phase[data-phase="error"] .label'); if(errorLabel) errorLabel.textContent = `Error: ${error.message.substring(0, 50)}...`;

    } finally {
        setTimeout(() => { progressContainer?.remove(); }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        window.log.handler(`[Trace] Finished attempt for endpoint key: ${endpointKey}`);
        setTimeout(() => requestAnimationFrame(window.updateDashboardUI), 100);
    }
}
window.handleTraceButton = handleTraceButton;


document.addEventListener('DOMContentLoaded', () => {
    if (!window.handlerTracer) window.handlerTracer = new HandlerTracer();
});
