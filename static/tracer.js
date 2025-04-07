/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-03
 */
class HandlerTracer {
    constructor() {
        this.domXssSinks = [
            { name: "eval", pattern: /\beval\s*\(/, severity: "Critical" },
            { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(/, severity: "Critical" },
            { name: "setTimeout with string", pattern: /setTimeout\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical" },
            { name: "setInterval with string", pattern: /setInterval\s*\(\s*("|'|`)(?![^"'`]*?function)/, severity: "Critical" },
            { name: "document.write", pattern: /document\.write\s*\(/, severity: "Critical" },
            { name: "document.writeln", pattern: /document\.writeln\s*\(/, severity: "Critical" },
            { name: "window.execScript", pattern: /window\.execScript\s*\(/, severity: "Critical" },
            { name: "innerHTML", pattern: /\.innerHTML\s*[\+\-]?=/, severity: "High" },
            { name: "outerHTML", pattern: /\.outerHTML\s*[\+\-]?=/, severity: "High" },
            { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/, severity: "High" },
            { name: "document.createElement('script')", pattern: /document\.createElement\s*\(\s*['"]script['"]/, severity: "High" },
            { name: "jQuery html", pattern: /\$\(.*\)\.html\s*\(|\$\.[a-zA-Z0-9_]+\.html\s*\(/, severity: "High" },
            { name: "createContextualFragment", pattern: /createContextualFragment\s*\(/, severity: "High" },
            { name: "DOMParser innerHTML", pattern: /DOMParser.*innerHTML/, severity: "High" },
            { name: "location assignment", pattern: /(?:window|document|self|top|parent)\.location\s*=|location\s*=/, severity: "High" },
            { name: "location.href", pattern: /\.location\.href\s*=/, severity: "High" },
            { name: "location.replace", pattern: /\.location\.replace\s*\(/, severity: "High" },
            { name: "location.assign", pattern: /\.location\.assign\s*\(/, severity: "High" },
            { name: "open", pattern: /\.open\s*\(/, severity: "Medium" },
            { name: "jQuery attr href", pattern: /\$.*?\.attr\s*\(\s*['"]href['"]/, severity: "Medium" },
            { name: "jQuery prop href", pattern: /\$.*?\.prop\s*\(\s*['"]href['"]/, severity: "Medium" },
            { name: "iframe.src", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High" },
            { name: "script.src", pattern: /\.src\s*=\s*(?!['"]https?:)/, severity: "High" },
            { name: "srcdoc", pattern: /\.srcdoc\s*=/, severity: "High" },
            { name: "document.domain", pattern: /document\.domain\s*=/, severity: "Medium" },
            { name: "document.cookie", pattern: /document\.cookie\s*=/, severity: "Medium" },
            { name: "document.implementation.createHTMLDocument", pattern: /document\.implementation\.createHTMLDocument/, severity: "Medium" },
            { name: "jQuery append", pattern: /\$.*?\.append\s*\(/, severity: "Medium" },
            { name: "jQuery prepend", pattern: /\$.*?\.prepend\s*\(/, severity: "Medium" },
            { name: "jQuery after", pattern: /\$.*?\.after\s*\(/, severity: "Medium" },
            { name: "jQuery before", pattern: /\$.*?\.before\s*\(/, severity: "Medium" },
            { name: "element.appendChild", pattern: /\.appendChild\s*\(/, severity: "Medium" },
            { name: "element.insertBefore", pattern: /\.insertBefore\s*\(/, severity: "Medium" },
            { name: "DOM setAttribute", pattern: /\.setAttribute\s*\(\s*['"](?:src|href|onclick|onerror|onload)['"]/, severity: "Medium" },
            { name: "template literal with expression", pattern: /`.*?\${(?![^{}]*?encodeURIComponent)(?![^{}]*?escape)/m, severity: "Medium" },
            { name: "Handlebars.compile", pattern: /Handlebars\.compile\s*\(/, severity: "Medium" },
            { name: "Vue $compile", pattern: /\$compile\s*\(/, severity: "Medium" },
            { name: "Web Worker", pattern: /new\s+Worker\s*\(/, severity: "Medium" },
            { name: "Blob URL creation", pattern: /URL\.createObjectURL\s*\(/, severity: "Medium" },
            { name: "Blob constructor", pattern: /new\s+Blob\s*\(\s*\[/, severity: "Medium" },
            { name: "WebSocket URL", pattern: /new\s+WebSocket\s*\((?![^)]*['"]wss?:\/\/)/, severity: "Medium" },
            { name: "JSON.parse", pattern: /JSON\.parse\s*\(/, severity: "Medium" },
            { name: "localStorage", pattern: /localStorage\.setItem\s*\(|localStorage\[\s*/, severity: "Low" },
            { name: "sessionStorage", pattern: /sessionStorage\.setItem\s*\(|sessionStorage\[\s*/, severity: "Low" },
            { name: "setAttribute(on*)", pattern: /\.setAttribute\s*\(\s*['"]on\w+['"]/, severity: "Medium" },
            { name: "element.on* assignment", pattern: /\.on(?:error|load|click|mouseover|keydown|submit)\s*=/, severity: "Medium" },
            { name: "addEventListener", pattern: /\.addEventListener\s*\(\s*['"](?!message)/, severity: "Low" },
            { name: "URL constructor", pattern: /new\s+URL\s*\(/, severity: "Low" },
            { name: "URL manipulation", pattern: /\.(?:searchParams|pathname|hash|search)\s*=/, severity: "Low" },
            { name: "window.history methods", pattern: /history\.(?:pushState|replaceState)\s*\(/, severity: "Low" },
            { name: "jQuery with selector", pattern: /\$\s*\(\s*[^"'`]*?(?!\$|jQuery)/, severity: "Medium" }
        ];

        this.securityChecks = [
            { name: "Missing origin check", pattern: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function|\([^)]*\)\s*=>|[a-zA-Z0-9_$]+)\s*(?:\([^)]*\))?\s*\{(?![^{}]*?(?:\.origin|origin\s*===|origin\s*==|origin\s*!==|origin\s*!=|allowedOrigins|checkOrigin|verifyOrigin))[^{}]*?\}/ms, severity: "High" },
            { name: "Loose origin check", pattern: /\.origin\.(?:indexOf|includes|startsWith|search|match)\s*\(/, severity: "Medium" },
            { name: "Weak origin comparison", pattern: /\.origin\s*(?:==|!=)\s*['"]/, severity: "Medium" },
            { name: "Wildcard origin in postMessage", pattern: /postMessage\s*\([^,]+,\s*['"][\*]['"]\s*\)/, severity: "Medium" },
            { name: "Using window.parent without origin check", pattern: /window\.parent\.postMessage\s*\((?![^)]*origin)/, severity: "Medium" },
            { name: "No message type check", pattern: /addEventListener\s*\(\s*['"]message['"](?![^{]*?\.(?:type|messageType|kind|action))/ms, severity: "Low" },
            //{ name: "No data validation", pattern: /\.data(?!\s*&&|\s*\?\?|\s*!=\s*null|\s*!==\s*undefined|\s*instanceof|\s*typeof)/, severity: "Medium" },
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
        if (typeof obj !== 'object' || obj === null) {
            return false;
        }
        let proto = Object.getPrototypeOf(obj);
        if (proto === null) {
            return true;
        }
        let baseProto = proto;
        while (Object.getPrototypeOf(baseProto) !== null) {
            baseProto = Object.getPrototypeOf(baseProto);
        }
        return proto === baseProto;
    }

    analyzeJsonStructures(messages) {
        const structureMap = new Map();
        if (!messages || messages.length === 0) {
            return [];
        }

        for (const message of messages) {
            if (!message) {
                continue;
            }
            try {
                let data = message.data;
                let dataType = typeof data;

                if (dataType === 'string') {
                    if ((data.startsWith('{') && data.endsWith('}')) || (data.startsWith('[') && data.endsWith(']'))) {
                        try {
                            data = JSON.parse(data);
                            dataType = typeof data;
                        } catch (e) {
                        }
                    }
                }

                if (this.isPlainObject(data)) {
                    const structure = this.getJsonStructure(data);
                    const hash = this.hashJsonStructure(structure);
                    if (!structureMap.has(hash)) {
                        const paths = this.identifyPathsToFuzz(structure);
                        structureMap.set(hash, {
                            structure: structure,
                            examples: [message],
                            pathsToFuzz: paths
                        });
                    } else {
                        const entry = structureMap.get(hash);
                        if (entry.examples.length < 3) {
                            entry.examples.push(message);
                        }
                    }
                } else {
                }
            } catch (error) {
            }
        }

        const structuresArray = Array.from(structureMap.values());
        return structuresArray;
    }

    getJsonStructure(obj, path = '') {
        if (obj === null || obj === undefined) {
            return { type: 'null', path };
        }
        const type = typeof obj;
        if (type !== 'object') {
            return { type: type, path };
        }
        if (Array.isArray(obj)) {
            const itemStructure = obj.length > 0 ? this.getJsonStructure(obj[0], `${path}[0]`) : { type: 'empty', path: `${path}[0]` };
            return { type: 'array', path, items: itemStructure };
        }

        const structure = { type: 'object', path, properties: {} };
        const keys = Object.keys(obj).sort();
        for (const key of keys) {
            const newPath = path ? `${path}.${key}` : key;
            structure.properties[key] = this.getJsonStructure(obj[key], newPath);
        }
        return structure;
    }

    hashJsonStructure(structure) {
        if (!structure || !structure.type) return 'invalid';
        if (structure.type === 'array') {
            return `array[${this.hashJsonStructure(structure.items)}]`;
        }
        if (structure.type !== 'object') return structure.type;

        const keys = Object.keys(structure.properties || {}).sort();
        return keys.map(k => `${k}:${this.hashJsonStructure(structure.properties[k])}`).join(',');
    }


    identifyPathsToFuzz(structure, currentPath = '', paths = []) {
        if (!structure) return paths;
        const nodePath = structure.path || currentPath;

        if (structure.type !== 'object' && structure.type !== 'array') {
            if (nodePath) paths.push({ path: nodePath, type: structure.type });
            return paths;
        }

        if (structure.type === 'array' && structure.items) {
            this.identifyPathsToFuzz(structure.items, '', paths);
        } else if (structure.type === 'object' && structure.properties) {
            for (const key of Object.keys(structure.properties)) {
                this.identifyPathsToFuzz(structure.properties[key], '', paths);
            }
        }
        const uniquePaths = [];
        const seenPaths = new Set();
        for(const p of paths) {
            if(p.path && !seenPaths.has(p.path)) {
                seenPaths.add(p.path);
                uniquePaths.push(p);
            }
        }
        return uniquePaths;
    }

    checkOriginValidation(handlerCode) {
        if (!handlerCode) return false;
        const originCheckPatterns = [
            /\.origin\s*===?\s*['"][^'"]*['"]/,
            /\.origin\s*!==?\s*['"][^'"]*['"]/,
            /\.origin\.(?:indexOf|includes|startsWith|endsWith|match)\s*\(/,
            /(?:checkOrigin|validateOrigin|isValidOrigin|verifyOrigin)\s*\(/i,
            /origin(?:Validation|Validator|Check|Checking)\s*\(/i,
            /(?:allowed|trusted|valid)Origin/i,
            /if\s*\([^)]*\.origin\s*[!=]==/,
            /\btrustedOrigins\b[.\[].*\.(?:includes|indexOf)\(/
        ];
        return originCheckPatterns.some(pattern => pattern.test(handlerCode));
    }

    analyzeHandlerForVulnerabilities(handlerCode) {
        const vulnerabilities = { sinks: [], securityIssues: [], dataFlows: [] };
        if (!handlerCode) return vulnerabilities;
        for (const sink of this.domXssSinks) {
            let match;
            const regex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || ''));
            while ((match = regex.exec(handlerCode)) !== null) {
                const context = this.extractContext(handlerCode, match.index, match[0].length);
                if (!vulnerabilities.sinks.some(s => s.type === sink.name && s.context === context)) {
                    vulnerabilities.sinks.push({
                        type: sink.name,
                        severity: sink.severity,
                        context: context
                    });
                }
            }
        }

        const hasMessageListener = /addEventListener\s*\(\s*['"]message['"]/i.test(handlerCode) ||
            /onmessage\s*=\s*function/i.test(handlerCode) ||
            /function\s*\([^)]*(?:event|e|msg|message|evt)[^)]*\)\s*{.*?\.data/ms.test(handlerCode);
        if (hasMessageListener && !this.checkOriginValidation(handlerCode)) {
            if (!vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) {
                vulnerabilities.securityIssues.push({
                    type: "Missing origin check", severity: "High",
                    context: "No explicit origin validation found within the analyzed handler code snippet."
                });
            }
        }

        for (const check of this.securityChecks) {
            if (check.name === "Missing origin check" && vulnerabilities.securityIssues.some(iss => iss.type === "Missing origin check")) continue;

            let match;
            try {
                const baseFlags = ['g', 'm', 's'];
                const originalFlags = check.pattern.flags || '';
                originalFlags.split('').forEach(flag => { if (flag !== 'g' && flag !== 'm' && flag !== 's' && !baseFlags.includes(flag)) baseFlags.push(flag); });
                const finalFlags = [...new Set(baseFlags)].join('');
                const regex = new RegExp(check.pattern.source, finalFlags);

                while ((match = regex.exec(handlerCode)) !== null) {
                    const context = this.extractContext(handlerCode, match.index, match[0].length);
                    if (!vulnerabilities.securityIssues.some(iss => iss.type === check.name && iss.context === context)) {
                        vulnerabilities.securityIssues.push({
                            type: check.name, severity: check.severity,
                            context: context
                        });
                    }
                    if (!regex.global) break;
                }
                if (regex.global) regex.lastIndex = 0;

            } catch (e) {
            }
        }

        vulnerabilities.dataFlows = this.analyzeDataFlowEnhanced(handlerCode);

        return vulnerabilities;
    }

    analyzeDataFlowEnhanced(handlerCode) {
        const dataFlows = [];
        if (!handlerCode || typeof handlerCode !== 'string') return dataFlows;
        const codeToAnalyze = handlerCode.length > 50000 ? handlerCode.substring(0, 50000) : handlerCode;
        const dataProperties = new Set();
        const assignmentPattern = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:event|e|msg|message|evt)\.data(?:\.([a-zA-Z0-9_$]+)|\[['"`](.+?)['"`]\])?/g;
        let assignmentMatch;
        while ((assignmentMatch = assignmentPattern.exec(codeToAnalyze)) !== null) {
            const varName = assignmentMatch[1];
            const directProp = assignmentMatch[2];
            const bracketProp = assignmentMatch[3];
            if (directProp) {
                dataProperties.add({ identifier: varName, sourcePath: `event.data.${directProp}` });
            } else if (bracketProp) {
                dataProperties.add({ identifier: varName, sourcePath: `event.data.${bracketProp}` });
            } else {
                dataProperties.add({ identifier: varName, sourcePath: 'event.data' });
            }
        }

        const directAccessPattern = /(?:event|e|msg|message|evt)\.data\.([a-zA-Z0-9_$]+(?:(?:\.[a-zA-Z0-9_$]+)|(?:\[.+?\]))?)/g;
        let directMatch;
        while ((directMatch = directAccessPattern.exec(codeToAnalyze)) !== null) {
            dataProperties.add({ identifier: `event.data.${directMatch[1]}`, sourcePath: `event.data.${directMatch[1]}` });
        }

        if (/(?<!\.)\b(?:event|e|msg|message|evt)\.data\b(?![\.\['])/.test(codeToAnalyze)) {
            dataProperties.add({ identifier: 'event.data', sourcePath: 'event.data'});
        }

        if (dataProperties.size === 0) {
            return dataFlows;
        }

        //log.debug(`[analyzeDataFlowEnhanced] Identified potential data sources:`, Array.from(dataProperties).map(p => p.identifier));
        for (const sink of this.domXssSinks) {
            const sinkRegex = new RegExp(sink.pattern.source, 'g' + (sink.pattern.flags || ''));
            let sinkMatch;
            while ((sinkMatch = sinkRegex.exec(codeToAnalyze)) !== null) {
                const sinkContext = this.extractContext(codeToAnalyze, sinkMatch.index, sinkMatch[0].length);

                for (const prop of dataProperties) {
                    const escapedIdentifier = prop.identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    const propUsagePattern = new RegExp(`\\b${escapedIdentifier}\\b`);

                    if (propUsagePattern.test(sinkContext)) {
                        const propertyName = prop.sourcePath.startsWith('event.data.') ? prop.sourcePath.substring('event.data.'.length) : prop.sourcePath;

                        if (!dataFlows.some(df => df.property === propertyName && df.sink === sink.name)) {
                            dataFlows.push({
                                property: propertyName,
                                sink: sink.name,
                                severity: sink.severity,
                                context: sinkContext
                            });
                        }
                    }
                }
            }
        }
        //log.debug(`[analyzeDataFlowEnhanced] Found ${dataFlows.length} potential data flows.`);
        return dataFlows;
    }

    extractContext(codeToSearchIn, index, length) {
        const before = Math.max(0, index - 50);
        const after = Math.min(codeToSearchIn.length, index + length + 50);
        let context = codeToSearchIn.substring(before, after);
        context = context.replace(/\n|\r/g, "↵").trim();
        if (context.length > 150) {
            context = context.substring(0, 70) + "..." + context.substring(context.length - 70);
        }
        return context;
    }


    generateFuzzingPayloads(uniqueStructures, vulnerabilities, originalMessages = []) {
        const generatedPayloads = [];
        const MAX_PAYLOADS = 10000;

        if (!Array.isArray(uniqueStructures)) {
            uniqueStructures = [];
        }
        const hasStringMessages = originalMessages.some(msg => typeof msg?.data === 'string');

        const allXssPayloads = window.FuzzingPayloads?.XSS || ['<script>alert("FP_XSS")</script>', '<img src=x onerror=alert("FP_XSS")>'];
        const xssPayloads = [...allXssPayloads].sort(() => 0.5 - Math.random()).slice(0, 100);

        let useSmartFuzzing = false;
        const directSinkPaths = new Set();

        if (vulnerabilities?.dataFlows) {
            vulnerabilities.dataFlows.forEach(flow => {
                if (flow.property && flow.property !== 'data') {
                    directSinkPaths.add(flow.property);
                }
            });
        }

        let validSmartPaths = new Set();
        if (directSinkPaths.size > 0 && uniqueStructures.length > 0) {
            const allStructurePaths = new Set();
            uniqueStructures.forEach(structure => {
                structure.pathsToFuzz?.forEach(p => allStructurePaths.add(p.path));
            });

            directSinkPaths.forEach(sinkPath => {
                if (allStructurePaths.has(sinkPath) || Array.from(allStructurePaths).some(p => p.startsWith(sinkPath + '.') || p.startsWith(sinkPath + '['))) {
                    validSmartPaths.add(sinkPath);
                }
            });

            if (validSmartPaths.size > 0) {
                useSmartFuzzing = true;
            }
        }

        if (uniqueStructures.length === 0 && !hasStringMessages && !useSmartFuzzing) {
            xssPayloads.slice(0, 10).forEach(payload => {
                if (generatedPayloads.length >= MAX_PAYLOADS) return;
                generatedPayloads.push({
                    type: 'dumb-generic',
                    payload: payload,
                    targetFlow: 'generic string',
                    description: 'Generic dumb payload (no structure/string input)'
                });
            });
            return generatedPayloads.slice(0, MAX_PAYLOADS);
        }

        structureLoop:
            for (const structure of uniqueStructures) {
                if (!structure.examples?.length) continue;
                let baseMsgData = structure.examples[0]?.data;
                if (baseMsgData === undefined) {
                    const { messageType, messageId, timestamp, origin, destinationUrl, ...actualData } = structure.examples[0] || {};
                    baseMsgData = Object.keys(actualData).length > 0 ? actualData : structure.examples[0];
                }
                if (typeof baseMsgData === 'string' && (baseMsgData.startsWith('{') || baseMsgData.startsWith('['))) {
                    try { baseMsgData = JSON.parse(baseMsgData); } catch (e) { continue; }
                }
                if (!this.isPlainObject(baseMsgData)) continue;

                if (useSmartFuzzing) {
                    pathLoop:
                        for (const smartPath of validSmartPaths) {
                            if (!structure.pathsToFuzz?.some(p => p.path === smartPath || p.path.startsWith(smartPath + '.') || p.path.startsWith(smartPath + '['))) {
                                continue;
                            }

                            const sinkPayloads = xssPayloads.slice(0, 50);
                            for (const payload of sinkPayloads) {
                                if (generatedPayloads.length >= MAX_PAYLOADS) break structureLoop;
                                try {
                                    const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                    this.setValueAtPath(modifiedMsg, smartPath, payload);
                                    generatedPayloads.push({
                                        type: 'smart',
                                        payload: modifiedMsg,
                                        targetPath: smartPath,
                                        description: `XSS targeting specific sink path: ${smartPath}`
                                    });
                                } catch (e) {
                                    log.debug(`Error generating smart payload for path ${smartPath}:`, e);
                                }
                            }
                        }
                } else {
                    const stringFields = structure.pathsToFuzz?.filter(p => p.type === 'string').map(p => p.path) || [];

                    if (stringFields.length > 0) {
                        const fieldsToTarget = stringFields.sort(() => 0.5 - Math.random()).slice(0, 5);
                        for (const field of fieldsToTarget) {
                            for (const payload of xssPayloads.slice(0, 20)) {
                                if (generatedPayloads.length >= MAX_PAYLOADS) break structureLoop;
                                try {
                                    const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                    this.setValueAtPath(modifiedMsg, field, payload);
                                    generatedPayloads.push({
                                        type: 'dumb-json',
                                        payload: modifiedMsg,
                                        targetFlow: `JSON Field: ${field}`,
                                        description: `Dumb XSS targeting string field ${field}`
                                    });
                                } catch (e) {
                                    log.debug(`Error generating dumb-json payload for field ${field}:`, e);
                                }
                            }
                        }
                    } else {
                        const commonFields = ['message', 'content', 'data', 'text', 'html', 'payload', 'value', 'url', 'src'];
                        for (const field of commonFields.slice(0,3)) {
                            for (const payload of xssPayloads.slice(0, 3)) {
                                if (generatedPayloads.length >= MAX_PAYLOADS) break structureLoop;
                                try{
                                    const modifiedMsg = JSON.parse(JSON.stringify(baseMsgData));
                                    modifiedMsg[field] = payload;
                                    generatedPayloads.push({
                                        type: 'dumb-json-fallback',
                                        payload: modifiedMsg,
                                        targetFlow: `JSON Common Field: ${field}`,
                                        description: `Dumb XSS targeting common field ${field}`
                                    });
                                } catch (e) {
                                    log.debug(`Error generating dumb-json-fallback payload for field ${field}:`, e);
                                }
                            }
                        }
                    }
                }
            }


        if (hasStringMessages && !useSmartFuzzing) {
            const originalStringMessagesData = originalMessages.filter(msg => typeof msg?.data === 'string').map(msg => msg.data);
            const uniqueStrings = [...new Set(originalStringMessagesData)].slice(0, 5);

            for (const originalString of uniqueStrings) {
                const looksLikeHtml = originalString.includes('<') && originalString.includes('>');
                const payloadsForString = xssPayloads.slice(0, looksLikeHtml ? 5 : 15);

                for (const payload of payloadsForString) {
                    if (generatedPayloads.length >= MAX_PAYLOADS) break;
                    generatedPayloads.push({ type: 'dumb-string-replace', payload: payload, targetFlow: 'string replacement', description: `Dumb XSS replacing original string`, original: originalString });
                    if (!looksLikeHtml) {
                        if (generatedPayloads.length < MAX_PAYLOADS) {
                            generatedPayloads.push({ type: 'dumb-string-append', payload: originalString + payload, targetFlow: 'string append', description: `Dumb XSS appending to original string`, original: originalString });
                        }
                        if (generatedPayloads.length < MAX_PAYLOADS) {
                            generatedPayloads.push({ type: 'dumb-string-prepend', payload: payload + originalString, targetFlow: 'string prepend', description: `Dumb XSS prepending to original string`, original: originalString });
                        }
                    }
                }
            }
        }

        log.debug(`[generateFuzzingPayloads] Final generated payload count: ${generatedPayloads.length}`);
        return generatedPayloads.slice(0, MAX_PAYLOADS);
    }

    setValueAtPath(obj, path, value) {
        if (!obj || typeof obj !== 'object' || !path) {
            if (typeof obj === 'string') return value;
            return;
        }
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
        let current = obj;

        for (let i = 0; i < parts.length - 1; i++) {
            let part = parts[i];
            if (part.startsWith('[')) {
                part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
            }

            const nextPartStr = parts[i + 1];
            let nextPartNormalized = nextPartStr;
            if (nextPartNormalized.startsWith('[')) {
                nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, '');
            }
            const isNextPartIndex = /^\d+$/.test(nextPartNormalized);
            if (current[part] === undefined || current[part] === null) {
                current[part] = isNextPartIndex ? [] : {};
            }

            current = current[part];
            if (typeof current !== 'object' || current === null) {
                return;
            }
        }

        let lastPart = parts[parts.length - 1];
        if (lastPart.startsWith('[')) {
            lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
        }

        if (typeof current === 'object' && current !== null) {
            const isIndex = /^\d+$/.test(lastPart);
            if (Array.isArray(current) && isIndex) {
                current[parseInt(lastPart)] = value;
            } else if (!Array.isArray(current)) {
                current[lastPart] = value;
            } else {
            }
        } else {
        }
    }


    calculateRiskScore(analysisResults) {
        let penaltyScore = 0;
        const MAX_PENALTY = 100;

        if (!analysisResults) return 100;

        const sinks = analysisResults.sinks || [];
        const issues = analysisResults.securityIssues || [];
        const dataFlows = analysisResults.dataFlows || [];

        let hasCriticalSink = false;
        let hasHighSink = false;

        sinks.forEach(sink => {
            switch (sink.severity?.toLowerCase()) {
                case 'critical':
                    hasCriticalSink = true;
                    penaltyScore += 35;
                    break;
                case 'high':
                    hasHighSink = true;
                    penaltyScore += 20;
                    break;
                case 'medium':
                    penaltyScore += 8;
                    break;
                case 'low':
                    penaltyScore += 2;
                    break;
                default:
                    penaltyScore += 1;
                    break;
            }
        });

        let hasHighIssue = false;
        let mediumIssueCount = 0;

        issues.forEach(issue => {
            switch (issue.severity?.toLowerCase()) {
                case 'high':
                    hasHighIssue = true;
                    penaltyScore += 15;
                    break;
                case 'medium':
                    mediumIssueCount++;
                    penaltyScore += 5 + Math.min(mediumIssueCount, 4);
                    break;
                case 'low':
                    penaltyScore += 3;
                    break;
                default:
                    penaltyScore += 1;
                    break;
            }
        });

        if (dataFlows.length > 0) {
            let flowPenalty = 0;
            dataFlows.forEach(flow => {
                switch (flow.severity?.toLowerCase()) {
                    case 'critical': flowPenalty += 5; break;
                    case 'high':     flowPenalty += 3; break;
                    case 'medium':   flowPenalty += 1; break;
                    default:         flowPenalty += 0.5; break;
                }
            });
            penaltyScore += Math.min(flowPenalty, 25);
        }

        const hasAnyOriginCheck = !issues.some(issue =>
            issue.type.toLowerCase().includes('origin check') ||
            issue.type.toLowerCase().includes('missing origin')
        );

        if (hasAnyOriginCheck) {
        }

        if (issues.some(issue =>
            issue.type.toLowerCase().includes('window.parent') &&
            issue.type.toLowerCase().includes('origin check')
        )) {
            penaltyScore += 10;
        }

        penaltyScore = Math.min(penaltyScore, MAX_PENALTY);

        let finalScore = Math.max(0, 100 - penaltyScore);
        if (hasCriticalSink) {
        } else if (hasHighSink && hasHighIssue) {
        } else if (hasHighSink || hasHighIssue) {
        } else if (mediumIssueCount >= 4) {
        }

        return Math.round(finalScore);
    }
}

if (typeof window !== 'undefined') {
    window.HandlerTracer = HandlerTracer;
}



const traceReportStyles = `
/* Base styles for the report panel */
.trace-results-panel {
    /* Styles for the panel itself */
}
.trace-panel-backdrop {
    /* Styles for the backdrop */
}
.trace-panel-header {
    /* Styles for the header */
}
.trace-panel-close {
    /* Styles for the close button */
}
.trace-results-content {
    /* Styles for the main content area */
}

/* Section styling */
.report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; }
.report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); }
.report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; }

/* Summary Section */
.report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; }
.security-score-container { display: flex; justify-content: center; }
.security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); }
.security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; }
.security-score div { position: relative; z-index: 2; }
.security-score-value { font-size: 28px; line-height: 1; }
.security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; }
/* Color indicators (could be applied dynamically) */
.security-score.critical { border-color: #e74c3c; }
.security-score.high { border-color: #e67e22; }
.security-score.medium { border-color: #f39c12; }
.security-score.low { border-color: #3498db; }
.security-score.negligible { border-color: #2ecc71; }

.summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; }
.metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; }
.metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; }
.metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; }

/* Recommendations */
.recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; }
.recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; }

/* Code Blocks */
.report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; }
.report-code-block pre { margin: 0; }
.report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; }

/* Handler Section */
.report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; }
details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; }
summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; }
summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); }
details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; }
.toggle-icon { font-size: 1.2em; transition: transform 0.2s; }
details[open] .toggle-icon { transform: rotate(90deg); }
.report-details > div { padding: 15px; } /* Padding for content inside details */

/* Tables */
.report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; }
.report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; }
.report-table th { background-color: #2c313a; font-weight: bold; color: #fff; }
.report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px;}
.report-table .context-snippet { max-width: 400px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; }

/* Severity highlighting in tables */
.severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
.severity-critical { background-color: #e74c3c; color: white; }
.severity-high { background-color: #e67e22; color: white; }
.severity-medium { background-color: #f39c12; color: #333; }
.severity-low { background-color: #3498db; color: white; }
.severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); }
.severity-row-high td { background-color: rgba(230, 126, 34, 0.15); }
.severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); }
.severity-row-low td { background-color: rgba(52, 152, 219, 0.1); }

/* Findings & Data Flow Sections */
.no-findings-text { color: #777; font-style: italic; padding: 10px 0; }
.dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; } /* Highlight source property */

/* Payload & Structure Lists */
.report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; /* Space for scrollbar */ }
.payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; }
.payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; }
.payload-header strong { color: #fff; }
.payload-meta { color: #8be9fd; margin: 0 5px; }
.payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; }
.structure-content { padding: 15px; }
.structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; }
.structure-content strong { color: #00e1ff; }
.structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; }

/* Show More Button */
.show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; }
.show-more-btn:hover { background-color: #4a5058; color: #fff; }

/* General Controls (example) */
.control-button { /* Base styles */ }
.secondary-button { /* Styles for secondary actions */ }

/* Error Message */
.error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; }
`;

const progressStyles = `
.trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; }
.trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.phase-list { display: flex; flex-direction: column; gap: 10px; }
.phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; }
.phase .emoji { font-size: 20px; line-height: 1; }
.phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; }
/* Active Phase */
.phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; }
.phase.active .label { color: #fff; font-weight: 600; }
.phase.active .emoji { animation: spin 1s linear infinite; }
/* Completed Phase */
.phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; }
.phase.completed .label { color: #50fa7b; }
.phase.completed .emoji::before { content: '✅'; }
/* Error Phase */
.phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; }
.phase.error .label { color: #ff5555; font-weight: 600; }
.phase.error .emoji::before { content: '❌'; }
/* Hide final states initially */
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
    log.debug(`Trace: Starting for original key ${endpointKey}`);

    if (!endpointKey) {
        log.error("Trace: Cannot determine endpoint key", originalFullEndpoint);
        updateTraceButton(traceButton, 'error');
        return;
    }

    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) {
        log.debug(`Trace already in progress for key: ${endpointKey}`);
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

    try {
        updatePhase('collection');
        if (!window.handlerTracer) window.handlerTracer = new HandlerTracer();

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;

        const analysisStorageKey = getStorageKeyForUrl(endpointUrlUsedForAnalysis);

        log.debug(`[Trace] Effective endpoint URL for analysis/saving report: ${endpointUrlUsedForAnalysis}`);
        log.debug(`[Trace] Storage key derived from analysis URL (for handler): ${analysisStorageKey}`);

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;

        if (!handlerCode) throw new Error(`No handler code found in storage (${bestHandlerStorageKey}). Run Play.`);

        const relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
        log.debug(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));
        const vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;

        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));
        const uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));
        const payloads = window.handlerTracer.generateFuzzingPayloads(uniqueStructures, vulnAnalysis, relevantMessages);

        updatePhase('saving');
        const securityScore = window.handlerTracer.calculateRiskScore(vulnAnalysis);

        const report = {
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
                analyzedHandler: {
                    code: handlerCode,
                    category: bestHandler?.category,
                    score: bestHandler?.score,
                    context: bestHandler?.context
                },
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

        if (reportStorageKey !== endpointUrlUsedForAnalysis) {
            await window.traceReportStorage.saveTraceReport(endpointUrlUsedForAnalysis, report);
            await window.traceReportStorage.saveReportPayloads(endpointUrlUsedForAnalysis, payloads);
        }

        if (!reportSaved || !payloadsSaved) throw new Error("Failed to save trace report or payloads.");
        log.success(`Trace report & ${payloads.length} payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true,
                criticalSinks: hasCriticalSinks,
                analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey
            }
        });

        log.debug(`Saved trace status for UI key ${traceInfoKey}: success=true, criticalSinks=${hasCriticalSinks}, analyzedUrl=${endpointUrlUsedForAnalysis}, storageKey=${analysisStorageKey}`);

        updateTraceButton(traceButton, 'success');
        if (playButton) updateButton(playButton, 'launch', {hasCriticalSinks: hasCriticalSinks, showEmoji: true });
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
            await chrome.storage.local.set({
                [traceInfoKey]: {
                    success: false,
                    criticalSinks: false
                }
            });
        } catch(e) {}

        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
    } finally {
        setTimeout(() => {
            if (progressContainer?.parentNode) progressContainer.parentNode.removeChild(progressContainer);
        }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        log.debug(`[Trace] Finished trace attempt for key ${endpointKey}`);
        updateDashboardUI()
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
