(function(global) {
    const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    const ADMIN_JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc0MjczNjM4NSwiZXhwIjoxNzQyNzM5OTg1fQ.vV4TGSb2INqsYWvUZMs3Y_HnUAXf1hnPw82atOhl0DE";

    class ImprovedMessageFuzzer {
        constructor() {
            this.payloads = [];
            this.messageStructures = [];
            this.vulnerablePaths = [];
            this.maxPayloadsPerField = 30;
            this.callbackUrl = null;
            this.fuzzerConfig = {
                enableSmartFuzzing: true,
                enableDumbFuzzing: true,
                enablePrototypePollution: true,
                enableOriginFuzzing: true,
                enableCallbackFuzzing: true,
                skipCriticalFields: false, // Changed to false to not skip any fields
                maxTotalPayloads: 2000,    // Increased from 1000
                randomizePayloadSelection: true,
                dumbFuzzingPayloadsPerField: 30,
                payloadDistribution: {
                    xss: 0.6,
                    callback: 0.2,
                    pollution: 0.1,
                    origin: 0.1
                }
            };
        }

        isPlainObject(obj) {
            if (typeof obj !== 'object' || obj === null) return false;
            let proto = Object.getPrototypeOf(obj);
            if (proto === null) return true;
            let baseProto = proto;
            while (Object.getPrototypeOf(baseProto) !== null) {
                baseProto = Object.getPrototypeOf(baseProto);
            }
            return proto === baseProto;
        }

        initialize(messages, handlerCode, sinks = [], targetUrl = null, callbackUrl = null) {
            this.messages = Array.isArray(messages) ? messages : [];
            this.handlerCode = handlerCode || '';
            this.targetUrl = targetUrl;
            this.callbackUrl = callbackUrl;
            this.messageStructures = [];

            if (this.messages && this.messages.length > 0) {
                this.messages.forEach((msg, idx) => {
                    let dataType = typeof msg.data !== 'undefined' ? typeof msg.data : typeof msg;
                    // console.log(`[Fuzzer] Message ${idx+1} data type: ${dataType}`);
                    let data = msg.data !== undefined ? msg.data : msg;
                    if (typeof data === 'object' && data !== null) {
                        // console.log(`[Fuzzer] Message ${idx+1} field count: ${Object.keys(data).length}`);
                    }
                });
            }

            this.vulnerablePaths = (sinks || []).map(sink => {
                let targetProperty = "message";
                if (sink.property) {
                    targetProperty = sink.property;
                } else if (sink.context && typeof sink.context === 'string') {
                    const contextMatch = sink.context.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/);
                    if (contextMatch && contextMatch[1]) {
                        targetProperty = contextMatch[1];
                    }
                }
                return {
                    path: targetProperty,
                    fullPath: `event.data.${targetProperty}`,
                    sinkType: sink.type || sink.name || "unknown",
                    severity: sink.severity?.toLowerCase() || "high",
                };
            }).filter(p => p.path);

            if (sinks && sinks.length > 0) {
                console.log(`[Fuzzer Initialize] Created ${this.vulnerablePaths.length} vulnerable paths from ${sinks.length} provided sinks.`);
            } else {
                console.log(`[Fuzzer Initialize] No sinks provided, vulnerablePaths will be empty.`);
            }

            console.log("[Fuzzer Initialize] Processing messages for structures:", this.messages?.length || 0);
            if (this.messages && this.messages.length > 0) {
                for (const message of this.messages) {
                    let msgData = message.data !== undefined ? message.data : message;
                    let dataType = typeof msgData;

                    if (dataType === 'string') {
                        if (msgData.startsWith('{') && msgData.endsWith('}') || msgData.startsWith('[') && msgData.endsWith(']')) {
                            try {
                                msgData = JSON.parse(msgData);
                                dataType = typeof msgData;
                            } catch (e) { /* Treat as raw string */ }
                        }
                    }

                    if (this.isPlainObject(msgData)) {
                        this.messageStructures.push({
                            type: 'object',
                            original: JSON.parse(JSON.stringify(msgData)),
                            fields: this.extractAllFields(msgData),
                            fieldTypes: this.getFieldTypes(msgData)
                        });
                    } else if (dataType === 'string') {
                        this.messageStructures.push({ type: 'raw_string', original: msgData });
                    } else {
                        console.log(`[Fuzzer Initialize] Skipping structure creation for message data (Type: ${dataType}).`);
                    }
                }
                console.log(`[Fuzzer Initialize] Created ${this.messageStructures.length} structures from ${this.messages.length} processed messages.`);
            } else {
                console.log("[Fuzzer Initialize] No messages provided to analyze for structures.");
            }

            if (this.messageStructures.length === 0 && this.vulnerablePaths.length > 0) {
                const defaultObj = { type: 'default_generated' };
                const firstVulnPath = this.vulnerablePaths[0]?.path || "message";
                defaultObj[firstVulnPath] = `Default Content for ${firstVulnPath}`;
                this.messageStructures.push({
                    type: 'object',
                    original: defaultObj,
                    fields: this.extractAllFields(defaultObj),
                    fieldTypes: this.getFieldTypes(defaultObj)
                });
                console.log(`[Fuzzer Initialize] Created default message structure as fallback:`, defaultObj);
            } else if (this.messageStructures.length === 0) {
                console.warn('[Fuzzer Initialize] No message structures found or generated.');
            }
            if (this.vulnerablePaths.length === 0) {
                console.log('[Fuzzer Initialize] No vulnerable paths identified - DUMB strategy will be used if generation fallback occurs.');
            }
            if (callbackUrl) {
                this.callbackUrl = callbackUrl;
            }
            return this;
        }

        initializeWithConfig(config = {}) {
            this.fuzzerConfig = {
                ...this.fuzzerConfig,
                ...config
            };

            if (config.maxPayloadsPerField) {
                this.maxPayloadsPerField = config.maxPayloadsPerField;
            }

            if (config.forceMinimumPayloads && typeof config.forceMinimumPayloads === 'number') {
                this.fuzzerConfig.forceMinimumPayloads = config.forceMinimumPayloads;
            }
            return this;
        }

        getFieldTypes(obj, prefix = '') {
            const result = {};
            if (!this.isPlainObject(obj)) return result;
            for (const key in obj) {
                if (!obj.hasOwnProperty(key)) continue;
                const fieldPath = prefix ? `${prefix}.${key}` : key;
                result[fieldPath] = typeof obj[key];
                if (this.isPlainObject(obj[key])) {
                    Object.assign(result, this.getFieldTypes(obj[key], fieldPath));
                }
            }
            return result;
        }

        extractAllFields(obj, prefix = '') {
            const fields = [];
            if (!this.isPlainObject(obj)) return fields;
            for (const key in obj) {
                if (!obj.hasOwnProperty(key)) continue;
                const fieldPath = prefix ? `${prefix}.${key}` : key;
                fields.push(fieldPath);
                if (this.isPlainObject(obj[key])) {
                    fields.push(...this.extractAllFields(obj[key], fieldPath));
                }
            }
            return fields;
        }

        setNestedValue(obj, path, value) {
            if (!obj || typeof obj !== 'object' || !path) {
                if (typeof obj === 'string') { return value; }
                console.error("[setNestedValue] Invalid input object or path.");
                return;
            }
            const parts = path.match(/[^.[\]]+/g) || [];
            let current = obj;
            for (let i = 0; i < parts.length - 1; i++) {
                const part = parts[i];
                const nextPart = parts[i + 1];
                const isNextPartIndex = /^\d+$/.test(nextPart);
                if (current[part] === undefined || current[part] === null) {
                    current[part] = isNextPartIndex ? [] : {};
                }
                current = current[part];
                if (typeof current !== 'object' || current === null) {
                    console.warn(`[setNestedValue] Path traversal stopped at non-object/array part: ${part}`);
                    return;
                }
            }
            const lastPart = parts[parts.length - 1];
            if (typeof current === 'object' && current !== null) {
                if (Array.isArray(current) && /^\d+$/.test(lastPart)) {
                    current[parseInt(lastPart)] = value;
                } else {
                    current[lastPart] = value;
                }
            } else {
                console.warn(`[setNestedValue] Cannot set value on non-object/array at final path part: ${lastPart}`);
            }
        }

        runPayloadGeneration() {
            console.log("[Fuzzer] Starting payload generation sequence...");
            this.payloads = [];

            if (!window.FuzzingPayloads) {
                console.error("[Fuzzer runPayloadGeneration] window.FuzzingPayloads not available. Cannot generate.");
                return [];
            }

            // Check for XSS payloads in the new simplified structure
            const allXssPayloads = window.FuzzingPayloads.XSS || [];

            console.log(`[Fuzzer] Total XSS payloads available: ${allXssPayloads.length}`);

            // Don't limit these - use all payloads
            const payloadList = allXssPayloads;

            for (const structure of this.messageStructures) {
                if (!structure || !structure.original) continue;

                if (structure.type === 'object') {
                    if (this.fuzzerConfig.enableSmartFuzzing && this.vulnerablePaths && this.vulnerablePaths.length > 0) {
                        this.generateSmartObjectPayloads(structure, this.vulnerablePaths, payloadList);
                    }

                    if (this.fuzzerConfig.enableDumbFuzzing) {
                        this.generateDumbObjectPayloads(structure, payloadList);
                    }

                    if (this.fuzzerConfig.enablePrototypePollution) {
                        this.generatePrototypePollutionPayloads(structure);
                    }
                } else if (structure.type === 'raw_string') {
                    this.generateRawStringPayloads(structure.original, payloadList);
                }
            }

            if (this.fuzzerConfig.enableCallbackFuzzing && this.callbackUrl) {
                this.generateCallbackPayloads();
            }

            if (this.fuzzerConfig.enableOriginFuzzing) {
                this.generateOriginFuzzingPayloads();
            }

            // Check for minimum payload requirement
            if (this.fuzzerConfig.forceMinimumPayloads &&
                typeof this.fuzzerConfig.forceMinimumPayloads === 'number' &&
                this.payloads.length < this.fuzzerConfig.forceMinimumPayloads) {

                console.log(`[Fuzzer] Generated ${this.payloads.length} payloads, below minimum ${this.fuzzerConfig.forceMinimumPayloads}. Generating more...`);

                // Add additional payloads until we reach the minimum
                this.generateAdditionalPayloads(
                    this.fuzzerConfig.forceMinimumPayloads - this.payloads.length,
                    payloadList
                );
            }

            // Log detailed payload stats
            console.log(`[Fuzzer] DETAILED PAYLOAD STATS:`);
            const typeStats = {};
            this.payloads.forEach(p => {
                const type = p.type || 'unknown';
                typeStats[type] = (typeStats[type] || 0) + 1;
            });

            Object.entries(typeStats).forEach(([type, count]) => {
                console.log(`[Fuzzer]   - ${type}: ${count} payloads`);
            });

            console.log(`[Fuzzer] Completed payload generation sequence. Total generated payloads: ${this.payloads.length}`);
            return this.payloads;
        }

        generateSmartObjectPayloads(structure, vulnerablePaths, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original || !vulnerablePaths || vulnerablePaths.length === 0) return;
            if (!payloadList || payloadList.length === 0) {
                console.error("[Fuzzer] Payloads missing for Smart generation.");
                return;
            }

            const baseMessage = JSON.parse(JSON.stringify(structure.original));
            let count = 0;

            // Calculate maximum payloads per sink based on config
            const maxPayloadsPerSink = Math.min(
                this.maxPayloadsPerField,
                Math.floor(this.fuzzerConfig.maxTotalPayloads / (vulnerablePaths.length || 1))
            );

            console.log(`[Fuzzer] Smart fuzzing ${vulnerablePaths.length} paths with up to ${maxPayloadsPerSink} payloads each`);

            for (const vulnPath of vulnerablePaths) {
                let targetPath = vulnPath.path;
                if (targetPath === 'data' && vulnPath.fullPath && vulnPath.fullPath !== 'event.data') {
                    const dataPathMatch = vulnPath.fullPath.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/);
                    if (dataPathMatch && dataPathMatch[1]) {
                        targetPath = dataPathMatch[1];
                    }
                }

                if (!targetPath || targetPath === '') {
                    const stringFields = Object.entries(structure.fieldTypes || {})
                        .filter(([, type]) => type === 'string')
                        .map(([field]) => field);
                    const suspiciousFields = stringFields.filter(field => /html|script|content|message|url|src/i.test(field));
                    targetPath = suspiciousFields[0] || stringFields[0];
                    if (!targetPath) {
                        console.log(`[Fuzzer] SMART: No target path found for sink ${vulnPath.sinkType}, skipping.`);
                        continue;
                    }
                }

                let relevantPayloads = [];
                const sinkTypeLower = vulnPath.sinkType?.toLowerCase() || '';

                // Check if we have sink-specific payloads
                if (window.FuzzingPayloads.SINK_SPECIFIC) {
                    if (sinkTypeLower.includes('eval'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.eval || [];
                    else if (sinkTypeLower.includes('innerhtml'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.innerHTML || [];
                    else if (sinkTypeLower.includes('write'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.document_write || [];
                    else if (sinkTypeLower.includes('settimeout'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setTimeout || [];
                    else if (sinkTypeLower.includes('setinterval'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setInterval || [];
                    else if (sinkTypeLower.includes('location') || sinkTypeLower.includes('href'))
                        relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.location_href || [];
                }

                // If no sink-specific payloads or they're empty, use the generic XSS payloads
                if (!relevantPayloads.length) {
                    relevantPayloads = payloadList;
                }

                // Randomize and select payloads
                if (this.fuzzerConfig.randomizePayloadSelection) {
                    relevantPayloads = [...relevantPayloads].sort(() => 0.5 - Math.random());
                }

                const payloadsToUse = relevantPayloads.slice(0, maxPayloadsPerSink);

                for (const payload of payloadsToUse) {
                    try {
                        if (count >= this.fuzzerConfig.maxTotalPayloads) {
                            console.log(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`);
                            return;
                        }

                        const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                        this.setNestedValue(modifiedMessage, targetPath, payload);
                        this.payloads.push({
                            type: 'smart',
                            sinkType: vulnPath.sinkType,
                            targetPath: targetPath,
                            fullPath: vulnPath.fullPath,
                            payload: modifiedMessage,
                            severity: vulnPath.severity || (vulnPath.sinkType === 'eval' ? 'critical' : 'high')
                        });
                        count++;
                    } catch (error) {
                        console.error(`[Fuzzer] Error creating SMART payload for path ${targetPath}:`, error);
                    }
                }
            }
        }

        generateDumbObjectPayloads(structure, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original) return;
            if (!payloadList || payloadList.length === 0) return;
            if (!this.fuzzerConfig.enableDumbFuzzing) return;

            const baseMessage = JSON.parse(JSON.stringify(structure.original));
            const fields = this.extractAllFields(baseMessage);

            // Filter for string fields and prioritize suspicious ones
            const stringFields = fields.filter(field => {
                if (this.fuzzerConfig.skipCriticalFields && this.isCriticalField(field)) return false;

                // Navigate to this field to check its type
                let currentObj = baseMessage;
                const parts = field.split('.');
                for (let i = 0; i < parts.length - 1; i++) {
                    if (!currentObj[parts[i]]) return false;
                    currentObj = currentObj[parts[i]];
                }

                const lastPart = parts[parts.length - 1];
                return typeof currentObj[lastPart] === 'string' ||
                    currentObj[lastPart] === null ||
                    currentObj[lastPart] === undefined;
            });

            // Suspicious patterns for prioritizing fields
            const suspiciousPatterns = [
                /html/i, /script/i, /content/i, /message/i, /url/i, /src/i,
                /href/i, /code/i, /exec/i, /eval/i, /callback/i, /function/i,
                /source/i, /target/i, /payload/i, /template/i, /markup/i,
                /auth/i, /token/i, /key/i, /secret/i, /pass/i, /user/i, /admin/i
            ];

            const prioritizedFields = stringFields.sort((a, b) => {
                const aIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(a));
                const bIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(b));

                if (aIsSuspicious && !bIsSuspicious) return -1;
                if (!aIsSuspicious && bIsSuspicious) return 1;
                return 0;
            });

            // Determine how many payloads per field based on field count
            const fieldsToFuzz = Math.min(prioritizedFields.length, 50); // Increased from 20
            const payloadsPerField = Math.min(
                this.fuzzerConfig.dumbFuzzingPayloadsPerField,
                Math.floor(this.fuzzerConfig.maxTotalPayloads / (fieldsToFuzz || 1))
            );

            console.log(`[Fuzzer] Dumb fuzzing ${fieldsToFuzz} fields with ${payloadsPerField} payloads each`);

            let totalPayloads = 0;
            for (let i = 0; i < prioritizedFields.length && i < fieldsToFuzz; i++) {
                const field = prioritizedFields[i];

                let selectedPayloads = payloadList;
                if (this.fuzzerConfig.randomizePayloadSelection) {
                    selectedPayloads = [...payloadList]
                        .sort(() => 0.5 - Math.random())
                        .slice(0, payloadsPerField);
                } else {
                    selectedPayloads = payloadList.slice(0, payloadsPerField);
                }

                for (const payload of selectedPayloads) {
                    try {
                        if (totalPayloads >= this.fuzzerConfig.maxTotalPayloads) {
                            console.warn(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`);
                            return;
                        }

                        const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                        this.setNestedValue(modifiedMessage, field, payload);
                        this.payloads.push({
                            type: 'dumb',
                            field: field,
                            targetPath: field,
                            payload: modifiedMessage,
                            severity: 'medium'
                        });
                        totalPayloads++;
                    } catch (error) {
                        console.error(`[Fuzzer] Error creating DUMB payload for field ${field}:`, error);
                    }
                }
            }
        }

        generateRawStringPayloads(original, payloadList) {
            if (typeof original !== 'string') return;
            if (!payloadList || payloadList.length === 0) {
                console.error("[Fuzzer] Payloads missing for Raw String generation.");
                return;
            }

            const maxPayloadsForRawString = Math.min(this.maxPayloadsPerField, 30);
            let count = 0;

            // Select a subset of payloads for raw string handling
            const selectedPayloads = this.fuzzerConfig.randomizePayloadSelection ?
                [...payloadList].sort(() => 0.5 - Math.random()).slice(0, maxPayloadsForRawString) :
                payloadList.slice(0, maxPayloadsForRawString);

            for (const payload of selectedPayloads) {
                if (count >= this.fuzzerConfig.maxTotalPayloads) {
                    console.log(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`);
                    return;
                }

                this.payloads.push({
                    type: 'raw_string_replace',
                    payload: payload,
                    severity: 'high',
                    isRawString: true,
                    original: original
                });
                count++;

                if (count >= this.fuzzerConfig.maxTotalPayloads) return;

                const injectionVariants = [`${payload}${original}`, `${original}${payload}`];
                if (original.length > 10) {
                    const mid = Math.floor(original.length / 2);
                    injectionVariants.push(original.substring(0, mid) + payload + original.substring(mid));
                }

                for (const injectedString of injectionVariants) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) return;

                    this.payloads.push({
                        type: `raw_string_inject`,
                        payload: injectedString,
                        severity: 'high',
                        isRawString: true,
                        original: original
                    });
                    count++;
                }
            }
        }

        generateCallbackPayloads() {
            if (!this.callbackUrl) {
                return;
            }
            if (!window.FuzzingPayloads?.CALLBACK_URL) {
                console.error("[Fuzzer] Callback payload templates missing.");
                return;
            }

            const callbackTemplates = window.FuzzingPayloads.CALLBACK_URL;
            let count = 0;

            for (const template of callbackTemplates) {
                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                    return;
                }

                const processedPayloadStr = template.replace(/%%CALLBACK_URL%%/g, this.callbackUrl);
                for (const structure of this.messageStructures) {
                    if (structure.type === 'object' && structure.original) {
                        const pathsToTarget = this.vulnerablePaths.length > 0 ?
                            this.vulnerablePaths :
                            Object.entries(structure.fieldTypes || {})
                                .filter(([, type]) => type === 'string')
                                .slice(0, 5)
                                .map(([path]) => ({ path: path, sinkType: 'generic_string', severity: 'medium' }));

                        if (pathsToTarget.length === 0 && structure.fields?.length > 0) {
                            pathsToTarget.push({ path: structure.fields[0], sinkType: 'first_field', severity: 'low'});
                        }

                        for (const vulnPath of pathsToTarget) {
                            if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;

                            try {
                                const targetPath = vulnPath.path;
                                if (!targetPath) continue;
                                const modifiedMessage = JSON.parse(JSON.stringify(structure.original));
                                this.setNestedValue(modifiedMessage, targetPath, processedPayloadStr);
                                this.payloads.push({
                                    type: 'callback_url_object',
                                    sinkType: vulnPath.sinkType,
                                    targetPath: targetPath,
                                    fullPath: vulnPath.fullPath,
                                    payload: modifiedMessage,
                                    severity: 'critical'
                                });
                                count++;
                            } catch (error) {
                                console.error(`[ImprovedFuzzer CB] Error creating object payload for path ${vulnPath.path}:`, error);
                            }
                        }
                    } else if (structure.type === 'raw_string') {
                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;

                        this.payloads.push({
                            type: 'callback_url_raw',
                            payload: processedPayloadStr,
                            severity: 'critical',
                            isRawString: true,
                            original: structure.original
                        });
                        count++;

                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;

                        const combined = `${structure.original || ''}${processedPayloadStr}`;
                        this.payloads.push({
                            type: 'callback_url_combined',
                            payload: combined,
                            severity: 'critical',
                            isRawString: true,
                            original: structure.original
                        });
                        count++;
                    }
                }
            }
        }

        generateOriginFuzzingPayloads() {
            for (const structure of this.messageStructures) {
                if (structure.type !== 'object' || !structure.original) continue;

                const baseMessage = JSON.parse(JSON.stringify(structure.original));

                // Create a new origin field if it doesn't exist
                if (!baseMessage.origin) {
                    baseMessage.origin = "https://malicious-origin.com";
                    this.payloads.push({
                        type: 'origin_injection',
                        targetPath: 'origin',
                        payload: baseMessage,
                        severity: 'medium'
                    });
                }

                // Modify an existing origin field if it exists
                const fields = this.extractAllFields(baseMessage);
                const originFields = fields.filter(f => /origin|source|from|sender/i.test(f));

                for (const field of originFields) {
                    try {
                        const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                        this.setNestedValue(modifiedMessage, field, "https://malicious-origin.com");
                        this.payloads.push({
                            type: 'origin_spoofing',
                            targetPath: field,
                            payload: modifiedMessage,
                            severity: 'medium'
                        });
                    } catch (error) {
                        console.error(`[Fuzzer] Error creating origin fuzzing payload for field ${field}:`, error);
                    }
                }
            }
        }

        generatePrototypePollutionPayloads(structure) {
            if (!window.FuzzingPayloads?.PROTOTYPE_POLLUTION) {
                console.error("[Fuzzer] Prototype Pollution vectors missing.");
                return;
            }

            if (!this.fuzzerConfig.enablePrototypePollution) return;

            const pollutionVectors = window.FuzzingPayloads.PROTOTYPE_POLLUTION;
            let count = 0;

            for (const structure of this.messageStructures) {
                if (structure.type === 'raw_string' || !structure.original) continue;
                const baseMessage = JSON.parse(JSON.stringify(structure.original));

                for (const { field, value } of pollutionVectors) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) {
                        console.log(`[Fuzzer] Reached maximum payload limit during prototype pollution generation`);
                        return;
                    }

                    const fuzzedMessage = JSON.parse(JSON.stringify(baseMessage));
                    try {
                        let pollutionTarget = fuzzedMessage;
                        let nestedKey = Object.keys(fuzzedMessage).find(k => this.isPlainObject(fuzzedMessage[k]));
                        if (nestedKey) {
                            pollutionTarget = fuzzedMessage[nestedKey];
                        } else {
                            if (!fuzzedMessage._pp_test_obj) fuzzedMessage._pp_test_obj = {};
                            pollutionTarget = fuzzedMessage._pp_test_obj;
                        }
                        this.setNestedValue(pollutionTarget, field, value);
                        this.payloads.push({
                            type: 'prototype_pollution',
                            field: field,
                            targetPath: field,
                            payload: fuzzedMessage,
                            severity: 'high'
                        });
                        count++;
                    } catch (error) {
                        console.warn(`[Fuzzer] Could not create prototype pollution payload for field '${field}': ${error.message}`);
                        if (field.startsWith('__proto__')) {
                            try {
                                if (count >= this.fuzzerConfig.maxTotalPayloads) return;

                                const topLevelFuzzed = JSON.parse(JSON.stringify(baseMessage));
                                topLevelFuzzed[field] = value;
                                this.payloads.push({
                                    type: 'prototype_pollution_direct',
                                    field: field,
                                    targetPath: field,
                                    payload: topLevelFuzzed,
                                    severity: 'high'
                                });
                                count++;
                            } catch (directError) {
                                console.warn(`[Fuzzer] Direct PP assignment failed for field '${field}': ${directError.message}`);
                            }
                        }
                    }
                }
            }
        }

        generateAdditionalPayloads(count, payloadList) {
            if (!count || count <= 0 || !payloadList || payloadList.length === 0) return;

            console.log(`[Fuzzer] Generating ${count} additional payloads to meet minimum requirement`);

            // For each message structure, generate additional payloads
            for (const structure of this.messageStructures) {
                if (!structure || !structure.original) continue;

                if (structure.type === 'object') {
                    const baseMessage = JSON.parse(JSON.stringify(structure.original));
                    const fields = this.extractAllFields(baseMessage);

                    // Select random fields to fuzz
                    const fieldCount = Math.min(fields.length, 10);
                    const selectedFields = fields
                        .sort(() => 0.5 - Math.random())
                        .slice(0, fieldCount);

                    // Select random payloads
                    const payloadsNeeded = Math.ceil(count / (fieldCount || 1));
                    const selectedPayloads = payloadList
                        .sort(() => 0.5 - Math.random())
                        .slice(0, payloadsNeeded);

                    let additionalCount = 0;

                    // Generate payloads for each field
                    for (const field of selectedFields) {
                        for (const payload of selectedPayloads) {
                            if (additionalCount >= count) return;

                            try {
                                const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                                this.setNestedValue(modifiedMessage, field, payload);
                                this.payloads.push({
                                    type: 'additional',
                                    field: field,
                                    targetPath: field,
                                    payload: modifiedMessage,
                                    severity: 'medium'
                                });
                                additionalCount++;
                            } catch (error) {
                                console.error(`[Fuzzer] Error creating additional payload for field ${field}:`, error);
                            }
                        }
                    }
                } else if (structure.type === 'raw_string') {
                    // For raw strings, generate additional payloads
                    const original = structure.original;
                    if (typeof original !== 'string') continue;

                    const payloadsNeeded = Math.min(count, 20);
                    const selectedPayloads = payloadList
                        .sort(() => 0.5 - Math.random())
                        .slice(0, payloadsNeeded);

                    let additionalCount = 0;

                    for (const payload of selectedPayloads) {
                        if (additionalCount >= count) return;

                        this.payloads.push({
                            type: 'additional_raw',
                            payload: payload,
                            severity: 'medium',
                            isRawString: true,
                            original: original
                        });
                        additionalCount++;
                    }
                }
            }
        }

        isCriticalField(field) {
            // This method identifies fields that might break functionality if modified
            // We've disabled this by default (skipCriticalFields = false) to maximize coverage
            const fieldName = field.split('.').pop().toLowerCase();
            const criticalFields = ['type', 'msgtype', 'messagetype', 'id', 'action', 'command'];
            return criticalFields.includes(fieldName);
        }
    }

    global.SinkAwarePostMessageFuzzer = class SinkAwarePostMessageFuzzer {
        constructor(messages, handlerCode, sinks) {
            this.messages = Array.isArray(messages) ? messages : [];
            this.handlerCode = handlerCode || '';
            this.sinks = Array.isArray(sinks) ? sinks : [];
            this.config = {
                messages: this.messages,
                handler: this.handlerCode,
                sinks: this.sinks,
            };
            this.fuzzer = new ImprovedMessageFuzzer();
            this.isExecutingPayloads = false;
            this.payloadIntervalId = null;
            this.reportData = null;
            this.target = null;
            this.callbackUrl = null;
            this._onCompleteCallback = null;
        }

        start(onCompleteCallback) {
            if (this.isExecutingPayloads) {
                console.warn("[Fuzzer Start] Fuzzing is already running.");
                return;
            }
            const payloadsToExecute = this.generatePayloads();
            if (payloadsToExecute.length > 0) {
                console.log(`[Fuzzer Start] Beginning execution with ${payloadsToExecute.length} payloads.`);
                this._onCompleteCallback = onCompleteCallback;
                this.executeFuzzing(payloadsToExecute);
            } else {
                console.warn('[Fuzzer Start] No payloads available to execute.');
                if (typeof onCompleteCallback === 'function') {
                    onCompleteCallback();
                }
                if(typeof updateStatus === 'function') {
                    updateStatus('Error: No payloads found or generated.', true);
                }
            }
        }

        stop() {
            if (this.payloadIntervalId) {
                clearInterval(this.payloadIntervalId);
                this.payloadIntervalId = null;
                console.log('[Fuzzer Stop] Fuzzing interval cleared.');
            }
            if (this.isExecutingPayloads) {
                this.isExecutingPayloads = false;
                console.log('[Fuzzer Stop] Fuzzing execution flag set to false.');
                if (typeof this._onCompleteCallback === 'function') {
                    this._onCompleteCallback(true);
                }
            }
        }

        generatePayloads() {
            let basePayloads = [];
            let ranFallbackGenerator = false;

            if (this.config?.payloads?.length > 0) {
                basePayloads = this.config.payloads;
            } else if (this.config?.traceData?.payloads?.length > 0) {
                basePayloads = this.config.traceData.payloads;
            }

            this.fuzzer.initialize(
                this.config?.messages || [], this.config?.handler || '',
                this.config?.sinks || [], this.config?.target, this.config?.callbackUrl
            );
            if (this.config?.fuzzerOptions) {
                this.fuzzer.initializeWithConfig(this.config.fuzzerOptions);
            }

            if (basePayloads.length === 0) {
                this.fuzzer.runPayloadGeneration();
                basePayloads = this.fuzzer.payloads;
                ranFallbackGenerator = true;
            }

            let additionalCallbackPayloads = [];
            const shouldAddCallbacks = !ranFallbackGenerator && this.config?.fuzzerOptions?.enableCallbackFuzzing && this.fuzzer.callbackUrl;

            if (shouldAddCallbacks) {
                this.fuzzer.payloads = [];
                this.fuzzer.generateCallbackPayloads();
                additionalCallbackPayloads = this.fuzzer.payloads;
            }

            const combinedPayloads = [...basePayloads, ...additionalCallbackPayloads];

            const uniquePayloadStrings = new Set();
            const uniqueFinalPayloads = combinedPayloads.filter(payloadItem => {
                const actualPayload = payloadItem.payload !== undefined ? payloadItem.payload : payloadItem;
                let payloadString;
                try {
                    payloadString = (typeof actualPayload === 'string') ? actualPayload : JSON.stringify(actualPayload);
                } catch (e) {
                    return true;
                }

                if (uniquePayloadStrings.has(payloadString)) {
                    return false;
                } else {
                    uniquePayloadStrings.add(payloadString);
                    return true;
                }
            });

            if (uniqueFinalPayloads.length === 0) {
                console.error('[SinkAware] Failed to generate or find any payloads after deduplication.');
            } else {
                const finalTypeStats = {};
                uniqueFinalPayloads.forEach(p => {
                    const type = p.type || 'unknown';
                    finalTypeStats[type] = (finalTypeStats[type] || 0) + 1;
                });
                console.log(`[SinkAware] Returning ${uniqueFinalPayloads.length} unique total payloads for execution.`);
                console.log("[SinkAware] Final Unique Payload Stats:");
                Object.entries(finalTypeStats).forEach(([type, count]) => {
                    console.log(`[SinkAware]    - ${type}: ${count}`);
                });
            }

            return uniqueFinalPayloads;
        }

        executeFuzzing(payloads) {
            if (!payloads || payloads.length === 0) {
                console.warn('[Fuzzer Execute] No payloads passed to executeFuzzing.');
                this.isExecutingPayloads = false;
                if (typeof this._onCompleteCallback === 'function') this._onCompleteCallback();
                return;
            }
            if (this.isExecutingPayloads) return;
            this.isExecutingPayloads = true;

            const sentPayloads = new Set();
            let messageIndex = 0;
            const iframe = document.getElementById('targetFrame');

            if (!iframe?.contentWindow) {
                console.error('[Fuzzer Execute] Target iframe not available');
                this.isExecutingPayloads = false;
                if(typeof updateStatus === 'function') updateStatus('Error: Target iframe not found.', true);
                if (typeof this._onCompleteCallback === 'function') this._onCompleteCallback();
                return;
            }

            if(typeof updateStatus === 'function') updateStatus(`Executing ${payloads.length} payloads... (0%)`);
            if (this.payloadIntervalId) clearInterval(this.payloadIntervalId);

            this.payloadIntervalId = setInterval(() => {
                if (!this.isExecutingPayloads || !iframe?.contentWindow || messageIndex >= payloads.length) {
                    if(typeof updateStatus === 'function') {
                        if(this.isExecutingPayloads) updateStatus(`Execution finished. Sent ${messageIndex} payloads.`);
                    }
                    console.log(`[Fuzzer Execute] Completed interval. Sent ${messageIndex} payloads. isExecuting=${this.isExecutingPayloads}`);
                    this.stop();
                    return;
                }

                const progress = Math.round(((messageIndex + 1) / payloads.length) * 100);
                if(typeof updateStatus === 'function') updateStatus(`Executing payload ${messageIndex + 1}/${payloads.length} (${progress}%)`);

                const fuzzerPayload = payloads[messageIndex];
                messageIndex++;

                try {
                    const payloadId = typeof fuzzerPayload?.payload === 'string' ?
                        `${fuzzerPayload.type || 'unknown'}-${fuzzerPayload.payload.substring(0, 30)}` :
                        `${fuzzerPayload?.type || 'unknown'}-${messageIndex}`;
                    if (sentPayloads.has(payloadId)) return;
                    sentPayloads.add(payloadId);

                    let payloadToSend = fuzzerPayload?.isRawString ? fuzzerPayload.payload
                        : (fuzzerPayload?.payload !== undefined ? fuzzerPayload.payload : fuzzerPayload);

                    if (payloadToSend === undefined || payloadToSend === null) {
                        console.warn(`[Fuzzer Execute] Skipping null/undefined payload at index ${messageIndex - 1}.`);
                        return;
                    }

                    const processedPayload = this.replaceJwtTokens(payloadToSend);

                    if (typeof window.sendToFrame === 'function') window.sendToFrame(processedPayload);
                    else iframe.contentWindow.postMessage(processedPayload, '*');

                } catch (error) {
                    console.error(`[Fuzzer Execute] Error sending payload index ${messageIndex - 1}:`, error, fuzzerPayload);
                }
            }, 200);
        }

        replaceJwtTokens(payload) {
            if (typeof payload === 'string') return payload.replace(JWT_REGEX, ADMIN_JWT);
            if (!payload || typeof payload !== 'object') return payload;
            let clonedPayload;
            try {
                clonedPayload = structuredClone(payload);
            } catch (e) {
                try {
                    clonedPayload = JSON.parse(JSON.stringify(payload));
                } catch (jsonError) {
                    console.error("Failed to clone payload:", jsonError);
                    return payload;
                }
            }

            const processObject = (obj) => {
                for (const key in obj) {
                    if(obj.hasOwnProperty(key)) {
                        if (typeof obj[key] === 'string') obj[key] = obj[key].replace(JWT_REGEX, ADMIN_JWT);
                        else if (typeof obj[key] === 'object' && obj[key] !== null) processObject(obj[key]);
                    }
                }
            };
            processObject(clonedPayload);
            return clonedPayload;
        }

        static initialize(config) {
            if (!config?.target) {
                console.error('[Fuzzer Init] Invalid config: missing target URL');
                if(typeof updateStatus === 'function') updateStatus('Error: Invalid configuration.', true);
                return null;
            }

            let sinks = config.sinks || config.traceData?.vulnerabilities || config.traceData?.sinks || [];
            const fuzzerInstance = new SinkAwarePostMessageFuzzer(config.messages || [], config.handler || "", sinks);
            fuzzerInstance.target = config.target;
            fuzzerInstance.callbackUrl = config.callbackUrl;
            fuzzerInstance.config = config;
            fuzzerInstance.reportData = config.traceData || null;

            // Pass fuzzer configuration options if provided
            if (fuzzerInstance.fuzzer && config.fuzzerOptions) {
                fuzzerInstance.fuzzer.initializeWithConfig(config.fuzzerOptions);
            }

            console.log(`[Fuzzer Init] Initialized for ${fuzzerInstance.target} with ${sinks.length} sinks and ${config.messages?.length || 0} messages`);
            return fuzzerInstance;
        }
    }

    global.ImprovedMessageFuzzer = ImprovedMessageFuzzer;
    global.SinkAwarePostMessageFuzzer = SinkAwarePostMessageFuzzer;

})(typeof window !== 'undefined' ? window : this);


// Fuzzer Environment Setup (localhost:1337)
if (typeof window !== 'undefined' && window.location?.href?.includes('localhost:1337')) {
    window.addEventListener('DOMContentLoaded', async () => {
        const statusContainer = document.getElementById('statusContainer');
        const fuzzerStatus = document.getElementById('fuzzerStatus') || document.createElement('div');
        fuzzerStatus.id = 'fuzzerStatus';
        if (statusContainer && !fuzzerStatus.parentNode) {
            statusContainer.appendChild(fuzzerStatus);
        }
        fuzzerStatus.textContent = 'Waiting for configuration...';
        fuzzerStatus.style.color = 'inherit';
        console.log('[Test Environment] Waiting for configuration...');

        try {
            const response = await fetch('/current-config');
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Failed to fetch configuration: ${response.status} - ${errorText}`);
            }
            const config = await response.json();
            if (!config?.target) {
                throw new Error("Received invalid or incomplete configuration from server.");
            }
            console.log('[Test Environment] Received configuration.');
            fuzzerStatus.textContent = `Configuration loaded for ${config.target}. Initializing...`;

            const fuzzerInstance = window.SinkAwarePostMessageFuzzer.initialize(config);

            if (!fuzzerInstance) {
                throw new Error("Fuzzer initialization failed.");
            }

            const iframeId = 'targetFrame';
            let iframe = document.getElementById(iframeId);
            if (!iframe) {
                console.log('[Test Environment] Creating target iframe...');
                iframe = document.createElement('iframe');
                iframe.id = iframeId;
                iframe.sandbox = "allow-scripts allow-modals allow-same-origin allow-popups allow-forms";
                iframe.style.width = "95%";
                iframe.style.height = "70vh";
                iframe.style.border = "1px solid #ccc";
                const iframeContainer = document.getElementById('iframeContainer') || document.body;
                iframeContainer.appendChild(iframe);
            }

            console.log(`[Test Environment] Setting iframe src to: ${config.target}`);
            iframe.src = config.target;

            iframe.onload = () => {
                console.log('[Test Environment] Target iframe loaded. Starting fuzzer...');
                fuzzerStatus.textContent = 'Target loaded. Starting fuzzing...';
                fuzzerInstance.start();
            };
            iframe.onerror = (error) => {
                console.error('[Test Environment] Target iframe failed to load:', error);
                fuzzerStatus.textContent = `Error: Target iframe failed to load (${config.target})`;
                fuzzerStatus.style.color = 'red';
            };

            window.addEventListener('message', event => {
                if (event.source === iframe.contentWindow) {
                    console.log('[Test Environment] Received response from iframe:', event.data);
                }
            });

        } catch (error) {
            console.error('[Test Environment] Error setting up fuzzer:', error);
            fuzzerStatus.textContent = `Error: ${error.message}`;
            fuzzerStatus.style.color = 'red';
        }
    });
}
