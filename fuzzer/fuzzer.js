/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
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
                maxTotalPayloads: 2000,
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
                    let data = msg.data !== undefined ? msg.data : msg;
                });
            }

            this.vulnerablePaths = (sinks || []).map(sink => {
                let targetProperty = "message";
                if (sink.property) {
                    targetProperty = sink.property;
                } else if (sink.path && sink.path !== '(root)') {
                    targetProperty = sink.path;
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
                            try { msgData = JSON.parse(msgData); dataType = typeof msgData; } catch (e) { }
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
            this.fuzzerConfig = { ...this.fuzzerConfig, ...config };
            if (config.maxPayloadsPerField) this.maxPayloadsPerField = config.maxPayloadsPerField;
            if (config.forceMinimumPayloads && typeof config.forceMinimumPayloads === 'number') this.fuzzerConfig.forceMinimumPayloads = config.forceMinimumPayloads;
            return this;
        }

        getFieldTypes(obj, prefix = '') {
            const result = {}; if (!this.isPlainObject(obj)) return result;
            for (const key in obj) { if (!obj.hasOwnProperty(key)) continue; const fieldPath = prefix ? `${prefix}.${key}` : key; result[fieldPath] = typeof obj[key]; if (this.isPlainObject(obj[key])) { Object.assign(result, this.getFieldTypes(obj[key], fieldPath)); } }
            return result;
        }

        extractAllFields(obj, prefix = '') {
            const fields = []; if (!this.isPlainObject(obj)) return fields;
            for (const key in obj) { if (!obj.hasOwnProperty(key)) continue; const fieldPath = prefix ? `${prefix}.${key}` : key; fields.push(fieldPath); if (this.isPlainObject(obj[key])) { fields.push(...this.extractAllFields(obj[key], fieldPath)); } }
            return fields;
        }

        runPayloadGeneration() {
            console.log("[Fuzzer] Starting payload generation sequence...");
            this.payloads = [];

            return new Promise((resolve) => {
                chrome.storage.session.get(['customXssPayloads', 'callback_url'], (result) => {
                    const customPayloads = result.customXssPayloads || [];
                    const callbackUrl = result.callback_url || null;

                    if (callbackUrl) {
                        this.callbackUrl = callbackUrl;
                    }

                    if (customPayloads.length > 0) {
                        console.log(`%c[Custom Payloads In Use]`, "color: #2ecc71; font-weight: bold; font-size: 14px",
                            `Using ${customPayloads.length} custom payloads from uploaded file instead of default payloads.`);

                        if (this.messageStructures.length > 0) {
                            console.log(`[Fuzzer] Integrating custom payloads into ${this.messageStructures.length} message structures`);

                            for (const structure of this.messageStructures) {
                                if (!structure || !structure.original) continue;

                                if (structure.type === 'object') {
                                    const paths = this.vulnerablePaths.length > 0
                                        ? this.vulnerablePaths.map(p => p.path)
                                        : (structure.pathsToFuzz || []).map(p => p.path);

                                    if (paths.length > 0) {
                                        for (const path of paths) {
                                            if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;

                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;

                                                try {
                                                    const modifiedMsg = JSON.parse(JSON.stringify(structure.original));
                                                    this.setNestedValue(modifiedMsg, path, payload);
                                                    this.payloads.push({
                                                        type: 'custom-structured',
                                                        payload: modifiedMsg,
                                                        targetPath: path,
                                                        description: `Custom payload in structured message`
                                                    });
                                                } catch (e) {
                                                    console.warn(`[Fuzzer] Error applying custom payload to path ${path}:`, e);
                                                }
                                            }
                                        }
                                    } else {
                                        const objCopy = JSON.parse(JSON.stringify(structure.original));
                                        const bestProperty = this.findBestStringProperty(objCopy);

                                        if (bestProperty) {
                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                                try {
                                                    const modifiedMsg = JSON.parse(JSON.stringify(structure.original));
                                                    this.setNestedValue(modifiedMsg, bestProperty, payload);
                                                    this.payloads.push({
                                                        type: 'custom-auto-path',
                                                        payload: modifiedMsg,
                                                        targetPath: bestProperty,
                                                        description: `Custom payload auto-targeting ${bestProperty}`
                                                    });
                                                } catch (e) {
                                                    console.warn(`[Fuzzer] Error applying custom payload to auto path ${bestProperty}:`, e);
                                                }
                                            }
                                        } else {
                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                                this.payloads.push({
                                                    type: 'custom-raw',
                                                    payload: payload,
                                                    description: 'Custom raw payload (no suitable structure)'
                                                });
                                            }
                                        }
                                    }
                                } else if (structure.type === 'raw_string') {
                                    for (const payload of customPayloads) {
                                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                        this.payloads.push({
                                            type: 'custom-raw',
                                            payload: payload,
                                            description: 'Custom raw payload'
                                        });
                                    }
                                }
                            }
                        } else {
                            for (const payload of customPayloads) {
                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                this.payloads.push({
                                    type: 'custom-raw',
                                    payload: payload,
                                    description: 'Custom raw payload (no structures)'
                                });
                            }
                        }

                        if (this.payloads.length === 0) {
                            customPayloads.forEach(customPayload => {
                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;
                                this.payloads.push({
                                    type: 'custom-raw',
                                    payload: customPayload,
                                    description: 'Custom raw payload (fallback)'
                                });
                            });
                        }

                        if (this.fuzzerConfig.enableCallbackFuzzing && this.callbackUrl) {
                            console.log(`[Fuzzer] Adding callback payloads to custom payloads because callback URL is set`);
                            this.generateCallbackPayloads();
                        }
                    } else {
                        const allXssPayloads = window.FuzzingPayloads?.XSS || [];
                        console.log(`[Fuzzer] Using default XSS payloads: ${allXssPayloads.length} total`);
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

                        if (this.fuzzerConfig.forceMinimumPayloads &&
                            typeof this.fuzzerConfig.forceMinimumPayloads === 'number' &&
                            this.payloads.length < this.fuzzerConfig.forceMinimumPayloads) {

                            console.log(`[Fuzzer] Generated ${this.payloads.length} payloads, below minimum ${this.fuzzerConfig.forceMinimumPayloads}. Generating more...`);
                            this.generateAdditionalPayloads(this.fuzzerConfig.forceMinimumPayloads - this.payloads.length, payloadList);
                        }
                    }

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
                    resolve(this.payloads);
                });
            });
        }

        findBestStringProperty(obj, path = '') {
            if (!obj || typeof obj !== 'object') return null;
            const htmlRelatedProps = ['html', 'content', 'message', 'text', 'body', 'data', 'value', 'src', 'url', 'href'];
            for (const prop of htmlRelatedProps) {
                if (typeof obj[prop] === 'string') {
                    return path ? `${path}.${prop}` : prop;
                }
            }

            for (const key in obj) {
                if (typeof obj[key] === 'string') {
                    return path ? `${path}.${key}` : key;
                }
            }

            for (const key in obj) {
                if (obj[key] && typeof obj[key] === 'object') {
                    const nestedPath = path ? `${path}.${key}` : key;
                    const result = this.findBestStringProperty(obj[key], nestedPath);
                    if (result) return result;
                }
            }
            const keys = Object.keys(obj);
            if (keys.length > 0) {
                return path ? `${path}.${keys[0]}` : keys[0];
            }

            return null;
        }

        generateSmartObjectPayloads(structure, vulnerablePaths, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original || !vulnerablePaths || vulnerablePaths.length === 0) return; if (!payloadList || payloadList.length === 0) { console.error("[Fuzzer] Payloads missing for Smart generation."); return; }
            const baseMessage = JSON.parse(JSON.stringify(structure.original)); let count = 0;
            const maxPayloadsPerSink = Math.min(this.maxPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (vulnerablePaths.length || 1)));
            console.log(`[Fuzzer] Smart fuzzing ${vulnerablePaths.length} paths with up to ${maxPayloadsPerSink} payloads each`);
            for (const vulnPath of vulnerablePaths) {
                let targetPath = vulnPath.path; if (targetPath === 'data' && vulnPath.fullPath && vulnPath.fullPath !== 'event.data') { const dataPathMatch = vulnPath.fullPath.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/); if (dataPathMatch && dataPathMatch[1]) { targetPath = dataPathMatch[1]; } }
                if (!targetPath || targetPath === '') { const stringFields = Object.entries(structure.fieldTypes || {}).filter(([, type]) => type === 'string').map(([field]) => field); const suspiciousFields = stringFields.filter(field => /html|script|content|message|url|src/i.test(field)); targetPath = suspiciousFields[0] || stringFields[0]; if (!targetPath) { console.log(`[Fuzzer] SMART: No target path found for sink ${vulnPath.sinkType}, skipping.`); continue; } }
                let relevantPayloads = []; const sinkTypeLower = vulnPath.sinkType?.toLowerCase() || '';
                if (window.FuzzingPayloads.SINK_SPECIFIC) {
                    if (sinkTypeLower.includes('eval')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.eval || [];
                    else if (sinkTypeLower.includes('innerhtml')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.innerHTML || [];
                    else if (sinkTypeLower.includes('write')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.document_write || [];
                    else if (sinkTypeLower.includes('settimeout')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setTimeout || [];
                    else if (sinkTypeLower.includes('setinterval')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setInterval || [];
                    else if (sinkTypeLower.includes('location') || sinkTypeLower.includes('href')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.location_href || [];
                }
                if (!relevantPayloads.length) { relevantPayloads = payloadList; }
                if (this.fuzzerConfig.randomizePayloadSelection) { relevantPayloads = [...relevantPayloads].sort(() => 0.5 - Math.random()); }
                const payloadsToUse = relevantPayloads.slice(0, maxPayloadsPerSink);
                for (const payload of payloadsToUse) {
                    try { if (count >= this.fuzzerConfig.maxTotalPayloads) { console.log(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`); return; } const modifiedMessage = JSON.parse(JSON.stringify(baseMessage)); this.setNestedValue(modifiedMessage, targetPath, payload); this.payloads.push({ type: 'smart', sinkType: vulnPath.sinkType, targetPath: targetPath, fullPath: vulnPath.fullPath, payload: modifiedMessage, severity: vulnPath.severity || (vulnPath.sinkType === 'eval' ? 'critical' : 'high') }); count++; }
                    catch (error) { console.error(`[Fuzzer] Error creating SMART payload for path ${targetPath}:`, error); }
                }
            }
        }

        generateDumbObjectPayloads(structure, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original) return; if (!payloadList || payloadList.length === 0) return; if (!this.fuzzerConfig.enableDumbFuzzing) return;
            const baseMessage = JSON.parse(JSON.stringify(structure.original)); const fields = this.extractAllFields(baseMessage);
            const stringFields = fields.filter(field => { let currentObj = baseMessage; const parts = field.split('.'); try { for (let i = 0; i < parts.length - 1; i++) { if (currentObj[parts[i]] === undefined || currentObj[parts[i]] === null) return false; currentObj = currentObj[parts[i]]; } const lastPart = parts[parts.length - 1]; const value = currentObj[lastPart]; return typeof value === 'string' || value === null || value === undefined; } catch (e) { return false; } });
            const suspiciousPatterns = [ /html/i, /script/i, /content/i, /message/i, /url/i, /src/i, /href/i, /code/i, /exec/i, /eval/i, /callback/i, /function/i, /source/i, /target/i, /payload/i, /template/i, /markup/i, /auth/i, /token/i, /key/i, /secret/i, /pass/i, /user/i, /admin/i ];
            const prioritizedFields = stringFields.sort((a, b) => { const aIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(a)); const bIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(b)); if (aIsSuspicious && !bIsSuspicious) return -1; if (!aIsSuspicious && bIsSuspicious) return 1; return 0; });
            const fieldsToFuzz = Math.min(prioritizedFields.length, 50); const payloadsPerField = Math.min(this.fuzzerConfig.dumbFuzzingPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (fieldsToFuzz || 1)));
            console.log(`[Fuzzer] Dumb fuzzing ${fieldsToFuzz} fields with ${payloadsPerField} payloads each`); let totalPayloads = 0;
            for (let i = 0; i < prioritizedFields.length && i < fieldsToFuzz; i++) {
                const field = prioritizedFields[i]; let selectedPayloads = payloadList;
                if (this.fuzzerConfig.randomizePayloadSelection) { selectedPayloads = [...payloadList].sort(() => 0.5 - Math.random()).slice(0, payloadsPerField); } else { selectedPayloads = payloadList.slice(0, payloadsPerField); }
                for (const payload of selectedPayloads) {
                    try { if (totalPayloads >= this.fuzzerConfig.maxTotalPayloads) { console.warn(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`); return; } const modifiedMessage = JSON.parse(JSON.stringify(baseMessage)); this.setNestedValue(modifiedMessage, field, payload); this.payloads.push({ type: 'dumb', field: field, targetPath: field, payload: modifiedMessage, severity: 'medium' }); totalPayloads++; }
                    catch (error) { console.error(`[Fuzzer] Error creating DUMB payload for field ${field}:`, error); }
                }
            }
        }

        generateRawStringPayloads(original, payloadList) {
            if (typeof original !== 'string') return; if (!payloadList || payloadList.length === 0) { console.error("[Fuzzer] Payloads missing for Raw String generation."); return; }
            const maxPayloadsForRawString = Math.min(this.maxPayloadsPerField, 30); let count = 0;
            const selectedPayloads = this.fuzzerConfig.randomizePayloadSelection ? [...payloadList].sort(() => 0.5 - Math.random()).slice(0, maxPayloadsForRawString) : payloadList.slice(0, maxPayloadsForRawString);
            for (const payload of selectedPayloads) {
                if (count >= this.fuzzerConfig.maxTotalPayloads) { console.log(`[Fuzzer] Reached maximum payload limit (${this.fuzzerConfig.maxTotalPayloads})`); return; }
                this.payloads.push({ type: 'raw_string_replace', payload: payload, severity: 'high', isRawString: true, original: original }); count++; if (count >= this.fuzzerConfig.maxTotalPayloads) return;
                const injectionVariants = [`${payload}${original}`, `${original}${payload}`]; if (original.length > 10) { const mid = Math.floor(original.length / 2); injectionVariants.push(original.substring(0, mid) + payload + original.substring(mid)); }
                for (const injectedString of injectionVariants) { if (count >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: `raw_string_inject`, payload: injectedString, severity: 'high', isRawString: true, original: original }); count++; }
            }
        }

        generateCallbackPayloads() {
            if (!this.callbackUrl) return; if (!window.FuzzingPayloads?.CALLBACK_URL) { console.error("[Fuzzer] Callback payload templates missing."); return; }
            const callbackTemplates = window.FuzzingPayloads.CALLBACK_URL; let count = 0;
            for (const template of callbackTemplates) {
                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; const processedPayloadStr = template.replace(/%%CALLBACK_URL%%/g, this.callbackUrl);
                for (const structure of this.messageStructures) {
                    if (structure.type === 'object' && structure.original) {
                        const pathsToTarget = this.vulnerablePaths.length > 0 ? this.vulnerablePaths : Object.entries(structure.fieldTypes || {}).filter(([, type]) => type === 'string').slice(0, 5).map(([path]) => ({ path: path, sinkType: 'generic_string', severity: 'medium' }));
                        if (pathsToTarget.length === 0 && structure.fields?.length > 0) { pathsToTarget.push({ path: structure.fields[0], sinkType: 'first_field', severity: 'low'}); }
                        for (const vulnPath of pathsToTarget) {
                            if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;
                            try { const targetPath = vulnPath.path; if (!targetPath) continue; const modifiedMessage = JSON.parse(JSON.stringify(structure.original)); this.setNestedValue(modifiedMessage, targetPath, processedPayloadStr); this.payloads.push({ type: 'callback_url_object', sinkType: vulnPath.sinkType, targetPath: targetPath, fullPath: vulnPath.fullPath, payload: modifiedMessage, severity: 'critical' }); count++; }
                            catch (error) { console.error(`[ImprovedFuzzer CB] Error creating object payload for path ${vulnPath.path}:`, error); }
                        }
                    } else if (structure.type === 'raw_string') {
                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: 'callback_url_raw', payload: processedPayloadStr, severity: 'critical', isRawString: true, original: structure.original }); count++; if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; const combined = `${structure.original || ''}${processedPayloadStr}`; this.payloads.push({ type: 'callback_url_combined', payload: combined, severity: 'critical', isRawString: true, original: structure.original }); count++;
                    }
                }
            }
        }

        generateOriginFuzzingPayloads() {
            for (const structure of this.messageStructures) {
                if (structure.type !== 'object' || !structure.original) continue; const baseMessage = JSON.parse(JSON.stringify(structure.original));
                if (!baseMessage.origin) { baseMessage.origin = "https://malicious-origin.com"; this.payloads.push({ type: 'origin_injection', targetPath: 'origin', payload: baseMessage, severity: 'medium' }); }
                const fields = this.extractAllFields(baseMessage); const originFields = fields.filter(f => /origin|source|from|sender/i.test(f));
                for (const field of originFields) { try { const modifiedMessage = JSON.parse(JSON.stringify(baseMessage)); this.setNestedValue(modifiedMessage, field, "https://malicious-origin.com"); this.payloads.push({ type: 'origin_spoofing', targetPath: field, payload: modifiedMessage, severity: 'medium' }); } catch (error) { console.error(`[Fuzzer] Error creating origin fuzzing payload for field ${field}:`, error); } }
            }
        }

        generatePrototypePollutionPayloads(structure) {
            if (!window.FuzzingPayloads?.PROTOTYPE_POLLUTION) { console.error("[Fuzzer] Prototype Pollution vectors missing."); return; } if (!this.fuzzerConfig.enablePrototypePollution) return;
            const pollutionVectors = window.FuzzingPayloads.PROTOTYPE_POLLUTION; let count = 0;
            for (const structure of this.messageStructures) {
                if (structure.type === 'raw_string' || !structure.original) continue; const baseMessage = JSON.parse(JSON.stringify(structure.original));
                for (const { field, value } of pollutionVectors) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) { console.log(`[Fuzzer] Reached maximum payload limit during prototype pollution generation`); return; }
                    const fuzzedMessage = JSON.parse(JSON.stringify(baseMessage));
                    try { let pollutionTarget = fuzzedMessage; let nestedKey = Object.keys(fuzzedMessage).find(k => this.isPlainObject(fuzzedMessage[k])); if (nestedKey) { pollutionTarget = fuzzedMessage[nestedKey]; } else { if (!fuzzedMessage._pp_test_obj) fuzzedMessage._pp_test_obj = {}; pollutionTarget = fuzzedMessage._pp_test_obj; } this.setNestedValue(pollutionTarget, field, value); this.payloads.push({ type: 'prototype_pollution', field: field, targetPath: field, payload: fuzzedMessage, severity: 'high' }); count++; }
                    catch (error) { console.warn(`[Fuzzer] Could not create prototype pollution payload for field '${field}': ${error.message}`); if (field.startsWith('__proto__')) { try { if (count >= this.fuzzerConfig.maxTotalPayloads) return; const topLevelFuzzed = JSON.parse(JSON.stringify(baseMessage)); topLevelFuzzed[field] = value; this.payloads.push({ type: 'prototype_pollution_direct', field: field, targetPath: field, payload: topLevelFuzzed, severity: 'high' }); count++; } catch (directError) { console.warn(`[Fuzzer] Direct PP assignment failed for field '${field}': ${directError.message}`); } } }
                }
            }
        }

        generateAdditionalPayloads(count, payloadList) {
            if (!count || count <= 0 || !payloadList || payloadList.length === 0) return; console.log(`[Fuzzer] Generating ${count} additional payloads to meet minimum requirement`);
            for (const structure of this.messageStructures) {
                if (!structure || !structure.original) continue;
                if (structure.type === 'object') {
                    const baseMessage = JSON.parse(JSON.stringify(structure.original)); const fields = this.extractAllFields(baseMessage); const fieldCount = Math.min(fields.length, 10); const selectedFields = fields.sort(() => 0.5 - Math.random()).slice(0, fieldCount); const payloadsNeeded = Math.ceil(count / (fieldCount || 1)); const selectedPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, payloadsNeeded); let additionalCount = 0;
                    for (const field of selectedFields) { for (const payload of selectedPayloads) { if (additionalCount >= count) return; try { const modifiedMessage = JSON.parse(JSON.stringify(baseMessage)); this.setNestedValue(modifiedMessage, field, payload); this.payloads.push({ type: 'additional', field: field, targetPath: field, payload: modifiedMessage, severity: 'medium' }); additionalCount++; } catch (error) { console.error(`[Fuzzer] Error creating additional payload for field ${field}:`, error); } } }
                } else if (structure.type === 'raw_string') {
                    const original = structure.original; if (typeof original !== 'string') continue; const payloadsNeeded = Math.min(count, 20); const selectedPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, payloadsNeeded); let additionalCount = 0;
                    for (const payload of selectedPayloads) { if (additionalCount >= count) return; this.payloads.push({ type: 'additional_raw', payload: payload, severity: 'medium', isRawString: true, original: original }); additionalCount++; }
                }
            }
        }
    }

    global.SinkAwarePostMessageFuzzer = class SinkAwarePostMessageFuzzer {
        constructor(messages, handlerCode, sinks) {
            this.messages = Array.isArray(messages) ? messages : []; this.handlerCode = handlerCode || ''; this.sinks = Array.isArray(sinks) ? sinks : [];
            this.config = { messages: this.messages, handler: this.handlerCode, sinks: this.sinks, };
            this.fuzzer = new ImprovedMessageFuzzer(); this.isExecutingPayloads = false; this.payloadIntervalId = null; this.reportData = null; this.target = null; this.callbackUrl = null; this._onCompleteCallback = null;
        }

        start(onCompleteCallback) {
            if (this.isExecutingPayloads) { console.warn("[Fuzzer Start] Fuzzing is already running."); return; }
            const payloadsToExecute = this.generatePayloads();
            if (payloadsToExecute.length > 0) { console.log(`[Fuzzer Start] Beginning execution with ${payloadsToExecute.length} payloads.`); this._onCompleteCallback = onCompleteCallback; this.executeFuzzing(payloadsToExecute); }
            else { console.warn('[Fuzzer Start] No payloads available to execute.'); if (typeof onCompleteCallback === 'function') { onCompleteCallback(); } if(typeof updateStatus === 'function') { updateStatus('Error: No payloads found or generated.', true); } }
        }

        stop() {
            if (this.payloadIntervalId) { clearInterval(this.payloadIntervalId); this.payloadIntervalId = null; console.log('[Fuzzer Stop] Fuzzing interval cleared.'); }
            if (this.isExecutingPayloads) { this.isExecutingPayloads = false; console.log('[Fuzzer Stop] Fuzzing execution flag set to false.'); if (typeof this._onCompleteCallback === 'function') { this._onCompleteCallback(true); } }
        }

        generatePayloads() {
            let basePayloads = [];
            let ranFallbackGenerator = false;

            if (this.config?.payloads?.length > 0) {
                basePayloads = this.config.payloads;
                console.log(`[SinkAware] Using ${basePayloads.length} payloads directly from configuration.`);
            } else if (this.config?.traceData?.payloads?.length > 0) {
                basePayloads = this.config.traceData.payloads;
                console.log(`[SinkAware] Using ${basePayloads.length} payloads from traceData.`);
            }

            if (basePayloads.length === 0) {
                console.warn("[SinkAware] No payloads provided in config or traceData. Running fallback generator.");
                this.fuzzer.initialize(
                    this.config?.messages || [],
                    this.config?.handler || '',
                    this.config?.sinks || [],
                    this.config?.target,
                    this.config?.callbackUrl
                );
                if (this.config?.fuzzerOptions) {
                    this.fuzzer.initializeWithConfig(this.config.fuzzerOptions);
                }
                this.fuzzer.runPayloadGeneration();
                basePayloads = this.fuzzer.payloads;
                ranFallbackGenerator = true;
                console.log(`[SinkAware] Fallback generator created ${basePayloads.length} payloads.`);
            }

            const finalPayloadsToExecute = basePayloads;


            if (finalPayloadsToExecute.length === 0) {
                console.error('[SinkAware] Failed to generate or find any payloads.');
            } else {
                const finalTypeStats = {};
                finalPayloadsToExecute.forEach(p => {
                    const type = p?.type || (p?.isRawString ? 'raw_string' : 'unknown');
                    finalTypeStats[type] = (finalTypeStats[type] || 0) + 1;
                });
                console.log(`[SinkAware] Returning ${finalPayloadsToExecute.length} total payloads for execution.`);
                console.log("[SinkAware] Final Payload Stats:");
                Object.entries(finalTypeStats).forEach(([type, count]) => {
                    console.log(`[SinkAware]    - ${type}: ${count}`);
                });
            }
            return finalPayloadsToExecute;
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
                    const payloadId = typeof fuzzerPayload?.payload === 'string'
                        ? `${fuzzerPayload.type || 'unknown'}-${fuzzerPayload.payload.substring(0, 30)}`
                        : `${fuzzerPayload?.type || 'unknown'}-${messageIndex}`;

                    if (sentPayloads.has(payloadId)) {
                        return;
                    }
                    sentPayloads.add(payloadId);

                    let payloadToSend;
                    const rawTypes = ['ast-raw', 'raw_string_replace', 'raw_string_inject', 'additional_raw', 'callback_url_raw', 'callback_url_combined'];

                    if (fuzzerPayload?.isRawString || rawTypes.includes(fuzzerPayload?.type)) {
                        payloadToSend = fuzzerPayload.payload;
                    } else if (fuzzerPayload?.payload !== undefined) {
                        payloadToSend = fuzzerPayload.payload;
                    } else {
                        payloadToSend = fuzzerPayload;
                    }

                    if (payloadToSend === undefined || payloadToSend === null) {
                        console.warn(`[Fuzzer Execute] Skipping null/undefined payload at index ${messageIndex - 1}.`);
                        return;
                    }

                    const processedPayload = this.replaceJwtTokens(payloadToSend);

                    if (typeof window.sendToFrame === 'function') {
                        window.sendToFrame(processedPayload);
                    } else {
                        iframe.contentWindow.postMessage(processedPayload, '*');
                    }
                }
                catch (error) {
                    console.error(`[Fuzzer Execute] Error sending payload index ${messageIndex - 1}:`, error, fuzzerPayload);
                }
            }, 200);
        }

        replaceJwtTokens(payload) {
            if (typeof payload === 'string') return payload.replace(JWT_REGEX, ADMIN_JWT);
            if (!payload || typeof payload !== 'object') return payload;

            let clonedPayload;
            try {
                if (typeof structuredClone === 'function') {
                    clonedPayload = structuredClone(payload);
                } else {
                    clonedPayload = JSON.parse(JSON.stringify(payload));
                }
            } catch (error) {
                console.error("Failed to clone payload:", error);
                return payload;
            }

            const processObject = (obj) => {
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        if (typeof obj[key] === 'string') {
                            obj[key] = obj[key].replace(JWT_REGEX, ADMIN_JWT);
                        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                            processObject(obj[key]);
                        }
                    }
                }
            };

            processObject(clonedPayload);
            return clonedPayload;
        }

        static initialize(config) {
            if (!config?.target) { console.error('[Fuzzer Init] Invalid config: missing target URL'); if(typeof updateStatus === 'function') updateStatus('Error: Invalid configuration.', true); return null; }
            let sinks = config.sinks || config.traceData?.vulnerabilities || config.traceData?.sinks || [];
            const fuzzerInstance = new SinkAwarePostMessageFuzzer(config.messages || [], config.handler || "", sinks); fuzzerInstance.target = config.target; fuzzerInstance.callbackUrl = config.callbackUrl; fuzzerInstance.config = config; fuzzerInstance.reportData = config.traceData || null;
            if (fuzzerInstance.fuzzer && config.fuzzerOptions) { fuzzerInstance.fuzzer.initializeWithConfig(config.fuzzerOptions); }
            console.log(`[Fuzzer Init] Initialized for ${fuzzerInstance.target} with ${sinks.length} sinks and ${config.messages?.length || 0} messages`);
            return fuzzerInstance;
        }
    }

    global.ImprovedMessageFuzzer = ImprovedMessageFuzzer;
    global.SinkAwarePostMessageFuzzer = SinkAwarePostMessageFuzzer;

    function generatePocHtml(targetUrl, payloads) {
        if (!targetUrl) {
            console.error("generatePocHtml: No target URL provided");
            return '<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error generating POC: Target URL missing.</h1></body></html>';
        }

        console.log("generatePocHtml: Processing payloads:", Array.isArray(payloads) ? payloads.length : typeof payloads);

        let validPayloads = [];
        try {
            if (Array.isArray(payloads)) {
                validPayloads = payloads;
            } else if (payloads && typeof payloads === 'object') {
                validPayloads = [payloads];
            } else if (typeof payloads === 'string') {
                try {
                    const parsed = JSON.parse(payloads);
                    validPayloads = Array.isArray(parsed) ? parsed : [parsed];
                } catch (e) {
                    validPayloads = [payloads];
                }
            }
        } catch (e) {
            console.error("generatePocHtml: Error preparing payloads:", e);
            validPayloads = [];
        }

        if (validPayloads.length === 0) {
            console.error("generatePocHtml: No valid payloads found");
            return '<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error generating POC: No valid payloads provided.</h1></body></html>';
        }

        const escapeHTML = (str) => {
            if (str === undefined || str === null) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        };

        try {
            const safeTargetUrl = escapeHTML(targetUrl);
            console.log("generatePocHtml: Creating Base64 data for", validPayloads.length, "payloads");

            let serializedPayloadsBase64;
            try {
                serializedPayloadsBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(validPayloads))));
                console.log("generatePocHtml: Base64 data created successfully");
            } catch (e) {
                console.error("generatePocHtml: Error creating Base64 data:", e);
                serializedPayloadsBase64 = "";
            }

            const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FrogPost POC: ${safeTargetUrl}</title>
    <style>
        body { font-family: sans-serif; margin: 0; background-color: #f4f4f4; color: #333; }
        .container { padding: 20px; max-width: 1000px; margin: 20px auto; background-color: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 5px;}
        h1 { color: #4CAF50; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 0; }
        p { font-size: 0.9em; }
        code { background-color: #eee; padding: 2px 5px; border-radius: 3px; word-break: break-all; font-size: 0.85em;}
        #pocControl { margin-bottom: 15px; }
        button { padding: 8px 15px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }
        button:hover { background-color: #45a049; }
        button:disabled { background-color: #ccc; cursor: not-allowed; }
        iframe { width: 100%; height: 60vh; border: 1px solid #ccc; box-sizing: border-box; }
        #status { margin-top: 10px; font-style: italic; color: #666; font-size: 0.9em; }
        pre.error { background: #ffeeee; color: #dd0000; padding: 10px; border-radius: 4px; overflow: auto; }
        .log-entry { margin: 5px 0; padding: 5px; border-left: 3px solid #ccc; background: #f9f9f9; font-family: monospace; font-size: 12px; }
        .log-entry.received { border-left-color: #4CAF50; }
    </style>
</head>
<body>
    <div class="container">
        <h1>FrogPost Proof of Concept</h1>
        <p>Target Iframe: <code>${safeTargetUrl}</code></p>
        <div id="pocControl">
            <button id="startPocButton" disabled>Send Payloads</button>
        </div>
        <div id="status">Status: Idle</div>
        <div id="errorContainer"></div>
        <div id="responseLog"></div>
        <iframe id="pocTargetFrame" src="${safeTargetUrl}" sandbox="allow-scripts allow-modals allow-same-origin allow-popups allow-forms"></iframe>
    </div>

    <script>
        let pocPayloads = [];
        const targetFrame = document.getElementById('pocTargetFrame');
        const startButton = document.getElementById('startPocButton');
        const statusDiv = document.getElementById('status');
        const errorContainer = document.getElementById('errorContainer');
        const responseLog = document.getElementById('responseLog');
        let payloadIntervalId = null;
        let currentPayloadIndex = 0;

        function updateStatus(message) {
            if (statusDiv) statusDiv.textContent = 'Status: ' + message;
        }

        function showError(message, error) {
            if (!errorContainer) return;
            
            const errorDisplay = document.createElement('pre');
            errorDisplay.className = 'error';
            errorDisplay.textContent = message + '\\n' + (error ? error.toString() : '');
            
            errorContainer.innerHTML = '';
            errorContainer.appendChild(errorDisplay);
        }

        function logResponse(data, fromTarget = false) {
            if (!responseLog) return;
            
            const entry = document.createElement('div');
            entry.className = 'log-entry' + (fromTarget ? ' received' : '');
            
            let content = '';
            try {
                if (typeof data === 'object') {
                    content = JSON.stringify(data, null, 2);
                } else {
                    content = String(data);
                }
            } catch (e) {
                content = 'Error displaying data: ' + e.message;
            }
            
            entry.textContent = (fromTarget ? '← ' : '→ ') + content;
            responseLog.appendChild(entry);
            
            responseLog.scrollTop = responseLog.scrollHeight;
        }

        function initializePOC() {
            try {
                const base64Data = "${serializedPayloadsBase64}";
                
                if (!base64Data) {
                    throw new Error("No payload data provided. Base64 data is empty.");
                }
                
                const jsonString = decodeURIComponent(escape(atob(base64Data)));
                pocPayloads = JSON.parse(jsonString);
                
                if (!Array.isArray(pocPayloads)) {
                    throw new Error("Payload data is not an array");
                }
                
                if (pocPayloads.length === 0) {
                    throw new Error("No payloads found");
                }
                
                if (startButton) {
                    startButton.textContent = 'Send Payloads (' + pocPayloads.length + ')';
                    startButton.disabled = false;
                }
                
                updateStatus('Ready. Loaded ' + pocPayloads.length + ' payloads. Click button to send.');
            } catch (e) {
                console.error("POC Error: Failed to initialize payloads.", e);
                updateStatus("Error: Could not load payloads. Check console.");
                showError("Failed to initialize payloads", e);
                if (startButton) startButton.disabled = true;
            }
        }

        function sendPayloads() {
            if (!targetFrame || !targetFrame.contentWindow) {
                updateStatus('Error: Target frame not accessible.');
                showError("Target frame not accessible");
                if (startButton) startButton.disabled = false;
                return;
            }
            
            if (!pocPayloads || pocPayloads.length === 0) {
                updateStatus('No payloads to send.');
                showError("No payloads to send");
                if (startButton) startButton.disabled = false;
                return;
            }

            if (errorContainer) errorContainer.innerHTML = '';
            
            console.log("Starting to send payloads:", pocPayloads.length);

            if (startButton) startButton.disabled = true;
            updateStatus('Sending payload 1/' + pocPayloads.length + '...');
            currentPayloadIndex = 0;

            if (payloadIntervalId) {
                clearInterval(payloadIntervalId);
                payloadIntervalId = null;
            }

            function sendSinglePayload() {
                if (currentPayloadIndex >= pocPayloads.length) {
                    clearInterval(payloadIntervalId);
                    payloadIntervalId = null;
                    updateStatus('Finished sending ' + pocPayloads.length + ' payloads.');
                    if (startButton) startButton.disabled = false;
                    return;
                }

                const payloadItem = pocPayloads[currentPayloadIndex];
                console.log("Sending payload #" + (currentPayloadIndex + 1), payloadItem);
                
                try {
                    const dataToSend = (typeof payloadItem === 'object' && payloadItem !== null && payloadItem.payload !== undefined)
                                ? payloadItem.payload
                                : payloadItem;
                    
                    console.log("Actual data being sent:", dataToSend);
                    logResponse(dataToSend, false);
                    
                    if (targetFrame && targetFrame.contentWindow) {
                        targetFrame.contentWindow.postMessage(dataToSend, '*');
                        console.log("postMessage sent successfully");
                    } else {
                        throw new Error("Target frame no longer available");
                    }
                } catch (e) {
                    console.error('POC Error sending payload:', e);
                    showError('Error sending payload #' + (currentPayloadIndex + 1), e);
                }

                currentPayloadIndex++;
                if (currentPayloadIndex < pocPayloads.length) {
                    updateStatus('Sending payload ' + (currentPayloadIndex + 1) + '/' + pocPayloads.length + '...');
                }
            }

            sendSinglePayload();
            
            payloadIntervalId = setInterval(sendSinglePayload, 250);
        }

        window.addEventListener('message', function(event) {
            if (targetFrame && event.source === targetFrame.contentWindow) {
                console.log('POC Received Response:', event.data);
                logResponse(event.data, true);
            }
        });

        if (startButton) {
            startButton.addEventListener('click', sendPayloads);
        }

        initializePOC();
    </script>
</body>
</html>`;

            console.log("generatePocHtml: HTML generated successfully");
            return html;
        } catch (error) {
            console.error('[POC Gen] Error generating POC HTML:', error);
            return `<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error generating POC</h1><p>${escapeHTML(error.message)}</p></body></html>`;
        }
    }

    function openPocWindow(htmlContent) {
        if (!htmlContent) {
            console.error("openPocWindow: No HTML content provided");
            alert('Error: No HTML content to display. Please try again.');
            return;
        }

        try {
            console.log("openPocWindow: Opening new window");
            const pocWindow = window.open('about:blank', 'FrogPostPOC', 'width=1000,height=800,resizable=yes,scrollbars=yes');

            if (!pocWindow) {
                console.error("openPocWindow: Window creation failed, likely blocked by popup blocker");
                alert('Failed to open POC window. Please check your browser pop-up settings and try again.');
                return;
            }

            console.log("openPocWindow: Writing HTML content to window");
            pocWindow.document.open();

            const chunkSize = 10000;

            for (let i = 0; i < htmlContent.length; i += chunkSize) {
                const chunk = htmlContent.substring(i, i + chunkSize);
                pocWindow.document.write(chunk);
            }

            pocWindow.document.close();
            pocWindow.originalHtmlContent = htmlContent;

            console.log("openPocWindow: Setting up window load handler");
            pocWindow.addEventListener('load', function() {
                try {
                    console.log("openPocWindow: Window loaded, adding copy button");

                    const controlBar = pocWindow.document.createElement('div');
                    controlBar.style.padding = '8px 10px';
                    controlBar.style.backgroundColor = '#f0f0f0';
                    controlBar.style.borderBottom = '1px solid #ccc';
                    controlBar.style.position = 'sticky';
                    controlBar.style.top = '0';
                    controlBar.style.zIndex = '1000';

                    // Create copy button
                    const copyButton = pocWindow.document.createElement('button');
                    copyButton.textContent = 'Copy POC Source';
                    copyButton.style.padding = '5px 10px';
                    copyButton.style.backgroundColor = '#4CAF50';
                    copyButton.style.color = 'white';
                    copyButton.style.border = 'none';
                    copyButton.style.borderRadius = '4px';
                    copyButton.style.cursor = 'pointer';
                    const statusSpan = pocWindow.document.createElement('span');
                    statusSpan.style.marginLeft = '10px';
                    statusSpan.style.color = 'green';
                    statusSpan.style.display = 'none';

                    const downloadLink = pocWindow.document.createElement('a');
                    downloadLink.textContent = 'Download HTML File';
                    downloadLink.style.marginLeft = '15px';
                    downloadLink.style.textDecoration = 'underline';
                    downloadLink.style.color = '#4CAF50';
                    downloadLink.style.cursor = 'pointer';
                    const blob = new Blob([htmlContent], {type: 'text/html'});
                    downloadLink.href = URL.createObjectURL(blob);
                    downloadLink.download = 'frogpost_poc.html';

                    copyButton.addEventListener('click', function() {
                        console.log("openPocWindow: Copy button clicked");

                        const tempTextarea = pocWindow.document.createElement('textarea');
                        tempTextarea.value = pocWindow.originalHtmlContent || htmlContent;
                        pocWindow.document.body.appendChild(tempTextarea);
                        tempTextarea.style.position = 'fixed';
                        tempTextarea.style.left = '-9999px';
                        tempTextarea.select();

                        let copySuccess = false;
                        try {
                            copySuccess = pocWindow.document.execCommand('copy');
                            console.log("openPocWindow: Copy command result:", copySuccess);
                        } catch(e) {
                            console.error('openPocWindow: Copy failed:', e);
                        }

                        pocWindow.document.body.removeChild(tempTextarea);

                        if (copySuccess) {
                            statusSpan.textContent = 'Copied to clipboard!';
                            statusSpan.style.display = 'inline';
                            setTimeout(function() {
                                statusSpan.style.display = 'none';
                            }, 2000);
                        } else {
                            alert('Copy failed. Please use the download link instead.');
                        }
                    });

                    controlBar.appendChild(copyButton);
                    controlBar.appendChild(statusSpan);
                    controlBar.appendChild(downloadLink);

                    if (pocWindow.document.body) {
                        pocWindow.document.body.insertBefore(controlBar, pocWindow.document.body.firstChild);
                        console.log("openPocWindow: Control bar added successfully");
                    } else {
                        console.error("openPocWindow: Document body not available");
                    }

                } catch (e) {
                    console.error("openPocWindow: Error adding copy button to POC window:", e);
                }
            });

            console.log("openPocWindow: Window creation complete");
        } catch (error) {
            console.error("openPocWindow: Error opening POC window:", error);
            alert('An error occurred while creating the POC window. See console for details.');
        }
    }

    if (typeof global !== 'undefined') {
        global.generatePocHtml = generatePocHtml;
        global.openPocWindow = openPocWindow;
    }

})(typeof window !== 'undefined' ? window : this);
