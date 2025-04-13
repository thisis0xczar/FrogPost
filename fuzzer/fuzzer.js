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
            this.originValidationChecks = [];
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

        initialize(messages, handlerCode, sinks = [], targetUrl = null, callbackUrl = null, originChecks = []) {
            this.messages = Array.isArray(messages) ? messages : [];
            this.handlerCode = handlerCode || '';
            this.targetUrl = targetUrl;
            this.callbackUrl = callbackUrl;
            this.originValidationChecks = Array.isArray(originChecks) ? originChecks : [];
            this.messageStructures = [];

            if (this.messages && this.messages.length > 0) {
                this.messages.forEach((msg) => {
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
                    const ctxMatch = sink.context.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/);
                    if (ctxMatch && ctxMatch[1]) {
                        targetProperty = ctxMatch[1];
                    }
                }
                return {
                    path: targetProperty,
                    fullPath: `event.data.${targetProperty}`,
                    sinkType: sink.type || sink.name || "unknown",
                    severity: sink.severity?.toLowerCase() || "high",
                };
            }).filter(p => p.path);

            if (this.messages && this.messages.length > 0) {
                for (const msg of this.messages) {
                    let msgData = msg.data !== undefined ? msg.data : msg;
                    let dataType = typeof msgData;
                    if (dataType === 'string') {
                        if (msgData.startsWith('{') && msgData.endsWith('}') || msgData.startsWith('[') && msgData.endsWith(']')) {
                            try {
                                msgData = JSON.parse(msgData);
                                dataType = typeof msgData;
                            } catch (e) {}
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
                    }
                }
            }

            if (this.messageStructures.length === 0 && this.vulnerablePaths.length > 0) {
                const defObj = { type: 'default_generated' };
                const firstPath = this.vulnerablePaths[0]?.path || "message";
                defObj[firstPath] = `Default Content for ${firstPath}`;
                this.messageStructures.push({
                    type: 'object',
                    original: defObj,
                    fields: this.extractAllFields(defObj),
                    fieldTypes: this.getFieldTypes(defObj)
                });
            }
            if (callbackUrl) {
                this.callbackUrl = callbackUrl;
            }
            return this;
        }

        initializeWithConfig(config = {}) {
            this.fuzzerConfig = { ...this.fuzzerConfig, ...config };
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
            if (!this.isPlainObject(obj)) {
                return result;
            }
            for (const key in obj) {
                if (!obj.hasOwnProperty(key)) {
                    continue;
                }
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
            if (!this.isPlainObject(obj)) {
                return fields;
            }
            for (const key in obj) {
                if (!obj.hasOwnProperty(key)) {
                    continue;
                }
                const fieldPath = prefix ? `${prefix}.${key}` : key;
                fields.push(fieldPath);
                if (this.isPlainObject(obj[key])) {
                    fields.push(...this.extractAllFields(obj[key], fieldPath));
                }
            }
            return fields;
        }

        runPayloadGeneration() {
            this.payloads = [];
            return new Promise((resolve) => {
                chrome.storage.session.get(['customXssPayloads', 'callback_url'], (result) => {
                    const customPayloads = result.customXssPayloads || [];
                    const callbackUrl = result.callback_url || this.callbackUrl;
                    if (callbackUrl) {
                        this.callbackUrl = callbackUrl;
                    }

                    if (customPayloads.length > 0) {
                        if (this.messageStructures.length > 0) {
                            for (const structure of this.messageStructures) {
                                if (!structure || !structure.original) {
                                    continue;
                                }
                                if (structure.type === 'object') {
                                    const paths = this.vulnerablePaths.length > 0 ? this.vulnerablePaths.map(p => p.path) : (structure.pathsToFuzz || []).map(p => p.path);
                                    if (paths.length > 0) {
                                        for (const path of paths) {
                                            if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                                try {
                                                    const modMsg = JSON.parse(JSON.stringify(structure.original));
                                                    this.setNestedValue(modMsg, path, payload);
                                                    this.payloads.push({ type: 'custom-structured', payload: modMsg, targetPath: path, description: `Custom payload in structured message` });
                                                } catch (e) {}
                                            }
                                        }
                                    } else {
                                        const objCopy = JSON.parse(JSON.stringify(structure.original));
                                        const bestProp = this.findBestStringProperty(objCopy);
                                        if (bestProp) {
                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                                try {
                                                    const modMsg = JSON.parse(JSON.stringify(structure.original));
                                                    this.setNestedValue(modMsg, bestProp, payload);
                                                    this.payloads.push({ type: 'custom-auto-path', payload: modMsg, targetPath: bestProp, description: `Custom payload auto-targeting ${bestProp}` });
                                                } catch (e) {}
                                            }
                                        } else {
                                            for (const payload of customPayloads) {
                                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                                this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload (no suitable structure)' });
                                            }
                                        }
                                    }
                                } else if (structure.type === 'raw_string') {
                                    for (const payload of customPayloads) {
                                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                        this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload' });
                                    }
                                }
                            }
                        } else {
                            for (const payload of customPayloads) {
                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break;
                                this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload (no structures)' });
                            }
                        }
                        if (this.payloads.length === 0) {
                            customPayloads.forEach(p => {
                                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return;
                                this.payloads.push({ type: 'custom-raw', payload: p, description: 'Custom raw payload (fallback)' });
                            });
                        }
                        if (this.fuzzerConfig.enableCallbackFuzzing && this.callbackUrl) {
                            this.generateCallbackPayloads();
                        }
                        if (this.fuzzerConfig.enableOriginFuzzing) {
                            this.generateOriginFuzzingPayloads();
                        }
                    } else {
                        const allXssPayloads = window.FuzzingPayloads?.XSS || [];
                        const payloadList = allXssPayloads;
                        for (const structure of this.messageStructures) {
                            if (!structure || !structure.original) {
                                continue;
                            }
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
                        if (this.fuzzerConfig.forceMinimumPayloads && typeof this.fuzzerConfig.forceMinimumPayloads === 'number' && this.payloads.length < this.fuzzerConfig.forceMinimumPayloads) {
                            this.generateAdditionalPayloads(this.fuzzerConfig.forceMinimumPayloads - this.payloads.length, payloadList);
                        }
                    }
                    const typeStats = {};
                    this.payloads.forEach(p => {
                        const type = p.type || 'unknown';
                        typeStats[type] = (typeStats[type] || 0) + 1;
                    });
                    console.log(`[Fuzzer] Completed payload generation. Total: ${this.payloads.length}`);
                    Object.entries(typeStats).forEach(([type, count]) => {
                        console.log(`  - ${type}: ${count}`);
                    });
                    resolve(this.payloads);
                });
            });
        }

        findBestStringProperty(obj, path = '') {
            if (!obj || typeof obj !== 'object') {
                return null;
            }
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
                    if (result) {
                        return result;
                    }
                }
            }
            const keys = Object.keys(obj);
            if (keys.length > 0) {
                return path ? `${path}.${keys[0]}` : keys[0];
            }
            return null;
        }

        generateSmartObjectPayloads(structure, vulnerablePaths, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original || !vulnerablePaths || vulnerablePaths.length === 0 || !payloadList || payloadList.length === 0) {
                return;
            }
            const baseMessage = JSON.parse(JSON.stringify(structure.original));
            let count = 0;
            const maxPayloadsPerSink = Math.min(this.maxPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (vulnerablePaths.length || 1)));

            for (const vulnPath of vulnerablePaths) {
                let targetPath = vulnPath.path;
                if (targetPath === 'data' && vulnPath.fullPath && vulnPath.fullPath !== 'event.data') {
                    const dataPathMatch = vulnPath.fullPath.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/);
                    if (dataPathMatch && dataPathMatch[1]) {
                        targetPath = dataPathMatch[1];
                    }
                }
                if (!targetPath || targetPath === '') {
                    const stringFields = Object.entries(structure.fieldTypes || {}).filter(([, type]) => type === 'string').map(([field]) => field);
                    const suspiciousFields = stringFields.filter(field => /html|script|content|message|url|src/i.test(field));
                    targetPath = suspiciousFields[0] || stringFields[0];
                    if (!targetPath) {
                        continue;
                    }
                }
                let relevantPayloads = [];
                const sinkTypeLower = vulnPath.sinkType?.toLowerCase() || '';
                if (window.FuzzingPayloads.SINK_SPECIFIC) {
                    if (sinkTypeLower.includes('eval')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.eval || [];
                    else if (sinkTypeLower.includes('innerhtml')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.innerHTML || [];
                    else if (sinkTypeLower.includes('write')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.document_write || [];
                    else if (sinkTypeLower.includes('settimeout')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setTimeout || [];
                    else if (sinkTypeLower.includes('setinterval')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.setInterval || [];
                    else if (sinkTypeLower.includes('location') || sinkTypeLower.includes('href')) relevantPayloads = window.FuzzingPayloads.SINK_SPECIFIC.location_href || [];
                }
                if (!relevantPayloads.length) {
                    relevantPayloads = payloadList;
                }
                if (this.fuzzerConfig.randomizePayloadSelection) {
                    relevantPayloads = [...relevantPayloads].sort(() => 0.5 - Math.random());
                }
                const payloadsToUse = relevantPayloads.slice(0, maxPayloadsPerSink);

                for (const payload of payloadsToUse) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) {
                        return;
                    }
                    try {
                        const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                        this.setNestedValue(modifiedMessage, targetPath, payload);
                        this.payloads.push({
                            type: 'smart',
                            sinkType: vulnPath.sinkType,
                            targetPath: targetPath,
                            fullPath: vulnPath.fullPath,
                            payload: modifiedMessage,
                            severity: vulnPath.severity || 'high'
                        });
                        count++;
                    } catch (error) {}
                }
            }
        }

        generateDumbObjectPayloads(structure, payloadList) {
            if (!structure || structure.type !== 'object' || !structure.original || !payloadList || payloadList.length === 0 || !this.fuzzerConfig.enableDumbFuzzing) {
                return;
            }
            const baseMessage = JSON.parse(JSON.stringify(structure.original));
            const fields = this.extractAllFields(baseMessage);
            const stringFields = fields.filter(field => {
                let currentObj = baseMessage;
                const parts = field.split('.');
                try {
                    for (let i = 0; i < parts.length - 1; i++) {
                        if (currentObj[parts[i]] === undefined || currentObj[parts[i]] === null) return false;
                        currentObj = currentObj[parts[i]];
                    }
                    const lastPart = parts[parts.length - 1];
                    const value = currentObj[lastPart];
                    return typeof value === 'string' || value === null || value === undefined;
                } catch (e) { return false; }
            });
            const suspiciousPatterns = [ /html/i, /script/i, /content/i, /message/i, /url/i, /src/i, /href/i, /code/i, /exec/i, /eval/i, /callback/i, /function/i, /source/i, /target/i, /payload/i, /template/i, /markup/i, /auth/i, /token/i, /key/i, /secret/i, /pass/i, /user/i, /admin/i ];
            const prioritizedFields = stringFields.sort((a, b) => { const aIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(a)); const bIsSuspicious = suspiciousPatterns.some(pattern => pattern.test(b)); if (aIsSuspicious && !bIsSuspicious) return -1; if (!aIsSuspicious && bIsSuspicious) return 1; return 0; });
            const fieldsToFuzz = Math.min(prioritizedFields.length, 50);
            const payloadsPerField = Math.min(this.fuzzerConfig.dumbFuzzingPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (fieldsToFuzz || 1)));
            let totalPayloads = 0;

            for (let i = 0; i < prioritizedFields.length && i < fieldsToFuzz; i++) {
                const field = prioritizedFields[i];
                let selectedPayloads = payloadList;
                if (this.fuzzerConfig.randomizePayloadSelection) {
                    selectedPayloads = [...payloadList].sort(() => 0.5 - Math.random()).slice(0, payloadsPerField);
                } else {
                    selectedPayloads = payloadList.slice(0, payloadsPerField);
                }
                for (const payload of selectedPayloads) {
                    if (totalPayloads >= this.fuzzerConfig.maxTotalPayloads) {
                        return;
                    }
                    try {
                        const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                        this.setNestedValue(modifiedMessage, field, payload);
                        this.payloads.push({ type: 'dumb', field: field, targetPath: field, payload: modifiedMessage, severity: 'medium' });
                        totalPayloads++;
                    } catch (error) {}
                }
            }
        }

        generateRawStringPayloads(original, payloadList) {
            if (typeof original !== 'string' || !payloadList || payloadList.length === 0) {
                return;
            }
            const maxPayloadsForRawString = Math.min(this.maxPayloadsPerField, 30);
            let count = 0;
            const selectedPayloads = this.fuzzerConfig.randomizePayloadSelection ? [...payloadList].sort(() => 0.5 - Math.random()).slice(0, maxPayloadsForRawString) : payloadList.slice(0, maxPayloadsForRawString);
            for (const payload of selectedPayloads) {
                if (count >= this.fuzzerConfig.maxTotalPayloads) {
                    return;
                }
                this.payloads.push({ type: 'raw_string_replace', payload: payload, severity: 'high', isRawString: true, original: original });
                count++;
                if (count >= this.fuzzerConfig.maxTotalPayloads) {
                    return;
                }
                const injectionVariants = [`${payload}${original}`, `${original}${payload}`];
                if (original.length > 10) {
                    const mid = Math.floor(original.length / 2);
                    injectionVariants.push(original.substring(0, mid) + payload + original.substring(mid));
                }
                for (const injectedString of injectionVariants) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) {
                        return;
                    }
                    this.payloads.push({ type: `raw_string_inject`, payload: injectedString, severity: 'high', isRawString: true, original: original });
                    count++;
                }
            }
        }

        generateCallbackPayloads() {
            if (!this.callbackUrl || !window.FuzzingPayloads?.CALLBACK_URL) {
                return;
            }
            const callbackTemplates = window.FuzzingPayloads.CALLBACK_URL;
            for (const template of callbackTemplates) {
                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                    return;
                }
                const processedPayloadStr = template.replace(/%%CALLBACK_URL%%/g, this.callbackUrl);
                for (const structure of this.messageStructures) {
                    if (structure.type === 'object' && structure.original) {
                        const pathsToTarget = this.vulnerablePaths.length > 0 ? this.vulnerablePaths : Object.entries(structure.fieldTypes || {}).filter(([, type]) => type === 'string').slice(0, 5).map(([path]) => ({ path: path, sinkType: 'generic_string', severity: 'medium' }));
                        if (pathsToTarget.length === 0 && structure.fields?.length > 0) {
                            pathsToTarget.push({ path: structure.fields[0], sinkType: 'first_field', severity: 'low'});
                        }
                        for (const vulnPath of pathsToTarget) {
                            if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                                return;
                            }
                            try {
                                const targetPath = vulnPath.path;
                                if (!targetPath) {
                                    continue;
                                }
                                const modifiedMessage = JSON.parse(JSON.stringify(structure.original));
                                this.setNestedValue(modifiedMessage, targetPath, processedPayloadStr);
                                this.payloads.push({ type: 'callback_url_object', sinkType: vulnPath.sinkType, targetPath: targetPath, fullPath: vulnPath.fullPath, payload: modifiedMessage, severity: 'critical' });
                            } catch (error) {}
                        }
                    } else if (structure.type === 'raw_string') {
                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                            return;
                        }
                        this.payloads.push({ type: 'callback_url_raw', payload: processedPayloadStr, severity: 'critical', isRawString: true, original: structure.original });
                        if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                            return;
                        }
                        const combined = `${structure.original || ''}${processedPayloadStr}`;
                        this.payloads.push({ type: 'callback_url_combined', payload: combined, severity: 'critical', isRawString: true, original: structure.original });
                    }
                }
            }
        }

        generateOriginFuzzingPayloads() {
            if (!this.fuzzerConfig.enableOriginFuzzing) {
                return;
            }
            let generatedOrigins = new Set(['null', 'https://evil.com', 'data:text/html,foo', 'blob:http://localhost/123']);
            let targetOrigin = null;
            try {
                if(this.targetUrl) {
                    targetOrigin = new URL(this.targetUrl).origin;
                }
            } catch {}

            this.originValidationChecks.forEach(check => {
                if (check.type === 'Strict Equality' || check.type === 'Loose Equality') {
                    if (typeof check.value === 'string' && check.value.startsWith('http')) {
                        try {
                            const url = new URL(check.value);
                            generatedOrigins.add(url.origin);
                            generatedOrigins.add(`${url.protocol}//${url.hostname}:${url.port || (url.protocol==='https:'?443:80)}`);
                            generatedOrigins.add(`${url.protocol === 'https:' ? 'http:' : 'https:'}//${url.hostname}`);
                            generatedOrigins.add(`${url.origin}/`);
                            generatedOrigins.add(` ${url.origin}`);
                            if (url.hostname !== 'localhost') {
                                generatedOrigins.add(`${url.protocol}//sub.${url.hostname}`);
                            }
                        } catch {}
                    }
                } else if (check.type?.includes('Method Call') && typeof check.value === 'string') {
                    if (check.type.includes('endsWith')) {
                        generatedOrigins.add(`https://test${check.value}.evil.com`);
                    }
                    if (check.type.includes('startsWith')) {
                        generatedOrigins.add(`${check.value}.evil.com`);
                    }
                    if (check.type.includes('includes') || check.type.includes('indexOf')) {
                        generatedOrigins.add(`https://prefix-${check.value}-suffix.com`);
                    }
                } else if (check.type?.includes('Lookup') && check.value) {
                    generatedOrigins.add(`https://${check.value}.evil.com/`);
                }
            });
            if(targetOrigin) {
                generatedOrigins.add(targetOrigin);
            }

            for (const origin of generatedOrigins) {
                if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                    break;
                }
                let applied = false;
                for (const struct of this.messageStructures) {
                    if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) {
                        break;
                    }
                    if (struct.type === 'object' && struct.original) {
                        try {
                            const modMsg = JSON.parse(JSON.stringify(struct.original));
                            const originKeys = ['origin', 'senderOrigin', 'sourceOrigin'];
                            let keyFound = false;
                            for(const key of originKeys) {
                                if(modMsg.hasOwnProperty(key)) {
                                    this.setNestedValue(modMsg, key, origin);
                                    keyFound = true;
                                    break;
                                }
                            }
                            if(!keyFound) {
                                modMsg.origin = origin;
                            }
                            this.payloads.push({ type: 'origin_fuzzing', payload: modMsg, severity: 'medium', targetOriginAttempt: origin });
                            applied = true;
                        } catch {}
                    }
                }
                if (!applied) {
                    this.payloads.push({ type: 'origin_fuzzing_raw', payload: origin, severity: 'low', targetOriginAttempt: origin });
                }
            }
        }

        generatePrototypePollutionPayloads(structure) {
            if (!window.FuzzingPayloads?.PROTOTYPE_POLLUTION || !this.fuzzerConfig.enablePrototypePollution) {
                return;
            }
            const pollutionVectors = window.FuzzingPayloads.PROTOTYPE_POLLUTION;
            let count = 0;
            for (const s of this.messageStructures) {
                if (s.type === 'raw_string' || !s.original) {
                    continue;
                }
                const baseMessage = JSON.parse(JSON.stringify(s.original));
                for (const { field, value } of pollutionVectors) {
                    if (count >= this.fuzzerConfig.maxTotalPayloads) {
                        return;
                    }
                    const fuzzedMessage = JSON.parse(JSON.stringify(baseMessage));
                    try {
                        let pollutionTarget = fuzzedMessage;
                        let nestedKey = Object.keys(fuzzedMessage).find(k => this.isPlainObject(fuzzedMessage[k]));
                        if (nestedKey) {
                            pollutionTarget = fuzzedMessage[nestedKey];
                        } else {
                            if (!fuzzedMessage._pp_test_obj) {
                                fuzzedMessage._pp_test_obj = {};
                            }
                            pollutionTarget = fuzzedMessage._pp_test_obj;
                        }
                        this.setNestedValue(pollutionTarget, field, value);
                        this.payloads.push({ type: 'prototype_pollution', field: field, targetPath: field, payload: fuzzedMessage, severity: 'high' });
                        count++;
                    } catch (error) {
                        if (field.startsWith('__proto__')) {
                            try {
                                if (count >= this.fuzzerConfig.maxTotalPayloads) return;
                                const topLevelFuzzed = JSON.parse(JSON.stringify(baseMessage));
                                topLevelFuzzed[field] = value;
                                this.payloads.push({ type: 'prototype_pollution_direct', field: field, targetPath: field, payload: topLevelFuzzed, severity: 'high' });
                                count++;
                            } catch (directError) {}
                        }
                    }
                }
            }
        }

        generateAdditionalPayloads(count, payloadList) {
            if (!count || count <= 0 || !payloadList || payloadList.length === 0) {
                return;
            }
            for (const structure of this.messageStructures) {
                if (!structure || !structure.original) {
                    continue;
                }
                if (structure.type === 'object') {
                    const baseMessage = JSON.parse(JSON.stringify(structure.original));
                    const fields = this.extractAllFields(baseMessage);
                    const fieldCount = Math.min(fields.length, 10);
                    const selectedFields = fields.sort(() => 0.5 - Math.random()).slice(0, fieldCount);
                    const payloadsNeeded = Math.ceil(count / (fieldCount || 1));
                    const selectedPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, payloadsNeeded);
                    let additionalCount = 0;
                    for (const field of selectedFields) {
                        for (const payload of selectedPayloads) {
                            if (additionalCount >= count) return;
                            try {
                                const modifiedMessage = JSON.parse(JSON.stringify(baseMessage));
                                this.setNestedValue(modifiedMessage, field, payload);
                                this.payloads.push({ type: 'additional', field: field, targetPath: field, payload: modifiedMessage, severity: 'medium' });
                                additionalCount++;
                            } catch (error) {}
                        }
                    }
                } else if (structure.type === 'raw_string') {
                    const original = structure.original;
                    if (typeof original !== 'string') {
                        continue;
                    }
                    const payloadsNeeded = Math.min(count, 20);
                    const selectedPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, payloadsNeeded);
                    let additionalCount = 0;
                    for (const payload of selectedPayloads) {
                        if (additionalCount >= count) return;
                        this.payloads.push({ type: 'additional_raw', payload: payload, severity: 'medium', isRawString: true, original: original });
                        additionalCount++;
                    }
                }
            }
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
                    current[parseInt(lastPart, 10)] = value;
                } else if (!Array.isArray(current)) {
                    current[lastPart] = value;
                }
            }
        }
    }

    global.SinkAwarePostMessageFuzzer = class SinkAwarePostMessageFuzzer {
        constructor(messages, handlerCode, sinks, originChecks = []) {
            this.messages = Array.isArray(messages) ? messages : [];
            this.handlerCode = handlerCode || '';
            this.sinks = Array.isArray(sinks) ? sinks : [];
            this.config = {
                messages: this.messages,
                handler: this.handlerCode,
                sinks: this.sinks,
                originValidationChecks: originChecks
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
                return;
            }
            const payloadsToExecute = this.generatePayloads();
            if (payloadsToExecute.length > 0) {
                this._onCompleteCallback = onCompleteCallback;
                this.executeFuzzing(payloadsToExecute);
            } else {
                if (typeof onCompleteCallback === 'function') {
                    onCompleteCallback();
                }
                if(typeof updateStatus === 'function') {
                    updateStatus('Error: No payloads.', true);
                }
            }
        }

        stop() {
            if (this.payloadIntervalId) {
                clearInterval(this.payloadIntervalId);
                this.payloadIntervalId = null;
            }
            if (this.isExecutingPayloads) {
                this.isExecutingPayloads = false;
                if (typeof this._onCompleteCallback === 'function') {
                    this._onCompleteCallback(true);
                }
            }
        }

        generatePayloads() {
            let basePayloads = [];
            let ranFallback = false;

            if (this.config?.payloads?.length > 0) {
                basePayloads = this.config.payloads;
            } else if (this.config?.traceData?.details?.payloads?.length > 0) {
                basePayloads = this.config.traceData.details.payloads;
            } else if (this.config?.traceData?.payloads?.length > 0) {
                basePayloads = this.config.traceData.payloads;
            }

            if (basePayloads.length === 0) {
                ranFallback = true;
                this.fuzzer.initialize(
                    this.config?.messages || [],
                    this.config?.handler || '',
                    this.config?.sinks || [],
                    this.config?.target,
                    this.config?.callbackUrl,
                    this.config?.originValidationChecks || []
                );
                if (this.config?.fuzzerOptions) {
                    this.fuzzer.initializeWithConfig(this.config.fuzzerOptions);
                }
                this.fuzzer.runPayloadGeneration();
                basePayloads = this.fuzzer.payloads;
            }
            return basePayloads;
        }

        executeFuzzing(payloads) {
            if (!payloads || payloads.length === 0) {
                this.isExecutingPayloads = false;
                if (typeof this._onCompleteCallback === 'function') {
                    this._onCompleteCallback();
                }
                return;
            }
            if (this.isExecutingPayloads) {
                return;
            }
            this.isExecutingPayloads = true;
            const sentPayloads = new Set();
            let messageIndex = 0;
            const iframe = document.getElementById('targetFrame');
            if (!iframe?.contentWindow) {
                this.isExecutingPayloads = false;
                if(typeof updateStatus === 'function') {
                    updateStatus('Error: Target iframe missing.', true);
                }
                if (typeof this._onCompleteCallback === 'function') {
                    this._onCompleteCallback();
                }
                return;
            }
            if(typeof updateStatus === 'function') {
                updateStatus(`Executing ${payloads.length} payloads... (0%)`);
            }
            if (this.payloadIntervalId) {
                clearInterval(this.payloadIntervalId);
            }

            this.payloadIntervalId = setInterval(() => {
                if (!this.isExecutingPayloads || !iframe?.contentWindow || messageIndex >= payloads.length) {
                    if(typeof updateStatus === 'function' && this.isExecutingPayloads) {
                        updateStatus(`Finished. Sent ${messageIndex} payloads.`);
                    }
                    this.stop();
                    return;
                }

                const progress = Math.round(((messageIndex + 1) / payloads.length) * 100);
                if(typeof updateStatus === 'function') {
                    updateStatus(`Executing payload ${messageIndex + 1}/${payloads.length} (${progress}%)`);
                }

                const fuzzerPayload = payloads[messageIndex];
                messageIndex++;

                try {
                    const payloadId = typeof fuzzerPayload?.payload === 'string'
                        ? `${fuzzerPayload.type || '?'}-${fuzzerPayload.payload.substring(0, 30)}`
                        : `${fuzzerPayload?.type || '?'}-${messageIndex}`;

                    if (sentPayloads.has(payloadId)) {
                        return;
                    }
                    sentPayloads.add(payloadId);

                    let payloadToSend;
                    const rawTypes = ['ast-raw', 'raw_string_replace', 'raw_string_inject', 'additional_raw', 'callback_url_raw', 'callback_url_combined', 'origin_fuzzing_raw'];

                    if (fuzzerPayload?.isRawString || rawTypes.includes(fuzzerPayload?.type)) {
                        payloadToSend = fuzzerPayload.payload;
                    } else if (fuzzerPayload?.payload !== undefined) {
                        payloadToSend = fuzzerPayload.payload;
                    } else {
                        payloadToSend = fuzzerPayload;
                    }

                    if (payloadToSend === undefined || payloadToSend === null) {
                        return;
                    }

                    const processedPayload = this.replaceJwtTokens(payloadToSend);

                    if (typeof window.sendToFrame === 'function') {
                        window.sendToFrame(processedPayload);
                    } else {
                        iframe.contentWindow.postMessage(processedPayload, '*');
                    }
                } catch (error) {
                    console.error(`[Fuzzer] Error sending payload index ${messageIndex - 1}:`, error);
                }
            }, 200);
        }

        replaceJwtTokens(payload) {
            if (typeof payload === 'string') {
                return payload.replace(JWT_REGEX, ADMIN_JWT);
            }
            if (!payload || typeof payload !== 'object') {
                return payload;
            }
            let clonedPayload;
            try {
                if (typeof structuredClone === 'function') {
                    clonedPayload = structuredClone(payload);
                } else {
                    clonedPayload = JSON.parse(JSON.stringify(payload));
                }
            } catch (error) {
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
            if (!config?.target) {
                if(typeof updateStatus==='function') {
                    updateStatus('Error: Invalid config.', true);
                }
                return null;
            }
            let sinks = config.sinks || config.traceData?.vulnerabilities || config.traceData?.details?.sinks || [];
            let originChecks = config.originValidationChecks || config.traceData?.details?.originValidationChecks || [];
            const fuzzerInstance = new SinkAwarePostMessageFuzzer(config.messages || [], config.handler || "", sinks, originChecks);
            fuzzerInstance.target = config.target;
            fuzzerInstance.callbackUrl = config.callbackUrl;
            fuzzerInstance.config = config;
            fuzzerInstance.reportData = config.traceData || null;
            if (fuzzerInstance.fuzzer && config.fuzzerOptions) {
                fuzzerInstance.fuzzer.initializeWithConfig(config.fuzzerOptions);
            }
            return fuzzerInstance;
        }
    }

    global.ImprovedMessageFuzzer = ImprovedMessageFuzzer;
    global.SinkAwarePostMessageFuzzer = SinkAwarePostMessageFuzzer;

    function generatePocHtml(targetUrl, payloads) {
        if (!targetUrl) {
            return '<!DOCTYPE html><html><body><h1>Error: Target URL missing.</h1></body></html>';
        }
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
            validPayloads = [];
        }
        if (validPayloads.length === 0) {
            return '<!DOCTYPE html><html><body><h1>Error: No valid payloads.</h1></body></html>';
        }
        const escapeHTML = window.escapeHTML || function(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');};
        try {
            const safeTargetUrl = escapeHTML(targetUrl);
            let serializedPayloadsBase64;
            try {
                serializedPayloadsBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(validPayloads))));
            } catch (e) {
                serializedPayloadsBase64 = "";
            }
            const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>FrogPost POC: ${safeTargetUrl}</title><style>body{font-family:sans-serif;margin:20px;}iframe{width:100%;height:60vh;border:1px solid #ccc;}button{padding:8px 15px;}pre{background:#eee;padding:10px;overflow:auto;max-height:200px;}</style></head><body><h1>FrogPost POC</h1><p>Target: <code>${safeTargetUrl}</code></p><button id="startPocButton" disabled>Send Payloads</button><div id="status">Status: Idle</div><pre id="errorContainer" style="color:red;display:none;"></pre><pre id="responseLog"></pre><iframe id="pocTargetFrame" src="${safeTargetUrl}" sandbox="allow-scripts allow-modals allow-same-origin allow-popups allow-forms"></iframe><script>let pocPayloads=[],targetFrame=document.getElementById('pocTargetFrame'),startButton=document.getElementById('startPocButton'),statusDiv=document.getElementById('status'),errorContainer=document.getElementById('errorContainer'),responseLog=document.getElementById('responseLog'),payloadIntervalId=null,currentPayloadIndex=0;function updateStatus(m){if(statusDiv)statusDiv.textContent='Status: '+m}function showError(m,e){if(!errorContainer)return;errorContainer.textContent=m+(e?'\\n'+e.toString():'');errorContainer.style.display='block'}function logResponse(d,fromTarget=false){if(!responseLog)return;const entry=document.createElement('div');let content='';try{content=typeof d==='object'?JSON.stringify(d,null,2):String(d)}catch(e){content='Error displaying data'}entry.textContent=(fromTarget?'← ':'→ ')+content;responseLog.appendChild(entry);responseLog.scrollTop=responseLog.scrollHeight}function initializePOC(){try{const b64="${serializedPayloadsBase64}";if(!b64)throw new Error("No payload data.");const json=decodeURIComponent(escape(atob(b64)));pocPayloads=JSON.parse(json);if(!Array.isArray(pocPayloads)||pocPayloads.length===0)throw new Error("Invalid/empty payloads.");if(startButton){startButton.textContent='Send Payloads ('+pocPayloads.length+')';startButton.disabled=false}updateStatus('Ready ('+pocPayloads.length+' payloads).')}catch(e){console.error("POC Init Error:",e);updateStatus("Error loading payloads.");showError("Failed to init payloads",e);if(startButton)startButton.disabled=true}}function sendPayloads(){if(!targetFrame||!targetFrame.contentWindow){updateStatus('Error: Target frame missing.');showError("Target frame missing");if(startButton)startButton.disabled=false;return}if(!pocPayloads||pocPayloads.length===0){updateStatus('No payloads.');showError("No payloads");if(startButton)startButton.disabled=false;return}errorContainer.style.display='none';if(startButton)startButton.disabled=true;updateStatus('Sending 1/'+pocPayloads.length+'...');currentPayloadIndex=0;if(payloadIntervalId)clearInterval(payloadIntervalId);function sendSingle(){if(currentPayloadIndex>=pocPayloads.length){clearInterval(payloadIntervalId);payloadIntervalId=null;updateStatus('Finished sending '+pocPayloads.length+' payloads.');if(startButton)startButton.disabled=false;return}const item=pocPayloads[currentPayloadIndex];try{const data=(typeof item==='object'&&item!==null&&item.payload!==undefined)?item.payload:item;logResponse(data,false);if(targetFrame&&targetFrame.contentWindow)targetFrame.contentWindow.postMessage(data,'*');else throw new Error("Target frame gone")}catch(e){console.error('POC Send Error:',e);showError('Error sending #'+(currentPayloadIndex+1),e)}currentPayloadIndex++;if(currentPayloadIndex<pocPayloads.length)updateStatus('Sending '+(currentPayloadIndex+1)+'/'+pocPayloads.length+'...')}sendSingle();payloadIntervalId=setInterval(sendSingle,250)}window.addEventListener('message',function(ev){if(targetFrame&&ev.source===targetFrame.contentWindow){logResponse(ev.data,true)}});if(startButton)startButton.addEventListener('click',sendPayloads);initializePOC();</script></body></html>`;
            return html;
        } catch (error) {
            return `<!DOCTYPE html><html><body><h1>Error generating POC</h1><p>${escapeHTML(error.message)}</p></body></html>`;
        }
    }

    function openPocWindow(htmlContent) {
        if (!htmlContent) {
            alert('Error: No HTML content.');
            return;
        }
        try {
            const pocWindow = window.open('about:blank', 'FrogPostPOC', 'width=1000,height=800,resizable=yes,scrollbars=yes');
            if (!pocWindow) {
                alert('Failed to open POC window. Check pop-up blocker.');
                return;
            }
            pocWindow.document.open();
            pocWindow.document.write(htmlContent);
            pocWindow.document.close();
        } catch (error) {
            alert('Error opening POC window.');
        }
    }

    if (typeof global !== 'undefined') {
        global.generatePocHtml = generatePocHtml;
        global.openPocWindow = openPocWindow;
    }

})(typeof window !== 'undefined' ? window : this);
