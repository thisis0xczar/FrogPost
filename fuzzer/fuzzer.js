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
            this.payloads = []; this.messageStructures = []; this.vulnerablePaths = []; this.maxPayloadsPerField = 30; this.callbackUrl = null; this.originValidationChecks = [];
            this.fuzzerConfig = { enableSmartFuzzing: true, enableDumbFuzzing: true, enablePrototypePollution: true, enableOriginFuzzing: true, enableCallbackFuzzing: true, maxTotalPayloads: 2000, randomizePayloadSelection: true, dumbFuzzingPayloadsPerField: 30, payloadDistribution: { xss: 0.6, callback: 0.2, pollution: 0.1, origin: 0.1 } };
        }
        isPlainObject(obj) { if (typeof obj !== 'object' || obj === null) return false; let proto = Object.getPrototypeOf(obj); if (proto === null) return true; let baseProto = proto; while (Object.getPrototypeOf(baseProto) !== null) baseProto = Object.getPrototypeOf(baseProto); return proto === baseProto; }

        initialize(messages, handlerCode, sinks = [], targetUrl = null, callbackUrl = null, originChecks = []) {
            this.messages = Array.isArray(messages) ? messages : []; this.handlerCode = handlerCode || ''; this.targetUrl = targetUrl; this.callbackUrl = callbackUrl; this.originValidationChecks = Array.isArray(originChecks) ? originChecks : []; this.messageStructures = [];
            if (this.messages?.length > 0) this.messages.forEach((msg) => { let data = msg.data !== undefined ? msg.data : msg; });
            this.vulnerablePaths = (sinks || []).map(sink => { let targetProperty = "message"; if (sink.property) targetProperty = sink.property; else if (sink.path && sink.path !== '(root)') targetProperty = sink.path; else if (sink.context && typeof sink.context === 'string') { const ctxMatch = sink.context.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/); if (ctxMatch?.[1]) targetProperty = ctxMatch[1]; } return { path: targetProperty, fullPath: `event.data.${targetProperty}`, sinkType: sink.type || sink.name || "unknown", severity: sink.severity?.toLowerCase() || "high", }; }).filter(p => p.path);
            if (this.messages?.length > 0) { for (const msg of this.messages) { let msgData = msg.data !== undefined ? msg.data : msg; let dataType = typeof msgData; if (dataType === 'string') { if (msgData.startsWith('{') && msgData.endsWith('}') || msgData.startsWith('[') && msgData.endsWith(']')) try { msgData = JSON.parse(msgData); dataType = typeof msgData; } catch {} } if (this.isPlainObject(msgData)) this.messageStructures.push({ type: 'object', original: JSON.parse(JSON.stringify(msgData)), fields: this.extractAllFields(msgData), fieldTypes: this.getFieldTypes(msgData) }); else if (dataType === 'string') this.messageStructures.push({ type: 'raw_string', original: msgData }); } }
            if (this.messageStructures.length === 0 && this.vulnerablePaths.length > 0) { const defObj = { type: 'default_generated' }; const firstPath = this.vulnerablePaths[0]?.path || "message"; defObj[firstPath] = `Default Content for ${firstPath}`; this.messageStructures.push({ type: 'object', original: defObj, fields: this.extractAllFields(defObj), fieldTypes: this.getFieldTypes(defObj) }); }
            if (callbackUrl) this.callbackUrl = callbackUrl; return this;
        }

        initializeWithConfig(config = {}) { this.fuzzerConfig = { ...this.fuzzerConfig, ...config }; if (config.maxPayloadsPerField) this.maxPayloadsPerField = config.maxPayloadsPerField; if (config.forceMinimumPayloads && typeof config.forceMinimumPayloads === 'number') this.fuzzerConfig.forceMinimumPayloads = config.forceMinimumPayloads; return this; }
        getFieldTypes(obj, prefix = '') { const res = {}; if (!this.isPlainObject(obj)) return res; for (const key in obj) { if (!obj.hasOwnProperty(key)) continue; const p = prefix ? `${prefix}.${key}` : key; res[p] = typeof obj[key]; if (this.isPlainObject(obj[key])) Object.assign(res, this.getFieldTypes(obj[key], p)); } return res; }
        extractAllFields(obj, prefix = '') { const fields = []; if (!this.isPlainObject(obj)) return fields; for (const key in obj) { if (!obj.hasOwnProperty(key)) continue; const p = prefix ? `${prefix}.${key}` : key; fields.push(p); if (this.isPlainObject(obj[key])) fields.push(...this.extractAllFields(obj[key], p)); } return fields; }

        runPayloadGeneration() {
            this.payloads = [];
            return new Promise((resolve) => {
                chrome.storage.session.get(['customXssPayloads', 'callback_url'], (result) => {
                    const customPayloads = result.customXssPayloads || []; const callbackUrl = result.callback_url || this.callbackUrl; if (callbackUrl) this.callbackUrl = callbackUrl;
                    if (customPayloads.length > 0) {
                        if (this.messageStructures.length > 0) { for (const struct of this.messageStructures) { if (!struct || !struct.original) continue; if (struct.type === 'object') { const paths = this.vulnerablePaths.length > 0 ? this.vulnerablePaths.map(p => p.path) : (struct.pathsToFuzz || []).map(p => p.path); if (paths.length > 0) { for (const path of paths) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; for (const payload of customPayloads) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; try { const modMsg = JSON.parse(JSON.stringify(struct.original)); this.setNestedValue(modMsg, path, payload); this.payloads.push({ type: 'custom-structured', payload: modMsg, targetPath: path, description: `Custom payload in structured message` }); } catch (e) {} } } } else { const objCopy = JSON.parse(JSON.stringify(struct.original)); const bestProp = this.findBestStringProperty(objCopy); if (bestProp) { for (const payload of customPayloads) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; try { const modMsg = JSON.parse(JSON.stringify(struct.original)); this.setNestedValue(modMsg, bestProp, payload); this.payloads.push({ type: 'custom-auto-path', payload: modMsg, targetPath: bestProp, description: `Custom payload auto-targeting ${bestProp}` }); } catch (e) {} } } else { for (const payload of customPayloads) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload (no suitable structure)' }); } } } } else if (struct.type === 'raw_string') { for (const payload of customPayloads) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload' }); } } } }
                        else { for (const payload of customPayloads) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; this.payloads.push({ type: 'custom-raw', payload: payload, description: 'Custom raw payload (no structures)' }); } }
                        if (this.payloads.length === 0) customPayloads.forEach(p => { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: 'custom-raw', payload: p, description: 'Custom raw payload (fallback)' }); });
                        if (this.fuzzerConfig.enableCallbackFuzzing && this.callbackUrl) this.generateCallbackPayloads();
                        if (this.fuzzerConfig.enableOriginFuzzing) this.generateOriginFuzzingPayloads();
                    } else {
                        const allXssPayloads = window.FuzzingPayloads?.XSS || [];
                        const payloadList = allXssPayloads;
                        for (const struct of this.messageStructures) { if (!struct || !struct.original) continue; if (struct.type === 'object') { if (this.fuzzerConfig.enableSmartFuzzing && this.vulnerablePaths && this.vulnerablePaths.length > 0) this.generateSmartObjectPayloads(struct, this.vulnerablePaths, payloadList); if (this.fuzzerConfig.enableDumbFuzzing) this.generateDumbObjectPayloads(struct, payloadList); if (this.fuzzerConfig.enablePrototypePollution) this.generatePrototypePollutionPayloads(struct); } else if (struct.type === 'raw_string') this.generateRawStringPayloads(struct.original, payloadList); }
                        if (this.fuzzerConfig.enableCallbackFuzzing && this.callbackUrl) this.generateCallbackPayloads();
                        if (this.fuzzerConfig.enableOriginFuzzing) this.generateOriginFuzzingPayloads();
                        if (this.fuzzerConfig.forceMinimumPayloads && typeof this.fuzzerConfig.forceMinimumPayloads === 'number' && this.payloads.length < this.fuzzerConfig.forceMinimumPayloads) this.generateAdditionalPayloads(this.fuzzerConfig.forceMinimumPayloads - this.payloads.length, payloadList);
                    }
                    const typeStats = {}; this.payloads.forEach(p => { const type = p.type || 'unknown'; typeStats[type] = (typeStats[type] || 0) + 1; });
                    console.log(`[Fuzzer] Completed payload generation. Total: ${this.payloads.length}`); Object.entries(typeStats).forEach(([type, count]) => console.log(`  - ${type}: ${count}`)); resolve(this.payloads);
                });
            });
        }

        findBestStringProperty(obj, path = '') { if (!obj || typeof obj !== 'object') return null; const htmlProps = ['html', 'content', 'message', 'text', 'body', 'data', 'value', 'src', 'url', 'href']; for (const prop of htmlProps) if (typeof obj[prop] === 'string') return path ? `${path}.${prop}` : prop; for (const key in obj) if (typeof obj[key] === 'string') return path ? `${path}.${key}` : key; for (const key in obj) { if (obj[key] && typeof obj[key] === 'object') { const nestedPath = path ? `${path}.${key}` : key; const res = this.findBestStringProperty(obj[key], nestedPath); if (res) return res; } } const keys = Object.keys(obj); return keys.length > 0 ? (path ? `${path}.${keys[0]}` : keys[0]) : null; }
        generateSmartObjectPayloads(struct, vulnPaths, payloadList) { if (!struct || struct.type !== 'object' || !struct.original || !vulnPaths || vulnPaths.length === 0 || !payloadList || payloadList.length === 0) return; const base = JSON.parse(JSON.stringify(struct.original)); let count = 0; const maxPerSink = Math.min(this.maxPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (vulnPaths.length || 1))); for (const vuln of vulnPaths) { let target = vuln.path; if (target === 'data' && vuln.fullPath && vuln.fullPath !== 'event.data') { const m = vuln.fullPath.match(/(?:event|e|msg|message)\.data\.([a-zA-Z0-9_$.[\]]+)/); if (m?.[1]) target = m[1]; } if (!target || target === '') { const strFields = Object.entries(struct.fieldTypes || {}).filter(([,t])=>t==='string').map(([f])=>f); const susFields=strFields.filter(f=>/html|script|content|message|url|src/i.test(f)); target=susFields[0]||strFields[0]; if(!target)continue; } let relPayloads=[]; const sinkType=vuln.sinkType?.toLowerCase()||''; if(window.FuzzingPayloads.SINK_SPECIFIC){ if(sinkType.includes('eval'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.eval||[]; else if(sinkType.includes('innerhtml'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.innerHTML||[]; else if(sinkType.includes('write'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.document_write||[]; else if(sinkType.includes('settimeout'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.setTimeout||[]; else if(sinkType.includes('setinterval'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.setInterval||[]; else if(sinkType.includes('location')||sinkType.includes('href'))relPayloads=window.FuzzingPayloads.SINK_SPECIFIC.location_href||[];} if(!relPayloads.length)relPayloads=payloadList; if(this.fuzzerConfig.randomizePayloadSelection)relPayloads=[...relPayloads].sort(()=>0.5-Math.random()); const usePayloads=relPayloads.slice(0,maxPerSink); for(const p of usePayloads){if(count>=this.fuzzerConfig.maxTotalPayloads)return; try{const modMsg=JSON.parse(JSON.stringify(base)); this.setNestedValue(modMsg,target,p); this.payloads.push({type:'smart',sinkType:vuln.sinkType,targetPath:target,fullPath:vuln.fullPath,payload:modMsg,severity:vuln.severity||'high'}); count++;}catch{}} } }
        generateDumbObjectPayloads(struct, payloadList) { if (!struct || struct.type !== 'object' || !struct.original || !payloadList || payloadList.length === 0 || !this.fuzzerConfig.enableDumbFuzzing) return; const base = JSON.parse(JSON.stringify(struct.original)); const fields = this.extractAllFields(base); const strFields = fields.filter(f => { let curr=base; const parts=f.split('.'); try{for(let i=0;i<parts.length-1;i++){if(curr[parts[i]]===undefined||curr[parts[i]]===null)return false;curr=curr[parts[i]];}const last=parts[parts.length-1];const val=curr[last]; return typeof val==='string'||val===null||val===undefined;}catch{return false;} }); const susPats = [/html/i,/script/i,/content/i,/message/i,/url/i,/src/i,/href/i,/code/i,/exec/i,/eval/i,/callback/i,/function/i,/source/i,/target/i,/payload/i,/template/i,/markup/i,/auth/i,/token/i,/key/i,/secret/i,/pass/i,/user/i,/admin/i]; const priFields = strFields.sort((a,b)=>{const aSus=susPats.some(p=>p.test(a));const bSus=susPats.some(p=>p.test(b));return aSus&&!bSus?-1:!aSus&&bSus?1:0;}); const fieldsFuzz = Math.min(priFields.length, 50); const perField = Math.min(this.fuzzerConfig.dumbFuzzingPayloadsPerField, Math.floor(this.fuzzerConfig.maxTotalPayloads / (fieldsFuzz || 1))); let total = 0; for (let i=0; i<priFields.length && i<fieldsFuzz; i++) { const field = priFields[i]; let selPayloads = this.fuzzerConfig.randomizePayloadSelection ? [...payloadList].sort(()=>0.5-Math.random()).slice(0,perField) : payloadList.slice(0,perField); for (const p of selPayloads) { if (total >= this.fuzzerConfig.maxTotalPayloads) return; try { const modMsg=JSON.parse(JSON.stringify(base)); this.setNestedValue(modMsg, field, p); this.payloads.push({ type: 'dumb', field: field, targetPath: field, payload: modMsg, severity: 'medium' }); total++; } catch {} } } }
        generateRawStringPayloads(orig, payloadList) { if (typeof orig !== 'string' || !payloadList || payloadList.length === 0) return; const max = Math.min(this.maxPayloadsPerField, 30); let count = 0; const selPayloads = this.fuzzerConfig.randomizePayloadSelection ? [...payloadList].sort(()=>0.5-Math.random()).slice(0, max) : payloadList.slice(0, max); for (const p of selPayloads) { if (count >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: 'raw_string_replace', payload: p, severity: 'high', isRawString: true, original: orig }); count++; if (count >= this.fuzzerConfig.maxTotalPayloads) return; const variants = [`${p}${orig}`, `${orig}${p}`]; if (orig.length > 10) { const mid=Math.floor(orig.length/2); variants.push(orig.substring(0,mid)+p+orig.substring(mid)); } for (const inj of variants) { if (count >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: `raw_string_inject`, payload: inj, severity: 'high', isRawString: true, original: orig }); count++; } } }
        generateCallbackPayloads() { if (!this.callbackUrl || !window.FuzzingPayloads?.CALLBACK_URL) return; const templates = window.FuzzingPayloads.CALLBACK_URL; for (const tmpl of templates) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; const pStr = tmpl.replace(/%%CALLBACK_URL%%/g, this.callbackUrl); for (const struct of this.messageStructures) { if (struct.type === 'object' && struct.original) { const paths = this.vulnerablePaths.length>0?this.vulnerablePaths:Object.entries(struct.fieldTypes||{}).filter(([,t])=>t==='string').slice(0,5).map(([p])=>({path:p,sinkType:'generic_string',severity:'medium'})); if (paths.length===0&&struct.fields?.length>0) paths.push({path:struct.fields[0],sinkType:'first_field',severity:'low'}); for (const vuln of paths) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; try { const target = vuln.path; if (!target) continue; const modMsg = JSON.parse(JSON.stringify(struct.original)); this.setNestedValue(modMsg, target, pStr); this.payloads.push({ type: 'callback_url_object', sinkType: vuln.sinkType, targetPath: target, fullPath: vuln.fullPath, payload: modMsg, severity: 'critical' }); } catch {} } } else if (struct.type === 'raw_string') { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: 'callback_url_raw', payload: pStr, severity: 'critical', isRawString: true, original: struct.original }); if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) return; this.payloads.push({ type: 'callback_url_combined', payload: `${struct.original||''}${pStr}`, severity: 'critical', isRawString: true, original: struct.original }); } } } }
        generateOriginFuzzingPayloads() { if (!this.fuzzerConfig.enableOriginFuzzing) return; let genOrigins = new Set(['null', 'https://evil.com', 'data:text/html,foo', 'blob:http://localhost/123']); let targetOrigin = null; try { if(this.targetUrl) targetOrigin = new URL(this.targetUrl).origin; } catch {} this.originValidationChecks.forEach(check => { if ((check.type==='Strict Equality'||check.type==='Loose Equality') && typeof check.value==='string' && check.value.startsWith('http')) { try { const url=new URL(check.value); genOrigins.add(url.origin); genOrigins.add(`${url.protocol}//${url.hostname}:${url.port||(url.protocol==='https:'?443:80)}`); genOrigins.add(`${url.protocol==='https:'?'http:':'https:'}//${url.hostname}`); genOrigins.add(`${url.origin}/`); genOrigins.add(` ${url.origin}`); if(url.hostname!=='localhost') genOrigins.add(`${url.protocol}//sub.${url.hostname}`); } catch {} } else if (check.type?.includes('Method Call') && typeof check.value === 'string') { if (check.type.includes('endsWith')) genOrigins.add(`https://test${check.value}.evil.com`); if (check.type.includes('startsWith')) genOrigins.add(`${check.value}.evil.com`); if (check.type.includes('includes')||check.type.includes('indexOf')) genOrigins.add(`https://prefix-${check.value}-suffix.com`); } else if (check.type?.includes('Lookup') && check.value) { genOrigins.add(`https://${check.value}.evil.com/`); } }); if(targetOrigin) genOrigins.add(targetOrigin); for (const origin of genOrigins) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; let applied = false; for (const struct of this.messageStructures) { if (this.payloads.length >= this.fuzzerConfig.maxTotalPayloads) break; if (struct.type==='object'&&struct.original) { try { const modMsg=JSON.parse(JSON.stringify(struct.original)); const keys=['origin','senderOrigin','sourceOrigin']; let found=false; for(const k of keys){if(modMsg.hasOwnProperty(k)){this.setNestedValue(modMsg,k,origin);found=true;break;}} if(!found)modMsg.origin=origin; this.payloads.push({type:'origin_fuzzing',payload:modMsg,severity:'medium',targetOriginAttempt:origin}); applied=true; } catch {} } } if (!applied) { this.payloads.push({type:'origin_fuzzing_raw',payload:origin,severity:'low',targetOriginAttempt:origin}); } } }
        generatePrototypePollutionPayloads(structure) { if (!window.FuzzingPayloads?.PROTOTYPE_POLLUTION || !this.fuzzerConfig.enablePrototypePollution) return; const vectors = window.FuzzingPayloads.PROTOTYPE_POLLUTION; let count = 0; for (const s of this.messageStructures) { if (s.type === 'raw_string' || !s.original) continue; const base = JSON.parse(JSON.stringify(s.original)); for (const { field, value } of vectors) { if (count >= this.fuzzerConfig.maxTotalPayloads) return; const fuzzed = JSON.parse(JSON.stringify(base)); try { let target = fuzzed; let nested = Object.keys(fuzzed).find(k => this.isPlainObject(fuzzed[k])); if (nested) target = fuzzed[nested]; else { if (!fuzzed._pp_test_obj) fuzzed._pp_test_obj = {}; target = fuzzed._pp_test_obj; } this.setNestedValue(target, field, value); this.payloads.push({ type: 'prototype_pollution', field: field, targetPath: field, payload: fuzzed, severity: 'high' }); count++; } catch { if (field.startsWith('__proto__')) { try { if (count >= this.fuzzerConfig.maxTotalPayloads) return; const top = JSON.parse(JSON.stringify(base)); top[field] = value; this.payloads.push({ type: 'prototype_pollution_direct', field: field, targetPath: field, payload: top, severity: 'high' }); count++; } catch {} } } } } }
        generateAdditionalPayloads(count, payloadList) { if (!count || count <= 0 || !payloadList || payloadList.length === 0) return; for (const struct of this.messageStructures) { if (!struct || !struct.original) continue; if (struct.type === 'object') { const base = JSON.parse(JSON.stringify(struct.original)); const fields = this.extractAllFields(base); const fieldCount = Math.min(fields.length, 10); const selFields = fields.sort(() => 0.5 - Math.random()).slice(0, fieldCount); const needed = Math.ceil(count / (fieldCount || 1)); const selPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, needed); let addCount = 0; for (const field of selFields) { for (const p of selPayloads) { if (addCount >= count) return; try { const modMsg = JSON.parse(JSON.stringify(base)); this.setNestedValue(modMsg, field, p); this.payloads.push({ type: 'additional', field: field, targetPath: field, payload: modMsg, severity: 'medium' }); addCount++; } catch {} } } } else if (struct.type === 'raw_string') { const orig = struct.original; if (typeof orig !== 'string') continue; const needed = Math.min(count, 20); const selPayloads = payloadList.sort(() => 0.5 - Math.random()).slice(0, needed); let addCount = 0; for (const p of selPayloads) { if (addCount >= count) return; this.payloads.push({ type: 'additional_raw', payload: p, severity: 'medium', isRawString: true, original: orig }); addCount++; } } } }
        setNestedValue(obj, path, value) { if (!obj || typeof obj !== 'object' || !path) { if(typeof obj === 'string') return value; return; } const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || []; let current = obj; for (let i = 0; i < parts.length - 1; i++) { let part = parts[i]; if (part.startsWith('[')) part = part.substring(1, part.length - 1).replace(/['"`]/g, ''); const nextPartStr = parts[i + 1]; let nextPartNormalized = nextPartStr; if (nextPartNormalized.startsWith('[')) nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, ''); const isNextPartIndex = /^\d+$/.test(nextPartNormalized); if (current[part] === undefined || current[part] === null || typeof current[part] !== 'object') current[part] = isNextPartIndex ? [] : {}; current = current[part]; if (typeof current !== 'object' || current === null) return; } let lastPart = parts[parts.length - 1]; if (lastPart.startsWith('[')) lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, ''); if (typeof current === 'object' && current !== null) { const isIndex = /^\d+$/.test(lastPart); if (Array.isArray(current) && isIndex) current[parseInt(lastPart, 10)] = value; else if (!Array.isArray(current)) current[lastPart] = value; } }
    }

    global.SinkAwarePostMessageFuzzer = class SinkAwarePostMessageFuzzer {
        constructor(messages, handlerCode, sinks, originChecks = []) {
            this.messages = Array.isArray(messages) ? messages : [];
            this.handlerCode = handlerCode || '';
            this.sinks = Array.isArray(sinks) ? sinks : [];
            this.config = { messages: this.messages, handler: this.handlerCode, sinks: this.sinks, originValidationChecks: originChecks };
            this.fuzzer = new ImprovedMessageFuzzer();
            this.isExecutingPayloads = false; this.payloadIntervalId = null; this.reportData = null; this.target = null; this.callbackUrl = null; this._onCompleteCallback = null;
        }
        start(onCompleteCallback) {
            if (this.isExecutingPayloads) return;
            const payloadsToExecute = this.generatePayloads();
            if (payloadsToExecute.length > 0) { this._onCompleteCallback = onCompleteCallback; this.executeFuzzing(payloadsToExecute); }
            else { if (typeof onCompleteCallback === 'function') onCompleteCallback(); if(typeof updateStatus === 'function') updateStatus('Error: No payloads.', true); }
        }
        stop() {
            if (this.payloadIntervalId) { clearInterval(this.payloadIntervalId); this.payloadIntervalId = null; }
            if (this.isExecutingPayloads) { this.isExecutingPayloads = false; if (typeof this._onCompleteCallback === 'function') this._onCompleteCallback(true); }
        }
        generatePayloads() {
            let basePayloads = []; let ranFallback = false;
            if (this.config?.payloads?.length > 0) basePayloads = this.config.payloads;
            else if (this.config?.traceData?.details?.payloads?.length > 0) basePayloads = this.config.traceData.details.payloads;
            else if (this.config?.traceData?.payloads?.length > 0) basePayloads = this.config.traceData.payloads;
            if (basePayloads.length === 0) { ranFallback = true; this.fuzzer.initialize( this.config?.messages || [], this.config?.handler || '', this.config?.sinks || [], this.config?.target, this.config?.callbackUrl, this.config?.originValidationChecks || [] ); if (this.config?.fuzzerOptions) this.fuzzer.initializeWithConfig(this.config.fuzzerOptions); this.fuzzer.runPayloadGeneration(); basePayloads = this.fuzzer.payloads; }
            return basePayloads;
        }
        executeFuzzing(payloads) {
            if (!payloads || payloads.length === 0) { this.isExecutingPayloads = false; if (typeof this._onCompleteCallback === 'function') this._onCompleteCallback(); return; }
            if (this.isExecutingPayloads) return;
            this.isExecutingPayloads = true; const sentPayloads = new Set(); let msgIdx = 0; const iframe = document.getElementById('targetFrame');
            if (!iframe?.contentWindow) { this.isExecutingPayloads = false; if(typeof updateStatus === 'function') updateStatus('Error: Target iframe missing.', true); if (typeof this._onCompleteCallback === 'function') this._onCompleteCallback(); return; }
            if(typeof updateStatus === 'function') updateStatus(`Executing ${payloads.length} payloads... (0%)`);
            if (this.payloadIntervalId) clearInterval(this.payloadIntervalId);
            this.payloadIntervalId = setInterval(() => {
                if (!this.isExecutingPayloads || !iframe?.contentWindow || msgIdx >= payloads.length) { if(typeof updateStatus === 'function' && this.isExecutingPayloads) updateStatus(`Finished. Sent ${msgIdx} payloads.`); this.stop(); return; }
                const progress = Math.round(((msgIdx + 1) / payloads.length) * 100); if(typeof updateStatus === 'function') updateStatus(`Executing payload ${msgIdx + 1}/${payloads.length} (${progress}%)`);
                const fuzzerPayload = payloads[msgIdx]; msgIdx++;
                try { const pId = typeof fuzzerPayload?.payload === 'string' ? `${fuzzerPayload.type || '?'}-${fuzzerPayload.payload.substring(0, 30)}` : `${fuzzerPayload?.type || '?'}-${msgIdx}`; if (sentPayloads.has(pId)) return; sentPayloads.add(pId);
                    let payloadToSend; const rawTypes = ['ast-raw', 'raw_string_replace', 'raw_string_inject', 'additional_raw', 'callback_url_raw', 'callback_url_combined', 'origin_fuzzing_raw'];
                    if (fuzzerPayload?.isRawString || rawTypes.includes(fuzzerPayload?.type)) payloadToSend = fuzzerPayload.payload;
                    else if (fuzzerPayload?.payload !== undefined) payloadToSend = fuzzerPayload.payload;
                    else payloadToSend = fuzzerPayload;
                    if (payloadToSend === undefined || payloadToSend === null) return;
                    const processed = this.replaceJwtTokens(payloadToSend);
                    if (typeof window.sendToFrame === 'function') window.sendToFrame(processed);
                    else iframe.contentWindow.postMessage(processed, '*');
                } catch (error) { console.error(`[Fuzzer] Error sending payload index ${msgIdx - 1}:`, error); }
            }, 200);
        }
        replaceJwtTokens(payload) {
            if (typeof payload === 'string') return payload.replace(JWT_REGEX, ADMIN_JWT);
            if (!payload || typeof payload !== 'object') return payload;
            let cloned; try { cloned = typeof structuredClone === 'function' ? structuredClone(payload) : JSON.parse(JSON.stringify(payload)); } catch { return payload; }
            const processObj = (obj) => { for (const key in obj) { if (obj.hasOwnProperty(key)) { if (typeof obj[key] === 'string') obj[key] = obj[key].replace(JWT_REGEX, ADMIN_JWT); else if (typeof obj[key] === 'object' && obj[key] !== null) processObj(obj[key]); } } };
            processObj(cloned); return cloned;
        }
        static initialize(config) {
            if (!config?.target) { if(typeof updateStatus==='function') updateStatus('Error: Invalid config.', true); return null; }
            let sinks = config.sinks || config.traceData?.vulnerabilities || config.traceData?.details?.sinks || [];
            let originChecks = config.originValidationChecks || config.traceData?.details?.originValidationChecks || [];
            const fuzzerInstance = new SinkAwarePostMessageFuzzer(config.messages || [], config.handler || "", sinks, originChecks);
            fuzzerInstance.target = config.target; fuzzerInstance.callbackUrl = config.callbackUrl; fuzzerInstance.config = config; fuzzerInstance.reportData = config.traceData || null;
            if (fuzzerInstance.fuzzer && config.fuzzerOptions) fuzzerInstance.fuzzer.initializeWithConfig(config.fuzzerOptions);
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
            const chunkSize = 65536;

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
