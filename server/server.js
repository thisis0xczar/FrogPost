#!/usr/bin/env node

/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-11-15
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');

const rootDir = path.join(__dirname, '..');

require(path.join(rootDir, 'fuzzer', 'fuzzer.js'));

function shapeOnlyMessages(messages = []) {
  // Keep at most 3 unique “shapes”: a JSON type signature that ignores values.
  const MAX = 3;
  const seen = new Set();
  const out = [];
  const shapeOf = (v) => {
    if (v === null) return 'null';
    if (Array.isArray(v)) return `[${v.slice(0,2).map(shapeOf).join(',')},…]`;
    if (typeof v === 'object') {
      const keys = Object.keys(v).sort();
      return `{${keys.map(k => `${k}:${shapeOf(v[k])}`).join(',')}}`;
    }
    return typeof v;
  };
  for (const m of messages) {
    const shaped = {
      origin: typeof m.origin === 'string' ? 'string' : typeof m.origin,
      destination: typeof m.destinationUrl === 'string' ? 'string' : typeof m.destinationUrl,
      // Only shape of data, not values
      dataShape: shapeOf(m.data ?? null),
      // Keep message type if present (e.g., {type:"message"})
      type: typeof m.type === 'string' ? m.type : undefined,
      channel: typeof m.channel === 'string' ? m.channel : undefined,
    };
    const key = JSON.stringify(shaped);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(shaped);
      if (out.length >= MAX) break;
    }
  }
  return out;
}

function sanitizeForLLMContext(ctx = {}) {
  const clone = JSON.parse(JSON.stringify(ctx));
  
  const scrubSecrets = (s) => {
    if (typeof s !== 'string') return s;
    // Only scrub secrets, not HTML/JS content needed for analysis
    s = s.replace(/Bearer\s+[A-Za-z0-9._\-]+/g, 'Bearer ***');
    s = s.replace(/eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*/g, '***.***.***'); // JWT
    s = s.replace(/api[_-]?key["\s:=]+[A-Za-z0-9_\-]{16,}/gi, 'apikey="***"');
    return s;
  };
  
  const scrubPayloads = (s) => {
    if (typeof s !== 'string') return s;
    // Scrub secrets first
    s = scrubSecrets(s);
    // Then scrub HTML/JS payloads (but NOT from handler code)
    s = s.replace(/<[^>]+>/g, '<…>');
    s = s.replace(/\bjavascript:[^"'\s)]+/gi, 'javascript:…');
    return s;
  };
  
  // Handler code: only scrub secrets, preserve HTML/JS for sink detection
  if (clone.handlerCode) clone.handlerCode = scrubSecrets(clone.handlerCode);
  
  // Message content: scrub everything including HTML/JS
  if (Array.isArray(clone.observedMessagesRaw)) {
    clone.observedMessages = shapeOnlyMessages(clone.observedMessagesRaw);
    delete clone.observedMessagesRaw;
  }
  
  // Never pass current payloads to LLM
  delete clone.currentPayloads;
  return clone;
}

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use('/fuzzer', express.static(path.join(rootDir, 'fuzzer')));
app.use(express.static(rootDir));

const port = 1337;
let testData = null;
let serverReady = false;

// Lightweight, route-scoped JSON parser to avoid raw-body/iconv-lite issues
function safeJson(req, res, next) {
  if (req.method !== 'POST') return next();
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (!contentType.includes('application/json')) { req.body = {}; return next(); }
  let raw = '';
  req.setEncoding('utf8');
  req.on('data', chunk => {
    raw += chunk;
    if (raw.length > 50 * 1024 * 1024) { // 50MB limit
      res.status(413).type('text/plain').send('Payload too large');
      try { req.destroy(); } catch(_) {}
    }
  });
  req.on('end', () => {
    if (!raw) { req.body = {}; return next(); }
    try { req.body = JSON.parse(raw); return next(); }
    catch (e) { return res.status(400).type('text/plain').send(`Invalid JSON: ${e.message}`); }
  });
  req.on('error', err => {
    return res.status(400).type('text/plain').send(`Read error: ${err.message}`);
  });
}

app.post('/current-config', safeJson, (req, res) => {
    testData = req.body;
    res.type('json').send(JSON.stringify({ success: true }));
});

app.get('/current-config', (req, res) => {
    res.type('json').send(JSON.stringify(testData || {}));
});

app.get('/health', (req, res) => {
    res.type('json').send(JSON.stringify({ 
        status: serverReady ? 'ok' : 'initializing' 
    }));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(rootDir, 'fuzzer', 'test-environment.html'));
});

// Old separate endpoints removed - replaced by /llm/unified-analyze

app.post('/llm/unified-analyze', safeJson, async (req, res) => {
  try {
    const { provider, model, apiKey } = req.body || {};
    const handlerCode = req.body?.context?.handlerCode || '';
    const observedMessages = Array.isArray(req.body?.context?.observedMessages) ? req.body.context.observedMessages : [];
    
    console.log(`🚀 [Unified LLM] Starting combined analysis for handler (${handlerCode.length} chars) with ${observedMessages.length} messages`);
    
    const prompt = buildUnifiedAnalysisPrompt(handlerCode, observedMessages);
    const raw = await runLLM(provider, model, apiKey, prompt);
    
    if (!raw || (!raw.content && !raw.choices)) {
      const staticSinks = await getStaticAnalysisSinks(handlerCode);
      return res.json({ 
        ok: true, 
        handler_assessment: "Analysis provided by static analysis",
        handler_score: 50,
        handler_match: 50,
        risks: staticSinks.length > 0 ? ["DOM XSS vulnerability detected by static analysis"] : [],
        dom_xss_sinks: staticSinks,
        prototype_pollution_indicators: [],
        data_type: staticSinks.length > 0 ? "JSON" : "STRING",
        new_payloads: [],
        payload_class: 'none',
        notes: 'Static analysis fallback used',
        llm_raw_output: raw 
      });
    }
    
    const jsonString = raw?.content || raw;
    const parsed = robustParseLlmJson(jsonString) || {};
    
    console.log('🔍 [Unified LLM] Raw response:', jsonString);
    console.log('🔍 [Unified LLM] Parsed response:', parsed);
    
    // Validate required fields
    if (typeof parsed.handler_match !== 'number') {
      console.error('❌ [Unified LLM] Missing handler_match field. LLM response:', parsed);
      throw new Error('LLM failed to provide required handler_match score.');
    }
    
    // Normalize the unified response
    const normalized = normalizeUnifiedLlmResponse(parsed, { handlerCode, observedMessages });
    
    res.json({ ok: true, ...normalized, llm_raw_output: raw });
  } catch (e) {
    console.error('Unified LLM analysis error:', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Legacy endpoint removed - now using unified-analyze

function mergePayloads(existing, incoming) {
    const toNorm = (p) => {
        if (p == null) return 'null';
        if (typeof p === 'string') return p.trim();
        try { return JSON.stringify(p, Object.keys(p).sort()); } catch { return String(p); }
    };
    const fromNorm = (s) => { try { return JSON.parse(s); } catch { return s; } };
    const set = new Set((existing||[]).map(toNorm));
    for (const p of (incoming||[])) {
        const n = toNorm(p);
        if (!set.has(n)) set.add(n);
    }
    return Array.from(set).map(fromNorm);
}


// Old prompt building functions removed - now using buildUnifiedAnalysisPrompt

function buildUnifiedAnalysisPrompt(handlerCode, observedMessages) {
  const sanitizedContext = sanitizeForLLMContext({ handlerCode, observedMessages });
  const messagesToAnalyze = shapeOnlyMessages(sanitizedContext.observedMessages || []);
  
  const SYSTEM = `You are an expert security researcher performing comprehensive postMessage handler analysis. 

**YOUR TASK: Analyze the handler and messages to provide:**
1. **Security Analysis** - Detect DOM XSS vulnerabilities and prototype pollution indicators
2. **Handler-Message Matching** - Score how well the handler correlates with intercepted messages (0-100)
3. **Payload Generation** - Generate up to 10 XSS payloads if DOM XSS sink found, up to 10 prototype pollution payloads if prototype pollution indicators found

**CRITICAL: DOM XSS Sink Detection**
Analyze the handler code and identify ANY of these DOM XSS sinks:
- innerHTML, outerHTML, insertAdjacentHTML
- document.write, document.writeln
- eval, Function constructor, setTimeout/setInterval with strings
- location.href, location.assign, location.replace
- window.open, document.location
- element.src, element.href, element.action
- element.setAttribute with event handlers
- jQuery: .html(), .append(), .prepend(), .after(), .before()
- React: dangerouslySetInnerHTML
- Range.createContextualFragment, Range.insertNode

**CRITICAL: Prototype Pollution Detection**
Look for these prototype pollution indicators:
- Unsafe object property access patterns: obj[key] = value where key comes from user input
- Dangerous property names: __proto__, constructor, prototype
- Unsafe merge operations without proper filtering
- Dynamic property assignment from untrusted data

**DATA TYPE ANALYSIS:**
- If handler uses \`evt.data\` directly: STRING data type
- If handler accesses properties (like \`evt.data.html\`): JSON data type
- If handler calls \`JSON.parse(evt.data)\`: JSON STRING data type

**Handler Match Scoring Guidelines:**
- 90-100: Complex business logic, multiple event.data accesses, sophisticated processing
- 70-89: Good postMessage patterns, some complexity, clear data handling
- 50-69: Basic postMessage functionality, simple data access
- 30-49: Minimal postMessage characteristics, limited functionality
- 0-29: Non-postMessage code, utility functions, or positioning logic

**MANDATORY OUTPUT FORMAT - You MUST include ALL these fields:**
{
  "handler_assessment": "detailed security analysis of the handler",
  "handler_score": 85,
  "handler_match": 78,
  "risks": ["risk description 1", "risk description 2"],
  "dom_xss_sinks": [{"type":"innerHTML assignment","severity":"High","line":"target.innerHTML = data","sink":"innerHTML"}],
  "prototype_pollution_indicators": [{"type":"unsafe merge","severity":"Medium","line":"Object.assign(obj, userInput)","indicator":"object_assign"}],
  "data_type": "JSON|STRING",
  "new_payloads": {
    "xss_payloads": ["<script>alert(1)</script>"],
    "prototype_pollution_payloads": [{"__proto__": {"isAdmin": true}}]
  },
  "payload_class": "xss|prototype_pollution|mixed|none",
  "notes": "comprehensive analysis summary"
}

**Payload Generation Rules:**
- If DOM XSS sinks found: Generate up to 10 XSS payloads targeting those sinks
- If prototype pollution indicators found: Generate up to 10 prototype pollution payloads
- Use the detected data_type format (JSON objects vs strings)
- If no vulnerabilities found: Return empty payload arrays

**CRITICAL REQUIREMENTS:**
1. You MUST provide handler_match score (0-100)
2. You MUST provide all required fields - no omissions allowed
3. Empty arrays are acceptable for sinks/indicators if none found
4. Payloads must match the data_type format

Return ONLY valid JSON, no markdown, no explanations.`;

  const USER = {
    handler_code: sanitizedContext.handlerCode,
    intercepted_messages: messagesToAnalyze,
    task: "Perform unified security analysis: 1) Detect vulnerabilities 2) Score handler-message correlation 3) Generate payloads if vulnerabilities found"
  };

  return { system: SYSTEM, user: JSON.stringify(USER, null, 2) };
}

function normalizeUnifiedLlmResponse(parsed, context) {
  const out = { ...parsed };
  
  // Normalize basic fields
  if (typeof out.handler_assessment !== 'string') out.handler_assessment = 'No assessment provided by LLM.';
  if (typeof out.handler_score !== 'number') {
    const len = (context?.handlerCode || '').length;
    const msgs = (context?.observedMessages || []).length;
    out.handler_score = Math.min(100, Math.max(10, Math.round((len/300) + (msgs>0?20:0))));
  }
  if (typeof out.handler_match !== 'number') out.handler_match = 50;
  if (!Array.isArray(out.risks)) out.risks = [];
  if (typeof out.notes !== 'string') out.notes = 'Unified analysis completed';
  
  // Normalize vulnerability detection
  if (!Array.isArray(out.dom_xss_sinks)) out.dom_xss_sinks = [];
  if (!Array.isArray(out.prototype_pollution_indicators)) out.prototype_pollution_indicators = [];
  if (typeof out.data_type !== 'string') out.data_type = 'JSON';
  
  // Normalize payloads - handle both old and new format
  let xssPayloads = [];
  let prototypePollutionPayloads = [];
  
  if (out.new_payloads && typeof out.new_payloads === 'object' && !Array.isArray(out.new_payloads)) {
    // New unified format
    xssPayloads = Array.isArray(out.new_payloads.xss_payloads) ? out.new_payloads.xss_payloads : [];
    prototypePollutionPayloads = Array.isArray(out.new_payloads.prototype_pollution_payloads) ? out.new_payloads.prototype_pollution_payloads : [];
  } else if (Array.isArray(out.new_payloads)) {
    // Legacy format - assume all are XSS payloads
    xssPayloads = out.new_payloads;
  }
  
  // Combine payloads for UI compatibility
  const allPayloads = [];
  
  // Add XSS payloads
  xssPayloads.slice(0, 10).forEach(payload => {
    allPayloads.push({
      source: 'LLM',
      type: 'XSS',
      payload: payload,
      targetPath: '(XSS vulnerability)',
      sinkType: out.dom_xss_sinks.length > 0 ? out.dom_xss_sinks[0].sink : 'innerHTML'
    });
  });
  
  // Add prototype pollution payloads
  prototypePollutionPayloads.slice(0, 10).forEach(payload => {
    allPayloads.push({
      source: 'LLM',
      type: 'Prototype Pollution',
      payload: payload,
      targetPath: '(Prototype pollution)',
      sinkType: 'prototype'
    });
  });
  
  out.new_payloads = allPayloads;
  out.newPayloadsCount = allPayloads.length;
  
  // Determine payload class
  if (xssPayloads.length > 0 && prototypePollutionPayloads.length > 0) {
    out.payload_class = 'mixed';
  } else if (xssPayloads.length > 0) {
    out.payload_class = 'xss';
  } else if (prototypePollutionPayloads.length > 0) {
    out.payload_class = 'prototype_pollution';
  } else {
    out.payload_class = 'none';
  }
  
  return out;
}

function robustParseLlmJson(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let s = raw.trim();
    if (s.startsWith('```')) {
        const firstNl = s.indexOf('\n');
        if (firstNl !== -1) s = s.substring(firstNl + 1);
        if (s.endsWith('```')) s = s.substring(0, s.length - 3);
    }
    try { return JSON.parse(s); } catch {}
    const start = s.indexOf('{');
    const end = s.lastIndexOf('}');
    if (start !== -1 && end !== -1 && end > start) {
        const candidate = s.substring(start, end + 1);
        try { return JSON.parse(candidate); } catch {}
    }
    return null;
}

async function getStaticAnalysisSinks(handlerCode) {
    if (!handlerCode || typeof handlerCode !== 'string') {
        return [];
    }
    
    try {
        if (typeof window !== 'undefined' && window.analyzeHandlerStatically) {
            const analysis = window.analyzeHandlerStatically(handlerCode);
            if (analysis && analysis.success && analysis.analysis) {
                const detectedSinks = analysis.analysis.potentialSinks || [];
                return detectedSinks.map(sink => ({
                    type: sink.name || sink.type,
                    severity: sink.severity || 'Medium',
                    line: sink.snippet || 'Unknown',
                    sink: sink.name?.toLowerCase().replace(/\s+/g, '_') || 'unknown',
                    category: sink.category || 'generic',
                    method: 'static_analyzer',
                    path: sink.sourcePath || 'unknown'
                }));
            }
        }
    } catch (error) {
        console.error('Static analyzer error:', error.message);
    }
    
    return [];
}

// Old normalization functions removed - now using normalizeUnifiedLlmResponse

async function runLLM(provider, model, apiKey, prompt) {
    if (provider === 'none' || !apiKey || !model) {
        console.warn(`Skipping LLM call - provider: ${provider}, hasKey: ${!!apiKey}, hasModel: ${!!model}`);
        return { content: null };
    }
    
    const callOpenAICompatible = async (baseUrl, headers) => {
        const body = {
            model,
            messages: [
                { role: 'system', content: prompt.system },
                { role: 'user', content: prompt.user }
            ],
            temperature: 0.2,
            response_format: { type: 'json_object' }
        };
        
        const resp = await fetch(baseUrl, { method: 'POST', headers, body: JSON.stringify(body) });
        
        if (!resp.ok) {
            const errorText = await resp.text();
            console.error(`LLM API Error ${resp.status}:`, errorText);
            throw new Error(`LLM HTTP ${resp.status}: ${errorText}`);
        }
        
        const data = await resp.json();
        const content = data?.choices?.[0]?.message?.content || '';
        
        const usage = data?.usage || {};
        return { 
            content,
            usage: {
                prompt_tokens: usage.prompt_tokens || 0,
                completion_tokens: usage.completion_tokens || 0,
                total_tokens: usage.total_tokens || 0
            }
        };
    };

    try {
        let result;
        if (provider === 'openai') {
            result = await callOpenAICompatible('https://api.openai.com/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'groq') {
            result = await callOpenAICompatible('https://api.groq.com/openai/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'mistral') {
            result = await callOpenAICompatible('https://api.mistral.ai/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'anthropic') {
            const body = {
                model,
                max_tokens: 1500,
                temperature: 0.2,
                system: prompt.system,
                messages: [{ role: 'user', content: prompt.user }]
            };
            const resp = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
                body: JSON.stringify(body)
            });
            if (!resp.ok) throw new Error(`LLM HTTP ${resp.status}`);
            const data = await resp.json();
            const content = (data?.content?.[0]?.text) || '';
            
            const usage = data?.usage || {};
            return { 
                content,
                usage: {
                    prompt_tokens: usage.input_tokens || 0,
                    completion_tokens: usage.output_tokens || 0,
                    total_tokens: (usage.input_tokens || 0) + (usage.output_tokens || 0)
                }
            };
        } else if (provider === 'google') {
            const body = {
                contents: [{
                    parts: [{ text: `${prompt.system}\n\n${prompt.user}` }]
                }],
                generationConfig: {
                    temperature: 0.2,
                    maxOutputTokens: 1500
                }
            };
            const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
                body: JSON.stringify(body)
            });
            if (!resp.ok) throw new Error(`LLM HTTP ${resp.status}`);
            const data = await resp.json();
            const content = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
            return { content, usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } };
        } else if (provider === 'cohere') {
            const body = {
                model,
                message: `${prompt.system}\n\n${prompt.user}`,
                max_tokens: 1500,
                temperature: 0.2
            };
            const resp = await fetch('https://api.cohere.ai/v1/chat', {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'authorization': `Bearer ${apiKey}` },
                body: JSON.stringify(body)
            });
            if (!resp.ok) throw new Error(`LLM HTTP ${resp.status}`);
            const data = await resp.json();
            const content = data?.text || '';
            return { content, usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } };
        } else if (provider === 'perplexity') {
            result = await callOpenAICompatible('https://api.perplexity.ai/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'together') {
            result = await callOpenAICompatible('https://api.together.xyz/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'deepseek') {
            result = await callOpenAICompatible('https://api.deepseek.com/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'moonshot') {
            result = await callOpenAICompatible('https://api.moonshot.cn/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'zhipu') {
            result = await callOpenAICompatible('https://open.bigmodel.cn/api/paas/v4/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'baichuan') {
            result = await callOpenAICompatible('https://api.baichuan-ai.com/v1/chat/completions', { 'authorization': `Bearer ${apiKey}`, 'content-type': 'application/json' });
            return result;
        } else if (provider === 'qwen') {
            const body = {
                model,
                input: {
                    messages: [
                        { role: 'system', content: prompt.system },
                        { role: 'user', content: prompt.user }
                    ]
                },
                parameters: {
                    max_tokens: 1500,
                    temperature: 0.2
                }
            };
            const resp = await fetch('https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation', {
                method: 'POST',
                headers: { 'content-type': 'application/json', 'authorization': `Bearer ${apiKey}` },
                body: JSON.stringify(body)
            });
            if (!resp.ok) throw new Error(`LLM HTTP ${resp.status}`);
            const data = await resp.json();
            const content = data?.output?.text || '';
            return { content, usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } };
        } else if (provider === 'local') {
            result = await callOpenAICompatible('http://localhost:11434/v1/chat/completions', { 'authorization': `Bearer ${apiKey || 'ollama'}`, 'content-type': 'application/json' });
            return result;
        }
    } catch (e) {
        console.error(`LLM call failed for ${provider}:`, e.message);
        return { content: null };
    }
    
    console.warn(`Unknown provider: ${provider}`);
    return { content: null };
}



process.on('uncaughtException', e => console.error('Uncaught:', e?.message));
process.on('unhandledRejection', e => console.error('Unhandled:', e?.message));

server.listen(port, '0.0.0.0', () => {
    console.log(`FrogPost server running on port ${port}`);
    serverReady = true;
    console.log('Server fully initialized');
});
