#!/usr/bin/env node
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');

const rootDir = '/Users/lidorbs/Downloads/Tools/FrogPost';

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
app.use(express.json({ limit: '50mb' }));
app.use('/fuzzer', express.static(path.join(rootDir, 'fuzzer')));
app.use(express.static(rootDir));

const port = 1337;
let testData = null;
let serverReady = false;

app.post('/current-config', (req, res) => {
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

app.post('/llm/analyze-handler', async (req, res) => {
  try {
    const { provider, model, apiKey } = req.body || {};
    const handlerCode = req.body?.context?.handlerCode || '';
    
    const prompt = buildAnalyzeHandlerPrompt(handlerCode);
    const raw = await runLLM(provider, model, apiKey, prompt);
    
    if (!raw || (!raw.content && !raw.choices)) {
      const staticSinks = await getStaticAnalysisSinks(handlerCode);
      return res.json({ 
        ok: true, 
        handler_assessment: "Analysis provided by static analysis",
        handler_score: 50,
        risks: staticSinks.length > 0 ? ["DOM XSS vulnerability detected by static analysis"] : [],
        dom_xss_sinks: staticSinks,
        data_type: staticSinks.length > 0 ? "JSON" : "STRING",
        llm_raw_output: raw 
      });
    }
    
    const jsonString = raw?.content || raw;
    const parsed = robustParseLlmJson(jsonString) || {};
    
    if (!Array.isArray(parsed.dom_xss_sinks)) {
      parsed.dom_xss_sinks = [];
      
      if (Array.isArray(parsed.risks)) {
        parsed.risks.forEach((risk) => {
          const riskLower = risk.toLowerCase();
          if (riskLower.includes('xss') || riskLower.includes('innerhtml') || riskLower.includes('cross-site scripting')) {
            parsed.dom_xss_sinks.push({
              type: "innerHTML assignment", 
              severity: "High", 
              line: "target.innerHTML = event.data.html", 
              sink: "innerHTML",
              source: "fallback_from_risks"
            });
          }
        });
      }
    }
    
    const normalized = normalizeLlmResponse(parsed, { handlerCode });
    
    res.json({ ok: true, ...normalized, llm_raw_output: raw });
  } catch (e) {
    console.error('Handler analysis error:', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post('/llm/analyze-messages', async (req, res) => {
  try {
    const { provider, model, apiKey } = req.body || {};
    const observedMessages = Array.isArray(req.body?.context?.observedMessages) ? req.body.context.observedMessages : [];
    const prompt = buildAnalyzeMessagesPrompt(observedMessages);
    const raw = await runLLM(provider, model, apiKey, prompt);
    const jsonString = raw?.content || raw;
    const parsed = robustParseLlmJson(jsonString) || {};
    res.json({ ok: true, ...parsed, llm_raw_output: raw });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post('/llm/analyze', async (req, res) => {
  try {
    const { provider, model, apiKey } = req.body || {};
    const ctx = req.body?.context || {};
    const sinks = Array.isArray(ctx.sinks) ? ctx.sinks : [];
    const hasSinks = sinks.length > 0;
    if (!hasSinks) return res.json({ ok: true, newPayloads: [], payload_class: 'none', newPayloadsCount: 0 });

    const prompt = buildPayloadGenerationPrompt({
      handlerCode: ctx.handlerCode || '',
      observedMessages: Array.isArray(ctx.observedMessages) ? ctx.observedMessages : [],
      sinks
    });
    
    const raw = await runLLM(provider, model, apiKey, prompt);
    const jsonString = raw?.content || raw;
    const parsed = robustParseLlmJson(jsonString) || {};
    const norm = normalizePayloadGenResponse(parsed, ctx);

    res.json({
      ok: true,
      newPayloads: norm.new_payloads,
      payload_class: norm.payload_class,
      llm_raw_output: raw,
      newPayloadsCount: norm.new_payloads.length
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

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

function buildPrompt(context) {
    const originalMessages = context.observedMessages || [];
    const sanitizedMessages = global.sanitizeMessagesForLlm ? global.sanitizeMessagesForLlm(originalMessages) : originalMessages;
    
    const messageTypes = { strings: [], objects: [], mixed: false };
    sanitizedMessages.forEach(msg => {
        const data = msg?.data !== undefined ? msg.data : msg;
        if (typeof data === 'string') {
            messageTypes.strings.push(data);
        } else if (typeof data === 'object' && data !== null) {
            messageTypes.objects.push(data);
        }
    });
    messageTypes.mixed = messageTypes.strings.length > 0 && messageTypes.objects.length > 0;
    
    const sys = `You are a senior offensive security engineer analyzing window.postMessage handlers.

**CRITICAL: Handler Quality Assessment Guidelines**
When scoring handlers (0-100), consider:
- COMPLEXITY: Multi-line handlers with business logic score 70-100
- SIMPLE WRAPPERS: Single-line forwarding functions score 20-40  
- REALISTIC BEHAVIOR: Handlers that parse/validate/process data score higher
- WEBPACK/MINIFIED: Obfuscated production code typically scores 80-95
- FUNCTION CALLS: Handlers calling other functions (like onMessageCallback) are often incomplete stubs

**Your tasks:**
1) **VALIDATE** the detected handler against observed messages - score its correctness (0-100)
2) **ASSESS** handler complexity vs simplicity (complex webpack handlers >> simple forwarders)
3) **GENERATE** attack payloads matching the observed message formats
4) **IDENTIFY** specific risks based on handler patterns

**Return STRICT JSON:**
{"handler_assessment":"detailed validation with complexity analysis","handler_score":number,"better_handler":"improved code|null","new_payloads":[mixed_types],"risks":["specific_risks"],"notes":"analysis_summary"}

**Handler Assessment Must Include:**
- Code complexity analysis (simple wrapper vs sophisticated logic)
- Match quality vs observed messages  
- Production-ready indicators (error handling, validation)
- Missing functionality assessment

**Payload Requirements:**
- Generate ${messageTypes.mixed ? 'BOTH string AND object' : messageTypes.strings.length > 0 ? 'string-focused' : 'object-focused'} payloads
- Match observed message patterns: ${messageTypes.strings.length} strings, ${messageTypes.objects.length} objects
- Include XSS, prototype pollution, type confusion attacks
- Target specific message keys/formats from observations

Only output valid JSON, no markdown.`;
    
    const user = `**TARGET:** ${context.url}

**OBSERVED MESSAGES (${sanitizedMessages.length} total):**
String messages: ${JSON.stringify(messageTypes.strings.slice(0,3), null, 2)}
Object messages: ${JSON.stringify(messageTypes.objects.slice(0,3), null, 2)}

**DETECTED HANDLER (${context.handlerCode?.length || 0} chars):**
\`\`\`javascript
${context.handlerCode || "<no handler detected>"}
\`\`\`

**HANDLER ANALYSIS REQUIRED:**
- Is this a simple forwarder (like "onMessageCallback(ev.data)") or complex business logic?
- Does it match the observed message patterns (strings vs objects)?
- Are there webpack/minification indicators suggesting production code?
- Does it include error handling, validation, or sophisticated processing?

**CURRENT PAYLOADS (${(context.currentPayloads||[]).length} existing):**
${JSON.stringify((context.currentPayloads||[]).slice(0,3), null, 2)}

**SECURITY CONTEXT:**
- DOM Sinks: ${(context.sinks||[]).map(s => s.name || s.type || s).join(", ") || "none detected"}
- Origin Checks: ${(context.originChecks||[]).length || 0} found
- Message Security: ${messageTypes.mixed ? 'Mixed types increase attack surface' : messageTypes.strings.length > 0 ? 'String messages - XSS risk' : 'Object messages - injection/pollution risk'}

**GENERATE PAYLOADS** matching the ${messageTypes.mixed ? 'MIXED (string+object)' : messageTypes.strings.length > 0 ? 'STRING' : 'OBJECT'} pattern observed.`;
    
    return { system: sys, user };
}

function buildHandlerAnalysisPrompt(context) {
    const sys = `You are an expert code reviewer. Your ONLY task is to analyze the following JavaScript postMessage handler.
- Assess its quality, correctness, and potential security risks.
- Provide a score from 0-100 on how accurately it seems to match typical postMessage logic. Complex, realistic handlers should score higher.
- Identify specific security risks you see in the code.
- Return a strict JSON object: {"handler_assessment": "your analysis text", "handler_score": number, "risks": ["risk 1", "risk 2"]}`;
    const user = `**DETECTED HANDLER:**\n\`\`\`javascript\n${context.handlerCode || "<no handler detected>"}\n\`\`\``;
    return { system: sys, user };
}

function buildMessageAnalysisPrompt(context) {
    const limitedMessages = (context.observedMessages || []).slice(0, 3);
    const sys = `You are a data pattern analyst. Your ONLY task is to analyze these sample postMessage messages.
- Identify patterns, structures, and potential security risks based on the data format.
- Do NOT analyze handler code or generate payloads.
- Return a strict JSON object: {"risks": ["risk based on message data"], "notes": "your summary of the patterns"}`;
    const user = `**OBSERVED MESSAGES (max 3):**\n\`\`\`json\n${JSON.stringify(limitedMessages, null, 2)}\n\`\`\``;
    return { system: sys, user };
}

function buildAnalyzeHandlerPrompt(handlerCode) {
  const SYSTEM = `You are an expert security researcher analyzing JavaScript postMessage handlers for DOM XSS vulnerabilities.

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

**DATA TYPE ANALYSIS:**
- If handler uses \`evt.data\` directly (like \`innerHTML = evt.data\`): STRING data type
- If handler accesses properties (like \`evt.data.html\` or \`evt.data.type\`): JSON data type
- If handler calls \`JSON.parse(evt.data)\`: JSON STRING data type

**Your task:**
1) **DETECT DOM XSS SINKS** - Identify any dangerous DOM manipulation
2) **ASSESS HANDLER QUALITY** - Score complexity and production-readiness (0-100)
3) **IDENTIFY SECURITY RISKS** - List specific vulnerabilities
4) **DETERMINE DATA TYPE** - Specify if handler expects STRING or JSON data

**CRITICAL: You MUST return the dom_xss_sinks field!**

**Return STRICT JSON:**
{"handler_assessment":string,"handler_score":number,"risks":string[],"dom_xss_sinks":array,"data_type":"STRING|JSON"}

**dom_xss_sinks format (REQUIRED FIELD):**
- If you find innerHTML, outerHTML, insertAdjacentHTML: [{"type":"innerHTML assignment","severity":"High","line":"target.innerHTML = data","sink":"innerHTML"}]
- If you find document.write: [{"type":"document.write","severity":"High","line":"document.write(data)","sink":"document.write"}]
- If you find eval: [{"type":"eval execution","severity":"Critical","line":"eval(data)","sink":"eval"}]
- If NO sinks found: "dom_xss_sinks":[]

**EXAMPLES:**
- For "target.innerHTML = event.data.html": {"dom_xss_sinks":[{"type":"innerHTML assignment","severity":"High","line":"target.innerHTML = event.data.html","sink":"innerHTML"}],"data_type":"JSON"}
- For "target.innerHTML = evt.data": {"dom_xss_sinks":[{"type":"innerHTML assignment","severity":"High","line":"target.innerHTML = evt.data","sink":"innerHTML"}],"data_type":"STRING"}

Only output valid JSON, no markdown.`;
  
  const USER = { 
    handler_code: sanitizeForLLMContext({ handlerCode }).handlerCode,
    task: "Analyze this postMessage handler for DOM XSS sinks, security issues, and data type expectations"
  };
  return { system: SYSTEM, user: JSON.stringify(USER, null, 2) };
}

function buildAnalyzeMessagesPrompt(messages) {
  const SYSTEM = `You analyze ONLY postMessage SHAPES (no values).
Return STRICT JSON: {"message_risks":string[],"shape_summary":string}. No prose.`;
  const USER = { message_shapes: shapeOnlyMessages(messages || []) };
  return { system: SYSTEM, user: JSON.stringify(USER, null, 2) };
}

function buildPayloadGenerationPrompt(context) {
  const safe = sanitizeForLLMContext(context || {});
  const sinks = Array.isArray(safe.sinks) ? safe.sinks : [];
  const hasSinks = sinks.length > 0;

  // Use the detected sinks to determine data type
  const handlerCode = safe.handlerCode || '';
  const primarySink = sinks[0] || {};
  const sinkLine = primarySink.line || '';
  
  // Determine data type based on sink usage
  const expectsJSON = sinkLine.includes('event.data.') || 
                     sinkLine.includes('evt.data.') ||
                     sinkLine.includes('data.type') ||
                     sinkLine.includes('data.html') ||
                     sinkLine.includes('data[') ||
                     handlerCode.includes('JSON.parse');
  
  const expectsString = !expectsJSON && (sinkLine.includes('evt.data') || sinkLine.includes('event.data'));
  

  const SYSTEM = `
You are a creative and methodical security researcher specializing in postMessage vulnerability exploitation.

**Primary Goal: Generate high-quality, diverse, and context-aware payloads.**

**CRITICAL RULES:**
1.  **Analyze the Handler's Data Type:** 
    - If the handler uses \`evt.data\` directly (like \`innerHTML = evt.data\`), generate STRING payloads
    - If the handler accesses properties (like \`evt.data.html\` or \`evt.data.type\`), generate JSON payloads
    - If the handler calls \`JSON.parse(evt.data)\`, generate JSON STRING payloads (stringified JSON)
2.  **Match Message Structure EXACTLY:** 
    - For STRING handlers: Generate simple string payloads like \`"<img src=x onerror=alert(1)>"\`
    - For JSON handlers: Generate complete JSON objects that match intercepted message structure
3.  **Quality over Quantity:** Generate up to 10 high-quality payloads. If you can only generate a few very good ones, that is better than 10 generic ones.
4.  **Payload Diversity:** Create a mix of payloads:
    *   **Simple & Direct:** Basic XSS payloads targeting the sink
    *   **Obfuscated:** Payloads using encoding (HTML entities, String.fromCharCode) to bypass filters
    *   **Logic-Based:** Payloads that abuse the handler's intended logic
5.  **Target the Sink:** Ensure your malicious input reaches the detected DOM XSS sink

**STRICT PROHIBITIONS:**
- Do NOT generate JSON payloads for string-based handlers (like \`{"type":"render","html":"..."}\` when handler uses \`evt.data\` directly)
- Do NOT generate string payloads for JSON-based handlers
- Do NOT change the top-level structure of the message
- For string handlers: Generate strings like \`"<script>alert(1)</script>"\`, NOT objects like \`{"html":"<script>alert(1)</script>"}\`

**OUTPUT FORMAT (Strict JSON):**
{"new_payloads": [/* up to 10 payload objects */], "payload_class": "xss"}
`;

  const USER = {
    task: hasSinks 
      ? `Generate up to 10 diverse, high-quality XSS payloads. The handler ${expectsJSON ? 'expects JSON data' : 'expects string data'}. Analyze the handler code to ensure your payloads are effective.` 
      : "No sinks were detected. Return an empty array for new_payloads.",
    handler_analysis: {
      details: "The following JavaScript code is the message handler. Analyze its data handling to determine if it expects JSON or string data.",
      code: safe.handlerCode || "No handler code available.",
      data_type: expectsJSON ? "JSON" : "STRING",
      reasoning: expectsJSON ? "Handler accesses properties like evt.data.property or uses JSON.parse" : "Handler uses evt.data directly without property access"
    },
    intercepted_message_examples: safe.observedMessages || [],
    detected_sinks: sinks,
    payload_requirements: {
      count: hasSinks ? "Up to 10" : 0,
      data_format: expectsJSON ? "JSON objects matching intercepted message structure" : "Simple strings",
      target_field: hasSinks ? "Inject malicious content into the field(s) that flow into the 'detected_sinks'." : "N/A",
      diversity: "Provide a mix of simple, obfuscated, and logic-based payloads."
    },
    example_of_correct_transformation: hasSinks 
      ? (expectsJSON 
          ? 'If handler uses evt.data.html and intercepted message is `{"type":"render","html":"<b>Hello</b>"}`, generate `{"type":"render","html":"<img src=x onerror=alert(1)>"}`'
          : 'If handler uses evt.data directly (like innerHTML = evt.data), generate simple string payloads like: `"<img src=x onerror=alert(1)>"`, `"<svg onload=alert(1)>"`, `"<script>alert(1)</script>"` - NOT JSON objects!')
      : "No example needed."
  };

  return { system: SYSTEM, user: JSON.stringify(USER, null, 2) };
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

function normalizeLlmResponse(parsed, context) {
    const out = { ...parsed };
    if (typeof out.handler_assessment !== 'string') out.handler_assessment = 'No assessment provided by LLM.';
    if (typeof out.handler_score !== 'number') {
        const len = (context?.handlerCode || '').length; const msgs = (context?.observedMessages || []).length;
        out.handler_score = Math.min(100, Math.max(10, Math.round((len/300) + (msgs>0?20:0))));
    }
    if (!Array.isArray(out.new_payloads)) out.new_payloads = [];
    if (!Array.isArray(out.risks)) out.risks = [];
    if (typeof out.notes !== 'string') out.notes = 'LLM response normalized';
    if (!Array.isArray(out.sinks_detected)) out.sinks_detected = [];
    if (typeof out.payload_class !== 'string') {
        out.payload_class = out.new_payloads.length > 0 ? 'xss' : 'none';
    }
    return out;
}

function normalizePayloadGenResponse(parsed, context) {
  const out = { new_payloads: [], payload_class: 'none' };
  const sinks = Array.isArray(context?.sinks) ? context.sinks : [];
  const hasSinks = sinks.length > 0;

  if (parsed && Array.isArray(parsed.new_payloads)) {
    // Accept both objects (preferred) and strings (legacy)
    out.new_payloads = parsed.new_payloads.filter(p => 
      (typeof p === 'object' && p !== null) || typeof p === 'string'
    ).slice(0, 10);
  }
  if (typeof parsed?.payload_class === 'string') out.payload_class = parsed.payload_class;

  if (!hasSinks) { out.new_payloads = []; out.payload_class = 'none'; return out; }

  // Wrap LLM payloads with metadata for consistent UI display
  const primarySink = sinks?.[0] || {};
  out.new_payloads = out.new_payloads.map(p => {
    let type = 'LLM-generated';
    if (typeof p === 'object' && p !== null && p.type) {
      type = p.type;
    }

    return {
      source: 'LLM',
      type: type,
      payload: p,
      targetPath: '(derived by LLM)',
      sinkType: primarySink?.type || primarySink?.name || 'unknown'
    };
  });

  return out;
}

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

function computePipelineScore({ handlerOk, messagesOk, payloadsOk, sinksFound }) {
  if (sinksFound && handlerOk && messagesOk && payloadsOk) return 100;
  let score = 0;
  if (handlerOk) score += 40;
  if (messagesOk) score += 30;
  if (payloadsOk) score += 20;
  if (sinksFound) score += 10;
  return Math.min(95, score);
}

function robustParseLlmJson(raw) {
  if (!raw || typeof raw !== 'string') return {};
  
  let cleaned = raw.replace(/```json\s*\n?/gi, '').replace(/```\s*$/gi, '');
  
  try {
    return JSON.parse(cleaned);
  } catch {
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        return JSON.parse(jsonMatch[0]);
      } catch {
        return {};
      }
    }
    return {};
  }
}

function safeParseJson(str) {
    try {
        return JSON.parse(str);
    } catch {
        return {};
    }
}

process.on('uncaughtException', e => console.error('Uncaught:', e?.message));
process.on('unhandledRejection', e => console.error('Unhandled:', e?.message));

server.listen(port, '0.0.0.0', () => {
    console.log(`FrogPost server running on port ${port}`);
    serverReady = true;
    console.log('Server fully initialized');
});