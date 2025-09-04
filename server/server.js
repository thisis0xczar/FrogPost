#!/usr/bin/env node
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');

const rootDir = '/Users/lidorbs/Downloads/Tools/FrogPost';

require(path.join(rootDir, 'fuzzer', 'fuzzer.js'));

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

app.post('/llm/analyze', async (req, res) => {
    try {
        const { provider, model, apiKey, context } = req.body || {};
        console.log(`🤖 LLM analyze: ${provider}/${model}, context keys:`, Object.keys(context || {}));
        
        if (!provider || provider === 'none' || !model || !apiKey) {
            console.log('❌ [LLM Validation] Missing required configuration:', { provider, model, hasApiKey: !!apiKey });
            return res.status(400).json({
                ok: false,
                error: 'LLM configuration required',
                message: 'Please configure LLM provider, model, and API key in the options page',
                newPayloadsCount: 0,
                mergedCount: 0
            });
        }
        
        const prompt = buildPrompt(context);
        const llm = await runLLM(provider, model, apiKey, prompt);
        
        if (!llm?.content) {
            console.log('❌ [LLM Validation] No content received from LLM');
            return res.status(400).json({
                ok: false,
                error: 'LLM analysis failed',
                message: 'No response received from LLM provider. Please check your API key and try again.',
                newPayloadsCount: 0,
                mergedCount: 0
            });
        }
        
        const raw = llm.content;
        const actualUsage = llm?.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
        
        const parsed = safeParseJson(raw);
        
        if (!parsed || typeof parsed !== 'object') {
            console.log('❌ [LLM Validation] Invalid JSON response from LLM');
            return res.status(400).json({
                ok: false,
                error: 'Invalid LLM response',
                message: 'LLM returned invalid JSON. Please try again.',
                newPayloadsCount: 0,
                mergedCount: 0
            });
        }
        
        if (!parsed.handler_assessment || typeof parsed.handler_score !== 'number' || !Array.isArray(parsed.new_payloads)) {
            console.log('❌ [LLM Validation] Missing required fields in LLM response');
            return res.status(400).json({
                ok: false,
                error: 'Incomplete LLM response',
                message: 'LLM response missing required fields. Please try again.',
                newPayloadsCount: 0,
                mergedCount: 0
            });
        }
        
        const newPayloads = parsed.new_payloads;
        
        if (global.sanitizeJwts && newPayloads.length > 0) {
            console.log(`🔐 [JWT Sanitization] Sanitizing ${newPayloads.length} LLM payloads`);
            newPayloads = newPayloads.map(payload => global.sanitizeJwts(payload));
        }
        
        const merged = mergePayloads(context?.currentPayloads || [], newPayloads);
        
        const analysisDetails = {
            messageTypes: { totalMessages: context?.observedMessages?.length || 0 },
            handlerLength: context?.handlerInfo?.handler?.length || 0,
            sinksFound: 0,
            originChecks: 0,
            existingPayloads: context?.currentPayloads?.length || 0
        };
        
        const formattedPayloads = newPayloads.map(p => {
            if (typeof p === 'object' && p !== null && p.type) {
                return p; // Already formatted
            }
            return {
                type: 'llm-generated',
                payload: p,
                targetPath: typeof p === 'string' ? 'raw' : '(root)',
                sinkType: 'llm',
                sinkSeverity: 'Medium',
                description: 'LLM suggested'
            };
        });
        
        res.json({
            ok: true,
            newHandler: parsed.better_handler || null,
            newPayloads: formattedPayloads,
            summary: parsed.notes || `LLM analysis completed with ${newPayloads.length} payloads generated`,
            handler_assessment: parsed.handler_assessment,
            risks: parsed.risks || [],
            notes: parsed.notes || `LLM analysis: ${newPayloads.length} payloads generated`,
            llm_raw_output: raw,
            llm_prompt_excerpt: JSON.stringify({ system: prompt.system, user: prompt.user.substring(0, 500) + '...' }),
            handler_score: parsed.handler_score,
            analysis_details: analysisDetails,
            newPayloadsCount: formattedPayloads.length,
            mergedCount: merged.length,
            actual_usage: {
                prompt_tokens: actualUsage.prompt_tokens,
                completion_tokens: actualUsage.completion_tokens,
                total_tokens: actualUsage.total_tokens
            }
        });
    } catch (error) {
        console.error('❌ LLM analyze error:', error);
        return res.status(500).json({ 
            ok: false,
            error: String(error?.message || error),
            newPayloadsCount: 0,
            mergedCount: 0
        });
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
    console.log(`🔐 Sanitized ${originalMessages.length} messages for LLM analysis`);
    
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

async function runLLM(provider, model, apiKey, prompt) {
    if (provider === 'none' || !apiKey || !model) {
        console.warn(`🤖 Skipping LLM call - provider: ${provider}, hasKey: ${!!apiKey}, hasModel: ${!!model}`);
        return { content: null };
    }
    
    const callOpenAICompatible = async (baseUrl, headers) => {
        const body = {
            model,
            messages: [
                { role: 'system', content: prompt.system },
                { role: 'user', content: prompt.user }
            ]
        };
        
        if (!model.includes('o3')) {
            body.temperature = 0.3;
            body.top_p = 0.9;
            body.max_tokens = 1500;
        }
        
        const resp = await fetch(baseUrl, { method: 'POST', headers, body: JSON.stringify(body) });
        
        if (!resp.ok) {
            const errorText = await resp.text();
            console.error(`❌ LLM API Error ${resp.status}:`, errorText);
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
        console.log(`🤖 Making ${provider} API call...`);
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
                messages: [{ role: 'user', content: `${prompt.system}\n\n${prompt.user}` }]
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
        }
    } catch (e) {
        console.error(`❌ LLM call failed for ${provider}:`, e.message);
        return { content: null };
    }
    
    console.warn(`🤖 Unknown provider: ${provider}`);
    return { content: null };
}

function safeParseJson(str) {
    try {
        return JSON.parse(str);
    } catch {
        return {};
    }
}

process.on('uncaughtException', e => console.error('❌ Uncaught:', e?.message));
process.on('unhandledRejection', e => console.error('❌ Unhandled:', e?.message));

server.listen(port, '0.0.0.0', () => {
    console.log(`🚀 FrogPost server running on port ${port}`);
    serverReady = true;
    console.log('✅ Server fully initialized');
});