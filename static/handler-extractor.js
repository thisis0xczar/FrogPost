/**
 * DEPRECATED AS OF 2025-10-29 - REAL-TIME HANDLER CAPTURE ARCHITECTURE
 * 
 * FrogPost Extension - Handler Extractor (No Longer Used)
 * Originally Created by thisis0xczar/Lidor
 * Refined on: 2025-10-22
 * Deprecated on: 2025-10-29 for BlackHat presentation
 * 
 * This file is NO LONGER USED as of the real-time handler capture refactor.
 * Handlers are now captured immediately when registered via DOM agent hooks.
 * 
 * Kept for reference/backup only. All extraction now happens via:
 * - dom_injection_agent.js: Captures handlers when addEventListener/onmessage is called
 * - background.js: Stores handlers in-memory cache
 * - dashboard.js: Retrieves handlers instantly from cache
 * 
 * Benefits of new architecture:
 * - 100% accuracy (captures exact handler function reference)
 * - Instant retrieval (<50ms vs seconds for static analysis)
 * - No CSP issues, no key mismatches, no scoring complexity
 * - Simpler codebase (-650 lines of complex regex/AST/fuzzy matching)
 */

class HandlerExtractor {
    constructor() {
        this.endpoint = null;
        this.messages = [];
        this.messageKeys = new Set();
        this.messageTypes = new Set();
        this.messageValues = new Set();
        this.functionDefinitions = new Map();
        this.debugLevel = this._resolveDebugLevel(); // 0:none,1:basic,2:verbose,3:trace
    }

    _is(n, t) { return !!n && n.type === t; }
    _prop(o, k) { return (o && Object.prototype.hasOwnProperty.call(o, k)) ? o[k] : undefined; }
    _safeLog(...args) { try { console.debug(...args); } catch {} }

    _resolveDebugLevel() {
        try {
            if (typeof HandlerExtractor.globalDebugLevel === 'number') return HandlerExtractor.globalDebugLevel;
            if (typeof localStorage !== 'undefined') {
                const raw = localStorage.getItem('frogpost_debug_level');
                if (!raw) return 1;
                const norm = String(raw).toLowerCase();
                if (norm === 'off' || norm === '0') return 0;
                if (norm === 'basic' || norm === '1') return 1;
                if (norm === 'verbose' || norm === '2') return 2;
                if (norm === 'trace' || norm === '3') return 3;
            }
        } catch (_) {}
        return 1;
    }

    setDebugLevel(level) {
        const n = Number(level);
        this.debugLevel = Number.isFinite(n) ? Math.max(0, Math.min(3, n)) : this.debugLevel;
        try { if (typeof localStorage !== 'undefined') localStorage.setItem('frogpost_debug_level', String(this.debugLevel)); } catch(_){}
    }

    static setGlobalDebugLevel(level) {
        const n = Number(level);
        HandlerExtractor.globalDebugLevel = Number.isFinite(n) ? Math.max(0, Math.min(3, n)) : 1;
    }

    _log(level, method, ...args) {
        if (this.debugLevel < level) return;
        try {
            if (typeof log !== 'undefined' && typeof log[method] === 'function') return log[method](...args);
        } catch(_) {}
        try { console[method === 'success' ? 'log' : (method || 'log')](...args); } catch(_) {}
    }

    // Heuristic: shrink oversized/minified snippets to the actual postMessage handler core
    _shrinkToHandlerCore(handlerCode) {
        try {
            if (!handlerCode || typeof handlerCode !== 'string') return null;
            const code = handlerCode;
            // 1) Prefer returning the full binding expression (call/assignment), not just the function
            // 1a) addEventListener('message', fn [, options])
            {
                const m = /addEventListener\s*\(\s*["']message["']\s*,/i.exec(code);
                if (m) {
                    // walk forward to the closing parenthesis of this call
                    let i = m.index; let open = 0; let started = false;
                    for (; i < code.length; i++) {
                        const ch = code[i];
                        if (ch === '(') { open++; started = true; }
                        else if (ch === ')') { open--; if (started && open === 0) { const end = i + 1; return code.slice(m.index, end); } }
                    }
                }
            }
            // 1b) onmessage = fn;
            {
                const m = /onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[\s\S]*?\}|\([^)]*\)\s*=>\s*\{[\s\S]*?\})/i.exec(code);
                if (m) {
                    // extend forward to semicolon or line end to keep the assignment context
                    let end = m.index + m[0].length; while (end < code.length && code[end] !== ';' && code[end] !== '\n') end++; if (end < code.length) end++;
                    return code.slice(m.index, end);
                }
            }
            // 3) Anchor on event.data usage and backtrack to function start; then forward to matching brace
            const pats = [/(?:event|e|evt|msg)\.data/i, /\.data\s*\]/i, /\.data\s*\./i];
            let anchor = -1; for (const p of pats) { const m = p.exec(code); if (m) { anchor = m.index; break; } }
            if (anchor >= 0) {
                let start = anchor;
                for (let i = anchor; i >= 0; i--) {
                    const slice = code.slice(Math.max(0, i - 16), i + 1);
                    if (/function\s*\([^)]*\)\s*$/.test(slice) || /=>\s*\{$/.test(slice) || /\{$/.test(slice)) { start = i; break; }
                }
                let open = 0, end = code.length - 1, found = false;
                for (let i = start; i < code.length; i++) {
                    const ch = code[i];
                    if (ch === '{') open++; else if (ch === '}') { open--; if (open === 0) { end = i; found = true; break; } }
                }
                if (found && end > start) {
                    // Try to include small binding context backwards if the call/assignment is immediately before
                    const pre = code.slice(Math.max(0, start - 200), start);
                    const bindIdx = pre.search(/addEventListener\s*\(\s*['"]message['"]\s*,\s*$/i);
                    if (bindIdx >= 0) return code.substring(start - (pre.length - bindIdx), end + 1);
                    const assignIdx = pre.search(/onmessage\s*=\s*$/i);
                    if (assignIdx >= 0) return code.substring(start - (pre.length - assignIdx), end + 1);
                    return code.substring(start, end + 1);
                }
            }
            // 4) Fallback: focused window around message keywords
            if (code.length > 2000) {
                const kw = /(onmessage|addEventListener\s*\(\s*['"]message|event\.data|\.postMessage\s*\()/i.exec(code);
                if (kw) {
                    const c = kw.index, half = 800; return code.slice(Math.max(0, c - half), Math.min(code.length, c + half));
                }
            }
        } catch(_) {}
        return null;
    }

    // Known noisy/minified code families that often get mistaken for handlers
    _isKnownNoiseNonHandler(handlerCode) {
        try {
            if (!handlerCode || typeof handlerCode !== 'string') return false;
            const noise = [
                /wpemoji|twemoji|concatemoji|emojiSettings|EmojiObserver/i,          // WordPress emoji loader
                /supports\.everything|supports\.everythingExceptFlag/i,
                /Promise\s*\.\s*then|\.then\s*\(/i,
                /scheduler|MessageChannel|unstable_now/i,                            // React scheduler internals
                /\bterminate\s*\(/i                                                   // workers/terminals often unrelated to message handler
            ];
            const hasNoise = noise.some(p => p.test(handlerCode));
            // If it matches noise patterns, it's noise - no exceptions
            return hasNoise;
        } catch(_) { return false; }
    }

    _isNonPostMessageHandler(handlerCode, handlerFlags) {
        if (!handlerCode || typeof handlerCode !== 'string') return false;

        // Check for common non-postMessage handler patterns
        const nonPostMessagePatterns = [
            // Positioning/UI related functions
            /positioning|offset|placement|floating|platform|isRTL/i,
            // Scheduler/async related
            /scheduler|async.*fn|unstable_now|MessageChannel/i,
            // Generic utility functions
            /utility|helper|util|common|shared/i,
            // Event handling without message focus
            /addEventListener.*(?!message)|removeEventListener/i,
            // Function that doesn't access event.data
            /function.*\{[^}]*\}(?!.*event\.data)/i
        ];

        // Check if handler code matches non-postMessage patterns
        for (const pattern of nonPostMessagePatterns) {
            if (pattern.test(handlerCode)) return true;
        }

        // Check if handler doesn't access event.data at all
        if (!handlerCode.includes('event.data') && !handlerCode.includes('evt.data')) {
            return true;
        }

        // Check if handler doesn't have any DOM manipulation or postMessage processing
        const domPatterns = [/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function|createElement|appendChild|setAttribute|style\.|classList\./i];
        const processingPatterns = [/JSON\.parse|JSON\.stringify|switch.*case|if.*event\.data|\.type|\.action|\.command/i];
        const hasDOMManipulation = domPatterns.some(pattern => pattern.test(handlerCode));
        const hasProcessingLogic = processingPatterns.some(pattern => pattern.test(handlerCode));

        // If no DOM manipulation AND no processing logic, likely not a postMessage handler
        if (!hasDOMManipulation && !hasProcessingLogic) return true;

        // Check if handler is too complex for a simple postMessage handler
        if (handlerCode.length > 1000 && !handlerFlags.accessesEventDataConditionally) {
            return true;
        }

        return false;
    }

    _resolveStringLiteral(node) {
        if (!node) return null;
        const lit = (n) => (n && n.type === 'Literal' && typeof n.value === 'string') ? n.value : null;
        const tmpl = (n) => {
            if (!n || n.type !== 'TemplateLiteral' || (n.expressions && n.expressions.length)) return null;
            return n.quasis.map(q => (q.value.cooked ?? q.value.raw ?? '')).join('');
        };
        const bin = (n) => {
            if (!n || n.type !== 'BinaryExpression' || n.operator !== '+') return null;
            const l = this._resolveStringLiteral(n.left);
            const r = this._resolveStringLiteral(n.right);
            return (typeof l === 'string' && typeof r === 'string') ? (l + r) : null;
        };
        const id = (n) => {
            if (!n || n.type !== 'Identifier' || !this._constStringEnv) return null;
            return this._constStringEnv.get(n.name) || null;
        };
        return lit(node) ?? tmpl(node) ?? bin(node) ?? id(node) ?? null;
    }

    _seedConstStringEnv(ast) {
        this._constStringEnv = new Map();
        // Acorn AST parsing removed - no longer used
        return;
        /* DEPRECATED: acorn.walk.simple(ast, {
            VariableDeclarator: (n) => {
                try {
                    if (n?.id?.name && n.init) {
                        const v = this._resolveStringLiteral(n.init);
                        if (typeof v === 'string') this._constStringEnv.set(n.id.name, v);
                    }
                } catch (e) { this._safeLog('[ConstSeed] var error:', e?.message); }
            },
            AssignmentExpression: (n) => {
                try {
                    if (n?.operator === '=' && n.left?.type === 'Identifier') {
                        const v = this._resolveStringLiteral(n.right);
                        if (typeof v === 'string') this._constStringEnv.set(n.left.name, v);
                    }
                } catch (e) { this._safeLog('[ConstSeed] assign error:', e?.message); }
            }
        }); */
    }

    initialize(endpoint, messages = []) {
        this.endpoint = endpoint;
        this.messages = messages || [];
        this.debugLevel = this._resolveDebugLevel();
        this.messageKeys = this._extractKeysFromMessages(this.messages);
        this.messageTypes = this._extractMessageTypes(this.messages);
        this.messageValues = this._extractMessageValues(this.messages);
        this.functionDefinitions.clear();
        this._log(1, 'debug', `[Extractor Init] Initialized for ${endpoint}. Message count: ${this.messages.length}, Keys: ${this.messageKeys.size}, Types: ${this.messageTypes.size}, DebugLevel: ${this.debugLevel}`);
        return this;
    }

    _extractKeysFromMessages(messages) {
        const keys = new Set();
        (messages || []).forEach(msg => {
            if (typeof msg.data === 'object' && msg.data !== null) {
                Object.keys(msg.data).forEach(key => keys.add(key));
                if (typeof msg.data.data === 'object' && msg.data.data !== null) {
                    Object.keys(msg.data.data).forEach(key => keys.add(key));
                }
            }
        });
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message keys:`, Array.from(keys));
        return keys;
    }

    _extractMessageTypes(messages) {
        const types = new Set();
        (messages || []).forEach(msg => {
            const kind = msg.data?.kind || msg.data?.messageType || msg.data?.type || msg.data?.action;
            if (typeof kind === 'string') {
                types.add(kind);
            }
        });
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message types/kinds:`, Array.from(types));
        return types;
    }

    _extractMessageValues(messages) {
        const values = new Set();
        const collectValues = (obj) => {
            if (!obj) return;
            try {
                Object.values(obj).forEach(v => {
                    if (typeof v === 'string') values.add(v);
                    else if (v && typeof v === 'object') {
                        // Only go one level deeper to avoid heavy recursion
                        Object.values(v).forEach(nv => { if (typeof nv === 'string') values.add(nv); });
                    }
                });
            } catch (_) {}
        };
        (messages || []).forEach(msg => {
            if (typeof msg?.data === 'string') values.add(msg.data);
            else if (msg?.data && typeof msg.data === 'object') {
                collectValues(msg.data);
                if (msg.data.data && typeof msg.data.data === 'object') collectValues(msg.data.data);
            }
        });
        this._log(2, 'debug', `[Extractor Scoring Context] Extracted message values (sample):`, Array.from(values).slice(0, 10));
        return values;
    }

    analyzeScriptContent(content, sourceIdentifier) {
        // TELEMETRY-FIRST: Use regex-only extraction (AST parsing removed)
        const handlers = [];
        if (!content || typeof content !== 'string' || content.length < 50) return handlers;
        
        this._log(2, 'debug', `[Extractor] Using regex-based extraction for: ${sourceIdentifier}`);
        handlers.push(...this.analyzeWithRegex(content, sourceIdentifier));
        
        this._log(2, 'debug', `[Extractor] Found ${handlers.length} potential handlers in ${sourceIdentifier} (regex-based)`);
        return handlers;
    }

    _mapFunctionDeclarations(ast) {
        // Acorn AST parsing removed - no longer used
        return;
    }

    _mapPrototypeMethods(ast) {
        // Acorn AST parsing removed - no longer used
        return;
    }


    analyzeAst(ast, scriptContent, sourceUrl) {
        // Acorn AST parsing removed - no longer used
        const foundHandlers = [];
        return foundHandlers;
    }


    scoreHandler(handlerInfo) {
        const { handlerNode, category, source, fullScriptContent, functionName, handlerFlags = {}, eventParamName } = handlerInfo;
        const handlerCode = handlerInfo.handler || fullScriptContent;
        let score = 0;
        const dbg = this.debugLevel >= 3 ? { contributions: [], notes: [] } : null;
        const MIN_CODE_LENGTH_ESTIMATE = 25;
        const MAX_CODE_LENGTH_ESTIMATE = 30000;
        const MIN_COMPLEXITY_LENGTH = 65;

        const SCHEDULER_PENALTY = -250;
        const POSTMESSAGE_NULL_PENALTY = -75;
        const SIMPLICITY_PENALTY = -50;
        const NON_POSTMESSAGE_PENALTY = -200; // Heavy penalty for non-postMessage handlers

        const VERIFIER_BONUS = 120;
        const CALLBACK_MAP_BONUS = 110;
        const CONDITIONAL_ORIGIN_ACCESS_BONUS = 125;
        const SWITCH_BONUS = 140;
        const CONDITIONAL_DATA_ACCESS_BONUS = 75;
        const ORIGIN_CHECK_STRUCTURE_BONUS = 90;

        // New bonuses for better handler detection
        const POSTMESSAGE_HANDLER_BONUS = 200;  // Strong indicator
        const DOM_SINK_BONUS = 150;             // Has DOM manipulation
        const JSON_PROCESSING_BONUS = 100;       // Processes JSON data
        const TYPE_CHECKING_BONUS = 80;          // Checks message type/action

        const COMMON_DATA_FIELD_BONUS = 30;
        const ANY_DATA_FIELD_BONUS = 5;
        const ORIGIN_FIELD_BONUS = 10;
        const SPECIFIC_KEY_MATCH_BONUS = 150;
        const SPECIFIC_TYPE_MATCH_BONUS = 100;
        const JSON_PARSE_BONUS = 40;
        const POSTMESSAGE_CALL_BONUS = 5;

        let handlerCodeLength = handlerNode?.end && handlerNode?.start ? handlerNode.end - handlerNode.start : (handlerCode?.length || 0);
        if (handlerCodeLength < MIN_CODE_LENGTH_ESTIMATE) return 0;

        let baseScore = 5; score += baseScore; if (dbg) dbg.contributions.push({rule:'BASE', delta:baseScore});
        let featureScore = 0;
        let hasStrongSignal = handlerFlags.hasStrongSignal || false;

        if (handlerFlags.looksLikeScheduler) { featureScore += SCHEDULER_PENALTY; if (dbg) dbg.contributions.push({rule:'SCHEDULER_PENALTY', delta:SCHEDULER_PENALTY}); }
        if (handlerFlags.mentionsPostMessageNull) { featureScore += POSTMESSAGE_NULL_PENALTY; if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_NULL_PENALTY', delta:POSTMESSAGE_NULL_PENALTY}); }

        // Check if this looks like a non-postMessage handler
        const isNonPostMessageHandler = this._isNonPostMessageHandler(handlerCode, handlerFlags);
        if (isNonPostMessageHandler) { featureScore += NON_POSTMESSAGE_PENALTY; if (dbg) dbg.contributions.push({rule:'NON_POSTMESSAGE_PENALTY', delta:NON_POSTMESSAGE_PENALTY}); }

        if (handlerFlags.callsVerifier) { featureScore += VERIFIER_BONUS; if (dbg) dbg.contributions.push({rule:'VERIFIER_BONUS', delta:VERIFIER_BONUS}); }
        if (handlerFlags.usesCallbackMap) { featureScore += CALLBACK_MAP_BONUS; if (dbg) dbg.contributions.push({rule:'CALLBACK_MAP_BONUS', delta:CALLBACK_MAP_BONUS}); }
        if (handlerFlags.accessesEventOriginConditionally) { featureScore += CONDITIONAL_ORIGIN_ACCESS_BONUS; if (dbg) dbg.contributions.push({rule:'CONDITIONAL_ORIGIN_ACCESS_BONUS', delta:CONDITIONAL_ORIGIN_ACCESS_BONUS}); }
        if (handlerFlags.usesSwitchOnEventData) { featureScore += SWITCH_BONUS; if (dbg) dbg.contributions.push({rule:'SWITCH_BONUS', delta:SWITCH_BONUS}); }
        if (handlerFlags.accessesEventDataConditionally) { featureScore += CONDITIONAL_DATA_ACCESS_BONUS; if (dbg) dbg.contributions.push({rule:'CONDITIONAL_DATA_ACCESS_BONUS', delta:CONDITIONAL_DATA_ACCESS_BONUS}); }

        if (handlerFlags.accessesCommonDataFields > 0) { const d = (handlerFlags.accessesCommonDataFields * COMMON_DATA_FIELD_BONUS); featureScore += d; if (dbg) dbg.contributions.push({rule:'COMMON_DATA_FIELDS', delta:d}); }
        if (handlerFlags.accessesAnyDataField && !handlerFlags.accessesEventDataConditionally && handlerFlags.accessesCommonDataFields === 0) { featureScore += ANY_DATA_FIELD_BONUS; if (dbg) dbg.contributions.push({rule:'ANY_DATA_FIELD_BONUS', delta:ANY_DATA_FIELD_BONUS}); }
        if (handlerFlags.accessesOriginField && !handlerFlags.accessesEventOriginConditionally) { featureScore += ORIGIN_FIELD_BONUS; if (dbg) dbg.contributions.push({rule:'ORIGIN_FIELD_BONUS', delta:ORIGIN_FIELD_BONUS}); }

        // Apply new pattern-based bonuses
        if (/addEventListener.*message|window\.onmessage|message.*event/i.test(handlerCode)) { featureScore += POSTMESSAGE_HANDLER_BONUS; if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_HANDLER_BONUS', delta:POSTMESSAGE_HANDLER_BONUS}); }
        if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write|createElement/i.test(handlerCode)) { featureScore += DOM_SINK_BONUS; if (dbg) dbg.contributions.push({rule:'DOM_SINK_BONUS', delta:DOM_SINK_BONUS}); }
        if (/JSON\.parse|JSON\.stringify/i.test(handlerCode)) { featureScore += JSON_PROCESSING_BONUS; if (dbg) dbg.contributions.push({rule:'JSON_PROCESSING_BONUS', delta:JSON_PROCESSING_BONUS}); }
        if (/\.type|\.action|\.command|switch.*case|if.*event\.data\./i.test(handlerCode)) { featureScore += TYPE_CHECKING_BONUS; if (dbg) dbg.contributions.push({rule:'TYPE_CHECKING_BONUS', delta:TYPE_CHECKING_BONUS}); }

        // Hard penalties to suppress far-from-handler utility blobs
        try {
            const hasExplicitBinding = /(addEventListener\s*\(\s*['"]message['"]|onmessage\s*=)/i.test(handlerCode);
            const isAstBound = (category?.includes('ast-event-listener') || category?.includes('ast-onmessage'));
            if (!hasExplicitBinding && !isAstBound && !handlerFlags.hasStrongSignal) {
                const PEN = -200; featureScore += PEN; if (dbg) dbg.contributions.push({rule:'MISSING_EXPLICIT_BINDING_PENALTY', delta:PEN});
            }
            if (this && typeof this._isKnownNoiseNonHandler === 'function' && this._isKnownNoiseNonHandler(handlerCode)) {
                const PEN2 = -200; featureScore += PEN2; if (dbg) dbg.contributions.push({rule:'KNOWN_NOISE_PENALTY', delta:PEN2});
            }
            if (/\bterminate\s*\(/i.test(handlerCode) && !hasExplicitBinding) {
                const PEN3 = -80; featureScore += PEN3; if (dbg) dbg.contributions.push({rule:'WORKER_LIKE_TERMINATE_PENALTY', delta:PEN3});
            }
        } catch(_) {}

        // String-based scoring (replaces Acorn AST parsing)
        if (handlerCode) {
            try {
                // Check for specific intercepted keys in handler code
                let foundSpecificKeys = 0;
                for (const key of this.messageKeys) {
                    if (handlerCode.includes(key)) foundSpecificKeys++;
                }
                
                // Check for specific intercepted types/values
                let foundSpecificTypes = 0;
                for (const type of this.messageTypes) {
                    if (handlerCode.includes(type)) foundSpecificTypes++;
                }
                
                // Check for postMessage patterns
                const usesPostMessageCall = /\.postMessage\s*\(/.test(handlerCode) && 
                                           !/postMessage\s*\(\s*null\s*\)/.test(handlerCode);
                
                // Check for origin validation patterns
                const hasOriginCheckStructure = /\.origin\s*[!=]=/.test(handlerCode) ||
                                               /\.origin\s*\.\s*(startsWith|endsWith|includes)/.test(handlerCode);
                
                // Check for JSON.parse
                const usesJsonParse = /JSON\s*\.\s*parse/.test(handlerCode);
                
                // Check for event.data access
                const accessesEventData = /\.(data|payload)\s*[.\[]/.test(handlerCode);
                
                const keysDelta = foundSpecificKeys * SPECIFIC_KEY_MATCH_BONUS;
                const typesDelta = foundSpecificTypes * SPECIFIC_TYPE_MATCH_BONUS;
                featureScore += keysDelta; 
                if (dbg && keysDelta) dbg.contributions.push({rule:'SPECIFIC_KEY_MATCH_BONUS(string)', delta:keysDelta, count:foundSpecificKeys});
                featureScore += typesDelta; 
                if (dbg && typesDelta) dbg.contributions.push({rule:'SPECIFIC_TYPE_MATCH_BONUS(string)', delta:typesDelta, count:foundSpecificTypes});
                
                if (usesPostMessageCall && !handlerFlags.mentionsPostMessageNull) { 
                    featureScore += POSTMESSAGE_CALL_BONUS; 
                    if (dbg) dbg.contributions.push({rule:'POSTMESSAGE_CALL_BONUS(string)', delta:POSTMESSAGE_CALL_BONUS}); 
                }
                if (hasOriginCheckStructure) { 
                    featureScore += ORIGIN_CHECK_STRUCTURE_BONUS; 
                    hasStrongSignal = true; 
                    if (dbg) dbg.contributions.push({rule:'ORIGIN_CHECK_STRUCTURE_BONUS(string)', delta:ORIGIN_CHECK_STRUCTURE_BONUS}); 
                }
                if (usesJsonParse) { 
                    featureScore += JSON_PARSE_BONUS; 
                    if (dbg) dbg.contributions.push({rule:'JSON_PARSE_BONUS(string)', delta:JSON_PARSE_BONUS}); 
                }
                if (accessesEventData) {
                    featureScore += 20; // Small bonus for event.data access
                    if (dbg) dbg.contributions.push({rule:'EVENT_DATA_ACCESS(string)', delta:20});
                }
            } catch (e) { 
                this._log(2, 'warn', '[String-based scoring error]', e?.message);
            }
        }

        if(!hasStrongSignal && handlerFlags.hasStrongSignal !== undefined) {
            hasStrongSignal = handlerFlags.hasStrongSignal;
        }

        if (handlerCodeLength < MIN_COMPLEXITY_LENGTH && !hasStrongSignal && featureScore < (VERIFIER_BONUS / 2)) {
            featureScore += SIMPLICITY_PENALTY; if (dbg) dbg.contributions.push({rule:'SIMPLICITY_PENALTY', delta:SIMPLICITY_PENALTY});
        }

        if (!handlerNode && handlerCode) {
            if (!hasStrongSignal) {
                if (handlerCode.match(/(event|msg|message|e)\.data\.(type|action|kind|msgType|payload|message)/)) featureScore += 15;
                else if (handlerCode.match(/(event|msg|message|e)\.data\.\w+/)) featureScore += 5;
                if (handlerCode.match(/(event|msg|message|e)\.origin/)) featureScore += 10;
                if (handlerCode.match(/\.origin\s*(===|!==|==|!=)/)) featureScore += 20;
                else if (handlerCode.match(/\.origin\.(startsWith|endsWith|includes|indexOf|test)\(/)) featureScore += 20;
                if (handlerCode.match(/switch\s*\([^)]*?\.data\.\w+\)/)) featureScore += 30;
                if (handlerCode.includes('JSON.parse')) featureScore += 10;
            }
            if (handlerCode.includes('postMessage') && !handlerCode.match(/postMessage\s*\(\s*null\s*\)/)) featureScore += POSTMESSAGE_CALL_BONUS;
            if (handlerCode.match(/unstable_now|MessageChannel/)) featureScore += SCHEDULER_PENALTY / 2;
        }

        if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE && featureScore < 200) { featureScore -= 150; if (dbg) dbg.contributions.push({rule:'OVERSIZE_CODE_PENALTY_HEAVY', delta:-150}); }
        else if (handlerCodeLength > MAX_CODE_LENGTH_ESTIMATE) { featureScore -= 50; if (dbg) dbg.contributions.push({rule:'OVERSIZE_CODE_PENALTY_LIGHT', delta:-50}); }

        score += featureScore;

        if (category?.includes('runtime')) { score += 150; if (dbg) dbg.contributions.push({rule:'CATEGORY_RUNTIME', delta:150}); }
        else if (category?.includes('debugger') || category?.includes('breakpoint')) { score += 75; if (dbg) dbg.contributions.push({rule:'CATEGORY_DEBUGGER', delta:75}); }
        else if (category?.includes('ast-event-listener') || category?.startsWith('ast-onmessage')) { score += 50; if (dbg) dbg.contributions.push({rule:'CATEGORY_AST', delta:50}); }
        else if (category?.includes('inline-onmessage-attribute')) { score += 5; if (dbg) dbg.contributions.push({rule:'CATEGORY_INLINE', delta:5}); }
        else if (category?.includes('regex')) { 
            // Regex handlers need higher base score to survive feature penalties
            score += 10; 
            if (dbg) dbg.contributions.push({rule:'CATEGORY_REGEX', delta:10}); 
        }
        const finalScore = Math.max(0, score);
        if (dbg) this._log(3, 'debug', `[Score] ${source || 'inline'} (${category}) => ${finalScore}`, { functionName, flags: handlerFlags, breakdown: dbg.contributions });
        return finalScore;
    }


    getBestHandler(handlersInfo) {
        if (!handlersInfo || handlersInfo.length === 0) return null;

        const calculateHeuristicBoost = (handlerInfo) => {
            let boost = 0;
            const source = handlerInfo.source || '';
            const category = handlerInfo.category || '';
            const filename = source.substring(source.lastIndexOf('/') + 1);
            let reason = "No boost applied";

            if (category.includes('breakpoint') || category.includes('ast')) {
                if (filename.match(/app\.js|main\.js|index\.js/i)) {
                    boost = 50;
                    reason = "App-like name";
                } else if (filename.match(/^inline_\d+\.js$/i)) {
                    // Inline handlers are common and valid (e.g., script tags in HTML)
                    boost = 25;
                    reason = "Inline handler";
                } else if (filename.match(/^(npm|vendor|chunk|bundle|poly|webpack)/i) || filename.match(/^\d+\.js$/)) {
                    // Penalize only if there are other non-chunk candidates
                    boost = (handlersInfo.some(h => {
                        const f = (h.source||'').split('/').pop()||'';
                        return !/^(npm|vendor|chunk|bundle|poly|webpack)/i.test(f) && !/^\d+\.js$/.test(f);
                    })) ? -15 : 0;
                    reason = "Lib/Chunk-like name";
                } else if (filename.length > 20 && filename.endsWith('.js')) { // Boost longer JS names slightly more
                    boost = 15;
                    reason = "Longer/specific name";
                } else {
                    reason = "Filename pattern mismatch";
                }
            } else {
                reason = "Category not eligible for boost";
            }
            if(typeof log !== 'undefined') log.debug(`[getBestHandler Boost Calc] File: ${filename}, Category: ${category}, Calculated Boost: ${boost} (Reason: ${reason})`);
            return boost;
        };

        // Early exit for extremely high confidence handlers (saves processing time)
        const HIGH_CONFIDENCE_THRESHOLD = 800;
        for (const handlerInfo of handlersInfo) {
            if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
            }
            if (handlerInfo.handler) {
                const quickScore = this.scoreHandler(handlerInfo);
                if (quickScore >= HIGH_CONFIDENCE_THRESHOLD) {
                    if(typeof log !== 'undefined') log.success(`[getBestHandler] Early exit - found high confidence handler (score: ${quickScore})`);
                    return { ...handlerInfo, score: quickScore };
                }
            }
        }

        const scoredHandlers = handlersInfo.map((handlerInfo, index) => {
            let originalScore = 0;
            let boostedScore = 0;
            const handlerCodePresent = !!handlerInfo.handler || (handlerInfo.fullScriptContent && handlerInfo.handlerNode);

            if (!handlerInfo.handler && handlerInfo.fullScriptContent && handlerInfo.handlerNode) {
                try { handlerInfo.handler = handlerInfo.fullScriptContent.substring(handlerInfo.handlerNode.start, handlerInfo.handlerNode.end); } catch {}
            }

            // Heuristically shrink oversized/minified snippets to the likely handler core
            if (handlerInfo.handler && handlerInfo.handler.length > 800) {
                const shrunken = this._shrinkToHandlerCore(handlerInfo.handler);
                if (shrunken && shrunken.length >= 40) {
                    this._log(2, 'debug', `[getBestHandler] Shrunk oversized candidate from ${handlerInfo.handler.length} → ${shrunken.length}`);
                    handlerInfo.handler = shrunken;
                }
            }

            if (!handlerInfo.handler) {
                if(typeof log !== 'undefined') log.warn(`[getBestHandler Map] Handler candidate ${index} missing handler code. Assigning score 0.`);
                originalScore = 0;
                boostedScore = 0;
            } else {
                // If this looks like known noise (e.g., emoji loader, React scheduler), REJECT IT
                const MIN_LEGITIMATE_HANDLER_LENGTH = 100; // Most real handlers are >100 chars
                const handlerLength = (handlerInfo.handler || '').length;
                const isNoise = this._isKnownNoiseNonHandler(handlerInfo.handler);
                // Don't reject arrow-in-parens handlers even if short - they're method delegates
                const isMethodDelegate = handlerInfo.category?.includes('arrow-in-parens');
                const isTooShort = handlerLength < MIN_LEGITIMATE_HANDLER_LENGTH && handlerInfo.category?.includes('regex') && !isMethodDelegate;
                
                if (isNoise) {
                    this._log(1, 'warn', `[getBestHandler] Handler ${index} REJECTED as NOISE (${handlerInfo.source}): ${(handlerInfo.handler || '').substring(0, 100)}...`);
                    handlerInfo.category = (handlerInfo.category ? handlerInfo.category + '+' : '') + 'noise-filter';
                    originalScore = 0;
                    boostedScore = 0;
                    this._log(1, 'warn', `[getBestHandler] Noise handler score set to: original=${originalScore}, boosted=${boostedScore}`);
                } else if (isTooShort) {
                    this._log(2, 'debug', `[getBestHandler] Handler ${index} REJECTED: too short (${handlerLength} chars)`);
                    handlerInfo.category = (handlerInfo.category ? handlerInfo.category + '+' : '') + 'too-short';
                    originalScore = 0;
                    boostedScore = 0;
                } else {
                    originalScore = this.scoreHandler(handlerInfo);
                    boostedScore = originalScore;
                    this._log(1, 'warn', `[getBestHandler] Handler ${index} (${handlerInfo.source?.split('/').pop()}) scored: ${originalScore}, category: ${handlerInfo.category}`);
                }
                
                this._log(2, 'debug', `[getBestHandler Scoring] Candidate ${index} BEFORE boost: Category=${handlerInfo.category}, OriginalScore=${originalScore}, HandlerLength=${handlerInfo.handler?.length || 0}`);

                // CRITICAL: Skip boost logic for rejected handlers (noise, too-short, etc.)
                if (boostedScore > 0) {
                    if (handlerInfo.category?.includes('prototype') || handlerInfo.category?.includes('objectMethod') || handlerInfo.category?.includes('indirect')) boostedScore += 10;
                    else if (handlerInfo.category?.includes('ast-event-listener-identifier') || handlerInfo.category?.includes('ast-onmessage-assignment-identifier')) boostedScore += 5;
                    else if (handlerInfo.category?.includes('breakpoint')) boostedScore += 20;
                    else if (handlerInfo.category?.includes('regex')) {
                        // CRITICAL: Regex-extracted handlers need a boost to be viable
                        boostedScore += 50;
                        this._log(2, 'debug', `[getBestHandler Boost] Regex handler detected, adding +50 boost`);
                    }

                    boostedScore += calculateHeuristicBoost(handlerInfo);
                    boostedScore = Math.max(0, boostedScore);
                } else {
                    this._log(1, 'warn', `[getBestHandler] Skipping boost for rejected handler (score=${boostedScore})`);
                }
            }

            this._log(2, 'debug', `[getBestHandler Map] Candidate ${index}: Source=${handlerInfo.source?.substring(handlerInfo.source?.lastIndexOf('/')+1)}, BaseScore=${originalScore}, FinalScore=${boostedScore}`);
            const result = { ...handlerInfo, score: boostedScore };
            if (handlerInfo.category?.includes('noise-filter')) {
                this._log(1, 'warn', `[getBestHandler Map] Returning noise handler with score: ${result.score}, category: ${result.category}`);
            }
            return result;
        }).filter(h => {
            if (h.score <= 0) {
                this._log(1, 'warn', `[getBestHandler Filter] Removing handler with score ${h.score}: ${h.source}`);
                return false;
            }
            return true;
        });

        if (scoredHandlers.length === 0) {
            if(typeof log !== 'undefined') log.debug("[getBestHandler] No candidates scored above 0 after boosting/filtering.");
            return null;
        }

        this._log(2, 'debug', "[getBestHandler] Scored Candidates (After Boost, Pre-sort):", JSON.stringify(scoredHandlers.map(h => ({ score: h.score, category: h.category, source: h.source?.substring(h.source?.lastIndexOf('/')+1), name: h.functionName || 'N/A', flags: h.handlerFlags })), null, 2));

        const categoryPriority = { 'runtime': 1, 'debugger': 2, 'breakpoint': 3, 'ast-event-listener': 4, 'ast-onmessage': 5, 'regex': 7, 'inline-onmessage-attribute': 8 };

        scoredHandlers.sort((a, b) => {
            if (b.score !== a.score) return b.score - a.score;
            const priorityA = categoryPriority[a.category?.split('-')[0]] || 99;
            const priorityB = categoryPriority[b.category?.split('-')[0]] || 99;
            if (priorityA !== priorityB) return priorityA - priorityB;
            const lenA = a.handlerNode ? a.handlerNode.end - a.handlerNode.start : (a.handler?.length || 0);
            const lenB = b.handlerNode ? b.handlerNode.end - b.handlerNode.start : (b.handler?.length || 0);
            if (lenA !== lenB) return lenB - lenA;
            return (a.source || '').localeCompare(b.source || '');
        });

        let bestHandlerInfo = scoredHandlers[0];

        if (scoredHandlers.length > 1) {
            const flags = bestHandlerInfo.handlerFlags || {};
            const isLikelyScheduler = flags.looksLikeScheduler || flags.mentionsPostMessageNull;
            const hasStrongSignals = flags.hasStrongSignal || flags.callsVerifier || flags.usesCallbackMap || flags.accessesEventOriginConditionally || flags.usesSwitchOnEventData || flags.accessesEventDataConditionally || bestHandlerInfo.score > 200;
            const handlerLen = bestHandlerInfo.handlerNode ? bestHandlerInfo.handlerNode.end - bestHandlerInfo.handlerNode.start : (bestHandlerInfo.handler?.length || 0);
            const isTooSimple = handlerLen > 0 && handlerLen < 65;

            if ((isLikelyScheduler || (isTooSimple && !hasStrongSignals)) && bestHandlerInfo.score > 0) {
                for (let i = 1; i < scoredHandlers.length; i++) {
                    const alternative = scoredHandlers[i];
                    const altFlags = alternative.handlerFlags || {};
                    const altIsLikelyScheduler = altFlags.looksLikeScheduler || altFlags.mentionsPostMessageNull;
                    const altHasStrongSignals = altFlags.hasStrongSignal || altFlags.callsVerifier || altFlags.usesCallbackMap || altFlags.accessesEventOriginConditionally || altFlags.usesSwitchOnEventData || altFlags.accessesEventDataConditionally || alternative.score > 150;
                    const altHandlerLen = alternative.handlerNode ? alternative.handlerNode.end - alternative.handlerNode.start : (alternative.handler?.length || 0);
                    const altIsTooSimple = altHandlerLen > 0 && altHandlerLen < 65;

                    if (!altIsLikelyScheduler && (altHasStrongSignals || !altIsTooSimple)) {
                        const scoreDifference = bestHandlerInfo.score - alternative.score;
                        if (alternative.score > 100 || scoreDifference < 150 ) {
                            if(typeof log !== 'undefined') log.debug(`[getBestHandler] Top handler (${bestHandlerInfo.score}) rejected (Scheduler/Too Simple: ${isLikelyScheduler}/${isTooSimple}, StrongSignals: ${hasStrongSignals}). Promoting alternative (${alternative.score}, StrongSignals: ${altHasStrongSignals}, Simple: ${altIsTooSimple}).`);
                            bestHandlerInfo = alternative;
                            break;
                        }
                    }
                }
            }
        }

        let finalHandlerCode = bestHandlerInfo.handler || '';
        if (!finalHandlerCode && bestHandlerInfo.fullScriptContent && bestHandlerInfo.handlerNode) {
            try { finalHandlerCode = bestHandlerInfo.fullScriptContent.substring(bestHandlerInfo.handlerNode.start, bestHandlerInfo.handlerNode.end); }
            catch (e) { finalHandlerCode = "[Error extracting code string]"; }
        } else if (!finalHandlerCode && bestHandlerInfo.fullScriptContent) {
            finalHandlerCode = bestHandlerInfo.fullScriptContent;
        }
        if (!bestHandlerInfo.handler && finalHandlerCode !== "[Error extracting code string]") {
            bestHandlerInfo.handler = finalHandlerCode;
        }

        const bestLen = bestHandlerInfo.handlerNode ? bestHandlerInfo.handlerNode.end - bestHandlerInfo.handlerNode.start : finalHandlerCode.length;
        this._log(1, 'debug', `[getBestHandler] Selected Handler: Score=${bestHandlerInfo.score}, Category=${bestHandlerInfo.category}, Source=${bestHandlerInfo.source}, EstLen=${bestLen}, Name=${bestHandlerInfo.functionName || 'N/A'}, Flags=${JSON.stringify(bestHandlerInfo.handlerFlags)}`);

        return bestHandlerInfo;
    }

    // Helper: Try stripping one path segment from URL (for broken build paths)
    _tryStripOnePathSegment(url) {
        try {
            const u = new URL(url);
            const pathParts = u.pathname.split('/').filter(Boolean);
            
            this._log(2, 'debug', `[URL Strip] Original: ${url}, Path parts: [${pathParts.join(', ')}]`);
            
            if (pathParts.length <= 1) {
                this._log(2, 'debug', `[URL Strip] Too few path segments, cannot strip`);
                return null;
            }
            
            // Remove one segment from the middle
            // Example: /costcard/costcard/main.js → /costcard/main.js
            pathParts.splice(-2, 1);
            u.pathname = '/' + pathParts.join('/');
            
            this._log(2, 'debug', `[URL Strip] Result: ${u.href}`);
            return u.href;
        } catch (e) {
            this._log(2, 'warn', `[URL Strip] Error: ${e.message}`);
            return null;
        }
    }

    analyzeWithRegex(content, sourceUrl) {
        const handlers = [];
        let match;
        
        // Pattern 1a: window.onmessage = function(...) { ... }
        // IMPROVED: Use brace counting for complex nested handlers (like Foxit)
        const onMessageRegex = /\bonmessage\s*=\s*function\s*\([^)]*\)\s*\{/gi;
        while ((match = onMessageRegex.exec(content)) !== null) {
            // Use proper brace counting to handle deeply nested structures
            const startIdx = match.index;
            const braceStart = content.indexOf('{', match.index + match[0].length - 1);
            if (braceStart > -1) {
                let depth = 1;
                let endIdx = braceStart + 1;
                
                while (depth > 0 && endIdx < content.length) {
                    const char = content[endIdx];
                    // Skip string literals to avoid false brace matches
                    if (char === '"' || char === "'" || char === '`') {
                        const quote = char;
                        endIdx++;
                        while (endIdx < content.length && content[endIdx] !== quote) {
                            if (content[endIdx] === '\\') endIdx++; // Skip escaped characters
                            endIdx++;
                        }
                    } else if (char === '{') {
                        depth++;
                    } else if (char === '}') {
                        depth--;
                    }
                    endIdx++;
                }
                
                if (depth === 0) {
                    const fullHandler = content.substring(startIdx, endIdx);
                    handlers.push({ handler: fullHandler, category: 'regex-onmessage-balanced', source: sourceUrl });
                    this._log(2, 'debug', `[Regex] Extracted balanced onmessage handler: ${fullHandler.length} chars`);
                }
            }
        }
        
        // Pattern 1b: window.onmessage = (event) => { ... }
        const onMessageArrowRegex = /\bonmessage\s*=\s*(\([^)]*\)\s*=>\s*\{(?:[^}]|\}(?![\s;]))*\})/gi;
        while ((match = onMessageArrowRegex.exec(content)) !== null) {
            handlers.push({ handler: match[1], category: 'regex-onmessage-arrow', source: sourceUrl });
        }
        
        // Pattern 2: .addEventListener('message', function(...) { ... })
        const addEventListenerRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*(function\s*\([^)]*\)\s*\{(?:[^}]|\}(?!\s*\)))*\})/gi;
        while ((match = addEventListenerRegex.exec(content)) !== null) {
            handlers.push({ handler: match[1], category: 'regex-event-listener-inline', source: sourceUrl });
        }
        
        // Pattern 3: .addEventListener('message', (param) => { ... }) - ARROW FUNCTIONS
        // Match everything from arrow to closing brace before addEventListener's closing paren
        // Updated to handle multiline and edge cases
        const arrowFunctionRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*(\([^)]*\)\s*=>\s*\{[\s\S]*?\})\s*\)/gi;
        while ((match = arrowFunctionRegex.exec(content)) !== null) {
            // Trim trailing whitespace/newlines from captured group
            const handlerCode = match[1].trim();
            
            // Special case: Check if handler just calls another method (e.g., "this.messageReceived(e)")
            const methodCallMatch = handlerCode.match(/\([^)]*\)\s*=>\s*\{\s*(?:this\.(\w+)|(\w+))\s*\([^)]*\)\s*\}/);
            if (methodCallMatch) {
                const methodName = methodCallMatch[1] || methodCallMatch[2]; // Support both this.method and method
                this._log(2, 'debug', `[Regex] Arrow function calls method: ${methodName}, attempting to extract full method`);
                // Try to find the method definition in the same file
                const methodDefRegex = new RegExp(`\\b${methodName}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{50,5000}?)\\n\\s{0,20}\\}`, 'i');
                const methodMatch = content.match(methodDefRegex);
                if (methodMatch) {
                    const fullMethod = `function ${methodName}${methodMatch[0]}`;
                    this._log(2, 'info', `[Regex] ✅ Extracted full method ${methodName} (${fullMethod.length} chars) from ${sourceUrl}`);
                    handlers.push({ handler: fullMethod, category: 'regex-event-listener-arrow+method-ref', source: sourceUrl });
                    continue; // Skip adding the wrapper
                } else {
                    this._log(2, 'debug', `[Regex] Could not find method definition for ${methodName}`);
                }
            }
            
            handlers.push({ handler: handlerCode, category: 'regex-event-listener-arrow', source: sourceUrl });
        }
        
        // Pattern 4: .addEventListener('message', param => { ... }) - ARROW WITHOUT PARENS
        const arrowNoParensRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*\s*=>\s*\{[\s\S]*?\})\s*\)/gi;
        while ((match = arrowNoParensRegex.exec(content)) !== null) {
            const handlerCode = match[1].trim();
            handlers.push({ handler: handlerCode, category: 'regex-event-listener-arrow-simple', source: sourceUrl });
        }
        
        // Pattern 4b: .addEventListener('message', (param => { ... })) - ARROW INSIDE PARENS (Azure pattern)
        const arrowInParensRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*\(([a-zA-Z_$][a-zA-Z0-9_$]*\s*=>\s*\{[\s\S]*?\})\s*\)\s*\)/gi;
        while ((match = arrowInParensRegex.exec(content)) !== null) {
            const handlerCode = match[1].trim();
            
            // Check if handler just calls another method
            const methodCallMatch = handlerCode.match(/([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*\{\s*(?:this\.(\w+)|(\w+))\s*\([^)]*\)\s*\}/);
            if (methodCallMatch) {
                const methodName = methodCallMatch[2] || methodCallMatch[3];
                this._log(2, 'debug', `[Regex] Arrow-in-parens calls method: ${methodName}, attempting to extract`);
                
                // Try multiple patterns for method definition (function, class method, arrow, etc.)
                const patterns = [
                    // Class/object method: methodName(params) { body }
                    new RegExp(`${methodName}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{50,5000}?)\\n\\s{0,20}\\}`, 'i'),
                    // Function: function methodName(params) { body }
                    new RegExp(`function\\s+${methodName}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]{50,5000}?)\\n\\s{0,20}\\}`, 'i'),
                    // Arrow: const/let/var methodName = (params) => { body }
                    new RegExp(`(?:const|let|var)\\s+${methodName}\\s*=\\s*\\([^)]*\\)\\s*=>\\s*\\{([\\s\\S]{50,5000}?)\\n\\s{0,20}\\}`, 'i')
                ];
                
                let methodMatch = null;
                for (const pattern of patterns) {
                    methodMatch = content.match(pattern);
                    if (methodMatch) break;
                }
                
                if (methodMatch) {
                    const fullMethod = `function ${methodName}${methodMatch[0].substring(methodMatch[0].indexOf(methodName) + methodName.length)}`;
                    this._log(2, 'info', `[Regex] ✅ Extracted method ${methodName} (${fullMethod.length} chars)`);
                    handlers.push({ handler: fullMethod, category: 'regex-event-listener-arrow-in-parens+method-ref', source: sourceUrl });
                    continue;
                } else {
                    this._log(2, 'debug', `[Regex] Method ${methodName} not found in ${sourceUrl}`);
                }
            }
            
            handlers.push({ handler: handlerCode, category: 'regex-event-listener-arrow-in-parens', source: sourceUrl });
        }
        
        // Pattern 5: .addEventListener('message', handlerName) - identifier reference
        const addEventListenerIdentifierRegex = /\.addEventListener\s*\(\s*["']message["']\s*,\s*([a-zA-Z0-9_$]+)\s*[,)]/gi;
        while ((match = addEventListenerIdentifierRegex.exec(content)) !== null) {
            const functionName = match[1];
            // Try to find the function definition (regular function or arrow function)
            const funcDefRegex = new RegExp(
                `(?:function\\s+${functionName}\\s*\\(|(?:var|let|const)\\s+${functionName}\\s*=\\s*(?:function\\s*\\(|\\([^)]*\\)\\s*=>|[a-zA-Z_$][a-zA-Z0-9_$]*\\s*=>))([\\s\\S]{0,5000}?)(?:\\n(?:function|var|let|const|class)|$)`,
                'i'
            );
            const funcMatch = content.match(funcDefRegex);
            if (funcMatch?.[0]) {
                handlers.push({ 
                    handler: funcMatch[0], 
                    category: 'regex-event-listener-identifier', 
                    source: sourceUrl, 
                    functionName: functionName 
                });
            }
        }
        
        // Pattern 6: Minified addEventListener (no spaces, webpack-style)
        // e.g., addEventListener("message",function(e){...},!1)
        const minifiedRegex = /addEventListener\(["']message["'],function\(([^)]*)\)\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}/gi;
        while ((match = minifiedRegex.exec(content)) !== null) {
            const fullHandler = 'function(' + match[1] + '){' + match[2] + '}';
            handlers.push({ 
                handler: fullHandler, 
                category: 'regex-minified-addEventListener', 
                source: sourceUrl 
            });
        }
        
        // Pattern 7: React useEffect with postMessage listener
        // e.g., useEffect(() => { window.addEventListener('message', handler) }, [])
        const reactUseEffectRegex = /useEffect\s*\(\s*\(\)\s*=>\s*\{([^}]*addEventListener\s*\(\s*["']message["']\s*,\s*([^)]+)\)[^}]*)\}/gi;
        while ((match = reactUseEffectRegex.exec(content)) !== null) {
            const effectBody = match[1];
            const handlerRef = match[2];
            // Try to extract the actual handler function from the effect body
            handlers.push({ 
                handler: effectBody, 
                category: 'regex-react-useEffect', 
                source: sourceUrl,
                note: 'React useEffect with message listener'
            });
        }
        
        // Pattern 8: Variable declaration then addEventListener (split pattern)
        // e.g., const handler = e => {...}; window.addEventListener('message', handler)
        const splitDeclarationRegex = /(?:const|let|var)\s+(\w+)\s*=\s*((?:function\s*\([^)]*\)|(?:\([^)]*\)|[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})[\s\S]{0,200}?addEventListener\s*\(\s*["']message["']\s*,\s*\1\s*[,)]/gi;
        while ((match = splitDeclarationRegex.exec(content)) !== null) {
            const variableName = match[1];
            const handlerCode = match[2];
            handlers.push({ 
                handler: handlerCode, 
                category: 'regex-split-declaration', 
                source: sourceUrl,
                functionName: variableName 
            });
        }
        
        return handlers.map(h => ({ 
            ...h, 
            handlerNode: null, 
            fullScriptContent: h.handler,
            handlerFlags: {},  // Empty flags for regex-extracted handlers
            score: 0  // Will be calculated by scoreHandler
        }));
    }

    // REMOVED: extractDynamicallyViaDebugger
    // This heavy debugger-based method has been removed for the slim fallback.
    // Primary extraction now happens via FrogPost DOM agent runtime telemetry.

    // REMOVED: confirmHandlerViaBreakpointExecution
    // This heavy breakpoint-based validation has been removed for the slim fallback.
    // Primary extraction now happens via FrogPost DOM agent runtime telemetry.

    // Webpack bundle unwrapping for better SPA handler detection
    _unwrapWebpackBundle(content, sourceUrl) {
        const handlers = [];
        
        // Pattern 1: Webpack 4/5 IIFE pattern
        // (function(modules) { ... })([function(e,t,n){...}, function(e,t,n){...}])
        const webpackIIFEPattern = /\(function\s*\([^)]*\)\s*\{[\s\S]*?\}\)\s*\(\s*\[([\s\S]+?)\]\s*\)/g;
        let match;
        
        while ((match = webpackIIFEPattern.exec(content)) !== null) {
            try {
                const modulesArray = match[1];
                const modules = this._extractWebpackModules(modulesArray);
                
                this._log(2, 'info', `[Webpack] Found ${modules.length} webpack modules in bundle`);
                
                modules.forEach((moduleCode, idx) => {
                    const moduleHandlers = this.analyzeScriptContent(moduleCode, `${sourceUrl}#webpack-module-${idx}`);
                    moduleHandlers.forEach(h => {
                        handlers.push({
                            ...h,
                            category: h.category + '-webpack',
                            source: `${sourceUrl}#webpack-module-${idx}`
                        });
                    });
                });
            } catch (e) {
                this._log(2, 'warn', `[Webpack] Failed to extract modules: ${e.message}`);
            }
        }
        
        return handlers;
    }
    
    _extractWebpackModules(modulesString) {
        const modules = [];
        let depth = 0;
        let currentModule = '';
        let inFunction = false;
        
        for (let i = 0; i < modulesString.length; i++) {
            const char = modulesString[i];
            
            // Detect function start
            if (char === 'f' && modulesString.substring(i, i + 8) === 'function') {
                if (depth === 0) {
                    inFunction = true;
                }
            }
            
            if (char === '{') {
                depth++;
            } else if (char === '}') {
                depth--;
                
                if (depth === 0 && inFunction) {
                    currentModule += char;
                    modules.push(currentModule.trim());
                    currentModule = '';
                    inFunction = false;
                    
                    // Skip comma and whitespace
                    while (i + 1 < modulesString.length && /[,\s]/.test(modulesString[i + 1])) {
                        i++;
                    }
                    continue;
                }
            }
            
            if (inFunction || depth > 0) {
                currentModule += char;
            }
        }
        
        // Add last module if exists
        if (currentModule.trim().length > 0) {
            modules.push(currentModule.trim());
        }
        
        this._log(2, 'debug', `[Webpack] Extracted ${modules.length} modules from bundle`);
        return modules;
    }

}

// New methods added to support dashboard calls
HandlerExtractor.prototype.extractStaticallyWithContext = async function(targetUrl, messageKeys, messageTypes, messageValues) {
    const handlers = new Set();
    
    // TELEMETRY-FIRST: Regex-based extraction only (AST removed)
    this._log(1, 'debug', '[Static Context] Using regex-based handler extraction');
    
    try {
        this._log(1, 'debug', `[Static Context] Fetching HTML for: ${targetUrl}`);
        const res = await fetch(targetUrl, { credentials: 'omit', cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const html = await res.text();

        // Extract external script src URLs
        const srcRegex = /<script[^>]*\bsrc=["']([^"']+)["'][^>]*><\/script>/gi;
        const srcs = new Set();
        let m;
        while ((m = srcRegex.exec(html)) !== null) {
            try {
                let scriptSrc = m[1];
                
                // CRITICAL FIX: Detect duplicate path segments in relative URLs
                // Example: page is /costcard/index.html, script is "costcard/main.js"
                // This creates /costcard/costcard/main.js (wrong!)
                // Fix: Detect and remove the duplicate segment
                if (!scriptSrc.startsWith('http://') && !scriptSrc.startsWith('https://') && !scriptSrc.startsWith('//')) {
                    try {
                        const baseUrl = new URL(targetUrl);
                        const basePath = baseUrl.pathname;
                        const baseDir = basePath.substring(0, basePath.lastIndexOf('/') + 1); // e.g., "/costcard/"
                        const baseDirSegments = baseDir.split('/').filter(Boolean); // ["costcard"]
                        const scriptSegments = scriptSrc.split('/').filter(Boolean); // ["costcard", "main.js"]
                        
                        // Check if first segment of script matches last segment of base directory
                        if (baseDirSegments.length > 0 && scriptSegments.length > 0) {
                            const lastBaseSeg = baseDirSegments[baseDirSegments.length - 1];
                            const firstScriptSeg = scriptSegments[0];
                            
                            if (lastBaseSeg === firstScriptSeg) {
                                // Remove duplicate segment from script src
                                scriptSegments.shift();
                                const fixedSrc = scriptSegments.join('/');
                                this._log(1, 'warn', `[URL Resolution] Duplicate path segment detected! Original: ${scriptSrc}, Fixed: ${fixedSrc}`);
                                scriptSrc = fixedSrc;
                            }
                        }
                    } catch (e) {
                        // If analysis fails, continue with original scriptSrc
                        this._log(2, 'debug', `[URL Resolution] Duplicate detection failed: ${e.message}`);
                    }
                }
                
                const absolute = new URL(scriptSrc, targetUrl).href;
                
                // Debug log for URL resolution
                this._log(2, 'debug', `[URL Resolution] Page: ${targetUrl}, Script src: ${m[1]}, Resolved: ${absolute}`);
                
                // Skip extension and data URLs
                if (!absolute.startsWith('chrome-extension://') && !absolute.startsWith('data:')) {
                    srcs.add(absolute);
                }
            } catch (err) {
                this._log(2, 'warn', `[URL Resolution] Failed to resolve: ${m[1]} from ${targetUrl}:`, err.message);
            }
        }

        // Extract inline scripts
        const inlineRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
        let im;
        let inlineIndex = 0;
        while ((im = inlineRegex.exec(html)) !== null) {
            const content = im[1] || '';
            if (content.trim().length < 20) { inlineIndex++; continue; }
            const sourceId = `${new URL(targetUrl).origin}/inline_${inlineIndex}.js`;
            const found = this.analyzeScriptContent(content, sourceId);
            found.forEach(h => handlers.add(h));
            inlineIndex++;
        }

        this._log(1, 'debug', `[Static Context] Found ${srcs.size} external script(s). Fetching...`, Array.from(srcs).slice(0, 30));
        const fetchLimit = 40; // Avoid fetching too many scripts
        const srcsArray = Array.from(srcs).slice(0, fetchLimit);
        
        // PERFORMANCE OPTIMIZATION: Batch fetch scripts in parallel (10 at a time)
        const BATCH_SIZE = 10;
        let totalFetched = 0;
        
        for (let i = 0; i < srcsArray.length; i += BATCH_SIZE) {
            const batch = srcsArray.slice(i, i + BATCH_SIZE);
            this._log(2, 'debug', `[Static Context] Fetching batch ${Math.floor(i/BATCH_SIZE) + 1}/${Math.ceil(srcsArray.length/BATCH_SIZE)} (${batch.length} scripts)`);
            
            const batchResults = await Promise.all(
                batch.map(async (src) => {
                    try {
                        let sres = await fetch(src, { credentials: 'omit', cache: 'no-store' });
                        
                        // CRITICAL: If 404, try removing one path segment (common build issue)
                        if (!sres.ok && sres.status === 404) {
                            this._log(2, 'warn', `[Static Context] ❌ 404: ${src}`);
                            const altUrl = this._tryStripOnePathSegment(src);
                            if (altUrl && altUrl !== src) {
                                this._log(2, 'debug', `[Static Context] Trying alternate URL: ${altUrl}`);
                                try {
                                    const altRes = await fetch(altUrl, { credentials: 'omit', cache: 'no-store' });
                                    if (altRes.ok) {
                                        sres = altRes;
                                        this._log(2, 'success', `[Static Context] ✓ Alternate URL worked!`);
                                    }
                                } catch (e) {
                                    // Silent fail
                                }
                            }
                        }
                        
                        if (!sres.ok) return null;
                        
                        const js = await sres.text();
                        return { src, js };
                    } catch (e) {
                        this._log(2, 'warn', `[Static Context] Failed to fetch ${src}: ${e.message}`);
                        return null;
                    }
                })
            );
            
            // Analyze all successful fetches in the batch
            for (const result of batchResults) {
                if (!result) continue;
                
                const { src, js } = result;
                totalFetched++;
                
                this._log(2, 'debug', `[Static Context] Analyzing script: ${js.length} bytes from ${src.split('/').pop()}`);
                
                // First: try webpack unwrapping for bundled code
                const webpackHandlers = this._unwrapWebpackBundle(js, src);
                webpackHandlers.forEach(h => handlers.add(h));
                if (webpackHandlers.length > 0) {
                    this._log(1, 'success', `[Static Context] Webpack: Found ${webpackHandlers.length} handler(s) in webpack bundle`);
                }
                
                // Second: regular analysis on full script
                const found = this.analyzeScriptContent(js, src);
                found.forEach(h => handlers.add(h));
                this._log(1, 'info', `[Static Context] Analyzed ${src.split('/').pop()}. Found ${found.length} candidate(s) via regex.`);
            }
        }
        
        this._log(1, 'success', `[Static Context] Successfully fetched ${totalFetched}/${srcsArray.length} scripts in parallel batches`);
        this._log(1, 'success', `[Static Context] Extraction complete. Candidates: ${handlers.size}`);
    } catch (e) {
        this._log(1, 'error', `[Static Context] Error: ${e?.message || e}`);
    }
    return Array.from(handlers);
};

// REMOVED: extractWithStrictIframe
// This method has been simplified away since it depended on the removed debugger extraction.
// Use extractStaticallyWithContext instead as the slim fallback.
HandlerExtractor.prototype.extractWithStrictIframe = async function(targetUrl, messageKeys, messageTypes, messageValues) {
    // Redirected to static analysis fallback
    this._log(1, 'debug', `[Slim Fallback] Redirecting to static analysis...`);
    return this.extractStaticallyWithContext(targetUrl, messageKeys, messageTypes, messageValues);
};
