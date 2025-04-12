/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-12
 */
window.frogPostState = {
    frameConnections: new Map(),
    messages: [],
    activeEndpoint: null,
    activeUrl: null,
    loadedData: {
        urls: new Set()
    }
};

let debugMode = false;

const log = {
    styles: {
        info: 'color: #0066cc; font-weight: bold',
        success: 'color: #00cc66; font-weight: bold',
        warning: 'color: #ff9900; font-weight: bold',
        error: 'color: #cc0000; font-weight: bold',
        handler: 'color: #6600cc; font-weight: bold',
        scan: 'color: #FFDC77; font-weight: bold',
        debug: 'color: #999999; font-style: italic'
    },
    _log: (style, icon, msg, details) => {
        console.log(`%c ${icon} ${msg}`, style);
        // Use the debugMode variable directly from dashboard.js scope
        if (details && (debugMode || typeof details === 'string')) {
            const detailStyle = style === log.styles.error ? 'color: #cc0000;' : 'color: #666666;';
            if (details instanceof Error) {
                console.error('%c    ' + details.message, detailStyle);
                if (details.stack && debugMode) {
                    console.error('%c    Stack Trace:', detailStyle, details.stack);
                }
            } else if (typeof details === 'object' && debugMode) {
                console.log('%c    Details:', detailStyle, details);
            } else {
                console.log('%c    ' + details, detailStyle);
            }
        }
    },
    info: (msg, details) => log._log(log.styles.info, 'ℹ️', msg, details),
    success: (msg, details) => log._log(log.styles.success, '✅', msg, details),
    warning: (msg, details) => log._log(log.styles.warning, '⚠️', msg, details),
    warn: (msg, details) => log.warning(msg, details),
    error: (msg, details) => log._log(log.styles.error, '❌', msg, details),
    handler: (msg, details) => log._log(log.styles.handler, '🔍', msg, details),
    scan: (msg, details) => log._log(log.styles.scan, '🔄', msg, details),
    debug: (msg, ...args) => {
        if (debugMode) { // Access dashboard.js's debugMode directly
            console.log('%c 🔧 ' + msg, log.styles.debug, ...args);
        }
    }
};
window.log = log;

function printBanner() {
    console.log(`
  _____                ____           _
 |  ___| __ ___   __ _|  _ \\ ___  ___| |_
 | |_ | '__/ _ \\ / _\` | |_) / _ \\/ __| __|
 |  _|| | | (_) | (_| |  __/ (_) \\__ \\ |_
 |_|  |_|  \\___/ \\__, |_|   \\___/|___/\\__|
                 |___/
\n`);
    log.info('Initializing dashboard...');
    localStorage.clear();
    sessionStorage.clear();
    log.info('All Storage cleared!');
}

function toggleDebugMode() {
    debugMode = !debugMode;
    log.info(`Debug mode ${debugMode ? 'enabled' : 'disabled'}`);
    const debugButton = document.getElementById('debugToggle');
    if (debugButton) {
        debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF';
        debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off';
    }
    return debugMode;
}

const knownHandlerEndpoints = new Set();
const endpointsWithHandlers = new Set();
const messages = [];
let activeEndpoint = null;
const buttonStates = new Map();
const reportButtonStates = new Map();
const traceButtonStates = new Map();
let callbackUrl = null;
const CALLBACK_URL_STORAGE_KEY = 'callback_url';
let refreshInterval;
const modifiedEndpoints = new Map();
const launchInProgressEndpoints = new Set();
const connectionCache = new Map();

function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    const xssPatterns = [
        /<\s*script/i, /<\s*img[^>]+onerror/i, /javascript\s*:/i,
        /on\w+\s*=/i, /<\s*iframe/i, /<\s*svg[^>]+on\w+/i,
        /alert\s*\(/i, /console\.log\s*\(/i, /eval\s*\(/i,
        /Function\s*\(/i, /setTimeout\s*\(/i, /setInterval\s*\(/i,
        /document\.domain/i, /document\.location/i, /location\.href/i
    ];
    let containsXss = false;
    for (const pattern of xssPatterns) {
        if (pattern.test(str)) {
            containsXss = true;
            break;
        }
    }
    if (containsXss) {
        let sanitized = str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
        return `[SANITIZED PAYLOAD] ${sanitized}`;
    }
    return str;
}

function getBaseUrl(url) {
    try {
        const norm = normalizeEndpointUrl(url);
        return norm?.components ? norm.components.origin + norm.components.path : null;
    } catch (e) {
        log.handler(`[Get Base URL] Error getting base URL for: ${url}`, e.message);
        return null;
    }
}


function sanitizeMessageData(data) {
    if (!data) return data;
    if (typeof data === 'string') {
        try {
            const parsed = JSON.parse(data);
            return sanitizeMessageData(parsed);
        } catch (e) {
            return sanitizeString(data);
        }
    }
    if (Array.isArray(data)) {
        return data.map(item => sanitizeMessageData(item));
    }
    if (typeof data === 'object' && data !== null) {
        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            sanitized[key] = sanitizeMessageData(value);
        }
        return sanitized;
    }
    return data;
}

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function normalizeEndpointUrl(url) {
    try {
        if (!url || typeof url !== 'string' || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) {
            return { normalized: url, components: null, key: url };
        }
        let absoluteUrlStr = url;
        if (!url.includes('://') && !url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }
        else if (url.startsWith('//')) { absoluteUrlStr = 'https:' + url; }
        const urlObj = new URL(absoluteUrlStr);
        if (['about:', 'chrome:', 'moz-extension:', 'chrome-extension:', 'blob:', 'data:'].includes(urlObj.protocol)) {
            return { normalized: url, components: null, key: url };
        }
        const key = urlObj.origin + urlObj.pathname + urlObj.search;
        const normalized = key;
        return {
            normalized: normalized,
            components: { origin: urlObj.origin, path: urlObj.pathname, query: urlObj.search, hash: urlObj.hash },
            key: key
        };
    } catch (e) {
        log.handler(`[Normalize URL] Error: ${e.message}`, url);
        return { normalized: url, components: null, key: url };
    }
}

function getStorageKeyForUrl(url) {
    return normalizeEndpointUrl(url)?.key || url;
}

function addFrameConnection(originUrl, destinationUrl, targetMap) {
    const originInfo = normalizeEndpointUrl(originUrl);
    const destInfo = normalizeEndpointUrl(destinationUrl);
    const originKey = originInfo?.key;
    const destKey = destInfo?.key;

    if (!originKey || !destKey || originKey === destKey || originKey === 'null' || destKey === 'null' || originKey === 'access-denied-or-invalid' || destKey === 'access-denied-or-invalid') {
        return false;
    }

    let addedNew = false;
    if (!targetMap.has(originKey)) {
        targetMap.set(originKey, new Set());
        addedNew = true;
    }
    const destSet = targetMap.get(originKey);
    if (!destSet.has(destKey)) {
        destSet.add(destKey);
        addedNew = true;
    }
    return addedNew;
}

function showToastNotification(message, type = 'error', duration = 5000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    const timeoutId = setTimeout(() => {
        toast.classList.remove('show'); // Trigger fade-out via CSS transition
        toast.classList.add('fade-out');

        toast.addEventListener('transitionend', () => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
            // Optional: Remove container if it becomes empty
            // if (container.children.length === 0 && container.parentNode) {
            //    container.parentNode.removeChild(container);
            // }
        }, { once: true }); // Use once: true for reliability

        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, duration + 600);

    }, duration);

    toast.addEventListener('click', () => {
        clearTimeout(timeoutId);
        toast.classList.remove('show');
        toast.classList.add('fade-out');
        toast.addEventListener('transitionend', () => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, { once: true });
        setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 600);
    });
}

function updateButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint'));
    if (endpointKey) {
        buttonStates.set(endpointKey, { state, options });
    }

    const states = {
        start: { text: '▶', title: 'Start checks', class: 'default' },
        csp: { text: '⏳', title: 'Checking CSP...', class: 'checking is-working' },
        analyze: { text: '⏳', title: 'Analyzing...', class: 'checking is-working' },
        launch: { text: '🚀', title: 'Launch Payload Testing', class: 'green' },
        success: { text: '✓', title: 'Check successful', class: 'success' },
        warning: { text: '⚠', title: 'No handler found', class: 'yellow' },
        error: { text: '✕', title: 'Check failed', class: 'red' }
    };
    let newState = states[state] || states.start;

    button.textContent = newState.text;
    button.title = newState.title;
    button.classList.remove('default', 'checking', 'is-working', 'green', 'success', 'yellow', 'red', 'has-critical-sinks', 'show-next-step-arrow', 'show-next-step-emoji');
    button.classList.add(...newState.class.split(' '));
    button.style.animation = '';

    if (newState.class.includes('is-working')) button.classList.add('is-working');
    if (state === 'launch' && options.hasCriticalSinks) {
        button.classList.add('has-critical-sinks');
        button.title += ' (Critical Sinks Found!)';
    }
    if (options.showArrow) button.classList.add('show-next-step-arrow');
    if (options.showEmoji) button.classList.add('show-next-step-emoji');
}


async function handleTraceButton(endpoint, traceButton) {
    const originalFullEndpoint = endpoint;
    const endpointKey = getStorageKeyForUrl(originalFullEndpoint);

    traceButton.classList.remove('show-next-step-emoji');
    traceButton.style.animation = '';

    if (!endpointKey) {
        window.log.error("Trace: Cannot determine endpoint key", originalFullEndpoint);
        updateTraceButton(traceButton, 'error');
        return;
    }

    const traceInProgressKey = `trace-in-progress-${endpointKey}`;
    if (sessionStorage.getItem(traceInProgressKey)) {
        window.log.handler(`Trace already in progress for key: ${endpointKey}`);
        return;
    }
    sessionStorage.setItem(traceInProgressKey, 'true');
    window.log.scan(`Starting message trace for endpoint key: ${endpointKey}`);
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
    let analysisStorageKey = endpointKey;
    let report = {};
    let payloads = [];
    let vulnAnalysis = { sinks: [], securityIssues: [], dataFlows: [] };
    let uniqueStructures = [];
    let usedAstGenerator = false;
    let staticAnalyzer = null;
    let staticAnalysisData = null;

    try {
        updatePhase('collection');
        if (!window.handlerTracer) window.handlerTracer = new HandlerTracer();
        if (typeof window.analyzeHandlerStatically === 'function') {
            staticAnalyzer = window.analyzeHandlerStatically;
        } else {
            window.log.warn("Static analyzer (analyzeHandlerStatically) not found on window object.");
        }

        const mappingKey = `analyzed-url-for-${endpointKey}`;
        const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
        endpointUrlUsedForAnalysis = mappingResult[mappingKey] || originalFullEndpoint;
        analysisStorageKey = getStorageKeyForUrl(endpointUrlUsedForAnalysis);

        const bestHandlerStorageKey = `best-handler-${analysisStorageKey}`;
        const storedHandlerData = await new Promise(resolve => chrome.storage.local.get([bestHandlerStorageKey], resolve));
        bestHandler = storedHandlerData[bestHandlerStorageKey];
        handlerCode = bestHandler?.handler || bestHandler?.code;

        if (!handlerCode) throw new Error(`No handler code found in storage (${bestHandlerStorageKey}). Run Play first.`);

        const relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
        window.log.handler(`[Trace] Using ${relevantMessages.length} messages for analysis (key: ${endpointKey}).`);

        updatePhase('analysis');
        await new Promise(r => setTimeout(r, 50));

        if (staticAnalyzer && handlerCode) {
            try {
                const staticAnalysisResults = staticAnalyzer(handlerCode);
                if (staticAnalysisResults?.success && staticAnalysisResults.analysis) {
                    staticAnalysisData = staticAnalysisResults.analysis;
                    window.log.handler(`[Trace] Static analysis successful. Paths: ${staticAnalysisData.accessedEventDataPaths?.size || 0}, Flows: ${staticAnalysisData.dataFlows?.length || 0}, Conditions: ${Object.keys(staticAnalysisData.requiredConditions || {}).length}`);
                } else {
                    window.log.warn(`[Trace] Static analysis failed or returned no/invalid analysis object: ${staticAnalysisResults?.error}.`);
                }
            } catch(e) {
                window.log.error("Error executing static analyzer:", e);
            }
        }

        vulnAnalysis = window.handlerTracer.analyzeHandlerForVulnerabilities(handlerCode, staticAnalysisData);
        hasCriticalSinks = vulnAnalysis.sinks?.some(s => ['Critical', 'High'].includes(s.severity)) || false;


        updatePhase('structure');
        await new Promise(r => setTimeout(r, 50));

        updatePhase('generation');
        await new Promise(r => setTimeout(r, 50));

        if (relevantMessages.length > 0) {
            window.log.handler("[Trace] Messages found. Using standard message-based payload generation.");
            uniqueStructures = window.handlerTracer.analyzeJsonStructures(relevantMessages);
            window.log.handler(`[Trace] Found ${uniqueStructures.length} unique structures from messages.`);
            payloads = await window.handlerTracer.generateFuzzingPayloads(
                uniqueStructures,
                vulnAnalysis,
                relevantMessages
            );
        } else {
            window.log.handler("[Trace] No messages found (Silent Listener). Attempting AST-based payload generation.");
            if (staticAnalysisData && (staticAnalysisData.accessedEventDataPaths?.size > 0 || staticAnalysisData.dataFlows?.length > 0)) {
                payloads = await window.handlerTracer.generateAstBasedPayloads(
                    staticAnalysisData,
                    vulnAnalysis
                );
                usedAstGenerator = true;
                window.log.handler(`[Trace] AST-based generator created ${payloads.length} payloads.`);
            } else {
                window.log.warn("[Trace] No messages and insufficient AST data. Payload generation skipped.");
                payloads = [];
            }
        }

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
                dataFlows: vulnAnalysis.dataFlows || [],
                payloadsGeneratedCount: payloads.length,
                uniqueStructures: uniqueStructures || [],
                staticAnalysisUsed: usedAstGenerator,
                messagesAvailable: relevantMessages.length > 0,
                requiredConditions: staticAnalysisData?.requiredConditions || {}
            },
            summary: {
                messagesAnalyzed: relevantMessages.length,
                patternsIdentified: uniqueStructures.length,
                sinksFound: vulnAnalysis.sinks?.length || 0,
                issuesFound: vulnAnalysis.securityIssues?.length || 0,
                payloadsGenerated: payloads.length,
                securityScore: securityScore,
                staticAnalysisUsed: usedAstGenerator
            }
        };

        window.log.info(`[Trace] Proceeding to save report. Payload count: ${payloads?.length}. Used AST Generator: ${usedAstGenerator}`);
        const reportStorageKey = analysisStorageKey;

        const reportSaved = await window.traceReportStorage.saveTraceReport(reportStorageKey, report);
        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(reportStorageKey, payloads);

        if (!reportSaved || !payloadsSaved) {
            throw new Error("Failed to save trace report or payloads.");
        }
        window.log.success(`Trace report & ${payloads?.length} payloads saved for key: ${reportStorageKey}`);

        const traceInfoKey = `trace-info-${endpointKey}`;
        await chrome.storage.local.set({
            [traceInfoKey]: {
                success: true,
                criticalSinks: hasCriticalSinks,
                analyzedUrl: endpointUrlUsedForAnalysis,
                analysisStorageKey: analysisStorageKey,
                timestamp: Date.now(),
                payloadCount: payloads?.length || 0,
                sinkCount: vulnAnalysis.sinks?.length || 0,
                usedStaticAnalysis: usedAstGenerator
            }
        });
        window.log.handler(`Saved trace status for UI key ${traceInfoKey}: success=true, criticalSinks=${hasCriticalSinks}, payloadCount=${payloads?.length || 0}, usedStatic=${usedAstGenerator}...`);

        updateTraceButton(traceButton, 'success');
        if (playButton) updateButton(playButton, 'launch', { hasCriticalSinks: hasCriticalSinks, showEmoji: true });
        if (reportButton) {
            const reportState = hasCriticalSinks || (vulnAnalysis.securityIssues?.length || 0) > 0 ? 'green' : 'default';
            updateReportButton(reportButton, reportState, originalFullEndpoint);
        }

        window.log.info("[Trace] Analysis completed successfully");
        updatePhase('saving', 'completed');

    } catch (error) {
        console.error(`[Trace] Error during trace for ${originalFullEndpoint}:`, error);
        window.log.error(`[Trace] Error for ${originalFullEndpoint}:`, error.message);
        updateTraceButton(traceButton, 'error');
        const traceInfoKey = `trace-info-${endpointKey}`;
        try {
            await chrome.storage.local.set({ [traceInfoKey]: { success: false, criticalSinks: false, error: error.message } });
        } catch (e) { console.error("Failed to save error state:", e); }

        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        updatePhase('error', 'error');
        const errorPhaseLabel = progressContainer?.querySelector('.phase[data-phase="error"] .label');
        if(errorPhaseLabel) errorPhaseLabel.textContent = `Error: ${error.message.substring(0, 50)}...`;

    } finally {
        setTimeout(() => { if (progressContainer?.parentNode) progressContainer.parentNode.removeChild(progressContainer); }, 3000);
        sessionStorage.removeItem(traceInProgressKey);
        window.log.handler(`[Trace] Finished trace attempt for key ${endpointKey}`);
        setTimeout(() => requestAnimationFrame(updateDashboardUI), 100);
    }
}

function extractAllFieldsFromObject(obj, prefix = '', fields = []) {
    if (!obj || typeof obj !== 'object') return fields;
    for (const key in obj) {
        if (Object.hasOwnProperty.call(obj, key)) {
            const fieldPath = prefix ? `${prefix}.${key}` : key;
            fields.push(fieldPath);
            if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                extractAllFieldsFromObject(obj[key], fieldPath, fields);
            } else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') {
                extractAllFieldsFromObject(obj[key][0], `${fieldPath}[0]`, fields);
            }
        }
    }
    return [...new Set(fields)];
}

function getFieldTypesFromObject(obj, prefix = '', types = {}) {
    if (!obj || typeof obj !== 'object') return types;
    for (const key in obj) {
        if (Object.hasOwnProperty.call(obj, key)) {
            const fieldPath = prefix ? `${prefix}.${key}` : key;
            types[fieldPath] = Array.isArray(obj[key]) ? 'array' : typeof obj[key];
            if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
                getFieldTypesFromObject(obj[key], fieldPath, types);
            } else if (Array.isArray(obj[key]) && obj[key].length > 0 && typeof obj[key][0] === 'object') {
                getFieldTypesFromObject(obj[key][0], `${fieldPath}[0]`, types);
            }
        }
    }
    return types;
}

function createSyntheticStructureFromPaths(pathsSet) {
    const structure = {};

    function setPathValue(obj, pathParts, value) {
        let current = obj;
        for (let i = 0; i < pathParts.length - 1; i++) {
            const part = pathParts[i];
            if (!current[part] || typeof current[part] !== 'object') {
                const nextPart = pathParts[i + 1];
                current[part] = /^\d+$/.test(nextPart) ? [] : {};
            }
            current = current[part];
        }
        const lastPart = pathParts[pathParts.length - 1];
        if (typeof current === 'object' && current !== null) {
            if (current[lastPart] === undefined) {
                current[lastPart] = value;
            }
        }
    }

    const getDefaultValue = (path) => {
        const lowerPath = path.toLowerCase();
        if (lowerPath.includes('url') || lowerPath.includes('src') || lowerPath.includes('href')) return "https://example.com";
        if (lowerPath.includes('id') || lowerPath.includes('count') || lowerPath.includes('index')) return 0;
        if (lowerPath.includes('enabled') || lowerPath.includes('isvalid') || lowerPath.includes('success')) return true;
        if (lowerPath.includes('name') || lowerPath.includes('title')) return "Placeholder Name";
        if (lowerPath.includes('description') || lowerPath.includes('text')) return "Placeholder text content.";
        return "placeholder_value";
    };

    const sortedPaths = Array.from(pathsSet).sort((a, b) => a.split(/[\.\[]/).length - b.split(/[\.\[]/).length);

    sortedPaths.forEach(path => {
        const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g)
            ?.map(part => part.startsWith('[') ? part.substring(1, part.length - 1).replace(/['"`]/g, '') : part) || [];

        if (parts.length > 0 && path !== '(root)') {
            setPathValue(structure, parts, getDefaultValue(path));
        }
    });

    if (pathsSet.has('(root)') && Object.keys(structure).length === 0) {
        return [{
            type: 'raw_value',
            original: getDefaultValue('(root)'),
            fields: [],
            fieldTypes: {}
        }];
    }

    const fieldTypes = getFieldTypesFromObject(structure);
    const fields = extractAllFieldsFromObject(structure);

    return [{
        type: 'object',
        original: JSON.parse(JSON.stringify(structure)),
        pathsToFuzz: fields.map(f => ({ path: f, type: fieldTypes[f] || typeof f })),
        examples: [{ data: JSON.parse(JSON.stringify(structure)) }],
        source: 'static-analysis'
    }];
}

function updateTraceButton(button, state, options = {}) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint'));
    if (endpointKey) {
        traceButtonStates.set(endpointKey, { state, options });
    }

    const states = {
        default: { text: '✨', title: 'Start message tracing', class: 'default' },
        disabled: { text: '✨', title: 'Start message tracing (disabled)', class: 'disabled' },
        checking: { text: '⏳', title: 'Tracing in progress...', class: 'checking is-working' },
        success: { text: '✨', title: 'Trace completed', class: 'green' },
        error: { text: '❌', title: 'Tracing failed', class: 'error' }
    };

    const newState = states[state] || states.disabled;
    button.textContent = newState.text;
    button.title = newState.title;

    const classesToRemove = ['default', 'disabled', 'checking', 'is-working', 'green', 'error', 'show-next-step-emoji', 'highlight-next-step'];
    button.classList.remove(...classesToRemove);
    button.classList.add('iframe-trace-button');
    button.classList.add(...newState.class.split(' '));

    button.style.animation = '';

    if (newState.class.includes('is-working')) {
        button.classList.add('is-working');
    }

    if (options?.showEmoji) {
        button.classList.add('show-next-step-emoji');
    }

    if (state === 'disabled') {
        button.setAttribute('disabled', 'true');
        button.classList.add('disabled');
    } else {
        button.removeAttribute('disabled');
    }
}

function updateReportButton(button, state, endpoint) {
    if (!button) return;
    const endpointKey = getStorageKeyForUrl(endpoint);

    const states = {
        disabled: { text: '📋', title: 'Analysis Report (disabled)', className: 'iframe-report-button disabled' },
        default: { text: '📋', title: 'View Analysis Report', className: 'iframe-report-button default' }, // Applies 'default' class
        green: { text: '📋', title: 'View Analysis Report (Findings)', className: 'iframe-report-button green' } // Applies 'green' class
    };
    const newState = states[state] || states.disabled;
    button.textContent = newState.text;
    button.title = newState.title;
    button.className = newState.className;

    if (endpointKey) {
        reportButtonStates.set(endpointKey, state);
    }
}

function originMatchesSource(currentOrigin, source, endpointOrigin) {
    if (source === '*') {
        return true;
    }
    if (source === "'self'") {
        return endpointOrigin !== null && currentOrigin === endpointOrigin;
    }
    if (source === "'none'") {
        return false;
    }
    const cleanCurrentOrigin = currentOrigin.endsWith('/') ? currentOrigin.slice(0, -1) : currentOrigin;
    const cleanSource = source.endsWith('/') ? source.slice(0, -1) : source;
    if (cleanCurrentOrigin === cleanSource) {
        return true;
    }
    if (cleanSource.startsWith('*.')) {
        const domainPart = cleanSource.substring(2);
        // Check if origin ends with '.domain.com' and is not just 'domain.com' itself
        // Ensure there's something before the matched part (e.g., 'www.' in 'www.domain.com')
        return cleanCurrentOrigin.endsWith('.' + domainPart) && cleanCurrentOrigin.length > (domainPart.length + 1);
    }

    return false;
}

async function performEmbeddingCheck(endpoint) {
    log.handler(`[Embedding Check] Starting for: ${endpoint}`);
    try {
        const response = await fetch(endpoint, { method: 'HEAD', cache: 'no-store' });
        log.handler(`[Embedding Check] HEAD request status: ${response.status}`);

        const xFrameOptions = response.headers.get('X-Frame-Options');
        if (xFrameOptions) {
            log.handler(`[Embedding Check] Found X-Frame-Options: ${xFrameOptions}`);
            const xfoUpper = xFrameOptions.toUpperCase();
            if (xfoUpper === 'DENY') {
                const reason = `X-Frame-Options: ${xFrameOptions}`;
                log.warning(`[Embedding Check] Blocked by ${reason}`);
                return { status: reason, className: 'red', embeddable: false };
            }
            if (xfoUpper === 'SAMEORIGIN') {
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try { endpointOrigin = new URL(endpoint).origin; } catch(e) { /* ignore */ }

                if (!endpointOrigin || currentOrigin !== endpointOrigin) {
                    const reason = `X-Frame-Options: ${xFrameOptions} (Origin mismatch: ${currentOrigin} vs ${endpointOrigin || 'invalid'})`;
                    log.warning(`[Embedding Check] Blocked by ${reason}`);
                    return { status: reason, className: 'red', embeddable: false };
                }
            }
        }

        const csp = response.headers.get('Content-Security-Policy');
        if (csp) {
            log.handler(`[Embedding Check] Found Content-Security-Policy header.`);
            const directives = csp.split(';').map(d => d.trim());
            const frameAncestors = directives.find(d => d.startsWith('frame-ancestors'));

            if (frameAncestors) {
                const sourcesString = frameAncestors.substring('frame-ancestors'.length).trim();
                const sources = sourcesString.split(/\s+/);
                log.handler(`[Embedding Check] Parsed frame-ancestors sources: [${sources.join(', ')}]`);

                if (sources.includes("'none'")) {
                    const reason = `CSP: frame-ancestors 'none'`;
                    log.warning(`[Embedding Check] Blocked by ${reason}`);
                    return { status: reason, className: 'red', embeddable: false };
                }
                const currentOrigin = window.location.origin;
                let endpointOrigin = null;
                try {
                    endpointOrigin = new URL(endpoint).origin;
                    log.handler(`[Embedding Check] Current Origin: ${currentOrigin}, Endpoint Origin: ${endpointOrigin}`);
                } catch(e) {
                    const reason = `Invalid endpoint URL for origin check: ${endpoint}`;
                    log.error(`[Embedding Check] Error: ${reason}`, e);
                    return { status: reason, className: 'red', embeddable: false };
                }

                let isAllowedByDirective = false;
                for (const source of sources) {
                    if (originMatchesSource(currentOrigin, source, endpointOrigin)) {
                        log.handler(`[Embedding Check] Origin ${currentOrigin} MATCHED source '${source}'`);
                        isAllowedByDirective = true;
                        break;
                    } else {
                        log.handler(`[Embedding Check] Origin ${currentOrigin} did NOT match source '${source}'`);
                    }
                }

                if (!isAllowedByDirective) {
                    const reason = `CSP: frame-ancestors does not allow ${currentOrigin}`;
                    log.warning(`[Embedding Check] Blocked by ${reason}. Allowed: [${sources.join(', ')}]`);
                    return { status: reason, className: 'red', embeddable: false };
                }
                // If loop finishes and isAllowedByDirective is true, embedding is permitted by CSP
                log.handler(`[Embedding Check] Origin ${currentOrigin} was allowed by frame-ancestors directive.`);
            } else {
                log.handler(`[Embedding Check] No frame-ancestors directive found in CSP.`);
            }
        } else {
            log.handler(`[Embedding Check] No Content-Security-Policy header found.`);
        }

        log.success(`[Embedding Check] Frame can be embedded for ${endpoint}`);
        return { status: 'Frame can be embedded', className: 'green', embeddable: true };

    } catch (error) {
        log.error(`[Embedding Check] Header check failed for ${endpoint}: ${error.message}`, error);
        return { status: `Header check failed: ${error.message}`, className: 'red', embeddable: false };
    }
}


function getMessageCount(endpointKey) {
    return messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === endpointKey || destKey === endpointKey;
    }).length;
}

function createHostElement(hostKey, iframesSet) {
    const hostElement = document.createElement("div");
    hostElement.className = "endpoint-host";

    const hostRow = document.createElement("div");
    hostRow.className = "host-row";

    const hostName = document.createElement("span");
    hostName.className = "host-name";
    const hostMessageCount = getMessageCount(hostKey);
    hostName.textContent = hostMessageCount > 0 ? `${hostKey} (${hostMessageCount})` : hostKey;

    hostRow.addEventListener("click", (e) => {
        e.stopPropagation();
        activeEndpoint = hostKey;
        renderMessages();
        highlightActiveEndpoint();
    });

    hostRow.appendChild(hostName);
    hostElement.appendChild(hostRow);

    const iframeContainer = document.createElement("div");
    iframeContainer.className = "iframe-container";

    iframesSet.forEach((iframeKey) => {
        const iframeRow = document.createElement("div");
        iframeRow.className = "iframe-row";
        iframeRow.setAttribute("data-endpoint-key", iframeKey);

        const iframeName = document.createElement("span");
        iframeName.className = "iframe-name";
        const iframeMessageCount = getMessageCount(iframeKey);
        iframeName.textContent = iframeMessageCount > 0 ? `${iframeKey} (${iframeMessageCount})` : iframeKey;

        iframeRow.addEventListener("click", (e) => {
            e.stopPropagation();
            activeEndpoint = iframeKey;
            renderMessages();
            highlightActiveEndpoint();
        });

        const iframeButtonContainer = createActionButtonContainer(iframeKey);
        iframeRow.appendChild(iframeName);
        iframeRow.appendChild(iframeButtonContainer);
        iframeContainer.appendChild(iframeRow);
    });

    if (iframesSet.size > 0) {
        hostElement.appendChild(iframeContainer);
    }
    return hostElement;
}


function createActionButtonContainer(endpointKey) {
    const buttonContainer = document.createElement("div");
    buttonContainer.className = "button-container";

    const playButton = document.createElement("button");
    playButton.className = "iframe-check-button default";
    playButton.setAttribute("data-endpoint", endpointKey);
    playButton.textContent = '▶';
    playButton.title = 'Start checks / Launch Fuzzer';

    const traceButton = document.createElement("button");
    traceButton.className = "iframe-trace-button disabled";
    traceButton.setAttribute("data-endpoint", endpointKey);
    traceButton.textContent = '✨';
    traceButton.title = 'Start message tracing (disabled)';
    traceButton.setAttribute('disabled', 'true');

    const reportButton = document.createElement("button");
    reportButton.className = "iframe-report-button disabled";
    reportButton.setAttribute("data-endpoint", endpointKey);
    reportButton.textContent = '📋';
    reportButton.title = 'Analysis Report (disabled)';

    const handlerButton = document.createElement("button");
    handlerButton.className = "iframe-handler-button";
    handlerButton.setAttribute("data-endpoint", endpointKey);
    handlerButton.textContent = '{ }';

    const hasHandler = endpointsWithHandlers.has(endpointKey);

    handlerButton.disabled = !hasHandler;
    handlerButton.title = hasHandler ? 'View Captured Listeners' : 'No Listeners Captured Yet';
    if (hasHandler) {
        handlerButton.classList.add('green');
        handlerButton.style.backgroundColor = '#222';
    } else {
        handlerButton.classList.add('disabled');
    }

    handlerButton.disabled = !hasHandler;
    handlerButton.title = hasHandler ? 'View Captured Listeners' : 'No Listeners Captured Yet';
    handlerButton.classList.add(hasHandler ? 'green' : 'disabled');
    const savedPlayStateInfo = buttonStates.get(endpointKey);
    if (savedPlayStateInfo) { updateButton(playButton, savedPlayStateInfo.state, savedPlayStateInfo.options); }
    else { updateButton(playButton, 'start'); }

    const savedTraceStateInfo = traceButtonStates.get(endpointKey);
    if (savedTraceStateInfo) { updateTraceButton(traceButton, savedTraceStateInfo.state, savedTraceStateInfo.options); }
    else { if (playButton.classList.contains('success') || playButton.classList.contains('green')) { updateTraceButton(traceButton, 'default'); } else { updateTraceButton(traceButton, 'disabled'); } }

    const savedReportStateInfo = reportButtonStates.get(endpointKey);
    if (savedReportStateInfo) { updateReportButton(reportButton, savedReportStateInfo, endpointKey); }
    else { if (traceButton.classList.contains('green')) { updateReportButton(reportButton, 'default', endpointKey); } else { updateReportButton(reportButton, 'disabled', endpointKey); } }

    playButton.addEventListener("click", async (e) => { e.stopPropagation(); await handlePlayButton(endpointKey, playButton); });

    traceButton.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) {
            await handleTraceButton(endpointKey, traceButton);
        }
    });

    reportButton.addEventListener("click", async (e) => { e.stopPropagation(); if (!reportButton.classList.contains('disabled')) { await handleReportButton(endpointKey); } });
    handlerButton.addEventListener("click", (e) => {
        e.stopPropagation();
        if (!handlerButton.disabled) {
            const key = handlerButton.getAttribute('data-endpoint');
            if (key) { showHandlerModal(key); }
        }
    });

    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(handlerButton);
    buttonContainer.appendChild(reportButton);
    return buttonContainer;
}


function renderEndpoints(filter = "") {
    const endpointsList = document.getElementById("endpointsList");
    if (!endpointsList) return;
    const currentFrameConnections = new Map();
    const messageKeys = new Set();
    messages.forEach(msg => {
        if (msg.origin && msg.destinationUrl) {
            const originKey = normalizeEndpointUrl(msg.origin)?.normalized;
            const destKey = normalizeEndpointUrl(msg.destinationUrl)?.normalized;
            if (originKey && destKey && originKey !== destKey && originKey !== 'null' && destKey !== 'null') {
                if (!currentFrameConnections.has(originKey)) {
                    currentFrameConnections.set(originKey, new Set());
                }
                currentFrameConnections.get(originKey).add(destKey);
                messageKeys.add(originKey);
                messageKeys.add(destKey);
            } else if (originKey && originKey !== 'null') {
                messageKeys.add(originKey);
            } else if (destKey && destKey !== 'null') {
                messageKeys.add(destKey);
            }
        }
    });
    const endpointHierarchy = new Map(currentFrameConnections);
    const allRenderedKeys = new Set(messageKeys);

    // 3. Merge in handler-only endpoints
    knownHandlerEndpoints.forEach(handlerKey => {
        if (handlerKey && !allRenderedKeys.has(handlerKey)) {
            try {
                if (handlerKey.startsWith('http:') || handlerKey.startsWith('https:')) {
                    const url = new URL(handlerKey);
                    const hostKey = url.origin;

                    // Check if this origin already exists as a host from message data
                    if (endpointHierarchy.has(hostKey)) {
                        endpointHierarchy.get(hostKey).add(handlerKey);
                    } else {
                        endpointHierarchy.set(hostKey, new Set([handlerKey]));
                        allRenderedKeys.add(hostKey);
                    }
                    allRenderedKeys.add(handlerKey);
                } else {
                    if (!endpointHierarchy.has(handlerKey)) {
                        endpointHierarchy.set(handlerKey, new Set([handlerKey]));
                        allRenderedKeys.add(handlerKey);
                    }
                }
            } catch(e) {
                log.warn(`[RenderEndpoints] Error parsing or placing handler-only key: ${handlerKey}`, e);
                if (!endpointHierarchy.has(handlerKey)) {
                    endpointHierarchy.set(handlerKey, new Set([handlerKey]));
                    allRenderedKeys.add(handlerKey);
                }
            }
        }
    });
    const finalHostKeys = Array.from(endpointHierarchy.keys());
    if (finalHostKeys.length === 0 && knownHandlerEndpoints.size === 0) {
        endpointsList.innerHTML = "<div class='no-endpoints'>No hosts or iframes detected or no communication captured yet. Check for captured listeners.</div>";
        return;
    }


    // 5. Render the list based on the combined hierarchy
    endpointsList.innerHTML = "";
    let hostCount = 0;
    const sortedHostKeys = finalHostKeys.sort();

    sortedHostKeys.forEach(hostKey => {
        const iframesSet = endpointHierarchy.get(hostKey) || new Set();

        // Apply filter - Check if host OR any of its iframes match
        const hostMatches = !filter || hostKey.toLowerCase().includes(filter.toLowerCase());
        const anyIframeMatches = !filter || Array.from(iframesSet).some(iframeKey =>
            iframeKey.toLowerCase().includes(filter.toLowerCase())
        );

        if (!hostMatches && !anyIframeMatches) {
            return;
        }

        try {
            let displayedIframeSet = iframesSet;
            if (filter && !hostMatches && anyIframeMatches) {
                displayedIframeSet = new Set(Array.from(iframesSet).filter(iframeKey =>
                    iframeKey.toLowerCase().includes(filter.toLowerCase())
                ));
            }

            // Pass the potentially filtered set of iframes to createHostElement
            const hostElement = createHostElement(hostKey, displayedIframeSet);
            if (hostElement) {
                endpointsList.appendChild(hostElement);
                hostCount++;
            }
        } catch (e) {
            log.error(`[RenderEndpoints] Error processing host key: "${hostKey}". Message: ${e.message}\nStack: ${e.stack || 'N/A'}`);
        }
    });


    if (hostCount === 0 && filter) {
        endpointsList.innerHTML = `<div class='no-endpoints'>No endpoints match filter "${filter}".</div>`;
    } else if (hostCount === 0 && (finalHostKeys.length > 0 || knownHandlerEndpoints.size > 0)) {
        endpointsList.innerHTML = "<div class='no-endpoints'>No endpoints match the filter or failed to render.</div>";
        log.handler("[RenderEndpoints] Final hostCount is 0, check hierarchy building logic or filter.");
    }

    highlightActiveEndpoint();
}


async function sendMessageTo(targetKey, button) {
    try {
        const messageItem = button.closest('.message-item');
        if (!messageItem) return false;
        const messageDataElement = messageItem.querySelector('.message-data');
        if (!messageDataElement) return false;

        const messageContent = messageDataElement.textContent;
        let data;
        try { data = JSON.parse(messageContent); } catch (e) { data = messageContent; }

        if (targetKey.startsWith('chrome-extension://')) {
            // Consider storing original full URL alongside the key if needed here
            // chrome.runtime.sendMessage({ action: "forwardPostMessage", data: data, targetUrl: targetKey });
        } else {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
            iframe.src = targetKey;

            await new Promise((resolve) => {
                iframe.onload = resolve;
                iframe.onerror = resolve;
                setTimeout(resolve, 3000);
            });

            if (iframe.contentWindow) {
                iframe.contentWindow.postMessage(data, '*');
            } else {
                throw new Error("Iframe content window not accessible");
            }

            setTimeout(() => {
                if (document.body.contains(iframe)) {
                    document.body.removeChild(iframe);
                }
            }, 1000);
        }

        button.classList.add('success');
        setTimeout(() => button.classList.remove('success'), 1000);
        return true;
    } catch (error) {
        button.classList.add('error');
        setTimeout(() => button.classList.remove('error'), 1000);
        return false;
    }
}

function escapeHTML(str) {
    if (str === undefined || str === null) return '';
    str = String(str);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}


function renderMessages() {
    const messagesList = document.getElementById("messagesList");
    if (!messagesList) return;
    messagesList.innerHTML = "";

    if (!activeEndpoint) {
        messagesList.innerHTML = "<div class='no-messages'>Select a host or iframe to view messages.</div>";
        return;
    }

    const relevantMessages = messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === activeEndpoint || destKey === activeEndpoint;
    });

    if (relevantMessages.length === 0) {
        messagesList.innerHTML = "<div class='no-messages'>No messages captured involving this endpoint.</div>";
        return;
    }

    const sortedMessages = [...relevantMessages].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    sortedMessages.forEach((msg) => {
        try {
            const messageItem = document.createElement("div");
            messageItem.className = "message-item";
            messageItem.setAttribute('data-message-id', msg.messageId);

            const sanitizedData = sanitizeMessageData(msg.data);
            let formattedData;
            try {
                formattedData = typeof sanitizedData === 'string' ? sanitizedData : JSON.stringify(sanitizedData, null, 2);
            } catch (e) {
                formattedData = String(sanitizedData);
            }

            const header = document.createElement("div");
            header.className = "message-header";
            const originDisplay = normalizeEndpointUrl(msg.origin)?.normalized || msg.origin || '?';
            const destDisplay = normalizeEndpointUrl(msg.destinationUrl)?.normalized || msg.destinationUrl || '?';
            const messageTypeDisplay = (msg.messageType || 'unknown').replace(/\s+/g, '-').toLowerCase();
            header.innerHTML = `<strong>Origin:</strong> ${escapeHTML(originDisplay)}<br><strong>Destination:</strong> ${escapeHTML(destDisplay)}<br><strong>Time:</strong> ${new Date(msg.timestamp).toLocaleString()}<br><strong>Msg Type:</strong> <span class="message-type message-type-${messageTypeDisplay}">${escapeHTML(msg.messageType || '?')}</span>`;

            const dataPre = document.createElement("pre");
            dataPre.className = "message-data";
            dataPre.textContent = formattedData;

            const controls = document.createElement("div");
            controls.className = "message-controls";

            const originBtn = document.createElement("button");
            originBtn.className = "send-origin";
            originBtn.textContent = "Resend to Origin";
            const originKey = getStorageKeyForUrl(msg.origin);
            originBtn.addEventListener('click', () => sendMessageTo(originKey, originBtn));

            const destBtn = document.createElement("button");
            destBtn.className = "send-destination";
            destBtn.textContent = "Resend to Destination";
            const destKey = getStorageKeyForUrl(msg.destinationUrl);
            destBtn.addEventListener('click', () => sendMessageTo(destKey, destBtn));

            const editBtn = document.createElement("button");
            editBtn.className = "edit-send";
            editBtn.textContent = "Edit & Send";
            editBtn.addEventListener('click', () => showEditModal(msg));

            controls.appendChild(originBtn);
            controls.appendChild(destBtn);
            controls.appendChild(editBtn);
            messageItem.appendChild(header);
            messageItem.appendChild(dataPre);
            messageItem.appendChild(controls);
            messagesList.appendChild(messageItem);
        } catch (e) {
            log.error("Error rendering message item:", e);
        }
    });
}

function showEditModal(messageObject) {
    const modalContainer = document.getElementById('editMessageModalContainer');
    if (!modalContainer) {
        console.error("Edit modal container not found");
        return;
    }
    modalContainer.innerHTML = '';

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    const modal = document.createElement('div');
    modal.className = 'edit-message-modal';

    let dataToEdit;
    try {
        dataToEdit = (typeof messageObject.data === 'string')
            ? messageObject.data
            : JSON.stringify(messageObject.data, null, 2);
    } catch (e) {
        dataToEdit = String(messageObject.data);
    }

    const originDisplay = escapeHTML(normalizeEndpointUrl(messageObject.origin)?.normalized || messageObject.origin);
    const destDisplay = escapeHTML(normalizeEndpointUrl(messageObject.destinationUrl)?.normalized || messageObject.destinationUrl);

    modal.innerHTML = `
        <div class="edit-modal-header">
            <h4>Edit Message</h4>
            <div class="message-info">
                 <strong>Origin:</strong> ${originDisplay}<br>
                 <strong>Destination:</strong> ${destDisplay}<br>
                 <strong>Time:</strong> ${new Date(messageObject.timestamp).toLocaleString()}
            </div>
            <button class="close-modal-btn">&times;</button>
        </div>
        <div class="edit-modal-body">
            <textarea id="messageEditTextarea">${escapeHTML(dataToEdit)}</textarea>
        </div>
        <div class="edit-modal-footer">
            <button id="editCancelBtn" class="control-button secondary-button">Cancel</button>
            <button id="editSendDestBtn" class="control-button">Send to Destination</button>
            <button id="editSendOriginBtn" class="control-button">Send to Origin</button>
        </div>
    `;

    modalContainer.appendChild(backdrop);
    modalContainer.appendChild(modal);

    const closeModal = () => {
        if (modal && modal.parentNode) modal.remove();
        if (backdrop && backdrop.parentNode) backdrop.remove();
    };

    modal.querySelector('.close-modal-btn').addEventListener('click', closeModal);
    modal.querySelector('#editCancelBtn').addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);

    const textarea = modal.querySelector('#messageEditTextarea');
    const originKey = getStorageKeyForUrl(messageObject.origin);
    const destKey = getStorageKeyForUrl(messageObject.destinationUrl);

    modal.querySelector('#editSendOriginBtn').addEventListener('click', async () => {
        const editedData = textarea.value;
        const buttonElement = modal.querySelector('#editSendOriginBtn');
        const success = await sendMessageFromModal(originKey, editedData, buttonElement, "Send to Origin");
        if (success) closeModal();
    });

    modal.querySelector('#editSendDestBtn').addEventListener('click', async () => {
        const editedData = textarea.value;
        const buttonElement = modal.querySelector('#editSendDestBtn');
        const success = await sendMessageFromModal(destKey, editedData, buttonElement, "Send to Destination");
        if (success) closeModal();
    });
}

async function sendMessageFromModal(targetKey, editedDataString, buttonElement, originalButtonText) {
    if (!targetKey || !buttonElement) return false;

    let dataToSend;
    try {
        dataToSend = JSON.parse(editedDataString);
    } catch (e) {
        dataToSend = editedDataString;
    }

    buttonElement.textContent = 'Sending...';
    buttonElement.disabled = true;
    buttonElement.classList.remove('success', 'error');

    try {
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        iframe.src = targetKey;

        await new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                console.warn("iframe load timeout for sending");
                reject(new Error("Iframe load timeout"));
            }, 5000);

            iframe.onload = () => {
                clearTimeout(timeoutId);
                resolve();
            };
            iframe.onerror = (err) => {
                clearTimeout(timeoutId);
                console.error("iframe load error for sending", err);
                reject(new Error("Iframe load error"));
            };
        });

        if (iframe.contentWindow) {
            iframe.contentWindow.postMessage(dataToSend, '*');
            log.info(`Sent message from modal to ${targetKey}`, dataToSend);

            buttonElement.textContent = 'Sent ✓';
            buttonElement.classList.add('success');
            await new Promise(res => setTimeout(res, 1000));
            if (iframe.parentNode) iframe.parentNode.removeChild(iframe);

            return true;
        } else {
            throw new Error("Iframe content window not accessible after load");
        }

    } catch (error) {
        log.error(`Error sending message from modal to ${targetKey}:`, error);
        buttonElement.textContent = 'Error ✕';
        buttonElement.classList.add('error');
        await new Promise(res => setTimeout(res, 2000));
        buttonElement.textContent = originalButtonText;
        buttonElement.classList.remove('error');
        const tempIframe = document.body.querySelector(`iframe[src="${targetKey}"]`);
        if (tempIframe && tempIframe.parentNode) tempIframe.parentNode.removeChild(tempIframe);


        return false;
    } finally {
        if (buttonElement && !buttonElement.classList.contains('success')) {
            buttonElement.disabled = false;
        }
    }
}


function highlightActiveEndpoint() {
    document.querySelectorAll('.endpoint-host, .iframe-row').forEach(el => {
        el.classList.remove('active');
    });
    if (activeEndpoint) {
        document.querySelectorAll('.host-row, .iframe-row').forEach(el => {
            if (el.classList.contains('host-row')) {
                const hostNameSpan = el.querySelector('.host-name');
                const textContent = hostNameSpan?.textContent || '';
                const keyFromText = textContent.includes(' (') ? textContent.substring(0, textContent.lastIndexOf(' (')) : textContent;
                if(keyFromText === activeEndpoint) {
                    el.closest('.endpoint-host').classList.add('active');
                }
            } else if (el.classList.contains('iframe-row')) {
                if(el.getAttribute('data-endpoint-key') === activeEndpoint) {
                    el.classList.add('active');
                }
            }
        });
    }
}


function updateDashboardUI() {
    const filterInput = document.getElementById("endpointFilter");
    const filterValue = filterInput ? filterInput.value : "";

    renderEndpoints(filterValue);
    renderMessages();
    updateEndpointCounts();
    highlightActiveEndpoint();
}

function startAutoRefresh() {
    // For now, UI updates are driven by messages from background script
}


function updateEndpointCounts() {
    try {
        const endpointElements = document.querySelectorAll('.host-name, .iframe-name');
        endpointElements.forEach(el => {
            const fullText = el.textContent || '';
            const keyText = fullText.includes(' (') ? fullText.substring(0, fullText.lastIndexOf(' (')) : fullText;
            if (!keyText) return;

            const count = getMessageCount(keyText);
            el.textContent = `${keyText} (${count})`;
        });
    } catch (e) {
    }
}

function initializeMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message || !message.type) return false;

        let needsUiUpdate = false;

        try {
            if (message.type === "newPostMessage" && message.payload) {
                const newMsg = message.payload;
                const existingIndex = messages.findIndex(m => m.messageId === newMsg.messageId);
                if (existingIndex >= 0) { messages[existingIndex] = newMsg; } else { messages.push(newMsg); }
                needsUiUpdate = true;
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "newFrameConnection") {
                needsUiUpdate = true;
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "updateMessages" && message.messages) {
                messages.length = 0; messages.push(...message.messages);
                needsUiUpdate = true;
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "handlerCapturedForEndpoint" && message.payload?.endpointKey) {
                const endpointKey = message.payload.endpointKey;
                if (!endpointsWithHandlers.has(endpointKey)) {
                    endpointsWithHandlers.add(endpointKey);
                    needsUiUpdate = true;
                    log.handler(`Received notification: Handler captured/added for ${endpointKey}`);
                }
                if (!knownHandlerEndpoints.has(endpointKey)) {
                    knownHandlerEndpoints.add(endpointKey);
                    needsUiUpdate = true;
                }
                if (sendResponse) sendResponse({ success: true });
                return false;

            } else if (message.type === "handlerEndpointDetected" && message.payload?.endpointKey) {
                const endpointKey = message.payload.endpointKey;
                if (!knownHandlerEndpoints.has(endpointKey)) {
                    knownHandlerEndpoints.add(endpointKey);
                    needsUiUpdate = true;
                    log.handler(`Received notification: Endpoint with handler detected: ${endpointKey}`);
                }
                if (sendResponse) sendResponse({ success: true });

            } else if (message.type === "forwardedPostMessage") {
                if (sendResponse) sendResponse({ success: true });
            }

            if (needsUiUpdate) {
                requestAnimationFrame(updateDashboardUI);
            }

        } catch (e) {
            console.error("[Dashboard Msg Handler] Error:", e);
            if (sendResponse) try { sendResponse({ success: false, error: e.message }); } catch (respErr) {}
        }
        return false;
    });

    window.traceReportStorage.listAllReports().then(() => {
        chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => {
            if (chrome.runtime.lastError) {
                log.error("Error fetching initial state:", chrome.runtime.lastError);
                return;
            }
            if (response?.success) {
                if (response.messages) {
                    messages.length = 0;
                    messages.push(...response.messages);
                    log.debug(`Workspaceed ${response.messages.length} initial messages.`);
                }
                if (response.handlerEndpointKeys) {
                    knownHandlerEndpoints.clear();
                    response.handlerEndpointKeys.forEach(key => knownHandlerEndpoints.add(key));
                    log.debug(`Workspaceed ${response.handlerEndpointKeys.length} handler endpoint keys.`);
                    response.handlerEndpointKeys.forEach(key => {
                        if (!endpointsWithHandlers.has(key)) {
                            endpointsWithHandlers.add(key);
                        }
                    });
                }
                updateDashboardUI();
            } else {
                log.error("Failed to fetch initial state:", response?.error);
            }
        });
    });
}


async function showHandlerModal(endpointKey) {
    const modalContainer = document.getElementById('handlerDisplayModalContainer');
    if (!modalContainer) {
        console.error("Handler display modal container not found");
        alert("Error: Cannot display handlers - UI element missing.");
        return;
    }
    modalContainer.innerHTML = '';

    const storageKey = `runtime-listeners-${endpointKey}`;
    log.handler(`[Show Handler] Fetching listeners for key: ${storageKey}`);
    modalContainer.innerHTML = '<div class="modal-backdrop"></div><div class="handler-display-modal"><div class="modal-loading">Loading listeners...</div></div>';
    const backdrop = modalContainer.querySelector('.modal-backdrop');
    const modal = modalContainer.querySelector('.handler-display-modal');

    const closeModal = () => {
        if (modalContainer) modalContainer.innerHTML = '';
    };
    if(backdrop) backdrop.onclick = closeModal;


    chrome.storage.local.get([storageKey], (result) => {
        if (chrome.runtime.lastError) {
            log.error(`[Show Handler] Error fetching listeners for ${endpointKey}:`, chrome.runtime.lastError);
            modal.innerHTML = `
                <div class="handler-modal-header">
                    <h4>Error</h4>
                    <button class="close-modal-btn">&times;</button>
                </div>
                <div class="handler-modal-body">
                    <p class="error-message">Failed to load listeners: ${chrome.runtime.lastError.message}</p>
                </div>`;
            modal.querySelector('.close-modal-btn').onclick = closeModal;
            return;
        }

        const listeners = result[storageKey];
        log.handler(`[Show Handler] Found ${listeners?.length || 0} listeners for ${endpointKey}`);
        modal.innerHTML = `
            <div class="handler-modal-header">
                <h4>Captured Listeners</h4>
                <div class="endpoint-info">For: ${escapeHTML(endpointKey)}</div>
                <button class="close-modal-btn">&times;</button>
            </div>
            <div class="handler-modal-body">
                ${ /* Content added below */ '' }
            </div>
        `;
        modal.querySelector('.close-modal-btn').onclick = closeModal;


        const modalBody = modal.querySelector('.handler-modal-body');

        if (!listeners || listeners.length === 0) {
            modalBody.innerHTML = `<p class="no-listeners-found">No runtime listeners were captured for this endpoint.</p>`;
        } else {
            listeners.forEach((listener, index) => {
                const detailsElement = document.createElement('details');
                detailsElement.className = 'listener-details';
                if (listeners.length === 1) {
                    detailsElement.open = true;
                }

                const summaryElement = document.createElement('summary');
                summaryElement.className = 'listener-summary';
                const captureContext = listener.context || 'unknown source';
                const captureTime = listener.timestamp ? new Date(listener.timestamp).toLocaleString() : 'unknown time';
                summaryElement.innerHTML = `Listener #${index + 1} (via <code>${escapeHTML(captureContext)}</code> at ${escapeHTML(captureTime)}) <span class="toggle-icon">${listeners.length === 1 ? '▼' : '▶'}</span>`;

                const contentElement = document.createElement('div');
                contentElement.className = 'listener-content';
                const codeBlock = document.createElement('pre');
                codeBlock.className = 'report-code-block listener-code';
                const codeElement = document.createElement('code');
                try {
                    const formattedCode = listener.code.replace(/^ {8}/gm, '').replace(/\t/g, '  ');
                    codeElement.textContent = formattedCode;
                } catch(e){
                    codeElement.textContent = listener.code || '[Code Unavailable]';
                }
                codeBlock.appendChild(codeElement);
                contentElement.appendChild(codeBlock);
                if (listener.stack) {
                    const stackTitle = document.createElement('strong');
                    stackTitle.textContent = 'Capture Stack Trace:';
                    stackTitle.style.display = 'block';
                    stackTitle.style.marginTop = '10px';
                    stackTitle.style.fontSize = '12px';
                    const stackBlock = document.createElement('pre');
                    stackBlock.className = 'report-code-block listener-stack';
                    stackBlock.style.fontSize = '11px';
                    stackBlock.style.maxHeight = '150px';
                    stackBlock.style.borderColor = '#555';
                    stackBlock.textContent = listener.stack;
                    contentElement.appendChild(stackTitle);
                    contentElement.appendChild(stackBlock);
                }

                detailsElement.appendChild(summaryElement);
                detailsElement.appendChild(contentElement);
                modalBody.appendChild(detailsElement);
                detailsElement.addEventListener('toggle', () => {
                    const icon = summaryElement.querySelector('.toggle-icon');
                    if (icon) icon.textContent = detailsElement.open ? '▼' : '▶';
                });
            });
        }
    });
}

function setupCallbackUrl() {
    const urlInput = document.getElementById('callbackUrlInput');
    const saveButton = document.getElementById('saveCallbackUrl');
    const statusElement = document.getElementById('callback-status');

    if (!urlInput || !saveButton || !statusElement) {
        log.error("Callback URL UI elements not found.");
        return;
    }

    // Use chrome.storage.session
    chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], (result) => {
        if (chrome.runtime.lastError) {
            log.error("[Callback URL] Error getting session storage:", chrome.runtime.lastError);
            updateCallbackStatus(null, `Error loading URL: ${chrome.runtime.lastError.message}`);
            return;
        }
        const storedUrl = result[CALLBACK_URL_STORAGE_KEY] || null;
        if (storedUrl) {
            urlInput.value = storedUrl;
            window.frogPostState.callbackUrl = storedUrl;
            updateCallbackStatus(storedUrl);
            log.info(`[Callback URL] Loaded from session storage: ${storedUrl}`);
        } else {
            window.frogPostState.callbackUrl = null;
            updateCallbackStatus(null);
        }
    });

    saveButton.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (!url) {
            chrome.storage.session.remove(CALLBACK_URL_STORAGE_KEY, () => {
                if (chrome.runtime.lastError) {
                    updateCallbackStatus(window.frogPostState.callbackUrl, `Error clearing URL: ${chrome.runtime.lastError.message}`);
                    log.error("[Callback URL] Error clearing session storage:", chrome.runtime.lastError);
                } else {
                    window.frogPostState.callbackUrl = null;
                    updateCallbackStatus(null);
                    log.info(`[Callback URL] Cleared from session.`);
                }
            });
        } else if (isValidUrl(url)) {
            chrome.storage.session.set({
                [CALLBACK_URL_STORAGE_KEY]: url
            }, () => {
                if (chrome.runtime.lastError) {
                    updateCallbackStatus(window.frogPostState.callbackUrl, `Error saving URL: ${chrome.runtime.lastError.message}`);
                    log.error("[Callback URL] Error saving session storage:", chrome.runtime.lastError);
                } else {
                    window.frogPostState.callbackUrl = url;
                    updateCallbackStatus(url);
                    log.info(`[Callback URL] Saved to session: ${url}`);
                }
            });
        } else {
            updateCallbackStatus(window.frogPostState.callbackUrl, 'Please enter a valid URL (e.g., https://...).');
        }
    });

    function updateCallbackStatus(url, errorMessage = null) {
        if (!statusElement) return;

        statusElement.innerHTML = '';
        statusElement.className = 'callback-status';
        if (errorMessage) {
            statusElement.innerHTML = `<div class="error-message">${escapeHTML(errorMessage)}</div>`;
            statusElement.classList.add('callback-status-error');

        } else if (url) {
            statusElement.innerHTML = `
                <div class="success-icon">✓</div>
                <div class="status-message">Active (Session): <span class="url-value">${escapeHTML(url)}</span></div>
            `;
            statusElement.classList.add('callback-status-success');
        } else {
            statusElement.innerHTML = `<div class="info-message">No callback URL set for this session.</div>`;
            statusElement.classList.add('callback-status-info');
        }
    }
}

function setupUIControls() {
    const clearMessagesButton = document.getElementById("clearMessages");
    const exportMessagesButton = document.getElementById("exportMessages");
    const checkAllButton = document.getElementById("checkAll");
    const debugButton = document.getElementById("debugToggle");
    const refreshMessagesButton = document.getElementById("refreshMessages");
    const uploadPayloadsButton = document.getElementById("uploadCustomPayloadsBtn");
    const payloadFileInput = document.getElementById("customPayloadsFile");
    const clearPayloadsButton = document.getElementById("clearCustomPayloadsBtn");

    if (refreshMessagesButton) {
        refreshMessagesButton.addEventListener("click", () => {
            chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => {
                if (chrome.runtime.lastError) {
                    log.error("Error fetching state on refresh:", chrome.runtime.lastError);
                    return;
                }
                if (response?.success) {
                    if (response.messages) {
                        messages.length = 0;
                        messages.push(...response.messages);
                    }
                    if (response.handlerEndpointKeys) {
                        knownHandlerEndpoints.clear();
                        response.handlerEndpointKeys.forEach(key => knownHandlerEndpoints.add(key));
                        response.handlerEndpointKeys.forEach(key => {
                            if (!endpointsWithHandlers.has(key)) {
                                endpointsWithHandlers.add(key);
                            }
                        });
                    }
                    log.info("Dashboard refreshed.");
                    updateDashboardUI();
                } else {
                    log.error("Failed to fetch state on refresh:", response?.error);
                }
            });
        });
    }

    if (clearMessagesButton) {
        clearMessagesButton.addEventListener("click", () => {
            log.info("Clearing dashboard state...");
            messages.length = 0;
            buttonStates.clear();
            traceButtonStates.clear();
            reportButtonStates.clear();
            activeEndpoint = null;
            endpointsWithHandlers.clear();
            knownHandlerEndpoints.clear();
            modifiedEndpoints.clear();
            launchInProgressEndpoints.clear();
            chrome.storage.local.clear(); // Also clear local storage? Be careful.
            chrome.runtime.sendMessage({ type: "resetState" }, (response) => {
                if (response?.success) {
                    log.success("Background state reset acknowledged.");
                } else {
                    log.error("Background state reset failed or timed out.", response?.error);
                }
                updateDashboardUI();
            });
        });
    }

    if (exportMessagesButton) {
        exportMessagesButton.addEventListener("click", () => {
            const sanitizedMessages = messages.map(msg => ({
                origin: msg.origin,
                destinationUrl: msg.destinationUrl,
                timestamp: msg.timestamp,
                data: sanitizeMessageData(msg.data),
                messageType: msg.messageType,
                messageId: msg.messageId
            }));
            const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "frogpost_messages.json";
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    if (checkAllButton) {
        checkAllButton.addEventListener("click", checkAllEndpoints);
    }

    if (debugButton) {
        debugButton.addEventListener("click", toggleDebugMode);
        // Initialize button state based on current debugMode
        debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF';
        debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off';
    }

    if (uploadPayloadsButton && payloadFileInput) {
        uploadPayloadsButton.addEventListener('click', () => {
            payloadFileInput.click();
        });
        payloadFileInput.addEventListener('change', handlePayloadFileSelect);
    }

    if (clearPayloadsButton) { // Listener for the new Clear button
        clearPayloadsButton.addEventListener('click', clearCustomPayloads);
    }

    setupCallbackUrl();
    updatePayloadStatus(); // Check initial status on load
}

async function handlePayloadFileSelect(event) {
    const file = event.target.files[0];
    const statusElement = document.getElementById("customPayloadStatus"); // Assuming you have this element

    if (!file || !file.name.toLowerCase().endsWith('.txt')) {
        showToastNotification('Invalid file type. Please upload a .txt file.', 'error');
        if (statusElement) statusElement.textContent = 'Upload: Invalid file type.';
        event.target.value = null; // Clear selection
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        const content = e.target.result;
        validateAndStorePayloads(content);
        event.target.value = null; // Clear selection
    };
    reader.onerror = (e) => {
        showToastNotification('Error reading file.', 'error');
        if (statusElement) statusElement.textContent = 'Upload: Error reading file.';
        event.target.value = null; // Clear selection
    };
    reader.readAsText(file);
}

// Enhanced modal function with higher z-index and more attention-grabbing design

function showPayloadInfoModal(payloads, isFirstTime = false) {
    if (!payloads || !payloads.length) return;

    // Force remove any existing modals first
    const existingModals = document.querySelectorAll('.payload-info-modal, .modal-backdrop');
    existingModals.forEach(el => el.remove());

    // Create modal container if needed
    let modalContainer = document.getElementById('payloadInfoModalContainer');
    if (!modalContainer) {
        modalContainer = document.createElement('div');
        modalContainer.id = 'payloadInfoModalContainer';
        modalContainer.style.zIndex = '100000'; // Very high z-index
        document.body.appendChild(modalContainer);
    }

    // Clear previous content
    modalContainer.innerHTML = '';

    // Create backdrop
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.style.position = 'fixed';
    backdrop.style.top = '0';
    backdrop.style.left = '0';
    backdrop.style.width = '100%';
    backdrop.style.height = '100%';
    backdrop.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
    backdrop.style.zIndex = '100001';
    modalContainer.appendChild(backdrop);

    // Create modal
    const modal = document.createElement('div');
    modal.className = 'payload-info-modal';
    modal.style.position = 'fixed';
    modal.style.top = '50%';
    modal.style.left = '50%';
    modal.style.transform = 'translate(-50%, -50%) scale(1.1)';
    modal.style.width = '600px';
    modal.style.maxWidth = '90%';
    modal.style.backgroundColor = '#2a2a2a';
    modal.style.borderRadius = '8px';
    modal.style.boxShadow = '0 10px 30px rgba(0, 0, 0, 0.7), 0 0 20px rgba(46, 204, 113, 0.5)';
    modal.style.zIndex = '100002';
    modal.style.overflow = 'hidden';
    modal.style.color = '#d0d8e8';
    modal.style.border = '3px solid #2ecc71';
    modal.style.animation = 'modalFadeIn 0.3s forwards';
    modalContainer.appendChild(modal);

    // Sample a few payloads to show
    const sampleCount = Math.min(5, payloads.length);
    const samples = [];
    for (let i = 0; i < sampleCount; i++) {
        const idx = Math.floor(i * payloads.length / sampleCount);
        const payload = payloads[idx];
        const displayPayload = payload.length > 50
            ? payload.substring(0, 50) + '...'
            : payload;
        samples.push(displayPayload);
    }

    // Create modal content
    modal.innerHTML = `
        <div class="modal-header" style="padding: 15px 20px; background: #2ecc71; display: flex; justify-content: space-between; align-items: center;">
            <h3 style="margin: 0; color: #ffffff; font-size: 1.3em; text-shadow: 1px 1px 1px rgba(0,0,0,0.5);">Custom Payloads Active</h3>
            <button class="close-modal-btn" style="background: none; border: none; color: white; font-size: 24px; cursor: pointer; line-height: 1;">&times;</button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <p class="payload-info-message" style="font-size: 15px; margin-bottom: 20px; display: flex; align-items: center;">
                <span class="success-icon" style="font-size: 20px; color: #2ecc71; margin-right: 10px; font-weight: bold;">✓</span>
                <strong>${payloads.length}</strong> custom payloads will be used for all fuzzing operations instead of the default payloads.
            </p>
            <div class="payload-samples" style="background: #222; padding: 15px; border-radius: 5px; margin-bottom: 15px; border: 1px solid #444;">
                <h4 style="margin-top: 0; color: #aaa; font-size: 0.9em; margin-bottom: 10px;">Sample Payloads:</h4>
                <ul class="sample-list" style="list-style-type: none; padding: 0; margin: 0;">
                    ${samples.map(sample => `<li style="margin-bottom: 8px; padding: 8px 12px; background: #333; border-radius: 3px; overflow: hidden; text-overflow: ellipsis;"><code style="font-family: monospace; font-size: 12px; color: #2ecc71;">${escapeHTML(sample)}</code></li>`).join('')}
                </ul>
            </div>
            ${isFirstTime ? `
            <div class="info-note" style="font-size: 13px; padding: 15px; border-left: 3px solid #3498db; background: rgba(52, 152, 219, 0.1); margin-top: 15px;">
                <strong>Note:</strong> These payloads will be stored for this session only and will be used in all fuzzing operations. 
                You can use the "Clear Payloads" button to revert to the default payloads at any time.
            </div>
            ` : ''}
        </div>
        <div class="modal-footer" style="padding: 15px 20px; text-align: right; border-top: 1px solid #444;">
            <button class="modal-ok-btn" style="padding: 10px 25px; background: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 14px;">OK</button>
        </div>
    `;

    // Add styles if not already added
    if (!document.getElementById('payload-info-modal-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'payload-info-modal-styles';
        styleEl.textContent = `
            @keyframes modalFadeIn {
                from { opacity: 0; transform: translate(-50%, -50%) scale(0.9); }
                to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
            }
            
            @keyframes pulse {
                0% { box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7), 0 0 20px rgba(46, 204, 113, 0.5); }
                50% { box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7), 0 0 30px rgba(46, 204, 113, 0.8); }
                100% { box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7), 0 0 20px rgba(46, 204, 113, 0.5); }
            }
            
            .payload-info-modal {
                animation: pulse 2s infinite;
            }
            
            .modal-ok-btn:hover {
                background-color: #27ae60 !important;
                transform: translateY(-2px);
                transition: all 0.2s;
            }
        `;
        document.head.appendChild(styleEl);
    }

    // Add event listeners
    const closeBtn = modal.querySelector('.close-modal-btn');
    const okBtn = modal.querySelector('.modal-ok-btn');
    const closeModal = () => {
        modal.style.animation = 'none';
        modal.style.opacity = '0';
        modal.style.transform = 'translate(-50%, -50%) scale(0.9)';
        backdrop.style.opacity = '0';

        // Give time for fade out animation
        setTimeout(() => {
            if (modalContainer && modalContainer.parentNode) {
                modalContainer.parentNode.removeChild(modalContainer);
            }
        }, 300);
    };

    closeBtn.addEventListener('click', closeModal);
    okBtn.addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);

    // Force focus to the modal to ensure it's noticeable
    setTimeout(() => {
        if (okBtn) okBtn.focus();
    }, 100);

    // Auto-close after 20 seconds if user doesn't interact with it
    const autoCloseTimeout = setTimeout(() => {
        closeModal();
    }, 20000);

    // Clear timeout if user interacts
    modal.addEventListener('click', () => clearTimeout(autoCloseTimeout));
}

function showCustomPayloadsNotification(payloadCount) {
    // First, remove any existing notifications
    const existingNotifications = document.querySelectorAll('.custom-payloads-notification');
    existingNotifications.forEach(el => el.remove());

    // Create the notification element
    const notification = document.createElement('div');
    notification.className = 'custom-payloads-notification';
    notification.innerHTML = `
        <div class="notification-icon">✓</div>
        <div class="notification-content">
            <h3>Custom Payloads Active</h3>
            <p>${payloadCount} custom payloads will be used for testing</p>
        </div>
        <button class="notification-close">&times;</button>
    `;

    // Add the notification to the page
    document.body.appendChild(notification);

    // Add styles if they don't exist yet
    if (!document.getElementById('custom-payloads-notification-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'custom-payloads-notification-styles';
        styleEl.textContent = `
            .custom-payloads-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                width: 350px;
                background: #2ecc71;
                color: white;
                border-radius: 8px;
                box-shadow: 0 5px 20px rgba(0,0,0,0.3);
                display: flex;
                align-items: center;
                padding: 15px;
                z-index: 100000;
                animation: slideInRight 0.5s forwards, pulse-notification 2s infinite;
            }
            
            .notification-icon {
                font-size: 24px;
                font-weight: bold;
                margin-right: 15px;
            }
            
            .notification-content {
                flex-grow: 1;
            }
            
            .notification-content h3 {
                margin: 0 0 5px 0;
                font-size: 16px;
            }
            
            .notification-content p {
                margin: 0;
                font-size: 14px;
                opacity: 0.9;
            }
            
            .notification-close {
                background: none;
                border: none;
                color: white;
                font-size: 20px;
                cursor: pointer;
                opacity: 0.7;
                transition: opacity 0.2s;
            }
            
            .notification-close:hover {
                opacity: 1;
            }
            
            @keyframes slideInRight {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes pulse-notification {
                0% { box-shadow: 0 5px 20px rgba(0,0,0,0.3); }
                50% { box-shadow: 0 5px 20px rgba(46, 204, 113, 0.5); }
                100% { box-shadow: 0 5px 20px rgba(0,0,0,0.3); }
            }
        `;
        document.head.appendChild(styleEl);
    }

    // Set up close button
    const closeButton = notification.querySelector('.notification-close');
    closeButton.addEventListener('click', () => {
        notification.style.animation = 'none';
        notification.style.transform = 'translateX(100%)';
        notification.style.opacity = '0';

        // Remove after animation
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    });

    // Auto-close after 10 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'none';
            notification.style.transform = 'translateX(100%)';
            notification.style.opacity = '0';

            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }
    }, 10000);
}

function validateAndStorePayloads(content) {
    const lines = content.split('\n');
    const payloads = lines.map(line => line.trim()).filter(line => line.length > 0);

    if (payloads.length === 0) {
        showToastNotification('No valid payloads found in the file.', 'warning');
        updatePayloadStatus(false, 0);
        return;
    }

    console.log(`[Custom Payloads] Loaded ${payloads.length} payloads. Sample:`);
    const sampleSize = Math.min(5, payloads.length);
    for (let i = 0; i < sampleSize; i++) {
        console.log(`  - Payload ${i+1}: ${payloads[i].length > 50 ? payloads[i].substring(0, 50) + '...' : payloads[i]}`);
    }

    chrome.storage.session.set({ customXssPayloads: payloads }, () => {
        if (chrome.runtime.lastError) {
            showToastNotification(`Error saving custom payloads: ${chrome.runtime.lastError.message}`, 'error');
            updatePayloadStatus(false, 0);
        } else {
            try {
                localStorage.setItem('customXssPayloads', JSON.stringify(payloads));
            } catch (e) {
                console.warn("Could not backup custom payloads to localStorage:", e);
            }

            if (window.FuzzingPayloads) {
                if (!window.FuzzingPayloads._originalXSS) {
                    window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS];
                }

                window.FuzzingPayloads.XSS = [...payloads];

                console.log("[Custom Payloads] Successfully replaced FuzzingPayloads.XSS with custom payloads");
            }

            showToastNotification(`Stored ${payloads.length} custom payloads for this session.`, 'success');
            updatePayloadStatus(true, payloads.length);

            console.log("%c[🚀 Custom Payloads Active]", "color: #2ecc71; font-weight: bold; font-size: 14px",
                `${payloads.length} custom payloads will be used for fuzzing instead of default payloads.`);
        }
    });
}

function updatePayloadStatus(isActive = null, count = 0) {
    const statusElement = document.getElementById("customPayloadStatus");
    const uploadButton = document.getElementById("uploadCustomPayloadsBtn");
    const clearButton = document.getElementById("clearCustomPayloadsBtn");

    const updateUI = (active, payloadCount) => {
        if (statusElement) {
            statusElement.textContent = active
                ? `Custom Payloads Active (${payloadCount})`
                : 'Using Default Payloads';
            statusElement.style.color = active ? 'var(--accent-primary)' : 'var(--text-secondary)';
        }
        if (uploadButton) {
            uploadButton.textContent = active ? 'Update Payloads' : 'Upload Payloads';
        }
        if (clearButton) {
            clearButton.style.display = active ? 'inline-block' : 'none'; // Show/hide clear button
        }
    };

    if (isActive !== null) {
        updateUI(isActive, count);
    } else {
        // Check storage on initial load or refresh
        chrome.storage.session.get('customXssPayloads', (result) => {
            const storedPayloads = result.customXssPayloads;
            const active = storedPayloads && storedPayloads.length > 0;
            updateUI(active, active ? storedPayloads.length : 0);
        });
    }
}


function clearCustomPayloads() {
    chrome.storage.session.remove('customXssPayloads', () => {
        if (chrome.runtime.lastError) {
            showToastNotification(`Error clearing custom payloads: ${chrome.runtime.lastError.message}`, 'error');
        } else {
            // Remove from localStorage backup too
            try {
                localStorage.removeItem('customXssPayloads');
            } catch (e) {
                console.warn("Could not remove custom payloads from localStorage:", e);
            }

            // Restore original payloads in window.FuzzingPayloads if available
            if (window.FuzzingPayloads && window.FuzzingPayloads._originalXSS) {
                window.FuzzingPayloads.XSS = [...window.FuzzingPayloads._originalXSS];
                console.log("[Custom Payloads] Restored original default payloads");
            }

            showToastNotification('Custom payloads cleared. Using defaults.', 'info');
            updatePayloadStatus(false, 0);
        }
    });
}

async function launchFuzzerEnvironment(endpoint, testData) {
    try {
        let traceReport = null;
        const baseEndpoint = getBaseUrl(endpoint);
        const endpointKey = getStorageKeyForUrl(endpoint);

        try {
            traceReport = await window.traceReportStorage.getTraceReport(endpointKey);
            if (!traceReport) {
                traceReport = await window.traceReportStorage.getTraceReport(endpoint);
                if (!traceReport) {
                    const traceInfoKey = `trace-info-${endpointKey}`;
                    const traceInfo = await new Promise(resolve => {
                        chrome.storage.local.get([traceInfoKey], result => {
                            resolve(result[traceInfoKey]);
                        });
                    });

                    if (traceInfo?.analysisStorageKey) {
                        traceReport = await window.traceReportStorage.getTraceReport(traceInfo.analysisStorageKey);
                    }

                    if (!traceReport && traceInfo?.analyzedUrl) {
                        traceReport = await window.traceReportStorage.getTraceReport(traceInfo.analyzedUrl);

                        if (!traceReport) {
                            const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                            traceReport = await window.traceReportStorage.getTraceReport(analyzedUrlKey);
                        }
                    }

                    if (!traceReport) {
                        const localReport = localStorage.getItem('traceReport');
                        if (localReport) {
                            traceReport = JSON.parse(localReport);
                            await window.traceReportStorage.saveTraceReport(endpointKey, traceReport);
                        }
                    }
                }
            }
        } catch (e) { console.error('Error retrieving trace report:', e); }

        if (!traceReport) {
            throw new Error('No trace report found. Please run Play and Trace first.');
        }

        let handlerCode = '';
        if (testData && testData.handler) {
            handlerCode = testData.handler;
        } else if (traceReport && traceReport.bestHandler) {
            handlerCode = traceReport.bestHandler.handler || traceReport.bestHandler.code || '';
        } else if (traceReport && traceReport.analyzedHandler) {
            handlerCode = traceReport.analyzedHandler.code || '';
        } else {
            try {
                const bestHandlerKey = `best-handler-${endpointKey}`;
                const storedHandler = await new Promise(resolve => {
                    chrome.storage.local.get(bestHandlerKey, result => {
                        resolve(result[bestHandlerKey]);
                    });
                });

                if (storedHandler) {
                    handlerCode = storedHandler.handler || storedHandler.code || '';
                }

                if (!handlerCode) {
                    const traceInfoKey = `trace-info-${endpointKey}`;
                    const traceInfo = await new Promise(resolve => {
                        chrome.storage.local.get([traceInfoKey], result => {
                            resolve(result[traceInfoKey]);
                        });
                    });

                    if (traceInfo?.analysisStorageKey) {
                        const altHandlerKey = `best-handler-${traceInfo.analysisStorageKey}`;
                        const altHandler = await new Promise(resolve => {
                            chrome.storage.local.get(altHandlerKey, result => {
                                resolve(result[altHandlerKey]);
                            });
                        });
                        if (altHandler) {
                            handlerCode = altHandler.handler || altHandler.code || '';
                        }
                    }
                }
            } catch (e) { console.error('Error retrieving handler:', e); }
        }

        if (!handlerCode) {
            throw new Error('No handler code found. Please run Play first.');
        }

        let messages = [];
        if (testData && testData.originalMessages) {
            messages = testData.originalMessages;
        } else {
            messages = await retrieveMessagesWithFallbacks(endpointKey);
            if (messages.length === 0) {
                if (traceReport?.details?.uniqueStructures?.length > 0) {
                    messages = traceReport.details.uniqueStructures.flatMap(s => s.examples || []) || [];
                } else {
                    console.warn('[Test Environment] No messages found but continuing with defaults.');
                }
            }
        }

        let vulnerabilities = [];
        if (traceReport && traceReport.details && traceReport.details.sinks) {
            vulnerabilities = traceReport.details.sinks;
        } else if (traceReport && traceReport.vulnerabilities) {
            vulnerabilities = traceReport.vulnerabilities;
        } else if(traceReport?.details?.securityIssues) {
            vulnerabilities = traceReport.details.securityIssues;
        }

        let payloads = [];
        try {
            payloads = await window.traceReportStorage.getReportPayloads(endpointKey);
            if (!payloads || payloads.length === 0) {
                const traceInfoKey = `trace-info-${endpointKey}`;
                const traceInfo = await new Promise(resolve => {
                    chrome.storage.local.get([traceInfoKey], result => {
                        resolve(result[traceInfoKey]);
                    });
                });

                if (traceInfo?.analysisStorageKey) {
                    payloads = await window.traceReportStorage.getReportPayloads(traceInfo.analysisStorageKey);
                }

                if ((!payloads || payloads.length === 0) && traceInfo?.analyzedUrl) {
                    const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                    payloads = await window.traceReportStorage.getReportPayloads(analyzedUrlKey);
                }
            }

            if (!payloads || payloads.length === 0) {
                if (traceReport?.details?.payloads?.length > 0) {
                    payloads = traceReport.details.payloads;
                } else if (traceReport?.payloads?.length > 0) {
                    payloads = traceReport.payloads;
                }
            }
        } catch (e) {
            console.error('Error retrieving original payloads:', e);
            payloads = [];
        }

        if (payloads.length === 0) {
            payloads = testData?.payloads || [];
            if (payloads.length === 0) {
                log.warning('[Test Environment] No payloads found in storage or testData, using empty list.');
            }
        }

        await chrome.runtime.sendMessage({ action: "startServer" });
        await new Promise(resolve => setTimeout(resolve, 2000));

        let serverStarted = false;
        let attempts = 0;
        const maxAttempts = 5;

        while (!serverStarted && attempts < maxAttempts) {
            attempts++;
            try {
                const health = await fetch('http://127.0.0.1:1337/health', {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
                    cache: 'no-store'
                });
                if (health.ok) {
                    serverStarted = true;
                    break;
                }
            } catch (e) {
                await new Promise(r => setTimeout(r, 1000));
            }
        }

        if (!serverStarted) {
            throw new Error("Failed to start fuzzer server after multiple attempts");
        }

        const storageData = await chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY]);
        const currentCallbackUrl = storageData[CALLBACK_URL_STORAGE_KEY] || null;

        const customPayloadsResult = await new Promise(resolve => {
            chrome.storage.session.get('customXssPayloads', result => resolve(result.customXssPayloads));
        });
        const useCustomPayloads = customPayloadsResult && customPayloadsResult.length > 0;


        const config = {
            target: endpoint,
            messages: messages,
            handler: handlerCode,
            sinks: vulnerabilities,
            payloads: payloads, // Directly use payloads from storage
            traceData: traceReport ? {
                vulnerabilities: traceReport.vulnerabilities || traceReport.details?.sinks || [],
                dataFlows: traceReport.details?.dataFlows || [],
                securityIssues: traceReport.securityIssues || traceReport.details?.securityIssues || [],
                payloads: payloads
            } : null,
            callbackUrl: currentCallbackUrl,
            fuzzerOptions: {
                skipInitialLoad: false,
                ignoreCSP: true,
                timeout: 10000,
                autoStart: true,
                maxPayloadsPerField: 30,
                maxTotalPayloads: 2000,
                dumbFuzzingPayloadsPerField: 30,
                enableSmartFuzzing: true,
                enableDumbFuzzing: true,
                enablePrototypePollution: true,
                enableCallbackFuzzing: !!currentCallbackUrl,
                enableOriginFuzzing: true,
                randomizePayloadSelection: true,
                useCustomPayloads: useCustomPayloads, // Indicate if custom were used during Trace
                payloadDistribution: {
                    xss: 0.6,
                    callback: 0.2,
                    pollution: 0.1,
                    origin: 0.1
                }
            }
        };

        const response = await fetch('http://127.0.0.1:1337/current-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config),
            signal: AbortSignal.timeout(5000)
        });

        if (!response.ok) {
            throw new Error(`Config update failed: ${response.statusText}`);
        }

        const tab = await chrome.tabs.create({ url: 'http://127.0.0.1:1337/' });

        await new Promise(resolve => {
            let tabLoaded = false;
            const listener = (tabId, info) => {
                if (tabId === tab.id && info.status === 'complete') {
                    chrome.tabs.onUpdated.removeListener(listener);
                    tabLoaded = true;
                    chrome.scripting.executeScript({
                        target: { tabId: tab.id },
                        func: (callbackUrl) => {
                            window.postMessage({
                                type: "serverReady",
                                autoStart: true,
                                callbackUrl: callbackUrl
                            }, "*");
                        },
                        args: [currentCallbackUrl]
                    })
                        .then(() => {
                            resolve();
                        })
                        .catch(err => {
                            resolve();
                        });
                }
            };
            chrome.tabs.onUpdated.addListener(listener);

            setTimeout(() => {
                if (!tabLoaded) {
                    chrome.tabs.onUpdated.removeListener(listener);
                    resolve();
                }
            }, 10000);
        });

        const cleanupListener = (tabId) => {
            if (tabId === tab.id) {
                chrome.runtime.sendMessage({ action: "stopServer" }).catch(e => console.error("Error sending stopServer message:", e));
                chrome.tabs.onRemoved.removeListener(cleanupListener);
            }
        };
        chrome.tabs.onRemoved.addListener(cleanupListener);

        return true;
    } catch (error) {
        alert(`Failed to launch fuzzer: ${error.message}\n\nPlease check if the fuzzer server component is installed and running.`);
        try {
            await chrome.runtime.sendMessage({ action: "stopServer" });
        } catch (e) {
            console.error("Failed to stop server:", e.message);
        }
        return false;
    }
}

function findBestPropertyToReplace(obj) {
    if (!obj || typeof obj !== 'object') return null;

    // Look for string properties first, preferring ones with HTML-related names
    const htmlKeys = ['html', 'content', 'body', 'message', 'text', 'value', 'src', 'url'];

    // Check for direct string properties first
    for (const key of htmlKeys) {
        if (obj[key] && typeof obj[key] === 'string') {
            return key;
        }
    }

    // Check for any string property
    for (const key in obj) {
        if (typeof obj[key] === 'string') {
            return key;
        }
    }

    // Look for nested object properties
    for (const key in obj) {
        if (typeof obj[key] === 'object' && obj[key] !== null) {
            const nestedProperty = findBestPropertyToReplace(obj[key]);
            if (nestedProperty) {
                return `${key}.${nestedProperty}`;
            }
        }
    }

    // If we couldn't find any string property, just return the first key
    const keys = Object.keys(obj);
    return keys.length > 0 ? keys[0] : null;
}

function modifyObjectProperty(obj, path, value) {
    if (!path) return;

    const parts = path.split('.');
    let current = obj;

    // Follow the path to the property container
    for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i];
        if (current[part] === undefined || current[part] === null) {
            current[part] = {};
        }
        current = current[part];
    }

    // Set the value on the final property
    const finalPart = parts[parts.length - 1];
    current[finalPart] = value;
}

function showQueryModal(endpoint) {
    return new Promise((resolve) => {
        try {
            log.handler(`[Query Modal] Opening for endpoint: ${endpoint}`);
            const originalUrl = new URL(endpoint);
            const currentParams = new URLSearchParams(originalUrl.search);

            const modalContainer = document.getElementById('queryModalContainer');
            if (!modalContainer) {
                log.error("[Query Modal] Container element 'queryModalContainer' not found.");
                resolve({ url: endpoint, modified: false, cancelled: true });
                return;
            }
            modalContainer.innerHTML = '';

            const modal = document.createElement('div');
            modal.className = 'query-modal';

            let modalContentHTML = `<h2 class="query-modal-title">Modify Query Parameters</h2><div class="query-modal-body">`;
            let paramCount = 0;

            currentParams.forEach((value, key) => {
                paramCount++;
                modalContentHTML += `<div class="query-param-row">
                                       <label class="query-param-label">${escapeHTML(key)}:</label>
                                       <input type="text" class="query-param-input" value="${escapeHTML(value)}" data-param="${escapeHTML(key)}">
                                    </div>`;
            });

            if (paramCount === 0) {
                modalContentHTML += '<p class="query-modal-no-params">No query parameters found in URL.</p>';
            }

            modalContentHTML += `</div><div class="query-modal-footer">
                                    <button id="cancelBtn" class="control-button secondary-button">Cancel</button>
                                    <button id="okBtn" class="control-button primary-button">OK</button>
                                </div>`;

            modal.innerHTML = modalContentHTML;

            const backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop';
            const closeModal = (result) => {
                modal.remove();
                backdrop.remove();
                resolve(result);
            };


            modalContainer.appendChild(backdrop);
            modalContainer.appendChild(modal);

            modal.querySelector('#okBtn').addEventListener('click', () => {
                const inputs = modal.querySelectorAll('input.query-param-input');
                const modifiedUrl = new URL(endpoint);
                modifiedUrl.search = '';

                inputs.forEach(input => {
                    const param = input.dataset.param;
                    const value = input.value;
                    modifiedUrl.searchParams.set(param, value);
                });

                log.handler(`[Query Modal] OK clicked. Modified URL: ${modifiedUrl.toString()}`);
                closeModal({ url: modifiedUrl.toString(), modified: true, originalUrl: endpoint });
            });

            modal.querySelector('#cancelBtn').addEventListener('click', () => {
                log.handler(`[Query Modal] Cancel clicked.`);
                closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint });
            });

            backdrop.addEventListener('click', () => {
                log.handler(`[Query Modal] Backdrop clicked.`);
                closeModal({ url: endpoint, modified: false, cancelled: true, originalUrl: endpoint });
            });


        } catch (error) {
            log.error('[Query Modal] Error:', error);
            resolve({ url: endpoint, modified: false, originalUrl: endpoint });
        }
    });
}


async function saveRandomPostMessages(endpointKey) {
    const MAX_MESSAGES = 20;
    let relevantMessages = messages.filter(msg => {
        if (!msg?.origin || !msg?.destinationUrl) return false;
        const originKey = getStorageKeyForUrl(msg.origin);
        const destKey = getStorageKeyForUrl(msg.destinationUrl);
        return originKey === endpointKey || destKey === endpointKey;
    });

    relevantMessages = relevantMessages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, MAX_MESSAGES);

    const processedMessages = relevantMessages.map(msg => {
        if (!msg.messageType) {
            let messageType = 'unknown';
            let data = msg.data;
            if (data === undefined || data === null) messageType = 'null_or_undefined';
            else if (typeof data === 'string') { try { JSON.parse(data); messageType = 'json_string'; } catch (e) { messageType = 'string'; } }
            else if (Array.isArray(data)) messageType = 'array';
            else if (typeof data === 'object') messageType = 'object';
            else messageType = typeof data;
            return {...msg, messageType: messageType};
        }
        return msg;
    });

    const storageKey = `saved-messages-${endpointKey}`;
    try {
        await chrome.storage.local.set({ [storageKey]: processedMessages });
        return processedMessages;
    } catch (error) {
        try { await chrome.storage.local.remove(storageKey); } catch (removeError) {}
        return [];
    }
}

async function retrieveMessagesWithFallbacks(endpointKey) {
    const primaryStorageKey = `saved-messages-${endpointKey}`;
    try {
        const primaryResult = await new Promise(resolve => {
            chrome.storage.local.get([primaryStorageKey], result => {
                resolve(result[primaryStorageKey] || null);
            });
        });
        if (primaryResult?.length > 0) {
            return primaryResult;
        }
    } catch(e) { /* ignore storage errors */ }
    return [];
}

async function handlePlayButton(endpoint, button, skipCheck = false) {

    const endpointKey = button.getAttribute('data-endpoint');
    if (!endpointKey) {
        log.error("[Play Button] Critical: Could not determine endpoint key from button attribute.");
        updateButton(button, 'error');
        return;
    }
    const originalFullEndpoint = endpoint;

    const currentButtonContainer = button.closest('.button-container');
    const traceButton = currentButtonContainer?.querySelector('.iframe-trace-button');
    const reportButton = currentButtonContainer?.querySelector('.iframe-report-button');

    button.classList.remove('show-next-step-emoji', 'show-next-step-arrow');
    if (traceButton) traceButton.classList.remove('show-next-step-emoji');
    if (button.classList.contains('has-critical-sinks') || button.textContent === '🚀') {
        if (launchInProgressEndpoints.has(endpointKey)) {
            log.handler(`Launch already in progress for key: ${endpointKey}`);
            return;
        }
        launchInProgressEndpoints.add(endpointKey);
        log.scan(`Starting launch for endpoint represented by key: ${endpointKey}`);

        try {
            const traceInfoKey = `trace-info-${endpointKey}`;
            const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
            const traceInfo = traceInfoResult[traceInfoKey];

            if (!traceInfo?.success || !traceInfo?.analyzedUrl) {
                const mappingKey = `analyzed-url-for-${endpointKey}`;
                const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
                const mappedUrl = mappingResult[mappingKey];
                if (!mappedUrl) {
                    throw new Error(`Trace/Analyzed URL info not found for key ${endpointKey}. Run Play/Trace again.`);
                }
                log.warning(`[Launch] Trace info missing, using stored analyzed URL: ${mappedUrl}`);
                traceInfo = { analyzedUrl: mappedUrl };
            }

            const endpointKeyForReport = traceInfo.analyzedUrl;
            log.handler(`[Launch] Using effective endpoint from trace/mapping for fetching report/payloads: ${endpointKeyForReport}`);

            const [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(endpointKeyForReport),
                window.traceReportStorage.getReportPayloads(endpointKeyForReport)
            ]);

            log.handler(`[Launch] Retrieved report data and ${reportPayloads?.length || 0} payloads using key: ${endpointKeyForReport}`);

            const payloads = reportPayloads || [];
            const targetEndpointForLaunch = endpointKeyForReport;

            const details = reportData.details || {};
            const bestHandlerRef = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler;
            let handlerCode = bestHandlerRef ? (bestHandlerRef.handler || bestHandlerRef.code) : null;
            const sinks = details.sinks || reportData.vulnerabilities || [];

            let relevantMessages = await retrieveMessagesWithFallbacks(endpointKey);
            if (relevantMessages.length === 0 && details.uniqueStructures?.length > 0) {
                relevantMessages = details.uniqueStructures.flatMap(s => s.examples || []);
            }

            if (!handlerCode) {
                const analysisStorageKeyForHandler = getStorageKeyForUrl(endpointKeyForReport);
                const handlerStorageKey = `best-handler-${analysisStorageKeyForHandler}`;
                log.warning(`[Launch] Handler missing in report, attempting fetch from: ${handlerStorageKey}`);
                const handlerResult = await new Promise(resolve => chrome.storage.local.get(handlerStorageKey, resolve));
                handlerCode = handlerResult[handlerStorageKey]?.handler || handlerResult[handlerStorageKey]?.code;
                if (!handlerCode) throw new Error(`Handler code missing for launch. Key: ${handlerStorageKey}`);
            }

            const testData = { target: targetEndpointForLaunch, originalMessages: relevantMessages, handler: handlerCode, sinks: sinks, payloads: payloads };

            // Check if custom payloads are active
            try {
                const customPayloadsResult = await new Promise(resolve => {
                    chrome.storage.session.get('customXssPayloads', result => resolve(result.customXssPayloads));
                });
                if (customPayloadsResult && customPayloadsResult.length > 0) {
                    log.info(`[Play Button] Using ${customPayloadsResult.length} custom payloads for this test run.`);
                }
            } catch (e) {
                log.debug("[Play Button] Error checking custom payloads:", e);
            }

            const success = await launchFuzzerEnvironment(targetEndpointForLaunch, testData);
            updateButton(button, success ? 'launch' : 'error', { hasCriticalSinks: button.classList.contains('has-critical-sinks') });
            if (traceButton) updateTraceButton(traceButton, success ? 'success' : 'default');

        } catch (error) {
            log.error('[Launch Error]:', error?.message, error?.stack);
            alert(`Fuzzer launch failed: ${error.message}`);
            updateButton(button, 'error');
            if (traceButton) updateTraceButton(traceButton, 'disabled');
            try { await chrome.runtime.sendMessage({ action: "stopServer" }); } catch (e) { /* ignore */ }
        } finally {
            launchInProgressEndpoints.delete(endpointKey);
            log.handler(`Finished launch attempt for key ${endpointKey}`);
            setTimeout(() => requestAnimationFrame(updateDashboardUI), 100);
        }
        return;
    }

    if (launchInProgressEndpoints.has(endpointKey)) {
        log.handler(`Play/Analysis already in progress for key: ${endpointKey}`);
        return;
    }
    launchInProgressEndpoints.add(endpointKey);

    let analysisStorageKey = endpointKey;
    let endpointUrlForAnalysis = originalFullEndpoint;
    let handlerStateUpdated = false;
    let foundHandlerObject = null;
    let usingStaticFallback = false;

    try {
        await saveRandomPostMessages(endpointKey);
        const modalResult = await showQueryModal(originalFullEndpoint);
        log.handler('[Play Revised] Modal Result:', JSON.stringify(modalResult, null, 2));

        if (modalResult.cancelled) {
            updateButton(button, 'start');
            throw new Error("User cancelled");
        }

        if (modalResult.modified) {
            endpointUrlForAnalysis = modalResult.url;
            analysisStorageKey = getStorageKeyForUrl(endpointUrlForAnalysis);
            const mappingKey = `analyzed-url-for-${endpointKey}`;
            await chrome.storage.local.set({ [mappingKey]: endpointUrlForAnalysis });
            modifiedEndpoints.set(endpointKey, endpointUrlForAnalysis);
            await chrome.storage.local.set({ [`analysis-storage-key-for-${endpointKey}`]: analysisStorageKey });
            log.handler(`Stored analyzed URL mapping: ${mappingKey} -> ${endpointUrlForAnalysis}, analysis storage key: ${analysisStorageKey}`);
        } else {
            analysisStorageKey = getStorageKeyForUrl(originalFullEndpoint);
            endpointUrlForAnalysis = originalFullEndpoint;
            const mappingKey = `analyzed-url-for-${endpointKey}`;
            await chrome.storage.local.remove(mappingKey);
            await chrome.storage.local.remove(`analysis-storage-key-for-${endpointKey}`);
            modifiedEndpoints.delete(endpointKey);
            log.handler(`Using original URL for analysis. Removed any previous analyzed URL mapping for: ${mappingKey}. Analysis key: ${analysisStorageKey}`);
        }

        if (!skipCheck) {
            updateButton(button, 'csp');
            log.handler(`[Play Revised] Performing embedding check for URL: ${endpointUrlForAnalysis}`);
            const cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
            log.handler('[Play Revised] CSP Check Result Object:', JSON.stringify(cspResult, null, 2));
            if (!cspResult.embeddable) {
                log.handler('[Play Revised] CSP Check determined NOT embeddable. Throwing error...');
                throw new Error(`Embedding check failed: ${cspResult.status}`);
            } else {
                log.handler('[Play Revised] CSP Check determined embeddable. Proceeding to handler retrieval.');
            }
        } else {
            log.handler('[Play Revised] Skipping CSP Check because skipCheck=true.');
        }

        updateButton(button, 'analyze');
        const runtimeListenerKey = `runtime-listeners-${endpointKey}`;
        log.handler(`[Play Revised] Attempting runtime listener retrieval using key: ${runtimeListenerKey}`);

        const runtimeResult = await new Promise((resolve, reject) => {
            chrome.storage.local.get([runtimeListenerKey], (result) => {
                if (chrome.runtime.lastError) {
                    log.error(`Error getting runtime listeners for ${runtimeListenerKey}:`, chrome.runtime.lastError);
                    resolve(null);
                } else {
                    resolve(result);
                }
            });
        });
        const runtimeListeners = runtimeResult ? runtimeResult[runtimeListenerKey] : null;

        const validRuntimeListeners = runtimeListeners?.filter(l =>
            l?.code &&
            typeof l.code === 'string' &&
            !l.code.includes('[native code]') &&
            l.code.length > 25
        ) || [];

        if (validRuntimeListeners.length > 0) {
            log.success(`[Play Revised] Found ${validRuntimeListeners.length} valid runtime listener(s) in storage.`);
            usingStaticFallback = false;

            if (validRuntimeListeners.length > 1) {
                const scoringMessages = await retrieveMessagesWithFallbacks(endpointKey);
                if (scoringMessages.length > 0) {
                    try {
                        const extractorForScoring = new HandlerExtractor();
                        extractorForScoring.initialize(endpointUrlForAnalysis, scoringMessages);
                        let bestListener = null, highestScore = -1;
                        validRuntimeListeners.forEach(listener => {
                            const score = extractorForScoring.scoreHandler(listener.code, 'runtime-captured-scored', scoringMessages);
                            if (score > highestScore) { highestScore = score; bestListener = listener; }
                        });
                        if (bestListener) {
                            foundHandlerObject = { handler: bestListener.code, category: 'runtime-captured-scored', score: highestScore, source: 'runtime-instrumentation', timestamp: bestListener.timestamp, stack: bestListener.stack, context: bestListener.context || 'unknown' };
                            log.success(`[Play Revised] Selected best runtime handler via scoring (Score: ${highestScore.toFixed(1)})`);
                        } else {
                            log.warning("[Play Revised] Scoring ran on multiple runtime handlers but didn't yield a best one.");
                        }
                    } catch (scoringError) {
                        log.error("[Play Revised] Error during runtime handler scoring:", scoringError);
                    }
                } else {
                    log.info("[Play Revised] Multiple runtime handlers found, but no messages available for scoring.");
                }
            }

            if (!foundHandlerObject) {
                const chosenListener = validRuntimeListeners[0];
                foundHandlerObject = { handler: chosenListener.code, category: 'runtime-captured-first', score: 50, source: 'runtime-instrumentation', timestamp: chosenListener.timestamp, stack: chosenListener.stack, context: chosenListener.context || 'unknown' };
                log.success(`[Play Revised] Selected first valid runtime handler (unscored or single listener).`);
            }

        } else {
            log.warning(`[Play Revised] No valid runtime listeners found (or only found '[native code]' listeners) for key: ${runtimeListenerKey}.`);
            usingStaticFallback = true;
            log.info(`[Play Revised] Initiating static handler extraction (using HandlerExtractor) as fallback for URL: ${endpointUrlForAnalysis}`);

            try {
                const extractor = new HandlerExtractor();
                const fallbackMessages = await retrieveMessagesWithFallbacks(endpointKey);
                extractor.initialize(endpointUrlForAnalysis, fallbackMessages);
                const extractedFallbackHandlers = await extractor.extract();

                if (extractedFallbackHandlers?.length > 0) {
                    const bestFallbackHandler = extractor.getBestHandler(extractedFallbackHandlers);
                    if (bestFallbackHandler) {
                        foundHandlerObject = bestFallbackHandler;
                        log.success(`[Play Revised] Selected best handler via static fallback extraction (Score: ${foundHandlerObject.score?.toFixed(1)}, Cat: ${foundHandlerObject.category})`);
                    } else {
                        log.warning(`[Play Revised] Static fallback extraction ran but getBestHandler determined none were suitable.`);
                        foundHandlerObject = null;
                    }
                } else {
                    log.warning(`[Play Revised] Static fallback extraction found no potential handlers.`);
                    foundHandlerObject = null;
                }
            } catch (extractionError) {
                log.error(`[Play Revised] Error during static fallback extraction:`, extractionError);
                foundHandlerObject = null;
            }
        }

        if (foundHandlerObject && foundHandlerObject.handler) {
            const finalBestHandlerKey = `best-handler-${analysisStorageKey}`;
            try {
                await chrome.storage.local.set({ [finalBestHandlerKey]: foundHandlerObject });
                log.success(`Saved best ${usingStaticFallback ? 'static fallback' : 'runtime'} handler to storage key: ${finalBestHandlerKey}`);
                const runtimeListenerStorageKey = `runtime-listeners-${endpointKey}`;
                try {
                    const result = await new Promise((resolve, reject) => {
                        chrome.storage.local.get([runtimeListenerStorageKey], (res) => { if (chrome.runtime.lastError) reject(chrome.runtime.lastError); else resolve(res); });
                    });
                    let listeners = result[runtimeListenerStorageKey] || [];
                    const handlerCodeOnly = foundHandlerObject.handler;
                    const alreadyExists = listeners.some(l => l.code === handlerCodeOnly);

                    if (!alreadyExists) {
                        listeners.push({
                            code: handlerCodeOnly,
                            context: `selected-by-play (${foundHandlerObject.category || (usingStaticFallback ? 'static-fallback' : 'runtime')})`,
                            timestamp: foundHandlerObject.timestamp || Date.now(),
                            stack: foundHandlerObject.stack,
                        });
                        if (listeners.length > 30) listeners = listeners.slice(-30);
                        await chrome.storage.local.set({ [runtimeListenerStorageKey]: listeners });
                        log.handler(`Added/updated selected handler in runtime list: ${runtimeListenerStorageKey}`);
                        if (!endpointsWithHandlers.has(endpointKey)) {
                            endpointsWithHandlers.add(endpointKey);
                            handlerStateUpdated = true;
                            log.handler(`Updated in-memory set: Handler now known for ${endpointKey}`);
                        }
                    } else {
                        log.handler(`Selected handler code already exists in runtime list for ${endpointKey}.`);
                        if (!endpointsWithHandlers.has(endpointKey)) {
                            endpointsWithHandlers.add(endpointKey);
                            handlerStateUpdated = true;
                            log.handler(`Force updated in-memory set: Handler known for ${endpointKey}`);
                        }
                    }
                } catch (runtimeSaveError) {
                    log.error(`Failed to update runtime listeners list for ${runtimeListenerStorageKey}:`, runtimeSaveError);
                }

                updateButton(button, 'success');
                if (traceButton) updateTraceButton(traceButton, 'default', { showEmoji: true });
                if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);

            } catch (storageError) {
                log.error(`Failed to save best handler to storage (${finalBestHandlerKey}):`, storageError);
                updateButton(button, 'error');
                if (traceButton) updateTraceButton(traceButton, 'disabled');
                if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
            }

        } else {
            log.error(`[Play Revised] No usable handler found for URL ${endpointUrlForAnalysis} (key: ${endpointKey}) after all methods.`);
            updateButton(button, 'warning');
            if (traceButton) updateTraceButton(traceButton, 'disabled');
            if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        }

        if (handlerStateUpdated) {
            requestAnimationFrame(updateDashboardUI);
        }

    } catch (error) {
        let errorMessage = error.message || "Unknown error";
        let errorTooltip = 'Check failed';

        if (errorMessage.startsWith("Embedding check failed:")) {
            errorTooltip = errorMessage;
            log.error(`[Play Button CSP Error] for endpoint key ${endpointKey}:`, errorMessage);
            showToastNotification(errorMessage, 'error', 7000);
            updateButton(button, 'error', { errorMessage: 'Embedding check failed' });
        } else if (error.message === "User cancelled") {
            log.info(`User cancelled Play action for key ${endpointKey}.`);
            const currentState = buttonStates.get(endpointKey)?.state || 'start';
            if (['start', 'csp', 'analyze', 'checking', 'default'].includes(currentState)) {
                updateButton(button, 'start');
            }
            launchInProgressEndpoints.delete(endpointKey);
            log.handler(`Cancelled checks for key ${endpointKey}. State lock released.`);
            return;
        } else {
            errorTooltip = `Error: ${errorMessage.substring(0, 100)}${errorMessage.length > 100 ? '...' : ''}`;
            log.error(`[Play Button Error] for endpoint key ${endpointKey}:`, errorMessage, error.stack);
            showToastNotification(`Error: ${errorMessage.substring(0, 150)}...`, 'error');
            updateButton(button, 'error', { errorMessage: 'An error occurred' });
        }

        if (traceButton) updateTraceButton(traceButton, 'disabled');
        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);

    } finally {
        launchInProgressEndpoints.delete(endpointKey);
        log.handler(`Finished checks/attempt for key ${endpointKey}. State lock released.`);
        setTimeout(() => requestAnimationFrame(updateDashboardUI), 150);
    }
}


function getRiskLevelAndColor(score) {
    if (score <= 20) return { riskLevel: 'Critical', riskColor: 'critical' };
    if (score <= 40) return { riskLevel: 'High', riskColor: 'high' };
    if (score <= 60) return { riskLevel: 'Medium', riskColor: 'medium' };
    if (score <= 80) return { riskLevel: 'Low', riskColor: 'low' };
    return { riskLevel: 'Good', riskColor: 'negligible' };
}

function getRecommendationText(score, reportData) {

    const hasCriticalSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'critical') || false;
    const hasHighSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'high') || false;
    const hasHighIssue = reportData?.details?.securityIssues?.some(s => s.severity?.toLowerCase() === 'high') || false;
    const mediumIssueCount = reportData?.details?.securityIssues?.filter(s => s.severity?.toLowerCase() === 'medium')?.length || 0;

    if (hasCriticalSink) {
        return 'Immediate attention required. Critical vulnerabilities present. Fix critical sinks (eval, innerHTML, etc.) and implement strict origin/data validation.';
    }

    if (score <= 20) {
        return 'Immediate attention required. Security posture is critically weak. Focus on fixing high-risk issues and implementing strict origin/data validation.';
    }

    if (hasHighSink || hasHighIssue || score <= 40) {
        return 'Significant risks identified. Implement strict origin checks and sanitize all inputs used in sinks. Consider a Content Security Policy (CSP).';
    }

    if (mediumIssueCount >= 3 || score <= 60) {
        return 'Potential vulnerabilities detected. Review security issues (e.g., origin checks, data validation) and ensure data flowing to sinks is safe.';
    }

    if (score <= 80) {
        return 'Low risk detected, but review identified issues and follow security best practices (origin/data validation).';
    }

    const hasFindings = (reportData?.details?.sinks?.length > 0) ||
        (reportData?.details?.securityIssues?.length > 0);

    if (hasFindings) {
        return 'Good score, but minor issues or informational findings detected. Review details and ensure best practices are followed.';
    }

    return 'Excellent score. Analysis found no major vulnerabilities. Continue to follow security best practices for postMessage handling.';
}

function renderStructureItem(structureData, index) {
    const exampleData = structureData.examples?.[0]?.data || structureData.examples?.[0] || {};
    let formattedExample = '';
    try { formattedExample = typeof exampleData === 'string' ? exampleData : JSON.stringify(exampleData, null, 2); }
    catch (e) { formattedExample = String(exampleData); }
    // const pathsString = structureData.pathsToFuzz?.map(p => `<code>${escapeHTML(p.path)} (${escapeHTML(p.type)})</code>`).join(', ') || 'N/A';

    return `
        <details class="report-details structure-item" data-structure-index="${index}">
            <summary class="report-summary-toggle">Structure ${index + 1} <span class="toggle-icon">▶</span></summary>
            <div class="structure-content">
                <p><strong>Example Message:</strong></p>
                <div class="report-code-block"><pre><code>${escapeHTML(formattedExample)}</code></pre></div>
            </div>
        </details>`;
}

function renderPayloadItem(payloadItem, index) {
    let displayString = '(Error displaying payload)';
    const maxDisplayLength = 150;

    const safeEscapeHTML = (str) => { try { return escapeHTML(str); } catch(e){ console.error("escapeHTML failed in renderPayloadItem", e); return '[Error]'; }};

    try {
        const actualPayloadData = (payloadItem && payloadItem.payload !== undefined)
            ? payloadItem.payload
            : payloadItem;

        if (typeof actualPayloadData === 'object' && actualPayloadData !== null) {
            const payloadJson = JSON.stringify(actualPayloadData, null, 2);
            displayString = payloadJson.substring(0, maxDisplayLength) + (payloadJson.length > maxDisplayLength ? '...' : '');
        } else {
            const payloadAsString = String(actualPayloadData);
            displayString = payloadAsString.substring(0, maxDisplayLength) + (payloadAsString.length > maxDisplayLength ? '...' : '');
        }
    } catch (e) {
        console.error(`[renderPayloadItem] Internal error processing payload index ${index}:`, payloadItem, e);
        return `<div class="payload-item error">Error rendering payload ${index + 1}. See console.</div>`;
    }

    return `<div class="payload-item" data-payload-index="${index}">
                <pre><code>${safeEscapeHTML(displayString)}</code></pre>
                <button class="view-full-payload-btn control-button secondary-button" style="font-size:10px; padding: 2px 5px; margin-top: 5px;">View Full</button>
            </div>`;
}

function attachReportEventListeners(panel, reportData) {
    panel.querySelectorAll('details.report-details').forEach(detailsElement => {
        const iconElement = detailsElement.querySelector('.toggle-icon');
        if (detailsElement && iconElement) {
            detailsElement.addEventListener('toggle', () => {
                iconElement.textContent = detailsElement.open ? '▼' : '▶';
            });
        }
    });

    panel.querySelectorAll('.view-full-payload-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const item = e.target.closest('.payload-item');
            const index = parseInt(item?.getAttribute('data-payload-index'));
            const payloads = reportData?.details?.payloads || [];
            if (payloads[index] !== undefined) {
                showFullPayloadModal(payloads[index]);
            }
        });
    });

    const showAllPayloadsBtn = panel.querySelector('#showAllPayloadsBtn');
    if (showAllPayloadsBtn) {
        showAllPayloadsBtn.addEventListener('click', () => {
            const list = panel.querySelector('#payloads-list');
            const payloads = reportData?.details?.payloads || [];
            if (list && payloads.length > 0) {
                list.innerHTML = payloads.map((p, index) => renderPayloadItem(p, index)).join('');
                attachReportEventListeners(panel, reportData);
            }
            showAllPayloadsBtn.remove();
        }, { once: true });
    }

    const showAllStructuresBtn = panel.querySelector('#showAllStructuresBtn');
    if (showAllStructuresBtn) {
        showAllStructuresBtn.addEventListener('click', () => {
            const list = panel.querySelector('.structures-list');
            const structures = reportData?.details?.uniqueStructures || [];
            if (list && structures.length > 0) {
                list.innerHTML = structures.map((s, index) => renderStructureItem(s, index)).join('');
                attachReportEventListeners(panel, reportData);
            }
            showAllStructuresBtn.remove();
        }, { once: true });
    }
}

function displayReport(reportData, panel) {
    try {
        while (panel.firstChild) {
            panel.removeChild(panel.firstChild);
        }
    } catch (clearError) {
        panel.innerHTML = '<p class="error-message">Internal error clearing report panel.</p>'; // Add basic error message to panel
        return; // Stop if clearing fails
    }

    let header;
    try {
        header = document.createElement('div');
        header.className = 'trace-panel-header';
        header.innerHTML = `<h3>PostMessage Analysis Report</h3><button class="trace-panel-close">✕</button>`;
        panel.appendChild(header);
        header.querySelector('.trace-panel-close').onclick = () => {
            const backdrop = document.querySelector('.trace-panel-backdrop');
            if (backdrop) backdrop.remove();
            panel.remove();
        };
    } catch (headerError) {
        console.error("[displayReport] Error creating/adding header:", headerError);
        // Attempt to add error message even if header fails
        panel.innerHTML = '<p class="error-message">Internal error creating report header.</p>';
        return;
    }

    let content;
    try {
        content = document.createElement('div');
        content.className = 'trace-results-content';
        panel.appendChild(content);
    } catch (contentError) {
        console.error("[displayReport] Error creating/adding content container:", contentError);
        panel.innerHTML = (header ? header.outerHTML : '') + '<p class="error-message">Internal error creating report content area.</p>';
        return;
    }

    if (!reportData || typeof reportData !== 'object') {
        console.error("[displayReport] Invalid or missing report data object.");
        content.innerHTML = '<p class="error-message">Error: Invalid or missing report data.</p>';
        return;
    }
    try {

        const details = reportData.details || {};
        const summary = reportData.summary || {};
        const bestHandler = details.bestHandler || reportData.bestHandler || reportData.analyzedHandler;
        const vulnerabilities = [...(details.sinks || []), ...(reportData.vulnerabilities || [])];
        const securityIssues = [...(details.securityIssues || []), ...(reportData.securityIssues || [])];
        const dataFlows = details.dataFlows || [];
        const payloads = details.payloads || [];
        const structures = details.uniqueStructures || [];

        const safeEscapeHTML = (str) => { try { return escapeHTML(str); } catch(e){ console.error('escapeHTML failed:', e); return '[Error]'; }};
        const safeGetRisk = (score) => { try { return getRiskLevelAndColor(score); } catch(e){ console.error('getRiskLevelAndColor failed:', e); return { riskLevel: 'Error', riskColor: 'critical' }; }};
        const safeGetRec = (score, data) => { try { return getRecommendationText(score, data); } catch(e){ console.error('getRecommendationText failed:', e); return 'Error generating recommendation.'; }};
        const safeRenderPayload = (p, i) => { try { return renderPayloadItem(p, i); } catch(e){ console.error('renderPayloadItem failed:', e); return '<p class="error-message">Error rendering payload item.</p>'; }};
        const safeRenderStructure = (s, i) => { try { return renderStructureItem(s, i); } catch(e){ console.error('renderStructureItem failed:', e); return '<p class="error-message">Error rendering structure item.</p>'; }};


        const uniqueVulns = vulnerabilities.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const uniqueIssues = securityIssues.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const score = reportData.securityScore ?? summary.securityScore ?? 100;
        const { riskLevel, riskColor } = safeGetRisk(score);

        const summarySection = document.createElement('div');
        summarySection.className = 'report-section report-summary';
        summarySection.innerHTML = `
            <h4 class="report-section-title">Analysis Summary</h4>
            <div class="summary-grid">
            <div class="security-score-container">
                     <h5 class="risk-score-title">Risk Score:</h5>
                     <div class="security-score ${riskColor}" title="Risk Score: ${score} (${riskLevel})">
                         <div class="security-score-value">${score}</div>
                         <div class="security-score-label">${riskLevel}</div>
                     </div>
                 </div>
                 <div class="summary-metrics">
                     <div class="metric"><span class="metric-label">Msgs Analyzed</span><span class="metric-value">${summary.messagesAnalyzed ?? 'N/A'}</span></div>
                     <div class="metric"><span class="metric-label">Msg Structures</span><span class="metric-value">${structures?.length ?? 0}</span></div>
                     <div class="metric"><span class="metric-label">Sinks Found</span><span class="metric-value">${uniqueVulns?.length ?? 0}</span></div>
                     <div class="metric"><span class="metric-label">Sec. Issues</span><span class="metric-value">${uniqueIssues?.length ?? 0}</span></div>
                     <div class="metric"><span class="metric-label">Payloads Gen.</span><span class="metric-value">${payloads?.length ?? 0}</span></div>
                 </div>
            </div>
            <div class="risk-score-explanation">
                <p><strong>About the Risk Score (0-100):</strong> Estimates handler security. Lower scores mean higher risk based on detected sinks & issues.</p>
                <p>Categories: Critical (≤20), High (≤40), Medium (≤60), Low (≤80), Good (>80).</p>
            </div>
            <div class="recommendations">
                <h5 class="report-subsection-title">Recommendation</h5>
                <p class="recommendation-text">${safeEscapeHTML(safeGetRec(score, reportData))}</p>
            </div>
        `;
        content.appendChild(summarySection);

        if (bestHandler?.handler) {
            const handlerSection = document.createElement('div');
            handlerSection.className = 'report-section report-handler';
            handlerSection.innerHTML = `<details class="report-details"><summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Category: ${safeEscapeHTML(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▶</span></summary><div class="report-code-block handler-code"><pre><code>${safeEscapeHTML(bestHandler.handler)}</code></pre></div></details>`;
            content.appendChild(handlerSection);
        } else {
            console.log("[displayReport] No best handler found to display.");
        }

        const findingsSection = document.createElement('div');
        findingsSection.className = 'report-section report-findings';
        let findingsHTML = '<h4 class="report-section-title">Findings</h4>';
        if (uniqueVulns.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">DOM XSS Sinks Detected (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueVulns.forEach(vuln => {
                // Added checks for potentially missing properties in vuln
                const type = vuln?.type || '?';
                const severity = vuln?.severity || 'N/A';
                const context = vuln?.context || '';
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscapeHTML(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscapeHTML(severity)}</span></td><td><code class="context-snippet">${safeEscapeHTML(context)}</code></td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        } else { findingsHTML += `<p class="no-findings-text">No direct DOM XSS sinks found.</p>`; }

        if (uniqueIssues.length > 0) {
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueIssues.forEach(issue => {
                const type = issue?.type || '?';
                const severity = issue?.severity || 'N/A';
                const context = issue?.context || '';
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${safeEscapeHTML(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${safeEscapeHTML(severity)}</span></td><td><code class="context-snippet">${safeEscapeHTML(context)}</code></td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        } else { findingsHTML += `<p class="no-findings-text">No other security issues found.</p>`; }
        findingsSection.innerHTML = findingsHTML;
        content.appendChild(findingsSection);

        if (dataFlows?.length > 0) {
            const flowSection = document.createElement('div');
            flowSection.className = 'report-section report-dataflow';
            flowSection.innerHTML = `<h4 class="report-section-title">Data Flow (Message Data → Sink)</h4><table class="report-table dataflow-table"><thead><tr><th>Source Property</th><th>Sink Function</th><th>Context Snippet</th></tr></thead><tbody>`;
            dataFlows.forEach(flow => {
                const prop = flow?.property || '?';
                const sink = flow?.sink || '?';
                const context = flow?.context || '';
                flowSection.innerHTML += `<tr><td><code>event.data.${safeEscapeHTML(prop)}</code></td><td>${safeEscapeHTML(sink)}</td><td><code class="context-snippet">${safeEscapeHTML(context)}</code></td></tr>`;
            });
            flowSection.innerHTML += `</tbody></table>`;
            content.appendChild(flowSection);
        } else {
            log.debug("[displayReport] No data flows to display.");
        }

        if (payloads?.length > 0) {
            const payloadSection = document.createElement('div');
            payloadSection.className = 'report-section report-payloads';
            // Use safe renderer
            payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (${payloads.length})</h4><div id="payloads-list" class="payloads-list report-list">${payloads.slice(0, 10).map((p, index) => safeRenderPayload(p, index)).join('')}</div>${payloads.length > 10 ? `<button id="showAllPayloadsBtn" class="control-button secondary-button show-more-btn">Show All ${payloads.length} Payloads</button>` : ''}`;
            content.appendChild(payloadSection);
        } else {
            const payloadSection = document.createElement('div');
            payloadSection.className = 'report-section report-payloads';
            payloadSection.innerHTML = `<h4 class="report-section-title">Generated Payloads (0)</h4><p class="no-findings-text">No specific payloads were generated for this analysis.</p>`;
            content.appendChild(payloadSection);
        }

        if (structures?.length > 0) { // Check if structures exists and has length
            const structureSection = document.createElement('div');
            structureSection.className = 'report-section report-structures';
            let structuresHTML = `<h4 class="report-section-title">Unique Message Structures (${structures.length})</h4><div class="structures-list report-list">`;
            // Use safe renderer
            structures.slice(0, 3).forEach((s, index) => { structuresHTML += safeRenderStructure(s, index); });
            structuresHTML += `</div>`;
            if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length} Structures</button>`; }
            structureSection.innerHTML = structuresHTML;
            content.appendChild(structureSection);
        } else {
            const structureSection = document.createElement('div');
            structureSection.className = 'report-section report-structures';
            structureSection.innerHTML = `<h4 class="report-section-title">Unique Message Structures (0)</h4><p class="no-findings-text">No distinct message structures could be analyzed.</p>`;
            content.appendChild(structureSection);
        }

        attachReportEventListeners(panel, reportData); // Attach all listeners at the end

    } catch (renderError) {
        content.innerHTML = `<p class="error-message">Error rendering report details: ${renderError.message}<br><pre>${renderError.stack}</pre></p>`;
    }
}


function showFullPayloadModal(payloadItem) {
    const existingModal = document.querySelector('.payload-modal');
    if (existingModal) existingModal.remove();
    const existingBackdrop = document.querySelector('.payload-modal-backdrop');
    if (existingBackdrop) existingBackdrop.remove();

    const modal = document.createElement('div');
    modal.className = 'payload-modal';

    const modalContent = document.createElement('div');
    modalContent.className = 'payload-modal-content';

    const closeBtn = document.createElement('span');
    closeBtn.className = 'close-modal';
    closeBtn.innerHTML = '&times;';

    const backdrop = document.createElement('div');
    backdrop.className = 'payload-modal-backdrop';

    const closeModal = () => {
        modal.remove();
        backdrop.remove();
    };
    closeBtn.onclick = closeModal;
    backdrop.onclick = closeModal;


    const heading = document.createElement('h4');


    const targetInfo = document.createElement('p');
    targetInfo.style.marginBottom = '15px';
    targetInfo.style.fontSize = '13px';
    targetInfo.style.color = '#aaa';


    const payloadPre = document.createElement('pre');
    payloadPre.className = 'report-code-block';
    payloadPre.style.maxHeight = '50vh';
    payloadPre.style.overflowY = 'auto';

    const payloadCode = document.createElement('code');


    const actualPayloadData = (payloadItem && payloadItem.payload !== undefined)
        ? payloadItem.payload
        : payloadItem;

    heading.textContent = `Payload Details (Type: ${escapeHTML(payloadItem?.type || 'unknown')})`;
    targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payloadItem?.targetPath || payloadItem?.targetFlow || payloadItem?.description || 'N/A')}`;

    let formattedPayload = '';
    try {
        if (typeof actualPayloadData === 'object' && actualPayloadData !== null) {
            formattedPayload = JSON.stringify(actualPayloadData, null, 2);
        } else {
            formattedPayload = String(actualPayloadData);
        }
    } catch (e) { formattedPayload = String(actualPayloadData); }
    payloadCode.textContent = formattedPayload;


    payloadPre.appendChild(payloadCode);

    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy Payload';
    copyBtn.className = 'control-button';
    copyBtn.style.marginTop = '15px';
    copyBtn.onclick = () => {
        navigator.clipboard.writeText(formattedPayload)
            .then(() => {
                copyBtn.textContent = 'Copied!';
                copyBtn.style.borderColor = 'var(--success-color)';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy Payload';
                    copyBtn.style.borderColor = '';
                }, 2000);
            })
            .catch(() => {
                copyBtn.textContent = 'Copy Failed';
                copyBtn.style.borderColor = 'var(--error-color)';
                setTimeout(() => { copyBtn.textContent = 'Copy Payload'; copyBtn.style.borderColor = '';}, 2000);
            });
    };

    modalContent.appendChild(closeBtn);
    modalContent.appendChild(heading);
    modalContent.appendChild(targetInfo);
    modalContent.appendChild(payloadPre);
    modalContent.appendChild(copyBtn);
    modal.appendChild(modalContent);

    document.body.appendChild(backdrop);
    document.body.appendChild(modal);
}

async function handleReportButton(endpoint) {
    const originalEndpoint = endpoint;
    const endpointKey = getStorageKeyForUrl(originalEndpoint);

    if (!endpointKey) {
        log.error('Could not determine key for report button:', originalEndpoint);
        alert('Internal error: Could not process endpoint URL for report.');
        return;
    }
    log.handler(`Report button clicked for key: ${endpointKey}`);

    try {
        const traceInfoKey = `trace-info-${endpointKey}`;
        const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
        const traceInfo = traceInfoResult[traceInfoKey];

        let endpointKeyForReport = endpointKey;
        let reportData = null;
        let reportPayloads = null;

        if (traceInfo) {
            if (traceInfo.analysisStorageKey) {
                endpointKeyForReport = traceInfo.analysisStorageKey;
                log.handler(`[Report] Using analysis storage key from trace info: ${endpointKeyForReport}`);

                [reportData, reportPayloads] = await Promise.all([
                    window.traceReportStorage.getTraceReport(endpointKeyForReport),
                    window.traceReportStorage.getReportPayloads(endpointKeyForReport)
                ]);
            }

            if (!reportData && traceInfo.analyzedUrl) {
                endpointKeyForReport = traceInfo.analyzedUrl;
                log.handler(`[Report] Using analyzed URL from trace info: ${endpointKeyForReport}`);

                [reportData, reportPayloads] = await Promise.all([
                    window.traceReportStorage.getTraceReport(endpointKeyForReport),
                    window.traceReportStorage.getReportPayloads(endpointKeyForReport)
                ]);

                if (!reportData) {
                    const analyzedUrlKey = getStorageKeyForUrl(traceInfo.analyzedUrl);
                    log.handler(`[Report] Trying with normalized analyzed URL key: ${analyzedUrlKey}`);

                    [reportData, reportPayloads] = await Promise.all([
                        window.traceReportStorage.getTraceReport(analyzedUrlKey),
                        window.traceReportStorage.getReportPayloads(analyzedUrlKey)
                    ]);

                    if (reportData) endpointKeyForReport = analyzedUrlKey;
                }
            }
        }

        if (!reportData) {
            log.handler(`[Report] No report from trace info. Trying original key: ${endpointKey}`);

            [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(endpointKey),
                window.traceReportStorage.getReportPayloads(endpointKey)
            ]);
        }

        if (!reportData) {
            log.handler(`[Report] No report with storage key. Trying with full URL: ${originalEndpoint}`);

            [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(originalEndpoint),
                window.traceReportStorage.getReportPayloads(originalEndpoint)
            ]);
        }

        if (!reportData) {
            throw new Error(`No report data found. Run Trace first.`);
        }

        if (typeof reportData !== 'object' || reportData === null) {
            throw new Error(`Invalid report data format retrieved`);
        }

        log.handler(`Retrieved report data. Payload count from separate storage: ${reportPayloads?.length || 0}`);

        if (!reportData.details) reportData.details = {};
        reportData.details.payloads = reportPayloads || [];
        if (!reportData.summary) reportData.summary = {};
        reportData.summary.payloadsGenerated = reportPayloads?.length || 0;

        const existingPanel = document.querySelector('.trace-results-panel');
        if (existingPanel) existingPanel.remove();
        const existingBackdrop = document.querySelector('.trace-panel-backdrop');
        if (existingBackdrop) existingBackdrop.remove();
        const tracePanel = document.createElement('div');
        tracePanel.className = 'trace-results-panel';
        const backdrop = document.createElement('div');
        backdrop.className = 'trace-panel-backdrop';
        backdrop.onclick = () => {
            try { if (tracePanel?.parentNode) tracePanel.remove(); } catch(e){}
            try { if (backdrop?.parentNode) backdrop.remove(); } catch(e){}
        };

        const reportContainer = document.getElementById('reportPanelContainer') || document.body;
        reportContainer.appendChild(backdrop);
        reportContainer.appendChild(tracePanel);
        displayReport(reportData, tracePanel);

    } catch (error) {
        log.error('Error retrieving or displaying report:', error?.message, error?.stack);
        alert(`Failed to retrieve or display report data: ${error?.message}`);
    }
}

async function checkAllEndpoints() {
    const endpointButtons = document.querySelectorAll('.iframe-row .iframe-check-button');
    for (const button of endpointButtons) {
        const endpointKey = button.getAttribute('data-endpoint');
        if (endpointKey && !button.classList.contains('green')) {
            try {
                await handlePlayButton(endpointKey, button);
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch (e) {
            }
        }
    }
}

async function populateInitialHandlerStates() {
    log.handler("Populating initial handler states from storage...");
    try {
        const allData = await chrome.storage.local.get(null);
        endpointsWithHandlers.clear();
        for (const key in allData) {
            if (key.startsWith('runtime-listeners-')) {
                const listeners = allData[key];
                if (Array.isArray(listeners) && listeners.length > 0) {
                    const endpointKey = key.substring('runtime-listeners-'.length);
                    endpointsWithHandlers.add(endpointKey);
                }
            }
        }
        log.handler(`Initial handler states populated. Count: ${endpointsWithHandlers.size}`);
    } catch (error) {
        log.error("Error populating initial handler states:", error);
    } finally {
        updateDashboardUI();
    }
}

function addTraceReportStyles() {
    const traceReportStyles = `
        .trace-results-panel { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.7); display: flex; justify-content: center; align-items: center; z-index: 1000; font-family: sans-serif; color: #d0d8e8; }
        .trace-panel-content { background: #1e1e1e; width: 80%; max-width: 1200px; height: 85%; max-height: 90vh; overflow: hidden; border-radius: 8px; display: flex; flex-direction: column; box-shadow: 0 5px 25px rgba(0,0,0,0.5); border: 1px solid #444; }
        .trace-panel-header { padding: 15px 20px; background: #2a2a2a; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #444; }
        .trace-panel-header h2 { margin: 0; font-size: 1.4em; color: #00e1ff; }
        .trace-panel-close { background: none; border: none; color: #ccc; font-size: 1.8em; cursor: pointer; line-height: 1; padding: 0 5px; }
        .trace-panel-close:hover { color: #fff; }
        .trace-results-content { padding: 25px; overflow-y: auto; flex-grow: 1; background: #1a1d21; }
        .report-section { margin-bottom: 30px; padding: 20px; background: #22252a; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; }
        .report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; }
        .report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; }
        .report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; }
        .security-score-container { display: flex; justify-content: center; }
        .security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); }
        .security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; }
        .security-score div { position: relative; z-index: 2; }
        .security-score-value { font-size: 28px; line-height: 1; }
        .security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; }
        .security-score.critical { border-color: #e74c3c; } .security-score.high { border-color: #e67e22; } .security-score.medium { border-color: #f39c12; } .security-score.low { border-color: #3498db; } .security-score.negligible { border-color: #2ecc71; }
        .summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; }
        .metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; }
        .metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; }
        .metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; }
        .recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; }
        .recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; }
        .report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; }
        .report-code-block pre { margin: 0; }
        .report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; }
        .report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; }
        details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; }
        summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; }
        summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); }
        details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; }
        .toggle-icon { font-size: 1.2em; transition: transform 0.2s; }
        details[open] .toggle-icon { transform: rotate(90deg); }
        .report-details > div { padding: 15px; }
        .report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; }
        .report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; }
        .report-table th { background-color: #2c313a; font-weight: bold; color: #fff; }
        .report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px;}
        .report-table .context-snippet { max-width: 400px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle; cursor: pointer; }
        .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .severity-critical { background-color: #e74c3c; color: white; } .severity-high { background-color: #e67e22; color: white; } .severity-medium { background-color: #f39c12; color: #333; } .severity-low { background-color: #3498db; color: white; }
        .severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); } .severity-row-high td { background-color: rgba(230, 126, 34, 0.15); } .severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); } .severity-row-low td { background-color: rgba(52, 152, 219, 0.1); }
        .no-findings-text { color: #777; font-style: italic; padding: 10px 0; }
        .dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; }
        .report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; }
        .payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; }
        .payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; }
        .payload-header strong { color: #fff; }
        .payload-meta { color: #8be9fd; margin: 0 5px; }
        .payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; }
        .structure-content { padding: 15px; }
        .structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; }
        .structure-content strong { color: #00e1ff; }
        .structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; }
        .show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; padding: 8px; cursor: pointer; border-radius: 4px; }
        .show-more-btn:hover { background-color: #4a5058; color: #fff; }
        .error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; }
    `;
    if (!document.getElementById('frogpost-report-styles')) {
        const styleElement = document.createElement('style');
        styleElement.id = 'frogpost-report-styles';
        styleElement.textContent = traceReportStyles;
        document.head.appendChild(styleElement);
    }
}

function addProgressStyles() {
    const progressStyles = `
        .trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; }
        .trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .phase-list { display: flex; flex-direction: column; gap: 10px; }
        .phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; }
        .phase .emoji { font-size: 20px; line-height: 1; }
        .phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; }
        .phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; }
        .phase.active .label { color: #fff; font-weight: 600; }
        .phase.active .emoji { animation: spin 1s linear infinite; }
        .phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; }
        .phase.completed .label { color: #50fa7b; }
        .phase.completed .emoji::before { content: '✅'; animation: none; }
        .phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; }
        .phase.error .label { color: #ff5555; font-weight: 600; }
        .phase.error .emoji::before { content: '❌'; animation: none; }
        .phase[data-phase="finished"], .phase[data-phase="error"] { display: none; }
        .phase[data-phase="finished"].completed, .phase[data-phase="error"].error { display: flex; }
        @keyframes pulse-border { 0% { border-color: #00e1ff; } 50% { border-color: rgba(0, 225, 255, 0.5); } 100% { border-color: #00e1ff; } }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    `;
    if (!document.getElementById('frogpost-progress-styles')) {
        const styleEl = document.createElement('style');
        styleEl.id = 'frogpost-progress-styles';
        styleEl.textContent = progressStyles;
        document.head.appendChild(styleEl);
    }
}


window.addEventListener('DOMContentLoaded', () => {
    const clearStoredMessages = () => {
        chrome.runtime.sendMessage({ type: "resetState" });
        localStorage.removeItem('interceptedMessages');
        messages.length = 0;
        window.frogPostState.frameConnections.clear();
        buttonStates.clear();
        reportButtonStates.clear();
        traceButtonStates.clear();
        activeEndpoint = null;
    };
    clearStoredMessages();

    const sidebarToggle = document.getElementById('sidebarToggle');
    const controlSidebar = document.getElementById('controlSidebar');

    if (sidebarToggle && controlSidebar) {
        if (!controlSidebar.classList.contains('open')) {
            sidebarToggle.classList.add('animate-toggle');
        }

        sidebarToggle.addEventListener('click', () => {
            controlSidebar.classList.toggle('open');
            if (controlSidebar.classList.contains('open')) {
                sidebarToggle.classList.remove('animate-toggle');
            } else {
                sidebarToggle.classList.add('animate-toggle');
            }
        });
    } else {
        log.error("Sidebar toggle or container not found.");
    }
    printBanner();
    setupUIControls();
    initializeMessageHandling();
    populateInitialHandlerStates();
    addTraceReportStyles();
    addProgressStyles()

    const filterInput = document.getElementById("endpointFilter");
    if (filterInput) {
        filterInput.addEventListener("input", (e) => {
            updateDashboardUI();
        });
    }
    startAutoRefresh();
    updateDashboardUI();

    try {
        chrome.storage.session.get('customXssPayloads', (result) => {
            const storedPayloads = result.customXssPayloads;

            if (!storedPayloads || !storedPayloads.length) {
                try {
                    const localStoragePayloads = localStorage.getItem('customXssPayloads');
                    if (localStoragePayloads) {
                        const parsedPayloads = JSON.parse(localStoragePayloads);
                        if (Array.isArray(parsedPayloads) && parsedPayloads.length > 0) {
                            chrome.storage.session.set({ customXssPayloads: parsedPayloads }, () => {
                                if (!chrome.runtime.lastError) {
                                    console.log(`[Init] Restored ${parsedPayloads.length} custom payloads from localStorage to session storage`);
                                    updatePayloadStatus(true, parsedPayloads.length);

                                    if (window.FuzzingPayloads) {
                                        if (!window.FuzzingPayloads._originalXSS) {
                                            window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS];
                                        }
                                        window.FuzzingPayloads.XSS = [...parsedPayloads];
                                    }
                                }
                            });
                        }
                    }
                } catch (e) {
                    console.warn("Error checking localStorage for custom payloads:", e);
                }
            } else if (storedPayloads && storedPayloads.length > 0) {
                console.log(`[Init] Found ${storedPayloads.length} custom payloads in session storage`);
                updatePayloadStatus(true, storedPayloads.length);

                if (window.FuzzingPayloads) {
                    if (!window.FuzzingPayloads._originalXSS) {
                        window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS];
                    }
                    window.FuzzingPayloads.XSS = [...storedPayloads];
                }
            }
        });
    } catch (e) {
        console.warn("Error initializing custom payloads:", e);
    }
});
