/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-10-22
 */

class SensitiveDataDetector {
    constructor() {
        this.patterns = this.initializePatterns();
        this.sanitizedReplacements = this.initializeSafeReplacements();
    }

    initializePatterns() {
        return {
            jwt: /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
            bearerToken: /Bearer\s+[A-Za-z0-9_\-\.]+/gi,
            apiKey: /(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|private[_-]?key)["\s:=]+[A-Za-z0-9_\-]{16,}/gi,
            sessionId: /(?:session[_-]?id|sessionid|jsessionid)["\s:=]+[A-Za-z0-9_\-]{8,}/gi,
            oauth: /(?:access_token|refresh_token)["\s:=]+[A-Za-z0-9_\-\.]{20,}/gi,
            authToken: /(?:auth[_-]?token|authentication[_-]?token)["\s:=]+[A-Za-z0-9_\-\.]{20,}/gi,
            csrfToken: /(?:csrf[_-]?token|xsrf[_-]?token)["\s:=]+[A-Za-z0-9_\-\.]{16,}/gi,
            apiSecret: /(?:api[_-]?secret|app[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{16,}/gi,
            clientSecret: /(?:client[_-]?secret|consumer[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{16,}/gi,
            webhookSecret: /(?:webhook[_-]?secret|hook[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{16,}/gi,
            
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            phone: /\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g,
            ssn: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
            passport: /(?:passport[_-]?number|passport[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            driverLicense: /(?:driver[_-]?license|dl[_-]?number)["\s:=]+[A-Za-z0-9]{6,}/gi,
            nationalId: /(?:national[_-]?id|citizen[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            taxId: /(?:tax[_-]?id|tin[_-]?number)["\s:=]+[A-Za-z0-9]{6,}/gi,
            address: /(?:street[_-]?address|home[_-]?address)["\s:=]+[A-Za-z0-9\s,.-]{10,}/gi,
            zipCode: /\b\d{5}(?:-\d{4})?\b/g,
            ipAddress: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
            
            creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
            iban: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/g,
            accountNumber: /(?:account[_-]?(?:number|num|id)|acct[_-]?(?:number|num|id))["\s:=]+[0-9]{6,}/gi,
            routingNumber: /(?:routing[_-]?number|aba[_-]?number)["\s:=]+[0-9]{9}/gi,
            swiftCode: /\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b/g,
            bitcoin: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
            ethereum: /\b0x[a-fA-F0-9]{40}\b/g,
            bankAccount: /(?:bank[_-]?account|checking[_-]?account)["\s:=]+[0-9]{6,}/gi,
            debitCard: /(?:debit[_-]?card|atm[_-]?card)["\s:=]+[0-9]{13,19}/gi,
            pin: /(?:pin[_-]?number|personal[_-]?identification)["\s:=]+[0-9]{4,8}/gi,
            
            privateKey: /-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----/gi,
            certificate: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gi,
            connectionString: /(?:mongodb|mysql|postgres|oracle|mssql):\/\/[^\s"']+/gi,
            password: /(?:password|passwd|pwd)["\s:=]+[^\s"',}]{6,}/gi,
            databaseUrl: /(?:database[_-]?url|db[_-]?url)["\s:=]+[^\s"',}]{10,}/gi,
            redisUrl: /redis:\/\/[^\s"']+/gi,
            elasticsearchUrl: /elasticsearch:\/\/[^\s"']+/gi,
            rabbitmqUrl: /amqp:\/\/[^\s"']+/gi,
            kafkaUrl: /kafka:\/\/[^\s"']+/gi,
            dockerSecret: /(?:docker[_-]?secret|container[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{16,}/gi,
            
            awsKey: /(?:AKIA|ASIA|AROA)[A-Z0-9]{16}/g,
            azureKey: /[A-Za-z0-9/+]{88}==/g,
            gcpKey: /AIza[A-Za-z0-9_\-]{35}/g,
            awsSecret: /(?:aws[_-]?secret|amazon[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{20,}/gi,
            azureSecret: /(?:azure[_-]?secret|microsoft[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{20,}/gi,
            gcpSecret: /(?:gcp[_-]?secret|google[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{20,}/gi,
            slackToken: /xox[baprs]-[A-Za-z0-9-]+/g,
            discordToken: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
            githubToken: /ghp_[A-Za-z0-9]{36}/g,
            stripeKey: /(?:sk_|pk_)[A-Za-z0-9]{24,}/g,
            
            uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
            mongoId: /\b[0-9a-f]{24}\b/g,
            redisKey: /(?:redis[_-]?key|cache[_-]?key)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            elasticsearchId: /(?:elasticsearch[_-]?id|es[_-]?id)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            kafkaKey: /(?:kafka[_-]?key|message[_-]?key)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            rabbitmqKey: /(?:rabbitmq[_-]?key|queue[_-]?key)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            dockerId: /(?:docker[_-]?id|container[_-]?id)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            kubernetesSecret: /(?:k8s[_-]?secret|kubernetes[_-]?secret)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            terraformKey: /(?:terraform[_-]?key|tf[_-]?key)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            ansibleKey: /(?:ansible[_-]?key|playbook[_-]?key)["\s:=]+[A-Za-z0-9_\-\.]{6,}/gi,
            
            medicalId: /(?:patient[_-]?id|medical[_-]?record)["\s:=]+[A-Za-z0-9]{6,}/gi,
            healthRecord: /(?:health[_-]?record|medical[_-]?history)["\s:=]+[A-Za-z0-9]{6,}/gi,
            insuranceId: /(?:insurance[_-]?id|policy[_-]?number)["\s:=]+[A-Za-z0-9]{6,}/gi,
            prescriptionId: /(?:prescription[_-]?id|rx[_-]?number)["\s:=]+[A-Za-z0-9]{6,}/gi,
            labResult: /(?:lab[_-]?result|test[_-]?result)["\s:=]+[A-Za-z0-9]{6,}/gi,
            diagnosisCode: /(?:diagnosis[_-]?code|icd[_-]?code)["\s:=]+[A-Za-z0-9]{6,}/gi,
            treatmentId: /(?:treatment[_-]?id|therapy[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            appointmentId: /(?:appointment[_-]?id|visit[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            doctorId: /(?:doctor[_-]?id|physician[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            hospitalId: /(?:hospital[_-]?id|facility[_-]?id)["\s:=]+[A-Za-z0-9]{6,}/gi,
            
            custom: []
        };
    }

    initializeSafeReplacements() {
        return {
            jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciIsImFkbWluIjpmYWxzZX0.DEMO_SIGNATURE',
            bearerToken: 'Bearer demo_token_12345',
            apiKey: 'demo_api_key_abcd1234',
            sessionId: 'demo_session_xyz789',
            oauth: 'demo_oauth_token_456',
            email: 'user@example.com',
            phone: '+1-555-0123',
            ssn: '555-00-0000',
            creditCard: '4111111111111111',
            iban: 'GB82WEST12345698765432',
            accountNumber: '123456789',
            privateKey: '-----BEGIN PRIVATE KEY-----\nDEMO_PRIVATE_KEY_CONTENT\n-----END PRIVATE KEY-----',
            certificate: '-----BEGIN CERTIFICATE-----\nDEMO_CERTIFICATE_CONTENT\n-----END CERTIFICATE-----',
            connectionString: 'mongodb://demo:password@demo.example.com:27017/demo',
            password: 'demo_password',
            uuid: '12345678-1234-1234-1234-123456789abc',
            mongoId: '507f1f77bcf86cd799439011',
            medicalId: 'DEMO_MED_123',
            awsKey: 'AKIAIOSFODNN7EXAMPLE',
            azureKey: 'DEMO_AZURE_KEY_CONTENT_BASE64_ENCODED=' + '='.repeat(87),
            gcpKey: 'AIzaSyDemoGoogleCloudPlatformAPIKey123'
        };
    }

    detectSensitiveData(data) {
        const results = {
            hasSensitiveData: false,
            sensitiveFields: [],
            detectedTypes: new Set(),
            riskLevel: 'LOW',
            summary: ''
        };

        const dataString = this.convertToString(data);
        
        for (const [type, pattern] of Object.entries(this.patterns)) {
            if (type === 'custom') continue;
            
            if (Array.isArray(pattern)) {
                pattern.forEach(p => this.scanPattern(dataString, type, p, results));
            } else {
                this.scanPattern(dataString, type, pattern, results);
            }
        }

        results.riskLevel = this.calculateRiskLevel(results.detectedTypes);
        results.summary = this.generateSummary(results);
        
        return results;
    }

    sanitizeData(data) {
        if (!data) return data;
        
        let sanitized = this.deepClone(data);
        let sanitizedString = this.convertToString(sanitized);
        let wasModified = false;

        for (const [type, pattern] of Object.entries(this.patterns)) {
            if (type === 'custom' || !pattern) continue;
            
            const replacement = this.sanitizedReplacements[type];
            if (replacement && pattern.test && pattern.test(sanitizedString)) {
                sanitizedString = sanitizedString.replace(pattern, replacement);
                wasModified = true;
            }
        }

        if (wasModified) {
            try {
                if (typeof sanitized === 'string') {
                    return sanitizedString;
                } else if (typeof sanitized === 'object') {
                    return this.reconstructObject(sanitized, sanitizedString);
                }
            } catch (e) {
                console.warn('[Sensitive Data] Sanitization reconstruction failed:', e);
            }
        }

        return sanitized;
    }

    analyzeLLMSafety(messages) {
        const analysis = {
            totalMessages: messages.length,
            totalSize: 0,
            sensitiveMsgCount: 0,
            riskLevel: 'LOW',
            recommendations: [],
            sanitizedMessages: [],
            costEstimate: 0
        };

        messages.forEach((msg, index) => {
            const msgString = JSON.stringify(msg);
            analysis.totalSize += msgString.length;
            
            const detection = this.detectSensitiveData(msg);
            console.log(`🔍 [Sensitive Data] Message ${index + 1}:`, {
                hasSensitiveData: detection.hasSensitiveData,
                detectedTypes: detection.detectedTypes,
                detectedData: detection.detectedData?.length || 0,
                riskLevel: detection.riskLevel
            });
            
            if (detection.hasSensitiveData) {
                analysis.sensitiveMsgCount++;
                analysis.riskLevel = this.getMaxRisk(analysis.riskLevel, detection.riskLevel);
                console.log(`🔍 [Sensitive Data] Message ${index + 1} marked as sensitive`);
            }

            const sanitizedMsg = this.sanitizeData(msg);
            analysis.sanitizedMessages.push({
                original: msg,
                sanitized: sanitizedMsg,
                detection: detection,
                index: index
            });
        });

        analysis.recommendations = this.generateRecommendations(analysis);
        analysis.costEstimate = this.estimateLLMCost(analysis.totalSize);

        return analysis;
    }

    convertToString(data) {
        if (typeof data === 'string') return data;
        try { return JSON.stringify(data, null, 2); } catch { return String(data); }
    }

    scanPattern(dataString, type, pattern, results) {
        if (pattern.test && pattern.test(dataString)) {
            results.hasSensitiveData = true;
            results.detectedTypes.add(type);
            const matches = dataString.match(pattern);
            results.sensitiveFields.push({
                type: type,
                matches: matches ? matches.length : 1,
                samples: matches ? matches.slice(0, 2) : []
            });
        }
    }

    calculateRiskLevel(detectedTypes) {
        const highRiskTypes = ['privateKey', 'password', 'apiKey', 'connectionString'];
        const mediumRiskTypes = ['creditCard', 'ssn', 'oauth', 'awsKey', 'azureKey', 'gcpKey'];
        const lowRiskTypes = ['email', 'phone', 'uuid'];

        for (const type of detectedTypes) {
            if (highRiskTypes.includes(type)) return 'CRITICAL';
        }
        for (const type of detectedTypes) {
            if (mediumRiskTypes.includes(type)) return 'HIGH';
        }
        for (const type of detectedTypes) {
            if (mediumRiskTypes.includes(type) || lowRiskTypes.includes(type)) return 'MEDIUM';
        }
        return 'LOW';
    }

    generateSummary(results) {
        if (!results.hasSensitiveData) return 'No sensitive data detected';
        const types = Array.from(results.detectedTypes);
        const count = results.sensitiveFields.reduce((sum, field) => sum + field.matches, 0);
        return `Found ${count} sensitive items: ${types.join(', ')}`;
    }

    generateRecommendations(analysis) {
        const recs = [];
        if (analysis.sensitiveMsgCount > 0) {
            recs.push(`⚠️ ${analysis.sensitiveMsgCount}/${analysis.totalMessages} messages contain sensitive data`);
            recs.push('🛡️ All sensitive data will be sanitized before sending to LLM');
        }
        if (analysis.totalSize > 50000) {
            recs.push('💰 Large payload detected - consider reducing message count to save API costs');
        }
        if (analysis.riskLevel === 'CRITICAL') {
            recs.push('🚨 CRITICAL: Private keys or credentials detected - review before analysis');
        }
        return recs;
    }

    estimateLLMCost(sizeInBytes) {
        const tokens = Math.ceil(sizeInBytes / 4);
        const costPer1KTokens = 0.002;
        return (tokens / 1000) * costPer1KTokens;
    }

    getMaxRisk(risk1, risk2) {
        const levels = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
        return levels[risk1] > levels[risk2] ? risk1 : risk2;
    }

    deepClone(obj) {
        if (typeof obj !== 'object' || obj === null) return obj;
        if (typeof structuredClone === 'function') return structuredClone(obj);
        return JSON.parse(JSON.stringify(obj));
    }

    reconstructObject(original, sanitizedString) {
        try { return JSON.parse(sanitizedString); } catch { return sanitizedString; }
    }
}
class LLMCostProtector {
    constructor() {
        this.limits = this.initializeLimits();
        this.rateLimiter = new Map();
    }

    initializeLimits() {
        return {
            maxMessagesPerAnalysis: 10,
            maxMessageSizeBytes: 2048,
            maxTotalPayloadBytes: 20480,
            maxCallsPerMinute: 5,
            maxCallsPerHour: 30,
            maxHandlerCodeLength: 5000,
            costWarningThreshold: 0.10,
            PRICES_PER_1K: {
                openai: {
                    "gpt-4o": { in: 0.0025, out: 0.0100, cachedIn: 0.00125 },
                    "gpt-4o-mini": { in: 0.0006, out: 0.0024, cachedIn: 0.0003 },
                    "gpt-4-turbo": { in: 0.0100, out: 0.0300 },
                    "gpt-3.5-turbo": { in: 0.0005, out: 0.0015 },
                    "o1-mini": { in: 0.0030, out: 0.0150 },
                    "o1-preview": { in: 0.0150, out: 0.0600 }
                },
                anthropic: {
                    "claude-3-5-sonnet-20241022": { in: 0.0030, out: 0.0150 },
                    "claude-3-5-haiku-20241022": { in: 0.0008, out: 0.0040 },
                    "claude-3-haiku-20240307": { in: 0.00025, out: 0.00125 },
                    "claude-3-opus-20240229": { in: 0.0150, out: 0.0750 }
                },
                groq: {
                    "llama-3.1-70b-versatile": { in: 0.00059, out: 0.00079 },
                    "llama-3.1-8b-instant": { in: 0.00005, out: 0.00008 },
                    "mixtral-8x7b-32768": { in: 0.00027, out: 0.00027 },
                    "gemma-7b-it": { in: 0.00007, out: 0.00007 }
                },
                mistral: {
                    "mistral-large-latest": { in: 0.0020, out: 0.0060 },
                    "mistral-medium-latest": { in: 0.0004, out: 0.0020 },
                    "open-mixtral-8x7b": { in: 0.0007, out: 0.0007 },
                    "mistral-small-latest": { in: 0.0002, out: 0.0006 }
                }
            },
            providerLimits: {
                'openai': { maxTokens: 4000, costPerToken: 0.00005 },
                'anthropic': { maxTokens: 4000, costPerToken: 0.00008 },
                'groq': { maxTokens: 8000, costPerToken: 0.00001 },
                'mistral': { maxTokens: 4000, costPerToken: 0.00006 }
            }
        };
    }

    analyzeRequest(analysisRequest, provider = 'openai') {
        const analysis = {
            approved: false,
            warnings: [],
            modifications: [],
            costEstimate: 0,
            tokenEstimate: 0,
            originalSize: 0,
            optimizedSize: 0,
            rateLimitStatus: this.checkRateLimit(),
            optimizedRequest: null
        };

        analysis.originalSize = this.calculatePayloadSize(analysisRequest);
        
        if (!analysis.rateLimitStatus.allowed) {
            analysis.warnings.push(`🚫 Rate limit exceeded: ${analysis.rateLimitStatus.message}`);
            return analysis;
        }

        const optimizedRequest = this.optimizeRequest(analysisRequest);
        analysis.optimizedRequest = optimizedRequest;
        analysis.optimizedSize = this.calculatePayloadSize(optimizedRequest);

        const model = analysisRequest.model || this.getDefaultModel(provider);
        
        const inputTokenEstimate = this.estimateTokens(optimizedRequest, provider, model);
        
        const expectedOutputTokens = this.estimateExpectedOutputTokens(analysisRequest);
        
        analysis.tokenEstimate = inputTokenEstimate;
        analysis.expectedOutputTokens = expectedOutputTokens;
        analysis.totalTokenEstimate = inputTokenEstimate + expectedOutputTokens;
        
        const costBreakdown = this.calculateCost(provider, model, inputTokenEstimate, expectedOutputTokens);
        analysis.costEstimate = costBreakdown.total || 0;
        analysis.costBreakdown = costBreakdown;
        

        if (analysis.costEstimate > this.limits.costWarningThreshold) {
            analysis.warnings.push(`💰 High cost estimate: ~$${analysis.costEstimate.toFixed(4)} USD`);
        }

        if (analysis.optimizedSize < analysis.originalSize) {
            const reduction = ((analysis.originalSize - analysis.optimizedSize) / analysis.originalSize * 100).toFixed(1);
            analysis.modifications.push(`🗜️ Payload optimized: ${reduction}% size reduction`);
        }

        analysis.approved = this.shouldApproveRequest(analysis);
        return analysis;
    }

    optimizeRequest(request) {
        const optimized = JSON.parse(JSON.stringify(request));

        if (optimized.observedMessages && optimized.observedMessages.length > this.limits.maxMessagesPerAnalysis) {
            optimized.observedMessages = this.selectBestMessages(
                optimized.observedMessages, 
                this.limits.maxMessagesPerAnalysis
            );
        }

        if (optimized.observedMessages) {
            optimized.observedMessages = optimized.observedMessages.map(msg => {
                return this.truncateMessage(msg, this.limits.maxMessageSizeBytes);
            });
        }

        if (optimized.handlerCode && optimized.handlerCode.length > this.limits.maxHandlerCodeLength) {
            optimized.handlerCode = this.truncateCode(optimized.handlerCode, this.limits.maxHandlerCodeLength);
        }

        optimized.timestamp = undefined;
        optimized.debugInfo = undefined;

        return optimized;
    }

    selectBestMessages(messages, maxCount) {
        if (messages.length <= maxCount) return messages;
        const selected = [];
        const uniqueStructures = new Set();

        for (const msg of messages) {
            if (selected.length >= maxCount) break;
            const structure = this.getMessageStructure(msg);
            if (!uniqueStructures.has(structure)) {
                selected.push(msg);
                uniqueStructures.add(structure);
            }
        }

        if (selected.length < maxCount) {
            const remaining = messages
                .filter(msg => !selected.includes(msg))
                .slice(-Math.max(0, maxCount - selected.length));
            selected.push(...remaining);
        }

        return selected.slice(0, maxCount);
    }

    truncateMessage(message, maxBytes) {
        const msgString = JSON.stringify(message);
        if (msgString.length <= maxBytes) return message;

        try {
            if (typeof message === 'object' && message !== null) {
                const truncated = { ...message };
                if (truncated.data && typeof truncated.data === 'string' && truncated.data.length > maxBytes / 2) {
                    const maxDataLength = Math.floor(maxBytes / 2);
                    truncated.data = truncated.data.substring(0, maxDataLength) + '...[TRUNCATED]';
                }
                if (JSON.stringify(truncated).length > maxBytes) {
                    return { ...truncated, data: '[LARGE_DATA_TRUNCATED]', _truncated: true };
                }
                return truncated;
            }
        } catch (e) {
            console.warn('[Cost Protector] Message truncation failed:', e);
        }

        return msgString.substring(0, maxBytes) + '...[TRUNCATED]';
    }

    truncateCode(code, maxLength) {
        if (code.length <= maxLength) return code;
        const cutPoint = Math.floor(maxLength * 0.8);
        const logicalCuts = [
            code.lastIndexOf('}', cutPoint),
            code.lastIndexOf(';', cutPoint),
            code.lastIndexOf('\n', cutPoint)
        ].filter(pos => pos > cutPoint / 2);

        const bestCut = Math.max(...logicalCuts, cutPoint);
        return code.substring(0, bestCut) + '\n\n/* [CODE_TRUNCATED_FOR_COST_PROTECTION] */';
    }

    checkRateLimit() {
        const now = Date.now();
        const minuteAgo = now - 60000;
        const hourAgo = now - 3600000;

        for (const [timestamp] of this.rateLimiter) {
            if (timestamp < hourAgo) {
                this.rateLimiter.delete(timestamp);
            }
        }

        const callsInLastMinute = Array.from(this.rateLimiter.keys())
            .filter(timestamp => timestamp > minuteAgo).length;
        const callsInLastHour = this.rateLimiter.size;

        if (callsInLastMinute >= this.limits.maxCallsPerMinute) {
            return { allowed: false, message: `Max ${this.limits.maxCallsPerMinute} calls per minute exceeded` };
        }

        if (callsInLastHour >= this.limits.maxCallsPerHour) {
            return { allowed: false, message: `Max ${this.limits.maxCallsPerHour} calls per hour exceeded` };
        }

        return { allowed: true, message: 'Within rate limits' };
    }

    recordAPICall() {
        this.rateLimiter.set(Date.now(), true);
    }

    calculatePayloadSize(payload) {
        try {
            return new TextEncoder().encode(JSON.stringify(payload)).length;
        } catch {
            return JSON.stringify(payload).length;
        }
    }

    estimateTokens(payload, provider = 'openai', model = 'gpt-4o') {
        try {
            const text = JSON.stringify(payload);
            
            if (provider === 'openai') {
                return this.estimateOpenAITokens(text, model);
            } else if (provider === 'anthropic') {
                return this.estimateAnthropicTokens(text);
            } else if (provider === 'groq') {
                return this.estimateGroqTokens(text, model);
            } else if (provider === 'mistral') {
                return this.estimateMistralTokens(text);
            }
            
            return this.estimateTokensHeuristic(text);
        } catch (error) {
            console.warn('Token estimation failed, using fallback:', error);
            return this.estimateTokensHeuristic(JSON.stringify(payload));
        }
    }

    estimateOpenAITokens(text, model) {
        const ratios = {
            'gpt-4o': 3.2,
            'gpt-4o-mini': 3.2,
            'gpt-4-turbo': 3.5,
            'gpt-3.5-turbo': 3.8,
            'o1-mini': 3.2,
            'o1-preview': 3.2
        };
        
        const ratio = ratios[model] || 3.5;
        return Math.ceil(text.length / ratio);
    }

    estimateAnthropicTokens(text) {
        return Math.ceil(text.length / 3.0);
    }

    estimateGroqTokens(text, model) {
        const ratios = {
            'llama-3.1-70b-versatile': 3.1,
            'llama-3.1-8b-instant': 3.1,
            'mixtral-8x7b-32768': 3.2,
            'gemma-7b-it': 3.3
        };
        
        const ratio = ratios[model] || 3.2;
        return Math.ceil(text.length / ratio);
    }

    estimateMistralTokens(text) {
        return Math.ceil(text.length / 3.1);
    }

    estimateTokensHeuristic(text) {
        let tokenCount = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (char === ' ' || char === '\n' || char === '\t') {
                tokenCount += 0.25;
            } else if (/[a-zA-Z0-9]/.test(char)) {
                tokenCount += 0.3;
            } else {
                tokenCount += 1;
            }
        }
        return Math.ceil(tokenCount);
    }

    calculateCost(provider, model, inputTokens, outputTokens = 0, cachedInputTokens = 0, useBatch = false) {
        const prices = this.limits.PRICES_PER_1K[provider.toLowerCase()];
        if (!prices || !prices[model]) {
            const legacyInfo = this.limits.providerLimits[provider.toLowerCase()] || this.limits.providerLimits.openai;
            const totalTokens = inputTokens + outputTokens;
            const legacyCost = totalTokens * legacyInfo.costPerToken;
            console.warn('⚠️ [Cost Calculation] Using legacy pricing fallback:', { provider, model, totalTokens, legacyCost });
            return {
                inputCost: legacyCost * 0.7,
                cachedCost: 0,
                outputCost: legacyCost * 0.3,
                total: legacyCost,
                breakdown: {
                    inputTokens: inputTokens,
                    cachedInputTokens: 0,
                    outputTokens: outputTokens,
                    inputRate: legacyInfo.costPerToken,
                    cachedRate: 0,
                    outputRate: legacyInfo.costPerToken,
                    batchDiscount: 1.0
                }
            };
        }

        const modelPricing = prices[model];
        const inRate = modelPricing.in / 1000;
        const outRate = modelPricing.out / 1000;
        const cachedRate = (modelPricing.cachedIn || modelPricing.in * 0.5) / 1000;

        let inputCost = (inputTokens - cachedInputTokens) * inRate;
        let cachedCost = cachedInputTokens * cachedRate;
        let outputCost = outputTokens * outRate;
        let total = inputCost + cachedCost + outputCost;

        if (useBatch && (provider === 'anthropic' || provider === 'openai')) {
            total *= 0.5;
        }

        return {
            inputCost,
            cachedCost,
            outputCost,
            total,
            breakdown: {
                inputTokens: inputTokens - cachedInputTokens,
                cachedInputTokens,
                outputTokens,
                inputRate: inRate,
                cachedRate,
                outputRate: outRate,
                batchDiscount: useBatch ? 0.5 : 1.0
            }
        };
    }

    getDefaultModel(provider) {
        const defaults = {
            'openai': 'gpt-4o-mini',
            'anthropic': 'claude-3-5-haiku-20241022',
            'groq': 'llama-3.1-8b-instant',
            'mistral': 'mistral-small-latest'
        };
        return defaults[provider.toLowerCase()] || 'gpt-4o-mini';
    }

    estimateExpectedOutputTokens(analysisRequest) {
        let baseTokens = 200;
        
        const handlerLength = analysisRequest.handlerCode?.length || 0;
        if (handlerLength > 1000) baseTokens += 300;
        else if (handlerLength > 500) baseTokens += 200;
        else if (handlerLength > 100) baseTokens += 100;
        
        const messageCount = analysisRequest.observedMessages?.length || 0;
        baseTokens += messageCount * 50;
        
        const currentPayloads = analysisRequest.currentPayloads?.length || 0;
        baseTokens += Math.min(currentPayloads * 20, 200);
        
        return Math.min(baseTokens, 1500);
    }

    getMessageStructure(message) {
        if (typeof message !== 'object' || message === null) {
            return typeof message;
        }
        const keys = Object.keys(message).sort();
        return keys.join('|');
    }

    shouldApproveRequest(analysis) {
        if (!analysis.rateLimitStatus.allowed) return false;
        if (analysis.costEstimate > 1.0) return false;
        return true;
    }

    calculateActualCost(provider, model, usage) {
        const promptTokens = usage.prompt_tokens || 0;
        const completionTokens = usage.completion_tokens || 0;
        
        return this.calculateCost(provider, model, promptTokens, completionTokens);
    }

    generateReport(analysis) {
        const breakdown = analysis.costBreakdown || {};
        return {
            status: analysis.approved ? '✅ APPROVED' : '❌ BLOCKED',
            estimatedCost: `$${analysis.costEstimate.toFixed(4)} USD`,
            costBreakdown: {
                input: `$${breakdown.inputCost?.toFixed(4) || '0.0000'}`,
                output: `$${breakdown.outputCost?.toFixed(4) || '0.0000'}`,
                cached: breakdown.cachedCost > 0 ? `$${breakdown.cachedCost.toFixed(4)}` : null,
                total: `$${analysis.costEstimate.toFixed(4)}`
            },
            tokenBreakdown: {
                input: analysis.tokenEstimate || 0,
                output: analysis.expectedOutputTokens || 0,
                total: analysis.totalTokenEstimate || 0
            },
            payloadReduction: analysis.originalSize > 0 ? 
                `${((analysis.originalSize - analysis.optimizedSize) / analysis.originalSize * 100).toFixed(1)}%` : '0%',
            warnings: analysis.warnings,
            modifications: analysis.modifications,
            rateLimitInfo: `${this.rateLimiter.size}/${this.limits.maxCallsPerHour} calls this hour`
        };
    }
}


window.frogPostState = {
    frameConnections: new Map(),
    messages: [],
    activeUrl: null,
    loadedData: { urls: new Set() },
    callbackUrl: null
};

let debugMode = false;

const log = {
    styles: { info: 'color: #0066cc; font-weight: bold', success: 'color: #00cc66; font-weight: bold', warning: 'color: #ff9900; font-weight: bold', error: 'color: #cc0000; font-weight: bold', handler: 'color: #6600cc; font-weight: bold', scan: 'color: #FFDC77; font-weight: bold', debug: 'color: #999999; font-style: italic' },
    _log: (style, icon, msg, details) => { console.log(`%c ${icon} ${msg}`, style); if (details && (debugMode || typeof details === 'string' || style === log.styles.error)) { const detailStyle = style === log.styles.error ? 'color: #cc0000;' : 'color: #666666;'; if (details instanceof Error) { console.error('%c    ' + details.message, detailStyle); if (details.stack && debugMode) console.error('%c    Stack Trace:', detailStyle, details.stack); } else if (typeof details === 'object' && debugMode) console.log('%c    Details:', detailStyle, details); else console.log('%c    ' + String(details), detailStyle); } },
    info: (msg, details) => log._log(log.styles.info, 'ℹ️', msg, details), success: (msg, details) => log._log(log.styles.success, '✅', msg, details), warning: (msg, details) => log._log(log.styles.warning, '⚠️', msg, details), warn: (msg, details) => log.warning(msg, details), error: (msg, details) => log._log(log.styles.error, '❌', msg, details), handler: (msg, details) => log._log(log.styles.handler, '🔍', msg, details), scan: (msg, details) => log._log(log.styles.scan, '🔄', msg, details),
    debug: (msg, ...args) => { if (debugMode) console.log('%c 🔧 ' + msg, log.styles.debug, ...args); }
};
window.log = log;
let currentVersion = 'N/A';
const endpointsWithDetectedHandlers = new Set();
const knownHandlerEndpoints = new Set();
const endpointsWithHandlers = new Set();
const buttonStates = new Map();
const reportButtonStates = new Map();
const traceButtonStates = new Map();
const CALLBACK_URL_STORAGE_KEY = 'callback_url';
const launchInProgressEndpoints = new Set();
let uiUpdateTimer = null;
const DEBOUNCE_DELAY = 150;
let debuggerApiModeEnabled = false;
const DEBUGGER_MODE_STORAGE_KEY = 'debuggerApiModeEnabled';
const HANDLER_CONFIDENCE_THRESHOLD = 100;

function printBanner() {
    console.log(`%c
  _____                ____           _
 |  ___| __ ___   __ _|  _ \\ ___  ___| |_
 | |_ | '__/ _ \\ / _\` | |_) / _ \\/ __| __|
 |  _|| | | (_) | (_| |  __/ (_) \\__ \\ |_
 |_|  |_|  \\___/ \\__, |_|   \\___/|___/\\__|
                 |___/
`, 'color: #4dd051; font-weight: bold;');
    log.info('Initializing dashboard...');
    console.log('%c💡 Helper Functions:', 'color: #4dd051; font-weight: bold;');
    console.log('%c  • clearFailedEndpoint(endpointKey) - Retry a previously failed endpoint', 'color: #999;');
    console.log('%c  • clearAllFailedEndpoints() - Clear all failed endpoint cache', 'color: #999;');
}

function displayCurrentVersion() {
    const versionDisplay = document.getElementById('current-version-display');
    try {
        currentVersion = chrome.runtime.getManifest().version;
        if (versionDisplay) {
            versionDisplay.textContent = currentVersion;
        } else {
            log.error("Version display element not found");
        }
    } catch (e) {
        log.error("Failed to get manifest version", e);
        if (versionDisplay) {
            versionDisplay.textContent = 'Error';
        }
    }
}

async function checkLatestVersion() {
    const checkButton = document.getElementById('check-version-button');
    const statusDisplay = document.getElementById('update-status-display');
    if (!checkButton || !statusDisplay) return;

    checkButton.disabled = true;
    checkButton.textContent = 'Checking...';
    statusDisplay.textContent = '';
    statusDisplay.style.color = '';

    log.info('Checking for latest version via background script...');

    try {
        const releaseInfo = await new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({ type: "checkVersion" }, (response) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message || "Communication error"));
                } else if (response?.success) {
                    resolve(response);
                } else {
                    reject(new Error(response?.error || "Background script returned failure"));
                }
            });
        });

        if (!releaseInfo || !releaseInfo.tagName) {
            throw new Error("Could not get valid release tag name from background script.");
        }

        const tagMatch = releaseInfo.tagName.match(/v?([\d.]+)/);
        if (!tagMatch || !tagMatch[1]) {
            throw new Error(`Could not parse version number from tag: ${releaseInfo.tagName}`);
        }
        const latestVersionTag = tagMatch[1];

        const currentVersionNorm = currentVersion.toLowerCase().replace('v', '');

        log.info(`Current version: ${currentVersionNorm}, Latest tag found on GitHub: ${latestVersionTag}`);

        const currentParts = currentVersionNorm.split('.').map(Number);
        const latestParts = latestVersionTag.split('.').map(Number);
        let updateAvailable = false;

        for (let i = 0; i < Math.max(currentParts.length, latestParts.length); i++) {
            const currentPart = currentParts[i] || 0;
            const latestPart = latestParts[i] || 0;
            if (latestPart > currentPart) { updateAvailable = true; break; }
            if (latestPart < currentPart) { break; }
        }

        if (updateAvailable) {
            statusDisplay.innerHTML = `Update available: <a href="${releaseInfo.url || '#'}" target="_blank" title="Go to release page">v${latestVersionTag}</a>`;
            statusDisplay.style.color = 'var(--success-color)';
            showToastNotification(`Newer FrogPost version found: v${latestVersionTag}`, 'success');
        } else {
            statusDisplay.textContent = 'Up to date';
            statusDisplay.style.color = 'var(--text-secondary)';
            showToastNotification('FrogPost is up to date.', 'info');
        }

    } catch (error) {
        log.error("Version check failed:", error);
        statusDisplay.textContent = 'Check failed';
        statusDisplay.style.color = 'var(--error-color)';
        showToastNotification(`Version check failed: ${error.message}`, 'error');
    } finally {
        checkButton.disabled = false;
        checkButton.textContent = 'Check Version';
    }
}

function updateDebuggerModeButton() {
    const btn = document.getElementById('toggleDebuggerApiMode');
    if (btn) {
        btn.textContent = `Debugger Mode: ${debuggerApiModeEnabled ? 'ON' : 'OFF'}`;
        btn.classList.toggle('debugger-mode-on', debuggerApiModeEnabled);
        btn.classList.toggle('debugger-mode-off', !debuggerApiModeEnabled);
        btn.classList.toggle('secondary', !debuggerApiModeEnabled);
        btn.title = debuggerApiModeEnabled
            ? "Debugger is currently attaching to web pages on load. Click to disable."
            : "Attach debugger to web pages on load to find handlers (EXPERIMENTAL). Click to enable.";
    }
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

function sanitizeString(str) {
    if (typeof str !== 'string') return str;
    const xssPatterns = [ /<\s*script/i, /<\s*img[^>]+onerror/i, /javascript\s*:/i, /on\w+\s*=/i, /<\s*iframe/i, /<\s*svg[^>]+on\w+/i, /Function\s*\(/i, /setTimeout\s*\(/i, /setInterval\s*\(/i, /document\.domain/i, /document\.location/i, /location\.href/i ];
    let containsXss = false;
    for (const pattern of xssPatterns) { if (pattern.test(str)) { containsXss = true; break; } }
    if (containsXss) { let sanitized = str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); return `[SANITIZED PAYLOAD] ${sanitized}`; }
    return str;
}

function isLocalDevUrl(urlString) {
    if (!urlString) return false;
    try {
        const u = new URL(urlString);
        return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    } catch {
        return false;
    }
}

function isEndpointAlreadyScanned(endpoint) {
    if (!endpoint) return false;
    const key = getStorageKeyForUrl(endpoint);
    return window.endpointsWithDetectedHandlers?.has(key);
}
window.isEndpointAlreadyScanned = isEndpointAlreadyScanned;

function getBaseUrl(url) {
    try { const norm = normalizeEndpointUrl(url); return norm?.components ? norm.components.origin + norm.components.path : null; }
    catch (e) { log.handler(`[Get Base URL] Error getting base URL for: ${url}`, e.message); return null; }
}
window.getBaseUrl = getBaseUrl;

function sanitizeMessageData(data) {
    if (!data) return data;
    if (typeof data === 'string') { try { const parsed = JSON.parse(data); return sanitizeMessageData(parsed); } catch (e) { return sanitizeString(data); } }
    if (Array.isArray(data)) { return data.map(item => sanitizeMessageData(item)); }
    if (typeof data === 'object') { const sanitized = {}; for (const [key, value] of Object.entries(data)) sanitized[key] = sanitizeMessageData(value); return sanitized; }
    return data;
}

function isValidUrl(url) {
    try { new URL(url); return true; } catch { return false; }
}

function normalizeEndpointUrl(url) {
    let absUrl = url;
    try {
        if (!url || typeof url !== 'string' || url.length < 5 || ['access-denied-or-invalid', 'unknown-origin', 'null'].includes(url)) {
            return { normalized: url, components: null, key: url };
        }

        if (url.startsWith('about:') || url.startsWith('chrome:') || url.startsWith('chrome-extension:') || 
            url.startsWith('moz-extension:') || url.startsWith('safari-extension:') || url.startsWith('ms-browser-extension:') ||
            url.startsWith('blob:') || url.startsWith('data:') || url.startsWith('http://127.0.0.1:1337/')) {
            // Only log non-about:blank URLs to reduce spam
            if (!url.startsWith('about:blank')) {
                log.debug(`[Normalize URL] Special browser URL or FrogPost fuzzer URL detected: ${url}`);
            }
            return { normalized: url, components: null, key: url };
        }

        if (!url.includes('://') && !url.startsWith('//')) {
            absUrl = 'https://' + url;
        } else if (url.startsWith('//')) {
            absUrl = 'https:' + url;
        }


        const obj = new URL(absUrl);

        if (['about:', 'blob:', 'data:'].includes(obj.protocol)) {
            return { normalized: url, components: null, key: url };
        }

        const origin = obj.origin || '';
        const pathname = obj.pathname || '';
        const search = obj.search || '';
        const key = origin && pathname ? (origin + pathname + search) : url;

        return { normalized: key, components: { origin: origin, path: pathname, query: search, hash: obj.hash || '' }, key: key };

    } catch (e) {
        if (!absUrl || absUrl.startsWith('http://') || absUrl.startsWith('https://')) {
            log.error(`[Normalize URL] Error: "${e.message}".`, { originalInput: url, urlUsedInConstructor: absUrl });
        } else {
            log.debug(`[Normalize URL] Expected constructor skip for: ${url}`);
        }
        return { normalized: url, components: null, key: url };
    }
}
window.normalizeEndpointUrl = normalizeEndpointUrl;

function getStorageKeyForUrl(url) {
    return normalizeEndpointUrl(url)?.key || url;
}
window.getStorageKeyForUrl = getStorageKeyForUrl;

function showToastNotification(message, type = 'error', duration = 5000) {
    let container = document.getElementById('toast-container');
    if (!container) { container = document.createElement('div'); container.id = 'toast-container'; document.body.appendChild(container); }
    const toast = document.createElement('div'); toast.className = `toast toast-${type}`; toast.textContent = message; let removalTimeoutId = null; let removed = false;
    const removeToast = () => { if (removed || !toast.parentNode) return; removed = true; clearTimeout(removalTimeoutId); toast.classList.remove('show'); toast.classList.add('fade-out'); toast.addEventListener('transitionend', () => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, { once: true }); setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 600); };
    container.appendChild(toast); requestAnimationFrame(() => { toast.classList.add('show'); }); removalTimeoutId = setTimeout(removeToast, duration); toast.addEventListener('click', removeToast);
}


function updateButton(button, state, options = {}) {
    if (!button) return;

    const endpoint = button.getAttribute('data-endpoint');
    const endpointKey = getStorageKeyForUrl(endpoint);

    if (endpointKey) buttonStates.set(endpointKey, { state, options });

    const states = {
        start: { text: '▶', title: 'Start checks', class: 'default' },
        csp: { text: '⏳', title: 'Checking CSP...', class: 'checking is-working' },
        analyze: { text: '⏳', title: 'Analyzing...', class: 'checking is-working' },
        launch: { text: '🚀', title: 'Launch Payload Testing', class: 'green' },
        launching: { text: '🚀', title: 'Launching Fuzzer...', class: 'checking is-working launching' },
        success: { text: '✓', title: 'Check successful, handler found', class: 'success' },
        warning: { text: '⚠', title: options.errorMessage || 'Check completed with warnings', class: 'yellow' },
        error: { text: '✕', title: options.errorMessage || 'Check failed', class: 'red' }
    };

    let newState = states[state] || states.start;

    button.textContent = newState.text;
    button.title = newState.title;
    button.classList.remove(
        'default', 'checking', 'is-working', 'green', 'success', 'yellow', 'red',
        'has-critical-sinks', 'show-next-step-arrow', 'show-next-step-emoji',
        'launching'
    );
    button.classList.add(...newState.class.split(' '));
    button.style.animation = '';

    if (newState.class.includes('is-working')) button.classList.add('is-working');
    if (state === 'launch' && options.hasCriticalSinks) button.classList.add('has-critical-sinks');
    if (options.showArrow) button.classList.add('show-next-step-arrow');
    if (options.showEmoji) button.classList.add('show-next-step-emoji');

    if (endpoint && isEndpointAlreadyScanned(endpoint)) {
        button.disabled = true;
        button.title = "Handler already found (via Debugger Auto-Attach)";
        button.textContent = '✓';
        button.classList.remove('default', 'checking', 'is-working', 'green', 'yellow', 'red');
        button.classList.add('success');
    } else {
        button.disabled = false;
    }
}
window.updateButton = updateButton;

(async function preloadDetectedHandlerEndpoints() {
    try {
        const result = await chrome.storage.session.get(['handler_endpoint_keys']);
        if (result['handler_endpoint_keys']) {
            for (const key of result['handler_endpoint_keys']) {
                window.endpointsWithDetectedHandlers.add(key);
            }
            log.success(`[Dashboard] Loaded ${window.endpointsWithDetectedHandlers.size} detected handler endpoints`);
        }
    } catch (e) {
        log.info("[Dashboard] Failed loading handler_endpoint_keys:", e);
    }
})();


function updateTraceButton(button, state, options = {}) {
    if (!button) return; const endpointKey = getStorageKeyForUrl(button.getAttribute('data-endpoint')); if (endpointKey) traceButtonStates.set(endpointKey, { state, options });
    const states = { default: { text: '✨', title: 'Start message tracing', class: 'default' }, disabled: { text: '✨', title: 'Start message tracing (disabled)', class: 'disabled' }, checking: { text: '⏳', title: 'Tracing in progress...', class: 'checking is-working' }, success: { text: '✨', title: 'Trace completed', class: 'green' }, error: { text: '❌', title: 'Tracing failed', class: 'error' } };
    const newState = states[state] || states.disabled; button.textContent = newState.text; button.title = newState.title; const classesToRemove = ['default', 'disabled', 'checking', 'is-working', 'green', 'error', 'show-next-step-emoji', 'highlight-next-step']; button.classList.remove(...classesToRemove); button.classList.add('iframe-trace-button'); button.classList.add(...newState.class.split(' ')); button.style.animation = '';
    if (newState.class.includes('is-working')) button.classList.add('is-working'); if (options?.showEmoji) button.classList.add('show-next-step-emoji');
    if (state === 'disabled') { button.setAttribute('disabled', 'true'); button.classList.add('disabled'); } else button.removeAttribute('disabled');
}
window.updateTraceButton = updateTraceButton;

function updateReportButton(button, state, endpoint) {
    if (!button) return; const endpointKey = getStorageKeyForUrl(endpoint);
    const states = { disabled: { text: '📋', title: 'Analysis Report (disabled)', className: 'iframe-report-button disabled' }, default: { text: '📋', title: 'View Analysis Report', className: 'iframe-report-button default' }, green: { text: '📋', title: 'View Analysis Report (Findings)', className: 'iframe-report-button green' } };
    const newState = states[state] || states.disabled; button.textContent = newState.text; button.title = newState.title; button.className = newState.className; if (endpointKey) reportButtonStates.set(endpointKey, state);
}
window.updateReportButton = updateReportButton;

function originMatchesSource(currentOrigin, source, endpointOrigin) {
    if (source === '*') return true; if (source === "'self'") return endpointOrigin !== null && currentOrigin === endpointOrigin; if (source === "'none'") return false;
    const cleanCurrentOrigin = currentOrigin.endsWith('/') ? currentOrigin.slice(0, -1) : currentOrigin; const cleanSource = source.endsWith('/') ? source.slice(0, -1) : source;
    if (cleanCurrentOrigin === cleanSource) return true; if (cleanSource.startsWith('*.')) { const domainPart = cleanSource.substring(2); return cleanCurrentOrigin.endsWith('.' + domainPart) && cleanCurrentOrigin.length > (domainPart.length + 1); } return false;
}

async function performEmbeddingCheck(endpoint) {
    log.handler(`[Embedding Check] Starting HEAD request for: ${endpoint}`);
    try {
        const response = await fetch(endpoint, { method: 'HEAD', cache: 'no-store', signal: AbortSignal.timeout(8000) });
        if (!response.ok) {
            log.warn(`[Embedding Check] Received non-OK status: ${response.status} for ${endpoint}`);
            return { status: `HTTP Error: ${response.status}`, className: 'red', embeddable: false };
        }
        log.handler(`[Embedding Check] HEAD request status OK: ${response.status}`);
        const xFrameOptions = response.headers.get('X-Frame-Options');
        if (xFrameOptions) {
            log.handler(`[Embedding Check] Found X-Frame-Options: ${xFrameOptions}`);
            const xfoUpper = xFrameOptions.toUpperCase();
            if (xfoUpper === 'DENY') return { status: `X-Frame-Options: DENY`, className: 'red', embeddable: false };
            if (xfoUpper === 'SAMEORIGIN') {
                log.warn(`[Embedding Check] X-Frame-Options: SAMEORIGIN detected. Tool cannot directly embed.`);
                return { status: `X-Frame-Options: SAMEORIGIN`, className: 'red', embeddable: false };
            }
        }
        const csp = response.headers.get('Content-Security-Policy');
        if (csp) {
            log.handler(`[Embedding Check] Found Content-Security-Policy header.`);
            const directives = csp.split(';').map(d => d.trim());
            const frameAncestors = directives.find(d => d.startsWith('frame-ancestors'));
            if (frameAncestors) {
                const sourcesString = frameAncestors.substring('frame-ancestors'.length).trim(); const sources = sourcesString.split(/\\s+/);
                log.handler(`[Embedding Check] Parsed frame-ancestors sources: [${sources.join(', ')}]`);
                if (sources.includes("'none'")) return { status: `CSP: frame-ancestors 'none'`, className: 'red', embeddable: false };
                if (!sources.includes('*')) {
                    log.warn(`[Embedding Check] CSP: frame-ancestors found without '*'. Tool cannot directly embed.`);
                    return { status: `CSP: frame-ancestors restricted`, className: 'red', embeddable: false };
                }
            }
        }
        log.success(`[Embedding Check] No prohibitive XFO/CSP headers found via HEAD for ${endpoint}`);
        return { status: 'Potentially embeddable (No restrictive headers found)', className: 'green', embeddable: true };

    } catch (error) {
        log.error(`[Embedding Check] Network/Fetch error for ${endpoint}: ${error.message}`, error);
        throw error;
    }
}

function getMessageCount(endpointKey) {
    return window.frogPostState.messages.filter(msg => { if (!msg?.origin || !msg?.destinationUrl) return false; const originKey = getStorageKeyForUrl(msg.origin); const destKey = getStorageKeyForUrl(msg.destinationUrl); return originKey === endpointKey || destKey === endpointKey; }).length;
}

function escapeHTML(str) {
    if (str === undefined || str === null) return ''; return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
window.escapeHTML = escapeHTML;

async function sendMessageTo(targetKey, button) {
    let success = false;
    
    try {
        if (!targetKey || !button) {
            throw new Error("Missing required parameters");
        }
        
        const messageItem = button.closest('.message-item');
        if (!messageItem) {
            throw new Error("Message item not found");
        }
        
        const messageDataElement = messageItem.querySelector('.message-data');
        if (!messageDataElement) {
            throw new Error("Message data element not found");
        }
        
        const messageContent = messageDataElement.textContent;
        let data;
        try {
            data = JSON.parse(messageContent);
        } catch (e) {
            data = messageContent;
        }
        
        try {
            const targetUrl = new URL(targetKey);
            
            // Try 1: Look for tabs matching the target hostname (for main frames)
            const domainPattern = `*://${targetUrl.hostname}/*`;
            let tabs = await chrome.tabs.query({ url: domainPattern });
            console.log('[FrogPost] Tabs matching', targetUrl.hostname, ':', tabs.length);
            
            // Try 2: If no match, it's likely an iframe - try ALL tabs with http/https
            if (tabs.length === 0) {
                console.log('[FrogPost] No direct match - target is likely an iframe. Checking all tabs...');
                tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
                console.log('[FrogPost] Found', tabs.length, 'total tabs to check');
            }
            
            if (tabs.length === 0) {
                throw new Error('No web pages open');
            }
            
            // Try sending to each tab until one succeeds
            let lastError = null;
            let attemptsCount = 0;
            for (const tab of tabs) {
                try {
                    // Skip chrome:// and other special URLs
                    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || 
                        tab.url.startsWith('chrome-extension://') || tab.url.startsWith('file://')) {
                        continue;
                    }
                    
                    attemptsCount++;
                    console.log('[FrogPost] Trying tab', attemptsCount, ':', tab.id, '-', tab.url?.substring(0, 50));
                    
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'sendPostMessageToIframe',
                        message: data,
                        targetUrl: targetKey
                    });
                    
                    console.log('[FrogPost] Response from tab', tab.id, ':', response);
                    
                    if (response && response.success) {
                        console.log('[FrogPost] ✓ Message sent successfully via tab:', tab.id, response.debug || '');
                        success = true;
                        break;
                    } else {
                        lastError = response?.error || 'No iframe found';
                        console.log('[FrogPost] Tab', tab.id, 'failed:', lastError);
                    }
                } catch (err) {
                    // Content script not loaded or connection failed - this is expected, try next tab
                    if (err.message && err.message.includes('Receiving end does not exist')) {
                        console.log('[FrogPost] Tab', tab.id, 'has no content script, skipping');
                    } else {
                        console.log('[FrogPost] Tab', tab.id, 'error:', err.message);
                    }
                    lastError = err.message;
                    continue;
                }
            }
            
            if (!success) {
                if (attemptsCount === 0) {
                    throw new Error('No accessible web pages found. Please reload the target page.');
                } else {
                    throw new Error(`Tried ${attemptsCount} tabs but couldn't find iframe for ${targetUrl.hostname}. Try reloading the page.`);
                }
            }
        } catch (error) {
            console.error('[FrogPost] Send failed:', error.message);
            throw error;
        }
        
    } catch (error) {
        console.error("[FrogPost] Error in sendMessageTo:", error);
        success = false;
    } finally {
        button.classList.toggle('success', success);
        button.classList.toggle('error', !success);
        
        setTimeout(() => {
            button.classList.remove('success', 'error');
        }, 1500);
    }
    
    return success;
}

async function sendMessageFromModal(targetKey, editedDataString, buttonElement, originalButtonText) {
    if (!targetKey || !buttonElement) {
        console.error("Missing required parameters");
        return false;
    }
    
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
        const targetUrl = new URL(targetKey);
        
        // Try 1: Look for tabs matching the target hostname (for main frames)
        const domainPattern = `*://${targetUrl.hostname}/*`;
        let tabs = await chrome.tabs.query({ url: domainPattern });
        console.log('[FrogPost] Tabs matching', targetUrl.hostname, ':', tabs.length);
        
        // Try 2: If no match, it's likely an iframe - try ALL tabs with http/https
        if (tabs.length === 0) {
            console.log('[FrogPost] No direct match - target is likely an iframe. Checking all tabs...');
            tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
            console.log('[FrogPost] Found', tabs.length, 'total tabs to check');
        }
        
        if (tabs.length === 0) {
            throw new Error('No web pages open');
        }
        
        // Try sending to each tab until one succeeds
        let lastError = null;
        let sent = false;
        let attemptsCount = 0;
        for (const tab of tabs) {
            try {
                // Skip chrome:// and other special URLs
                if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || 
                    tab.url.startsWith('chrome-extension://') || tab.url.startsWith('file://')) {
                    continue;
                }
                
                attemptsCount++;
                console.log('[FrogPost] Trying tab', attemptsCount, ':', tab.id, '-', tab.url?.substring(0, 50));
                
                const response = await chrome.tabs.sendMessage(tab.id, {
                    action: 'sendPostMessageToIframe',
                    message: dataToSend,
                    targetUrl: targetKey
                });
                
                console.log('[FrogPost] Response from tab', tab.id, ':', response);
                
                if (response && response.success) {
                    console.log('[FrogPost] ✓ Edited message sent successfully via tab:', tab.id, response.debug || '');
                    buttonElement.textContent = 'Sent ✓';
                    buttonElement.classList.add('success');
                    await new Promise(res => setTimeout(res, 1000));
                    sent = true;
                    break;
                } else {
                    lastError = response?.error || 'No iframe found';
                    console.log('[FrogPost] Tab', tab.id, 'failed:', lastError);
                }
            } catch (err) {
                // Content script not loaded or connection failed - this is expected, try next tab
                if (err.message && err.message.includes('Receiving end does not exist')) {
                    console.log('[FrogPost] Tab', tab.id, 'has no content script, skipping');
                } else {
                    console.log('[FrogPost] Tab', tab.id, 'error:', err.message);
                }
                lastError = err.message;
                continue;
            }
        }
        
        if (!sent) {
            if (attemptsCount === 0) {
                throw new Error('No accessible web pages found. Please reload the target page.');
            } else {
                throw new Error(`Tried ${attemptsCount} tabs but couldn't find iframe for ${targetUrl.hostname}. Try reloading the page.`);
            }
        }
        
        return true;
    } catch (error) {
        console.error('[FrogPost] Error in sendMessageFromModal:', error);
        buttonElement.textContent = 'Error ✕';
        buttonElement.classList.add('error');
        
        await new Promise(res => setTimeout(res, 2000));
        return false;
        
    } finally {
        if (buttonElement && !buttonElement.classList.contains('success')) {
            buttonElement.disabled = false;
            buttonElement.textContent = originalButtonText;
            buttonElement.classList.remove('error');
        }
    }
}

function showEditModal(messageObject) {
    const modalContainer = document.getElementById('editMessageModalContainer'); if (!modalContainer) return; modalContainer.innerHTML = ''; const backdrop = document.createElement('div'); backdrop.className = 'modal-backdrop'; const modal = document.createElement('div'); modal.className = 'edit-message-modal'; let dataToEdit; try { dataToEdit = (typeof messageObject.data === 'string') ? messageObject.data : JSON.stringify(messageObject.data, null, 2); } catch (e) { dataToEdit = String(messageObject.data); } const originDisplay = escapeHTML(normalizeEndpointUrl(messageObject.origin)?.normalized || messageObject.origin); const destDisplay = escapeHTML(normalizeEndpointUrl(messageObject.destinationUrl)?.normalized || messageObject.destinationUrl);
    modal.innerHTML = `<div class="edit-modal-header"><h4>Edit Message</h4><div class="message-info"><strong>Origin:</strong> ${originDisplay}<br><strong>Destination:</strong> ${destDisplay}<br><strong>Time:</strong> ${new Date(messageObject.timestamp).toLocaleString()}</div><button class="close-modal-btn">&times;</button></div><div class="edit-modal-body"><textarea id="messageEditTextarea">${escapeHTML(dataToEdit)}</textarea></div><div class="edit-modal-footer"><button id="editCancelBtn" class="control-button secondary-button">Cancel</button><button id="editSendDestBtn" class="control-button">Send to Destination</button><button id="editSendOriginBtn" class="control-button">Send to Origin</button></div>`;
    modalContainer.appendChild(backdrop); modalContainer.appendChild(modal); const closeModal = () => { modalContainer.innerHTML = ''; }; modal.querySelector('.close-modal-btn').addEventListener('click', closeModal); modal.querySelector('#editCancelBtn').addEventListener('click', closeModal); backdrop.addEventListener('click', closeModal); const textarea = modal.querySelector('#messageEditTextarea'); const originKey = getStorageKeyForUrl(messageObject.origin); const destKey = getStorageKeyForUrl(messageObject.destinationUrl);
    modal.querySelector('#editSendOriginBtn').addEventListener('click', async () => { const success = await sendMessageFromModal(originKey, textarea.value, modal.querySelector('#editSendOriginBtn'), "Send to Origin"); if (success) closeModal(); }); modal.querySelector('#editSendDestBtn').addEventListener('click', async () => { const success = await sendMessageFromModal(destKey, textarea.value, modal.querySelector('#editSendDestBtn'), "Send to Destination"); if (success) closeModal(); });
}

function generateFallbackMessageId(messageObject) {
    try {
        const ts = messageObject?.timestamp || Date.now();
        const seed = JSON.stringify({ o: messageObject?.origin, d: messageObject?.destinationUrl, t: messageObject?.messageType, data: messageObject?.data }).length;
        const rand = Math.floor((Math.random() + 1) * 0x100000).toString(16);
        return new Date(ts).toISOString() + '-' + rand + '-' + seed.toString(16);
    } catch {
        return 'local-' + Date.now().toString(36) + '-' + Math.random().toString(16).slice(2);
    }
}
function createMessageElement(msg, indexInList, totalCount) {
    const item = document.createElement('div');
    item.classList.add('message-item');
    const visibleId = msg?.messageId || generateFallbackMessageId(msg);

    const source = msg?.origin || 'Unknown Source';
    const target = msg?.destinationUrl || 'Unknown Target';
    const type = msg?.messageType || 'Unknown Type';
    const rawData = msg.data;
    const sanitizedData = sanitizeMessageData(rawData);

    const highlightInMessages = false;

    let sensitiveDataInfo = null;
    if (highlightInMessages) {
        try {
            if (typeof SensitiveDataDetector !== 'undefined') {
                const detector = new SensitiveDataDetector();
                sensitiveDataInfo = detector.detectSensitiveData(rawData);
            }
        } catch (e) {
            console.warn('[Sensitive Data] Detection failed for message:', e);
        }
    }

    let dataForDisplay;
    try {
        dataForDisplay = typeof sanitizedData === 'string' ? sanitizedData : JSON.stringify(sanitizedData, null, 2);
    } catch (e) {
        dataForDisplay = String(sanitizedData);
    }

    const header = document.createElement("div");
    header.className = "message-header";
    const originDisplay = normalizeEndpointUrl(source)?.normalized || source;
    const destDisplay = normalizeEndpointUrl(target)?.normalized || target;
    const messageTypeDisplay = String(type).replace(/\s+/g, '-').toLowerCase(); // Ensure type is string
    
    let sensitiveWarning = '';
    if (highlightInMessages && sensitiveDataInfo?.hasSensitiveData) {
        const riskColor = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }[sensitiveDataInfo.riskLevel] || '#6c757d';
        
        sensitiveWarning = `<br><div style="display: inline-flex; align-items: center; gap: 6px; margin-top: 4px;">
            <span style="background: ${riskColor}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">
                🔍 ${sensitiveDataInfo.riskLevel} RISK
            </span>
            <span style="font-size: 11px; color: #6c757d;" title="${sensitiveDataInfo.summary}">
                Sensitive data detected
            </span>
        </div>`;
    }
    
    const displayNumber = Math.max(1, (Number(totalCount) || 0) - Number(indexInList));
    header.innerHTML = `<strong>#:</strong> ${displayNumber}<br><strong>Origin:</strong> ${escapeHTML(originDisplay)}<br><strong>Destination:</strong> ${escapeHTML(destDisplay)}<br><strong>Time:</strong> ${new Date(msg.timestamp).toLocaleString()}<br><strong>ID:</strong> ${escapeHTML(String(visibleId))}<br><strong>Msg Type:</strong> <span class="message-type message-type-${messageTypeDisplay}">${escapeHTML(type)}</span>${sensitiveWarning}`;

    const dataPre = document.createElement("pre");
    dataPre.className = "message-data";
    
    if (highlightInMessages && sensitiveDataInfo?.hasSensitiveData) {
        dataPre.style.border = `1px solid ${{'LOW':'#28a745','MEDIUM':'#ffc107','HIGH':'#fd7e14','CRITICAL':'#dc3545'}[sensitiveDataInfo.riskLevel]}`;
        dataPre.style.borderLeft = `4px solid ${{'LOW':'#28a745','MEDIUM':'#ffc107','HIGH':'#fd7e14','CRITICAL':'#dc3545'}[sensitiveDataInfo.riskLevel]}`;
        dataPre.style.backgroundColor = sensitiveDataInfo.riskLevel === 'CRITICAL' ? '#fff5f5' : 
                                        sensitiveDataInfo.riskLevel === 'HIGH' ? '#fff8f1' :
                                        sensitiveDataInfo.riskLevel === 'MEDIUM' ? '#fffbf0' : '#f8fff9';
    }
    
    dataPre.textContent = dataForDisplay;

    const controls = document.createElement("div");
    controls.className = "message-controls";

    const originBtn = document.createElement("button");
    originBtn.className = "send-origin";
    originBtn.textContent = "Resend to Origin";
    originBtn.addEventListener('click', () => sendMessageTo(getStorageKeyForUrl(source), originBtn));

    const destBtn = document.createElement("button");
    destBtn.className = "send-destination";
    destBtn.textContent = "Resend to Destination";
    destBtn.addEventListener('click', () => sendMessageTo(getStorageKeyForUrl(target), destBtn));

    const editBtn = document.createElement("button");
    editBtn.className = "edit-send";
    editBtn.textContent = "Edit & Send";
    editBtn.addEventListener('click', () => showEditModal(msg));

    const copyBtn = document.createElement("button");
    copyBtn.className = "copy-data";
    copyBtn.textContent = "Copy Data";
    copyBtn.addEventListener('click', (event) => {
        const buttonElement = event.target;
        let dataToCopy;
        try {
            dataToCopy = (typeof rawData === 'string' || typeof rawData === 'number' || typeof rawData === 'boolean' || rawData === null)
                ? String(rawData ?? '')
                : JSON.stringify(rawData, null, 2);
        } catch (e) {
            dataToCopy = String(rawData);
        }

        navigator.clipboard.writeText(dataToCopy).then(() => {
            const originalText = buttonElement.textContent;
            buttonElement.textContent = 'Copied!';
            buttonElement.classList.add('success');
            setTimeout(() => {
                buttonElement.textContent = originalText;
                buttonElement.classList.remove('success');
            }, 1500);
        }).catch(err => {
            const originalText = buttonElement.textContent;
            buttonElement.textContent = 'Error!';
            buttonElement.classList.add('error');
            log.error("Failed to copy data:", err);
            showToastNotification("Failed to copy data to clipboard.", "error");
            setTimeout(() => {
                buttonElement.textContent = originalText;
                buttonElement.classList.remove('error');
            }, 2000);
        });
    });

    controls.appendChild(originBtn);
    controls.appendChild(destBtn);
    controls.appendChild(copyBtn);
    controls.appendChild(editBtn);
    
    item.appendChild(header);
    item.appendChild(dataPre);
    item.appendChild(controls);

    return item;
}



function updateMessageListForUrl(url) {
    const messageList = document.getElementById('messagesList');
    if (!messageList) return;
    const noMessagesDiv = messageList.querySelector('.no-messages');
    messageList.querySelectorAll('.message-item').forEach(item => item.remove());

    const TEST_MESSAGE_KEY = "FrogPost";
    const TEST_MESSAGE_VALUE = "BreakpointTest";

    if (!url) {
        if (noMessagesDiv) {
            noMessagesDiv.style.display = 'block';
            noMessagesDiv.textContent = 'Select an endpoint to view messages.';
        }
        return;
    }

    const selectedKey = getStorageKeyForUrl(url);

    const relatedMessages = window.frogPostState.messages.filter(msg => {
        const originKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
        const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
        return originKey === selectedKey || destKey === selectedKey;
    });

    const filteredMessagesToDisplay = relatedMessages.filter(msg => {
        return !(typeof msg.data === 'object' && msg.data !== null && msg.data.hasOwnProperty(TEST_MESSAGE_KEY) && msg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE);
    });

    if (filteredMessagesToDisplay.length === 0) {
        if (noMessagesDiv) {
            noMessagesDiv.style.display = 'block';
            const totalRelatedCount = relatedMessages.length;
            if (totalRelatedCount > 0) {
                noMessagesDiv.textContent = `No organic messages found involving endpoint: ${url} (Internal test messages hidden).`;
            } else {
                noMessagesDiv.textContent = `No messages found involving endpoint: ${url}`;
            }
        }
    } else {
        if (noMessagesDiv) noMessagesDiv.style.display = 'none';
        const toTime = (t) => (typeof t === 'number') ? t : (Date.parse(t) || 0);
        const sortedMessages = [...filteredMessagesToDisplay].sort((a, b) => toTime(b.timestamp) - toTime(a.timestamp));
        const totalCount = sortedMessages.length;
        sortedMessages.forEach((msg, idx) => {
            const messageElement = createMessageElement(msg, idx, totalCount);
            if (messageElement) messageList.appendChild(messageElement);
        });
    }
    restoreLastReport(url);
}

function setActiveUrl(url) {
    if (window.frogPostState.activeUrl !== url) {
        window.frogPostState.activeUrl = url;
        log.info(`Selected endpoint: ${url}`);
        requestUiUpdate();
    }
}
function createActionButtonContainer(endpointKey) {
    const buttonContainer = document.createElement("div");
    buttonContainer.className = "button-container";
    
    const playButton = document.createElement("button");
    playButton.className = "iframe-check-button";
    playButton.setAttribute("data-endpoint", endpointKey);
    const traceButton = document.createElement("button");
    traceButton.className = "iframe-trace-button";
    traceButton.setAttribute("data-endpoint", endpointKey);
    const reportButton = document.createElement("button");
    reportButton.className = "iframe-report-button";
    reportButton.setAttribute("data-endpoint", endpointKey);

    const isExtensionUrl = endpointKey.startsWith('chrome-extension://');
    const handlerExists = endpointsWithDetectedHandlers.has(endpointKey);
    const traceInfo = traceButtonStates.get(endpointKey);
    const reportInfo = reportButtonStates.get(endpointKey);
    
    // CRITICAL: Check if endpoint is marked as failed (CSP/embedding blocked)
    const failureInfo = isEndpointFailed(endpointKey);

    if (isExtensionUrl) {
        if (handlerExists) {
            updateButton(playButton, 'success');
            updateTraceButton(traceButton, traceInfo?.state || 'default', traceInfo?.options || { showEmoji: true });
            updateReportButton(reportButton, reportInfo || (traceButton.classList.contains('green') || traceButton.classList.contains('success') ? 'default' : 'disabled'), endpointKey);
        } else {
            updateButton(playButton, 'start');
            updateTraceButton(traceButton, 'disabled');
            updateReportButton(reportButton, 'disabled', endpointKey);
        }
    } else {
        // If endpoint failed (CSP blocked), override state to show error
        if (failureInfo) {
            updateButton(playButton, 'error', { errorMessage: failureInfo.reason });
            updateTraceButton(traceButton, 'disabled');
            updateReportButton(reportButton, 'disabled', endpointKey);
        } else {
            const savedPlayStateInfo = buttonStates.get(endpointKey);
            updateButton(playButton, savedPlayStateInfo?.state || 'start', savedPlayStateInfo?.options || {});
            const canTrace = playButton.classList.contains('success') || playButton.classList.contains('green') || playButton.classList.contains('launch');
            updateTraceButton(traceButton, traceInfo?.state || (canTrace ? 'default' : 'disabled'), traceInfo?.options || {});
            const canReport = traceButton.classList.contains('green') || traceButton.classList.contains('success');
            updateReportButton(reportButton, reportInfo || (canReport ? 'default' : 'disabled'), endpointKey);
        }
    }

    playButton.addEventListener("click", (e) => { e.stopPropagation(); handlePlayButtonWithTimeout(endpointKey, playButton); });
    traceButton.addEventListener("click", (e) => { e.stopPropagation(); if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) window.handleTraceButton(endpointKey, traceButton); });
    reportButton.addEventListener("click", (e) => { e.stopPropagation(); if (!reportButton.classList.contains('disabled')) handleReportButton(endpointKey); });

    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(reportButton);
    
    // Add exploitability badge if report exists
    const traceReportsMap = window.traceReports || new Map();
    const report = traceReportsMap.get(endpointKey);
    if (report?.exploitability && report.exploitability.level !== 'INFO' && report.exploitability.level !== 'UNKNOWN') {
        const badge = document.createElement('span');
        badge.className = `exploit-badge exploit-${report.exploitability.level.toLowerCase()}`;
        badge.textContent = report.exploitability.level;
        badge.title = `${report.exploitability.impact}\n${report.exploitability.recommendation}`;
        buttonContainer.appendChild(badge);
    }
    
    return buttonContainer;
}

function computePipelineScoreClient({ handlerOk, messagesOk, payloadsOk, sinksFound }) {
  if (sinksFound && handlerOk && messagesOk && payloadsOk) return 100;
  let score = 0;
  if (handlerOk) score += 40;
  if (messagesOk) score += 30;
  if (payloadsOk) score += 20;
  if (sinksFound) score += 10;
  return Math.min(95, score);
}

async function analyzeWithLLM(endpointKey, buttonEl) {
  try {
    if (buttonEl) { buttonEl.classList.add('checking'); buttonEl.disabled = true; }
    
    console.log(`🚀 [Unified LLM] Starting unified analysis for: ${endpointKey}`);
    
    const settings = await chrome.storage.sync.get(['llm_provider','llm_model']);
    const sess = await chrome.storage.session.get(['llm_api_key']);
    const provider = settings.llm_provider || 'none';
    const model = settings.llm_model || '';
    const apiKey = sess.llm_api_key || '';

    if (!provider || provider === 'none' || !model || !apiKey) {
      showToastNotification('⚠️ LLM configuration required in Options.', 'warning');
      return;
    }

    const bestKey = `best-handler-${endpointKey}`;
    const saved = await chrome.storage.local.get([bestKey]);
    const handlerInfo = saved[bestKey] || {};
    const handlerCode = handlerInfo?.handler || handlerInfo?.code || '';
    
    const savedMessages = await chrome.storage.local.get([`saved-messages-${endpointKey}`]);
    const capturedMessages = savedMessages[`saved-messages-${endpointKey}`] || [];
    
    console.log(`📊 [Unified] Handler: ${handlerCode.length} chars, Messages: ${capturedMessages.length} total`);

    const sensitiveDetector = new SensitiveDataDetector();
    const costProtector = new LLMCostProtector();
    
    const sensitivityAnalysis = sensitiveDetector.analyzeLLMSafety(capturedMessages);
    const costAnalysis = costProtector.analyzeRequest({
      url: endpointKey,
      observedMessages: capturedMessages,
      handlerCode: handlerCode
    }, provider);
    
    console.log(`🛡️ [Safety] Messages for analysis: ${sensitivityAnalysis.totalMessages}`);
    
    const proceed = await showSafetyConsentDialog(sensitivityAnalysis, costAnalysis);
    if (!proceed) {
      showToastNotification('🛡️ LLM analysis cancelled by user', 'info');
      return;
    }
    
    if (!costAnalysis.approved) {
      showToastNotification(`🚫 Request blocked: ${costAnalysis.warnings.join(', ')}`, 'error');
      return;
    }
    
    costProtector.recordAPICall();

    console.log(`🔥 [Unified Analysis] Sending ${handlerCode.length} chars of handler code + ${capturedMessages.length} messages`);
    
    const unifiedRes = await fetch('http://127.0.0.1:1337/llm/unified-analyze', { 
      method: 'POST', 
      headers: {'Content-Type':'application/json'}, 
      body: JSON.stringify({
        provider, model, apiKey,
        context: { 
          handlerCode,
          observedMessages: capturedMessages
        }
      })
    });
    
    if (!unifiedRes.ok) {
      throw new Error(`Unified analysis failed: ${unifiedRes.status}`);
    }
    
    const unifiedData = await unifiedRes.json();
    const analysisOk = !!unifiedData?.ok;
    
    const detectedSinks = Array.isArray(unifiedData?.dom_xss_sinks) ? unifiedData.dom_xss_sinks : [];
    const prototypePollutionIndicators = Array.isArray(unifiedData?.prototype_pollution_indicators) ? unifiedData.prototype_pollution_indicators : [];
    const handlerMatch = unifiedData?.handler_match || 50;
    
    console.log(`✅ [Unified Analysis] Complete. DOM XSS sinks: ${detectedSinks.length}, Prototype pollution indicators: ${prototypePollutionIndicators.length}, Handler match: ${handlerMatch}/100`);
    console.log(`🔍 [Unified Analysis] Generated payloads: ${unifiedData?.newPayloadsCount || 0}`);
    console.log(`🔍 [Unified Analysis] Payload array length: ${Array.isArray(unifiedData?.new_payloads) ? unifiedData.new_payloads.length : 'not array'}`);

    const handlerOk = analysisOk;
    const messagesOk = analysisOk;  
    const payloadsOk = analysisOk;
    const payloadData = unifiedData;
    const sinksFound = detectedSinks.length > 0 || prototypePollutionIndicators.length > 0;

    const finalScore = computePipelineScoreClient({ handlerOk, messagesOk, payloadsOk, sinksFound });
    
    console.log(`🏆 [Pipeline Complete] Final Score: ${finalScore}/100`);
    console.log(`📊 [Pipeline Summary] Handler: ${handlerOk ? '✅' : '❌'}, Messages: ${messagesOk ? '✅' : '❌'}, Payloads: ${payloadsOk ? '✅' : '❌'}, Sinks: ${sinksFound ? detectedSinks.length : 0}`);

    const existingReport = await window.traceReportStorage.getTraceReport(endpointKey);
    const reportToSave = {
      endpoint: endpointKey,
      timestamp: Date.now(),
      details: {
        handlerAssessment: unifiedData?.handler_assessment || '',
        risks: Array.isArray(unifiedData?.risks) ? unifiedData.risks : [],
        messageFindings: [], // Not separately analyzed in unified approach
        sinks: detectedSinks,
        prototypePollutionIndicators,
        sinksFound,
        handlerMatch,
        llmProvider: provider,
        model,
        score: finalScore,
        dataType: unifiedData?.data_type || 'JSON'
      },
      summary: { 
        totalPayloads: payloadData?.newPayloads?.length || 0,
        pipelineSteps: { handlerOk, messagesOk, payloadsOk },
        unifiedAnalysis: true
      }
    };

    if (existingReport && typeof existingReport === 'object') {
      try {
        const llmGeneratedDetails = reportToSave.details;
        reportToSave = JSON.parse(JSON.stringify(existingReport)); // Deep clone to avoid mutation
        reportToSave.details = { ...(existingReport.details || {}), ...llmGeneratedDetails };
        
        if (!reportToSave.details.analyzedHandler && existingReport.details?.analyzedHandler) {
          reportToSave.details.analyzedHandler = existingReport.details.analyzedHandler;
        }
        if (!reportToSave.details.bestHandler && existingReport.details?.bestHandler) {
          reportToSave.details.bestHandler = existingReport.details.bestHandler;
        }
        if (!reportToSave.details.uniqueStructures && existingReport.details?.uniqueStructures) {
          reportToSave.details.uniqueStructures = existingReport.details.uniqueStructures;
        }
        if (!reportToSave.details.originValidationChecks && existingReport.details?.originValidationChecks) {
          reportToSave.details.originValidationChecks = existingReport.details.originValidationChecks;
        }
      } catch {}
    }

    const existingPayloads = await window.traceReportStorage.getReportPayloads(endpointKey);
    const incoming = Array.isArray(payloadData?.new_payloads) ? payloadData.new_payloads : [];
    
    console.log(`🎯 [Payload Merge] Existing payloads: ${existingPayloads?.length || 0}, Incoming: ${incoming.length}`);
    
    const combined = (() => {
      const all = [...(existingPayloads || []), ...incoming];
      const uniq = new Map();
      all.forEach(p => {
        try {
          const payloadStr = typeof p?.payload === 'object' && p?.payload !== null ? JSON.stringify(p.payload) : String(p?.payload);
          const key = `${p?.type || p?.generator || 'unknown'}|${p?.targetPath || ''}|${payloadStr}`;
          if (!uniq.has(key)) uniq.set(key, p);
        } catch { /* ignore */ }
      });
      return Array.from(uniq.values());
    })();

    reportToSave.summary.totalPayloads = combined.length;
    await window.traceReportStorage.saveTraceReport(endpointKey, reportToSave);
    await window.traceReportStorage.saveReportPayloads(endpointKey, combined);

    console.log(`💾 [Report] Saved complete pipeline results to IndexedDB: ${combined.length} total payloads`);

    try {
        const handlerAnalysis = {
            handler_assessment: unifiedData?.handler_assessment || '',
            handler_score: unifiedData?.handler_score || 0,
            handler_match: handlerMatch,
            risks: unifiedData?.risks || [],
            notes: unifiedData?.notes || '',
            dom_xss_sinks: detectedSinks || [],
            prototype_pollution_indicators: prototypePollutionIndicators || [],
            data_type: unifiedData?.data_type || 'JSON'
        };
        updateHandlerWithLLMAnalysis(handlerAnalysis);
        
        const newPayloadCount = incoming.length;
        if (newPayloadCount > 0) {
            const payloadCountElement = document.querySelector(`[id*="payload-count-display"]`);
            if (payloadCountElement) {
                const currentCount = parseInt(payloadCountElement.textContent) || 0;
                const newCount = currentCount + newPayloadCount;
                payloadCountElement.textContent = newCount;
                
                const payloadSection = payloadCountElement.closest('.metric');
                if (payloadSection) {
                    const existingIndicator = payloadSection.querySelector('.llm-payload-indicator');
                    if (!existingIndicator) {
                        const indicator = document.createElement('div');
                        indicator.className = 'llm-payload-indicator';
                        indicator.style.cssText = 'font-size: 10px; color: var(--accent-primary); margin-top: 2px;';
                        indicator.textContent = `+${newPayloadCount} Added by LLM!`;
                        payloadCountElement.parentNode.appendChild(indicator);
                    }
                }
            }
            console.log(`✅ [UI Update] Updated payload count display: +${newPayloadCount} LLM payloads`);
            
            const reportContent = document.getElementById('report-content');
            if (reportContent && reportContent.style.display !== 'none') {
                try {
                    console.log('🔄 [UI Refresh] Refreshing payload display with updated data');
                    const updatedPayloads = await window.traceReportStorage.getReportPayloads(endpointKey);
                    const updatedReport = await window.traceReportStorage.getTraceReport(endpointKey);
                    if (updatedReport && updatedPayloads) {
                        await renderReportUI(updatedReport, updatedPayloads);
                        console.log(`🔄 [UI Refresh] Successfully refreshed report with ${updatedPayloads.length} payloads`);
                    }
                } catch (e) {
                    console.error('🔄 [UI Refresh] Failed to refresh report UI:', e);
                }
            }
        }
        
        console.log('✅ [UI Update] Successfully updated UI with unified LLM results');
    } catch(e){ console.error('[LLM UI Patch] Failed:',e);}

    showToastNotification(`🎯 Pipeline Complete! Score: ${finalScore}/100, Payloads: +${incoming.length} added (total ${combined.length})`, 'success');

  } catch (e) {
    console.error('💥 [LLM Pipeline] Failed:', e);
    showToastNotification(`❌ Pipeline failed: ${e.message}`, 'error');
  } finally {
    if (buttonEl) { buttonEl.classList.remove('checking'); buttonEl.disabled = false; }
  }
}
/**
 * Show safety consent dialog for LLM analysis
 * @param {Object} sensitivityAnalysis - Results from sensitive data detection
 * @param {Object} costAnalysis - Results from cost protection analysis
 * @returns {Promise<boolean>} User's consent decision
 */
async function showSafetyConsentDialog(sensitivityAnalysis, costAnalysis) {
    console.log('🛡️ [Dialog] Starting showSafetyConsentDialog...');
    return new Promise((resolve) => {
        try {
            const overlay = document.createElement('div');
        overlay.className = 'safety-modal-overlay';
        overlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
            background: rgba(0,0,0,0.7); z-index: 10000; 
            display: flex; align-items: center; justify-content: center;
        `;
        
        const modal = document.createElement('div');
        modal.className = 'safety-modal';
        modal.style.cssText = `
            background: var(--bg-primary); border-radius: 12px; padding: 24px;
            max-width: 500px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 1px solid var(--border-color);
        `;
        
        const title = document.createElement('h3');
        title.textContent = '🛡️ LLM Analysis Safety Review';
        title.style.cssText = 'margin: 0 0 16px 0; color: var(--text-primary); font-size: 18px;';
        
        const content = document.createElement('div');
        content.style.cssText = 'margin-bottom: 20px; line-height: 1.5;';
        
        let warningsHTML = '<div style="margin-bottom: 16px;">';
        
        if (sensitivityAnalysis.sensitiveMsgCount > 0) {
            let sensitiveDataDetails = '';
            if (sensitivityAnalysis.sanitizedMessages && sensitivityAnalysis.sanitizedMessages.length > 0) {
                console.log('🛡️ [Dialog] Sanitized messages structure:', sensitivityAnalysis.sanitizedMessages[0]);
                const sensitiveMessages = sensitivityAnalysis.sanitizedMessages.filter(sm => sm.detection && sm.detection.hasSensitiveData);
                console.log('🛡️ [Dialog] Sensitive messages found:', sensitiveMessages.length);
                console.log('🛡️ [Dialog] Sensitive messages details:', sensitiveMessages.map(sm => ({
                    index: sm.index,
                    hasSensitiveData: sm.detection.hasSensitiveData,
                    detectedData: sm.detection.detectedData?.length || 0,
                    detectedTypes: Array.from(sm.detection.detectedTypes || [])
                })));
                if (sensitiveMessages.length > 0) {
                    sensitiveDataDetails = '<div style="margin-top: 8px; font-size: 12px;">';
                    sensitiveDataDetails += '<strong>Detected sensitive data:</strong><br/>';
                    
                    sensitiveMessages.slice(0, 3).forEach((sm, index) => {
                        const detectedDataArr = sm.detection?.detectedData || sm.detection?.sensitiveFields || [];
                        const detectedTypesArr = sm.detection?.detectedTypes ? Array.from(sm.detection.detectedTypes) : (detectedDataArr.map(d => d.type).filter(Boolean));
                        if ((detectedDataArr?.length || 0) === 0 && (detectedTypesArr?.length || 0) === 0) return;
                        
                        const dataTypes = detectedTypesArr;
                        const sampleData = (detectedDataArr || []).slice(0, 2).map(d => {
                            const rawVal = typeof d === 'string' ? d : d?.value;
                            const preview = (rawVal && String(rawVal).length > 20) ? String(rawVal).substring(0, 20) + '...' : String(rawVal || '')
                            return `${d.type || 'Sensitive'}: ${preview}`;
                        }).join(', ');
                        
                        sensitiveDataDetails += `• Message ${index + 1}: ${dataTypes.join(', ')}${sampleData ? ` (${sampleData})` : ''}<br/>`;
                    });
                    
                    if (sensitiveMessages.length > 3) {
                        sensitiveDataDetails += `• ... and ${sensitiveMessages.length - 3} more messages<br/>`;
                    }
                    
                    sensitiveDataDetails += '</div>';
                    
                    sensitiveDataDetails += `
                        <div style="margin-top: 8px;">
                            <button id="showSensitiveDetails" style="
                                background: none; border: none; color: #856404; 
                                text-decoration: underline; cursor: pointer; font-size: 12px;
                                padding: 0; margin: 0;
                            ">Show detailed breakdown</button>
                        </div>
                        <div id="sensitiveDetails" style="display: none; margin-top: 8px; font-size: 11px; color: #6c757d; max-height: 200px; overflow-y: auto; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            ${sensitiveMessages.map((sm, index) => {
                                const detectedDataArr = sm.detection?.detectedData || sm.detection?.sensitiveFields || [];
                                if ((detectedDataArr?.length || 0) === 0) return '';
                                const dataList = detectedDataArr.map(d => {
                                    const rawVal = typeof d === 'string' ? d : d?.value;
                                    const preview = (rawVal && String(rawVal).length > 30) ? String(rawVal).substring(0, 30) + '...' : String(rawVal || '');
                                    return `• ${d.type || 'Sensitive'}: "${preview}"`;
                                }).join('<br/>');
                                return dataList ? `<strong>Message ${index + 1}:</strong><br/>${dataList}<br/>` : '';
                            }).filter(html => html.length > 0).join('')}
                        </div>
                    `;
                }
            }
            
            warningsHTML += `
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #856404; margin-bottom: 6px;">
                        🔍 Sensitive Data Detected
                    </div>
                    <div style="color: #856404; font-size: 13px;">
                        ${sensitivityAnalysis.sensitiveMsgCount}/${sensitivityAnalysis.totalMessages} messages contain sensitive data<br/>
                        <strong>All sensitive data will be sanitized before sending to AI</strong>
                        ${sensitiveDataDetails}
                    </div>
                </div>
            `;
        } else {
            warningsHTML += `
                <div style="background: #e2f7e1; border: 1px solid #c6efc5; border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #1e7e34; margin-bottom: 6px;">
                        ✅ No Sensitive Data Detected
                    </div>
                    <div style="color: #1e7e34; font-size: 13px;">
                        Messages analyzed: ${sensitivityAnalysis.totalMessages}. Nothing sensitive was found. We will still sanitize before sending.
                    </div>
                </div>
            `;
        }
        
        const costVal = Number(costAnalysis.costEstimate || 0);
        warningsHTML += `
            <div style="background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 6px; padding: 12px; margin-bottom: 12px;">
                <div style="font-weight: 600; color: #0c5460; margin-bottom: 6px;">
                    💰 Estimated Cost
                </div>
                <div style="color: #0c5460; font-size: 13px;">
                    Estimated API cost: <strong>$${costVal.toFixed(4)} USD</strong><br/>
                    ${costAnalysis.tokenEstimate || 0} input tokens · expected output ${costAnalysis.expectedOutputTokens || 0} tokens
                </div>
            </div>
        `;
        
        const safetyMeasures = [
            ...costAnalysis.modifications
        ];
        
        if (sensitivityAnalysis.sensitiveMsgCount > 0) {
            safetyMeasures.push('All sensitive data will be sanitized before sending to LLM');
        }
        
        if (safetyMeasures.length > 0) {
            warningsHTML += `
                <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 12px;">
                    <div style="font-weight: 600; color: #495057; margin-bottom: 6px;">
                        📋 Safety Measures Applied
                    </div>
                    <ul style="margin: 0; padding-left: 18px; color: #6c757d; font-size: 13px;">
                        ${safetyMeasures.map(measure => `<li style="margin-bottom: 4px;">${measure}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        warningsHTML += '</div>';
        
        warningsHTML += `
            <div style="font-size: 14px; color: var(--text-secondary); margin-bottom: 16px;">
                Do you want to proceed with AI analysis using the safety protections shown above?
            </div>
        `;
        
        content.innerHTML = warningsHTML;
        
        const showDetailsBtn = content.querySelector('#showSensitiveDetails');
        const detailsDiv = content.querySelector('#sensitiveDetails');
        if (showDetailsBtn && detailsDiv) {
            showDetailsBtn.addEventListener('click', () => {
                const isVisible = detailsDiv.style.display !== 'none';
                detailsDiv.style.display = isVisible ? 'none' : 'block';
                showDetailsBtn.textContent = isVisible ? 'Show detailed breakdown' : 'Hide detailed breakdown';
            });
        }
        
        const buttonContainer = document.createElement('div');
        buttonContainer.style.cssText = 'display: flex; gap: 12px; justify-content: flex-end;';
        
        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = `
            padding: 8px 16px; border: 1px solid var(--border-color); 
            background: var(--bg-secondary); color: var(--text-primary);
            border-radius: 6px; cursor: pointer; font-size: 14px;
        `;
        
        const proceedBtn = document.createElement('button');
        proceedBtn.textContent = 'Proceed with AI Analysis';
        proceedBtn.style.cssText = `
            padding: 8px 16px; border: none; background: #007bff; color: white;
            border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500;
        `;
        
        const cleanup = () => document.body.removeChild(overlay);
        
        cancelBtn.addEventListener('click', () => {
            cleanup();
            resolve(false);
        });
        
        proceedBtn.addEventListener('click', () => {
            cleanup();
            resolve(true);
        });
        
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                cleanup();
                resolve(false);
            }
        });
        
        buttonContainer.appendChild(cancelBtn);
        buttonContainer.appendChild(proceedBtn);
        modal.appendChild(title);
        modal.appendChild(content);
        modal.appendChild(buttonContainer);
        overlay.appendChild(modal);
        
        console.log('🛡️ [Dialog] Adding modal to DOM...');
        document.body.appendChild(overlay);
        console.log('🛡️ [Dialog] Modal added to DOM successfully');
        
        proceedBtn.focus();
        } catch (error) {
            console.error('❌ [Dialog] Error in showSafetyConsentDialog:', error);
            resolve(false); // Default to cancel if there's an error
        }
    });
}

function createEndpointGroupElement(parentKey, childKeysSet, filterText) {
    const hostElement = document.createElement("div");
    hostElement.className = "endpoint-host";
    
    // Check if group is collapsed
    const isCollapsed = collapsedGroups.has(parentKey);
    if (isCollapsed) {
        hostElement.classList.add('collapsed');
    }

    const hostRow = document.createElement("div");
    hostRow.className = "host-row";
    hostRow.dataset.url = parentKey;
    if (parentKey === window.frogPostState.activeUrl) {
        hostRow.classList.add('active');
    }
    
    // Add collapse/expand button
    const collapseBtn = document.createElement("button");
    collapseBtn.className = "group-collapse-btn";
    collapseBtn.innerHTML = isCollapsed ? "▶" : "▼";
    collapseBtn.title = isCollapsed ? "Expand group" : "Collapse group";
    collapseBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        await toggleGroupCollapse(parentKey);
    });

    const hostName = document.createElement("span");
    hostName.className = "host-name";
    hostName.textContent = parentKey;
    hostName.title = parentKey;

    hostRow.addEventListener("click", async (e) => {
        e.stopPropagation();
        setActiveUrl(parentKey);
        await restoreLastReport(parentKey);
    });

    const parentButtonContainer = createActionButtonContainer(parentKey);

    hostRow.appendChild(collapseBtn);
    hostRow.appendChild(hostName);
    hostRow.appendChild(parentButtonContainer);
    hostElement.appendChild(hostRow);

    const iframeContainer = document.createElement("div");
    iframeContainer.className = "iframe-container";

    const sortedChildKeys = Array.from(childKeysSet).sort();
    let displayedChildrenCount = 0;

    sortedChildKeys.forEach((childKey) => {
        const childMatchesFilter = !filterText || childKey.toLowerCase().includes(filterText);
        let showChild = childMatchesFilter;

        if (showChild) {
            const iframeRow = document.createElement("div");
            iframeRow.className = "iframe-row";
            iframeRow.setAttribute("data-endpoint-key", childKey);
            iframeRow.dataset.url = childKey;
            if (childKey === window.frogPostState.activeUrl) {
                iframeRow.classList.add('active');
            }

            const iframeName = document.createElement("span");
            iframeName.className = "iframe-name";
            iframeName.textContent = childKey;
            iframeName.title = childKey;

            iframeRow.addEventListener("click", async (e) => {
                e.stopPropagation();
                setActiveUrl(childKey);
                await restoreLastReport(childKey);
            });

            const childButtonContainer = createActionButtonContainer(childKey);

            iframeRow.appendChild(iframeName);
            iframeRow.appendChild(childButtonContainer);
            iframeContainer.appendChild(iframeRow);
            displayedChildrenCount++;
        }
    });

    if (displayedChildrenCount > 0) {
        hostElement.appendChild(iframeContainer);
    }

    return hostElement;
}

function updateDashboardUI() {
    const endpointsList = document.getElementById('endpointsList');
    if (!endpointsList) { log.error("Cannot find endpointsList element"); return; }

    const filterInput = document.getElementById('endpointFilterInput');
    const filterText = filterInput ? filterInput.value.toLowerCase().trim() : '';
    const filterContainer = endpointsList.querySelector('.endpoint-filter-container');

    endpointsList.querySelectorAll('.endpoint-host, .no-endpoints').forEach(el => el.remove());


    const groupsByTopLevel = new Map();
    const allKnownKeys = new Set();

    const processedEndpoints = new Set();

    window.frogPostState.messages.forEach(msg => {
        if (msg.origin && msg.origin.startsWith('http://127.0.0.1:1337/')) return;
        if (msg.destinationUrl && msg.destinationUrl.startsWith('http://127.0.0.1:1337/')) return;
        if (msg.topLevelUrl && msg.topLevelUrl.startsWith('http://127.0.0.1:1337/')) return;
        if (msg.topLevelUrl && msg.topLevelUrl.startsWith('chrome-extension://')) return;
        if (isLocalDevUrl(msg.origin)) return;
        if (isLocalDevUrl(msg.destinationUrl)) return;
        if (isLocalDevUrl(msg.topLevelUrl)) return;
        
        if (msg.origin && msg.origin.includes('frogpost_handler_extraction=true')) return;
        if (msg.destinationUrl && msg.destinationUrl.includes('frogpost_handler_extraction=true')) return;
        if (msg.topLevelUrl && msg.topLevelUrl.includes('frogpost_handler_extraction=true')) return;
        
        // Filter out ignored endpoints
        if (msg.origin && isEndpointIgnored(getStorageKeyForUrl(msg.origin))) return;
        if (msg.destinationUrl && isEndpointIgnored(getStorageKeyForUrl(msg.destinationUrl))) return;
        if (msg.topLevelUrl && isEndpointIgnored(getStorageKeyForUrl(msg.topLevelUrl))) return;
        
        if (!msg.topLevelUrl) {
            if(msg.origin) allKnownKeys.add(getStorageKeyForUrl(msg.origin));
            if(msg.destinationUrl) allKnownKeys.add(getStorageKeyForUrl(msg.destinationUrl));
            return;
        }

        const topLevelKey = getStorageKeyForUrl(msg.topLevelUrl);
        if (!topLevelKey || topLevelKey === 'null') return;

        allKnownKeys.add(topLevelKey);

        if (!groupsByTopLevel.has(topLevelKey)) {
            groupsByTopLevel.set(topLevelKey, new Set());
        }
        const relatedEndpoints = groupsByTopLevel.get(topLevelKey);

        const sourceKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
        const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;

        if (sourceKey && sourceKey !== topLevelKey && sourceKey !== 'null' && !isLocalDevUrl(msg.origin)) {
            relatedEndpoints.add(sourceKey);
            allKnownKeys.add(sourceKey);
        }
        if (destKey && destKey !== topLevelKey && destKey !== 'null' && !isLocalDevUrl(msg.destinationUrl)) {
            relatedEndpoints.add(destKey);
            allKnownKeys.add(destKey);
        }
    });

    knownHandlerEndpoints.forEach(key => { if (!isLocalDevUrl(key)) allKnownKeys.add(key); });
    window.frogPostState.loadedData.urls.forEach(url => {
        const key = getStorageKeyForUrl(url);
        if(key && key !== 'null' && !isLocalDevUrl(url) && !isLocalDevUrl(key)) allKnownKeys.add(key);
    });


    const fragment = document.createDocumentFragment();
    let displayedEndpointCount = 0;
    const renderedKeys = new Set();

    // Render Custom URLs group first if it exists
    if (customUrlsList && customUrlsList.length > 0) {
        const customUrlsSet = new Set(customUrlsList.map(url => getStorageKeyForUrl(url)));
        const customUrlsGroupElement = createEndpointGroupElement('Custom URLs', customUrlsSet, filterText);
        if (customUrlsGroupElement) {
            customUrlsGroupElement.classList.add('custom-urls-group');
            fragment.appendChild(customUrlsGroupElement);
            displayedEndpointCount++;
            customUrlsSet.forEach(key => renderedKeys.add(key));
        }
    }

    const sortedTopLevelKeys = Array.from(groupsByTopLevel.keys()).filter(k => !isLocalDevUrl(k)).sort();

    sortedTopLevelKeys.forEach(topLevelKey => {
        if (renderedKeys.has(topLevelKey)) return;

        const childKeysSet = groupsByTopLevel.get(topLevelKey) || new Set();

        const topLevelMatchesFilter = !filterText || topLevelKey.toLowerCase().includes(filterText);
        const childrenMatchFilter = !filterText || Array.from(childKeysSet).some(childKey => childKey.toLowerCase().includes(filterText));

        let showGroup = topLevelMatchesFilter || childrenMatchFilter;

        if (showGroup) {
            const endpointGroupElement = createEndpointGroupElement(topLevelKey, childKeysSet, filterText);
            if (endpointGroupElement) {
                fragment.appendChild(endpointGroupElement);
                displayedEndpointCount++;
                renderedKeys.add(topLevelKey);
                childKeysSet.forEach(childKey => renderedKeys.add(childKey));
            }
        }
    });

    allKnownKeys.forEach(key => {
        if (isLocalDevUrl(key)) return;
        if (!renderedKeys.has(key)) {
            const matchesFilter = !filterText || key.toLowerCase().includes(filterText);
            let showStandalone = matchesFilter;

            if (showStandalone) {
                const endpointGroupElement = createEndpointGroupElement(key, new Set(), filterText);
                if (endpointGroupElement) {
                    fragment.appendChild(endpointGroupElement);
                    displayedEndpointCount++;
                    renderedKeys.add(key);
                }
            }
        }
    });


    let noEndpointsDiv = endpointsList.querySelector('.no-endpoints');
    if (!noEndpointsDiv) { noEndpointsDiv = document.createElement('div'); noEndpointsDiv.className = 'no-endpoints'; /* ... append correctly ... */ if(filterContainer && filterContainer.nextSibling) endpointsList.insertBefore(noEndpointsDiv, filterContainer.nextSibling); else endpointsList.appendChild(noEndpointsDiv); }

    if (displayedEndpointCount > 0) {
        endpointsList.appendChild(fragment);
        noEndpointsDiv.style.display = 'none';
    } else {
        noEndpointsDiv.style.display = 'block';
        const hasAnyData = window.frogPostState.messages.length > 0 || knownHandlerEndpoints.size > 0 || window.frogPostState.loadedData.urls.size > 0;
        if (filterText) {
            noEndpointsDiv.textContent = `No endpoints match active filters.`;
        } else if (hasAnyData) {
            noEndpointsDiv.textContent = "No endpoint groups to display based on captured messages.";
        } else {
            noEndpointsDiv.textContent = "No endpoints captured or listeners found.";
        }
    }

    updateMessageListForUrl(window.frogPostState.activeUrl);
    updateEndpointCounts();
}

function requestUiUpdate() {
    clearTimeout(uiUpdateTimer);
    uiUpdateTimer = setTimeout(updateDashboardUI, DEBOUNCE_DELAY);
}
window.requestUiUpdate = requestUiUpdate;

function updateEndpointCounts() {
    try {
        document.querySelectorAll('#endpointsList .endpoint-host .host-name, #endpointsList .endpoint-host .iframe-name').forEach(el => {
            const url = el.textContent?.replace(/ \(\d+\)$/, '') || '';
            if (!url) return;
            const count = getMessageCount(url);
            el.textContent = `${url} (${count})`;
        });
    } catch(e) {
        log.error("Error updating endpoint counts", e);
    }
}
function initializeMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (!message?.type) return false;
        let needsUiUpdate = false;
        const TEST_MESSAGE_KEY = "FrogPost";
        const TEST_MESSAGE_VALUE = "BreakpointTest";

        try {
            switch (message.type) {
                case "newPostMessage":
                    if (message.payload) {
                        const newMsg = message.payload;
                        let isTestMessage = false;
                        if (typeof newMsg.data === 'object' && newMsg.data !== null && newMsg.data.hasOwnProperty(TEST_MESSAGE_KEY) && newMsg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE) {
                            isTestMessage = true;
                        }

                        if (!isTestMessage) {
                            const existingIndex = window.frogPostState.messages.findIndex(m => m.messageId === newMsg.messageId);
                            const isNewEndpoint = existingIndex < 0;
                            
                            if (existingIndex >= 0) {
                                window.frogPostState.messages[existingIndex] = newMsg;
                            } else {
                                window.frogPostState.messages.push(newMsg);
                            }

                            // Enforce per-iframe message cap (keep last 30 for each destination iframe)
                            try {
                                const destKey = getStorageKeyForUrl(newMsg.destinationUrl || '');
                                if (destKey) {
                                    const indicesForDest = [];
                                    for (let i = 0; i < window.frogPostState.messages.length; i++) {
                                        const msg = window.frogPostState.messages[i];
                                        const key = getStorageKeyForUrl(msg.destinationUrl || '');
                                        if (key === destKey) indicesForDest.push(i);
                                    }
                                    const over = indicesForDest.length - 30;
                                    if (over > 0) {
                                        // Remove oldest entries for this iframe (by array order)
                                        for (let j = 0; j < over; j++) {
                                            const removeIndex = indicesForDest[j] - j; // adjust for prior removals
                                            window.frogPostState.messages.splice(removeIndex, 1);
                                        }
                                    }
                                }
                            } catch (e) { /* ignore */ }
                            needsUiUpdate = true;
                            
                            // Trigger Auto Pilot for new iframe if enabled
                            if (isNewEndpoint && autoPilotEnabled && !urlScanInProgress) {
                                const endpointKey = getStorageKeyForUrl(newMsg.origin || newMsg.destinationUrl);
                                // Skip if already scanned/scanning, is localhost, or currently being scanned
                                if (endpointKey && 
                                    !endpointKey.startsWith('http://127.0.0.1:1337/') && 
                                    !autoPilotScannedEndpoints.has(endpointKey) &&
                                    !autoPilotActiveScans.has(endpointKey)) {
                                    
                                    // Mark as scanning immediately to prevent duplicate triggers
                                    autoPilotScannedEndpoints.add(endpointKey);
                                    autoPilotActiveScans.add(endpointKey); // Per-endpoint lock
                                    
                                    // Persist to storage immediately to prevent duplicate scans on refresh
                                    chrome.storage.sync.set({ 
                                        [AUTOPILOT_SCANNED_KEY]: Array.from(autoPilotScannedEndpoints) 
                                    }).catch(err => log.warn('[Auto Pilot] Failed to save scanned endpoints:', err));
                                    
                                    // Trigger scan immediately (no delay needed with per-endpoint locks)
                                    triggerAutoPilotScan(endpointKey).catch(err => {
                                        log.error(`[Auto Pilot] Failed to auto-scan ${endpointKey}:`, err);
                                    }).finally(() => {
                                        // Release per-endpoint lock when done
                                        autoPilotActiveScans.delete(endpointKey);
                                    });
                                }
                            }
                        }
                    }
                    break;
                case "newFrameConnection":
                    needsUiUpdate = true;
                    break;
                case "updateMessages":
                    if (Array.isArray(message.messages)) {
                        const filteredMessages = message.messages.filter(msg => !(typeof msg.data === 'object' && msg.data !== null && msg.data.hasOwnProperty(TEST_MESSAGE_KEY) && msg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE));
                        window.frogPostState.messages.length = 0;
                        window.frogPostState.messages.push(...filteredMessages);
                        needsUiUpdate = true;
                    }
                    break;
                case "handlerCapturedForEndpoint":
                case "handlerEndpointDetected":
                    if (message.payload?.endpointKey) {
                        const key = message.payload.endpointKey;
                        let addedNew = false;
                        if (!endpointsWithHandlers.has(key)) { endpointsWithHandlers.add(key); addedNew = true; }
                        if (!knownHandlerEndpoints.has(key)) { knownHandlerEndpoints.add(key); addedNew = true; }
                        if(addedNew) needsUiUpdate = true;
                    }
                    break;
            }
            if (needsUiUpdate) requestUiUpdate();
            if (sendResponse) { Promise.resolve().then(() => sendResponse({success: true})); return true; }

        } catch (e) {
            log.error("[Dashboard Msg Handler] Error:", e);
            if (sendResponse) try { sendResponse({ success: false, error: e.message }); } catch(respErr){}
        }
        return true;
    });

    window.traceReportStorage.listAllReports().then(() => {
        chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => {
            if (chrome.runtime.lastError) {
                log.error("[MsgListener] Error receiving fetchInitialState response:", chrome.runtime.lastError.message);
                requestUiUpdate();
                return;
            }
            if (response?.success) {
                const TEST_MESSAGE_KEY = "FrogPost";
                const TEST_MESSAGE_VALUE = "BreakpointTest";
                if (response.messages && Array.isArray(response.messages)) {
                    const filteredMessages = response.messages.filter(msg => !(typeof msg.data === 'object' && msg.data !== null && msg.data.hasOwnProperty(TEST_MESSAGE_KEY) && msg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE));
                    window.frogPostState.messages.length = 0;
                    // Apply per-iframe cap as we ingest initial messages
                    const byDest = new Map();
                    for (const m of filteredMessages) {
                        const key = getStorageKeyForUrl(m.destinationUrl || '');
                        if (!byDest.has(key)) byDest.set(key, []);
                        byDest.get(key).push(m);
                    }
                    const capped = [];
                    byDest.forEach(list => {
                        // Keep last 30 per destination
                        if (list.length > 30) list = list.slice(-30);
                        capped.push(...list);
                    });
                    window.frogPostState.messages.push(...capped);
                }
                if (response.handlerEndpointKeys && Array.isArray(response.handlerEndpointKeys)) {
                    knownHandlerEndpoints.clear();
                    endpointsWithHandlers.clear();
                    response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); });
                }
                requestUiUpdate();
            } else {
                log.error("Failed to fetch initial state:", response?.error);
                requestUiUpdate();
            }
        });
    });
}

function setupCallbackUrl() {
    const urlInput = document.getElementById('callbackUrlInput'); const saveButton = document.getElementById('saveCallbackUrl'); const statusElement = document.getElementById('callback-status'); if (!urlInput || !saveButton || !statusElement) return;
    const updateCallbackStatus = (url, errorMessage = null) => { if (!statusElement) return; statusElement.innerHTML = ''; statusElement.className = 'callback-status'; if (errorMessage) { statusElement.innerHTML = `<div class="error-message">${escapeHTML(errorMessage)}</div>`; statusElement.classList.add('callback-status-error'); } else if (url) { statusElement.innerHTML = `<div class="success-icon">✓</div><div class="status-message">Active (Session): <span class="url-value">${escapeHTML(url)}</span></div>`; statusElement.classList.add('callback-status-success'); } else { statusElement.innerHTML = `<div class="info-message">No callback URL set.</div>`; statusElement.classList.add('callback-status-info'); } };
    chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], (result) => { if (chrome.runtime.lastError) { updateCallbackStatus(null, `Error loading URL`); return; } const storedUrl = result[CALLBACK_URL_STORAGE_KEY] || null; if (storedUrl) { urlInput.value = storedUrl; window.frogPostState.callbackUrl = storedUrl; } updateCallbackStatus(storedUrl); });
    saveButton.addEventListener('click', () => { const url = urlInput.value.trim(); if (!url) { chrome.storage.session.remove(CALLBACK_URL_STORAGE_KEY, () => { window.frogPostState.callbackUrl = null; updateCallbackStatus(null, chrome.runtime.lastError ? 'Error clearing URL' : null); }); } else if (isValidUrl(url)) { chrome.storage.session.set({ [CALLBACK_URL_STORAGE_KEY]: url }, () => { window.frogPostState.callbackUrl = url; updateCallbackStatus(url, chrome.runtime.lastError ? 'Error saving URL' : null); }); } else updateCallbackStatus(window.frogPostState.callbackUrl, 'Invalid URL format.'); });
}

function setupUIControls() {
    document.getElementById("clearMessages")?.addEventListener("click", async () => { 
        log.info("Clearing ALL extension data..."); 
        
        window.frogPostState.messages.length = 0; 
        window.frogPostState.activeUrl = null; 
        buttonStates.clear(); 
        traceButtonStates.clear(); 
        reportButtonStates.clear(); 
        endpointsWithHandlers.clear(); 
        knownHandlerEndpoints.clear(); 
        launchInProgressEndpoints.clear(); 
        
        await new Promise(resolve => {
            chrome.storage.local.clear(() => {
                log.info("Chrome local storage cleared.");
                resolve();
            });
        });
        
        await new Promise(resolve => {
            chrome.storage.session.clear(() => {
                log.info("Chrome session storage cleared.");
                resolve();
            });
        });
        
        try {
            if (window.traceReportStorage) {
                await window.traceReportStorage.clearAllData();
                log.info("IndexedDB trace reports cleared.");
            }
        } catch (e) {
            log.warn("Error clearing IndexedDB:", e);
        }
        
        try {
            localStorage.clear();
            log.info("localStorage cleared.");
        } catch (e) {
            log.warn("Error clearing localStorage:", e);
        }
        
        try {
            sessionStorage.clear();
            log.info("sessionStorage cleared.");
        } catch (e) {
            log.warn("Error clearing sessionStorage:", e);
        }
        
        chrome.runtime.sendMessage({ type: "resetState" }, (response) => {
            log.info("Background state reset.");
        });
        
        if (window.FuzzingPayloads && window.FuzzingPayloads._originalXSS) {
            window.FuzzingPayloads.XSS = [...window.FuzzingPayloads._originalXSS];
        }
        
        log.success("All extension data cleared successfully!");
        requestUiUpdate(); 
    });
    document.getElementById("exportMessages")?.addEventListener("click", () => { const sanitizedMessages = window.frogPostState.messages.map(msg => ({ origin: msg.origin, destinationUrl: msg.destinationUrl, timestamp: msg.timestamp, data: sanitizeMessageData(msg.data), messageType: msg.messageType, messageId: msg.messageId })); const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "frogpost_messages.json"; a.click(); URL.revokeObjectURL(url); });
 const debugButton = document.getElementById("debugToggle"); if (debugButton) { debugButton.addEventListener("click", toggleDebugMode); debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF'; debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off'; }
    document.getElementById("refreshMessages")?.addEventListener("click", () => { chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => { if (response?.success) { if (response.messages) { window.frogPostState.messages.length = 0; window.frogPostState.messages.push(...response.messages); } if (response.handlerEndpointKeys) { knownHandlerEndpoints.clear(); endpointsWithHandlers.clear(); response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); }); } log.info("Dashboard refreshed."); requestUiUpdate(); } else log.error("Failed refresh:", response?.error); }); });
    const uploadPayloadsButton = document.getElementById("uploadCustomPayloadsBtn"); const payloadFileInput = document.getElementById("customPayloadsFile"); if(uploadPayloadsButton && payloadFileInput){ uploadPayloadsButton.addEventListener('click', () => payloadFileInput.click()); payloadFileInput.addEventListener('change', handlePayloadFileSelect); }
    document.getElementById("clearCustomPayloadsBtn")?.addEventListener('click', clearCustomPayloads);
    
    // Auto Pilot & URL List button listeners
    document.getElementById("uploadUrlListBtn")?.addEventListener("click", showUploadUrlModal);
    document.getElementById("autoPilotToggle")?.addEventListener("click", toggleAutoPilot);
    document.getElementById("openOptionsBtn")?.addEventListener("click", () => { if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage(); else window.open(chrome.runtime.getURL("../options/options.html")); });
    const debuggerModeBtn = document.getElementById('toggleDebuggerApiMode');
    if (debuggerModeBtn) {
        debuggerModeBtn.addEventListener('click', async () => {
            const newState = !debuggerApiModeEnabled;
            if (newState === true) {
                const warningMessage = "WARNING:\n\nEnabling Debugger Mode will attach the browser's debugger to newly loaded web pages.\n\n- This WILL trigger a warning bar in the target tabs unless you launched Brave/Chrome with specific flags (--silent-debugger-extension-api).\n- It may significantly impact browser performance.\n- Use only for specific research or debugging purposes in controlled environments.\n\nDo you want to proceed?";
                if (!confirm(warningMessage)) {
                    return;
                }
            }
            debuggerApiModeEnabled = newState;
            updateDebuggerModeButton();
            try {
                await chrome.storage.local.set({ [DEBUGGER_MODE_STORAGE_KEY]: debuggerApiModeEnabled });
                // setDebuggerMode message handler removed from background
                log.info(`Debugger API Mode ${debuggerApiModeEnabled ? 'ENABLED' : 'DISABLED'}`);
                showToastNotification(`Debugger Mode ${debuggerApiModeEnabled ? 'Enabled' : 'Disabled'}`, debuggerApiModeEnabled ? 'warning' : 'info');
            } catch (error) {
                log.error("Error setting debugger mode state:", error);
                showToastNotification("Error updating debugger mode", "error");
                debuggerApiModeEnabled = !newState;
                updateDebuggerModeButton();
            }
        });
    }
    setupCallbackUrl();
    updatePayloadStatus();
}

async function handlePayloadFileSelect(event) {
    const file = event.target.files[0]; const statusElement = document.getElementById("customPayloadStatus"); if (!file || !file.name.toLowerCase().endsWith('.txt')) { showToastNotification('Invalid file type (.txt only).', 'error'); if (statusElement) statusElement.textContent = 'Upload: Invalid file type.'; event.target.value = null; return; }
    const reader = new FileReader(); reader.onload = (e) => { validateAndStorePayloads(e.target.result); event.target.value = null; }; reader.onerror = () => { showToastNotification('Error reading file.', 'error'); if (statusElement) statusElement.textContent = 'Upload: Error reading file.'; event.target.value = null; }; reader.readAsText(file);
}

function validateAndStorePayloads(content) {
    const lines = content.split('\n'); const payloads = lines.map(line => line.trim()).filter(line => line.length > 0); if (payloads.length === 0) { showToastNotification('No valid payloads found.', 'warning'); updatePayloadStatus(false, 0); return; }
    chrome.storage.session.set({ customXssPayloads: payloads }, () => { if (chrome.runtime.lastError) { showToastNotification(`Error saving payloads`, 'error'); updatePayloadStatus(false, 0); } else { try { localStorage.setItem('customXssPayloads', JSON.stringify(payloads)); } catch (e) {} if (window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...payloads]; } showToastNotification(`Stored ${payloads.length} custom payloads.`, 'success'); updatePayloadStatus(true, payloads.length); } });
}

function updatePayloadStatus(isActive = null, count = 0) {
    const statusElement = document.getElementById("customPayloadStatus"); const uploadButton = document.getElementById("uploadCustomPayloadsBtn"); const clearButton = document.getElementById("clearCustomPayloadsBtn");
    const updateUI = (active, payloadCount) => { if (statusElement) { statusElement.textContent = active ? `Custom Payloads Active (${payloadCount})` : 'Using Default Payloads'; statusElement.style.color = active ? 'var(--accent-primary)' : 'var(--text-secondary)'; } if (uploadButton) uploadButton.textContent = active ? 'Update Payloads' : 'Upload Payloads'; if (clearButton) clearButton.style.display = active ? 'inline-block' : 'none'; };
    if (isActive !== null) updateUI(isActive, count); else chrome.storage.session.get('customXssPayloads', (result) => { const storedPayloads = result.customXssPayloads; const active = storedPayloads && storedPayloads.length > 0; updateUI(active, active ? storedPayloads.length : 0); });
}

function clearCustomPayloads() {
    chrome.storage.session.remove('customXssPayloads', () => { if (chrome.runtime.lastError) showToastNotification(`Error clearing payloads`, 'error'); else { try { localStorage.removeItem('customXssPayloads'); } catch (e) {} if (window.FuzzingPayloads && window.FuzzingPayloads._originalXSS) window.FuzzingPayloads.XSS = [...window.FuzzingPayloads._originalXSS]; showToastNotification('Custom payloads cleared.', 'info'); updatePayloadStatus(false, 0); } });
}

async function launchFuzzerEnvironment(targetUrl, handlerCode, messages, payloads, traceReportData, fuzzerOptions, analysisKeyForReport) {
    let serverStarted = false;
    try {
        if (!analysisKeyForReport) throw new Error("Internal error: Missing analysis key for launching fuzzer.");
        if (!traceReportData) throw new Error(`Internal error: Trace report data missing.`);
        if (!targetUrl || !handlerCode || !messages || !payloads || !fuzzerOptions) throw new Error("Internal error: Missing data for launching fuzzer.");

        await chrome.runtime.sendMessage({ type: "startServer" });
        await new Promise(resolve => setTimeout(resolve, 1500));
        let attempts = 0;
        while (!serverStarted && attempts < 3) {
            attempts++;
            try { const health = await fetch('http://127.0.0.1:1337/health', { method: 'GET', cache: 'no-store', signal: AbortSignal.timeout(800) }); if (health.ok) serverStarted = true; else await new Promise(r => setTimeout(r, 700)); } catch(err) { await new Promise(r => setTimeout(r, 700)); }
        }
        if (!serverStarted) throw new Error("Fuzzer server did not start.");

        const config = {
            target: targetUrl,
            messages: messages, // Assuming messages are already simple objects/strings
            handler: handlerCode,
            payloads: payloads, // Assuming payloads are simple objects/strings
            traceData: {
                endpoint: traceReportData.endpoint,
                originalEndpointKey: traceReportData.originalEndpointKey,
                analysisStorageKey: traceReportData.analysisStorageKey,
                timestamp: traceReportData.timestamp,
                securityScore: traceReportData.securityScore,
                details: {
                    payloadsGeneratedCount: traceReportData.details?.payloadsGeneratedCount,
                    uniqueStructures: traceReportData.details?.uniqueStructures, // Might need sanitization if examples contain complex objects
                    staticAnalysisUsed: traceReportData.details?.staticAnalysisUsed,
                    messagesAvailable: traceReportData.details?.messagesAvailable,
                },
                summary: traceReportData.summary // Summary should be safe
            },
            callbackUrl: fuzzerOptions.callbackUrl,
            fuzzerOptions: {
                autoStart: fuzzerOptions.autoStart,
                useCustomPayloads: fuzzerOptions.useCustomPayloads,
                enableCallbackFuzzing: fuzzerOptions.enableCallbackFuzzing
            }
        };

        log.debug("[Launch Fuzzer Env] Sending sanitized config:", config);

        const response = await fetch('http://127.0.0.1:1337/current-config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config), signal: AbortSignal.timeout(5000) }); // Stringify the sanitized config
        if (!response.ok) { const errorText = await response.text(); throw new Error(`Config update failed: ${response.statusText} - ${errorText}`); }

        const tab = await chrome.tabs.create({ url: 'http://127.0.0.1:1337/' });
        const cleanupListener = (tabId, removeInfo) => { if (tabId === tab.id) { chrome.runtime.sendMessage({ type: "stopServer" }).catch(e => {}); chrome.tabs.onRemoved.removeListener(cleanupListener); } };
        chrome.tabs.onRemoved.addListener(cleanupListener);
        return true;
    } catch (error) {
        log.error("[Launch Fuzzer Env] Caught error:", error);
        alert(`Fuzzer Launch Failed: ${error.message}`);
        if (serverStarted === false) try { await chrome.runtime.sendMessage({ type: "stopServer" }); } catch {}
        return false;
    }
}

async function saveRandomPostMessages(endpointKey, messagesToSave = null) {
    const MAX_MESSAGES = 20; let relevantMessages = [];
    if (messagesToSave && Array.isArray(messagesToSave)) relevantMessages = messagesToSave; else relevantMessages = window.frogPostState.messages.filter(msg => { if (!msg?.origin || !msg?.destinationUrl) return false; const originKey = getStorageKeyForUrl(msg.origin); const destKey = getStorageKeyForUrl(msg.destinationUrl); return originKey === endpointKey || destKey === endpointKey; });
    relevantMessages = relevantMessages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, MAX_MESSAGES); const processedMessages = relevantMessages.map(msg => { if (!msg.messageType) { let messageType = 'unknown'; let data = msg.data; if (data === undefined || data === null) messageType = 'null_or_undefined'; else if (typeof data === 'string') { try { JSON.parse(data); messageType = 'json_string'; } catch { messageType = 'string'; } } else if (Array.isArray(data)) messageType = 'array'; else if (typeof data === 'object') messageType = 'object'; else messageType = typeof data; return {...msg, messageType: messageType}; } return msg; });
    const storageKey = `saved-messages-${endpointKey}`; try { if (processedMessages.length > 0) await chrome.storage.local.set({ [storageKey]: processedMessages }); else await chrome.storage.local.remove(storageKey); return processedMessages; } catch (error) { log.error("Failed to save messages:", error); try { await chrome.storage.local.remove(storageKey); } catch {} return []; }
}

async function retrieveMessagesWithFallbacks(primaryKey, originalKey = null) {
    const storageKey = `saved-messages-${primaryKey}`;
    let messages = [];
    const keyToLog = originalKey || primaryKey;

    try {
        const result = await new Promise((resolve, reject) => {
            chrome.storage.local.get(storageKey, (storageResult) => {
                if (chrome.runtime.lastError) {
                    log.warn(`[RetrieveMessages] Error getting from storage key ${storageKey}:`, chrome.runtime.lastError.message);
                    resolve(null);
                } else {
                    resolve(storageResult?.[storageKey] || null);
                }
            });
        });
        if (result && Array.isArray(result) && result.length > 0) {
            log.debug(`[RetrieveMessages] Retrieved ${result.length} messages from storage key ${storageKey} (for endpoint ${keyToLog})`);
            messages = result;
        }
    } catch (e) {
        log.error(`[RetrieveMessages] Error accessing storage for key ${storageKey} (for endpoint ${keyToLog}):`, e);
    }

    const retrievedMessageIds = new Set(messages.map(m => m.messageId));
    const globalMessages = window.frogPostState.messages || [];

    if(globalMessages.length > 0) {
        log.debug(`[RetrieveMessages] Filtering ${globalMessages.length} global messages for endpoint ${keyToLog} using keys: Primary='${primaryKey}'${originalKey ? `, Original='${originalKey}'` : ''}`);
        const fallbackKeys = new Set([primaryKey]);
        if (originalKey && originalKey !== primaryKey) {
            fallbackKeys.add(originalKey);
        }

        const filteredGlobalMessages = globalMessages.filter(msg => {
            if (!msg || retrievedMessageIds.has(msg.messageId)) return false;
            const originKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
            const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
            const originMatches = originKey && fallbackKeys.has(originKey);
            const destMatches = destKey && fallbackKeys.has(destKey);
            return originMatches || destMatches;
        });

        if(filteredGlobalMessages.length > 0){
            log.debug(`[RetrieveMessages] Found ${filteredGlobalMessages.length} additional messages from global state for endpoint ${keyToLog}.`);
            messages.push(...filteredGlobalMessages);
            filteredGlobalMessages.forEach(m => retrievedMessageIds.add(m.messageId));
        } else {
            log.debug(`[RetrieveMessages] No additional messages found in global state for endpoint ${keyToLog}.`);
        }
    }


    if (messages.length === 0) {
        log.warn(`[RetrieveMessages] Retrieved 0 relevant messages for endpoint ${keyToLog} (Primary Key: ${primaryKey})`);
    }

    return messages.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
}
window.retrieveMessagesWithFallbacks = retrieveMessagesWithFallbacks;

async function showUrlModificationModal(originalUrl, failureReason) {
    return new Promise((resolve) => { const modalContainer = document.getElementById('urlModificationModalContainer'); if (!modalContainer) { resolve({ action: 'cancel', modifiedUrl: null }); return; } modalContainer.innerHTML = ''; const backdrop = document.createElement('div'); backdrop.className = 'modal-backdrop'; const modal = document.createElement('div'); modal.className = 'url-modification-modal'; let currentUrl = new URL(originalUrl); const params = new URLSearchParams(currentUrl.search); let paramInputs = {}; let paramsHTML = ''; if (Array.from(params.keys()).length > 0) { params.forEach((value, key) => { const inputId = `param-input-${key}`; paramsHTML += `<div class="url-param-row"><label for="${inputId}" class="url-param-label">${escapeHTML(key)}:</label><input type="text" id="${inputId}" class="url-param-input" value="${escapeHTML(value)}"></div>`; paramInputs[key] = inputId; }); } else paramsHTML = '<p class="url-modal-no-params">No query parameters found.</p>'; modal.innerHTML = `<div class="url-modal-header"><h4>Embedding Check Failed - Modify URL?</h4><button class="close-modal-btn">&times;</button></div><div class="url-modal-body"><p class="url-modal-reason"><strong>Reason:</strong> ${escapeHTML(failureReason)}</p><p class="url-modal-original"><strong>Original URL:</strong> <span class="url-display">${escapeHTML(originalUrl)}</span></p><hr><h5 class="url-modal-params-title">Edit Query Parameters:</h5><div class="url-params-editor">${paramsHTML}</div></div><div class="url-modal-footer"><button id="urlCancelBtn" class="control-button secondary-button">Cancel Analysis</button><button id="urlContinueBtn" class="control-button secondary-button orange-button">Analyze Original Anyway</button><button id="urlRetryBtn" class="control-button primary-button">Modify & Retry Analysis</button></div>`; modalContainer.appendChild(backdrop); modalContainer.appendChild(modal); const closeModal = (result) => { modalContainer.innerHTML = ''; resolve(result); }; modal.querySelector('.close-modal-btn').addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); backdrop.addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); modal.querySelector('#urlCancelBtn').addEventListener('click', () => closeModal({ action: 'cancel', modifiedUrl: null })); modal.querySelector('#urlContinueBtn').addEventListener('click', () => closeModal({ action: 'continue', modifiedUrl: originalUrl })); modal.querySelector('#urlRetryBtn').addEventListener('click', () => { const newParams = new URLSearchParams(); let changed = false; params.forEach((originalValue, key) => { const inputElement = document.getElementById(paramInputs[key]); const newValue = inputElement ? inputElement.value : originalValue; newParams.set(key, newValue); if (newValue !== originalValue) changed = true; }); if (!changed) { showToastNotification("No parameters were changed.", "info", 3000); return; } currentUrl.search = newParams.toString(); const modifiedUrlString = currentUrl.toString(); if (!isValidUrl(modifiedUrlString)) { showToastNotification("Modified URL is invalid.", "error", 4000); return; } closeModal({ action: 'retry', modifiedUrl: modifiedUrlString }); }); });
}
/**
 * CSP Header Checker - validates if iframe embedding will be allowed
 */
async function checkCSPHeaders(url) {
    try {
        log.info(`[CSP Check] Checking framing headers for: ${url}`);
        let finalStatus = { canEmbed: true, reason: 'No blocking headers found', headers: {}, warnings: [], testedAncestors: [] };
        let finalUrl = url; // Track final URL after redirects
        let response = null;

        // OPTIMIZED: Try HEAD/GET first (fast, no tab opening), only use debugger if needed
        log.debug(`[CSP Check] Trying HEAD/GET request first (optimized path)...`);
        let headResponse = null;
        try {
            headResponse = await fetch(url, {
                method: 'HEAD',
                mode: 'cors',
                credentials: 'omit',
                signal: AbortSignal.timeout(3000)
            });
            
            // Check if we got CSP/XFO headers from HEAD
            const hasCspHeaders = headResponse.headers.get('content-security-policy') || headResponse.headers.get('x-frame-options');
            
            if (headResponse.ok && hasCspHeaders) {
                log.debug(`[CSP Check] ✓ Got headers from HEAD request (fast path)`);
                response = headResponse;
            }
        } catch (e) {
            log.debug(`[CSP Check] HEAD failed: ${e.message}`);
        }
        
        // If HEAD didn't work or didn't get headers, use debugger API
        if (!response || !response.ok) {
            log.debug(`[CSP Check] Falling back to debugger API for accurate redirect tracking...`);
            const debugResult = await new Promise(resolve => {
                try { chrome.runtime.sendMessage({ type: 'fetchResponseHeaders', url }, resolve); } catch (e) { resolve(null); }
            });
            
            if (debugResult && debugResult.success) {
                // Use debugger result as primary source
                finalStatus.headers = Object.assign({}, finalStatus.headers, debugResult.headers || {});
                
                // CRITICAL: Use finalUrl from debugger if redirects occurred
                if (debugResult.finalUrl && debugResult.finalUrl !== url) {
                    finalUrl = debugResult.finalUrl;
                    log.warn(`[CSP Check] ⚠️ REDIRECT DETECTED: ${url} → ${finalUrl}`);
                    finalStatus.warnings.push(`URL redirected from ${url} to ${finalUrl}`);
                    if (debugResult.redirectChain && debugResult.redirectChain.length > 0) {
                        const chain = debugResult.redirectChain.map(r => `${r.status}: ${r.to}`).join(' → ');
                        log.info(`[CSP Check] Redirect chain: ${chain}`);
                    }
                }
                
                // Build a synthetic response-like reader
                const lower = key => key && (key.toLowerCase ? key.toLowerCase() : String(key).toLowerCase());
                const getHeader = name => debugResult.headers[lower(name)] || debugResult.headers[name] || null;
                response = {
                    ok: true,
                    headers: { get: getHeader }
                };
            } else {
                // Debugger failed, try GET as final fallback
                log.warn(`[CSP Check] Debugger API failed: ${debugResult?.error || 'unknown error'}. Trying GET...`);
                try {
                    const getResponse = await fetch(url, {
                        method: 'GET',
                        mode: 'cors',
                        credentials: 'omit',
                        signal: AbortSignal.timeout(5000)
                    });
                    
                    if (getResponse.ok) {
                        response = getResponse;
                        if (getResponse.url && getResponse.url !== url) {
                            finalUrl = getResponse.url;
                            log.warn(`[CSP Check] ⚠️ REDIRECT DETECTED (GET): ${url} → ${finalUrl}`);
                            finalStatus.warnings.push(`URL redirected from ${url} to ${finalUrl}`);
                        }
                    }
                } catch (getError) {
                    log.warn(`[CSP Check] GET request also failed: ${getError.message}.`);
                }
            }
        }
        
        // Store final URL for later use
        finalStatus.finalUrl = finalUrl;
        if (!response || !response.ok) {
            log.error(`[CSP Check] Unable to read headers via any method`);
            finalStatus.canEmbed = false;
            finalStatus.reason = `Network error: Could not retrieve headers`;
            return finalStatus;
        }

        // Build set of ancestor origins to test against frame-ancestors
        // CRITICAL: Use finalUrl (after redirects), not original url
        const resourceOrigin = new URL(finalUrl).origin;
        log.info(`[CSP Check] Resource origin (after redirects): ${resourceOrigin}`);
        const testedAncestors = new Set();
        testedAncestors.add(window.location.origin);
        try {
            const override = typeof localStorage !== 'undefined' ? localStorage.getItem('frogpost_parent_origin_override') : null;
            if (override) { const o = new URL(override).origin; if (o) testedAncestors.add(o); }
        } catch (_) {}
        finalStatus.testedAncestors = Array.from(testedAncestors);

        // 3. Record X-Frame-Options (legacy); decide later if no CSP FA is present
        let xfo = response.headers.get('x-frame-options') || response.headers.get('X-Frame-Options');
        let xfoDecision = null;
        if (xfo) {
            const xfoLower = xfo.toLowerCase();
            finalStatus.headers['X-Frame-Options'] = xfoLower;
            if (xfoLower === 'deny') {
                xfoDecision = { canEmbed: false, reason: 'X-Frame-Options: DENY' };
            } else if (xfoLower === 'sameorigin') {
                const sameOrigin = Array.from(testedAncestors).some(a => a === resourceOrigin);
                xfoDecision = sameOrigin ? { canEmbed: true, reason: 'X-Frame-Options: SAMEORIGIN (same-origin)' } : { canEmbed: false, reason: 'X-Frame-Options: SAMEORIGIN (cross-origin)' };
            }
        }

        // Get CSP header (already retrieved by debugger or fetch)
        let cspHeader = response.headers.get('content-security-policy') || response.headers.get('Content-Security-Policy');
        
        // CRITICAL: Check for meta refresh redirects (client-side redirects via HTML)
        // These won't show up as HTTP redirects but will cause the iframe to navigate
        if (finalStatus.headers && !finalUrl.startsWith('chrome-extension://')) {
            try {
                log.debug(`[CSP Check] Checking for meta refresh redirects...`);
                const htmlResponse = await fetch(finalUrl, {
                    method: 'GET',
                    mode: 'cors',
                    credentials: 'omit',
                    signal: AbortSignal.timeout(5000)
                });
                const htmlContent = await htmlResponse.text();
                
                // Match: <meta http-equiv="refresh" content="0; url=https://example.com/" />
                const metaRefreshMatch = htmlContent.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']([^"']+)["'][^>]*>/i);
                if (metaRefreshMatch) {
                    const content = metaRefreshMatch[1];
                    const urlMatch = content.match(/url=([^;]+)/i);
                    if (urlMatch) {
                        const metaRefreshUrl = urlMatch[1].trim();
                        try {
                            const absoluteMetaUrl = new URL(metaRefreshUrl, finalUrl).href;
                            if (absoluteMetaUrl !== finalUrl) {
                                log.warn(`[CSP Check] ⚠️ META REFRESH DETECTED: ${finalUrl} → ${absoluteMetaUrl}`);
                                finalStatus.warnings.push(`Meta refresh redirect from ${finalUrl} to ${absoluteMetaUrl}`);
                                
                                // RECURSIVELY check CSP on the meta refresh destination
                                log.info(`[CSP Check] Recursively checking CSP on meta refresh destination...`);
                                const metaRefreshResult = await checkCSPHeaders(absoluteMetaUrl);
                                
                                // Use the most restrictive result
                                if (!metaRefreshResult.canEmbed) {
                                    finalStatus.canEmbed = false;
                                    finalStatus.reason = `Meta refresh destination blocked: ${metaRefreshResult.reason}`;
                                    finalStatus.finalUrl = absoluteMetaUrl;
                                    finalStatus.warnings.push(...metaRefreshResult.warnings);
                                    log.warn(`[CSP Check] Meta refresh destination ${absoluteMetaUrl} blocks embedding`);
                                } else {
                                    finalStatus.warnings.push(`Meta refresh destination ${absoluteMetaUrl} allows embedding`);
                                }
                            }
                        } catch (e) {
                            log.warn(`[CSP Check] Failed to parse meta refresh URL: ${metaRefreshUrl}`, e.message);
                        }
                    }
                }
            } catch (e) {
                log.debug(`[CSP Check] Meta refresh check failed: ${e.message}`);
            }
        }

        // 4. Check for Content-Security-Policy (modern)
        if (cspHeader) {
            finalStatus.headers['Content-Security-Policy'] = cspHeader;
            const frameAncestorsMatch = cspHeader.match(/frame-ancestors\s+([^;]+)/i);
            if (frameAncestorsMatch) {
                const faRaw = frameAncestorsMatch[1].trim();
                const tokens = faRaw.split(/\s+/).filter(Boolean);
                const tokensLower = tokens.map(t => t.toLowerCase());

                const hasNone = tokensLower.includes("'none'");
                const hasStar = tokensLower.includes('*');
                const hasSelf = tokensLower.includes("'self'");
                const parentOrigins = Array.from(testedAncestors);

                const matchHostSource = (parentOrigin, sourceToken) => {
                    try {
                        const p = new URL(parentOrigin);
                        const s = sourceToken;
                        if (/^[a-z]+:$/i.test(s)) { return (p.protocol === s.toLowerCase()); }
                        const hasScheme = /^[a-z]+:\/\//i.test(s);
                        const originToTest = hasScheme ? s : `https://${s}`;
                        const su = new URL(originToTest);
                        if (hasScheme && su.protocol !== p.protocol) return false;
                        const sh = su.hostname.toLowerCase();
                        const ph = p.hostname.toLowerCase();
                        if (sh.startsWith('*.')) { const bare = sh.slice(2); return ph === bare || ph.endsWith(`.${bare}`); }
                        return ph === sh;
                    } catch(_) { return false; }
                };

                let allowed = false;
                if (hasNone) allowed = false;
                else if (hasStar) allowed = true;
                else {
                    allowed = parentOrigins.some(parentOrigin => {
                        if (hasSelf && parentOrigin === resourceOrigin) return true;
                        return tokensLower.some(tok => tok !== "'self'" && matchHostSource(parentOrigin, tok));
                    });
                }

                if (!allowed) {
                    finalStatus.canEmbed = false;
                    finalStatus.reason = `CSP frame-ancestors restricts embedding`;
                    finalStatus.warnings.push(`frame-ancestors evaluated against ancestors ${parentOrigins.join(', ')} with tokens [${tokens.join(' ')}]`);
                } else {
                    finalStatus.canEmbed = true;
                    finalStatus.reason = `CSP frame-ancestors allows embedding for at least one ancestor`;
                }

                if (xfo) {
                    finalStatus.warnings.push('CSP frame-ancestors present: user agents ignore X-Frame-Options.');
                }
            }
        }

        // Note: Meta CSP tags are ignored (they don't support frame-ancestors anyway)
        
        // 5. If CSP lacked frame-ancestors, apply XFO decision
        if (!/frame-ancestors\s+[^;]+/i.test(cspHeader || '')) {
            if (xfoDecision) { finalStatus.canEmbed = xfoDecision.canEmbed; finalStatus.reason = xfoDecision.reason; }
        }

        // Add redirect warning to reason if URL changed
        if (finalUrl !== url) {
            finalStatus.reason = `${finalStatus.reason} (URL redirected to ${finalUrl})`;
        }
        
        log.success(`[CSP Check] Final status for ${url}:`, finalStatus);
        if (finalUrl !== url) {
            log.warn(`[CSP Check] ⚠️ IMPORTANT: CSP evaluated on redirected URL: ${finalUrl}`);
        }
        return finalStatus;

    } catch (error) {
        log.error(`[CSP Check] Unexpected error for ${url}: ${error.message}`, error);
        return {
            canEmbed: false,
            reason: `Unexpected error during check: ${error.message}`,
            headers: {},
            warnings: []
        };
    }
}

// Timeout configuration for Play extraction process
const PLAY_TIMEOUT_MS = 45000; // 45 seconds total timeout per endpoint

// Wrapper function with timeout and failed endpoint check
async function handlePlayButtonWithTimeout(endpoint, button, skipCheck = false, silentMode = false, hideFromUser = false) {
    const endpointKey = button.getAttribute('data-endpoint') || endpoint;
    
    // Check if endpoint previously failed
    const failureInfo = isEndpointFailed(endpointKey);
    if (failureInfo) {
        const elapsed = Math.round((Date.now() - failureInfo.timestamp) / 1000 / 60);
        log.warn(`[Play] Skipping ${endpointKey} - previously failed: ${failureInfo.reason} (${elapsed}m ago)`);
        
        updateButton(button, 'error', { 
            errorMessage: `Skipped: ${failureInfo.reason}`,
            previouslyFailed: true
        });
        
        if (!silentMode && !hideFromUser) {
            showToastNotification(`⏭️ Skipped (failed ${elapsed}m ago): ${failureInfo.reason}`, 'warning', 4000);
        }
        return;
    }
    
    // Wrap the actual handler with a timeout
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Timeout: Play extraction exceeded ${PLAY_TIMEOUT_MS / 1000}s`)), PLAY_TIMEOUT_MS);
    });
    
    try {
        await Promise.race([
            handlePlayButton(endpoint, button, skipCheck, silentMode, hideFromUser),
            timeoutPromise
        ]);
    } catch (error) {
        if (error.message.includes('Timeout')) {
            log.error(`[Play] Timeout for ${endpointKey}: ${error.message}`);
            await markEndpointAsFailed(endpointKey, 'Timeout (45s exceeded)');
            updateButton(button, 'error', { errorMessage: 'Timeout (45s)' });
            if (!silentMode && !hideFromUser) {
                showToastNotification(`⏱️ Timeout: ${endpointKey} took too long`, 'error', 5000);
            }
        } else {
            // Re-throw non-timeout errors
            throw error;
        }
    }
}

async function handlePlayButton(endpoint, button, skipCheck = false, silentMode = false, hideFromUser = false) {
    const originalFullEndpoint = endpoint;
    const endpointKey = button.getAttribute('data-endpoint');
    if (!endpointKey) {
        log.error("[Play Button] No endpoint key found.");
        updateButton(button, 'error');
        return;
    }
    if (launchInProgressEndpoints.has(endpointKey)) return;

    const currentStateInfo = buttonStates.get(endpointKey);

    if (currentStateInfo?.state === 'launch') {
        launchInProgressEndpoints.add(endpointKey);
        let launchSuccess = false;
        try {
            if (!hideFromUser) {
                updateButton(button, 'launching', currentStateInfo.options);
                showToastNotification("Preparing Fuzzer Environment...", "info", 3000);
            }
            const successfulUrlStorageKey = `successful-url-${endpointKey}`;
            let successfulUrlResult = await new Promise(resolve => chrome.storage.local.get(successfulUrlStorageKey, resolve));
            let successfulUrl = successfulUrlResult[successfulUrlStorageKey];
            let analysisKeyToUse = successfulUrl ? getStorageKeyForUrl(successfulUrl) : null;

            if (!analysisKeyToUse) {
                const mappingKey = `analyzed-url-for-${endpointKey}`;
                const mappingResult = await new Promise(resolve => chrome.storage.local.get(mappingKey, resolve));
                if (mappingResult && mappingResult[mappingKey]) {
                    analysisKeyToUse = mappingResult[mappingKey];
                    const mappedSuccessfulUrlKey = `successful-url-${analysisKeyToUse}`;
                    successfulUrlResult = await new Promise(resolve => chrome.storage.local.get(mappedSuccessfulUrlKey, resolve));
                    successfulUrl = successfulUrlResult[mappedSuccessfulUrlKey] || analysisKeyToUse;
                } else {
                    analysisKeyToUse = endpointKey;
                    successfulUrl = originalFullEndpoint;
                }
            }
            if (!successfulUrl) successfulUrl = analysisKeyToUse;


            const [traceReport, storedPayloads, storedMessages] = await Promise.all([
                window.traceReportStorage.getTraceReport(analysisKeyToUse),
                window.traceReportStorage.getReportPayloads(analysisKeyToUse),
                retrieveMessagesWithFallbacks(analysisKeyToUse, endpointKey)
            ]);


            if (!traceReport) throw new Error(`No trace report found for analysis key ${analysisKeyToUse}. Run Play & Trace again.`);
            let handlerCode = traceReport?.analyzedHandler?.handler || traceReport?.analyzedHandler?.code;
            if (!handlerCode) {
                try {
                    const bestKey = `best-handler-${analysisKeyToUse}`;
                    const bestStore = await new Promise(resolve => chrome.storage.local.get([bestKey], resolve));
                    const best = bestStore[bestKey];
                    handlerCode = best?.handler || best?.code || '';
                } catch {}
            }
            if (!handlerCode) {
                showToastNotification('Handler not available. Please run Play again to capture the handler.', 'warning');
                updateButton(button, 'error', { ...currentStateInfo?.options, errorMessage: 'Missing handler' });
                launchSuccess = false;
                return;
            }

            const payloads = storedPayloads || [];

            let messagesForFuzzer = Array.isArray(storedMessages) && storedMessages.length > 0 ?
                storedMessages :
                (traceReport?.details?.uniqueStructures ? traceReport.details.uniqueStructures.flatMap(s => s.examples || []) : []);

            const callbackStorageData = await new Promise(resolve => chrome.storage.session.get([CALLBACK_URL_STORAGE_KEY], resolve));
            const currentCallbackUrl = callbackStorageData[CALLBACK_URL_STORAGE_KEY] || null;
            const customPayloadsResult = await new Promise(resolve => chrome.storage.session.get('customXssPayloads', result => resolve(result.customXssPayloads)));
            const useCustomPayloads = customPayloadsResult && customPayloadsResult.length > 0;
            const fuzzerOptions = {
                autoStart: false,
                useCustomPayloads: useCustomPayloads,
                enableCallbackFuzzing: !!currentCallbackUrl,
                callbackUrl: currentCallbackUrl
            };
            launchSuccess = await launchFuzzerEnvironment(successfulUrl, handlerCode, messagesForFuzzer, payloads, traceReport, fuzzerOptions, analysisKeyToUse);
        } catch (error) {
            log.error(`[Launch Error for ${originalFullEndpoint}]:`, error?.message);
            alert(`Fuzzer launch failed: ${error.message}`);
            launchSuccess = false;
            try { await chrome.runtime.sendMessage({ type: "stopServer" }); } catch {}
        } finally {
            updateButton(button, launchSuccess ? 'launch' : 'error', { ...currentStateInfo?.options, errorMessage: launchSuccess ? undefined : 'Fuzzer launch failed' });
            launchInProgressEndpoints.delete(endpointKey);
            setTimeout(requestUiUpdate, 150);
        }
        return;
    }
    launchInProgressEndpoints.add(endpointKey);
    const isExtensionUrl = endpointKey.startsWith('chrome-extension://');
    const reportButton = button.closest('.button-container')?.querySelector('.iframe-report-button');
    let endpointUrlForAnalysis = originalFullEndpoint;
    let analysisStorageKey = getStorageKeyForUrl(endpointKey);
    let successfullyAnalyzedUrl = null;
    let handlerStateUpdated = false;
    let foundHandlerObject = null;
    let analysisErrorMsg = '';
    let proceedSilentlyOnError = false;
    let potentialHandlers = [];

    try {
        const originalMessages = await retrieveMessagesWithFallbacks(analysisStorageKey, endpointKey);
        const testMessage = originalMessages.length > 0 ? originalMessages[0].data : {"FrogPost": "BreakpointTest"};

        if (isExtensionUrl) {
            log.info("[Play] Processing extension URL. Attempting to use pre-detected handler.");
            successfullyAnalyzedUrl = endpointUrlForAnalysis;
            analysisStorageKey = getStorageKeyForUrl(successfullyAnalyzedUrl);

            const previouslyFoundHandlerData = await chrome.storage.local.get(`best-handler-${analysisStorageKey}`);
            if (previouslyFoundHandlerData && previouslyFoundHandlerData[`best-handler-${analysisStorageKey}`]) {
                foundHandlerObject = previouslyFoundHandlerData[`best-handler-${analysisStorageKey}`];
                log.success(`[Play] Successfully loaded pre-detected handler for extension URL ${analysisStorageKey} from local storage.`);
                if (!endpointsWithDetectedHandlers.has(analysisStorageKey)) {
                    endpointsWithDetectedHandlers.add(analysisStorageKey);
                    handlerStateUpdated = true;
                }
            } else {
                log.warn(`[Play] No pre-detected handler found in local storage for extension URL ${analysisStorageKey}. The 'Play' action for extensions currently relies on prior auto-detection.`);
            }
        } else if (!skipCheck) {
            if (!hideFromUser) {
                updateButton(button, 'csp');
            }
            if (!silentMode && !hideFromUser) {
                showToastNotification("Checking CSP compatibility for iframe embedding...", "info", 3000);
            }
            let cspResult = await checkCSPHeaders(endpointUrlForAnalysis);
            log.info(`[Play] Enhanced CSP check result:`, cspResult);

            if (!cspResult.canEmbed) {
                log.warn(`[Play] Embedding check failed for ${endpointUrlForAnalysis}: ${cspResult.reason}`);
                
                // In silent mode (Auto Pilot / URL Upload), skip without showing modal
                if (silentMode) {
                    log.info(`[Play] Silent mode (Auto Pilot/URL Upload): Skipping CSP-blocked endpoint ${endpointUrlForAnalysis}`);
                    await markEndpointAsFailed(endpointKey, `CSP: ${cspResult.reason}`);
                    return; // Don't proceed with handler extraction
                }
                
                // In normal mode (manual Play button), ALWAYS show the query modal for CSP failures
                showToastNotification(`Embedding blocked by: ${cspResult.reason}`, 'error');
                const modalResult = await showUrlModificationModal(endpointUrlForAnalysis, cspResult.reason);
                
                if (modalResult.action === 'retry' && modalResult.modifiedUrl) {
                    log.info("[Play] User modified URL after CSP block. Retrying check...");
                    const modifiedUrl = modalResult.modifiedUrl;
                    const originalTelemetryKey = analysisStorageKey; // Save original key for telemetry
                    
                    // Retry CSP check with modified URL
                    const retryResult = await checkCSPHeaders(modifiedUrl);
                    log.info(`[Play] CSP check result for modified URL:`, retryResult);
                    
                    if (retryResult.canEmbed) {
                        log.success(`[Play] CSP bypass successful with modified URL`);
                        // Use modified URL for embedding, but keep original key for telemetry
                        endpointUrlForAnalysis = modifiedUrl;
                        successfullyAnalyzedUrl = modifiedUrl;
                        // ⚠️ CRITICAL: analysisStorageKey stays as original for telemetry!
                        log.info(`[Play] Telemetry key (original): ${analysisStorageKey}`);
                        log.info(`[Play] Embedding URL (modified): ${successfullyAnalyzedUrl}`);
                        
                        // Store mapping: original endpoint → original storage key (NOT modified URL!)
                        // This mapping tells Launch Fuzzer where to find the data
                        const mappingKey = `analyzed-url-for-${endpointKey}`;
                        await chrome.storage.local.set({ [mappingKey]: analysisStorageKey });
                        log.info(`[Play] Stored mapping: ${mappingKey} → ${analysisStorageKey}`);
                        
                        // ⚠️ Update cspResult so the next check passes
                        cspResult = retryResult;
                        
                        // Continue to handler extraction (don't return)
                    } else {
                        log.error(`[Play] Modified URL still blocked: ${retryResult.reason}`);
                        showToastNotification(`Modified URL still blocked: ${retryResult.reason}`, 'error');
                        updateButton(button, 'start');
                        return;
                    }
                } else if (modalResult.action === 'continue') {
                    log.warn(`[Play] User chose to continue analysis despite CSP block: ${cspResult.reason}`);
                    proceedSilentlyOnError = true;
                    updateButton(button, 'warning', { errorMessage: `Proceeding despite block: ${cspResult.reason}` });
                } else {
                    // User cancelled
                    updateButton(button, 'start');
                    return;
                }
            }

            if (cspResult.canEmbed || proceedSilentlyOnError) {
                // Only set successfullyAnalyzedUrl if not already set by CSP bypass flow
                if (!successfullyAnalyzedUrl) {
                    successfullyAnalyzedUrl = endpointUrlForAnalysis;
                }
                // ⚠️ CRITICAL: Only update analysisStorageKey if not a CSP bypass scenario
                // If successfullyAnalyzedUrl !== endpointUrlForAnalysis, it means CSP was bypassed
                // and analysisStorageKey should stay as the original URL
                if (successfullyAnalyzedUrl === endpointUrlForAnalysis && !analysisStorageKey) {
                    analysisStorageKey = getStorageKeyForUrl(successfullyAnalyzedUrl);
                }
                if (cspResult.canEmbed) {
                    log.success(`[Play] Initial embedding check passed for ${successfullyAnalyzedUrl}`);
                } else {
                    log.warn(`[Play] Proceeding with analysis for ${successfullyAnalyzedUrl} despite earlier check failures/uncertainty.`);
                }
                log.info(`[Play] Final keys - Telemetry: ${analysisStorageKey}, Embedding: ${successfullyAnalyzedUrl}`);
            } else {
                throw new Error("Failed to determine a valid URL for analysis or user cancelled.");
            }

        } else {
            successfullyAnalyzedUrl = endpointUrlForAnalysis;
            analysisStorageKey = getStorageKeyForUrl(successfullyAnalyzedUrl);
        }


        if (!successfullyAnalyzedUrl && !isExtensionUrl) {
            throw new Error("Analysis cannot proceed: No valid or confirmed URL.");
        }


        if(!button.classList.contains('warning') && !isExtensionUrl){
            updateButton(button, 'analyze');
        } else if (isExtensionUrl && !foundHandlerObject && !button.classList.contains('warning')) {
            updateButton(button, 'analyze');
        }


        await saveRandomPostMessages(analysisStorageKey, originalMessages);
        const successfulUrlStorageKey = `successful-url-${analysisStorageKey}`;
        await chrome.storage.local.set({ [successfulUrlStorageKey]: successfullyAnalyzedUrl });

        analysisErrorMsg = '';

        if (isExtensionUrl){
            if (!foundHandlerObject) {
                log.info("[Play] Extension URL: No pre-existing handler in storage, and no new dynamic discovery performed by Play button.");
            }
        } else {
            try {
                // ============================================================
                // FROGPOST APPROACH: Check for pre-extracted handlers FIRST
                // ============================================================
                if (!hideFromUser) {
                    updateButton(button, 'analyze', { message: 'Checking for pre-captured handlers...' });
                    showToastNotification("🐸 Checking runtime telemetry...", "info", 2000);
                }

                // Try to retrieve pre-extracted handler from DOM agent telemetry
                log.info(`[Play] Requesting pre-extracted handler for key: ${analysisStorageKey}`);
                
                // Check if runtime is available (background script might be terminated)
                if (!chrome?.runtime?.id) {
                    log.error(`[Play] Chrome runtime not available - extension context invalidated`);
                    if (!hideFromUser) {
                        showToastNotification("⚠️ Extension reloaded. Please refresh dashboard.", "error", 5000);
                    }
                } else {
                    log.debug(`[Play] Chrome runtime available, ID: ${chrome.runtime.id}`);
                }
                
                let preExtractedResult = null;
                try {
                    preExtractedResult = await chrome.runtime.sendMessage({
                        type: 'getPreExtractedHandler',
                        payload: { endpointKey: analysisStorageKey }
                    });
                    log.info(`[Play] Telemetry retrieval response:`, JSON.stringify(preExtractedResult, null, 2));
                } catch (err) {
                    log.error(`[Play] Error retrieving telemetry:`, err);
                    log.error(`[Play] Error details:`, err?.message || 'Unknown error', err?.stack || 'No stack trace');
                }

                if (preExtractedResult?.success && preExtractedResult?.handler) {
                    // SUCCESS: Found pre-extracted handler from DOM agent!
                    foundHandlerObject = preExtractedResult.handler;
                    log.success(`[FrogPost] Retrieved pre-extracted handler from DOM agent telemetry!`);
                    log.info(`[FrogPost] Handler source: ${foundHandlerObject.source}, Score: ${foundHandlerObject.score}`);
                    
                    if (!hideFromUser) {
                        showToastNotification("✅ Handler retrieved from telemetry", "success", 3000);
                    }
                } else {
                    // Fallback: No pre-extracted handler found
                    log.warn("[Play] No pre-extracted handler found in telemetry. Using slim fallback...");
                    if (preExtractedResult) {
                        log.debug(`[Play] Telemetry response details:`, { success: preExtractedResult?.success, hasHandler: !!preExtractedResult?.handler, error: preExtractedResult?.error });
                    }
                    
                    if (!hideFromUser) {
                        updateButton(button, 'analyze', { message: 'Using fallback extraction...' });
                        showToastNotification("⚠️ No telemetry found. Using AST fallback...", "warning", 3000);
                    }

                    // Initialize slim extractor for fallback
                    const extractor = new HandlerExtractor().initialize(successfullyAnalyzedUrl, originalMessages);

                    // SLIM FALLBACK: AST-only analysis (no debugger, no iframe loading)
                    potentialHandlers = await extractor.extractStaticallyWithContext(
                        successfullyAnalyzedUrl, 
                        extractor.messageKeys, 
                        extractor.messageTypes, 
                        extractor.messageValues
                    );

                    if (potentialHandlers && potentialHandlers.length > 0) {
                        log.info(`[Slim Fallback] Found ${potentialHandlers.length} handlers via AST analysis`);
                        foundHandlerObject = extractor.getBestHandler(potentialHandlers);
                        
                        if (foundHandlerObject) {
                            log.info(`[Slim Fallback] Selected best handler via scoring`);
                            if (!hideFromUser) {
                                showToastNotification(`✅ Handler found via fallback`, "success", 3000);
                            }
                        }
                    } else {
                        log.warn("[Play] Slim fallback found no handlers");
                        foundHandlerObject = null;
                        if (!hideFromUser) {
                            showToastNotification("⚠️ No handlers found", "warning", 4000);
                        }
                    }
                }
                
                // ZOMBIE ENDPOINT EXTRACTION: If no handler found, check if this is a zombie endpoint (0 messages)
                if (!foundHandlerObject) {
                    const messageCount = getMessageCount(originalFullEndpoint);
                    if (messageCount === 0) {
                        log.info('[Play] Zombie endpoint detected (0 messages). Attempting extraction...');
                        
                        if (!hideFromUser) {
                            updateButton(button, 'analyze', { message: 'Zombie endpoint - extracting...' });
                            showToastNotification('🧟 Zombie endpoint - attempting handler extraction...', 'info', 3000);
                        }
                        
                        // Strategy: Static AST analysis for zombie endpoints
                        try {
                            log.info('[Zombie] Attempting static AST analysis...');
                            
                            const zombieExtractor = new HandlerExtractor();
                            const staticHandlers = await zombieExtractor.extractStaticallyWithContext(
                                originalFullEndpoint, 
                                new Set(), // no message keys
                                new Set(), // no message types
                                new Set()  // no message values
                            );
                            
                            if (staticHandlers && staticHandlers.length > 0) {
                                const bestStatic = zombieExtractor.getBestHandler(staticHandlers);
                                if (bestStatic) {
                                    foundHandlerObject = {
                                        handler: bestStatic.code,
                                        code: bestStatic.code,
                                        source: 'static-ast-zombie',
                                        score: bestStatic.score || 50,
                                        category: 'static-zombie'
                                    };
                                    log.success('[Zombie] Handler extracted via static analysis');
                                    if (!hideFromUser) {
                                        showToastNotification('✅ Zombie handler extracted', 'success', 3000);
                                    }
                                }
                            } else {
                                log.warn('[Zombie] Static analysis found no handlers');
                            }
                        } catch (zombieError) {
                            log.error('[Zombie] Static analysis failed:', zombieError);
                        }
                        
                        if (!foundHandlerObject) {
                            log.error('[Zombie] All extraction methods failed for zombie endpoint');
                            if (!hideFromUser) {
                                showToastNotification('❌ No handler found for zombie endpoint', 'error', 3000);
                            }
                        }
                    }
                }

            } catch (discoveryError) {
                log.error(`[Play] Handler discovery failed:`, discoveryError);
                analysisErrorMsg = discoveryError.message;
                potentialHandlers = [];
                foundHandlerObject = null;
                if (!hideFromUser) {
                    showToastNotification("Handler extraction failed", "error", 4000);
                }
            }
        }


        if (foundHandlerObject?.handler) {
            const finalBestHandlerKey = `best-handler-${analysisStorageKey}`;
            try {
                if (typeof window.analyzeHandlerStatically === 'function' && foundHandlerObject.handler) {
                    try {
                        const quickAnalysis = window.analyzeHandlerStatically(foundHandlerObject.handler);
                        if (quickAnalysis?.analysis?.identifiedEventParam) foundHandlerObject.eventParamName = quickAnalysis.analysis.identifiedEventParam;
                    }
                    catch (quickAnalysisError) {
                        log.warn("Quick analysis for event param failed", quickAnalysisError);
                    }
                }
                if (analysisStorageKey !== endpointKey) {
                    const mappingKey = `analyzed-url-for-${endpointKey}`;
                    await chrome.storage.local.set({ [mappingKey]: analysisStorageKey });
                    log.debug(`[Play] Stored mapping: ${mappingKey} -> ${analysisStorageKey}`);
                } else { const mappingKey = `analyzed-url-for-${endpointKey}`; await chrome.storage.local.remove(mappingKey); }

                await chrome.storage.local.set({ [finalBestHandlerKey]: foundHandlerObject });
                if (!endpointsWithDetectedHandlers.has(analysisStorageKey)) {
                    endpointsWithDetectedHandlers.add(analysisStorageKey);
                    handlerStateUpdated = true;
                }
                log.success(`[Play] Successfully identified and saved handler for ${analysisStorageKey}. Category: ${foundHandlerObject.category}, Score: ${foundHandlerObject.score ?? 'N/A'}`);

                if (isExtensionUrl) {
                    updateButton(button, 'success');
                    const traceButtonExt = button.closest('.button-container')?.querySelector('.iframe-trace-button');
                    if (traceButtonExt) updateTraceButton(traceButtonExt, 'default', {showEmoji: true});
                    if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
                } else {
                    updateButton(button, 'success');
                    const traceButtonWeb = button.closest('.button-container')?.querySelector('.iframe-trace-button');
                    if (traceButtonWeb) updateTraceButton(traceButtonWeb, 'default', {showEmoji: true});
                    if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
                }

            } catch (storageError) {
                log.error(`Failed to save handler (${finalBestHandlerKey}):`, storageError);
                updateButton(button, 'error', {errorMessage: 'Failed to save handler'});
                const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button');
                if (traceButton) updateTraceButton(traceButton, 'disabled');
                if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
            }
        } else {
            log.warn(`[Play] Final failure check: No usable handler object available.`);
            if (isExtensionUrl) {
                log.warn(`[Play] No handler confirmed for extension URL ${analysisStorageKey} even after checking storage.`);
                updateButton(button, 'warning', {errorMessage: `No handler found by this action. Auto-attach should find it.`});
            } else {
                const failureMessage = `No usable handler confirmed for ${endpointUrlForAnalysis}. ${analysisErrorMsg || 'Reason unknown.'}`;
                log.warn(`[Play] ${failureMessage}`);
                if(!button.classList.contains('warning')) {
                    updateButton(button, 'warning', {errorMessage: `No handler confirmed. ${analysisErrorMsg || ''}`.trim()});
                } else {
                    button.title = `No handler confirmed. ${analysisErrorMsg || ''}`.trim();
                }
            }
            const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button');
            if (traceButton) updateTraceButton(traceButton, 'disabled');
            if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);
        }
        if (handlerStateUpdated) requestUiUpdate();

    } catch (error) {
        log.error(`[Play Button Error Handler] Error for ${originalFullEndpoint}: ${error.message}`, error);
        if (!button.classList.contains('error') && !button.classList.contains('warning') && !button.classList.contains('success') && !button.classList.contains('launch')) {
            updateButton(button, 'start');
        } else if(error.message.startsWith("Analysis stopped") || error.message.startsWith("Analysis cancelled")) {
            if (!button.classList.contains('start')) {
                updateButton(button, 'start');
            }
        } else if (!button.classList.contains('error') && !button.classList.contains('warning')){
            updateButton(button, 'error', {errorMessage: error.message || 'Analysis error occurred'});
        }
        const traceButton = button.closest('.button-container')?.querySelector('.iframe-trace-button');
        if (traceButton) updateTraceButton(traceButton, 'disabled');
        if (reportButton) updateReportButton(reportButton, 'disabled', originalFullEndpoint);

    } finally {
        launchInProgressEndpoints.delete(endpointKey);
        if (endpointUrlForAnalysis !== originalFullEndpoint && analysisStorageKey){
            launchInProgressEndpoints.delete(analysisStorageKey);
        }
        setTimeout(requestUiUpdate, 150);
    }
}


function getRiskLevelAndColor(score) {
  if (score <= 40) return { riskLevel: 'High', riskColor: 'high' };
  if (score <= 70) return { riskLevel: 'Medium', riskColor: 'medium' };
  return { riskLevel: 'Low', riskColor: 'low' };
}

function getHandlerScoreClass(score10) {
  const n = Number(score10 || 0);
  if (n >= 10) return 'score-safe';      // explicitly "Safe"
  if (n >= 7) return 'score-risk-low';   // good
  if (n >= 4) return 'score-risk-medium';// caution
  return 'score-risk-high';              // 1-3 high risk
}

function sanitizeMessagesForLLM(messages) {
    if (!Array.isArray(messages)) return [];
    
    const commonSecretPatterns = [
        { pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g, replacement: '[JWT_TOKEN]' },
        { pattern: /sk-[A-Za-z0-9]{20,}/g, replacement: '[API_KEY]' },
        { pattern: /pk_[A-Za-z0-9]{20,}/g, replacement: '[API_KEY]' },
        { pattern: /Bearer\s+[A-Za-z0-9_-]{20,}/g, replacement: 'Bearer [TOKEN]' },
        { pattern: /AKIA[0-9A-Z]{16}/g, replacement: '[AWS_ACCESS_KEY]' },
        { pattern: /[A-Za-z0-9/+=]{40}/g, replacement: '[AWS_SECRET_KEY]' },
        { pattern: /mongodb:\/\/[^@]+@[^/]+\/[^\s]*/g, replacement: 'mongodb://[USER]:[PASSWORD]@[HOST]/[DB]' },
        { pattern: /postgres:\/\/[^@]+@[^/]+\/[^\s]*/g, replacement: 'postgres://[USER]:[PASSWORD]@[HOST]/[DB]' },
        { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, replacement: '[CREDIT_CARD]' },
        { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[EMAIL]' }
    ];
    
    return messages.map(msg => {
        const sanitized = JSON.parse(JSON.stringify(msg)); // Deep clone
        
        if (sanitized.data && typeof sanitized.data === 'object') {
            const dataStr = JSON.stringify(sanitized.data);
            let sanitizedDataStr = dataStr;
            
            commonSecretPatterns.forEach(({ pattern, replacement }) => {
                sanitizedDataStr = sanitizedDataStr.replace(pattern, replacement);
            });
            
            try {
                sanitized.data = JSON.parse(sanitizedDataStr);
            } catch (e) {
                console.warn('Failed to parse sanitized data, keeping original');
            }
        }
        
        Object.keys(sanitized).forEach(key => {
            if (typeof sanitized[key] === 'string') {
                let sanitizedStr = sanitized[key];
                commonSecretPatterns.forEach(({ pattern, replacement }) => {
                    sanitizedStr = sanitizedStr.replace(pattern, replacement);
                });
                sanitized[key] = sanitizedStr;
            }
        });
        
        return sanitized;
    });
}

function estimateTokenCount(text) {
    if (typeof text === 'string') {
        return Math.ceil(text.length / 4);
    }
    if (typeof text === 'object') {
        return Math.ceil(JSON.stringify(text).length / 4);
    }
    return 0;
}

function analyzeSensitiveDataInMessages(messages) {
    const detectedTypes = new Set();
    let hasSensitiveData = false;
    
    const commonSecretPatterns = [
        { name: 'JWT Tokens', pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g },
        { name: 'API Keys', pattern: /sk-[A-Za-z0-9]{20,}|pk_[A-Za-z0-9]{20,}/g },
        { name: 'Bearer Tokens', pattern: /Bearer\s+[A-Za-z0-9_-]{20,}/g },
        { name: 'AWS Keys', pattern: /AKIA[0-9A-Z]{16}|[A-Za-z0-9/+=]{40}/g },
        { name: 'Database URLs', pattern: /mongodb:\/\/[^@]+@[^/]+\/[^\s]*|postgres:\/\/[^@]+@[^/]+\/[^\s]*/g },
        { name: 'Credit Cards', pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g },
        { name: 'Email Addresses', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g }
    ];
    
    messages.forEach(msg => {
        const msgStr = JSON.stringify(msg);
        commonSecretPatterns.forEach(({ name, pattern }) => {
            if (pattern.test(msgStr)) {
                detectedTypes.add(name);
                hasSensitiveData = true;
            }
        });
    });
    
    return { hasSensitiveData, detectedTypes };
}
function generateSanitizationSummary(originalMessages, sanitizedMessages) {
    const changes = [];
    
    originalMessages.forEach((original, index) => {
        const sanitized = sanitizedMessages[index];
        const originalStr = JSON.stringify(original);
        const sanitizedStr = JSON.stringify(sanitized);
        
        if (originalStr !== sanitizedStr) {
            changes.push(`Message ${index + 1}: ${originalStr.length} → ${sanitizedStr.length} chars`);
        }
    });
    
    return {
        hasChanges: changes.length > 0,
        changes: changes,
        totalOriginalSize: JSON.stringify(originalMessages).length,
        totalSanitizedSize: JSON.stringify(sanitizedMessages).length
    };
}

function showLLMConsentPopup(handlerCode, messages, onConfirm, onCancel) {
    const sanitizedMessages = sanitizeMessagesForLLM(messages);
    const handlerTokens = estimateTokenCount(handlerCode);
    const messagesTokens = estimateTokenCount(sanitizedMessages);
    const totalTokens = handlerTokens + messagesTokens;
    
    const sensitiveDataAnalysis = analyzeSensitiveDataInMessages(messages);
    const hasSensitiveData = sensitiveDataAnalysis.hasSensitiveData;
    const detectedTypes = Array.from(sensitiveDataAnalysis.detectedTypes);
    const sanitizationSummary = generateSanitizationSummary(messages, sanitizedMessages);
    
    console.log('🔍 [Consent Popup] Sensitive data analysis:', {
        hasSensitiveData,
        detectedTypes,
        sanitizationSummary
    });
    
    const popupHTML = `
        <div id="llm-consent-overlay" style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-sans);
        ">
            <div style="
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 30px;
                max-width: 600px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            ">
                <h3 style="
                    margin: 0 0 20px 0;
                    color: var(--accent-primary);
                    font-size: 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                ">
                    🤖 LLM Analysis Consent
                </h3>
                
                <div style="margin-bottom: 20px;">
                    <h4 style="color: var(--text-primary); margin: 0 0 10px 0; font-size: 16px;">What will be sent to the LLM:</h4>
                    <ul style="margin: 0; padding-left: 20px; color: var(--text-secondary); line-height: 1.6;">
                        <li><strong>Handler Code:</strong> ${handlerCode.length} characters (~${handlerTokens} tokens)</li>
                        <li><strong>Intercepted Messages:</strong> ${messages.length} messages (~${messagesTokens} tokens)</li>
                        <li><strong>Total Estimated Tokens:</strong> ~${totalTokens} tokens</li>
                    </ul>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <h4 style="color: var(--text-primary); margin: 0 0 10px 0; font-size: 16px;">🔒 Data Protection:</h4>
                    <div style="
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 8px;
                        padding: 15px;
                        font-size: 14px;
                        color: var(--text-secondary);
                        line-height: 1.5;
                    ">
                        ${hasSensitiveData ? `
                            <div style="
                                background: #ff6b6b20;
                                border: 1px solid #ff6b6b;
                                border-radius: 6px;
                                padding: 12px;
                                margin-bottom: 15px;
                            ">
                                <p style="margin: 0 0 8px 0; color: #ff6b6b; font-weight: 600;">
                                    ⚠️ Sensitive Data Detected
                                </p>
                                <p style="margin: 0 0 8px 0; font-size: 13px;">
                                    <strong>Found:</strong> ${detectedTypes.join(', ')}
                                </p>
                                <p style="margin: 0; font-size: 13px;">
                                    <strong>Action:</strong> Will be sanitized before sending to LLM
                                </p>
                            </div>
                        ` : `
                            <div style="
                                background: #66bb6a20;
                                border: 1px solid #66bb6a;
                                border-radius: 6px;
                                padding: 12px;
                                margin-bottom: 15px;
                            ">
                                <p style="margin: 0; color: #66bb6a; font-weight: 600;">
                                    ✅ No Sensitive Data Detected
                                </p>
                            </div>
                        `}
                        
                        <p style="margin: 0 0 10px 0;"><strong>FrogPost automatically sanitizes sensitive data before sending:</strong></p>
                        <ul style="margin: 0; padding-left: 20px;">
                            <li>JWT tokens, API keys, and bearer tokens</li>
                            <li>AWS access keys and secret keys</li>
                            <li>Database connection strings</li>
                            <li>Credit card numbers and email addresses</li>
                            <li>Other common secret patterns</li>
                        </ul>
                        <p style="margin: 10px 0 0 0; font-style: italic;">
                            Sensitive data is replaced with placeholder values like [JWT_TOKEN], [API_KEY], etc.
                        </p>
                        
                        ${sanitizationSummary.hasChanges ? `
                            <div style="
                                background: var(--bg-primary);
                                border: 1px solid var(--border-color);
                                border-radius: 6px;
                                padding: 10px;
                                margin-top: 15px;
                                font-size: 12px;
                            ">
                                <p style="margin: 0 0 8px 0; font-weight: 600;">📊 Sanitization Preview:</p>
                                <p style="margin: 0 0 5px 0;">Data size: ${sanitizationSummary.totalOriginalSize} → ${sanitizationSummary.totalSanitizedSize} characters</p>
                                <p style="margin: 0; font-size: 11px; color: var(--text-secondary);">
                                    ${sanitizationSummary.changes.join(', ')}
                                </p>
                            </div>
                        ` : ''}
                    </div>
                </div>
                
                <div style="margin-bottom: 20px;">
                    <h4 style="color: var(--text-primary); margin: 0 0 10px 0; font-size: 16px;">📊 Analysis Process:</h4>
                    <ol style="margin: 0; padding-left: 20px; color: var(--text-secondary); line-height: 1.6;">
                        <li>Analyze handler code for DOM XSS vulnerabilities</li>
                        <li>Examine intercepted messages for security patterns</li>
                        <li>Generate targeted payloads based on detected vulnerabilities</li>
                    </ol>
                </div>
                
                <div style="
                    display: flex;
                    gap: 15px;
                    justify-content: flex-end;
                    margin-top: 25px;
                ">
                    <button id="llm-consent-cancel" style="
                        padding: 10px 20px;
                        background: var(--bg-secondary);
                        color: var(--text-primary);
                        border: 1px solid var(--border-color);
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 14px;
                        font-weight: 500;
                    ">Cancel</button>
                    <button id="llm-consent-confirm" style="
                        padding: 10px 20px;
                        background: var(--accent-primary);
                        color: #111;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 14px;
                        font-weight: 600;
                    ">Proceed with Analysis</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', popupHTML);
    
    document.getElementById('llm-consent-cancel').addEventListener('click', () => {
        document.getElementById('llm-consent-overlay').remove();
        onCancel();
    });
    
    document.getElementById('llm-consent-confirm').addEventListener('click', () => {
        document.getElementById('llm-consent-overlay').remove();
        onConfirm();
    });
    
    document.getElementById('llm-consent-overlay').addEventListener('click', (e) => {
        if (e.target.id === 'llm-consent-overlay') {
            document.getElementById('llm-consent-overlay').remove();
            onCancel();
        }
    });
}

function parseLLMResponse(response) {
    try {
        let cleanResponse = response.trim();
        if (cleanResponse.startsWith('```json')) {
            cleanResponse = cleanResponse.replace(/^```json\s*/, '').replace(/\s*```$/, '');
        } else if (cleanResponse.startsWith('```')) {
            cleanResponse = cleanResponse.replace(/^```\s*/, '').replace(/\s*```$/, '');
        }
        
        return JSON.parse(cleanResponse);
    } catch (error) {
        console.error('Failed to parse LLM response as JSON:', error);
        console.log('Raw response:', response);
        
        return {
            error: 'Failed to parse LLM response',
            rawResponse: response,
            analysis: 'The LLM response could not be parsed as valid JSON. Please check the response format.'
        };
    }
}

class LLMAnalyzer {
    constructor() {
        this.providers = {
            'openai': {
                name: 'OpenAI',
                models: [
                    'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo',
                    'gpt-4o-2024-08-06', 'gpt-4-turbo-2024-04-09', 'gpt-4-0613',
                    'gpt-3.5-turbo-1106', 'gpt-3.5-turbo-0613', 'gpt-3.5-turbo-16k'
                ],
                baseUrl: 'https://api.openai.com/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'anthropic': {
                name: 'Anthropic',
                models: [
                    'claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 
                    'claude-3-opus-20240229', 'claude-3-sonnet-20240229',
                    'claude-3-haiku-20240307', 'claude-2.1', 'claude-2.0'
                ],
                baseUrl: 'https://api.anthropic.com/v1/messages',
                headers: (apiKey) => ({
                    'x-api-key': apiKey,
                    'Content-Type': 'application/json',
                    'anthropic-version': '2023-06-01'
                })
            },
            'groq': {
                name: 'Groq',
                models: [
                    'llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768',
                    'llama-3-70b-8192', 'llama-3-8b-8192', 'gemma-7b-it', 'gemma-2-9b-it',
                    'llama-2-70b-4096', 'llama-2-13b-chat', 'llama-2-7b-chat'
                ],
                baseUrl: 'https://api.groq.com/openai/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'mistral': {
                name: 'Mistral',
                models: [
                    'mistral-large-latest', 'mistral-medium-latest', 'open-mixtral-8x7b',
                    'mistral-small-latest', 'mistral-7b-instruct', 'mistral-tiny'
                ],
                baseUrl: 'https://api.mistral.ai/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'google': {
                name: 'Google',
                models: [
                    'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-pro',
                    'gemini-1.5-pro-latest', 'gemini-1.5-flash-latest'
                ],
                baseUrl: 'https://generativelanguage.googleapis.com/v1beta/models',
                headers: (apiKey) => ({
                    'x-goog-api-key': apiKey,
                    'Content-Type': 'application/json'
                })
            },
            'cohere': {
                name: 'Cohere',
                models: [
                    'command-r-plus', 'command-r', 'command', 'command-light',
                    'command-nightly', 'command-light-nightly'
                ],
                baseUrl: 'https://api.cohere.ai/v1/chat',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'perplexity': {
                name: 'Perplexity',
                models: [
                    'llama-3.1-sonar-small-128k-online', 'llama-3.1-sonar-large-128k-online',
                    'llama-3.1-sonar-huge-128k-online', 'llama-3.1-sonar-small-128k-chat',
                    'llama-3.1-sonar-large-128k-chat', 'llama-3.1-sonar-huge-128k-chat'
                ],
                baseUrl: 'https://api.perplexity.ai/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'together': {
                name: 'Together AI',
                models: [
                    'meta-llama/Llama-2-70b-chat-hf', 'meta-llama/Llama-2-13b-chat-hf',
                    'meta-llama/Llama-2-7b-chat-hf', 'mistralai/Mistral-7B-Instruct-v0.1',
                    'mistralai/Mixtral-8x7b-Instruct-v0.1', 'codellama/CodeLlama-34b-Instruct-hf',
                    'WizardLM/WizardCoder-15B-V1.0', 'NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO'
                ],
                baseUrl: 'https://api.together.xyz/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'replicate': {
                name: 'Replicate',
                models: [
                    'meta/llama-2-70b-chat', 'meta/llama-2-13b-chat', 'meta/llama-2-7b-chat',
                    'mistralai/mistral-7b-instruct-v0.1', 'mistralai/mixtral-8x7b-instruct-v0.1',
                    'codellama/codellama-34b-instruct', 'wizardlm/wizardcoder-15b-v1.0'
                ],
                baseUrl: 'https://api.replicate.com/v1/predictions',
                headers: (apiKey) => ({
                    'Authorization': `Token ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'huggingface': {
                name: 'Hugging Face',
                models: [
                    'microsoft/DialoGPT-large', 'microsoft/DialoGPT-medium', 'microsoft/DialoGPT-small',
                    'facebook/blenderbot-400M-distill', 'facebook/blenderbot-1B-distill',
                    'microsoft/DialoGPT-medium', 'google/flan-t5-large', 'google/flan-t5-xl'
                ],
                baseUrl: 'https://api-inference.huggingface.co/models',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'deepseek': {
                name: 'DeepSeek',
                models: [
                    'deepseek-chat', 'deepseek-coder', 'deepseek-coder-6.7b-instruct',
                    'deepseek-coder-33b-instruct', 'deepseek-llm-7b-chat', 'deepseek-llm-67b-chat'
                ],
                baseUrl: 'https://api.deepseek.com/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'qwen': {
                name: 'Qwen (Alibaba)',
                models: [
                    'qwen-turbo', 'qwen-plus', 'qwen-max', 'qwen-long',
                    'qwen-72b-chat', 'qwen-14b-chat', 'qwen-7b-chat'
                ],
                baseUrl: 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'moonshot': {
                name: 'Moonshot AI',
                models: [
                    'moonshot-v1-8k', 'moonshot-v1-32k', 'moonshot-v1-128k',
                    'moonshot-v1-8k-2024-03-01', 'moonshot-v1-32k-2024-03-01'
                ],
                baseUrl: 'https://api.moonshot.cn/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'zhipu': {
                name: 'Zhipu AI (GLM)',
                models: [
                    'glm-4', 'glm-4v', 'glm-3-turbo', 'glm-3-turbo-128k',
                    'glm-3-6b', 'glm-3-6b-32k', 'glm-3-6b-128k'
                ],
                baseUrl: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'baichuan': {
                name: 'Baichuan AI',
                models: [
                    'Baichuan2-Turbo', 'Baichuan2-Turbo-192k', 'Baichuan2-53B',
                    'Baichuan2-13B-Chat', 'Baichuan2-7B-Chat', 'Baichuan2-13B'
                ],
                baseUrl: 'https://api.baichuan-ai.com/v1/chat/completions',
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                })
            },
            'local': {
                name: 'Local/OpenAI Compatible',
                models: [
                    'llama-3.1-70b', 'llama-3.1-8b', 'mixtral-8x7b', 'codellama-34b',
                    'wizardcoder-15b', 'vicuna-13b', 'alpaca-13b', 'dolphin-2.6-mistral-7b'
                ],
                baseUrl: 'http://localhost:11434/v1/chat/completions', // Default Ollama
                headers: (apiKey) => ({
                    'Authorization': `Bearer ${apiKey || 'ollama'}`,
                    'Content-Type': 'application/json'
                })
            }
        };
    }

    async unifiedAnalyze(provider, model, apiKey, handlerCode, observedMessages) {
        try {
            console.log('🔍 [Unified Analysis] Starting combined analysis');
            
            const response = await fetch('http://localhost:1337/llm/unified-analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    provider,
                    model,
                    apiKey,
                    context: {
                        handlerCode,
                        observedMessages
                    }
                })
            });

            if (!response.ok) {
                throw new Error(`Server request failed: ${response.status} ${response.statusText}`);
            }

            const result = await response.json();
            if (!result.ok) {
                throw new Error(result.error || 'Server returned error');
            }

            return JSON.stringify({
                handler_assessment: result.handler_assessment || 'No analysis provided',
                handler_score: result.handler_score || 0,
                handler_match: result.handler_match || 50,
                risks: result.risks || [],
                dom_xss_sinks: result.dom_xss_sinks || [],
                prototype_pollution_indicators: result.prototype_pollution_indicators || [],
                data_type: result.data_type || 'JSON',
                new_payloads: result.new_payloads || [],
                payload_class: result.payload_class || 'none',
                notes: result.notes || 'Unified analysis completed'
            });
        } catch (error) {
            console.error('Unified analysis error:', error);
            throw error;
        }
    }

    async makeRequest(config, model, apiKey, prompt) {
        const headers = config.headers(apiKey);
        let requestBody;
        let responseUrl = config.baseUrl;

        if (config.name === 'Anthropic') {
            requestBody = {
                model: model,
                max_tokens: 4000,
                messages: [{ role: 'user', content: prompt }]
            };
        } else if (config.name === 'Google') {
            responseUrl = `${config.baseUrl}/${model}:generateContent`;
            requestBody = {
                contents: [{
                    parts: [{ text: prompt }]
                }],
                generationConfig: {
                    temperature: 0.1,
                    maxOutputTokens: 4000
                }
            };
        } else if (config.name === 'Cohere') {
            requestBody = {
                model: model,
                message: prompt,
                max_tokens: 4000,
                temperature: 0.1
            };
        } else if (config.name === 'Hugging Face') {
            responseUrl = `${config.baseUrl}/${model}`;
            requestBody = {
                inputs: prompt,
                parameters: {
                    max_new_tokens: 4000,
                    temperature: 0.1
                }
            };
        } else if (config.name === 'Replicate') {
            requestBody = {
                version: model,
                input: {
                    prompt: prompt,
                    max_length: 4000,
                    temperature: 0.1
                }
            };
        } else if (config.name === 'Qwen (Alibaba)') {
            requestBody = {
                model: model,
                input: {
                    messages: [{ role: 'user', content: prompt }]
                },
                parameters: {
                    max_tokens: 4000,
                    temperature: 0.1
                }
            };
        } else if (config.name === 'Zhipu AI (GLM)') {
            requestBody = {
                model: model,
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 4000,
                temperature: 0.1
            };
        } else if (config.name === 'Baichuan AI') {
            requestBody = {
                model: model,
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 4000,
                temperature: 0.1
            };
        } else {
            requestBody = {
                model: model,
                messages: [{ role: 'user', content: prompt }],
                max_tokens: 4000,
                temperature: 0.1
            };
        }

        const response = await fetch(responseUrl, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (config.name === 'Anthropic') {
            return data.content[0].text;
        } else if (config.name === 'Google') {
            return data.candidates[0].content.parts[0].text;
        } else if (config.name === 'Cohere') {
            return data.text;
        } else if (config.name === 'Hugging Face') {
            return data[0].generated_text;
        } else if (config.name === 'Replicate') {
            return data.output;
        } else if (config.name === 'Qwen (Alibaba)') {
            return data.output.text;
        } else if (config.name === 'Zhipu AI (GLM)') {
            return data.choices[0].message.content;
        } else if (config.name === 'Baichuan AI') {
            return data.choices[0].message.content;
        } else {
            return data.choices[0].message.content;
        }
    }
}

function createLLMAnalysisSection(analysisStorageKey, endpointDisplay) {
    const llmSection = document.createElement('div');
    llmSection.className = 'report-section report-llm';
    llmSection.innerHTML = `
        <h4 class="report-section-title">🤖 LLM Security Analysis</h4>
        <div class="llm-config">
            <div class="llm-provider-selector">
                <label for="llm-provider">Provider:</label>
                <select id="llm-provider" class="llm-select">
                    <option value="openai">OpenAI</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="groq">Groq</option>
                    <option value="mistral">Mistral</option>
                    <option value="google">Google (Gemini)</option>
                    <option value="cohere">Cohere</option>
                    <option value="perplexity">Perplexity</option>
                    <option value="together">Together AI</option>
                    <option value="replicate">Replicate</option>
                    <option value="huggingface">Hugging Face</option>
                    <option value="deepseek">DeepSeek</option>
                    <option value="qwen">Qwen (Alibaba)</option>
                    <option value="moonshot">Moonshot AI</option>
                    <option value="zhipu">Zhipu AI (GLM)</option>
                    <option value="baichuan">Baichuan AI</option>
                    <option value="local">Local/OpenAI Compatible</option>
                </select>
            </div>
            <div class="llm-model-selector">
                <label for="llm-model">Model:</label>
                <select id="llm-model" class="llm-select">
                    <option value="gpt-4o">GPT-4o</option>
                    <option value="gpt-4o-mini">GPT-4o Mini</option>
                    <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                </select>
            </div>
            <div class="llm-api-key">
                <label for="llm-api-key">API Key:</label>
                <input type="password" id="llm-api-key" class="llm-input" placeholder="Enter your API key">
            </div>
            <div class="llm-save-button">
                <button id="save-api-key" class="llm-button">Save</button>
            </div>
            <div class="llm-actions">
                <button id="analyze-llm" class="llm-analyze-button" disabled>🚀 Analyze</button>
            </div>
        </div>
    `;

    llmSection.dataset.analysisKey = analysisStorageKey;
    
    return llmSection;
}

function setupLLMEventListeners(analysisStorageKey, retryCount = 0) {
    const maxRetries = 10;
    const retryDelay = 200;
    
    // Check if already set up to prevent duplicates
    if (window.llmEventListenersSetup) {
        console.log('LLM event listeners already set up, skipping...');
        return;
    }
    
    setTimeout(() => {
        const providerSelect = document.getElementById('llm-provider');
        const modelSelect = document.getElementById('llm-model');
        const apiKeyInput = document.getElementById('llm-api-key');
        const saveButton = document.getElementById('save-api-key');
        const analyzeButton = document.getElementById('analyze-llm');
        
        if (!providerSelect || !modelSelect || !apiKeyInput || !saveButton || !analyzeButton) {
            if (retryCount < maxRetries) {
                console.warn(`LLM elements not found, retrying... (${retryCount + 1}/${maxRetries})`);
                setupLLMEventListeners(analysisStorageKey, retryCount + 1);
                return;
            } else {
                console.error('LLM elements not found after maximum retries, giving up.');
                return;
            }
        }

        console.log('LLM elements found, setting up event listeners...');
        window.llmEventListenersSetup = true;
        
        loadSavedAPIKey();

        providerSelect.addEventListener('change', updateModelOptions);
        
        saveButton.addEventListener('click', saveAPIKey);
        
        analyzeButton.addEventListener('click', () => performLLMAnalysis(analysisStorageKey));
    }, retryDelay);
}

function updateModelOptions() {
    const provider = document.getElementById('llm-provider').value;
    const modelSelect = document.getElementById('llm-model');
    
    const analyzer = new LLMAnalyzer();
    const models = analyzer.providers[provider]?.models || [];
    
    modelSelect.innerHTML = models.map(model => 
        `<option value="${model}">${model}</option>`
    ).join('');
}

async function loadSavedAPIKey() {
    try {
        const result = await chrome.storage.local.get(['llm_api_key']);
        if (result.llm_api_key) {
            document.getElementById('llm-api-key').value = result.llm_api_key;
            document.getElementById('analyze-llm').disabled = false;
        }
    } catch (error) {
        console.error('Error loading API key:', error);
    }
}

async function saveAPIKey() {
    const apiKey = document.getElementById('llm-api-key').value.trim();
    if (!apiKey) {
        alert('Please enter an API key');
        return;
    }
    
    try {
        await chrome.storage.local.set({ llm_api_key: apiKey });
        document.getElementById('analyze-llm').disabled = false;
        updateLLMStatus('Saved!', 'success');
    } catch (error) {
        console.error('Error saving API key:', error);
        updateLLMStatus('Error saving API key', 'error');
    }
}

async function performLLMAnalysis(analysisStorageKey) {
    const provider = document.getElementById('llm-provider').value;
    const model = document.getElementById('llm-model').value;
    const apiKey = document.getElementById('llm-api-key').value.trim();
    
    if (!apiKey) {
        alert('Please enter and save your API key first');
        return;
    }
    
    const analyzer = new LLMAnalyzer();
    const analyzeBtn = document.getElementById('analyze-llm');
    
    try {
        // Disable button and show analyzing state
        if (analyzeBtn) {
            analyzeBtn.disabled = true;
        }
        updateLLMStatus('Preparing...', 'info');
        
        const reportData = await getReportData(analysisStorageKey);
        if (!reportData) {
            throw new Error('No report data found');
        }
        
        const details = reportData.details || {};
        const bestHandler = details.bestHandler || details.analyzedHandler || reportData.bestHandler || reportData.analyzedHandler;
        const handlerCode = bestHandler?.handler || bestHandler?.code || '';
        
        if (!handlerCode) {
            throw new Error('No handler code found for analysis');
        }
        
        const messages = await getMessagesForAnalysis(analysisStorageKey);
        
        showLLMConsentPopup(handlerCode, messages, async () => {
            await executeLLMAnalysis(analyzer, provider, model, apiKey, handlerCode, messages, analysisStorageKey);
        }, () => {
            updateLLMStatus('Cancelled', 'info');
        });
        
    } catch (error) {
        console.error('LLM analysis error:', error);
        updateLLMStatus(`Analysis failed: ${error.message}`, 'error');
        // Re-enable button on error
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
        }
    }
}

async function executeLLMAnalysis(analyzer, provider, model, apiKey, handlerCode, messages, analysisStorageKey) {
    const analyzeBtn = document.getElementById('analyze-llm');
    
    try {
        updateLLMStatus('Starting...', 'info');
        
        const sanitizedMessages = sanitizeMessagesForLLM(messages);
        console.log('🔒 [Sanitization] Sanitized messages for LLM:', sanitizedMessages);
        
        updateLLMStatus('Analyzing...', 'info');
        console.log('🔍 [Debug] About to call unifiedAnalyze with:', {
            provider,
            model,
            handlerCodeLength: handlerCode.length,
            messagesCount: sanitizedMessages.length
        });
        
        const unifiedAnalysis = await analyzer.unifiedAnalyze(provider, model, apiKey, handlerCode, sanitizedMessages);
        const parsedUnifiedAnalysis = parseLLMResponse(unifiedAnalysis);
        
        console.log('🔍 [Debug] Unified analysis response:', parsedUnifiedAnalysis);
        
        updateHandlerWithLLMAnalysis(parsedUnifiedAnalysis);
        
        const newPayloads = parsedUnifiedAnalysis.new_payloads || [];
        if (newPayloads.length > 0) {
            console.log(`✅ [Legacy UI Update] Generated ${newPayloads.length} LLM payloads via executeLLMAnalysis`);
        }
        
        await saveLLMAnalysisToReport(analysisStorageKey, parsedUnifiedAnalysis);
        
        if (newPayloads.length > 0) {
            await handleLLMPayloadUpdate(newPayloads, analysisStorageKey);
        }
        
        updateLLMStatus('Complete!', 'success');
        // Re-enable button after completion
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
        }
        
    } catch (error) {
        console.error('LLM analysis error:', error);
        updateLLMStatus(`Analysis failed: ${error.message}`, 'error');
        // Re-enable button on error
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
        }
    }
}

async function handleLLMPayloadUpdate(newPayloads, analysisStorageKey) {
    if (newPayloads && newPayloads.length > 0) {
        console.log(`🚀 [Payloads] Starting update with ${newPayloads.length} new payloads.`);
        
        await updatePayloadsWithLLM({
            payloads_generated: true,
            new_payloads: newPayloads
        }, analysisStorageKey);

        console.log(`✅ [Payloads] Successfully processed ${newPayloads.length} LLM payloads.`);
    } else {
        console.log('🤔 [Payloads] No new LLM payloads to process.');
    }
}

async function getReportData(analysisStorageKey) {
    try {
        const reportData = await window.traceReportStorage.getTraceReport(analysisStorageKey);
        
        if (!reportData) {
            console.error('No report data found for key:', analysisStorageKey);
            return null;
        }
        
        console.log('Report data structure:', {
            hasDetails: !!reportData.details,
            hasBestHandler: !!reportData.details?.bestHandler,
            hasAnalyzedHandler: !!reportData.details?.analyzedHandler,
            bestHandlerKeys: reportData.details?.bestHandler ? Object.keys(reportData.details.bestHandler) : [],
            analyzedHandlerKeys: reportData.details?.analyzedHandler ? Object.keys(reportData.details.analyzedHandler) : []
        });
        
        return reportData;
    } catch (error) {
        console.error('Error getting report data:', error);
        return null;
    }
}

async function getMessagesForAnalysis(analysisStorageKey) {
    try {
        const messages = (window.frogPostState?.messages || []).filter(msg => {
            const k = analysisStorageKey;
            const o = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
            const d = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
            const isTest = (typeof msg.data === 'object' && msg.data !== null && Object.prototype.hasOwnProperty.call(msg.data, 'FrogPost') && msg.data['FrogPost'] === 'BreakpointTest');
            return !isTest && (o === k || d === k);
        });
        
        const structureGroups = {};
        messages.forEach(msg => {
            const structure = JSON.stringify(msg.data);
            if (!structureGroups[structure]) {
                structureGroups[structure] = [];
            }
            if (structureGroups[structure].length < 3) {
                structureGroups[structure].push(msg);
            }
        });
        
        return Object.values(structureGroups).flat();
    } catch (error) {
        console.error('Error getting messages:', error);
        return [];
    }
}


function updateLLMStatus(message, type) {
    const analyzeBtn = document.getElementById('analyze-llm');
    if (analyzeBtn) {
        const originalText = '🚀 Analyze';
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : '⏳';
        analyzeBtn.textContent = `${icon} ${message}`;
        analyzeBtn.className = `llm-analyze-button ${type}`;
        
        // Only auto-reset for success messages, not for info (analyzing) messages
        if (type === 'success') {
            setTimeout(() => {
                analyzeBtn.textContent = originalText;
                analyzeBtn.className = 'llm-analyze-button';
            }, 3000);
        }
        // For error messages, keep them visible until manually reset
        // For info messages (analyzing), keep them until the next status update
    }
}

function resetAnalyzeButton() {
    const analyzeBtn = document.getElementById('analyze-llm');
    if (analyzeBtn) {
        analyzeBtn.textContent = '🚀 Analyze';
        analyzeBtn.className = 'llm-analyze-button';
        analyzeBtn.disabled = false;
    }
}

function updateHandlerWithLLMAnalysis(analysis) {
    const handlerSection = document.querySelector('.report-handler');
    if (!handlerSection) return;

    const summaryElement = handlerSection.querySelector('.handler-meta');
    if (summaryElement && !analysis.error) {
        const cleanText = summaryElement.textContent.replace(/\s*\|\s*(LLM Score|Risk Score):[^|]*/ig, '');
        summaryElement.textContent = cleanText;
        
        const codeBlock = handlerSection.querySelector('.handler-code');
        if (codeBlock) {
            const existingSummary = codeBlock.parentNode.querySelector('.llm-handler-summary');
            if (existingSummary) {
                existingSummary.remove();
            }
            
            const assessment = analysis.security_assessment || analysis.handler_assessment || 'No assessment provided';
            const riskScore = analysis.risk_score || analysis.handler_score || 0;
            
            let llmSummary = `
                <div class="llm-handler-summary" style="margin-top: 15px; padding: 12px; background: var(--bg-primary); border-radius: 6px; border: 1px solid var(--border-color);">
                    <h6 style="margin: 0 0 8px 0; color: var(--accent-primary); font-size: 13px;">🤖 LLM Handler Summary</h6>
                    <p style="margin: 4px 0; font-size: 12px;"><strong>Security Assessment:</strong> ${assessment}</p>
                    <p style="margin: 4px 0; font-size: 12px;"><strong>Risk Score:</strong> ${riskScore}/100</p>
            `;
            
            const handlerMatch = typeof analysis.handler_match === 'number' ? analysis.handler_match
                                  : (typeof analysis.match_score === 'number' ? analysis.match_score : null);
            console.log(handlerMatch)
            if (handlerMatch !== null) {
                const matchColor = handlerMatch >= 85 ? '#22c55e' : handlerMatch >= 60 ? '#d97706' : '#dc2626';
                llmSummary += `<p style="margin: 4px 0; font-size: 12px;"><strong>Handler Match:</strong> <span style="color: ${matchColor};">${handlerMatch}/100</span></p>`;
            }
            
            if (analysis.dom_xss_sinks && analysis.dom_xss_sinks.length > 0) {
                const sinksText = Array.isArray(analysis.dom_xss_sinks) 
                    ? analysis.dom_xss_sinks.map(sink => typeof sink === 'object' ? sink.sink || sink.type : sink).join(', ')
                    : analysis.dom_xss_sinks;
                llmSummary += `<p style="margin: 4px 0; font-size: 12px;"><strong>DOM XSS Sinks:</strong> ${sinksText}</p>`;
            }
            
            if (analysis.prototype_pollution) {
                llmSummary += `<p style="margin: 4px 0; font-size: 12px; color: #ff6b6b;"><strong>⚠️ Prototype Pollution Risk Detected</strong></p>`;
            }
            
            if (analysis.recommendations && analysis.recommendations.length > 0) {
                llmSummary += `<p style="margin: 4px 0; font-size: 12px;"><strong>Recommendations:</strong> ${analysis.recommendations.join('; ')}</p>`;
            }
            
            llmSummary += `</div>`;
            codeBlock.insertAdjacentHTML('afterend', llmSummary);
        }
    }
}
async function saveLLMAnalysisToReport(analysisStorageKey, llmAnalysis) {
    try {
        const reportData = await window.traceReportStorage.getTraceReport(analysisStorageKey);
        if (reportData) {
            if (!reportData.llmAnalysis) {
                reportData.llmAnalysis = {};
            }
            const existing = reportData.llmAnalysis.handlerAnalysis || {};
            reportData.llmAnalysis.handlerAnalysis = { ...existing, ...llmAnalysis };


            await window.traceReportStorage.saveTraceReport(analysisStorageKey, reportData);
            console.log('💾 [LLM Analysis] Saved handler analysis to report data');
        }
    } catch (error) {
        console.error('Error saving LLM analysis to report:', error);
    }
}

async function updatePayloadsWithLLM(payloadAnalysis, analysisStorageKey) {
    if (!payloadAnalysis.payloads_generated || payloadAnalysis.error) {
        return;
    }

    try {
        const existingPayloads = await window.traceReportStorage.getReportPayloads(analysisStorageKey) || [];
        
        const llmPayloads = payloadAnalysis.new_payloads || [];
        
        console.log(`🎯 [Payloads] Attempting to add ${llmPayloads.length} LLM-generated payloads`);
        
        if (llmPayloads.length > 0) {
            const updatedPayloads = [...existingPayloads, ...llmPayloads];
            await window.traceReportStorage.saveReportPayloads(analysisStorageKey, updatedPayloads);
            
            await window.traceReportStorage.saveLLMPayloadCount(analysisStorageKey, llmPayloads.length);
            
            const payloadCountElement = document.querySelector(`[id*="payload-count-display"]`);
            if (payloadCountElement) {
                const currentCount = parseInt(payloadCountElement.textContent) || 0;
                const newCount = currentCount + llmPayloads.length;
                payloadCountElement.textContent = newCount;
                
                const payloadSection = payloadCountElement.closest('.metric');
                if (payloadSection) {
                    const existingIndicator = payloadSection.querySelector('.llm-payload-indicator');
                    if (!existingIndicator) {
                        const indicator = document.createElement('div');
                        indicator.className = 'llm-payload-indicator';
                        indicator.style.cssText = 'font-size: 10px; color: var(--accent-primary); margin-top: 2px;';
                        indicator.textContent = `+${llmPayloads.length} Added by LLM!`;
                        payloadCountElement.parentNode.appendChild(indicator);
                    }
                }
            }
            
            const payloadsList = document.getElementById('payloads-list');
            if (payloadsList) {
                const reportButton = document.querySelector('.iframe-report-button');
                if (reportButton) {
                    reportButton.click();
                }
            }
        }
    } catch (error) {
        console.error('Error updating payloads with LLM results:', error);
    }
}

function getWorstRiskLevel(levelA, levelB) {
  const order = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
  const a = order[String(levelA || 'LOW').toUpperCase()] ?? 0;
  const b = order[String(levelB || 'LOW').toUpperCase()] ?? 0;
  const worst = a >= b ? String(levelA || 'LOW').toUpperCase() : String(levelB || 'LOW').toUpperCase();
  return worst;
}

function getRiskBadgeClass(level) {
  const map = { 'LOW': 'risk-low', 'MEDIUM': 'risk-medium', 'HIGH': 'risk-high', 'CRITICAL': 'risk-critical' };
  return map[String(level || 'LOW').toUpperCase()] || 'risk-low';
}

function createRiskBadge(level) {
  const normalized = String(level || 'LOW').toUpperCase();
  return `<span class="risk-badge ${getRiskBadgeClass(normalized)}">${normalized}</span>`;
}

function summarizeTypesFromDetections(sanitizedMessages) {
  const allTypes = new Set();
  sanitizedMessages?.forEach(m => {
    if (m?.detection?.detectedTypes) {
      m.detection.detectedTypes.forEach(t => allTypes.add(t));
    }
  });
  return Array.from(allTypes);
}

function computeMessagesRisk(messages) {
  try {
    const detector = new SensitiveDataDetector();
    const analysis = detector.analyzeLLMSafety(messages || []);
    const types = summarizeTypesFromDetections(analysis.sanitizedMessages);
    const has = analysis.sensitiveMsgCount > 0;
    const summary = has
      ? `Found ${analysis.sensitiveMsgCount}/${analysis.totalMessages} messages with sensitive data (${types.join(', ') || 'types unknown'})`
      : 'No sensitive data detected in messages';
    return {
      level: String(analysis.riskLevel || 'LOW').toUpperCase(),
      summary,
      recommendations: analysis.recommendations || []
    };
  } catch (e) {
    return { level: 'LOW', summary: 'Risk analysis unavailable', recommendations: [] };
  }
}

function computeStructuresRisk(structures) {
  try {
    const detector = new SensitiveDataDetector();
    let worst = 'LOW';
    let totalSensitive = 0;
    const types = new Set();
    (structures || []).forEach(s => {
      const example = s?.examples?.[0]?.data ?? s?.examples?.[0] ?? s;
      const det = detector.detectSensitiveData(example);
      if (det?.hasSensitiveData) {
        totalSensitive += 1;
        worst = getWorstRiskLevel(worst, det.riskLevel);
        det.detectedTypes?.forEach?.(t => types.add(t));
      }
    });
    const summary = totalSensitive > 0
      ? `Sensitive indicators in ${totalSensitive}/${(structures || []).length} structures (${Array.from(types).join(', ') || 'types unknown'})`
      : 'No sensitive indicators in example structures';
    const recs = totalSensitive > 0 ? ['Review and redact sensitive fields from structure examples'] : [];
    return { level: String(worst || 'LOW').toUpperCase(), summary, recommendations: recs };
  } catch {
    return { level: 'LOW', summary: 'Risk analysis unavailable', recommendations: [] };
  }
}

function mapSeverityToRisk(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH') return 'HIGH';
  if (s === 'MEDIUM') return 'MEDIUM';
  if (!s) return 'LOW';
  return 'LOW';
}

function computeSeverityArrayRisk(items) {
  let worst = 'LOW';
  (items || []).forEach(it => { worst = getWorstRiskLevel(worst, mapSeverityToRisk(it?.severity)); });
  return String(worst || 'LOW').toUpperCase();
}

function computeSinksRisk(sinks) {
  const level = computeSeverityArrayRisk(sinks || []);
  const summary = (sinks?.length || 0) > 0 ? `Detected ${sinks.length} potential sinks` : 'No sinks detected';
  const recs = (sinks?.length || 0) > 0 ? ['Validate data paths and sanitize before sink usage'] : [];
  return { level, summary, recommendations: recs };
}

function computeIssuesRisk(issues) {
  const level = computeSeverityArrayRisk(issues || []);
  const summary = (issues?.length || 0) > 0 ? `${issues.length} security issues reported` : 'No security issues reported';
  const recs = (issues?.length || 0) > 0 ? ['Prioritize remediation of highest-severity issues'] : [];
  return { level, summary, recommendations: recs };
}

function computePayloadsRisk(count) {
  const summary = `${count} default payloads ready`;
  const recs = ['Use responsibly in controlled environments'];
  return { level: 'LOW', summary, recommendations: recs };
}

function getRecommendationText(score, reportData) { const hasCriticalSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'critical') || false; const hasHighSink = reportData?.details?.sinks?.some(s => s.severity?.toLowerCase() === 'high') || false; const hasHighIssue = reportData?.details?.securityIssues?.some(s => s.severity?.toLowerCase() === 'high') || false; const mediumIssueCount = reportData?.details?.securityIssues?.filter(s => s.severity?.toLowerCase() === 'medium')?.length || 0; if (hasCriticalSink) return 'Immediate attention required. Critical vulnerabilities present. Fix critical sinks (eval, innerHTML, etc.) and implement strict origin/data validation.'; if (score <= 20) return 'Immediate attention required. Security posture is critically weak. Focus on fixing high-risk issues and implementing strict origin/data validation.'; if (hasHighSink || hasHighIssue || score <= 40) return 'Significant risks identified. Implement strict origin checks and sanitize all inputs used in sinks. Consider a Content Security Policy (CSP).'; if (mediumIssueCount >= 3 || score <= 60) return 'Potential vulnerabilities detected. Review security issues (e.g., origin checks, data validation) and ensure data flowing to sinks is safe.'; if (score <= 80) return 'Low risk detected, but review identified issues and follow security best practices (origin/data validation).'; const hasFindings = (reportData?.details?.sinks?.length > 0) || (reportData?.details?.securityIssues?.length > 0); if (hasFindings) return 'Good score, but minor issues or informational findings detected. Review details and ensure best practices are followed.'; return 'Excellent score. Analysis found no major vulnerabilities. Continue to follow security best practices for postMessage handling.'; }

function renderStructureItem(structureData, index) { const exampleData = structureData.examples?.[0]?.data || structureData.examples?.[0] || {}; let formattedExample = ''; try { formattedExample = typeof exampleData === 'string' ? exampleData : JSON.stringify(exampleData, null, 2); } catch (e) { formattedExample = String(exampleData); } return `<details class="report-details structure-item" data-structure-index="${index}"><summary class="report-summary-toggle">Structure ${index + 1} <span class="toggle-icon">▶</span></summary><div class="structure-content"><p><strong>Example Message:</strong></p><div class="report-code-block"><pre><code>${escapeHTML(formattedExample)}</code></pre></div></div></details>`; }

function attachReportEventListeners(panel, reportData) { panel.querySelectorAll('details.report-details').forEach(detailsElement => { const iconElement = detailsElement.querySelector('.toggle-icon'); if (detailsElement && iconElement) { detailsElement.addEventListener('toggle', () => { iconElement.textContent = detailsElement.open ? '▼' : '▶'; }); } }); panel.querySelectorAll('.view-full-payload-btn').forEach(btn => { btn.addEventListener('click', (e) => { const item = e.target.closest('.payload-item'); const index = parseInt(item?.getAttribute('data-payload-index')); const payloads = reportData?.details?.payloads || []; if (payloads[index] !== undefined) showFullPayloadModal(payloads[index]); }); }); const showAllPayloadsBtn = panel.querySelector('#showAllPayloadsBtn'); if (showAllPayloadsBtn) { showAllPayloadsBtn.addEventListener('click', () => { const list = panel.querySelector('#payloads-list'); const payloads = reportData?.details?.payloads || []; if (list && payloads.length > 0) { list.innerHTML = payloads.map((p, index) => renderPayloadItem(p, index)).join(''); attachReportEventListeners(panel, reportData); } showAllPayloadsBtn.remove(); }, { once: true }); } const showAllStructuresBtn = panel.querySelector('#showAllStructuresBtn'); if (showAllStructuresBtn) { showAllStructuresBtn.addEventListener('click', () => { const list = panel.querySelector('.structures-list'); const structures = reportData?.details?.uniqueStructures || []; if (list && structures.length > 0) { list.innerHTML = structures.map((s, index) => renderStructureItem(s, index)).join(''); attachReportEventListeners(panel, reportData); } showAllStructuresBtn.remove(); }, { once: true }); }

 try {
   const providerSel = panel.querySelector('#llm-provider-inline');
   const modelSel = panel.querySelector('#llm-model-inline');
   const keyInp = panel.querySelector('#llm-key-inline');
   const saveBtn = panel.querySelector('#llm-save-inline');
   const runBtn = panel.querySelector('#llm-run-inline');
   const status = panel.querySelector('#llm-status-inline');
   const endpointKey = panel.querySelector('.llm-controls')?.dataset?.endpointKey;
   const MODEL_PRESETS = {
     openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'o3-mini'],
     anthropic: ['claude-3-5-sonnet-20240620', 'claude-3-opus-20240229', 'claude-3-haiku-20240307'],
     groq: ['llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'],
     mistral: ['mistral-large-latest', 'open-mixtral-8x7b', 'mistral-small-latest']
   };
   const populateModels = (provider, prefill) => {
     modelSel.innerHTML = '';
     const list = MODEL_PRESETS[provider] || [];
     if (list.length === 0) { const opt = document.createElement('option'); opt.value=''; opt.textContent='Select model'; modelSel.appendChild(opt); return; }
     list.forEach(m => { const opt = document.createElement('option'); opt.value = m; opt.textContent = m; modelSel.appendChild(opt); });
     if (prefill && list.includes(prefill)) modelSel.value = prefill;
   };
   if (providerSel && modelSel && keyInp && saveBtn && runBtn) {
     providerSel.addEventListener('change', () => { populateModels(providerSel.value); });
     chrome.storage.sync.get(['llm_provider','llm_model'], (stored) => {
       const p = stored?.llm_provider || 'none';
       providerSel.value = p;
       populateModels(p, stored?.llm_model);
     });
     chrome.storage.session.get(['llm_api_key'], (sess) => { if (sess?.llm_api_key) keyInp.value = sess.llm_api_key; });
     saveBtn.addEventListener('click', async (e) => {
       e.stopPropagation();
       try {
         await chrome.storage.sync.set({ llm_provider: providerSel.value || 'none', llm_model: modelSel.value || '' });
         await chrome.storage.session.set({ llm_api_key: keyInp.value || '' });
         if (status) { status.textContent = 'Saved'; setTimeout(()=> status.textContent = '', 1500); }
       } catch { if (status) status.textContent = 'Save failed'; }
     });
     runBtn.addEventListener('click', async (e) => {
       e.stopPropagation();
       if (!endpointKey) { if (status) status.textContent = 'Missing endpoint'; return; }
       try {
         runBtn.disabled = true; runBtn.textContent = 'Analyzing...';
         await analyzeWithLLM(endpointKey);
         if (status) status.textContent = 'Done'; setTimeout(()=> status.textContent = '', 2000);
       } catch (err) { if (status) status.textContent = 'Error'; }
       finally { runBtn.disabled = false; runBtn.textContent = 'Analyze with LLM'; }
     });
   }
 } catch {}
}

function renderPayloadItem(payloadItem, index) {
    if (!payloadItem) {
        return `<div class="payload-item error">Error: Invalid payload data for item ${index + 1}.</div>`;
    }

    const actualPayload = payloadItem.payload ?? payloadItem;
    const payloadJson = typeof actualPayload === 'object' ? JSON.stringify(actualPayload, null, 2) : String(actualPayload);
    const displayString = payloadJson.substring(0, 300) + (payloadJson.length > 300 ? '...' : '');

    let source = 'unknown';
    if (payloadItem.source === 'LLM' || payloadItem.generator === 'LLM') {
        source = 'LLM';
    } else if (payloadItem.type) {
        source = 'FrogPost';
    }

    let type = payloadItem.type || 'unknown';
    if (source === 'LLM') {
        type = payloadItem.payload_class || 'AI-Generated';
    } else {
        type = type.replace(/^(FrogPost|default)-/i, '');
    }

    const typeClass = `payload-type-${escapeHTML(type).split('-')[0]}`;

    return `
        <div class="payload-item" data-payload-index="${index}">
            <div class="payload-meta ${typeClass}">
                Type: ${escapeHTML(type)} | Source: ${escapeHTML(source)}
                    </div>
            <div class="report-code-block">
                <pre><code>${escapeHTML(displayString)}</code></pre>
                </div>
            ${payloadJson.length > 300 ? `<button class="control-button secondary-button view-full-payload-btn" style="margin: 0 12px 12px;">View Full Payload</button>` : ''}
            </div>`;
}

async function displayReport(reportData, panel) {
    try {
        panel.innerHTML = '';
        // Reset LLM event listeners flag when clearing report
        window.llmEventListenersSetup = false;
    } catch (clearError) {
        panel.innerHTML = '<p class="error-message">Internal error clearing report panel.</p>';
        return;
    }
    let content;
    try {
        content = document.createElement('div');
        content.className = 'trace-results-content';
        panel.appendChild(content);
    } catch (contentError) {
        panel.innerHTML = '<p class="error-message">Internal error creating report content area.</p>';
        return;
    }

    if (!reportData || typeof reportData !== 'object') {
        content.innerHTML = '<p class="error-message">Error: Invalid or missing report data.</p>';
        return;
    }
    try {
        const details = reportData.details || {};
        const summary = reportData.summary || {};
        const bestHandler = details.bestHandler || details.analyzedHandler || reportData.bestHandler || reportData.analyzedHandler;
        const sinks = details.sinks || [];
        const securityIssues = details.securityIssues || [];
        const dataFlows = details.dataFlows || [];
        const structures = details.uniqueStructures || [];
        const endpointDisplay = reportData.endpoint || reportData.originalEndpointKey || 'Unknown';
        const analysisStorageKey = reportData.analysisStorageKey || getStorageKeyForUrl(reportData.endpoint || reportData.originalEndpointKey || '');
        const originalEndpointKey = reportData.originalEndpointKey || analysisStorageKey;
        const originChecks = details.originValidationChecks || [];

        let uiMessageCount = 0;
        try {
            const TEST_MESSAGE_KEY = 'FrogPost';
            const TEST_MESSAGE_VALUE = 'BreakpointTest';
            const panelKey = analysisStorageKey;
            const relatedMessages = (window.frogPostState?.messages || []).filter(msg => {
                const originKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
                const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
                return originKey === panelKey || destKey === panelKey;
            });
            const filteredMessages = relatedMessages.filter(msg => !(typeof msg.data === 'object' && msg.data !== null && Object.prototype.hasOwnProperty.call(msg.data, TEST_MESSAGE_KEY) && msg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE));
            uiMessageCount = filteredMessages.length;
        } catch { uiMessageCount = summary.messagesAnalyzed ?? 0; }

        const currentPayloadCount = details.payloadsGeneratedCount ?? 0;
        const currentPayloadMode = details.payloadMode || 'default';
        const staticAnalysisUsed = details.staticAnalysisUsed || false;

        const escapeHTML = window.escapeHTML || function(str) { return String(str ?? '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); };
        const safeGetRisk = (score) => { try { return getRiskLevelAndColor(score); } catch(e){ return { riskLevel: 'Error', riskColor: 'critical' }; }};
        const safeGetRec = (score, data) => { try { return getRecommendationText(score, data); } catch(e){ return 'Error generating recommendation.'; }};
        const safeRenderPayload = (p, i) => { try { return renderPayloadItem(p, i); } catch(e){ return '<p class="error-message">Error rendering payload item.</p>'; }};
        const safeRenderStructure = (s, i) => { try { return renderStructureItem(s, i); } catch(e){ return '<p class="error-message">Error rendering structure item.</p>'; }};

        const uniqueVulns = sinks.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const uniqueIssues = securityIssues.filter((v, i, a) => a.findIndex(t => t?.type === v?.type && t?.context === v?.context) === i);
        const score = reportData.securityScore ?? summary.securityScore ?? 100;
        const { riskLevel, riskColor } = safeGetRisk(score);
        const safeKeyIdPart = analysisStorageKey.replace(/[^a-zA-Z0-9_-]/g, '_');

        const summarySection = document.createElement('div');
        summarySection.className = 'report-section report-summary';
        summarySection.innerHTML = `
            <h4 class="report-section-title">Analysis Summary - <span class="report-endpoint-title">${escapeHTML(endpointDisplay)}</span></h4>
            <div class="summary-grid compact">
                <div class="security-score-container">
                     <h5 class="risk-score-title">Risk</h5>
                     <div class="risk-inline-container">
                         <div class="risk-track">
                             <span class="tick t33"></span>
                             <span class="tick t67"></span>
                             <span class="risk-caret" style="left: ${Math.max(0, Math.min(100, score))}%"></span>
                     </div>
                         <span class="risk-level-text ${riskColor}">${riskLevel}</span>
                </div>
                 </div>
                 <div class="summary-metrics" id="summary-metrics">
                     <div class="metric" data-metric="handler">
                        <div class="metric-header"><span class="metric-label">Handler Security Score</span></div>
                        <span class="metric-value ${getHandlerScoreClass(Math.round(Math.max(1, Math.min(10, Math.round((10*score)/100))))) }">${Math.round(Math.max(1, Math.min(10, Math.round((10*score)/100))))}/10</span>
                     </div>
                     <div class="metric" data-metric="msgs">
                         <div class="metric-header">
                             <span class="metric-label">Msgs</span>
                         </div>
                         <span class="metric-value">${uiMessageCount}</span>
                         <div class="risk-details"></div>
                     </div>
                     <div class="metric" data-metric="structs">
                         <div class="metric-header">
                             <span class="metric-label">Structs</span>
                         </div>
                         <span class="metric-value">${structures?.length ?? 0}</span>
                         <div class="risk-details"></div>
                     </div>
                     <div class="metric" data-metric="sinks">
                         <div class="metric-header">
                             <span class="metric-label">Sinks</span>
                         </div>
                         <span class="metric-value">${uniqueVulns?.length ?? 0}</span>
                         <div class="risk-details"></div>
                     </div>
                     <div class="metric" data-metric="payloads" id="report-payload-count-metric-${safeKeyIdPart}">
                         <div class="metric-header">
                         <span class="metric-label">Payloads (<span id="payload-mode-display-${safeKeyIdPart}">${currentPayloadMode.replace(/_/g, ' ')}</span>)</span>
                         </div>
                         <span class="metric-value" id="payload-count-display-${safeKeyIdPart}">${currentPayloadCount}</span>
                         <div class="risk-details"></div>
                     </div>
                 </div>
            </div>`;
        content.appendChild(summarySection);

        try {
            const llmPayloadCount = await window.traceReportStorage.getLLMPayloadCount(analysisStorageKey);
            if (llmPayloadCount > 0) {
                const payloadSection = content.querySelector(`#report-payload-count-metric-${safeKeyIdPart}`);
                if (payloadSection) {
                    const existingIndicator = payloadSection.querySelector('.llm-payload-indicator');
                    if (!existingIndicator) {
                        const indicator = document.createElement('div');
                        indicator.className = 'llm-payload-indicator';
                        indicator.style.cssText = 'font-size: 10px; color: var(--accent-primary); margin-top: 2px;';
                        indicator.textContent = `+${llmPayloadCount} Added by LLM!`;
                        const payloadCountElement = payloadSection.querySelector(`#payload-count-display-${safeKeyIdPart}`);
                        if (payloadCountElement) {
                            payloadCountElement.parentNode.appendChild(indicator);
                        }
                    }
                }
            }
        } catch (error) {
            console.warn('Could not load LLM payload count:', error);
        }

        try {
            if (reportData.llmAnalysis && reportData.llmAnalysis.handlerAnalysis) {
                console.log('💾 [LLM Analysis] Found saved LLM analysis, displaying...');
                setTimeout(() => {
                    updateHandlerWithLLMAnalysis(reportData.llmAnalysis.handlerAnalysis);
                }, 100);
            }
        } catch (error) {
            console.warn('Could not load saved LLM analysis:', error);
        }

        try {
            const messagesForPanel = (window.frogPostState?.messages || []).filter(msg => {
                const k = analysisStorageKey;
                const o = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
                const d = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
                const isTest = (typeof msg.data === 'object' && msg.data !== null && Object.prototype.hasOwnProperty.call(msg.data, 'FrogPost') && msg.data['FrogPost'] === 'BreakpointTest');
                return !isTest && (o === k || d === k);
            });

            const risks = {
                msgs: computeMessagesRisk(messagesForPanel),
                structs: computeStructuresRisk(structures),
                sinks: computeSinksRisk(uniqueVulns),
                issues: computeIssuesRisk(uniqueIssues),
                payloads: computePayloadsRisk(currentPayloadCount)
            };

            const metricsEl = content.querySelector('#summary-metrics');
            if (metricsEl) {
                Object.entries(risks).forEach(([key, r]) => {
                    const tile = null;
                    
                });
                metricsEl.querySelectorAll('.metric').forEach(m => {
                    m.addEventListener('click', (e) => { if (e.target.closest('button') || e.target.closest('a')) return; m.classList.toggle('open'); });
                });
            }

            
        } catch {}

        const bestHandlerCode = bestHandler?.handler || bestHandler?.code;
        if (bestHandlerCode) {
            const handlerSection = document.createElement('div');
            handlerSection.className = 'report-section report-handler';
            
            const llmAnalysis = details.llmAnalysis || {};
            const handlerScore = llmAnalysis.handler_score;
            const handlerAssessment = llmAnalysis.handler_assessment;
            
            let handlerHTML = `<details class="report-details" open>
                     <summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Cat: ${escapeHTML(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▼</span></summary>
                <div class="report-code-block handler-code"><pre><code>${escapeHTML(bestHandlerCode)}</code></pre></div>`;
            
            if (handlerScore !== undefined || handlerAssessment) {
                const score = handlerScore || 0;
                const scoreColor = score >= 80 ? '#4CAF50' : score >= 60 ? '#FF9800' : score >= 40 ? '#FF5722' : '#f44336';
                const scoreDescription = score >= 80 ? 'Excellent handler detection' : 
                                      score >= 60 ? 'Good handler detection' : 
                                      score >= 40 ? 'Partial handler detection' : 'Poor/incomplete handler';
                
                handlerHTML += `
                    <div class="llm-handler-validation" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-top: 12px;">
                        <div style="display: flex; align-items: center; margin-bottom: 8px;">
                            <span style="font-size: 14px; margin-right: 6px;">🤖</span>
                            <strong style="color: #2d3748; font-size: 13px;">AI Handler Validation</strong>
                        </div>
                        ${handlerAssessment ? `<div style="font-size: 12px; line-height: 1.4; color: #4a5568; margin-bottom: 8px;">${escapeHTML(handlerAssessment)}</div>` : ''}
                        ${handlerScore !== undefined ? `
                            <div style="margin-top: 8px;">
                                <div style="font-size: 11px; color: #718096; margin-bottom: 3px;">Accuracy Score:</div>
                                <div style="background-color: #e2e8f0; border-radius: 8px; height: 18px; width: 200px; position: relative; overflow: hidden;">
                                    <div style="background: ${scoreColor}; height: 100%; width: ${Math.min(100, Math.max(0, score))}%; transition: width 0.5s ease;"></div>
                                    <div style="position: absolute; top: 0; left: 0; right: 0; text-align: center; line-height: 18px; font-weight: bold; color: #2d3748; font-size: 10px;">${score}/100</div>
                                </div>
                                <div style="margin-top: 3px; font-size: 10px; color: #718096; font-style: italic;">${scoreDescription}</div>
                            </div>
                        ` : ''}
                    </div>`;
            }
            
            handlerHTML += `</details>`;
            handlerSection.innerHTML = handlerHTML;
            content.appendChild(handlerSection);
        }

        const llmSection = createLLMAnalysisSection(analysisStorageKey, endpointDisplay);
        content.appendChild(llmSection);
        
        setupLLMEventListeners(analysisStorageKey);

        const findingsSection = document.createElement('div');
        findingsSection.className = 'report-section report-findings';
        let findingsHTML = '<h4 class="report-section-title">Findings</h4>';
        let findingsExist = false;

        const llmAnalysis = details.llmAnalysis || {};
        if (llmAnalysis.risks && Array.isArray(llmAnalysis.risks) && llmAnalysis.risks.length > 0) {
            findingsExist = true;
            findingsHTML += `
                <div class="subsection llm-security-risks">
                    <h5 class="report-subsection-title">🤖 AI-Identified Security Risks (${llmAnalysis.risks.length})</h5>
                    <div class="llm-risks-container" style="background: #fef5e7; border: 1px solid #f6ad55; border-radius: 6px; padding: 12px; margin-bottom: 15px;">
                        <ul style="margin: 0; padding-left: 20px;">
                            ${llmAnalysis.risks.map(risk => `<li style="font-size: 13px; line-height: 1.4; color: #744210; margin-bottom: 4px;">${escapeHTML(risk)}</li>`).join('')}
                        </ul>
                        ${llmAnalysis.notes ? `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #f6ad55; font-size: 11px; color: #744210; font-style: italic;">Note: ${escapeHTML(llmAnalysis.notes)}</div>` : ''}
                    </div>
                </div>`;
        }

        if (originChecks.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Origin Validation (${originChecks.length})</h5><table class="report-table"><thead><tr><th>Detection Result</th><th>Analysis Method</th><th>Code Evidence</th></tr></thead><tbody>`;
            originChecks.forEach(check => {
                const type = check?.type || '?'; 
                const strength = check?.strength || 'N/A'; 
                const value = check?.comparedValue !== null && check?.comparedValue !== undefined ? String(check.comparedValue).substring(0, 100) : 'N/A'; 
                const snippetHTML = check?.rawSnippet ? `<code class="context-snippet">${escapeHTML(check.rawSnippet)}</code>` : 'N/A';
                
                let detectionResult, analysisMethod, codeEvidence;
                
                if(strength === 'Missing') {
                    detectionResult = '<span style="color: #dc2626; font-weight: bold;">❌ NO ORIGIN VALIDATION DETECTED</span>';
                    analysisMethod = 'Static code analysis scanned entire handler for origin validation patterns (event.origin comparisons, method calls, etc.)';
                    codeEvidence = '<span style="color: #888; font-style: italic;">Handler code analyzed - no origin validation patterns found</span>';
                } else {
                    detectionResult = `<span style="color: #16a34a; font-weight: bold;">✅ ORIGIN VALIDATION FOUND</span>`;
                    analysisMethod = `Detected ${type} validation with ${strength} strength`;
                    codeEvidence = snippetHTML;
                }
                
                findingsHTML += `<tr><td>${detectionResult}</td><td>${analysisMethod}</td><td>${codeEvidence}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueVulns.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Potential Sinks Reached (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Detection Method</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueVulns.forEach(vuln => {
                const type = vuln?.name || vuln?.type || '?'; const severity = vuln?.severity || 'N/A'; const contextHTML = vuln?.context || ''; const sourcePath = vuln?.sourcePath || '(unknown)'; const conditions = vuln?.conditions || [];
                let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = escapeHTML(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${escapeHTML(c.path)} ${escapeHTML(c.op)} ${valStr}</code>`; }).join('<br>'); }
                let severityClass = severity.toLowerCase(); if(severity === 'Critical') severityClass = 'critical'; else if(severity === 'High') severityClass = 'high'; else if(severity === 'Medium') severityClass = 'medium'; else if(severity === 'Low') severityClass = 'low'; else severityClass='unknown';
                const detectionMethod = vuln?.method || 'Unknown';
                findingsHTML += `<tr class="severity-row-${severityClass}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severityClass}">${escapeHTML(severity)}</span></td><td><code>${escapeHTML(detectionMethod)}</code></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;

        }

        if (uniqueIssues.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Other Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueIssues.forEach(issue => {
                const type = issue?.type || '?'; const severity = issue?.severity || 'N/A'; const contextHTML = issue?.context || '';
                let severityClass = severity.toLowerCase(); if(severity === 'Critical') severityClass = 'critical'; else if(severity === 'High') severityClass = 'high'; else if(severity === 'Medium') severityClass = 'medium'; else if(severity === 'Low') severityClass = 'low'; else severityClass='unknown';
                const detectionMethod = issue?.method || 'Unknown';
                findingsHTML += `<tr class="severity-row-${severityClass}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severityClass}">${escapeHTML(severity)}</span></td><td><code>${escapeHTML(detectionMethod)}</code></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (!findingsExist) { findingsHTML += '<p class="no-findings-text">No significant findings detected.</p>'; }
        findingsSection.innerHTML = findingsHTML;
        content.appendChild(findingsSection);

        if (dataFlows?.length > 0) {
            const flowSection = document.createElement('div');
            flowSection.className = 'report-section report-dataflow';
            flowSection.innerHTML = ` <h4 class="report-section-title">Data Flow</h4> <table class="report-table dataflow-table"> <thead> <tr> <th>Source Property</th> <th>Sink / Target</th> <th>Conditions</th> <th>Code Snippet</th> </tr> </thead> <tbody> </tbody> </table>`;
            const tbody = flowSection.querySelector('tbody');
            if (tbody) { dataFlows.forEach(flow => { const prop = flow?.sourcePath || '?'; const sink = flow?.destinationContext || '?'; const context = flow?.fullCodeSnippet || flow?.taintedNodeSnippet || ''; const displayProp = prop === '(root)' ? '(root data)' : `event.data.${escapeHTML(prop)}`; const conditions = flow?.requiredConditionsForFlow || flow?.conditions || []; let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = escapeHTML(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${escapeHTML(c.path)} ${escapeHTML(c.op)} ${valStr}</code>`; }).join('<br>'); } const rowHtml = ` <tr> <td><code>${displayProp}</code></td> <td>${escapeHTML(sink)}</td> <td>${conditionsHtml}</td> <td><code class="context-snippet">${escapeHTML(context)}</code></td> </tr>`; tbody.insertAdjacentHTML('beforeend', rowHtml); }); }
            else { flowSection.innerHTML += '<p class="error-message">Error rendering data flow table body.</p>'; }
            content.appendChild(flowSection);
        }

        const payloadSection = document.createElement('div');
        payloadSection.className = 'report-section report-payloads';
        payloadSection.id = 'report-payload-section-' + safeKeyIdPart;

        let payloadsHTML = `<h4 class="report-section-title">Generated Payloads (<span id="payload-count-display-${safeKeyIdPart}">${currentPayloadCount}</span> - <span id="payload-mode-display-${safeKeyIdPart}">${currentPayloadMode.replace(/_/g, ' ')}</span>)</h4>`;
        payloadsHTML += `<div id="payloads-list-${safeKeyIdPart}" class="payloads-list report-list">`;

        const initiallyLoadedPayloads = details.payloads || [];
        if (currentPayloadCount > 0 && initiallyLoadedPayloads.length > 0) {
            payloadsHTML += initiallyLoadedPayloads.slice(0, 10).map((p, i) => safeRenderPayload(p, i)).join('');
        } else if (currentPayloadCount > 0) {
            payloadsHTML += `<p>Click button below to load payloads.</p>`;
        } else {
            payloadsHTML += `<p>No payloads generated yet for mode: ${currentPayloadMode.replace(/_/g, ' ')}.</p>`;
        }
        payloadsHTML += `</div>`;

        if (currentPayloadCount > 0) {
            let buttonText = `Load All ${currentPayloadCount} Payloads`;
            if (initiallyLoadedPayloads.length > 0 && initiallyLoadedPayloads.length < currentPayloadCount && initiallyLoadedPayloads.length >=10) {
                buttonText = `Load All ${currentPayloadCount} Payloads`;
            } else if (initiallyLoadedPayloads.length === currentPayloadCount && currentPayloadCount <= 10) {
                buttonText = '';
            }

            if (buttonText) {
                payloadsHTML += `<button class="control-button secondary-button show-more-btn load-payloads-btn" data-analysis-key="${escapeHTML(analysisStorageKey)}">${buttonText}</button>`;
            }
        }

        payloadSection.innerHTML = payloadsHTML;
        content.appendChild(payloadSection);

        if (structures?.length > 0) {
            const structureSection = document.createElement('div');
            structureSection.className = 'report-section report-structures';
            let structuresHTML = `<h4 class="report-section-title">Unique Msg Structures (${structures.length})</h4><div class="structures-list report-list">`;
            structures.slice(0, 3).forEach((s, i) => { structuresHTML += safeRenderStructure(s, i); }); structuresHTML += `</div>`;
            if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length}</button>`; }
            structureSection.innerHTML = structuresHTML;
            content.appendChild(structureSection);
        }

        const bottomButtonContainer = document.createElement('div'); bottomButtonContainer.style.cssText = 'margin-top:20px; display: flex; justify-content: center; gap: 15px;'; 
        
        const exportJsonBtn = document.createElement('button'); exportJsonBtn.textContent = 'Export JSON'; exportJsonBtn.className = 'control-button secondary-button'; exportJsonBtn.addEventListener('click', (e) => { e.stopPropagation(); try { const jsonData = JSON.stringify(reportData, null, 2); const blob = new Blob([jsonData], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); const safeFilename = (analysisStorageKey || 'frogpost_report').replace(/[^a-z0-9_\-.]/gi, '_'); a.href = url; a.download = `${safeFilename}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); } catch (exportError) { alert("Failed to export report as JSON."); } }); 
        
        const ignoreBtn = document.createElement('button'); ignoreBtn.textContent = '🚫 Add to Ignore List'; ignoreBtn.className = 'control-button danger-button'; ignoreBtn.title = 'Hide this endpoint from results'; ignoreBtn.addEventListener('click', async (e) => { e.stopPropagation(); if (confirm(`Add "${analysisStorageKey}" to ignore list?\n\nThis endpoint will be hidden from the dashboard until removed from the ignore list.`)) { await addToIgnoreList(analysisStorageKey); showToastNotification(`Endpoint added to ignore list`, 'success', 3000); } }); 
        
        const closeBtnInside = document.createElement('button'); closeBtnInside.textContent = 'Close Report'; closeBtnInside.className = 'control-button secondary-button'; closeBtnInside.onclick = () => { document.querySelector('.trace-panel-backdrop')?.remove(); panel.remove(); }; 
        
        bottomButtonContainer.appendChild(exportJsonBtn); bottomButtonContainer.appendChild(ignoreBtn); bottomButtonContainer.appendChild(closeBtnInside); content.appendChild(bottomButtonContainer);
        attachReportEventListeners(panel, reportData);

    } catch (renderError) {
        content.innerHTML = `<p class="error-message">Error rendering report details: ${renderError.message}</p>`;
        console.error("Error rendering report:", renderError);
    }
}


function showFullPayloadModal(payloadItem) {
    document.querySelector('.payload-modal')?.remove(); document.querySelector('.payload-modal-backdrop')?.remove(); const modal = document.createElement('div'); modal.className = 'payload-modal'; const modalContent = document.createElement('div'); modalContent.className = 'payload-modal-content'; const closeBtn = document.createElement('span'); closeBtn.className = 'close-modal'; closeBtn.innerHTML = '&times;'; const backdrop = document.createElement('div'); backdrop.className = 'payload-modal-backdrop'; const closeModal = () => { modal.remove(); backdrop.remove(); }; closeBtn.onclick = closeModal; backdrop.onclick = closeModal; const heading = document.createElement('h4'); const targetInfo = document.createElement('p'); targetInfo.style.cssText = 'margin-bottom:15px;font-size:13px;color:#aaa;'; const payloadPre = document.createElement('pre'); payloadPre.className = 'report-code-block'; payloadPre.style.cssText = 'max-height:50vh;overflow-y:auto;'; const payloadCode = document.createElement('code'); const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem; heading.textContent = `Payload Details (Type: ${escapeHTML(payloadItem?.type || 'unknown')})`; targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payloadItem?.targetPath || payloadItem?.targetFlow || payloadItem?.description || 'N/A')}`; let formattedPayload = ''; try { if (typeof actualPayloadData === 'object' && actualPayloadData !== null) formattedPayload = JSON.stringify(actualPayloadData, null, 2); else formattedPayload = String(actualPayloadData); } catch { formattedPayload = String(actualPayloadData); } payloadCode.textContent = formattedPayload; payloadPre.appendChild(payloadCode); const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy Payload'; copyBtn.className = 'control-button'; copyBtn.style.marginTop = '15px'; copyBtn.onclick = () => { navigator.clipboard.writeText(formattedPayload).then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }).catch(() => { copyBtn.textContent = 'Copy Failed'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }); }; modalContent.appendChild(closeBtn); modalContent.appendChild(heading); modalContent.appendChild(targetInfo); modalContent.appendChild(payloadPre); modalContent.appendChild(copyBtn); modal.appendChild(modalContent); document.body.appendChild(backdrop); document.body.appendChild(modal);
}

async function handleReportButton(endpointKey) {
    let reportData = null;
    let reportPayloads = null;
    let keyUsed = endpointKey;
    
    try {
        const traceInfoKey = `trace-info-${endpointKey}`;
        const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
        const traceInfo = traceInfoResult[traceInfoKey];
        
        if (traceInfo?.analysisStorageKey) {
            keyUsed = traceInfo.analysisStorageKey;
        } else if (traceInfo?.analyzedUrl) {
            keyUsed = getStorageKeyForUrl(traceInfo.analyzedUrl);
        }
        
        [reportData, reportPayloads] = await Promise.all([
            window.traceReportStorage.getTraceReport(keyUsed),
            window.traceReportStorage.getReportPayloads(keyUsed)
        ]);
        
        if (!reportData && keyUsed !== endpointKey) {
            keyUsed = endpointKey;
            [reportData, reportPayloads] = await Promise.all([
                window.traceReportStorage.getTraceReport(keyUsed),
                window.traceReportStorage.getReportPayloads(keyUsed)
            ]);
        }
        
        if (!reportData || typeof reportData !== 'object') {
            throw new Error(`No report data found for key ${keyUsed}. Run Trace first.`);
        }
        
        if (!reportData.details) reportData.details = {};
        reportData.details.payloads = reportPayloads || [];
        
        if (!reportData.summary) reportData.summary = {};
        reportData.summary.payloadsGenerated = reportPayloads?.length || 0;
        
        document.querySelector('.trace-results-panel')?.remove();
        document.querySelector('.trace-panel-backdrop')?.remove();
        
        const tracePanel = document.createElement('div');
        tracePanel.className = 'trace-results-panel';
        
        const backdrop = document.createElement('div');
        backdrop.className = 'trace-panel-backdrop';
        backdrop.onclick = () => {
            tracePanel.remove();
            backdrop.remove();
        };
        
        const reportContainer = document.getElementById('reportPanelContainer') || document.body;
        reportContainer.appendChild(backdrop);
        reportContainer.appendChild(tracePanel);
        
        addTraceReportStyles();
        await displayReport(reportData, tracePanel);
        
    } catch (error) {
        log.error('Error handling report button:', error);
        alert(`Failed to display report: ${error?.message}`);
    }
}
/**
 * On dashboard load, restore and render the last report for the current endpoint.
 */
async function restoreLastReport(endpointKey) {
  try {
    if (!endpointKey) return;
    
    console.log(`🔄 [Restore] Checking for saved report for ${endpointKey}`);
    const stored = await window.traceReportStorage.getTraceReport(endpointKey);
    const payloads = await window.traceReportStorage.getReportPayloads(endpointKey);
    
    if (stored && stored.details && stored.timestamp) {
      console.log(`🎨 [Restore] Rendering saved report from ${new Date(stored.timestamp).toLocaleString()}`);
      renderReportUI(stored, payloads || []);
    } else {
      console.log(`ℹ️ [Restore] No saved report found for ${endpointKey}.`);
      const reportContent = document.getElementById('report-content');
      if (reportContent) {
      }
    }
  } catch (e) {
    console.warn('⚠️ [Restore] Restore report failed', e);
  }
}


async function populateInitialHandlerStates() {
    log.debug("Populating initial handler states...");
    try {
        const response = await new Promise((resolve) => {
            chrome.runtime.sendMessage({ type: "fetchInitialState" }, (res) => {
                if (chrome.runtime.lastError) resolve({ success: false, error: chrome.runtime.lastError.message });
                else resolve(res);
            });
        });

        endpointsWithDetectedHandlers.clear();

        if (response?.success) {
            if (response.messages) {
                window.frogPostState.messages.length = 0;
                window.frogPostState.messages.push(...response.messages);
            }
            if (response.handlerEndpointKeys && Array.isArray(response.handlerEndpointKeys)) {
                response.handlerEndpointKeys.forEach(key => endpointsWithDetectedHandlers.add(key));
                log.debug(`Populated ${endpointsWithDetectedHandlers.size} handler keys from background state.`);
            } else {
                log.debug("No handler keys received from background state.");
            }
        } else {
            log.warn("Could not fetch initial state from background:", response?.error);
        }
    } catch (error) {
        log.error("Error populating initial handler states:", error);
        endpointsWithDetectedHandlers.clear();
    }
}
const traceReportStyles = `.trace-results-panel {} .trace-panel-backdrop {} .trace-panel-header {} .trace-panel-close {} .trace-results-content {} .report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; } .report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); } .report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; } .report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 0; align-items: center; margin-bottom: 20px; } .security-score-container { display: flex; justify-content: center; } .security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); } .security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; } .security-score div { position: relative; z-index: 2; } .security-score-value { font-size: 28px; line-height: 1; } .security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; } .security-score.critical { border-color: #e74c3c; } .security-score.high { border-color: #e67e22; } .security-score.medium { border-color: #f39c12; } .security-score.low { border-color: #3498db; } .security-score.negligible { border-color: #2ecc71; } .summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; } .metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; } .metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; } .metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; } .recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; } .recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; } .report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; } .report-code-block pre { margin: 0; } .report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; } .report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; } details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; } summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; } summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); } details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; } .toggle-icon { font-size: 1.2em; transition: transform 0.2s; } details[open] .toggle-icon { transform: rotate(90deg); } .report-details > div { padding: 15px; } .report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; } .report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; } .report-table th { background-color: #2c313a; font-weight: bold; color: #fff; } .report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; } .report-table .context-snippet { max-width: 400px; white-space: pre-wrap; word-break: break-all; display: inline-block; vertical-align: middle; } .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; } .severity-critical { background-color: #e74c3c; color: white; } .severity-high { background-color: #e67e22; color: white; } .severity-medium { background-color: #f39c12; color: #333; } .severity-low { background-color: #3498db; color: white; } .severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); } .severity-row-high td { background-color: rgba(230, 126, 34, 0.15); } .severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); } .severity-row-low td { background-color: rgba(52, 152, 219, 0.1); } .no-findings-text { color: #777; font-style: italic; padding: 10px 0; } .dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; } .report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; } .payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; } .payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; } .payload-header strong { color: #fff; } .payload-meta { color: #8be9fd; margin: 0 5px; } .payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; } .structure-content { padding: 15px; } .structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; } .structure-content strong { color: #00e1ff; } .structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; } .show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; } .show-more-btn:hover { background-color: #4a5058; color: #fff; } .control-button {} .secondary-button {} .error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; } span.highlight-finding { background-color: rgba(255, 0, 0, 0.3); color: #ffdddd; font-weight: bold; padding: 1px 2px; border-radius: 2px; border: 1px solid rgba(255, 100, 100, 0.5); }`;

const progressStyles = `.trace-progress-container { position: fixed; bottom: 20px; right: 20px; background: rgba(40, 44, 52, 0.95); padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); z-index: 1001; border: 1px solid #555; font-family: sans-serif; width: 280px; color: #d0d8e8; } .trace-progress-container h4 { margin: 0 0 12px 0; font-size: 14px; color: #00e1ff; border-bottom: 1px solid #444; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; } .phase-list { display: flex; flex-direction: column; gap: 10px; } .phase { display: flex; align-items: center; gap: 12px; padding: 8px 12px; border-radius: 4px; transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease; border: 1px solid #444; } .phase .emoji { font-size: 20px; line-height: 1; } .phase .label { font-size: 13px; flex-grow: 1; color: #a8b3cf; } .phase.active { background-color: rgba(0, 225, 255, 0.1); border-color: #00e1ff; animation: pulse-border 1.5s infinite; } .phase.active .label { color: #fff; font-weight: 600; } .phase.active .emoji { animation: spin 1s linear infinite; } .phase.completed { background-color: rgba(80, 250, 123, 0.1); border-color: #50fa7b; } .phase.completed .label { color: #50fa7b; } .phase.completed .emoji::before { content: '✅'; } .phase.error { background-color: rgba(255, 85, 85, 0.1); border-color: #ff5555; } .phase.error .label { color: #ff5555; font-weight: 600; } .phase.error .emoji::before { content: '❌'; } .phase[data-phase="finished"], .phase[data-phase="error"] { display: none; } .phase[data-phase="finished"].completed, .phase[data-phase="error"].error { display: flex; } @keyframes pulse-border { 0% { border-color: #00e1ff; } 50% { border-color: rgba(0, 225, 255, 0.5); } 100% { border-color: #00e1ff; } } @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`;

function addTraceReportStyles() { if (!document.getElementById('frogpost-report-styles')) { const styleElement = document.createElement('style'); styleElement.id = 'frogpost-report-styles'; styleElement.textContent = traceReportStyles; document.head.appendChild(styleElement); } }
window.addTraceReportStyles = addTraceReportStyles;

function addProgressStyles() { if (!document.getElementById('frogpost-progress-styles')) { const styleEl = document.createElement('style'); styleEl.id = 'frogpost-progress-styles'; styleEl.textContent = progressStyles; document.head.appendChild(styleEl); } }
window.addProgressStyles = addProgressStyles;

let serverStatus = { running: false, lastCheck: 0 };

async function checkServerStatus() {
    try {
        const response = await fetch('http://127.0.0.1:1337/health', { 
            method: 'GET',
            signal: AbortSignal.timeout(2000)
        });
        serverStatus.running = response.ok;
        serverStatus.lastCheck = Date.now();
        return serverStatus.running;
    } catch {
        serverStatus.running = false;
        serverStatus.lastCheck = Date.now();
        return false;
    }
}

function updateServerStatusUI() {
    const badge = document.getElementById('server-status-badge');
    if (!badge) return;
    
    const isRunning = serverStatus.running;
    const statusText = badge.querySelector('.status-text');
    
    // Remove all status classes
    badge.classList.remove('online', 'offline', 'checking');
    
    // Add appropriate class
    if (isRunning) {
        badge.classList.add('online');
        if (statusText) statusText.textContent = 'Server: Online';
    } else {
        badge.classList.add('offline');
        if (statusText) statusText.textContent = 'Server: Offline';
    }
}

function addServerStatusToUI() {
    const container = document.querySelector('.container') || document.body;
    const statusHTML = `
        <div id="server-status-container" style="position: sticky; top: 0; z-index: 100; background: var(--bg-primary); padding: 8px 0; border-bottom: 1px solid var(--border-color);">
            <div id="server-status"></div>
        </div>`;
    container.insertAdjacentHTML('afterbegin', statusHTML);
    
    const style = document.createElement('style');
    style.textContent = `
        .server-status {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            background: var(--bg-secondary);
        }
        .server-status.running {
            border: 1px solid #22c55e;
            background: #22c55e15;
        }
        .server-status.stopped {
            border: 1px solid #ef4444;
            background: #ef444415;
        }
        .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .status-indicator.green { background: #22c55e; }
        .status-indicator.red { background: #ef4444; }
        .server-status small {
            margin-left: auto;
            opacity: 0.7;
        }
        .server-status code {
            background: var(--bg-primary);
            padding: 2px 4px;
            border-radius: 3px;
            font-size: 11px;
        }
    `;
    document.head.appendChild(style);
}

// Clean extension storage on load (development/testing)
async function cleanExtensionStorage() {
    try {
        log.info('[Storage Cleanup] Starting extension storage cleanup...');
        
        // Get all storage keys
        const allLocalStorage = await chrome.storage.local.get(null);
        const allSessionStorage = await chrome.storage.session.get(null);
        const allSyncStorage = await chrome.storage.sync.get(null);
        
        // Keys to preserve (settings that should persist)
        // Note: Auto Pilot state is intentionally NOT preserved - it resets to OFF on load
        const preserveKeys = [
            AUTOPILOT_WARNING_SHOWN_KEY,
            DEBUGGER_MODE_STORAGE_KEY,
            'llm_provider',
            'llm_model',
            'llm_api_key'
        ];
        
        // CRITICAL: Also preserve data keys (telemetry, reports, caches)
        const preserveKeyPatterns = [
            'dom-agent-telemetry-',    // Handler telemetry from runtime
            'trace-report-',            // Saved trace reports
            'failed-endpoints',         // Failed endpoint cache
            'ignored-endpoints',        // User-ignored endpoints
            'autopilot-scanned-endpoints', // Auto Pilot history
            'frogpost-messages-',       // Intercepted messages
        ];
        
        // Clear local storage except preserved keys
        const localKeysToRemove = Object.keys(allLocalStorage).filter(key => {
            // Keep if in exact match list
            if (preserveKeys.includes(key)) return false;
            // Keep if matches any pattern
            if (preserveKeyPatterns.some(pattern => key.startsWith(pattern))) return false;
            return true;
        });
        
        const telemetryCount = Object.keys(allLocalStorage).filter(k => k.startsWith('dom-agent-telemetry-')).length;
        const messagesCount = Object.keys(allLocalStorage).filter(k => k.startsWith('frogpost-messages-')).length;
        log.info(`[Storage Cleanup] Preserving ${telemetryCount} telemetry entries, ${messagesCount} message caches`);
        
        if (localKeysToRemove.length > 0) {
            await chrome.storage.local.remove(localKeysToRemove);
            log.info(`[Storage Cleanup] Cleared ${localKeysToRemove.length} local storage keys (preserved ${Object.keys(allLocalStorage).length - localKeysToRemove.length})`);
        } else {
            log.info(`[Storage Cleanup] No local storage keys to clear`);
        }
        
        // Clear session storage except preserved keys
        const sessionKeysToRemove = Object.keys(allSessionStorage).filter(key => {
            if (preserveKeys.includes(key)) return false;
            if (preserveKeyPatterns.some(pattern => key.startsWith(pattern))) return false;
            return true;
        });
        if (sessionKeysToRemove.length > 0) {
            await chrome.storage.session.remove(sessionKeysToRemove);
            log.info(`[Storage Cleanup] Cleared ${sessionKeysToRemove.length} session storage keys`);
        }
        
        // Clear sync storage except preserved keys
        const syncKeysToRemove = Object.keys(allSyncStorage).filter(key => {
            if (preserveKeys.includes(key)) return false;
            if (preserveKeyPatterns.some(pattern => key.startsWith(pattern))) return false;
            return true;
        });
        if (syncKeysToRemove.length > 0) {
            await chrome.storage.sync.remove(syncKeysToRemove);
            log.info(`[Storage Cleanup] Cleared ${syncKeysToRemove.length} sync storage keys`);
        }
        
        // Clear in-memory state
        window.frogPostState.messages.length = 0;
        knownHandlerEndpoints.clear();
        endpointsWithHandlers.clear();
        endpointsWithDetectedHandlers.clear();
        buttonStates.clear();
        reportButtonStates.clear();
        traceButtonStates.clear();
        launchInProgressEndpoints.clear();
        customUrlsList = [];
        ignoredEndpoints.clear();
        autoPilotScannedEndpoints.clear();
        autoPilotActiveScans.clear();
        
        // Reset Auto Pilot to OFF by default on load (do this AFTER cleanup)
        autoPilotEnabled = false;
        autoPilotScanInProgress = false; // Deprecated, kept for compatibility
        await chrome.storage.sync.set({ 
            [AUTOPILOT_ENABLED_KEY]: false,
            [AUTOPILOT_SCANNED_KEY]: [],
            [URL_SCAN_IN_PROGRESS_KEY]: false 
        });
        
        log.success('[Storage Cleanup] Extension storage cleaned successfully');
        log.info('[Storage Cleanup] Auto Pilot reset to OFF');
    } catch (error) {
        log.error('[Storage Cleanup] Failed to clean storage:', error);
    }
}

/**
 * Load existing handler telemetry from storage on dashboard initialization
 * This ensures handlers captured before dashboard opened are available
 */
async function loadExistingTelemetry() {
    try {
        log.info('[Init] Querying all existing handler telemetry from storage...');
        
        // Get all storage keys
        const allStorage = await chrome.storage.local.get(null);
        const telemetryKeys = Object.keys(allStorage).filter(k => k.startsWith('dom-agent-telemetry-'));
        
        log.info(`[Init] Found ${telemetryKeys.length} existing telemetry entries`);
        
        // For each telemetry entry, ensure it's properly mapped
        telemetryKeys.forEach(key => {
            const endpointKey = key.replace('dom-agent-telemetry-', '');
            const telemetry = allStorage[key];
            
            if (telemetry?.handlers && telemetry.handlers.length > 0) {
                knownHandlerEndpoints.add(endpointKey);
                log.debug(`[Init] Loaded telemetry for: ${endpointKey} (${telemetry.handlers.length} handlers)`);
            }
        });
        
        log.success(`[Init] Loaded ${knownHandlerEndpoints.size} handler endpoints from telemetry`);
        requestUiUpdate();
    } catch (error) {
        log.error('[Init] Error loading existing telemetry:', error);
    }
}

window.addEventListener('DOMContentLoaded', async () => {
    printBanner();
    displayCurrentVersion();
    
    // Clean storage on load (comment out in production if needed)
    await cleanExtensionStorage();
    
    // Initialize Auto Pilot state
    await initializeAutoPilot();
    
    // CRITICAL: Load existing telemetry from storage
    await loadExistingTelemetry();
    
    await checkServerStatus();
    updateServerStatusUI();
    setInterval(async () => { await checkServerStatus(); updateServerStatusUI(); }, 10000);
    document.getElementById('check-version-button')?.addEventListener('click', checkLatestVersion);

    const sidebarToggle = document.getElementById('sidebarToggle');
    const controlSidebar = document.getElementById('controlSidebar');
    if (sidebarToggle && controlSidebar) {
        if (!controlSidebar.classList.contains('open')) { sidebarToggle.classList.add('animate-toggle'); }
        sidebarToggle.addEventListener('click', () => { controlSidebar.classList.toggle('open'); sidebarToggle.classList.toggle('animate-toggle', !controlSidebar.classList.contains('open')); });
    }
    const filterInput = document.getElementById('endpointFilterInput');
    if (filterInput) { filterInput.addEventListener('input', requestUiUpdate); }
    else { log.error("Could not find endpoint filter input element (#endpointFilterInput)"); }

    initializeMessageHandling();
    addTraceReportStyles();
    addProgressStyles();

    try {
        const result = await chrome.storage.local.get([DEBUGGER_MODE_STORAGE_KEY]);
        debuggerApiModeEnabled = result[DEBUGGER_MODE_STORAGE_KEY] || false;
        log.info(`Initial Debugger Mode State loaded: ${debuggerApiModeEnabled}`);
    } catch (error) {
        log.error("Error loading debugger mode state:", error);
        debuggerApiModeEnabled = false;
    }

    setupUIControls();
    updateDebuggerModeButton();
    setupCallbackUrl();
    updatePayloadStatus();

    try {
        const providerSel = document.getElementById('llmProviderSelect');
        const modelInp = document.getElementById('llmModelInput');
        const keyInp = document.getElementById('llmApiKeyInput');
        const saveBtn = document.getElementById('saveLlmSettingsBtn');
        const status = document.getElementById('llmSettingsStatus');
        if (providerSel && modelInp && keyInp && saveBtn) {
            const stored = await chrome.storage.sync.get(['llm_provider','llm_model']);
            const storedSess = await chrome.storage.session.get(['llm_api_key']);
            if (stored.llm_provider) providerSel.value = stored.llm_provider;
            if (stored.llm_model) modelInp.value = stored.llm_model;
            if (storedSess.llm_api_key) keyInp.value = storedSess.llm_api_key;
            saveBtn.addEventListener('click', async () => {
                try {
                    const provider = providerSel.value || 'none';
                    const model = modelInp.value || '';
                    const key = keyInp.value || '';
                    await chrome.storage.sync.set({ llm_provider: provider, llm_model: model });
                    await chrome.storage.session.set({ llm_api_key: key });
                    if (status) { status.textContent = 'Saved'; setTimeout(()=> status.textContent = '', 1500); }
                } catch (e) { if (status) { status.textContent = 'Save failed'; } }
            });
        }
    } catch (e) { }

    await populateInitialHandlerStates();

    try {
        chrome.storage.session.get('customXssPayloads', (result) => { if (chrome.runtime.lastError) { log.warn("Error getting custom payloads status:", chrome.runtime.lastError.message); return; } const storedPayloads = result.customXssPayloads; const active = storedPayloads && storedPayloads.length > 0; updatePayloadStatus(active, active ? storedPayloads.length : 0); if (active && window.FuzzingPayloads) { if (!window.FuzzingPayloads._originalXSS) window.FuzzingPayloads._originalXSS = [...window.FuzzingPayloads.XSS]; window.FuzzingPayloads.XSS = [...storedPayloads]; } });
    } catch (e) { log.error("Error checking custom payload status:", e); }

    if (!document.body.hasAttribute('data-dashboard-listeners-attached')) {
        document.body.setAttribute('data-dashboard-listeners-attached', 'true');
        document.body.addEventListener('click', (event) => {
            if (event.target) {
                if (event.target.matches('.load-payloads-btn')) {
                    console.log('Load payloads button clicked');
                    handleLoadPayloadsClick(event);
                }
            }
        });
    }

    requestUiUpdate();
});
function getFirstEndpointKey() {
    const firstEndpoint = document.querySelector('.endpoint-host .host-row, .endpoint-host .iframe-row');
    return firstEndpoint?.dataset.url || null;
}


function getCurrentEndpointKey() {
  const selected = document.querySelector('.endpoint-item.selected');
  return selected?.dataset.endpointKey || getFirstEndpointKey();
}
window.verifyLLMPayloads = async function(endpointKey = null) {
  const targetEndpoint = endpointKey || getCurrentEndpointKey();
  if (!targetEndpoint) {
    console.error("❌ No endpoint selected or provided");
    return;
  }

  console.log(`🔍 [Payload Verification] Analyzing payloads for: ${targetEndpoint}`);
  
  try {
    const report = await window.traceReportStorage.getTraceReport(targetEndpoint);
    const payloads = await window.traceReportStorage.getReportPayloads(targetEndpoint);
    
    if (!report || !payloads) {
      console.error("❌ No report or payloads found for this endpoint");
      return;
    }

    console.log(`📊 [Report Summary]`);
    console.log(`   • Handler Score: ${report.details?.score || 'N/A'}/100`);
    console.log(`   • Sinks Found: ${report.details?.sinks?.length || 0}`);
    console.log(`   • Total Payloads: ${payloads.length}`);
    
    const savedMessages = await chrome.storage.local.get([`saved-messages-${targetEndpoint}`]);
    const interceptedMessages = savedMessages[`saved-messages-${targetEndpoint}`] || [];
    
    console.log(`📨 [Intercepted Messages] Found ${interceptedMessages.length} messages:`);
    interceptedMessages.slice(0, 3).forEach((msg, i) => {
      console.log(`   ${i+1}. Type: ${typeof msg.data}, Structure:`, msg.data);
    });

    const payloadAnalysis = {
      llmGenerated: [],
      defaultFrogPost: [],
      structureMatches: 0,
      structureMismatches: 0
    };

    payloads.forEach((payload, i) => {
      const isLLMGenerated = payload.type !== 'default-dumb-xss';
      const payloadData = payload.payload || payload;
      
      if (isLLMGenerated) {
        payloadAnalysis.llmGenerated.push({index: i, payload: payloadData});
      } else {
        payloadAnalysis.defaultFrogPost.push({index: i, payload: payloadData});
      }

      const hasMatchingStructure = interceptedMessages.some(msg => {
        const msgKeys = Object.keys(msg.data || {}).sort();
        const payloadKeys = Object.keys(payloadData || {}).sort();
        return JSON.stringify(msgKeys) === JSON.stringify(payloadKeys);
      });

      if (hasMatchingStructure) {
        payloadAnalysis.structureMatches++;
      } else {
        payloadAnalysis.structureMismatches++;
      }
    });

    console.log(`🎯 [Payload Analysis]`);
    console.log(`   • LLM Generated: ${payloadAnalysis.llmGenerated.length}`);
    console.log(`   • FrogPost Default: ${payloadAnalysis.defaultFrogPost.length}`);
    console.log(`   • Structure Matches: ${payloadAnalysis.structureMatches}`);
    console.log(`   • Structure Mismatches: ${payloadAnalysis.structureMismatches}`);

    if (payloadAnalysis.llmGenerated.length > 0) {
      console.log(`🤖 [LLM Generated Payloads] Sample (first 5):`);
      payloadAnalysis.llmGenerated.slice(0, 5).forEach((item, i) => {
        console.log(`   ${i+1}. Index ${item.index}:`, item.payload);
        
        const interceptedExample = interceptedMessages.find(msg => msg.data && typeof msg.data === 'object');
        if (interceptedExample) {
          const interceptedKeys = Object.keys(interceptedExample.data).sort();
          const payloadKeys = Object.keys(item.payload || {}).sort();
          const structureMatch = JSON.stringify(interceptedKeys) === JSON.stringify(payloadKeys);
          console.log(`      Structure Match: ${structureMatch ? '✅' : '❌'} (Expected: [${interceptedKeys.join(', ')}], Got: [${payloadKeys.join(', ')}])`);
        }
      });
    }

    if (payloadAnalysis.defaultFrogPost.length > 0) {
      console.log(`🐸 [FrogPost Default Payloads] Sample (first 3):`);
      payloadAnalysis.defaultFrogPost.slice(0, 3).forEach((item, i) => {
        console.log(`   ${i+1}. Index ${item.index}:`, item.payload);
      });
    }

    console.log(`⚡ [Effectiveness Analysis]`);
    const renderPayloads = payloads.filter(p => {
      const data = p.payload || p;
      return data.type === 'render' && data.html && data.html.includes('alert');
    });
    console.log(`   • Render + XSS Payloads: ${renderPayloads.length}`);
    
    const uniqueXSSVectors = new Set();
    renderPayloads.forEach(p => {
      const html = (p.payload || p).html || '';
      if (html.includes('<img')) uniqueXSSVectors.add('img_onerror');
      if (html.includes('<svg')) uniqueXSSVectors.add('svg_onload');
      if (html.includes('<script')) uniqueXSSVectors.add('script_tag');
      if (html.includes('<iframe')) uniqueXSSVectors.add('iframe_src');
      if (html.includes('onload')) uniqueXSSVectors.add('onload_event');
    });
    console.log(`   • Unique XSS Vectors: ${Array.from(uniqueXSSVectors).join(', ')}`);

    const successRate = (payloadAnalysis.structureMatches / payloads.length * 100).toFixed(1);
    console.log(`🏆 [Final Verdict]`);
    console.log(`   • Structure Match Rate: ${successRate}%`);
    console.log(`   • LLM Quality: ${payloadAnalysis.llmGenerated.length > 0 && successRate > 80 ? '✅ EXCELLENT' : payloadAnalysis.llmGenerated.length > 0 ? '⚠️ NEEDS IMPROVEMENT' : '❌ NO LLM PAYLOADS'}`);
    
    return {
      endpoint: targetEndpoint,
      analysis: payloadAnalysis,
      successRate: parseFloat(successRate),
      payloads: payloads
    };

  } catch (error) {
    console.error("❌ Error during payload verification:", error);
    return null;
  }
};

async function showTraceReport(key, report) {
    if (!report) {
        report = await window.traceReportStorage.getTraceReport(key);
    }
    if (report) {
        const payloads = await window.traceReportStorage.getReportPayloads(key);
        await renderReportUI(report, payloads);
    } else {
        showToastNotification(`No report found for ${key}`, 'info');
    }
}
async function renderReportUI(traceReportData, initialPayloads = null) {
    let traceResultsPanel = document.getElementById('trace-results-panel');
    let content = document.getElementById('trace-results-content');

    if (!traceResultsPanel) {
        traceResultsPanel = document.createElement('div');
        traceResultsPanel.id = 'trace-results-panel';
        traceResultsPanel.className = 'trace-results-panel';
        traceResultsPanel.innerHTML = `<div class="trace-results-content" id="trace-results-content"></div>`;
        document.body.appendChild(traceResultsPanel);
        const backdrop = document.createElement('div');
        backdrop.className = 'trace-panel-backdrop';
        backdrop.onclick = () => { backdrop.remove(); traceResultsPanel.remove(); };
        document.body.appendChild(backdrop);
        content = traceResultsPanel.querySelector('#trace-results-content');
    }

    if (!traceReportData || typeof traceReportData !== 'object') {
        content.innerHTML = '<p class="error-message">Error: Invalid or missing report data.</p>';
        return;
    }

    try {
        const details = traceReportData.details || {};
        const analysisStorageKey = traceReportData.endpoint || details.endpointKey || traceReportData.summary?.endpointKey || '';
        if (!analysisStorageKey) {
            console.error("Could not determine endpoint key for the report. UI may be incomplete.");
        }
        const endpointDisplay = traceReportData.url || traceReportData.endpoint || analysisStorageKey || 'Unknown Endpoint';
        const safeKeyIdPart = (analysisStorageKey || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');
        const originalEndpointKey = analysisStorageKey;
        let payloadsToRender = initialPayloads;
        if (payloadsToRender === null && analysisStorageKey) {
            try {
                payloadsToRender = await window.traceReportStorage.getReportPayloads(analysisStorageKey);
            } catch (e) {
                console.error(`Failed to load payloads for ${analysisStorageKey}:`, e);
                payloadsToRender = [];
            }
        }
        payloadsToRender = payloadsToRender || [];
        const summary = traceReportData.summary || {};
        const score = summary.riskScore ?? 100;

        const llmAnalysisData = details.llm_analysis || null;
        const currentPayloadCount = details.payloadsGeneratedCount ?? 0;
        const currentPayloadMode = details.payloadMode || 'default';

        const escapeHTML = window.escapeHTML || function(str) { return String(str ?? '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); };
        const safeGetRisk = (score) => { try { return getRiskLevelAndColor(score); } catch(e){ return { riskLevel: 'Error', riskColor: 'critical' }; }};
        const safeGetRec = (score, data) => { try { return getRecommendationText(score, data); } catch(e){ return 'Error generating recommendation.'; }};
        const safeRenderPayload = (p, i) => { try { return renderPayloadItem(p, i); } catch(e){ return '<p class="error-message">Error rendering payload item.</p>'; }};
        const safeRenderStructure = (s, i) => { try { return renderStructureItem(s, i); } catch(e){ return '<p class="error-message">Error rendering structure item.</p>'; }};

        const uniqueVulns = details.sinks || details.dom_xss_sinks || [];
        const uniqueIssues = details.securityIssues || [];
        const riskLevel = safeGetRisk(score);
        const riskColor = riskLevel.riskColor;

        const summarySection = document.createElement('div');
        summarySection.className = 'report-section report-summary';
        summarySection.innerHTML = `
            <h4 class="report-section-title">Analysis Summary - <span class="report-endpoint-title">${escapeHTML(endpointDisplay)}</span></h4>
            <div class="summary-grid compact">
                <div class="summary-metrics" id="summary-metrics">
                    <div class="metric" data-metric="handler">
                        <div class="metric-header"><span class="metric-label">Handler Security Score</span></div>
                        <span class="metric-value ${getHandlerScoreClass(Math.max(1, Math.min(10, Math.round((10 * (reportData.securityScore ?? summary.securityScore ?? 100) / 100)))))}">${Math.max(1, Math.min(10, Math.round((10 * (reportData.securityScore ?? summary.securityScore ?? 100) / 100))))}/10</span>
                        <div class="handler-severity"></div>
                    </div>
                    <div class="metric" data-metric="msgs">
                        <div class="metric-header"><span class="metric-label">Msgs</span></div>
                        <span class="metric-value">${uiMessageCount}</span>
                    </div>
                    <div class="metric" data-metric="structs">
                        <div class="metric-header"><span class="metric-label">Structs</span></div>
                        <span class="metric-value">${structures?.length ?? 0}</span>
                    </div>
                    <div class="metric" data-metric="sinks">
                        <div class="metric-header"><span class="metric-label">Sinks</span></div>
                        <span class="metric-value">${uniqueVulns?.length ?? 0}</span>
                    </div>
                    <div class="metric" data-metric="payloads" id="report-payload-count-metric-${safeKeyIdPart}">
                        <div class="metric-header"><span class="metric-label">Payloads (<span id="payload-mode-display-${safeKeyIdPart}">${currentPayloadMode.replace(/_/g, ' ')}</span>)</span></div>
                        <span class="metric-value" id="payload-count-display-${safeKeyIdPart}">${currentPayloadCount}</span>
                    </div>
                </div>
            </div>`;

        content.appendChild(summarySection);


        const bestHandlerCode = details.bestHandler?.handler || details.analyzedHandler?.handler || details.analyzedHandler?.code;
        if (bestHandlerCode) {
            const handlerSection = document.createElement('div');
            handlerSection.className = 'report-section report-handler';

            const llmAnalysis = details.llmAnalysis || {};
            const handlerScore = llmAnalysis.handler_score;
            const handlerAssessment = llmAnalysis.handler_assessment;

            let handlerHTML = `<details class="report-details" open>
                     <summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Cat: ${escapeHTML(details.bestHandler?.category || 'N/A')} | Score: ${details.bestHandler?.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▼</span></summary>
                <div class="report-code-block handler-code"><pre><code>${escapeHTML(bestHandlerCode)}</code></pre></div>`;

            if (handlerScore !== undefined || handlerAssessment) {
                const score = handlerScore || 0;
                const scoreColor = score >= 80 ? '#4CAF50' : score >= 60 ? '#FF9800' : score >= 40 ? '#FF5722' : '#f44336';
                const scoreDescription = score >= 80 ? 'Excellent handler detection' :
                                      score >= 60 ? 'Good handler detection' :
                                      score >= 40 ? 'Partial handler detection' : 'Poor/incomplete handler';

                handlerHTML += `
                    <div class="llm-handler-validation" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-top: 12px;">
                        <div style="display: flex; align-items: center; margin-bottom: 8px;">
                            <span style="font-size: 14px; margin-right: 6px;">🤖</span>
                            <strong style="color: #2d3748; font-size: 13px;">AI Handler Validation</strong>
                        </div>
                        ${handlerAssessment ? `<div style="font-size: 12px; line-height: 1.4; color: #4a5568; margin-bottom: 8px;">${escapeHTML(handlerAssessment)}</div>` : ''}
                        ${handlerScore !== undefined ? `
                            <div style="margin-top: 8px;">
                                <div style="font-size: 11px; color: #718096; margin-bottom: 3px;">Accuracy Score:</div>
                                <div style="background-color: #e2e8f0; border-radius: 8px; height: 18px; width: 200px; position: relative; overflow: hidden;">
                                    <div style="background: ${scoreColor}; height: 100%; width: ${Math.min(100, Math.max(0, score))}%; transition: width 0.5s ease;"></div>
                                    <div style="position: absolute; top: 0; left: 0; right: 0; text-align: center; line-height: 18px; font-weight: bold; color: #2d3748; font-size: 10px;">${score}/100</div>
                                </div>
                                <div style="margin-top: 3px; font-size: 10px; color: #718096; font-style: italic;">${scoreDescription}</div>
                            </div>
                        ` : ''}
                    </div>`;
            }

            handlerHTML += `</details>`;
            handlerSection.innerHTML = handlerHTML;
            content.appendChild(handlerSection);
        }

        const llmSection = createLLMAnalysisSection(analysisStorageKey, endpointDisplay);
        content.appendChild(llmSection);
        
        setupLLMEventListeners(analysisStorageKey);

        const findingsSection = document.createElement('div');
        findingsSection.className = 'report-section report-findings';
        let findingsHTML = '<h4 class="report-section-title">Findings</h4>';
        let findingsExist = false;

        if (details.originValidationChecks?.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Origin Validation (${details.originValidationChecks.length})</h5><table class="report-table"><thead><tr><th>Detection Result</th><th>Analysis Method</th><th>Code Evidence</th></tr></thead><tbody>`;
            details.originValidationChecks.forEach(check => {
                const type = check?.type || '?'; 
                const strength = check?.strength || 'N/A'; 
                const value = check?.comparedValue !== null && check?.comparedValue !== undefined ? String(check.comparedValue).substring(0, 100) : 'N/A'; 
                const snippetHTML = check?.rawSnippet ? `<code class="context-snippet">${escapeHTML(check.rawSnippet)}</code>` : 'N/A';
                
                let detectionResult, analysisMethod, codeEvidence;
                
                if(strength === 'Missing') {
                    detectionResult = '<span style="color: #dc2626; font-weight: bold;">❌ NO ORIGIN VALIDATION DETECTED</span>';
                    analysisMethod = 'Static code analysis scanned entire handler for origin validation patterns (event.origin comparisons, method calls, etc.)';
                    codeEvidence = '<span style="color: #888; font-style: italic;">Handler code analyzed - no origin validation patterns found</span>';
                } else {
                    detectionResult = `<span style="color: #16a34a; font-weight: bold;">✅ ORIGIN VALIDATION FOUND</span>`;
                    analysisMethod = `Detected ${type} validation with ${strength} strength`;
                    codeEvidence = snippetHTML;
                }
                
                findingsHTML += `<tr><td>${detectionResult}</td><td>${analysisMethod}</td><td>${codeEvidence}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueVulns.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Potential Sinks Reached (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Detection Method</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueVulns.forEach(vuln => {
                const type = vuln?.name || vuln?.type || '?'; const severity = vuln?.severity || 'N/A'; const contextHTML = vuln?.context || ''; const sourcePath = vuln?.sourcePath || '(unknown)'; const conditions = vuln?.conditions || [];
                let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = escapeHTML(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${escapeHTML(c.path)} ${escapeHTML(c.op)} ${valStr}</code>`; }).join('<br>'); }
                let severityClass = severity.toLowerCase(); if(severity === 'Critical') severityClass = 'critical'; else if(severity === 'High') severityClass = 'high'; else if(severity === 'Medium') severityClass = 'medium'; else if(severity === 'Low') severityClass = 'low'; else severityClass='unknown';
                const detectionMethod = vuln?.method || 'Unknown';
                findingsHTML += `<tr class="severity-row-${severityClass}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severityClass}">${escapeHTML(severity)}</span></td><td><code>${escapeHTML(detectionMethod)}</code></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueIssues.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Other Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueIssues.forEach(issue => {
                const type = issue?.type || '?'; const severity = issue?.severity || 'N/A'; const contextHTML = issue?.context || '';
                let severityClass = severity.toLowerCase(); if(severity === 'Critical') severityClass = 'critical'; else if(severity === 'High') severityClass = 'high'; else if(severity === 'Medium') severityClass = 'medium'; else if(severity === 'Low') severityClass = 'low'; else severityClass='unknown';
                const detectionMethod = issue?.method || 'Unknown';
                findingsHTML += `<tr class="severity-row-${severityClass}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severityClass}">${escapeHTML(severity)}</span></td><td><code>${escapeHTML(detectionMethod)}</code></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (!findingsExist) { findingsHTML += '<p class="no-findings-text">No significant findings detected.</p>'; }
        findingsSection.innerHTML = findingsHTML;
        content.appendChild(findingsSection);

        if (details.dataFlows?.length > 0) {
            const flowSection = document.createElement('div');
            flowSection.className = 'report-section report-dataflow';
            flowSection.innerHTML = ` <h4 class="report-section-title">Data Flow</h4> <table class="report-table dataflow-table"> <thead> <tr> <th>Source Property</th> <th>Sink / Target</th> <th>Conditions</th> <th>Code Snippet</th> </tr> </thead> <tbody> </tbody> </table>`;
            const tbody = flowSection.querySelector('tbody');
            if (tbody) { details.dataFlows.forEach(flow => { const prop = flow?.sourcePath || '?'; const sink = flow?.destinationContext || '?'; const context = flow?.fullCodeSnippet || flow?.taintedNodeSnippet || ''; const displayProp = prop === '(root)' ? '(root data)' : `event.data.${escapeHTML(prop)}`; const conditions = flow?.requiredConditionsForFlow || flow?.conditions || []; let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = escapeHTML(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${escapeHTML(c.path)} ${escapeHTML(c.op)} ${valStr}</code>`; }).join('<br>'); } const rowHtml = ` <tr> <td><code>${displayProp}</code></td> <td>${escapeHTML(sink)}</td> <td>${conditionsHtml}</td> <td><code class="context-snippet">${escapeHTML(context)}</code></td> </tr>`; tbody.insertAdjacentHTML('beforeend', rowHtml); }); }
            else { flowSection.innerHTML += '<p class="error-message">Error rendering data flow table body.</p>'; }
            content.appendChild(flowSection);
        }

        const payloadSection = document.createElement('div');
        payloadSection.className = 'report-section report-payloads';
        payloadSection.id = 'report-payload-section-' + safeKeyIdPart;

        let payloadsHTML = `<h4 class="report-section-title">Generated Payloads (<span id="payload-count-display-${safeKeyIdPart}">${payloadsToRender.length}</span> - <span id="payload-mode-display-${safeKeyIdPart}">${currentPayloadMode.replace(/_/g, ' ')}</span>)</h4>`;
        payloadsHTML += `<div id="payloads-list-${safeKeyIdPart}" class="payloads-list report-list">`;
        if (payloadsToRender.length > 0) {
            payloadsHTML += payloadsToRender.map((p, i) => safeRenderPayload(p, i)).join('');
        } else {
            payloadsHTML += `<p>No payloads generated yet for mode: ${currentPayloadMode.replace(/_/g, ' ')}.</p>`;
        }
        payloadsHTML += `</div>`;
        if (payloadsToRender.length < (details.payloadsGeneratedCount || 0)) {
            const buttonText = `Load All ${details.payloadsGeneratedCount || 0} Payloads`;
            payloadsHTML += `<button class="control-button secondary-button show-more-btn load-payloads-btn" data-analysis-key="${escapeHTML(analysisStorageKey)}">${buttonText}</button>`;
        }
        payloadSection.innerHTML = payloadsHTML;
        content.appendChild(payloadSection);

        if (structures?.length > 0) {
            const structureSection = document.createElement('div');
            structureSection.className = 'report-section report-structures';
            let structuresHTML = `<h4 class="report-section-title">Unique Msg Structures (${structures.length})</h4><div class="structures-list report-list">`;
            structures.slice(0, 3).forEach((s, i) => { structuresHTML += safeRenderStructure(s, i); }); structuresHTML += `</div>`;
            if (structures.length > 3) { structuresHTML += `<button id="showAllStructuresBtn" class="control-button secondary-button show-more-btn">Show All ${structures.length}</button>`; }
            structureSection.innerHTML = structuresHTML;
            content.appendChild(structureSection);
        }

        const bottomButtonContainer = document.createElement('div'); bottomButtonContainer.style.cssText = 'margin-top:20px; display: flex; justify-content: center; gap: 15px;'; 
        
        const exportJsonBtn = document.createElement('button'); exportJsonBtn.textContent = 'Export JSON'; exportJsonBtn.className = 'control-button secondary-button'; exportJsonBtn.addEventListener('click', (e) => { e.stopPropagation(); try { const jsonData = JSON.stringify(reportData, null, 2); const blob = new Blob([jsonData], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); const safeFilename = (analysisStorageKey || 'frogpost_report').replace(/[^a-z0-9_\-.]/gi, '_'); a.href = url; a.download = `${safeFilename}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); } catch (exportError) { alert("Failed to export report as JSON."); } }); 
        
        const ignoreBtn = document.createElement('button'); ignoreBtn.textContent = '🚫 Add to Ignore List'; ignoreBtn.className = 'control-button danger-button'; ignoreBtn.title = 'Hide this endpoint from results'; ignoreBtn.addEventListener('click', async (e) => { e.stopPropagation(); if (confirm(`Add "${analysisStorageKey}" to ignore list?\n\nThis endpoint will be hidden from the dashboard until removed from the ignore list.`)) { await addToIgnoreList(analysisStorageKey); showToastNotification(`Endpoint added to ignore list`, 'success', 3000); } }); 
        
        const closeBtnInside = document.createElement('button'); closeBtnInside.textContent = 'Close Report'; closeBtnInside.className = 'control-button secondary-button'; closeBtnInside.onclick = () => { document.querySelector('.trace-panel-backdrop')?.remove(); panel.remove(); }; 
        
        bottomButtonContainer.appendChild(exportJsonBtn); bottomButtonContainer.appendChild(ignoreBtn); bottomButtonContainer.appendChild(closeBtnInside); content.appendChild(bottomButtonContainer);
        attachReportEventListeners(panel, reportData);

    } catch (renderError) {
        content.innerHTML = `<p class="error-message">Error rendering report details: ${renderError.message}</p>`;
        console.error("Error rendering report:", renderError);
    }
}

async function handleLoadPayloadsClick(event) {
    const button = event.target;
    const analysisKey = button.dataset.analysisKey;
    const reportPanel = button.closest('.trace-results-panel');
    const safeKeyIdPart = analysisKey?.replace(/[^a-zA-Z0-9_-]/g, '_');
    const payloadListElement = reportPanel?.querySelector(`#payloads-list-${safeKeyIdPart}`);

    if (!analysisKey || !payloadListElement) {
        log.error("Cannot load payloads: missing analysis key or list element.", { key: analysisKey, listFound: !!payloadListElement });
        showToastNotification("Error: Could not find elements to load payloads.", "error");
        button.textContent = `Load Payloads`;
        button.disabled = false;
        return;
    }

    button.textContent = 'Loading...';
    button.disabled = true;

    try {
        const payloads = await window.traceReportStorage.getReportPayloads(analysisKey);
        if (payloads && payloads.length > 0) {
            const newPayloadsHtml = payloads.map((p, i) => renderPayloadItem(p, i)).join('');
            if (payloadListElement.innerHTML.includes('Click button below to load payloads')) {
                payloadListElement.innerHTML = newPayloadsHtml;
            } else {
                payloadListElement.insertAdjacentHTML('beforeend', newPayloadsHtml);
            }
            const countDisplay = reportPanel.querySelector(`#payload-count-display-${safeKeyIdPart}`);
            if(countDisplay) countDisplay.textContent = payloads.length;

        } else {
            payloadListElement.innerHTML = `<p>No payloads found in storage for this report.</p>`;
        }
        button.remove();
    } catch (error) {
        log.error(`Error loading payloads:`, error);
        payloadListElement.innerHTML = `<p class="error-message">Error loading payloads.</p>`;
        button.textContent = `Retry Load Payloads`;
        button.disabled = false;
    }
}

// --- FrogPost postMessage helpers (UI hooks) ---
async function frogpostCollectPostMessage() {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs && tabs[0];
        if (!tab || !tab.id) return;
        const res = await chrome.runtime.sendMessage({ type: 'frogpost.pm.collect', tabId: tab.id });
        if (res && res.ok) {
            console.log('[FrogPost] postMessage frames:', res.frames);
            // Optionally integrate into existing UI: renderPostMessageReport(res.frames)
        }
    } catch (e) {
        console.error('[FrogPost] Collect postMessage failed:', e);
    }
}

async function frogpostDownloadPostMessageJSON() {
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs && tabs[0];
        if (!tab || !tab.id) return;
        await chrome.runtime.sendMessage({ type: 'frogpost.pm.collectAndDownload', tabId: tab.id, filename: `frogpost-postmessage-report-${Date.now()}.json` });
    } catch (e) {
        console.error('[FrogPost] Download postMessage JSON failed:', e);
    }
}

// ====== Auto Pilot & URL List Upload Features ======

// Global state for Auto Pilot and URL List scanning
let autoPilotEnabled = false;
let urlScanInProgress = false;
let autoPilotScanInProgress = false; // DEPRECATED: No longer used
let customUrlsList = [];
let autoPilotMonitorInterval = null;
let autoPilotScannedEndpoints = new Set(); // Track ALL endpoints scanned by Auto Pilot
let autoPilotActiveScans = new Set(); // Track currently scanning endpoints (per-endpoint lock)
const CUSTOM_URLS_STORAGE_KEY = 'customUrlList';
const AUTOPILOT_ENABLED_KEY = 'autoPilotEnabled';
const AUTOPILOT_WARNING_SHOWN_KEY = 'autoPilotWarningShown';
const URL_SCAN_IN_PROGRESS_KEY = 'urlScanInProgress';
const AUTOPILOT_SCANNED_KEY = 'autoPilotScannedEndpoints';

// Ignore list for endpoints
let ignoredEndpoints = new Set();
const IGNORED_ENDPOINTS_STORAGE_KEY = 'ignoredEndpoints';

// Failed endpoints cache (to prevent retrying failed CSP checks or timeouts)
let failedEndpoints = new Map(); // Map<endpointKey, {reason: string, timestamp: number}>
const FAILED_ENDPOINTS_STORAGE_KEY = 'failedEndpoints';
const FAILED_ENDPOINT_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

// Collapsed groups state
let collapsedGroups = new Set();
const COLLAPSED_GROUPS_STORAGE_KEY = 'collapsedGroups';

// Load ignored endpoints from localStorage
async function loadIgnoredEndpoints() {
    try {
        const result = await chrome.storage.local.get([IGNORED_ENDPOINTS_STORAGE_KEY]);
        ignoredEndpoints = new Set(result[IGNORED_ENDPOINTS_STORAGE_KEY] || []);
        log.info(`[Ignore List] Loaded ${ignoredEndpoints.size} ignored endpoint(s)`);
    } catch (error) {
        log.error('[Ignore List] Failed to load:', error);
    }
}

// Save ignored endpoints to localStorage
async function saveIgnoredEndpoints() {
    try {
        await chrome.storage.local.set({ [IGNORED_ENDPOINTS_STORAGE_KEY]: Array.from(ignoredEndpoints) });
        log.info(`[Ignore List] Saved ${ignoredEndpoints.size} ignored endpoint(s)`);
    } catch (error) {
        log.error('[Ignore List] Failed to save:', error);
    }
}

// Load failed endpoints from localStorage
async function loadFailedEndpoints() {
    try {
        const result = await chrome.storage.local.get([FAILED_ENDPOINTS_STORAGE_KEY]);
        const stored = result[FAILED_ENDPOINTS_STORAGE_KEY] || {};
        const now = Date.now();
        
        // Load and clean expired entries
        failedEndpoints = new Map();
        for (const [key, value] of Object.entries(stored)) {
            if (value && value.timestamp && (now - value.timestamp < FAILED_ENDPOINT_CACHE_DURATION)) {
                failedEndpoints.set(key, value);
            }
        }
        
        log.info(`[Failed Cache] Loaded ${failedEndpoints.size} failed endpoint(s)`);
    } catch (error) {
        log.error('[Failed Cache] Failed to load:', error);
    }
}

// Save failed endpoints to localStorage
async function saveFailedEndpoints() {
    try {
        const obj = Object.fromEntries(failedEndpoints);
        await chrome.storage.local.set({ [FAILED_ENDPOINTS_STORAGE_KEY]: obj });
        log.debug(`[Failed Cache] Saved ${failedEndpoints.size} failed endpoint(s)`);
    } catch (error) {
        log.error('[Failed Cache] Failed to save:', error);
    }
}

// Mark endpoint as failed
async function markEndpointAsFailed(endpointKey, reason) {
    failedEndpoints.set(endpointKey, {
        reason: reason,
        timestamp: Date.now()
    });
    await saveFailedEndpoints();
    log.info(`[Failed Cache] Marked ${endpointKey} as failed: ${reason}`);
    
    // CRITICAL: Update button state to error
    buttonStates.set(endpointKey, {
        state: 'error',
        options: { errorMessage: reason }
    });
    
    // CRITICAL: Trigger UI update to show red button
    requestUiUpdate();
}

// Check if endpoint previously failed
function isEndpointFailed(endpointKey) {
    const failureInfo = failedEndpoints.get(endpointKey);
    if (!failureInfo) return null;
    
    // Check if cache is still valid
    const now = Date.now();
    if (now - failureInfo.timestamp > FAILED_ENDPOINT_CACHE_DURATION) {
        failedEndpoints.delete(endpointKey);
        saveFailedEndpoints(); // Clean up expired entry
        return null;
    }
    
    return failureInfo;
}

// Clear failed endpoint (for manual retry)
async function clearFailedEndpoint(endpointKey) {
    if (failedEndpoints.has(endpointKey)) {
        failedEndpoints.delete(endpointKey);
        await saveFailedEndpoints();
        log.info(`[Failed Cache] Cleared failed status for ${endpointKey}`);
        
        // CRITICAL: Reset button state to default
        buttonStates.set(endpointKey, {
            state: 'start',
            options: {}
        });
        
        // CRITICAL: Trigger UI update to restore button
        requestUiUpdate();
    }
}

// Load collapsed groups state
async function loadCollapsedGroups() {
    try {
        const result = await chrome.storage.local.get([COLLAPSED_GROUPS_STORAGE_KEY]);
        collapsedGroups = new Set(result[COLLAPSED_GROUPS_STORAGE_KEY] || []);
    } catch (error) {
        log.error('[Collapsed Groups] Failed to load:', error);
    }
}

// Save collapsed groups state
async function saveCollapsedGroups() {
    try {
        await chrome.storage.local.set({ 
            [COLLAPSED_GROUPS_STORAGE_KEY]: Array.from(collapsedGroups) 
        });
    } catch (error) {
        log.error('[Collapsed Groups] Failed to save:', error);
    }
}

// Toggle collapse state for a group
async function toggleGroupCollapse(groupKey) {
    if (collapsedGroups.has(groupKey)) {
        collapsedGroups.delete(groupKey);
    } else {
        collapsedGroups.add(groupKey);
    }
    await saveCollapsedGroups();
    requestUiUpdate();
}

// Add endpoint to ignore list
async function addToIgnoreList(endpointKey) {
    if (!endpointKey) return false;
    
    ignoredEndpoints.add(endpointKey);
    await saveIgnoredEndpoints();
    log.info(`[Ignore List] Added: ${endpointKey}`);
    
    // Close any open reports for this endpoint
    document.querySelector('.trace-results-panel')?.remove();
    document.querySelector('.trace-panel-backdrop')?.remove();
    
    // Update UI to hide the endpoint
    requestUiUpdate();
    
    return true;
}

// Remove endpoint from ignore list
async function removeFromIgnoreList(endpointKey) {
    if (!endpointKey) return false;
    
    ignoredEndpoints.delete(endpointKey);
    await saveIgnoredEndpoints();
    log.info(`[Ignore List] Removed: ${endpointKey}`);
    
    // Update UI to show the endpoint again
    requestUiUpdate();
    
    return true;
}

// Check if endpoint is ignored
function isEndpointIgnored(endpointKey) {
    return ignoredEndpoints.has(endpointKey);
}

// Parse and validate URLs from text
function parseAndValidateUrls(text) {
    const lines = text.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
    const validUrls = [];
    const invalidUrls = [];
    
    lines.forEach(line => {
        try {
            const url = new URL(line);
            if (url.protocol === 'http:' || url.protocol === 'https:') {
                validUrls.push(line);
            } else {
                invalidUrls.push(line);
            }
        } catch (e) {
            invalidUrls.push(line);
        }
    });
    
    return { validUrls, invalidUrls };
}

// Show URL List upload modal
function showUploadUrlModal() {
    const container = document.getElementById('urlListModalContainer');
    if (!container) return;
    
    // Create backdrop
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    
    // Create modal
    const modal = document.createElement('div');
    modal.className = 'url-list-modal';
    
    // Modal header
    const header = document.createElement('div');
    header.className = 'url-list-modal-header';
    header.innerHTML = `
        <h4>📋 Upload URL List for Batch Scanning</h4>
        <button class="close-modal-btn" aria-label="Close">&times;</button>
    `;
    
    // Modal body
    const body = document.createElement('div');
    body.className = 'url-list-modal-body';
    body.innerHTML = `
        <p>Enter URLs to scan (one per line). FrogPost will automatically run Play+Trace on each URL.</p>
        <textarea class="url-list-textarea" placeholder="https://example.com/page1
https://example.com/page2
https://example.com/page3" id="urlListTextarea"></textarea>
        <div class="url-list-file-upload">
            <p style="margin: 0; color: var(--text-secondary);">Or click to upload a .txt file with URLs</p>
            <input type="file" id="urlListFileInput" accept=".txt" />
        </div>
    `;
    
    // Modal footer
    const footer = document.createElement('div');
    footer.className = 'url-list-modal-footer';
    footer.innerHTML = `
        <button class="control-button secondary-button" id="cancelUrlList">Cancel</button>
        <button class="control-button primary-button" id="startUrlScan">Start Scan</button>
    `;
    
    modal.appendChild(header);
    modal.appendChild(body);
    modal.appendChild(footer);
    
    container.innerHTML = '';
    container.appendChild(backdrop);
    container.appendChild(modal);
    
    // Event listeners
    const closeBtn = header.querySelector('.close-modal-btn');
    const cancelBtn = footer.querySelector('#cancelUrlList');
    const startBtn = footer.querySelector('#startUrlScan');
    const textarea = body.querySelector('#urlListTextarea');
    const fileInput = body.querySelector('#urlListFileInput');
    const fileUploadDiv = body.querySelector('.url-list-file-upload');
    
    const closeModal = () => {
        container.innerHTML = '';
    };
    
    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);
    backdrop.addEventListener('click', closeModal);
    
    // File upload handler
    fileUploadDiv.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                textarea.value = event.target.result;
            };
            reader.readAsText(file);
        }
    });
    
    // Start scan handler
    startBtn.addEventListener('click', async () => {
        const text = textarea.value.trim();
        if (!text) {
            showToastNotification('Please enter at least one URL', 'warning');
            return;
        }
        
        const { validUrls, invalidUrls } = parseAndValidateUrls(text);
        
        if (invalidUrls.length > 0) {
            const proceed = confirm(`Found ${invalidUrls.length} invalid URL(s):\n${invalidUrls.slice(0, 5).join('\n')}${invalidUrls.length > 5 ? '\n...' : ''}\n\nProceed with ${validUrls.length} valid URL(s)?`);
            if (!proceed) return;
        }
        
        if (validUrls.length === 0) {
            showToastNotification('No valid URLs found', 'error');
            return;
        }
        
        closeModal();
        await startBatchUrlScan(validUrls);
    });
}

// Start batch URL scanning
async function startBatchUrlScan(urls) {
    if (urlScanInProgress) {
        showToastNotification('A URL scan is already in progress', 'warning');
        return;
    }
    
    urlScanInProgress = true;
    await chrome.storage.local.set({ [URL_SCAN_IN_PROGRESS_KEY]: true });
    
    // Store custom URLs
    customUrlsList = urls;
    await chrome.storage.local.set({ [CUSTOM_URLS_STORAGE_KEY]: urls });
    
    // Temporarily disable Auto Pilot
    const autoPilotWasEnabled = autoPilotEnabled;
    if (autoPilotEnabled) {
        await disableAutoPilot(true); // true = silent disable
    }
    
    showToastNotification(`Starting batch scan of ${urls.length} URL(s)...`, 'info', 3000);
    
    // Update UI to show Custom URLs group
    requestUiUpdate();
    
    // Scan each URL sequentially
    let successCount = 0;
    let failCount = 0;
    
    log.info(`[Batch Scan] ═══════════════════════════════════════════════════`);
    log.info(`[Batch Scan] Starting sequential scan of ${urls.length} endpoint URLs`);
    log.info(`[Batch Scan] Strategy: Open endpoint → Wait for handler detection → Analyze`);
    log.info(`[Batch Scan] ═══════════════════════════════════════════════════`);
    
    for (let i = 0; i < urls.length; i++) {
        const url = urls[i];
        const urlNum = i + 1;
        
        // Clear, organized progress message
        log.info(`\n[Batch Scan] ─────────────────────────────────────────────────`);
        log.info(`[Batch Scan] 📍 Endpoint ${urlNum}/${urls.length}: ${url}`);
        log.info(`[Batch Scan] ─────────────────────────────────────────────────`);
        
        updateAutoPilotFooter(`Scanning ${urlNum}/${urls.length}: ${url}`);
        
        let tabId = null;
        
        try {
            // Get the endpoint key for this URL
            const endpointKey = getStorageKeyForUrl(url);
            log.info(`[Batch Scan] [${urlNum}/${urls.length}] Endpoint key: ${endpointKey}`);
            
            // OPTIMIZED: Skip if already failed recently (within cache duration)
            const failureInfo = isEndpointFailed(endpointKey);
            if (failureInfo) {
                log.warn(`[Batch Scan] [${urlNum}/${urls.length}] ⏭ Skipping (previously failed: ${failureInfo.reason})`);
                failCount++;
                continue;
            }
            
            // Step 1: Open URL in a new tab to allow DOM agent to inject and capture handlers
            log.info(`[Batch Scan] [${urlNum}/${urls.length}] Step 1/3: Opening endpoint in new tab...`);
            const tab = await chrome.tabs.create({ url: url, active: false });
            tabId = tab.id;
            log.success(`[Batch Scan] [${urlNum}/${urls.length}] ✓ Tab created (ID: ${tabId})`);
            
            // Step 2: Wait for page to load and DOM agent to capture handlers
            log.info(`[Batch Scan] [${urlNum}/${urls.length}] Step 2/3: Waiting for page load and handler detection...`);
            
            // OPTIMIZED: Reduced initial wait from 4s to 2s
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Poll to check if handler was detected
            let totalWaitTime = 2000;
            const maxWaitTime = 7000; // OPTIMIZED: Reduced from 12s to 7s
            const pollInterval = 500; // OPTIMIZED: Poll more frequently (500ms vs 1s)
            let hasHandler = false;
            
            while (totalWaitTime < maxWaitTime) {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                totalWaitTime += pollInterval;
                
                // Check if handler was detected for this endpoint
                hasHandler = endpointsWithDetectedHandlers.has(endpointKey);
                
                if (hasHandler) {
                    log.success(`[Batch Scan] [${urlNum}/${urls.length}] ✓ Handler detected after ${totalWaitTime/1000}s`);
                    break;
                }
            }
            
            if (!hasHandler) {
                log.warn(`[Batch Scan] [${urlNum}/${urls.length}] ⚠ No handler detected after ${maxWaitTime/1000}s - endpoint may not have postMessage listeners`);
            }
            
            // Step 3: Run Play+Trace analysis regardless (fallback to static analysis if needed)
            log.info(`[Batch Scan] [${urlNum}/${urls.length}] Step 3/3: Running Play+Trace analysis...`);
            
            // Find or create button element
            let button = document.querySelector(`.iframe-check-button[data-endpoint="${endpointKey}"]`);
            
            if (!button) {
                button = document.createElement('button');
                button.className = 'iframe-check-button';
                button.setAttribute('data-endpoint', endpointKey);
            }
            
            // Reset button state
            buttonStates.delete(endpointKey);
            
            // Run Play (handler extraction) - will use runtime telemetry if available, else fallback
            await handlePlayButtonWithTimeout(endpointKey, button, false, true, true);
            
            // OPTIMIZED: Reduced wait from 1.5s to 0.3s
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Check if handler was successfully extracted
            const handlerExtracted = endpointsWithDetectedHandlers.has(endpointKey);
            
            if (handlerExtracted) {
                // Run Trace
                let traceButton = document.querySelector(`.iframe-trace-button[data-endpoint="${endpointKey}"]`);
                
                if (!traceButton) {
                    traceButton = document.createElement('button');
                    traceButton.className = 'iframe-trace-button';
                    traceButton.setAttribute('data-endpoint', endpointKey);
                }
                
                log.info(`[Batch Scan] [${urlNum}/${urls.length}] Running Trace analysis...`);
                if (window.handleTraceButton) {
                    await window.handleTraceButton(endpointKey, traceButton, true);
                }
                
                // OPTIMIZED: Reduced wait from 1.5s to 0.3s
                await new Promise(resolve => setTimeout(resolve, 300));
                
                successCount++;
                log.success(`[Batch Scan] [${urlNum}/${urls.length}] ✅ COMPLETED SUCCESSFULLY`);
            } else {
                log.warn(`[Batch Scan] [${urlNum}/${urls.length}] ⏭ Skipping Trace (no handler found)`);
                failCount++;
            }
            
        } catch (error) {
            failCount++;
            log.error(`[Batch Scan] [${urlNum}/${urls.length}] ❌ ERROR: ${error.message}`);
        } finally {
            // Always close the tab
            if (tabId) {
                try {
                    await chrome.tabs.remove(tabId);
                    log.info(`[Batch Scan] [${urlNum}/${urls.length}] Tab closed`);
                } catch (e) {
                    log.debug(`[Batch Scan] Could not close tab ${tabId}: ${e.message}`);
                }
            }
        }
        
        // OPTIMIZED: Reduced delay between URLs from 1.5s to 0.5s
        if (i < urls.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    
    log.info(`\n[Batch Scan] ═══════════════════════════════════════════════════`);
    log.info(`[Batch Scan] Scan Complete: ${successCount} succeeded, ${failCount} failed`);
    log.info(`[Batch Scan] ═══════════════════════════════════════════════════`);
    
    // Cleanup
    urlScanInProgress = false;
    await chrome.storage.local.set({ [URL_SCAN_IN_PROGRESS_KEY]: false });
    hideAutoPilotFooter();
    
    // Re-enable Auto Pilot if it was enabled before
    if (autoPilotWasEnabled) {
        await enableAutoPilot(true); // true = silent enable
    }
    
    showToastNotification(`Batch scan complete: ${successCount} succeeded, ${failCount} failed out of ${urls.length} endpoint(s)`, successCount > 0 ? 'success' : 'warning', 5000);
    
    // Refresh UI
    requestUiUpdate();
}

// Show Auto Pilot warning dialog
function showAutoPilotWarning() {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-backdrop';
        overlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); z-index: 10000;
            display: flex; align-items: center; justify-content: center;
        `;
        
        const modal = document.createElement('div');
        modal.style.cssText = `
            background: var(--bg-primary); border-radius: 12px; padding: 24px;
            max-width: 500px; width: 90%; box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            border: 2px solid #3498db;
        `;
        
        modal.innerHTML = `
            <h3 style="margin: 0 0 16px 0; color: #3498db; font-size: 18px;">
                🤖 Auto Pilot Mode
            </h3>
            <div style="margin-bottom: 20px; line-height: 1.6; color: var(--text-secondary);">
                <p><strong style="color: var(--text-primary);">Warning:</strong> When Auto Pilot is enabled, FrogPost will automatically run <strong>Play + Trace</strong> on every new iframe that is intercepted.</p>
                <p>This mode will:</p>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li>Automatically analyze new iframes in the background</li>
                    <li>Suppress CSP error popups (silent mode)</li>
                    <li>Show progress in a footer bar</li>
                    <li>NOT run the Launch/Fuzzer step automatically</li>
                </ul>
                <p style="margin-top: 12px;"><strong style="color: #f39c12;">Note:</strong> This feature is designed for security research. Use responsibly.</p>
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 10px;">
                <button id="autopilotWarningCancel" class="control-button secondary-button" style="padding: 8px 20px;">Cancel</button>
                <button id="autopilotWarningAccept" class="control-button primary-button" style="padding: 8px 20px;">Enable Auto Pilot</button>
            </div>
        `;
        
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        
        const acceptBtn = modal.querySelector('#autopilotWarningAccept');
        const cancelBtn = modal.querySelector('#autopilotWarningCancel');
        
        acceptBtn.addEventListener('click', () => {
            document.body.removeChild(overlay);
            resolve(true);
        });
        
        cancelBtn.addEventListener('click', () => {
            document.body.removeChild(overlay);
            resolve(false);
        });
    });
}

// Scan existing intercepted endpoints when Auto Pilot is enabled
// SIMPLIFIED: Scan all unmarked endpoints
async function scanUnmarkedEndpoints() {
    // CRITICAL: Only one scan at a time - prevent concurrent scans
    if (!autoPilotEnabled || urlScanInProgress || autoPilotScanInProgress) {
        return;
    }
    
    // Lock to prevent concurrent scans
    autoPilotScanInProgress = true;
    
    try {
        log.debug('[Auto Pilot] Checking for unmarked endpoints...');
            
        // Step 1: Collect ALL current endpoints
        const allEndpoints = new Set();
        
        // From messages
        window.frogPostState.messages.forEach(msg => {
            // Skip localhost/extension/special URLs
            if (msg.origin && (msg.origin.startsWith('http://127.0.0.1:1337/') || msg.origin.startsWith('chrome-extension://') || msg.origin.startsWith('about:') || isLocalDevUrl(msg.origin) || msg.origin.includes('frogpost_handler_extraction=true'))) return;
            if (msg.destinationUrl && (msg.destinationUrl.startsWith('http://127.0.0.1:1337/') || msg.destinationUrl.startsWith('about:') || isLocalDevUrl(msg.destinationUrl) || msg.destinationUrl.includes('frogpost_handler_extraction=true'))) return;
            if (msg.topLevelUrl && (msg.topLevelUrl.startsWith('http://127.0.0.1:1337/') || msg.topLevelUrl.startsWith('chrome-extension://') || msg.topLevelUrl.startsWith('about:') || isLocalDevUrl(msg.topLevelUrl) || msg.topLevelUrl.includes('frogpost_handler_extraction=true'))) return;
            
            // Add endpoints
            if (msg.topLevelUrl) {
                const key = getStorageKeyForUrl(msg.topLevelUrl);
                if (key && key !== 'null' && key !== 'about:blank' && !isEndpointIgnored(key)) allEndpoints.add(key);
            }
            if (msg.origin) {
                const key = getStorageKeyForUrl(msg.origin);
                if (key && key !== 'null' && key !== 'about:blank' && !isEndpointIgnored(key)) allEndpoints.add(key);
            }
            if (msg.destinationUrl) {
                const key = getStorageKeyForUrl(msg.destinationUrl);
                if (key && key !== 'null' && key !== 'about:blank' && !isEndpointIgnored(key)) allEndpoints.add(key);
            }
        });
        
        // From loadedData.urls
        if (window.frogPostState.loadedData && window.frogPostState.loadedData.urls) {
            window.frogPostState.loadedData.urls.forEach(url => {
                // Skip special URLs
                if (url.startsWith('about:') || url.startsWith('chrome-extension://') || url.startsWith('http://127.0.0.1:1337/')) return;
                
                const key = getStorageKeyForUrl(url);
                if (key && key !== 'null' && key !== 'about:blank' && !isLocalDevUrl(url) && !isEndpointIgnored(key)) {
                    allEndpoints.add(key);
                }
            });
        }
        
        // Step 2: Filter out already scanned endpoints (ONLY check marker)
        const unmarkedEndpoints = Array.from(allEndpoints).filter(key => 
            !autoPilotScannedEndpoints.has(key) && !launchInProgressEndpoints.has(key)
        );
        
        if (unmarkedEndpoints.length === 0) {
            log.debug(`[Auto Pilot] No new endpoints to scan (${allEndpoints.size} total, ${autoPilotScannedEndpoints.size} already scanned)`);
            return; // Lock will be released in finally
        }
        
        log.info(`[Auto Pilot] Found ${unmarkedEndpoints.length} unmarked endpoint(s) to scan (${allEndpoints.size} total)`);
        
        // Step 3: Scan each unmarked endpoint
        for (let i = 0; i < unmarkedEndpoints.length; i++) {
            const endpointKey = unmarkedEndpoints[i];
            
            // Mark as scanned IMMEDIATELY (before scanning) to prevent duplicates
            autoPilotScannedEndpoints.add(endpointKey);
            
            // Persist to storage
            await chrome.storage.sync.set({ 
                [AUTOPILOT_SCANNED_KEY]: Array.from(autoPilotScannedEndpoints) 
            });
            
            // Update footer
            updateAutoPilotFooter(`Auto Pilot: ${i + 1}/${unmarkedEndpoints.length} - ${endpointKey}`);
            
            // Scan the endpoint
            try {
                await triggerAutoPilotScan(endpointKey, false);
                
                // Small delay between scans to avoid overwhelming the system
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (err) {
                log.error(`[Auto Pilot] Failed to scan ${endpointKey}:`, err.message);
            }
        }
    
        hideAutoPilotFooter();
        log.info(`[Auto Pilot] Completed scanning ${unmarkedEndpoints.length} endpoint(s)`);
        
    } catch (error) {
        log.error('[Auto Pilot] Error during scanning:', error);
    } finally {
        // Always release lock
        autoPilotScanInProgress = false;
    }
}

// Enable Auto Pilot
async function enableAutoPilot(silent = false) {
    // Check if warning has been shown
    const storage = await chrome.storage.sync.get([AUTOPILOT_WARNING_SHOWN_KEY]);
    const warningShown = storage[AUTOPILOT_WARNING_SHOWN_KEY] || false;
    
    if (!silent && !warningShown) {
        const accepted = await showAutoPilotWarning();
        if (!accepted) return;
        await chrome.storage.sync.set({ [AUTOPILOT_WARNING_SHOWN_KEY]: true });
    }
    
    autoPilotEnabled = true;
    await chrome.storage.sync.set({ [AUTOPILOT_ENABLED_KEY]: true });
    
    // Update button
    const button = document.getElementById('autoPilotToggle');
    if (button) {
        button.textContent = '🤖 Auto Pilot: ON';
        button.classList.remove('autopilot-off');
        button.classList.add('autopilot-on');
    }
    
    if (!silent) {
        showToastNotification('🤖 Auto Pilot enabled! Scanning endpoints...', 'success', 3000);
    }
    
    log.info('[Auto Pilot] Enabled');
    
    // Immediately scan any existing unmarked endpoints
    await scanUnmarkedEndpoints();
    
    // Start continuous monitoring (checks every 3 seconds for new unmarked endpoints)
    startAutoPilotMonitoring();
}

// SIMPLIFIED: Monitor for new unmarked endpoints
function startAutoPilotMonitoring() {
    // Clear any existing interval
    if (autoPilotMonitorInterval) {
        clearInterval(autoPilotMonitorInterval);
    }
    
    // Check for new unmarked endpoints every 3 seconds
    autoPilotMonitorInterval = setInterval(async () => {
        if (!autoPilotEnabled || urlScanInProgress) return;
        await scanUnmarkedEndpoints();
    }, 3000);
    
    log.info('[Auto Pilot] Monitoring started - checking for new endpoints every 3 seconds');
}

// Disable Auto Pilot
async function disableAutoPilot(silent = false) {
    autoPilotEnabled = false;
    await chrome.storage.sync.set({ [AUTOPILOT_ENABLED_KEY]: false });
    
    // Stop monitoring for new endpoints
    if (autoPilotMonitorInterval) {
        clearInterval(autoPilotMonitorInterval);
        autoPilotMonitorInterval = null;
        log.debug('[Auto Pilot] Stopped monitoring for new endpoints');
    }
    
    // Release any active scan lock
    autoPilotScanInProgress = false;
    
    // Clear scanned endpoints list and persist to storage
    autoPilotScannedEndpoints.clear();
    await chrome.storage.sync.set({ [AUTOPILOT_SCANNED_KEY]: [] });
    
    // Update button
    const button = document.getElementById('autoPilotToggle');
    if (button) {
        button.textContent = '🤖 Auto Pilot: OFF';
        button.classList.remove('autopilot-on');
        button.classList.add('autopilot-off');
    }
    
    if (!silent) {
        showToastNotification('Auto Pilot disabled', 'info', 2000);
    }
    
    log.info('[Auto Pilot] Disabled');
}

// Toggle Auto Pilot
async function toggleAutoPilot() {
    if (autoPilotEnabled) {
        await disableAutoPilot();
    } else {
        await enableAutoPilot();
    }
}

// Update Auto Pilot footer
function updateAutoPilotFooter(message) {
    const footer = document.getElementById('autoPilotFooter');
    if (!footer) return;
    
    footer.className = 'autopilot-footer-bar';
    footer.style.display = 'flex';
    footer.innerHTML = `
        <div class="autopilot-footer-content">
            <div class="autopilot-footer-spinner"></div>
            <span>Auto Pilot: ${message || 'Scanning...'}</span>
        </div>
        <button class="autopilot-footer-close" onclick="hideAutoPilotFooter()">Dismiss</button>
    `;
}

// Hide Auto Pilot footer
function hideAutoPilotFooter() {
    const footer = document.getElementById('autoPilotFooter');
    if (footer) {
        footer.style.display = 'none';
    }
}
window.hideAutoPilotFooter = hideAutoPilotFooter;

// Initialize Auto Pilot state on load
async function initializeAutoPilot() {
    const storage = await chrome.storage.sync.get([AUTOPILOT_ENABLED_KEY, AUTOPILOT_SCANNED_KEY]);
    const stored = storage[AUTOPILOT_ENABLED_KEY] || false;
    const storedScanned = storage[AUTOPILOT_SCANNED_KEY];
    
    // Restore scanned endpoints from storage (persistent tracking)
    if (storedScanned && Array.isArray(storedScanned)) {
        autoPilotScannedEndpoints = new Set(storedScanned);
        log.info(`[Auto Pilot Init] Restored ${autoPilotScannedEndpoints.size} previously scanned endpoint(s)`);
    }
    
    log.info(`[Auto Pilot Init] Stored value: ${stored}, setting autoPilotEnabled to: ${stored}`);
    
    autoPilotEnabled = stored;
    const button = document.getElementById('autoPilotToggle');
    if (button) {
        if (stored) {
            log.warn('[Auto Pilot Init] State is ON - this should not happen on clean load!');
            button.textContent = '🤖 Auto Pilot: ON';
            button.classList.remove('autopilot-off');
            button.classList.add('autopilot-on');
        } else {
            log.info('[Auto Pilot Init] State is OFF (correct default)');
            button.textContent = '🤖 Auto Pilot: OFF';
            button.classList.remove('autopilot-on');
            button.classList.add('autopilot-off');
        }
    }
    
    // Load custom URLs list
    const urlStorage = await chrome.storage.local.get([CUSTOM_URLS_STORAGE_KEY]);
    customUrlsList = urlStorage[CUSTOM_URLS_STORAGE_KEY] || [];
    
    // Load ignored endpoints
    await loadIgnoredEndpoints();
    
    // Load failed endpoints cache
    await loadFailedEndpoints();
    
    // Load collapsed groups
    await loadCollapsedGroups();
}

// Expose functions to global scope
window.addToIgnoreList = addToIgnoreList;
window.removeFromIgnoreList = removeFromIgnoreList;
window.isEndpointIgnored = isEndpointIgnored;
window.clearFailedEndpoint = clearFailedEndpoint;
window.clearAllFailedEndpoints = async function() {
    failedEndpoints.clear();
    await saveFailedEndpoints();
    log.success('[Failed Cache] Cleared all failed endpoints');
    requestUiUpdate();
};
window.toggleGroupCollapse = toggleGroupCollapse;

// Trigger Auto Pilot scan for new iframe
async function triggerAutoPilotScan(endpointKey, manageFooter = true) {
    if (!autoPilotEnabled || urlScanInProgress) return;
    
    log.info(`[Auto Pilot] Scanning: ${endpointKey}`);
    if (manageFooter) {
        updateAutoPilotFooter(`Scanning: ${endpointKey}`);
    }
    
    try {
        // CRITICAL: Check CSP headers BEFORE attempting to scan
        // This prevents false positives from endpoints that block framing
        log.debug(`[Auto Pilot] Checking CSP for ${endpointKey}...`);
        const cspResult = await checkCSPHeaders(endpointKey);
        
        if (!cspResult.canEmbed) {
            log.warn(`[Auto Pilot] Skipping ${endpointKey} - CSP blocks framing: ${cspResult.reason}`);
            log.debug(`[Auto Pilot] CSP Headers:`, cspResult.headers);
            
            // Store CSP error state so button shows correctly when UI updates
            buttonStates.set(endpointKey, { 
                state: 'error', 
                options: { errorMessage: `CSP Blocked: ${cspResult.reason}` } 
            });
            
            // Update button immediately if it exists
            let button = document.querySelector(`.iframe-check-button[data-endpoint="${endpointKey}"]`);
            if (button) {
                updateButton(button, 'error', { errorMessage: `CSP Blocked: ${cspResult.reason}` });
            }
            
            // Trigger UI update to ensure button is rendered with error state
            requestUiUpdate();
            
            return; // Skip this endpoint entirely
        }
        
        log.debug(`[Auto Pilot] CSP check passed for ${endpointKey}`);
        
        // Find or create buttons
        let button = document.querySelector(`.iframe-check-button[data-endpoint="${endpointKey}"]`);
        if (!button) {
            button = document.createElement('button');
            button.className = 'iframe-check-button';
            button.setAttribute('data-endpoint', endpointKey);
        }
        
        // CRITICAL: Reset button state to prevent Launch from being triggered
        // Auto Pilot should ONLY do Play+Trace, NEVER Launch
        buttonStates.delete(endpointKey);
        
        // Run Play with silent mode AND hideFromUser mode (silentMode=true, hideFromUser=true)
        await handlePlayButtonWithTimeout(endpointKey, button, false, true, true);
        
        // Wait a bit for handler extraction to complete
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Check if handler was found by checking endpointsWithDetectedHandlers (updated immediately)
        const hasHandler = endpointsWithDetectedHandlers.has(endpointKey);
        
        if (hasHandler) {
            log.info(`[Auto Pilot] Handler detected for ${endpointKey}, running Trace...`);
            
            // Run Trace with silent mode
            let traceButton = document.querySelector(`.iframe-trace-button[data-endpoint="${endpointKey}"]`);
            if (!traceButton) {
                traceButton = document.createElement('button');
                traceButton.className = 'iframe-trace-button';
                traceButton.setAttribute('data-endpoint', endpointKey);
            }
            
            if (window.handleTraceButton) {
                await window.handleTraceButton(endpointKey, traceButton, true);
            }
            
            log.success(`[Auto Pilot] Completed Play+Trace for ${endpointKey}`);
        } else {
            log.warn(`[Auto Pilot] No handler found for ${endpointKey}, skipping Trace`);
        }
        
    } catch (error) {
        log.error(`[Auto Pilot] Failed to scan ${endpointKey}:`, error.message);
    } finally {
        if (manageFooter) {
            hideAutoPilotFooter();
        }
    }
}

