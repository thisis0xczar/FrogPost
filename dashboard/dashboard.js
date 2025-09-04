/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-09-04
 */


/**
 * Sensitive Data Detection & Sanitization Engine for FrogPost
 * Protects users by identifying and sanitizing sensitive data before LLM analysis
 */
class SensitiveDataDetector {
    constructor() {
        this.patterns = this.initializePatterns();
        this.sanitizedReplacements = this.initializeSafeReplacements();
    }

    /**
     * Initialize comprehensive sensitive data patterns (Top 50+ patterns)
     */
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
            
            custom: [] // Populated from user settings
        };
    }

    /**
     * Initialize safe replacement values
     */
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

    /**
     * Detect sensitive data in a message or object
     */
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

    /**
     * Sanitize data by replacing sensitive patterns with safe alternatives
     */
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

    /**
     * Analyze messages specifically for LLM safety
     */
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

/**
 * LLM Cost Protection System for FrogPost
 * Prevents expensive API calls and provides cost estimates
 */
class LLMCostProtector {
    constructor() {
        this.limits = this.initializeLimits();
        this.rateLimiter = new Map();
    }

    /**
     * Initialize cost protection limits
     */
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
                    "gpt-4o": { in: 0.0025, out: 0.0100, cachedIn: 0.00125 }, // $2.50/$10 per 1M, cached $1.25
                    "gpt-4o-mini": { in: 0.0006, out: 0.0024, cachedIn: 0.0003 }, // $0.60/$2.40 per 1M, cached $0.30
                    "gpt-4-turbo": { in: 0.0100, out: 0.0300 }, // Legacy pricing
                    "gpt-3.5-turbo": { in: 0.0005, out: 0.0015 }, // Legacy pricing
                    "o1-mini": { in: 0.0030, out: 0.0150 }, // $3/$15 per 1M
                    "o1-preview": { in: 0.0150, out: 0.0600 } // $15/$60 per 1M
                },
                anthropic: {
                    "claude-3-5-sonnet-20241022": { in: 0.0030, out: 0.0150 }, // $3/$15 per 1M
                    "claude-3-5-haiku-20241022": { in: 0.0008, out: 0.0040 }, // $0.80/$4 per 1M
                    "claude-3-haiku-20240307": { in: 0.00025, out: 0.00125 }, // $0.25/$1.25 per 1M
                    "claude-3-opus-20240229": { in: 0.0150, out: 0.0750 } // $15/$75 per 1M
                },
                groq: {
                    "llama-3.1-70b-versatile": { in: 0.00059, out: 0.00079 }, // $0.59/$0.79 per 1M
                    "llama-3.1-8b-instant": { in: 0.00005, out: 0.00008 }, // $0.05/$0.08 per 1M
                    "mixtral-8x7b-32768": { in: 0.00027, out: 0.00027 }, // $0.27/$0.27 per 1M
                    "gemma-7b-it": { in: 0.00007, out: 0.00007 } // $0.07/$0.07 per 1M
                },
                mistral: {
                    "mistral-large-latest": { in: 0.0020, out: 0.0060 }, // $2/$6 per 1M (estimated)
                    "mistral-medium-latest": { in: 0.0004, out: 0.0020 }, // $0.40/$2 per 1M (estimated)
                    "open-mixtral-8x7b": { in: 0.0007, out: 0.0007 }, // $0.70/$0.70 per 1M (estimated)
                    "mistral-small-latest": { in: 0.0002, out: 0.0006 } // $0.20/$0.60 per 1M (estimated)
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

    /**
     * Analyze request for cost and safety before sending to LLM
     */
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
        console.log('🔍 [Model Detection] Using model:', { requested: analysisRequest.model, provider, selected: model });
        
        const inputTokenEstimate = this.estimateTokens(optimizedRequest, provider, model);
        
        const expectedOutputTokens = this.estimateExpectedOutputTokens(analysisRequest);
        
        analysis.tokenEstimate = inputTokenEstimate;
        analysis.expectedOutputTokens = expectedOutputTokens;
        analysis.totalTokenEstimate = inputTokenEstimate + expectedOutputTokens;
        
        const costBreakdown = this.calculateCost(provider, model, inputTokenEstimate, expectedOutputTokens);
        analysis.costEstimate = costBreakdown.total || 0;
        analysis.costBreakdown = costBreakdown;
        
        console.log('💰 [Cost Calculation] Debug:', {
            provider,
            model,
            inputTokens: inputTokenEstimate,
            outputTokens: expectedOutputTokens,
            costBreakdown,
            finalCost: analysis.costEstimate
        });

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

    /**
     * Optimize analysis request to reduce costs
     */
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

    /**
     * Estimate tokens using provider-specific tokenizers
     * Falls back to improved heuristic if tokenizer unavailable
     */
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

    /**
     * OpenAI token estimation with model-specific encodings
     */
    estimateOpenAITokens(text, model) {
        const ratios = {
            'gpt-4o': 3.2,        // o200k encoding
            'gpt-4o-mini': 3.2,   // o200k encoding  
            'gpt-4-turbo': 3.5,   // cl100k_base encoding
            'gpt-3.5-turbo': 3.8, // cl100k_base encoding
            'o1-mini': 3.2,       // o200k encoding
            'o1-preview': 3.2     // o200k encoding
        };
        
        const ratio = ratios[model] || 3.5;
        return Math.ceil(text.length / ratio);
    }

    /**
     * Anthropic token estimation
     */
    estimateAnthropicTokens(text) {
        return Math.ceil(text.length / 3.0);
    }

    /**
     * Groq token estimation (Llama tokenizer)
     */
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

    /**
     * Mistral token estimation
     */
    estimateMistralTokens(text) {
        return Math.ceil(text.length / 3.1);
    }

    /**
     * Improved heuristic fallback
     */
    estimateTokensHeuristic(text) {
        let tokenCount = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text[i];
            if (char === ' ' || char === '\n' || char === '\t') {
                tokenCount += 0.25; // Whitespace is often tokenized separately
            } else if (/[a-zA-Z0-9]/.test(char)) {
                tokenCount += 0.3; // Alphanumeric characters
            } else {
                tokenCount += 1; // Special characters, punctuation
            }
        }
        return Math.ceil(tokenCount);
    }

    /**
     * Calculate accurate cost using per-model input/output pricing
     */
    calculateCost(provider, model, inputTokens, outputTokens = 0, cachedInputTokens = 0, useBatch = false) {
        const prices = this.limits.PRICES_PER_1K[provider.toLowerCase()];
        if (!prices || !prices[model]) {
            const legacyInfo = this.limits.providerLimits[provider.toLowerCase()] || this.limits.providerLimits.openai;
            const totalTokens = inputTokens + outputTokens;
            const legacyCost = totalTokens * legacyInfo.costPerToken;
            console.warn('⚠️ [Cost Calculation] Using legacy pricing fallback:', { provider, model, totalTokens, legacyCost });
            return {
                inputCost: legacyCost * 0.7, // Rough split
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
        const inRate = modelPricing.in / 1000;  // Convert per-1K to per-token
        const outRate = modelPricing.out / 1000;
        const cachedRate = (modelPricing.cachedIn || modelPricing.in * 0.5) / 1000;

        let inputCost = (inputTokens - cachedInputTokens) * inRate;
        let cachedCost = cachedInputTokens * cachedRate;
        let outputCost = outputTokens * outRate;
        let total = inputCost + cachedCost + outputCost;

        if (useBatch && (provider === 'anthropic' || provider === 'openai')) {
            total *= 0.5; // 50% discount for batch APIs
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

    /**
     * Get default model for provider
     */
    getDefaultModel(provider) {
        const defaults = {
            'openai': 'gpt-4o-mini',
            'anthropic': 'claude-3-5-haiku-20241022',
            'groq': 'llama-3.1-8b-instant',
            'mistral': 'mistral-small-latest'
        };
        return defaults[provider.toLowerCase()] || 'gpt-4o-mini';
    }

    /**
     * Estimate expected output tokens based on request complexity
     */
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

    /**
     * Calculate actual cost from API usage data
     */
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
let showOnlySilentIframes = false;
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
            chrome.runtime.sendMessage({ type: "checkVersion" }, (response) => { // Use new message type
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
            url.startsWith('blob:') || url.startsWith('data:')) {
            log.debug(`[Normalize URL] Special browser URL detected: ${url}`);
            return { normalized: url, components: null, key: url };
        }

        if (!url.includes('://') && !url.startsWith('//')) {
            absUrl = 'https://' + url; // Default to https if no protocol
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
    let success = false; try { const messageItem = button.closest('.message-item'); if (!messageItem) throw new Error("Message item not found"); const messageDataElement = messageItem.querySelector('.message-data'); if (!messageDataElement) throw new Error("Message data element not found"); const messageContent = messageDataElement.textContent; let data; try { data = JSON.parse(messageContent); } catch (e) { data = messageContent; } const iframe = document.createElement('iframe'); iframe.style.display = 'none'; document.body.appendChild(iframe); iframe.src = targetKey; await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error("Iframe load timeout")), 3000); iframe.onload = () => { clearTimeout(timer); resolve(); }; iframe.onerror = () => { clearTimeout(timer); reject(new Error("Iframe load error")); }; }); if (iframe.contentWindow) { iframe.contentWindow.postMessage(data, '*'); success = true; } else throw new Error("Iframe content window not accessible"); setTimeout(() => { if (document.body.contains(iframe)) document.body.removeChild(iframe); }, 500); } catch (error) { log.error("Error in sendMessageTo:", error); success = false; } finally { button.classList.toggle('success', success); button.classList.toggle('error', !success); setTimeout(() => button.classList.remove('success', 'error'), 1000); } return success;
}

async function sendMessageFromModal(targetKey, editedDataString, buttonElement, originalButtonText) {
    if (!targetKey || !buttonElement) return false; let dataToSend; try { dataToSend = JSON.parse(editedDataString); } catch (e) { dataToSend = editedDataString; } buttonElement.textContent = 'Sending...'; buttonElement.disabled = true; buttonElement.classList.remove('success', 'error'); let iframe = null;
    try { iframe = document.createElement('iframe'); iframe.style.display = 'none'; document.body.appendChild(iframe); iframe.src = targetKey; await new Promise((resolve, reject) => { const timeoutId = setTimeout(() => reject(new Error("Iframe load timeout")), 5000); iframe.onload = () => { clearTimeout(timeoutId); resolve(); }; iframe.onerror = (err) => { clearTimeout(timeoutId); reject(new Error("Iframe load error")); }; }); if (iframe.contentWindow) { iframe.contentWindow.postMessage(dataToSend, '*'); buttonElement.textContent = 'Sent ✓'; buttonElement.classList.add('success'); await new Promise(res => setTimeout(res, 1000)); return true; } else throw new Error("Iframe content window not accessible"); } catch (error) { log.error(`Error sending message from modal to ${targetKey}:`, error); buttonElement.textContent = 'Error ✕'; buttonElement.classList.add('error'); await new Promise(res => setTimeout(res, 2000)); return false; } finally { if (iframe && iframe.parentNode) iframe.parentNode.removeChild(iframe); if (buttonElement && !buttonElement.classList.contains('success')) { buttonElement.disabled = false; buttonElement.textContent = originalButtonText; buttonElement.classList.remove('error'); } }
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
    item.setAttribute('data-message-id', visibleId);

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
        const savedPlayStateInfo = buttonStates.get(endpointKey);
        updateButton(playButton, savedPlayStateInfo?.state || 'start', savedPlayStateInfo?.options || {});
        const canTrace = playButton.classList.contains('success') || playButton.classList.contains('green') || playButton.classList.contains('launch');
        updateTraceButton(traceButton, traceInfo?.state || (canTrace ? 'default' : 'disabled'), traceInfo?.options || {});
        const canReport = traceButton.classList.contains('green') || traceButton.classList.contains('success');
        updateReportButton(reportButton, reportInfo || (canReport ? 'default' : 'disabled'), endpointKey);
    }

    playButton.addEventListener("click", (e) => { e.stopPropagation(); handlePlayButton(endpointKey, playButton); });
    traceButton.addEventListener("click", (e) => { e.stopPropagation(); if (!traceButton.hasAttribute('disabled') && !traceButton.classList.contains('checking')) window.handleTraceButton(endpointKey, traceButton); });
    reportButton.addEventListener("click", (e) => { e.stopPropagation(); if (!reportButton.classList.contains('disabled')) handleReportButton(endpointKey); });

    buttonContainer.appendChild(playButton);
    buttonContainer.appendChild(traceButton);
    buttonContainer.appendChild(reportButton);
    
    return buttonContainer;
}

async function analyzeWithLLM(endpointKey, buttonEl) {
    try {
        if (buttonEl) { buttonEl.classList.add('checking'); buttonEl.disabled = true; }
        const settings = await chrome.storage.sync.get(['llm_provider','llm_model']);
        const sess = await chrome.storage.session.get(['llm_api_key']);
        const provider = settings.llm_provider || 'none';
        const model = settings.llm_model || '';
        const apiKey = sess.llm_api_key || '';
        const bestKey = `best-handler-${endpointKey}`;
        const saved = await chrome.storage.local.get([bestKey]);
        const handlerInfo = saved[bestKey] || {};
        const report = await window.traceReportStorage.getTraceReport(endpointKey);
        const payloads = await window.traceReportStorage.getReportPayloads(endpointKey);
        
        const savedMessages = await chrome.storage.local.get([`saved-messages-${endpointKey}`]);
        let capturedMessages = savedMessages[`saved-messages-${endpointKey}`] || [];
        
        try {
            const TEST_MESSAGE_KEY = 'FrogPost';
            const TEST_MESSAGE_VALUE = 'BreakpointTest';
            const panelKey = getStorageKeyForUrl(endpointKey);
            const uiRelated = (window.frogPostState?.messages || []).filter(msg => {
                const originKey = msg.origin ? getStorageKeyForUrl(msg.origin) : null;
                const destKey = msg.destinationUrl ? getStorageKeyForUrl(msg.destinationUrl) : null;
                return originKey === panelKey || destKey === panelKey;
            }).filter(msg => !(typeof msg.data === 'object' && msg.data !== null && Object.prototype.hasOwnProperty.call(msg.data, TEST_MESSAGE_KEY) && msg.data[TEST_MESSAGE_KEY] === TEST_MESSAGE_VALUE));
            if (uiRelated.length > 0) capturedMessages = uiRelated;
            const seen = new Set();
            const deduped = [];
            for (const m of capturedMessages) {
                const id = m?.messageId || `${m?.origin || ''}|${m?.destinationUrl || ''}|${m?.timestamp || ''}|${typeof m?.data === 'string' ? m.data : JSON.stringify(m?.data || {})}`;
                if (!seen.has(id)) { seen.add(id); deduped.push(m); }
            }
            capturedMessages = deduped;
        } catch (e) { console.warn('⚠️ [LLM] UI message alignment failed, using raw storage list:', e); }
        
        console.log(`🤖 [LLM Analysis] Starting analysis for: ${endpointKey}`);
        console.log(`🤖 [LLM Settings] Provider: ${provider}, Model: ${model}, HasKey: ${!!apiKey}`);
        
        if (!provider || provider === 'none' || !model || !apiKey) {
            showToastNotification('⚠️ LLM configuration required. Please configure provider, model, and API key in Options.', 'warning');
            console.log('❌ [LLM Validation] Missing configuration:', { provider, model, hasApiKey: !!apiKey });
            return;
        }
        console.log(`🤖 [LLM Context] Handler: ${!!handlerInfo?.handler}, Messages (UI-aligned): ${capturedMessages.length}, Payloads: ${payloads?.length || 0}`);
        console.log(`🤖 [LLM Context] Captured messages details:`, capturedMessages.map(m => ({ 
            id: m.messageId, 
            type: m.messageType, 
            data: m.data,
            origin: m.origin,
            destination: m.destinationUrl 
        })));
        
        const context = {
            url: endpointKey,
            observedMessages: capturedMessages,
            currentPayloads: payloads || [],
            handlerCode: handlerInfo?.handler || '',
            sinks: report?.details?.sinks || [],
            originChecks: report?.details?.originValidationChecks || []
        };
        
        console.log('🛡️ [Safety] Performing pre-LLM safety analysis...');
        
        const sensitiveDetector = new SensitiveDataDetector();
        const costProtector = new LLMCostProtector();
        
        const sensitivityAnalysis = sensitiveDetector.analyzeLLMSafety(capturedMessages);
        console.log('🔍 [Sensitive Data] Analysis results:', sensitivityAnalysis);
        
        const costAnalysis = costProtector.analyzeRequest(context, provider);
        console.log('💰 [Cost Protection] Analysis results:', costAnalysis);
        
        console.log('🛡️ [Safety Check] Triggering consent dialog:', {
            sensitiveMsgCount: sensitivityAnalysis.sensitiveMsgCount,
            costEstimate: costAnalysis.costEstimate,
            shouldShowDialog: true
        });
        
        console.log('🛡️ [Safety] About to show consent dialog...');
        try {
            const proceed = await showSafetyConsentDialog(sensitivityAnalysis, costAnalysis);
            console.log('🛡️ [Safety] Dialog result:', proceed);
            if (!proceed) {
                showToastNotification('🛡️ LLM analysis cancelled by user', 'info');
                return;
            }
        } catch (error) {
            console.error('❌ [Safety] Error showing consent dialog:', error);
            showToastNotification('❌ Error showing safety dialog. Proceeding with analysis.', 'warning');
        }
        
        if (!costAnalysis.approved) {
            showToastNotification(`🚫 Request blocked: ${costAnalysis.warnings.join(', ')}`, 'error');
            return;
        }
        
        const safeContext = {
            ...costAnalysis.optimizedRequest,
            observedMessages: sensitivityAnalysis.sanitizedMessages.map(sm => sm.sanitized)
        };
        
        console.log('🧮 [Messages] Counts:', {
            captured: capturedMessages.length,
            sentToLLM: safeContext.observedMessages.length,
            optimizedReduction: `${sensitivityAnalysis.totalMessages - safeContext.observedMessages.length}/${sensitivityAnalysis.totalMessages}`
        });
        
        console.log(`🛡️ [Safety] Protected context - Original: ${JSON.stringify(context).length} bytes, Safe: ${JSON.stringify(safeContext).length} bytes`);
        
        costProtector.recordAPICall();
        
        console.log(`🤖 [LLM Context Details]:`, {
            messagesCount: safeContext.observedMessages.length,
            messageTypes: safeContext.observedMessages.map(m => ({type: typeof m, hasData: !!m?.data, dataType: typeof m?.data})),
            currentPayloadsCount: safeContext.currentPayloads.length,
            handlerLength: safeContext.handlerCode.length,
            sinksCount: safeContext.sinks.length,
            originChecksCount: safeContext.originChecks.length,
            safetyInfo: {
                sensitiveDataDetected: sensitivityAnalysis.sensitiveMsgCount,
                costEstimate: costAnalysis.costEstimate,
                costBreakdown: costAnalysis.costBreakdown,
                tokenBreakdown: {
                    input: costAnalysis.tokenEstimate,
                    output: costAnalysis.expectedOutputTokens,
                    total: costAnalysis.totalTokenEstimate
                },
                payloadReduction: costAnalysis.originalSize > 0 ? ((costAnalysis.originalSize - costAnalysis.optimizedSize) / costAnalysis.originalSize * 100).toFixed(1) + '%' : '0%'
            }
        });
        
        const reqBody = { provider, model, apiKey, context: safeContext };
        console.log(`🤖 [LLM Request] Sending to server with safety protections...`);
        const res = await fetch('http://127.0.0.1:1337/llm/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody) });
        
        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            if (res.status === 400 && errorData.error === 'LLM configuration required') {
                showToastNotification('⚠️ LLM configuration required. Please set up provider, model, and API key in Options.', 'warning');
                return;
            }
            throw new Error(`LLM server responded ${res.status}: ${errorData.message || 'Unknown error'}`);
        }
        const data = await res.json();
        
        if (!data || !data.llm_raw_output || (Array.isArray(data.newPayloads) && data.newPayloads.length === 0)) {
            console.warn('⚠️ [LLM Gating] Missing llm_raw_output or no new payloads. Blocking heuristic/fallback results.');
            showToastNotification('⚠️ LLM returned no content. Please check your API key/model and try again.', 'warning');
            return;
        }
        
        console.log(`LLM analysis complete. +${data.newPayloadsCount || 0} new, total merged: ${data.mergedCount || 0}`);
        console.log('Full LLM response:', data);
        if (data.analysis_details) {
            console.log('🔍 [LLM Analysis Details]:', data.analysis_details);
        }
        
        if (data.handler_assessment || data.risks || data.notes || data.handler_score !== undefined) {
            const llmAnalysisData = {
                handler_assessment: data.handler_assessment,
                handler_score: data.handler_score,
                risks: data.risks,
                notes: data.notes,
                summary: data.summary,
                newPayloadsCount: data.newPayloadsCount,
                llm_raw_output: data.llm_raw_output,
                llm_prompt_excerpt: data.llm_prompt_excerpt
            };
            
            console.log('🤖 [LLM Analysis] Structured data to save:', llmAnalysisData);
            
            try {
                const report = await window.traceReportStorage.getTraceReport(endpointKey);
                if (report && report.summary) {
                    report.summary.messagesAnalyzed = (capturedMessages || []).length;
                    await window.traceReportStorage.saveTraceReport(endpointKey, report);
                    console.log('🧮 [Report] Updated messagesAnalyzed in summary to', report.summary.messagesAnalyzed);
                }
            } catch (e) { console.warn('⚠️ [Report] Unable to update messagesAnalyzed:', e); }
            
            try {
                const existing = report?.details || {};
                existing.llmAnalysis = existing.llmAnalysis || {};
                Object.assign(existing.llmAnalysis, llmAnalysisData);
                report.details = existing;
                await window.traceReportStorage.saveTraceReport(endpointKey, report);
            } catch (e) { console.warn('⚠️ [LLM Analysis] Unable to persist LLM analysis into report:', e); }
            
            updateExistingReportWithLLM(llmAnalysisData);
        }
        
        if (data?.betterHandler || data?.better_handler) { 
            const newHandler = data.betterHandler || data.better_handler;
            const merged = { ...(handlerInfo||{}), handler: newHandler }; 
            await chrome.storage.local.set({ [bestKey]: merged }); 
        }
        
        let newPayloads = [];
        if (Array.isArray(data?.new_payloads)) {
            newPayloads = data.new_payloads;
        } else if (Array.isArray(data?.newPayloads)) {
            newPayloads = data.newPayloads;
        }
        
        if (newPayloads.length > 0) { 
            console.log(`Saving ${newPayloads.length} new LLM payloads:`, newPayloads);
            const existing = await window.traceReportStorage.getReportPayloads(endpointKey); 
            await window.traceReportStorage.saveReportPayloads(endpointKey, [ ...(existing||[]), ...newPayloads ]); 
        }
        if (report) { 
            report.details = report.details || {}; 
            report.details.llmAnalysis = {
                summary: `${data.newPayloadsCount} new payloads generated`,
                newPayloadsCount: data?.newPayloadsCount || 0,
                mergedCount: data?.mergedCount || 0,
                raw_output: data?.llm_raw_output || ''
            };
            await window.traceReportStorage.saveTraceReport(endpointKey, report); 
        }
        if (buttonEl) { buttonEl.classList.remove('checking'); buttonEl.classList.add('green'); setTimeout(()=> buttonEl.classList.remove('green'), 1500); }
    } catch (e) { if (buttonEl) { buttonEl.classList.remove('checking'); buttonEl.classList.add('error'); setTimeout(()=> buttonEl.classList.remove('error'), 2000); } }
    finally { if (buttonEl) buttonEl.disabled = false; }
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

    const hostRow = document.createElement("div");
    hostRow.className = "host-row";
    hostRow.dataset.url = parentKey;
    if (parentKey === window.frogPostState.activeUrl) {
        hostRow.classList.add('active');
    }

    const hostName = document.createElement("span");
    hostName.className = "host-name";
    hostName.textContent = parentKey;
    hostName.title = parentKey;

    hostRow.addEventListener("click", (e) => {
        e.stopPropagation();
        setActiveUrl(parentKey);
    });

    const parentButtonContainer = createActionButtonContainer(parentKey);

    hostRow.appendChild(hostName);
    hostRow.appendChild(parentButtonContainer);
    hostElement.appendChild(hostRow);

    const iframeContainer = document.createElement("div");
    iframeContainer.className = "iframe-container";

    const sortedChildKeys = Array.from(childKeysSet).sort();
    let displayedChildrenCount = 0;

    sortedChildKeys.forEach((childKey) => {
        const childMatchesFilter = !filterText || childKey.toLowerCase().includes(filterText);
        const isChildSilent = getMessageCount(childKey) === 0;

        let showChild = false;
        if (showOnlySilentIframes) {
            showChild = isChildSilent && childMatchesFilter;
        } else {
            showChild = childMatchesFilter;
        }

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

            iframeRow.addEventListener("click", (e) => {
                e.stopPropagation();
                setActiveUrl(childKey);
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

    window.frogPostState.messages.forEach(msg => {
        if (!msg.topLevelUrl) { // Can't group without top-level context
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

        if (sourceKey && sourceKey !== topLevelKey && sourceKey !== 'null') {
            relatedEndpoints.add(sourceKey);
            allKnownKeys.add(sourceKey);
        }
        if (destKey && destKey !== topLevelKey && destKey !== 'null') {
            relatedEndpoints.add(destKey);
            allKnownKeys.add(destKey);
        }
    });

    knownHandlerEndpoints.forEach(key => allKnownKeys.add(key));
    window.frogPostState.loadedData.urls.forEach(url => {
        const key = getStorageKeyForUrl(url);
        if(key && key !== 'null') allKnownKeys.add(key);
    });


    const fragment = document.createDocumentFragment();
    let displayedEndpointCount = 0;
    const renderedKeys = new Set();

    const sortedTopLevelKeys = Array.from(groupsByTopLevel.keys()).sort();

    sortedTopLevelKeys.forEach(topLevelKey => {
        if (renderedKeys.has(topLevelKey)) return;

        const childKeysSet = groupsByTopLevel.get(topLevelKey) || new Set();

        const topLevelMatchesFilter = !filterText || topLevelKey.toLowerCase().includes(filterText);
        const childrenMatchFilter = !filterText || Array.from(childKeysSet).some(childKey => childKey.toLowerCase().includes(filterText));

        let showGroup = topLevelMatchesFilter || childrenMatchFilter;

        if (showOnlySilentIframes) {
            const isTopLevelConsideredSilent = getMessageCount(topLevelKey) === 0;
            const hasVisibleSilentChild = Array.from(childKeysSet).some(ck => getMessageCount(ck) === 0 && (!filterText || ck.toLowerCase().includes(filterText)));
            showGroup = hasVisibleSilentChild;
        }

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
        if (!renderedKeys.has(key)) {
            const matchesFilter = !filterText || key.toLowerCase().includes(filterText);
            const isSilent = getMessageCount(key) === 0;
            let showStandalone = matchesFilter && (!showOnlySilentIframes || isSilent);

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
        if (filterText || showOnlySilentIframes) {
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
                            if (existingIndex >= 0) {
                                window.frogPostState.messages[existingIndex] = newMsg;
                            } else {
                                window.frogPostState.messages.push(newMsg);
                            }
                            needsUiUpdate = true;
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
                    window.frogPostState.messages.push(...filteredMessages);
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
    document.getElementById("clearMessages")?.addEventListener("click", () => { log.info("Clearing dashboard state..."); window.frogPostState.messages.length = 0; window.frogPostState.activeUrl = null; buttonStates.clear(); traceButtonStates.clear(); reportButtonStates.clear(); endpointsWithHandlers.clear(); knownHandlerEndpoints.clear(); launchInProgressEndpoints.clear(); chrome.storage.local.clear(() => log.info("Local storage cleared.")); chrome.runtime.sendMessage({ type: "resetState" }, (response) => log.info("Background reset")); requestUiUpdate(); });
    document.getElementById("exportMessages")?.addEventListener("click", () => { const sanitizedMessages = window.frogPostState.messages.map(msg => ({ origin: msg.origin, destinationUrl: msg.destinationUrl, timestamp: msg.timestamp, data: sanitizeMessageData(msg.data), messageType: msg.messageType, messageId: msg.messageId })); const blob = new Blob([JSON.stringify(sanitizedMessages, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "frogpost_messages.json"; a.click(); URL.revokeObjectURL(url); });
    document.getElementById("checkAll")?.addEventListener("click", checkAllEndpoints); const debugButton = document.getElementById("debugToggle"); if (debugButton) { debugButton.addEventListener("click", toggleDebugMode); debugButton.textContent = debugMode ? 'Debug: ON' : 'Debug: OFF'; debugButton.className = debugMode ? 'control-button debug-on' : 'control-button debug-off'; }
    document.getElementById("refreshMessages")?.addEventListener("click", () => { chrome.runtime.sendMessage({ type: "fetchInitialState" }, (response) => { if (response?.success) { if (response.messages) { window.frogPostState.messages.length = 0; window.frogPostState.messages.push(...response.messages); } if (response.handlerEndpointKeys) { knownHandlerEndpoints.clear(); endpointsWithHandlers.clear(); response.handlerEndpointKeys.forEach(key => { knownHandlerEndpoints.add(key); endpointsWithHandlers.add(key); }); } log.info("Dashboard refreshed."); requestUiUpdate(); } else log.error("Failed refresh:", response?.error); }); });
    const uploadPayloadsButton = document.getElementById("uploadCustomPayloadsBtn"); const payloadFileInput = document.getElementById("customPayloadsFile"); if(uploadPayloadsButton && payloadFileInput){ uploadPayloadsButton.addEventListener('click', () => payloadFileInput.click()); payloadFileInput.addEventListener('change', handlePayloadFileSelect); }
    document.getElementById("clearCustomPayloadsBtn")?.addEventListener('click', clearCustomPayloads);
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
                await chrome.runtime.sendMessage({ type: "setDebuggerMode", enabled: debuggerApiModeEnabled });
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

async function handlePlayButton(endpoint, button, skipCheck = false) {
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
            updateButton(button, 'launching', currentStateInfo.options);
            showToastNotification("Preparing Fuzzer Environment...", "info", 3000);
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
            updateButton(button, 'csp');
            let cspResult;
            let headErrorOccurred = false;
            let is404 = false;
            let originToCheck = null;

            try {
                cspResult = await performEmbeddingCheck(endpointUrlForAnalysis);
                if (String(cspResult?.status || '').includes('404')) {
                    is404 = true;
                    try { originToCheck = new URL(endpointUrlForAnalysis).origin; } catch {  }
                }
            } catch (headError) {
                log.warn(`[Play] Initial HEAD request failed: ${headError.message}.`);
                cspResult = { status: `HEAD Error: ${headError.message}`, className: 'yellow', embeddable: false };
                headErrorOccurred = true;
                if (headError.message.includes('404') || String(cspResult.status).includes('404')) {
                    is404 = true;
                    try { originToCheck = new URL(endpointUrlForAnalysis).origin; } catch {  }
                }
            }

            if (is404 && originToCheck) {
                log.info(`[Play] HEAD for full URL got 404. Checking origin (${originToCheck}) for framing headers...`);
                showToastNotification(`Checking origin due to 404...`, 'info', 3000);
                let originCspResult;
                try {
                    originCspResult = await performEmbeddingCheck(originToCheck);
                    if (!originCspResult.embeddable) {
                        const originStatus = String(originCspResult.status || '').toLowerCase();
                        const isOriginFramingRestriction = originStatus.includes('x-frame-options') || originStatus.includes('csp:') || originStatus.includes('frame-ancestors');
                        if (isOriginFramingRestriction) {
                            log.warn(`[Play] Origin check found framing restriction: ${originCspResult.status}`);
                            cspResult = originCspResult;
                            is404 = false;
                            headErrorOccurred = false;
                        } else {
                            log.warn(`[Play] Origin check also failed or had no specific restriction (${originCspResult.status}). Proceeding cautiously.`);
                            proceedSilentlyOnError = true;
                        }
                    } else {
                        log.info(`[Play] Origin check passed. Proceeding cautiously based on original 404.`);
                        proceedSilentlyOnError = true;
                    }
                } catch (originErr) {
                    log.warn(`[Play] HEAD request for origin ${originToCheck} also failed: ${originErr.message}. Proceeding cautiously.`);
                    proceedSilentlyOnError = true;
                }
                if(proceedSilentlyOnError && !button.classList.contains('warning')){
                    updateButton(button, 'warning', {errorMessage: `Proceeding despite 404/origin check issues`});
                }
            }


            if (!cspResult.embeddable && !proceedSilentlyOnError) {
                log.warn(`[Play] Embedding check failed for ${endpointUrlForAnalysis}: ${cspResult.status}`);
                const statusString = String(cspResult.status || '').toLowerCase();
                const isFramingRestriction = !headErrorOccurred && (statusString.includes('x-frame-options') || statusString.includes('csp:') || statusString.includes('frame-ancestors'));

                if (isFramingRestriction) {
                    log.error(`[Play] Embedding explicitly blocked by header: ${cspResult.status}.`);
                    showToastNotification(`Embedding blocked by header: ${cspResult.status}`, 'error');
                    if(!statusString.includes('deny') && !statusString.includes("'none'")) {
                        const modalResult = await showUrlModificationModal(endpointUrlForAnalysis, cspResult.status);
                        if (modalResult.action === 'retry' && modalResult.modifiedUrl) {
                            log.info("[Play] User modified URL after header block. Retrying check...");
                            endpointUrlForAnalysis = modalResult.modifiedUrl;
                            analysisStorageKey = getStorageKeyForUrl(endpointUrlForAnalysis);
                            launchInProgressEndpoints.delete(endpointKey);
                            await handlePlayButton(endpointUrlForAnalysis, button, false);
                            return;
                        } else if(modalResult.action === 'continue'){
                            log.warn(`[Play] User chose to continue analysis despite known header restriction: ${cspResult.status}`);
                            proceedSilentlyOnError = true;
                            updateButton(button, 'warning', {errorMessage: `Proceeding despite block: ${cspResult.status}`});
                        } else {
                            updateButton(button, 'start');
                            throw new Error("Analysis stopped due to embedding restriction.");
                        }
                    } else {
                        updateButton(button, 'error', {errorMessage: `Embedding blocked: ${cspResult.status}`});
                        throw new Error(`Embedding blocked by policy: ${cspResult.status}`);
                    }
                } else {
                    log.warn(`[Play] Initial check failed (${cspResult.status}). Proceeding analysis attempt cautiously.`);
                    showToastNotification(`HEAD check failed (${cspResult.status}), analysis might fail.`, 'warning');
                    proceedSilentlyOnError = true;
                    updateButton(button, 'warning', {errorMessage: `Proceeding despite HEAD fail: ${cspResult.status}`});
                }
            }

            if (cspResult.embeddable || proceedSilentlyOnError) {
                successfullyAnalyzedUrl = endpointUrlForAnalysis;
                analysisStorageKey = getStorageKeyForUrl(successfullyAnalyzedUrl);
                if(cspResult.embeddable){
                    log.success(`[Play] Initial embedding check passed for ${successfullyAnalyzedUrl}`);
                } else {
                    log.warn(`[Play] Proceeding with analysis for ${successfullyAnalyzedUrl} despite earlier check failures/uncertainty.`);
                }
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

        const extractor = new HandlerExtractor().initialize(successfullyAnalyzedUrl, originalMessages);

        analysisErrorMsg = '';

        if (isExtensionUrl){
            if (!foundHandlerObject) {
                log.info("[Play] Extension URL: No pre-existing handler in storage, and no new dynamic discovery performed by Play button.");
            }
        } else {
            try {
                potentialHandlers = await extractor.extractDynamicallyViaDebugger(successfullyAnalyzedUrl);
                if (potentialHandlers.length === 0) log.warn("[Play] Dynamic discovery found no handlers.");
                else log.info(`[Play] Dynamic discovery found ${potentialHandlers.length} potential handlers.`);
            } catch (discoveryError) {
                log.error(`[Play] Handler discovery failed:`, discoveryError);
                analysisErrorMsg = discoveryError.message;
                potentialHandlers = [];
            }

            if (potentialHandlers && potentialHandlers.length > 0) {
                log.info(`[Play] Attempting breakpoint execution confirmation for ${potentialHandlers.length} candidates...`);
                if(!button.classList.contains('warning')) showToastNotification(`Confirming handler via breakpoints...`, 'info', 10000);
                try {
                    potentialHandlers.forEach(h => { if(!h.handler && h.fullScriptContent && h.handlerNode) { try { h.handler = h.fullScriptContent.substring(h.handlerNode.start, h.handlerNode.end); } catch {}} });
                    const validCandidates = potentialHandlers.filter(h => h.handler);
                    if (validCandidates.length === 0) throw new Error("No valid handler candidates with code found for breakpoint setting.");
                    foundHandlerObject = await extractor.confirmHandlerViaBreakpointExecution(successfullyAnalyzedUrl, validCandidates, testMessage);
                    if (foundHandlerObject) { log.success(`[Play] Handler confirmed via breakpoint execution.`); }
                    else { log.warn(`[Play] Breakpoint confirmation did not identify a single handler. Falling back to scoring.`); analysisErrorMsg += (analysisErrorMsg ? ' ' : '') + 'Breakpoint confirmation failed.'; foundHandlerObject = extractor.getBestHandler(potentialHandlers); if(foundHandlerObject) log.info(`[Play] Selected best handler via scoring fallback.`); else log.warn(`[Play] Scoring fallback also failed to select a handler.`);}
                } catch (breakpointError) {
                    log.error(`[Play] Breakpoint confirmation failed:`, breakpointError); analysisErrorMsg = (analysisErrorMsg ? analysisErrorMsg + ' ' : '') + breakpointError.message; log.info(`[Play] Falling back to scoring potential handlers due to breakpoint error.`); foundHandlerObject = extractor.getBestHandler(potentialHandlers); if(!foundHandlerObject) log.warn(`[Play] Scoring fallback also failed to select a handler after breakpoint error.`);
                }
            } else {
                log.warn(`[Play] No potential handlers found during initial discovery. ${analysisErrorMsg}`);
                foundHandlerObject = null;
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

function getRiskLevelAndColor(score) { if (score <= 20) return { riskLevel: 'Critical', riskColor: 'critical' }; if (score <= 40) return { riskLevel: 'High', riskColor: 'high' }; if (score <= 60) return { riskLevel: 'Medium', riskColor: 'medium' }; if (score <= 80) return { riskLevel: 'Low', riskColor: 'low' }; return { riskLevel: 'Good', riskColor: 'negligible' }; }

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
    let displayString = '(Error displaying payload)';
    const maxDisplayLength = 500;
    const escapeHTML = window.escapeHTML || function(str) {
        return String(str ?? '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };
    try {
        const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem;
        if (typeof actualPayloadData === 'object' && actualPayloadData !== null) {
            const payloadJson = JSON.stringify(actualPayloadData, null, 2);
            displayString = payloadJson.substring(0, maxDisplayLength) + (payloadJson.length > maxDisplayLength ? '...' : '');
        } else {
            const payloadAsString = String(actualPayloadData ?? '');
            displayString = payloadAsString.substring(0, maxDisplayLength) + (payloadAsString.length > maxDisplayLength ? '...' : '');
        }
    } catch (e) {
        return `<div class="payload-item error" style="padding:10px; border:1px solid var(--accent-secondary); background:rgba(240,113,120,0.1);">Error rendering payload ${index + 1}.</div>`;
    }
    const payloadType = payloadItem?.type || 'unknown';
    const payloadSource = payloadItem?.baseSource || 'unknown';
    const payloadDesc = payloadItem?.description || 'N/A';
    const typeClass = `payload-type-${escapeHTML(payloadType).split('-')[0]}`;

    return `
        <div class="payload-item" data-payload-index="${index}" style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 4px; margin-bottom: 10px; padding: 10px 12px; font-size: 13px;">
            <div class="payload-meta-info ${typeClass}" style="font-size: 11px; color: var(--text-secondary); margin-bottom: 8px; padding-bottom: 5px; border-bottom: 1px dashed var(--border-color); text-transform: capitalize;">
                Type: ${escapeHTML(payloadType)} | Source: ${escapeHTML(payloadSource)}
            </div>
            <pre class="report-code-block" style="margin: 8px 0; padding: 10px; background: var(--code-bg); border: 1px solid var(--border-color); border-radius: 3px; max-height: 150px; overflow: auto;"><code>${escapeHTML(displayString)}</code></pre>
            <div class="payload-description" style="font-size: 11px; color: var(--text-muted); margin-top: 8px; font-style: italic;">
                Desc: ${escapeHTML(payloadDesc)}
            </div>
        </div>`;
}


function updateExistingReportWithLLM(llmAnalysisData) {
    console.log('🤖 [LLM Update] Updating existing report sections with LLM analysis');
    
    const escapeHTML = window.escapeHTML || function(str) { 
        return String(str ?? '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); 
    };

    const handlerSection = document.querySelector('.report-handler');
    console.log('🤖 [Debug] Handler section found:', !!handlerSection);
    console.log('🤖 [Debug] LLM data:', {
        handler_score: llmAnalysisData.handler_score,
        handler_assessment: llmAnalysisData.handler_assessment ? 'present' : 'missing',
        newPayloadsCount: llmAnalysisData.newPayloadsCount
    });
    
    if (handlerSection && (llmAnalysisData.handler_score !== undefined || llmAnalysisData.handler_assessment)) {
        const existingValidation = handlerSection.querySelector('.llm-handler-validation');
        if (existingValidation) {
            existingValidation.remove();
        }

        const score = llmAnalysisData.handler_score || 0;
        const scoreColor = score >= 80 ? '#4CAF50' : score >= 60 ? '#FF9800' : score >= 40 ? '#FF5722' : '#f44336';
        const scoreDescription = score >= 80 ? 'Excellent handler detection' : 
                              score >= 60 ? 'Good handler detection' : 
                              score >= 40 ? 'Partial handler detection' : 'Poor/incomplete handler';

        const validationHTML = `
            <div class="llm-handler-validation" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-top: 12px;">
                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 14px; margin-right: 6px;">🤖</span>
                    <strong style="color: #2d3748; font-size: 13px;">AI Handler Validation</strong>
                </div>
                ${llmAnalysisData.handler_assessment ? `<div style="font-size: 12px; line-height: 1.4; color: #4a5568; margin-bottom: 8px;">${escapeHTML(llmAnalysisData.handler_assessment)}</div>` : ''}
                ${llmAnalysisData.handler_score !== undefined ? `
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

        const handlerDetailsContent = handlerSection.querySelector('.report-details > .report-code-block');
        if (handlerDetailsContent) {
            handlerDetailsContent.insertAdjacentHTML('afterend', validationHTML);
        }
    }

    const findingsSection = document.querySelector('.report-findings');
    if (findingsSection && llmAnalysisData.risks && Array.isArray(llmAnalysisData.risks) && llmAnalysisData.risks.length > 0) {
        const existingLLMRisks = findingsSection.querySelector('.llm-security-risks');
        if (existingLLMRisks) {
            existingLLMRisks.remove();
        }

        const risksHTML = `
            <div class="subsection llm-security-risks">
                <h5 class="report-subsection-title">🤖 AI-Identified Security Risks (${llmAnalysisData.risks.length})</h5>
                <div class="llm-risks-container" style="background: #fef5e7; border: 1px solid #f6ad55; border-radius: 6px; padding: 12px; margin-bottom: 15px;">
                    <ul style="margin: 0; padding-left: 20px;">
                        ${llmAnalysisData.risks.map(risk => `<li style="font-size: 13px; line-height: 1.4; color: #744210; margin-bottom: 4px;">${escapeHTML(risk)}</li>`).join('')}
                    </ul>
                    ${llmAnalysisData.notes ? `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #f6ad55; font-size: 11px; color: #744210; font-style: italic;">Note: ${escapeHTML(llmAnalysisData.notes)}</div>` : ''}
                </div>
            </div>`;

        const findingsTitle = findingsSection.querySelector('.report-section-title');
        if (findingsTitle && findingsTitle.nextSibling) {
            findingsTitle.insertAdjacentHTML('afterend', risksHTML);
        }
    }

    if (llmAnalysisData.newPayloadsCount) {
        const payloadSection = document.querySelector('.report-payloads');
        if (payloadSection) {
            const payloadTitle = payloadSection.querySelector('.report-section-title');
            if (payloadTitle) {
                const currentText = payloadTitle.textContent;
                if (!currentText.includes('🤖')) {
                    const match = currentText.match(/Generated Payloads \((\d+)/);
                    if (match) {
                        const totalCount = parseInt(match[1]);
                        payloadTitle.innerHTML = `Generated Payloads (${totalCount} total, <span style="color: #4CAF50;">+${llmAnalysisData.newPayloadsCount} 🤖 AI-generated</span> - <span id="payload-mode-display-${payloadSection.id?.split('-')?.pop() || 'default'}">enhanced</span>)`;
                    }
                }
            }
            
            const existingLLMSummary = payloadSection.querySelector('.llm-payload-summary');
            if (existingLLMSummary) {
                existingLLMSummary.remove();
            }
            
            const llmSummaryHTML = `
                <div class="llm-payload-summary" style="background: #e8f5e8; border: 1px solid #4CAF50; border-radius: 4px; padding: 8px; margin-bottom: 12px; font-size: 12px;">
                    <div style="display: flex; align-items: center; margin-bottom: 4px;">
                        <span style="font-size: 14px; margin-right: 6px;">🤖</span>
                        <strong style="color: #2e7d2e;">AI Generated ${llmAnalysisData.newPayloadsCount} New Payloads</strong>
                    </div>
                    <div style="color: #2e7d2e;">
                        Types: Mixed attack vectors including XSS, prototype pollution, type confusion, and injection payloads
                        ${llmAnalysisData.notes ? `<br>Strategy: ${escapeHTML(llmAnalysisData.notes)}` : ''}
                    </div>
                </div>`;
            
            const payloadTitle2 = payloadSection.querySelector('.report-section-title');
            if (payloadTitle2) {
                payloadTitle2.insertAdjacentHTML('afterend', llmSummaryHTML);
            }
        }
    }

    const llmControls = document.querySelector('.llm-controls');
    if (llmControls) {
        const statusSpan = llmControls.querySelector('#llm-status-inline');
        if (statusSpan) {
            statusSpan.innerHTML = `<span style="color: #4CAF50;">✅ Analysis complete! Generated ${llmAnalysisData.newPayloadsCount || 0} new payloads</span>`;
            setTimeout(() => {
                if (statusSpan) statusSpan.innerHTML = '';
            }, 5000); // Clear after 5 seconds
        }
    }

    console.log('🤖 [LLM Update] Successfully updated existing report sections with handler score and payload info');
}

function displayReport(reportData, panel) {
    try {
        panel.innerHTML = '';
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
            <div class="summary-grid">
                <div class="security-score-container">
                     <h5 class="risk-score-title">Risk Score:</h5>
                     <div class="security-score ${riskColor}" title="Score: ${score} (${riskLevel})">
                         <div class="security-score-value">${score}</div>
                         <div class="security-score-label">${riskLevel}</div>
                     </div>
                 </div>
                 <div class="summary-metrics">
                     <div class="metric"><span class="metric-label">Msgs</span><span class="metric-value">${uiMessageCount}</span></div>
                     <div class="metric"><span class="metric-label">Structs</span><span class="metric-value">${structures?.length ?? 0}</span></div>
                     <div class="metric"><span class="metric-label">Sinks</span><span class="metric-value">${uniqueVulns?.length ?? 0}</span></div>
                     <div class="metric"><span class="metric-label">Issues</span><span class="metric-value">${uniqueIssues?.length ?? 0}</span></div>
                     <div class="metric" id="report-payload-count-metric-${safeKeyIdPart}">
                         <span class="metric-label">Payloads (<span id="payload-mode-display-${safeKeyIdPart}">${currentPayloadMode.replace(/_/g, ' ')}</span>)</span>
                         <span class="metric-value" id="payload-count-display-${safeKeyIdPart}">${currentPayloadCount}</span>
                     </div>
                 </div>
            </div>`;
        content.appendChild(summarySection);

        const bestHandlerCode = bestHandler?.handler || bestHandler?.code;
        if (bestHandlerCode) {
            const handlerSection = document.createElement('div');
            handlerSection.className = 'report-section report-handler';
            
            const llmAnalysis = details.llmAnalysis || {};
            const handlerScore = llmAnalysis.handler_score;
            const handlerAssessment = llmAnalysis.handler_assessment;
            
            let handlerHTML = `<details class="report-details">
                     <summary class="report-summary-toggle"><strong>Analyzed Handler</strong><span class="handler-meta">(Cat: ${escapeHTML(bestHandler.category || 'N/A')} | Score: ${bestHandler.score?.toFixed(1) || 'N/A'})</span><span class="toggle-icon">▶</span></summary>
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

        const llmSection = document.createElement('div');
        llmSection.className = 'report-section report-llm';
        
        let llmHTML = `
            <details class="report-details">
                <summary class="report-summary-toggle"><strong>🤖 AI Security Analysis</strong><span class="handler-meta">(Enhanced Analysis)</span><span class="toggle-icon">▶</span></summary>
                <div class="llm-controls" data-endpoint-key="${escapeHTML(originalEndpointKey)}" style="padding: 15px; background: var(--bg-secondary); border-radius: 6px; margin-top: 8px;">
                <div style="display:flex; gap:10px; flex-wrap: wrap; align-items: center;">
                    <label>Provider:</label>
                    <select id="llm-provider-inline" class="control-select">
                        <option value="none">None</option>
                        <option value="openai">OpenAI</option>
                        <option value="anthropic">Anthropic</option>
                        <option value="groq">Groq</option>
                        <option value="mistral">Mistral</option>
                    </select>
                    <label>Model:</label>
                    <select id="llm-model-inline" class="control-select" style="min-width:220px;"></select>
                    <label>API Key:</label>
                    <input type="password" id="llm-key-inline" placeholder="sk-..." style="min-width:220px;"/>
                    <button id="llm-save-inline" class="control-button secondary-button">Save</button>
                    <button id="llm-run-inline" class="control-button primary-button">Analyze with LLM</button>
                    <span id="llm-status-inline" style="margin-left:8px; font-style: italic; color: var(--text-secondary);"></span>
                </div>
                    <p style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">AI analysis integrates directly into Handler and Findings sections above. Keys are stored locally.</p>
                                </div>
            </details>`;
        
        llmSection.innerHTML = llmHTML;
        content.appendChild(llmSection);

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
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Origin Validation (${originChecks.length})</h5><table class="report-table"><thead><tr><th>Check Type</th><th>Strength</th><th>Compared Value</th><th>Snippet</th></tr></thead><tbody>`;
            originChecks.forEach(check => {
                const type = check?.type || '?'; const strength = check?.strength || 'N/A'; const value = check?.comparedValue !== null && check?.comparedValue !== undefined ? String(check.comparedValue).substring(0, 100) : 'N/A'; const snippetHTML = check?.rawSnippet ? `<code class="context-snippet">${escapeHTML(check.rawSnippet)}</code>` : 'N/A';
                let strengthClass = strength.toLowerCase(); if(strength === 'Missing') strengthClass = 'critical'; else if(strength === 'Weak') strengthClass = 'high'; else if(strength === 'Medium') strengthClass = 'medium'; else if(strength === 'Strong') strengthClass = 'negligible'; else strengthClass='low';
                findingsHTML += `<tr class="severity-row-${strengthClass}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${strengthClass}">${escapeHTML(strength)}</span></td><td><code>${escapeHTML(value)}</code></td><td>${snippetHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;
        }

        if (uniqueVulns.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Potential Sinks Reached (${uniqueVulns.length})</h5><table class="report-table"><thead><tr><th>Sink</th><th>Severity</th><th>Data Path</th><th>Conditions</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueVulns.forEach(vuln => {
                const type = vuln?.name || vuln?.type || '?'; const severity = vuln?.severity || 'N/A'; const contextHTML = vuln?.context || ''; const sourcePath = vuln?.sourcePath || '(unknown)'; const conditions = vuln?.conditions || [];
                let conditionsHtml = 'None'; if (conditions.length > 0) { conditionsHtml = conditions.map(c => { let valStr = escapeHTML(String(c.value)); if (typeof c.value === 'string') valStr = `'${valStr}'`; return `<code>${escapeHTML(c.path)} ${escapeHTML(c.op)} ${valStr}</code>`; }).join('<br>'); }
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${escapeHTML(severity)}</span></td><td><code>${escapeHTML(sourcePath)}</code></td><td>${conditionsHtml}</td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
            });
            findingsHTML += `</tbody></table></div>`;

            const smartPayloadDescription = staticAnalysisUsed 
                ? "Generate targeted payloads based on identified sinks and data flows. This will merge with any existing default payloads."
                : "Generate enhanced payloads using advanced fuzzing techniques. Static analysis wasn't available, but smart fuzzing can still be performed.";
            
            const buttonText = staticAnalysisUsed 
                ? "Generate & Merge Smart Payloads" 
                : "Generate & Merge Enhanced Payloads";
                
                findingsHTML += `
                     <div class="subsection smart-payload-section">
                         <h5 class="report-subsection-title">Smart Payload Generation</h5>
                     <div id="smart-payload-controls-${safeKeyIdPart}" class="smart-payload-controls" data-analysis-key="${escapeHTML(analysisStorageKey)}" data-endpoint-key="${escapeHTML(originalEndpointKey)}" data-static-analysis="${staticAnalysisUsed}">
                         <p>${smartPayloadDescription}</p>
                             <button class="control-button primary-button generate-smart-payloads-btn">
                             ${buttonText}
                             </button>
                             <span class="smart-payload-status" style="margin-left: 10px; font-style: italic; color: var(--text-secondary);"></span>
                         </div>
                     </div>`;
        }

        if (uniqueIssues.length > 0) {
            findingsExist = true;
            findingsHTML += `<div class="subsection"><h5 class="report-subsection-title">Other Security Issues (${uniqueIssues.length})</h5><table class="report-table"><thead><tr><th>Issue</th><th>Severity</th><th>Context Snippet</th></tr></thead><tbody>`;
            uniqueIssues.forEach(issue => {
                const type = issue?.type || '?'; const severity = issue?.severity || 'N/A'; const contextHTML = issue?.context || '';
                findingsHTML += `<tr class="severity-row-${severity.toLowerCase()}"><td>${escapeHTML(type)}</td><td><span class="severity-badge severity-${severity.toLowerCase()}">${escapeHTML(severity)}</span></td><td class="context-snippet-cell">${contextHTML}</td></tr>`;
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

        const bottomButtonContainer = document.createElement('div'); bottomButtonContainer.style.cssText = 'margin-top:20px; display: flex; justify-content: center; gap: 15px;'; const exportJsonBtn = document.createElement('button'); exportJsonBtn.textContent = 'Export JSON'; exportJsonBtn.className = 'control-button secondary-button'; exportJsonBtn.addEventListener('click', (e) => { e.stopPropagation(); try { const jsonData = JSON.stringify(reportData, null, 2); const blob = new Blob([jsonData], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); const safeFilename = (analysisStorageKey || 'frogpost_report').replace(/[^a-z0-9_\-.]/gi, '_'); a.href = url; a.download = `${safeFilename}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); } catch (exportError) { alert("Failed to export report as JSON."); } }); const closeBtnInside = document.createElement('button'); closeBtnInside.textContent = 'Close Report'; closeBtnInside.className = 'control-button secondary-button'; closeBtnInside.onclick = () => { document.querySelector('.trace-panel-backdrop')?.remove(); panel.remove(); }; bottomButtonContainer.appendChild(exportJsonBtn); bottomButtonContainer.appendChild(closeBtnInside); content.appendChild(bottomButtonContainer);
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
            payloadListElement.innerHTML = payloads.map((p, i) => renderPayloadItem(p, i)).join('');
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

async function handleGenerateSmartPayloadsClick(event) {
    const button = event.target;
    const controlsDiv = button.closest('.smart-payload-controls');
    if (!controlsDiv) {
        log.error("Cannot find smart payload controls container.");
        return;
    }

    const statusSpan = controlsDiv.querySelector('.smart-payload-status');
    const analysisKey = controlsDiv.dataset.analysisKey;
    const originalEndpointKey = controlsDiv.dataset.endpointKey;
    const reportPanel = button.closest('.trace-results-panel');
    const safeKeyIdPart = analysisKey?.replace(/[^a-zA-Z0-9_-]/g, '_');

    if (!analysisKey || !originalEndpointKey || !reportPanel) {
        log.error("Missing analysis key, original endpoint key, or report panel for generating smart payloads.");
        if (statusSpan) statusSpan.textContent = 'Error: Missing data context.';
        return;
    }

    button.disabled = true;
    button.textContent = 'Generating...';
    if (statusSpan) statusSpan.textContent = 'Fetching data...';

    try {
        if (!window.handlerTracer) { window.handlerTracer = new HandlerTracer(); }

        const reportData = await window.traceReportStorage.getTraceReport(analysisKey);
        const existingPayloads = await window.traceReportStorage.getReportPayloads(analysisKey) || [];

        const relevantMessages = await window.retrieveMessagesWithFallbacks(analysisKey, originalEndpointKey);

        if (!reportData) throw new Error("Could not retrieve saved report data to generate smart payloads.");

        const handlerCode = reportData.analyzedHandler?.handler || reportData.analyzedHandler?.code;
        if (!handlerCode) throw new Error("Handler code missing from report.");

        const staticAnalysisData = reportData.details?.staticAnalysisRawOutput?.analysis;
        if (!staticAnalysisData || !reportData.details?.staticAnalysisRawOutput?.success) {
            log.warn("Static analysis data missing or indicates failure. Smart generation might be less effective or not possible.");
            if (statusSpan) statusSpan.textContent = 'Static analysis data issue.';
            button.disabled = false;
            button.textContent = 'Generate Smart Payloads';
            return;
        }

        const uniqueStructures = reportData.details?.uniqueStructures || window.handlerTracer.analyzeJsonStructures(relevantMessages);
        const vulnerabilities = { sinks: reportData.details?.sinks || [], securityIssues: reportData.details?.securityIssues || [] };

        if (statusSpan) statusSpan.textContent = 'Generating smart payloads...';
        const generationContext = { uniqueStructures, vulnerabilities, staticAnalysisData, originalMessages: relevantMessages, dynamicAnalysisResults: null };

        const smartPayloads = await window.handlerTracer.generateSmartPayloads(generationContext);
        log.info(`[Smart Payload Gen] Generated ${smartPayloads.length} smart payloads for ${analysisKey}`);

        if (statusSpan) statusSpan.textContent = 'Merging and saving payloads...';

        let combinedPayloads = [...existingPayloads, ...smartPayloads];
        const uniquePayloadsMap = new Map();
        combinedPayloads.forEach(p => {
            const payloadDataStr = (typeof p.payload === 'object' && p.payload !== null) ? JSON.stringify(p.payload) : String(p.payload);
            const key = `${p.type}|${p.targetPath}|${payloadDataStr}|${p.baseSource}`;
            if (!uniquePayloadsMap.has(key)) {
                uniquePayloadsMap.set(key, p);
            }
        });
        combinedPayloads = Array.from(uniquePayloadsMap.values());
        if (combinedPayloads.length > window.handlerTracer.MAX_PAYLOADS_TOTAL) {
            combinedPayloads = combinedPayloads.slice(0, window.handlerTracer.MAX_PAYLOADS_TOTAL);
        }
        log.info(`[Smart Payload Gen] Combined and deduplicated. Total payloads: ${combinedPayloads.length}`);

        const payloadsSaved = await window.traceReportStorage.saveReportPayloads(analysisKey, combinedPayloads);
        if (!payloadsSaved) throw new Error("Failed to save combined payloads.");

        const newPayloadMode = (existingPayloads.length > 0 && smartPayloads.length > 0) ?
            'smart_and_default' :
            (smartPayloads.length > 0 ? 'smart' :
                (existingPayloads.length > 0 ? 'default' : 'none'));

        reportData.details.payloadMode = newPayloadMode;
        reportData.details.payloadsGeneratedCount = combinedPayloads.length;
        if(reportData.summary) reportData.summary.payloadsGenerated = combinedPayloads.length;

        const reportMetadataSaved = await window.traceReportStorage.saveTraceReport(analysisKey, reportData);
        if (!reportMetadataSaved) throw new Error("Failed to save updated report metadata.");

        const traceInfoKey = `trace-info-${originalEndpointKey}`;
        const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve));
        const existingTraceInfo = traceInfoResult[traceInfoKey] || {};
        await chrome.storage.local.set({
            [traceInfoKey]: {
                ...existingTraceInfo,
                payloadMode: newPayloadMode,
                payloadCount: combinedPayloads.length,
                timestamp: Date.now()
            }
        });

        if (statusSpan) statusSpan.textContent = 'Done!';
        button.textContent = 'Smart Payloads Generated & Merged';
        button.disabled = true;

        const countDisplayId = `payload-count-display-${safeKeyIdPart}`;
        const modeDisplayId = `payload-mode-display-${safeKeyIdPart}`;
        const payloadListId = `payloads-list-${safeKeyIdPart}`;
        const payloadSectionId = `report-payload-section-${safeKeyIdPart}`;

        const countDisplay = reportPanel.querySelector(`#${countDisplayId}`);
        const modeDisplay = reportPanel.querySelector(`#${modeDisplayId}`);
        const payloadListElement = reportPanel.querySelector(`#${payloadListId}`);
        const payloadSection = reportPanel.querySelector(`#${payloadSectionId}`);


        if (countDisplay) countDisplay.textContent = combinedPayloads.length;
        if (modeDisplay) modeDisplay.textContent = newPayloadMode.replace(/_/g, ' ');

        reportPanel.querySelectorAll(`#${payloadSectionId} .load-payloads-btn`).forEach(btn => btn.remove());

        if(payloadListElement) {
            if(combinedPayloads.length > 0) {
                payloadListElement.innerHTML = combinedPayloads.slice(0, 10).map((p, i) => renderPayloadItem(p, i)).join('');
                if (combinedPayloads.length > 10 || (combinedPayloads.length > 0 && !payloadListElement.querySelector('.payload-item')) ) {
                    const loadAllBtn = document.createElement('button');
                    loadAllBtn.className = 'control-button secondary-button show-more-btn load-payloads-btn';
                    loadAllBtn.dataset.analysisKey = analysisKey;
                    loadAllBtn.textContent = `Load All ${combinedPayloads.length} Payloads`;
                    if (payloadSection) payloadSection.appendChild(loadAllBtn);
                }
            } else {
                payloadListElement.innerHTML = '<p>No payloads generated or available after merge.</p>';
            }
        }

        showToastNotification('Smart payloads generated and merged successfully!', 'success');

    } catch (error) {
        log.error('Error generating/saving smart payloads:', error);
        if (statusSpan) statusSpan.textContent = `Error: ${error.message.substring(0, 100)}`;
        showToastNotification(`Smart payload generation failed: ${error.message}`, 'error');
        button.disabled = false;
        button.textContent = 'Generate Smart Payloads';
    }
}

function showFullPayloadModal(payloadItem) {
    document.querySelector('.payload-modal')?.remove(); document.querySelector('.payload-modal-backdrop')?.remove(); const modal = document.createElement('div'); modal.className = 'payload-modal'; const modalContent = document.createElement('div'); modalContent.className = 'payload-modal-content'; const closeBtn = document.createElement('span'); closeBtn.className = 'close-modal'; closeBtn.innerHTML = '&times;'; const backdrop = document.createElement('div'); backdrop.className = 'payload-modal-backdrop'; const closeModal = () => { modal.remove(); backdrop.remove(); }; closeBtn.onclick = closeModal; backdrop.onclick = closeModal; const heading = document.createElement('h4'); const targetInfo = document.createElement('p'); targetInfo.style.cssText = 'margin-bottom:15px;font-size:13px;color:#aaa;'; const payloadPre = document.createElement('pre'); payloadPre.className = 'report-code-block'; payloadPre.style.cssText = 'max-height:50vh;overflow-y:auto;'; const payloadCode = document.createElement('code'); const actualPayloadData = (payloadItem && payloadItem.payload !== undefined) ? payloadItem.payload : payloadItem; heading.textContent = `Payload Details (Type: ${escapeHTML(payloadItem?.type || 'unknown')})`; targetInfo.innerHTML = `<strong>Target/Desc:</strong> ${escapeHTML(payloadItem?.targetPath || payloadItem?.targetFlow || payloadItem?.description || 'N/A')}`; let formattedPayload = ''; try { if (typeof actualPayloadData === 'object' && actualPayloadData !== null) formattedPayload = JSON.stringify(actualPayloadData, null, 2); else formattedPayload = String(actualPayloadData); } catch { formattedPayload = String(actualPayloadData); } payloadCode.textContent = formattedPayload; payloadPre.appendChild(payloadCode); const copyBtn = document.createElement('button'); copyBtn.textContent = 'Copy Payload'; copyBtn.className = 'control-button'; copyBtn.style.marginTop = '15px'; copyBtn.onclick = () => { navigator.clipboard.writeText(formattedPayload).then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }).catch(() => { copyBtn.textContent = 'Copy Failed'; setTimeout(() => copyBtn.textContent = 'Copy Payload', 2000); }); }; modalContent.appendChild(closeBtn); modalContent.appendChild(heading); modalContent.appendChild(targetInfo); modalContent.appendChild(payloadPre); modalContent.appendChild(copyBtn); modal.appendChild(modalContent); document.body.appendChild(backdrop); document.body.appendChild(modal);
}

async function handleReportButton(endpoint) {
    const endpointKey = getStorageKeyForUrl(endpoint); if (!endpointKey) return; let reportData = null; let reportPayloads = null; let keyUsed = endpointKey;
    try { const traceInfoKey = `trace-info-${endpointKey}`; const traceInfoResult = await new Promise(resolve => chrome.storage.local.get(traceInfoKey, resolve)); const traceInfo = traceInfoResult[traceInfoKey]; if (traceInfo?.analysisStorageKey) keyUsed = traceInfo.analysisStorageKey; else if (traceInfo?.analyzedUrl) keyUsed = getStorageKeyForUrl(traceInfo.analyzedUrl); [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]); if (!reportData && keyUsed !== endpointKey) { keyUsed = endpointKey; [reportData, reportPayloads] = await Promise.all([ window.traceReportStorage.getTraceReport(keyUsed), window.traceReportStorage.getReportPayloads(keyUsed) ]); } if (!reportData || typeof reportData !== 'object') throw new Error(`No report data found for key ${keyUsed}. Run Trace first.`); if (!reportData.details) reportData.details = {}; reportData.details.payloads = reportPayloads || []; if (!reportData.summary) reportData.summary = {}; reportData.summary.payloadsGenerated = reportPayloads?.length || 0; document.querySelector('.trace-results-panel')?.remove(); document.querySelector('.trace-panel-backdrop')?.remove(); const tracePanel = document.createElement('div'); tracePanel.className = 'trace-results-panel'; const backdrop = document.createElement('div'); backdrop.className = 'trace-panel-backdrop'; backdrop.onclick = () => { tracePanel.remove(); backdrop.remove(); }; const reportContainer = document.getElementById('reportPanelContainer') || document.body; reportContainer.appendChild(backdrop); reportContainer.appendChild(tracePanel); addTraceReportStyles(); displayReport(reportData, tracePanel); }
    catch (error) { log.error('Error handling report button:', error); alert(`Failed to display report: ${error?.message}`); }
}

async function checkAllEndpoints() {
    const endpointButtons = document.querySelectorAll('.iframe-row .iframe-check-button');
    for (const button of endpointButtons) {
        const endpointKey = button.getAttribute('data-endpoint');
        if (endpointKey && !button.classList.contains('green') && !button.classList.contains('success')) {
            try { await handlePlayButton(endpointKey, button);
                await new Promise(resolve => setTimeout(resolve, 500)); } catch {} } } }

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

const traceReportStyles = `.trace-results-panel {} .trace-panel-backdrop {} .trace-panel-header {} .trace-panel-close {} .trace-results-content {} .report-section { margin-bottom: 30px; padding: 20px; background: #1a1d21; border-radius: 8px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3); border: 1px solid #333; } .report-section-title { margin-top: 0; padding-bottom: 10px; border-bottom: 1px solid #444; color: #00e1ff; font-size: 1.3em; font-weight: 600; text-shadow: 0 0 5px rgba(0, 225, 255, 0.5); } .report-subsection-title { margin-top: 0; color: #a8b3cf; font-size: 1.1em; margin-bottom: 10px; } .report-summary .summary-grid { display: grid; grid-template-columns: auto 1fr; gap: 25px; align-items: center; margin-bottom: 20px; } .security-score-container { display: flex; justify-content: center; } .security-score { width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: #fff; font-weight: bold; background: conic-gradient(#e74c3c 0% 20%, #e67e22 20% 40%, #f39c12 40% 60%, #3498db 60% 80%, #2ecc71 80% 100%); position: relative; border: 3px solid #555; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); } .security-score::before { content: ''; position: absolute; inset: 5px; background: #1a1d21; border-radius: 50%; z-index: 1; } .security-score div { position: relative; z-index: 2; } .security-score-value { font-size: 28px; line-height: 1; } .security-score-label { font-size: 12px; margin-top: 3px; text-transform: uppercase; letter-spacing: 0.5px; } .security-score.critical { border-color: #e74c3c; } .security-score.high { border-color: #e67e22; } .security-score.medium { border-color: #f39c12; } .security-score.low { border-color: #3498db; } .security-score.negligible { border-color: #2ecc71; } .summary-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px 20px; } .metric { background-color: #252a30; padding: 10px; border-radius: 4px; text-align: center; border: 1px solid #3a3f44; } .metric-label { display: block; font-size: 11px; color: #a8b3cf; margin-bottom: 4px; text-transform: uppercase; } .metric-value { display: block; font-size: 18px; font-weight: bold; color: #fff; } .recommendations { margin-top: 15px; padding: 15px; background: rgba(0, 225, 255, 0.05); border-radius: 4px; border-left: 3px solid #00e1ff; } .recommendation-text { color: #d0d8e8; font-size: 13px; line-height: 1.6; margin: 0; } .report-code-block { background: #111316; border: 1px solid #333; border-radius: 4px; padding: 12px; overflow-x: auto; margin: 10px 0; max-height: 300px; } .report-code-block pre { margin: 0; } .report-code-block code { font-family: 'Courier New', Courier, monospace; font-size: 13px; color: #c4c4c4; white-space: pre; } .report-handler .handler-meta { font-size: 0.8em; color: #777; margin-left: 10px; } details.report-details { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 10px; } summary.report-summary-toggle { cursor: pointer; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; font-weight: 600; color: #d0d8e8; } summary.report-summary-toggle:focus { outline: none; box-shadow: 0 0 0 2px rgba(0, 225, 255, 0.5); } details[open] > summary.report-summary-toggle { border-bottom: 1px solid #3a3f44; } .toggle-icon { font-size: 1.2em; transition: transform 0.2s; } details[open] .toggle-icon { transform: rotate(90deg); } .report-details > div { padding: 15px; } .report-table { width: 100%; border-collapse: collapse; margin: 15px 0; background-color: #22252a; } .report-table th, .report-table td { padding: 10px 12px; text-align: left; border: 1px solid #3a3f44; font-size: 13px; color: #d0d8e8; } .report-table th { background-color: #2c313a; font-weight: bold; color: #fff; } .report-table td code { font-size: 12px; color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; } .report-table .context-snippet { max-width: 400px; white-space: pre-wrap; word-break: break-all; display: inline-block; vertical-align: middle; } .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; } .severity-critical { background-color: #e74c3c; color: white; } .severity-high { background-color: #e67e22; color: white; } .severity-medium { background-color: #f39c12; color: #333; } .severity-low { background-color: #3498db; color: white; } .severity-row-critical td { background-color: rgba(231, 76, 60, 0.15); } .severity-row-high td { background-color: rgba(230, 126, 34, 0.15); } .severity-row-medium td { background-color: rgba(243, 156, 18, 0.1); } .severity-row-low td { background-color: rgba(52, 152, 219, 0.1); } .no-findings-text { color: #777; font-style: italic; padding: 10px 0; } .dataflow-table td:first-child code { font-weight: bold; color: #ffb86c; } .report-list { max-height: 400px; overflow-y: auto; padding-right: 10px; } .payload-item, .structure-item { background: #22252a; border: 1px solid #3a3f44; border-radius: 4px; margin-bottom: 15px; overflow: hidden; } .payload-header { padding: 8px 12px; background-color: #2c313a; color: #a8b3cf; font-size: 12px; } .payload-header strong { color: #fff; } .payload-meta { color: #8be9fd; margin: 0 5px; } .payload-item .report-code-block { margin: 0; border: none; border-top: 1px solid #3a3f44; border-radius: 0 0 4px 4px; } .structure-content { padding: 15px; } .structure-content p { margin: 0 0 10px 0; color: #d0d8e8; font-size: 13px; } .structure-content strong { color: #00e1ff; } .structure-content code { color: #a8b3cf; background-color: #111316; padding: 2px 4px; border-radius: 3px; } .show-more-btn { display: block; width: 100%; margin-top: 15px; text-align: center; background-color: #343a42; border: 1px solid #4a5058; color: #a8b3cf; } .show-more-btn:hover { background-color: #4a5058; color: #fff; } .control-button {} .secondary-button {} .error-message { color: #e74c3c; font-weight: bold; padding: 15px; background-color: rgba(231, 76, 60, 0.1); border: 1px solid #e74c3c; border-radius: 4px; } span.highlight-finding { background-color: rgba(255, 0, 0, 0.3); color: #ffdddd; font-weight: bold; padding: 1px 2px; border-radius: 2px; border: 1px solid rgba(255, 100, 100, 0.5); }`;

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
    const inline = document.getElementById('server-status-inline');
    const isRunning = serverStatus.running;
    if (inline) {
        inline.innerHTML = `<span style="width:8px;height:8px;border-radius:50%;display:inline-block;background:${isRunning ? '#22c55e' : '#ef4444'}"></span><span>${isRunning ? 'Server: ✅ Running' : 'Server: ❌ Stopped'}</span>`;
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

window.addEventListener('DOMContentLoaded', async () => {
    printBanner();
    displayCurrentVersion();
    
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
    const silentFilterToggle = document.getElementById('silentFilterToggle');
    if (silentFilterToggle) {
        const textSpan = silentFilterToggle.querySelector('.button-text');
        if (textSpan) textSpan.textContent = showOnlySilentIframes ? 'Silent Listeners On' : 'Silent Listeners Off';
        silentFilterToggle.classList.toggle('active', showOnlySilentIframes);
        silentFilterToggle.addEventListener('click', () => { showOnlySilentIframes = !showOnlySilentIframes; silentFilterToggle.classList.toggle('active', showOnlySilentIframes); const textSpan = silentFilterToggle.querySelector('.button-text'); if (textSpan) textSpan.textContent = showOnlySilentIframes ? 'Silent Listeners On' : 'Silent Listeners Off'; log.info(`Silent iframe filter ${showOnlySilentIframes ? 'ON (Showing ONLY Silent)' : 'OFF (Showing All)'}.`); requestUiUpdate(); });
    } else { log.error("Could not find silent filter toggle button (#silentFilterToggle)"); }

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
                if (event.target.matches('.generate-smart-payloads-btn')) {
                    handleGenerateSmartPayloadsClick(event);
                } else if (event.target.matches('.load-payloads-btn')) {
                    handleLoadPayloadsClick(event);
                }
            }
        });
    }

    requestUiUpdate();
});
