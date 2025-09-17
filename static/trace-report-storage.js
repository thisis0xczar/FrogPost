/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor 
 * Refined on: 2025-09-16
 */
class TraceReportStorage {
    constructor() {
        this.dbName = 'FrogPostTraceReports';
        this.dbVersion = 2;
        this.db = null;
    }

    async openDatabase() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject('IndexedDB not supported'); return;
            }
            const request = indexedDB.open(this.dbName, this.dbVersion);
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains('reports')) {
                    const reportStore = db.createObjectStore('reports', { keyPath: 'endpoint' });
                    reportStore.createIndex('timestamp', 'timestamp', { unique: false });
                }
                if (!db.objectStoreNames.contains('payloads')) {
                    const payloadStore = db.createObjectStore('payloads', { keyPath: 'endpoint' });
                }
            };
            request.onsuccess = (event) => { this.db = event.target.result; resolve(this.db); };
            request.onerror = (event) => { console.error('IndexedDB open error:', event.target.error); reject(`IndexedDB error: ${event.target.error}`); };
        });
    }

    async saveTraceReport(endpoint, traceReport) {
        if (!this.db) await this.openDatabase();

        let mainReportData;
        try {
            traceReport.endpoint = endpoint;
            mainReportData = structuredClone(traceReport);
            if (mainReportData.details) {
                delete mainReportData.details.payloads;
            }
        } catch(e) {
            console.warn("structuredClone failed during save trace report metadata, using JSON fallback.", e);
            mainReportData = JSON.parse(JSON.stringify(traceReport));
            if (mainReportData.details) delete mainReportData.details.payloads;
        }

        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readwrite');
                const store = transaction.objectStore('reports');
                const reportToStore = { endpoint: endpoint, timestamp: Date.now(), report: mainReportData };
                const request = store.put(reportToStore);
                request.onsuccess = () => {
                    log.debug(`Main trace report metadata saved for ${endpoint}`);
                    resolve(true);
                };
                request.onerror = (event) => {
                    console.error('Error saving main trace report metadata:', event.target.error);
                    reject(false);
                };
            } catch (err) {
                console.error("Error creating save transaction for report metadata:", err);
                reject(false);
            }
        });
    }

    async saveReportPayloads(endpoint, payloads) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['payloads'], 'readwrite');
                const store = transaction.objectStore('payloads');
                const payloadData = { endpoint: endpoint, payloads: payloads || [] };
                const request = store.put(payloadData);
                request.onsuccess = () => {
                    log.debug(`${payloads?.length || 0} payloads saved for ${endpoint}`);
                    resolve(true);
                };
                request.onerror = (event) => {
                    console.error('Error saving report payloads:', event.target.error);
                    reject(false);
                };
            } catch (err) {
                console.error("Error creating save transaction for payloads:", err);
                reject(false);
            }
        });
    }

    async getTraceReport(endpoint) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readonly');
                const store = transaction.objectStore('reports');
                const request = store.get(endpoint);
                request.onsuccess = (event) => { resolve(event.target.result ? event.target.result.report : null); };
                request.onerror = (event) => { console.error('Error retrieving trace report:', event.target.error); reject(null); };
            } catch (err) { console.error("Error creating get transaction for report:", err); reject(null); }
        });
    }

    async getReportPayloads(endpoint) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['payloads'], 'readonly');
                const store = transaction.objectStore('payloads');
                const request = store.get(endpoint);
                request.onsuccess = (event) => { resolve(event.target.result ? event.target.result.payloads : []); };
                request.onerror = (event) => { console.error('Error retrieving payloads:', event.target.error); reject([]); };
            } catch (err) { console.error("Error creating get transaction for payloads:", err); reject([]); }
        });
    }

    async listAllReports() {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readonly');
                const store = transaction.objectStore('reports');
                const request = store.getAll();
                request.onsuccess = (event) => { resolve(event.target.result || []); };
                request.onerror = (event) => { console.error('Error listing reports:', event.target.error); reject([]); };
            } catch (err) { console.error("Error creating list transaction for reports:", err); reject([]); }
        });
    }

    async saveLLMPayloadCount(reportKey, count) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readwrite');
                const store = transaction.objectStore('reports');
                const request = store.get(reportKey);
                request.onsuccess = (event) => {
                    const report = event.target.result;
                    if (report) {
                        report.llmPayloadCount = count;
                        const updateRequest = store.put(report);
                        updateRequest.onsuccess = () => resolve();
                        updateRequest.onerror = (e) => { console.error('Error updating LLM payload count:', e.target.error); reject(e.target.error); };
                    } else {
                        reject(new Error('Report not found'));
                    }
                };
                request.onerror = (event) => { console.error('Error getting report for LLM payload count:', event.target.error); reject(event.target.error); };
            } catch (err) { console.error("Error saving LLM payload count:", err); reject(err); }
        });
    }

    async getLLMPayloadCount(reportKey) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readonly');
                const store = transaction.objectStore('reports');
                const request = store.get(reportKey);
                request.onsuccess = (event) => { 
                    const report = event.target.result;
                    resolve(report ? (report.llmPayloadCount || 0) : 0);
                };
                request.onerror = (event) => { console.error('Error getting LLM payload count:', event.target.error); resolve(0); };
            } catch (err) { console.error("Error getting LLM payload count:", err); resolve(0); }
        });
    }

    async clearAllData() {
        if (!this.db) await this.openDatabase();

        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports', 'payloads'], 'readwrite');
                
                // Clear reports store
                const reportsStore = transaction.objectStore('reports');
                const clearReportsRequest = reportsStore.clear();
                
                // Clear payloads store
                const payloadsStore = transaction.objectStore('payloads');
                const clearPayloadsRequest = payloadsStore.clear();
                
                transaction.oncomplete = () => {
                    log.info("IndexedDB cleared successfully");
                    resolve(true);
                };
                
                transaction.onerror = (event) => {
                    console.error('Error clearing IndexedDB:', event.target.error);
                    reject(false);
                };
                
            } catch (err) {
                console.error("Error creating clear transaction:", err);
                reject(false);
            }
        });
    }
}
window.traceReportStorage = new TraceReportStorage();
