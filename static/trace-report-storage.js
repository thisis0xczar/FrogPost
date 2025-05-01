/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-05-01
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

        const payloadsToSave = traceReport.details?.payloads || [];
        let mainReportData;
        try {
            mainReportData = structuredClone(traceReport);
            if (mainReportData.details) {
                delete mainReportData.details.payloads;
            }
        } catch(e) {
            console.warn("structuredClone failed during save, using JSON fallback.");
            mainReportData = JSON.parse(JSON.stringify(traceReport));
            if (mainReportData.details) delete mainReportData.details.payloads;
        }

        const reportSaved = await new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['reports'], 'readwrite');
                const store = transaction.objectStore('reports');
                const reportToStore = { endpoint: endpoint, timestamp: Date.now(), report: mainReportData };
                const request = store.put(reportToStore);
                request.onsuccess = () => resolve(true);
                request.onerror = (event) => { console.error('Error saving main trace report:', event.target.error); reject(false); };
            } catch (err) { console.error("Error creating save transaction for report:", err); reject(false); }
        });

        const payloadsSaved = await this.saveReportPayloads(endpoint, payloadsToSave);
        log.debug(`Trace report saved for ${endpoint}`);
        return reportSaved && payloadsSaved;
    }

    async saveReportPayloads(endpoint, payloads) {
        if (!this.db) await this.openDatabase();
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['payloads'], 'readwrite');
                const store = transaction.objectStore('payloads');
                const payloadData = { endpoint: endpoint, payloads: payloads };
                const request = store.put(payloadData);
                request.onsuccess = () => resolve(true);
                request.onerror = (event) => { console.error('Error saving payloads:', event.target.error); reject(false); };
            } catch (err) { console.error("Error creating save transaction for payloads:", err); reject(false); }
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

}
window.traceReportStorage = new TraceReportStorage();
