/**
 * FrogPost Performance Utilities
 * Shared optimization functions for debouncing, throttling, and caching
 * Created: 2025-10-24
 */

/**
 * Debounce function - delays execution until after wait time has elapsed
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @param {boolean} immediate - Trigger on leading edge instead of trailing
 * @returns {Function} Debounced function
 */
function debounce(func, wait, immediate = false) {
    let timeout;
    return function executedFunction(...args) {
        const context = this;
        const later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        if (callNow) func.apply(context, args);
    };
}

/**
 * Throttle function - ensures function is called at most once per time period
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit) {
    let inThrottle;
    let lastResult;
    return function(...args) {
        const context = this;
        if (!inThrottle) {
            inThrottle = true;
            lastResult = func.apply(context, args);
            setTimeout(() => inThrottle = false, limit);
        }
        return lastResult;
    };
}

/**
 * Throttle with RAF - uses requestAnimationFrame for UI updates
 * @param {Function} func - Function to throttle
 * @returns {Function} RAF-throttled function
 */
function throttleRAF(func) {
    let rafId = null;
    let lastArgs = null;
    
    return function(...args) {
        lastArgs = args;
        
        if (rafId === null) {
            rafId = requestAnimationFrame(() => {
                func.apply(this, lastArgs);
                rafId = null;
                lastArgs = null;
            });
        }
    };
}

/**
 * Simple hash function for cache keys (FNV-1a)
 * @param {string} str - String to hash
 * @returns {string} Hash value
 */
function fastHash(str) {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(36);
}

/**
 * Memoize function results with LRU cache
 * @param {Function} func - Function to memoize
 * @param {number} maxSize - Maximum cache size
 * @returns {Function} Memoized function
 */
function memoize(func, maxSize = 100) {
    const cache = new Map();
    const keyOrder = [];
    
    return function(...args) {
        const key = JSON.stringify(args);
        
        if (cache.has(key)) {
            // Move to end (most recently used)
            const index = keyOrder.indexOf(key);
            if (index > -1) {
                keyOrder.splice(index, 1);
                keyOrder.push(key);
            }
            return cache.get(key);
        }
        
        const result = func.apply(this, args);
        cache.set(key, result);
        keyOrder.push(key);
        
        // Remove oldest if cache is full
        if (keyOrder.length > maxSize) {
            const oldestKey = keyOrder.shift();
            cache.delete(oldestKey);
        }
        
        return result;
    };
}

/**
 * Deep clone using structuredClone with fallback
 * @param {*} obj - Object to clone
 * @returns {*} Cloned object
 */
function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    
    // Use structuredClone if available (3-5x faster)
    if (typeof structuredClone !== 'undefined') {
        try {
            return structuredClone(obj);
        } catch (e) {
            // Fall through to JSON method
        }
    }
    
    // Fallback to JSON (slower but compatible)
    try {
        return JSON.parse(JSON.stringify(obj));
    } catch (e) {
        // Manual deep copy as last resort
        const copy = Array.isArray(obj) ? [] : {};
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                copy[key] = deepClone(obj[key]);
            }
        }
        return copy;
    }
}

/**
 * Performance marker for measuring execution time
 */
class PerformanceMarker {
    constructor(name) {
        this.name = name;
        this.start = performance.now();
    }
    
    end(log = true) {
        const duration = performance.now() - this.start;
        if (log && typeof console !== 'undefined') {
            console.log(`[Performance] ${this.name}: ${duration.toFixed(2)}ms`);
        }
        return duration;
    }
}

/**
 * Batch processor for accumulating operations
 */
class BatchProcessor {
    constructor(processFn, interval = 100, maxBatchSize = 50) {
        this.processFn = processFn;
        this.interval = interval;
        this.maxBatchSize = maxBatchSize;
        this.batch = [];
        this.timer = null;
    }
    
    add(item) {
        this.batch.push(item);
        
        if (this.batch.length >= this.maxBatchSize) {
            this.flush();
        } else if (!this.timer) {
            this.timer = setTimeout(() => this.flush(), this.interval);
        }
    }
    
    flush() {
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }
        
        if (this.batch.length > 0) {
            const items = this.batch.splice(0, this.batch.length);
            this.processFn(items);
        }
    }
}

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.FrogPostPerf = {
        debounce,
        throttle,
        throttleRAF,
        fastHash,
        memoize,
        deepClone,
        PerformanceMarker,
        BatchProcessor
    };
}

// Export for Node.js if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        debounce,
        throttle,
        throttleRAF,
        fastHash,
        memoize,
        deepClone,
        PerformanceMarker,
        BatchProcessor
    };
}

