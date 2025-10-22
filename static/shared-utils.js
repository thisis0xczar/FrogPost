/**
 * FrogPost Extension - Shared Utilities
 * Created: 2025-10-22
 * Purpose: Centralized utility functions to reduce code duplication
 */

/**
 * Sets a nested value in an object using a property path
 * @param {Object} obj - The object to modify
 * @param {string} path - The property path (e.g., "data.user.name" or "items[0].value")
 * @param {*} value - The value to set
 */
function setNestedValue(obj, path, value) {
    if (!obj || typeof obj !== 'object' || !path) {
        return;
    }

    // Parse path into parts (handles both dot notation and bracket notation)
    const parts = path.match(/([^[.\]]+)|\[['"`]?([^\]'"`]+)['"`]?\]/g) || [];
    let current = obj;

    // Navigate to the parent of the target property
    for (let i = 0; i < parts.length - 1; i++) {
        let part = parts[i];
        
        // Handle bracket notation
        if (part.startsWith('[')) {
            part = part.substring(1, part.length - 1).replace(/['"`]/g, '');
        }
        
        // Check if index or property
        const isIndex = /^\d+$/.test(part);
        const parsedPart = isIndex ? parseInt(part, 10) : part;

        // Determine if next part is an index
        const nextPartStr = parts[i + 1];
        let nextPartNormalized = nextPartStr;
        if (nextPartNormalized && nextPartNormalized.startsWith('[')) {
            nextPartNormalized = nextPartNormalized.substring(1, nextPartNormalized.length - 1).replace(/['"`]/g, '');
        }
        const isNextPartIndex = /^\d+$/.test(nextPartNormalized);

        // Create intermediate structure if needed
        if (current[parsedPart] === undefined || current[parsedPart] === null || typeof current[parsedPart] !== 'object') {
            current[parsedPart] = isNextPartIndex ? [] : {};
        }

        current = current[parsedPart];
        
        // Safety check
        if (typeof current !== 'object' || current === null) {
            return;
        }
    }

    // Set the final value
    let lastPart = parts[parts.length - 1];
    if (lastPart.startsWith('[')) {
        lastPart = lastPart.substring(1, lastPart.length - 1).replace(/['"`]/g, '');
    }
    
    const isIndex = /^\d+$/.test(lastPart);
    const parsedLastPart = isIndex ? parseInt(lastPart, 10) : lastPart;

    if (typeof current === 'object' && current !== null) {
        if (Array.isArray(current) && isIndex) {
            current[parsedLastPart] = value;
        } else if (!Array.isArray(current)) {
            current[parsedLastPart] = value;
        }
    }
}

/**
 * Checks if a message/data is an internal FrogPost extension message
 * @param {*} data - The message data to check
 * @returns {boolean} - True if it's an extension message, false otherwise
 */
function isExtensionMessage(data) {
    // Check for string breakpoint test
    if (typeof data === 'string' && data === 'FrogPost::BreakpointTest') {
        return true;
    }

    // Check for object breakpoint test
    if (data && typeof data === 'object' && data.FrogPost === 'BreakpointTest') {
        return true;
    }

    // Check for type-based markers
    if (data && typeof data === 'object' && typeof data.type === 'string') {
        const type = data.type;
        if (type.startsWith('frogPost') ||
            type.startsWith('FROGPOST_') ||
            type === 'realTimeDetectorReady' ||
            type === 'realTimeHandlerDetected' ||
            type === 'realTimeMessageSent' ||
            type === '__FROGPOST_SET_INDEX__') {
            return true;
        }
    }

    // Check for internal coordination messages
    if (data && typeof data === 'object' && data.__frogPostInternal) {
        return true;
    }

    return false;
}

/**
 * Checks if a message event is from FrogPost agent (for content script filtering)
 * @param {MessageEvent} event - The message event
 * @returns {boolean} - True if it's from FrogPost agent
 */
function isFrogPostAgentMessage(event) {
    return event.source === window && 
           event.data?.type === 'frogPostAgent->ForwardToBackground';
}

// Export for use in different contexts
if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = {
        setNestedValue,
        isExtensionMessage,
        isFrogPostAgentMessage
    };
} else if (typeof window !== 'undefined') {
    // Browser environment
    window.FrogPostUtils = {
        setNestedValue,
        isExtensionMessage,
        isFrogPostAgentMessage
    };
}

