/**
 * Header Scoring Utilities
 * Shared scoring functions for header analysis modules
 */

/**
 * Calculate score for a header based on category and presence
 * @param {Object} headerDef - Header definition with category and name
 * @param {string|null} headerValue - Header value from response
 * @returns {number} Header score
 */
function calculateHeaderScore(headerDef, headerValue) {
    const present = !!headerValue;
    
    // Base scores by category
    const categoryScores = {
        'critical': 15,
        'important': 12,
        'modern': 8,
        'legacy': 5,
        'additional': 6,
        'deprecated': 3,
        'information': -5 // Negative score for information disclosure
    };
    
    const baseScore = categoryScores[headerDef.category] || 5;
    
    // For information headers, presence is bad
    if (headerDef.category === 'information') {
        return present ? baseScore : 0; // Negative score for presence, 0 for absence
    }
    
    // For all other headers, presence is good
    return present ? baseScore : 0;
}

/**
 * Find header value with case-insensitive matching
 * @param {Object} responseHeaders - HTTP response headers
 * @param {string} headerName - Header name to find
 * @returns {string|null} Header value or null if not found
 */
function findHeaderValue(responseHeaders, headerName) {
    // Direct match (exact case)
    if (responseHeaders[headerName]) {
        return responseHeaders[headerName];
    }

    // Case-insensitive match
    const lowerHeaderName = headerName.toLowerCase();
    if (responseHeaders[lowerHeaderName]) {
        return responseHeaders[lowerHeaderName];
    }

    // Search through all headers for case-insensitive match
    for (const [key, value] of Object.entries(responseHeaders)) {
        if (key.toLowerCase() === lowerHeaderName) {
            return value;
        }
    }

    return null;
}

module.exports = {
    calculateHeaderScore,
    findHeaderValue
};
