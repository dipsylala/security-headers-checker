/**
 * Modern Security Headers Module
 * Handles modern security headers (Cross-Origin-*, NEL, etc.)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Cross-Origin-Embedder-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkCrossOriginEmbedderPolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Cross-Origin-Embedder-Policy');
    
    return {
        name: 'Cross-Origin-Embedder-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls loading of cross-origin resources in the document',
        recommendation: 'Set to require-corp for enhanced security',
        category: 'modern',
        example: 'require-corp',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'modern', name: 'Cross-Origin-Embedder-Policy' }, headerValue)
    };
}

/**
 * Check Cross-Origin-Opener-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkCrossOriginOpenerPolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Cross-Origin-Opener-Policy');
    
    return {
        name: 'Cross-Origin-Opener-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls cross-origin window interactions',
        recommendation: 'Set to same-origin for enhanced security',
        category: 'modern',
        example: 'same-origin',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'modern', name: 'Cross-Origin-Opener-Policy' }, headerValue)
    };
}

/**
 * Check Cross-Origin-Resource-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkCrossOriginResourcePolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Cross-Origin-Resource-Policy');
    
    return {
        name: 'Cross-Origin-Resource-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls which origins can load this resource',
        recommendation: 'Set to same-origin or same-site',
        category: 'modern',
        example: 'same-origin',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'modern', name: 'Cross-Origin-Resource-Policy' }, headerValue)
    };
}

/**
 * Check Network Error Logging header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkNEL(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'NEL');
    
    return {
        name: 'NEL',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Enables network error logging for monitoring',
        recommendation: 'Configure NEL for network error monitoring',
        category: 'modern',
        example: '{"report_to":"errors","max_age":31536000}',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'modern', name: 'NEL' }, headerValue)
    };
}

/**
 * Perform all modern header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkCrossOriginEmbedderPolicy(responseHeaders),
        checkCrossOriginOpenerPolicy(responseHeaders),
        checkCrossOriginResourcePolicy(responseHeaders),
        checkNEL(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    name: 'Modern Headers',
    description: 'Checks for modern security headers (Cross-Origin-*, NEL)',
    category: 'modern'
};
