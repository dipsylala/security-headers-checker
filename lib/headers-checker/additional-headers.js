/**
 * Additional Security Headers Module
 * Handles additional security headers (Cache-Control, Expect-CT, Report-To)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Cache-Control header for security
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkCacheControl(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Cache-Control');
    
    return {
        name: 'Cache-Control',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls caching behavior to prevent sensitive data exposure',
        recommendation: 'Use no-cache, no-store for sensitive pages',
        category: 'additional',
        example: 'no-cache, no-store, must-revalidate',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'additional', name: 'Cache-Control' }, headerValue)
    };
}

/**
 * Check Expect-CT header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkExpectCT(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Expect-CT');
    
    return {
        name: 'Expect-CT',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Enables Certificate Transparency monitoring',
        recommendation: 'Configure Expect-CT for certificate transparency',
        category: 'additional',
        example: 'max-age=86400, enforce',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'additional', name: 'Expect-CT' }, headerValue)
    };
}

/**
 * Check Report-To header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkReportTo(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Report-To');
    
    return {
        name: 'Report-To',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Configures endpoints for security violation reporting',
        recommendation: 'Configure reporting endpoints for security monitoring',
        category: 'additional',
        example: '{"group":"csp-violations","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'additional', name: 'Report-To' }, headerValue)
    };
}

/**
 * Perform all additional header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkCacheControl(responseHeaders),
        checkExpectCT(responseHeaders),
        checkReportTo(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    checkCacheControl,
    checkExpectCT,
    checkReportTo,
    name: 'Additional Headers',
    description: 'Checks for additional security headers (Cache-Control, Expect-CT, Report-To)'
};
