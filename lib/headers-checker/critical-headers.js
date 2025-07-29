/**
 * Critical Security Headers Module
 * Handles the most important security headers (HSTS, CSP)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Strict-Transport-Security header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkStrictTransportSecurity(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Strict-Transport-Security');
    
    return {
        name: 'Strict-Transport-Security',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Enforces secure HTTPS connections and prevents protocol downgrade attacks',
        recommendation: 'Add HSTS header with max-age, includeSubDomains, and preload directives',
        category: 'critical',
        example: 'max-age=31536000; includeSubDomains; preload',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'critical', name: 'Strict-Transport-Security' }, headerValue)
    };
}

/**
 * Check Content-Security-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkContentSecurityPolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Content-Security-Policy');
    
    return {
        name: 'Content-Security-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls resource loading to prevent XSS and data injection attacks',
        recommendation: 'Implement a strict CSP with specific source allowlists',
        category: 'critical',
        example: 'default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'critical', name: 'Content-Security-Policy' }, headerValue)
    };
}

/**
 * Perform all critical header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkStrictTransportSecurity(responseHeaders),
        checkContentSecurityPolicy(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    checkStrictTransportSecurity,
    checkContentSecurityPolicy,
    name: 'Critical Headers',
    description: 'Checks for critical security headers (HSTS, CSP)'
};
