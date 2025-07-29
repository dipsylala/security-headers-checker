/**
 * Legacy Security Headers Module
 * Handles legacy security headers (Public-Key-Pins, X-XSS-Protection, etc.)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Public-Key-Pins header (deprecated but may still be used)
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkPublicKeyPins(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Public-Key-Pins');
    
    return {
        name: 'Public-Key-Pins',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Deprecated. Previously used for certificate pinning',
        recommendation: 'Avoid using HPKP due to deployment risks. Consider other certificate validation methods',
        category: 'legacy',
        example: 'pin-sha256="..."; max-age=2592000',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'legacy', name: 'Public-Key-Pins' }, headerValue)
    };
}

/**
 * Check X-XSS-Protection header (legacy)
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkXXSSProtection(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'X-XSS-Protection');
    
    return {
        name: 'X-XSS-Protection',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Legacy XSS filter header (largely superseded by CSP)',
        recommendation: 'Use Content-Security-Policy instead for modern XSS protection',
        category: 'legacy',
        example: '1; mode=block',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'legacy', name: 'X-XSS-Protection' }, headerValue)
    };
}

/**
 * Check X-Permitted-Cross-Domain-Policies header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkXPermittedCrossDomainPolicies(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'X-Permitted-Cross-Domain-Policies');
    
    return {
        name: 'X-Permitted-Cross-Domain-Policies',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls Adobe Flash and PDF cross-domain policies',
        recommendation: 'Set to none to restrict Flash/PDF cross-domain access',
        category: 'legacy',
        example: 'none',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'legacy', name: 'X-Permitted-Cross-Domain-Policies' }, headerValue)
    };
}

/**
 * Perform all legacy header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkPublicKeyPins(responseHeaders),
        checkXXSSProtection(responseHeaders),
        checkXPermittedCrossDomainPolicies(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    checkPublicKeyPins,
    checkXXSSProtection,
    checkXPermittedCrossDomainPolicies,
    name: 'Legacy Headers',
    description: 'Checks for legacy security headers (Public-Key-Pins, X-XSS-Protection, etc.)'
};
