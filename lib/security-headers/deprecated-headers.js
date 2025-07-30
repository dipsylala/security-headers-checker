/**
 * Deprecated Security Headers Module
 * Handles deprecated security headers that should not be used
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Content-Security-Policy-Report-Only header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkContentSecurityPolicyReportOnly(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Content-Security-Policy-Report-Only');

    return {
        name: 'Content-Security-Policy-Report-Only',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Report-only mode for CSP (deprecated approach)',
        recommendation: 'Use regular Content-Security-Policy header instead',
        category: 'deprecated',
        example: 'default-src \'self\'; report-uri /csp-violations',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'deprecated', name: 'Content-Security-Policy-Report-Only' }, headerValue)
    };
}

/**
 * Perform all deprecated header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkContentSecurityPolicyReportOnly(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    name: 'Deprecated Headers',
    description: 'Checks for deprecated security headers',
    category: 'deprecated'
};
