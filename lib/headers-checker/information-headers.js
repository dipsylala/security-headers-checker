/**
 * Information Security Headers Module
 * Handles information disclosure headers (Server, X-Powered-By, Via)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check Server header for information disclosure
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkServer(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Server');
    
    return {
        name: 'Server',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Server software information (potential information disclosure)',
        recommendation: 'Consider removing or obfuscating server information',
        category: 'information',
        example: 'nginx/1.18.0',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'information', name: 'Server' }, headerValue)
    };
}

/**
 * Check X-Powered-By header for information disclosure
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkXPoweredBy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'X-Powered-By');
    
    return {
        name: 'X-Powered-By',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Technology stack information (information disclosure)',
        recommendation: 'Remove X-Powered-By header to reduce information disclosure',
        category: 'information',
        example: 'Express',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'information', name: 'X-Powered-By' }, headerValue)
    };
}

/**
 * Check Via header for information disclosure
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkVia(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Via');
    
    return {
        name: 'Via',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Proxy/gateway information (potential information disclosure)',
        recommendation: 'Review Via header for sensitive proxy information',
        category: 'information',
        example: '1.1 varnish',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'information', name: 'Via' }, headerValue)
    };
}

/**
 * Perform all information header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkServer(responseHeaders),
        checkXPoweredBy(responseHeaders),
        checkVia(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    checkServer,
    checkXPoweredBy,
    checkVia,
    name: 'Information Headers',
    description: 'Checks for information disclosure headers (Server, X-Powered-By, Via)'
};
