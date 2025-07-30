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
    const poweredBy = findHeaderValue(responseHeaders, 'X-Powered-By');
    const versionInfo = findHeaderValue(responseHeaders, 'X-AspNet-Version') || 
                       findHeaderValue(responseHeaders, 'X-AspNetMvc-Version');

    let status = 'missing';
    let score = 0;
    let recommendation = 'Consider removing or obfuscating server information';
    let details = [];

    if (headerValue) {
        status = 'present';
        details.push(`Server: ${headerValue}`);
        
        // Check for detailed server version disclosure
        if (headerValue.includes('/')) {
            const versionPattern = /\/[\d.]+([\s(]|$)/;
            if (versionPattern.test(headerValue)) {
                status = 'warning';
                recommendation = 'Consider hiding detailed server version information to reduce attack surface';
                details.push('Contains version information');
            }
        }
    }

    if (poweredBy) {
        status = 'warning';
        details.push(`X-Powered-By: ${poweredBy}`);
        recommendation = 'Remove X-Powered-By header to reduce information disclosure';
    }

    if (versionInfo) {
        status = 'warning';
        details.push('ASP.NET version headers exposed');
        recommendation = 'Remove version information headers (X-AspNet-Version, X-AspNetMvc-Version) to prevent targeted attacks';
    }

    // Calculate score based on information disclosure
    if (status === 'missing') {
        score = 0; // Good - no information disclosed
    } else if (status === 'present' && !headerValue.includes('/')) {
        score = 0; // Acceptable - basic server info without version
    } else {
        score = 0; // Information disclosed - security concern
    }

    return {
        name: 'Server',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Server software information (potential information disclosure)',
        recommendation: recommendation,
        category: 'information',
        example: 'nginx/1.18.0',
        status: status,
        score: score,
        details: details.length > 0 ? details.join(', ') : undefined
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
        status: headerValue ? 'warning' : 'missing',
        score: headerValue ? 0 : 0 // 0 score regardless since information disclosure is always a concern
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
    name: 'Information Headers',
    description: 'Checks for information disclosure headers (Server, X-Powered-By, Via)',
    category: 'information'
};
