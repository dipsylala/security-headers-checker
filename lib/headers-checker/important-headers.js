/**
 * Important Security Headers Module
 * Handles important security headers (X-Frame-Options, X-Content-Type-Options, etc.)
 */

const { calculateHeaderScore, findHeaderValue } = require('./scoring-utils');

/**
 * Check X-Frame-Options header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkXFrameOptions(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'X-Frame-Options');
    
    return {
        name: 'X-Frame-Options',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Prevents iframe clickjacking attacks',
        recommendation: 'Set to DENY or SAMEORIGIN',
        category: 'important',
        example: 'DENY',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'important', name: 'X-Frame-Options' }, headerValue)
    };
}

/**
 * Check X-Content-Type-Options header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkXContentTypeOptions(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'X-Content-Type-Options');
    
    return {
        name: 'X-Content-Type-Options',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Prevents MIME type sniffing vulnerabilities',
        recommendation: 'Set to nosniff',
        category: 'important',
        example: 'nosniff',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'important', name: 'X-Content-Type-Options' }, headerValue)
    };
}

/**
 * Check Referrer-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkReferrerPolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Referrer-Policy');
    
    return {
        name: 'Referrer-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls referrer information sent with requests',
        recommendation: 'Set to strict-origin-when-cross-origin or strict-origin',
        category: 'important',
        example: 'strict-origin-when-cross-origin',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'important', name: 'Referrer-Policy' }, headerValue)
    };
}

/**
 * Check Permissions-Policy header
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkPermissionsPolicy(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Permissions-Policy');
    
    return {
        name: 'Permissions-Policy',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls which browser features can be used by the page',
        recommendation: 'Configure to restrict potentially dangerous features',
        category: 'important',
        example: 'geolocation=(), microphone=(), camera=()',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'important', name: 'Permissions-Policy' }, headerValue)
    };
}

/**
 * Check CORS headers (Access-Control-Allow-Origin)
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Object} Header analysis result
 */
function checkAccessControlAllowOrigin(responseHeaders) {
    const headerValue = findHeaderValue(responseHeaders, 'Access-Control-Allow-Origin');
    
    return {
        name: 'Access-Control-Allow-Origin',
        present: !!headerValue,
        value: headerValue || '',
        description: 'Controls cross-origin resource sharing',
        recommendation: 'Set specific origins instead of wildcard (*) when possible',
        category: 'important',
        example: 'https://trusted-domain.com',
        status: headerValue ? 'present' : 'missing',
        score: calculateHeaderScore({ category: 'important', name: 'Access-Control-Allow-Origin' }, headerValue)
    };
}

/**
 * Perform all important header checks
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function performCheck(responseHeaders) {
    return [
        checkXFrameOptions(responseHeaders),
        checkXContentTypeOptions(responseHeaders),
        checkReferrerPolicy(responseHeaders),
        checkPermissionsPolicy(responseHeaders),
        checkAccessControlAllowOrigin(responseHeaders)
    ];
}

module.exports = {
    performCheck,
    checkXFrameOptions,
    checkXContentTypeOptions,
    checkReferrerPolicy,
    checkPermissionsPolicy,
    checkAccessControlAllowOrigin,
    name: 'Important Headers',
    description: 'Checks for important security headers (X-Frame-Options, X-Content-Type-Options, etc.)'
};
