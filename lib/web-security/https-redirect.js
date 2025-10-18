/**
 * HTTPS Redirect Security Check
 * Verifies that HTTP requests are properly redirected to HTTPS
 */

const http = require('http');

/**
 * Create a result object for HTTPS redirect checks
 * @param {string} status - pass, fail, or warning
 * @param {string} details - Detailed message about the check
 * @param {number} score - Score awarded (0-2)
 * @param {string|null} recommendation - Recommendation for improvement
 * @returns {Object} Formatted result object
 */
function createResult(status, details, score, recommendation) {
    return {
        name: 'HTTPS Redirect',
        status,
        description: 'Checks if HTTP requests are redirected to HTTPS',
        details,
        score,
        maxScore: 2,
        recommendation
    };
}

/**
 * Determine if a Location header redirects to HTTPS
 * @param {string} location - The Location header value
 * @returns {Object} Analysis of the redirect location
 */
function analyzeRedirectLocation(location) {
    const isAbsoluteHttps = location.startsWith('https://');
    const isRelativeUrl = !location.includes('://');
    const redirectsToHttps = isAbsoluteHttps || isRelativeUrl;
    const redirectType = isAbsoluteHttps ? 'absolute HTTPS URL' : 'relative URL (inherits HTTPS)';

    return { redirectsToHttps, redirectType };
}

/**
 * Handle the HTTP response and determine redirect status
 * @param {Object} response - HTTP response object
 * @returns {Object} Result object based on response analysis
 */
function handleRedirectResponse(response) {
    const isRedirect = response.statusCode >= 300 && response.statusCode < 400;
    const location = response.headers.location;

    if (!isRedirect) {
        return createResult(
            'warning',
            `HTTP request returned ${response.statusCode} without redirect`,
            1,
            'Configure server to redirect all HTTP requests to HTTPS'
        );
    }

    if (!location) {
        return createResult(
            'fail',
            `Redirect response (${response.statusCode}) missing Location header`,
            0,
            'Configure server to include Location header in redirect responses'
        );
    }

    const { redirectsToHttps, redirectType } = analyzeRedirectLocation(location);

    if (redirectsToHttps) {
        return createResult(
            'pass',
            `HTTP requests properly redirect to HTTPS (${response.statusCode} to ${redirectType})`,
            2,
            null
        );
    }

    return createResult(
        'fail',
        `HTTP redirects to non-HTTPS URL: ${location}`,
        0,
        'Configure server to redirect HTTP requests to HTTPS URLs'
    );
}

/**
 * Check if HTTP requests are redirected to HTTPS
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} HTTPS redirect check result with scoring
 */
function checkHttpsRedirect(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);

        if (urlObj.protocol === 'http:') {
            resolve(createResult(
                'fail',
                'URL is using HTTP instead of HTTPS',
                0,
                'Use HTTPS instead of HTTP for secure communication'
            ));
            return;
        }

        const httpUrl = url.replace('https://', 'http://');
        const httpUrlObj = new URL(httpUrl);

        const options = {
            hostname: httpUrlObj.hostname,
            port: httpUrlObj.port || 80,
            path: httpUrlObj.pathname || '/',
            method: 'HEAD',
            timeout: 5000
        };

        const request = http.request(options, (response) => {
            resolve(handleRedirectResponse(response));
        });

        request.on('error', () => {
            resolve(createResult(
                'pass',
                'HTTPS is being used',
                2,
                null
            ));
        });

        request.on('timeout', () => {
            request.destroy();
            resolve(createResult(
                'warning',
                'Unable to verify HTTP redirect (timeout)',
                1,
                'Verify server redirects HTTP to HTTPS'
            ));
        });

        request.end();
    });
}

module.exports = {
    performCheck: checkHttpsRedirect,
    name: 'HTTPS Redirect',
    description: 'Verifies that HTTP requests are properly redirected to HTTPS'
};
