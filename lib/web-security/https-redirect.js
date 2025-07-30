/**
 * HTTPS Redirect Security Check
 * Verifies that HTTP requests are properly redirected to HTTPS
 */

const http = require('http');

/**
 * Check if HTTP requests are redirected to HTTPS
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} HTTPS redirect check result with scoring
 */
function checkHttpsRedirect(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);

        if (urlObj.protocol === 'http:') {
            resolve({
                name: 'HTTPS Redirect',
                status: 'fail',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'URL is using HTTP instead of HTTPS',
                score: 0,
                maxScore: 2,
                recommendation: 'Use HTTPS instead of HTTP for secure communication'
            });
            return;
        }

        // Check if HTTP version redirects to HTTPS
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
            const isRedirect = response.statusCode >= 300 && response.statusCode < 400;
            const location = response.headers.location;
            const redirectsToHttps = location && location.startsWith('https://');

            if (isRedirect && redirectsToHttps) {
                resolve({
                    name: 'HTTPS Redirect',
                    status: 'pass',
                    description: 'Checks if HTTP requests are redirected to HTTPS',
                    details: `HTTP requests properly redirect to HTTPS (${response.statusCode})`,
                    score: 2,
                    maxScore: 2,
                    recommendation: null
                });
            } else {
                resolve({
                    name: 'HTTPS Redirect',
                    status: 'warning',
                    description: 'Checks if HTTP requests are redirected to HTTPS',
                    details: 'HTTP requests may not redirect to HTTPS',
                    score: 1,
                    maxScore: 2,
                    recommendation: 'Configure server to redirect all HTTP requests to HTTPS'
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'HTTPS Redirect',
                status: 'pass',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'HTTPS is being used',
                score: 2,
                maxScore: 2,
                recommendation: null
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTPS Redirect',
                status: 'warning',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'Unable to verify HTTP redirect (timeout)',
                score: 1,
                maxScore: 2,
                recommendation: 'Verify server redirects HTTP to HTTPS'
            });
        });

        request.end();
    });
}

module.exports = {
    performCheck: checkHttpsRedirect,
    name: 'HTTPS Redirect',
    description: 'Verifies that HTTP requests are properly redirected to HTTPS'
};
