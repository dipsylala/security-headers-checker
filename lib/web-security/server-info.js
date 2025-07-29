/**
 * Server Information Security Check
 * Analyzes server information disclosure in HTTP headers
 */

const https = require('https');
const http = require('http');

/**
 * Check server information disclosure
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Server information check result with scoring
 */
async function checkServerInfo(url) {
    return new Promise((resolve) => {
        let redirectCount = 0;
        const maxRedirects = 5;

        function makeRequest(currentUrl) {
            const urlObj = new URL(currentUrl);
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname || '/',
                method: 'HEAD',
                timeout: 5000
            };

            const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
                // Handle redirects
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    if (redirectCount >= maxRedirects) {
                        resolve({
                            name: 'Server Information',
                            status: 'info',
                            description: 'Server software disclosure analysis',
                            details: 'Too many redirects',
                            score: 1,
                            maxScore: 1,
                            recommendation: null
                        });
                        return;
                    }
                    
                    redirectCount++;
                    const redirectUrl = new URL(response.headers.location, currentUrl).href;
                    makeRequest(redirectUrl);
                    return;
                }
                // Process the final response
                const server = response.headers.server || 'Unknown';
                const poweredBy = response.headers['x-powered-by'] || null;
                const versionInfo = response.headers['x-aspnet-version'] || response.headers['x-aspnetmvc-version'] || null;

                let details = `Server: ${server}`;
                let score = 1; // Base score for providing info
                let status = 'info';
                let recommendation = null;

                if (poweredBy) {
                    details += `, Powered by: ${poweredBy}`;
                    // Exposing technology stack reduces security through obscurity
                    score = 0.5;
                    status = 'warning';
                    recommendation = 'Consider hiding X-Powered-By header to reduce information disclosure';
                }

                if (versionInfo) {
                    details += `, Version info exposed`;
                    score = 0;
                    status = 'warning';
                    recommendation = 'Remove version information headers (X-AspNet-Version, X-AspNetMvc-Version) to prevent targeted attacks';
                }

                // Check for detailed server version disclosure
                if (server && server.includes('/')) {
                    const versionPattern = /\/[\d\.]+([\s\(]|$)/;
                    if (versionPattern.test(server)) {
                        score = Math.min(score, 0.5);
                        status = 'warning';
                        recommendation = recommendation || 'Consider hiding detailed server version information';
                    }
                }

                resolve({
                    name: 'Server Information',
                    status: status,
                    description: 'Server software disclosure analysis',
                    details: details,
                    score: score,
                    maxScore: 1,
                    recommendation: recommendation
                });
            });

            request.on('error', () => {
                resolve({
                    name: 'Server Information',
                    status: 'info',
                    description: 'Server software disclosure analysis',
                    details: 'Server information unavailable',
                    score: 1,
                    maxScore: 1,
                    recommendation: null
                });
            });

            request.on('timeout', () => {
                request.destroy();
                resolve({
                    name: 'Server Information',
                    status: 'info',
                    description: 'Server software disclosure analysis',
                    details: 'Server information unavailable (timeout)',
                    score: 1,
                    maxScore: 1,
                    recommendation: null
                });
            });

            request.end();
        }

        // Start the request chain
        makeRequest(url);
    });
}

module.exports = {
    performCheck: checkServerInfo,
    name: 'Server Information',
    description: 'Analyzes server information disclosure in HTTP headers'
};
