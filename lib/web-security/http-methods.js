/**
 * HTTP Methods Security Check
 * Analyzes potentially dangerous HTTP methods exposed by the server
 */

const https = require('https');
const http = require('http');

/**
 * Check HTTP methods for potentially dangerous methods
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} HTTP methods check result with scoring
 */
function checkHttpMethods(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname || '/',
            method: 'OPTIONS',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            const analysis = analyzeHttpMethodsResponse(response);
            resolve({
                name: 'HTTP Methods',
                status: analysis.status,
                description: 'Checks for potentially dangerous HTTP methods',
                details: analysis.details,
                score: analysis.score,
                maxScore: 2,
                recommendation: analysis.recommendation
            });
        });

        request.on('error', (error) => {
            const analysis = analyzeHttpMethodsError(error);
            resolve({
                name: 'HTTP Methods',
                status: analysis.status,
                description: 'Checks for potentially dangerous HTTP methods',
                details: analysis.details,
                score: analysis.score,
                maxScore: 2,
                recommendation: analysis.recommendation
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTP Methods',
                status: 'info',
                description: 'Checks for potentially dangerous HTTP methods',
                details: 'HTTP methods check timed out (server may be filtering OPTIONS requests)',
                score: 1,
                maxScore: 2,
                recommendation: null
            });
        });

        request.end();
    });
}

/**
 * Analyze HTTP OPTIONS response
 * @param {Object} response - HTTP response object
 * @returns {Object} Analysis result with status, details, score, and recommendation
 */
function analyzeHttpMethodsResponse(response) {
    const allowHeader = response.headers.allow || '';
    const dangerousMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];
    const moderatelyDangerousMethods = ['POST'];

    // Check response status
    if (response.statusCode === 405) {
        // Method not allowed - this is actually good for security
        return {
            status: 'pass',
            details: 'OPTIONS method not allowed (good security practice)',
            score: 2,
            recommendation: null
        };
    }

    if (response.statusCode >= 400 && response.statusCode !== 405) {
        // Other error responses
        return {
            status: 'pass',
            details: `Server restricts OPTIONS requests (HTTP ${response.statusCode})`,
            score: 2,
            recommendation: null
        };
    }

    if (allowHeader) {
        const allowedMethods = allowHeader.toUpperCase().split(',').map(m => m.trim());
        const foundDangerous = dangerousMethods.filter(method =>
            allowedMethods.includes(method)
        );
        const foundModerate = moderatelyDangerousMethods.filter(method =>
            allowedMethods.includes(method)
        );

        if (foundDangerous.length > 0) {
            // Critical security risk
            const score = 0;
            let recommendation = `Disable dangerous HTTP methods: ${foundDangerous.join(', ')}`;

            // TRACE is particularly dangerous due to XST attacks
            if (foundDangerous.includes('TRACE')) {
                recommendation += '. TRACE method is especially dangerous and should be disabled immediately';
            }

            return {
                status: 'fail',
                details: `Dangerous methods enabled: ${foundDangerous.join(', ')} (from Allow: ${allowHeader})`,
                score: score,
                recommendation: recommendation
            };
        } else if (foundModerate.length > 0 && allowedMethods.length > 3) {
            // Many methods enabled including POST - moderate risk
            return {
                status: 'warning',
                details: `Multiple methods enabled including: ${allowedMethods.join(', ')}`,
                score: 1,
                recommendation: 'Consider restricting HTTP methods to only those necessary (GET, POST, HEAD)'
            };
        } else {
            // Only safe methods
            return {
                status: 'pass',
                details: `Safe methods only: ${allowHeader}`,
                score: 2,
                recommendation: null
            };
        }
    } else {
        // No Allow header but successful response
        return {
            status: 'info',
            details: 'Server accepts OPTIONS but does not advertise allowed methods',
            score: 1,
            recommendation: 'Consider configuring server to properly advertise allowed HTTP methods'
        };
    }
}

/**
 * Analyze HTTP methods request error
 * @param {Error} error - Request error
 * @returns {Object} Analysis result with status, details, score, and recommendation
 */
function analyzeHttpMethodsError(error) {
    // Connection errors often mean the server is properly secured
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        return {
            status: 'info',
            details: 'Unable to test HTTP methods (connection error)',
            score: 1,
            recommendation: null
        };
    } else {
        return {
            status: 'info',
            details: `HTTP methods check failed: ${error.message}`,
            score: 1,
            recommendation: null
        };
    }
}

module.exports = {
    performCheck: checkHttpMethods,
    name: 'HTTP Methods',
    description: 'Analyzes potentially dangerous HTTP methods exposed by the server'
};
