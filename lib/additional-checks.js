/**
 * Additional Security Checks Module
 * Handles HTTP methods, HTTPS redirects, mixed content, security.txt, and other security checks
 */

const https = require('https');
const http = require('http');

/**
 * Perform all additional security checks
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Object with checks array and score
 */
async function performAdditionalChecks(url) {
    const checks = [];
    
    try {
        // HTTPS Redirect check
        const httpsRedirect = await checkHttpsRedirect(url);
        checks.push(httpsRedirect);
        
        // Server information check
        const serverInfo = await checkServerInfo(url);
        checks.push(serverInfo);
        
        // Mixed content check
        const mixedContent = await checkMixedContent(url);
        checks.push(mixedContent);
        
        // HTTP methods check
        const httpMethods = await checkHttpMethods(url);
        checks.push(httpMethods);
        
        // Security.txt check
        const securityTxt = await checkSecurityTxt(url);
        checks.push(securityTxt);
        
    } catch (error) {
        console.error('Additional checks error:', error);
    }
    
    const score = calculateAdditionalChecksScore(checks);
    
    return {
        checks: checks,
        score: score
    };
}

/**
 * Check if HTTP requests are redirected to HTTPS
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} HTTPS redirect check result
 */
async function checkHttpsRedirect(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        
        if (urlObj.protocol === 'http:') {
            resolve({
                name: 'HTTPS Redirect',
                status: 'fail',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'URL is using HTTP instead of HTTPS'
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
                    details: `HTTP requests properly redirect to HTTPS (${response.statusCode})`
                });
            } else {
                resolve({
                    name: 'HTTPS Redirect',
                    status: 'warning',
                    description: 'Checks if HTTP requests are redirected to HTTPS',
                    details: 'HTTP requests may not redirect to HTTPS'
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'HTTPS Redirect',
                status: 'pass',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'HTTPS is being used'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTPS Redirect',
                status: 'warning',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'Unable to verify HTTP redirect (timeout)'
            });
        });

        request.end();
    });
}

/**
 * Check server information disclosure
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Server information check result
 */
async function checkServerInfo(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname || '/',
            method: 'HEAD',
            timeout: 5000
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            const server = response.headers.server || 'Unknown';
            const poweredBy = response.headers['x-powered-by'] || null;
            
            let details = `Server: ${server}`;
            if (poweredBy) {
                details += `, Powered by: ${poweredBy}`;
            }
            
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: details
            });
        });

        request.on('error', () => {
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: 'Server information unavailable'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: 'Server information unavailable (timeout)'
            });
        });

        request.end();
    });
}

/**
 * Check for mixed content issues on HTTPS pages
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Mixed content check result
 */
async function checkMixedContent(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        
        if (urlObj.protocol !== 'https:') {
            resolve({
                name: 'Mixed Content',
                status: 'warning',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Site is not using HTTPS'
            });
            return;
        }

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname || '/',
            method: 'GET',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0',
                'Accept': 'text/html'
            }
        };

        const request = https.request(options, (response) => {
            let data = '';
            let dataLength = 0;
            const maxDataLength = 50000; // Limit data to prevent memory issues

            response.on('data', chunk => {
                if (dataLength < maxDataLength) {
                    data += chunk;
                    dataLength += chunk.length;
                }
            });

            response.on('end', () => {
                const analysis = analyzeMixedContent(data);
                resolve({
                    name: 'Mixed Content',
                    status: analysis.status,
                    description: 'Checks for insecure resources on HTTPS pages',
                    details: analysis.details
                });
            });
        });

        request.on('error', () => {
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Unable to check mixed content'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Mixed content check timed out'
            });
        });

        request.end();
    });
}

/**
 * Analyze HTML content for mixed content issues
 * @param {string} htmlContent - HTML content to analyze
 * @returns {Object} Analysis result with status and details
 */
function analyzeMixedContent(htmlContent) {
    // Simple check for HTTP resources in HTML
    const httpResources = htmlContent.match(/http:\/\/[^"\s>]+/gi);
    
    if (httpResources && httpResources.length > 0) {
        return {
            status: 'warning',
            details: `Found ${httpResources.length} potential HTTP resources`
        };
    } else {
        return {
            status: 'pass',
            details: 'No obvious mixed content detected'
        };
    }
}

/**
 * Check HTTP methods for potentially dangerous methods
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} HTTP methods check result
 */
async function checkHttpMethods(url) {
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
                details: analysis.details
            });
        });

        request.on('error', (error) => {
            const analysis = analyzeHttpMethodsError(error);
            resolve({
                name: 'HTTP Methods',
                status: analysis.status,
                description: 'Checks for potentially dangerous HTTP methods',
                details: analysis.details
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTP Methods',
                status: 'info',
                description: 'Checks for potentially dangerous HTTP methods',
                details: 'HTTP methods check timed out (server may be filtering OPTIONS requests)'
            });
        });

        request.end();
    });
}

/**
 * Analyze HTTP OPTIONS response
 * @param {Object} response - HTTP response object
 * @returns {Object} Analysis result with status and details
 */
function analyzeHttpMethodsResponse(response) {
    const allowHeader = response.headers.allow || '';
    const dangerousMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE'];
    
    // Check response status
    if (response.statusCode === 405) {
        // Method not allowed - this is actually good for security
        return {
            status: 'pass',
            details: 'OPTIONS method not allowed (good security practice)'
        };
    }
    
    if (response.statusCode >= 400) {
        // Other error responses
        return {
            status: 'pass',
            details: `Server restricts OPTIONS requests (HTTP ${response.statusCode})`
        };
    }
    
    if (allowHeader) {
        const foundDangerous = dangerousMethods.filter(method => 
            allowHeader.toUpperCase().includes(method)
        );

        if (foundDangerous.length > 0) {
            return {
                status: 'warning',
                details: `Dangerous methods enabled: ${foundDangerous.join(', ')} (from Allow: ${allowHeader})`
            };
        } else {
            return {
                status: 'pass',
                details: `Safe methods only: ${allowHeader}`
            };
        }
    } else {
        // No Allow header but successful response
        return {
            status: 'info',
            details: 'Server accepts OPTIONS but does not advertise allowed methods'
        };
    }
}

/**
 * Analyze HTTP methods request error
 * @param {Error} error - Request error
 * @returns {Object} Analysis result with status and details
 */
function analyzeHttpMethodsError(error) {
    // Connection errors often mean the server is properly secured
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        return {
            status: 'info',
            details: 'Unable to test HTTP methods (connection error)'
        };
    } else {
        return {
            status: 'info',
            details: `HTTP methods check failed: ${error.message}`
        };
    }
}

/**
 * Check for security.txt file (RFC 9116)
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Security.txt check result
 */
async function checkSecurityTxt(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: '/.well-known/security.txt',
            method: 'HEAD',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            if (response.statusCode === 200) {
                resolve({
                    name: 'Security.txt',
                    status: 'pass',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: 'Security.txt file found - good security practice'
                });
            } else {
                resolve({
                    name: 'Security.txt',
                    status: 'info',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: 'No security.txt file found'
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Unable to check for security.txt'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Security.txt check timed out'
            });
        });

        request.end();
    });
}

/**
 * Calculate additional checks score for overall security score
 * @param {Array} additionalChecks - Array of additional check results
 * @returns {Object} Score object with score and maxScore
 */
function calculateAdditionalChecksScore(additionalChecks) {
    const passedChecks = additionalChecks.filter(check => check.status === 'pass').length;
    const totalChecks = additionalChecks.filter(check => check.status !== 'info').length;
    const maxScore = 10;
    
    if (totalChecks > 0) {
        return {
            score: (passedChecks / totalChecks) * maxScore,
            maxScore: maxScore,
            passed: passedChecks,
            total: totalChecks
        };
    } else {
        return {
            score: 5, // Partial credit if no additional checks
            maxScore: maxScore,
            passed: 0,
            total: 0
        };
    }
}

/**
 * Get summary of additional checks by status
 * @param {Array} additionalChecks - Array of additional check results
 * @returns {Object} Summary grouped by status
 */
function getAdditionalChecksSummary(additionalChecks) {
    const summary = {
        pass: 0,
        warning: 0,
        info: 0,
        fail: 0
    };
    
    additionalChecks.forEach(check => {
        summary[check.status] = (summary[check.status] || 0) + 1;
    });
    
    return summary;
}

module.exports = {
    performAdditionalChecks,
    checkHttpsRedirect,
    checkServerInfo,
    checkMixedContent,
    checkHttpMethods,
    checkSecurityTxt,
    calculateAdditionalChecksScore,
    getAdditionalChecksSummary
};
