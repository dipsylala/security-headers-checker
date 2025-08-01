/**
 * Network Reachability Checker
 * Provides fast connectivity checks before performing expensive security analysis
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const logger = require('./logger');

/**
 * Check if a URL/domain is reachable with basic connectivity test
 * @param {string} url - The URL to test for reachability
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<Object>} Reachability result with status and details
 */
function checkReachability(url, timeout = 5000) {
    return new Promise((resolve) => {
        const startTime = Date.now();

        try {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const client = isHttps ? https : http;

            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: '/',
                method: 'HEAD', // Use HEAD request for fast connectivity check
                timeout: timeout,
                headers: {
                    'User-Agent': 'Security-Headers-Checker/1.0 (Reachability-Check)'
                },
                // Don't verify SSL certificates in reachability check - we'll do detailed SSL analysis later
                rejectUnauthorized: false
            };

            const req = client.request(options, (res) => {
                const responseTime = Date.now() - startTime;

                resolve({
                    reachable: true,
                    status: 'success',
                    httpStatus: res.statusCode,
                    responseTime: responseTime,
                    message: `Host is reachable (${res.statusCode} in ${responseTime}ms)`,
                    details: {
                        hostname: urlObj.hostname,
                        port: options.port,
                        protocol: urlObj.protocol,
                        responseTime: responseTime
                    }
                });
            });

            req.on('error', (error) => {
                const responseTime = Date.now() - startTime;

                // Categorize different types of connection errors
                let errorType = 'unknown';
                let userMessage = 'Host is not reachable';

                if (error.code === 'ENOTFOUND') {
                    errorType = 'dns_resolution';
                    userMessage = 'Domain name could not be resolved (DNS lookup failed)';
                } else if (error.code === 'ECONNREFUSED') {
                    errorType = 'connection_refused';
                    userMessage = 'Connection refused - server may be down or port blocked';
                } else if (error.code === 'ETIMEDOUT' || error.code === 'ECONNRESET') {
                    errorType = 'timeout';
                    userMessage = 'Connection timed out - server may be slow or unreachable';
                } else if (error.code === 'EHOSTUNREACH') {
                    errorType = 'host_unreachable';
                    userMessage = 'Host unreachable - network routing issue';
                } else if (error.code === 'EPROTO' || error.code === 'ECONNRESET') {
                    errorType = 'protocol_error';
                    userMessage = 'Protocol error - server may not support the requested protocol';
                }

                resolve({
                    reachable: false,
                    status: 'error',
                    errorType: errorType,
                    errorCode: error.code,
                    responseTime: responseTime,
                    message: userMessage,
                    technicalDetails: error.message,
                    details: {
                        hostname: urlObj.hostname,
                        port: options.port,
                        protocol: urlObj.protocol,
                        responseTime: responseTime
                    }
                });
            });

            req.on('timeout', () => {
                req.destroy();
                const responseTime = Date.now() - startTime;

                resolve({
                    reachable: false,
                    status: 'timeout',
                    errorType: 'timeout',
                    responseTime: responseTime,
                    message: `Connection timed out after ${timeout}ms`,
                    details: {
                        hostname: urlObj.hostname,
                        port: options.port,
                        protocol: urlObj.protocol,
                        timeout: timeout,
                        responseTime: responseTime
                    }
                });
            });

            req.end();

        } catch (error) {
            // Handle URL parsing errors or other synchronous errors
            resolve({
                reachable: false,
                status: 'error',
                errorType: 'invalid_url',
                message: 'Invalid URL format',
                technicalDetails: error.message,
                responseTime: Date.now() - startTime
            });
        }
    });
}

/**
 * Check reachability with retry logic for more robust testing
 * @param {string} url - The URL to test
 * @param {number} retries - Number of retry attempts (default: 2)
 * @param {number} timeout - Timeout per attempt in milliseconds (default: 5000)
 * @returns {Promise<Object>} Reachability result with retry information
 */
async function checkReachabilityWithRetry(url, retries = 2, timeout = 5000) {
    const attempts = [];

    for (let attempt = 1; attempt <= retries + 1; attempt++) {
        logger.info(`Reachability attempt ${attempt}/${retries + 1} for URL`);

        // eslint-disable-next-line no-await-in-loop
        const result = await checkReachability(url, timeout);
        attempts.push({
            attempt: attempt,
            ...result
        });

        if (result.reachable) {
            // Success - return immediately
            return {
                ...result,
                attempts: attempts,
                totalAttempts: attempt,
                finalStatus: 'reachable'
            };
        }

        // If not the last attempt, wait before retrying
        if (attempt <= retries) {
            logger.info(`Retrying reachability check in 1s... (${result.message})`);
            // eslint-disable-next-line no-await-in-loop
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }

    // All attempts failed
    const lastResult = attempts[attempts.length - 1];
    return {
        ...lastResult,
        attempts: attempts,
        totalAttempts: retries + 1,
        finalStatus: 'unreachable'
    };
}

/**
 * Get user-friendly suggestions based on reachability check results
 * @param {Object} reachabilityResult - Result from checkReachability
 * @returns {Array<string>} Array of helpful suggestions
 */
function getReachabilitySuggestions(reachabilityResult) {
    const suggestions = [];

    if (!reachabilityResult.reachable) {
        switch (reachabilityResult.errorType) {
            case 'dns_resolution':
                suggestions.push('Verify the domain name is spelled correctly');
                suggestions.push('Check if the domain exists and is registered');
                suggestions.push('Try accessing the site in a web browser');
                break;

            case 'connection_refused':
                suggestions.push('The server may be temporarily down');
                suggestions.push('Check if the website is accessible in a browser');
                suggestions.push('Verify the correct port is being used');
                break;

            case 'timeout':
                suggestions.push('The server may be slow or overloaded');
                suggestions.push('Try again in a few moments');
                suggestions.push('Check your network connection');
                break;

            case 'host_unreachable':
                suggestions.push('Network routing issue - server may be down');
                suggestions.push('Check if the website works from other locations');
                suggestions.push('Verify your network connectivity');
                break;

            case 'protocol_error':
                suggestions.push('Server may not support HTTPS/HTTP properly');
                suggestions.push('Try the opposite protocol (HTTP vs HTTPS)');
                suggestions.push('Check if the website loads in a browser');
                break;

            default:
                suggestions.push('Verify the URL is correct and accessible');
                suggestions.push('Check your network connection');
                suggestions.push('Try accessing the site in a web browser');
        }
    }

    return suggestions;
}

module.exports = {
    checkReachabilityWithRetry,
    getReachabilitySuggestions
};
