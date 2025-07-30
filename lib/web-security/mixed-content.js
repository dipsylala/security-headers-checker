/**
 * Mixed Content Security Check
 * Detects insecure HTTP resources loaded on HTTPS pages
 */

const https = require('https');

/**
 * Check for mixed content issues on HTTPS pages
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Mixed content check result with scoring
 */
function checkMixedContent(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);

        if (urlObj.protocol !== 'https:') {
            resolve({
                name: 'Mixed Content',
                status: 'warning',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Site is not using HTTPS',
                score: 0,
                maxScore: 2,
                recommendation: 'Use HTTPS to prevent mixed content issues'
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
                    details: analysis.details,
                    score: analysis.score,
                    maxScore: 2,
                    recommendation: analysis.recommendation
                });
            });
        });

        request.on('error', () => {
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Unable to check mixed content',
                score: 1,
                maxScore: 2,
                recommendation: null
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Mixed content check timed out',
                score: 1,
                maxScore: 2,
                recommendation: null
            });
        });

        request.end();
    });
}

/**
 * Analyze HTML content for mixed content issues
 * @param {string} htmlContent - HTML content to analyze
 * @returns {Object} Analysis result with status, details, score, and recommendation
 */
function analyzeMixedContent(htmlContent) {
    // Check for HTTP resources in HTML
    const httpResources = htmlContent.match(/http:\/\/[^"\s>]+/gi);

    // Check for specific dangerous patterns
    const imagePattern = /src\s*=\s*["']http:\/\/[^"']+/gi;
    const scriptPattern = /<script[^>]*src\s*=\s*["']http:\/\/[^"']+/gi;
    const linkPattern = /<link[^>]*href\s*=\s*["']http:\/\/[^"']+/gi;
    const iframePattern = /<iframe[^>]*src\s*=\s*["']http:\/\/[^"']+/gi;

    const images = htmlContent.match(imagePattern) || [];
    const scripts = htmlContent.match(scriptPattern) || [];
    const links = htmlContent.match(linkPattern) || [];
    const iframes = htmlContent.match(iframePattern) || [];

    const totalHttpResources = (httpResources || []).length;
    const criticalResources = scripts.length + iframes.length; // Scripts and iframes are more critical
    const passiveResources = images.length + links.length; // Images and stylesheets are less critical

    if (criticalResources > 0) {
        return {
            status: 'fail',
            details: `Found ${criticalResources} critical HTTP resources (scripts/iframes) and ${passiveResources} passive resources`,
            score: 0,
            recommendation: 'Immediately fix critical mixed content - scripts and iframes must use HTTPS'
        };
    } else if (passiveResources > 0) {
        return {
            status: 'warning',
            details: `Found ${passiveResources} passive HTTP resources (images/stylesheets)`,
            score: 1,
            recommendation: 'Update images and stylesheets to use HTTPS for better security'
        };
    } else if (totalHttpResources > 0) {
        return {
            status: 'warning',
            details: `Found ${totalHttpResources} potential HTTP resources`,
            score: 1,
            recommendation: 'Review and update any HTTP resources to use HTTPS'
        };
    } else {
        return {
            status: 'pass',
            details: 'No obvious mixed content detected',
            score: 2,
            recommendation: null
        };
    }
}

module.exports = {
    performCheck: checkMixedContent,
    name: 'Mixed Content',
    description: 'Detects insecure HTTP resources loaded on HTTPS pages'
};
