/**
 * Security Headers Checker Module
 * Handles HTTP security header detection and analysis
 */

const https = require('https');
const http = require('http');
const { SECURITY_HEADERS, calculateHeaderScore } = require('./security-headers');

/**
 * Check security headers for a given URL
 * @param {string} url - The URL to check
 * @param {number} redirectCount - Internal redirect counter
 * @returns {Promise<Object>} Object with headers array and score
 */
async function checkSecurityHeaders(url, redirectCount = 0) {
    return new Promise((resolve) => {
        let resolved = false;
        
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname + (urlObj.search || ''),
            method: 'HEAD',
            timeout: 10000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            if (resolved) return;
            
            // Handle redirects (301, 302, 307, 308)
            if ([301, 302, 307, 308].includes(response.statusCode) && response.headers.location && redirectCount < 5) {
                const redirectUrl = new URL(response.headers.location, url).href;
                console.log(`Following redirect from ${url} to ${redirectUrl}`);
                
                resolved = true;
                request.destroy();
                
                // Follow redirect recursively
                checkSecurityHeaders(redirectUrl, redirectCount + 1).then(resolve);
                return;
            }
            
            resolved = true;
            const headers = analyzeResponseHeaders(response.headers);
            const score = calculateHeadersScore(headers);
            resolve({
                headers: headers,
                score: score
            });
        });

        request.on('error', (error) => {
            if (resolved) return;
            resolved = true;
            
            console.error('Headers check error:', error);
            const defaultHeaders = getDefaultHeaders();
            const score = calculateHeadersScore(defaultHeaders);
            resolve({
                headers: defaultHeaders,
                score: score
            });
        });

        request.on('timeout', () => {
            if (resolved) return;
            resolved = true;
            
            console.error('Headers check timeout');
            request.destroy();
            const defaultHeaders = getDefaultHeaders();
            const score = calculateHeadersScore(defaultHeaders);
            resolve({
                headers: defaultHeaders,
                score: score
            });
        });

        request.end();
    });
}

/**
 * Analyze response headers against security header definitions
 * @param {Object} responseHeaders - HTTP response headers
 * @returns {Array} Array of header analysis results
 */
function analyzeResponseHeaders(responseHeaders) {
    return SECURITY_HEADERS.map(secHeader => {
        // Check multiple possible header names (case variations)
        const headerValue = findHeaderValue(responseHeaders, secHeader.name);
        
        // Determine status and recommendation
        const analysis = analyzeHeaderPresence(secHeader, headerValue);
        
        return {
            name: secHeader.name,
            present: !!headerValue,
            value: headerValue || '',
            description: secHeader.description,
            recommendation: analysis.recommendation,
            category: secHeader.category,
            example: secHeader.example || '',
            status: analysis.status,
            score: calculateHeaderScore(secHeader, headerValue)
        };
    });
}

/**
 * Find header value with case-insensitive matching
 * @param {Object} responseHeaders - HTTP response headers
 * @param {string} headerName - Header name to find
 * @returns {string|null} Header value or null if not found
 */
function findHeaderValue(responseHeaders, headerName) {
    // Direct match (exact case)
    if (responseHeaders[headerName]) {
        return responseHeaders[headerName];
    }
    
    // Case-insensitive match
    const lowerHeaderName = headerName.toLowerCase();
    if (responseHeaders[lowerHeaderName]) {
        return responseHeaders[lowerHeaderName];
    }
    
    // Search through all headers for case-insensitive match
    for (const [key, value] of Object.entries(responseHeaders)) {
        if (key.toLowerCase() === lowerHeaderName) {
            return value;
        }
    }
    
    return null;
}

/**
 * Analyze header presence and determine status/recommendation
 * @param {Object} secHeader - Security header definition
 * @param {string|null} headerValue - Header value from response
 * @returns {Object} Analysis result with status and recommendation
 */
function analyzeHeaderPresence(secHeader, headerValue) {
    // Special handling for information disclosure headers
    if (secHeader.category === 'information') {
        if (headerValue) {
            return {
                status: 'present',
                recommendation: `Remove this header: "${headerValue}"`
            };
        } else {
            return {
                status: 'good',
                recommendation: 'Good - header not present'
            };
        }
    }
    
    // For all other headers, presence is generally good
    if (headerValue) {
        return {
            status: 'present',
            recommendation: secHeader.recommendation
        };
    } else {
        return {
            status: 'missing',
            recommendation: secHeader.recommendation
        };
    }
}

/**
 * Get default headers array when request fails
 * @returns {Array} Array of headers with all missing status
 */
function getDefaultHeaders() {
    return SECURITY_HEADERS.map(secHeader => ({
        name: secHeader.name,
        present: false,
        value: '',
        description: secHeader.description,
        recommendation: secHeader.recommendation,
        category: secHeader.category,
        example: secHeader.example || '',
        status: 'missing',
        score: 0
    }));
}

/**
 * Get headers summary by category
 * @param {Array} headers - Array of header analysis results
 * @returns {Object} Summary grouped by category
 */
function getHeadersSummary(headers) {
    const summary = {};
    
    headers.forEach(header => {
        if (!summary[header.category]) {
            summary[header.category] = {
                total: 0,
                present: 0,
                missing: 0,
                score: 0
            };
        }
        
        summary[header.category].total++;
        summary[header.category].score += header.score || 0;
        
        if (header.present) {
            summary[header.category].present++;
        } else {
            summary[header.category].missing++;
        }
    });
    
    return summary;
}

/**
 * Get critical and important headers that are missing
 * @param {Array} headers - Array of header analysis results
 * @returns {Object} Missing critical and important headers
 */
function getMissingCriticalHeaders(headers) {
    const missing = {
        critical: [],
        important: []
    };
    
    headers.forEach(header => {
        if (!header.present) {
            if (header.category === 'critical') {
                missing.critical.push(header);
            } else if (header.category === 'important') {
                missing.important.push(header);
            }
        }
    });
    
    return missing;
}

/**
 * Calculate headers score for overall security score
 * @param {Array} headers - Array of header analysis results
 * @returns {Object} Score calculation details
 */
function calculateHeadersScore(headers) {
    const { HEADER_SCORING } = require('./security-headers');
    
    let totalHeaderScore = 0;
    let maxHeaderScore = 0;
    
    Object.keys(HEADER_SCORING).forEach(category => {
        const categoryHeaders = headers.filter(h => h.category === category);
        const categoryScore = categoryHeaders.reduce((sum, header) => sum + (header.score || 0), 0);
        const categoryMaxScore = HEADER_SCORING[category].maxHeaders * 
            HEADER_SCORING[category].points * HEADER_SCORING[category].weight;
        
        totalHeaderScore += categoryScore * HEADER_SCORING[category].weight;
        maxHeaderScore += categoryMaxScore;
    });
    
    return {
        totalScore: totalHeaderScore,
        maxScore: maxHeaderScore,
        normalizedScore: maxHeaderScore > 0 ? Math.min(60, (totalHeaderScore / maxHeaderScore) * 60) : 0
    };
}

module.exports = {
    checkSecurityHeaders,
    analyzeResponseHeaders,
    getHeadersSummary,
    getMissingCriticalHeaders,
    calculateHeadersScore
};
