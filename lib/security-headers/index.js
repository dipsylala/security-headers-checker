/**
 * Security Headers Orchestrator
 * Combines configuration, analysis, and scoring logic for comprehensive header security analysis
 *
 * ARCHITECTURE:
 * - checkSecurityHeaders(url): Main interface - fetches headers and analyzes them
 * - analyzeHeaders(headers): Internal function - analyzes already-retrieved headers
 * - getAllHeaders(): Configuration interface - returns header definitions
 */

const https = require('https');
const http = require('http');
const criticalHeaders = require('./critical-headers');
const importantHeaders = require('./important-headers');
const modernHeaders = require('./modern-headers');
const legacyHeaders = require('./legacy-headers');
const additionalHeaders = require('./additional-headers');
const deprecatedHeaders = require('./deprecated-headers');
const informationHeaders = require('./information-headers');

// Header modules in order of priority
const HEADER_MODULES = [
    criticalHeaders,
    importantHeaders,
    modernHeaders,
    legacyHeaders,
    additionalHeaders,
    deprecatedHeaders,
    informationHeaders
];

/**
 * Get all security headers from all modules
 * @returns {Array} Complete list of all security headers
 */
function getAllHeaders() {
    const allHeaders = [];

    // Since header modules now use performCheck instead of headers array,
    // we need to simulate getting headers by running performCheck with empty headers
    HEADER_MODULES.forEach(module => {
        try {
            if (module.performCheck && typeof module.performCheck === 'function') {
                // Get header definitions by running performCheck with empty headers
                const mockHeaders = {};
                const headerResults = module.performCheck(mockHeaders);

                // Convert results back to header definitions
                headerResults.forEach(result => {
                    allHeaders.push({
                        name: result.name,
                        description: result.description,
                        recommendation: result.recommendation,
                        category: result.category,
                        example: result.example || ''
                    });
                });
            } else if (module.headers && Array.isArray(module.headers)) {
                // Fallback for old-style modules with headers array
                allHeaders.push(...module.headers);
            }
        } catch (error) {
            console.warn(`Error getting headers from module ${module.name}:`, error.message);
        }
    });

    return allHeaders;
}

/**
 * Perform comprehensive security headers analysis on already-retrieved headers
 * Internal function - used by checkSecurityHeaders after fetching headers
 * @param {Object} responseHeaders - HTTP response headers from the target URL
 * @returns {Object} Complete headers analysis results
 */
function analyzeHeaders(responseHeaders) {
    const startTime = Date.now();

    try {
        // Run all header module checks
        const moduleResults = [];
        const allHeaderResults = [];

        for (const module of HEADER_MODULES) {
            const moduleStartTime = Date.now();
            const headerResults = module.performCheck(responseHeaders);
            const moduleEndTime = Date.now();

            moduleResults.push({
                name: module.name,
                description: module.description,
                results: headerResults,
                duration: moduleEndTime - moduleStartTime,
                headerCount: headerResults.length,
                presentCount: headerResults.filter(h => h.present).length
            });

            allHeaderResults.push(...headerResults);
        }

        // Calculate overall statistics
        const totalHeaders = allHeaderResults.length;
        const presentHeaders = allHeaderResults.filter(h => h.present).length;
        const missingHeaders = totalHeaders - presentHeaders;
        const totalScore = allHeaderResults.reduce((sum, header) => sum + header.score, 0);
        const maxScore = allHeaderResults.length * 15; // Assuming max 15 points per header
        const scorePercentage = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

        // Categorize headers by status
        const headersByCategory = {};
        const headersByStatus = {
            present: allHeaderResults.filter(h => h.present),
            missing: allHeaderResults.filter(h => !h.present)
        };

        allHeaderResults.forEach(header => {
            if (!headersByCategory[header.category]) {
                headersByCategory[header.category] = [];
            }
            headersByCategory[header.category].push(header);
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        return {
            success: true,
            timestamp: new Date().toISOString(),
            duration: duration,
            summary: {
                totalHeaders: totalHeaders,
                presentHeaders: presentHeaders,
                missingHeaders: missingHeaders,
                score: totalScore,
                maxScore: maxScore,
                scorePercentage: scorePercentage,
                grade: getSecurityGrade(scorePercentage)
            },
            moduleResults: moduleResults,
            headersByCategory: headersByCategory,
            headersByStatus: headersByStatus,
            allHeaders: allHeaderResults,
            recommendations: generateRecommendations(allHeaderResults)
        };

    } catch (error) {
        console.error('Headers analysis error:', error);
        return {
            success: false,
            error: error.message,
            timestamp: new Date().toISOString(),
            duration: Date.now() - startTime
        };
    }
}

/**
 * Get security grade based on score percentage
 * @param {number} scorePercentage - Score as percentage (0-100)
 * @returns {string} Security grade (A+, A, B, C, D, F)
 */
function getSecurityGrade(scorePercentage) {
    if (scorePercentage >= 95) { return 'A+'; }
    if (scorePercentage >= 85) { return 'A'; }
    if (scorePercentage >= 75) { return 'B'; }
    if (scorePercentage >= 65) { return 'C'; }
    if (scorePercentage >= 50) { return 'D'; }
    return 'F';
}

/**
 * Generate recommendations based on missing headers
 * @param {Array} allHeaders - All header analysis results
 * @returns {Array} Array of recommendations
 */
function generateRecommendations(allHeaders) {
    const recommendations = [];

    // Priority recommendations for missing critical headers
    const missingCritical = allHeaders.filter(h => h.category === 'critical' && !h.present);
    missingCritical.forEach(header => {
        recommendations.push({
            priority: 'high',
            category: header.category,
            header: header.name,
            issue: `Missing critical security header: ${header.name}`,
            recommendation: header.recommendation,
            impact: 'High security risk'
        });
    });

    // Important headers recommendations
    const missingImportant = allHeaders.filter(h => h.category === 'important' && !h.present);
    missingImportant.forEach(header => {
        recommendations.push({
            priority: 'medium',
            category: header.category,
            header: header.name,
            issue: `Missing important security header: ${header.name}`,
            recommendation: header.recommendation,
            impact: 'Medium security risk'
        });
    });

    // Information disclosure warnings
    const informationHeaders = allHeaders.filter(h => h.category === 'information' && h.present);
    informationHeaders.forEach(header => {
        recommendations.push({
            priority: 'low',
            category: header.category,
            header: header.name,
            issue: `Information disclosure header present: ${header.name}`,
            recommendation: header.recommendation,
            impact: 'Information disclosure risk'
        });
    });

    return recommendations;
}

/**
 * Check security headers for a given URL - MAIN INTERFACE
 * Fetches headers from the URL and performs comprehensive security analysis
 * @param {string} url - The URL to check
 * @param {number} redirectCount - Internal redirect counter
 * @returns {Promise<Object>} Object with headers array and score
 */
function checkSecurityHeaders(url, redirectCount = 0) {
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
            if (resolved) { return; }

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
            // Use the modular headers checker
            const result = analyzeHeaders(response.headers);
            if (result.success) {
                resolve({
                    headers: result.allHeaders,
                    score: result.summary,
                    moduleResults: result.moduleResults,
                    recommendations: result.recommendations
                });
            } else {
                const defaultHeaders = getDefaultHeaders();
                resolve({
                    headers: defaultHeaders,
                    score: { score: 0, maxScore: 0, scorePercentage: 0 }
                });
            }
        });

        request.on('error', (error) => {
            if (resolved) { return; }
            resolved = true;

            console.error('Headers check error:', error);
            const defaultHeaders = getDefaultHeaders();
            resolve({
                headers: defaultHeaders,
                score: { score: 0, maxScore: 0, scorePercentage: 0 }
            });
        });

        request.on('timeout', () => {
            if (resolved) { return; }
            resolved = true;

            console.error('Headers check timeout');
            request.destroy();
            const defaultHeaders = getDefaultHeaders();
            resolve({
                headers: defaultHeaders,
                score: { score: 0, maxScore: 0, scorePercentage: 0 }
            });
        });

        request.end();
    });
}

/**
 * Get default headers array when request fails
 * @returns {Array} Array of headers with all missing status
 */
function getDefaultHeaders() {
    const SECURITY_HEADERS = getAllHeaders();
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

module.exports = {
    // Main interface function (replaces headers-checker)
    checkSecurityHeaders,

    // Module metadata
    name: 'Security Headers Analyzer',
    description: 'Comprehensive security headers configuration, analysis, and scoring system',
    modules: HEADER_MODULES.map(m => ({ name: m.name, description: m.description, category: m.category || 'unknown' }))
};
