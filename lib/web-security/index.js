/**
 * Web Security Checks Index
 * Exports all available web security protocol and configuration checks
 */

const httpsRedirect = require('./https-redirect');
const serverInfo = require('./server-info');
const mixedContent = require('./mixed-content');
const httpMethods = require('./http-methods');
const securityTxt = require('./security-txt');

/**
 * Registry of all available web security checks
 */
const WEB_SECURITY_CHECKS = [
    {
        id: 'https-redirect',
        module: httpsRedirect,
        enabled: true,
        weight: 2 // Higher weight for more important checks
    },
    {
        id: 'mixed-content',
        module: mixedContent,
        enabled: true,
        weight: 2
    },
    {
        id: 'http-methods',
        module: httpMethods,
        enabled: true,
        weight: 2
    },
    {
        id: 'security-txt',
        module: securityTxt,
        enabled: true,
        weight: 1
    },
    {
        id: 'server-info',
        module: serverInfo,
        enabled: true,
        weight: 1 // Lower weight for informational checks
    }
];

/**
 * Get all enabled web security checks
 * @returns {Array} Array of enabled check configurations
 */
function getEnabledChecks() {
    return WEB_SECURITY_CHECKS.filter(check => check.enabled);
}

/**
 * Perform all web security checks
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Object with checks array and score
 */
async function performWebSecurityChecks(url) {
    const checks = [];
    const enabledChecks = getEnabledChecks();

    console.log(`Running ${enabledChecks.length} web security checks...`);

    try {
        // Run all checks in parallel for better performance
        const checkPromises = enabledChecks.map(async (checkConfig) => {
            try {
                console.log(`Running ${checkConfig.module.name}...`);
                const startTime = Date.now();

                // Get the main check function using standard interface
                const checkFunction = checkConfig.module.performCheck;

                if (!checkFunction || typeof checkFunction !== 'function') {
                    throw new Error(`Module ${checkConfig.id} does not export a 'performCheck' function`);
                }

                const result = await checkFunction(url);
                const duration = Date.now() - startTime;

                // Add metadata to the result
                result.checkId = checkConfig.id;
                result.weight = checkConfig.weight;
                result.duration = duration;

                console.log(`${checkConfig.module.name} completed in ${duration}ms`);
                return result;
            } catch (error) {
                console.error(`Error in ${checkConfig.id} check:`, error.message);

                // Return a safe fallback result
                return {
                    checkId: checkConfig.id,
                    name: checkConfig.module.name || checkConfig.id,
                    status: 'info',
                    description: checkConfig.module.description || 'Additional security check',
                    details: `Check failed: ${error.message}`,
                    score: 0,
                    maxScore: 2,
                    weight: checkConfig.weight,
                    recommendation: 'Manual verification recommended',
                    duration: 0
                };
            }
        });

        // Wait for all checks to complete
        const results = await Promise.all(checkPromises);
        checks.push(...results);

    } catch (error) {
        console.error('Additional checks error:', error);
    }

    const score = calculateWebSecurityScore(checks);

    return {
        checks: checks,
        score: score,
        summary: getWebSecuritySummary(checks)
    };
}

/**
 * Calculate web security checks score using weighted scoring
 * @param {Array} webSecurityChecks - Array of web security check results
 * @returns {Object} Score object with detailed metrics
 */
function calculateWebSecurityScore(webSecurityChecks) {
    let totalWeightedScore = 0;
    let totalWeightedMaxScore = 0;
    let passedChecks = 0;
    let failedChecks = 0;
    let warningChecks = 0;
    let infoChecks = 0;

    webSecurityChecks.forEach(check => {
        const weight = check.weight || 1;
        const score = check.score || 0;
        const maxScore = check.maxScore || 2;

        totalWeightedScore += score * weight;
        totalWeightedMaxScore += maxScore * weight;

        // Count by status
        switch (check.status) {
            case 'pass':
                passedChecks++;
                break;
            case 'fail':
                failedChecks++;
                break;
            case 'warning':
                warningChecks++;
                break;
            case 'info':
                infoChecks++;
                break;
            default:
                // Unknown status - count as info
                infoChecks++;
                break;
        }
    });

    const percentageScore = totalWeightedMaxScore > 0 ?
        (totalWeightedScore / totalWeightedMaxScore) * 100 : 0;

    return {
        score: totalWeightedScore,
        maxScore: totalWeightedMaxScore,
        percentage: Math.round(percentageScore * 10) / 10, // Round to 1 decimal
        passed: passedChecks,
        failed: failedChecks,
        warnings: warningChecks,
        info: infoChecks,
        total: webSecurityChecks.length
    };
}

/**
 * Get summary of web security checks by status
 * @param {Array} webSecurityChecks - Array of web security check results
 * @returns {Object} Summary grouped by status with details
 */
function getWebSecuritySummary(webSecurityChecks) {
    const summary = {
        pass: [],
        warning: [],
        info: [],
        fail: []
    };

    webSecurityChecks.forEach(check => {
        const status = check.status || 'info';
        if (summary[status]) {
            summary[status].push({
                name: check.name,
                checkId: check.checkId,
                score: check.score,
                maxScore: check.maxScore,
                details: check.details,
                recommendation: check.recommendation,
                duration: check.duration
            });
        }
    });

    // Add counts for each status
    summary.counts = {
        pass: summary.pass.length,
        warning: summary.warning.length,
        info: summary.info.length,
        fail: summary.fail.length,
        total: webSecurityChecks.length
    };

    return summary;
}

module.exports = {
    // Main orchestrated analysis
    performWebSecurityChecks,

    // Module metadata
    name: 'Web Security Checker',
    description: 'Comprehensive web security protocol and configuration analysis'
};