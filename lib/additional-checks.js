/**
 * Additional Security Checks Module
 * Orchestrates all additional security checks using modular approach
 */

const { getEnabledChecks, getTotalMaxScore } = require('./additional-checks/index.js');

/**
 * Perform all additional security checks
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Object with checks array and score
 */
async function performAdditionalChecks(url) {
    const checks = [];
    const enabledChecks = getEnabledChecks();

    console.log(`Running ${enabledChecks.length} additional security checks...`);

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

    const score = calculateAdditionalChecksScore(checks);

    return {
        checks: checks,
        score: score,
        summary: getAdditionalChecksSummary(checks)
    };
}

/**
 * Calculate additional checks score using weighted scoring
 * @param {Array} additionalChecks - Array of additional check results
 * @returns {Object} Score object with detailed metrics
 */
function calculateAdditionalChecksScore(additionalChecks) {
    let totalWeightedScore = 0;
    let totalWeightedMaxScore = 0;
    let passedChecks = 0;
    let failedChecks = 0;
    let warningChecks = 0;
    let infoChecks = 0;

    additionalChecks.forEach(check => {
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
        total: additionalChecks.length
    };
}

/**
 * Get summary of additional checks by status
 * @param {Array} additionalChecks - Array of additional check results
 * @returns {Object} Summary grouped by status with details
 */
function getAdditionalChecksSummary(additionalChecks) {
    const summary = {
        pass: [],
        warning: [],
        info: [],
        fail: []
    };

    additionalChecks.forEach(check => {
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
        total: additionalChecks.length
    };

    return summary;
}

module.exports = {
    performAdditionalChecks,
    calculateAdditionalChecksScore,
    getAdditionalChecksSummary
};
