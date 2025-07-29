/**
 * Additional Security Checks Index
 * Exports all available additional security checks
 */

const httpsRedirect = require('./https-redirect');
const serverInfo = require('./server-info');
const mixedContent = require('./mixed-content');
const httpMethods = require('./http-methods');
const securityTxt = require('./security-txt');

/**
 * Registry of all available additional security checks
 */
const ADDITIONAL_CHECKS = [
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
 * Get all enabled additional checks
 * @returns {Array} Array of enabled check configurations
 */
function getEnabledChecks() {
    return ADDITIONAL_CHECKS.filter(check => check.enabled);
}

/**
 * Get check by ID
 * @param {string} checkId - The check ID
 * @returns {Object|null} Check configuration or null if not found
 */
function getCheckById(checkId) {
    return ADDITIONAL_CHECKS.find(check => check.id === checkId) || null;
}

/**
 * Get total maximum score for all enabled checks
 * @returns {number} Total maximum score
 */
function getTotalMaxScore() {
    return getEnabledChecks().reduce((total, check) => {
        // Assume each check has a maxScore of 2 by default, weight it accordingly
        const maxScore = check.module.maxScore || 2;
        return total + (maxScore * check.weight);
    }, 0);
}

module.exports = {
    ADDITIONAL_CHECKS,
    getEnabledChecks,
    getCheckById,
    getTotalMaxScore,
    
    // Export individual check modules for direct access
    httpsRedirect,
    serverInfo,
    mixedContent,
    httpMethods,
    securityTxt
};
