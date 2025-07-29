/**
 * Headers Checker Orchestrator
 * Coordinates all header analysis modules and provides the main interface
 */

const criticalHeaders = require('./critical-headers');
const importantHeaders = require('./important-headers');
const modernHeaders = require('./modern-headers');
const legacyHeaders = require('./legacy-headers');
const additionalHeaders = require('./additional-headers');
const deprecatedHeaders = require('./deprecated-headers');
const informationHeaders = require('./information-headers');

// Header analysis modules in order of execution
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
 * Perform comprehensive security headers analysis
 * @param {Object} responseHeaders - HTTP response headers from the target URL
 * @returns {Object} Complete headers analysis results
 */
function performCheck(responseHeaders) {
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
    if (scorePercentage >= 95) return 'A+';
    if (scorePercentage >= 85) return 'A';
    if (scorePercentage >= 75) return 'B';
    if (scorePercentage >= 65) return 'C';
    if (scorePercentage >= 50) return 'D';
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
 * Get specific header analysis result
 * @param {Object} responseHeaders - HTTP response headers
 * @param {string} headerName - Name of the header to analyze
 * @returns {Object|null} Header analysis result or null if not found
 */
function getHeaderAnalysis(responseHeaders, headerName) {
    // Find which module handles this header
    for (const module of HEADER_MODULES) {
        const results = module.performCheck(responseHeaders);
        const headerResult = results.find(h => h.name.toLowerCase() === headerName.toLowerCase());
        if (headerResult) {
            return {
                ...headerResult,
                module: module.name
            };
        }
    }
    return null;
}

/**
 * Get summary statistics for headers analysis
 * @param {Object} analysisResult - Result from performCheck
 * @returns {Object} Summary statistics
 */
function getSummary(analysisResult) {
    if (!analysisResult.success) {
        return {
            error: analysisResult.error,
            timestamp: analysisResult.timestamp
        };
    }
    
    return {
        timestamp: analysisResult.timestamp,
        duration: analysisResult.duration,
        totalHeaders: analysisResult.summary.totalHeaders,
        presentHeaders: analysisResult.summary.presentHeaders,
        missingHeaders: analysisResult.summary.missingHeaders,
        score: analysisResult.summary.score,
        maxScore: analysisResult.summary.maxScore,
        scorePercentage: analysisResult.summary.scorePercentage,
        grade: analysisResult.summary.grade,
        moduleCount: analysisResult.moduleResults.length,
        highPriorityRecommendations: analysisResult.recommendations.filter(r => r.priority === 'high').length
    };
}

module.exports = {
    performCheck,
    getHeaderAnalysis,
    getSummary,
    name: 'Security Headers Checker',
    description: 'Comprehensive security headers analysis across multiple categories',
    modules: HEADER_MODULES.map(m => ({ name: m.name, description: m.description }))
};
