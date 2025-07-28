/**
 * Scoring System Module
 * Handles overall security score calculation and grade assignment
 */

/**
 * Security scoring weights for different categories
 */
const SCORING_WEIGHTS = {
    ssl: 0.30, // 30% - SSL/TLS security
    headers: 0.40, // 40% - Security headers
    additional: 0.20, // 20% - Additional security checks
    accessibility: 0.10 // 10% - Basic accessibility/connectivity
};

/**
 * Grade thresholds for overall security score
 */
const GRADE_THRESHOLDS = {
    'A+': 95,
    'A': 85,
    'B': 75,
    'C': 65,
    'D': 55,
    'F': 0
};

/**
 * Risk level mappings
 */
const RISK_LEVELS = {
    'A+': 'Very Low',
    'A': 'Low',
    'B': 'Medium',
    'C': 'High',
    'D': 'Very High',
    'F': 'Critical'
};

/**
 * Calculate overall security score from component scores
 * @param {Object} scores - Component scores object with score and maxScore properties
 * @returns {Object} Overall score calculation result
 */
function calculateOverallScore(scores) {
    const {
        ssl = { score: 0, maxScore: 100 },
        headers = { score: 0, maxScore: 100 },
        additional = { score: 0, maxScore: 10 },
        accessibility = { score: 10, maxScore: 10 }
    } = scores;

    // Normalize all scores to 0-100 scale using their respective maxScores
    const normalizedScores = {
        ssl: Math.max(0, Math.min(100, (ssl.score / ssl.maxScore) * 100)),
        headers: Math.max(0, Math.min(100, (headers.score / headers.maxScore) * 100)),
        additional: Math.max(0, Math.min(100, (additional.score / additional.maxScore) * 100)),
        accessibility: Math.max(0, Math.min(100, (accessibility.score / accessibility.maxScore) * 100))
    };

    // Calculate weighted score
    const weightedScore =
        (normalizedScores.ssl * SCORING_WEIGHTS.ssl) +
        (normalizedScores.headers * SCORING_WEIGHTS.headers) +
        (normalizedScores.additional * SCORING_WEIGHTS.additional) +
        (normalizedScores.accessibility * SCORING_WEIGHTS.accessibility);

    const roundedScore = Math.round(weightedScore);

    return {
        overallScore: roundedScore,
        componentScores: normalizedScores,
        rawScores: {
            ssl: ssl,
            headers: headers,
            additional: additional,
            accessibility: accessibility
        },
        weights: SCORING_WEIGHTS,
        breakdown: {
            ssl: Math.round(normalizedScores.ssl * SCORING_WEIGHTS.ssl),
            headers: Math.round(normalizedScores.headers * SCORING_WEIGHTS.headers),
            additional: Math.round(normalizedScores.additional * SCORING_WEIGHTS.additional),
            accessibility: Math.round(normalizedScores.accessibility * SCORING_WEIGHTS.accessibility)
        }
    };
}

/**
 * Assign letter grade based on numerical score
 * @param {number} score - Numerical score (0-100)
 * @returns {string} Letter grade
 */
function assignGrade(score) {
    for (const [grade, threshold] of Object.entries(GRADE_THRESHOLDS)) {
        if (score >= threshold) {
            return grade;
        }
    }
    return 'F';
}

/**
 * Get risk level based on grade
 * @param {string} grade - Letter grade
 * @returns {string} Risk level description
 */
function getRiskLevel(grade) {
    return RISK_LEVELS[grade] || 'Unknown';
}

/**
 * Generate comprehensive security assessment
 * @param {Object} scores - Component scores
 * @param {Object} results - Detailed results from each check
 * @returns {Object} Complete security assessment
 */
function generateSecurityAssessment(scores, results = {}) {
    const scoreCalculation = calculateOverallScore(scores);
    const grade = assignGrade(scoreCalculation.overallScore);
    const riskLevel = getRiskLevel(grade);

    // Generate summary statistics
    const summary = generateSummary(results);

    // Generate recommendations
    const recommendations = generateRecommendations(scores, results, grade);

    // Calculate improvement potential
    const improvement = calculateImprovementPotential(scores);

    return {
        score: scoreCalculation.overallScore,
        grade: grade,
        riskLevel: riskLevel,
        scoreBreakdown: scoreCalculation,
        summary: summary,
        recommendations: recommendations,
        improvement: improvement,
        timestamp: new Date().toISOString(),
        version: '1.0'
    };
}

/**
 * Generate summary statistics from results
 * @param {Object} results - Results from security checks
 * @returns {Object} Summary statistics
 */
function generateSummary(results) {
    const summary = {
        total: 0,
        passed: 0,
        warnings: 0,
        failed: 0,
        info: 0,
        categories: {}
    };

    // Count SSL results
    if (results.ssl) {
        summary.categories.ssl = {
            total: 1,
            passed: results.ssl.grade && ['A+', 'A', 'B'].includes(results.ssl.grade) ? 1 : 0,
            failed: results.ssl.grade && ['D', 'F'].includes(results.ssl.grade) ? 1 : 0,
            warnings: results.ssl.grade === 'C' ? 1 : 0
        };
        summary.total += 1;
        summary.passed += summary.categories.ssl.passed;
        summary.failed += summary.categories.ssl.failed;
        summary.warnings += summary.categories.ssl.warnings;
    }

    // Count headers results
    if (results.headers && Array.isArray(results.headers)) {
        const headerStats = countResultsByStatus(results.headers);
        summary.categories.headers = headerStats;
        summary.total += headerStats.total;
        summary.passed += headerStats.passed;
        summary.warnings += headerStats.warnings;
        summary.failed += headerStats.failed;
        summary.info += headerStats.info;
    }

    // Count additional checks results
    if (results.additional && Array.isArray(results.additional)) {
        const additionalStats = countResultsByStatus(results.additional);
        summary.categories.additional = additionalStats;
        summary.total += additionalStats.total;
        summary.passed += additionalStats.passed;
        summary.warnings += additionalStats.warnings;
        summary.failed += additionalStats.failed;
        summary.info += additionalStats.info;
    }

    return summary;
}

/**
 * Count results by status
 * @param {Array} results - Array of result objects with status property
 * @returns {Object} Count by status
 */
function countResultsByStatus(results) {
    const counts = {
        total: results.length,
        passed: 0,
        warnings: 0,
        failed: 0,
        info: 0
    };

    results.forEach(result => {
        switch (result.status) {
            case 'pass':
                counts.passed++;
                break;
            case 'warning':
                counts.warnings++;
                break;
            case 'fail':
                counts.failed++;
                break;
            case 'info':
                counts.info++;
                break;
            default:
                // Unknown status, could be logged if needed
                break;
        }
    });

    return counts;
}

/**
 * Generate personalized recommendations based on results
 * @param {Object} scores - Component scores
 * @param {Object} results - Detailed results
 * @param {string} grade - Overall grade
 * @returns {Array} Array of recommendation objects
 */
function generateRecommendations(scores, results, grade) {
    const recommendations = [];

    // SSL/TLS recommendations
    if (scores.ssl < 8) {
        recommendations.push({
            category: 'SSL/TLS',
            priority: 'High',
            description: 'Improve SSL/TLS configuration',
            details: 'Consider updating to newer TLS versions, stronger ciphers, or addressing certificate issues'
        });
    }

    // Headers recommendations
    if (scores.headers < 8) {
        const missingHeaders = getMissingCriticalHeaders(results.headers);
        if (missingHeaders.length > 0) {
            recommendations.push({
                category: 'Security Headers',
                priority: 'High',
                description: `Implement missing critical security headers`,
                details: `Missing: ${missingHeaders.join(', ')}`
            });
        }
    }

    // Additional checks recommendations
    if (scores.additional < 7) {
        recommendations.push({
            category: 'Additional Security',
            priority: 'Medium',
            description: 'Address additional security concerns',
            details: 'Review HTTPS redirects, HTTP methods, and other security configurations'
        });
    }

    // Grade-specific recommendations
    if (grade === 'F') {
        recommendations.unshift({
            category: 'Critical',
            priority: 'Critical',
            description: 'Immediate security attention required',
            details: 'Multiple critical security issues found. Prioritize SSL/TLS and security headers implementation.'
        });
    } else if (['D', 'C'].includes(grade)) {
        recommendations.push({
            category: 'General',
            priority: 'Medium',
            description: 'Security posture needs improvement',
            details: 'Focus on implementing security best practices and addressing identified vulnerabilities'
        });
    }

    return recommendations;
}

/**
 * Get list of missing critical headers
 * @param {Array} headersResults - Headers check results
 * @returns {Array} Array of missing critical header names
 */
function getMissingCriticalHeaders(headersResults) {
    if (!Array.isArray(headersResults)) { return []; }

    const criticalHeaders = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options'
    ];

    const foundHeaders = headersResults
        .filter(result => result.status === 'pass')
        .map(result => result.name);

    return criticalHeaders.filter(header => !foundHeaders.includes(header));
}

/**
 * Calculate improvement potential
 * @param {Object} scores - Current component scores with score and maxScore objects
 * @returns {Object} Improvement analysis
 */
function calculateImprovementPotential(scores) {
    const maxScores = {
        ssl: { score: scores.ssl.maxScore, maxScore: scores.ssl.maxScore },
        headers: { score: scores.headers.maxScore, maxScore: scores.headers.maxScore },
        additional: { score: scores.additional.maxScore, maxScore: scores.additional.maxScore },
        accessibility: { score: scores.accessibility.maxScore, maxScore: scores.accessibility.maxScore }
    };

    const currentTotal = calculateOverallScore(scores).overallScore;
    const maxPossible = calculateOverallScore(maxScores).overallScore;
    const improvementPotential = maxPossible - currentTotal;

    // Identify areas with highest improvement potential
    const improvements = [];

    Object.entries(scores).forEach(([category, scoreObj]) => {
        const currentScore = scoreObj.score;
        const maxScore = scoreObj.maxScore;
        const potential = maxScore - currentScore;
        const weight = SCORING_WEIGHTS[category] || 0.1;
        const normalizedPotential = (potential / maxScore) * 100; // Normalize to 0-100
        const weightedPotential = normalizedPotential * weight;

        if (normalizedPotential > 20) { // More than 20% improvement possible
            improvements.push({
                category: category,
                currentScore: currentScore,
                maxScore: maxScore,
                potential: potential,
                normalizedPotential: Math.round(normalizedPotential),
                weightedPotential: Math.round(weightedPotential),
                priority: weightedPotential > 10 ? 'High' : weightedPotential > 5 ? 'Medium' : 'Low'
            });
        }
    });

    // Sort by weighted potential (highest first)
    improvements.sort((a, b) => b.weightedPotential - a.weightedPotential);

    return {
        totalPotential: Math.round(improvementPotential),
        maxPossibleScore: Math.round(maxPossible),
        improvements: improvements,
        quickWins: improvements.filter(imp => imp.normalizedPotential <= 30 && imp.weightedPotential > 3)
    };
}

/**
 * Get grade color for UI display
 * @param {string} grade - Letter grade
 * @returns {string} Color code or name
 */
function getGradeColor(grade) {
    const colors = {
        'A+': '#00C851', // Green
        'A': '#2E7D32', // Dark Green
        'B': '#FFA726', // Orange
        'C': '#FF7043', // Deep Orange
        'D': '#F44336', // Red
        'F': '#B71C1C' // Dark Red
    };

    return colors[grade] || '#9E9E9E'; // Gray for unknown
}

/**
 * Format score for display
 * @param {number} score - Numerical score
 * @param {boolean} includeGrade - Whether to include letter grade
 * @returns {string} Formatted score string
 */
function formatScore(score, includeGrade = true) {
    const grade = assignGrade(score);
    const formattedScore = Math.round(score);

    if (includeGrade) {
        return `${formattedScore}/100 (${grade})`;
    } else {
        return `${formattedScore}/100`;
    }
}

module.exports = {
    SCORING_WEIGHTS,
    GRADE_THRESHOLDS,
    RISK_LEVELS,
    calculateOverallScore,
    assignGrade,
    getRiskLevel,
    generateSecurityAssessment,
    generateSummary,
    generateRecommendations,
    calculateImprovementPotential,
    getGradeColor,
    formatScore
};
