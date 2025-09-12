/**
 * SSL Certificate Grading System
 * Handles SSL/TLS grade calculation and scoring algorithms
 */

/**
 * Calculate SSL Grade with detailed explanations (Enhanced with cipher suite analysis)
 * @param {Object} cert - Certificate object
 * @param {string} protocol - TLS protocol version
 * @param {boolean} authorized - Whether certificate is authorized
 * @param {string} signatureAlgorithm - Signature algorithm
 * @param {string} authorizationError - Specific authorization error
 * @param {Object} cipherSuiteSummary - Cipher suite analysis summary
 * @returns {Object} Grade information with explanation and recommendations
 */
function calculateSSLGrade(cert, protocol, authorized, signatureAlgorithm = null, authorizationError = null, cipherSuiteSummary = null) {
    const issues = [];
    const recommendations = [];
    let score = 0;

    // Check authorization first
    if (!authorized) {
        if (authorizationError && authorizationError.includes('CERT_HAS_EXPIRED')) {
            issues.push('Certificate has expired');
            recommendations.push('Renew the SSL certificate immediately');
            return createGradeResult('F', 0, issues, recommendations, 'Certificate has expired - immediate renewal required');
        } else if (authorizationError && authorizationError.includes('HOSTNAME_MISMATCH')) {
            issues.push('Certificate hostname does not match the domain');
            recommendations.push('Obtain a certificate that includes the correct domain name');
            return createGradeResult('F', 0, issues, recommendations, 'Hostname mismatch - certificate is not valid for this domain');
        } else if (authorizationError && authorizationError.includes('SELF_SIGNED_CERT_IN_CHAIN')) {
            issues.push('Self-signed certificate in chain');
            recommendations.push('Use a certificate from a trusted Certificate Authority');
            return createGradeResult('F', 0, issues, recommendations, 'Self-signed certificate - not trusted by browsers');
        } else {
            issues.push(`Certificate authorization failed: ${authorizationError || 'Unknown error'}`);
            recommendations.push('Check certificate configuration and validity');
            return createGradeResult('F', 0, issues, recommendations, 'Certificate authorization failed');
        }
    }

    // Base score for valid certificate
    score = 25; // Reduced from 40 to make room for cipher suite scoring

    // Score TLS protocol version (0-25 points, reduced from 30)
    const protocolScore = scoreProtocol(protocol, issues, recommendations);
    score += protocolScore;

    // Score signature algorithm (0-15 points)
    const signatureScore = scoreSignatureAlgorithm(signatureAlgorithm, issues, recommendations);
    score += signatureScore;

    // Score key strength (0-15 points)
    const keyScore = scoreKeyStrength(cert, issues, recommendations);
    score += keyScore;

    // Score cipher suites (0-20 points) - NEW!
    const cipherScore = scoreCipherSuites(cipherSuiteSummary, issues, recommendations);
    score += cipherScore;

    // Determine final grade
    const grade = determineGrade(score);
    const explanation = generateGradeExplanation(grade, score, issues);

    return createGradeResult(grade, score, issues, recommendations, explanation);
}

/**
 * Score TLS protocol version
 * @param {string} protocol - TLS protocol
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Protocol score
 */
function scoreProtocol(protocol, issues, recommendations) {
    if (!protocol || protocol === 'Unknown') {
        issues.push('Unknown TLS protocol version');
        recommendations.push('Ensure server supports modern TLS protocols');
        return 0;
    }

    const protocolLower = protocol.toLowerCase();

    if (protocolLower.includes('tlsv1.3') || protocolLower.includes('tls 1.3')) {
        return 30; // Best possible score
    } else if (protocolLower.includes('tlsv1.2') || protocolLower.includes('tls 1.2')) {
        issues.push('Using TLS 1.2 (secure but not optimal)');
        recommendations.push('Consider upgrading to TLS 1.3 for enhanced security and performance');
        return 25; // Good score
    } else if (protocolLower.includes('tlsv1.1') || protocolLower.includes('tls 1.1')) {
        issues.push('Using deprecated TLS 1.1 protocol');
        recommendations.push('Upgrade to TLS 1.2 or TLS 1.3');
        return 10;
    } else if (protocolLower.includes('tlsv1') || protocolLower.includes('tls 1.0')) {
        issues.push('Using deprecated TLS 1.0 protocol');
        recommendations.push('Upgrade to TLS 1.2 or TLS 1.3');
        return 5;
    } else if (protocolLower.includes('ssl')) {
        issues.push('Using insecure SSL protocol');
        recommendations.push('Disable SSL and use TLS 1.2 or TLS 1.3 only');
        return 0;
    }

    issues.push(`Unknown or unsupported protocol: ${protocol}`);
    recommendations.push('Use TLS 1.2 or TLS 1.3');
    return 0;
}

/**
 * Score signature algorithm strength
 * @param {string} signatureAlgorithm - Signature algorithm
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Signature algorithm score
 */
function scoreSignatureAlgorithm(signatureAlgorithm, issues, recommendations) {
    if (!signatureAlgorithm || signatureAlgorithm === 'Unknown') {
        issues.push('Unknown signature algorithm');
        recommendations.push('Use modern signature algorithms (SHA-256 or better)');
        return 0;
    }

    const alg = signatureAlgorithm.toLowerCase();

    // Check for strong algorithms
    if (alg.includes('sha256') || alg.includes('sha-256')) {
        return 15; // Excellent - SHA-256 is current industry standard
    } else if (alg.includes('sha384') || alg.includes('sha-384') ||
               alg.includes('sha512') || alg.includes('sha-512')) {
        return 15; // Excellent
    } else if (alg.includes('ecdsa')) {
        return 15; // ECDSA is generally good
    }

    // Check for weak algorithms
    if (alg.includes('md5')) {
        issues.push('Using weak MD5 signature algorithm');
        recommendations.push('Upgrade to SHA-256 or better signature algorithm');
        return 0;
    } else if (alg.includes('sha1') || alg.includes('sha-1')) {
        issues.push('Using weak SHA-1 signature algorithm');
        recommendations.push('Upgrade to SHA-256 or better signature algorithm');
        return 3;
    }

    // Default for unknown but not explicitly weak algorithms
    return 8;
}

/**
 * Score key strength
 * @param {Object} cert - Certificate object
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Key strength score
 */
function scoreKeyStrength(cert, issues, recommendations) {
    const keyLength = cert.bits || 0;
    const isECC = cert.asn1Curve || cert.nistCurve || (keyLength <= 384 && keyLength >= 224);

    if (keyLength === 0) {
        issues.push('Unknown key length');
        recommendations.push('Use strong key lengths (RSA 2048+ or ECDSA 256+)');
        return 0;
    }

    if (isECC) {
        // ECDSA key scoring
        if (keyLength >= 384) {
            return 15; // P-384 or P-521
        } else if (keyLength >= 256) {
            issues.push('Using ECDSA P-256 key (secure but not optimal)');
            recommendations.push('Consider upgrading to ECDSA P-384 or P-521 for maximum security');
            return 13; // P-256
        } else {
            issues.push(`Weak ECDSA key length: ${keyLength} bits`);
            recommendations.push('Use ECDSA P-256 or stronger');
            return 5;
        }
    } else {
        // RSA key scoring
        if (keyLength >= 4096) {
            return 15; // Very strong
        } else if (keyLength >= 2048) {
            issues.push('Using RSA 2048-bit key (secure but not optimal)');
            recommendations.push('Consider upgrading to RSA 4096-bit or switching to ECDSA P-256+ for enhanced security');
            return 12; // Good
        } else if (keyLength >= 1024) {
            issues.push(`Weak RSA key length: ${keyLength} bits`);
            recommendations.push('Use RSA 2048-bit or stronger, or switch to ECDSA');
            return 5;
        } else {
            issues.push(`Very weak RSA key length: ${keyLength} bits`);
            recommendations.push('Immediate upgrade to RSA 2048-bit or ECDSA required');
            return 0;
        }
    }
}

/**
 * Determine letter grade from numerical score
 * @param {number} score - Numerical score (0-100)
 * @returns {string} Letter grade
 */
function determineGrade(score) {
    if (score >= 95) { return 'A+'; }
    if (score >= 85) { return 'A'; }
    if (score >= 75) { return 'B'; }
    if (score >= 65) { return 'C'; }
    if (score >= 50) { return 'D'; }
    return 'F';
}

/**
 * Generate grade explanation text
 * @param {string} grade - Letter grade
 * @param {number} score - Numerical score
 * @param {Array} issues - Array of issues found
 * @returns {string} Explanation text
 */
function generateGradeExplanation(grade, score, issues) {
    let explanation = `SSL Grade: ${grade} (${score}/100 points). `;

    if (grade === 'A+') {
        if (score === 100) {
            explanation += 'Perfect SSL configuration with optimal security settings.';
        } else {
            explanation += `Excellent SSL configuration with optimal security settings.`;
        }
    } else if (grade === 'A') {
        explanation += 'Excellent SSL configuration with strong security (minor optimizations possible).';
    } else if (grade === 'B') {
        explanation += 'Good SSL configuration with minor areas for improvement.';
    } else if (grade === 'C') {
        explanation += 'Adequate SSL configuration but needs improvement.';
    } else if (grade === 'D') {
        explanation += 'Poor SSL configuration with significant security issues.';
    } else {
        explanation += 'Failed SSL configuration with critical security problems.';
    }

    if (issues.length > 0) {
        // Separate security issues from optimization suggestions
        const securityIssues = issues.filter(issue =>
            !issue.includes('secure but not optimal') &&
            !issue.includes('(secure but not optimal)')
        );
        const optimizations = issues.filter(issue =>
            issue.includes('secure but not optimal') ||
            issue.includes('(secure but not optimal)')
        );

        if (securityIssues.length > 0) {
            explanation += ` Security issues: ${securityIssues.join(', ')}.`;
        }
        if (optimizations.length > 0) {
            explanation += ` Optimization opportunities: ${optimizations.join(', ')}.`;
        }
    }

    return explanation;
}

/**
 * Create standardized grade result object
 * @param {string} grade - Letter grade
 * @param {number} score - Numerical score
 * @param {Array} issues - Array of issues
 * @param {Array} recommendations - Array of recommendations
 * @param {string} explanation - Grade explanation
 * @returns {Object} Grade result object
 */
function createGradeResult(grade, score, issues, recommendations, explanation) {
    return {
        grade,
        score,
        explanation,
        recommendations,
        issues,
        breakdown: {
            baseScore: score >= 40 ? 40 : 0,
            protocolScore: score - (score >= 40 ? 40 : 0),
            maxPossibleScore: 100
        }
    };
}

/**
 * Score cipher suite configuration
 * @param {Object} cipherSuiteSummary - Cipher suite analysis summary
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Cipher suite score (0-20 points)
 */
function scoreCipherSuites(cipherSuiteSummary, issues, recommendations) {
    if (!cipherSuiteSummary || cipherSuiteSummary.totalSuites === 0) {
        issues.push('No cipher suite information available');
        recommendations.push('Ensure server supports modern cipher suites');
        return 0;
    }

    let score = 0;
    const summary = cipherSuiteSummary;

    // Penalty for insecure cipher suites (severe)
    if (summary.insecureSuites > 0) {
        issues.push(`${summary.insecureSuites} insecure cipher suite(s) detected`);
        recommendations.push('Disable all insecure cipher suites (RC4, DES, NULL ciphers)');
        score -= 10; // Heavy penalty
    }

    // Penalty for weak cipher suites (moderate)
    if (summary.weakSuites > 0) {
        issues.push(`${summary.weakSuites} weak cipher suite(s) detected`);
        recommendations.push('Replace weak cipher suites with modern alternatives');
        score -= Math.min(5, summary.weakSuites); // Penalty up to 5 points
    }

    // Bonus for secure cipher suites
    const secureRatio = summary.secureSuites / summary.totalSuites;
    if (secureRatio >= 0.8) {
        score += 8; // Most suites are secure
    } else if (secureRatio >= 0.5) {
        score += 5; // Half are secure
    } else if (summary.secureSuites > 0) {
        score += 2; // Some secure suites
    }

    // Bonus for forward secrecy support
    const fsRatio = summary.forwardSecrecySuites / summary.totalSuites;
    if (fsRatio >= 0.8) {
        score += 5; // Most suites support FS
    } else if (fsRatio >= 0.5) {
        score += 3; // Half support FS
    } else if (summary.forwardSecrecySuites > 0) {
        score += 1; // Some FS support
    } else {
        issues.push('No forward secrecy support detected');
        recommendations.push('Enable ECDHE or DHE cipher suites for forward secrecy');
    }

    // Penalty for supporting legacy protocols
    if (summary.legacyProtocols > 0) {
        issues.push(`${summary.legacyProtocols} legacy TLS protocol(s) enabled`);
        recommendations.push('Disable TLS 1.0 and TLS 1.1, use only TLS 1.2+');
        score -= Math.min(3, summary.legacyProtocols);
    }

    // Bonus for modern protocol support
    if (summary.modernProtocols >= 2) {
        score += 2; // Both TLS 1.2 and 1.3
    } else if (summary.modernProtocols === 1) {
        score += 1; // Either TLS 1.2 or 1.3
    }

    // Ensure score is within bounds
    return Math.max(0, Math.min(20, score));
}

/**
 * Enhanced grade explanation with cipher suite information
 * @param {string} grade - SSL grade
 * @param {number} score - Numeric score
 * @param {Array} issues - List of issues
 * @returns {string} Grade explanation
 */
function generateEnhancedGradeExplanation(grade, score, issues) {
    const baseExplanation = generateGradeExplanation(grade, score, issues);
    
    if (issues.some(issue => issue.includes('cipher suite'))) {
        return baseExplanation + ' Cipher suite configuration affects the security grade.';
    }
    
    return baseExplanation;
}

module.exports = {
    calculateSSLGrade,
    scoreProtocol,
    scoreCipherSuites,
    determineGrade,
    generateEnhancedGradeExplanation,

    // Module metadata
    name: 'SSL Certificate Grading System',
    description: 'SSL/TLS certificate grading, scoring, and security assessment algorithms with cipher suite analysis'
};
