/**
 * SSL Certificate Analysis Module
 * Orchestrates comprehensive SSL/TLS analysis combining certificate validation and vulnerability testing
 */

// Import modular SSL analyzer components
const sslAnalyzer = require('./ssl-analyzer');
const sslyzeIntegration = require('./sslyze-integration');
const grading = require('./grading');

/**
 * Perform comprehensive SSL certificate analysis
 * Combines basic SSL checks with optional SSLyze analysis
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} Comprehensive SSL analysis results
 */
async function performSSLAnalysis(url, options = {}) {
    console.log(`[SSL-INDEX] performSSLAnalysis called for ${url}`);
    console.log(`[SSL-INDEX] Received options:`, JSON.stringify(options, null, 2));

    const startTime = Date.now();
    const debug = options.debug || false;

    // Detect BadSSL sites and apply much shorter timeouts
    const isBadSSL = url.includes('badssl.com');
    const sslTimeout = isBadSSL ? 5000 : (options.timeout || 30000); // 5s for BadSSL, 30s for others

    const results = {
        basic: null,
        detailed: null,
        sslyze: null,
        combined: null,
        score: null,
        summary: null,
        duration: 0
    };

    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);

        // Always perform SSL certificate analysis
        if (debug) { console.log(`🔍 Performing SSL certificate analysis for ${hostname}:${port}`); }
        results.basic = await sslAnalyzer.checkSSLCertificate(url, { timeout: sslTimeout });

        // Perform detailed analysis if HTTPS
        if (urlObj.protocol === 'https:') {
            console.log(`[SSL-INDEX] About to call analyzeSSLCertificateDetailed with fast=${options.fast}`);
            if (debug) { console.log(`🔍 Performing comprehensive SSL analysis for ${hostname}:${port}`); }
            results.detailed = await sslAnalyzer.analyzeSSLCertificateDetailed(
                hostname,
                port,
                { fast: options.fast, timeout: sslTimeout }
            );
            console.log(`[SSL-INDEX] analyzeSSLCertificateDetailed completed. Enhanced: ${results.detailed?.enhanced}`);
        }

        // Optionally perform SSLyze analysis (skip if fast mode is enabled)
        if (!options.fast) {
            if (debug) { console.log(`🔍 Checking SSLyze availability...`); }
            const sslyzeAvailable = await sslyzeIntegration.checkSSLyzeAvailability();

            if (sslyzeAvailable.available) {
                if (debug) { console.log(`🔍 Running SSLyze scan for ${hostname}:${port}`); }
                const sslyzeResult = await sslyzeIntegration.runSSLyzeScan(hostname, port, { timeout: sslTimeout });

                if (sslyzeResult.success) {
                    results.sslyze = {
                        available: true,
                        data: sslyzeResult.data,
                        tests: sslyzeIntegration.convertSSLyzeToTests(sslyzeResult.data, hostname)
                    };
                } else {
                    results.sslyze = {
                        available: true,
                        error: sslyzeResult.error,
                        tests: null
                    };
                }
            } else {
                results.sslyze = {
                    available: false,
                    reason: sslyzeAvailable.error || 'SSLyze not installed',
                    recommendation: sslyzeAvailable.recommendation
                };
            }
        } else {
            if (debug) { console.log(`⚡ Fast mode enabled - skipping SSLyze analysis`); }
            results.sslyze = {
                available: false,
                reason: 'Skipped in fast mode',
                recommendation: 'Use regular mode for comprehensive analysis'
            };
        }

        // Combine results and calculate score
        results.combined = combineSSLResults(results);
        results.score = calculateSSLScore(results.combined);
        results.summary = generateSSLSummary(results);

        // Generate tests array for frontend compatibility
        results.tests = generateTestsArray(results);

    } catch (error) {
        if (debug) { console.error('SSL analysis error:', error); }
        results.error = error.message;
        results.score = {
            total: 0,
            maxScore: 100,
            percentage: 0,
            grade: 'F'
        };
    }

    results.duration = Date.now() - startTime;
    if (debug) { console.log(`✅ SSL analysis completed in ${results.duration}ms`); }

    return results;
}

/**
 * Combine SSL analysis results from different sources
 * @param {Object} results - Raw SSL analysis results
 * @returns {Object} Combined SSL analysis
 */
function combineSSLResults(results) {
    const combined = {
        basic: results.basic,
        certificate: null,
        protocol: null,
        security: null,
        vulnerabilities: [],
        recommendations: []
    };

    // Extract certificate information
    if (results.basic && results.basic.valid) {
        combined.certificate = {
            valid: results.basic.valid,
            issuer: results.basic.issuer,
            subject: results.basic.subject,
            validFrom: results.basic.validFrom,
            validTo: results.basic.validTo,
            keyLength: results.basic.keyLength,
            signatureAlgorithm: results.basic.signatureAlgorithm,
            grade: results.basic.grade
        };
    }

    // Extract protocol information
    if (results.basic) {
        combined.protocol = {
            version: results.basic.protocol,
            grade: results.basic.grade
        };
    }

    // Combine security findings from SSLyze if available
    if (results.sslyze && results.sslyze.tests) {
        const tests = results.sslyze.tests;

        // Add cipher suite analysis
        try {
            combined.cipherSuites = {
                analysis: sslyzeIntegration.getCipherSuiteSummary(tests),
                details: {
                    tls1_0Support: tests.tls1_0Support,
                    tls1_1Support: tests.tls1_1Support,
                    tls1_2Support: tests.tls1_2Support,
                    tls1_3Support: tests.tls1_3Support
                }
            };
        } catch (error) {
            console.error(`[SSL-INDEX] Error generating cipher suite summary:`, error);
            combined.cipherSuites = null;
        }

        // Check for vulnerabilities
        if (tests.heartbleed && tests.heartbleed.vulnerable) {
            combined.vulnerabilities.push({
                name: 'Heartbleed',
                severity: 'Critical',
                description: 'Server is vulnerable to Heartbleed attack'
            });
            combined.recommendations.push('Update OpenSSL to fix Heartbleed vulnerability');
        }

        if (tests.robot && tests.robot.vulnerable) {
            combined.vulnerabilities.push({
                name: 'ROBOT',
                severity: 'High',
                description: 'Server is vulnerable to ROBOT attack'
            });
            combined.recommendations.push('Update TLS implementation to fix ROBOT vulnerability');
        }

        if (tests.ccsInjection && tests.ccsInjection.vulnerable) {
            combined.vulnerabilities.push({
                name: 'CCS Injection',
                severity: 'High',
                description: 'Server is vulnerable to CCS Injection'
            });
            combined.recommendations.push('Update OpenSSL to fix CCS Injection vulnerability');
        }

        // Check protocol support
        if (tests.ssl2Support && tests.ssl2Support.supported) {
            combined.vulnerabilities.push({
                name: 'SSL 2.0 Support',
                severity: 'High',
                description: 'Server supports deprecated SSL 2.0 protocol'
            });
            combined.recommendations.push('Disable SSL 2.0 protocol support');
        }

        if (tests.ssl3Support && tests.ssl3Support.supported) {
            combined.vulnerabilities.push({
                name: 'SSL 3.0 Support',
                severity: 'Medium',
                description: 'Server supports deprecated SSL 3.0 protocol'
            });
            combined.recommendations.push('Disable SSL 3.0 protocol support');
        }
    }

    return combined;
}

/**
 * Calculate comprehensive SSL score
 * @param {Object} combinedResults - Combined SSL analysis results
 * @returns {Object} SSL score breakdown
 */
function calculateSSLScore(combinedResults) {

    const maxScore = 100;
    const breakdown = {
        certificate: 0,
        protocol: 0,
        vulnerabilities: 0,
        total: 0,
        maxScore: maxScore,
        percentage: 0,
        grade: 'F'
    };

    // Certificate score (40 points max)
    if (combinedResults.certificate && combinedResults.certificate.valid) {
        breakdown.certificate = 30; // Base score for valid certificate

        // Bonus for key strength
        if (combinedResults.certificate.keyLength >= 2048) {
            breakdown.certificate += 5;
        }

        // Bonus for signature algorithm
        if (combinedResults.certificate.signatureAlgorithm &&
            combinedResults.certificate.signatureAlgorithm.includes('SHA256')) {
            breakdown.certificate += 5;
        }
    }

    // Protocol score (30 points max)
    if (combinedResults.protocol) {
        const protocolScore = grading.scoreProtocol(combinedResults.protocol.version, [], []);
        breakdown.protocol = protocolScore;
    }

    // Vulnerability deductions (30 points max)
    breakdown.vulnerabilities = 30; // Start with full points

    if (combinedResults.vulnerabilities) {
        combinedResults.vulnerabilities.forEach(vuln => {
            switch (vuln.severity) {
                case 'Critical':
                    breakdown.vulnerabilities -= 15;
                    break;
                case 'High':
                    breakdown.vulnerabilities -= 10;
                    break;
                case 'Medium':
                    breakdown.vulnerabilities -= 5;
                    break;
                case 'Low':
                    breakdown.vulnerabilities -= 2;
                    break;
                default:
                    // Unknown severity - apply minimal deduction
                    breakdown.vulnerabilities -= 1;
                    break;
            }
        });
    }

    // Ensure no negative scores
    breakdown.vulnerabilities = Math.max(0, breakdown.vulnerabilities);

    // Calculate total
    breakdown.total = breakdown.certificate + breakdown.protocol + breakdown.vulnerabilities;
    breakdown.percentage = Math.round((breakdown.total / maxScore) * 100);
    breakdown.grade = grading.determineGrade(breakdown.total);

    return breakdown;
}

/**
 * Generate SSL analysis summary
 * @param {Object} results - Complete SSL analysis results
 * @returns {Object} SSL analysis summary
 */
function generateSSLSummary(results) {
    const summary = {
        status: 'unknown',
        message: '',
        certificateValid: false,
        vulnerabilitiesFound: 0,
        recommendations: [],
        grade: 'F'
    };

    if (results.combined) {
        summary.certificateValid = results.combined.certificate && results.combined.certificate.valid;
        summary.vulnerabilitiesFound = results.combined.vulnerabilities ? results.combined.vulnerabilities.length : 0;
        summary.recommendations = results.combined.recommendations || [];

        if (results.score) {
            summary.grade = results.score.grade;

            if (results.score.grade === 'A+' || results.score.grade === 'A') {
                summary.status = 'excellent';
                summary.message = 'Excellent SSL configuration with strong security';
            } else if (results.score.grade === 'B') {
                summary.status = 'good';
                summary.message = 'Good SSL configuration with minor areas for improvement';
            } else if (results.score.grade === 'C') {
                summary.status = 'warning';
                summary.message = 'Adequate SSL configuration but needs improvement';
            } else if (results.score.grade === 'D') {
                summary.status = 'poor';
                summary.message = 'Poor SSL configuration with significant security issues';
            } else {
                summary.status = 'fail';
                summary.message = 'Failed SSL configuration with critical security problems';
            }
        }
    }

    return summary;
}

/**
 * Generate tests array for frontend compatibility
 * @param {Object} results - SSL analysis results
 * @returns {Array} Array of test objects with name, description, status, recommendation
 */
function generateTestsArray(results) {
    const tests = [];

    // Debug log to see what results structure we have
    console.log('generateTestsArray received:', JSON.stringify(results.sslyze, null, 2));

    // Basic SSL Certificate Test
    if (results.basic) {
        tests.push({
            name: 'SSL Certificate Validity',
            description: 'Verifies that the SSL certificate is valid and properly configured',
            status: results.basic.valid ? 'pass' : 'fail',
            recommendation: results.basic.valid ? null : 'Install a valid SSL certificate from a trusted Certificate Authority'
        });

        // Certificate expiration test
        if (results.basic.validTo) {
            const expiryDate = new Date(results.basic.validTo);
            const now = new Date();
            const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));

            let status, recommendation, description;
            
            if (daysUntilExpiry < 0) {
                // Certificate has expired
                const daysExpired = Math.abs(daysUntilExpiry);
                status = 'fail';
                description = `Certificate expired ${daysExpired} days ago on ${results.basic.validTo}`;
                recommendation = 'Certificate has expired. Immediate renewal required.';
            } else if (daysUntilExpiry <= 7) {
                // Expires within a week
                status = 'fail';
                description = `Certificate expires on ${results.basic.validTo}`;
                recommendation = 'Certificate expires very soon. Immediate renewal required.';
            } else if (daysUntilExpiry <= 14) {
                // Expires within 2 weeks
                status = 'warning';
                description = `Certificate expires on ${results.basic.validTo}`;
                recommendation = 'Certificate expires soon. Plan for renewal.';
            } else if (daysUntilExpiry <= 30) {
                // Expires within a month
                status = 'warning';
                description = `Certificate expires on ${results.basic.validTo}`;
                recommendation = 'Certificate expires soon. Plan for renewal.';
            } else {
                // Certificate is valid for more than 30 days
                status = 'pass';
                description = `Certificate expires on ${results.basic.validTo}`;
                recommendation = null;
            }

            tests.push({
                name: 'Certificate Expiration',
                description: description,
                status: status,
                recommendation: recommendation
            });
        }

        // Key strength test
        if (results.basic.keyLength) {
            const keyLength = parseInt(results.basic.keyLength);
            tests.push({
                name: 'Key Strength',
                description: `Certificate uses ${keyLength}-bit key`,
                status: keyLength >= 2048 ? 'pass' : 'fail',
                recommendation: keyLength < 2048 ? 'Use at least 2048-bit RSA or 256-bit ECC keys' : null
            });
        }

        // Protocol version test
        if (results.basic.protocol) {
            const isSecureProtocol = results.basic.protocol.includes('TLS');
            tests.push({
                name: 'Protocol Security',
                description: `Server uses ${results.basic.protocol}`,
                status: isSecureProtocol ? 'pass' : 'fail',
                recommendation: !isSecureProtocol ? 'Disable SSL 2.0/3.0 and use TLS 1.2 or higher' : null
            });
        }
    }

    // Enhanced SSLyze tests
    if (results.sslyze && results.sslyze.tests) {
        const sslyzeTests = results.sslyze.tests;

        // Heartbleed vulnerability
        if (sslyzeTests.heartbleed) {
            tests.push({
                name: 'Heartbleed Vulnerability',
                description: 'Checks for the Heartbleed SSL vulnerability (CVE-2014-0160)',
                status: sslyzeTests.heartbleed.vulnerable ? 'fail' : 'pass',
                recommendation: sslyzeTests.heartbleed.vulnerable ? 'Update OpenSSL to version 1.0.1g or later' : null
            });
        }

        // ROBOT vulnerability
        if (sslyzeTests.robot) {
            tests.push({
                name: 'ROBOT Attack',
                description: 'Checks for Return of Bleichenbacher\'s Oracle Threat (ROBOT)',
                status: sslyzeTests.robot.vulnerable ? 'fail' : 'pass',
                recommendation: sslyzeTests.robot.vulnerable ? 'Update TLS implementation to fix ROBOT vulnerability' : null
            });
        }

        // CCS Injection
        if (sslyzeTests.ccsInjection) {
            tests.push({
                name: 'CCS Injection',
                description: 'Checks for ChangeCipherSpec injection vulnerability',
                status: sslyzeTests.ccsInjection.vulnerable ? 'fail' : 'pass',
                recommendation: sslyzeTests.ccsInjection.vulnerable ? 'Update OpenSSL to fix CCS injection vulnerability' : null
            });
        }

        // SSL 2.0 Support
        if (sslyzeTests.ssl2Support) {
            tests.push({
                name: 'SSL 2.0 Support',
                description: 'Checks if the deprecated SSL 2.0 protocol is supported',
                status: sslyzeTests.ssl2Support.supported ? 'fail' : 'pass',
                recommendation: sslyzeTests.ssl2Support.supported ? 'Disable SSL 2.0 protocol support' : null
            });
        }

        // SSL 3.0 Support
        if (sslyzeTests.ssl3Support) {
            tests.push({
                name: 'SSL 3.0 Support',
                description: 'Checks if the deprecated SSL 3.0 protocol is supported',
                status: sslyzeTests.ssl3Support.supported ? 'warning' : 'pass',
                recommendation: sslyzeTests.ssl3Support.supported ? 'Disable SSL 3.0 protocol support' : null
            });
        }

        // TLS 1.3 Support
        if (sslyzeTests.tls13Support) {
            tests.push({
                name: 'TLS 1.3 Support',
                description: 'Checks if the modern TLS 1.3 protocol is supported',
                status: sslyzeTests.tls13Support.supported ? 'pass' : 'warning',
                recommendation: !sslyzeTests.tls13Support.supported ? 'Consider enabling TLS 1.3 for better security and performance' : null
            });
        }
    }

    // Add vulnerability assessments from combined results
    if (results.combined && results.combined.vulnerabilities) {
        results.combined.vulnerabilities.forEach(vuln => {
            tests.push({
                name: vuln.name,
                description: vuln.description,
                status: vuln.severity === 'Critical' ? 'fail' : vuln.severity === 'High' ? 'fail' : 'warning',
                recommendation: `${vuln.severity} severity: Address this security issue`
            });
        });
    }

    return tests;
}

// Export orchestrated SSL analysis functions
module.exports = {
    // Main orchestrated analysis
    performSSLAnalysis,

    // Module metadata
    name: 'SSL Certificate Analysis Suite',
    description: 'Comprehensive SSL/TLS certificate analysis orchestrator combining custom checks and SSLyze results.'
};
