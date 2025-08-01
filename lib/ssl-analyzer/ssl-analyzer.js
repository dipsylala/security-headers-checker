/**
 * Unified SSL Analyzer
 * Comprehensive SSL/TLS security analysis combining certificate validation and vulnerability testing
 */

const tls = require('tls');
const logger = require('../logger');
const { determineKeyAlgorithm } = require('./certificate-parser');
const { checkSSLyzeAvailability, runSSLyzeScan, convertSSLyzeToTests } = require('./sslyze-integration');
/**
 * Analyze SSL certificate and security configuration
 * @param {string} url - The URL to check SSL certificate for
 * @param {Object} options - Options including timeout
 * @returns {Promise<Object>} Comprehensive SSL analysis results
 */
function checkSSLCertificate(url, options = {}) {
    return new Promise((resolve) => {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;
            const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);

            if (urlObj.protocol !== 'https:' || (port !== 443 && port !== 8443)) {
                resolve({
                    valid: false,
                    error: 'SSL check only available for HTTPS ports',
                    issuer: 'N/A',
                    subject: url,
                    validFrom: null,
                    validTo: null,
                    keyLength: 0,
                    signatureAlgorithm: 'N/A',
                    protocol: 'N/A',
                    grade: 'F',
                    score: 0,
                    gradeExplanation: 'SSL certificate analysis is only available for HTTPS connections (ports 443, 8443)',
                    recommendations: ['Use HTTPS instead of HTTP', 'Ensure the website supports SSL/TLS encryption']
                });
                return;
            }

            // Detect BadSSL sites for timeout handling
            const isBadSSL = url.includes('badssl.com');
            const connectionTimeout = isBadSSL ? 3000 : (options.timeout || 10000); // 3s for BadSSL, 10s default

            const tlsOptions = {
                host: hostname,
                port: port,
                rejectUnauthorized: false,
                servername: hostname,
                timeout: connectionTimeout
            };

            const socket = tls.connect(tlsOptions, () => {
                try {
                    const cert = socket.getPeerCertificate(true);
                    const protocol = socket.getProtocol();

                    // Extract signature algorithm
                    const { extractSignatureAlgorithm } = require('./certificate-parser');
                    const { calculateSSLGrade } = require('./grading');
                    const { logCertificateDebugInfo } = require('./utils');

                    const signatureAlgorithm = extractSignatureAlgorithm(cert);
                    logCertificateDebugInfo(cert, signatureAlgorithm);

                    // Determine key algorithm
                    const keyAlgorithm = determineKeyAlgorithm(cert);

                    // Extract certificate chain
                    const certificateChain = extractCertificateChain(cert);

                    const gradeInfo = calculateSSLGrade(cert,
                        protocol,
                        socket.authorized,
                        signatureAlgorithm,
                        socket.authorizationError);

                    resolve({
                        valid: socket.authorized,
                        error: socket.authorized ? null : socket.authorizationError,
                        issuer: cert.issuer ? cert.issuer.CN || cert.issuer.O || 'Unknown' : 'Unknown',
                        subject: cert.subject ? cert.subject.CN || hostname : hostname,
                        validFrom: cert.valid_from || null,
                        validTo: cert.valid_to || null,
                        keyLength: cert.bits || 0,
                        keyAlgorithm: keyAlgorithm,
                        signatureAlgorithm: signatureAlgorithm,
                        protocol: protocol || 'Unknown',
                        serialNumber: cert.serialNumber || 'Unknown',
                        fingerprint: cert.fingerprint || 'Unknown',
                        certificateChain: certificateChain,
                        grade: gradeInfo.grade,
                        score: gradeInfo.score || 0,
                        gradeExplanation: gradeInfo.explanation,
                        recommendations: gradeInfo.recommendations
                    });

                    socket.end();
                } catch (error) {
                    const gradeInfo = {
                        grade: 'F',
                        explanation: error.message,
                        recommendations: ['Fix SSL certificate configuration']
                    };

                    resolve({
                        valid: false,
                        error: error.message,
                        issuer: 'Unknown',
                        subject: hostname,
                        validFrom: null,
                        validTo: null,
                        keyLength: 0,
                        keyAlgorithm: 'Unknown',
                        signatureAlgorithm: 'Unknown',
                        protocol: 'Unknown',
                        grade: gradeInfo.grade,
                        score: 0,
                        gradeExplanation: gradeInfo.explanation,
                        recommendations: gradeInfo.recommendations
                    });
                    socket.end();
                }
            });

            socket.on('error', (error) => {
                const gradeInfo = {
                    grade: 'F',
                    explanation: `Connection error: ${error.message}`,
                    recommendations: ['Check if the website supports HTTPS', 'Verify the hostname is correct']
                };

                resolve({
                    valid: false,
                    error: error.message,
                    issuer: 'Unknown',
                    subject: hostname,
                    validFrom: null,
                    validTo: null,
                    keyLength: 0,
                    keyAlgorithm: 'Unknown',
                    signatureAlgorithm: 'Unknown',
                    protocol: 'Unknown',
                    grade: gradeInfo.grade,
                    score: 0,
                    gradeExplanation: gradeInfo.explanation,
                    recommendations: gradeInfo.recommendations
                });
            });

            socket.setTimeout(10000, () => {
                socket.destroy();
                const gradeInfo = {
                    grade: 'F',
                    explanation: 'Connection timeout - server did not respond within 10 seconds',
                    recommendations: ['Check if the server is online', 'Verify firewall settings allow HTTPS connections']
                };

                resolve({
                    valid: false,
                    error: 'Connection timeout',
                    issuer: 'Unknown',
                    subject: hostname,
                    validFrom: null,
                    validTo: null,
                    keyLength: 0,
                    keyAlgorithm: 'Unknown',
                    signatureAlgorithm: 'Unknown',
                    protocol: 'Unknown',
                    grade: gradeInfo.grade,
                    score: 0,
                    gradeExplanation: gradeInfo.explanation,
                    recommendations: gradeInfo.recommendations
                });
            });

        } catch (urlError) {
            resolve({
                valid: false,
                error: `Invalid URL: ${urlError.message}`,
                issuer: 'N/A',
                subject: url,
                validFrom: null,
                validTo: null,
                keyLength: 0,
                keyAlgorithm: 'N/A',
                signatureAlgorithm: 'N/A',
                protocol: 'N/A',
                grade: 'F',
                score: 0,
                gradeExplanation: 'Invalid URL provided for SSL analysis',
                recommendations: ['Provide a valid HTTPS URL']
            });
        }
    });
}

/**
 * Perform comprehensive SSL analysis with vulnerability testing
 * @param {string} hostname - The hostname to analyze
 * @param {number} port - The port number (default 443)
 * @param {Object} options - Options including fast mode
 * @returns {Promise<Object>} Comprehensive SSL analysis results including vulnerability tests
 */
async function analyzeSSLCertificateDetailed(hostname, port = 443, options = {}) {
    logger.info(`Analyzing SSL certificate for ${hostname}:${port}`);
    logger.info(`SSL analysis options: fast=${options.fast}`);

    try {
        // Skip SSLyze if fast mode is enabled
        if (options.fast) {
            logger.info(`Fast mode enabled - using basic SSL analysis for ${hostname}:${port}`);
            const basicResult = await checkSSLCertificate(`https://${hostname}:${port}`, options);

            return {
                hostname: hostname,
                port: port,
                enhanced: false,
                fastMode: true,
                basicResult: basicResult,
                summary: {
                    totalTests: 1,
                    passedTests: basicResult.valid ? 1 : 0,
                    failedTests: basicResult.valid ? 0 : 1,
                    warningTests: 0,
                    totalScore: basicResult.score || 0,
                    maxScore: 100
                }
            };
        }

        logger.info(`Full SSL analysis mode enabled - running comprehensive SSLyze analysis for ${hostname}:${port}`);
        // Check if SSLyze is available for enhanced analysis
        const sslyzeAvailable = await checkSSLyzeAvailability();

        if (sslyzeAvailable.available) {
            logger.info(`Using SSLyze for comprehensive SSL analysis of ${hostname}:${port}`);

            const sslyzeResult = await runSSLyzeScan(hostname, port);
            if (sslyzeResult.success) {
                const tests = convertSSLyzeToTests(sslyzeResult.data, hostname);

                return {
                    hostname: hostname,
                    port: port,
                    enhanced: true,
                    sslyzeVersion: sslyzeAvailable.version,
                    tests: tests,
                    summary: {
                        totalTests: tests.length,
                        passedTests: tests.filter(t => t.status === 'pass').length,
                        failedTests: tests.filter(t => t.status === 'fail').length,
                        warningTests: tests.filter(t => t.status === 'warning').length,
                        totalScore: tests.reduce((sum, t) => sum + (t.score || 0), 0),
                        maxScore: tests.length * 30 // Approximate max score
                    },
                    rawSSLyzeData: sslyzeResult.data
                };
            } else {
                logger.warn(`SSLyze scan failed for ${hostname}:${port}: ${sslyzeResult.error}`);
            }
        }

        // Fallback to certificate-only analysis
        logger.info(`Using certificate-only SSL analysis for ${hostname}:${port} (SSLyze not available)`);
        const basicResult = await checkSSLCertificate(`https://${hostname}:${port}`);

        return {
            hostname: hostname,
            port: port,
            enhanced: false,
            basicResult: basicResult,
            summary: {
                totalTests: 1,
                passedTests: basicResult.valid ? 1 : 0,
                failedTests: basicResult.valid ? 0 : 1,
                warningTests: 0,
                totalScore: basicResult.score || 0,
                maxScore: 100
            }
        };

    } catch (error) {
        return {
            hostname: hostname,
            port: port,
            enhanced: false,
            error: error.message,
            summary: {
                totalTests: 0,
                passedTests: 0,
                failedTests: 1,
                warningTests: 0,
                totalScore: 0,
                maxScore: 100
            }
        };
    }
}

/**
 * Extract certificate chain from the peer certificate
 * @param {Object} cert - The peer certificate object
 * @returns {Array} Array of certificate objects in the chain
 */
function extractCertificateChain(cert) {
    const chain = [];
    let currentCert = cert;
    let certIndex = 0;

    while (currentCert) {
        const isLeaf = certIndex === 0;
        const isRoot = currentCert.subject && currentCert.issuer &&
                      JSON.stringify(currentCert.subject) === JSON.stringify(currentCert.issuer);

        // Determine certificate type
        let certType = 'Unknown Certificate';
        if (isLeaf) {
            certType = 'Leaf Certificate (Server)';
        } else if (isRoot) {
            certType = 'Root Certificate Authority';
        } else {
            certType = 'Intermediate Certificate Authority';
        }

        // Determine validity status
        let validityStatus = 'Unknown';
        if (currentCert.valid_from && currentCert.valid_to) {
            const now = new Date();
            const validFrom = new Date(currentCert.valid_from);
            const validTo = new Date(currentCert.valid_to);

            if (now < validFrom) {
                validityStatus = 'Not Yet Valid';
            } else if (now > validTo) {
                validityStatus = 'Expired';
            } else {
                validityStatus = 'Valid';
            }
        }

        // Add current certificate to chain
        const certInfo = {
            type: certType,
            subject: currentCert.subject ? (currentCert.subject.CN || currentCert.subject.O || 'Unknown') : 'Unknown',
            issuer: currentCert.issuer ? (currentCert.issuer.CN || currentCert.issuer.O || 'Unknown') : 'Unknown',
            validFrom: currentCert.valid_from || null,
            validTo: currentCert.valid_to || null,
            serialNumber: currentCert.serialNumber || 'Unknown',
            fingerprint: currentCert.fingerprint || 'Unknown',
            fingerprint256: currentCert.fingerprint256 || currentCert.fingerprint || 'Unknown',
            keyLength: currentCert.bits || 'Unknown',
            keyAlgorithm: determineKeyAlgorithm(currentCert),
            signatureAlgorithm: require('./certificate-parser').extractSignatureAlgorithm(currentCert),
            isRoot: isRoot,
            validity: {
                status: validityStatus
            },
            // Organization information
            organization: {
                name: currentCert.subject?.O || 'Unknown',
                unit: currentCert.subject?.OU || 'Unknown',
                country: currentCert.subject?.C || 'Unknown',
                locality: currentCert.subject?.L || 'Unknown',
                state: currentCert.subject?.ST || 'Unknown'
            }
        };

        chain.push(certInfo);

        // Move to next certificate in chain (issuer certificate)
        currentCert = currentCert.issuerCertificate;

        // Prevent infinite loops (self-signed root certificates reference themselves)
        if (currentCert && currentCert === cert) {
            break;
        }

        // Stop if we've reached a self-signed certificate and already added it
        if (isRoot) {
            break;
        }

        certIndex++;

        // Safety limit to prevent infinite loops
        if (certIndex > 10) {
            break;
        }
    }

    return chain;
}

module.exports = {
    checkSSLCertificate,
    analyzeSSLCertificateDetailed,

    // Module metadata
    name: 'Unified SSL Analyzer',
    description: 'Comprehensive SSL/TLS security analysis with certificate validation and vulnerability testing'
};
