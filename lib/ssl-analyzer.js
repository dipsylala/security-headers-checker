/**
 * SSL Certificate Analysis Module
 * Handles SSL certificate checking, validation, and grading
 */

const tls = require('tls');
const crypto = require('crypto');

/**
 * Check SSL certificate for a given URL
 * @param {string} url - The URL to check SSL certificate for
 * @returns {Promise<Object>} SSL certificate analysis results
 */
async function checkSSLCertificate(url) {
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

            const options = {
                host: hostname,
                port: port,
                rejectUnauthorized: false,
                servername: hostname
            };

            const socket = tls.connect(options, () => {
                try {
                    const cert = socket.getPeerCertificate(true);
                    const protocol = socket.getProtocol();
                    
                    // Extract signature algorithm
                    const signatureAlgorithm = extractSignatureAlgorithm(cert);
                logCertificateDebugInfo(cert, signatureAlgorithm);
                
                const gradeInfo = calculateSSLGrade(cert, protocol, socket.authorized, signatureAlgorithm);
                
                resolve({
                    valid: socket.authorized,
                    error: socket.authorized ? null : socket.authorizationError,
                    issuer: cert.issuer ? cert.issuer.CN || cert.issuer.O || 'Unknown' : 'Unknown',
                    subject: cert.subject ? cert.subject.CN || hostname : hostname,
                    validFrom: cert.valid_from || null,
                    validTo: cert.valid_to || null,
                    keyLength: cert.bits || 0,
                    signatureAlgorithm: signatureAlgorithm,
                    protocol: protocol || 'Unknown',
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
 * Extract signature algorithm from certificate using multiple methods
 * @param {Object} cert - Certificate object from tls.getPeerCertificate()
 * @returns {string} Signature algorithm
 */
function extractSignatureAlgorithm(cert) {
    let signatureAlgorithm = 'Unknown';
    
    // Method 1: Direct sigalg property
    if (cert.sigalg) {
        return cert.sigalg;
    }
    
    // Method 2: Alternative property names
    if (cert.signatureAlgorithm) {
        return cert.signatureAlgorithm;
    }
    
    // Method 3: Use crypto module to parse certificate
    if (cert.raw) {
        try {
            const x509 = new crypto.X509Certificate(cert.raw);
            
            if (x509.signatureAlgorithm) {
                return x509.signatureAlgorithm;
            }
            
            // Parse certificate text for signature algorithm
            const certPem = x509.toString();
            const sigAlgMatch = certPem.match(/Signature Algorithm:\s*([^\n\r]+)/i);
            if (sigAlgMatch) {
                return sigAlgMatch[1].trim();
            }
        } catch (e) {
            console.log('Could not parse certificate with crypto.X509Certificate:', e.message);
        }
    }
    
    // Method 4: Infer from certificate type and properties
    return inferSignatureAlgorithm(cert);
}

/**
 * Infer signature algorithm from certificate properties
 * @param {Object} cert - Certificate object
 * @returns {string} Inferred signature algorithm
 */
function inferSignatureAlgorithm(cert) {
    if (cert.asn1Curve || cert.nistCurve) {
        // ECC certificate - likely ECDSA
        if (cert.bits >= 384) {
            return 'ecdsa-with-SHA384';
        } else if (cert.bits >= 256) {
            return 'ecdsa-with-SHA256';
        } else {
            return 'ecdsa-with-SHA1';
        }
    } else {
        // RSA certificate - likely RSA with SHA
        if (cert.fingerprint256) {
            return 'sha256WithRSAEncryption';
        } else if (cert.fingerprint) {
            return 'sha1WithRSAEncryption';
        }
    }
    
    return 'Unknown';
}

/**
 * Log certificate debug information
 * @param {Object} cert - Certificate object
 * @param {string} signatureAlgorithm - Detected signature algorithm
 */
function logCertificateDebugInfo(cert, signatureAlgorithm) {
    console.log('Certificate properties available:', Object.keys(cert));
    console.log('Certificate type indicators:');
    console.log('- asn1Curve:', cert.asn1Curve);
    console.log('- nistCurve:', cert.nistCurve);
    console.log('- bits:', cert.bits);
    console.log('Certificate sigalg property:', cert.sigalg);
    console.log('Certificate signatureAlgorithm property:', cert.signatureAlgorithm);
    console.log('Final signature algorithm found:', signatureAlgorithm);
    
    // Log certificate fingerprints
    if (cert.fingerprint) console.log('Certificate fingerprint (SHA-1):', cert.fingerprint);
    if (cert.fingerprint256) console.log('Certificate fingerprint (SHA-256):', cert.fingerprint256);
    if (cert.fingerprint512) console.log('Certificate fingerprint (SHA-512):', cert.fingerprint512);
}

/**
 * Calculate SSL Grade with detailed explanations
 * @param {Object} cert - Certificate object
 * @param {string} protocol - TLS protocol version
 * @param {boolean} authorized - Whether certificate is authorized
 * @param {string} signatureAlgorithm - Signature algorithm
 * @returns {Object} Grade information with explanation and recommendations
 */
function calculateSSLGrade(cert, protocol, authorized, signatureAlgorithm = null) {
    const issues = [];
    const recommendations = [];
    let score = 0;
    
    // Check authorization first
    if (!authorized) {
        return {
            grade: 'F',
            explanation: 'SSL certificate is not trusted or has critical security issues',
            recommendations: [
                'Install a valid SSL certificate from a trusted Certificate Authority', 
                'Check certificate chain configuration', 
                'Verify hostname matches certificate'
            ]
        };
    }
    
    // Protocol scoring
    score += scoreProtocol(protocol, issues, recommendations);
    
    // Key length scoring
    score += scoreKeyLength(cert, issues, recommendations);
    
    // Certificate validity scoring
    score += scoreCertificateValidity(cert, issues, recommendations);
    
    // Signature algorithm scoring
    score += scoreSignatureAlgorithm(signatureAlgorithm, issues, recommendations);
    
    // Determine grade
    const grade = determineGradeFromScore(score);
    
    // Build explanation
    const explanation = buildExplanation(issues, protocol, cert.bits || 0, signatureAlgorithm);
    
    // Add default recommendations if none exist
    if (recommendations.length === 0) {
        recommendations.push('SSL configuration is optimal');
    }
    
    return { 
        grade, 
        score, 
        maxScore: 100, // Protocol(30) + KeyLength(30) + Validity(20) + Signature(20)
        explanation, 
        recommendations 
    };
}

/**
 * Score TLS protocol version
 * @param {string} protocol - TLS protocol
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Protocol score
 */
function scoreProtocol(protocol, issues, recommendations) {
    if (protocol === 'TLSv1.3') return 30;
    if (protocol === 'TLSv1.2') return 25;
    
    if (protocol === 'TLSv1.1') {
        issues.push('Using outdated TLS 1.1 protocol');
        recommendations.push('Upgrade to TLS 1.2 or 1.3 for better security');
        return 15;
    }
    
    if (protocol === 'TLSv1') {
        issues.push('Using deprecated TLS 1.0 protocol');
        recommendations.push('Immediately upgrade to TLS 1.2 or 1.3 - TLS 1.0 is insecure');
        return 10;
    }
    
    issues.push('Unknown or unsupported TLS protocol');
    recommendations.push('Configure server to use TLS 1.2 or 1.3');
    return 0;
}

/**
 * Score key length (handles ECC vs RSA differently)
 * @param {Object} cert - Certificate object
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Key length score
 */
function scoreKeyLength(cert, issues, recommendations) {
    const keyLength = cert.bits || 0;
    const isECC = cert.asn1Curve || cert.nistCurve || (keyLength <= 384 && keyLength >= 224);
    
    if (isECC) {
        return scoreECCKeyLength(keyLength, issues, recommendations);
    } else {
        return scoreRSAKeyLength(keyLength, issues, recommendations);
    }
}

/**
 * Score ECC key length
 * @param {number} keyLength - Key length in bits
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} ECC key score
 */
function scoreECCKeyLength(keyLength, issues, recommendations) {
    if (keyLength >= 384) return 30; // P-384 or higher
    if (keyLength >= 256) return 28; // P-256 (very strong for ECC)
    
    if (keyLength >= 224) {
        issues.push(`ECC key could be stronger: ${keyLength} bits`);
        recommendations.push('Consider upgrading to P-256 or P-384 ECC keys for maximum security');
        return 20;
    }
    
    if (keyLength > 0) {
        issues.push(`Weak ECC key length: ${keyLength} bits`);
        recommendations.push('Upgrade to at least P-256 ECC keys');
        return 10;
    }
    
    return 0;
}

/**
 * Score RSA key length
 * @param {number} keyLength - Key length in bits
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} RSA key score
 */
function scoreRSAKeyLength(keyLength, issues, recommendations) {
    if (keyLength >= 4096) return 30;
    if (keyLength >= 2048) return 25;
    
    if (keyLength >= 1024) {
        issues.push(`Weak RSA key length: ${keyLength} bits`);
        recommendations.push('Use at least 2048-bit RSA keys or 256-bit ECC keys');
        return 15;
    }
    
    if (keyLength > 0) {
        issues.push(`Very weak RSA key length: ${keyLength} bits`);
        recommendations.push('Immediately upgrade to at least 2048-bit RSA keys');
        return 0;
    }
    
    issues.push('Key length information unavailable');
    return 0;
}

/**
 * Score certificate validity
 * @param {Object} cert - Certificate object
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Validity score
 */
function scoreCertificateValidity(cert, issues, recommendations) {
    if (!cert.valid_from || !cert.valid_to) {
        issues.push('Certificate validity dates unavailable');
        return 0;
    }
    
    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
    
    if (now >= validFrom && now <= validTo) {
        if (daysUntilExpiry <= 30) {
            issues.push(`Certificate expires soon (${daysUntilExpiry} days)`);
            recommendations.push('Renew SSL certificate before expiration');
        }
        return 20;
    }
    
    if (now > validTo) {
        issues.push('Certificate has expired');
        recommendations.push('Renew SSL certificate immediately');
        return 0;
    }
    
    if (now < validFrom) {
        issues.push('Certificate is not yet valid');
        recommendations.push('Check system clock or certificate validity dates');
        return 0;
    }
    
    return 0;
}

/**
 * Score signature algorithm
 * @param {string} sigAlg - Signature algorithm
 * @param {Array} issues - Issues array to populate
 * @param {Array} recommendations - Recommendations array to populate
 * @returns {number} Signature algorithm score
 */
function scoreSignatureAlgorithm(sigAlg, issues, recommendations) {
    if (!sigAlg || sigAlg === 'Unknown') {
        issues.push('Signature algorithm information unavailable - this may indicate an issue with certificate analysis');
        recommendations.push('This is likely a limitation of our analysis tool rather than your certificate');
        return 0;
    }
    
    const lowerSigAlg = sigAlg.toLowerCase();
    
    // Modern secure algorithms
    if (lowerSigAlg.includes('sha256') || lowerSigAlg.includes('sha-256') || 
        lowerSigAlg.includes('ecdsa-with-sha256')) {
        return 20;
    }
    
    if (lowerSigAlg.includes('sha384') || lowerSigAlg.includes('sha-384') ||
        lowerSigAlg.includes('ecdsa-with-sha384')) {
        return 20;
    }
    
    if (lowerSigAlg.includes('sha512') || lowerSigAlg.includes('sha-512') ||
        lowerSigAlg.includes('ecdsa-with-sha512')) {
        return 20;
    }
    
    // ECDSA is generally good
    if (lowerSigAlg.includes('ecdsa')) {
        if (lowerSigAlg.includes('inferred')) {
            return 18; // Partial credit for inferred
        }
        return 15;
    }
    
    // Deprecated algorithms
    if (lowerSigAlg.includes('sha1') || lowerSigAlg.includes('sha-1')) {
        issues.push('Using deprecated SHA-1 signature algorithm');
        recommendations.push('Upgrade to SHA-256 or higher signature algorithm');
        return 5;
    }
    
    if (lowerSigAlg.includes('md5')) {
        issues.push('Using insecure MD5 signature algorithm');
        recommendations.push('Immediately upgrade to SHA-256 or higher - MD5 is cryptographically broken');
        return 0;
    }
    
    // Unknown but has info
    issues.push(`Unknown signature algorithm: ${sigAlg}`);
    recommendations.push('Verify signature algorithm is secure (SHA-256 or higher)');
    return 5;
}

/**
 * Determine grade from numeric score
 * @param {number} score - Numeric score
 * @returns {string} Letter grade
 */
function determineGradeFromScore(score) {
    if (score >= 90) return 'A+';
    if (score >= 80) return 'A';
    if (score >= 70) return 'B';
    if (score >= 60) return 'C';
    if (score >= 50) return 'D';
    return 'F';
}

/**
 * Build explanation string
 * @param {Array} issues - Array of issues found
 * @param {string} protocol - TLS protocol
 * @param {number} keyLength - Key length
 * @param {string} sigAlg - Signature algorithm
 * @returns {string} Explanation text
 */
function buildExplanation(issues, protocol, keyLength, sigAlg) {
    if (issues.length === 0) {
        return `Excellent SSL configuration! Protocol: ${protocol}, Key: ${keyLength} bits, Signature: ${sigAlg || 'Unknown'}`;
    } else {
        return `Issues found: ${issues.join('; ')}. Protocol: ${protocol}, Key: ${keyLength} bits, Signature: ${sigAlg || 'Unknown'}`;
    }
}

module.exports = {
    checkSSLCertificate,
    calculateSSLGrade,
    extractSignatureAlgorithm
};
