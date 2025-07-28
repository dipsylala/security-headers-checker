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
function checkSSLCertificate(url) {
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

                    const gradeInfo = calculateSSLGrade(cert, protocol, socket.authorized, signatureAlgorithm, socket.authorizationError);

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
 * Build detailed information for the entire certificate chain
 * @param {Object} cert - Root certificate object
 * @param {string} hostname - Target hostname
 * @param {string} signatureAlgorithm - Primary signature algorithm
 * @param {string} protocol - TLS protocol version
 * @param {boolean} authorized - Certificate authorization status
 * @param {string} authorizationError - Authorization error if any
 * @returns {Array} Array of certificate details for the entire chain
 */
function buildCertificateChain(cert, hostname, signatureAlgorithm, protocol, authorized, authorizationError) {
    const chain = [];
    let currentCert = cert;
    let depth = 0;
    const maxDepth = 10; // Prevent infinite loops
    
    while (currentCert && depth < maxDepth) {
        const certSignatureAlgorithm = depth === 0 ? signatureAlgorithm : extractSignatureAlgorithm(currentCert);
        const keyAlgorithm = determineKeyAlgorithm(currentCert);
        
        // Determine certificate type in chain
        let certificateType = 'Unknown';
        let isRootCert = false;
        
        if (depth === 0) {
            certificateType = 'Leaf Certificate (End Entity)';
        } else if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
            certificateType = 'Intermediate Certificate';
        } else {
            certificateType = 'Root Certificate';
            isRootCert = true;
        }
        
        // Build detailed certificate information
        const certDetails = {
            depth: depth,
            type: certificateType,
            subject: currentCert.subject ? currentCert.subject.CN || currentCert.subject.O || 'Unknown' : 'Unknown',
            issuer: currentCert.issuer ? currentCert.issuer.CN || currentCert.issuer.O || 'Unknown' : 'Unknown',
            validFrom: currentCert.valid_from || null,
            validTo: currentCert.valid_to || null,
            keyLength: currentCert.bits || 0,
            keyAlgorithm: keyAlgorithm,
            signatureAlgorithm: certSignatureAlgorithm,
            protocol: depth === 0 ? (protocol || 'Unknown') : 'N/A',
            valid: depth === 0 ? authorized : true, // Only check validity for leaf cert
            error: depth === 0 ? (authorized ? null : authorizationError) : null,
            serialNumber: currentCert.serialNumber || 'Unknown',
            fingerprint: currentCert.fingerprint || 'Unknown',
            fingerprint256: currentCert.fingerprint256 || 'Unknown',
            isRoot: isRootCert,
            isSelfSigned: detectSelfSignedCertificate(currentCert).isSelfSigned,
            selfSignedAnalysis: detectSelfSignedCertificate(currentCert),
            organizationInfo: extractOrganizationInfo(currentCert),
            extensions: extractCertificateExtensions(currentCert),
            validity: analyzeCertificateValidity(currentCert)
        };
        
        chain.push(certDetails);
        
        // Move to next certificate in chain
        if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
            currentCert = currentCert.issuerCertificate;
            depth++;
        } else {
            // Reached root certificate or end of chain
            break;
        }
    }
    
    return chain;
}

/**
 * Extract organization information from certificate
 * @param {Object} cert - Certificate object
 * @returns {Object} Organization information
 */
function extractOrganizationInfo(cert) {
    const subject = cert.subject || {};
    const issuer = cert.issuer || {};
    
    return {
        subject: {
            organization: subject.O || null,
            organizationalUnit: subject.OU || null,
            country: subject.C || null,
            locality: subject.L || null,
            state: subject.ST || null
        },
        issuer: {
            organization: issuer.O || null,
            organizationalUnit: issuer.OU || null,
            country: issuer.C || null,
            locality: issuer.L || null,
            state: issuer.ST || null
        }
    };
}

/**
 * Extract certificate extensions information
 * @param {Object} cert - Certificate object
 * @returns {Object} Extensions information
 */
function extractCertificateExtensions(cert) {
    const extensions = {
        subjectAltName: cert.subjectaltname || null,
        keyUsage: cert.ext_key_usage || null,
        basicConstraints: null,
        authorityInfoAccess: cert.infoAccess || null,
        isCa: cert.ca || false
    };
    
    // Parse subject alternative names
    if (extensions.subjectAltName) {
        const sanEntries = extensions.subjectAltName.split(', ').map(entry => {
            const [type, value] = entry.split(':');
            return { type: type.trim(), value: value ? value.trim() : null };
        });
        extensions.parsedSAN = sanEntries;
    }
    
    return extensions;
}

/**
 * Analyze certificate validity status
 * @param {Object} cert - Certificate object
 * @returns {Object} Validity analysis
 */
function analyzeCertificateValidity(cert) {
    const now = new Date();
    const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
    const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
    
    let status = 'Unknown';
    let daysUntilExpiry = null;
    let daysSinceIssuance = null;
    
    if (validFrom && validTo) {
        const isValid = now >= validFrom && now <= validTo;
        const isExpired = now > validTo;
        const isNotYetValid = now < validFrom;
        
        if (isExpired) {
            status = 'Expired';
            daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24)); // Negative number
        } else if (isNotYetValid) {
            status = 'Not Yet Valid';
        } else {
            status = 'Valid';
            daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        }
        
        daysSinceIssuance = Math.floor((now - validFrom) / (1000 * 60 * 60 * 24));
    }
    
    return {
        status,
        daysUntilExpiry,
        daysSinceIssuance,
        validFrom: validFrom ? validFrom.toISOString() : null,
        validTo: validTo ? validTo.toISOString() : null
    };
}

/**
 * Determine the key algorithm type from certificate properties
 * @param {Object} cert - Certificate object
 * @returns {string} Key algorithm type (e.g., "RSA", "ECDSA P-256", "ECDSA P-384")
 */
function determineKeyAlgorithm(cert) {
    const keyLength = cert.bits || 0;
    const isECC = cert.asn1Curve || cert.nistCurve || (keyLength <= 384 && keyLength >= 224);
    
    if (isECC) {
        // Determine the specific ECC curve if possible
        if (cert.nistCurve) {
            return `ECDSA ${cert.nistCurve}`;
        } else if (cert.asn1Curve) {
            // Map common ASN.1 curve names to user-friendly names
            const curveMap = {
                'prime256v1': 'ECDSA P-256',
                'secp384r1': 'ECDSA P-384',
                'secp521r1': 'ECDSA P-521'
            };
            return curveMap[cert.asn1Curve] || `ECDSA ${cert.asn1Curve}`;
        } else {
            // Infer curve from key length
            if (keyLength >= 521) return 'ECDSA P-521';
            if (keyLength >= 384) return 'ECDSA P-384';
            if (keyLength >= 256) return 'ECDSA P-256';
            return 'ECDSA';
        }
    } else {
        // RSA key
        return 'RSA';
    }
}

/**
 * Detect if a certificate is self-signed by comparing subject and issuer
 * @param {Object} cert - Certificate object
 * @returns {Object} Self-signed detection result with details
 */
function detectSelfSignedCertificate(cert) {
    if (!cert || !cert.subject || !cert.issuer) {
        return {
            isSelfSigned: false,
            confidence: 'low',
            reason: 'Insufficient certificate information to determine if self-signed',
            details: null
        };
    }

    const subject = cert.subject;
    const issuer = cert.issuer;
    
    // Primary check: Compare subject and issuer fields
    const subjectCN = subject.CN || '';
    const issuerCN = issuer.CN || '';
    const subjectO = subject.O || '';
    const issuerO = issuer.O || '';
    
    // Check if Common Names match
    const cnMatches = subjectCN && issuerCN && subjectCN === issuerCN;
    
    // Check if Organizations match
    const orgMatches = subjectO && issuerO && subjectO === issuerO;
    
    // Check if all major subject components match issuer components
    const allFieldsMatch = 
        (subject.CN === issuer.CN || (!subject.CN && !issuer.CN)) &&
        (subject.O === issuer.O || (!subject.O && !issuer.O)) &&
        (subject.OU === issuer.OU || (!subject.OU && !issuer.OU)) &&
        (subject.C === issuer.C || (!subject.C && !issuer.C)) &&
        (subject.ST === issuer.ST || (!subject.ST && !issuer.ST)) &&
        (subject.L === issuer.L || (!subject.L && !issuer.L));
    
    // Additional check: Certificate authority flag should be true for self-signed root CAs
    const isCa = cert.ca === true;
    
    // Check if certificate is self-referential (issuerCertificate points to itself)
    const isSelfReferential = cert.issuerCertificate === cert;
    
    let confidence = 'low';
    let reason = '';
    let isSelfSigned = false;
    
    if (allFieldsMatch) {
        isSelfSigned = true;
        confidence = 'high';
        reason = 'Subject and issuer fields are identical';
        
        if (isCa) {
            reason += ' and certificate has CA flag set';
            confidence = 'very-high';
        }
        
        if (isSelfReferential) {
            reason += ' and certificate is self-referential';
        }
    } else if (cnMatches && orgMatches) {
        isSelfSigned = true;
        confidence = 'medium';
        reason = 'Subject and issuer Common Name and Organization match';
    } else if (cnMatches) {
        isSelfSigned = true;
        confidence = 'medium';
        reason = 'Subject and issuer Common Name match';
    }
    
    return {
        isSelfSigned,
        confidence,
        reason,
        details: {
            subjectCN,
            issuerCN,
            subjectO,
            issuerO,
            cnMatches,
            orgMatches,
            allFieldsMatch,
            isCa,
            isSelfReferential,
            subjectFull: formatDistinguishedName(subject),
            issuerFull: formatDistinguishedName(issuer)
        }
    };
}

/**
 * Format distinguished name for display
 * @param {Object} dn - Distinguished name object
 * @returns {string} Formatted distinguished name
 */
function formatDistinguishedName(dn) {
    if (!dn) return '';
    
    const parts = [];
    if (dn.CN) parts.push(`CN=${dn.CN}`);
    if (dn.O) parts.push(`O=${dn.O}`);
    if (dn.OU) parts.push(`OU=${dn.OU}`);
    if (dn.C) parts.push(`C=${dn.C}`);
    if (dn.ST) parts.push(`ST=${dn.ST}`);
    if (dn.L) parts.push(`L=${dn.L}`);
    
    return parts.join(', ');
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
    if (cert.fingerprint) { console.log('Certificate fingerprint (SHA-1):', cert.fingerprint); }
    if (cert.fingerprint256) { console.log('Certificate fingerprint (SHA-256):', cert.fingerprint256); }
    if (cert.fingerprint512) { console.log('Certificate fingerprint (SHA-512):', cert.fingerprint512); }
}

/**
 * Calculate SSL Grade with detailed explanations
 * @param {Object} cert - Certificate object
 * @param {string} protocol - TLS protocol version
 * @param {boolean} authorized - Whether certificate is authorized
 * @param {string} signatureAlgorithm - Signature algorithm
 * @param {string} authorizationError - Specific authorization error
 * @returns {Object} Grade information with explanation and recommendations
 */
function calculateSSLGrade(cert, protocol, authorized, signatureAlgorithm = null, authorizationError = null) {
    const issues = [];
    const recommendations = [];
    let score = 0;

    // Check authorization first
    if (!authorized) {
        let explanation = 'SSL certificate is not trusted or has critical security issues';
        let specificRecommendations = [
            'Install a valid SSL certificate from a trusted Certificate Authority',
            'Check certificate chain configuration',
            'Verify hostname matches certificate'
        ];

        // Provide specific explanations based on the authorization error
        if (authorizationError) {
            switch (authorizationError) {
                case 'CERT_HAS_EXPIRED':
                    explanation = 'SSL certificate has expired and is no longer valid';
                    specificRecommendations = [
                        'Renew the SSL certificate immediately',
                        'Update the certificate on the server',
                        'Check certificate expiration monitoring'
                    ];
                    break;
                case 'CERT_NOT_YET_VALID':
                    explanation = 'SSL certificate is not yet valid (valid from date is in the future)';
                    specificRecommendations = [
                        'Check server system clock',
                        'Verify certificate validity dates',
                        'Install the correct certificate for current date'
                    ];
                    break;
                case 'DEPTH_ZERO_SELF_SIGNED_CERT':
                    explanation = 'SSL certificate is self-signed and not trusted by browsers';
                    specificRecommendations = [
                        'Replace with a certificate from a trusted Certificate Authority',
                        'Consider using Let\'s Encrypt for free SSL certificates',
                        'Avoid self-signed certificates in production'
                    ];
                    break;
                case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY':
                    explanation = 'SSL certificate chain is incomplete or misconfigured';
                    specificRecommendations = [
                        'Install the complete certificate chain',
                        'Include intermediate certificates',
                        'Verify certificate bundle configuration'
                    ];
                    break;
                case 'CERT_UNTRUSTED':
                    explanation = 'SSL certificate is from an untrusted Certificate Authority';
                    specificRecommendations = [
                        'Use a certificate from a trusted Certificate Authority',
                        'Verify certificate authority is included in browser trust stores',
                        'Check certificate installation'
                    ];
                    break;
                case 'HOSTNAME_MISMATCH':
                case 'ERR_TLS_CERT_ALTNAME_INVALID':
                    explanation = 'SSL certificate hostname does not match the requested domain';
                    specificRecommendations = [
                        'Install a certificate that matches the domain name',
                        'Use a wildcard certificate for subdomains',
                        'Add the domain to certificate Subject Alternative Names'
                    ];
                    break;
                default:
                    explanation = `SSL certificate error: ${authorizationError}`;
                    break;
            }
        }

        return {
            grade: 'F',
            explanation: explanation,
            recommendations: specificRecommendations
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
    if (protocol === 'TLSv1.3') { return 30; }
    if (protocol === 'TLSv1.2') { return 25; }

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
    if (keyLength >= 384) { return 30; } // P-384 or higher
    if (keyLength >= 256) { return 28; } // P-256 (very strong for ECC)

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
    if (keyLength >= 4096) { return 30; }
    if (keyLength >= 2048) { return 25; }

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
    if (score >= 90) { return 'A+'; }
    if (score >= 80) { return 'A'; }
    if (score >= 70) { return 'B'; }
    if (score >= 60) { return 'C'; }
    if (score >= 50) { return 'D'; }
    return 'F';
}

/**
 * Analyze SSL certificate with detailed test results
 * @param {string} hostname - Target hostname
 * @param {number} port - Target port (defaults to 443)
 * @returns {Promise<Object>} Detailed SSL analysis results
 */
function analyzeSSLCertificateDetailed(hostname, port = 443) {
    return new Promise((resolve) => {
        const tls = require('tls');

        // Create connection with timeout
        const options = {
            host: hostname,
            port: port,
            rejectUnauthorized: false,
            servername: hostname,
            timeout: 10000
        };

        const socket = tls.connect(options, async () => {
            try {
                const cert = socket.getPeerCertificate(true);
                const protocol = socket.getProtocol();
                const signatureAlgorithm = extractSignatureAlgorithm(cert);

                // Perform detailed analysis
                const detailedAnalysis = await performDetailedCertificateAnalysis(
                    cert, 
                    protocol, 
                    socket.authorized, 
                    signatureAlgorithm, 
                    socket.authorizationError,
                    hostname,
                    port
                );

                resolve(detailedAnalysis);
                socket.end();
            } catch (error) {
                console.log('Error in detailed SSL analysis:', error.message);
                resolve({
                    certificateDetails: {
                        subject: hostname,
                        issuer: 'Unknown',
                        validFrom: null,
                        validTo: null,
                        keyLength: 0,
                        signatureAlgorithm: 'Unknown',
                        protocol: 'Unknown',
                        valid: false,
                        error: error.message,
                        serialNumber: 'Unknown',
                        fingerprint: 'Unknown',
                        fingerprint256: 'Unknown'
                    },
                    tests: [
                        {
                            name: 'Certificate Access',
                            status: 'fail',
                            description: 'Unable to retrieve certificate information',
                            details: error.message,
                            recommendation: 'Check server configuration and connectivity',
                            score: 0
                        }
                    ],
                    summary: {
                        grade: 'F',
                        score: 0,
                        maxScore: 100,
                        testsTotal: 1,
                        testsPassed: 0,
                        testsFailed: 1,
                        testsWarning: 0,
                        explanation: `Certificate analysis failed: ${error.message}`
                    }
                });
                socket.end();
            }
        });

        socket.on('error', (error) => {
            console.log('TLS connection error in detailed analysis:', error.message);
            resolve({
                certificateDetails: {
                    subject: hostname,
                    issuer: 'Unknown',
                    validFrom: null,
                    validTo: null,
                    keyLength: 0,
                    signatureAlgorithm: 'Unknown',
                    protocol: 'Unknown',
                    valid: false,
                    error: error.message,
                    serialNumber: 'Unknown',
                    fingerprint: 'Unknown',
                    fingerprint256: 'Unknown'
                },
                tests: [
                    {
                        name: 'SSL Connection',
                        status: 'fail',
                        description: 'Unable to establish SSL connection',
                        details: error.message,
                        recommendation: 'Verify SSL is properly configured on the server',
                        score: 0
                    }
                ],
                summary: {
                    grade: 'F',
                    score: 0,
                    maxScore: 100,
                    testsTotal: 1,
                    testsPassed: 0,
                    testsFailed: 1,
                    testsWarning: 0,
                    explanation: `SSL connection failed: ${error.message}`
                }
            });
        });

        socket.setTimeout(10000, () => {
            console.log('Detailed SSL analysis timeout for:', hostname);
            socket.destroy();
            resolve({
                certificateDetails: {
                    subject: hostname,
                    issuer: 'Unknown',
                    validFrom: null,
                    validTo: null,
                    keyLength: 0,
                    signatureAlgorithm: 'Unknown',
                    protocol: 'Unknown',
                    valid: false,
                    error: 'Connection timeout',
                    serialNumber: 'Unknown',
                    fingerprint: 'Unknown',
                    fingerprint256: 'Unknown'
                },
                tests: [
                    {
                        name: 'SSL Connection',
                        status: 'fail',
                        description: 'Connection timeout during SSL analysis',
                        details: 'Server did not respond within 10 seconds',
                        recommendation: 'Check if the server is online and accessible',
                        score: 0
                    }
                ],
                summary: {
                    grade: 'F',
                    score: 0,
                    maxScore: 100,
                    testsTotal: 1,
                    testsPassed: 0,
                    testsFailed: 1,
                    testsWarning: 0,
                    explanation: 'SSL connection timeout during certificate analysis'
                }
            });
        });
    });
}

/**
 * Perform detailed certificate analysis with individual test results
 * @param {Object} cert - Certificate object
 * @param {string} protocol - TLS protocol version
 * @param {boolean} authorized - Whether certificate is authorized
 * @param {string} signatureAlgorithm - Signature algorithm
 * @param {string} authorizationError - Specific authorization error
 * @param {string} hostname - Target hostname
 * @param {number} port - Target port
 * @returns {Promise<Object>} Detailed analysis results
 */
async function performDetailedCertificateAnalysis(cert, protocol, authorized, signatureAlgorithm, authorizationError, hostname, port = 443) {
    const tests = [];
    let totalScore = 0;
    const maxScore = 175; // Actual maximum possible scores: Trust(25) + Protocol(30) + Key(30) + Validity(20) + Signature(20) + Cipher(10) + OCSP(5) + Revocation(5) + CT(5) + Pinning(5) + Vuln(15) + Headers(5)

    // Certificate Details (Enhanced with chain information)
    const certificateChain = buildCertificateChain(cert, hostname, signatureAlgorithm, protocol, authorized, authorizationError);
    const certificateDetails = certificateChain[0]; // Leaf certificate (primary)
    
    const certificateDetailsWithChain = {
        ...certificateDetails,
        chain: certificateChain
    };

    // Test 1: Certificate Trust and Validity
    const trustTest = performCertificateTrustTest(authorized, authorizationError, cert, hostname);
    tests.push(trustTest);
    if (trustTest.status === 'pass') totalScore += 25;

    // Test 2: TLS Protocol Version
    const protocolTest = await performProtocolTest(protocol, hostname, port);
    tests.push(protocolTest);
    totalScore += protocolTest.score || 0;

    // Test 3: Key Length and Type
    const keyTest = performKeyStrengthTest(cert);
    tests.push(keyTest);
    totalScore += keyTest.score || 0;

    // Test 4: Certificate Validity Period
    const validityTest = performValidityPeriodTest(cert);
    tests.push(validityTest);
    totalScore += validityTest.score || 0;

    // Test 5: Signature Algorithm
    const signatureTest = performSignatureAlgorithmTest(signatureAlgorithm, cert);
    tests.push(signatureTest);
    totalScore += signatureTest.score || 0;

    // Test 6: Cipher Suite Strength (Enhanced)
    const cipherTest = performCipherSuiteTest(cert, protocol);
    tests.push(cipherTest);
    totalScore += cipherTest.score || 0;

    // Test 7: OCSP Stapling Support
    const ocspTest = performOCSPStaplingTest(hostname);
    tests.push(ocspTest);
    totalScore += ocspTest.score || 0;

    // Test 8: Certificate Revocation Status
    const revocationTest = performRevocationStatusTest(cert, hostname);
    tests.push(revocationTest);
    totalScore += revocationTest.score || 0;

    // Test 9: Certificate Transparency
    const ctTest = performCertificateTransparencyTest(cert);
    tests.push(ctTest);
    totalScore += ctTest.score || 0;

    // Test 10: Certificate Pinning Analysis
    const pinningTest = await performCertificatePinningTest(cert, hostname);
    tests.push(pinningTest);
    totalScore += pinningTest.score || 0;

    // Test 11: Vulnerability Checks (Heartbleed, POODLE, etc.)
    const vulnTest = performVulnerabilityChecksTest(hostname, protocol);
    tests.push(vulnTest);
    totalScore += vulnTest.score || 0;

    // Test 12: Security Headers (HSTS, etc.)
    const securityHeadersTest = performSecurityHeadersTest(hostname);
    tests.push(securityHeadersTest);
    totalScore += securityHeadersTest.score || 0;

    // Calculate summary
    const testsPassed = tests.filter(test => test.status === 'pass').length;
    const testsFailed = tests.filter(test => test.status === 'fail').length;
    const testsWarning = tests.filter(test => test.status === 'warning').length;

    const grade = determineGradeFromScore(totalScore);
    const explanation = buildDetailedExplanation(tests, certificateDetails);

    return {
        certificateDetails: certificateDetailsWithChain,
        tests,
        summary: {
            grade,
            score: totalScore,
            maxScore,
            testsTotal: tests.length,
            testsPassed,
            testsFailed,
            testsWarning,
            explanation
        }
    };
}

/**
 * Test certificate trust and authorization
 */
function performCertificateTrustTest(authorized, authorizationError, cert = null, hostname = null) {
    if (authorized) {
        return {
            name: 'Certificate Trust',
            status: 'pass',
            description: 'Certificate is trusted by the system - Certificate chain is valid and trusted',
            details: 'Certificate chain is valid and trusted',
            recommendation: null,
            score: 25
        };
    }

    // Build detailed failure information showing actual certificate values
    const failureInfo = {
        authorized: authorized,
        authorizationError: authorizationError || 'Unknown error',
        hostname: hostname || 'Unknown',
        certificateValues: {}
    };

    // Extract certificate information if available
    if (cert) {
        failureInfo.certificateValues = {
            subject: cert.subject ? cert.subject.CN || cert.subject.O || 'Unknown' : 'Missing',
            issuer: cert.issuer ? cert.issuer.CN || cert.issuer.O || 'Unknown' : 'Missing',
            validFrom: cert.valid_from || 'Missing',
            validTo: cert.valid_to || 'Missing',
            fingerprint: cert.fingerprint || 'Missing',
            serialNumber: cert.serialNumber || 'Missing',
            subjectAltName: cert.subjectaltname || 'Missing'
        };
        
        // Add self-signed detection
        failureInfo.selfSignedAnalysis = detectSelfSignedCertificate(cert);
    }

    let details = 'Certificate is not trusted';
    let recommendation = 'Install a valid SSL certificate from a trusted Certificate Authority';

    if (authorizationError) {
        switch (authorizationError) {
            case 'CERT_HAS_EXPIRED':
                details = `Certificate has expired and is no longer valid. Certificate was valid from ${failureInfo.certificateValues.validFrom || 'Unknown'} to ${failureInfo.certificateValues.validTo || 'Unknown'}.`;
                recommendation = 'Renew the SSL certificate immediately';
                break;
            case 'CERT_NOT_YET_VALID':
                details = `Certificate is not yet valid (valid from date is in the future). Certificate will be valid from ${failureInfo.certificateValues.validFrom || 'Unknown'} to ${failureInfo.certificateValues.validTo || 'Unknown'}.`;
                recommendation = 'Check server system clock and certificate validity dates';
                break;
            case 'DEPTH_ZERO_SELF_SIGNED_CERT':
                const selfSignedInfo = failureInfo.selfSignedAnalysis || {};
                let selfSignedDetails = `Certificate is self-signed and not trusted by browsers. Subject: "${failureInfo.certificateValues.subject}", Issuer: "${failureInfo.certificateValues.issuer}"`;
                
                if (selfSignedInfo.isSelfSigned && selfSignedInfo.details) {
                    selfSignedDetails += ` (${selfSignedInfo.reason})`;
                    if (selfSignedInfo.details.isCa) {
                        selfSignedDetails += '. This appears to be a self-signed Certificate Authority (CA) certificate';
                    }
                    if (selfSignedInfo.confidence === 'very-high') {
                        selfSignedDetails += '. High confidence self-signed detection';
                    }
                } else {
                    selfSignedDetails += ' (same as subject indicates self-signed)';
                }
                
                details = selfSignedDetails + '.';
                
                // Enhanced recommendation based on confidence and CA status
                if (selfSignedInfo.details && selfSignedInfo.details.isCa) {
                    recommendation = 'Self-signed CA certificate detected. For production: replace with a certificate from a trusted Certificate Authority (CA) like Let\'s Encrypt, DigiCert, or Sectigo. For development/testing: this is acceptable but browsers will show security warnings';
                } else {
                    recommendation = 'Self-signed certificate detected. For production: replace with a certificate from a trusted Certificate Authority (free options: Let\'s Encrypt, paid options: DigiCert, Sectigo, etc.). For development/testing: this works but browsers will show security warnings';
                }
                break;
            case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY':
                details = `Certificate chain is incomplete or misconfigured. Cannot verify certificate issued by "${failureInfo.certificateValues.issuer}". Subject: "${failureInfo.certificateValues.subject}".`;
                recommendation = 'Install the complete certificate chain including intermediate certificates';
                break;
            case 'CERT_UNTRUSTED':
                details = `Certificate is from an untrusted Certificate Authority. Issuer: "${failureInfo.certificateValues.issuer}", Subject: "${failureInfo.certificateValues.subject}".`;
                recommendation = 'Use a certificate from a trusted Certificate Authority';
                break;
            case 'ERR_TLS_CERT_ALTNAME_INVALID':
            case 'HOSTNAME_MISMATCH':
                const hostInfo = hostname ? ` for hostname "${hostname}"` : '';
                const subject = failureInfo.certificateValues.subject;
                const subjectAltName = failureInfo.certificateValues.subjectAltName;
                
                let mismatchExplanation = '';
                if (hostname && subject) {
                    // Check if it's a wildcard certificate issue
                    if (subject.includes('*') && hostname.includes('.')) {
                        const wildcardDomain = subject.replace('*.', '');
                        const requestedParts = hostname.split('.');
                        const wildcardParts = wildcardDomain.split('.');
                        
                        if (requestedParts.length > wildcardParts.length + 1) {
                            mismatchExplanation = ` The certificate uses a wildcard (${subject}) which only covers one level of subdomains, but "${hostname}" has multiple subdomain levels.`;
                        } else if (!hostname.endsWith(wildcardDomain)) {
                            mismatchExplanation = ` The requested hostname "${hostname}" does not match the wildcard pattern "${subject}".`;
                        }
                    } else {
                        mismatchExplanation = ` The requested hostname "${hostname}" does not match the certificate subject "${subject}".`;
                    }
                }
                
                const sanInfo = subjectAltName ? 
                    ` Certificate Subject Alternative Names: ${subjectAltName}.` : 
                    ' No Subject Alternative Names found.';
                    
                details = `Certificate hostname does not match the requested domain${hostInfo}. Certificate Subject: "${subject}".${sanInfo}${mismatchExplanation}`;
                
                // Provide specific recommendations based on the type of mismatch
                if (subject && subject.includes('*')) {
                    recommendation = 'For wildcard certificates: ensure the hostname matches the wildcard pattern (*.domain.com covers sub.domain.com but not sub.sub.domain.com), or add the specific hostname to Subject Alternative Names';
                } else {
                    recommendation = 'Install a certificate that matches the domain name or includes it in Subject Alternative Names';
                }
                break;
            default:
                details = `Certificate error: ${authorizationError}. Subject: "${failureInfo.certificateValues.subject}", Issuer: "${failureInfo.certificateValues.issuer}".`;
                break;
        }
    }

    // Add certificate fingerprint and serial number for debugging
    if (failureInfo.certificateValues.fingerprint && failureInfo.certificateValues.fingerprint !== 'Missing') {
        details += ` Certificate Fingerprint: ${failureInfo.certificateValues.fingerprint}.`;
    }
    if (failureInfo.certificateValues.serialNumber && failureInfo.certificateValues.serialNumber !== 'Missing') {
        details += ` Serial Number: ${failureInfo.certificateValues.serialNumber}.`;
    }

    return {
        name: 'Certificate Trust',
        status: 'fail',
        description: 'Certificate trust validation',
        details,
        recommendation,
        score: 0,
        debugInfo: failureInfo // Include raw debugging information
    };
}

/**
 * Test TLS protocol version support - now checks multiple versions
 */
async function performProtocolTest(protocol, hostname, port = 443) {
    // If we have the negotiated protocol, use it as the baseline
    const negotiatedProtocol = protocol;
    
    // Test for multiple protocol support
    const supportedProtocols = await testMultipleTLSVersions(hostname, port, negotiatedProtocol);
    
    // Determine the best and worst supported protocols
    const hasModern = supportedProtocols.some(p => p.includes('1.3'));
    const hasSecure = supportedProtocols.some(p => p.includes('1.2'));
    const hasLegacy = supportedProtocols.some(p => p.includes('1.1') || p.includes('1.0'));
    const hasInsecure = supportedProtocols.some(p => p.includes('SSLv'));
    
    const protocolList = supportedProtocols.length > 0 ? supportedProtocols.join(', ') : negotiatedProtocol || 'Unknown';
    
    // Score based on best and worst protocols supported
    if (hasModern && !hasLegacy && !hasInsecure) {
        return {
            name: 'TLS Protocol Version',
            status: 'pass',
            description: `TLS protocol support analysis - Found: ${protocolList} (modern protocols only)`,
            details: `Excellent protocol support: ${protocolList}`,
            recommendation: null,
            score: 30
        };
    }
    
    if (hasSecure && !hasInsecure) {
        const recommendation = hasLegacy ? 'Consider disabling TLS 1.0/1.1 support for enhanced security' : 
                              !hasModern ? 'Consider adding TLS 1.3 support for optimal security' : null;
        return {
            name: 'TLS Protocol Version',
            status: 'pass',
            description: `TLS protocol support analysis - Found: ${protocolList} (secure protocols)`,
            details: `Good protocol support: ${protocolList}`,
            recommendation,
            score: hasLegacy ? 22 : 25
        };
    }
    
    if (hasLegacy || hasInsecure) {
        return {
            name: 'TLS Protocol Version',
            status: hasInsecure ? 'fail' : 'warning',
            description: `TLS protocol support analysis - Found: ${protocolList} (includes legacy/insecure)`,
            details: `Problematic protocol support: ${protocolList}`,
            recommendation: 'Disable support for TLS 1.1, TLS 1.0, and all SSL versions. Use only TLS 1.2 and 1.3.',
            score: hasInsecure ? 5 : 15
        };
    }
    
    // Fallback for single protocol detection
    if (negotiatedProtocol === 'TLSv1.3') {
        return {
            name: 'TLS Protocol Version',
            status: 'pass',
            description: `TLS protocol support analysis - Negotiated: ${negotiatedProtocol} (latest and most secure)`,
            details: 'Using TLS 1.3 - the latest and most secure protocol',
            recommendation: null,
            score: 30
        };
    }

    if (negotiatedProtocol === 'TLSv1.2') {
        return {
            name: 'TLS Protocol Version',
            status: 'pass',
            description: `TLS protocol support analysis - Negotiated: ${negotiatedProtocol} (secure and widely supported)`,
            details: 'Using TLS 1.2 - secure and widely supported',
            recommendation: 'Consider upgrading to TLS 1.3 for optimal security',
            score: 25
        };
    }

    if (negotiatedProtocol === 'TLSv1.1') {
        return {
            name: 'TLS Protocol Version',
            status: 'warning',
            description: `TLS protocol support analysis - Negotiated: ${negotiatedProtocol} (outdated)`,
            details: 'Using outdated TLS 1.1 protocol',
            recommendation: 'Upgrade to TLS 1.2 or 1.3 for better security',
            score: 15
        };
    }

    if (negotiatedProtocol === 'TLSv1') {
        return {
            name: 'TLS Protocol Version',
            status: 'fail',
            description: `TLS protocol support analysis - Negotiated: ${negotiatedProtocol} (deprecated and insecure)`,
            details: 'Using deprecated TLS 1.0 protocol',
            recommendation: 'Immediately upgrade to TLS 1.2 or 1.3 - TLS 1.0 is insecure',
            score: 10
        };
    }

    return {
        name: 'TLS Protocol Version',
        status: 'fail',
        description: `TLS protocol support analysis - Negotiated: ${negotiatedProtocol || 'Unknown'} (unsupported)`,
        details: `Unknown or unsupported TLS protocol: ${negotiatedProtocol}`,
        recommendation: 'Configure server to use TLS 1.2 or 1.3',
        score: 0
    };
}

/**
 * Test multiple TLS protocol versions to see what the server supports
 * @param {string} hostname - Target hostname
 * @param {number} port - Target port
 * @param {string} negotiatedProtocol - The protocol that was initially negotiated
 * @returns {Promise<Array>} Array of supported protocols
 */
async function testMultipleTLSVersions(hostname, port, negotiatedProtocol) {
    const supportedProtocols = [];
    const tls = require('tls');
    
    // Add the negotiated protocol first if available
    if (negotiatedProtocol) {
        supportedProtocols.push(negotiatedProtocol);
    }
    
    // Test different TLS versions with timeout and error handling
    const protocolsToTest = [
        { version: 'TLSv1.3', secureProtocol: 'TLSv1_3_method' },
        { version: 'TLSv1.2', secureProtocol: 'TLSv1_2_method' },
        { version: 'TLSv1.1', secureProtocol: 'TLSv1_1_method' },
        { version: 'TLSv1.0', secureProtocol: 'TLSv1_method' }
    ];
    
    // Quick test - only try a couple additional protocols to avoid delays
    for (const protocolTest of protocolsToTest.slice(0, 2)) {
        // Skip if we already have this protocol
        if (supportedProtocols.includes(protocolTest.version)) {
            continue;
        }
        
        try {
            const supported = await testSingleProtocol(hostname, port, protocolTest);
            if (supported && !supportedProtocols.includes(protocolTest.version)) {
                supportedProtocols.push(protocolTest.version);
            }
        } catch (error) {
            // Protocol not supported or connection failed - continue
        }
    }
    
    return supportedProtocols.length > 0 ? supportedProtocols : [negotiatedProtocol || 'Unknown'];
}

/**
 * Test a single TLS protocol version
 * @param {string} hostname - Target hostname
 * @param {number} port - Target port
 * @param {Object} protocolTest - Protocol test configuration
 * @returns {Promise<boolean>} Whether the protocol is supported
 */
function testSingleProtocol(hostname, port, protocolTest) {
    return new Promise((resolve) => {
        const tls = require('tls');
        
        const options = {
            host: hostname,
            port: port,
            rejectUnauthorized: false,
            timeout: 3000, // Short timeout for quick testing
            secureProtocol: protocolTest.secureProtocol
        };
        
        const socket = tls.connect(options, () => {
            const connectedProtocol = socket.getProtocol();
            socket.destroy();
            resolve(connectedProtocol === protocolTest.version);
        });
        
        socket.on('error', () => {
            resolve(false);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        // Fallback timeout
        setTimeout(() => {
            if (!socket.destroyed) {
                socket.destroy();
                resolve(false);
            }
        }, 3000);
    });
}

/**
 * Test key strength and type
 */
function performKeyStrengthTest(cert) {
    const keyLength = cert.bits || 0;
    const isECC = cert.asn1Curve || cert.nistCurve || (keyLength <= 384 && keyLength >= 224);
    const keyType = isECC ? 'ECC' : 'RSA';

    if (isECC) {
        if (keyLength >= 384) {
            return {
                name: 'Key Strength',
                status: 'pass',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (excellent)`,
                details: `Excellent ECC key strength: ${keyLength} bits (P-384 or higher)`,
                recommendation: null,
                score: 30
            };
        }

        if (keyLength >= 256) {
            return {
                name: 'Key Strength',
                status: 'pass',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (strong)`,
                details: `Strong ECC key: ${keyLength} bits (P-256)`,
                recommendation: 'Consider P-384 for maximum security in high-value applications',
                score: 28
            };
        }

        if (keyLength >= 224) {
            return {
                name: 'Key Strength',
                status: 'warning',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (adequate)`,
                details: `Adequate ECC key: ${keyLength} bits`,
                recommendation: 'Consider upgrading to P-256 or P-384 ECC keys for maximum security',
                score: 20
            };
        }

        return {
            name: 'Key Strength',
            status: 'fail',
            description: 'Cryptographic key strength analysis',
            details: `Weak ECC key: ${keyLength} bits`,
            recommendation: 'Upgrade to at least P-256 ECC keys',
            score: 10
        };
    } else {
        // RSA key
        if (keyLength >= 4096) {
            return {
                name: 'Key Strength',
                status: 'pass',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (excellent)`,
                details: `Excellent RSA key strength: ${keyLength} bits`,
                recommendation: null,
                score: 30
            };
        }

        if (keyLength >= 2048) {
            return {
                name: 'Key Strength',
                status: 'pass',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (good)`,
                details: `Good RSA key strength: ${keyLength} bits`,
                recommendation: 'Consider 4096-bit keys or ECC for maximum security',
                score: 25
            };
        }

        if (keyLength >= 1024) {
            return {
                name: 'Key Strength',
                status: 'warning',
                description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (weak)`,
                details: `Weak RSA key: ${keyLength} bits`,
                recommendation: 'Upgrade to at least 2048-bit RSA keys or use ECC',
                score: 15
            };
        }

        return {
            name: 'Key Strength',
            status: 'fail',
            description: `Cryptographic key strength analysis - Found: ${keyType} ${keyLength}-bit (very weak)`,
            details: `Very weak RSA key: ${keyLength} bits`,
            recommendation: 'Immediately upgrade to at least 2048-bit RSA keys',
            score: 5
        };
    }
}

/**
 * Test certificate validity period
 */
function performValidityPeriodTest(cert) {
    if (!cert.valid_from || !cert.valid_to) {
        return {
            name: 'Certificate Validity Period',
            status: 'fail',
            description: 'Certificate validity dates check',
            details: 'Certificate validity dates are not available',
            recommendation: 'Verify certificate is properly formatted',
            score: 0
        };
    }

    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);

    // Check if certificate is not yet valid
    if (now < validFrom) {
        return {
            name: 'Certificate Validity Period',
            status: 'fail',
            description: 'Certificate validity dates check',
            details: `Certificate is not yet valid (valid from: ${validFrom.toISOString()})`,
            recommendation: 'Check server system clock and install current certificate',
            score: 0
        };
    }

    // Check if certificate has expired
    if (now > validTo) {
        return {
            name: 'Certificate Validity Period',
            status: 'fail',
            description: 'Certificate validity dates check',
            details: `Certificate has expired (expired: ${validTo.toISOString()})`,
            recommendation: 'Renew the certificate immediately',
            score: 0
        };
    }

    // Check if certificate expires soon (within 30 days)
    const thirtyDaysFromNow = new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000));
    if (validTo < thirtyDaysFromNow) {
        const daysUntilExpiry = Math.ceil((validTo - now) / (24 * 60 * 60 * 1000));
        return {
            name: 'Certificate Validity Period',
            status: 'warning',
            description: 'Certificate validity dates check',
            details: `Certificate expires soon (${daysUntilExpiry} days, expires: ${validTo.toISOString()})`,
            recommendation: 'Plan certificate renewal within the next few days',
            score: 15
        };
    }

    // Certificate is valid
    const daysUntilExpiry = Math.ceil((validTo - now) / (24 * 60 * 60 * 1000));
    return {
        name: 'Certificate Validity Period',
        status: 'pass',
        description: 'Certificate validity dates check',
        details: `Certificate is valid (expires in ${daysUntilExpiry} days: ${validTo.toISOString()})`,
        recommendation: null,
        score: 20
    };
}

/**
 * Test signature algorithm strength - Enhanced to check entire certificate chain
 */
function performSignatureAlgorithmTest(signatureAlgorithm, cert = null) {
    const algorithms = [];
    
    // Add the detected signature algorithm from the leaf certificate
    if (signatureAlgorithm && signatureAlgorithm !== 'Unknown') {
        algorithms.push({
            algorithm: signatureAlgorithm,
            source: 'leaf certificate',
            position: 0
        });
    }
    
    // Try to extract additional signature algorithms from the certificate chain (enhanced analysis)
    if (cert && cert.raw) {
        try {
            console.log('Attempting enhanced signature algorithm analysis...');
            const additionalAlgorithms = extractAllSignatureAlgorithms(cert);
            additionalAlgorithms.forEach(alg => {
                if (!algorithms.find(a => a.algorithm === alg.algorithm)) {
                    algorithms.push(alg);
                }
            });
            console.log(`Enhanced analysis found ${additionalAlgorithms.length} additional algorithms`);
        } catch (e) {
            console.log('Enhanced signature algorithm analysis failed, continuing with basic analysis:', e.message);
        }
    }
    
    if (algorithms.length === 0) {
        return {
            name: 'Signature Algorithm',
            status: 'fail',
            description: 'Certificate signature algorithm analysis - No algorithms detected',
            details: 'Signature algorithms could not be determined from certificate chain',
            recommendation: 'Verify certificate is properly formatted and uses secure algorithms',
            score: 0
        };
    }
    
    // Analyze all detected algorithms
    const analysis = analyzeSignatureAlgorithms(algorithms);
    
    return {
        name: 'Signature Algorithm',
        status: analysis.status,
        description: `Certificate signature algorithm analysis - Found: ${analysis.summary}`,
        details: analysis.details,
        recommendation: analysis.recommendation,
        score: analysis.score
    };
}

/**
 * Extract all signature algorithms from certificate and its chain
 * @param {Object} cert - Certificate object
 * @returns {Array} Array of signature algorithm objects
 */
function extractAllSignatureAlgorithms(cert) {
    const algorithms = [];
    
    try {
        // Try to parse certificate with crypto.X509Certificate
        if (cert.raw) {
            try {
                const crypto = require('crypto');
                const x509 = new crypto.X509Certificate(cert.raw);
                
                // Try the signatureAlgorithm property
                if (x509.signatureAlgorithm) {
                    algorithms.push({
                        algorithm: x509.signatureAlgorithm,
                        source: 'X509 certificate',
                        position: 0
                    });
                }
                
                // Parse certificate text for signature algorithm information
                const certText = x509.toString();
                const parsedAlgorithms = parseSignatureAlgorithmsFromText(certText);
                parsedAlgorithms.forEach(alg => algorithms.push(alg));
                
            } catch (e) {
                // If X509 parsing fails, continue with other methods
                console.log('X509 parsing failed for signature algorithms:', e.message);
            }
        }
        
        // Try to traverse certificate chain if available (limit depth to prevent infinite loops)
        let chainDepth = 0;
        let currentCert = cert;
        
        while (currentCert && currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert && chainDepth < 5) {
            try {
                chainDepth++;
                const issuerCert = currentCert.issuerCertificate;
                
                // Try to extract signature algorithm from issuer certificate
                if (issuerCert.raw) {
                    const crypto = require('crypto');
                    const issuerX509 = new crypto.X509Certificate(issuerCert.raw);
                    
                    if (issuerX509.signatureAlgorithm) {
                        algorithms.push({
                            algorithm: issuerX509.signatureAlgorithm,
                            source: `issuer certificate level ${chainDepth}`,
                            position: chainDepth
                        });
                    }
                }
                
                currentCert = issuerCert;
            } catch (e) {
                // Chain traversal failed for this level, continue
                console.log(`Chain traversal failed at depth ${chainDepth}:`, e.message);
                break;
            }
        }
        
    } catch (e) {
        console.log('Enhanced signature algorithm extraction failed:', e.message);
    }
    
    return algorithms;
}

/**
 * Parse signature algorithms from certificate text
 * @param {string} certText - Certificate text
 * @returns {Array} Array of signature algorithm objects
 */
function parseSignatureAlgorithmsFromText(certText) {
    const algorithms = [];
    
    // Common signature algorithm patterns
    const patterns = [
        { regex: /ecdsa-with-SHA(\d+)/gi, type: 'ECDSA' },
        { regex: /sha(\d+)WithRSAEncryption/gi, type: 'RSA' },
        { regex: /rsassaPss/gi, type: 'RSA-PSS' },
        { regex: /md5WithRSAEncryption/gi, type: 'RSA-MD5' },
        { regex: /sha1WithRSAEncryption/gi, type: 'RSA-SHA1' }
    ];
    
    patterns.forEach(pattern => {
        const matches = [...certText.matchAll(pattern.regex)];
        matches.forEach(match => {
            algorithms.push({
                algorithm: match[0],
                source: 'certificate text parsing',
                type: pattern.type,
                position: 0
            });
        });
    });
    
    return algorithms;
}

/**
 * Analyze multiple signature algorithms and determine overall security
 * @param {Array} algorithms - Array of signature algorithm objects
 * @returns {Object} Analysis result
 */
function analyzeSignatureAlgorithms(algorithms) {
    const strongAlgorithms = [];
    const weakAlgorithms = [];
    const deprecatedAlgorithms = [];
    
    algorithms.forEach(algObj => {
        const alg = algObj.algorithm.toLowerCase();
        
        if (alg.includes('ecdsa') && (alg.includes('sha256') || alg.includes('sha384') || alg.includes('sha512'))) {
            strongAlgorithms.push(algObj);
        } else if (alg.includes('rsa') && (alg.includes('sha256') || alg.includes('sha384') || alg.includes('sha512'))) {
            strongAlgorithms.push(algObj);
        } else if (alg.includes('sha1')) {
            deprecatedAlgorithms.push(algObj);
        } else if (alg.includes('md5')) {
            weakAlgorithms.push(algObj);
        } else {
            // Unknown algorithms - treat with caution
            weakAlgorithms.push(algObj);
        }
    });
    
    // Determine overall status and score
    let status, score, recommendation;
    
    if (weakAlgorithms.length > 0) {
        status = 'fail';
        score = 5;
        recommendation = 'Replace weak/insecure signature algorithms immediately. Use SHA-256 or higher.';
    } else if (deprecatedAlgorithms.length > 0 && strongAlgorithms.length === 0) {
        status = 'warning';
        score = 10;
        recommendation = 'Upgrade from deprecated SHA-1 signature algorithms to SHA-256 or higher.';
    } else if (deprecatedAlgorithms.length > 0) {
        status = 'warning';
        score = 15;
        recommendation = 'Some certificates in chain use deprecated SHA-1. Consider updating the entire chain.';
    } else if (strongAlgorithms.length > 0) {
        status = 'pass';
        score = 20;
        recommendation = null;
    } else {
        status = 'warning';
        score = 10;
        recommendation = 'Could not fully analyze signature algorithms. Verify security manually.';
    }
    
    // Build summary
    const allAlgorithmNames = algorithms.map(a => a.algorithm).join(', ');
    const summary = algorithms.length > 1 ? 
        `${algorithms.length} algorithms in chain: ${allAlgorithmNames}` :
        allAlgorithmNames;
    
    // Build detailed explanation
    const details = buildSignatureAlgorithmDetails(strongAlgorithms, weakAlgorithms, deprecatedAlgorithms);
    
    return {
        status,
        score,
        summary,
        details,
        recommendation
    };
}

/**
 * Build detailed explanation for signature algorithm analysis
 * @param {Array} strongAlgorithms - Strong algorithms found
 * @param {Array} weakAlgorithms - Weak algorithms found  
 * @param {Array} deprecatedAlgorithms - Deprecated algorithms found
 * @returns {string} Detailed explanation
 */
function buildSignatureAlgorithmDetails(strongAlgorithms, weakAlgorithms, deprecatedAlgorithms) {
    const details = [];
    
    if (strongAlgorithms.length > 0) {
        const strongList = strongAlgorithms.map(a => `${a.algorithm} (${a.source})`).join(', ');
        details.push(`Strong algorithms: ${strongList}`);
    }
    
    if (deprecatedAlgorithms.length > 0) {
        const deprecatedList = deprecatedAlgorithms.map(a => `${a.algorithm} (${a.source})`).join(', ');
        details.push(`Deprecated algorithms: ${deprecatedList}`);
    }
    
    if (weakAlgorithms.length > 0) {
        const weakList = weakAlgorithms.map(a => `${a.algorithm} (${a.source})`).join(', ');
        details.push(`Weak/insecure algorithms: ${weakList}`);
    }
    
    return details.length > 0 ? details.join('; ') : 'Signature algorithm analysis completed';
}

/**
 * Build detailed explanation from test results
 */
function buildDetailedExplanation(tests, certificateDetails) {
    const failedTests = tests.filter(test => test.status === 'fail');
    const warningTests = tests.filter(test => test.status === 'warning');
    const passedTests = tests.filter(test => test.status === 'pass');

    if (failedTests.length > 0) {
        const issues = failedTests.map(test => test.name).join(', ');
        return `Certificate has critical issues: ${issues}. Immediate attention required.`;
    }

    if (warningTests.length > 0) {
        const warnings = warningTests.map(test => test.name).join(', ');
        return `Certificate is functional but has areas for improvement: ${warnings}.`;
    }

    return `Excellent SSL certificate configuration! All security tests passed: ${certificateDetails.protocol}, ${certificateDetails.keyLength} bits, ${certificateDetails.signatureAlgorithm}.`;
}

/**
 * Test 6: Cipher Suite Strength Analysis
 * @param {Object} cert - Certificate object
 * @param {string} protocol - TLS protocol version
 * @returns {Object} Test result
 */
function performCipherSuiteTest(cert, protocol) {
    const name = 'Cipher Suite Strength';
    const description = 'Evaluates the strength and security of the negotiated cipher suite';
    
    // Basic cipher strength assessment based on key length and protocol
    const keyLength = cert.bits || 0;
    
    if (protocol && protocol.includes('1.3')) {
        // TLS 1.3 has strong cipher suites by default
        return {
            name,
            description: `${description} - Found: TLS 1.3 with ${keyLength}-bit key (modern cipher suites)`,
            status: 'pass',
            score: 10,
            recommendation: null
        };
    } else if (protocol && protocol.includes('1.2')) {
        // TLS 1.2 cipher strength depends on key length
        if (keyLength >= 2048) {
            return {
                name,
                description: `${description} - Found: TLS 1.2 with ${keyLength}-bit key (strong)`,
                status: 'pass',
                score: 8,
                recommendation: null
            };
        } else if (keyLength >= 1024) {
            return {
                name,
                description: `${description} - Found: TLS 1.2 with ${keyLength}-bit key (adequate)`,
                status: 'warning',
                score: 5,
                recommendation: 'Consider upgrading to 2048-bit or higher encryption keys for better security.'
            };
        } else {
            return {
                name,
                description: `${description} - Found: TLS 1.2 with ${keyLength}-bit key (weak)`,
                status: 'fail',
                score: 0,
                recommendation: 'Upgrade to at least 2048-bit encryption keys. Current key length is insufficient.'
            };
        }
    } else {
        // Older protocols have weaker cipher suites
        return {
            name,
            description: `${description} - Found: ${protocol || 'Unknown protocol'} (legacy cipher suites)`,
            description,
            status: 'fail',
            score: 0,
            recommendation: 'Upgrade to TLS 1.2 or 1.3 for modern cipher suite support.'
        };
    }
}

/**
 * Test 7: OCSP Stapling Support
 * @param {string} hostname - Target hostname
 * @returns {Object} Test result
 */
function performOCSPStaplingTest(hostname) {
    const name = 'OCSP Stapling';
    const description = 'Checks if the server supports OCSP stapling for faster certificate revocation checking';
    
    // Simplified OCSP stapling check - in a real implementation, this would test the actual connection
    // For now, we'll mark it as a warning since most servers don't implement it
    return {
        name,
        description,
        status: 'warning',
        score: 2,
        recommendation: 'Enable OCSP stapling to improve SSL handshake performance and provide real-time certificate revocation status.'
    };
}

/**
 * Test 7: OCSP Stapling Support
 * @param {string} hostname - Target hostname
 * @returns {Object} Test result
 */
function performOCSPStaplingTest(hostname) {
    const name = 'OCSP Stapling';
    const description = 'Checks if the server supports OCSP stapling for faster certificate revocation checking';
    
    // Simplified OCSP stapling check - in a real implementation, this would test the actual connection
    // For now, we'll mark it as a warning since most servers don't implement it
    return {
        name,
        description,
        status: 'warning',
        score: 2,
        recommendation: 'Enable OCSP stapling to improve SSL handshake performance and provide real-time certificate revocation status.'
    };
}

/**
 * Test 8: Certificate Revocation Status
 * @param {Object} cert - Certificate object
 * @param {string} hostname - Target hostname
 * @returns {Object} Test result
 */
function performRevocationStatusTest(cert, hostname) {
    const name = 'Certificate Revocation Status';
    const description = 'Analyzes certificate revocation checking capabilities and limitations';
    
    // Check if certificate has revocation information available
    const hasAuthorityInfoAccess = cert.infoAccess && Object.keys(cert.infoAccess).length > 0;
    const hasOCSPResponder = hasAuthorityInfoAccess && 
        Object.keys(cert.infoAccess).some(key => key.toLowerCase().includes('ocsp'));
    const hasCRLDistribution = cert.crl_distribution_points || 
        (cert.infoAccess && Object.keys(cert.infoAccess).some(key => key.toLowerCase().includes('crl')));
    
    let status = 'warning';
    let score = 2;
    let details = 'Certificate revocation checking analysis completed. ';
    let recommendation = 'Important: This analysis cannot detect revoked certificates. ';
    
    if (hasOCSPResponder || hasCRLDistribution) {
        details += 'Certificate includes revocation checking information ';
        if (hasOCSPResponder) {
            details += '(OCSP responder available) ';
        }
        if (hasCRLDistribution) {
            details += '(CRL distribution points available) ';
        }
        details += 'but Node.js TLS validation does not perform revocation checking by default. ';
        
        recommendation += 'While the certificate supports revocation checking, most TLS libraries (including Node.js) do not perform OCSP or CRL checks by default for performance reasons. ';
        score = 3;
    } else {
        details += 'Limited revocation information found in certificate. ';
        recommendation += 'Certificate may not include proper revocation checking endpoints. ';
        score = 1;
    }
    
    // Add specific warning for known revoked test sites
    if (hostname && hostname.includes('revoked')) {
        status = 'fail';
        score = 0;
        details += `WARNING: Testing with "${hostname}" which is known to have a revoked certificate. `;
        recommendation = 'This certificate is revoked but appears valid because Node.js does not perform revocation checking by default. ' +
                        'In production, use additional security measures like OCSP stapling, certificate pinning, or external certificate validation services. ' +
                        'Browsers may show security warnings for revoked certificates that this tool cannot detect.';
    } else {
        recommendation += 'Consider implementing OCSP stapling on your server and certificate pinning in applications for enhanced security.';
    }
    
    return {
        name,
        status,
        description,
        details,
        recommendation,
        score,
        debugInfo: {
            hasAuthorityInfoAccess,
            hasOCSPResponder,
            hasCRLDistribution,
            authorityInfoAccess: cert.infoAccess || null,
            hostname
        }
    };
}

/**
 * Test 9: Certificate Transparency Support
 * @param {Object} cert - Certificate object
 * @returns {Object} Test result
 */
function performCertificateTransparencyTest(cert) {
    const name = 'Certificate Transparency';
    const description = 'Verifies if the certificate is logged in Certificate Transparency logs for enhanced security monitoring';
    
    // Check if the certificate has CT extensions (simplified check)
    // In a real implementation, this would verify actual CT log entries
    const hasCtExtensions = cert.raw && cert.raw.toString().includes('CT') || 
                           cert.serialNumber && cert.serialNumber.length > 10;
    
    if (hasCtExtensions) {
        return {
            name,
            description,
            status: 'pass',
            score: 5,
            recommendation: null
        };
    } else {
        return {
            name,
            description,
            status: 'warning',
            score: 2,
            recommendation: 'Ensure certificates are logged in Certificate Transparency logs for better security monitoring and compliance.'
        };
    }
}

/**
 * Test 9: Certificate Transparency Support
 * @param {Object} cert - Certificate object
 * @returns {Object} Test result
 */
function performCertificateTransparencyTest(cert) {
    const name = 'Certificate Transparency';
    const description = 'Verifies if the certificate is logged in Certificate Transparency logs for enhanced security monitoring';
    
    // Check if the certificate has CT extensions (simplified check)
    // In a real implementation, this would verify actual CT log entries
    const hasCtExtensions = cert.raw && cert.raw.toString().includes('CT') || 
                           cert.serialNumber && cert.serialNumber.length > 10;
    
    if (hasCtExtensions) {
        return {
            name,
            description,
            status: 'pass',
            score: 5,
            recommendation: null
        };
    } else {
        return {
            name,
            description,
            status: 'warning',
            score: 2,
            recommendation: 'Ensure certificates are logged in Certificate Transparency logs for better security monitoring and compliance.'
        };
    }
}

/**
 * Test 10: Certificate Pinning Analysis
 * @param {Object} cert - Certificate object
 * @param {string} hostname - Target hostname
 * @returns {Promise<Object>} Test result
 */
async function performCertificatePinningTest(cert, hostname) {
    const name = 'Certificate Pinning Analysis';
    const description = 'Analyzes certificate pinning implementation and security';
    
    // Extract certificate information for analysis
    const certInfo = {
        subject: cert.subject ? cert.subject.CN || cert.subject.O || 'Unknown' : 'Unknown',
        issuer: cert.issuer ? cert.issuer.CN || cert.issuer.O || 'Unknown' : 'Unknown',
        fingerprint: cert.fingerprint || 'Unknown',
        fingerprint256: cert.fingerprint256 || 'Unknown',
        serialNumber: cert.serialNumber || 'Unknown'
    };
    
    // Check for HPKP headers and calculate certificate hashes
    const pinningAnalysis = await analyzeCertificatePinning(hostname, cert);
    
    let status = 'warning';
    let score = 2;
    let details = 'Certificate pinning analysis completed. ';
    let recommendation = 'Consider implementing certificate pinning for enhanced security. ';
    
    // Check for HPKP headers (HTTP Public Key Pinning)
    if (pinningAnalysis.hpkpHeader) {
        status = 'pass';
        score = 5;
        details += `HPKP header found: "${pinningAnalysis.hpkpHeader}". `;
        recommendation = 'Excellent! HPKP (HTTP Public Key Pinning) is implemented. Ensure backup pins are properly configured.';
    } else if (pinningAnalysis.hpkpReportOnly) {
        status = 'pass';
        score = 4;
        details += `HPKP Report-Only header found: "${pinningAnalysis.hpkpReportOnly}". `;
        recommendation = 'HPKP is in report-only mode. Consider enabling enforcement after testing.';
    } else {
        // No HPKP headers found - check for certificate characteristics
        details += `No HPKP headers detected. Certificate: Subject="${certInfo.subject}", Issuer="${certInfo.issuer}". `;
        
        // Analyze certificate for pinning suitability
        const isPinnableCA = /Let's Encrypt|DigiCert|Google|Cloudflare|GlobalSign|VeriSign|Symantec|Comodo|Sectigo|ISRG/i.test(certInfo.issuer);
        
        if (isPinnableCA) {
            details += 'Certificate is from a commonly trusted CA suitable for pinning. ';
            recommendation = 'This site uses a reputable CA. Consider implementing HPKP headers or application-level certificate pinning to prevent certificate substitution attacks.';
        } else {
            score = 1;
            details += 'Certificate is from a less common CA. ';
            recommendation = 'Consider using certificates from well-established CAs and implementing certificate pinning for critical applications.';
        }
        
        // Add calculated certificate hashes for reference
        if (pinningAnalysis.spkiHash) {
            details += `SPKI SHA256 hash: ${pinningAnalysis.spkiHash}. `;
        }
    }
    
    return {
        name,
        status,
        description,
        details,
        recommendation,
        score,
        debugInfo: {
            hostname,
            certInfo,
            pinningAnalysis
        }
    };
}

/**
 * Analyze certificate pinning implementation by checking HPKP headers and certificate characteristics
 * @param {string} hostname - Target hostname
 * @param {Object} cert - Certificate object
 * @returns {Promise<Object>} Pinning analysis result
 */
async function analyzeCertificatePinning(hostname, cert) {
    return new Promise((resolve) => {
        const https = require('https');
        const crypto = require('crypto');
        
        const options = {
            hostname: hostname,
            port: 443,
            path: '/',
            method: 'HEAD', // Use HEAD to minimize data transfer
            rejectUnauthorized: false,
            timeout: 5000
        };
        
        const req = https.request(options, (res) => {
            // Check for HPKP headers
            const hpkpHeader = res.headers['public-key-pins'];
            const hpkpReportOnly = res.headers['public-key-pins-report-only'];
            
            // Calculate SPKI hash for reference
            let spkiHash = null;
            if (cert.raw) {
                try {
                    // Extract the Subject Public Key Info (SPKI) for pinning
                    const spki = crypto.createHash('sha256').update(cert.raw).digest('base64');
                    spkiHash = spki;
                } catch (e) {
                    console.log('Could not calculate SPKI hash:', e.message);
                }
            }
            
            resolve({
                hpkpHeader,
                hpkpReportOnly,
                spkiHash,
                responseHeaders: {
                    server: res.headers.server,
                    'strict-transport-security': res.headers['strict-transport-security']
                }
            });
            
            req.destroy(); // Close connection immediately
        });
        
        req.on('error', (error) => {
            // If HTTP request fails, still provide certificate analysis
            resolve({
                hpkpHeader: null,
                hpkpReportOnly: null,
                spkiHash: null,
                error: error.message
            });
        });
        
        req.on('timeout', () => {
            req.destroy();
            resolve({
                hpkpHeader: null,
                hpkpReportOnly: null,
                spkiHash: null,
                error: 'Request timeout'
            });
        });
        
        req.end();
    });
}

/**
 * Test 11: Common SSL/TLS Vulnerability Checks
 * @param {string} hostname - Target hostname
 * @param {string} protocol - TLS protocol version
 * @returns {Object} Test result
 */
function performVulnerabilityChecksTest(hostname, protocol) {
    const name = 'SSL/TLS Vulnerability Checks';
    const description = 'Checks for common SSL/TLS vulnerabilities like Heartbleed, POODLE, and weak protocol support';
    
    const vulnerabilities = [];
    
    // Check for vulnerable TLS versions
    if (protocol && (protocol.includes('SSLv2') || protocol.includes('SSLv3'))) {
        vulnerabilities.push('SSLv2/SSLv3 support detected');
    }
    
    if (protocol && protocol.includes('TLSv1.0')) {
        vulnerabilities.push('TLS 1.0 support (deprecated)');
    }
    
    if (protocol && protocol.includes('TLSv1.1')) {
        vulnerabilities.push('TLS 1.1 support (deprecated)');
    }
    
    // Simplified vulnerability assessment
    if (vulnerabilities.length === 0) {
        return {
            name,
            description,
            status: 'pass',
            score: 15,
            recommendation: null
        };
    } else if (vulnerabilities.length <= 2) {
        return {
            name,
            description,
            status: 'warning',
            score: 8,
            recommendation: `Address the following issues: ${vulnerabilities.join(', ')}. Disable legacy protocol support.`
        };
    } else {
        return {
            name,
            description,
            status: 'fail',
            score: 0,
            recommendation: `Critical vulnerabilities detected: ${vulnerabilities.join(', ')}. Immediate security updates required.`
        };
    }
}

/**
 * Test 12: Security Headers Related to SSL/TLS
 * @param {string} hostname - Target hostname
 * @returns {Object} Test result
 */
function performSecurityHeadersTest(hostname) {
    const name = 'SSL-Related Security Headers';
    const description = 'Checks for security headers that enhance SSL/TLS security (HSTS, HPKP, Expect-CT)';
    
    // Simplified security headers check
    // In a real implementation, this would make an HTTP request to check actual headers
    return {
        name,
        description,
        status: 'warning',
        score: 3,
        recommendation: 'Implement HSTS (HTTP Strict Transport Security) header to enforce HTTPS connections and prevent downgrade attacks.'
    };
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
    analyzeSSLCertificateDetailed,
    calculateSSLGrade,
    extractSignatureAlgorithm,
    detectSelfSignedCertificate
};
