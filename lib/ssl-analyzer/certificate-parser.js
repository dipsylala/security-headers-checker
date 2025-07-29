/**
 * Certificate Parser and Analysis Module
 * Handles certificate parsing, signature extraction, and detailed analysis
 */

const crypto = require('crypto');

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
            daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
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
            return `ECDSA ${cert.asn1Curve}`;
        } else {
            return `ECDSA (${keyLength}-bit)`;
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
            confidence = 'very_high';
            reason += ' and certificate has CA flag set';
        }
        
        if (isSelfReferential) {
            confidence = 'very_high';
            reason += ' and certificate is self-referential';
        }
    } else if (cnMatches && orgMatches) {
        isSelfSigned = true;
        confidence = 'medium';
        reason = 'Common Name and Organization match between subject and issuer';
    } else if (cnMatches) {
        isSelfSigned = true;
        confidence = 'low';
        reason = 'Common Name matches between subject and issuer';
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
    if (!dn) return 'Unknown';
    
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
        return 'ECDSA with SHA-256';
    } else if (cert.bits) {
        return 'RSA with SHA-256';
    }

    return 'Unknown';
}

module.exports = {
    extractSignatureAlgorithm,
    buildCertificateChain,
    extractOrganizationInfo,
    extractCertificateExtensions,
    analyzeCertificateValidity,
    determineKeyAlgorithm,
    detectSelfSignedCertificate,
    formatDistinguishedName,
    inferSignatureAlgorithm,
    
    // Module metadata
    name: 'Certificate Parser and Analyzer',
    description: 'Certificate parsing, analysis, and detailed information extraction'
};
