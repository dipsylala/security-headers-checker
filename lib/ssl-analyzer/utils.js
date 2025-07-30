/**
 * SSL Analyzer Utilities
 * Common utility functions for SSL/TLS certificate analysis
 */

const crypto = require('crypto');

/**
 * Log certificate debug information
 * @param {Object} cert - Certificate object
 * @param {string} hostname - Target hostname
 * @param {Object} options - Logging options
 */
function logCertificateDebugInfo(cert, hostname, options = {}) {
    if (!options.debug) { return; }

    const timestamp = new Date().toISOString();
    console.log(`\n[${timestamp}] SSL Certificate Debug Information for ${hostname}:`);

    if (!cert) {
        console.log('  No certificate available');
        return;
    }

    console.log(`  Subject: ${cert.subject ? formatX509Name(cert.subject) : 'Unknown'}`);
    console.log(`  Issuer: ${cert.issuer ? formatX509Name(cert.issuer) : 'Unknown'}`);
    console.log(`  Valid From: ${cert.valid_from || 'Unknown'}`);
    console.log(`  Valid To: ${cert.valid_to || 'Unknown'}`);
    console.log(`  Serial Number: ${cert.serialNumber || 'Unknown'}`);
    console.log(`  Fingerprint: ${cert.fingerprint || 'Unknown'}`);
    console.log(`  Key Length: ${cert.bits || 'Unknown'} bits`);
    console.log(`  Signature Algorithm: ${cert.sigalg || 'Unknown'}`);

    if (cert.subjectaltname) {
        console.log(`  Subject Alternative Names: ${cert.subjectaltname}`);
    }

    if (cert.ext_key_usage) {
        console.log(`  Extended Key Usage: ${cert.ext_key_usage.join(', ')}`);
    }

    if (cert.issuerCertificate && cert.issuerCertificate !== cert) {
        console.log(`  Issuer Certificate Subject: ${formatX509Name(cert.issuerCertificate.subject)}`);
    }

    console.log('');
}

/**
 * Format X509 name object to readable string
 * @param {Object} nameObj - X509 name object
 * @returns {string} Formatted name string
 */
function formatX509Name(nameObj) {
    if (!nameObj) { return 'Unknown'; }

    const parts = [];
    if (nameObj.CN) { parts.push(`CN=${nameObj.CN}`); }
    if (nameObj.O) { parts.push(`O=${nameObj.O}`); }
    if (nameObj.OU) { parts.push(`OU=${nameObj.OU}`); }
    if (nameObj.C) { parts.push(`C=${nameObj.C}`); }
    if (nameObj.ST) { parts.push(`ST=${nameObj.ST}`); }
    if (nameObj.L) { parts.push(`L=${nameObj.L}`); }

    return parts.length > 0 ? parts.join(', ') : JSON.stringify(nameObj);
}

/**
 * Clean and normalize hostname for SSL analysis
 * @param {string} hostname - Input hostname
 * @returns {string} Cleaned hostname
 */
function cleanHostname(hostname) {
    if (!hostname) { return ''; }

    // Remove protocol if present
    hostname = hostname.replace(/^https?:\/\//, '');

    // Remove port if present
    hostname = hostname.replace(/:\d+$/, '');

    // Remove path if present
    hostname = hostname.split('/')[0];

    // Remove www prefix for certain analyses
    // hostname = hostname.replace(/^www\./, '');

    return hostname.toLowerCase().trim();
}

/**
 * Validate if hostname matches certificate
 * @param {string} hostname - Target hostname
 * @param {Object} cert - Certificate object
 * @returns {Object} Match validation result
 */
function validateHostnameMatch(hostname, cert) {
    const result = {
        matches: false,
        exactMatch: false,
        wildcardMatch: false,
        sanMatch: false,
        cnMatch: false,
        details: []
    };

    if (!cert) {
        result.details.push('No certificate provided');
        return result;
    }

    const cleanHost = cleanHostname(hostname);

    // Check Common Name (CN)
    if (cert.subject && cert.subject.CN) {
        const cn = cert.subject.CN.toLowerCase();
        if (cn === cleanHost) {
            result.cnMatch = true;
            result.exactMatch = true;
            result.matches = true;
            result.details.push(`Exact CN match: ${cn}`);
        } else if (cn.startsWith('*.') && cleanHost.endsWith(cn.substring(2))) {
            result.cnMatch = true;
            result.wildcardMatch = true;
            result.matches = true;
            result.details.push(`Wildcard CN match: ${cn}`);
        }
    }

    // Check Subject Alternative Names (SAN)
    if (cert.subjectaltname) {
        const sanList = cert.subjectaltname.split(', ');
        for (const san of sanList) {
            const sanValue = san.replace(/^DNS:/, '').toLowerCase();
            if (sanValue === cleanHost) {
                result.sanMatch = true;
                result.exactMatch = true;
                result.matches = true;
                result.details.push(`Exact SAN match: ${sanValue}`);
            } else if (sanValue.startsWith('*.') && cleanHost.endsWith(sanValue.substring(2))) {
                result.sanMatch = true;
                result.wildcardMatch = true;
                result.matches = true;
                result.details.push(`Wildcard SAN match: ${sanValue}`);
            }
        }
    }

    if (!result.matches) {
        result.details.push(`No match found for hostname: ${cleanHost}`);
        if (cert.subject && cert.subject.CN) {
            result.details.push(`Certificate CN: ${cert.subject.CN}`);
        }
        if (cert.subjectaltname) {
            result.details.push(`Certificate SANs: ${cert.subjectaltname}`);
        }
    }

    return result;
}

/**
 * Calculate days until certificate expiration
 * @param {Object} cert - Certificate object
 * @returns {Object} Expiration information
 */
function calculateExpirationInfo(cert) {
    const result = {
        daysUntilExpiration: null,
        isExpired: false,
        isNearExpiration: false,
        validFrom: null,
        validTo: null,
        warning: null
    };

    if (!cert || !cert.valid_to) {
        result.warning = 'Certificate expiration date not available';
        return result;
    }

    try {
        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now = new Date();

        result.validFrom = validFrom;
        result.validTo = validTo;

        if (validTo < now) {
            result.isExpired = true;
            result.daysUntilExpiration = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            result.warning = `Certificate expired ${Math.abs(result.daysUntilExpiration)} days ago`;
        } else {
            result.daysUntilExpiration = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
            if (result.daysUntilExpiration <= 30) {
                result.isNearExpiration = true;
                result.warning = `Certificate expires in ${result.daysUntilExpiration} days`;
            }
        }
    } catch (error) {
        result.warning = `Error calculating expiration: ${error.message}`;
    }

    return result;
}

/**
 * Parse and validate certificate dates
 * @param {Object} cert - Certificate object
 * @returns {Object} Date validation result
 */
function validateCertificateDates(cert) {
    const result = {
        valid: false,
        notBefore: null,
        notAfter: null,
        currentlyValid: false,
        issues: []
    };

    if (!cert) {
        result.issues.push('No certificate provided');
        return result;
    }

    try {
        if (cert.valid_from) {
            result.notBefore = new Date(cert.valid_from);
        }

        if (cert.valid_to) {
            result.notAfter = new Date(cert.valid_to);
        }

        const now = new Date();

        if (result.notBefore && result.notAfter) {
            result.valid = true;

            if (now < result.notBefore) {
                result.issues.push('Certificate is not yet valid');
            } else if (now > result.notAfter) {
                result.issues.push('Certificate has expired');
            } else {
                result.currentlyValid = true;
            }
        } else {
            result.issues.push('Certificate date information incomplete');
        }

    } catch (error) {
        result.issues.push(`Date parsing error: ${error.message}`);
    }

    return result;
}

/**
 * Extract certificate fingerprints
 * @param {Object} cert - Certificate object
 * @returns {Object} Certificate fingerprints
 */
function extractCertificateFingerprints(cert) {
    const fingerprints = {
        sha1: null,
        sha256: null,
        md5: null
    };

    if (!cert) { return fingerprints; }

    // Use existing fingerprint if available
    if (cert.fingerprint) {
        fingerprints.sha1 = cert.fingerprint;
    }

    if (cert.fingerprint256) {
        fingerprints.sha256 = cert.fingerprint256;
    }

    // Calculate additional fingerprints if certificate raw data is available
    if (cert.raw) {
        try {
            fingerprints.sha256 = crypto.createHash('sha256').update(cert.raw).digest('hex').toUpperCase();
            fingerprints.md5 = crypto.createHash('md5').update(cert.raw).digest('hex').toUpperCase();
        } catch (_) {
            // Fingerprint calculation failed, use existing values
        }
    }

    return fingerprints;
}

/**
 * Determine certificate type (DV, OV, EV)
 * @param {Object} cert - Certificate object
 * @returns {Object} Certificate type information
 */
function determineCertificateType(cert) {
    const result = {
        type: 'DV', // Default to Domain Validated
        confidence: 'low',
        indicators: []
    };

    if (!cert) { return result; }

    // Check for Extended Validation indicators
    if (cert.subject) {
        const subject = cert.subject;

        // EV certificates typically have business information
        if (subject.businessCategory || subject.jurisdictionCountryName ||
            subject.jurisdictionStateOrProvinceName || subject.serialNumber) {
            result.type = 'EV';
            result.confidence = 'high';
            result.indicators.push('Contains EV-specific fields');
        } else if (subject.O && subject.O !== subject.CN) {
            // OV certificates have organization information
            result.type = 'OV';
            result.confidence = 'medium';
            result.indicators.push('Contains organization information');
        }
    }

    // Check certificate policies
    if (cert.infoAccess) {
        result.indicators.push('Has Authority Information Access');
    }

    return result;
}

/**
 * Format bytes to human readable format
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted string
 */
function formatBytes(bytes) {
    if (bytes === 0) { return '0 Bytes'; }

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2)) } ${ sizes[i]}`;
}

/**
 * Sanitize hostname for display
 * @param {string} hostname - Input hostname
 * @returns {string} Sanitized hostname
 */
function sanitizeHostname(hostname) {
    if (!hostname) { return ''; }

    // Remove any potential XSS vectors
    return hostname.replace(/[<>"'&]/g, (char) => {
        const entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            '\'': '&#x27;',
            '&': '&amp;'
        };
        return entities[char];
    });
}

/**
 * Create timeout promise for async operations
 * @param {number} ms - Timeout in milliseconds
 * @param {string} operation - Operation description
 * @returns {Promise} Timeout promise
 */
function createTimeout(ms, operation = 'operation') {
    return new Promise((_, reject) => {
        setTimeout(() => {
            reject(new Error(`${operation} timed out after ${ms}ms`));
        }, ms);
    });
}

/**
 * Retry async operation with exponential backoff
 * @param {Function} operation - Async operation to retry
 * @param {number} maxRetries - Maximum number of retries
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise} Operation result
 */
async function retryOperation(operation, maxRetries = 3, baseDelay = 1000) {
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            // eslint-disable-next-line no-await-in-loop
            return await operation();
        } catch (error) {
            lastError = error;

            if (attempt === maxRetries) {
                break;
            }

            const delay = baseDelay * Math.pow(2, attempt);
            // eslint-disable-next-line no-await-in-loop
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    throw lastError;
}

/**
 * Parse URL and extract hostname and port
 * @param {string} url - Input URL
 * @returns {Object} Parsed URL components
 */
function parseUrlComponents(url) {
    const result = {
        hostname: '',
        port: 443,
        protocol: 'https:',
        valid: false
    };

    if (!url) { return result; }

    try {
        // Add protocol if missing
        if (!url.includes('://')) {
            url = `https://${ url}`;
        }

        const parsed = new URL(url);
        result.hostname = parsed.hostname;
        result.port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
        result.protocol = parsed.protocol;
        result.valid = true;
    } catch (_) {
        // Fallback parsing
        const cleaned = url.replace(/^https?:\/\//, '');
        const parts = cleaned.split(':');
        result.hostname = parts[0];
        result.port = parts[1] ? parseInt(parts[1]) : 443;
        result.valid = !!result.hostname;
    }

    return result;
}

module.exports = {
    logCertificateDebugInfo,
    formatX509Name,
    cleanHostname,
    validateHostnameMatch,
    calculateExpirationInfo,
    validateCertificateDates,
    extractCertificateFingerprints,
    determineCertificateType,
    formatBytes,
    sanitizeHostname,
    createTimeout,
    retryOperation,
    parseUrlComponents,

    // Module metadata
    name: 'SSL Analyzer Utilities',
    description: 'Common utility functions for SSL/TLS certificate analysis and validation'
};
