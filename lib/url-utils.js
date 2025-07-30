/**
 * URL Utilities Module
 * Handles URL parsing, validation, and construction utilities
 */

/**
 * Parse and validate a URL string
 * @param {string} url - The URL to parse
 * @returns {Object} Parsed URL data with validation status
 */
function parseAndValidateUrl(url) {
    try {
        // Add protocol if missing
        let processedUrl = url;
        if (!url.includes('://')) {
            processedUrl = `https://${ url}`;
        }

        const urlObj = new URL(processedUrl);

        return {
            isValid: true,
            url: urlObj.href,
            protocol: urlObj.protocol,
            hostname: urlObj.hostname,
            port: urlObj.port,
            pathname: urlObj.pathname,
            search: urlObj.search,
            hash: urlObj.hash,
            origin: urlObj.origin,
            isHttps: urlObj.protocol === 'https:',
            isHttp: urlObj.protocol === 'http:',
            isSecure: urlObj.protocol === 'https:',
            domain: urlObj.hostname,
            domainParts: urlObj.hostname.split('.'),
            hasPort: !!urlObj.port,
            originalInput: url,
            processedInput: processedUrl
        };
    } catch (error) {
        return {
            isValid: false,
            error: error.message,
            originalInput: url,
            processedInput: null
        };
    }
}

/**
 * Validate URL format and protocol
 * @param {string} url - The URL to validate
 * @returns {Object} Validation result with details
 */
function validateUrl(url) {
    const parsed = parseAndValidateUrl(url);

    if (!parsed.isValid) {
        return {
            valid: false,
            error: 'Invalid URL format',
            details: parsed.error
        };
    }

    // Check for supported protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        return {
            valid: false,
            error: 'Unsupported protocol',
            details: `Protocol ${parsed.protocol} is not supported. Only HTTP and HTTPS are allowed.`
        };
    }

    // Check for valid hostname
    if (!parsed.hostname || parsed.hostname.length === 0) {
        return {
            valid: false,
            error: 'Invalid hostname',
            details: 'URL must contain a valid hostname'
        };
    }

    // Check for localhost or private IP warnings
    const warnings = [];
    if (isLocalhost(parsed.hostname)) {
        warnings.push('Using localhost - results may not represent production environment');
    }

    if (isPrivateIP(parsed.hostname)) {
        warnings.push('Using private IP address - may not be publicly accessible');
    }

    return {
        valid: true,
        url: parsed.url,
        parsed: parsed,
        warnings: warnings
    };
}

/**
 * Check if hostname is localhost
 * @param {string} hostname - The hostname to check
 * @returns {boolean} True if localhost
 */
function isLocalhost(hostname) {
    const localhostPatterns = [
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0'
    ];

    return localhostPatterns.some(pattern =>
        hostname.toLowerCase() === pattern ||
        hostname.toLowerCase().startsWith(`${pattern }:`)
    );
}

/**
 * Check if hostname is a private IP address
 * @param {string} hostname - The hostname to check
 * @returns {boolean} True if private IP
 */
function isPrivateIP(hostname) {
    // IPv4 private ranges
    const ipv4PrivateRanges = [
        /^10\./, // 10.0.0.0/8
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
        /^192\.168\./, // 192.168.0.0/16
        /^169\.254\./ // 169.254.0.0/16 (link-local)
    ];

    return ipv4PrivateRanges.some(range => range.test(hostname));
}

/**
 * Get URL security assessment
 * @param {string} url - The URL to assess
 * @returns {Object} Security assessment
 */
function getUrlSecurityAssessment(url) {
    const parsed = parseAndValidateUrl(url);

    if (!parsed.isValid) {
        return {
            score: 0,
            issues: ['Invalid URL format'],
            recommendations: ['Provide a valid URL']
        };
    }

    const issues = [];
    const recommendations = [];
    let score = 10;

    // Check protocol security
    if (!parsed.isSecure) {
        issues.push('Using insecure HTTP protocol');
        recommendations.push('Use HTTPS instead of HTTP');
        score -= 5;
    }

    // Check for non-standard ports
    if (parsed.hasPort &&
        !['443', '80'].includes(parsed.port) &&
        !isLocalhost(parsed.hostname)) {
        issues.push(`Using non-standard port: ${parsed.port}`);
        recommendations.push('Consider using standard ports (80/443) for production');
        score -= 1;
    }

    // Check for localhost/development environments
    if (isLocalhost(parsed.hostname)) {
        issues.push('Using localhost - not suitable for production assessment');
        recommendations.push('Test against production or staging environment');
        score -= 2;
    }

    // Check for private IPs
    if (isPrivateIP(parsed.hostname)) {
        issues.push('Using private IP address');
        recommendations.push('Ensure URL is publicly accessible for accurate results');
        score -= 1;
    }

    return {
        score: Math.max(0, score),
        maxScore: 10,
        issues: issues,
        recommendations: recommendations,
        isSecure: parsed.isSecure,
        isPublic: !isLocalhost(parsed.hostname) && !isPrivateIP(parsed.hostname)
    };
}

module.exports = {
    validateUrl,
    getUrlSecurityAssessment
};
