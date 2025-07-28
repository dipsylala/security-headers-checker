/**
 * Security Headers Configuration
 * Defines all security headers, their categories, descriptions, and recommendations
 */

const SECURITY_HEADERS = [
    // Core Security Headers
    {
        name: 'Strict-Transport-Security',
        description: 'Enforces secure HTTPS connections and prevents protocol downgrade attacks',
        recommendation: 'Add HSTS header with max-age, includeSubDomains, and preload directives',
        category: 'critical',
        example: 'max-age=31536000; includeSubDomains; preload'
    },
    {
        name: 'Content-Security-Policy',
        description: 'Controls resource loading to prevent XSS and data injection attacks',
        recommendation: 'Implement a strict CSP with specific source allowlists',
        category: 'critical',
        example: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    },
    {
        name: 'X-Frame-Options',
        description: 'Prevents clickjacking attacks by controlling iframe embedding',
        recommendation: 'Set to DENY or SAMEORIGIN (CSP frame-ancestors is preferred)',
        category: 'important',
        example: 'DENY'
    },
    {
        name: 'X-Content-Type-Options',
        description: 'Prevents MIME type sniffing vulnerabilities',
        recommendation: 'Set to nosniff to prevent MIME confusion attacks',
        category: 'important',
        example: 'nosniff'
    },
    {
        name: 'Referrer-Policy',
        description: 'Controls referrer information sent with requests',
        recommendation: 'Set appropriate policy for privacy and security',
        category: 'important',
        example: 'strict-origin-when-cross-origin'
    },
    {
        name: 'Permissions-Policy',
        description: 'Controls browser feature access and API permissions',
        recommendation: 'Disable unnecessary browser features and APIs',
        category: 'important',
        example: 'geolocation=(), microphone=(), camera=()'
    },
    
    // Legacy but still relevant headers
    {
        name: 'X-XSS-Protection',
        description: 'Legacy XSS protection (superseded by CSP)',
        recommendation: 'Set to "1; mode=block" or "0" if using CSP',
        category: 'legacy',
        example: '1; mode=block'
    },
    
    // Modern Security Headers
    {
        name: 'Cross-Origin-Embedder-Policy',
        description: 'Controls cross-origin resource embedding capabilities',
        recommendation: 'Set to require-corp for enhanced isolation',
        category: 'modern',
        example: 'require-corp'
    },
    {
        name: 'Cross-Origin-Opener-Policy',
        description: 'Controls cross-origin window interactions',
        recommendation: 'Set to same-origin for enhanced isolation',
        category: 'modern',
        example: 'same-origin'
    },
    {
        name: 'Cross-Origin-Resource-Policy',
        description: 'Controls cross-origin resource access',
        recommendation: 'Set appropriate policy for resource sharing',
        category: 'modern',
        example: 'cross-origin'
    },
    {
        name: 'Origin-Agent-Cluster',
        description: 'Requests origin-keyed agent clustering',
        recommendation: 'Set to ?1 for enhanced isolation',
        category: 'modern',
        example: '?1'
    },
    
    // Additional Security Headers
    {
        name: 'X-Permitted-Cross-Domain-Policies',
        description: 'Controls Adobe Flash and PDF cross-domain policies',
        recommendation: 'Set to none to prevent cross-domain access',
        category: 'additional',
        example: 'none'
    },
    {
        name: 'X-Download-Options',
        description: 'Prevents file downloads from being executed in IE',
        recommendation: 'Set to noopen for IE compatibility',
        category: 'additional',
        example: 'noopen'
    },
    {
        name: 'X-DNS-Prefetch-Control',
        description: 'Controls DNS prefetching behavior',
        recommendation: 'Set to off for privacy-sensitive applications',
        category: 'additional',
        example: 'off'
    },
    {
        name: 'Expect-CT',
        description: 'Certificate Transparency monitoring (deprecated)',
        recommendation: 'Consider removing as it is deprecated',
        category: 'deprecated',
        example: 'max-age=86400, enforce'
    },
    
    // Cache and Content Headers
    {
        name: 'Cache-Control',
        description: 'Controls caching behavior for sensitive content',
        recommendation: 'Use no-cache, no-store for sensitive pages',
        category: 'important',
        example: 'no-cache, no-store, must-revalidate'
    },
    {
        name: 'Pragma',
        description: 'Legacy cache control header',
        recommendation: 'Set to no-cache for legacy browser compatibility',
        category: 'legacy',
        example: 'no-cache'
    },
    {
        name: 'Expires',
        description: 'Legacy expiration header',
        recommendation: 'Set to past date to prevent caching',
        category: 'legacy',
        example: '0'
    },
    
    // Server Information Headers (should be removed/minimized)
    {
        name: 'Server',
        description: 'Server software information (security risk if detailed)',
        recommendation: 'Remove or minimize server version information',
        category: 'information',
        example: 'nginx'
    },
    {
        name: 'X-Powered-By',
        description: 'Technology stack information (security risk)',
        recommendation: 'Remove this header to avoid information disclosure',
        category: 'information',
        example: 'Express'
    },
    {
        name: 'X-AspNet-Version',
        description: 'ASP.NET version information (security risk)',
        recommendation: 'Remove this header to avoid version disclosure',
        category: 'information',
        example: '4.0.30319'
    },
    {
        name: 'X-AspNetMvc-Version',
        description: 'ASP.NET MVC version information (security risk)',
        recommendation: 'Remove this header to avoid version disclosure',
        category: 'information',
        example: '5.2'
    }
];

// Header scoring configuration
const HEADER_SCORING = {
    critical: { weight: 3, maxHeaders: 4, points: 15 },
    important: { weight: 2, maxHeaders: 6, points: 10 },
    modern: { weight: 1.5, maxHeaders: 4, points: 8 },
    additional: { weight: 1, maxHeaders: 3, points: 5 },
    legacy: { weight: 0.5, maxHeaders: 3, points: 3 },
    information: { weight: 1, maxHeaders: 4, points: 10 }, // Good when absent
    deprecated: { weight: 0, maxHeaders: 2, points: -2 } // Negative points
};

/**
 * Calculate header-specific score
 * @param {Object} header - Header configuration
 * @param {string} value - Header value (or null if missing)
 * @returns {number} Score for this header
 */
function calculateHeaderScore(header, value) {
    const config = HEADER_SCORING[header.category];
    if (!config) return 0;
    
    if (!value && header.category === 'information') {
        return config.points; // Good that information headers are not present
    }
    
    if (!value) {
        return 0; // Missing header
    }
    
    return config.points;
}

/**
 * Get headers by category
 * @param {string} category - Header category
 * @returns {Array} Headers in the specified category
 */
function getHeadersByCategory(category) {
    return SECURITY_HEADERS.filter(header => header.category === category);
}

/**
 * Get all header categories
 * @returns {Array} List of all categories
 */
function getHeaderCategories() {
    return [...new Set(SECURITY_HEADERS.map(header => header.category))];
}

module.exports = {
    SECURITY_HEADERS,
    HEADER_SCORING,
    calculateHeaderScore,
    getHeadersByCategory,
    getHeaderCategories
};
