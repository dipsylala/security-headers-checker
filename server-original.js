const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const https = require('https');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false // Disable for demo purposes
}));
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Security headers to check
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

// API endpoint to analyze a URL
app.post('/api/analyze', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // Validate and normalize URL
        const normalizedUrl = normalizeUrl(url);
        if (!normalizedUrl) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        console.log(`Analyzing: ${normalizedUrl}`);

        // Perform security checks
        const results = await performSecurityAnalysis(normalizedUrl);
        
        res.json({
            url: normalizedUrl,
            timestamp: new Date().toISOString(),
            ...results
        });

    } catch (error) {
        console.error('Analysis error:', error);
        res.status(500).json({ 
            error: 'Failed to analyze URL',
            details: error.message 
        });
    }
});

// Normalize URL function
function normalizeUrl(inputUrl) {
    try {
        // Check if it's an IP address
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (ipRegex.test(inputUrl)) {
            return `https://${inputUrl}`;
        }
        
        // Add protocol if missing
        if (!inputUrl.startsWith('http://') && !inputUrl.startsWith('https://')) {
            inputUrl = `https://${inputUrl}`;
        }
        
        const url = new URL(inputUrl);
        return url.toString();
    } catch (error) {
        return null;
    }
}

// Main security analysis function
async function performSecurityAnalysis(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    const results = {
        domain: domain,
        ssl: null,
        headers: [],
        additional: [],
        score: 0
    };

    try {
        // Check SSL certificate
        results.ssl = await checkSSLCertificate(domain, urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80));
        
        // Check security headers
        results.headers = await checkSecurityHeaders(url);
        
        // Perform additional security checks
        results.additional = await performAdditionalChecks(url);
        
        // Calculate overall score
        results.score = calculateSecurityScore(results);
        
    } catch (error) {
        console.error('Error in security analysis:', error);
        throw error;
    }

    return results;
}

// SSL Certificate checking
async function checkSSLCertificate(hostname, port) {
    return new Promise((resolve) => {
        if (port !== 443 && port !== 8443) {
            resolve({
                valid: false,
                error: 'SSL check only available for HTTPS ports',
                issuer: 'N/A',
                subject: hostname,
                validFrom: null,
                validTo: null,
                keyLength: 0,
                signatureAlgorithm: 'N/A',
                protocol: 'N/A',
                grade: 'F',
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
                const cert = socket.getPeerCertificate(true); // Get detailed certificate info
                const protocol = socket.getProtocol();
                
                // Extract signature algorithm with multiple fallback methods
                let signatureAlgorithm = 'Unknown';
                
                // Method 1: Direct sigalg property
                if (cert.sigalg) {
                    signatureAlgorithm = cert.sigalg;
                }
                // Method 2: Alternative property names
                else if (cert.signatureAlgorithm) {
                    signatureAlgorithm = cert.signatureAlgorithm;
                }
                // Method 3: Use crypto module to parse certificate
                else if (cert.raw) {
                    try {
                        const x509 = new crypto.X509Certificate(cert.raw);
                        
                        // Try to get signature algorithm from X509Certificate
                        if (x509.signatureAlgorithm) {
                            signatureAlgorithm = x509.signatureAlgorithm;
                        } else {
                            // Parse the certificate manually for signature algorithm
                            const certPem = x509.toString();
                            
                            // Look for signature algorithm in the certificate text
                            const sigAlgMatch = certPem.match(/Signature Algorithm:\s*([^\n\r]+)/i);
                            if (sigAlgMatch) {
                                signatureAlgorithm = sigAlgMatch[1].trim();
                            } else {
                                // Fallback: infer from key type and common algorithms
                                if (cert.asn1Curve || cert.nistCurve) {
                                    // ECC certificate - likely ECDSA
                                    if (cert.bits >= 384) {
                                        signatureAlgorithm = 'ecdsa-with-SHA384';
                                    } else if (cert.bits >= 256) {
                                        signatureAlgorithm = 'ecdsa-with-SHA256';
                                    } else {
                                        signatureAlgorithm = 'ecdsa-with-SHA1';
                                    }
                                } else {
                                    // RSA certificate - likely RSA with SHA
                                    if (cert.fingerprint256) {
                                        signatureAlgorithm = 'sha256WithRSAEncryption';
                                    } else if (cert.fingerprint) {
                                        signatureAlgorithm = 'sha1WithRSAEncryption';
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        console.log('Could not parse certificate with crypto.X509Certificate:', e.message);
                        
                        // Enhanced fallback: Try to infer from available data
                        if (cert.asn1Curve || cert.nistCurve) {
                            // ECC certificate
                            if (cert.fingerprint256) {
                                signatureAlgorithm = 'ECDSA with SHA-256 (inferred from ECC certificate)';
                            } else if (cert.fingerprint512) {
                                signatureAlgorithm = 'ECDSA with SHA-512 (inferred from ECC certificate)';
                            } else {
                                signatureAlgorithm = 'ECDSA (inferred from ECC certificate)';
                            }
                        } else if (cert.fingerprint256) {
                            signatureAlgorithm = 'RSA with SHA-256 (inferred from fingerprint)';
                        } else if (cert.fingerprint512) {
                            signatureAlgorithm = 'RSA with SHA-512 (inferred from fingerprint)';
                        } else if (cert.fingerprint) {
                            signatureAlgorithm = 'RSA with SHA-1 (inferred from fingerprint)';
                        }
                    }
                }
                
                // Debug log for troubleshooting - show all available properties
                console.log('Certificate properties available:', Object.keys(cert));
                console.log('Certificate type indicators:');
                console.log('- asn1Curve:', cert.asn1Curve);
                console.log('- nistCurve:', cert.nistCurve);
                console.log('- bits:', cert.bits);
                console.log('Certificate sigalg property:', cert.sigalg);
                console.log('Certificate signatureAlgorithm property:', cert.signatureAlgorithm);
                console.log('Final signature algorithm found:', signatureAlgorithm);
                
                // Additional debug - log some certificate details
                if (cert.fingerprint) console.log('Certificate fingerprint (SHA-1):', cert.fingerprint);
                if (cert.fingerprint256) console.log('Certificate fingerprint (SHA-256):', cert.fingerprint256);
                if (cert.fingerprint512) console.log('Certificate fingerprint (SHA-512):', cert.fingerprint512);
                
                const gradeInfo = calculateSSLGrade(cert, protocol, socket.authorized, signatureAlgorithm);
                
                resolve({
                    valid: !socket.authorized ? false : true,
                    error: socket.authorized ? null : socket.authorizationError,
                    issuer: cert.issuer ? cert.issuer.CN || cert.issuer.O || 'Unknown' : 'Unknown',
                    subject: cert.subject ? cert.subject.CN || hostname : hostname,
                    validFrom: cert.valid_from || null,
                    validTo: cert.valid_to || null,
                    keyLength: cert.bits || 0,
                    signatureAlgorithm: signatureAlgorithm,
                    protocol: protocol || 'Unknown',
                    grade: gradeInfo.grade,
                    gradeExplanation: gradeInfo.explanation,
                    recommendations: gradeInfo.recommendations
                });
                
                socket.end();
            } catch (error) {
                const gradeInfo = { grade: 'F', explanation: error.message, recommendations: ['Fix SSL certificate configuration'] };
                
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
                    gradeExplanation: gradeInfo.explanation,
                    recommendations: gradeInfo.recommendations
                });
                socket.end();
            }
        });

        socket.on('error', (error) => {
            const gradeInfo = { grade: 'F', explanation: `Connection error: ${error.message}`, recommendations: ['Check if the website supports HTTPS', 'Verify the hostname is correct'] };
            
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
                gradeExplanation: gradeInfo.explanation,
                recommendations: gradeInfo.recommendations
            });
        });

        socket.setTimeout(10000, () => {
            socket.destroy();
            const gradeInfo = { grade: 'F', explanation: 'Connection timeout - server did not respond within 10 seconds', recommendations: ['Check if the server is online', 'Verify firewall settings allow HTTPS connections'] };
            
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
                gradeExplanation: gradeInfo.explanation,
                recommendations: gradeInfo.recommendations
            });
        });
    });
}

// Calculate SSL Grade with detailed explanations
function calculateSSLGrade(cert, protocol, authorized, signatureAlgorithm = null) {
    const issues = [];
    const recommendations = [];
    let score = 0;
    let explanation = '';
    
    // Check authorization first
    if (!authorized) {
        return {
            grade: 'F',
            explanation: 'SSL certificate is not trusted or has critical security issues',
            recommendations: ['Install a valid SSL certificate from a trusted Certificate Authority', 'Check certificate chain configuration', 'Verify hostname matches certificate']
        };
    }
    
    // Protocol scoring and analysis
    if (protocol === 'TLSv1.3') {
        score += 30;
    } else if (protocol === 'TLSv1.2') {
        score += 25;
    } else if (protocol === 'TLSv1.1') {
        score += 15;
        issues.push('Using outdated TLS 1.1 protocol');
        recommendations.push('Upgrade to TLS 1.2 or 1.3 for better security');
    } else if (protocol === 'TLSv1') {
        score += 10;
        issues.push('Using deprecated TLS 1.0 protocol');
        recommendations.push('Immediately upgrade to TLS 1.2 or 1.3 - TLS 1.0 is insecure');
    } else {
        issues.push('Unknown or unsupported TLS protocol');
        recommendations.push('Configure server to use TLS 1.2 or 1.3');
    }
    
    // Key length scoring and analysis - handle ECC vs RSA differently
    const keyLength = cert.bits || 0;
    const isECC = cert.asn1Curve || cert.nistCurve || (keyLength <= 384 && keyLength >= 224);
    
    if (isECC) {
        // ECC key analysis
        if (keyLength >= 384) {
            score += 30; // P-384 or higher
        } else if (keyLength >= 256) {
            score += 28; // P-256 (very strong for ECC)
        } else if (keyLength >= 224) {
            score += 20; // P-224 (acceptable for ECC)
            issues.push(`ECC key could be stronger: ${keyLength} bits`);
            recommendations.push('Consider upgrading to P-256 or P-384 ECC keys for maximum security');
        } else if (keyLength > 0) {
            score += 10;
            issues.push(`Weak ECC key length: ${keyLength} bits`);
            recommendations.push('Upgrade to at least P-256 ECC keys');
        }
    } else {
        // RSA key analysis
        if (keyLength >= 4096) {
            score += 30;
        } else if (keyLength >= 2048) {
            score += 25;
        } else if (keyLength >= 1024) {
            score += 15;
            issues.push(`Weak RSA key length: ${keyLength} bits`);
            recommendations.push('Use at least 2048-bit RSA keys or 256-bit ECC keys');
        } else if (keyLength > 0) {
            issues.push(`Very weak RSA key length: ${keyLength} bits`);
            recommendations.push('Immediately upgrade to at least 2048-bit RSA keys');
        } else {
            issues.push('Key length information unavailable');
        }
    }
    
    // Certificate validity analysis
    if (cert.valid_from && cert.valid_to) {
        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
        
        if (now >= validFrom && now <= validTo) {
            score += 20;
            if (daysUntilExpiry <= 30) {
                issues.push(`Certificate expires soon (${daysUntilExpiry} days)`);
                recommendations.push('Renew SSL certificate before expiration');
            }
        } else if (now > validTo) {
            issues.push('Certificate has expired');
            recommendations.push('Renew SSL certificate immediately');
        } else if (now < validFrom) {
            issues.push('Certificate is not yet valid');
            recommendations.push('Check system clock or certificate validity dates');
        }
    } else {
        issues.push('Certificate validity dates unavailable');
    }
    
    // Signature algorithm analysis - use provided parameter or fallback to cert property
    const sigAlg = signatureAlgorithm || cert.sigalg || '';
    if (sigAlg && sigAlg !== 'Unknown') {
        // Check for various signature algorithms
        if (sigAlg.toLowerCase().includes('sha256') || sigAlg.toLowerCase().includes('sha-256') || 
            sigAlg.toLowerCase().includes('ecdsa-with-sha256')) {
            score += 20;
        } else if (sigAlg.toLowerCase().includes('sha384') || sigAlg.toLowerCase().includes('sha-384') ||
                   sigAlg.toLowerCase().includes('ecdsa-with-sha384')) {
            score += 20;
        } else if (sigAlg.toLowerCase().includes('sha512') || sigAlg.toLowerCase().includes('sha-512') ||
                   sigAlg.toLowerCase().includes('ecdsa-with-sha512')) {
            score += 20;
        } else if (sigAlg.toLowerCase().includes('ecdsa') && sigAlg.toLowerCase().includes('inferred')) {
            // ECDSA is generally good, give partial credit for inferred
            score += 18;
        } else if (sigAlg.toLowerCase().includes('ecdsa')) {
            // ECDSA without specific hash - still generally secure
            score += 15;
        } else if (sigAlg.toLowerCase().includes('sha1') || sigAlg.toLowerCase().includes('sha-1') ||
                   sigAlg.toLowerCase().includes('ecdsa-with-sha1')) {
            score += 5;
            issues.push('Using deprecated SHA-1 signature algorithm');
            recommendations.push('Upgrade to SHA-256 or higher signature algorithm');
        } else if (sigAlg.toLowerCase().includes('md5')) {
            issues.push('Using insecure MD5 signature algorithm');
            recommendations.push('Immediately upgrade to SHA-256 or higher - MD5 is cryptographically broken');
        } else if (sigAlg.toLowerCase().includes('likely') || sigAlg.toLowerCase().includes('inferred')) {
            // For inferred algorithms, give partial credit based on strength
            if (sigAlg.toLowerCase().includes('sha-256') || sigAlg.toLowerCase().includes('sha256')) {
                score += 18; // Good credit for inferred SHA-256
            } else if (sigAlg.toLowerCase().includes('sha-384') || sigAlg.toLowerCase().includes('sha384')) {
                score += 18; // Good credit for inferred SHA-384
            } else if (sigAlg.toLowerCase().includes('sha-512') || sigAlg.toLowerCase().includes('sha512')) {
                score += 18; // Good credit for inferred SHA-512
            } else if (sigAlg.toLowerCase().includes('sha-1') || sigAlg.toLowerCase().includes('sha1')) {
                score += 8; // Minimal credit for inferred SHA-1
                issues.push('Signature algorithm appears to be SHA-1 (deprecated)');
                recommendations.push('Upgrade to SHA-256 or higher signature algorithm');
            }
        } else {
            score += 5; // Some credit for having algorithm info
            issues.push(`Unknown signature algorithm: ${sigAlg}`);
            recommendations.push('Verify signature algorithm is secure (SHA-256 or higher)');
        }
    } else {
        issues.push('Signature algorithm information unavailable - this may indicate an issue with certificate analysis');
        recommendations.push('This is likely a limitation of our analysis tool rather than your certificate');
    }
    
    // Determine grade
    let grade;
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 60) grade = 'C';
    else if (score >= 50) grade = 'D';
    else grade = 'F';
    
    // Build explanation
    if (issues.length === 0) {
        explanation = `Excellent SSL configuration! Protocol: ${protocol}, Key: ${keyLength} bits, Signature: ${sigAlg || 'Unknown'}`;
    } else {
        explanation = `Issues found: ${issues.join('; ')}. Protocol: ${protocol}, Key: ${keyLength} bits, Signature: ${sigAlg || 'Unknown'}`;
    }
    
    // Add default recommendations if none exist
    if (recommendations.length === 0) {
        recommendations.push('SSL configuration is optimal');
    }
    
    return {
        grade,
        explanation,
        recommendations
    };
}

// Check security headers
async function checkSecurityHeaders(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname || '/',
            method: 'HEAD',
            timeout: 10000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            const headers = SECURITY_HEADERS.map(secHeader => {
                // Check multiple possible header names (case variations)
                const headerValue = response.headers[secHeader.name.toLowerCase()] || 
                                  response.headers[secHeader.name] ||
                                  null;
                
                // Special handling for information disclosure headers
                let status = 'missing';
                let recommendation = secHeader.recommendation;
                
                if (secHeader.category === 'information') {
                    // For information headers, presence is actually negative
                    status = headerValue ? 'present' : 'good';
                    if (headerValue) {
                        recommendation = `Remove this header: "${headerValue}"`;
                    } else {
                        recommendation = 'Good - header not present';
                    }
                } else {
                    status = headerValue ? 'present' : 'missing';
                }
                
                return {
                    name: secHeader.name,
                    present: !!headerValue,
                    value: headerValue || '',
                    description: secHeader.description,
                    recommendation: recommendation,
                    category: secHeader.category,
                    example: secHeader.example || '',
                    status: status,
                    score: calculateHeaderScore(secHeader, headerValue)
                };
            });
            
            resolve(headers);
        });

        request.on('error', (error) => {
            console.error('Headers check error:', error);
            // Return headers with all missing status
            const headers = SECURITY_HEADERS.map(secHeader => ({
                name: secHeader.name,
                present: false,
                value: '',
                description: secHeader.description,
                recommendation: secHeader.recommendation,
                category: secHeader.category,
                example: secHeader.example || '',
                status: 'missing',
                score: 0
            }));
            resolve(headers);
        });

        request.on('timeout', () => {
            console.error('Headers check timeout');
            request.destroy();
            const headers = SECURITY_HEADERS.map(secHeader => ({
                name: secHeader.name,
                present: false,
                value: '',
                description: secHeader.description,
                recommendation: secHeader.recommendation,
                category: secHeader.category,
                example: secHeader.example || '',
                status: 'missing',
                score: 0
            }));
            resolve(headers);
        });

        request.end();
    });
}

// Calculate header-specific score
function calculateHeaderScore(header, value) {
    if (!value && header.category === 'information') {
        return 10; // Good that information headers are not present
    }
    
    if (!value) {
        return 0; // Missing header
    }
    
    // Score based on category importance
    switch (header.category) {
        case 'critical': return 15;
        case 'important': return 10;
        case 'modern': return 8;
        case 'additional': return 5;
        case 'legacy': return 3;
        case 'deprecated': return -2; // Negative score for deprecated headers
        case 'information': return -5; // Negative score for information disclosure
        default: return 5;
    }
}

// Additional security checks
async function performAdditionalChecks(url) {
    const checks = [];
    
    try {
        // HTTPS Redirect check
        const httpsRedirect = await checkHttpsRedirect(url);
        checks.push(httpsRedirect);
        
        // Server information check
        const serverInfo = await checkServerInfo(url);
        checks.push(serverInfo);
        
        // Mixed content check
        const mixedContent = await checkMixedContent(url);
        checks.push(mixedContent);
        
        // HTTP methods check
        const httpMethods = await checkHttpMethods(url);
        checks.push(httpMethods);
        
        // Security.txt check
        const securityTxt = await checkSecurityTxt(url);
        checks.push(securityTxt);
        
    } catch (error) {
        console.error('Additional checks error:', error);
    }
    
    return checks;
}

// Check HTTPS redirect
async function checkHttpsRedirect(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        
        if (urlObj.protocol === 'http:') {
            resolve({
                name: 'HTTPS Redirect',
                status: 'fail',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'URL is using HTTP instead of HTTPS'
            });
            return;
        }
        
        // Check if HTTP version redirects to HTTPS
        const httpUrl = url.replace('https://', 'http://');
        const httpUrlObj = new URL(httpUrl);
        
        const options = {
            hostname: httpUrlObj.hostname,
            port: httpUrlObj.port || 80,
            path: httpUrlObj.pathname || '/',
            method: 'HEAD',
            timeout: 5000
        };

        const request = http.request(options, (response) => {
            const isRedirect = response.statusCode >= 300 && response.statusCode < 400;
            const location = response.headers.location;
            const redirectsToHttps = location && location.startsWith('https://');
            
            if (isRedirect && redirectsToHttps) {
                resolve({
                    name: 'HTTPS Redirect',
                    status: 'pass',
                    description: 'Checks if HTTP requests are redirected to HTTPS',
                    details: `HTTP requests properly redirect to HTTPS (${response.statusCode})`
                });
            } else {
                resolve({
                    name: 'HTTPS Redirect',
                    status: 'warning',
                    description: 'Checks if HTTP requests are redirected to HTTPS',
                    details: 'HTTP requests may not redirect to HTTPS'
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'HTTPS Redirect',
                status: 'pass',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'HTTPS is being used'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTPS Redirect',
                status: 'warning',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: 'Unable to verify HTTP redirect (timeout)'
            });
        });

        request.end();
    });
}

// Check server information
async function checkServerInfo(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname || '/',
            method: 'HEAD',
            timeout: 5000
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            const server = response.headers.server || 'Unknown';
            const poweredBy = response.headers['x-powered-by'] || null;
            
            let details = `Server: ${server}`;
            if (poweredBy) {
                details += `, Powered by: ${poweredBy}`;
            }
            
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: details
            });
        });

        request.on('error', () => {
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: 'Server information unavailable'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: 'Server information unavailable (timeout)'
            });
        });

        request.end();
    });
}

// Check for mixed content issues
async function checkMixedContent(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        
        if (urlObj.protocol !== 'https:') {
            resolve({
                name: 'Mixed Content',
                status: 'warning',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Site is not using HTTPS'
            });
            return;
        }

        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname || '/',
            method: 'GET',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0',
                'Accept': 'text/html'
            }
        };

        const request = https.request(options, (response) => {
            let data = '';
            let dataLength = 0;
            const maxDataLength = 50000; // Limit data to prevent memory issues

            response.on('data', chunk => {
                if (dataLength < maxDataLength) {
                    data += chunk;
                    dataLength += chunk.length;
                }
            });

            response.on('end', () => {
                // Simple check for HTTP resources in HTML
                const httpResources = data.match(/http:\/\/[^"\s>]+/gi);
                
                if (httpResources && httpResources.length > 0) {
                    resolve({
                        name: 'Mixed Content',
                        status: 'warning',
                        description: 'Checks for insecure resources on HTTPS pages',
                        details: `Found ${httpResources.length} potential HTTP resources`
                    });
                } else {
                    resolve({
                        name: 'Mixed Content',
                        status: 'pass',
                        description: 'Checks for insecure resources on HTTPS pages',
                        details: 'No obvious mixed content detected'
                    });
                }
            });
        });

        request.on('error', () => {
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Unable to check mixed content'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Mixed Content',
                status: 'info',
                description: 'Checks for insecure resources on HTTPS pages',
                details: 'Mixed content check timed out'
            });
        });

        request.end();
    });
}

// Check HTTP methods
async function checkHttpMethods(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: urlObj.pathname || '/',
            method: 'OPTIONS',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            const allowHeader = response.headers.allow || '';
            const dangerousMethods = ['PUT', 'DELETE', 'PATCH', 'TRACE'];
            
            // Check response status
            if (response.statusCode === 405) {
                // Method not allowed - this is actually good for security
                resolve({
                    name: 'HTTP Methods',
                    status: 'pass',
                    description: 'Checks for potentially dangerous HTTP methods',
                    details: 'OPTIONS method not allowed (good security practice)'
                });
                return;
            }
            
            if (response.statusCode >= 400) {
                // Other error responses
                resolve({
                    name: 'HTTP Methods',
                    status: 'pass',
                    description: 'Checks for potentially dangerous HTTP methods',
                    details: `Server restricts OPTIONS requests (HTTP ${response.statusCode})`
                });
                return;
            }
            
            if (allowHeader) {
                const foundDangerous = dangerousMethods.filter(method => 
                    allowHeader.toUpperCase().includes(method)
                );

                if (foundDangerous.length > 0) {
                    resolve({
                        name: 'HTTP Methods',
                        status: 'warning',
                        description: 'Checks for potentially dangerous HTTP methods',
                        details: `Dangerous methods enabled: ${foundDangerous.join(', ')} (from Allow: ${allowHeader})`
                    });
                } else {
                    resolve({
                        name: 'HTTP Methods',
                        status: 'pass',
                        description: 'Checks for potentially dangerous HTTP methods',
                        details: `Safe methods only: ${allowHeader}`
                    });
                }
            } else {
                // No Allow header but successful response
                resolve({
                    name: 'HTTP Methods',
                    status: 'info',
                    description: 'Checks for potentially dangerous HTTP methods',
                    details: 'Server accepts OPTIONS but does not advertise allowed methods'
                });
            }
        });

        request.on('error', (error) => {
            // Connection errors often mean the server is properly secured
            if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
                resolve({
                    name: 'HTTP Methods',
                    status: 'info',
                    description: 'Checks for potentially dangerous HTTP methods',
                    details: 'Unable to test HTTP methods (connection error)'
                });
            } else {
                resolve({
                    name: 'HTTP Methods',
                    status: 'info',
                    description: 'Checks for potentially dangerous HTTP methods',
                    details: `HTTP methods check failed: ${error.message}`
                });
            }
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'HTTP Methods',
                status: 'info',
                description: 'Checks for potentially dangerous HTTP methods',
                details: 'HTTP methods check timed out (server may be filtering OPTIONS requests)'
            });
        });

        request.end();
    });
}

// Check for security.txt file
async function checkSecurityTxt(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: '/.well-known/security.txt',
            method: 'HEAD',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            if (response.statusCode === 200) {
                resolve({
                    name: 'Security.txt',
                    status: 'pass',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: 'Security.txt file found - good security practice'
                });
            } else {
                resolve({
                    name: 'Security.txt',
                    status: 'info',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: 'No security.txt file found'
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Unable to check for security.txt'
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Security.txt check timed out'
            });
        });

        request.end();
    });
}

// Calculate overall security score
function calculateSecurityScore(results) {
    let score = 0;
    let maxScore = 0;

    // SSL Score (30 points)
    maxScore += 30;
    if (results.ssl && results.ssl.valid) {
        switch (results.ssl.grade) {
            case 'A+': score += 30; break;
            case 'A': score += 25; break;
            case 'B': score += 20; break;
            case 'C': score += 10; break;
            case 'D': score += 5; break;
            default: score += 0;
        }
    }

    // Headers Score (60 points) - Updated for comprehensive headers
    maxScore += 60;
    
    // Calculate score based on header categories
    const headerScores = {
        critical: { weight: 3, maxHeaders: 4 }, // HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        important: { weight: 2, maxHeaders: 6 }, // Referrer-Policy, Permissions-Policy, Cache-Control, etc.
        modern: { weight: 1.5, maxHeaders: 4 }, // COEP, COOP, CORP, Origin-Agent-Cluster
        additional: { weight: 1, maxHeaders: 3 }, // Various additional headers
        legacy: { weight: 0.5, maxHeaders: 3 }, // Legacy headers (partial credit)
        information: { weight: 1, maxHeaders: 4 } // Information disclosure (good when absent)
    };
    
    let totalHeaderScore = 0;
    let maxHeaderScore = 0;
    
    Object.keys(headerScores).forEach(category => {
        const categoryHeaders = results.headers.filter(h => h.category === category);
        const categoryScore = categoryHeaders.reduce((sum, header) => sum + (header.score || 0), 0);
        const categoryMaxScore = headerScores[category].maxHeaders * 
            (category === 'critical' ? 15 : 
             category === 'important' ? 10 : 
             category === 'modern' ? 8 : 
             category === 'additional' ? 5 : 
             category === 'legacy' ? 3 : 
             category === 'information' ? 10 : 5) * headerScores[category].weight;
        
        totalHeaderScore += categoryScore * headerScores[category].weight;
        maxHeaderScore += categoryMaxScore;
    });
    
    // Normalize header score to 60 points
    if (maxHeaderScore > 0) {
        score += Math.min(60, (totalHeaderScore / maxHeaderScore) * 60);
    }

    // Additional checks (10 points) - Reduced to accommodate more header scoring
    maxScore += 10;
    const passedChecks = results.additional.filter(check => check.status === 'pass').length;
    const totalChecks = results.additional.filter(check => check.status !== 'info').length;
    if (totalChecks > 0) {
        score += (passedChecks / totalChecks) * 10;
    } else {
        score += 5; // Partial credit if no additional checks
    }

    return Math.round(Math.max(0, Math.min(100, score))); // Ensure score is between 0-100
}

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Security Headers Checker running on port ${PORT}`);
    console.log(`Open your browser to http://localhost:${PORT}`);
});

module.exports = { app, performSecurityAnalysis };
