/**
 * Security Headers Checker - Main Server
 * Modular Express.js application for comprehensive security analysis
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

// Import custom modules
const { validateUrl, getUrlSecurityAssessment } = require('./lib/url-utils');
const sslAnalyzer = require('./lib/ssl-analyzer/index.js');
const securityHeaders = require('./lib/security-headers/index.js');
const webSecurity = require('./lib/web-security/index.js');
const { generateSecurityAssessment } = require('./lib/scoring-system');
const { checkReachabilityWithRetry, getReachabilitySuggestions } = require('./lib/reachability-checker');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false // Disable for demo purposes
}));
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Serve main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        modules: {
            'url-utils': 'loaded',
            'ssl-analyzer': 'loaded',
            'security-headers': 'loaded',
            'web-security': 'loaded',
            'scoring-system': 'loaded'
        }
    });
});

// Main security analysis endpoint
app.post('/api/analyze', async (req, res) => {
    const startTime = Date.now();

    try {
        const { url, fast } = req.body;

        if (!url) {
            return res.status(400).json({
                error: 'URL is required',
                details: 'Please provide a URL to analyze'
            });
        }

        console.log(`[${new Date().toISOString()}] Starting analysis for: ${url}`);

        // Step 1: Validate URL
        const urlValidation = validateUrl(url);
        if (!urlValidation.valid) {
            return res.status(400).json({
                error: 'Invalid URL',
                details: urlValidation.error,
                suggestions: [
                    'Ensure URL includes protocol (http:// or https://)',
                    'Check for typos in the domain name',
                    'Verify the URL is accessible'
                ]
            });
        }

        const validatedUrl = urlValidation.url;
        const urlAssessment = getUrlSecurityAssessment(validatedUrl);

        // Step 2: Check reachability before expensive operations
        console.log(`[${new Date().toISOString()}] Checking reachability...`);
        const reachabilityResult = await checkReachabilityWithRetry(validatedUrl, 1, 5000); // 1 retry, 5s timeout

        if (!reachabilityResult.reachable) {
            const suggestions = getReachabilitySuggestions(reachabilityResult);

            return res.status(503).json({
                error: 'Host unreachable',
                message: reachabilityResult.message,
                details: reachabilityResult.technicalDetails || 'Unable to establish connection to the target host',
                reachability: {
                    status: reachabilityResult.finalStatus,
                    errorType: reachabilityResult.errorType,
                    attempts: reachabilityResult.totalAttempts,
                    responseTime: reachabilityResult.responseTime
                },
                suggestions: suggestions
            });
        }

        console.log(`[${new Date().toISOString()}] Host reachable (${reachabilityResult.responseTime}ms) - proceeding with security analysis...`);

        // Step 3: Perform parallel security checks
        console.log(`[${new Date().toISOString()}] Performing security checks...`);

        const [sslResult, headersResult, additionalResult] = await Promise.allSettled([
            sslAnalyzer.performSSLAnalysis(validatedUrl, {
                debug: false,
                fast: fast || false // Skip SSLyze if fast mode is requested
            }), // Orchestrated SSL analysis
            securityHeaders.checkSecurityHeaders(validatedUrl),
            webSecurity.performWebSecurityChecks(validatedUrl)
        ]);

        // Process results and handle any failures
        const results = {
            url: validatedUrl,
            urlAssessment: urlAssessment,
            reachability: {
                status: reachabilityResult.finalStatus,
                responseTime: reachabilityResult.responseTime,
                attempts: reachabilityResult.totalAttempts
            },
            ssl: sslResult.status === 'fulfilled' ? {
                // SSL certificate and security info
                ...sslResult.value.basic,
                // Use comprehensive score if available, otherwise fall back to certificate score
                score: sslResult.value.score?.total || sslResult.value.basic?.score || 0,
                maxScore: sslResult.value.score?.maxScore || 100,
                grade: sslResult.value.score?.grade || sslResult.value.basic?.grade || 'F',
                // Ensure recommendations are prominently included
                recommendations: sslResult.value.basic?.recommendations || []
            } : {
                error: sslResult.reason?.message || 'SSL analysis failed',
                grade: 'F',
                score: 0,
                maxScore: 100
            },
            detailedSsl: sslResult.status === 'fulfilled' ? {
                // Structure expected by frontend
                certificateDetails: {
                    issuer: sslResult.value.basic?.issuer || 'Unknown',
                    subject: sslResult.value.basic?.subject || 'Unknown',
                    serialNumber: sslResult.value.basic?.serialNumber || 'Unknown',
                    keyAlgorithm: sslResult.value.basic?.keyAlgorithm || 'Unknown',
                    validFrom: sslResult.value.basic?.validFrom || 'Unknown',
                    validTo: sslResult.value.basic?.validTo || 'Unknown',
                    keyLength: sslResult.value.basic?.keyLength || 0,
                    protocol: sslResult.value.basic?.protocol || 'Unknown',
                    fingerprint: sslResult.value.basic?.fingerprint || 'Unknown',
                    chain: sslResult.value.basic?.certificateChain || []
                },
                tests: sslResult.value.tests || [],
                summary: {
                    grade: sslResult.value.score?.grade || 'F',
                    score: sslResult.value.score?.total || 0,
                    maxScore: sslResult.value.score?.maxScore || 100,
                    testsPassed: sslResult.value.tests ? sslResult.value.tests.filter(t => t.status === 'pass').length : 0,
                    testsTotal: sslResult.value.tests ? sslResult.value.tests.length : 0,
                    explanation: sslResult.value.summary?.message || 'SSL analysis completed'
                },
                combinedResults: sslResult.value.combined,
                sslyzeResults: sslResult.value.sslyze,
                analysisTime: sslResult.value.duration
            } : null,
            headers: headersResult.status === 'fulfilled' ? headersResult.value : {
                error: headersResult.reason?.message || 'Headers check failed',
                headers: [],
                score: 0
            },
            additional: additionalResult.status === 'fulfilled' ? additionalResult.value : {
                error: additionalResult.reason?.message || 'Additional checks failed',
                checks: [],
                score: 0
            }
        };

        // Step 3: Calculate overall security score
        const scores = {
            ssl: {
                score: results.ssl.score || 0,
                maxScore: results.ssl.maxScore || 100
            },
            headers: {
                score: results.headers.score?.normalizedScore || results.headers.score?.score || 0,
                maxScore: 100 // Headers are already normalized to 0-100 via normalizedScore
            },
            additional: results.additional.score || { score: 0, maxScore: 10 },
            accessibility: {
                score: urlAssessment.score || 5,
                maxScore: urlAssessment.maxScore || 10
            }
        };

        const securityAssessment = generateSecurityAssessment(scores, {
            ssl: results.ssl,
            headers: results.headers.headers,
            additional: results.additional.checks
        });

        // Step 4: Prepare response
        const analysisTime = Date.now() - startTime;

        const response = {
            analysis: {
                url: validatedUrl,
                timestamp: new Date().toISOString(),
                analysisTime: `${analysisTime}ms`,
                version: '1.0.0'
            },
            security: securityAssessment,
            details: {
                url: urlAssessment,
                ssl: results.ssl,
                detailedSsl: results.detailedSsl,
                headers: results.headers,
                additional: results.additional
            },
            warnings: urlValidation.warnings || []
        };

        console.log(`[${new Date().toISOString()}] Analysis completed in ${analysisTime}ms - Score: ${securityAssessment.score}/100 (${securityAssessment.grade})`);

        res.json(response);

    } catch (error) {
        console.error('Analysis error:', error);

        const analysisTime = Date.now() - startTime;

        res.status(500).json({
            error: 'Analysis failed',
            details: error.message,
            timestamp: new Date().toISOString(),
            analysisTime: `${analysisTime}ms`,
            suggestions: [
                'Check if the URL is accessible',
                'Verify network connectivity',
                'Try again in a few moments'
            ]
        });
    }
});

// API documentation endpoint
app.get('/api-docs', (req, res) => {
    res.json({
        title: 'Security Headers Checker API',
        version: '1.0.0',
        description: 'Comprehensive security analysis for web applications',
        endpoints: {
            'POST /api/analyze': {
                description: 'Perform comprehensive security analysis',
                parameters: {
                    url: {
                        type: 'string',
                        required: true,
                        description: 'URL to analyze (with or without protocol)'
                    }
                },
                response: {
                    analysis: 'Analysis metadata',
                    security: 'Overall security assessment with score and grade',
                    details: 'Detailed results from each security check (includes enhanced SSL analysis)',
                    warnings: 'Any warnings about the analysis'
                }
            },
            'GET /api/health': {
                description: 'Health check endpoint',
                response: {
                    status: 'Application health status',
                    timestamp: 'Current timestamp',
                    version: 'Application version',
                    modules: 'Status of loaded modules'
                }
            }
        },
        scoring: {
            description: 'Security scores are calculated from multiple components',
            components: {
                'SSL/TLS (30%)': 'Certificate validity, encryption strength, configuration',
                'Security Headers (40%)': 'Implementation of security headers',
                'Additional Checks (20%)': 'HTTPS redirects, HTTP methods, etc.',
                'URL Assessment (10%)': 'Basic URL security evaluation'
            },
            grades: {
                'A+ (95-100)': 'Excellent security posture',
                'A (85-94)': 'Good security implementation',
                'B (75-84)': 'Adequate security with room for improvement',
                'C (65-74)': 'Below average security, needs attention',
                'D (55-64)': 'Poor security, immediate action needed',
                'F (0-54)': 'Critical security issues, urgent remediation required'
            }
        }
    });
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        error: 'API endpoint not found',
        availableEndpoints: [
            'POST /api/analyze',
            'GET /api/health',
            'GET /api-docs'
        ]
    });
});

// Handle other 404s
app.use('*', (req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// Global error handler
app.use((err, req, res, _next) => {
    console.error('Server error:', err);

    res.status(500).json({
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Security Headers Checker running on http://localhost:${PORT}`);
    console.log(`📊 API documentation available at http://localhost:${PORT}/api-docs`);
    console.log(`🏥 Health check available at http://localhost:${PORT}/api/health`);
    console.log(`📁 Serving static files from current directory`);

    // Log loaded modules
    console.log('📦 Loaded modules:');
    console.log('   ✓ URL Utilities');
    console.log('   ✓ SSL Analyzer (Comprehensive)');
    console.log('   ✓ Headers Checker');
    console.log('   ✓ Additional Checks');
    console.log('   ✓ Scoring System');

    console.log(`\n🎯 Ready to analyze security headers and configurations!`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT, shutting down gracefully...');
    process.exit(0);
});

module.exports = app;
