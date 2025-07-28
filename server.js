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
const { checkSSLCertificate, analyzeSSLCertificateDetailed } = require('./lib/ssl-analyzer');
const { checkSecurityHeaders } = require('./lib/headers-checker');
const { performAdditionalChecks } = require('./lib/additional-checks');
const { generateSecurityAssessment } = require('./lib/scoring-system');

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
            'enhanced-ssl-analyzer': 'loaded',
            'headers-checker': 'loaded',
            'additional-checks': 'loaded',
            'scoring-system': 'loaded'
        }
    });
});

// Main security analysis endpoint
app.post('/api/analyze', async (req, res) => {
    const startTime = Date.now();

    try {
        const { url } = req.body;

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

        // Step 2: Perform parallel security checks
        console.log(`[${new Date().toISOString()}] Performing security checks...`);

        // Extract hostname for detailed SSL analysis
        const urlObj = new URL(validatedUrl);
        const hostname = urlObj.hostname;
        const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);

        const [sslResult, detailedSslResult, headersResult, additionalResult] = await Promise.allSettled([
            checkSSLCertificate(validatedUrl),
            urlObj.protocol === 'https:' ? analyzeSSLCertificateDetailed(hostname, port) : Promise.resolve(null),
            checkSecurityHeaders(validatedUrl),
            performAdditionalChecks(validatedUrl)
        ]);

        // Process results and handle any failures
        const results = {
            url: validatedUrl,
            urlAssessment: urlAssessment,
            ssl: sslResult.status === 'fulfilled' ? sslResult.value : {
                error: sslResult.reason?.message || 'SSL check failed',
                grade: 'F',
                score: 0
            },
            detailedSsl: detailedSslResult.status === 'fulfilled' ? detailedSslResult.value : null,
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
