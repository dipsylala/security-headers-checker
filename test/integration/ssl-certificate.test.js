const assert = require('assert');
const http = require('http');

/**
 * SSL/TLS Certificate Integration Tests
 * Tests SSL certificate analysis, grading, and signature algorithm detection
 */

/**
 * Make HTTP request to the analysis API
 * @param {string} url - URL to analyze
 * @param {Object} options - Request options
 * @returns {Promise<Object>} Analysis result
 */
function performSecurityAnalysis(url, options = {}) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            url,
            fast: options.fast || false // Add fast option for basic SSL tests
        });

        const requestOptions = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/analyze',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: options.timeout || 15000 // Reduced timeout for faster tests
        };

        const req = http.request(requestOptions, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    if (res.statusCode === 200) {
                        resolve(result);
                    } else {
                        reject(new Error(result.error || `HTTP ${res.statusCode}`));
                    }
                } catch (error) {
                    reject(new Error(`Failed to parse response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.on('timeout', () => {
            req.destroy();
            reject(new Error(`Request timeout - analysis took longer than ${requestOptions.timeout / 1000} seconds`));
        });

        req.write(postData);
        req.end();
    });
}

const SSL_TEST_SITES = [
    {
        name: 'GitHub SSL Analysis',
        url: 'https://github.com',
        expectedResults: {
            valid: true,
            protocol: ['TLSv1.2', 'TLSv1.3'],
            gradeExpectation: ['A+', 'A', 'B'],
            minKeyLength: 256 // ECC certificates
        }
    },
    {
        name: 'Google SSL Analysis',
        url: 'https://google.com',
        expectedResults: {
            valid: true,
            protocol: ['TLSv1.2', 'TLSv1.3'],
            gradeExpectation: ['A+', 'A'],
            minKeyLength: 256 // ECC certificates
        }
    },
    {
        name: 'Cloudflare SSL Analysis',
        url: 'https://cloudflare.com',
        expectedResults: {
            valid: true,
            protocol: ['TLSv1.2', 'TLSv1.3'],
            gradeExpectation: ['A+', 'A'],
            minKeyLength: 256
        }
    },
    {
        name: 'Mozilla SSL Analysis (RSA)',
        url: 'https://developer.mozilla.org',
        expectedResults: {
            valid: true,
            protocol: ['TLSv1.2', 'TLSv1.3'],
            gradeExpectation: ['A+', 'A', 'B'],
            minKeyLength: 2048 // RSA certificates
        }
    }
];

async function runSSLTests() {
    console.log('🔒 Starting SSL/TLS Certificate Integration Tests...\n');

    const results = [];

    for (const test of SSL_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);

        try {
            const analysis = await performSecurityAnalysis(test.url, { fast: true }); // Use fast mode for SSL tests
            const ssl = analysis.details.ssl; // Updated path for modular API

            // Display SSL information
            console.log(`🔒 SSL Valid: ${ssl.valid}`);
            console.log(`🔐 Protocol: ${ssl.protocol}`);
            console.log(`🔑 Key Length: ${ssl.keyLength} bits`);
            console.log(`📜 Signature Algorithm: ${ssl.signatureAlgorithm}`);
            console.log(`🎯 Grade: ${ssl.grade}`);

            if (ssl.gradeExplanation) {
                console.log(`💬 Explanation: ${ssl.gradeExplanation}`);
            }

            // Test signature algorithm detection
            const signatureTests = {
                isNotUnknown: ssl.signatureAlgorithm !== 'Unknown',
                isNotUnavailable: !ssl.signatureAlgorithm.includes('unavailable'),
                hasAlgorithmInfo: ssl.signatureAlgorithm && ssl.signatureAlgorithm.length > 0,
                isValidAlgorithm: ssl.signatureAlgorithm && (
                    ssl.signatureAlgorithm.includes('ecdsa') ||
                    ssl.signatureAlgorithm.includes('rsa') ||
                    ssl.signatureAlgorithm.includes('RSA') ||
                    ssl.signatureAlgorithm.includes('SHA')
                )
            };

            console.log(`🧬 Signature Algorithm Tests:`);
            console.log(`   ✓ Not Unknown: ${signatureTests.isNotUnknown}`);
            console.log(`   ✓ Not Unavailable: ${signatureTests.isNotUnavailable}`);
            console.log(`   ✓ Has Algorithm Info: ${signatureTests.hasAlgorithmInfo}`);
            console.log(`   ✓ Valid Algorithm: ${signatureTests.isValidAlgorithm}`);

            // Validation
            let testPassed = true;
            const testErrors = [];

            // SSL validity test
            try {
                assert.strictEqual(ssl.valid, test.expectedResults.valid,
                    `SSL validity should be ${test.expectedResults.valid}`);
            } catch (e) {
                testErrors.push(e.message);
                testPassed = false;
            }

            // Protocol test
            if (test.expectedResults.protocol) {
                try {
                    assert(test.expectedResults.protocol.includes(ssl.protocol),
                        `SSL protocol should be one of ${test.expectedResults.protocol.join(', ')}, got ${ssl.protocol}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            // Grade test
            if (test.expectedResults.gradeExpectation) {
                try {
                    assert(test.expectedResults.gradeExpectation.includes(ssl.grade),
                        `SSL grade should be one of ${test.expectedResults.gradeExpectation.join(', ')}, got ${ssl.grade}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            // Key length test
            if (test.expectedResults.minKeyLength) {
                try {
                    assert(ssl.keyLength >= test.expectedResults.minKeyLength,
                        `Key length should be at least ${test.expectedResults.minKeyLength} bits, got ${ssl.keyLength}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            // Signature algorithm tests
            try {
                assert(signatureTests.isNotUnknown && signatureTests.hasAlgorithmInfo && signatureTests.isValidAlgorithm,
                    'Signature algorithm detection should work properly');
            } catch (e) {
                testErrors.push(e.message);
                testPassed = false;
            }

            results.push({
                test: test.name,
                url: test.url,
                passed: testPassed,
                errors: testErrors,
                ssl: ssl,
                signatureTests: signatureTests
            });

            if (testPassed) {
                console.log(`✅ ${test.name} PASSED\n`);
            } else {
                console.log(`❌ ${test.name} FAILED: ${testErrors.join('; ')}\n`);
            }

        } catch (error) {
            console.error(`❌ ${test.name} FAILED: ${error.message}\n`);
            results.push({
                test: test.name,
                url: test.url,
                passed: false,
                error: error.message
            });
        }
    }

    // Summary
    console.log('📊 SSL Certificate Test Summary:');
    console.log('═'.repeat(50));

    const passed = results.filter(r => r.passed).length;
    const total = results.length;

    console.log(`✅ Overall Results: ${passed}/${total} tests passed`);

    if (passed < total) {
        console.log('\n❌ Failed Tests:');
        results.filter(r => !r.passed).forEach(result => {
            console.log(`   • ${result.test}: ${result.errors?.join(', ') || result.error}`);
        });
    }

    // SSL Grade Distribution
    const sslResults = results.filter(r => r.passed && r.ssl);
    if (sslResults.length > 0) {
        console.log('\n🏆 SSL Grade Distribution:');
        const gradeDistribution = {};
        sslResults.forEach(r => {
            gradeDistribution[r.ssl.grade] = (gradeDistribution[r.ssl.grade] || 0) + 1;
        });
        Object.keys(gradeDistribution).sort().forEach(grade => {
            console.log(`   ${grade}: ${gradeDistribution[grade]} site(s)`);
        });

        // Signature Algorithm Summary
        console.log('\n🔐 Signature Algorithm Summary:');
        const workingAlgorithms = sslResults.filter(r => r.signatureTests?.isValidAlgorithm).length;
        console.log(`   Working detection: ${workingAlgorithms}/${sslResults.length}`);

        sslResults.forEach(r => {
            if (r.ssl && r.ssl.signatureAlgorithm) {
                console.log(`   ${r.test.split(' ')[0]}: ${r.ssl.signatureAlgorithm}`);
            }
        });
    }

    return results;
}

// Export for use in main test runner
module.exports = { runSSLTests, SSL_TEST_SITES };

// Run tests if called directly
if (require.main === module) {
    runSSLTests()
        .then(results => {
            const allPassed = results.every(r => r.passed);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 SSL test runner failed:', error);
            process.exit(1);
        });
}
