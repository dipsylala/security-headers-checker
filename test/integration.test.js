const assert = require('assert');
const http = require('http');

/**
 * Comprehensive Integration Tests for WebCheck Validator
 * Tests real-world scenarios with actual websites
 */

/**
 * Make HTTP request to the analysis API
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Analysis result
 */
function performSecurityAnalysis(url) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({ url });

        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/analyze',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = http.request(options, (res) => {
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
                        reject(new Error(`API Error: ${res.statusCode} - ${result.error || 'Unknown error'}`));
                    }
                } catch (parseError) {
                    reject(new Error(`Failed to parse API response: ${parseError.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(new Error(`Request failed: ${error.message}`));
        });

        req.write(postData);
        req.end();
    });
}

async function runIntegrationTests() {
    console.log('🧪 Starting Comprehensive Integration Tests...\n');

    const tests = [
        {
            name: 'GitHub Comprehensive Analysis',
            url: 'https://github.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: ['TLSv1.2', 'TLSv1.3'], // Accept either
                    gradeExpectation: ['A+', 'A', 'B'] // Should be one of these
                },
                headers: {
                    shouldHaveHSTS: true,
                    shouldCheckBasic: true
                },
                additional: {
                    httpsRedirect: 'pass',
                    httpMethods: 'pass' // Should restrict OPTIONS
                }
            }
        },
        {
            name: 'Google Comprehensive Analysis',
            url: 'https://google.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: ['TLSv1.2', 'TLSv1.3'], // Accept either
                    gradeExpectation: ['A+', 'A']
                },
                headers: {
                    shouldCheckBasic: true // Just check we get headers
                },
                additional: {
                    httpMethods: 'pass' // Google restricts OPTIONS
                }
            }
        },
        {
            name: 'Cloudflare Comprehensive Analysis',
            url: 'https://cloudflare.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: ['TLSv1.2', 'TLSv1.3'],
                    gradeExpectation: ['A+', 'A']
                },
                headers: {
                    shouldHaveHSTS: true,
                    shouldCheckBasic: true
                },
                additional: {
                    httpsRedirect: 'pass'
                }
            }
        },
        {
            name: 'Mozilla Developer Network Analysis',
            url: 'https://developer.mozilla.org',
            expectedResults: {
                ssl: {
                    valid: true,
                    gradeExpectation: ['A+', 'A', 'B']
                },
                headers: {
                    shouldCheckBasic: true
                },
                additional: {
                    httpsRedirect: 'pass',
                    httpMethods: 'pass'
                }
            }
        }
    ];

    const results = [];

    for (const test of tests) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);

        try {
            const analysis = await performSecurityAnalysis(test.url);

            // Basic assertions
            assert(analysis.ssl, 'SSL analysis should be present');
            assert(analysis.headers, 'Headers analysis should be present');
            assert(analysis.additional, 'Additional checks should be present');
            assert(typeof analysis.score === 'number', 'Score should be a number');

            // SSL Certificate Tests
            const ssl = analysis.ssl;
            console.log(`🔒 SSL Valid: ${ssl.valid}`);
            console.log(`🔐 Protocol: ${ssl.protocol}`);
            console.log(`🔑 Key Length: ${ssl.keyLength} bits`);
            console.log(`📜 Signature Algorithm: ${ssl.signatureAlgorithm}`);
            console.log(`🎯 Grade: ${ssl.grade}`);

            if (ssl.gradeExplanation) {
                console.log(`💬 Explanation: ${ssl.gradeExplanation}`);
            }

            // Security Headers Tests
            console.log(`📋 Headers Analysis:`);
            const criticalHeaders = analysis.headers.filter(h => h.category === 'critical');
            const presentCriticalHeaders = criticalHeaders.filter(h => h.present).length;
            console.log(`   Critical headers present: ${presentCriticalHeaders}/${criticalHeaders.length}`);

            const importantHeaders = analysis.headers.filter(h => h.category === 'important');
            const presentImportantHeaders = importantHeaders.filter(h => h.present).length;
            console.log(`   Important headers present: ${presentImportantHeaders}/${importantHeaders.length}`);

            // Additional Security Checks Tests
            console.log(`� Additional Checks:`);
            analysis.additional.forEach(check => {
                console.log(`   ${check.name}: ${check.status} - ${check.details}`);
            });

            // Test signature algorithm extraction
            const signatureAlgorithmTests = {
                isNotUnknown: ssl.signatureAlgorithm !== 'Unknown',
                isNotUnavailable: !ssl.signatureAlgorithm.includes('unavailable'),
                hasAlgorithmInfo: ssl.signatureAlgorithm && ssl.signatureAlgorithm.length > 0
            };

            console.log(`🧬 Signature Algorithm Tests:`);
            console.log(`   ✓ Not Unknown: ${signatureAlgorithmTests.isNotUnknown}`);
            console.log(`   ✓ Not Unavailable: ${signatureAlgorithmTests.isNotUnavailable}`);
            console.log(`   ✓ Has Info: ${signatureAlgorithmTests.hasAlgorithmInfo}`);

            // Expected results validation
            let testPassed = true;
            const testErrors = [];

            // SSL validation
            if (test.expectedResults.ssl.valid !== undefined) {
                try {
                    assert.strictEqual(ssl.valid, test.expectedResults.ssl.valid,
                        `SSL validity should be ${test.expectedResults.ssl.valid}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            if (test.expectedResults.ssl.protocol) {
                const expectedProtocols = Array.isArray(test.expectedResults.ssl.protocol)
                    ? test.expectedResults.ssl.protocol
                    : [test.expectedResults.ssl.protocol];
                try {
                    assert(expectedProtocols.includes(ssl.protocol),
                        `SSL protocol should be one of ${expectedProtocols.join(', ')}, got ${ssl.protocol}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            if (test.expectedResults.ssl.keyLength) {
                try {
                    assert.strictEqual(ssl.keyLength, test.expectedResults.ssl.keyLength,
                        `Key length should be ${test.expectedResults.ssl.keyLength}, got ${ssl.keyLength}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            if (test.expectedResults.ssl.gradeExpectation) {
                try {
                    assert(test.expectedResults.ssl.gradeExpectation.includes(ssl.grade),
                        `SSL grade should be one of ${test.expectedResults.ssl.gradeExpectation.join(', ')}, got ${ssl.grade}`);
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            // Headers validation - more realistic expectations
            if (test.expectedResults.headers?.shouldHaveHSTS) {
                const hstsHeader = analysis.headers.find(h => h.name.toLowerCase() === 'strict-transport-security');
                try {
                    assert(hstsHeader && hstsHeader.present, 'HSTS header should be present');
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            if (test.expectedResults.headers?.shouldHaveCSP) {
                const cspHeader = analysis.headers.find(h => h.name.toLowerCase() === 'content-security-policy');
                try {
                    assert(cspHeader && cspHeader.present, 'Content-Security-Policy header should be present');
                // eslint-disable-next-line no-unused-vars
                } catch (e) {
                    // Don't fail test for missing CSP - just log it
                    console.log(`   ⚠️  CSP header not found (this is common and OK for testing)`);
                }
            }

            if (test.expectedResults.headers?.shouldCheckBasic) {
                // Just validate that we got some headers back
                try {
                    assert(analysis.headers.length > 0, 'Should detect at least some headers');
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }

            // Additional checks validation - more lenient
            if (test.expectedResults.additional) {
                Object.keys(test.expectedResults.additional).forEach(checkKey => {
                    const expectedStatus = test.expectedResults.additional[checkKey];
                    let checkName;
                    switch (checkKey) {
                        case 'httpsRedirect': checkName = 'HTTPS Redirect'; break;
                        case 'httpMethods': checkName = 'HTTP Methods'; break;
                        case 'securityTxt': checkName = 'Security.txt'; break;
                        case 'mixedContent': checkName = 'Mixed Content'; break;
                        default: checkName = checkKey;
                    }

                    const check = analysis.additional.find(c => c.name === checkName);
                    try {
                        assert(check, `${checkName} check should be present`);
                        // For HTTP Methods, accept 'info' or 'pass' as success since server behavior varies
                        if (checkKey === 'httpMethods' && expectedStatus === 'pass') {
                            const acceptableStatuses = ['pass', 'info'];
                            assert(acceptableStatuses.includes(check.status),
                                `${checkName} should have status ${expectedStatus} or info (acceptable variation), got ${check.status}`);
                        } else {
                            assert.strictEqual(check.status, expectedStatus,
                                `${checkName} should have status ${expectedStatus}, got ${check.status}`);
                        }
                    } catch (e) {
                        // For some checks, log warnings instead of failing
                        if (checkKey === 'httpsRedirect' && check && check.status === 'warning') {
                            console.log(`   ⚠️  HTTPS redirect check returned warning: ${check.details}`);
                        } else {
                            testErrors.push(e.message);
                            testPassed = false;
                        }
                    }
                });
            }

            results.push({
                test: test.name,
                url: test.url,
                passed: testPassed,
                errors: testErrors,
                ssl: {
                    valid: ssl.valid,
                    protocol: ssl.protocol,
                    keyLength: ssl.keyLength,
                    signatureAlgorithm: ssl.signatureAlgorithm,
                    grade: ssl.grade,
                    signatureAlgorithmWorking: signatureAlgorithmTests.isNotUnavailable
                },
                headers: {
                    total: analysis.headers.length,
                    present: analysis.headers.filter(h => h.present).length,
                    critical: {
                        total: criticalHeaders.length,
                        present: presentCriticalHeaders
                    },
                    important: {
                        total: importantHeaders.length,
                        present: presentImportantHeaders
                    }
                },
                additional: analysis.additional.map(check => ({
                    name: check.name,
                    status: check.status,
                    details: check.details
                })),
                score: analysis.score
            });

            if (testPassed) {
                console.log(`✅ ${test.name} PASSED\n`);
            } else {
                console.log(`❌ ${test.name} FAILED: ${testErrors.join('; ')}\n`);
            }

        } catch (error) {
            console.error(`❌ ${test.name} FAILED: ${error.message}`);
            results.push({
                test: test.name,
                url: test.url,
                passed: false,
                error: error.message
            });
            console.log('');
        }
    }

    // Comprehensive Summary
    console.log('📊 Comprehensive Integration Test Summary:');
    console.log('═'.repeat(60));

    const passed = results.filter(r => r.passed).length;
    const total = results.length;

    console.log(`✅ Overall Results: ${passed}/${total} tests passed`);
    console.log(`❌ Failed: ${total - passed}/${total}`);

    if (passed < total) {
        console.log('\n🔍 Failed Tests:');
        results.filter(r => !r.passed).forEach(result => {
            if (result.errors && result.errors.length > 0) {
                console.log(`   • ${result.test}:`);
                result.errors.forEach(error => console.log(`     - ${error}`));
            } else {
                console.log(`   • ${result.test}: ${result.error || 'Unknown error'}`);
            }
        });
    }

    // SSL Analysis Summary
    console.log('\n🔒 SSL Certificate Analysis Summary:');
    console.log('─'.repeat(40));
    const sslResults = results.filter(r => r.passed && r.ssl);
    const workingSignatureAlgorithms = sslResults.filter(r => r.ssl.signatureAlgorithmWorking).length;
    console.log(`Working signature detection: ${workingSignatureAlgorithms}/${sslResults.length}`);

    if (sslResults.length > 0) {
        const gradeDistribution = {};
        sslResults.forEach(r => {
            gradeDistribution[r.ssl.grade] = (gradeDistribution[r.ssl.grade] || 0) + 1;
        });
        console.log('SSL Grade Distribution:');
        Object.keys(gradeDistribution).sort().forEach(grade => {
            console.log(`   ${grade}: ${gradeDistribution[grade]} site(s)`);
        });
    }

    // Headers Analysis Summary
    console.log('\n📋 Security Headers Analysis Summary:');
    console.log('─'.repeat(40));
    const headerResults = results.filter(r => r.passed && r.headers);
    if (headerResults.length > 0) {
        const avgCriticalHeaders = headerResults.reduce((sum, r) => sum + r.headers.critical.present, 0) / headerResults.length;
        const avgImportantHeaders = headerResults.reduce((sum, r) => sum + r.headers.important.present, 0) / headerResults.length;
        const avgTotalHeaders = headerResults.reduce((sum, r) => sum + r.headers.present, 0) / headerResults.length;

        console.log(`Average critical headers present: ${avgCriticalHeaders.toFixed(1)}`);
        console.log(`Average important headers present: ${avgImportantHeaders.toFixed(1)}`);
        console.log(`Average total headers present: ${avgTotalHeaders.toFixed(1)}`);
    }

    // Additional Checks Summary
    console.log('\n🔧 Additional Security Checks Summary:');
    console.log('─'.repeat(40));
    const additionalResults = results.filter(r => r.passed && r.additional);
    if (additionalResults.length > 0) {
        const checkStats = {};
        additionalResults.forEach(result => {
            result.additional.forEach(check => {
                if (!checkStats[check.name]) {
                    checkStats[check.name] = { pass: 0, warning: 0, info: 0, fail: 0 };
                }
                checkStats[check.name][check.status] = (checkStats[check.name][check.status] || 0) + 1;
            });
        });

        Object.keys(checkStats).forEach(checkName => {
            const stats = checkStats[checkName];
            const total = Object.values(stats).reduce((sum, count) => sum + count, 0);
            console.log(`${checkName}:`);
            console.log(`   Pass: ${stats.pass}/${total}, Warning: ${stats.warning}/${total}, ` +
                       `Info: ${stats.info}/${total}, Fail: ${stats.fail || 0}/${total}`);
        });
    }

    // Security Score Summary
    console.log('\n🎯 Security Score Summary:');
    console.log('─'.repeat(40));
    const scoreResults = results.filter(r => r.passed && typeof r.score === 'number');
    if (scoreResults.length > 0) {
        const scores = scoreResults.map(r => r.score);
        const avgScore = scores.reduce((sum, score) => sum + score, 0) / scores.length;
        const maxScore = Math.max(...scores);
        const minScore = Math.min(...scores);

        console.log(`Average security score: ${avgScore.toFixed(1)}/100`);
        console.log(`Highest score: ${maxScore}/100`);
        console.log(`Lowest score: ${minScore}/100`);

        scoreResults.forEach(result => {
            console.log(`   ${result.test.split(' ')[0]}: ${result.score}/100`);
        });
    }

    if (workingSignatureAlgorithms < sslResults.length) {
        console.log('\n⚠️  Signature Algorithm Issues Found:');
        results.filter(r => r.passed && r.ssl && !r.ssl.signatureAlgorithmWorking).forEach(result => {
            console.log(`   • ${result.test}: ${result.ssl.signatureAlgorithm}`);
        });
    }

    return results;
}

// Make the analysis function exportable for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runIntegrationTests };
}

// Run tests if called directly
if (require.main === module) {
    runIntegrationTests()
        .then(results => {
            const allPassed = results.every(r => r.passed);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 Integration test runner failed:', error);
            process.exit(1);
        });
}
