const assert = require('assert');
const http = require('http');

/**
 * Performance and Reliability Integration Tests
 * Tests response times, error handling, edge cases, and reliability
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
            port: 4000,
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
            reject(new Error('Request timeout - analysis took longer than 30 seconds'));
        });

        req.write(postData);
        req.end();
    });
}

const PERFORMANCE_TEST_SITES = [
    {
        name: 'Fast Response Test (Google)',
        url: 'https://google.com',
        timeout: 5000, // Should respond within 5 seconds
        expectedMinScore: 30
    },
    {
        name: 'Comprehensive Analysis Test (GitHub)',
        url: 'https://github.com',
        timeout: 10000, // More complex analysis, allow 10 seconds
        expectedMinScore: 50
    },
    {
        name: 'Invalid Domain Test',
        url: 'https://this-domain-definitely-does-not-exist-12345.com',
        timeout: 5000, // API handles gracefully with error responses
        expectedMinScore: 0 // Should return low score due to errors
    }
];

const ERROR_HANDLING_TESTS = [
    {
        name: 'Non-HTTPS Test',
        url: 'http://example.com',
        shouldFail: false, // Should redirect or handle gracefully
        timeout: 8000
    }
];

async function runPerformanceTests() {
    console.log('⚡ Starting Performance and Reliability Integration Tests...\n');

    const results = [];

    // Performance Tests
    console.log('🚀 Performance Tests:');
    console.log('─'.repeat(30));

    for (const test of PERFORMANCE_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);
        console.log(`⏱️  Timeout: ${test.timeout}ms`);

        const startTime = Date.now();

        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Timeout')), test.timeout)
            );

            const analysis = await Promise.race([
                performSecurityAnalysis(test.url),
                timeoutPromise
            ]);

            const responseTime = Date.now() - startTime;

            console.log(`⏱️  Response Time: ${responseTime}ms`);
            console.log(`🎯 Security Score: ${analysis.security?.score || 'N/A'}/100`);
            console.log(`🔒 SSL Grade: ${analysis.details?.ssl?.grade || 'N/A'}`);
            console.log(`📋 Headers Detected: ${analysis.details?.headers?.headers?.filter(h => h.present).length || 0}`);
            console.log(`🔧 Additional Checks: ${analysis.details?.additional?.checks?.length || 0}`);

            // Performance validation
            let testPassed = true;
            const testErrors = [];

            try {
                assert(responseTime < test.timeout,
                    `Response time should be under ${test.timeout}ms, got ${responseTime}ms`);
                assert(analysis.security?.score >= test.expectedMinScore,
                    `Score should be at least ${test.expectedMinScore}, got ${analysis.security?.score}`);
                assert(analysis.details?.ssl,
                    'SSL analysis should be present');
                assert(analysis.details?.headers && analysis.details.headers.headers && analysis.details.headers.headers.length > 0,
                    'Headers should be analyzed');
                assert(analysis.details?.additional && analysis.details.additional.checks && analysis.details.additional.checks.length > 0,
                    'Additional checks should be present');
            } catch (e) {
                testErrors.push(e.message);
                testPassed = false;
            }

            results.push({
                test: test.name,
                url: test.url,
                passed: testPassed,
                errors: testErrors,
                performance: {
                    responseTime,
                    score: analysis.score,
                    sslGrade: analysis.ssl?.grade,
                    headersCount: analysis.headers?.filter(h => h.present).length,
                    additionalChecksCount: analysis.additional?.length
                }
            });

            if (testPassed) {
                console.log(`✅ ${test.name} PASSED\n`);
            } else {
                console.log(`❌ ${test.name} FAILED: ${testErrors.join('; ')}\n`);
            }

        } catch (error) {
            const responseTime = Date.now() - startTime;
            console.log(`⏱️  Response Time: ${responseTime}ms (failed)`);
            console.error(`❌ ${test.name} FAILED: ${error.message}\n`);

            results.push({
                test: test.name,
                url: test.url,
                passed: false,
                error: error.message,
                performance: {
                    responseTime,
                    timedOut: error.message.includes('Timeout')
                }
            });
        }
    }

    // Error Handling Tests
    console.log('🛡️ Error Handling Tests:');
    console.log('─'.repeat(30));

    for (const test of ERROR_HANDLING_TESTS) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);
        console.log(`❌ Should Fail: ${test.shouldFail}`);

        const startTime = Date.now();

        try {
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Timeout')), test.timeout || 10000)
            );

            const analysis = await Promise.race([
                performSecurityAnalysis(test.url),
                timeoutPromise
            ]);

            const responseTime = Date.now() - startTime;

            console.log(`⏱️  Response Time: ${responseTime}ms`);

            if (test.shouldFail) {
                console.log(`❌ ${test.name} FAILED: Expected failure but got success\n`);
                results.push({
                    test: test.name,
                    url: test.url,
                    passed: false,
                    error: 'Expected failure but analysis succeeded',
                    performance: { responseTime }
                });
            } else {
                console.log(`🎯 Security Score: ${analysis.security?.score || 'N/A'}/100`);
                console.log(`✅ ${test.name} PASSED (graceful handling)\n`);
                results.push({
                    test: test.name,
                    url: test.url,
                    passed: true,
                    performance: {
                        responseTime,
                        score: analysis.security?.score
                    }
                });
            }

        } catch (error) {
            const responseTime = Date.now() - startTime;
            console.log(`⏱️  Response Time: ${responseTime}ms (failed)`);

            if (test.shouldFail) {
                console.log(`✅ ${test.name} PASSED (expected failure: ${error.message})\n`);
                results.push({
                    test: test.name,
                    url: test.url,
                    passed: true,
                    expectedError: error.message,
                    performance: { responseTime }
                });
            } else {
                console.log(`❌ ${test.name} FAILED: Unexpected error: ${error.message}\n`);
                results.push({
                    test: test.name,
                    url: test.url,
                    passed: false,
                    error: error.message,
                    performance: { responseTime }
                });
            }
        }
    }

    // Summary
    console.log('📊 Performance and Reliability Test Summary:');
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

    // Performance Statistics
    const performanceResults = results.filter(r => r.performance && r.performance.responseTime);
    if (performanceResults.length > 0) {
        console.log('\n⚡ Performance Statistics:');
        const responseTimes = performanceResults.map(r => r.performance.responseTime);
        const avgResponseTime = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;
        const maxResponseTime = Math.max(...responseTimes);
        const minResponseTime = Math.min(...responseTimes);

        console.log(`   Average response time: ${avgResponseTime.toFixed(0)}ms`);
        console.log(`   Fastest response: ${minResponseTime}ms`);
        console.log(`   Slowest response: ${maxResponseTime}ms`);

        // Response time breakdown
        console.log('\n⏱️  Response Time Breakdown:');
        performanceResults.forEach(result => {
            const time = result.performance.responseTime;
            const timeIcon = time < 2000 ? '🟢' : time < 5000 ? '🟡' : '🔴';
            console.log(`   ${timeIcon} ${result.test.split(' ')[0]}: ${time}ms`);
        });

        // Reliability Statistics
        console.log('\n🛡️ Reliability Statistics:');
        const timeouts = results.filter(r => r.performance?.timedOut).length;
        const networkErrors = results.filter(r => r.error && r.error.includes('network')).length;

        console.log(`   Timeouts: ${timeouts}/${total}`);
        console.log(`   Network errors: ${networkErrors}/${total}`);
        console.log(`   Success rate: ${((total - timeouts - networkErrors) / total * 100).toFixed(1)}%`);
    }

    return results;
}

// Export for use in main test runner
module.exports = { runPerformanceTests, PERFORMANCE_TEST_SITES, ERROR_HANDLING_TESTS };

// Run tests if called directly
if (require.main === module) {
    runPerformanceTests()
        .then(results => {
            const allPassed = results.every(r => r.passed);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 Performance test runner failed:', error);
            process.exit(1);
        });
}
