const http = require('http');

/**
 * Additional Security Checks Integration Tests
 * Tests HTTP methods, HTTPS redirects, mixed content, security.txt, and other security checks
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
            },
            timeout: 30000 // 30 second timeout for analysis
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

const ADDITIONAL_CHECKS_TEST_SITES = [
    {
        name: 'GitHub Additional Checks',
        url: 'https://github.com',
        expectedResults: {
            httpsRedirect: 'pass',
            minChecks: 3,
            shouldBeSecure: true
        }
    },
    {
        name: 'Cloudflare Additional Checks',
        url: 'https://cloudflare.com',
        expectedResults: {
            httpsRedirect: 'pass',
            minChecks: 3,
            shouldBeSecure: true
        }
    },
    {
        name: 'Google Additional Checks',
        url: 'https://google.com',
        expectedResults: {
            httpsRedirect: 'pass',
            minChecks: 3,
            shouldBeSecure: true
        }
    },
    {
        name: 'Mozilla Additional Checks',
        url: 'https://developer.mozilla.org',
        expectedResults: {
            httpsRedirect: 'pass',
            minChecks: 3,
            shouldBeSecure: true
        }
    }
];

async function runAdditionalChecksTests() {
    console.log('🔒 Starting Additional Security Checks Integration Tests...\n');

    const results = [];

    for (const test of ADDITIONAL_CHECKS_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);

        try {
            const analysis = await performSecurityAnalysis(test.url);
            const additional = analysis.details.additional; // Updated path for modular API

            // Display additional checks information
            console.log(`📊 Additional Checks Found: ${additional.checks ? additional.checks.length : 0}`);
            console.log(`🎯 Score: ${additional.score.score}/${additional.score.maxScore}`);

            if (additional.checks && additional.checks.length > 0) {
                console.log(`🔒 Additional Checks Details:`);
                additional.checks.forEach(check => {
                    const statusEmoji = check.status === 'pass' ? '✅' :
                        check.status === 'warning' ? '⚠️' :
                            check.status === 'fail' ? '❌' : 'ℹ️';
                    console.log(`   ${statusEmoji} ${check.name}: ${check.status}`);
                    if (check.details) {
                        console.log(`      Details: ${check.details.substring(0, 100)}${check.details.length > 100 ? '...' : ''}`);
                    }
                });
            }

            // Categorize checks by status
            const checksByStatus = {
                pass: additional.checks ? additional.checks.filter(c => c.status === 'pass').length : 0,
                warning: additional.checks ? additional.checks.filter(c => c.status === 'warning').length : 0,
                fail: additional.checks ? additional.checks.filter(c => c.status === 'fail').length : 0,
                info: additional.checks ? additional.checks.filter(c => c.status === 'info').length : 0
            };

            console.log(`📈 Additional Checks Status Summary:`);
            console.log(`   ✅ Passed: ${checksByStatus.pass}`);
            console.log(`   ⚠️  Warnings: ${checksByStatus.warning}`);
            console.log(`   ❌ Failed: ${checksByStatus.fail}`);
            console.log(`   ℹ️  Info: ${checksByStatus.info}`);

            // Validation
            let testPassed = true;
            const testErrors = [];

            // Check minimum checks count
            const totalChecks = additional.checks ? additional.checks.length : 0;
            if (totalChecks < test.expectedResults.minChecks) {
                testPassed = false;
                testErrors.push(`Expected at least ${test.expectedResults.minChecks} checks, found ${totalChecks}`);
            }

            // Check for HTTPS redirect check
            const hasHttpsCheck = additional.checks && additional.checks.some(c =>
                c.name.toLowerCase().includes('https') || c.name.toLowerCase().includes('redirect')
            );
            if (!hasHttpsCheck) {
                testPassed = false;
                testErrors.push('Missing HTTPS redirect check');
            }

            // Check score is reasonable
            if (additional.score < 1) {
                testPassed = false;
                testErrors.push(`Additional checks score too low: ${additional.score}/10`);
            }

            // Report results
            if (testPassed) {
                console.log(`✅ ${test.name} PASSED`);
                results.push({ test: test.name, passed: true, details: 'All checks passed' });
            } else {
                console.log(`❌ ${test.name} FAILED: ${testErrors.join(', ')}`);
                results.push({ test: test.name, passed: false, errors: testErrors });
            }

        } catch (error) {
            console.log(`❌ ${test.name} FAILED: ${error.message}`);
            results.push({ test: test.name, passed: false, error: error.message });
        }

        console.log(''); // Empty line for readability
    }

    return results;
}

// Test specific additional security features
async function validateAdditionalChecksStructure(url) {
    try {
        const analysis = await performSecurityAnalysis(url);
        const additional = analysis.details.additional;

        console.log(`🔍 Validating additional checks structure for: ${url}`);

        const structureTests = {
            hasCorrectStructure: additional.checks && Array.isArray(additional.checks),
            hasScoreField: typeof additional.score === 'number',
            hasValidChecks: additional.checks && additional.checks.every(c =>
                c.name && c.description && c.status
            ),
            scoreInValidRange: additional.score >= 0 && additional.score <= 10,
            hasCommonChecks: additional.checks && [
                'HTTPS Redirect',
                'Server Information',
                'Mixed Content',
                'HTTP Methods',
                'Security.txt'
            ].some(checkName =>
                additional.checks.some(c => c.name === checkName)
            )
        };

        console.log(`📋 Structure Validation Results:`);
        Object.entries(structureTests).forEach(([test, passed]) => {
            console.log(`   ${passed ? '✅' : '❌'} ${test}: ${passed}`);
        });

        return Object.values(structureTests).every(Boolean);

    } catch (error) {
        console.log(`❌ Additional checks structure validation failed: ${error.message}`);
        return false;
    }
}

module.exports = {
    runAdditionalChecksTests,
    validateAdditionalChecksStructure,
    ADDITIONAL_CHECKS_TEST_SITES
};
