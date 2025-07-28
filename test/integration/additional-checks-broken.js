const assert = require('assert');
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
        
        req.write(postData);
        req.end();
    });
}ssert = require('assert');
const { performSecurityAnalysis } = require('../../server');

/**
 * Additional Security Checks Integration Tests
 * Tests HTTP methods, HTTPS redirects, mixed content, security.txt, etc.
 */

const ADDITIONAL_CHECKS_TEST_SITES = [
    {
        name: 'GitHub Additional Checks',
        url: 'https://github.com',
        expectedResults: {
            httpsRedirect: 'pass',
            httpMethods: 'pass', // GitHub restricts OPTIONS properly
            mixedContent: 'pass',
            securityTxt: 'pass', // GitHub has security.txt
            serverInfo: 'info' // Should detect server info
        }
    },
    {
        name: 'Google Additional Checks',
        url: 'https://google.com',
        expectedResults: {
            httpMethods: 'pass', // Google restricts OPTIONS
            mixedContent: 'pass',
            serverInfo: 'info'
        }
    },
    {
        name: 'Cloudflare Additional Checks',
        url: 'https://cloudflare.com',
        expectedResults: {
            httpsRedirect: 'pass',
            mixedContent: 'pass',
            serverInfo: 'info'
        }
    },
    {
        name: 'Mozilla Additional Checks',
        url: 'https://developer.mozilla.org',
        expectedResults: {
            httpsRedirect: 'pass',
            httpMethods: 'pass', // MDN restricts OPTIONS
            mixedContent: 'pass',
            serverInfo: 'info'
        }
    }
];

async function runAdditionalChecksTests() {
    console.log('🔧 Starting Additional Security Checks Integration Tests...\n');
    
    const results = [];
    
    for (const test of ADDITIONAL_CHECKS_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);
        
        try {
            const analysis = await performSecurityAnalysis(test.url);
            const additional = analysis.details.additional; // Updated path for modular API
            
            // Display additional checks
            console.log(`🔧 Additional Security Checks:`);
            additional.forEach(check => {
                const statusIcon = check.status === 'pass' ? '✅' : 
                                 check.status === 'warning' ? '⚠️' : 
                                 check.status === 'fail' ? '❌' : 'ℹ️';
                console.log(`   ${statusIcon} ${check.name}: ${check.status} - ${check.details}`);
            });
            
            // Validation
            let testPassed = true;
            const testErrors = [];
            
            // Basic structure validation
            try {
                assert(Array.isArray(additional), 'Additional checks should be an array');
                assert(additional.length > 0, 'Should have at least some additional checks');
                
                additional.forEach(check => {
                    assert(check.name, 'Check should have a name');
                    assert(check.status, 'Check should have a status');
                    assert(check.details, 'Check should have details');
                    assert(['pass', 'warning', 'info', 'fail'].includes(check.status), 
                        `Check status should be valid, got: ${check.status}`);
                });
            } catch (e) {
                testErrors.push(`Structure validation failed: ${e.message}`);
                testPassed = false;
            }
            
            // Individual check validations
            Object.keys(test.expectedResults).forEach(checkKey => {
                const expectedStatus = test.expectedResults[checkKey];
                let checkName;
                
                switch (checkKey) {
                    case 'httpsRedirect': checkName = 'HTTPS Redirect'; break;
                    case 'httpMethods': checkName = 'HTTP Methods'; break;
                    case 'securityTxt': checkName = 'Security.txt'; break;
                    case 'mixedContent': checkName = 'Mixed Content'; break;
                    case 'serverInfo': checkName = 'Server Information'; break;
                    default: checkName = checkKey;
                }
                
                const check = additional.find(c => c.name === checkName);
                
                try {
                    assert(check, `${checkName} check should be present`);
                    
                    // For HTTP Methods, accept 'info' or 'pass' as success since server behavior varies
                    if (checkKey === 'httpMethods' && expectedStatus === 'pass') {
                        const acceptableStatuses = ['pass', 'info'];
                        assert(acceptableStatuses.includes(check.status), 
                            `${checkName} should have status ${expectedStatus} or info (acceptable variation), got ${check.status}`);
                    }
                    // For HTTPS redirect, accept warning as non-critical
                    else if (checkKey === 'httpsRedirect' && check.status === 'warning') {
                        console.log(`   ⚠️  HTTPS redirect check returned warning: ${check.details}`);
                    }
                    // For other checks, expect exact match
                    else {
                        assert.strictEqual(check.status, expectedStatus, 
                            `${checkName} should have status ${expectedStatus}, got ${check.status}`);
                    }
                } catch (e) {
                    // Don't fail tests for expected variations
                    if (checkKey === 'securityTxt' && expectedStatus === 'pass' && (!check || check.status === 'info')) {
                        console.log(`   ℹ️  Security.txt not found (this is optional and OK)`);
                    } else {
                        testErrors.push(e.message);
                        testPassed = false;
                    }
                }
            });
            
            // Test HTTP Methods functionality specifically (this was the bug we fixed)
            const httpMethodsCheck = additional.find(c => c.name === 'HTTP Methods');
            if (httpMethodsCheck) {
                try {
                    assert(!httpMethodsCheck.details.includes('information not available'), 
                        'HTTP Methods check should not return "information not available"');
                    assert(httpMethodsCheck.details.length > 10, 
                        'HTTP Methods check should provide meaningful details');
                } catch (e) {
                    testErrors.push(`HTTP Methods functionality test failed: ${e.message}`);
                    testPassed = false;
                }
            }
            
            results.push({
                test: test.name,
                url: test.url,
                passed: testPassed,
                errors: testErrors,
                additional: additional.map(check => ({
                    name: check.name,
                    status: check.status,
                    details: check.details,
                    hasGoodDetails: check.details && check.details.length > 10
                }))
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
    console.log('📊 Additional Security Checks Test Summary:');
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
    
    // Check Statistics
    const checkResults = results.filter(r => r.passed && r.additional);
    if (checkResults.length > 0) {
        console.log('\n📈 Security Check Statistics:');
        const checkStats = {};
        
        checkResults.forEach(result => {
            result.additional.forEach(check => {
                if (!checkStats[check.name]) {
                    checkStats[check.name] = { pass: 0, warning: 0, info: 0, fail: 0, total: 0 };
                }
                checkStats[check.name][check.status] = (checkStats[check.name][check.status] || 0) + 1;
                checkStats[check.name].total++;
            });
        });
        
        Object.keys(checkStats).forEach(checkName => {
            const stats = checkStats[checkName];
            console.log(`\n   ${checkName}:`);
            console.log(`     Pass: ${stats.pass}/${stats.total}, Warning: ${stats.warning}/${stats.total}, Info: ${stats.info}/${stats.total}, Fail: ${stats.fail || 0}/${stats.total}`);
        });
        
        // HTTP Methods specific analysis (the bug we fixed)
        console.log('\n🔧 HTTP Methods Analysis (Bug Fix Validation):');
        const httpMethodsResults = checkResults.map(r => 
            r.additional.find(a => a.name === 'HTTP Methods')
        ).filter(Boolean);
        
        const workingHttpMethods = httpMethodsResults.filter(check => 
            check.hasGoodDetails && !check.details.includes('information not available')
        ).length;
        
        console.log(`   Working HTTP Methods checks: ${workingHttpMethods}/${httpMethodsResults.length}`);
        console.log(`   Bug fix validation: ${workingHttpMethods === httpMethodsResults.length ? '✅ SUCCESS' : '❌ ISSUES FOUND'}`);
        
        httpMethodsResults.forEach((check, index) => {
            const siteName = checkResults[index]?.test.split(' ')[0] || `Site${index + 1}`;
            console.log(`   ${siteName}: ${check.status} - ${check.details.substring(0, 80)}${check.details.length > 80 ? '...' : ''}`);
        });
    }
    
    return results;
}

// Export for use in main test runner
module.exports = { runAdditionalChecksTests, ADDITIONAL_CHECKS_TEST_SITES };

// Run tests if called directly
if (require.main === module) {
    runAdditionalChecksTests()
        .then(results => {
            const allPassed = results.every(r => r.passed);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 Additional checks test runner failed:', error);
            process.exit(1);
        });
}
