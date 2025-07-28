const assert = require('assert');
const http = require('http');

/**
 * Security Headers Integration Tests
 * Tests security headers detection, validation, and scoring
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
}

const HEADER_TEST_SITES = [
    {
        name: 'GitHub Headers Analysis',
        url: 'https://github.com',
        expectedResults: {
            shouldHaveHSTS: true,
            shouldHaveMinimumHeaders: 5,
            criticalHeadersExpected: 1, // At least HSTS
            importantHeadersExpected: 2 // X-Frame-Options, etc.
        }
    },
    {
        name: 'Cloudflare Headers Analysis',
        url: 'https://cloudflare.com',
        expectedResults: {
            shouldHaveHSTS: true,
            shouldHaveMinimumHeaders: 4,
            criticalHeadersExpected: 1,
            importantHeadersExpected: 2
        }
    },
    {
        name: 'Mozilla Headers Analysis',
        url: 'https://developer.mozilla.org',
        expectedResults: {
            shouldHaveHSTS: true,
            shouldHaveMinimumHeaders: 6,
            criticalHeadersExpected: 2, // HSTS, CSP
            importantHeadersExpected: 3
        }
    },
    {
        name: 'Google Headers Analysis',
        url: 'https://google.com',
        expectedResults: {
            shouldHaveHSTS: true,
            shouldHaveMinimumHeaders: 3,
            criticalHeadersExpected: 1,
            importantHeadersExpected: 1
        }
    }
];

async function runHeadersTests() {
    console.log('🔒 Starting Security Headers Integration Tests...\n');
    
    const results = [];
    
    for (const test of HEADER_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);
        
        try {
            const analysis = await performSecurityAnalysis(test.url);
            const headers = analysis.details.headers; // Updated path for modular API
            
            // Display headers information
            console.log(`📊 Headers Found: ${headers.headers ? headers.headers.length : 0}`);
            console.log(`🎯 Score: ${headers.score}/10`);
            
            if (headers.headers && headers.headers.length > 0) {
                console.log(`🔒 Headers Details:`);
                headers.headers.forEach(header => {
                    const statusEmoji = header.status === 'pass' ? '✅' : 
                                      header.status === 'warning' ? '⚠️' : 
                                      header.status === 'fail' ? '❌' : 'ℹ️';
                    console.log(`   ${statusEmoji} ${header.name}: ${header.status}`);
                    if (header.value) {
                        console.log(`      Value: ${header.value.substring(0, 100)}${header.value.length > 100 ? '...' : ''}`);
                    }
                });
            }
            
            // Categorize headers by status
            const headersByStatus = {
                pass: headers.headers ? headers.headers.filter(h => h.status === 'pass').length : 0,
                warning: headers.headers ? headers.headers.filter(h => h.status === 'warning').length : 0,
                fail: headers.headers ? headers.headers.filter(h => h.status === 'fail').length : 0,
                info: headers.headers ? headers.headers.filter(h => h.status === 'info').length : 0
            };
            
            console.log(`📈 Header Status Summary:`);
            console.log(`   ✅ Passed: ${headersByStatus.pass}`);
            console.log(`   ⚠️  Warnings: ${headersByStatus.warning}`);
            console.log(`   ❌ Failed: ${headersByStatus.fail}`);
            console.log(`   ℹ️  Info: ${headersByStatus.info}`);
            
            // Validation
            let testPassed = true;
            const testErrors = [];
            
            // Check for HSTS if expected
            if (test.expectedResults.shouldHaveHSTS) {
                const hasHSTS = headers.headers && headers.headers.some(h => 
                    h.name === 'Strict-Transport-Security' && h.status === 'pass'
                );
                if (!hasHSTS) {
                    testPassed = false;
                    testErrors.push('Missing HSTS header');
                }
            }
            
            // Check minimum headers count
            const totalHeaders = headers.headers ? headers.headers.length : 0;
            if (totalHeaders < test.expectedResults.shouldHaveMinimumHeaders) {
                testPassed = false;
                testErrors.push(`Expected at least ${test.expectedResults.shouldHaveMinimumHeaders} headers, found ${totalHeaders}`);
            }
            
            // Check headers score is reasonable (not completely failing)
            if (headers.score < 2) {
                testPassed = false;
                testErrors.push(`Headers score too low: ${headers.score}/10`);
            }
            
            // Report results
            if (testPassed) {
                console.log(`✅ ${test.name} PASSED`);
                results.push({ name: test.name, status: 'passed', details: 'All checks passed' });
            } else {
                console.log(`❌ ${test.name} FAILED: ${testErrors.join(', ')}`);
                results.push({ name: test.name, status: 'failed', details: testErrors.join(', ') });
            }
            
        } catch (error) {
            console.log(`❌ ${test.name} FAILED: ${error.message}`);
            results.push({ name: test.name, status: 'failed', details: error.message });
        }
        
        console.log(''); // Empty line for readability
    }
    
    return results;
}

// Header-specific validation tests
async function validateHeaderFormatting(url) {
    try {
        const analysis = await performSecurityAnalysis(url);
        const headers = analysis.details.headers;
        
        console.log(`🔍 Validating header formatting for: ${url}`);
        
        let formatTests = {
            hasCorrectStructure: headers.headers && Array.isArray(headers.headers),
            hasScoreField: typeof headers.score === 'number',
            hasValidHeaders: headers.headers && headers.headers.every(h => 
                h.name && h.description && h.status
            ),
            scoreInValidRange: headers.score >= 0 && headers.score <= 10
        };
        
        console.log(`📋 Format Validation Results:`);
        Object.entries(formatTests).forEach(([test, passed]) => {
            console.log(`   ${passed ? '✅' : '❌'} ${test}: ${passed}`);
        });
        
        return Object.values(formatTests).every(Boolean);
        
    } catch (error) {
        console.log(`❌ Header format validation failed: ${error.message}`);
        return false;
    }
}

module.exports = {
    runHeadersTests,
    validateHeaderFormatting,
    HEADER_TEST_SITES
};
