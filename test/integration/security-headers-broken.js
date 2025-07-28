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
}ssert = require('assert');
const { performSecurityAnalysis } = require('../../server');

/**
 * Security Headers Integration Tests
 * Tests security header detection, categorization, and validation
 */

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
            shouldHaveMinimumHeaders: 3,
            criticalHeadersExpected: 1
        }
    },
    {
        name: 'Google Headers Analysis',
        url: 'https://google.com',
        expectedResults: {
            shouldHaveMinimumHeaders: 2,
            criticalHeadersExpected: 0 // Google's main page is minimal
        }
    },
    {
        name: 'Mozilla Headers Analysis',
        url: 'https://developer.mozilla.org',
        expectedResults: {
            shouldHaveMinimumHeaders: 2,
            criticalHeadersExpected: 0 // Developer docs may vary
        }
    }
];

async function runHeadersTests() {
    console.log('📋 Starting Security Headers Integration Tests...\n');
    
    const results = [];
    
    for (const test of HEADER_TEST_SITES) {
        console.log(`🔍 Testing: ${test.name}`);
        console.log(`📡 URL: ${test.url}`);
        
        try {
            const analysis = await performSecurityAnalysis(test.url);
            const headers = analysis.details.headers; // Updated path for modular API
            
            // Display header information
            console.log(`📋 Headers Analysis:`);
            const criticalHeaders = headers.filter(h => h.category === 'critical');
            const presentCriticalHeaders = criticalHeaders.filter(h => h.present).length;
            console.log(`   Critical headers present: ${presentCriticalHeaders}/${criticalHeaders.length}`);
            
            const importantHeaders = headers.filter(h => h.category === 'important');
            const presentImportantHeaders = importantHeaders.filter(h => h.present).length;
            console.log(`   Important headers present: ${presentImportantHeaders}/${importantHeaders.length}`);
            
            const presentHeaders = headers.filter(h => h.present);
            console.log(`   Total headers present: ${presentHeaders.length}/${headers.length}`);
            
            // List detected headers
            console.log(`📝 Detected Headers:`);
            presentHeaders.forEach(header => {
                const categoryIcon = header.category === 'critical' ? '🔴' : 
                                   header.category === 'important' ? '🟡' : '🟢';
                console.log(`   ${categoryIcon} ${header.name}: ${header.value ? 'configured' : 'default'}`);
            });
            
            // Validation
            let testPassed = true;
            const testErrors = [];
            
            // Basic header detection test
            try {
                assert(headers.length > 0, 'Should detect header definitions');
                assert(presentHeaders.length >= test.expectedResults.shouldHaveMinimumHeaders,
                    `Should have at least ${test.expectedResults.shouldHaveMinimumHeaders} headers present, got ${presentHeaders.length}`);
            } catch (e) {
                testErrors.push(e.message);
                testPassed = false;
            }
            
            // HSTS test
            if (test.expectedResults.shouldHaveHSTS) {
                const hstsHeader = headers.find(h => h.name.toLowerCase() === 'strict-transport-security');
                try {
                    assert(hstsHeader && hstsHeader.present, 'HSTS header should be present');
                } catch (e) {
                    testErrors.push(e.message);
                    testPassed = false;
                }
            }
            
            // Critical headers count test
            if (test.expectedResults.criticalHeadersExpected !== undefined) {
                try {
                    assert(presentCriticalHeaders >= test.expectedResults.criticalHeadersExpected,
                        `Should have at least ${test.expectedResults.criticalHeadersExpected} critical headers, got ${presentCriticalHeaders}`);
                } catch (e) {
                    // Don't fail for this - just log a warning
                    console.log(`   ⚠️  Expected ${test.expectedResults.criticalHeadersExpected} critical headers, got ${presentCriticalHeaders}`);
                }
            }
            
            // Important headers count test
            if (test.expectedResults.importantHeadersExpected !== undefined) {
                try {
                    assert(presentImportantHeaders >= test.expectedResults.importantHeadersExpected,
                        `Should have at least ${test.expectedResults.importantHeadersExpected} important headers, got ${presentImportantHeaders}`);
                } catch (e) {
                    // Don't fail for this - just log a warning
                    console.log(`   ⚠️  Expected ${test.expectedResults.importantHeadersExpected} important headers, got ${presentImportantHeaders}`);
                }
            }
            
            // Header structure validation
            try {
                headers.forEach(header => {
                    assert(header.name, 'Header should have a name');
                    assert(header.category, 'Header should have a category');
                    assert(typeof header.present === 'boolean', 'Header should have present boolean');
                    assert(header.description, 'Header should have a description');
                });
            } catch (e) {
                testErrors.push(`Header structure validation failed: ${e.message}`);
                testPassed = false;
            }
            
            results.push({
                test: test.name,
                url: test.url,
                passed: testPassed,
                errors: testErrors,
                headers: {
                    total: headers.length,
                    present: presentHeaders.length,
                    critical: {
                        total: criticalHeaders.length,
                        present: presentCriticalHeaders
                    },
                    important: {
                        total: importantHeaders.length,
                        present: presentImportantHeaders
                    },
                    detected: presentHeaders.map(h => ({
                        name: h.name,
                        category: h.category,
                        hasValue: !!h.value
                    }))
                }
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
    console.log('📊 Security Headers Test Summary:');
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
    
    // Header Statistics
    const headerResults = results.filter(r => r.passed && r.headers);
    if (headerResults.length > 0) {
        console.log('\n📈 Header Statistics:');
        const avgPresent = headerResults.reduce((sum, r) => sum + r.headers.present, 0) / headerResults.length;
        const avgCritical = headerResults.reduce((sum, r) => sum + r.headers.critical.present, 0) / headerResults.length;
        const avgImportant = headerResults.reduce((sum, r) => sum + r.headers.important.present, 0) / headerResults.length;
        
        console.log(`   Average headers present: ${avgPresent.toFixed(1)}`);
        console.log(`   Average critical headers: ${avgCritical.toFixed(1)}`);
        console.log(`   Average important headers: ${avgImportant.toFixed(1)}`);
        
        // Most common headers
        console.log('\n🏆 Most Common Headers:');
        const headerCounts = {};
        headerResults.forEach(result => {
            result.headers.detected.forEach(header => {
                headerCounts[header.name] = (headerCounts[header.name] || 0) + 1;
            });
        });
        
        Object.entries(headerCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .forEach(([header, count]) => {
                console.log(`   ${header}: ${count}/${headerResults.length} sites`);
            });
    }
    
    return results;
}

// Export for use in main test runner
module.exports = { runHeadersTests, HEADER_TEST_SITES };

// Run tests if called directly
if (require.main === module) {
    runHeadersTests()
        .then(results => {
            const allPassed = results.every(r => r.passed);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 Headers test runner failed:', error);
            process.exit(1);
        });
}
