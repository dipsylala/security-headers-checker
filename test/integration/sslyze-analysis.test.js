const assert = require('assert');
const http = require('http');
const { checkSSLyzeAvailability, runSSLyzeScan, convertSSLyzeToTests } = require('../../lib/ssl-analyzer');

/**
 * SSLyze Integration Tests
 * Tests SSLyze tool integration for enhanced SSL/TLS analysis
 * including vulnerability detection and protocol support analysis
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
            },
            timeout: 45000 // Extended timeout for sslyze
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
            reject(new Error('Request timeout'));
        });

        req.write(postData);
        req.end();
    });
}

/**
 * Test SSLyze availability and version detection
 */
async function testSSLyzeAvailability() {
    console.log('🔧 Testing SSLyze Availability...');

    try {
        const availability = await checkSSLyzeAvailability();
        
        console.log(`📦 SSLyze Available: ${availability.available}`);
        if (availability.available) {
            console.log(`📌 SSLyze Version: ${availability.version}`);
            console.log(`📄 Output: ${availability.output}`);
            console.log('✅ SSLyze availability test PASSED\n');
            return { passed: true, available: true, version: availability.version };
        } else {
            console.log(`❌ SSLyze Error: ${availability.error}`);
            console.log('⚠️ SSLyze not available - enhanced tests will be skipped');
            console.log('📦 To install SSLyze: pip install sslyze\n');
            return { passed: true, available: false, reason: availability.error };
        }
    } catch (error) {
        console.log(`❌ SSLyze availability test FAILED: ${error.message}\n`);
        return { passed: false, available: false, error: error.message };
    }
}

/**
 * Test direct SSLyze scan functionality
 */
async function testDirectSSLyzeScan() {
    console.log('🔍 Testing Direct SSLyze Scan...');
    console.log('📡 Target: github.com:443');

    try {
        // First check if sslyze is available
        const availability = await checkSSLyzeAvailability();
        if (!availability.available) {
            console.log('⚠️ SSLyze not available - skipping direct scan test');
            console.log('✅ Direct SSLyze scan test SKIPPED\n');
            return { passed: true, skipped: true, reason: 'SSLyze not available' };
        }

        const scanResult = await runSSLyzeScan('github.com', 443);
        
        console.log(`📊 Scan Success: ${scanResult.success}`);
        if (scanResult.success) {
            console.log(`📋 Data Available: ${scanResult.data ? 'Yes' : 'No'}`);
            
            if (scanResult.data && scanResult.data.server_scan_results) {
                const serverResults = scanResult.data.server_scan_results[0];
                console.log(`🔗 Server: ${serverResults.server_info?.hostname || 'Unknown'}`);
                console.log(`🏃 Scan Commands: ${Object.keys(serverResults.scan_commands_results || {}).length}`);
                
                // Test conversion to our test format
                const tests = convertSSLyzeToTests(scanResult.data, 'github.com');
                console.log(`🧪 Converted Tests: ${tests.length}`);
                
                tests.forEach(test => {
                    const statusIcon = test.status === 'pass' ? '✅' : test.status === 'fail' ? '❌' : '⚠️';
                    console.log(`   ${statusIcon} ${test.name}: ${test.status}`);
                });
            }
            
            console.log('✅ Direct SSLyze scan test PASSED\n');
            return { passed: true, testsGenerated: scanResult.data ? true : false };
        } else {
            console.log(`❌ Scan Error: ${scanResult.error}`);
            console.log('❌ Direct SSLyze scan test FAILED\n');
            return { passed: false, error: scanResult.error };
        }
    } catch (error) {
        console.log(`❌ Direct SSLyze scan test FAILED: ${error.message}\n`);
        return { passed: false, error: error.message };
    }
}

/**
 * Test SSLyze integration in comprehensive SSL analysis
 */
async function testSSLyzeIntegrationInAPI() {
    console.log('🔒 Testing SSLyze Integration in API...');
    console.log('📡 URL: https://github.com');

    try {
        const analysis = await performSecurityAnalysis('https://github.com');
        
        console.log(`📊 Analysis Success: ${analysis.success !== false}`);
        
        if (analysis.details && analysis.details.detailedSsl) {
            const detailedSsl = analysis.details.detailedSsl;
            
            console.log(`🎯 SSL Grade: ${detailedSsl.summary?.grade || 'N/A'}`);
            console.log(`📈 SSL Score: ${detailedSsl.summary?.score || 'N/A'}/${detailedSsl.summary?.maxScore || 'N/A'}`);
            console.log(`🧪 Total Tests: ${detailedSsl.tests?.length || 0}`);
            
            // Check for SSLyze-specific tests
            const sslyzeTests = detailedSsl.tests?.filter(test => test.name.toLowerCase().includes('sslyze')) || [];
            console.log(`🔍 SSLyze Tests: ${sslyzeTests.length}`);
            
            if (detailedSsl.sslyzeInfo) {
                console.log(`📦 SSLyze Available: ${detailedSsl.sslyzeInfo.available}`);
                console.log(`📌 SSLyze Version: ${detailedSsl.sslyzeInfo.version || 'Unknown'}`);
                console.log(`🧪 SSLyze Tests Run: ${detailedSsl.sslyzeInfo.testsRun || 0}`);
            }
            
            // Display SSLyze test results
            if (sslyzeTests.length > 0) {
                console.log('🔍 SSLyze Test Results:');
                sslyzeTests.forEach(test => {
                    const statusIcon = test.status === 'pass' ? '✅' : test.status === 'fail' ? '❌' : '⚠️';
                    console.log(`   ${statusIcon} ${test.name}: ${test.status}`);
                    if (test.details) {
                        console.log(`      └─ ${test.details}`);
                    }
                });
            }
            
            console.log('✅ SSLyze integration in API test PASSED\n');
            return { 
                passed: true, 
                sslyzeTestsFound: sslyzeTests.length,
                sslyzeAvailable: detailedSsl.sslyzeInfo?.available || false
            };
        } else {
            console.log('❌ No detailed SSL analysis found in response');
            console.log('❌ SSLyze integration in API test FAILED\n');
            return { passed: false, error: 'No detailed SSL analysis found' };
        }
        
    } catch (error) {
        console.log(`❌ SSLyze integration in API test FAILED: ${error.message}\n`);
        return { passed: false, error: error.message };
    }
}

/**
 * Test SSLyze vulnerability detection capabilities
 */
async function testSSLyzeVulnerabilityDetection() {
    console.log('🛡️ Testing SSLyze Vulnerability Detection...');
    console.log('📡 Target: badssl.com (for known SSL configurations)');

    try {
        // First check if sslyze is available
        const availability = await checkSSLyzeAvailability();
        if (!availability.available) {
            console.log('⚠️ SSLyze not available - skipping vulnerability detection test');
            console.log('✅ SSLyze vulnerability detection test SKIPPED\n');
            return { passed: true, skipped: true, reason: 'SSLyze not available' };
        }

        // Test with a site known to have good SSL configuration
        const scanResult = await runSSLyzeScan('badssl.com', 443);
        
        console.log(`📊 Scan Success: ${scanResult.success}`);
        
        if (scanResult.success && scanResult.data) {
            const tests = convertSSLyzeToTests(scanResult.data, 'badssl.com');
            const vulnTests = tests.filter(test => 
                test.name.toLowerCase().includes('heartbleed') ||
                test.name.toLowerCase().includes('robot') ||
                test.name.toLowerCase().includes('ccs') ||
                test.name.toLowerCase().includes('vulnerabil')
            );
            
            console.log(`🛡️ Vulnerability Tests Found: ${vulnTests.length}`);
            
            vulnTests.forEach(test => {
                const statusIcon = test.status === 'pass' ? '✅' : test.status === 'fail' ? '❌' : '⚠️';
                console.log(`   ${statusIcon} ${test.name}: ${test.status}`);
                if (test.details) {
                    console.log(`      └─ ${test.details}`);
                }
            });
            
            console.log('✅ SSLyze vulnerability detection test PASSED\n');
            return { 
                passed: true, 
                vulnerabilityTestsFound: vulnTests.length,
                allTestsCount: tests.length
            };
        } else {
            console.log(`❌ Scan failed: ${scanResult.error || 'Unknown error'}`);
            console.log('❌ SSLyze vulnerability detection test FAILED\n');
            return { passed: false, error: scanResult.error };
        }
        
    } catch (error) {
        console.log(`❌ SSLyze vulnerability detection test FAILED: ${error.message}\n`);
        return { passed: false, error: error.message };
    }
}

/**
 * Test SSLyze with different SSL configurations
 */
async function testSSLyzeWithDifferentConfigurations() {
    console.log('🔧 Testing SSLyze with Different SSL Configurations...');

    const testTargets = [
        { hostname: 'tls-v1-0.badssl.com', port: 1010, description: 'TLS 1.0 only (deprecated)' },
        { hostname: 'tls-v1-2.badssl.com', port: 1012, description: 'TLS 1.2 only (secure)' },
        { hostname: 'sha256.badssl.com', port: 443, description: 'SHA-256 certificate' }
    ];

    try {
        // First check if sslyze is available
        const availability = await checkSSLyzeAvailability();
        if (!availability.available) {
            console.log('⚠️ SSLyze not available - skipping configuration tests');
            console.log('✅ SSLyze configuration tests SKIPPED\n');
            return { passed: true, skipped: true, reason: 'SSLyze not available' };
        }

        const results = [];
        
        for (const target of testTargets) {
            console.log(`🔍 Testing ${target.hostname}:${target.port} (${target.description})`);
            
            try {
                const scanResult = await runSSLyzeScan(target.hostname, target.port);
                
                if (scanResult.success && scanResult.data) {
                    const tests = convertSSLyzeToTests(scanResult.data, target.hostname);
                    const protocolTests = tests.filter(test => test.name.toLowerCase().includes('protocol'));
                    
                    console.log(`   📋 Total Tests: ${tests.length}`);
                    console.log(`   🔐 Protocol Tests: ${protocolTests.length}`);
                    
                    protocolTests.forEach(test => {
                        if (test.sslyzeData && test.sslyzeData.supportedProtocols) {
                            console.log(`   📌 Protocols: ${test.sslyzeData.supportedProtocols.join(', ')}`);
                        }
                    });
                    
                    results.push({ target: target.hostname, success: true, tests: tests.length });
                } else {
                    console.log(`   ❌ Scan failed: ${scanResult.error}`);
                    results.push({ target: target.hostname, success: false, error: scanResult.error });
                }
            } catch (error) {
                console.log(`   ❌ Error: ${error.message}`);
                results.push({ target: target.hostname, success: false, error: error.message });
            }
        }
        
        const successfulScans = results.filter(r => r.success).length;
        console.log(`📊 Successful Scans: ${successfulScans}/${results.length}`);
        
        if (successfulScans > 0) {
            console.log('✅ SSLyze configuration tests PASSED\n');
            return { passed: true, successfulScans, totalScans: results.length, results };
        } else {
            console.log('❌ SSLyze configuration tests FAILED - no successful scans\n');
            return { passed: false, results };
        }
        
    } catch (error) {
        console.log(`❌ SSLyze configuration tests FAILED: ${error.message}\n`);
        return { passed: false, error: error.message };
    }
}

/**
 * Run all SSLyze integration tests
 */
async function runSSLyzeTests() {
    console.log('🚀 Starting SSLyze Integration Tests');
    console.log('====================================');
    console.log('📋 Note: SSLyze tests require the sslyze Python package');
    console.log('📦 Install with: pip install sslyze');
    console.log('====================================\n');

    const tests = [
        { name: 'SSLyze Availability', test: testSSLyzeAvailability },
        { name: 'Direct SSLyze Scan', test: testDirectSSLyzeScan },
        { name: 'SSLyze API Integration', test: testSSLyzeIntegrationInAPI },
        { name: 'SSLyze Vulnerability Detection', test: testSSLyzeVulnerabilityDetection },
        { name: 'SSLyze Configuration Tests', test: testSSLyzeWithDifferentConfigurations }
    ];

    const results = [];
    let sslyzeAvailable = false;

    for (const test of tests) {
        try {
            const result = await test.test();
            results.push({
                test: test.name,
                passed: result.passed,
                skipped: result.skipped || false,
                details: result
            });
            
            // Track SSLyze availability for summary
            if (test.name === 'SSLyze Availability' && result.available) {
                sslyzeAvailable = true;
            }
        } catch (error) {
            console.error(`❌ ${test.name} FAILED: ${error.message}\n`);
            results.push({
                test: test.name,
                passed: false,
                error: error.message
            });
        }
    }

    // Summary
    console.log('📊 SSLyze Integration Test Summary:');
    console.log('═'.repeat(50));

    const passed = results.filter(r => r.passed).length;
    const skipped = results.filter(r => r.skipped).length;
    const total = results.length;

    console.log(`✅ Overall Results: ${passed}/${total} tests passed (${skipped} skipped)`);
    console.log(`📦 SSLyze Available: ${sslyzeAvailable ? 'Yes' : 'No'}`);

    if (passed < total) {
        console.log('\n❌ Failed Tests:');
        results.filter(r => !r.passed && !r.skipped).forEach(result => {
            console.log(`   • ${result.test}: ${result.error || 'Unknown error'}`);
        });
    }

    if (skipped > 0) {
        console.log('\n⚠️ Skipped Tests:');
        results.filter(r => r.skipped).forEach(result => {
            console.log(`   • ${result.test}: ${result.details?.reason || 'Unknown reason'}`);
        });
    }

    // SSLyze Installation Guide
    if (!sslyzeAvailable) {
        console.log('\n📦 SSLyze Installation Guide:');
        console.log('─'.repeat(30));
        console.log('1. Install Python 3.7+ if not already installed');
        console.log('2. Run: pip install sslyze');
        console.log('3. Verify: python -m sslyze --version');
        console.log('4. Re-run tests to see enhanced SSL analysis');
    }

    return results;
}

// Export for use in main test runner
module.exports = { 
    runSSLyzeTests,
    testSSLyzeAvailability,
    testDirectSSLyzeScan,
    testSSLyzeIntegrationInAPI,
    testSSLyzeVulnerabilityDetection
};

// Run tests if called directly
if (require.main === module) {
    runSSLyzeTests()
        .then(results => {
            const allPassed = results.every(r => r.passed || r.skipped);
            process.exit(allPassed ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 SSLyze test runner failed:', error);
            process.exit(1);
        });
}
