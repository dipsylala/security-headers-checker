const assert = require('assert');
const { performSecurityAnalysis } = require('../server');

/**
 * Integration Tests for Security Headers Checker
 * Tests real-world scenarios with actual websites
 */

async function runIntegrationTests() {
    console.log('🧪 Starting Integration Tests...\n');
    
    const tests = [
        {
            name: 'GitHub SSL Certificate Analysis',
            url: 'https://github.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: 'TLSv1.2', // or TLSv1.3
                    keyLength: 256, // GitHub uses ECC certificates (256-bit is strong for ECC)
                    gradeExpectation: ['A+', 'A', 'B'] // Should be one of these
                }
            }
        },
        {
            name: 'Google SSL Certificate Analysis',
            url: 'https://google.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: 'TLSv1.3', // Google typically uses TLS 1.3
                    keyLength: 256, // Google uses ECC certificates
                    gradeExpectation: ['A+', 'A']
                }
            }
        },
        {
            name: 'Cloudflare SSL Certificate Analysis',
            url: 'https://cloudflare.com',
            expectedResults: {
                ssl: {
                    valid: true,
                    protocol: 'TLSv1.3',
                    gradeExpectation: ['A+', 'A']
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
            assert(typeof analysis.score === 'number', 'Score should be a number');
            
            // SSL-specific tests
            const ssl = analysis.ssl;
            console.log(`🔒 SSL Valid: ${ssl.valid}`);
            console.log(`🔐 Protocol: ${ssl.protocol}`);
            console.log(`🔑 Key Length: ${ssl.keyLength} bits`);
            console.log(`📜 Signature Algorithm: ${ssl.signatureAlgorithm}`);
            console.log(`🎯 Grade: ${ssl.grade}`);
            
            if (ssl.gradeExplanation) {
                console.log(`💬 Explanation: ${ssl.gradeExplanation}`);
            }
            
            if (ssl.recommendations && ssl.recommendations.length > 0) {
                console.log(`💡 Recommendations: ${ssl.recommendations.join('; ')}`);
            }
            
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
            if (test.expectedResults.ssl.valid !== undefined) {
                assert.strictEqual(ssl.valid, test.expectedResults.ssl.valid, 
                    `SSL validity should be ${test.expectedResults.ssl.valid}`);
            }
            
            if (test.expectedResults.ssl.gradeExpectation) {
                assert(test.expectedResults.ssl.gradeExpectation.includes(ssl.grade),
                    `SSL grade should be one of ${test.expectedResults.ssl.gradeExpectation.join(', ')}, got ${ssl.grade}`);
            }
            
            results.push({
                test: test.name,
                url: test.url,
                passed: true,
                ssl: {
                    valid: ssl.valid,
                    protocol: ssl.protocol,
                    keyLength: ssl.keyLength,
                    signatureAlgorithm: ssl.signatureAlgorithm,
                    grade: ssl.grade,
                    signatureAlgorithmWorking: signatureAlgorithmTests.isNotUnavailable
                },
                score: analysis.score
            });
            
            console.log(`✅ ${test.name} PASSED\n`);
            
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
    
    // Summary
    console.log('📊 Integration Test Summary:');
    console.log('═'.repeat(50));
    
    const passed = results.filter(r => r.passed).length;
    const total = results.length;
    
    console.log(`✅ Passed: ${passed}/${total}`);
    console.log(`❌ Failed: ${total - passed}/${total}`);
    
    if (passed < total) {
        console.log('\n🔍 Failed Tests:');
        results.filter(r => !r.passed).forEach(result => {
            console.log(`   • ${result.test}: ${result.error}`);
        });
    }
    
    // Signature algorithm analysis
    console.log('\n🧬 Signature Algorithm Analysis:');
    const workingSignatureAlgorithms = results.filter(r => r.passed && r.ssl?.signatureAlgorithmWorking).length;
    console.log(`Working signature detection: ${workingSignatureAlgorithms}/${passed}`);
    
    if (workingSignatureAlgorithms < passed) {
        console.log('\n⚠️  Signature Algorithm Issues Found:');
        results.filter(r => r.passed && !r.ssl?.signatureAlgorithmWorking).forEach(result => {
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
