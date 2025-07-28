#!/usr/bin/env node

/**
 * Comprehensive Integration Test Runner
 * Runs all integration tests including BadSSL certificate scenarios
 */

const { runSSLTests } = require('./ssl-certificate.test.js');
const { runHeadersTests } = require('./security-headers.test.js');
const { runAdditionalChecksTests } = require('./additional-checks.test.js');
const { runBadSSLTests } = require('./badssl-scenarios.test.js');

async function runAllIntegrationTests() {
    console.log('🚀 Starting Comprehensive Integration Test Suite...\n');
    console.log('=' .repeat(60));
    
    const startTime = Date.now();
    const allResults = [];
    
    try {
        // Test 1: Regular SSL Certificate Tests
        console.log('\n📋 Phase 1: SSL Certificate Analysis Tests');
        console.log('-'.repeat(40));
        const sslResults = await runSSLTests();
        allResults.push({ phase: 'SSL Certificates', results: sslResults });
        
        // Test 2: Security Headers Tests
        console.log('\n📋 Phase 2: Security Headers Analysis Tests');
        console.log('-'.repeat(40));
        const headersResults = await runHeadersTests();
        allResults.push({ phase: 'Security Headers', results: headersResults });
        
        // Test 3: Additional Security Checks Tests
        console.log('\n📋 Phase 3: Additional Security Checks Tests');
        console.log('-'.repeat(40));
        const additionalResults = await runAdditionalChecksTests();
        allResults.push({ phase: 'Additional Checks', results: additionalResults });
        
        // Test 4: BadSSL Certificate Scenarios
        console.log('\n📋 Phase 4: BadSSL Certificate Error Scenarios');
        console.log('-'.repeat(40));
        const badSSLResults = await runBadSSLTests();
        allResults.push({ phase: 'BadSSL Scenarios', results: badSSLResults });
        
    } catch (error) {
        console.error(`\n💥 Test phase failed: ${error.message}`);
        process.exit(1);
    }
    
    // Overall Summary
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);
    
    console.log('\n' + '='.repeat(60));
    console.log('🏁 COMPREHENSIVE INTEGRATION TEST SUMMARY');
    console.log('='.repeat(60));
    
    let totalTests = 0;
    let totalPassed = 0;
    
    allResults.forEach(phase => {
        const passed = phase.results.filter(r => r.passed).length;
        const total = phase.results.length;
        totalTests += total;
        totalPassed += passed;
        
        console.log(`📊 ${phase.phase}: ${passed}/${total} passed`);
    });
    
    console.log(`\n⏱️  Total Execution Time: ${duration}s`);
    console.log(`📈 Overall Success Rate: ${totalPassed}/${totalTests} (${Math.round(totalPassed/totalTests*100)}%)`);
    
    // Detailed Failure Analysis
    const failures = allResults.flatMap(phase => 
        phase.results.filter(r => !r.passed).map(r => ({ ...r, phase: phase.phase }))
    );
    
    if (failures.length > 0) {
        console.log(`\n❌ Failed Tests (${failures.length}):`);
        failures.forEach(failure => {
            console.log(`   • ${failure.phase}: ${failure.test}`);
            if (failure.errors && failure.errors.length > 0) {
                failure.errors.forEach(error => console.log(`     - ${error}`));
            } else if (failure.error) {
                console.log(`     - ${failure.error}`);
            }
        });
    } else {
        console.log('\n🎉 All tests passed! Excellent security analysis coverage.');
    }
    
    // Security Analysis Summary
    console.log('\n🔍 Security Analysis Coverage Summary:');
    console.log('-'.repeat(40));
    
    // SSL Analysis Coverage
    const sslAnalysisResults = allResults.find(p => p.phase === 'SSL Certificates')?.results || [];
    const badSSLAnalysisResults = allResults.find(p => p.phase === 'BadSSL Scenarios')?.results || [];
    
    console.log(`🔒 SSL Certificate Analysis:`);
    console.log(`   • Normal certificates: ${sslAnalysisResults.filter(r => r.passed).length}/${sslAnalysisResults.length}`);
    console.log(`   • Error scenarios: ${badSSLAnalysisResults.filter(r => r.passed).length}/${badSSLAnalysisResults.length}`);
    
    // Headers Analysis Coverage
    const headersAnalysisResults = allResults.find(p => p.phase === 'Security Headers')?.results || [];
    console.log(`📋 Security Headers Analysis:`);
    console.log(`   • Header detection: ${headersAnalysisResults.filter(r => r.passed).length}/${headersAnalysisResults.length}`);
    
    // Additional Checks Coverage
    const additionalAnalysisResults = allResults.find(p => p.phase === 'Additional Checks')?.results || [];
    console.log(`🔧 Additional Security Checks:`);
    console.log(`   • Security features: ${additionalAnalysisResults.filter(r => r.passed).length}/${additionalAnalysisResults.length}`);
    
    // Certificate Error Types Tested
    const errorTypes = [
        'Expired certificates',
        'Hostname mismatches', 
        'Untrusted root CAs',
        'Revoked certificates',
        'Certificate pinning scenarios',
        'Client certificate requirements'
    ];
    
    console.log(`\n🧪 Certificate Error Scenarios Tested:`);
    errorTypes.forEach((type, index) => {
        const testResult = badSSLAnalysisResults[index];
        const status = testResult?.passed ? '✅' : '❌';
        console.log(`   ${status} ${type}`);
    });
    
    // Exit with appropriate code
    const allPassed = totalPassed === totalTests;
    console.log(`\n${allPassed ? '🎉 ALL TESTS PASSED!' : '⚠️  SOME TESTS FAILED'}`);
    process.exit(allPassed ? 0 : 1);
}

// Run all tests
if (require.main === module) {
    runAllIntegrationTests()
        .catch(error => {
            console.error('💥 Integration test suite failed:', error);
            process.exit(1);
        });
}

module.exports = { runAllIntegrationTests };
