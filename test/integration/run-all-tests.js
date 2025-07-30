#!/usr/bin/env node

/**
 * Comprehensive Integration Test Runner
 * Runs all integration tests including BadSSL certificate scenarios
 */

const { runSSLTests } = require('./ssl-certificate.test.js');
const { runHeadersTests } = require('./security-headers-analysis.test.js');
const { runAdditionalChecksTests } = require('./web-security.test.js');
const { runBadSSLTests } = require('./badssl-scenarios.test.js');
const { runComprehensiveSSLTests } = require('./comprehensive-ssl.test.js');
const { runSSLyzeTests } = require('./sslyze-analysis.test.js');
const http = require('http');

/**
 * Check if the WebCheck Validator server is running
 * @returns {Promise<boolean>} True if server is running and responding
 */
function checkServerHealth() {
    return new Promise((resolve) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/health',
            method: 'GET',
            timeout: 5000 // 5 second timeout
        };

        const req = http.request(options, (_) => {
            // Any response (even 404) means server is running
            resolve(true);
        });

        req.on('error', (_) => {
            // Connection refused, server not running
            resolve(false);
        });

        req.on('timeout', () => {
            req.destroy();
            resolve(false);
        });

        req.end();
    });
}

/**
 * Attempt to check server with a simple API call
 * @returns {Promise<boolean>} True if server responds to API calls
 */
function checkServerAPI() {
    return new Promise((resolve) => {
        // Use health endpoint first as it's faster and more reliable
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/health',
            method: 'GET',
            timeout: 5000 // 5 second timeout for health check
        };

        const req = http.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    // Check for healthy response
                    if (res.statusCode === 200 && result.status === 'healthy') {
                        resolve(true); // Server is responding properly
                    } else {
                        console.log(`Health check returned status ${res.statusCode}: ${data}`);
                        resolve(false);
                    }
                } catch (error) {
                    console.log(`Health check response parsing error: ${error.message}`);
                    resolve(false);
                }
            });
        });

        req.on('error', (error) => {
            console.log(`Health check request error: ${error.message}`);
            resolve(false);
        });

        req.on('timeout', () => {
            req.destroy();
            console.log('Health check request timed out');
            resolve(false);
        });

        req.end();
    });
}

async function runAllIntegrationTests() {
    console.log('🚀 Starting Comprehensive Integration Test Suite...\n');
    console.log('=' .repeat(60));

    // Server Health Check
    console.log('🔍 Checking server health...');
    const serverRunning = await checkServerHealth();

    if (!serverRunning) {
        console.error('❌ Server is not running on localhost:3000');
        console.error('💡 Please start the server with: npm start or npm run dev');
        console.error('🛑 Integration tests require the server to be running\n');
        process.exit(1);
    }

    console.log('✅ Server is running on localhost:3000');

    // API Health Check
    console.log('🔍 Checking API health...');
    const apiWorking = await checkServerAPI();

    if (!apiWorking) {
        console.error('❌ API health check failed');
        console.error('💡 Server may be starting up, please wait a moment and try again');
        console.error('🛑 Integration tests require the API to be working\n');
        process.exit(1);
    }

    console.log('✅ API is healthy and responding correctly');
    console.log('🎯 All pre-flight checks passed - starting integration tests...\n');

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

        // Test 4: Comprehensive SSL Analysis Tests
        console.log('\n📋 Phase 4: Comprehensive SSL Analysis Tests');
        console.log('-'.repeat(40));
        const comprehensiveSSLResults = await runComprehensiveSSLTests();
        allResults.push({ phase: 'Comprehensive SSL', results: comprehensiveSSLResults });

        // Test 5: BadSSL Certificate Scenarios
        console.log('\n📋 Phase 5: BadSSL Certificate Error Scenarios');
        console.log('-'.repeat(40));
        const badSSLResults = await runBadSSLTests();
        allResults.push({ phase: 'BadSSL Scenarios', results: badSSLResults });

        // Test 6: SSLyze Enhanced Analysis Tests
        console.log('\n📋 Phase 6: SSLyze Enhanced SSL Analysis Tests');
        console.log('-'.repeat(40));
        const sslyzeResults = await runSSLyzeTests();
        allResults.push({ phase: 'SSLyze Analysis', results: sslyzeResults });

    } catch (error) {
        console.error(`\n💥 Test phase failed: ${error.message}`);
        process.exit(1);
    }

    // Overall Summary
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);

    console.log(`\n${ '='.repeat(60)}`);
    console.log('🏁 COMPREHENSIVE INTEGRATION TEST SUMMARY');
    console.log('='.repeat(60));

    let totalTests = 0;
    let totalPassed = 0;

    allResults.forEach(phase => {
        // Handle different result formats
        if (Array.isArray(phase.results)) {
            // Array format (SSL, Headers, Additional, BadSSL)
            const passed = phase.results.filter(r => r.passed).length;
            const total = phase.results.length;
            totalTests += total;
            totalPassed += passed;
            console.log(`📊 ${phase.phase}: ${passed}/${total} passed`);
        } else if (phase.results && typeof phase.results === 'object' && 'passed' in phase.results) {
            // Object format (Comprehensive SSL)
            const passed = phase.results.passed;
            const total = phase.results.total || (phase.results.passed + phase.results.failed);
            totalTests += total;
            totalPassed += passed;
            console.log(`📊 ${phase.phase}: ${passed}/${total} passed`);
        }
    });

    console.log(`\n⏱️  Total Execution Time: ${duration}s`);
    console.log(`📈 Overall Success Rate: ${totalPassed}/${totalTests} (${Math.round(totalPassed / totalTests * 100)}%)`);

    // Detailed Failure Analysis
    const failures = allResults.flatMap(phase => {
        if (Array.isArray(phase.results)) {
            // Array format - filter failed tests
            return phase.results.filter(r => !r.passed).map(r => ({ ...r, phase: phase.phase }));
        } else if (phase.results && typeof phase.results === 'object' && phase.results.failed > 0) {
            // Object format - create a failure entry if there are failed tests
            return [{ test: `${phase.phase} tests`, phase: phase.phase, error: `${phase.results.failed} tests failed` }];
        }
        return [];
    });

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
    const comprehensiveSSLAnalysisResults = allResults.find(p => p.phase === 'Comprehensive SSL')?.results;
    const badSSLAnalysisResults = allResults.find(p => p.phase === 'BadSSL Scenarios')?.results || [];

    console.log(`🔒 SSL Certificate Analysis:`);
    console.log(`   • Normal certificates: ${sslAnalysisResults.filter(r => r.passed).length}/${sslAnalysisResults.length}`);

    // Handle comprehensive SSL results (object format)
    if (comprehensiveSSLAnalysisResults && typeof comprehensiveSSLAnalysisResults === 'object') {
        const totalComprehensive = comprehensiveSSLAnalysisResults.total ||
            (comprehensiveSSLAnalysisResults.passed + comprehensiveSSLAnalysisResults.failed);
        console.log(`   • Comprehensive analysis: ${comprehensiveSSLAnalysisResults.passed}/${totalComprehensive}`);
    } else {
        console.log(`   • Comprehensive analysis: 0/0`);
    }

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
