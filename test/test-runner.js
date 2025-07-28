/**
 * Test Runner - Coordinates all integration tests
 * Runs SSL, headers, additional checks, and performance tests
 */

const { runSSLTests } = require('./integration/ssl-certificate.test.js');
const { runHeadersTests } = require('./integration/security-headers.test.js');
const { runAdditionalChecksTests } = require('./integration/additional-checks.test.js');
const { runPerformanceTests } = require('./integration/performance.test.js');

/**
 * Run all integration test suites
 */
async function runAllTests() {
    console.log('🚀 Starting Integration Test Suite');
    console.log('=' .repeat(50));

    const results = {
        ssl: { passed: 0, failed: 0, details: [] },
        headers: { passed: 0, failed: 0, details: [] },
        additional: { passed: 0, failed: 0, details: [] },
        performance: { passed: 0, failed: 0, details: [] }
    };

    let allPassed = true;

    try {
        // Run SSL Certificate Tests
        console.log('\n🔒 Running SSL Certificate Tests...');
        console.log('-'.repeat(40));
        const sslResults = await runSSLTests();

        sslResults.forEach(result => {
            if (result.passed) {
                results.ssl.passed++;
            } else {
                results.ssl.failed++;
                allPassed = false;
            }
            results.ssl.details.push(result);
        });

        console.log(`SSL Tests: ${results.ssl.passed} passed, ${results.ssl.failed} failed`);

    } catch (error) {
        console.error(`❌ SSL Tests failed: ${error.message}`);
        results.ssl.failed++;
        allPassed = false;
    }

    try {
        // Run Security Headers Tests
        console.log('\n🛡️  Running Security Headers Tests...');
        console.log('-'.repeat(40));
        const headerResults = await runHeadersTests();

        headerResults.forEach(result => {
            if (result.passed) {
                results.headers.passed++;
            } else {
                results.headers.failed++;
                allPassed = false;
            }
            results.headers.details.push(result);
        });

        console.log(`Headers Tests: ${results.headers.passed} passed, ${results.headers.failed} failed`);

    } catch (error) {
        console.error(`❌ Headers Tests failed: ${error.message}`);
        results.headers.failed++;
        allPassed = false;
    }

    try {
        // Run Additional Security Checks Tests
        console.log('\n🔍 Running Additional Security Checks Tests...');
        console.log('-'.repeat(40));
        const additionalResults = await runAdditionalChecksTests();

        additionalResults.forEach(result => {
            if (result.passed) {
                results.additional.passed++;
            } else {
                results.additional.failed++;
                allPassed = false;
            }
            results.additional.details.push(result);
        });

        console.log(`Additional Tests: ${results.additional.passed} passed, ${results.additional.failed} failed`);

    } catch (error) {
        console.error(`❌ Additional Tests failed: ${error.message}`);
        results.additional.failed++;
        allPassed = false;
    }

    try {
        // Run Performance Tests
        console.log('\n⚡ Running Performance Tests...');
        console.log('-'.repeat(40));
        const performanceResults = await runPerformanceTests();

        performanceResults.forEach(result => {
            if (result.passed) {
                results.performance.passed++;
            } else {
                results.performance.failed++;
                allPassed = false;
            }
            results.performance.details.push(result);
        });

        console.log(`Performance Tests: ${results.performance.passed} passed, ${results.performance.failed} failed`);

    } catch (error) {
        console.error(`❌ Performance Tests failed: ${error.message}`);
        results.performance.failed++;
        allPassed = false;
    }

    // Summary
    console.log('\n📊 Test Suite Summary');
    console.log('=' .repeat(50));

    const totalPassed = results.ssl.passed + results.headers.passed +
                       results.additional.passed + results.performance.passed;
    const totalFailed = results.ssl.failed + results.headers.failed +
                       results.additional.failed + results.performance.failed;

    console.log(`✅ Total Passed: ${totalPassed}`);
    console.log(`❌ Total Failed: ${totalFailed}`);
    console.log(`🎯 Overall Status: ${allPassed ? 'PASS' : 'FAIL'}`);

    if (!allPassed) {
        console.log('\n❌ Failed Tests Summary:');

        // Show failed test details
        const allResults = [
            ...results.ssl.details,
            ...results.headers.details,
            ...results.additional.details,
            ...results.performance.details
        ];

        allResults.filter(r => !r.passed).forEach(result => {
            console.log(`   • ${result.testName}: ${result.error || 'Failed'}`);
        });
    }

    return allPassed;
}

// Run tests if called directly
if (require.main === module) {
    runAllTests()
        .then(success => {
            process.exit(success ? 0 : 1);
        })
        .catch(error => {
            console.error('💥 Test runner failed:', error);
            process.exit(1);
        });
}

module.exports = { runAllTests };
