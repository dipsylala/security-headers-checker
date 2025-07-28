const { runSSLTests } = require('./ssl-certificate.test');
const { runHeadersTests } = require('./security-headers.test');
const { runAdditionalChecksTests } = require('./additional-checks.test');
const { runPerformanceTests } = require('./performance.test');

/**
 * Main Integration Test Runner
 * Coordinates running all integration test suites or specific areas
 */

const TEST_SUITES = {
    ssl: {
        name: 'SSL/TLS Certificate Tests',
        runner: runSSLTests,
        description: 'Tests SSL certificate analysis, grading, and signature algorithm detection'
    },
    headers: {
        name: 'Security Headers Tests',
        runner: runHeadersTests,
        description: 'Tests security header detection, categorization, and validation'
    },
    additional: {
        name: 'Additional Security Checks Tests',
        runner: runAdditionalChecksTests,
        description: 'Tests HTTP methods, HTTPS redirects, mixed content, security.txt, etc.'
    },
    performance: {
        name: 'Performance and Reliability Tests',
        runner: runPerformanceTests,
        description: 'Tests response times, error handling, edge cases, and reliability'
    }
};

async function runAllTests() {
    console.log('🧪 Starting Complete Integration Test Suite...\n');
    console.log('═'.repeat(70));
    
    const allResults = {};
    const overallStats = {
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        startTime: Date.now()
    };
    
    for (const [suiteKey, suite] of Object.entries(TEST_SUITES)) {
        console.log(`\n🎯 Running: ${suite.name}`);
        console.log(`📝 ${suite.description}`);
        console.log('─'.repeat(50));
        
        try {
            const results = await suite.runner();
            allResults[suiteKey] = results;
            
            const passed = results.filter(r => r.passed).length;
            const total = results.length;
            
            overallStats.totalTests += total;
            overallStats.passedTests += passed;
            overallStats.failedTests += (total - passed);
            
            console.log(`✅ ${suite.name}: ${passed}/${total} tests passed\n`);
            
        } catch (error) {
            console.error(`❌ ${suite.name} FAILED: ${error.message}\n`);
            allResults[suiteKey] = { error: error.message };
            overallStats.failedTests += 1;
        }
    }
    
    const totalTime = Date.now() - overallStats.startTime;
    
    // Final Summary
    console.log('\n📊 COMPLETE INTEGRATION TEST RESULTS');
    console.log('═'.repeat(70));
    console.log(`⏱️  Total execution time: ${(totalTime / 1000).toFixed(1)}s`);
    console.log(`✅ Total tests passed: ${overallStats.passedTests}`);
    console.log(`❌ Total tests failed: ${overallStats.failedTests}`);
    console.log(`📈 Success rate: ${((overallStats.passedTests / overallStats.totalTests) * 100).toFixed(1)}%`);
    
    // Suite-by-suite breakdown
    console.log('\n📋 Test Suite Breakdown:');
    Object.keys(TEST_SUITES).forEach(suiteKey => {
        const results = allResults[suiteKey];
        if (results && !results.error) {
            const passed = results.filter(r => r.passed).length;
            const total = results.length;
            const icon = passed === total ? '✅' : passed > 0 ? '⚠️' : '❌';
            console.log(`   ${icon} ${TEST_SUITES[suiteKey].name}: ${passed}/${total}`);
        } else {
            console.log(`   ❌ ${TEST_SUITES[suiteKey].name}: SUITE FAILED`);
        }
    });
    
    // Failed tests summary
    if (overallStats.failedTests > 0) {
        console.log('\n🔍 Failed Tests Summary:');
        Object.keys(allResults).forEach(suiteKey => {
            const results = allResults[suiteKey];
            if (results && !results.error) {
                const failed = results.filter(r => !r.passed);
                if (failed.length > 0) {
                    console.log(`\n   ${TEST_SUITES[suiteKey].name}:`);
                    failed.forEach(result => {
                        console.log(`     • ${result.test}: ${result.errors?.join(', ') || result.error}`);
                    });
                }
            }
        });
    }
    
    // Recommendations
    console.log('\n💡 Recommendations:');
    if (overallStats.passedTests === overallStats.totalTests) {
        console.log('   🎉 All tests passed! Your security analysis is working perfectly.');
    } else if (overallStats.passedTests / overallStats.totalTests > 0.8) {
        console.log('   👍 Most tests passed. Review failed tests for potential improvements.');
    } else {
        console.log('   ⚠️  Several tests failed. Review the analysis logic and error handling.');
    }
    
    return allResults;
}

async function runSpecificSuite(suiteName) {
    const suite = TEST_SUITES[suiteName];
    
    if (!suite) {
        console.error(`❌ Unknown test suite: ${suiteName}`);
        console.log('Available suites:', Object.keys(TEST_SUITES).join(', '));
        process.exit(1);
    }
    
    console.log(`🎯 Running: ${suite.name}`);
    console.log(`📝 ${suite.description}\n`);
    
    const results = await suite.runner();
    
    const passed = results.filter(r => r.passed).length;
    const total = results.length;
    
    console.log(`\n📊 ${suite.name} Results: ${passed}/${total} tests passed`);
    
    return results;
}

function printUsage() {
    console.log('🧪 Integration Test Runner');
    console.log('═'.repeat(40));
    console.log('Usage: node test-runner.js [suite]');
    console.log('');
    console.log('Available test suites:');
    Object.keys(TEST_SUITES).forEach(key => {
        console.log(`  ${key.padEnd(12)} - ${TEST_SUITES[key].description}`);
    });
    console.log('');
    console.log('Examples:');
    console.log('  node test-runner.js           # Run all test suites');
    console.log('  node test-runner.js ssl       # Run only SSL tests');
    console.log('  node test-runner.js headers   # Run only header tests');
    console.log('  node test-runner.js additional # Run only additional checks');
    console.log('  node test-runner.js performance # Run only performance tests');
}

// Export for use in other modules
module.exports = { 
    runAllTests, 
    runSpecificSuite, 
    TEST_SUITES,
    runSSLTests,
    runHeadersTests,
    runAdditionalChecksTests,
    runPerformanceTests
};

// Command line interface
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.includes('--help') || args.includes('-h')) {
        printUsage();
        process.exit(0);
    }
    
    const suiteName = args[0];
    
    if (!suiteName) {
        // Run all tests
        runAllTests()
            .then(results => {
                const allPassed = Object.values(results).every(suiteResults => 
                    !suiteResults.error && suiteResults.every(r => r.passed)
                );
                process.exit(allPassed ? 0 : 1);
            })
            .catch(error => {
                console.error('💥 Test runner failed:', error);
                process.exit(1);
            });
    } else {
        // Run specific suite
        runSpecificSuite(suiteName)
            .then(results => {
                const allPassed = results.every(r => r.passed);
                process.exit(allPassed ? 0 : 1);
            })
            .catch(error => {
                console.error('💥 Test runner failed:', error);
                process.exit(1);
            });
    }
}
