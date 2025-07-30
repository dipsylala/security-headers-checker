/**
 * Debug test for modular additional checks
 */

const { performAdditionalChecks } = require('../lib/additional-checks');

async function debugModularAdditionalChecks() {
    console.log('🔍 Debugging Modular Additional Checks');
    console.log('═════════════════════════════════════');

    const url = 'https://google.com';
    console.log(`Testing: ${url}`);

    try {
        const result = await performAdditionalChecks(url);

        console.log('\n📋 Detailed Check Results:');
        result.checks.forEach((check, index) => {
            console.log(`\n[${index + 1}] Check ID: ${check.checkId}`);
            console.log(`    Name: ${check.name}`);
            console.log(`    Status: ${check.status}`);
            console.log(`    Details: ${check.details}`);
            console.log(`    Score: ${check.score}/${check.maxScore}`);
            console.log(`    Weight: ${check.weight}`);
            console.log(`    Duration: ${check.duration}ms`);

            if (check.name === undefined || check.details === undefined) {
                console.log(`    ⚠️  UNDEFINED VALUES DETECTED!`);
                console.log(`    Raw result:`, JSON.stringify(check, null, 2));
            }
        });

    } catch (error) {
        console.error('❌ Error:', error);
    }
}

debugModularAdditionalChecks();
