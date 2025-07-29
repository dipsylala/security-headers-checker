/**
 * Quick test for modular additional checks
 */

const { performAdditionalChecks } = require('../lib/additional-checks');

async function testModularAdditionalChecks() {
    console.log('🧪 Testing Modular Additional Checks Implementation');
    console.log('═══════════════════════════════════════════════════');
    
    const testUrls = [
        'https://github.com',
        'https://google.com',
        'https://cloudflare.com'
    ];
    
    for (const url of testUrls) {
        console.log(`\n🔍 Testing: ${url}`);
        console.log('───────────────────────────────────────');
        
        try {
            const result = await performAdditionalChecks(url);
            
            console.log(`📊 Checks Performed: ${result.checks.length}`);
            console.log(`🎯 Score: ${result.score.score}/${result.score.maxScore} (${result.score.percentage}%)`);
            console.log(`✅ Passed: ${result.score.passed}`);
            console.log(`❌ Failed: ${result.score.failed}`);
            console.log(`⚠️  Warnings: ${result.score.warnings}`);
            console.log(`ℹ️  Info: ${result.score.info}`);
            
            console.log('\n📋 Individual Check Results:');
            result.checks.forEach(check => {
                const statusIcon = check.status === 'pass' ? '✅' : 
                                 check.status === 'fail' ? '❌' : 
                                 check.status === 'warning' ? '⚠️' : 'ℹ️';
                console.log(`   ${statusIcon} ${check.name}: ${check.details} (${check.score}/${check.maxScore} pts, weight: ${check.weight})`);
            });
            
        } catch (error) {
            console.error(`❌ Error testing ${url}:`, error.message);
        }
    }
    
    console.log('\n🎉 Modular Additional Checks Test Complete!');
}

testModularAdditionalChecks();
