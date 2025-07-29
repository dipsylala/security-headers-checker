#!/usr/bin/env node

/**
 * Debug script to check SSLyze scan results structure
 */

const { runSSLyzeScan, convertSSLyzeToTests } = require('./lib/ssl-analyzer');

async function debugSSLyzeResults() {
    console.log('🔍 Debugging SSLyze Results Structure');
    console.log('=' .repeat(50));

    try {
        const scanResult = await runSSLyzeScan('github.com', 443);
        
        if (!scanResult.success) {
            console.log('❌ SSLyze scan failed:', scanResult.error);
            return;
        }
        
        console.log('✅ SSLyze scan completed successfully');
        
        const serverResult = scanResult.data.server_scan_results[0];
        console.log('� Connectivity status:', serverResult.connectivity_status);
        console.log('🔍 Scan status:', serverResult.scan_status);
        
        // Now test the conversion function
        console.log('\n🧪 Testing convertSSLyzeToTests function...');
        const tests = convertSSLyzeToTests(scanResult.data, 'github.com'); // Pass full data object
        console.log(`� Generated ${tests.length} tests:`);
        
        for (let i = 0; i < tests.length; i++) {
            const test = tests[i];
            console.log(`${i + 1}. ${test.name}: ${test.status} (score: ${test.score})`);
            console.log(`   📝 ${test.details}`);
            if (test.recommendation) {
                console.log(`   💡 ${test.recommendation}`);
            }
            console.log('');
        }
        
        // Check specifically for high-priority features
        const highPriorityTests = [
            'SSLyze TLS Fallback SCSV',
            'SSLyze Session Renegotiation', 
            'SSLyze Certificate Transparency',
            'SSLyze OCSP Stapling',
            'SSLyze Extended Master Secret'
        ];

        console.log('🎯 High-Priority Features Check:');
        for (const testName of highPriorityTests) {
            const test = tests.find(t => t.name === testName);
            if (test) {
                console.log(`✅ Found: ${testName}`);
            } else {
                console.log(`❌ Missing: ${testName}`);
            }
        }
        
    } catch (error) {
        console.error('💥 Debug failed:', error.message);
        console.error('Stack trace:', error.stack);
    }
}

debugSSLyzeResults();
