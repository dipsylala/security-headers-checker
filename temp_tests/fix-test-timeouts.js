#!/usr/bin/env node

/**
 * Quick script to fix timeout issues in test files
 */

const fs = require('fs');
const path = require('path');

const testFiles = [
    'badssl-scenarios.test.js',
    'security-headers-analysis.test.js',
    'web-security.test.js',
    'performance.test.js',
    'sslyze-analysis.test.js'
];

const testDir = path.join(__dirname, '..', 'test', 'integration');

testFiles.forEach(filename => {
    const filePath = path.join(testDir, filename);

    if (fs.existsSync(filePath)) {
        console.log(`Fixing ${filename}...`);

        let content = fs.readFileSync(filePath, 'utf8');

        // Add timeout to options
        const optionsRegex = /(headers: \{[^}]+\}\s*)(}\s*;)/;
        if (content.includes('timeout: ')) {
            console.log(`  - ${filename} already has timeout`);
        } else if (optionsRegex.test(content)) {
            content = content.replace(optionsRegex, '$1,\n            timeout: 30000 // 30 second timeout for analysis\n        $2');
            console.log(`  - Added timeout to options in ${filename}`);
        }

        // Add timeout handler
        const timeoutHandlerRegex = /(req\.on\('error',[\s\S]*?\}\);)/;
        if (content.includes('req.on(\'timeout\'')) {
            console.log(`  - ${filename} already has timeout handler`);
        } else if (timeoutHandlerRegex.test(content)) {
            content = content.replace(timeoutHandlerRegex, `$1

        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout - analysis took longer than 30 seconds'));
        });`);
            console.log(`  - Added timeout handler to ${filename}`);
        }

        fs.writeFileSync(filePath, content);
        console.log(`  - ✅ Fixed ${filename}`);
    } else {
        console.log(`  - ❌ ${filename} not found`);
    }
});

console.log('\n🎉 Timeout fixes complete!');
