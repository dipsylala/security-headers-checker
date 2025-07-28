// Test hostname mismatch logic
function testHostnameMismatch(hostname, subject) {
    let mismatchExplanation = '';
    if (hostname && subject) {
        if (subject.includes('*') && hostname.includes('.')) {
            const wildcardDomain = subject.replace('*.', '');
            const requestedParts = hostname.split('.');
            const wildcardParts = wildcardDomain.split('.');
            
            if (requestedParts.length > wildcardParts.length + 1) {
                mismatchExplanation = ` The certificate uses a wildcard (${subject}) which only covers one level of subdomains, but "${hostname}" has multiple subdomain levels.`;
            } else if (!hostname.endsWith(wildcardDomain)) {
                mismatchExplanation = ` The requested hostname "${hostname}" does not match the wildcard pattern "${subject}".`;
            }
        } else {
            mismatchExplanation = ` The requested hostname "${hostname}" does not match the certificate subject "${subject}".`;
        }
    }
    return mismatchExplanation;
}

// Test cases
console.log('=== WILDCARD MISMATCH TESTS ===');
console.log('Test 1 - Multiple subdomains vs wildcard:');
console.log(testHostnameMismatch('wrong.host.badssl.com', '*.badssl.com'));

console.log('\nTest 2 - Single subdomain vs wildcard (should be empty):');
console.log(testHostnameMismatch('test.badssl.com', '*.badssl.com'));

console.log('\nTest 3 - Different domain vs wildcard:');
console.log(testHostnameMismatch('example.com', '*.badssl.com'));

console.log('\n=== NON-WILDCARD MISMATCH TESTS ===');
console.log('Test 4 - Regular hostname mismatch:');
console.log(testHostnameMismatch('example.com', 'different.com'));

console.log('\nTest 5 - Subdomain vs main domain:');
console.log(testHostnameMismatch('www.example.com', 'example.com'));
