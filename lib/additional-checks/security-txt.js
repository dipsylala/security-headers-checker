/**
 * Security.txt Security Check
 * Verifies presence and validity of security.txt file (RFC 9116)
 */

const https = require('https');
const http = require('http');

/**
 * Check for security.txt file (RFC 9116)
 * @param {string} url - The URL to check
 * @returns {Promise<Object>} Security.txt check result with scoring
 */
async function checkSecurityTxt(url) {
    return new Promise((resolve) => {
        const urlObj = new URL(url);
        
        // Try the standard location first: /.well-known/security.txt
        checkSecurityTxtLocation(urlObj, '/.well-known/security.txt')
            .then(result => {
                if (result.found) {
                    resolve(result);
                } else {
                    // Fallback to legacy location: /security.txt
                    return checkSecurityTxtLocation(urlObj, '/security.txt');
                }
            })
            .then(result => {
                if (result) {
                    if (result.found) {
                        // Found at legacy location
                        result.details += ' (found at legacy location /security.txt)';
                        result.recommendation = 'Move security.txt to standard location /.well-known/security.txt';
                        result.score = Math.max(0, result.score - 0.5); // Reduce score slightly for legacy location
                    }
                    resolve(result);
                } else {
                    // Not found at either location
                    resolve({
                        name: 'Security.txt',
                        status: 'info',
                        description: 'Checks for security.txt file (RFC 9116)',
                        details: 'No security.txt file found',
                        score: 0,
                        maxScore: 1,
                        recommendation: 'Consider creating a security.txt file to provide security contact information'
                    });
                }
            })
            .catch(() => {
                resolve({
                    name: 'Security.txt',
                    status: 'info',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: 'Unable to check for security.txt',
                    score: 0,
                    maxScore: 1,
                    recommendation: null
                });
            });
    });
}

/**
 * Check for security.txt at a specific location
 * @param {URL} urlObj - Parsed URL object
 * @param {string} path - Path to check for security.txt
 * @returns {Promise<Object>} Check result
 */
function checkSecurityTxtLocation(urlObj, path) {
    return new Promise((resolve) => {
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
            path: path,
            method: 'GET',
            timeout: 5000,
            headers: {
                'User-Agent': 'Security-Headers-Checker/1.0'
            }
        };

        const request = (urlObj.protocol === 'https:' ? https : http).request(options, (response) => {
            if (response.statusCode === 200) {
                let data = '';
                let dataLength = 0;
                const maxDataLength = 10000; // Limit data size

                response.on('data', chunk => {
                    if (dataLength < maxDataLength) {
                        data += chunk;
                        dataLength += chunk.length;
                    }
                });

                response.on('end', () => {
                    const analysis = analyzeSecurityTxtContent(data, response.headers);
                    resolve({
                        name: 'Security.txt',
                        status: analysis.status,
                        description: 'Checks for security.txt file (RFC 9116)',
                        details: analysis.details,
                        score: analysis.score,
                        maxScore: 1,
                        recommendation: analysis.recommendation,
                        found: true
                    });
                });
            } else {
                // Not found at this location
                resolve({
                    name: 'Security.txt',
                    status: 'info',
                    description: 'Checks for security.txt file (RFC 9116)',
                    details: `No security.txt file found at ${path} (HTTP ${response.statusCode})`,
                    score: 0,
                    maxScore: 1,
                    recommendation: null,
                    found: false,
                    statusCode: response.statusCode
                });
            }
        });

        request.on('error', () => {
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Unable to check for security.txt (connection error)',
                score: 0,
                maxScore: 1,
                recommendation: null,
                found: false,
                error: true
            });
        });

        request.on('timeout', () => {
            request.destroy();
            resolve({
                name: 'Security.txt',
                status: 'info',
                description: 'Checks for security.txt file (RFC 9116)',
                details: 'Security.txt check timed out',
                score: 0,
                maxScore: 1,
                recommendation: null,
                found: false,
                timeout: true
            });
        });

        request.end();
    });
}

/**
 * Analyze security.txt file content
 * @param {string} content - File content
 * @param {Object} headers - Response headers
 * @returns {Object} Analysis result
 */
function analyzeSecurityTxtContent(content, headers) {
    let score = 1; // Base score for having the file
    let status = 'pass';
    let details = 'Security.txt file found';
    let issues = [];
    let recommendation = null;

    // Check content type
    const contentType = headers['content-type'] || '';
    if (!contentType.includes('text/plain')) {
        issues.push('incorrect content-type (should be text/plain)');
        score -= 0.1;
    }

    // Check for required fields according to RFC 9116
    const requiredFields = ['Contact'];
    const optionalFields = ['Expires', 'Encryption', 'Acknowledgments', 'Policy', 'Hiring'];
    
    const lines = content.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
    const fields = {};
    
    lines.forEach(line => {
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const field = line.substring(0, colonIndex).trim();
            const value = line.substring(colonIndex + 1).trim();
            if (!fields[field]) {
                fields[field] = [];
            }
            fields[field].push(value);
        }
    });

    // Check required fields
    requiredFields.forEach(field => {
        if (!fields[field] || fields[field].length === 0) {
            issues.push(`missing required field: ${field}`);
            score -= 0.3;
        }
    });

    // Check if Contact field has valid format
    if (fields['Contact']) {
        const validContactFormats = fields['Contact'].every(contact => {
            return contact.startsWith('mailto:') || 
                   contact.startsWith('https://') || 
                   contact.startsWith('http://') ||
                   contact.startsWith('tel:');
        });
        
        if (!validContactFormats) {
            issues.push('Contact field should use mailto:, https://, or tel: URI schemes');
            score -= 0.2;
        }
    }

    // Check for Expires field and validate date
    if (fields['Expires']) {
        try {
            const expiryDate = new Date(fields['Expires'][0]);
            const now = new Date();
            
            if (expiryDate <= now) {
                issues.push('security.txt file has expired');
                score -= 0.3;
                status = 'warning';
            } else {
                const daysUntilExpiry = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
                if (daysUntilExpiry < 30) {
                    issues.push(`security.txt expires soon (${daysUntilExpiry} days)`);
                    score -= 0.1;
                }
            }
        } catch (e) {
            issues.push('invalid Expires date format');
            score -= 0.1;
        }
    } else {
        issues.push('missing Expires field (recommended)');
        score -= 0.1;
    }

    // Ensure score doesn't go below 0
    score = Math.max(0, score);

    if (issues.length > 0) {
        details += ` - Issues: ${issues.join(', ')}`;
        if (score < 0.7) {
            status = 'warning';
        }
        recommendation = `Fix security.txt issues: ${issues.slice(0, 2).join(', ')}${issues.length > 2 ? '...' : ''}`;
    } else {
        details += ' - properly configured';
    }

    return {
        status,
        details,
        score,
        recommendation
    };
}

module.exports = {
    performCheck: checkSecurityTxt,
    name: 'Security.txt',
    description: 'Verifies presence and validity of security.txt file (RFC 9116)'
};
