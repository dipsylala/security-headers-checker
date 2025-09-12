/**
 * SSLyze Integration Module
 * Handles SSLyze tool integration for advanced SSL/TLS analysis
 */

const { spawn, exec } = require('child_process');

/**
 * Check if SSLyze is available on the system
 * @returns {Promise<Object>} Availability status and version info
 */
function checkSSLyzeAvailability() {
    return new Promise((resolve) => {
        exec('sslyze --help', { timeout: 10000 }, (error, stdout, _) => {
            if (error) {
                resolve({
                    available: false,
                    error: error.message,
                    recommendation: 'Install SSLyze: pip install sslyze'
                });
                return;
            }

            // Check if the output contains expected SSLyze content
            if (stdout.includes('usage: sslyze') || stdout.includes('SSLyze')) {
                // Extract version from help output if available
                const versionMatch = stdout.match(/SSLyze version ([\d.]+)/);
                const version = versionMatch ? versionMatch[1] : 'Available';

                resolve({
                    available: true,
                    version: version,
                    path: 'sslyze'
                });
            } else {
                resolve({
                    available: false,
                    error: 'SSLyze command did not return expected output',
                    recommendation: 'Install SSLyze: pip install sslyze'
                });
            }
        });
    });
}

/**
 * Run SSLyze scan on a target host
 * @param {string} hostname - Target hostname
 * @param {number} port - Target port (default 443)
 * @param {Object} options - Scan options
 * @returns {Promise<Object>} SSLyze scan results
 */
async function runSSLyzeScan(hostname, port = 443, options = {}) {
    // Validate hostname (must be a valid domain or IP address)
    const hostnameRegex = /^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$/;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!hostname || (!hostnameRegex.test(hostname) && !ipRegex.test(hostname))) {
        return {
            success: false,
            error: 'Invalid hostname provided',
            details: { hostname }
        };
    }
    // Validate port (must be integer 1-65535)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return {
            success: false,
            error: 'Invalid port provided',
            details: { port }
        };
    }

    const availability = await checkSSLyzeAvailability();
    if (!availability.available) {
        return {
            success: false,
            error: 'SSLyze not available',
            details: availability
        };
    }

    const args = [
        '--json_out=-', // Output JSON to stdout
        '--certinfo', // Certificate information
        '--heartbleed', // Heartbleed vulnerability test
        '--robot', // ROBOT vulnerability test
        '--openssl_ccs', // OpenSSL CCS injection test
        '--sslv2', // SSL 2.0 support test
        '--sslv3', // SSL 3.0 support test
        '--tlsv1', // TLS 1.0 support test
        '--tlsv1_1', // TLS 1.1 support test
        '--tlsv1_2', // TLS 1.2 support test
        '--tlsv1_3', // TLS 1.3 support test
        `${hostname}:${port}`
    ];

    return new Promise((resolve) => {
        const timeoutMs = options.timeout || 60000; // Increase default timeout to 60 seconds
        const child = spawn('sslyze', args, {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        let stdout = '';
        let stderr = '';
        let timeoutId = null;
        let resolved = false;

        const handleResolve = (result) => {
            if (!resolved) {
                resolved = true;
                if (timeoutId) { clearTimeout(timeoutId); }
                resolve(result);
            }
        };

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            if (code === 0) {
                try {
                    const results = parseSSLyzeOutput(stdout);
                    handleResolve({
                        success: true,
                        data: results,
                        rawOutput: stdout
                    });
                } catch (parseError) {
                    handleResolve({
                        success: false,
                        error: 'Failed to parse SSLyze output',
                        details: parseError.message,
                        rawOutput: stdout,
                        rawError: stderr
                    });
                }
            } else {
                handleResolve({
                    success: false,
                    error: `SSLyze exited with code ${code}`,
                    stderr: stderr,
                    stdout: stdout
                });
            }
        });

        child.on('error', (error) => {
            handleResolve({
                success: false,
                error: 'Failed to execute SSLyze',
                details: error.message
            });
        });

        // Handle timeout
        timeoutId = setTimeout(() => {
            if (!child.killed) {
                child.kill('SIGTERM');
                setTimeout(() => {
                    if (!child.killed) {
                        child.kill('SIGKILL');
                    }
                }, 5000);
                handleResolve({
                    success: false,
                    error: 'SSLyze scan timeout',
                    timeout: timeoutMs
                });
            }
        }, timeoutMs);
    });
}

/**
 * Parse SSLyze JSON output
 * @param {string} jsonOutput - Raw JSON output from SSLyze
 * @returns {Object} Parsed SSLyze results
 */
function parseSSLyzeOutput(jsonOutput) {
    if (!jsonOutput || jsonOutput.trim() === '') {
        throw new Error('Empty SSLyze output');
    }

    try {
        const data = JSON.parse(jsonOutput);

        if (!data.server_scan_results || data.server_scan_results.length === 0) {
            throw new Error('No scan results in SSLyze output');
        }

        const scanResult = data.server_scan_results[0];
        const extractedData = {
            serverInfo: scanResult.server_location || {},
            connectivityResult: scanResult.connectivity_result || {},
            scanCommands: scanResult.scan_result || {}, // Updated path
            errors: scanResult.scan_commands_errors || []
        };

        return extractedData;
    } catch (error) {
        throw new Error(`JSON parsing failed: ${error.message}`);
    }
}

/**
 * Convert SSLyze results to our SSL test format
 * @param {Object} sslyzeResults - Parsed SSLyze results
 * @returns {Object} SSL tests in our format
 */
function convertSSLyzeToTests(sslyzeResults) {
    const tests = {};

    try {
        const scanCommands = sslyzeResults.scanCommands || {};

        // Certificate Information
        if (scanCommands.certificate_info) {
            tests.certificateInfo = analyzeCertificateInfo(scanCommands.certificate_info);
        }

        // SSL 2.0 and 3.0 Checks
        if (scanCommands.ssl_2_0_cipher_suites) {
            tests.ssl2Support = analyzeSSL2Support(scanCommands.ssl_2_0_cipher_suites);
        }

        if (scanCommands.ssl_3_0_cipher_suites) {
            tests.ssl3Support = analyzeSSL3Support(scanCommands.ssl_3_0_cipher_suites);
        }

        // TLS Versions
        if (scanCommands.tls_1_0_cipher_suites) {
            tests.tls1_0Support = analyzeTLSSupport(scanCommands.tls_1_0_cipher_suites, '1.0');
        }

        if (scanCommands.tls_1_1_cipher_suites) {
            tests.tls1_1Support = analyzeTLSSupport(scanCommands.tls_1_1_cipher_suites, '1.1');
        }

        if (scanCommands.tls_1_2_cipher_suites) {
            tests.tls1_2Support = analyzeTLSSupport(scanCommands.tls_1_2_cipher_suites, '1.2');
        }

        if (scanCommands.tls_1_3_cipher_suites) {
            tests.tls1_3Support = analyzeTLSSupport(scanCommands.tls_1_3_cipher_suites, '1.3');
        }

        // Vulnerabilities
        if (scanCommands.heartbleed) {
            tests.heartbleed = analyzeHeartbleed(scanCommands.heartbleed);
        }

        if (scanCommands.robot) {
            tests.robot = analyzeRobot(scanCommands.robot);
        }

        if (scanCommands.openssl_ccs_injection) {
            tests.ccsInjection = analyzeCCSInjection(scanCommands.openssl_ccs_injection);
        }

        // HSTS
        if (scanCommands.http_headers) {
            tests.hsts = analyzeHSTS(scanCommands.http_headers);
        }

    } catch (error) {
        tests.conversionError = {
            passed: false,
            error: `Failed to convert SSLyze results: ${error.message}`
        };
    }

    return tests;
}

/**
 * Analyze certificate information from SSLyze
 * @param {Object} certInfo - Certificate info from SSLyze
 * @returns {Object} Certificate analysis
 */
function analyzeCertificateInfo(certInfo) {
    const result = {
        passed: false,
        certificates: [],
        chainLength: 0,
        leafCertificate: null
    };

    try {
        if (certInfo.result && certInfo.result.certificate_deployments) {
            const deployment = certInfo.result.certificate_deployments[0];
            if (deployment && deployment.received_certificate_chain) {
                result.certificates = deployment.received_certificate_chain;
                result.chainLength = result.certificates.length;
                result.leafCertificate = result.certificates[0];
                result.passed = true;
            }
        }
    } catch (error) {
        result.error = `Certificate analysis failed: ${error.message}`;
    }

    return result;
}

/**
 * Analyze SSL 2.0 support
 * @param {Object} ssl2Results - SSL 2.0 scan results
 * @returns {Object} SSL 2.0 analysis
 */
function analyzeSSL2Support(ssl2Results) {
    return {
        passed: ssl2Results.result && ssl2Results.result.is_protocol_supported === false,
        supported: ssl2Results.result ? ssl2Results.result.is_protocol_supported : false,
        cipherSuites: ssl2Results.result ? ssl2Results.result.accepted_cipher_suites || [] : []
    };
}

/**
 * Analyze SSL 3.0 support
 * @param {Object} ssl3Results - SSL 3.0 scan results
 * @returns {Object} SSL 3.0 analysis
 */
function analyzeSSL3Support(ssl3Results) {
    return {
        passed: ssl3Results.result && ssl3Results.result.is_protocol_supported === false,
        supported: ssl3Results.result ? ssl3Results.result.is_protocol_supported : false,
        cipherSuites: ssl3Results.result ? ssl3Results.result.accepted_cipher_suites || [] : []
    };
}

/**
 * Analyze TLS version support with detailed cipher suite analysis
 * @param {Object} tlsResults - TLS scan results
 * @param {string} version - TLS version
 * @returns {Object} TLS analysis with detailed cipher suite information
 */
function analyzeTLSSupport(tlsResults, version) {
    const result = {
        version: version,
        supported: false,
        passed: false,
        cipherSuites: [],
        cipherSuiteDetails: [],
        preferredCipher: null,
        securityAnalysis: {
            secureSuites: 0,
            weakSuites: 0,
            insecureSuites: 0,
            forwardSecrecySuites: 0,
            recommendations: []
        }
    };

    try {
        if (tlsResults.result) {
            result.supported = tlsResults.result.is_protocol_supported;
            const rawCipherSuites = tlsResults.result.accepted_cipher_suites || [];
            
            // Process each cipher suite for detailed analysis
            result.cipherSuiteDetails = rawCipherSuites.map(suite => {
                const analysis = analyzeCipherSuite(suite, version);
                
                // Update security counters
                if (analysis.securityLevel === 'secure') result.securityAnalysis.secureSuites++;
                else if (analysis.securityLevel === 'weak') result.securityAnalysis.weakSuites++;
                else if (analysis.securityLevel === 'insecure') result.securityAnalysis.insecureSuites++;
                
                if (analysis.forwardSecrecy) result.securityAnalysis.forwardSecrecySuites++;
                
                return analysis;
            });
            
            // Keep backwards compatibility
            result.cipherSuites = rawCipherSuites;
            
            // Find preferred cipher (first in the list is usually preferred)
            if (result.cipherSuiteDetails.length > 0) {
                result.preferredCipher = result.cipherSuiteDetails[0];
            }
            
            // Generate security recommendations
            result.securityAnalysis.recommendations = generateCipherSuiteRecommendations(result, version);

            // TLS 1.2+ is good, older versions should ideally be disabled
            if (version === '1.2' || version === '1.3') {
                result.passed = result.supported && result.securityAnalysis.secureSuites > 0;
            } else {
                result.passed = !result.supported; // Older TLS should be disabled
            }
        }
    } catch (error) {
        result.error = `TLS ${version} analysis failed: ${error.message}`;
    }

    return result;
}

/**
 * Analyze Heartbleed vulnerability
 * @param {Object} heartbleedResults - Heartbleed scan results
 * @returns {Object} Heartbleed analysis
 */
function analyzeHeartbleed(heartbleedResults) {
    return {
        passed: heartbleedResults.result && heartbleedResults.result.is_vulnerable_to_heartbleed === false,
        vulnerable: heartbleedResults.result ? heartbleedResults.result.is_vulnerable_to_heartbleed : false
    };
}

/**
 * Analyze ROBOT vulnerability
 * @param {Object} robotResults - ROBOT scan results
 * @returns {Object} ROBOT analysis
 */
function analyzeRobot(robotResults) {
    return {
        passed: robotResults.result && robotResults.result.robot_result_enum !== 'VULNERABLE',
        vulnerable: robotResults.result ? robotResults.result.robot_result_enum === 'VULNERABLE' : false,
        result: robotResults.result ? robotResults.result.robot_result_enum : 'UNKNOWN'
    };
}

/**
 * Analyze CCS Injection vulnerability
 * @param {Object} ccsResults - CCS injection scan results
 * @returns {Object} CCS injection analysis
 */
function analyzeCCSInjection(ccsResults) {
    return {
        passed: ccsResults.result && ccsResults.result.is_vulnerable_to_ccs_injection === false,
        vulnerable: ccsResults.result ? ccsResults.result.is_vulnerable_to_ccs_injection : false
    };
}

/**
 * Analyze individual cipher suite for security characteristics
 * @param {Object} cipherSuite - Cipher suite object from SSLyze
 * @param {string} tlsVersion - TLS version context
 * @returns {Object} Detailed cipher suite analysis
 */
function analyzeCipherSuite(cipherSuite, tlsVersion) {
    const name = cipherSuite.cipher_suite?.name || 'Unknown';
    const openSslName = cipherSuite.cipher_suite?.openssl_name || name;
    
    const analysis = {
        name: name,
        openSslName: openSslName,
        keyExchange: extractKeyExchange(name),
        authentication: extractAuthentication(name),
        encryption: extractEncryption(name),
        mac: extractMAC(name),
        keySize: extractKeySize(name),
        forwardSecrecy: hasForwardSecrecy(name, tlsVersion),
        securityLevel: 'unknown',
        vulnerabilities: [],
        recommendations: []
    };
    
    // Determine security level
    analysis.securityLevel = evaluateCipherSuiteSecurity(analysis, tlsVersion);
    
    // Check for known vulnerabilities
    analysis.vulnerabilities = checkCipherSuiteVulnerabilities(analysis);
    
    // Generate specific recommendations
    if (analysis.securityLevel !== 'secure') {
        analysis.recommendations = generateCipherSuiteSpecificRecommendations(analysis, tlsVersion);
    }
    
    return analysis;
}

/**
 * Extract key exchange algorithm from cipher suite name
 * @param {string} cipherName - Cipher suite name
 * @returns {string} Key exchange algorithm
 */
function extractKeyExchange(cipherName) {
    if (cipherName.includes('ECDHE')) return 'ECDHE';
    if (cipherName.includes('DHE')) return 'DHE';
    if (cipherName.includes('ECDH_')) return 'ECDH';
    if (cipherName.includes('DH_')) return 'DH';
    if (cipherName.includes('RSA')) return 'RSA';
    if (cipherName.includes('PSK')) return 'PSK';
    return 'Unknown';
}

/**
 * Extract authentication algorithm from cipher suite name
 * @param {string} cipherName - Cipher suite name
 * @returns {string} Authentication algorithm
 */
function extractAuthentication(cipherName) {
    if (cipherName.includes('_RSA_')) return 'RSA';
    if (cipherName.includes('_ECDSA_')) return 'ECDSA';
    if (cipherName.includes('_DSS_')) return 'DSS';
    if (cipherName.includes('_PSK_')) return 'PSK';
    if (cipherName.includes('_anon_')) return 'Anonymous';
    return 'RSA'; // Default assumption
}

/**
 * Extract encryption algorithm and mode from cipher suite name
 * @param {string} cipherName - Cipher suite name
 * @returns {Object} Encryption details
 */
function extractEncryption(cipherName) {
    // AES variants
    if (cipherName.includes('AES_256_GCM')) return { algorithm: 'AES', keySize: 256, mode: 'GCM' };
    if (cipherName.includes('AES_128_GCM')) return { algorithm: 'AES', keySize: 128, mode: 'GCM' };
    if (cipherName.includes('AES_256_CCM')) return { algorithm: 'AES', keySize: 256, mode: 'CCM' };
    if (cipherName.includes('AES_128_CCM')) return { algorithm: 'AES', keySize: 128, mode: 'CCM' };
    if (cipherName.includes('AES_256_CBC')) return { algorithm: 'AES', keySize: 256, mode: 'CBC' };
    if (cipherName.includes('AES_128_CBC')) return { algorithm: 'AES', keySize: 128, mode: 'CBC' };
    if (cipherName.includes('AES_256')) return { algorithm: 'AES', keySize: 256, mode: 'CBC' };
    if (cipherName.includes('AES_128')) return { algorithm: 'AES', keySize: 128, mode: 'CBC' };
    
    // ChaCha20
    if (cipherName.includes('CHACHA20_POLY1305')) return { algorithm: 'ChaCha20', keySize: 256, mode: 'Poly1305' };
    
    // Legacy algorithms
    if (cipherName.includes('3DES_EDE_CBC')) return { algorithm: '3DES', keySize: 168, mode: 'CBC' };
    if (cipherName.includes('RC4_128')) return { algorithm: 'RC4', keySize: 128, mode: 'Stream' };
    if (cipherName.includes('RC4_40')) return { algorithm: 'RC4', keySize: 40, mode: 'Stream' };
    if (cipherName.includes('DES_CBC')) return { algorithm: 'DES', keySize: 56, mode: 'CBC' };
    if (cipherName.includes('NULL')) return { algorithm: 'NULL', keySize: 0, mode: 'None' };
    
    return { algorithm: 'Unknown', keySize: 0, mode: 'Unknown' };
}

/**
 * Extract MAC algorithm from cipher suite name
 * @param {string} cipherName - Cipher suite name
 * @returns {string} MAC algorithm
 */
function extractMAC(cipherName) {
    if (cipherName.includes('_SHA384')) return 'SHA384';
    if (cipherName.includes('_SHA256')) return 'SHA256';
    if (cipherName.includes('_SHA')) return 'SHA1';
    if (cipherName.includes('_MD5')) return 'MD5';
    if (cipherName.includes('GCM') || cipherName.includes('CCM') || cipherName.includes('POLY1305')) return 'AEAD';
    return 'Unknown';
}

/**
 * Extract effective key size from cipher suite name
 * @param {string} cipherName - Cipher suite name
 * @returns {number} Key size in bits
 */
function extractKeySize(cipherName) {
    const encryption = extractEncryption(cipherName);
    return encryption.keySize;
}

/**
 * Check if cipher suite provides forward secrecy
 * @param {string} cipherName - Cipher suite name
 * @param {string} tlsVersion - TLS version (e.g., '1.3', '1.2')
 * @returns {boolean} True if provides forward secrecy
 */
function hasForwardSecrecy(cipherName, tlsVersion = '1.2') {
    // TLS 1.3 inherently provides forward secrecy for all cipher suites
    if (tlsVersion === '1.3') {
        return true;
    }
    
    // For TLS 1.2 and earlier, check for ephemeral key exchange
    return cipherName.includes('ECDHE') || cipherName.includes('DHE');
}

/**
 * Evaluate overall security level of a cipher suite
 * @param {Object} analysis - Cipher suite analysis
 * @param {string} tlsVersion - TLS version context
 * @returns {string} Security level (secure, weak, insecure)
 */
function evaluateCipherSuiteSecurity(analysis, tlsVersion) {
    // Insecure algorithms
    if (analysis.encryption.algorithm === 'NULL' || 
        analysis.encryption.algorithm === 'RC4' || 
        analysis.encryption.algorithm === 'DES' ||
        analysis.mac === 'MD5' ||
        analysis.authentication === 'Anonymous') {
        return 'insecure';
    }
    
    // TLS 1.3 cipher suites are inherently secure
    if (tlsVersion === '1.3') {
        // All TLS 1.3 cipher suites are considered secure by design
        // They all use AEAD encryption and provide forward secrecy
        if ((analysis.encryption.algorithm === 'AES' && analysis.encryption.keySize >= 128) ||
            analysis.encryption.algorithm === 'ChaCha20') {
            return 'secure';
        }
    }
    
    // For TLS 1.2 and earlier, apply stricter rules
    // Weak configurations
    if (analysis.encryption.keySize < 128 ||
        analysis.encryption.algorithm === '3DES' ||
        analysis.mac === 'SHA1' ||
        !analysis.forwardSecrecy) {
        return 'weak';
    }
    
    // Strong modern ciphers for TLS 1.2 and earlier
    if ((analysis.encryption.algorithm === 'AES' && analysis.encryption.keySize >= 128) ||
        analysis.encryption.algorithm === 'ChaCha20') {
        if (analysis.forwardSecrecy && 
            (analysis.mac === 'AEAD' || analysis.mac === 'SHA256' || analysis.mac === 'SHA384')) {
            return 'secure';
        }
    }
    
    return 'weak';
}

/**
 * Check for known vulnerabilities in cipher suite
 * @param {Object} analysis - Cipher suite analysis
 * @returns {Array} List of vulnerabilities
 */
function checkCipherSuiteVulnerabilities(analysis) {
    const vulnerabilities = [];
    
    if (analysis.encryption.algorithm === 'RC4') {
        vulnerabilities.push('RC4 is vulnerable to bias attacks');
    }
    
    if (analysis.encryption.algorithm === 'DES') {
        vulnerabilities.push('DES has insufficient key length');
    }
    
    if (analysis.encryption.algorithm === '3DES') {
        vulnerabilities.push('3DES is vulnerable to Sweet32 attack');
    }
    
    if (analysis.mac === 'MD5') {
        vulnerabilities.push('MD5 is cryptographically broken');
    }
    
    if (analysis.mac === 'SHA1') {
        vulnerabilities.push('SHA1 is vulnerable to collision attacks');
    }
    
    if (analysis.authentication === 'Anonymous') {
        vulnerabilities.push('Anonymous authentication provides no server authentication');
    }
    
    if (analysis.encryption.mode === 'CBC' && analysis.mac !== 'AEAD') {
        vulnerabilities.push('CBC mode vulnerable to padding oracle attacks');
    }
    
    return vulnerabilities;
}

/**
 * Generate recommendations for specific cipher suite issues
 * @param {Object} analysis - Cipher suite analysis
 * @param {string} tlsVersion - TLS version (e.g., '1.3', '1.2')
 * @returns {Array} List of recommendations
 */
function generateCipherSuiteSpecificRecommendations(analysis, tlsVersion = '1.2') {
    const recommendations = [];
    
    if (analysis.encryption.algorithm === 'RC4' || analysis.encryption.algorithm === 'DES') {
        recommendations.push('Disable this cipher suite immediately');
    }
    
    if (analysis.encryption.algorithm === '3DES') {
        recommendations.push('Replace 3DES with AES-based cipher suites');
    }
    
    // Don't recommend forward secrecy for TLS 1.3 (it's built-in)
    if (!analysis.forwardSecrecy && tlsVersion !== '1.3') {
        recommendations.push('Use ECDHE or DHE key exchange for forward secrecy');
    }
    
    if (analysis.mac === 'SHA1') {
        recommendations.push('Upgrade to SHA256 or AEAD cipher suites');
    }
    
    if (analysis.encryption.keySize < 128) {
        recommendations.push('Use cipher suites with at least 128-bit encryption');
    }
    
    return recommendations;
}

/**
 * Generate overall recommendations for TLS cipher suite configuration
 * @param {Object} tlsAnalysis - Complete TLS analysis result
 * @param {string} version - TLS version
 * @returns {Array} List of recommendations
 */
function generateCipherSuiteRecommendations(tlsAnalysis, version) {
    const recommendations = [];
    const analysis = tlsAnalysis.securityAnalysis;
    
    if (analysis.insecureSuites > 0) {
        recommendations.push({
            priority: 'high',
            issue: `${analysis.insecureSuites} insecure cipher suite(s) detected in TLS ${version}`,
            action: 'Disable all insecure cipher suites immediately'
        });
    }
    
    if (analysis.weakSuites > 0) {
        recommendations.push({
            priority: 'medium',
            issue: `${analysis.weakSuites} weak cipher suite(s) detected in TLS ${version}`,
            action: 'Plan to replace weak cipher suites with modern alternatives'
        });
    }
    
    if (analysis.forwardSecrecySuites === 0 && tlsAnalysis.cipherSuiteDetails.length > 0 && version !== '1.3') {
        recommendations.push({
            priority: 'medium',
            issue: `No forward secrecy support in TLS ${version}`,
            action: 'Enable ECDHE or DHE cipher suites for forward secrecy'
        });
    }
    
    if (analysis.secureSuites === 0 && tlsAnalysis.supported) {
        recommendations.push({
            priority: 'high',
            issue: `No secure cipher suites found in TLS ${version}`,
            action: 'Configure modern AES-GCM or ChaCha20-Poly1305 cipher suites'
        });
    }
    
    // Version-specific recommendations
    if (version === '1.0' || version === '1.1') {
        if (tlsAnalysis.supported) {
            recommendations.push({
                priority: 'high',
                issue: `TLS ${version} is deprecated and should be disabled`,
                action: 'Disable TLS 1.0/1.1 and use only TLS 1.2+'
            });
        }
    }
    
    return recommendations;
}
function analyzeHSTS(httpHeaders) {
    const result = {
        passed: false,
        present: false,
        maxAge: null,
        includeSubdomains: false,
        preload: false
    };

    try {
        if (httpHeaders.result && httpHeaders.result.strict_transport_security_header) {
            const hsts = httpHeaders.result.strict_transport_security_header;
            result.present = true;
            result.maxAge = hsts.max_age;
            result.includeSubdomains = hsts.include_subdomains || false;
            result.preload = hsts.preload || false;
            result.passed = result.maxAge > 0;
        }
    } catch (error) {
        result.error = `HSTS analysis failed: ${error.message}`;
    }

    return result;
}

/**
 * Analyze HSTS from HTTP headers
 * @param {Object} httpHeaders - HTTP headers scan results
 * @returns {Object} HSTS analysis
 */
function analyzeHSTS(httpHeaders) {
    const result = {
        passed: false,
        present: false,
        maxAge: null,
        includeSubdomains: false,
        preload: false
    };

    try {
        if (httpHeaders.result && httpHeaders.result.strict_transport_security_header) {
            const hsts = httpHeaders.result.strict_transport_security_header;
            result.present = true;
            result.maxAge = hsts.max_age;
            result.includeSubdomains = hsts.include_subdomains || false;
            result.preload = hsts.preload || false;
            result.passed = result.maxAge > 0;
        }
    } catch (error) {
        result.error = `HSTS analysis failed: ${error.message}`;
    }

    return result;
}

/**
 * Get cipher suite security summary for all TLS versions
 * @param {Object} sslTests - All SSL test results
 * @returns {Object} Overall cipher suite security summary
 */
/**
 * Deduplicate recommendations based on action text, combining priorities and issues
 * @param {Array} recommendations - Array of recommendation objects
 * @returns {Array} Deduplicated recommendations
 */
function deduplicateRecommendations(recommendations) {
    const uniqueRecommendations = new Map();
    
    recommendations.forEach(rec => {
        const key = rec.action;
        
        if (uniqueRecommendations.has(key)) {
            const existing = uniqueRecommendations.get(key);
            
            // Combine issues if different
            if (existing.issue !== rec.issue) {
                existing.issue = `${existing.issue}; ${rec.issue}`;
            }
            
            // Keep the highest priority
            const priorities = ['high', 'medium', 'low'];
            const existingPriorityIndex = priorities.indexOf(existing.priority);
            const newPriorityIndex = priorities.indexOf(rec.priority);
            
            if (newPriorityIndex < existingPriorityIndex) {
                existing.priority = rec.priority;
            }
        } else {
            uniqueRecommendations.set(key, { ...rec });
        }
    });
    
    return Array.from(uniqueRecommendations.values());
}

/**
 * Get comprehensive cipher suite summary across all TLS versions
 * @param {Object} sslTests - SSL test results from SSLyze
 * @returns {Object} Cipher suite analysis summary
 */
function getCipherSuiteSummary(sslTests) {
    const summary = {
        totalSuites: 0,
        secureSuites: 0,
        weakSuites: 0,
        insecureSuites: 0,
        forwardSecrecySuites: 0,
        modernProtocols: 0,
        legacyProtocols: 0,
        recommendations: [],
        details: {}
    };
    
    // Analyze each TLS version
    ['tls1_0Support', 'tls1_1Support', 'tls1_2Support', 'tls1_3Support'].forEach(tlsTest => {
        if (sslTests[tlsTest] && sslTests[tlsTest].securityAnalysis) {
            const analysis = sslTests[tlsTest].securityAnalysis;
            if (analysis) {
                summary.totalSuites += analysis.secureSuites + analysis.weakSuites + analysis.insecureSuites;
                summary.secureSuites += analysis.secureSuites;
                summary.weakSuites += analysis.weakSuites;
                summary.insecureSuites += analysis.insecureSuites;
                summary.forwardSecrecySuites += analysis.forwardSecrecySuites;
                
                // Count protocol types
                if (tlsTest === 'tls1_2Support' || tlsTest === 'tls1_3Support') {
                    summary.modernProtocols++;
                } else {
                    summary.legacyProtocols++;
                }
                
                // Collect recommendations
                if (analysis.recommendations) {
                    summary.recommendations.push(...analysis.recommendations);
                }
                
                summary.details[tlsTest] = {
                    version: sslTests[tlsTest].version,
                    cipherSuiteCount: sslTests[tlsTest].cipherSuiteDetails?.length || 0,
                    securityBreakdown: analysis
                };
            }
        }
    });
    
    // Deduplicate recommendations by action text
    summary.recommendations = deduplicateRecommendations(summary.recommendations);
    
    // Calculate overall security level
    const securePercentage = summary.totalSuites > 0 ? (summary.secureSuites / summary.totalSuites) * 100 : 0;
    const weakPercentage = summary.totalSuites > 0 ? (summary.weakSuites / summary.totalSuites) * 100 : 0;
    const insecurePercentage = summary.totalSuites > 0 ? (summary.insecureSuites / summary.totalSuites) * 100 : 0;
    
    if (insecurePercentage > 0) {
        summary.overallSecurity = 'Critical';
    } else if (weakPercentage > 50) {
        summary.overallSecurity = 'Weak';
    } else if (securePercentage >= 70) {
        summary.overallSecurity = 'Strong';
    } else if (securePercentage >= 40) {
        summary.overallSecurity = 'Good';
    } else {
        summary.overallSecurity = 'Poor';
    }
    
    // Calculate forward secrecy status
    const forwardSecrecyPercentage = summary.totalSuites > 0 ? (summary.forwardSecrecySuites / summary.totalSuites) * 100 : 0;
    summary.hasForwardSecrecy = forwardSecrecyPercentage >= 50;
    
    return summary;
}

module.exports = {
    checkSSLyzeAvailability,
    runSSLyzeScan,
    convertSSLyzeToTests,
    getCipherSuiteSummary,
    analyzeCipherSuite,
    evaluateCipherSuiteSecurity,
    generateCipherSuiteRecommendations,
    deduplicateRecommendations,

    // Module metadata
    name: 'SSLyze Integration Module',
    description: 'Integration with SSLyze tool for advanced SSL/TLS security analysis with detailed cipher suite analysis'
};
