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
        const timeoutMs = options.timeout || 30000; // Reduce default timeout to 30 seconds
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
 * Analyze TLS version support
 * @param {Object} tlsResults - TLS scan results
 * @param {string} version - TLS version
 * @returns {Object} TLS analysis
 */
function analyzeTLSSupport(tlsResults, version) {
    const result = {
        version: version,
        supported: false,
        passed: false,
        cipherSuites: [],
        preferredCipher: null
    };

    try {
        if (tlsResults.result) {
            result.supported = tlsResults.result.is_protocol_supported;
            result.cipherSuites = tlsResults.result.accepted_cipher_suites || [];

            // TLS 1.2+ is good, older versions should ideally be disabled
            if (version === '1.2' || version === '1.3') {
                result.passed = result.supported;
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

module.exports = {
    checkSSLyzeAvailability,
    runSSLyzeScan,
    convertSSLyzeToTests,

    // Module metadata
    name: 'SSLyze Integration Module',
    description: 'Integration with SSLyze tool for advanced SSL/TLS security analysis'
};
