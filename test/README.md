# Security Headers Checker - Test Suite

## Overview

Comprehensive integration test suite for the Security Headers Checker with robust server health checks and extensive security analysis coverage.

## Test Structure

### Integration Tests

```
test/integration/
├── run-all-tests.js           # 🚀 Main comprehensive test runner with server health checks
├── ssl-certificate.test.js    # 🔒 SSL/TLS certificate analysis tests (4 tests)
├── comprehensive-ssl.test.js  # 🔐 Comprehensive SSL analysis tests (4 tests)  
├── security-headers.test.js   # 📋 Security headers detection tests (4 tests)
├── additional-checks.test.js  # 🔧 Additional security features tests (4 tests)
├── badssl-scenarios.test.js   # 🧪 Certificate error scenarios tests (6 tests)
└── performance.test.js        # ⚡ Performance and reliability tests (4 tests)
```

### Test Runner Scripts

```
test/
├── test-runner.js            # Legacy test runner (SSL, Headers, Additional, Performance)
└── run-all-tests.js         # Enhanced comprehensive test runner with health checks
```

## Available Test Commands

### Primary Test Commands

```bash
# Run all comprehensive integration tests (recommended)
npm run test:all              # 22 tests with server health checks

# Run legacy integration tests  
npm test                      # 20 tests (SSL, Headers, Additional, Performance)
npm run test:integration     # Same as above
```

### Individual Test Categories

```bash
# SSL/TLS Testing
npm run test:ssl              # Basic SSL certificate analysis (4 tests)
npm run test:enhanced-ssl     # Comprehensive SSL analysis (4 tests)

# Security Features Testing  
npm run test:headers          # Security headers detection (4 tests)
npm run test:additional       # Additional security checks (4 tests)
npm run test:badssl          # Certificate error scenarios (6 tests)

# Performance Testing
npm run test:performance      # Performance and reliability (4 tests)
```

## Server Health Check Features

The comprehensive test runner (`npm run test:all`) includes robust pre-flight checks:

### 🔍 Server Health Check
- Verifies server is running on localhost:3000
- Tests basic connectivity and responsiveness
- **Timeout**: 5 seconds

### 🔍 API Health Check  
- Validates `/api/analyze` endpoint functionality
- Tests with sample request to ensure API is working
- **Timeout**: 10 seconds

### ❌ Failure Handling
- Clear error messages when server is not running
- Helpful instructions to start the server
- Graceful exit with appropriate error codes

## Test Coverage

### 🔒 SSL Certificate Analysis (8 total tests)
- **Basic SSL Tests (4)**: Certificate validation, protocol detection, key strength
- **Comprehensive SSL Tests (4)**: 12-point SSL analysis, vulnerability checks, certificate chain analysis

### 📋 Security Headers Analysis (4 tests)
- Detection of 22 critical security headers
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options analysis
- CORS and modern security header validation

### 🔧 Additional Security Checks (4 tests)
- HTTPS redirect validation
- Mixed content detection
- HTTP methods security analysis
- Security.txt file discovery

### 🧪 Certificate Error Scenarios (6 tests)
- Expired certificates handling
- Hostname mismatch validation  
- Untrusted root CA detection
- Revoked certificate awareness
- Certificate pinning guidance
- Client certificate requirements

### ⚡ Performance & Reliability (4 tests)
- Response time analysis
- Error handling validation
- Network timeout management
- Comprehensive reliability metrics

## Usage Examples

### Quick Development Testing
```bash
# Start server and run comprehensive tests
npm start &
sleep 3
npm run test:all
```

### Continuous Integration
```bash
# The test runner will fail gracefully if server isn't running
npm run test:all
# Exit code 1 if server not running or tests fail
# Exit code 0 if all tests pass
```

### Debugging Specific Features
```bash
# Test only SSL analysis
npm run test:ssl
npm run test:enhanced-ssl

# Test only certificate error handling
npm run test:badssl
```

## Server Requirements

**Required**: Security Headers Checker server must be running on `localhost:3000`

```bash
# Start the server
npm start        # Production mode
npm run dev      # Development mode with auto-restart
```

The test suite will automatically detect if the server is not running and provide helpful guidance.

## Output Format

### Successful Health Check
```
🚀 Starting Comprehensive Integration Test Suite...
🔍 Checking server health...
✅ Server is running on localhost:3000
🔍 Checking API endpoint...
✅ API endpoint is responding correctly
🎯 All pre-flight checks passed - starting integration tests...
```

### Failed Health Check
```
🚀 Starting Comprehensive Integration Test Suite...
🔍 Checking server health...
❌ Server is not running on localhost:3000
💡 Please start the server with: npm start or npm run dev
🛑 Integration tests require the server to be running
```

## Test Results Summary

### Comprehensive Results (22 tests total)
```
🏁 COMPREHENSIVE INTEGRATION TEST SUMMARY
============================================================
📊 SSL Certificates: 4/4 passed
📊 Security Headers: 4/4 passed  
📊 Additional Checks: 4/4 passed
📊 Comprehensive SSL: 4/4 passed
📊 BadSSL Scenarios: 6/6 passed
⏱️  Total Execution Time: ~30s
📈 Overall Success Rate: 22/22 (100%)
🎉 ALL TESTS PASSED!
```

## Best Practices

1. **Always run `npm run test:all`** for comprehensive coverage
2. **Ensure server is running** before running integration tests
3. **Check individual test categories** when debugging specific issues
4. **Monitor test execution time** - should complete in under 45 seconds
5. **Use exit codes** for CI/CD pipeline integration

## Troubleshooting

### Server Not Running
```bash
# Start the server first
npm start
# Then run tests in another terminal
npm run test:all
```

### API Endpoint Issues
- Check server logs for errors
- Verify port 3000 is available
- Ensure no firewall blocking localhost:3000

### Slow Test Performance
- Network issues may affect external website testing
- BadSSL scenarios depend on external service availability
- Consider running individual test categories for faster feedback
