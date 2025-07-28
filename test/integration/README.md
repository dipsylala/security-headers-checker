# Integration Tests

This directory contains comprehensive integration tests for the Security Headers Checker, organized by functional area for better maintainability and focused testing.

## Test Structure

The integration tests are split into the following areas:

### 🔒 SSL/TLS Certificate Tests (`ssl-certificate.test.js`)
- **Purpose**: Tests SSL certificate analysis, grading, and signature algorithm detection
- **Coverage**: ECC and RSA certificates, TLS protocols, signature algorithms, SSL grading
- **Key Features**: 
  - Certificate fingerprint validation
  - Signature algorithm detection (ecdsa-with-SHA256, sha256WithRSAEncryption)
  - SSL grade distribution analysis
  - Multi-protocol support (TLSv1.2, TLSv1.3)

### 📋 Security Headers Tests (`security-headers.test.js`)
- **Purpose**: Tests security header detection, categorization, and validation
- **Coverage**: Critical and important security headers, header structure validation
- **Key Features**:
  - HSTS (Strict-Transport-Security) validation
  - Content-Security-Policy detection
  - Header categorization (critical, important, optional)
  - Statistics on header adoption across test sites

### 🔧 Additional Security Checks Tests (`additional-checks.test.js`)
- **Purpose**: Tests HTTP methods, HTTPS redirects, mixed content, security.txt, etc.
- **Coverage**: All non-SSL, non-header security checks
- **Key Features**:
  - **HTTP Methods bug fix validation** - Ensures the "information not available" bug is fixed
  - HTTPS redirect validation
  - Mixed content detection
  - Security.txt file detection
  - Server information gathering

### ⚡ Performance and Reliability Tests (`performance.test.js`)
- **Purpose**: Tests response times, error handling, edge cases, and reliability
- **Coverage**: Performance benchmarks, timeout handling, error scenarios
- **Key Features**:
  - Response time measurement
  - Timeout validation
  - Error handling for invalid domains
  - Reliability statistics

## Running Tests

### Individual Test Suites

```bash
# Run only SSL certificate tests
npm run test:ssl

# Run only security headers tests  
npm run test:headers

# Run only additional security checks (includes HTTP methods bug fix validation)
npm run test:additional

# Run only performance and reliability tests
npm run test:performance
```

### All Tests

```bash
# Run all integration test suites
npm test
# or
npm run test:integration
```

### Legacy Tests

```bash
# Run the original monolithic integration test
npm run test:legacy
```

## Test Runner Usage

The main test runner (`test-runner.js`) supports both command-line and programmatic usage:

```bash
# Show help
node test/integration/test-runner.js --help

# Run all tests
node test/integration/test-runner.js

# Run specific suite
node test/integration/test-runner.js ssl
node test/integration/test-runner.js headers
node test/integration/test-runner.js additional
node test/integration/test-runner.js performance
```

## Test Sites

All test suites use these real-world websites for validation:

- **GitHub** (`https://github.com`) - Excellent security headers, ECC certificates
- **Google** (`https://google.com`) - Minimal headers, ECC certificates  
- **Cloudflare** (`https://cloudflare.com`) - Good security headers, ECC certificates
- **Mozilla Developer Network** (`https://developer.mozilla.org`) - RSA certificates, varied headers

## Key Bug Fix Validation

The **Additional Security Checks** test suite specifically validates the HTTP methods bug fix:

- ✅ **Before**: HTTP methods returned "information not available"
- ✅ **After**: HTTP methods provide meaningful security analysis:
  - GitHub: "Server restricts OPTIONS requests (HTTP 404)" 
  - Google: "OPTIONS method not allowed (good security practice)"
  - Cloudflare: "Server accepts OPTIONS but does not advertise allowed methods"
  - Mozilla: "Server restricts OPTIONS requests (HTTP 404)"

## Benefits of Modular Structure

1. **Focused Testing**: Run only the tests relevant to your changes
2. **Faster Feedback**: Individual suites run much faster than the full test suite
3. **Better Organization**: Each test suite focuses on a specific functional area
4. **Easier Debugging**: Failures are isolated to specific areas
5. **Improved Maintainability**: Each test file is smaller and more focused
6. **Parallel Development**: Different team members can work on different test areas

## Test Output

Each test suite provides detailed output including:

- ✅ Individual test results with pass/fail status
- 📊 Summary statistics and analysis
- 🔍 Detailed validation of specific functionality
- 📈 Performance metrics (where applicable)
- 💡 Recommendations and insights

## Adding New Tests

To add new tests:

1. **For SSL/TLS features**: Add to `ssl-certificate.test.js`
2. **For new security headers**: Add to `security-headers.test.js`  
3. **For additional security checks**: Add to `additional-checks.test.js`
4. **For performance/reliability**: Add to `performance.test.js`
5. **For entirely new areas**: Create a new test file and add it to `test-runner.js`

Each test should include:
- Clear test name and description
- Expected results definition
- Comprehensive validation
- Detailed output for debugging
