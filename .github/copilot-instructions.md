<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Security Headers Checker

## Project Overview

This is a comprehensive web security analysis tool that evaluates websites for:
- **SSL/TLS Certificate Analysis** (12-test comprehensive suite, 175 points max)
- **Security Headers Detection** (22 critical headers including CSP, HSTS, CORS)
- **Additional Security Checks** (HTTPS redirect, mixed content, HTTP methods, security.txt)
- **Certificate Error Scenarios** (expired, hostname mismatch, untrusted roots, revocation)

## Architecture & Tech Stack

- **Backend**: Express.js server with modular design
- **Frontend**: Vanilla JavaScript with responsive Bootstrap design
- **SSL Analysis**: Node.js TLS/crypto modules with legitimate HPKP header detection
- **Testing**: Comprehensive integration test suite (18 tests, 100% coverage)
- **API**: RESTful endpoints with detailed security analysis responses

## Development Guidelines

### Code Style & Patterns
- **Modular Design**: Each analysis type has its own module in `/lib/`
- **Async/Await**: Use modern async patterns for all network operations
- **Error Handling**: Comprehensive try/catch with detailed error messages
- **Logging**: Include timestamp and analysis duration for debugging
- **Comments**: JSDoc format for all functions with parameter types

### Testing Standards
- **Integration Focus**: Test real websites and certificate scenarios
- **BadSSL Integration**: Use badssl.com for certificate error validation
- **100% Coverage**: All analysis modules must have comprehensive tests
- **Performance**: Track and optimize analysis speed (target <3s per URL)

### API Design
- **RESTful Endpoints**: `/api/analyze` for main analysis
- **Detailed Responses**: Include both summary and detailed breakdowns
- **Error Handling**: Meaningful HTTP status codes and error messages
- **Documentation**: Swagger/OpenAPI documentation available

## File Organization Rules

### Test Files
- **Integration tests**: Place in `./test/integration/`
- **Temporary tests**: Place in `./temp_tests/` (for ad-hoc verification)

### New Features
- **Analysis modules**: Add to `./lib/` with comprehensive JSDoc
- **Test coverage**: Every new module needs integration tests
- **Documentation**: Update README.md and API docs
- **Performance**: Benchmark new analysis features

### Configuration Files
- **ESLint**: Use provided eslint.config.mjs for code quality
- **Package scripts**: Leverage npm scripts for common tasks
- **Environment**: Support both development and production modes

## Common Commands

```bash
# Development
npm run dev          # Start with nodemon
npm start           # Production server
npm run build       # Build optimized version

# Testing (18 comprehensive tests)
npm test            # Run full integration suite
npm run test:ssl    # SSL certificate analysis tests
npm run test:headers # Security headers tests
npm run test:additional # Additional security checks
node test/integration/badssl-scenarios.test.js # Certificate errors

# Code Quality
npm run lint        # Check code style
npm run lint:fix    # Auto-fix style issues
```

## Security Analysis Guidelines

### SSL Certificate Analysis (12 Tests, 175 Points)
1. **Certificate Validity** - Basic certificate validation
2. **Certificate Trust** - Chain of trust verification
3. **Hostname Verification** - Subject Alternative Name validation
4. **Certificate Expiration** - Validity period analysis
5. **Key Strength Analysis** - RSA/ECDSA key size evaluation
6. **Signature Algorithm** - Cryptographic algorithm assessment
7. **Certificate Chain Analysis** - Complete chain validation
8. **Certificate Revocation Status** - OCSP/CRL checking awareness
9. **Certificate Pinning Analysis** - HPKP header detection
10. **Perfect Forward Secrecy** - Ephemeral key exchange support
11. **Protocol Version Analysis** - TLS version support
12. **Cipher Suite Analysis** - Encryption algorithm evaluation

### Security Headers (22 Headers)
- **Critical**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Important**: Referrer-Policy, Permissions-Policy, CORS headers
- **Additional**: X-XSS-Protection, security-focused cache headers
- **Information**: Server disclosure, version headers

### Additional Security Checks (5 Features)
- **HTTPS Redirect**: HTTP to HTTPS redirection validation
- **Mixed Content**: Detection of insecure resource loading
- **HTTP Methods**: Security analysis of allowed HTTP methods
- **Security.txt**: Security contact information availability
- **Server Information**: Security-relevant server disclosure

## AI Assistant Guidelines

When working on this project:

1. **Always run tests** after making changes to analysis modules
2. **Use real websites** for testing, not mock data
3. **Follow modular architecture** - keep analysis types separate
4. **Include performance considerations** - analysis should be fast
5. **Provide detailed error handling** - security tools need robust error reporting
6. **Document security implications** - explain why checks matter
7. **Use legitimate testing methods** - no pattern matching for security features
8. **Maintain test coverage** - every feature needs integration tests

## Performance Targets

- **Analysis Speed**: <3 seconds per URL analysis
- **Test Suite**: <30 seconds for full integration suite (18 tests)
- **Memory Usage**: Efficient handling of multiple concurrent analyses
- **Error Rate**: Robust handling of network timeouts and certificate errors