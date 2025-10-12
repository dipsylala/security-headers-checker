# WebCheck Validator - Technical Specification

**Version:** 1.0.0  
**Last Updated:** October 9, 2025  
**Project Type:** Web Security Analysis Tool  
**Tech Stack:** Node.js, Express.js, Vanilla JavaScript, Bootstrap 5

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Design Principles](#architecture--design-principles)
3. [Directory Structure](#directory-structure)
4. [Core Modules](#core-modules)
5. [API Specification](#api-specification)
6. [Scoring System](#scoring-system)
7. [Security Analysis Components](#security-analysis-components)
8. [Testing Strategy](#testing-strategy)
9. [Development Workflow](#development-workflow)
10. [Coding Standards](#coding-standards)
11. [Performance Requirements](#performance-requirements)
12. [Deployment](#deployment)

---

## Project Overview

### Purpose
WebCheck Validator is a comprehensive web security analysis tool that evaluates websites across three critical dimensions:
- **SSL/TLS Certificate Analysis** (12 comprehensive tests, 175 points maximum)
- **Security Headers Detection** (22+ headers across 7 categories)
- **Additional Security Checks** (5 tests covering HTTPS redirect, mixed content, HTTP methods, security.txt, server info)

### Key Features
- Real-time security analysis via web interface
- Detailed scoring system with letter grades (A+ to F)
- PDF report generation for audit compliance
- Modular architecture for easy extension
- Comprehensive error handling for certificate scenarios
- Performance-optimized with fast mode option

### Target Users
- Security professionals and penetration testers
- DevOps engineers implementing security best practices
- Compliance auditors requiring security assessments
- Developers learning web security fundamentals

---

## Architecture & Design Principles

### 1. Modular Design Pattern
Each analysis type is isolated in its own module with clear interfaces:

```
lib/
├── ssl-analyzer/          # SSL/TLS certificate analysis
├── security-headers/      # Security headers detection
├── web-security/          # Additional security checks
├── scoring-system.js      # Overall score calculation
├── url-utils.js           # URL validation & assessment
├── reachability-checker.js # Network connectivity
└── logger.js              # Centralized logging
```

**Principle:** Each module is self-contained with a single responsibility, making testing and maintenance easier.

### 2. Separation of Concerns

#### Backend (Node.js/Express)
- **Purpose:** API endpoints, security analysis, data processing
- **Location:** `server.js`, `lib/` directory
- **Responsibilities:**
  - HTTP server management
  - SSL/TLS analysis orchestration
  - Header fetching and analysis
  - Score calculation
  - PDF report generation

#### Frontend (Vanilla JavaScript)
- **Purpose:** User interface, API consumption, results display
- **Location:** `js/app.js`, `index.html`, `css/style.css`
- **Responsibilities:**
  - Form handling and validation
  - API communication
  - Results rendering
  - Progress indication
  - PDF download management

### 3. Async/Await Pattern
All network operations use modern async/await syntax:

```javascript
async function performSSLAnalysis(url, options = {}) {
    const results = {
        basic: null,
        detailed: null,
        sslyze: null
    };
    
    results.basic = await sslAnalyzer.checkSSLCertificate(url);
    results.detailed = await sslAnalyzer.analyzeSSLCertificateDetailed(hostname, port);
    
    return results;
}
```

**Principle:** Predictable, readable asynchronous code with proper error handling.

### 4. Fail-Safe Design
Every analysis component handles errors gracefully:

```javascript
try {
    // Attempt analysis
    result = await performAnalysis();
} catch (error) {
    // Return partial results with error details
    return {
        success: false,
        error: error.message,
        partialResults: {...}
    };
}
```

**Principle:** Partial results are better than complete failure. Always return actionable information.

### 5. Performance Optimization
Two-tier analysis modes:

- **Fast Mode** (`?fast=true`): Basic SSL checks + headers (2-3 seconds)
- **Comprehensive Mode** (default): Full analysis including SSLyze integration (5-15 seconds)

**Principle:** Users choose between speed and depth based on their needs.

---

## Directory Structure

### Root Level Files
```
├── index.html              # Main web interface
├── server.js               # Express.js application entry point
├── package.json            # NPM dependencies and scripts
├── eslint.config.mjs       # Code quality configuration
├── README.md               # User documentation
├── SPECIFICATION.md        # This file - technical specification
└── .github/
    └── copilot-instructions.md  # AI assistant guidelines
```

### Library Structure (`lib/`)
```
lib/
├── logger.js                    # Winston-based centralized logging
├── url-utils.js                 # URL validation and security assessment
├── reachability-checker.js      # Network connectivity testing
├── scoring-system.js            # Overall score calculation and grading
├── pdf-generator.js             # PDF report generation (Puppeteer)
│
├── ssl-analyzer/                # SSL/TLS Certificate Analysis Module
│   ├── index.js                 # Module orchestrator and main interface
│   ├── ssl-analyzer.js          # Core SSL certificate checks
│   ├── certificate-parser.js    # X.509 certificate parsing
│   ├── grading.js               # SSL-specific scoring logic
│   ├── sslyze-integration.js    # Optional SSLyze tool integration
│   └── utils.js                 # SSL utility functions
│
├── security-headers/            # Security Headers Analysis Module
│   ├── index.js                 # Module orchestrator
│   ├── critical-headers.js      # HSTS, CSP, X-Frame-Options, etc.
│   ├── important-headers.js     # Referrer-Policy, Permissions-Policy
│   ├── modern-headers.js        # Cross-Origin-*, NEL, Reporting-API
│   ├── legacy-headers.js        # X-XSS-Protection, X-Content-Type-Options
│   ├── additional-headers.js    # Cache-Control, Pragma, Expires
│   ├── deprecated-headers.js    # Public-Key-Pins (HPKP)
│   ├── information-headers.js   # Server, X-Powered-By disclosure
│   └── scoring-utils.js         # Header-specific scoring logic
│
└── web-security/                # Additional Security Checks Module
    ├── index.js                 # Module orchestrator
    ├── https-redirect.js        # HTTP to HTTPS redirection check
    ├── mixed-content.js         # Insecure resource detection
    ├── http-methods.js          # Dangerous HTTP methods check
    ├── security-txt.js          # RFC 9116 security.txt validation
    └── server-info.js           # Server header analysis
```

### Frontend Assets
```
├── css/
│   └── style.css               # Bootstrap-based responsive styling
└── js/
    └── app.js                  # Frontend application logic
```

### Testing Infrastructure
```
test/
├── test-runner.js              # Main test orchestrator
├── integration.test.js         # Legacy integration tests
├── README.md                   # Testing documentation
├── integration/                # Backend/API integration tests
│   ├── run-all-tests.js        # Execute all integration tests
│   ├── ssl-certificate.test.js # SSL certificate validation tests
│   ├── comprehensive-ssl.test.js # Extended SSL analysis tests
│   ├── enhanced-ssl.test.js    # Advanced SSL features
│   ├── sslyze-analysis.test.js # SSLyze integration tests
│   ├── badssl-scenarios.test.js # Certificate error scenarios
│   ├── security-headers-analysis.test.js # Headers detection tests
│   ├── web-security.test.js    # Additional checks tests
│   └── performance.test.js     # Performance benchmarking
└── ui/                         # Frontend UI tests (NEW)
    ├── basic-ui.test.js        # Puppeteer-based UI tests
    └── artifacts/              # Screenshot artifacts (auto-generated)
```

### Build & Deployment
```
├── scripts/
│   └── build.js                # Production build script
├── build/                      # Generated production build
│   ├── DEPLOYMENT.md           # Deployment instructions
│   ├── start.bat               # Windows startup script
│   ├── start.sh                # Unix startup script
│   └── [mirrored structure]    # Production-ready files
└── veracode_packaging/         # Security scanning artifacts
```

---

## Core Modules

### 1. SSL Analyzer Module (`lib/ssl-analyzer/`)

**Purpose:** Comprehensive SSL/TLS certificate analysis and vulnerability assessment

**Main Interface:** `index.js`
```javascript
async function performSSLAnalysis(url, options = {})
```

**Key Components:**

#### `ssl-analyzer.js` - Core Certificate Checks
- `checkSSLCertificate(url)` - Basic certificate validation
- `analyzeSSLCertificateDetailed(hostname, port, options)` - 12-test comprehensive analysis

**12 SSL Tests:**
1. Certificate Validity - Basic validation
2. Certificate Trust - Chain verification
3. Hostname Verification - SAN matching
4. Certificate Expiration - Validity period
5. Key Strength - RSA/ECDSA key size (minimum 2048-bit)
6. Signature Algorithm - Cryptographic strength
7. Certificate Chain - Complete chain validation
8. Revocation Status - OCSP/CRL awareness
9. Certificate Pinning - HPKP header detection
10. Perfect Forward Secrecy - Ephemeral key exchange
11. Protocol Version - TLS 1.2/1.3 support
12. Cipher Suite - Encryption algorithm evaluation

#### `certificate-parser.js` - X.509 Parsing
- Subject/Issuer extraction
- SAN (Subject Alternative Names) parsing
- Validity date parsing
- Public key information extraction

#### `grading.js` - SSL Scoring
- Converts 12 tests into 0-175 point score
- Maps scores to letter grades (A+ to F)
- Provides detailed recommendations

#### `sslyze-integration.js` - Optional Deep Analysis
- Detects SSLyze CLI tool availability
- Runs vulnerability scans (Heartbleed, ROBOT, etc.)
- Converts SSLyze JSON output to test results
- Gracefully degrades if SSLyze unavailable

**Design Patterns:**
- **Factory Pattern:** Different analyzers based on options
- **Strategy Pattern:** Fast vs. comprehensive analysis modes
- **Fail-Safe:** Returns partial results on errors

---

### 2. Security Headers Module (`lib/security-headers/`)

**Purpose:** Detect and analyze HTTP security headers across 7 categories

**Main Interface:** `index.js`
```javascript
async function checkSecurityHeaders(url, options = {})
function analyzeHeaders(responseHeaders)
function getAllHeaders()
```

**Architecture:**
```
index.js (Orchestrator)
    ↓
[Header Modules] → performCheck(headers) → Array of HeaderResult
    ↓
Scoring Logic → Category scores → Overall headers score
```

**Header Categories:**

1. **Critical Headers** (`critical-headers.js`) - 40 points max
   - Strict-Transport-Security (HSTS)
   - Content-Security-Policy (CSP)
   - X-Frame-Options
   - X-Content-Type-Options

2. **Important Headers** (`important-headers.js`) - 25 points max
   - Referrer-Policy
   - Permissions-Policy
   - CORS headers (Access-Control-*)

3. **Modern Headers** (`modern-headers.js`) - 15 points max
   - Cross-Origin-Embedder-Policy
   - Cross-Origin-Opener-Policy
   - Cross-Origin-Resource-Policy
   - NEL (Network Error Logging)

4. **Legacy Headers** (`legacy-headers.js`) - 10 points max
   - X-XSS-Protection
   - X-Download-Options
   - X-Permitted-Cross-Domain-Policies

5. **Additional Headers** (`additional-headers.js`) - 5 points max
   - Cache-Control
   - Pragma
   - Expires

6. **Deprecated Headers** (`deprecated-headers.js`) - Informational
   - Public-Key-Pins (HPKP) - deprecated

7. **Information Headers** (`information-headers.js`) - Informational
   - Server
   - X-Powered-By
   - X-AspNet-Version

**Header Result Object:**
```javascript
{
    name: "Strict-Transport-Security",
    present: true,
    value: "max-age=31536000; includeSubDomains",
    score: 10,
    maxScore: 10,
    category: "Critical",
    description: "Enforces HTTPS connections",
    recommendation: "Already configured correctly",
    issues: [],
    compliant: true
}
```

**Design Patterns:**
- **Module Pattern:** Each category is self-contained
- **Strategy Pattern:** Different scoring per category
- **Composite Pattern:** Aggregates results from all modules

---

### 3. Web Security Module (`lib/web-security/`)

**Purpose:** Additional security protocol checks beyond SSL and headers

**Main Interface:** `index.js`
```javascript
async function performAdditionalSecurityChecks(url, options = {})
```

**5 Security Checks:**

#### `https-redirect.js` - HTTPS Enforcement
```javascript
async function checkHTTPSRedirect(url)
```
- Tests if HTTP redirects to HTTPS
- Validates redirect chain
- Detects redirect loops
- **Score:** 2 points if proper redirect exists

#### `mixed-content.js` - Resource Security
```javascript
async function checkMixedContent(url)
```
- Uses Puppeteer to load page
- Detects insecure resources (HTTP on HTTPS pages)
- Lists all insecure URLs found
- **Score:** 2 points if no mixed content

#### `http-methods.js` - Method Security
```javascript
async function checkHTTPMethods(url)
```
- OPTIONS request to enumerate methods
- Flags dangerous methods: TRACE, PUT, DELETE
- Recommends disabling unused methods
- **Score:** 2 points if only safe methods

#### `security-txt.js` - RFC 9116 Compliance
```javascript
async function checkSecurityTxt(url)
```
- Checks `/.well-known/security.txt`
- Validates required fields (Contact, Expires)
- Parses security contact information
- **Score:** 2 points if valid security.txt exists

#### `server-info.js` - Information Disclosure
```javascript
async function checkServerInfo(url)
```
- Analyzes Server header
- Detects technology stack disclosure
- Recommends header removal/obfuscation
- **Score:** 2 points if server header absent or generic

**Total Possible Score:** 10 points

---

### 4. Scoring System (`lib/scoring-system.js`)

**Purpose:** Calculate overall security grade from component scores

**Scoring Weights:**
```javascript
const SCORING_WEIGHTS = {
    ssl: 0.30,           // 30% - SSL/TLS security
    headers: 0.40,       // 40% - Security headers
    additional: 0.20,    // 20% - Web security checks
    accessibility: 0.10  // 10% - Basic connectivity
};
```

**Grade Thresholds:**
```javascript
const GRADE_THRESHOLDS = {
    'A+': 95,  // Excellent security posture
    'A':  85,  // Strong security
    'B':  75,  // Good security
    'C':  65,  // Fair security
    'D':  55,  // Poor security
    'F':  0    // Critical security issues
};
```

**Scoring Formula:**
```
Overall Score = (SSL_Score × 0.30) + (Headers_Score × 0.40) + 
                (Additional_Score × 0.20) + (Accessibility_Score × 0.10)

Where:
- SSL_Score: 0-175 points normalized to 0-100%
- Headers_Score: 0-95 points normalized to 0-100%
- Additional_Score: 0-10 points normalized to 0-100%
- Accessibility_Score: 0-10 points (reachability)
```

**Key Functions:**
```javascript
function calculateOverallScore(scores)
function assignGrade(score)
function getRiskLevel(grade)
function generateSecurityAssessment(analysisResults)
```

---

### 5. URL Utilities (`lib/url-utils.js`)

**Purpose:** URL validation and security assessment

**Key Functions:**
```javascript
function validateUrl(url)           // URL syntax validation
function normalizeUrl(url)          // Standardize URL format
function getUrlSecurityAssessment(url) // Security-specific validation
```

**Security Validations:**
- Protocol restriction (HTTP/HTTPS only)
- Hostname validation (no localhost/private IPs)
- Port restrictions (standard ports only)
- Path sanitization (prevent path traversal)

---

### 6. Reachability Checker (`lib/reachability-checker.js`)

**Purpose:** Network connectivity testing with retry logic

**Key Functions:**
```javascript
async function checkReachability(url, timeout = 10000)
async function checkReachabilityWithRetry(url, maxRetries = 3)
function getReachabilitySuggestions(error)
```

**Features:**
- Exponential backoff retry logic
- DNS resolution checking
- Firewall detection
- Certificate error classification
- Actionable suggestions based on error type

---

### 7. Logger (`lib/logger.js`)

**Purpose:** Centralized logging with Winston

**Configuration:**
```javascript
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'app.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});
```

**Log Levels:**
- `error` - Critical failures
- `warn` - Potential issues
- `info` - Normal operations (default)
- `debug` - Detailed debugging

---

## API Specification

### Base URL
```
http://localhost:4000
```

### Endpoints

#### 1. Health Check
```http
GET /api/health
```

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2025-10-09T12:00:00.000Z",
    "version": "1.0.0",
    "modules": {
        "url-utils": "loaded",
        "ssl-analyzer": "loaded",
        "security-headers": "loaded",
        "web-security": "loaded",
        "scoring-system": "loaded",
        "reachability-checker": "loaded"
    }
}
```

#### 2. Analyze Website (Main Endpoint)
```http
POST /api/analyze
Content-Type: application/json
```

**Request Body:**
```json
{
    "url": "https://example.com",
    "fast": false
}
```

**Query Parameters:**
- `fast` (boolean, optional): Enable fast mode (skip SSLyze, reduce timeouts)

**Response Structure:**
```json
{
    "success": true,
    "url": "https://example.com",
    "timestamp": "2025-10-09T12:00:00.000Z",
    "duration": 8745,
    "analysis": {
        "ssl": {
            "score": 165,
            "maxScore": 175,
            "grade": "A",
            "tests": [...],
            "summary": {...}
        },
        "headers": {
            "score": 85,
            "maxScore": 95,
            "grade": "A",
            "headers": [...],
            "categories": {...}
        },
        "additional": {
            "score": 8,
            "maxScore": 10,
            "checks": [...]
        }
    },
    "overall": {
        "score": 91.2,
        "grade": "A+",
        "riskLevel": "Very Low",
        "recommendations": [...]
    }
}
```

**Error Response:**
```json
{
    "success": false,
    "error": "Invalid URL format",
    "details": "URL must start with http:// or https://",
    "code": "INVALID_URL"
}
```

#### 3. Generate PDF Report
```http
POST /api/generate-pdf
Content-Type: application/json
```

**Request Body:**
```json
{
    "url": "https://example.com",
    "analysisData": { /* full analysis results */ },
    "options": {
        "includeDetails": true,
        "format": "A4"
    }
}
```

**Response:**
```json
{
    "success": true,
    "pdf": "base64-encoded-pdf-data",
    "size": 245678,
    "pages": 5
}
```

#### 4. Get Available Headers
```http
GET /api/headers
```

**Response:**
```json
{
    "count": 22,
    "categories": [
        "Critical",
        "Important",
        "Modern",
        "Legacy",
        "Additional",
        "Deprecated",
        "Information"
    ],
    "headers": [
        {
            "name": "Strict-Transport-Security",
            "category": "Critical",
            "description": "Enforces HTTPS connections",
            "maxScore": 10,
            "example": "max-age=31536000; includeSubDomains"
        },
        // ... more headers
    ]
}
```

---

## Scoring System

### Component Scoring Breakdown

#### SSL/TLS Score (0-175 points)
```
Certificate Validity:        15 points
Certificate Trust:           15 points
Hostname Verification:       15 points
Certificate Expiration:      15 points
Key Strength:               15 points
Signature Algorithm:        15 points
Certificate Chain:          15 points
Revocation Status:          15 points
Certificate Pinning:        10 points
Perfect Forward Secrecy:    15 points
Protocol Version:           15 points
Cipher Suite:               20 points
                          ────────────
Total:                     175 points
```

**Normalization:** `SSL_Percentage = (score / 175) × 100`

#### Security Headers Score (0-95 points)
```
Critical Headers:    40 points (HSTS, CSP, X-Frame-Options, etc.)
Important Headers:   25 points (Referrer-Policy, Permissions-Policy)
Modern Headers:      15 points (Cross-Origin-*, NEL)
Legacy Headers:      10 points (X-XSS-Protection)
Additional Headers:   5 points (Cache-Control)
                    ──────────
Total:               95 points
```

**Normalization:** `Headers_Percentage = (score / 95) × 100`

#### Additional Security Score (0-10 points)
```
HTTPS Redirect:      2 points
Mixed Content:       2 points
HTTP Methods:        2 points
Security.txt:        2 points
Server Info:         2 points
                    ──────────
Total:              10 points
```

**Normalization:** `Additional_Percentage = (score / 10) × 100`

#### Accessibility Score (0-10 points)
```
Website Reachable:  10 points
Website Unreachable: 0 points
```

### Overall Score Calculation
```javascript
Overall_Score = (
    (SSL_Percentage × 0.30) +
    (Headers_Percentage × 0.40) +
    (Additional_Percentage × 0.20) +
    (Accessibility_Percentage × 0.10)
)
```

### Grade Assignment
```
Score ≥ 95  →  A+  (Excellent - Comprehensive security)
Score ≥ 85  →  A   (Strong - Well-configured security)
Score ≥ 75  →  B   (Good - Most security measures present)
Score ≥ 65  →  C   (Fair - Basic security, needs improvement)
Score ≥ 55  →  D   (Poor - Significant security gaps)
Score < 55  →  F   (Critical - Major security issues)
```

---

## Security Analysis Components

### SSL Certificate Error Scenarios

The application handles various certificate error scenarios using **BadSSL.com** for testing:

1. **Expired Certificate** (`expired.badssl.com`)
2. **Wrong Hostname** (`wrong.host.badssl.com`)
3. **Self-Signed Certificate** (`self-signed.badssl.com`)
4. **Untrusted Root** (`untrusted-root.badssl.com`)
5. **Revoked Certificate** (`revoked.badssl.com`)

**Error Handling Pattern:**
```javascript
try {
    const cert = await getTLSCertificate(hostname, port);
    // Analyze certificate
} catch (error) {
    if (error.code === 'CERT_HAS_EXPIRED') {
        return {
            test: 'Certificate Expiration',
            passed: false,
            score: 0,
            details: 'Certificate has expired',
            recommendation: 'Renew certificate immediately'
        };
    }
    // Handle other error codes
}
```

### Header Detection Logic

**Detection Pattern:**
```javascript
function performCheck(headers) {
    const results = [];
    
    // Case-insensitive header lookup
    const headerValue = Object.keys(headers).find(
        key => key.toLowerCase() === 'strict-transport-security'
    );
    
    if (headerValue) {
        // Parse and validate header value
        const analysis = analyzeHSTSValue(headers[headerValue]);
        results.push({
            name: 'Strict-Transport-Security',
            present: true,
            value: headers[headerValue],
            score: analysis.score,
            issues: analysis.issues
        });
    } else {
        // Header missing
        results.push({
            name: 'Strict-Transport-Security',
            present: false,
            score: 0,
            recommendation: 'Add HSTS header'
        });
    }
    
    return results;
}
```

---

## Testing Strategy

### Test Suite Overview

**Total Tests:** 18 integration tests  
**Target Coverage:** 100% of analysis modules  
**Test Duration:** <30 seconds for full suite

### Test Categories

#### 1. SSL Certificate Tests
```bash
npm run test:ssl            # Basic SSL validation
npm run test:enhanced-ssl   # Comprehensive 12-test suite
npm run test:badssl         # Certificate error scenarios
npm run test:sslyze         # SSLyze integration
```

**Test Sites:**
- `https://www.google.com` - Valid certificate
- `https://expired.badssl.com` - Expired certificate
- `https://self-signed.badssl.com` - Self-signed certificate
- `https://wrong.host.badssl.com` - Hostname mismatch

#### 2. Security Headers Tests
```bash
npm run test:headers
```

**Test Sites:**
- `https://securityheaders.com` - Comprehensive headers
- `https://www.mozilla.org` - Modern security headers
- `http://example.com` - Minimal headers

#### 3. Web Security Tests
```bash
npm run test:web-security
```

**Tests:**
- HTTPS redirect validation
- Mixed content detection
- HTTP methods enumeration
- Security.txt validation
- Server header analysis

#### 4. Performance Tests
```bash
npm run test:performance
```

**Benchmarks:**
- Analysis speed: <3 seconds per URL (fast mode)
- Analysis speed: <15 seconds (comprehensive mode)
- Memory usage: <100MB per analysis

#### 5. UI Tests (NEW)
```bash
npm run test:ui
```

**What It Tests:**
- Server availability and health checks
- Application page loading and rendering
- UI element presence validation (form, input field, submit button)
- Complete user workflow: Enter URL → Click Analyze → View Results
- Results content verification (grade, SSL analysis, headers, etc.)

**Screenshot Artifacts:**
- **Location:** `test/ui/artifacts/`
- **Auto-captured** at each test stage:
  1. `01_initial_load` - Homepage loaded
  2. `02_ui_elements` - Form elements verified
  3. `03_url_entered` - URL input captured
  4. `04_analysis_started` - Loading state
  5. `05_analysis_complete` - Results displayed
  6. `06_final_results` - Complete analysis view
  7. `error_screenshot` - Any failure states
- **Format:** Full-page PNG screenshots
- **Naming:** Timestamped (e.g., `01_initial_load_2025-10-09T12-30-45-123Z.png`)
- **Cleanup:** Automatically keeps only last 10 test runs

**Test Configuration:**
- **Default Target:** `https://veracode.com`
- **Browser:** Headless Chromium (Puppeteer v24.20.0)
- **Viewport:** 1920x1080 (desktop resolution)
- **Timeout:** 60 seconds for analysis completion
- **Prerequisites:** Server must be running (`npm start` or `npm run dev`)

**Test Stages:**
1. **Server Health Check** - Verify server running on localhost:4000
2. **Page Load** - Navigate to application homepage
3. **Element Verification** - Validate form, input, button presence
4. **User Interaction** - Enter URL and click analyze button
5. **Results Verification** - Check for grade, SSL data, headers, summary

**Use Cases:**
- **Regression Testing** - Ensure UI changes don't break functionality
- **Visual Verification** - Manual review of screenshots for layout issues
- **CI/CD Integration** - Automated frontend testing in deployment pipelines
- **Bug Reporting** - Screenshots provide visual evidence of issues

### Test Structure

**Standard Test Pattern:**
```javascript
async function runTest(testName, testFn) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Test: ${testName}`);
    console.log('='.repeat(60));
    
    const startTime = Date.now();
    
    try {
        await testFn();
        const duration = Date.now() - startTime;
        console.log(`✅ PASSED (${duration}ms)`);
        return { passed: true, duration };
    } catch (error) {
        const duration = Date.now() - startTime;
        console.error(`❌ FAILED (${duration}ms)`);
        console.error(`Error: ${error.message}`);
        return { passed: false, duration, error };
    }
}
```

### Running All Tests
```bash
npm test                    # Core integration tests
npm run test:all           # Complete test suite (18 tests)
```

---

## Development Workflow

### Initial Setup
```bash
# Clone repository
git clone https://github.com/dipsylala/security-headers-checker.git
cd security-headers-checker

# Install dependencies
npm install

# Run in development mode (auto-reload)
npm run dev

# Access application
http://localhost:4000
```

### VS Code Tasks
```json
{
    "Start WebCheck Validator": "npm start",
    "Start Development Server": "npm run dev",
    "Install Dependencies": "npm install",
    "Build Production": "npm run build",
    "Stop Server": "taskkill /F /IM node.exe"
}
```

**Usage:** `Ctrl+Shift+P` → "Tasks: Run Task" → Select task

### Build Process
```bash
# Create production build
npm run build

# Output: ./build/ directory with:
# - Minified/optimized code
# - Production dependencies only
# - Deployment scripts (start.bat, start.sh)
# - DEPLOYMENT.md instructions
```

### Code Quality
```bash
# Check code style
npm run lint

# Auto-fix issues
npm run lint:fix

# Enforce zero warnings
npm run lint:check
```

---

## Coding Standards

### 1. File Organization
```
Each module must have:
- JSDoc comments for all functions
- Clear separation of concerns
- Single responsibility principle
- Exported public interface at bottom
```

### 2. Function Documentation
```javascript
/**
 * Perform comprehensive SSL certificate analysis
 * 
 * @param {string} url - The URL to analyze (must be HTTPS)
 * @param {Object} options - Analysis options
 * @param {boolean} options.fast - Enable fast mode (skip SSLyze)
 * @param {number} options.timeout - Connection timeout in milliseconds
 * @returns {Promise<Object>} SSL analysis results with score and tests
 * @throws {Error} If URL is invalid or unreachable
 * 
 * @example
 * const results = await performSSLAnalysis('https://example.com', { fast: true });
 * console.log(`SSL Score: ${results.score}/${results.maxScore}`);
 */
async function performSSLAnalysis(url, options = {}) {
    // Implementation
}
```

### 3. Error Handling
```javascript
// Always use try/catch for async operations
try {
    const result = await performAnalysis();
    return { success: true, data: result };
} catch (error) {
    logger.error(`Analysis failed: ${error.message}`, { url, stack: error.stack });
    return {
        success: false,
        error: error.message,
        code: error.code || 'UNKNOWN_ERROR'
    };
}
```

### 4. Naming Conventions
```javascript
// Constants: UPPER_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 3;
const DEFAULT_TIMEOUT = 10000;

// Functions: camelCase
function calculateScore() {}
async function performAnalysis() {}

// Classes: PascalCase
class SSLAnalyzer {}

// Private functions: _camelCase
function _internalHelper() {}
```

### 5. Code Style (ESLint)
```javascript
// Use modern JavaScript features
const result = await fetchData();
const { score, grade } = analysis;
const headersList = headers.map(h => h.name);

// Avoid var, use const/let
const immutableValue = 42;
let mutableValue = 0;

// Arrow functions for callbacks
headers.filter(h => h.present).map(h => h.name);

// Template literals for strings
const message = `Analysis complete: ${score}/${maxScore}`;
```

---

## Performance Requirements

### Response Time Targets

| Operation | Fast Mode | Comprehensive Mode |
|-----------|-----------|-------------------|
| SSL Analysis | <2 seconds | <5 seconds |
| Headers Check | <1 second | <1 second |
| Additional Checks | <2 seconds | <5 seconds |
| **Total Analysis** | **<3 seconds** | **<15 seconds** |

### Optimization Techniques

#### 1. Parallel Execution
```javascript
// Run independent checks in parallel
const [sslResults, headersResults, additionalResults] = await Promise.all([
    performSSLAnalysis(url, options),
    checkSecurityHeaders(url, options),
    performAdditionalSecurityChecks(url, options)
]);
```

#### 2. Timeout Management
```javascript
// Different timeouts for different scenarios
const isBadSSL = url.includes('badssl.com');
const timeout = isBadSSL ? 5000 : 30000;

// Apply timeout to network requests
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), timeout);
```

#### 3. Fast Mode Optimizations
```javascript
// Skip expensive checks in fast mode
if (!options.fast) {
    // SSLyze analysis (adds 5-10 seconds)
    results.sslyze = await runSSLyzeScan(hostname, port);
} else {
    results.sslyze = { skipped: true, reason: 'Fast mode enabled' };
}
```

#### 4. Caching Strategy
```javascript
// Cache DNS resolutions (future enhancement)
const dnsCache = new Map();

// Cache certificate chains (future enhancement)
const certCache = new Map();
```

---

## Deployment

### Production Build
```bash
# Generate optimized build
npm run build

# Output structure
build/
├── server.js
├── package.json
├── index.html
├── DEPLOYMENT.md
├── start.bat (Windows)
├── start.sh (Linux/Mac)
├── lib/ (production code)
├── css/ (optimized styles)
└── js/ (minified JavaScript)
```

### Environment Variables
```bash
# Server configuration
PORT=4000
LOG_LEVEL=info

# Performance tuning
ANALYSIS_TIMEOUT=30000
FAST_MODE_DEFAULT=false

# SSLyze integration (optional)
SSLYZE_PATH=/usr/local/bin/sslyze
```

### Server Startup

**Windows:**
```batch
cd build
start.bat
```

**Linux/Mac:**
```bash
cd build
chmod +x start.sh
./start.sh
```

**Manual:**
```bash
cd build
npm install --production
node server.js
```

### Docker Deployment (Future Enhancement)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY build/ .
RUN npm install --production
EXPOSE 4000
CMD ["node", "server.js"]
```

### Health Monitoring
```bash
# Check server health
curl http://localhost:4000/api/health

# Expected response
{
    "status": "healthy",
    "timestamp": "2025-10-09T12:00:00.000Z",
    "version": "1.0.0"
}
```

---

## Extending the Application

### Adding New Security Headers

1. **Determine Category** (Critical, Important, Modern, etc.)
2. **Edit Appropriate Module** (`lib/security-headers/<category>-headers.js`)
3. **Add to performCheck Function:**

```javascript
// In critical-headers.js
function performCheck(headers) {
    const results = [];
    
    // Add new header check
    const newHeader = findHeader(headers, 'New-Security-Header');
    results.push({
        name: 'New-Security-Header',
        present: !!newHeader,
        value: newHeader || '',
        score: newHeader ? 10 : 0,
        maxScore: 10,
        category: 'Critical',
        description: 'Description of what this header does',
        recommendation: newHeader 
            ? 'Already configured' 
            : 'Add this header to improve security',
        issues: validateNewHeader(newHeader)
    });
    
    return results;
}
```

4. **Update Documentation** (README.md, SPECIFICATION.md)
5. **Add Test Case** (`test/integration/security-headers-analysis.test.js`)

### Adding New SSL Tests

1. **Edit SSL Analyzer** (`lib/ssl-analyzer/ssl-analyzer.js`)
2. **Add Test to analyzeSSLCertificateDetailed:**

```javascript
// New test function
function checkNewSSLFeature(certificate, connection) {
    return {
        test: 'New SSL Feature',
        category: 'ssl',
        passed: /* validation logic */,
        score: /* 0-15 based on result */,
        maxScore: 15,
        details: 'Detailed analysis of new feature',
        recommendation: 'How to improve this aspect'
    };
}

// Add to analysis results
const newFeatureTest = checkNewSSLFeature(cert, socket);
tests.push(newFeatureTest);
```

3. **Update Scoring** (`lib/ssl-analyzer/grading.js`)
4. **Add Integration Test** (`test/integration/comprehensive-ssl.test.js`)

### Adding New Additional Checks

1. **Create New Module** (`lib/web-security/new-check.js`)
2. **Implement Check Function:**

```javascript
/**
 * Check new security feature
 * @param {string} url - Target URL
 * @returns {Promise<Object>} Check result
 */
async function checkNewFeature(url) {
    try {
        // Perform check
        const result = await performCheck(url);
        
        return {
            name: 'New Security Feature',
            passed: result.valid,
            score: result.valid ? 2 : 0,
            maxScore: 2,
            details: result.details,
            recommendation: result.recommendation
        };
    } catch (error) {
        return {
            name: 'New Security Feature',
            passed: false,
            score: 0,
            error: error.message
        };
    }
}

module.exports = { checkNewFeature };
```

3. **Register in Orchestrator** (`lib/web-security/index.js`)
4. **Update Additional Checks Max Score** (`lib/scoring-system.js`)

---

## Troubleshooting

### Common Issues

#### 1. "Module not found" Errors
```bash
# Solution: Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

#### 2. "Port 4000 already in use"
```bash
# Windows
taskkill /F /IM node.exe

# Linux/Mac
lsof -ti:4000 | xargs kill -9

# Or change port
PORT=3001 npm start
```

#### 3. SSL Analysis Timeouts
```javascript
// Increase timeout in request
const options = { timeout: 60000 }; // 60 seconds
```

#### 4. SSLyze Not Found
```bash
# Install SSLyze (optional)
pip install --upgrade sslyze

# Or disable SSLyze checks
const options = { fast: true }; // Skips SSLyze
```

#### 5. Mixed Content Detection Fails
```bash
# Puppeteer requires Chromium
# If missing, reinstall
npm install puppeteer --force
```

---

## Security Considerations

### Application Security
- **Input Validation:** All URLs validated before analysis
- **Rate Limiting:** Consider adding to prevent abuse
- **CORS:** Enabled for cross-origin requests
- **Helmet.js:** Security headers on API responses
- **No Sensitive Data:** No credentials or keys in source

### Analysis Limitations
- **Client-Side Security:** Cannot analyze JavaScript security
- **Authentication:** Cannot test authenticated endpoints
- **Dynamic Content:** Limited analysis of SPA frameworks
- **Private Networks:** Cannot analyze internal sites

### Privacy
- **No Data Storage:** Analysis results not persisted
- **No Logging:** Target URLs not logged permanently
- **No Tracking:** No analytics or user tracking

---

## Future Enhancements

### Planned Features
1. **Authentication Support:** Analyze protected endpoints
2. **Scheduled Scans:** Periodic monitoring with alerts
3. **Historical Tracking:** Compare security scores over time
4. **API Key Management:** Secure multi-user access
5. **Docker Support:** Containerized deployment
6. **SPA Analysis:** Enhanced JavaScript security checks
7. **Compliance Reports:** OWASP, PCI-DSS, GDPR templates
8. **Webhook Integration:** Send results to external systems

---

## Contributing

### Development Process
1. **Fork Repository**
2. **Create Feature Branch:** `git checkout -b feature/new-check`
3. **Follow Coding Standards** (see above)
4. **Add Tests:** All new features need tests
5. **Run Test Suite:** `npm run test:all`
6. **Submit Pull Request**

### Code Review Checklist
- [ ] JSDoc comments for all functions
- [ ] Integration tests added
- [ ] ESLint passes (`npm run lint`)
- [ ] No performance regressions
- [ ] Documentation updated
- [ ] Error handling implemented

---

## License

MIT License - See LICENSE file

---

## Support

**Issues:** https://github.com/dipsylala/security-headers-checker/issues  
**Documentation:** README.md, DEPLOYMENT.md  
**AI Assistant Instructions:** `.github/copilot-instructions.md`

---

**Document Version:** 1.0.0  
**Last Updated:** October 9, 2025  
**Maintained By:** Project Contributors
