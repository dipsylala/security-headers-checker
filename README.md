# WebCheck Validator

A comprehensive web security analysis tool built with Bootstrap and Node.js that performs in-depth security assessments including SSL/TLS certificate analysis, security headers evaluation, and additional security protocol checks.

## 🔍 **Comprehensive Security Analysis**

WebCheck Validator performs **12 SSL certificate tests**, **22+ security header checks**, and **5 additional security protocol assessments** to provide a complete security posture evaluation.

### 🔒 **SSL/TLS Certificate Analysis (12 Comprehensive Tests)**
- **Certificate Validity** - Basic certificate validation and trust verification
- **Certificate Expiration** - Validity period analysis with early warning alerts
- **Hostname Verification** - Subject Alternative Name (SAN) validation
- **Key Strength Analysis** - RSA/ECDSA key size evaluation (2048-bit minimum recommended)
- **Signature Algorithm Assessment** - Cryptographic algorithm security analysis
- **Certificate Chain Verification** - Complete chain of trust validation
- **Certificate Revocation Status** - OCSP/CRL checking awareness
- **Certificate Pinning Detection** - HPKP header analysis
- **Perfect Forward Secrecy** - Ephemeral key exchange support detection
- **Protocol Version Analysis** - TLS version support (TLS 1.2/1.3 recommended)
- **Cipher Suite Analysis** - Encryption algorithm evaluation
- **Certificate Authority Trust** - Issuer validation and trust assessment

### 🛡️ **Security Headers Analysis (22+ Headers)**
- **Critical Security Headers** (Maximum impact on security score)
- **Important Security Headers** (High impact on security posture)
- **Modern Security Headers** (Next-generation web security)
- **Legacy Headers** (Older but still relevant security measures)
- **Information Disclosure Headers** (Privacy and security through obscurity)
- **Deprecated Headers** (Outdated security mechanisms)

### ⚡ **Additional Security Protocol Checks (5 Tests)**
- **HTTPS Redirect Verification** - Ensures HTTP traffic is properly redirected to HTTPS
- **Mixed Content Detection** - Identifies insecure resources on HTTPS pages
- **HTTP Methods Analysis** - Checks for potentially dangerous HTTP methods (TRACE, OPTIONS, etc.)
- **Security.txt Compliance** - Validates security contact information (RFC 9116)
- **Server Information Disclosure** - Analyzes server header information leakage

## Quick Start & Build Instructions

### Option 1: Using VS Code (Recommended)

1. Open the project in VS Code
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
3. Type "Tasks: Run Task" and select it
4. Choose "Start WebCheck Validator"
5. The application will be available at http://localhost:4000

### Option 2: Using Build Scripts

**Windows (Command Prompt):**
```bash
build-and-run.bat
```

**Windows (PowerShell):**
```powershell
.\build-and-run.ps1
```

### Option 3: Manual Setup

1. **Install Dependencies:**
   ```bash
   npm install
   ```

2. **Start the Application:**
   ```bash
   npm start
   ```

3. **For Development with Auto-reload:**
   ```bash
   npm run dev
   ```

### Option 4: Production Build

Create a production-ready build in `./build/` folder:

```bash
npm run build
```

This creates a complete, optimized production build with:
- All application files (excluding tests and development files)
- Production dependencies only
- Startup scripts for Windows and Linux/Mac
- Deployment documentation

To run the production build:
```bash
cd build
npm start
```

The application will be available at **http://localhost:4000**

## Features

### 🎯 **Core Analysis Capabilities**
- **Comprehensive SSL/TLS Analysis**: 12-test certificate security assessment with detailed grading
- **Security Headers Detection**: 22+ critical, important, and modern security headers
- **Additional Security Checks**: HTTPS redirects, mixed content, HTTP methods, and server disclosure
- **Advanced Certificate Validation**: Chain verification, revocation checking, and cryptographic analysis
- **Protocol Security Assessment**: TLS version analysis and cipher suite evaluation

### 💯 **Scoring & Reporting**
- **Weighted Scoring System**: Critical security issues have higher impact on overall score
- **Detailed Grade Calculation**: SSL certificates graded from F to A+ based on comprehensive criteria
- **Security Recommendations**: Actionable advice for improving security posture
- **Multiple Export Formats**: PDF, Excel, JSON, and CSV report generation
- **Performance Metrics**: Analysis timing and efficiency tracking

### 🌐 **User Experience**
- **URL/IP Analysis**: Enter any URL or IP address for comprehensive security analysis
- **Real-time Analysis**: Live security checking with visual progress feedback
- **Responsive Design**: Bootstrap-based responsive interface for all devices
- **Fast Mode**: Quick analysis option for basic security assessment
- **Comprehensive Mode**: Detailed analysis including advanced SSL vulnerability testing

## Security Headers Analyzed

### Critical Security Headers
- **Strict-Transport-Security (HSTS)** - Enforces secure HTTPS connections
- **Content-Security-Policy (CSP)** - Controls resource loading to prevent XSS attacks
- **X-Frame-Options** - Prevents clickjacking attacks
- **X-Content-Type-Options** - Prevents MIME type sniffing

### Important Security Headers
- **Referrer-Policy** - Controls referrer information sent with requests
- **Permissions-Policy** - Controls browser feature access and API permissions
- **Cache-Control** - Controls caching behavior for sensitive content

### Modern Security Headers
- **Cross-Origin-Embedder-Policy (COEP)** - Controls cross-origin resource embedding
- **Cross-Origin-Opener-Policy (COOP)** - Controls cross-origin window interactions
- **Cross-Origin-Resource-Policy (CORP)** - Controls cross-origin resource access
- **Origin-Agent-Cluster** - Requests origin-keyed agent clustering

### Additional Security Headers
- **X-Permitted-Cross-Domain-Policies** - Controls Adobe Flash and PDF policies
- **X-Download-Options** - Prevents file downloads from being executed in IE
- **X-DNS-Prefetch-Control** - Controls DNS prefetching behavior

### Legacy Headers (Still Relevant)
- **X-XSS-Protection** - Legacy XSS protection (superseded by CSP)
- **Pragma** - Legacy cache control header
- **Expires** - Legacy expiration header

### Information Disclosure Headers (Should be Removed)
- **Server** - Server software information
- **X-Powered-By** - Technology stack information
- **X-AspNet-Version** - ASP.NET version information
- **X-AspNetMvc-Version** - ASP.NET MVC version information

### Deprecated Headers
- **Expect-CT** - Certificate Transparency monitoring (deprecated)

## Installation

### Prerequisites

- Node.js (version 14 or higher)
- npm (Node Package Manager)

### Steps

1. Clone or download this repository
2. Navigate to the project directory
3. Install dependencies:

```powershell
npm install
```

## Usage

### Running the Application

1. Start the server:

```powershell
npm start
```

2. Open your web browser and navigate to:
```
http://localhost:4000
```

### Development Mode

For development with auto-restart on file changes:

```powershell
npm run dev
```

### Using the Application

1. **Enter URL or IP**: Type a complete URL (e.g., `https://example.com`) or IP address
2. **Click Analyze**: The application will perform comprehensive security checks
3. **Review Results**: Examine the security score, SSL certificate details, headers analysis, and additional checks
4. **Export Report**: Choose from PDF, Excel, JSON, or CSV export formats
5. **Test Another URL**: Use the "Test Another URL" button to analyze additional sites

## API Endpoints

### POST /api/analyze

Performs comprehensive security analysis of a given URL including SSL/TLS certificates, security headers, and additional security protocol checks.

**Request Body:**
```json
{
  "url": "https://example.com",
  "fast": false  // Optional: true for quick analysis, false for comprehensive
}
```

**Response Structure:**
```json
{
  "analysis": {
    "url": "https://example.com/",
    "timestamp": "2025-07-30T12:00:00.000Z",
    "analysisTime": "2.5s",
    "version": "1.0.0"
  },
  "security": {
    "score": 85,
    "grade": "A",
    "riskLevel": "Low",
    "scoreBreakdown": {
      "ssl": 28.5,
      "headers": 34.0,
      "additional": 8.0,
      "accessibility": 10.0
    }
  },
  "details": {
    "ssl": {
      "valid": true,
      "grade": "A+",
      "score": 95,
      "issuer": "Let's Encrypt Authority X3",
      "subject": "example.com",
      "validFrom": "Jan 15 00:00:00 2024 GMT",
      "validTo": "Apr 15 23:59:59 2025 GMT",
      "keyLength": 2048,
      "protocol": "TLSv1.3",
      "certificateChain": [...],
      "tests": [
        {
          "name": "Certificate Validity",
          "status": "pass",
          "description": "Certificate is valid and properly configured"
        },
        {
          "name": "Certificate Expiration",
          "status": "pass", 
          "description": "Certificate expires on Apr 15 23:59:59 2025 GMT"
        }
        // ... 10 more SSL tests
      ]
    },
    "headers": {
      "headers": [
        {
          "name": "Strict-Transport-Security",
          "present": true,
          "value": "max-age=31536000; includeSubDomains",
          "status": "pass",
          "category": "critical",
          "score": 10
        }
        // ... 21 more header checks
      ],
      "score": {
        "score": 85,
        "maxScore": 100,
        "scorePercentage": 85
      }
    },
    "additional": {
      "checks": [
        {
          "name": "HTTPS Redirect",
          "status": "pass",
          "description": "HTTP requests properly redirect to HTTPS",
          "score": 2,
          "maxScore": 2
        }
        // ... 4 more additional checks
      ]
    }
  }
}
```

### GET /api/health

Health check endpoint for monitoring application status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-07-30T12:00:00.000Z",
  "uptime": "2h 15m 30s",
  "version": "1.0.0"
}
```

## Security Features

### 🔐 **SSL/TLS Certificate Analysis (175 Points Maximum)**
- **Certificate Validity Verification** - Ensures certificates are properly signed and trusted
- **Expiration Monitoring** - Alerts for certificates expiring within 30 days (critical within 7 days)
- **Hostname Matching** - Validates certificate matches the requested domain
- **Key Strength Assessment** - Evaluates RSA (≥2048-bit) and ECDSA (≥256-bit) key sizes
- **Signature Algorithm Security** - Checks for secure algorithms (SHA-256+, excludes MD5/SHA-1)
- **Certificate Chain Validation** - Verifies complete chain to trusted root CA
- **Protocol Version Analysis** - Detects TLS 1.2/1.3 support and flags deprecated versions
- **Cipher Suite Evaluation** - Analyzes encryption algorithms and forward secrecy
- **Certificate Authority Trust** - Validates issuer reputation and trust status
- **Revocation Status Checking** - OCSP and CRL validation awareness
- **Certificate Pinning Detection** - Identifies HPKP implementation
- **Vulnerability Assessment** - Tests for common SSL/TLS vulnerabilities (optional comprehensive mode)

### 🛡️ **Security Headers Comprehensive Analysis**

#### Critical Security Headers (Maximum Security Impact)
- **Strict-Transport-Security (HSTS)** - Enforces secure HTTPS connections and prevents downgrade attacks
- **Content-Security-Policy (CSP)** - Controls resource loading to prevent XSS and data injection attacks
- **X-Frame-Options** - Prevents clickjacking attacks through iframe restrictions
- **X-Content-Type-Options** - Prevents MIME type sniffing vulnerabilities

#### Important Security Headers (High Security Impact)
- **Referrer-Policy** - Controls referrer information sent with cross-origin requests
- **Permissions-Policy** - Controls browser feature access and API permissions
- **Access-Control-Allow-Origin** - Manages cross-origin resource sharing (CORS) policies
- **Cross-Origin-Embedder-Policy (COEP)** - Controls cross-origin resource embedding
- **Cross-Origin-Opener-Policy (COOP)** - Controls cross-origin window interactions
- **Cross-Origin-Resource-Policy (CORP)** - Controls cross-origin resource access

#### Modern Security Headers (Next-Generation Protection)
- **NEL (Network Error Logging)** - Enables network error monitoring and reporting
- **Report-To** - Configures endpoints for security violation reporting
- **Expect-CT** - Certificate Transparency monitoring (being deprecated)

#### Legacy Headers (Backward Compatibility)
- **X-XSS-Protection** - Legacy XSS filter header (superseded by CSP)
- **X-Permitted-Cross-Domain-Policies** - Controls Adobe Flash and PDF cross-domain policies
- **Pragma** - Legacy cache control header
- **Cache-Control** - Controls caching behavior to prevent sensitive data exposure

#### Information Disclosure Headers (Security Through Obscurity)
- **Server** - Server software information (recommended to remove/obfuscate)
- **X-Powered-By** - Technology stack information (recommended to remove)
- **X-AspNet-Version** - ASP.NET version information (security risk if present)
- **Via** - Proxy/gateway information (potential information disclosure)

### ⚡ **Additional Security Protocol Checks**
- **HTTPS Redirect Verification** - Ensures HTTP requests are properly redirected to HTTPS (301/302 status)
- **Mixed Content Detection** - Identifies insecure HTTP resources loaded on HTTPS pages
- **HTTP Methods Analysis** - Checks for potentially dangerous methods (TRACE, DELETE, PUT)
- **Security.txt File Compliance** - Validates security contact information per RFC 9116
- **Server Information Disclosure Analysis** - Comprehensive server header and version detection

## Scoring System

The comprehensive security score is calculated using a weighted system across three main categories:

### 🔐 **SSL/TLS Certificate Score (30% Weight - Up to 175 Points)**
- **Grade-based Scoring**: A+ (175 pts) → A (150 pts) → B (125 pts) → C (100 pts) → D (75 pts) → F (0 pts)
- **Certificate Validity**: Valid certificates receive full points, expired/invalid receive 0
- **Key Strength**: RSA ≥2048-bit or ECDSA ≥256-bit for full points
- **Protocol Security**: TLS 1.2+ required, TLS 1.3 preferred
- **Algorithm Security**: SHA-256+ signatures, no MD5/SHA-1
- **Chain Validation**: Complete chain to trusted root CA
- **Vulnerability Deductions**: Critical (-15), High (-10), Medium (-5), Low (-2) per vulnerability

### 🛡️ **Security Headers Score (40% Weight - 100 Points)**
- **Critical Headers (3x Weight)**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Important Headers (2x Weight)**: Referrer-Policy, Permissions-Policy, CORS headers
- **Modern Headers (1.5x Weight)**: COEP, COOP, CORP, NEL, Report-To
- **Additional Headers (1x Weight)**: Cache-Control, Expect-CT, etc.
- **Legacy Headers (0.5x Weight)**: X-XSS-Protection, Pragma, etc.
- **Information Disclosure Penalty**: Points deducted for Server, X-Powered-By headers

### ⚡ **Additional Security Checks (20% Weight)**
- **HTTPS Redirect** (2 points): Proper HTTP→HTTPS redirection
- **Mixed Content** (2 points): No insecure resources on HTTPS pages
- **HTTP Methods** (2 points): Secure HTTP method configuration
- **Security.txt** (1 point): Proper security contact information
- **Server Info Disclosure** (1 point): Minimal server information exposure

### 📊 **Final Grade Calculation**

| Grade | Score Range | Security Posture | Action Required |
|-------|-------------|------------------|-----------------|
| **A+** | 90-100 | Exceptional | Maintain current security standards |
| **A**  | 80-89  | Excellent | Minor optimizations possible |
| **B**  | 70-79  | Good | Some improvements recommended |
| **C**  | 60-69  | Fair | Security improvements needed |
| **D**  | 40-59  | Poor | Immediate attention required |
| **F**  | 0-39   | Critical | Urgent security fixes needed |

**Formula**: `Final Score = (SSL Score × 0.3) + (Headers Score × 0.4) + (Additional Checks × 0.2)`

## File Structure

```
Security Headers/
├── index.html          # Main application interface
├── css/
│   └── style.css       # Custom styles
├── js/
│   └── app.js          # Frontend JavaScript
├── server.js           # Node.js backend server
├── package.json        # Node.js dependencies
└── README.md          # This file
```

## Dependencies

### Backend
- **express**: Web framework for Node.js
- **cors**: Cross-origin resource sharing
- **helmet**: Security middleware
- **https/http**: Built-in Node.js modules for HTTP requests
- **tls**: Built-in Node.js module for SSL/TLS

### Frontend
- **Bootstrap 5.3.0**: UI framework
- **Font Awesome 6.0.0**: Icons
- **jsPDF**: PDF generation
- **SheetJS**: Excel file generation

## Browser Compatibility

- Chrome/Chromium 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## Limitations

- CORS restrictions may prevent analysis of some websites
- SSL certificate analysis requires direct connection capabilities
- Some security headers may require specific server configurations to test
- Rate limiting may apply to prevent abuse

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Security Note

This tool is designed for legitimate security testing and educational purposes. Always ensure you have permission to test websites you don't own. The tool performs non-invasive checks and does not attempt to exploit vulnerabilities.

## Troubleshooting

### Common Issues

**"Cannot connect to URL"**
- Verify the URL is accessible
- Check if the site blocks automated requests
- Ensure proper URL format (include https://)

**"SSL check failed"**
- Site may not support HTTPS
- Firewall may be blocking connections
- Certificate may have expired

**"Headers not detected"**
- Site may not implement security headers
- CORS restrictions may prevent header reading
- Server may not respond to HEAD requests

### Support

For issues and questions, please check the GitHub issues page or create a new issue with detailed information about the problem.

## Changelog

### Version 1.0.0
- Initial release
- Basic security header checking
- SSL certificate analysis
- Export functionality
- Responsive web interface
