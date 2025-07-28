# Security Headers Checker

A comprehensive web application built with Bootstrap and Node.js that analyzes website security headers, SSL certificates, and performs various security checks.

## Quick Start & Build Instructions

### Option 1: Using VS Code (Recommended)

1. Open the project in VS Code
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
3. Type "Tasks: Run Task" and select it
4. Choose "Start Security Headers Checker"
5. The application will be available at http://localhost:3000

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

The application will be available at **http://localhost:3000**

## Features

- **URL/IP Analysis**: Enter any URL or IP address for security analysis
- **SSL Certificate Validation**: Check certificate validity, grade, and configuration
- **Security Headers Detection**: Analyze presence and configuration of critical security headers
- **Additional Security Checks**: HTTPS redirects, server information disclosure, and more
- **Comprehensive Scoring**: Get an overall security score out of 100
- **Multiple Export Formats**: Export reports in PDF, Excel, JSON, and CSV formats
- **Responsive Design**: Bootstrap-based responsive interface
- **Real-time Analysis**: Live security checking with visual feedback

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
http://localhost:3000
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

Analyzes a given URL for security headers and SSL configuration.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "timestamp": "2025-07-28T12:00:00.000Z",
  "ssl": {
    "valid": true,
    "grade": "A+",
    "issuer": "Let's Encrypt Authority X3",
    "validFrom": "2024-01-15T00:00:00Z",
    "validTo": "2025-04-15T23:59:59Z"
  },
  "headers": [...],
  "additional": [...],
  "score": 85
}
```

### GET /health

Health check endpoint for monitoring.

## Security Features

### SSL/TLS Analysis
- Certificate validity verification
- SSL grade calculation (A+ to F)
- Protocol version detection
- Key strength analysis
- Certificate chain verification

### Header Analysis
- Critical security headers detection
- Header value validation
- Security recommendations
- Best practice compliance

### Additional Checks
- HTTPS redirect verification
- Server information disclosure
- Mixed content detection
- HTTP methods analysis
- Security.txt file presence (RFC 9116)

## Scoring System

The security score is calculated based on:

- **SSL Certificate (30 points)**: Grade-based scoring from F (0 points) to A+ (30 points)
- **Security Headers (60 points)**: 
  - Critical headers (weighted 3x): HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - Important headers (weighted 2x): Referrer-Policy, Permissions-Policy, Cache-Control
  - Modern headers (weighted 1.5x): COEP, COOP, CORP, Origin-Agent-Cluster
  - Additional headers (weighted 1x): Various security enhancements
  - Legacy headers (weighted 0.5x): Partial credit for older standards
  - Information disclosure headers: Good when absent (negative when present)
- **Additional Checks (10 points)**: HTTPS redirects, mixed content, HTTP methods, etc.

### Score Interpretation

| Grade | Score Range | Description |
|-------|-------------|-------------|
| **A+** | 90-100 | Excellent security posture - industry best practices |
| **A**  | 80-89  | Very good security implementation |
| **B**  | 70-79  | Good security with minor improvements needed |
| **C**  | 60-69  | Adequate security but needs attention |
| **D**  | 40-59  | Poor security - immediate attention needed |
| **F**  | 0-39   | Critical security issues detected |

The scoring system uses weighted calculations where critical headers (HSTS, CSP) have more impact than legacy headers, and modern security features receive appropriate recognition.

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
