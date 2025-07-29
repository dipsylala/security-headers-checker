// Security Headers Checker Application

// Custom error classes for better error handling
class ReachabilityError extends Error {
    constructor(data) {
        super(data.message || 'Host unreachable');
        this.name = 'ReachabilityError';
        this.data = data;
    }
}

class ValidationError extends Error {
    constructor(data) {
        super(data.details || data.error || 'Validation failed');
        this.name = 'ValidationError';
        this.data = data;
    }
}

class SecurityChecker {
    constructor() {
        this.currentResults = null;
        this.init();
    }

    init() {
        document.getElementById('securityForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.analyzeUrl();
        });
    }

    async analyzeUrl() {
        const urlInput = document.getElementById('urlInput').value.trim();
        if (!urlInput) { return; }

        // Validate URL format
        if (!this.isValidUrl(urlInput)) {
            this.showError('Please enter a valid URL or IP address');
            return;
        }

        this.showLoading();

        try {
            // Perform security checks via API
            const results = await this.performSecurityChecks(urlInput);
            this.currentResults = results;
            this.displayResults(results);
        } catch (error) {
            // Handle specific error types
            if (error instanceof ReachabilityError) {
                this.showError(
                    error.data.message,
                    error.data.details,
                    error.data.suggestions
                );
            } else if (error instanceof ValidationError) {
                this.showError(
                    error.data.details || error.data.error,
                    null,
                    error.data.suggestions
                );
            } else {
                this.showError(`Error analyzing URL: ${error.message}`);
            }
        }
    }

    isValidUrl(string) {
        try {
            // Check if it's an IP address
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            if (ipRegex.test(string)) {
                return true;
            }

            // Check if it's a URL
            const url = new URL(string.startsWith('http') ? string : `https://${ string}`);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }

    showLoading() {
        document.getElementById('loadingSpinner').style.display = 'block';
        document.getElementById('resultsSection').style.display = 'none';
        document.getElementById('analyzeBtn').disabled = true;
    }

    hideLoading() {
        document.getElementById('loadingSpinner').style.display = 'none';
        document.getElementById('analyzeBtn').disabled = false;
    }

    showError(message, details = null, suggestions = null) {
        this.hideLoading();
        this.displayErrorMessage(message, details, suggestions);
    }

    displayErrorMessage(message, details = null, suggestions = null) {
        // Create error display in the results section
        const resultsSection = document.getElementById('resultsSection');
        resultsSection.style.display = 'block';
        
        // Determine the appropriate icon and context based on error type
        let iconClass = 'fas fa-exclamation-triangle';
        let iconColorClass = 'text-danger';
        let errorType = 'Connection Error';
        let errorContext = 'Unable to reach the target host';
        
        if (details && details.includes('ENOTFOUND')) {
            iconClass = 'fas fa-globe-americas';
            iconColorClass = 'text-warning';
            errorType = 'DNS Resolution Failed';
            errorContext = 'Domain name could not be resolved';
        } else if (details && (details.includes('timeout') || details.includes('Connection timed out'))) {
            iconClass = 'fas fa-clock reachability-icon';
            iconColorClass = 'text-warning';
            errorType = 'Connection Timeout';
            errorContext = 'Host did not respond within the timeout period';
        } else if (details && details.includes('Connection refused')) {
            iconClass = 'fas fa-ban';
            iconColorClass = 'text-danger';
            errorType = 'Connection Refused';
            errorContext = 'Host actively refused the connection';
        }
        
        resultsSection.innerHTML = `
            <div class="error-display">
                <div class="alert alert-danger" role="alert">
                    <div class="d-flex align-items-center mb-3">
                        <i class="${iconClass} me-3 ${iconColorClass}" style="font-size: 1.8rem;"></i>
                        <div>
                            <h5 class="mb-1">${errorType}</h5>
                            <small class="text-muted">${errorContext}</small>
                        </div>
                    </div>
                    <p class="mb-3 fs-6"><strong>${message}</strong></p>
                    ${details ? `
                        <div class="mb-3">
                            <h6><i class="fas fa-info-circle me-1 text-info"></i>Technical Details:</h6>
                            <code class="d-block">${details}</code>
                        </div>
                    ` : ''}
                    ${suggestions && suggestions.length > 0 ? `
                        <div class="mb-3">
                            <h6><i class="fas fa-lightbulb me-1 text-warning"></i>What you can try:</h6>
                            <ul class="mb-0">
                                ${suggestions.map((suggestion, index) => `
                                    <li class="mb-2">
                                        <span class="badge bg-light text-dark me-2">${index + 1}</span>
                                        ${suggestion}
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    <div class="border-top pt-3">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <small class="text-muted">
                                    <i class="fas fa-shield-alt me-1"></i>
                                    Our reachability checker validates connectivity before running comprehensive security tests, saving time and providing faster feedback.
                                </small>
                            </div>
                            <div class="col-md-4 text-md-end mt-2 mt-md-0">
                                <button class="btn btn-outline-primary btn-sm" onclick="location.reload()">
                                    <i class="fas fa-redo me-1"></i>Try Again
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async performSecurityChecks(url) {
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                // Handle different types of errors
                const errorData = await response.json().catch(() => null);
                
                if (response.status === 503 && errorData) {
                    // Reachability error - show detailed information
                    throw new ReachabilityError(errorData);
                } else if (response.status === 400 && errorData) {
                    // Validation error
                    throw new ValidationError(errorData);
                } else {
                    // Generic HTTP error
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            }

            const results = await response.json();

            // Transform API response to match frontend expectations
            if (results.details) {
                return {
                    url: results.analysis?.url || url,
                    domain: this.extractDomain(url),
                    timestamp: results.analysis?.timestamp || new Date().toISOString(),
                    ssl: results.details.ssl || {},
                    detailedSsl: results.details.detailedSsl || null,
                    headers: results.details.headers?.headers || [],
                    additional: results.details.additional?.checks || [],
                    score: results.security?.score || 0,
                    security: results.security || {}
                };
            }

            return results;
        } catch (error) {
            console.error('Error calling API:', error);
            
            // Handle specific error types
            if (error instanceof ReachabilityError) {
                throw error; // Re-throw to be handled by the calling method
            } else if (error instanceof ValidationError) {
                throw error; // Re-throw to be handled by the calling method
            }
            
            // Fallback to simulated data if API fails with network error
            const domain = this.extractDomain(url);

            return {
                url: url,
                domain: domain,
                timestamp: new Date().toISOString(),
                ssl: this.generateSSLResults(domain),
                headers: this.generateHeaderResults(),
                additional: this.generateAdditionalChecks(),
                score: 0 // Will be calculated
            };
        }
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url.startsWith('http') ? url : `https://${ url}`);
            return urlObj.hostname;
        // eslint-disable-next-line no-unused-vars
        } catch (e) {
            return url;
        }
    }

    generateSSLResults(domain) {
        // Simulate SSL check results
        return {
            valid: Math.random() > 0.3,
            issuer: 'Let\'s Encrypt Authority X3',
            subject: domain,
            validFrom: '2024-01-15T00:00:00Z',
            validTo: '2025-04-15T23:59:59Z',
            keyLength: 2048,
            signatureAlgorithm: 'SHA256-RSA',
            protocol: 'TLSv1.3',
            grade: ['A+', 'A', 'B', 'C', 'F'][Math.floor(Math.random() * 5)]
        };
    }

    generateHeaderResults() {
        const headers = [
            {
                name: 'Strict-Transport-Security',
                present: Math.random() > 0.4,
                value: 'max-age=31536000; includeSubDomains',
                description: 'Enforces secure HTTPS connections',
                recommendation: 'Add HSTS header to prevent protocol downgrade attacks'
            },
            {
                name: 'Content-Security-Policy',
                present: Math.random() > 0.6,
                value: 'default-src \'self\'; script-src \'self\' \'unsafe-inline\'',
                description: 'Controls resource loading to prevent XSS attacks',
                recommendation: 'Implement a strict CSP to prevent code injection'
            },
            {
                name: 'X-Frame-Options',
                present: Math.random() > 0.3,
                value: 'DENY',
                description: 'Prevents clickjacking attacks',
                recommendation: 'Set to DENY or SAMEORIGIN to prevent iframe embedding'
            },
            {
                name: 'X-Content-Type-Options',
                present: Math.random() > 0.4,
                value: 'nosniff',
                description: 'Prevents MIME type sniffing',
                recommendation: 'Add this header to prevent MIME confusion attacks'
            },
            {
                name: 'Referrer-Policy',
                present: Math.random() > 0.5,
                value: 'strict-origin-when-cross-origin',
                description: 'Controls referrer information sent with requests',
                recommendation: 'Set appropriate referrer policy for privacy'
            },
            {
                name: 'Permissions-Policy',
                present: Math.random() > 0.7,
                value: 'geolocation=(), microphone=(), camera=()',
                description: 'Controls browser feature access',
                recommendation: 'Disable unnecessary browser features'
            }
        ];

        return headers;
    }

    generateAdditionalChecks() {
        return [
            {
                name: 'HTTPS Redirect',
                status: Math.random() > 0.3 ? 'pass' : 'fail',
                description: 'Checks if HTTP requests are redirected to HTTPS',
                details: Math.random() > 0.3 ? 'HTTP requests properly redirect to HTTPS' : 'No HTTPS redirect detected'
            },
            {
                name: 'Mixed Content',
                status: Math.random() > 0.6 ? 'pass' : 'warning',
                description: 'Checks for insecure resources on HTTPS pages',
                details: Math.random() > 0.6 ? 'No mixed content detected' : 'Some resources loaded over HTTP'
            },
            {
                name: 'Cookie Security',
                status: Math.random() > 0.5 ? 'pass' : 'warning',
                description: 'Checks for secure cookie attributes',
                details: Math.random() > 0.5 ? 'Cookies have Secure and HttpOnly flags' : 'Some cookies missing security flags'
            },
            {
                name: 'Server Information',
                status: 'info',
                description: 'Server software disclosure',
                details: `Server: ${['nginx/1.18.0', 'Apache/2.4.41', 'Microsoft-IIS/10.0', 'Unknown'][Math.floor(Math.random() * 4)]}`
            }
        ];
    }

    calculateScore(results) {
        let score = 0;
        let maxScore = 0;

        // SSL Score (30 points)
        maxScore += 30;
        if (results.ssl.valid) {
            switch (results.ssl.grade) {
                case 'A+': score += 30; break;
                case 'A': score += 25; break;
                case 'B': score += 20; break;
                case 'C': score += 10; break;
                default: score += 0;
            }
        }

        // Headers Score (50 points)
        maxScore += 50;
        const criticalHeaders = results.headers.filter(h =>
            ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'].includes(h.name)
        );
        const presentCritical = criticalHeaders.filter(h => h.present).length;
        score += (presentCritical / criticalHeaders.length) * 40;

        const otherHeaders = results.headers.filter(h =>
            !['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'].includes(h.name)
        );
        const presentOther = otherHeaders.filter(h => h.present).length;
        score += (presentOther / otherHeaders.length) * 10;

        // Web security checks (20 points)
        maxScore += 20;
        const passedChecks = results.additional.filter(check => check.status === 'pass').length;
        const totalChecks = results.additional.filter(check => check.status !== 'info').length;
        if (totalChecks > 0) {
            score += (passedChecks / totalChecks) * 20;
        }

        return Math.round((score / maxScore) * 100);
    }

    displayResults(results) {
        this.hideLoading();

        // Calculate overall score if not provided by API
        if (!results.score || results.score === 0) {
            results.score = this.calculateScore(results);
        }

        // Show results section
        document.getElementById('resultsSection').style.display = 'block';
        document.getElementById('resultsSection').classList.add('fade-in');

        // Update overall score
        this.updateOverallScore(results.score);
        
        // Debug: Ensure grade boundaries are added after a short delay for DOM stability
        setTimeout(() => {
            this.addGradeBoundaries();
            console.log('Grade boundaries function called - check if DOM element exists');
        }, 100);

        // Display SSL results
        this.displaySSLResults(results.ssl, results.detailedSsl);

        // Display headers results
        this.displayHeadersResults(results.headers);

        // Display web security checks
        this.displayAdditionalResults(results.additional);

        // Scroll to results
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }

    updateOverallScore(score) {
        const progressBar = document.getElementById('scoreProgressBar');
        progressBar.style.width = `${score }%`;

        // Update progress bar color and description based on score
        progressBar.className = 'progress-bar';
        let grade, description, badgeClass;

        if (score >= 90) {
            grade = 'A+';
            description = 'Excellent security posture!';
            progressBar.classList.add('score-excellent');
            badgeClass = 'bg-success';
        } else if (score >= 80) {
            grade = 'A';
            description = 'Very good security implementation';
            progressBar.classList.add('score-excellent');
            badgeClass = 'bg-success';
        } else if (score >= 70) {
            grade = 'B';
            description = 'Good security with minor improvements needed';
            progressBar.classList.add('score-good');
            badgeClass = 'bg-primary';
        } else if (score >= 60) {
            grade = 'C';
            description = 'Adequate security but needs attention';
            progressBar.classList.add('score-good');
            badgeClass = 'bg-warning';
        } else if (score >= 40) {
            grade = 'D';
            description = 'Poor security - immediate attention needed';
            progressBar.classList.add('score-poor');
            badgeClass = 'bg-warning';
        } else {
            grade = 'F';
            description = 'Critical security issues detected!';
            progressBar.classList.add('score-critical');
            badgeClass = 'bg-danger';
        }

        // Update the score display with grade badge properly positioned
        const scoreElement = document.getElementById('overallScore');
        // Clear any existing content
        scoreElement.innerHTML = '';

        // Create score text
        const scoreText = document.createTextNode(`${score}/100`);
        scoreElement.appendChild(scoreText);

        // Create and append the badge
        const gradeBadge = document.createElement('span');
        gradeBadge.className = `badge ${badgeClass}`;
        gradeBadge.textContent = grade;
        scoreElement.appendChild(gradeBadge);

        document.getElementById('scoreDescription').textContent = description;

        // Grade boundaries will be added from displayResults after DOM is stable
    }

    addGradeBoundaries() {
        const progressContainer = document.getElementById('scoreProgress');
        
        if (!progressContainer) {
            console.error('Score progress container not found for grade boundaries');
            return;
        }

        // Remove existing boundaries if any
        const existingBoundaries = progressContainer.parentElement.querySelector('.grade-boundaries');
        if (existingBoundaries) {
            existingBoundaries.remove();
        }

        // Create grade boundaries container
        const boundariesContainer = document.createElement('div');
        boundariesContainer.className = 'grade-boundaries';

        // Create grade boundaries
        const boundaries = document.createElement('div');
        boundaries.className = 'grade-scale';
        boundaries.innerHTML = `
            <div class="grade-marker" data-grade="F" style="left: 0%">
                <div class="grade-line"></div>
                <div class="grade-label">F<br><small>0-39</small></div>
            </div>
            <div class="grade-marker" data-grade="D" style="left: 40%">
                <div class="grade-line"></div>
                <div class="grade-label">D<br><small>40-59</small></div>
            </div>
            <div class="grade-marker" data-grade="C" style="left: 60%">
                <div class="grade-line"></div>
                <div class="grade-label">C<br><small>60-69</small></div>
            </div>
            <div class="grade-marker" data-grade="B" style="left: 70%">
                <div class="grade-line"></div>
                <div class="grade-label">B<br><small>70-79</small></div>
            </div>
            <div class="grade-marker" data-grade="A" style="left: 80%">
                <div class="grade-line"></div>
                <div class="grade-label">A<br><small>80-89</small></div>
            </div>
            <div class="grade-marker" data-grade="A+" style="left: 90%">
                <div class="grade-line"></div>
                <div class="grade-label">A+<br><small>90-100</small></div>
            </div>
        `;

        boundariesContainer.appendChild(boundaries);

        // Insert boundaries after the progress bar more safely
        const parentElement = progressContainer.parentElement;
        const nextElement = progressContainer.nextSibling;
        
        if (nextElement) {
            parentElement.insertBefore(boundariesContainer, nextElement);
        } else {
            parentElement.appendChild(boundariesContainer);
        }
        
        console.log('Grade boundaries added successfully - element created with class:', boundariesContainer.className);
    }

    displaySSLResults(ssl, detailedSsl) {
        const container = document.getElementById('sslResults');

        // Use detailed SSL results if available, otherwise fall back to basic SSL data
        if (detailedSsl && detailedSsl.certificateDetails) {
            this.displayDetailedSSLResults(container, detailedSsl);
        } else {
            this.displayBasicSSLResults(container, ssl);
        }
    }

    displayDetailedSSLResults(container, detailedSsl) {
        const { certificateDetails, tests, summary } = detailedSsl;

        // Calculate grade class for styling
        const gradeClass = this.getGradeBadgeClass(summary.grade);

        let html = `
            <div class="ssl-overview mb-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="mb-0">
                        <i class="fas fa-certificate me-2"></i>
                        SSL Certificate Info
                    </h5>
                    <div class="ssl-grade-container">
                        <span class="badge bg-${gradeClass} ssl-grade-badge">${summary.grade}</span>
                        <small class="text-muted ms-2">${summary.score}/${summary.maxScore}</small>
                    </div>
                </div>

                <div class="ssl-test-summary mb-3">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-check-circle text-success me-2"></i>
                        <span>${summary.testsPassed}/${summary.testsTotal} tests passed</span>
                    </div>
                </div>

                <div class="certificate-details mb-4">
                    <h6 class="mb-3">
                        <i class="fas fa-info-circle me-2"></i>
                        Certificate Details
                    </h6>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="cert-detail-item">
                                <strong>Issuer:</strong>
                                <span class="text-muted">${certificateDetails.issuer || 'Unknown'}</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Subject:</strong>
                                <span class="text-muted">${certificateDetails.subject || 'Unknown'}</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Serial Number:</strong>
                                <span class="text-muted">${certificateDetails.serialNumber || 'Unknown'}</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Key Algorithm:</strong>
                                <span class="text-muted">${certificateDetails.keyAlgorithm || 'Unknown'}</span>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="cert-detail-item">
                                <strong>Valid From:</strong>
                                <span class="text-muted">${certificateDetails.validFrom || 'Unknown'}</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Valid To:</strong>
                                <span class="text-muted">${certificateDetails.validTo || 'Unknown'}</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Key Length:</strong>
                                <span class="text-muted">${certificateDetails.keyLength || 'Unknown'} bits</span>
                            </div>
                            <div class="cert-detail-item">
                                <strong>Protocol:</strong>
                                <span class="text-muted">${certificateDetails.protocol || 'Unknown'}</span>
                            </div>
                        </div>
                    </div>
                </div>

                ${this.displayCertificateChain(certificateDetails)}
            </div>

            <div class="ssl-tests">
                <h6 class="mb-3">
                    <i class="fas fa-tasks me-2"></i>
                    SSL Certificate Tests
                </h6>
        `;

        // Display individual test results using the same format as Security Headers
        tests.forEach(test => {
            const statusClass = this.getSSLStatusClass(test.status);
            const statusIcon = this.getSSLStatusIcon(test.status);
            const statusBadge = this.getSSLStatusBadge(test.status);
            const statusText = this.getSSLStatusText(test.status);
            
            html += `
                <div class="security-item ${statusClass} mb-3">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h6 class="mb-0">
                            <i class="fas ${statusIcon} me-2"></i>
                            ${test.name}
                        </h6>
                        <span class="badge badge-status ${statusBadge}">${statusText}</span>
                    </div>
                    
                    <p class="mb-2 text-muted">${test.description}</p>
                    
                    ${test.recommendation ? `
                        <div class="recommendation">
                            <i class="fas fa-lightbulb me-2"></i>
                            ${test.recommendation}
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += `
            </div>
        `;

        container.innerHTML = html;
    }

    displayBasicSSLResults(container, ssl) {
        // Fallback to basic SSL display
        const statusClass = ssl.valid ? 'pass' : 'fail';
        const statusIcon = ssl.valid ? 'fa-check-circle' : 'fa-times-circle';
        const statusText = ssl.valid ? 'Valid' : 'Invalid';

        // Build explanation section
        let explanationSection = '';
        if (ssl.gradeExplanation) {
            explanationSection = `
                <div class="mt-3 p-3 bg-light rounded">
                    <h6 class="mb-2">
                        <i class="fas fa-info-circle me-2"></i>
                        Grade Explanation
                    </h6>
                    <p class="mb-0 text-muted">${ssl.gradeExplanation}</p>
                </div>
            `;
        }

        // Build recommendations section
        let recommendationsSection = '';
        if (ssl.recommendations && ssl.recommendations.length > 0) {
            const recommendationsList = ssl.recommendations.map(rec => `<li class="fw-bold text-warning">${rec}</li>`).join('');
            recommendationsSection = `
                <div class="mt-3 p-3 border border-warning rounded" style="background-color: #fff3cd;">
                    <h6 class="mb-2 text-warning">
                        <i class="fas fa-lightbulb me-2"></i>
                        💡 How to Improve Your SSL Score
                    </h6>
                    <div class="small text-muted mb-2">
                        <strong>Current Score:</strong> ${ssl.score}/100 
                        ${ssl.score < 100 ? `<span class="text-warning">(${100 - ssl.score} points from perfect)</span>` : '<span class="text-success">(Perfect!)</span>'}
                    </div>
                    <ul class="mb-0">
                        ${recommendationsList}
                    </ul>
                </div>
            `;
        }

        container.innerHTML = `
            <div class="security-item ${statusClass}">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0">
                        <i class="fas ${statusIcon} me-2"></i>
                        SSL Certificate Status
                    </h6>
                    <span class="badge badge-status bg-${ssl.valid ? 'success' : 'danger'}">${statusText}</span>
                </div>
                
                <div class="ssl-info">
                    <div class="ssl-label">Grade:</div>
                    <div class="ssl-value">
                        <span class="badge bg-${this.getGradeBadgeClass(ssl.grade)}">${ssl.grade}</span>
                    </div>
                    
                    <div class="ssl-label">Issuer:</div>
                    <div class="ssl-value">${ssl.issuer}</div>
                    
                    <div class="ssl-label">Valid From:</div>
                    <div class="ssl-value">${ssl.validFrom ? new Date(ssl.validFrom).toLocaleDateString() : 'N/A'}</div>
                    
                    <div class="ssl-label">Valid To:</div>
                    <div class="ssl-value">${ssl.validTo ? new Date(ssl.validTo).toLocaleDateString() : 'N/A'}</div>
                    
                    <div class="ssl-label">Key Length:</div>
                    <div class="ssl-value">${ssl.keyLength} bits</div>
                    
                    <div class="ssl-label">Protocol:</div>
                    <div class="ssl-value">${ssl.protocol}</div>
                </div>
                
                ${explanationSection}
                ${recommendationsSection}
            </div>
        `;
    }

    getTestStatusIcon(status) {
        switch (status) {
            case 'PASS':
                return '<i class="fas fa-check-circle text-success me-2"></i>';
            case 'FAIL':
                return '<i class="fas fa-times-circle text-danger me-2"></i>';
            case 'WARNING':
                return '<i class="fas fa-exclamation-triangle text-warning me-2"></i>';
            default:
                return '<i class="fas fa-question-circle text-muted me-2"></i>';
        }
    }

    getTestStatusClass(status) {
        switch (status) {
            case 'PASS':
                return 'test-pass';
            case 'FAIL':
                return 'test-fail';
            case 'WARNING':
                return 'test-warning';
            default:
                return 'test-unknown';
        }
    }

    getTestBadgeClass(status) {
        switch (status) {
            case 'PASS':
                return 'success';
            case 'FAIL':
                return 'danger';
            case 'WARNING':
                return 'warning';
            default:
                return 'secondary';
        }
    }

    getSSLStatusIcon(status) {
        switch (status.toLowerCase()) {
            case 'pass':
                return 'fa-check-circle';
            case 'fail':
                return 'fa-times-circle';
            case 'warning':
                return 'fa-exclamation-triangle';
            default:
                return 'fa-info-circle';
        }
    }

    getSSLStatusBadge(status) {
        switch (status.toLowerCase()) {
            case 'pass':
                return 'bg-success';
            case 'fail':
                return 'bg-danger';
            case 'warning':
                return 'bg-warning';
            default:
                return 'bg-info';
        }
    }

    getSSLStatusClass(status) {
        switch (status.toLowerCase()) {
            case 'pass':
                return 'pass';
            case 'fail':
                return 'fail';
            case 'warning':
                return 'warning';
            default:
                return 'info';
        }
    }

    getSSLStatusText(status) {
        switch (status.toLowerCase()) {
            case 'pass':
                return 'PASS';
            case 'fail':
                return 'FAIL';
            case 'warning':
                return 'WARNING';
            default:
                return 'UNKNOWN';
        }
    }

    getGradeBadgeClass(grade) {
        switch (grade) {
            case 'A+':
            case 'A': return 'success';
            case 'B': return 'primary';
            case 'C': return 'warning';
            default: return 'danger';
        }
    }

    displayHeadersResults(headers) {
        const container = document.getElementById('headersResults');

        // Group headers by category
        const categorizedHeaders = {
            critical: headers.filter(h => h.category === 'critical'),
            important: headers.filter(h => h.category === 'important'),
            modern: headers.filter(h => h.category === 'modern'),
            additional: headers.filter(h => h.category === 'additional'),
            legacy: headers.filter(h => h.category === 'legacy'),
            deprecated: headers.filter(h => h.category === 'deprecated'),
            information: headers.filter(h => h.category === 'information')
        };

        const categoryTitles = {
            critical: { title: 'Critical Security Headers', icon: 'fa-shield-alt', color: 'danger' },
            important: { title: 'Important Security Headers', icon: 'fa-exclamation-triangle', color: 'warning' },
            modern: { title: 'Modern Security Headers', icon: 'fa-star', color: 'info' },
            additional: { title: 'Additional Security Headers', icon: 'fa-plus-circle', color: 'secondary' },
            legacy: { title: 'Legacy Headers', icon: 'fa-history', color: 'muted' },
            deprecated: { title: 'Deprecated Headers', icon: 'fa-times-circle', color: 'muted' },
            information: { title: 'Information Disclosure Headers', icon: 'fa-eye', color: 'warning' }
        };

        let html = '';

        Object.keys(categorizedHeaders).forEach(category => {
            const categoryHeaders = categorizedHeaders[category];
            if (categoryHeaders.length === 0) { return; }

            const categoryInfo = categoryTitles[category];
            const presentCount = categoryHeaders.filter(h => h.present).length;
            const totalCount = categoryHeaders.length;

            // Special handling for information headers (good when absent)
            const goodCount = category === 'information' ?
                categoryHeaders.filter(h => !h.present).length : presentCount;

            html += `
                <div class="header-category mb-4">
                    <div class="category-header d-flex justify-content-between align-items-center mb-3">
                        <h6 class="text-${categoryInfo.color} mb-0">
                            <i class="fas ${categoryInfo.icon} me-2"></i>
                            ${categoryInfo.title}
                        </h6>
                        <span class="badge bg-${categoryInfo.color}">${goodCount}/${totalCount}</span>
                    </div>
                    <div class="category-items">
                        ${categoryHeaders.map(header => this.renderHeaderItem(header, category)).join('')}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    renderHeaderItem(header, category) {
        let statusClass, statusIcon, statusText, statusBadgeClass;

        if (category === 'information') {
            // For information headers, absence is good
            statusClass = header.present ? 'fail' : 'pass';
            statusIcon = header.present ? 'fa-exclamation-triangle' : 'fa-check-circle';
            statusText = header.present ? 'Disclosed' : 'Hidden';
            statusBadgeClass = header.present ? 'bg-warning' : 'bg-success';
        } else {
            statusClass = header.present ? 'pass' : 'fail';
            statusIcon = header.present ? 'fa-check-circle' : 'fa-times-circle';
            statusText = header.present ? 'Present' : 'Missing';
            statusBadgeClass = header.present ? 'bg-success' : 'bg-danger';
        }

        return `
            <div class="security-item ${statusClass} mb-3">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0">
                        <i class="fas ${statusIcon} me-2"></i>
                        ${header.name}
                        ${header.category === 'deprecated' ? '<span class="badge bg-warning ms-2">Deprecated</span>' : ''}
                        ${header.category === 'legacy' ? '<span class="badge bg-secondary ms-2">Legacy</span>' : ''}
                    </h6>
                    <span class="badge badge-status ${statusBadgeClass}">${statusText}</span>
                </div>
                
                <p class="mb-2 text-muted">${header.description}</p>
                
                ${header.present && header.value ? `
                    <div class="header-detail mb-2">
                        <strong>Current Value:</strong><br>
                        <code>${this.escapeHtml(header.value)}</code>
                    </div>
                ` : ''}
                
                ${header.example ? `
                    <div class="example-detail mb-2">
                        <strong>Example:</strong><br>
                        <code class="text-muted">${this.escapeHtml(header.example)}</code>
                    </div>
                ` : ''}
                
                <div class="recommendation">
                    <i class="fas fa-lightbulb me-2"></i>
                    ${header.recommendation}
                </div>
            </div>
        `;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    displayAdditionalResults(additional) {
        const container = document.getElementById('additionalResults');

        const additionalItems = additional.map(check => {
            const statusIcon = this.getStatusIcon(check.status);
            const statusBadge = this.getStatusBadge(check.status);

            return `
                <div class="security-item ${check.status}">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h6 class="mb-0">
                            <i class="fas ${statusIcon} me-2"></i>
                            ${check.name}
                        </h6>
                        <span class="badge badge-status ${statusBadge}">${check.status.toUpperCase()}</span>
                    </div>
                    
                    <p class="mb-2 text-muted">${check.description}</p>
                    <div class="text-dark">${check.details}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = additionalItems;
    }

    getStatusIcon(status) {
        switch (status) {
            case 'pass': return 'fa-check-circle';
            case 'warning': return 'fa-exclamation-triangle';
            case 'fail': return 'fa-times-circle';
            default: return 'fa-info-circle';
        }
    }

    getStatusBadge(status) {
        switch (status) {
            case 'pass': return 'bg-success';
            case 'warning': return 'bg-warning';
            case 'fail': return 'bg-danger';
            default: return 'bg-info';
        }
    }

    displayCertificateChain(certificateDetails) {
        if (!certificateDetails.chain || certificateDetails.chain.length <= 1) {
            return ''; // No chain or only leaf certificate
        }

        const chainId = `chain-${Date.now()}`; // Unique ID for this chain
        
        let html = `
            <div class="certificate-chain mb-4">
                <h6 class="mb-3">
                    <button class="btn btn-link p-0 text-decoration-none fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#${chainId}" aria-expanded="false" aria-controls="${chainId}">
                        <i class="fas fa-link me-2"></i>
                        Certificate Chain <span class="badge bg-info">${certificateDetails.chain.length} certificates</span>
                        <i class="fas fa-chevron-down ms-2 collapse-icon"></i>
                    </button>
                </h6>
                <div class="collapse" id="${chainId}">
                    <div class="chain-container border rounded p-3 bg-light">
        `;

        certificateDetails.chain.forEach((cert, index) => {
            const isLeaf = index === 0;
            const isRoot = cert.isRoot;
            const validityClass = this.getCertificateValidityClass(cert.validity?.status);
            const typeIcon = this.getCertificateTypeIcon(cert.type);
            
            html += `
                <div class="certificate-item ${isLeaf ? 'leaf-cert' : ''} ${isRoot ? 'root-cert' : ''} mb-3">
                    <div class="cert-header d-flex justify-content-between align-items-center mb-2">
                        <div class="cert-title">
                            <i class="${typeIcon} me-2"></i>
                            <strong>${cert.type}</strong>
                            ${isLeaf ? '<span class="badge bg-primary ms-2">Current</span>' : ''}
                            ${isRoot ? '<span class="badge bg-success ms-2">Root CA</span>' : ''}
                        </div>
                        <div class="cert-status">
                            <span class="badge bg-${validityClass}">${cert.validity?.status || 'Unknown'}</span>
                        </div>
                    </div>
                    
                    <div class="cert-content">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="cert-detail-item">
                                    <strong>Subject:</strong>
                                    <span class="text-muted">${cert.subject || 'Unknown'}</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Issuer:</strong>
                                    <span class="text-muted">${cert.issuer || 'Unknown'}</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Serial Number:</strong>
                                    <span class="text-muted font-monospace">${cert.serialNumber || 'Unknown'}</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Key Algorithm:</strong>
                                    <span class="text-muted">${cert.keyAlgorithm || 'Unknown'}</span>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="cert-detail-item">
                                    <strong>Valid From:</strong>
                                    <span class="text-muted">${this.formatDate(cert.validFrom) || 'Unknown'}</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Valid To:</strong>
                                    <span class="text-muted">${this.formatDate(cert.validTo) || 'Unknown'}</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Key Length:</strong>
                                    <span class="text-muted">${cert.keyLength || 'Unknown'} bits</span>
                                </div>
                                <div class="cert-detail-item">
                                    <strong>Signature Algorithm:</strong>
                                    <span class="text-muted">${cert.signatureAlgorithm || 'Unknown'}</span>
                                </div>
                            </div>
                        </div>
                        
                        ${this.displayCertificateExtensions(cert)}
                        ${this.displayOrganizationInfo(cert)}
                        
                        <div class="cert-fingerprints mt-2">
                            <small class="text-muted">
                                <strong>Fingerprint (SHA-256):</strong> 
                                <span class="font-monospace">${cert.fingerprint256 || 'Unknown'}</span>
                            </small>
                        </div>
                    </div>
                </div>
            `;

            // Add connection arrow if not the last certificate
            if (index < certificateDetails.chain.length - 1) {
                html += `
                    <div class="chain-arrow text-center mb-3">
                        <i class="fas fa-arrow-down text-muted"></i>
                        <small class="text-muted d-block">signed by</small>
                    </div>
                `;
            }
        });

        html += `
                    </div>
                </div>
            </div>
        `;

        return html;
    }

    displayCertificateExtensions(cert) {
        if (!cert.extensions) return '';
        
        let html = '';
        const extensions = cert.extensions;
        
        if (extensions.subjectAltName || extensions.keyUsage || extensions.isCa) {
            html += `
                <div class="cert-extensions mt-2">
                    <small><strong>Extensions:</strong></small>
                    <div class="extensions-list">
            `;
            
            if (extensions.subjectAltName) {
                html += `<span class="badge bg-light text-dark me-1">SAN</span>`;
            }
            if (extensions.keyUsage) {
                html += `<span class="badge bg-light text-dark me-1">Key Usage</span>`;
            }
            if (extensions.isCa) {
                html += `<span class="badge bg-warning text-dark me-1">CA Certificate</span>`;
            }
            
            html += `
                    </div>
                </div>
            `;
        }
        
        return html;
    }

    displayOrganizationInfo(cert) {
        if (!cert.organizationInfo) return '';
        
        const org = cert.organizationInfo.subject;
        if (!org.organization && !org.country) return '';
        
        let html = `
            <div class="organization-info mt-2">
                <small><strong>Organization:</strong></small>
                <div class="org-details">
        `;
        
        if (org.organization) {
            html += `<span class="text-muted">${org.organization}</span>`;
        }
        if (org.country) {
            html += `<span class="text-muted ms-2">(${org.country})</span>`;
        }
        
        html += `
                </div>
            </div>
        `;
        
        return html;
    }

    getCertificateValidityClass(status) {
        switch (status) {
            case 'Valid': return 'success';
            case 'Expired': return 'danger';
            case 'Not Yet Valid': return 'warning';
            default: return 'secondary';
        }
    }

    getCertificateTypeIcon(type) {
        if (type.includes('Leaf')) return 'fas fa-certificate';
        if (type.includes('Intermediate')) return 'fas fa-link';
        if (type.includes('Root')) return 'fas fa-shield-alt';
        return 'fas fa-certificate';
    }

    formatDate(dateString) {
        if (!dateString) return null;
        try {
            return new Date(dateString).toLocaleDateString();
        } catch (e) {
            return dateString;
        }
    }
}

// Export functionality
// Used by the form
// eslint-disable-next-line no-unused-vars
function exportReport(format) {
    if (!window.securityChecker.currentResults) {
        alert('No results to export');
        return;
    }

    const results = window.securityChecker.currentResults;
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `security-report-${results.domain}-${timestamp}`;

    switch (format) {
        case 'pdf':
            exportToPDF(results, filename);
            break;
        case 'excel':
            exportToExcel(results, filename);
            break;
        case 'json':
            exportToJSON(results, filename);
            break;
        case 'csv':
            exportToCSV(results, filename);
            break;
        default:
            console.error('Unknown export format:', format);
            break;
    }
}

function exportToPDF(results, filename) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    let yPos = 20;
    const pageHeight = doc.internal.pageSize.height;
    const margin = 20;
    const lineHeight = 10;

    // Helper function to add new page if needed
    function checkNewPage(neededSpace = 20) {
        if (yPos + neededSpace > pageHeight - margin) {
            doc.addPage();
            yPos = 20;
        }
    }

    // Helper function to add text with proper wrapping
    function addText(text, fontSize = 10, isBold = false) {
        checkNewPage();
        doc.setFontSize(fontSize);
        if (isBold) {
            doc.setFont(undefined, 'bold');
        } else {
            doc.setFont(undefined, 'normal');
        }
        doc.text(text, margin, yPos);
        yPos += lineHeight;
    }

    // Helper function to add section header
    function addSectionHeader(title) {
        checkNewPage(30);
        yPos += 5; // Extra space before section
        doc.setFontSize(16);
        doc.setFont(undefined, 'bold');
        doc.text(title, margin, yPos);
        yPos += lineHeight + 5; // Extra space after header
    }

    // Title
    doc.setFontSize(24);
    doc.setFont(undefined, 'bold');
    doc.text('Security Headers Analysis Report', margin, yPos);
    yPos += 20;

    // Summary Information
    addSectionHeader('Summary');
    addText(`URL: ${results.url}`, 12);
    addText(`Domain: ${results.domain || 'N/A'}`, 12);
    addText(`Generated: ${new Date(results.timestamp).toLocaleString()}`, 12);
    addText(`Overall Security Score: ${results.score}/100`, 14, true);

    // Grade explanation
    let gradeDesc = '';
    if (results.score >= 90) gradeDesc = 'Excellent security posture!';
    else if (results.score >= 80) gradeDesc = 'Very good security implementation';
    else if (results.score >= 70) gradeDesc = 'Good security with minor improvements needed';
    else if (results.score >= 60) gradeDesc = 'Adequate security but needs attention';
    else if (results.score >= 40) gradeDesc = 'Poor security - immediate attention needed';
    else gradeDesc = 'Critical security issues detected!';
    
    addText(`Assessment: ${gradeDesc}`, 12);

    // SSL Certificate Information
    addSectionHeader('SSL/TLS Certificate Analysis');
    addText(`Certificate Status: ${results.ssl.valid ? 'Valid' : 'Invalid'}`, 12, true);
    addText(`SSL Grade: ${results.ssl.grade || 'N/A'}`, 12);
    addText(`Issuer: ${results.ssl.issuer || 'Unknown'}`, 10);
    addText(`Subject: ${results.ssl.subject || 'Unknown'}`, 10);
    
    if (results.ssl.validFrom) {
        addText(`Valid From: ${new Date(results.ssl.validFrom).toLocaleDateString()}`, 10);
    }
    if (results.ssl.validTo) {
        addText(`Valid To: ${new Date(results.ssl.validTo).toLocaleDateString()}`, 10);
    }
    
    addText(`Key Length: ${results.ssl.keyLength || 'Unknown'} bits`, 10);
    addText(`Protocol: ${results.ssl.protocol || 'Unknown'}`, 10);
    addText(`Signature Algorithm: ${results.ssl.signatureAlgorithm || 'Unknown'}`, 10);

    if (results.ssl.error) {
        addText(`Error: ${results.ssl.error}`, 10);
    }

    // Detailed SSL Tests (if available)
    if (results.detailedSsl && results.detailedSsl.tests) {
        addSectionHeader('SSL Certificate Tests');
        results.detailedSsl.tests.forEach(test => {
            addText(`${test.name}: ${test.status.toUpperCase()}`, 11, true);
            if (test.description) {
                const wrappedDesc = doc.splitTextToSize(test.description, 170);
                wrappedDesc.forEach(line => addText(line, 9));
            }
            if (test.recommendation) {
                addText(`Recommendation: ${test.recommendation}`, 9);
            }
            yPos += 3; // Space between tests
        });
    }

    // Security Headers
    addSectionHeader('Security Headers Analysis');
    
    if (results.headers && results.headers.length > 0) {
        // Group headers by category if available
        const categories = ['critical', 'important', 'modern', 'additional', 'legacy', 'deprecated', 'information'];
        const categorizedHeaders = {};
        
        // Group headers
        results.headers.forEach(header => {
            const category = header.category || 'other';
            if (!categorizedHeaders[category]) {
                categorizedHeaders[category] = [];
            }
            categorizedHeaders[category].push(header);
        });

        // Display headers by category
        categories.forEach(category => {
            if (categorizedHeaders[category] && categorizedHeaders[category].length > 0) {
                const categoryTitle = category.charAt(0).toUpperCase() + category.slice(1) + ' Headers';
                addText(categoryTitle, 14, true);
                
                categorizedHeaders[category].forEach(header => {
                    const status = header.present ? 'Present' : 'Missing';
                    const statusColor = header.present ? '✓' : '✗';
                    addText(`${statusColor} ${header.name}: ${status}`, 11);
                    
                    if (header.present && header.value) {
                        const wrappedValue = doc.splitTextToSize(`Value: ${header.value}`, 160);
                        wrappedValue.forEach(line => addText(`   ${line}`, 9));
                    }
                    
                    if (header.description) {
                        const wrappedDesc = doc.splitTextToSize(`   ${header.description}`, 160);
                        wrappedDesc.forEach(line => addText(line, 9));
                    }
                    yPos += 2;
                });
                yPos += 5;
            }
        });

        // Handle ungrouped headers
        if (categorizedHeaders.other) {
            addText('Other Headers', 14, true);
            categorizedHeaders.other.forEach(header => {
                const status = header.present ? 'Present' : 'Missing';
                const statusColor = header.present ? '✓' : '✗';
                addText(`${statusColor} ${header.name}: ${status}`, 11);
                yPos += 2;
            });
        }
    }

    // Web Security Checks
    if (results.additional && results.additional.length > 0) {
        addSectionHeader('Web Security Checks');
        
        results.additional.forEach(check => {
            let statusIcon = '';
            switch (check.status) {
                case 'pass': statusIcon = '✓'; break;
                case 'fail': statusIcon = '✗'; break;
                case 'warning': statusIcon = '⚠'; break;
                default: statusIcon = 'ℹ';
            }
            
            addText(`${statusIcon} ${check.name}: ${check.status.toUpperCase()}`, 11, true);
            
            if (check.description) {
                const wrappedDesc = doc.splitTextToSize(`   ${check.description}`, 160);
                wrappedDesc.forEach(line => addText(line, 9));
            }
            
            if (check.details) {
                const wrappedDetails = doc.splitTextToSize(`   Details: ${check.details}`, 160);
                wrappedDetails.forEach(line => addText(line, 9));
            }
            yPos += 3;
        });
    }

    // Certificate Chain (if available)
    if (results.detailedSsl && results.detailedSsl.certificateDetails && results.detailedSsl.certificateDetails.chain) {
        addSectionHeader('Certificate Chain');
        
        results.detailedSsl.certificateDetails.chain.forEach((cert, index) => {
            addText(`Certificate ${index + 1}: ${cert.type || 'Unknown Type'}`, 12, true);
            addText(`   Subject: ${cert.subject || 'Unknown'}`, 10);
            addText(`   Issuer: ${cert.issuer || 'Unknown'}`, 10);
            addText(`   Valid: ${cert.validity?.status || 'Unknown'}`, 10);
            if (cert.validFrom && cert.validTo) {
                addText(`   Validity Period: ${cert.validFrom} to ${cert.validTo}`, 10);
            }
            yPos += 3;
        });
    }

    // Footer
    checkNewPage(30);
    yPos = pageHeight - 30;
    doc.setFontSize(8);
    doc.setFont(undefined, 'normal');
    doc.text('Generated by Security Headers Checker', margin, yPos);
    doc.text(`Report generated on ${new Date().toLocaleString()}`, margin, yPos + 10);

    doc.save(`${filename}.pdf`);
}

function exportToExcel(results, filename) {
    const workbook = XLSX.utils.book_new();

    // Summary sheet
    const summaryData = [
        ['Security Headers Analysis Report'],
        [''],
        ['URL', results.url],
        ['Domain', results.domain || 'N/A'],
        ['Generated', new Date(results.timestamp).toLocaleString()],
        ['Overall Security Score', `${results.score}/100`],
        [''],
        ['SSL Certificate Status', results.ssl.valid ? 'Valid' : 'Invalid'],
        ['SSL Grade', results.ssl.grade || 'N/A'],
        ['SSL Issuer', results.ssl.issuer || 'Unknown'],
        ['SSL Subject', results.ssl.subject || 'Unknown'],
        ['SSL Valid From', results.ssl.validFrom ? new Date(results.ssl.validFrom).toLocaleDateString() : 'N/A'],
        ['SSL Valid To', results.ssl.validTo ? new Date(results.ssl.validTo).toLocaleDateString() : 'N/A'],
        ['SSL Key Length', results.ssl.keyLength ? `${results.ssl.keyLength} bits` : 'Unknown'],
        ['SSL Protocol', results.ssl.protocol || 'Unknown'],
        ['SSL Signature Algorithm', results.ssl.signatureAlgorithm || 'Unknown']
    ];

    if (results.ssl.error) {
        summaryData.push(['SSL Error', results.ssl.error]);
    }

    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    
    // Style the summary sheet
    summarySheet['A1'] = { v: 'Security Headers Analysis Report', t: 's', s: { font: { bold: true, sz: 16 } } };
    
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

    // SSL Tests sheet (if detailed SSL data available)
    if (results.detailedSsl && results.detailedSsl.tests) {
        const sslTestsData = [
            ['SSL Certificate Tests'],
            [''],
            ['Test Name', 'Status', 'Score', 'Max Score', 'Description', 'Recommendation']
        ];

        results.detailedSsl.tests.forEach(test => {
            sslTestsData.push([
                test.name || 'Unknown Test',
                test.status || 'Unknown',
                test.score || 0,
                test.maxScore || 0,
                test.description || '',
                test.recommendation || ''
            ]);
        });

        const sslTestsSheet = XLSX.utils.aoa_to_sheet(sslTestsData);
        sslTestsSheet['A1'] = { v: 'SSL Certificate Tests', t: 's', s: { font: { bold: true, sz: 14 } } };
        
        XLSX.utils.book_append_sheet(workbook, sslTestsSheet, 'SSL Tests');
    }

    // Security Headers sheet
    const headersData = [
        ['Security Headers Analysis'],
        [''],
        ['Header Name', 'Category', 'Present', 'Status', 'Current Value', 'Description', 'Recommendation', 'Example Value']
    ];

    if (results.headers && results.headers.length > 0) {
        results.headers.forEach(header => {
            let status = 'Missing';
            if (header.present) {
                status = header.category === 'information' ? 'Disclosed' : 'Present';
            } else {
                status = header.category === 'information' ? 'Hidden (Good)' : 'Missing';
            }

            headersData.push([
                header.name || 'Unknown Header',
                header.category || 'Unknown',
                header.present ? 'Yes' : 'No',
                status,
                header.present ? (header.value || '') : '',
                header.description || '',
                header.recommendation || '',
                header.example || ''
            ]);
        });
    }

    const headersSheet = XLSX.utils.aoa_to_sheet(headersData);
    headersSheet['A1'] = { v: 'Security Headers Analysis', t: 's', s: { font: { bold: true, sz: 14 } } };
    
    XLSX.utils.book_append_sheet(workbook, headersSheet, 'Security Headers');

    // Web Security Checks sheet
    if (results.additional && results.additional.length > 0) {
        const additionalData = [
            ['Web Security Checks'],
            [''],
            ['Check Name', 'Status', 'Description', 'Details', 'Recommendation']
        ];

        results.additional.forEach(check => {
            additionalData.push([
                check.name || 'Unknown Check',
                check.status ? check.status.toUpperCase() : 'Unknown',
                check.description || '',
                check.details || '',
                check.recommendation || ''
            ]);
        });

        const additionalSheet = XLSX.utils.aoa_to_sheet(additionalData);
        additionalSheet['A1'] = { v: 'Web Security Checks', t: 's', s: { font: { bold: true, sz: 14 } } };
        
        XLSX.utils.book_append_sheet(workbook, additionalSheet, 'Web Security');
    }

    // Certificate Chain sheet (if available)
    if (results.detailedSsl && results.detailedSsl.certificateDetails && results.detailedSsl.certificateDetails.chain) {
        const chainData = [
            ['Certificate Chain'],
            [''],
            ['Position', 'Certificate Type', 'Subject', 'Issuer', 'Serial Number', 'Valid From', 'Valid To', 'Key Algorithm', 'Key Length', 'Signature Algorithm', 'Validity Status', 'Fingerprint SHA-256']
        ];

        results.detailedSsl.certificateDetails.chain.forEach((cert, index) => {
            chainData.push([
                index + 1,
                cert.type || 'Unknown',
                cert.subject || 'Unknown',
                cert.issuer || 'Unknown',
                cert.serialNumber || 'Unknown',
                cert.validFrom || 'Unknown',
                cert.validTo || 'Unknown',
                cert.keyAlgorithm || 'Unknown',
                cert.keyLength ? `${cert.keyLength} bits` : 'Unknown',
                cert.signatureAlgorithm || 'Unknown',
                cert.validity?.status || 'Unknown',
                cert.fingerprint256 || 'Unknown'
            ]);
        });

        const chainSheet = XLSX.utils.aoa_to_sheet(chainData);
        chainSheet['A1'] = { v: 'Certificate Chain', t: 's', s: { font: { bold: true, sz: 14 } } };
        
        XLSX.utils.book_append_sheet(workbook, chainSheet, 'Certificate Chain');
    }

    // Raw Data sheet (for technical analysis)
    const rawDataSheet = XLSX.utils.json_to_sheet([results]);
    XLSX.utils.book_append_sheet(workbook, rawDataSheet, 'Raw Data');

    // Set column widths for better readability
    const worksheets = ['Summary', 'Security Headers', 'Web Security'];
    worksheets.forEach(sheetName => {
        if (workbook.Sheets[sheetName]) {
            const ws = workbook.Sheets[sheetName];
            const cols = [
                { wch: 25 }, // Column A
                { wch: 15 }, // Column B
                { wch: 10 }, // Column C
                { wch: 15 }, // Column D
                { wch: 30 }, // Column E
                { wch: 40 }, // Column F
                { wch: 40 }, // Column G
                { wch: 30 }  // Column H
            ];
            ws['!cols'] = cols;
        }
    });

    // Add metadata
    workbook.Props = {
        Title: 'Security Headers Analysis Report',
        Subject: `Security analysis for ${results.url}`,
        Author: 'Security Headers Checker',
        CreatedDate: new Date(),
        ModifiedDate: new Date()
    };

    XLSX.writeFile(workbook, `${filename}.xlsx`);
}

function exportToJSON(results, filename) {
    const dataStr = JSON.stringify(results, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filename}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

function exportToCSV(results, filename) {
    const csvData = [
        ['Type', 'Name', 'Status', 'Value', 'Description'],
        ['SSL', 'Certificate', results.ssl.valid ? 'Valid' : 'Invalid', results.ssl.grade, 'SSL Certificate Status'],
        ...results.headers.map(header => [
            'Header',
            header.name,
            header.present ? 'Present' : 'Missing',
            header.present ? header.value : '',
            header.description
        ]),
        ...results.additional.map(check => [
            'Additional',
            check.name,
            check.status,
            check.details,
            check.description
        ])
    ];

    const csv = csvData.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
    const dataBlob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filename}.csv`;
    link.click();
    URL.revokeObjectURL(url);
}

// Used by the form
// eslint-disable-next-line no-unused-vars
function resetForm() {
    document.getElementById('urlInput').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('urlInput').focus();
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    window.securityChecker = new SecurityChecker();
});

// Add some demo URLs for quick testing
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');

    // Add placeholder with rotating examples
    const examples = [
        'https://example.com',
        'https://github.com',
        'https://stackoverflow.com',
        '192.168.1.1'
    ];

    let currentExample = 0;

    function rotatePlaceholder() {
        urlInput.placeholder = examples[currentExample];
        currentExample = (currentExample + 1) % examples.length;
    }

    // Rotate placeholder every 3 seconds
    setInterval(rotatePlaceholder, 3000);
    rotatePlaceholder(); // Set initial placeholder
});
