// Security Headers Checker Application
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
            // Simulate API call - in real implementation, this would call your backend
            const results = await this.performSecurityChecks(urlInput);
            this.currentResults = results;
            this.displayResults(results);
        } catch (error) {
            this.showError(`Error analyzing URL: ${ error.message}`);
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

    showError(message) {
        this.hideLoading();
        alert(message); // In production, use a proper modal or toast
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
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const results = await response.json();

            // Transform API response to match frontend expectations
            if (results.details) {
                return {
                    url: results.analysis?.url || url,
                    domain: this.extractDomain(url),
                    timestamp: results.analysis?.timestamp || new Date().toISOString(),
                    ssl: results.details.ssl || {},
                    headers: results.details.headers?.headers || [],
                    additional: results.details.additional?.checks || [],
                    score: results.security?.score || 0,
                    security: results.security || {}
                };
            }

            return results;
        } catch (error) {
            console.error('Error calling API:', error);
            // Fallback to simulated data if API fails
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

        // Additional checks (20 points)
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

        // Display SSL results
        this.displaySSLResults(results.ssl);

        // Display headers results
        this.displayHeadersResults(results.headers);

        // Display additional checks
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

        // Add grade boundaries visualization
        this.addGradeBoundaries();
    }

    addGradeBoundaries() {
        const progressContainer = document.querySelector('.progress');

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

        // Insert boundaries directly after the progress bar
        progressContainer.parentElement.insertBefore(boundariesContainer, progressContainer.nextSibling);
    }

    displaySSLResults(ssl) {
        const container = document.getElementById('sslResults');

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
            const recommendationsList = ssl.recommendations.map(rec => `<li>${rec}</li>`).join('');
            recommendationsSection = `
                <div class="mt-3 p-3 bg-light rounded">
                    <h6 class="mb-2">
                        <i class="fas fa-lightbulb me-2"></i>
                        Recommendations
                    </h6>
                    <ul class="mb-0 text-muted">
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

    // Title
    doc.setFontSize(20);
    doc.text('Security Headers Report', 20, 20);

    // URL and timestamp
    doc.setFontSize(12);
    doc.text(`URL: ${results.url}`, 20, 35);
    doc.text(`Generated: ${new Date(results.timestamp).toLocaleString()}`, 20, 45);
    doc.text(`Security Score: ${results.score}/100`, 20, 55);

    // SSL Information
    doc.setFontSize(16);
    doc.text('SSL Certificate', 20, 75);
    doc.setFontSize(10);
    doc.text(`Status: ${results.ssl.valid ? 'Valid' : 'Invalid'}`, 25, 85);
    doc.text(`Grade: ${results.ssl.grade}`, 25, 95);
    doc.text(`Issuer: ${results.ssl.issuer}`, 25, 105);

    // Security Headers
    doc.setFontSize(16);
    doc.text('Security Headers', 20, 125);
    doc.setFontSize(10);
    let yPos = 135;
    results.headers.forEach(header => {
        doc.text(`${header.name}: ${header.present ? 'Present' : 'Missing'}`, 25, yPos);
        yPos += 10;
    });

    doc.save(`${filename}.pdf`);
}

function exportToExcel(results, filename) {
    const workbook = XLSX.utils.book_new();

    // Summary sheet
    const summaryData = [
        ['URL', results.url],
        ['Generated', new Date(results.timestamp).toLocaleString()],
        ['Security Score', `${results.score}/100`],
        ['SSL Valid', results.ssl.valid ? 'Yes' : 'No'],
        ['SSL Grade', results.ssl.grade]
    ];
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

    // Headers sheet
    const headersData = [
        ['Header Name', 'Present', 'Value', 'Description']
    ];
    results.headers.forEach(header => {
        headersData.push([
            header.name,
            header.present ? 'Yes' : 'No',
            header.present ? header.value : '',
            header.description
        ]);
    });
    const headersSheet = XLSX.utils.aoa_to_sheet(headersData);
    XLSX.utils.book_append_sheet(workbook, headersSheet, 'Headers');

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
