#!/usr/bin/env pwsh

Write-Host "Setting up Security Headers Checker..." -ForegroundColor Green
Write-Host ""

Write-Host "Installing dependencies..." -ForegroundColor Yellow
try {
    npm install
    if ($LASTEXITCODE -ne 0) {
        throw "npm install failed"
    }
}
catch {
    Write-Host "Failed to install dependencies!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Dependencies installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Starting Security Headers Checker..." -ForegroundColor Yellow
Write-Host "The application will be available at http://localhost:3000" -ForegroundColor Cyan
Write-Host ""

npm start
