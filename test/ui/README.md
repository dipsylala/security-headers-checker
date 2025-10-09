# UI Tests - Frontend Testing Suite

This directory contains UI/frontend tests using Puppeteer for end-to-end testing of the WebCheck Validator web interface.

## Overview

UI tests validate the complete user workflow from the browser's perspective, ensuring the frontend correctly interacts with the backend API and displays results properly.

## Test Files

### `basic-ui.test.js`
Complete end-to-end UI test that:
- Verifies server health before testing
- Loads the application homepage
- Validates UI elements (form, input, button)
- Performs a full analysis of `https://veracode.com`
- Captures screenshots at each stage
- Verifies results are displayed correctly

**5 Test Stages:**
1. Server Health Check
2. Load Application UI
3. Verify UI Elements
4. Perform Security Analysis
5. Verify Results Content

## Running UI Tests

### Prerequisites
1. **Start the server first:**
   ```bash
   npm start
   # or
   npm run dev
   ```

2. **In a separate terminal, run the UI tests:**
   ```bash
   npm run test:ui
   ```

## Test Configuration

- **Target URL:** `https://veracode.com` (configurable in test file)
- **Base URL:** `http://localhost:3000` (application must be running)
- **Browser:** Headless Chromium via Puppeteer
- **Viewport:** 1920x1080 (desktop resolution)
- **Timeout:** 60 seconds for analysis completion

## Screenshot Artifacts

### Location
All screenshots are saved to: `test/ui/artifacts/`

### Naming Convention
```
<stage>_<timestamp>.png

Examples:
01_initial_load_2025-10-09T12-30-45-123Z.png
02_ui_elements_2025-10-09T12-30-46-456Z.png
03_url_entered_2025-10-09T12-30-47-789Z.png
04_analysis_started_2025-10-09T12-30-48-012Z.png
05_analysis_complete_2025-10-09T12-31-15-345Z.png
06_final_results_2025-10-09T12-31-16-678Z.png
error_screenshot_2025-10-09T12-31-20-901Z.png (on failure)
```

### Auto-Cleanup
- Automatically keeps only the last 10 test runs
- Older screenshots are deleted to save disk space
- Screenshots are full-page captures for maximum context

## Expected Output

```
======================================================================
🖥️  WebCheck Validator - UI Test Suite
======================================================================
📍 Base URL: http://localhost:3000
🎯 Test Target: https://veracode.com
📁 Artifacts: C:\...\test\ui\artifacts
======================================================================

📋 Test 1: Server Health Check
----------------------------------------------------------------------
✅ Server is running and healthy

📋 Test 2: Load Application UI
----------------------------------------------------------------------
🚀 Launching headless browser...
📡 Navigating to http://localhost:3000...
✅ Application loaded successfully
📸 Screenshot saved: 01_initial_load_2025-10-09T12-30-45-123Z.png

📋 Test 3: Verify UI Elements
----------------------------------------------------------------------
✅ Found: URL Input
✅ Found: Analyze Button
✅ Found: Form
✅ UI elements verified (3/3)
📸 Screenshot saved: 02_ui_elements_2025-10-09T12-30-46-456Z.png

📋 Test 4: Perform Security Analysis
----------------------------------------------------------------------
🔍 Analyzing: https://veracode.com
✅ URL entered into input field
📸 Screenshot saved: 03_url_entered_2025-10-09T12-30-47-789Z.png
🔄 Clicking analyze button...
✅ Analysis started
📸 Screenshot saved: 04_analysis_started_2025-10-09T12-30-48-012Z.png
⏳ Waiting for analysis to complete...
✅ Results displayed
📸 Screenshot saved: 05_analysis_complete_2025-10-09T12-31-15-345Z.png
✅ Analysis completed successfully (27s)

📋 Test 5: Verify Results Content
----------------------------------------------------------------------
✅ Found: Grade/Score
✅ Found: SSL Analysis
✅ Found: Security Headers
✅ Found: Overall Results
✅ Results content verified (4/4 indicators)
📸 Screenshot saved: 06_final_results_2025-10-09T12-31-16-678Z.png

🔒 Browser closed

======================================================================
📊 UI Test Summary
======================================================================
✅ Tests Passed: 5
❌ Tests Failed: 0
⏱️  Duration: 32.45s
📁 Artifacts: C:\...\test\ui\artifacts
======================================================================

📸 Generated Screenshots:
   - 01_initial_load_2025-10-09T12-30-45-123Z.png (1234.5 KB)
   - 02_ui_elements_2025-10-09T12-30-46-456Z.png (1235.6 KB)
   - 03_url_entered_2025-10-09T12-30-47-789Z.png (1236.7 KB)
   - 04_analysis_started_2025-10-09T12-30-48-012Z.png (1237.8 KB)
   - 05_analysis_complete_2025-10-09T12-31-15-345Z.png (1456.9 KB)
   - 06_final_results_2025-10-09T12-31-16-678Z.png (1567.0 KB)
```

## Troubleshooting

### Server Not Running
```
❌ Server health check failed: Server not reachable
💡 Make sure to start the server first: npm start
```
**Solution:** Start the server in a separate terminal before running UI tests.

### Element Not Found
If UI elements aren't found, the test tries multiple selector strategies:
- By attribute name (`input[name="url"]`)
- By ID (`input#url-input`)
- By type (`input[type="url"]`)
- By partial ID matching

**Solution:** Ensure HTML elements have proper IDs or names for testing.

### Analysis Timeout
```
⚠️  Analysis may still be running or results not detected
💡 Screenshot saved - manual verification recommended
```
**Solution:** Check the `05_analysis_timeout.png` screenshot to see what happened. The target site may be slow or unreachable.

## Extending UI Tests

### Adding New Test Stages

1. **Add screenshot capture:**
   ```javascript
   await saveScreenshot(page, '07_new_stage');
   ```

2. **Add element validation:**
   ```javascript
   const element = await page.$('selector');
   if (element) {
       console.log('✅ Element found');
       testsPassed++;
   }
   ```

3. **Add interaction:**
   ```javascript
   await element.click();
   await page.waitForSelector('.result');
   ```

### Testing Different URLs

Modify the `TEST_URL` constant in `basic-ui.test.js`:
```javascript
const TEST_URL = 'https://example.com';
```

### Changing Viewport

Modify the viewport settings:
```javascript
await page.setViewport({ width: 1280, height: 720 }); // Laptop
await page.setViewport({ width: 375, height: 812 });  // Mobile
```

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run UI Tests
  run: |
    npm start &
    sleep 5
    npm run test:ui
  
- name: Upload Screenshots
  uses: actions/upload-artifact@v3
  if: always()
  with:
    name: ui-test-screenshots
    path: test/ui/artifacts/*.png
```

## Best Practices

1. **Always start server first** - UI tests require running application
2. **Review screenshots** - Visual verification catches layout issues
3. **Use realistic test data** - Test with actual target websites
4. **Keep artifacts clean** - Auto-cleanup prevents disk bloat
5. **Test on multiple viewports** - Ensure responsive design works
6. **Handle timeouts gracefully** - Real websites can be slow

## Dependencies

- **Puppeteer** (v24.20.0) - Headless Chrome automation
- **Node.js** (v18+) - JavaScript runtime
- **Express** - Running application server

## Learn More

- **Puppeteer Documentation:** https://pptr.dev/
- **Test Documentation:** `../README.md`
- **Project Specification:** `../../SPECIFICATION.md`
