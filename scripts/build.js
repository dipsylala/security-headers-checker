const fs = require('fs-extra');
const path = require('path');

const BUILD_DIR = 'build';
const SOURCE_FILES = [
    'server.js',
    'package.json',
    'index.html',
    'css/',
    'js/',
    'lib/',
    'README.md'
];

const EXCLUDE_PATTERNS = [
    'test/',
    'scripts/',
    '.vscode/',
    'node_modules/',
    'build/',
    '.git/',
    '.gitignore',
    'build-and-run.bat',
    'build-and-run.ps1',
    '*.test.js',
    'integration.test.js'
];

async function build() {
    console.log('🏗️  Building WebCheck Validator...\n');

    try {
        // Clean build directory
        console.log('🧹 Cleaning build directory...');
        await fs.remove(BUILD_DIR);
        await fs.ensureDir(BUILD_DIR);
        console.log('✅ Build directory cleaned\n');

        // Copy source files
        console.log('📁 Copying application files...');
        for (const file of SOURCE_FILES) {
            const sourcePath = path.join(__dirname, '..', file);
            const destPath = path.join(__dirname, '..', BUILD_DIR, file);

            // eslint-disable-next-line no-await-in-loop
            if (await fs.pathExists(sourcePath)) {
                // eslint-disable-next-line no-await-in-loop
                await fs.copy(sourcePath, destPath, {
                    filter: (src) => {
                        // Exclude test files and development files
                        const relativePath = path.relative(path.join(__dirname, '..'), src);
                        return !EXCLUDE_PATTERNS.some(pattern =>
                            relativePath.includes(pattern) || relativePath.endsWith('.test.js')
                        );
                    }
                });
                console.log(`   ✓ Copied ${file}`);
            } else {
                console.log(`   ⚠️  Skipped ${file} (not found)`);
            }
        }
        console.log('✅ Application files copied\n');

        // Create production package.json
        console.log('📦 Creating production package.json...');
        const packageJson = await fs.readJson(path.join(__dirname, '..', 'package.json'));

        // Remove dev dependencies and scripts
        const productionPackageJson = {
            ...packageJson,
            scripts: {
                start: packageJson.scripts.start,
                serve: packageJson.scripts.serve || packageJson.scripts.start
            },
            devDependencies: undefined
        };

        await fs.writeJson(
            path.join(__dirname, '..', BUILD_DIR, 'package.json'),
            productionPackageJson,
            { spaces: 2 }
        );
        console.log('✅ Production package.json created\n');

        // Install production dependencies
        console.log('📥 Installing production dependencies...');
        const { spawn } = require('child_process');

        await new Promise((resolve, reject) => {
            const npm = spawn('npm', ['install', '--production'], {
                cwd: path.join(__dirname, '..', BUILD_DIR),
                stdio: 'inherit',
                shell: true
            });

            npm.on('close', (code) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`npm install failed with code ${code}`));
                }
            });
        });
        console.log('✅ Production dependencies installed\n');

        // Create startup script
        console.log('🚀 Creating startup scripts...');

        // Create start.bat for Windows
        const startBat = `@echo off
echo Starting WebCheck Validator...
echo.
echo The application will be available at: http://localhost:3000
echo Press Ctrl+C to stop the server
echo.
node server.js
`;
        await fs.writeFile(path.join(__dirname, '..', BUILD_DIR, 'start.bat'), startBat);

        // Create start.sh for Linux/Mac
        const startSh = `#!/bin/bash
echo "Starting WebCheck Validator..."
echo ""
echo "The application will be available at: http://localhost:3000"
echo "Press Ctrl+C to stop the server"
echo ""
node server.js
`;
        await fs.writeFile(path.join(__dirname, '..', BUILD_DIR, 'start.sh'), startSh);

        // Make start.sh executable (on Unix systems)
        try {
            await fs.chmod(path.join(__dirname, '..', BUILD_DIR, 'start.sh'), '755');
        // eslint-disable-next-line no-unused-vars
        } catch (error) {
            // Ignore chmod errors on Windows
        }

        console.log('✅ Startup scripts created\n');

        // Create deployment README
        console.log('📖 Creating deployment README...');
        const deploymentReadme = `# WebCheck Validator - Production Build

This is a production-ready build of the WebCheck Validator application.

## Quick Start

### Windows
Run: \`start.bat\`

### Linux/Mac
Run: \`./start.sh\`

### Manual Start
\`\`\`bash
npm start
\`\`\`

## Deployment

1. Upload this entire folder to your server
2. Ensure Node.js 14+ is installed
3. Run the application using one of the methods above
4. Access the application at http://localhost:3000

## Environment Variables

- \`PORT\`: Server port (default: 3000)

## Files Included

- \`server.js\`: Main application server
- \`index.html\`: Web interface
- \`css/\`: Stylesheets
- \`js/\`: Frontend JavaScript
- \`package.json\`: Production dependencies only
- \`node_modules/\`: Production dependencies
- \`start.bat\`: Windows startup script
- \`start.sh\`: Linux/Mac startup script

## Security Notes

This build includes only production files and dependencies. 
Development tools, tests, and build scripts have been excluded.
`;

        await fs.writeFile(path.join(__dirname, '..', BUILD_DIR, 'DEPLOYMENT.md'), deploymentReadme);
        console.log('✅ Deployment README created\n');

        // Build summary
        console.log('🎉 Build completed successfully!\n');
        console.log('📊 Build Summary:');
        console.log('================');

        const buildStats = await getBuildStats(path.join(__dirname, '..', BUILD_DIR));
        console.log(`📁 Build directory: ./${BUILD_DIR}/`);
        console.log(`📄 Files: ${buildStats.fileCount}`);
        console.log(`📦 Size: ${formatBytes(buildStats.totalSize)}`);
        console.log('');
        console.log('🚀 Ready for deployment!');
        console.log('');
        console.log('To test the build:');
        console.log(`   cd ${BUILD_DIR}`);
        console.log('   npm start');

    } catch (error) {
        console.error('❌ Build failed:', error.message);
        process.exit(1);
    }
}

async function getBuildStats(buildPath) {
    let fileCount = 0;
    let totalSize = 0;

    async function traverse(dir) {
        const items = await fs.readdir(dir);

        for (const item of items) {
            const itemPath = path.join(dir, item);
            // eslint-disable-next-line no-await-in-loop
            const stats = await fs.stat(itemPath);

            if (stats.isDirectory()) {
                // eslint-disable-next-line no-await-in-loop
                await traverse(itemPath);
            } else {
                fileCount++;
                totalSize += stats.size;
            }
        }
    }

    await traverse(buildPath);
    return { fileCount, totalSize };
}

function formatBytes(bytes) {
    if (bytes === 0) { return '0 Bytes'; }
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2)) } ${ sizes[i]}`;
}

// Run the build
build();
