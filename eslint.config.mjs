import js from '@eslint/js';

export default [
    js.configs.recommended,
    {
        ignores: [
            'node_modules/**',
            'build/**',
            'dist/**',
            'coverage/**',
            '*.min.js',
            '.git/**',
            '.vscode/**',
            'package-lock.json',
            '**/*-broken.js',
            '**/*-fixed.js',
            'eslint.config.mjs'
        ]
    },
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                console: 'readonly',
                process: 'readonly',
                Buffer: 'readonly',
                __dirname: 'readonly',
                __filename: 'readonly',
                module: 'readonly',
                require: 'readonly',
                exports: 'readonly',
                global: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                setInterval: 'readonly',
                clearInterval: 'readonly',
                URL: 'readonly'
            }
        },
        rules: {
            // Possible Errors
            'no-console': 'off', // We use console for logging in this app
            'no-debugger': 'error',
            'no-alert': 'error',
            'no-await-in-loop': 'warn',
            'no-duplicate-imports': 'error',
            'no-template-curly-in-string': 'warn',
            'no-unreachable-loop': 'error',
            'no-unused-private-class-members': 'error',
            
            // Best Practices
            'curly': ['error', 'all'],
            'default-case': 'error',
            'dot-notation': 'error',
            'eqeqeq': ['error', 'always'],
            'no-empty-function': 'warn',
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-magic-numbers': 'off', // Disabled - many legitimate uses in security analysis
            'no-multi-spaces': 'error',
            'no-new': 'error',
            'no-new-func': 'error',
            'no-new-wrappers': 'error',
            'no-return-assign': 'error',
            'no-self-compare': 'error',
            'no-throw-literal': 'error',
            'no-unused-expressions': 'error',
            'no-useless-concat': 'error',
            'no-useless-return': 'error',
            'prefer-promise-reject-errors': 'error',
            'require-await': 'warn',
            
            // Variables
            'no-unused-vars': ['error', { 
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_'
            }],
            'no-use-before-define': ['error', { 
                functions: false,
                classes: true,
                variables: true
            }],
            
            // Stylistic Issues
            'array-bracket-spacing': ['error', 'never'],
            'block-spacing': 'error',
            'brace-style': ['error', '1tbs', { allowSingleLine: true }],
            'comma-dangle': ['error', 'never'],
            'comma-spacing': ['error', { before: false, after: true }],
            'comma-style': ['error', 'last'],
            'computed-property-spacing': ['error', 'never'],
            'func-call-spacing': ['error', 'never'],
            'indent': ['error', 4, { SwitchCase: 1 }],
            'key-spacing': ['error', { beforeColon: false, afterColon: true }],
            'keyword-spacing': ['error', { before: true, after: true }],
            'linebreak-style': ['error', 'windows'], // Adjust for Windows
            'max-len': ['warn', { 
                code: 120,
                tabWidth: 4,
                ignoreUrls: true,
                ignoreStrings: true,
                ignoreTemplateLiterals: true,
                ignoreRegExpLiterals: true
            }],
            'no-multiple-empty-lines': ['error', { max: 2, maxEOF: 1 }],
            'no-trailing-spaces': 'error',
            'object-curly-spacing': ['error', 'always'],
            'quotes': ['error', 'single', { allowTemplateLiterals: true }],
            'semi': ['error', 'always'],
            'semi-spacing': ['error', { before: false, after: true }],
            'space-before-blocks': 'error',
            'space-before-function-paren': ['error', {
                anonymous: 'never',
                named: 'never',
                asyncArrow: 'always'
            }],
            'space-in-parens': ['error', 'never'],
            'space-infix-ops': 'error',
            'space-unary-ops': ['error', { words: true, nonwords: false }],
            
            // ES6
            'arrow-spacing': ['error', { before: true, after: true }],
            'constructor-super': 'error',
            'no-const-assign': 'error',
            'no-dupe-class-members': 'error',
            'no-duplicate-imports': 'error',
            'no-new-symbol': 'error',
            'no-this-before-super': 'error',
            'no-var': 'error',
            'prefer-const': 'error',
            'prefer-spread': 'error',
            'prefer-template': 'warn',
            'require-yield': 'error'
        }
    },
    {
        // Browser files configuration
        files: ['js/**/*.js'],
        languageOptions: {
            globals: {
                document: 'readonly',
                window: 'readonly',
                alert: 'readonly',
                fetch: 'readonly',
                URL: 'readonly',
                Blob: 'readonly',
                XLSX: 'readonly'
            }
        },
        rules: {
            'no-alert': 'off', // Allow alerts in frontend code
            'no-magic-numbers': 'off' // Allow magic numbers in frontend
        }
    },
    {
        // Test files configuration
        files: ['test/**/*.js', '**/*.test.js'],
        rules: {
            'no-magic-numbers': 'off', // Allow magic numbers in tests
            'max-len': ['warn', { code: 150 }], // Longer lines allowed in tests
            'no-unused-expressions': 'off', // Allow assertions like expect(foo).to.be.true
            'no-await-in-loop': 'off' // Allow await in loops for sequential test execution
        }
    },
    {
        // Configuration files
        files: ['eslint.config.js', '*.config.js'],
        rules: {
            'no-magic-numbers': 'off'
        }
    }
];
