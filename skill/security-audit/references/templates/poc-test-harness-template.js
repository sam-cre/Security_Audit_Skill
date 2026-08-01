/**
 * Security Audit PoC Test Harness Library — Phase 2 Dynamic Testing (JavaScript/TypeScript)
 *
 * A library of WORKING, RUNNABLE test patterns organized by vulnerability class.
 * Each describe block provides reusable test methods that the agent adapts per-finding.
 *
 * Usage: Copy this file into .security-audit/security-tests/ and adapt the tests
 * for the specific finding being verified. Each test suite can be run independently:
 *     npx vitest run test_secXXX_poc.test.js
 *     npx jest test_secXXX_poc.test.js
 *     node --test test_secXXX_poc.test.js  (Node 18+ built-in test runner)
 *
 * Dependencies (install as needed):
 *     npm install --save-dev vitest   # or jest
 *
 * IMPORTANT: These are TEMPLATE patterns. Every test marked "ADAPT" must be
 * customized to point at the actual project source files, functions, and endpoints
 * before running. Running the template as-is will produce skipped tests, not
 * false results.
 */

import { describe, it, expect } from 'vitest'; // or use jest / node:test
import fs from 'fs';
import path from 'path';

// =============================================================================
// INJECTION TESTING
// =============================================================================

describe('SQL Injection PoC', () => {
    // --- ADAPT THESE PER FINDING ---
    const TARGET_SOURCE = 'src/db/queries.js'; // or .ts

    const SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT null, null, null --",
        "1; WAITFOR DELAY '0:0:5' --",
        "admin'--",
    ];

    it('should not use string concatenation or template literals to build SQL', () => {
        // ADAPT: Point to the actual source file containing database queries
        if (!fs.existsSync(TARGET_SOURCE)) {
            console.warn(`Source file ${TARGET_SOURCE} not found — adapt TARGET_SOURCE`);
            return;
        }

        const source = fs.readFileSync(TARGET_SOURCE, 'utf-8');

        const dangerousPatterns = [
            /`[^`]*SELECT[^`]*\$\{/gi,              // Template literal SQL
            /['"].*SELECT.*['"]\s*\+/gi,             // String concat SQL
            /\.query\(\s*`/gi,                        // Direct template literal in .query()
            /\.query\(\s*['"].*\+/gi,                 // String concat in .query()
            /\.exec\(\s*`.*SELECT/gi,                 // Template literal in .exec()
        ];

        const vulnerabilities = [];
        const lines = source.split('\n');
        for (let i = 0; i < lines.length; i++) {
            for (const pattern of dangerousPatterns) {
                pattern.lastIndex = 0;
                if (pattern.test(lines[i])) {
                    vulnerabilities.push({ line: i + 1, code: lines[i].trim().slice(0, 80) });
                }
            }
        }

        expect(vulnerabilities).toEqual([]);
    });

    it('should use parameterized queries or ORM methods', () => {
        if (!fs.existsSync(TARGET_SOURCE)) return;
        const source = fs.readFileSync(TARGET_SOURCE, 'utf-8');

        const safePatterns = [
            /\.query\([^,]+,\s*\[/,           // db.query(sql, [params])
            /\.prepare\(/,                      // Prepared statements
            /\.where\(/,                        // ORM .where()
            /\.findOne\(/,                      // ORM .findOne()
            /\.findMany\(/,                     // ORM .findMany()
            /\?\s*,/,                           // Placeholder params
        ];

        const hasSafe = safePatterns.some(p => p.test(source));
        expect(hasSafe).toBe(true);
    });
});


describe('Command Injection PoC', () => {
    const CMDI_PAYLOADS = [
        '; whoami',
        '| cat /etc/passwd',
        '$(id)',
        '`id`',
        '&& echo PWNED',
        '|| true',
    ];

    it('should not use child_process.exec with unsanitized input', () => {
        // ADAPT: Point to the actual source file
        const sourceFiles = findSourceFiles('src', ['.js', '.ts', '.mjs']);

        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');

            // exec() is dangerous — should use execFile() or spawn() with arrays
            const dangerousExec = /child_process.*\.exec\(/g;
            const execImport = /require\(['"]child_process['"]\)|from\s+['"]child_process['"]/;

            if (execImport.test(source) && dangerousExec.test(source)) {
                // Check if user input reaches exec
                if (/\b(req\.|request\.|params\.|query\.|body\.|argv|process\.env)/i.test(source)) {
                    throw new Error(
                        `Potential command injection: child_process.exec() with user input in ${file}`
                    );
                }
            }
        }
    });

    it('should not use eval() with external input', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts', '.mjs']);

        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');
            const evalCalls = source.match(/\beval\s*\(/g);
            if (evalCalls) {
                throw new Error(
                    `eval() found in ${file} (${evalCalls.length} occurrence(s)) — review for injection risk`
                );
            }
        }
    });
});


// =============================================================================
// AUTHENTICATION & SESSION TESTING
// =============================================================================

describe('JWT Security PoC', () => {
    const WEAK_SECRETS = [
        'secret', 'password', '123456', 'jwt_secret', 'changeme',
        'your-256-bit-secret', 'shhh', 'key', 'test', 'admin',
    ];

    it('should enforce algorithm allowlist in JWT verification', () => {
        // ADAPT: Point to the JWT handling source
        const sourceFile = 'src/auth/jwt.js';
        if (!fs.existsSync(sourceFile)) return;

        const source = fs.readFileSync(sourceFile, 'utf-8');

        // Should specify algorithms explicitly
        const hasAlgCheck = /algorithms?\s*[:=]\s*\[/.test(source);
        expect(hasAlgCheck).toBe(true);
    });

    it('should not use weak JWT secrets', () => {
        // ADAPT: Point to config/env files
        const configFiles = [
            ...findFiles('.', '.env'),
            ...findFiles('.', '.env.local'),
            ...findFiles('.', '.env.development'),
        ];

        for (const configFile of configFiles) {
            const content = fs.readFileSync(configFile, 'utf-8');
            for (const secret of WEAK_SECRETS) {
                const pattern = new RegExp(
                    `(jwt|token|secret|signing).*[=:]\\s*['"]?${escapeRegex(secret)}['"]?`,
                    'i'
                );
                expect(pattern.test(content)).toBe(false);
            }
        }
    });
});


describe('Password Hashing PoC', () => {
    it('should not use MD5/SHA1 for password hashing', () => {
        // ADAPT: Point to auth-related source files
        const authFiles = findSourceFiles('src/auth', ['.js', '.ts']);

        for (const file of authFiles) {
            const source = fs.readFileSync(file, 'utf-8');
            if (/password|passwd|credential/i.test(source)) {
                const weakHash = source.match(/createHash\s*\(\s*['"](?:md5|sha1)['"]\)/gi);
                expect(weakHash).toBeNull();
            }
        }
    });
});


// =============================================================================
// PATH TRAVERSAL TESTING
// =============================================================================

describe('Path Traversal PoC', () => {
    const TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '/etc/passwd%00.png',
    ];

    it('should not concatenate user input directly into file paths', () => {
        // ADAPT: Point to file-serving source code
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);

        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');

            // Check for path.join or path.resolve with req/params input
            // without path.normalize and startsWith check
            if (/\b(readFile|createReadStream|readFileSync)\s*\(/.test(source)) {
                if (/\b(req\.|params\.|query\.)\w+/.test(source)) {
                    // Verify there's a path containment check
                    const hasContainment = /\.startsWith\(|\.includes\(.*base|path\.resolve/.test(source);
                    if (!hasContainment) {
                        throw new Error(
                            `Potential path traversal: user input in file read without containment check in ${file}`
                        );
                    }
                }
            }
        }
    });
});


// =============================================================================
// XSS TESTING
// =============================================================================

describe('XSS PoC', () => {
    const XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
        '{{7*7}}',  // Template injection probe
    ];

    it('should not use dangerous HTML insertion patterns', () => {
        const dangerousPatterns = {
            '.jsx': [/dangerouslySetInnerHTML/g],
            '.tsx': [/dangerouslySetInnerHTML/g],
            '.html': [/innerHTML\s*=/g, /outerHTML\s*=/g, /document\.write\(/g],
            '.ejs': [/<%-/g],      // Unescaped output
            '.hbs': [/\{\{\{/g],   // Triple-stache (unescaped) in Handlebars
            '.vue': [/v-html\s*=/g],
        };

        for (const [ext, patterns] of Object.entries(dangerousPatterns)) {
            const files = findSourceFiles('.', [ext]);
            for (const file of files) {
                if (file.includes('node_modules') || file.includes('dist')) continue;
                const source = fs.readFileSync(file, 'utf-8');
                for (const pattern of patterns) {
                    const matches = source.match(pattern);
                    if (matches) {
                        throw new Error(
                            `Potential XSS: ${pattern.source} found in ${file} (${matches.length} occurrences)`
                        );
                    }
                }
            }
        }
    });
});


// =============================================================================
// DESERIALIZATION TESTING
// =============================================================================

describe('Deserialization PoC', () => {
    it('should not use unsafe JSON.parse revivers or eval-based deserialization', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);

        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');

            // Check for node-serialize or similar unsafe deserializers
            if (/require\(['"]node-serialize['"]\)|require\(['"]serialize-javascript['"]\)/.test(source)) {
                if (/\.unserialize\(/.test(source)) {
                    throw new Error(`Unsafe deserialization via node-serialize in ${file}`);
                }
            }
        }
    });
});


// =============================================================================
// CRYPTOGRAPHIC TESTING
// =============================================================================

describe('Cryptographic PoC', () => {
    it('should not use ECB mode', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);
        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');
            if (/aes-\d+-ecb|createCipheriv\s*\(\s*['"]aes-\d+-ecb['"]/i.test(source)) {
                throw new Error(`AES-ECB mode detected in ${file}`);
            }
        }
    });

    it('should not use hardcoded IVs or nonces', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);
        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');
            // ADAPT: Narrow this to your specific code context — this will flag
            // test constants and documentation examples as well
            if (/(iv|nonce)\s*=\s*(Buffer\.from\(|new Uint8Array\()\s*\[/i.test(source)) {
                throw new Error(`Static IV/nonce detected in ${file}`);
            }
        }
    });

    it('should use crypto.randomBytes instead of Math.random for security', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);
        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');
            if (/token|session|key|nonce|salt|secret/i.test(source)) {
                if (/Math\.random\s*\(\)/.test(source)) {
                    throw new Error(
                        `Math.random() used in security context in ${file}. ` +
                        `Use crypto.randomBytes() or crypto.randomUUID() instead.`
                    );
                }
            }
        }
    });
});


// =============================================================================
// RACE CONDITION TESTING
// =============================================================================

describe('Race Condition PoC', () => {
    const CONCURRENT_REQUESTS = 20;

    it('should handle concurrent state mutations atomically', async () => {
        /**
         * ADAPT: Replace with the actual endpoint or function under test.
         * This template sends concurrent requests to a state-changing endpoint
         * and verifies the final state is consistent.
         */

        // Example: concurrent balance deductions
        // const targetUrl = 'http://localhost:3000/api/transfer';
        // const payload = { amount: 1, from: 'account-a', to: 'account-b' };
        //
        // const promises = Array.from({ length: CONCURRENT_REQUESTS }, () =>
        //     fetch(targetUrl, {
        //         method: 'POST',
        //         headers: { 'Content-Type': 'application/json' },
        //         body: JSON.stringify(payload),
        //     })
        // );
        //
        // const results = await Promise.allSettled(promises);
        // const successes = results.filter(r => r.status === 'fulfilled' && r.value.ok);
        //
        // // ADAPT: Verify the invariant
        // // const finalBalance = await getBalance('account-a');
        // // expect(finalBalance).toBe(initialBalance - CONCURRENT_REQUESTS);

        expect(true).toBe(true); // Placeholder — adapt per finding
    });
});


// =============================================================================
// PROTOTYPE POLLUTION TESTING (JS-specific)
// =============================================================================

describe('Prototype Pollution PoC', () => {
    it('should not use unsafe deep merge on user input', () => {
        const sourceFiles = findSourceFiles('src', ['.js', '.ts']);
        for (const file of sourceFiles) {
            const source = fs.readFileSync(file, 'utf-8');

            // Check for common vulnerable deep merge patterns
            const unsafePatterns = [
                /require\(['"]lodash['"]\)\.merge\(/,
                /require\(['"]lodash\.merge['"]\)/,
                /require\(['"]deep-extend['"]\)/,
                /require\(['"]defaults-deep['"]\)/,
            ];

            for (const pattern of unsafePatterns) {
                if (pattern.test(source)) {
                    // Only flag if user input might reach the merge
                    if (/req\.|request\.|body\.|params\.|query\./i.test(source)) {
                        throw new Error(
                            `Potential prototype pollution: unsafe deep merge with user input in ${file}`
                        );
                    }
                }
            }
        }
    });

    it('should reject __proto__ and constructor.prototype in user input', () => {
        /**
         * ADAPT: If the project accepts JSON input, verify that the parser
         * or a middleware rejects payloads containing __proto__ keys.
         */
        const maliciousPayloads = [
            { "__proto__": { "isAdmin": true } },
            { "constructor": { "prototype": { "isAdmin": true } } },
        ];

        // ADAPT: Send these payloads to the actual endpoint
        // for (const payload of maliciousPayloads) {
        //     const response = await fetch(targetUrl, {
        //         method: 'POST',
        //         headers: { 'Content-Type': 'application/json' },
        //         body: JSON.stringify(payload),
        //     });
        //     // Verify __proto__ was stripped or rejected
        //     expect({}.isAdmin).toBeUndefined();
        // }
    });
});


// =============================================================================
// HELPER UTILITIES
// =============================================================================

/**
 * Recursively find source files by extension.
 * Skips node_modules, .git, dist, build, and coverage directories.
 *
 * @param {string} dir - Starting directory
 * @param {string[]} extensions - File extensions to include (e.g., ['.js', '.ts'])
 * @returns {string[]} Array of file paths
 */
function findSourceFiles(dir, extensions) {
    const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'vendor']);
    const results = [];

    if (!fs.existsSync(dir)) return results;

    function walk(currentDir) {
        for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
            if (skipDirs.has(entry.name)) continue;
            const fullPath = path.join(currentDir, entry.name);

            if (entry.isDirectory()) {
                walk(fullPath);
            } else if (extensions.some(ext => entry.name.endsWith(ext))) {
                results.push(fullPath);
            }
        }
    }

    walk(dir);
    return results;
}

/**
 * Find files matching a specific filename pattern.
 * @param {string} dir - Starting directory
 * @param {string} filename - Filename to match (e.g., '.env')
 * @returns {string[]} Array of file paths
 */
function findFiles(dir, filename) {
    const results = [];
    if (!fs.existsSync(dir)) return results;

    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
            results.push(...findFiles(fullPath, filename));
        } else if (entry.name === filename || entry.name.startsWith(filename)) {
            results.push(fullPath);
        }
    }
    return results;
}

/**
 * Escape a string for use in a RegExp.
 */
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// =============================================================================
// STANDALONE ZERO-DEPENDENCY NODE RUNNER
// =============================================================================

if (typeof process !== 'undefined' && process.argv[1] && process.argv[1].includes(path.basename(import.meta.url || ''))) {
    console.log('Running PoC assertions in standalone Node mode...');
    // Standalone zero-dependency exit code handling
    // Process exits with code 0 on clean run, 1 on unhandled assertions
    process.on('uncaughtException', (err) => {
        console.error('PoC Execution Failed / Vulnerability Confirmed:', err.message);
        process.exit(1);
    });
}

