"""
Security Audit PoC Test Harness Library — Phase 3 Dynamic Testing

A library of WORKING, RUNNABLE test patterns organized by vulnerability class.
Each class provides reusable test methods that the agent adapts per-finding.

Usage: Copy this file into .security-audit/security-tests/ and adapt the test methods
for the specific finding being verified. Each test class can be run independently:
    python -m pytest test_secXXX_poc.py -v
    python -m unittest test_secXXX_poc.TestSQLInjectionPoC -v
"""

import hashlib
import json
import os
import re
import sys
import threading
import time
import unittest
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import MagicMock, patch


# =============================================================================
# INJECTION TESTING
# =============================================================================

class TestSQLInjectionPoC(unittest.TestCase):
    """
    Verifies whether a function is vulnerable to SQL injection by testing
    string-concatenated queries vs. parameterized queries.
    """

    # --- ADAPT THESE PER FINDING ---
    TARGET_MODULE = None  # e.g., "src.db.queries"
    TARGET_FUNCTION = None  # e.g., "find_user"

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT null, null, null --",
        "1; WAITFOR DELAY '0:0:5' --",      # Time-based blind
        "' AND SUBSTRING(@@version,1,1)='M",  # Fingerprinting
        "admin'--",
    ]

    def test_string_concat_detection(self):
        """
        Direct source code analysis: check if the target function uses
        string concatenation or f-strings to build SQL queries.
        """
        # ADAPT: Point to the actual source file
        source_file = Path("src/db/queries.py")
        if not source_file.exists():
            self.skipTest(f"Source file {source_file} not found")

        source = source_file.read_text()

        dangerous_patterns = [
            r'f["\'].*SELECT.*\{',           # f-string SQL
            r'["\'].*SELECT.*["\']\s*\+',    # String concat SQL
            r'\.format\(.*SELECT',            # .format() SQL
            r'%s.*%\s*\(',                    # % formatting SQL
            r'execute\(\s*f["\']',            # Direct f-string execute
        ]

        vulnerabilities = []
        for i, line in enumerate(source.splitlines(), 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append((i, line.strip()))

        self.assertEqual(
            len(vulnerabilities), 0,
            f"SQL injection risk: string-built queries at lines: "
            f"{[f'L{ln}: {code[:80]}' for ln, code in vulnerabilities]}"
        )

    def test_parameterized_query_usage(self):
        """
        Verify the target function uses parameterized queries (?, %s placeholders
        passed as separate arguments) rather than string interpolation.
        """
        source_file = Path("src/db/queries.py")
        if not source_file.exists():
            self.skipTest(f"Source file {source_file} not found")

        source = source_file.read_text()

        safe_patterns = [
            r'execute\([^,]+,\s*[\[\(]',     # cursor.execute(query, [params])
            r'\.where\(',                      # ORM .where()
            r'\.filter\(',                     # ORM .filter()
        ]

        has_safe_query = any(re.search(p, source) for p in safe_patterns)
        self.assertTrue(has_safe_query, "No parameterized query pattern detected")


class TestCommandInjectionPoC(unittest.TestCase):
    """
    Verifies whether user input reaches shell execution without sanitization.
    """

    CMDI_PAYLOADS = [
        "; whoami",
        "| cat /etc/passwd",
        "$(id)",
        "`id`",
        "&& echo PWNED",
        "\n/bin/sh",
        "|| true",
    ]

    def test_subprocess_uses_shell_false(self):
        """Verify subprocess calls use shell=False (list form, not string)."""
        source_file = Path("src/utils/runner.py")
        if not source_file.exists():
            self.skipTest(f"Source file {source_file} not found")

        source = source_file.read_text()

        dangerous = re.findall(
            r'subprocess\.\w+\(.*shell\s*=\s*True', source, re.DOTALL
        )
        self.assertEqual(
            len(dangerous), 0,
            f"Found {len(dangerous)} subprocess calls with shell=True"
        )

    def test_os_system_absence(self):
        """Verify os.system() is not used (always unsafe with user input)."""
        source_file = Path("src/utils/runner.py")
        if not source_file.exists():
            self.skipTest(f"Source file {source_file} not found")

        source = source_file.read_text()
        matches = re.findall(r'os\.system\(', source)
        self.assertEqual(len(matches), 0, "os.system() found — always a risk")


# =============================================================================
# AUTHENTICATION & SESSION TESTING
# =============================================================================

class TestJWTSecurityPoC(unittest.TestCase):
    """
    Tests for JWT algorithm confusion, none-algorithm bypass, and weak secrets.
    """

    WEAK_SECRETS = [
        "secret", "password", "123456", "jwt_secret", "changeme",
        "your-256-bit-secret", "shhh", "key", "test", "admin",
    ]

    def test_alg_none_bypass(self):
        """
        Construct a JWT with alg:none and verify the application rejects it.
        ADAPT: Replace verify_token with the project's actual JWT verification function.
        """
        import base64

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b'=').decode()

        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "role": "admin", "iat": int(time.time())}).encode()
        ).rstrip(b'=').decode()

        forged_token = f"{header}.{payload}."

        # ADAPT: Call the project's token verification
        # result = verify_token(forged_token)
        # self.assertFalse(result.valid, "JWT alg:none token was accepted!")

        # Static check: verify the code enforces algorithm allowlist
        source_file = Path("src/auth/jwt_handler.py")
        if source_file.exists():
            source = source_file.read_text()
            has_alg_check = bool(re.search(
                r'algorithms?\s*=\s*\[', source
            ))
            self.assertTrue(
                has_alg_check,
                "JWT decode does not specify an algorithms allowlist"
            )

    def test_weak_secret_detection(self):
        """Check if JWT signing key is a commonly-guessed weak secret."""
        # ADAPT: Point to config/env where the JWT secret is defined
        config_files = list(Path(".").rglob("*.env*")) + list(Path(".").rglob("config.*"))

        for config in config_files:
            if config.stat().st_size > 1_000_000:
                continue
            content = config.read_text(errors='ignore')
            for secret in self.WEAK_SECRETS:
                pattern = rf'(?i)(jwt|token|secret|signing).*[=:]\s*[''"]?{re.escape(secret)}[''"]?'
                if re.search(pattern, content):
                    self.fail(
                        f"Weak JWT secret '{secret}' found in {config}"
                    )


class TestPasswordHashingPoC(unittest.TestCase):
    """Verify password hashing uses bcrypt/scrypt/argon2 with proper salting."""

    def test_no_md5_sha1_for_passwords(self):
        """Ensure MD5/SHA1 are not used for password hashing."""
        # ADAPT: Point to auth-related source files
        auth_files = list(Path("src/auth").rglob("*.py")) if Path("src/auth").exists() else []

        for f in auth_files:
            source = f.read_text(errors='ignore')
            # Only flag if context suggests password/credential usage
            if re.search(r'(?i)(password|passwd|credential)', source):
                bad_hash = re.findall(
                    r'(hashlib\.(md5|sha1)|MD5|SHA1)\s*\(', source
                )
                self.assertEqual(
                    len(bad_hash), 0,
                    f"Weak hash for passwords in {f}: {bad_hash}"
                )

    def test_salt_uniqueness(self):
        """
        If we can invoke the hash function, verify that hashing the same
        password twice produces different outputs (proves unique salting).
        """
        # ADAPT: Import and call the project's password hashing function
        # hash1 = hash_password("test_password_123")
        # hash2 = hash_password("test_password_123")
        # self.assertNotEqual(hash1, hash2, "Same password produced identical hashes — no salting")
        pass


# =============================================================================
# PATH TRAVERSAL TESTING
# =============================================================================

class TestPathTraversalPoC(unittest.TestCase):
    """Tests for directory traversal and arbitrary file read/write."""

    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd%00.png",
        "....\\\\....\\\\etc\\\\passwd",
    ]

    def test_path_normalization(self):
        """
        Verify the application normalizes paths and rejects traversal attempts.
        ADAPT: Replace with the project's file-serving function.
        """
        # ADAPT: Call the function that resolves user-supplied file paths
        # for payload in self.TRAVERSAL_PAYLOADS:
        #     resolved = resolve_file_path(payload)
        #     self.assertTrue(
        #         resolved.startswith(ALLOWED_BASE_DIR),
        #         f"Path traversal succeeded with payload: {payload} -> {resolved}"
        #     )

        # Static analysis: check for raw path concatenation
        source_files = list(Path("src").rglob("*.py")) if Path("src").exists() else []
        for f in source_files:
            source = f.read_text(errors='ignore')
            if re.search(r'open\(\s*[^)]*\+.*\breq', source, re.IGNORECASE):
                self.fail(
                    f"Potential path traversal: raw concatenation of user input in open() at {f}"
                )


# =============================================================================
# RACE CONDITION TESTING
# =============================================================================

class TestRaceConditionPoC(unittest.TestCase):
    """
    Tests for TOCTOU and race conditions using concurrent execution.
    """

    CONCURRENT_THREADS = 20
    ITERATIONS = 50

    def test_concurrent_state_mutation(self):
        """
        Send concurrent requests to a state-changing operation and verify
        the final state is consistent (no double-spend, no count skew).

        ADAPT: Replace the target_operation with the actual function under test.
        """
        results = []
        errors = []

        def target_operation(thread_id):
            """ADAPT: Replace with the actual state-changing operation."""
            # Example: balance deduction, resource allocation, counter increment
            # response = requests.post(f"{TARGET}/api/transfer", json={"amount": 1})
            # return response.status_code
            return 200  # Placeholder

        with ThreadPoolExecutor(max_workers=self.CONCURRENT_THREADS) as executor:
            futures = {
                executor.submit(target_operation, i): i
                for i in range(self.ITERATIONS)
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    errors.append(str(e))

        # ADAPT: Verify the invariant that should hold
        # e.g., final_balance = get_balance()
        # self.assertEqual(final_balance, initial_balance - ITERATIONS,
        #     f"Race condition: expected balance {initial_balance - ITERATIONS}, got {final_balance}")

        success_count = results.count(200)
        self.assertGreater(success_count, 0, "No successful concurrent requests")

    def test_file_toctou(self):
        """
        Test for Time-of-Check-to-Time-of-Use on file operations.
        Checks if access control check and file operation are atomic.
        """
        # CAUTION: This heuristic (exists() followed by open() within 5 lines)
        # is an extremely common SAFE pattern and will produce many false positives.
        # Only use this when you've already identified a specific TOCTOU-suspicious
        # code path from Phase 1 — narrow source_files to that specific file.
        # ADAPT: Point to code that checks file existence/permissions then reads
        source_files = list(Path("src").rglob("*.py")) if Path("src").exists() else []
        for f in source_files:
            source = f.read_text(errors='ignore')
            lines = source.splitlines()
            for i, line in enumerate(lines):
                if re.search(r'os\.path\.exists|os\.access|Path.*\.exists\(\)', line):
                    # Check if the next few lines use the same path in open()/read()
                    context = "\n".join(lines[i:i+5])
                    if re.search(r'open\(|\.read\(|shutil\.\w+\(', context):
                        self.fail(
                            f"TOCTOU pattern: existence check then file op at {f}:L{i+1}"
                        )


# =============================================================================
# DESERIALIZATION TESTING
# =============================================================================

class TestDeserializationPoC(unittest.TestCase):
    """Tests for unsafe deserialization of untrusted data."""

    def test_no_pickle_loads_on_untrusted(self):
        """Verify pickle.loads is not called on user-supplied data."""
        # CAUTION: The "untrusted source" check below (request|recv|read|stdin|argv)
        # is very broad — it will match safe method names like read_config(),
        # file_reader, etc. that have nothing to do with untrusted input.
        # ADAPT: Narrow the source_files to the specific file(s) identified in
        # Phase 1, and verify the actual data flow from source to pickle.loads().
        source_files = list(Path(".").rglob("*.py"))
        for f in source_files:
            if 'test' in str(f).lower() or 'venv' in str(f).lower():
                continue
            source = f.read_text(errors='ignore')
            if 'pickle.loads' in source or 'pickle.load(' in source:
                # Check if the input comes from an untrusted source
                if re.search(r'(request|recv|read|stdin|argv)', source, re.IGNORECASE):
                    self.fail(f"Unsafe pickle deserialization of untrusted input in {f}")

    def test_yaml_safe_load(self):
        """Verify yaml.safe_load is used instead of yaml.load."""
        source_files = list(Path(".").rglob("*.py"))
        for f in source_files:
            if 'test' in str(f).lower() or 'venv' in str(f).lower():
                continue
            source = f.read_text(errors='ignore')
            unsafe_yaml = re.findall(r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', source)
            if unsafe_yaml:
                self.fail(f"Unsafe yaml.load (no SafeLoader) in {f}")


# =============================================================================
# XSS TESTING
# =============================================================================

class TestXSSPoC(unittest.TestCase):
    """Tests for cross-site scripting through output encoding verification."""

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        '<iframe src="javascript:alert(1)">',
        "'-alert(1)-'",
        '{{7*7}}',  # Template injection probe
    ]

    def test_no_raw_html_insertion(self):
        """
        Check for dangerous HTML insertion patterns in template/frontend code.
        """
        dangerous_patterns = {
            '.html': [r'innerHTML\s*=', r'outerHTML\s*=', r'document\.write\('],
            '.jsx': [r'dangerouslySetInnerHTML'],
            '.tsx': [r'dangerouslySetInnerHTML'],
            '.py': [r'Markup\(', r'\|safe', r'autoescape\s*=\s*False'],
            '.jinja': [r'\|safe', r'{% autoescape false %}'],
            '.ejs': [r'<%-'],  # Unescaped output in EJS
        }

        for ext, patterns in dangerous_patterns.items():
            for f in Path(".").rglob(f"*{ext}"):
                if 'node_modules' in str(f) or 'venv' in str(f):
                    continue
                source = f.read_text(errors='ignore')
                for pattern in patterns:
                    matches = re.findall(pattern, source)
                    if matches:
                        self.fail(
                            f"Potential XSS: {pattern} found in {f} ({len(matches)} occurrences)"
                        )


# =============================================================================
# CRYPTOGRAPHIC TESTING
# =============================================================================

class TestCryptographicPoC(unittest.TestCase):
    """Tests for cryptographic implementation flaws."""

    def test_no_ecb_mode(self):
        """Verify AES-ECB is not used (identical plaintext blocks = identical ciphertext)."""
        source_files = list(Path(".").rglob("*.py"))
        for f in source_files:
            if 'test' in str(f).lower() or 'venv' in str(f).lower():
                continue
            source = f.read_text(errors='ignore')
            if re.search(r'MODE_ECB|AES\.ECB|ecb', source, re.IGNORECASE):
                if not re.search(r'#.*test|#.*example|#.*legacy', source.splitlines()[0] if source else '', re.IGNORECASE):
                    self.fail(f"AES-ECB mode detected in {f}")

    def test_no_static_iv(self):
        """Check for hardcoded IVs/nonces in crypto operations."""
        # CAUTION: This pattern is broad and WILL produce false positives on test
        # constants, documentation examples, and config defaults. ADAPT the file
        # list and pattern to your specific finding's source file before running.
        # Do NOT run this as-is against an entire project.
        source_files = list(Path(".").rglob("*.py"))
        for f in source_files:
            if 'test' in str(f).lower() or 'venv' in str(f).lower():
                continue
            source = f.read_text(errors='ignore')
            # Hardcoded byte strings assigned to iv/nonce variables
            if re.search(r"(?i)(iv|nonce)\s*=\s*(b['\"]|bytes\()", source):
                self.fail(f"Static IV/nonce detected in {f}")

    def test_csprng_usage(self):
        """Verify security-sensitive randomness uses os.urandom or secrets module."""
        source_files = list(Path(".").rglob("*.py"))
        for f in source_files:
            if 'test' in str(f).lower() or 'venv' in str(f).lower():
                continue
            source = f.read_text(errors='ignore')
            if re.search(r'(?i)(token|session|key|nonce|salt)', source):
                if re.search(r'random\.(randint|choice|random|randrange)\(', source):
                    self.fail(
                        f"Non-CSPRNG random used in security context in {f}. "
                        f"Use secrets or os.urandom instead."
                    )


# =============================================================================
# STANDALONE ZERO-DEPENDENCY RUNNER
# =============================================================================

if __name__ == "__main__":
    # Standard zero-dependency runner. Communicates verdict via exit code:
    # 0 = Pass / Vulnerability Mitigated
    # 1 = Fail / Vulnerability Confirmed Exploitable
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

