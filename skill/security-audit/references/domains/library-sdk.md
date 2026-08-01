# Vulnerability Reference: Libraries, SDKs & Packages

_Load this during Phase 1 when auditing published libraries, SDKs, client packages, reusable modules, or framework plugins._

---

## 1. Insecure Defaults & API Surface

### Dangerous Defaults
- SSL/TLS verification disabled by default (`verify=False`, `rejectUnauthorized: false`)
- Permissive CORS helpers enabled by default
- Debug/verbose logging enabled by default
- Authentication optional by default (secure behavior requires opt-in)
- Unsafe deserialization enabled by default

### Public API Safety
- Public functions accepting raw strings where structured, type-safe inputs should be required
- Missing input validation on exported function parameters
- Error messages exposing internal implementation details
- API methods that silently ignore invalid parameters instead of throwing

### Breaking Change Safety
- Major version bumps changing security-relevant behavior without migration warnings
- Deprecated APIs with insecure defaults still functional
- Missing security advisories for known vulnerability patterns in older versions

---

## 2. Supply Chain Attack Vectors

### Typosquatting & Dependency Confusion
- Package name similar to popular packages (e.g., `reqeusts` vs `requests`)
- Internal package names that could collide with public registry names
- Missing `.npmrc` / `pip.conf` scoping to prevent dependency confusion
- Pre/post-install scripts executing arbitrary code during `npm install` / `pip install`

### Lockfile Integrity
- Missing lockfile (`package-lock.json`, `yarn.lock`, `poetry.lock`, `Cargo.lock`)
- Lockfile not committed to version control (builds not reproducible)
- Lockfile integrity hash mismatches ignored during install
- Mixed registry sources in lockfile (some packages from untrusted registries)

### Build Reproducibility
- Non-deterministic build outputs (different binary each build)
- Build-time dependencies not pinned
- Missing provenance attestation (SLSA framework compliance)
- Publishing automation without 2FA or signing

---

## 3. Resource Exhaustion & DoS

### Regular Expression Safety (ReDoS)
- Catastrophic backtracking in regex patterns exposed via public validation functions
- Unbounded input passed to regex matching without length limits
- Common vulnerable patterns: nested quantifiers (`(a+)+`), overlapping alternation

### Memory & CPU
- Unbounded array/buffer allocations based on caller-supplied parameters
- Missing size limits on input processing (e.g., parsing arbitrarily large JSON/XML)
- CPU-intensive operations without timeout or cancellation support
- Recursive processing without depth limits (stack overflow via deep nesting)

---

## 4. Callback, Hook & Plugin Security

### Callback Safety
- User-supplied callbacks executed without error isolation (unhandled exception crashes host)
- Callbacks invoked with elevated privileges or access to internal state
- Missing timeout on callback execution (hanging callback blocks library)

### Plugin / Extension Systems
- Plugin code executed without sandboxing
- Plugin access to host application's full memory/state
- Missing plugin signature verification
- Plugin registration without capability/permission scoping

### Type Safety
- Prototype pollution via public helper/merge functions (`__proto__`, `constructor.prototype`)
- Type confusion enabling privilege escalation or code execution
- Unsafe type coercion in public APIs (string → number → different behavior)

---

## 5. Information Exposure

### Error & Debug Leakage
- Stack traces containing internal file paths, function names, or dependency versions
- Error objects exposing database connection strings or API keys
- Verbose logging that can't be disabled by the consuming application

### Metadata Leakage
- Package metadata (package.json, setup.py) containing internal URLs, email addresses, or infrastructure details
- README/documentation containing example credentials that are actually real
- `.npmignore` / `.gitignore` missing entries for test fixtures containing secrets

---

## 6. Cryptographic Library Concerns

### Implementation Safety
- Non-constant-time comparison functions for security tokens (timing attack)
- Custom cryptographic implementations instead of using established libraries
- Weak default parameters (short key sizes, insufficient rounds)
- Missing secure memory wiping after cryptographic operations

### Key Management
- API keys or secrets stored in library source code or test fixtures
- Example code showing insecure patterns that developers copy-paste
- Default encryption keys shipped with the library
