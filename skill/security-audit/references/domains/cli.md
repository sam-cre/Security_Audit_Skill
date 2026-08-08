# Vulnerability Reference: CLI Tools & Command-Line Utilities

_Load this during Phase 1 when auditing CLI applications, terminal utilities, shell scripts, system wrappers, or developer tooling._

---

## 1. Argument & Input Injection

### Argument Injection
- User-supplied inputs passed as command arguments where flags (e.g., `--config`, `--exec`, `-o`) can alter execution behavior
- Missing delimiter (`--`) to separate positional arguments from user-controlled flag parameters
- Shell glob expansion of user input leading to unexpected file matching

### Stdin / Pipe Injection
- Processing piped input without validation or sanitization
- Trusting data from stdin as if it were user-verified (could come from another compromised process)
- Missing input length limits on stdin processing

### Configuration Injection
- Config file paths controlled by user arguments (`--config /etc/shadow`)
- Config file formats that support code execution (YAML anchors, TOML exec, JSON with `$ref`)
- Environment variable interpolation in config files without sanitization

---

## 2. Unsafe Temporary File Creation

### Predictable Paths
- Hardcoded temporary file paths (`/tmp/app_export.txt`, `/tmp/pid`) without atomic creation flags (`O_EXCL` / `O_CREAT`)
- `mktemp` not used or used incorrectly (missing `-u` flag, missing template)
- Race condition between checking file existence and creating it (TOCTOU)

### Symlink & Hardlink Attacks
- Attacker pre-creates a symlink in `/tmp` pointing to a sensitive file (`/etc/passwd`, `~/.ssh/authorized_keys`)
- CLI tool follows the symlink and overwrites the target file
- Missing `O_NOFOLLOW` flag on file opens in temp directories

### Cleanup Failures
- Temporary files containing secrets not cleaned up on abnormal exit (SIGTERM, SIGINT, crash)
- Missing signal handlers for graceful cleanup
- Temp directories left behind with world-readable permissions

---

## 3. Environment Variable Poisoning

### PATH Manipulation
- Reliance on `PATH` to resolve executable names - attacker can prepend a malicious binary
- Subprocess invocations using short names (`git`, `curl`) instead of absolute paths
- Missing PATH sanitization before subprocess execution

### Library Loading
- `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` allowing code injection into the process
- `PYTHONPATH`, `RUBYLIB`, `NODE_PATH`, `PERL5LIB` prepending malicious module directories
- DLL search order hijacking on Windows (`PATH` → current directory → system)

### Configuration Override
- Security-critical behavior controlled by environment variables without validation
- `HOME`, `XDG_CONFIG_HOME`, `USERPROFILE` manipulation to redirect config file loading
- `http_proxy` / `HTTPS_PROXY` manipulation for man-in-the-middle attacks

### Subprocess Environment
- Subprocess invocations that inherit the full parent environment (including secrets)
- Missing environment scrubbing - pass explicit minimal environment dict instead of inheriting

---

## 4. Privilege Escalation & Execution

### SUID/SGID Binaries
- Insecure SUID binaries that fail to drop privileges before executing user-controlled operations
- SUID binaries that execute other programs without absolute paths (PATH exploitation)
- Missing privilege dropping after initial privileged operation

### Sudo Wrappers
- Sudo wrapper scripts that pass user input to privileged commands without sanitization
- Wildcard usage in sudoers file entries (`/usr/bin/tool *` allows argument injection)
- Missing `--` delimiter in sudo command construction

### Signal Handler Races
- Signal handlers that leave sensitive temporary files behind
- Race conditions in lock file / PID file management during concurrent execution
- SIGCHILD handler not properly cleaning up child processes (zombie processes)

---

## 5. Output & Logging Safety

### Terminal Injection
- ANSI escape sequence injection in CLI output (terminal command execution via `\e]` sequences)
- Log files containing user-controlled data rendered in terminal (escape sequences execute)
- Missing output sanitization for terminal-rendered content

### Sensitive Data in Output
- Passwords, tokens, or API keys printed to stdout/stderr
- Debug output containing internal paths, memory addresses, or system information
- Missing `--quiet` / `--no-color` flags for CI/CD environments where output is logged

---

## 6. File System Operations

### Path Traversal
- User-supplied file paths not validated against traversal (`../../../etc/passwd`)
- Missing canonicalization of paths before access checks
- Archive extraction (tar, zip) without path validation (Zip Slip vulnerability)

### Permission Issues
- Creating files/directories with overly permissive modes (0777, world-readable)
- Missing umask setting before file creation
- Following symbolic links when reading/writing files in shared directories

---

## 7. Network Operations (If Applicable)

### Download Safety
- Downloading resources over HTTP instead of HTTPS
- Missing integrity verification (checksum, GPG signature) on downloaded files
- Missing TLS certificate verification on HTTPS connections
- Auto-executing downloaded content (e.g., `curl | sh` pattern without verification)

### API Communication
- API keys passed as command-line arguments (visible in process listing via `ps`)
- Missing timeout on network requests (hangs indefinitely)
- DNS rebinding vulnerability in tools that validate hostnames then connect
