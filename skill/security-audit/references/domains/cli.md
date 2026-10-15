# Vulnerability Reference: CLI Tools & Command-Line Utilities

_Load in Phase 1 for CLI apps, terminal utilities, shell scripts, system wrappers, or developer tooling._

---

## 1. Argument & Input Injection

- User input passed as command arguments where flags (`--config`, `--exec`, `-o`) alter behavior; no `--` delimiter between flags and user-controlled positionals
- Shell glob expansion of user input
- Piped stdin processed unvalidated or trusted as verified (it may come from a compromised process); no length limit
- Config path controlled by arguments (`--config /etc/shadow`)
- Config formats that can execute code (YAML anchors, TOML exec, JSON `$ref`); env-var interpolation in config unsanitized

## 2. Temporary Files

- Predictable paths (`/tmp/app_export.txt`, `/tmp/pid`) without atomic creation (`O_EXCL`/`O_CREAT`); `mktemp` unused or misused
- TOCTOU between existence check and create
- Symlink/hardlink attack: attacker pre-creates a symlink in `/tmp` to a sensitive file (`/etc/passwd`, `~/.ssh/authorized_keys`) and the tool overwrites it; no `O_NOFOLLOW`
- Temp files with secrets not cleaned on SIGTERM, SIGINT, or crash; no signal handlers; world-readable temp dirs left behind

## 3. Environment Poisoning

- **PATH:** executables resolved via `PATH`; subprocesses use short names (`git`, `curl`) not absolute paths; PATH not sanitized
- **Library loading:** `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`; `PYTHONPATH`, `RUBYLIB`, `NODE_PATH`, `PERL5LIB` prepending hostile module dirs; Windows DLL search-order hijacking (`PATH`, then current directory, then system)
- **Config override:** security behavior driven by unvalidated env vars; `HOME`, `XDG_CONFIG_HOME`, `USERPROFILE` redirecting config; `http_proxy`/`HTTPS_PROXY` enabling MITM
- **Subprocess env:** children inherit the full environment, secrets included. Pass an explicit minimal env.

## 4. Privilege & Execution

- **SUID/SGID:** no privilege drop before user-controlled work; executes programs without absolute paths; no drop after the privileged step
- **Sudo wrappers:** user input passed to privileged commands unsanitized; wildcards in sudoers (`/usr/bin/tool *` allows argument injection); missing `--`
- **Signal/lock races:** handlers leaving sensitive temp files; lock/PID file races; SIGCHLD not reaping children

## 5. Output & Logging

- ANSI escape injection (`\e]` sequences can run terminal commands), including user data in logs viewed in a terminal; no output sanitization
- Passwords, tokens, or keys printed to stdout/stderr; debug output with paths, addresses, system info
- No `--quiet`/`--no-color` for logged CI output

## 6. File System

- Paths not checked for traversal (`../../../etc/passwd`); no canonicalization before access checks
- Archive extraction without path validation (Zip Slip)
- Files created with loose modes (0777, world-readable); no umask; symlinks followed in shared directories

## 7. Network (if applicable)

- Downloads over HTTP; no checksum or GPG verification; TLS verification off; auto-executing downloads (`curl | sh`)
- API keys as command-line arguments (visible in `ps`)
- No network timeouts
- DNS rebinding in tools that validate a hostname, then connect
