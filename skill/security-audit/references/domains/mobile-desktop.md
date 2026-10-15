# Vulnerability Reference: Mobile & Desktop Applications

_Load in Phase 1 for Mobile (Android, iOS, Flutter, React Native) or Desktop (Electron, Tauri, .NET WPF/WinUI) apps._

---

## 1. Electron & Desktop

**Electron**
- `nodeIntegration: true` in the renderer (web content runs Node code)
- `contextIsolation: false` (preload shares context with web content)
- `webSecurity: false`; `allowRunningInsecureContent: true`
- `shell.openExternal(url)` with user-controlled URLs or protocol handlers
- Unvalidated IPC (`ipcRenderer.send` data)
- No CSP in renderer windows
- `loadURL` of untrusted remote URLs

**Tauri**
- Permissive `allowlist` in `tauri.conf.json` (filesystem, shell, HTTP)
- IPC command handlers without input validation
- Missing `withGlobalTauri` scope limits
- Custom protocol handlers accepting untrusted input

**General desktop**
- Auto-update without signature verification; unsigned binaries
- Local privilege escalation via named pipes, shared memory, temp-file races
- Sensitive data left on the clipboard

## 2. Android

**Storage**
- Tokens in `SharedPreferences` unencrypted (use EncryptedSharedPreferences / Keystore)
- Unencrypted SQLite with sensitive data
- Sensitive data on external storage
- `android:allowBackup="true"` (ADB backup exposure)

**Exported components**
- Exported Activities, Services, Receivers, ContentProviders without permission checks
- Deep link `intent-filter` handlers with no authorization
- Implicit intents leaking data; PendingIntents with mutable flags

**WebView**
- `addJavascriptInterface` exposed to unverified content
- Untrusted URLs with JavaScript on
- SSL errors accepted in `WebViewClient`
- `setAllowFileAccess(true)`

**Network**
- No Network Security Config (cleartext allowed below API 28)
- No pinning for sensitive APIs; pinning bypassed via user CAs (missing `<trust-anchors>`)

## 3. iOS

**Storage**
- Credentials in `NSUserDefaults`, not Keychain
- Weak Keychain access (`kSecAttrAccessibleAlways`)
- Sensitive data not excluded from iCloud/iTunes backup
- Pasteboard readable by other apps

**Transport**
- ATS exceptions (`NSAllowsArbitraryLoads`)
- No pinning
- Custom URL scheme handlers without validation

**Binary**
- Missing or easily bypassed jailbreak detection
- Debug flags in production; no PIE
- Secrets visible via `strings` on the IPA binary

## 4. Cross-Platform Frameworks

**React Native:** bridge exposing native modules without access control; sensitive logic in the extractable JS bundle; `AsyncStorage` for secrets (unencrypted); dev menu in production; Hermes bytecode reversible.

**Flutter:** unvalidated platform-channel messages; secrets in Dart code; no root/jailbreak detection; `SharedPreferences` for secrets.

**Xamarin / .NET MAUI:** unobfuscated assemblies (ILSpy/dnSpy decompile); secrets in `app.config`/`appsettings.json`; no pinning in `HttpClient`.

## 5. Binary Hardening

| Protection | Check | Risk if missing |
|---|---|---|
| PIE/ASLR | `checksec --file=binary` | Predictable memory layout |
| Stack canaries | `checksec` | Stack overflow exploitation |
| NX/DEP | `checksec` | Code injection via executable stack |
| RELRO | `checksec` | GOT overwrite |
| Code signing | Platform-specific | Binary tampering |
| Stripped symbols | `file binary` | Debug info exposure |

## 6. Cross-Cutting

**Credentials:** hardcoded API keys; OAuth tokens in localStorage/SharedPreferences/NSUserDefaults; no token expiry or refresh rotation; biometric bypass via weak PIN fallback.

**Communication:** no or easily bypassed pinning; no mutual TLS for high-security APIs; sensitive data in URL parameters.

**Privacy:** permissions beyond need (camera, mic, location); analytics SDKs collecting undisclosed PII; no data-deletion path (GDPR erasure); screenshots and screen recording allowed on sensitive screens.
