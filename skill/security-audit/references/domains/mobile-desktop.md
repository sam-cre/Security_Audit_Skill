# Vulnerability Reference: Mobile & Desktop Applications

_Load this during Phase 1 when auditing Mobile (Android/iOS/Flutter/React Native) or Desktop (Electron, Tauri, .NET WPF/WinUI) applications._

---

## 1. Electron & Desktop Frameworks

### Electron Security
- `nodeIntegration: true` in renderer process (allows arbitrary Node.js code execution from web content)
- `contextIsolation: false` (preload scripts share context with web content)
- `webSecurity: false` disabling same-origin policy
- Insecure `shell.openExternal(url)` with user-controlled URLs or protocol handlers
- Unsanitized IPC messages between main and renderer processes (`ipcRenderer.send` with unvalidated data)
- Missing CSP in Electron renderer windows
- `allowRunningInsecureContent: true` mixing HTTPS with HTTP resources
- Remote code loading (`loadURL` with untrusted remote URLs)

### Tauri Security
- Overly permissive `allowlist` in `tauri.conf.json` (file system access, shell execution, HTTP requests)
- IPC command handlers without input validation
- Missing `withGlobalTauri` scope restrictions
- Custom protocol handlers accepting untrusted input

### General Desktop
- Auto-update mechanism without signature verification
- Missing code signing on distributed binaries
- Local privilege escalation via named pipes, shared memory, or temp file race conditions
- Clipboard data exposure (sensitive data copied to clipboard accessible to other apps)

---

## 2. Mobile Security (Android)

### Data Storage
- Credentials/tokens stored in `SharedPreferences` without encryption (use EncryptedSharedPreferences / Android Keystore)
- Unencrypted SQLite databases containing sensitive data
- Sensitive data in app's external storage (world-readable on older Android versions)
- Backup enabled (`android:allowBackup="true"`) exposing app data via ADB backup

### Exported Components
- Exported Activities, Services, BroadcastReceivers, or ContentProviders without permission checks
- Deep link handlers (`intent-filter`) operating without authorization validation
- Implicit intents leaking sensitive data to other apps
- Pending intents with mutable flags allowing intent modification

### WebView Security
- `addJavascriptInterface` exposing native Java methods to unverified web content
- WebView loading untrusted URLs with JavaScript enabled
- Missing SSL error handling in WebViewClient (accepting invalid certificates)
- File access enabled in WebView (`setAllowFileAccess(true)`)

### Network Security
- Missing Network Security Config (cleartext traffic allowed by default on API < 28)
- Missing certificate pinning for sensitive API connections
- Certificate pinning bypass via user-installed CA certificates (missing `<trust-anchors>` config)

---

## 3. Mobile Security (iOS)

### Data Storage
- Credentials stored in `NSUserDefaults` instead of Keychain
- Keychain items with weak access control (`kSecAttrAccessibleAlways`)
- Sensitive data not excluded from iCloud/iTunes backup
- Pasteboard (clipboard) data accessible to other apps

### App Transport Security
- ATS exceptions (`NSAllowsArbitraryLoads`) disabling TLS requirements
- Missing certificate pinning implementation
- Custom URL scheme handlers without input validation

### Binary Protection
- Missing jailbreak detection (or easily bypassed detection)
- Debug flags enabled in production build
- Missing PIE (Position Independent Executable) compilation
- Sensitive strings visible via `strings` on the IPA binary

---

## 4. Cross-Platform Framework Security

### React Native
- JavaScript bridge exposing native modules without access control
- Sensitive logic in JavaScript bundle (extractable and modifiable)
- AsyncStorage used for sensitive data (unencrypted by default)
- Debug mode / dev menu accessible in production builds
- Hermes bytecode reversible to readable JavaScript

### Flutter
- Platform channel message handling without input validation
- Sensitive data in Dart code (compilable to readable format)
- Missing root/jailbreak detection
- SharedPreferences used for sensitive data without encryption

### Xamarin / .NET MAUI
- Assembly not obfuscated (ILSpy/dnSpy can decompile to source)
- Sensitive data in `app.config` or `appsettings.json` bundled in app
- Missing certificate pinning in HttpClient

---

## 5. Binary Hardening Verification

For compiled desktop/mobile binaries, verify:

| Protection | Check Command | Risk if Missing |
|---|---|---|
| **PIE/ASLR** | `checksec --file=binary` | Predictable memory layout → easier exploitation |
| **Stack Canaries** | `checksec --file=binary` | Stack buffer overflow exploitation |
| **NX/DEP** | `checksec --file=binary` | Executable stack → code injection |
| **RELRO** | `checksec --file=binary` | GOT overwrite attacks |
| **Code Signing** | Platform-specific verification | Binary tampering |
| **Stripped Symbols** | `file binary` | Debug information exposure |

---

## 6. Common Cross-Cutting Issues

### Credential Management
- API keys hardcoded in source code or resource files
- OAuth tokens stored insecurely (localStorage, SharedPreferences, NSUserDefaults)
- Missing token expiration or refresh token rotation
- Biometric authentication bypass via fallback to weak PIN/password

### Communication Security
- Certificate pinning not implemented or easily bypassable
- Missing mutual TLS for high-security API connections
- Sensitive data in URL parameters (logged by proxies, web servers, browser history)

### Privacy
- Excessive permission requests (camera, microphone, location) beyond app requirements
- Analytics/tracking SDKs collecting PII without disclosure
- Missing data deletion capability (GDPR right to erasure)
- Screenshots/screen recording not prevented for sensitive screens
