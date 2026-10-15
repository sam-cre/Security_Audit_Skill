# Domain: Browser Extensions

_Load when the project has a `manifest.json` with `content_scripts`, `background`/`service_worker`, or WebExtension API use (Chrome, Edge, Firefox, Safari)._

Extensions run with privileges no web page has, inside every page the user visits. A compromised extension compromises every site the user is logged into.

---

## 1. Manifest & Permissions

- `<all_urls>` or `*://*/*` where a narrow list would do (the most common over-privilege)
- `permissions` beyond need: `tabs`, `cookies`, `webRequest`, `history`, `downloads`, `nativeMessaging`, `debugger`, `management`
- `debugger`: full CDP control of every tab, almost never justified
- Optional permissions available but everything requested up front
- Manifest V2 still shipping (deprecated, loses `webRequest` blocking)
- `content_security_policy` weakened with `unsafe-eval` or `unsafe-inline`
- `externally_connectable` too broad (any site can message the extension)
- `web_accessible_resources` exposing pages or scripts to all origins; also leaks the extension ID for fingerprinting

## 2. Content Script Boundaries

- Untrusted page data written to `innerHTML` on the page or an extension page
- Trusting anything read from the DOM (the page is attacker-controlled on a malicious site)
- Objects shared across the isolated-world boundary in a way the page can tamper with
- Injecting a script element, then trusting what it sends back
- `window.postMessage` without validating both `event.origin` **and** `event.source`
- Secrets, tokens, or API keys in a content script (reachable from a hostile page)
- Prototype pollution in either direction

## 3. Message Passing

- `chrome.runtime.onMessage` not verifying `sender.id`, `sender.origin`, `sender.tab`
- `onMessageExternal` accepting any extension or site
- Handler dispatching to a function by name from the message body (arbitrary internal call)
- Privileged work (fetch to any URL, cookie read, storage write) for an unvalidated caller: a confused deputy proxying requests past CORS and same-origin
- No schema validation on payloads

## 4. Remote Code & Supply Chain

- Loading and running remote script (forbidden in MV3, store-review failure)
- Dynamic code evaluation (`eval`, the `Function` constructor, string-form `setTimeout`) on externally influenced data
- Remote config changing behavior, selectors, or endpoints without review
- Third-party library loaded from a CDN, not vendored and integrity-checked
- Analytics or ad SDKs in an extension with broad host permissions
- No SRI on external resources loaded by extension pages

## 5. Data Handling & Privacy

- Tokens or PII unencrypted in `chrome.storage.local`/`sync` (disk-readable; `sync` leaves the machine)
- Browsing history, page content, or form data sent off-device; check the privacy policy and store listing disclose it
- Keystroke, clipboard, or screenshot capture beyond stated purpose
- Cookies read via `cookies` and forwarded
- Page URLs or content logged to a remote endpoint
- No data deletion on uninstall

## 6. Network Behavior

- `webRequest`/`declarativeNetRequest` rules that redirect or rewrite traffic unexpectedly
- Stripping `Content-Security-Policy`, `X-Frame-Options`, or CORS headers on visited pages (weakens every site)
- Hardcoded HTTP endpoints
- TLS validation bypassed in native components

## 7. Extension Pages & UI

- Popup, options, or side panel rendering untrusted content unescaped
- Page in `web_accessible_resources` and framable (clickjacking of privileged UI)
- OAuth via a raw URL instead of `chrome.identity.launchWebAuthFlow`; redirect URI not validated

## 8. Native Messaging

- `allowed_origins` lists more extensions than needed
- Host builds shell commands from message content (local command injection)
- Host runs elevated
- Host binary path writable by a non-admin (local privilege escalation)

## 9. Update & Distribution

- Self-hosted updates over HTTP or without signature verification
- Update URL on a domain that could lapse
- Publisher account without MFA (takeover is a mass compromise)
- No review of permission diffs across versions (silent escalation on update)

---

## Reviewing an Extension Well

1. **Start at the manifest.** Each permission asks: what code path needs this? Unused ones are findings.
2. **Treat the page as hostile.** Content scripts run on sites you don't control; DOM data is attacker input.
3. **Follow every message handler.** What does the most hostile sender achieve by calling it?
4. **Ask what leaves the machine.** Trace every `fetch` and `XMLHttpRequest` to its destination and compare with the privacy policy.
5. **Diff permissions across versions** if history exists. Silent escalation is a supply-chain signal.
