# Domain: Browser Extensions

_Load when the project has a `manifest.json` with `content_scripts`, `background`/`service_worker`, or WebExtension API usage (Chrome, Edge, Firefox, Safari)._

Extensions run with privileges no web page has and sit inside every page the user visits. A compromised extension is a compromise of every site the user is logged into.

---

## 1. Manifest & Permissions

- `<all_urls>` or `*://*/*` host permissions where a narrow list would do — the single most common over-privilege
- `permissions` requesting more than the feature set needs: `tabs`, `cookies`, `webRequest`, `history`, `downloads`, `nativeMessaging`, `debugger`, `management`
- `"debugger"` permission — grants full CDP control of every tab; almost never justified
- Optional permissions available but not used; everything requested up front instead of on demand
- Manifest V2 in a codebase still shipping — MV2 is deprecated and loses `webRequest` blocking
- `content_security_policy` weakened with `unsafe-eval` or `unsafe-inline`
- `externally_connectable` set too broadly, letting arbitrary sites message the extension
- `web_accessible_resources` exposing extension pages or scripts to all origins, which also leaks the extension ID for fingerprinting

## 2. Content Script Boundaries

- Content script writing untrusted page data into `innerHTML` on the page or in an extension page
- Trusting anything read out of the DOM — the page is attacker-controlled on a malicious site
- Sharing objects across the isolated-world boundary in a way the page can tamper with
- Injecting a script element into the page and then trusting what it sends back
- Using `window.postMessage` without validating both `event.origin` **and** `event.source`
- Content script holding secrets, tokens, or API keys — it is reachable from a hostile page context
- Prototype pollution in the content script affecting page scripts, or the reverse

## 3. Message Passing

- `chrome.runtime.onMessage` handler that does not verify `sender.id`, `sender.origin`, or `sender.tab`
- `onMessageExternal` accepting messages from any extension or site
- Message handler that dispatches to a function by name from the message body, giving an arbitrary internal call
- Message handler performing privileged work (fetch to arbitrary URL, cookie read, storage write) on behalf of an unvalidated caller — this turns the extension into a confused deputy that proxies requests past the page's own CORS and same-origin restrictions
- No schema validation on message payloads

## 4. Remote Code & Supply Chain

- Loading and executing remote script — forbidden in MV3 and a store-review failure
- Dynamic code evaluation (`eval`, the `Function` constructor, string-form `setTimeout`) applied to any externally influenced data
- Remote configuration that changes behavior, selectors, or endpoints without review
- Bundled third-party library loaded from a CDN rather than vendored and integrity-checked
- Analytics or ad SDKs inside an extension with broad host permissions
- No Subresource Integrity on any external resource the extension page loads

## 5. Data Handling & Privacy

- `chrome.storage.local` or `sync` holding tokens or PII unencrypted — readable by anyone with disk access, and `sync` leaves the machine
- Browsing history, page content, or form data transmitted off-device; check whether the privacy policy and store listing actually disclose it
- Keystroke, clipboard, or screenshot capture beyond the stated purpose
- Cookies read via the `cookies` permission and forwarded anywhere
- Logging page URLs or content to a remote endpoint
- No data deletion path on uninstall

## 6. Network Behavior

- `webRequest` / `declarativeNetRequest` rules that redirect or rewrite traffic in unexpected ways
- Header stripping that removes `Content-Security-Policy`, `X-Frame-Options`, or CORS headers on pages the user visits — this weakens every site's defenses
- Requests to hardcoded HTTP endpoints
- Certificate or TLS validation bypassed in native components

## 7. Extension Pages & UI

- Popup, options, or side-panel page rendering untrusted content without escaping
- Extension page reachable via `web_accessible_resources` and framable, allowing clickjacking of privileged UI
- OAuth handled by opening a raw URL rather than `chrome.identity.launchWebAuthFlow`
- Redirect URI in the extension OAuth flow not validated

## 8. Native Messaging

- Native host manifest `allowed_origins` listing more extensions than necessary
- Native host building shell commands from message content, giving local command injection
- Native host running with elevated privileges
- Native host binary path writable by a non-admin user, giving local privilege escalation

## 9. Update & Distribution

- Self-hosted updates over HTTP, or without signature verification
- Update URL pointing at a domain that could lapse
- Publisher account without MFA (an extension takeover is a mass-compromise event)
- No review process for what a new version's permission diff adds — silent permission escalation on update

---

## Reviewing an Extension Well

1. **Start at the manifest.** Every permission is a question: what code path needs this? Unused permissions are findings.
2. **Treat the page as hostile.** Content scripts run on sites you do not control. Anything from the DOM is attacker input.
3. **Follow every message handler.** Ask what the most hostile possible sender achieves by calling it.
4. **Ask what leaves the machine.** Trace every `fetch` and `XMLHttpRequest` to its destination and compare against the stated privacy policy.
5. **Diff permissions across versions** if history is available — silent escalation is a supply-chain signal.
