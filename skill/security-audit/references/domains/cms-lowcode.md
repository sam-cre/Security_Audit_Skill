# Domain: CMS, SaaS Platforms & Low-Code

_Load for WordPress, Drupal, Joomla, Shopify, Salesforce, ServiceNow, Retool, Airtable, n8n, Zapier, Make, Power Platform, and similar._

You mostly don't control the platform code. The audit shifts to configuration, extensions, permissions, and glue logic, where nearly all real incidents here start.

---

## 1. Extension Supply Chain (dominant risk)

- Plugins, themes, or apps from outside the official marketplace or from an unmaintained author
- No update in 12+ months, or abandoned
- Known-vulnerable versions: check WPScan, Patchstack, or the vendor feed; verify per `rules.md` section 5, never from memory
- Nulled, cracked, or repackaged premium plugins (common backdoor vector)
- Auto-update off with no patch process
- Installed but unused extensions (inactive plugins are still reachable code on most CMSs)
- No staging, so updates hit production blind

## 2. Platform Configuration

**WordPress**
- `wp-config.php` readable; default salts/keys
- `DISALLOW_FILE_EDIT` unset (admin compromise becomes code execution via the theme editor)
- `xmlrpc.php` reachable (brute force, pingback amplification)
- User enumeration at `/wp-json/wp/v2/users`
- Directory listing on `wp-content/uploads`
- Version in generator meta tag and asset query strings
- Default `admin` username; no login rate limit
- PHP execution not disabled in the uploads directory

**Drupal / Joomla**
- Update status module off or unmonitored; PHP filter module on
- Broad roles, especially "administer users" or "bypass node access"

**Shopify / commerce**
- App with read/write on orders and customers where read-only works
- Storefront API token exposed client-side with excess scope
- Webhook receiver not verifying HMAC
- Checkout logic (price, discount, quantity) overridable client-side

**Salesforce / ServiceNow / enterprise SaaS**
- Broad "View All Data" / "Modify All Data" profiles or permission sets
- Guest user or public community profile with object access
- Sharing rules opened for a bug and never narrowed
- Apex or scripted API without `WITH SECURITY_ENFORCED` / ACL checks
- Public Sites or Communities exposing objects unintentionally

## 3. Low-Code Automation (n8n, Zapier, Make, Retool, Power Automate)

- **Expression injection:** user data interpolated into a formula, template, or code node that executes
- Code nodes running untrusted input with full network and credential access
- Webhook triggers with no auth, signature, or IP restriction (anyone with the URL invokes it)
- Webhook URL treated as a secret while logged, shared, or embedded client-side
- Credentials shared workspace-wide, not scoped per workflow; one admin-scope OAuth connection reused everywhere
- Workflows writing to production with no approval or dry-run
- Error branches leaking PII or credentials into logs and alerts
- No audit trail of workflow edits
- Retool: SQL built by concatenating component values; client-side-only permission checks on admin views

## 4. Access Control & Accounts

- Admin accounts without MFA (the single highest-value fix here)
- Shared admin logins with no attribution
- Contributors/editors with code, template, or plugin change rights
- Former staff and contractors still with access
- API tokens and integration users with no expiry or rotation
- Admin reachable from the public internet with no IP allowlist, VPN, or SSO
- No admin session timeout

## 5. Content & Upload Handling

- Unrestricted upload: no type allowlist, size cap, or content inspection
- Uploads served same-origin with execute permission
- Original filename kept (path traversal, double extensions)
- SVG accepted unsanitized (carries script)
- Rich-text/HTML editors allowing raw `<script>` or event handlers for non-admins
- Media library publicly listable, exposing unpublished documents
- No malware scan in multi-author setups

## 6. Data Exposure

- Backups in the web root and downloadable
- `.sql` exports or migration dumps in a public directory
- Debug or trace mode in production
- `.git`, `.env`, `composer.lock`, `package.json` served over HTTP
- Public staging/dev with production data and weaker controls
- Authenticated pages indexed by search engines
- Form PII stored indefinitely with no retention policy

## 7. Custom Code Layer

Custom themes, plugins, Apex classes, script nodes, and serverless glue are first-party code. Load `web-api.md` and `auth-identity.md` and review them as such. This layer, not the platform, is where injection and authorization bugs live.

- Platform escaping/sanitization helpers bypassed
- Platform capability checks missing in custom endpoints
- Nonce/CSRF verification skipped in custom form handlers
- Direct DB access bypassing the platform ORM and its access controls

## 8. Hosting & Perimeter

- No WAF or managed ruleset (CMS scanning is constant and automated)
- No rate limit on login or password reset
- Web server can write to its own code directory; file permissions too broad
- No integrity monitoring for injected backdoors in core or plugin files
- End-of-life PHP, Node, or platform runtime
- No tested off-host backups (the real recovery control here)

---

## Reviewing a Platform Build Well

1. **Inventory everything installed** with version, last update, and source. Most findings fall out of this list.
2. **Enumerate accounts and roles.** Who can reach code execution, directly or via template, plugin, or script features? That set should be tiny.
3. **Read custom code as first-party.** The platform is probably fine; the glue usually isn't.
4. **Fetch what is publicly reachable:** admin paths, APIs, uploads, backups, staging.
5. **Confirm updates and backups actually happen.** Patch cadence and restore capability outrank almost every code-level finding here.
