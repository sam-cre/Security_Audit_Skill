# Domain: CMS, SaaS Platforms & Low-Code

_Load for WordPress, Drupal, Joomla, Shopify, Salesforce, ServiceNow, Retool, Airtable, n8n, Zapier, Make, Power Platform, and similar._

Here you mostly do **not** control the platform code. The audit shifts to configuration, extensions, permissions, and the glue logic — which is where essentially all real incidents in this space originate.

---

## 1. Extension Supply Chain (the dominant risk)

- Plugins, themes, or apps from outside the official marketplace, or from an unmaintained author
- Components with no update in 12+ months, or explicitly abandoned
- Known-vulnerable versions — check WPScan, Patchstack, or the vendor advisory feed; verify per `rules.md` section 5, never from memory
- Nulled, cracked, or repackaged premium plugins (a common backdoor vector)
- Auto-update disabled with no compensating patch process
- More extensions installed than used — every inactive plugin is still reachable code on most CMSs
- No staging environment, so updates are applied blind to production

## 2. Platform Configuration

**WordPress**
- `wp-config.php` readable, or salts/keys left at defaults
- `DISALLOW_FILE_EDIT` not set — admin compromise becomes code execution via the theme editor
- `xmlrpc.php` reachable (credential brute force and pingback amplification)
- REST API user enumeration at `/wp-json/wp/v2/users`
- Directory listing on `wp-content/uploads`
- Version disclosed in the generator meta tag and asset query strings
- Default `admin` username; no login rate limiting
- File uploads permitted to execute — PHP execution not disabled in the uploads directory

**Drupal / Joomla**
- Update status module disabled or unmonitored
- PHP filter module enabled
- Overly broad role permissions, particularly "administer users" or "bypass node access"

**Shopify / commerce platforms**
- App with read/write on orders and customers where read-only suffices
- Storefront API token exposed client-side with excessive scope
- Webhook receiver not verifying the HMAC signature
- Checkout logic overridable client-side (price, discount, quantity)

**Salesforce / ServiceNow / enterprise SaaS**
- Profiles and permission sets granting "View All Data" / "Modify All Data" broadly
- Guest user or public community profile with object access
- Sharing rules opened to fix a bug and never narrowed
- Apex or scripted API without `WITH SECURITY_ENFORCED` / ACL evaluation
- Public Sites or Communities exposing objects unintentionally

## 3. Low-Code Automation (n8n, Zapier, Make, Retool, Power Automate)

- **Expression injection** — user-controlled data interpolated into a formula, template, or code node that then executes
- Code/script nodes running untrusted input with full network and credential access
- Webhook triggers with no authentication, signature check, or IP restriction — anyone who learns the URL can invoke the workflow
- Webhook URL treated as a secret while being logged, shared, or embedded client-side
- Connections and credentials shared workspace-wide rather than scoped to a workflow
- A single OAuth connection with admin scope reused by every automation
- Workflows writing to production systems with no approval step or dry-run
- Error branches that leak payloads containing PII or credentials into logs and alerts
- No audit trail of who edited a workflow
- Retool: queries built by string-concatenating component values into SQL rather than using parameters
- Retool: client-side-only permission checks on admin views

## 4. Access Control & Accounts

- Admin accounts without MFA — the single highest-value fix in this domain
- Shared admin logins with no per-person attribution
- Contributors or editors holding roles that permit code, template, or plugin changes
- Former staff and contractors still holding access; no offboarding process
- API tokens and integration users with no expiry and no rotation
- Admin interface reachable from the public internet with no IP allowlist, VPN, or SSO gate
- No session timeout on admin sessions

## 5. Content & Upload Handling

- Unrestricted file upload — no type allowlist, no size cap, no content inspection
- Uploads served from the same origin with executable permissions
- Original filename preserved, allowing path traversal or double-extension tricks
- SVG uploads accepted without sanitization (SVG carries script)
- Rich-text or HTML block editors permitting raw `<script>` or event handlers for non-admin roles
- Media library publicly listable, exposing unpublished or internal documents
- No malware scan on uploaded content in a multi-author environment

## 6. Data Exposure

- Backups stored inside the web root and downloadable
- Database exports, `.sql` files, or migration dumps left in a public directory
- Debug or trace mode enabled in production
- `.git`, `.env`, `composer.lock`, or `package.json` served over HTTP
- Staging or dev environment publicly reachable with production data and weaker controls
- Search indexing of pages that should require authentication
- Form submissions containing PII stored in the CMS database indefinitely with no retention policy

## 7. Custom Code Layer

Wherever the project adds its own code — a custom theme, plugin, Apex class, script node, or serverless glue function — the standard classes apply. Load `web-api.md` and `auth-identity.md` and review it as first-party code. In practice this custom layer, not the platform, is where injection and authorization bugs live.

- Platform-provided escaping and sanitization helpers bypassed
- Platform capability/permission checks omitted in custom endpoints
- Nonce or CSRF token verification skipped in custom form handlers
- Direct database access bypassing the platform's ORM and its access controls

## 8. Hosting & Perimeter

- No WAF, and no managed ruleset for the platform (CMS-targeted scanning is constant and automated)
- No rate limiting on login or password reset
- File permissions too broad; web server able to write to its own code directory
- No integrity monitoring to detect an injected backdoor in core or plugin files
- Outdated PHP, Node, or platform runtime past end of life
- No off-host, tested backups — the actual recovery control for this domain

---

## Reviewing a Platform Build Well

1. **Inventory everything installed**, with version, last update date, and source. Most findings fall out of this list alone.
2. **Enumerate accounts and roles.** Who can reach code execution, directly or through a template, plugin, or script feature? That set should be very small.
3. **Read the custom code as first-party.** The platform is probably fine; the glue usually is not.
4. **Check what is publicly reachable** — admin paths, APIs, uploads, backups, staging. Fetch them and see.
5. **Confirm updates and backups actually happen.** In this domain, patch cadence and restore capability outrank almost every code-level finding.
