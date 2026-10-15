# Vulnerability Reference: Game Security

_Load in Phase 1 for game clients, game servers, multiplayer networking, virtual economies, or game services (matchmaking, leaderboards, item marketplaces)._

---

## 1. Client-Side State

**Memory tampering**
- State held client-side without server validation (health, ammo, position, inventory)
- Client-authoritative movement/physics (speed hacks, teleport)
- Values editable with Cheat Engine or GameGuardian; client-reported changes not validated server-side

**Binary**
- No obfuscation; unencrypted protocol enables packet crafting
- Debug builds or symbols shipped
- Anti-cheat bypass via DLL injection, hooking, or drivers

**Assets**
- Local textures, models, configs editable for advantage (wallhacks, transparent textures); no integrity checks
- Gameplay-affecting config values player-editable

## 2. Network & Multiplayer

- Plaintext UDP/TCP; no packet authentication (forged packets accepted); no sequence numbers or replay protection
- No rate limit on game actions (auto-fire, macros)
- Desync enabling duplication glitches; rollback/netcode "undo" exploits; lag switching; interpolation abuse
- Client-authoritative logic ("I killed player X" accepted unchecked); no server-side hit validation; trusting client timestamps or frame counts

## 3. Virtual Economy

**Currency**
- Negative-value transactions (negative price gains currency)
- Integer overflow/underflow in currency math
- Buy/sell races (double spend); non-atomic transactions leaving inconsistent state

**Duplication**
- Trade/mail race conditions; crash-during-trade rollback (both keep items); gift/transfer exploits; non-idempotent item creation

**Marketplace**
- Coordinated price manipulation; sniping bots; cross-currency arbitrage; no rate limits on list/delist

## 4. Accounts

- Session fixation or token theft; no 2FA on high-value accounts; weak recovery open to social engineering; no account-sharing detection
- Progression abuse: achievements or levels via API, XP injection, rank manipulation (deranking, boosting)
- Ban evasion: HWID spoofing, frictionless new accounts (no CAPTCHA or email verification), VPN around IP bans

## 5. Anti-Cheat

- No server-side statistical analysis (impossible accuracy, speed, reaction); no behavioral bot detection
- Client-side-only anti-cheat falls to kernel-level access
- Anti-cheat itself as risk: vulnerable kernel drivers, bypass via virtualization, no integrity checks on its components

## 6. Content & Social

- XSS via player names, chat, guild names, item descriptions; SQLi via search, leaderboard, profile fields
- Upload flaws in avatars or custom content; no moderation of user-made levels or maps
- No profanity filtering; private-message spam, phishing, RMT ads; voice chat without reporting

## 7. Platform-Specific

- **Mobile:** forged in-app purchase receipts; client-side ad-reward calculation; root/jailbreak bypass enabling save edits; device clock changes for timed events
- **Web:** WebSocket tamper-and-replay; state edits via dev tools; no CSP (cheat script injection)
- **Blockchain / play-to-earn:** reward-contract flaws (see `blockchain.md`); front-running reward claims (MEV); economy exploits (infinite mint, deflationary spiral)
