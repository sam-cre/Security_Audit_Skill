# Vulnerability Reference: Game Security

_Load this during Phase 1 when auditing game clients, game servers, multiplayer networking, virtual economies, or game-adjacent services (matchmaking, leaderboards, item marketplaces)._

---

## 1. Client-Side State Manipulation

### Memory Tampering
- Game state stored client-side without server validation (health, ammo, position, inventory)
- Client-authoritative movement/physics allowing speed hacks and teleportation
- Memory values modifiable via external tools (Cheat Engine, GameGuardian)
- Missing server-side validation of client-reported game state changes

### Client Binary Exploitation
- Missing code obfuscation allowing reverse engineering of game logic
- Unencrypted network protocol enabling packet crafting
- Debug builds or symbols shipped in production releases
- Anti-cheat bypass via DLL injection, hooking, or driver-level manipulation

### Asset Tampering
- Local asset files (textures, models, configs) modifiable for competitive advantage (wallhacks, transparent textures)
- Missing asset integrity verification (checksum/hash validation)
- Configuration files containing gameplay-affecting values editable by players

---

## 2. Network & Multiplayer Security

### Protocol Security
- Game protocol transmitted over unencrypted channels (plaintext UDP/TCP)
- Missing packet authentication (forged packets accepted by server)
- Missing sequence numbers or replay protection (action replay attacks)
- Missing rate limiting on game actions (auto-fire, auto-click, macro abuse)

### Desync & Exploitation
- Client-server desynchronization exploitable for duplication glitches
- Rollback/netcode exploits allowing players to "undo" damage or losses
- Lag switching — intentional latency manipulation for advantage
- Position interpolation exploits (rubber-banding abuse)

### Server Authority
- Client-authoritative game logic (client tells server "I killed player X" without server verification)
- Missing server-side hit detection/validation
- Trust of client-reported timestamps or frame counts

---

## 3. Virtual Economy & Currency Exploits

### Currency Manipulation
- Negative value transactions (buying items for negative price → gaining currency)
- Integer overflow/underflow in currency calculations
- Race conditions in simultaneous buy/sell operations (double-spend)
- Missing transaction atomicity (partial failures leaving inconsistent state)

### Item Duplication
- Duplication via trade/mail system race conditions
- Rollback-based duplication (crash during trade → both parties keep items)
- Gift/transfer exploits between accounts
- Missing idempotency on item creation endpoints

### Marketplace Abuse
- Price manipulation via coordinated buying/selling (market manipulation)
- Sniping bots on time-limited offers
- Cross-currency arbitrage exploits
- Missing rate limits on marketplace listing/delisting

---

## 4. Account & Authentication Security

### Account Takeover
- Session fixation or token theft enabling account hijacking
- Missing 2FA on high-value accounts
- Weak password recovery allowing social engineering attacks
- Account sharing detection and prevention

### Progression Abuse
- Achievement/level unlocking via API manipulation
- Experience/XP injection through modified game data
- Rank manipulation via matchmaking abuse (deranking, boosting)

### Ban Evasion
- Hardware ID (HWID) spoofing to circumvent bans
- New account creation without friction (missing CAPTCHA, email verification)
- IP ban circumvention via VPN (consider fingerprinting alternatives)

---

## 5. Anti-Cheat Considerations

### Detection Gaps
- Missing server-side statistical analysis (impossible accuracy, impossible speed, impossible reaction time)
- No behavioral analysis for automated play (bots, macros)
- Client-side-only anti-cheat easily bypassed via kernel-level access

### Anti-Cheat Security
- Anti-cheat system itself being a security risk (kernel drivers with vulnerabilities)
- Anti-cheat bypass via virtualization
- Missing integrity checks on anti-cheat components

---

## 6. Content & Social Security

### User-Generated Content (UGC)
- XSS via player names, chat messages, guild names, item descriptions
- SQL injection via in-game search, leaderboard, or profile fields
- Image/file upload vulnerabilities in avatar or custom content systems
- Missing content moderation on user-generated levels/maps

### Chat & Communication
- Missing profanity/hate speech filtering
- Private message abuse (spam, phishing, RMT advertising)
- Voice chat abuse without reporting mechanism

---

## 7. Platform-Specific

### Mobile Games
- In-app purchase receipt validation bypass (fake receipts)
- Client-side reward calculation for ad-watching
- Jailbreak/root detection bypass allowing save file manipulation
- Time manipulation attacks (changing device clock for timed events)

### Web-Based Games
- WebSocket message tampering (inspect → modify → replay)
- Browser developer tools enabling state inspection/modification
- Missing CSP allowing injection of cheat scripts

### Blockchain Games / Play-to-Earn
- Smart contract vulnerabilities in reward distribution (see `blockchain-smart-contracts.md`)
- Front-running on reward claims (MEV extraction)
- Economic model exploits (infinite mint, deflationary spiral)
