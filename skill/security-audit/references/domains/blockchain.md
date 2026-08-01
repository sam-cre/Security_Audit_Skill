# Vulnerability Reference: Blockchain & Smart Contract Security

_Load this during Phase 1 when auditing Solidity smart contracts, DeFi protocols, NFT platforms, cross-chain bridges, or blockchain-based applications. Aligned with **OWASP Smart Contract Top 10 (2026)**._

---

## SC01 — Reentrancy

### Classic Reentrancy
- External calls (`call`, `send`, `transfer`) made before state updates, allowing the callee to re-enter the function
- Pattern: `contract.call{value: amount}("")` before `balances[msg.sender] -= amount`
- **Fix pattern:** Checks-Effects-Interactions — update state before external calls, or use `ReentrancyGuard`

### Cross-Function Reentrancy
- State shared across multiple functions where one function's external call allows re-entry into a different function
- Read-only reentrancy via `view` functions that read stale state during an external call

---

## SC02 — Access Control & Authorization

### Owner/Admin Privilege
- Missing `onlyOwner`, `onlyRole`, or access control modifier on sensitive functions (mint, pause, withdraw, upgrade)
- Single-key admin control without multisig or timelock
- Unprotected `selfdestruct` or `delegatecall` functions

### Privilege Escalation
- Functions that allow changing ownership without proper authorization
- Missing two-step ownership transfer (immediate transfer without acceptance)
- Unchecked `tx.origin` for authentication (phishing vulnerability)

---

## SC03 — Logic Errors & Business Logic

### Arithmetic
- Integer overflow/underflow (in Solidity < 0.8.0 without SafeMath)
- Precision loss in division operations (divide before multiply)
- Rounding errors in token calculations

### Business Logic
- Flash loan attack vectors (borrow → manipulate → profit → repay in single transaction)
- Front-running / MEV (Miner Extractable Value) — transactions visible in mempool before execution
- Sandwich attacks on DEX swaps
- Price oracle manipulation (single-source oracle, spot price reliance)

---

## SC04 — Unchecked External Calls

- Return value of `call`, `send`, `delegatecall` not checked
- Failed external calls that silently continue execution
- Missing error handling on cross-contract calls
- Unvalidated return data from external contracts

---

## SC05 — Denial of Service

- Gas limit vulnerabilities in unbounded loops (iterating over growing arrays)
- Block gas limit exploits via expensive operations
- Unexpected revert in fallback functions blocking legitimate operations
- Griefing attacks where a contract refuses to accept ETH (blocking withdrawals in push-payment patterns)

---

## SC06 — Proxy & Upgrade Vulnerabilities

- Storage collision between proxy and implementation contracts
- Uninitialized implementation contracts allowing takeover
- Missing upgrade authorization checks
- Function selector clashing between proxy admin and implementation functions
- Missing storage gap (`uint256[50] private __gap`) in upgradeable base contracts

---

## SC07 — Oracle & Data Feed Security

- Single-source price oracles easily manipulated
- Spot price reliance without TWAP (Time-Weighted Average Price)
- Stale price data (missing freshness checks on oracle responses)
- Oracle front-running (manipulating price before critical transaction)

---

## SC08 — Token & Protocol Standards

- ERC-20: Missing return value handling, fee-on-transfer token incompatibility, rebasing token incompatibility
- ERC-721/1155: Missing `onERC721Received` / `onERC1155Received` callbacks
- Approval race condition (approve without first setting to zero)
- Infinite approval risks

---

## SC09 — Cross-Chain Bridge Security

- Message replay attacks across chains
- Missing chain ID validation
- Insufficient verification of cross-chain message authenticity
- Bridge operator centralization risks
- Liquidity pool imbalance exploitation

---

## SC10 — Cryptographic Issues

- Weak randomness from `block.timestamp`, `block.difficulty`, `blockhash` (predictable by miners)
- Missing commit-reveal schemes for on-chain randomness
- Signature malleability (ECDSA `s` value canonicalization)
- Missing nonce in signed messages → replay attacks

---

## Development & Deployment Checks

### Testing & Verification
- Missing invariant tests / fuzz tests (Echidna, Foundry)
- No formal verification on critical math (Certora, Halmos)
- Insufficient test coverage on edge cases

### Deployment Safety
- Constructor vs initializer confusion in upgradeable contracts
- Hardcoded addresses for wrong network (testnet addresses in mainnet deploy)
- Missing deployment verification (verify contract source matches bytecode)
- No emergency pause mechanism (circuit breaker pattern)

### Tooling
Check for availability of:
```bash
slither .                    # Static analysis (Crytic/Trail of Bits)
mythril analyze contract.sol # Symbolic execution
echidna .                   # Property-based fuzzing
forge test                  # Foundry test suite
```
