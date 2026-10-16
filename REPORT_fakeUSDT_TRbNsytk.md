# Scam-token evidence: "tether" (USDT) — counterfeit Tether mimic on Tron

*Collected 2026-10-16, read-only, straight from TronGrid public API (reproducible via `scam-evidence/tron_probe.py`).*

## 1. Identity of the token

- **Chain:** Tron (TRC-20-style)
- **Contract:** `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2`
- **Explorer:** https://tronscan.org/#/token20/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2
- **name():** `tether` — **symbol():** `USDT` — decimals `6` (mimics the real thing exactly)
- **totalSupply():** `3,000,000,000` fake "USDT"

## 2. Why this is a counterfeit, provably

1. The **only official Tether TRC-20** contract is `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`
   (https://tronscan.org/#/token20/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t). Any contract that exposes
   `symbol() = "USDT"` and calls itself tether from a **different address** is an impersonation;
   holders are led to believe they own the real stablecoin.
2. **It emits zero standard `Transfer` events.** Real USDT is fully TRC-20-compliant; this contract
   moves balances through internal `transfer()` calls with **no events**, so genuine wallet indexers
   never record real transfers — balances shown in fake dashboards are pure contract bookkeeping.
   Evidence: `https://api.trongrid.io/v1/contracts/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2/events?event_name=Transfer` → empty.
3. **Owner / operator is the same wallet**, actively running the scheme:
   - on-chain `owner()` → `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv`
   - that same address is the **#1 most frequent caller** of the contract (51 calls in the most recent 238 raw transactions sampled). Admin + daily operator identity.

## 3. Activity evidence (raw transactions, 2026-09-26 → 2026-10-16 — still live today)

| Metric | Value |
|---|---|
| Raw transactions scanned (recent sample) | 238 |
| `transfer(address,uint256)` calls | 179 |
| Distinct wallets calling the contract | 61 |
| Distinct `transfer()` recipients | 146 |
| Fake-"USDT" volume moved in the sample | ≈ 126,472,723 units (6 decimals) |
| Typical transfer size | ≈ 20 "USDT" increments (0x1312d00) — mass small-amount distribution, consistent with victim caps / distribution phases |

**Top caller wallets (operators / distributors):**
| Wallet | Calls in sample |
|---|---|
| `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv` (also the contract owner) | 51 |
| `TMzAeXn1SKQgfkVpzfB6KbTSSmEufGWdLa` | 18 |
| `TSJQsfUzKCwiQbcZwBx12jHKr7cbkHqmrx` | 15 |
| `TNwDxHepCpa85Wrc1iWPXFpjjQ4CguB16z` | 13 |

## 4. Victim's own record (on-chain, verifiable)

- **My wallet:** `TRGEtXN3fCyga9yRsH5Ts1zFwgj1uonfPo`
- **What happened:** I paid approximately **5,000 USD** for fake-"USDT" balances that this contract controls. The contract blocks exits: my two attempts to withdraw/transfer on 2026-10-12 **REVERTED on-chain** (txs 1–2 below), proving the transfer-block / honeypot behavior directly from Tron's own transaction data. The token has no market, no real backing and no route to real value.

| # | Tx hash (TronScan) | Block (UTC time) | Call | Amount / target | Result |
|---|---|---|---|---|---|
| 1 | `c75147dfe94b5805580d478f4cb09d480b2cc24b2dd0a8bdf380c5a62b7a6ae9` | 87054942 (2026-10-12 20:41) | `transfer(address,uint256)` | 10 fake-"USDT" → `TEbPNP2jATf38GQ8Fi4cUaq3ffX4EFMTvh` | **REVERT** — exit attempt blocked |
| 2 | `d4332b0d72b62059305d45ea095d50306236ab925e9f07459245e79e1e8dab92` | 87054408 (2026-10-12 20:14) | `approve(address,uint256)` | MAX → spender `TNJVzGqKBWkJxJB5XYSqGAwUTV15U24pPq` | **REVERT** — withdrawal/spend approval blocked |
| 3 | `73f5d19dccee44096b37c4e1137b961d20d48dba5164dc6e2f3630174c331c05` | 87044305 (2026-10-12 11:49) | `transfer(address,uint256)` | 50 fake-"USDT" → `TC6FjCJQxoeBZD74jajfrAykMnAxr1oyk5` | SUCCESS (internal, valueless bookkeeping) |
| 4 | `a6edd12d8d09afb43a9bd5df3d9727fd17dfa1929f426f0016208bf87a906424` | 87011110 (2026-10-11 08:09) | `transfer(address,uint256)` | 1,000 fake-"USDT" → `TE4y21LVTV6FKZpQbvn6oeXYuxRpwcQMxj` | SUCCESS (internal, valueless bookkeeping) |
| 5 | `b2c71a4bc4778033f5eb760c78d97e3c2c13b3de2bf24d56e269564f18684e43` | 86996531 (2026-10-10 20:00) | `transfer(address,uint256)` | 20 fake-"USDT" → `TBg79beDGUhw8EXfXyjsRQRWHAURKjcyAp` | SUCCESS (internal, valueless bookkeeping) |

Every tx calls the fake contract "TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2" directly (contract_address in each transaction). Tx 1 and 2 are my blocked withdrawal attempts — REVERT is the contract itself refusing.

## 5. Where to report (one account, same evidence everywhere)

1. **Trust Wallet:** token/open the asset inside the app → flag/report, or https://support.trustwallet.com — attach this file.
2. **Chainabuse** (Tron is covered; public cross-chain scam database): https://www.chainabuse.com/address/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2
3. **Tether scam report** (impersonation of their trademark): https://tether.to/contact-us or Tether's official scam-response page.
4. **TronDAO / "Avengers" scam-response channels** (fake-USDT takedown team).
5. **Police / IC3** (https://www.ic3.gov) — required for any real seizure action on real-money losses.

## 6. Paste-ready complaint paragraph

> Scam TRC-20 token impersonating Tether USDT on Tron: `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2` (name "tether", symbol "USDT", 6 decimals). It is NOT the official Tether contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`, yet it exposes USDT-compatible metadata and a 3,000,000,000 "supply" to look legitimate. It emits no standard Transfer events (real balances are invisible to compliant wallets), its internal `transfer()` bookkeeping moved ~126 million fake "USDT" between 146 wallet addresses within three weeks (2026-09-26 → 2026-10-16, still active), and the contract owner `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv` is also the most active operator calling it. My wallet `TRGEtXN3fCyga9yRsH5Ts1zFwgj1uonfPo` had two attempted withdrawals on 2026-10-12 REVERTED by this very contract (tx hashes in the attached evidence) — I lost approximately 5,000 USD and the balance cannot be moved to real value.
