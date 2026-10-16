# Trust Wallet scam report — counterfeit "USDT" token

**Copy everything below the line into the "Report Scam & Fraud" ticket at https://help.trustwallet.com/ (or the token-detail "Report" flag inside the app).**

---

**Subject:** Fake "tether / USDT" TRC-20 token — victim funds cannot exit (on-chain REVERT proof)

**Report type:** Scam token / counterfeit stablecoin impersonation

**Token contract (Tron):** `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2`
- TronScan: https://tronscan.org/#/token20/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2
- Name shown on-chain: **tether**, symbol **USDT**, 6 decimals, 3,000,000,000 "supply"
- ⚠️ It impersonates the **official Tether TRC-20 contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`**, to which it has no relation.

**Full evidence file:** https://github.com/joefin854-creator/fake-usdt-tron-scam-evidence

**What the evidence shows (all read-on-chain via TronGrid API):**
1. Zero standard TRC-20 `Transfer` events — real balances are invisible to compliant wallet indexers; the contract keeps balances in internal bookkeeping only.
2. ~126.4 million fake "USDT" moved between 146 wallet addresses in three weeks (2026-09-26 → 2026-10-16, still active today), in ~20-unit increments — typical victim-distribution pattern.
3. The contract's on-chain `owner()` is `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv` — which is also the single most active caller of the contract (admin + operator in one wallet).

**My victim record (verifiable on-chain):**
- Wallet: `TRGEtXN3fCyga9yRsH5Ts1zFwgj1uonfPo`
- Two withdrawal attempts on 2026-10-12 were **REVERTED by this contract itself** — proof that value cannot leave:
  - transfer attempt: `c75147dfe94b5805580d478f4cb09d480b2cc24b2dd0a8bdf380c5a62b7a6ae9`
  - approve (MAX) attempt: `d4332b0d72b62059305d45ea095d50306236ab925e9f07459245e79e1e8dab92`
- Real-value loss: approximately **5,000 USD** paid for token balances that have no market, no backing, and no exit path.

**Requested action:** flag/label the token `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2` ("tether"/"USDT") as a dangerous scam asset in Trust Wallet's risk scoring, and block similar listings that use `symbol() = "USDT"` from non-official Tether contracts.

*I am the victim; no other people's data is included. Happy to supply anything else needed.*
