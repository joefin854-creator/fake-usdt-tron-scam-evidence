# Chainabuse report — counterfeit "USDT" on Tron

**Chainabuse form:** https://www.chainabuse.com/address/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2
(copy each field below into the matching field of the report form)

---

**Blockchain:** Tron (Tron stakes / TRC20)

**Scam type:** Impersonation / fake stablecoin (counterfeit "USDT")

**Address / contract:** `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2`

**Title:** Fake "tether / USDT" TRC-20 token — victim funds cannot exit (on-chain REVERT proof)

**Description:**

A contract on Tron impersonates Tether USDT: name "tether", symbol "USDT", 6 decimals, claimed supply 3,000,000,000 — but it is NOT the official Tether TRC-20 contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`. Victims are led to believe they hold stable USDT; they hold a valueless token with no market and no backing.

On-chain evidence (collected read-only from the TronGrid public API 2026-10-16, full file linked below):

1. Zero standard TRC-20 `Transfer` events — the contract keeps balances in internal bookkeeping, hidden from compliant wallets/indexers (check: api.trongrid.io/v1/contracts/{addr}/events?event_name=Transfer → empty).
2. ~126.4M fake "USDT" passed through internal `transfer()` calls to 146 distinct wallet addresses between 2026-09-26 and 2026-10-16 (still active), mostly in ~20-unit increments — a mass-distribution pattern.
3. The contract owner on-chain is `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv` — which is also the #1 most frequent caller of the contract (51 of the latest 238 raw txs): admin + operator in one wallet.

Victim record (victim's wallet: `TRGEtXN3fCyga9yRsH5Ts1zFwgj1uonfPo`):

- Withdrawal attempts on 2026-10-12 REVERTED by the contract itself (on-chain proof that value cannot leave):
  - transfer 10 fake-"USDT": tx `c75147dfe94b5805580d478f4cb09d480b2cc24b2dd0a8bdf380c5a62b7a6ae9`
  - approve (MAX): tx `d4332b0d72b62059305d45ea095d50306236ab925e9f07459245e79e1e8dab92`
- Real-value loss: approximately **5,000 USD** paid for balances that are impossible to exit.

**Attachment / evidence link:** https://github.com/joefin854-creator/fake-usdt-tron-scam-evidence

**Reported by:** the victim (single account, own experience only).
