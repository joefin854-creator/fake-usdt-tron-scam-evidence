# Tether impersonation report — fake "USDT" TRC-20 on Tron

**Send via Tether's official report channel (https://tether.to/contact-us / their scam-response page) — copy everything below.**

---

**Subject:** Impersonation report — counterfeit "tether/USDT" TRC-20 token on Tron with active victims

**Report type:** Trademark/brand impersonation — counterfeit USDT token contract harming users

**Impersonating contract (Tron):** `TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2`
- On-chain metadata set to look official: name **"tether"**, symbol **"USDT"**, 6 decimals, supply 3,000,000,000
- TronScan: https://tronscan.org/#/token20/TRbNsytk97MTP7M99k5f1TPhwqPD7eW6r2
- It has no relation to the official Tether TRC-20 contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` (https://tronscan.org/#/token20/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t).

**Why this harms Tether users and Tether's brand:** victims are shown a "USDT" token and told they hold the stablecoin; the contract is non-compliant (emits no standard `Transfer` events — balances live only in internal bookkeeping), funds cannot exit (on-chain REVERT proof below), and ~126.4M fake "USDT" was moved to 146 wallet addresses in three weeks (2026-09-26 → 2026-10-16, still active).

**Controlling party:** contract `owner()` = `TYtxrq9XLZZxxJ7gmedFa6BULmN5NtKDDv`, which is simultaneously the most active caller of the contract (admin + operator).

**Victim proof (victim wallet `TRGEtXN3fCyga9yRsH5Ts1zFwgj1uonfPo`):** two withdrawal attempts on 2026-10-12 rejected by the contract (`REVERT`):
- `c75147dfe94b5805580d478f4cb09d480b2cc24b2dd0a8bdf380c5a62b7a6ae9`
- `d4332b0d72b62059305d45ea095d50306236ab925e9f07459245e79e1e8dab92`
Loss approx. **5,000 USD**.

**Full evidence:** https://github.com/joefin854-creator/fake-usdt-tron-scam-evidence

*Report of impersonation made by the victim; happy to provide any additional on-chain data you require.*
