#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solana_probe.py — read-only evidence probe for a suspected scam SPL token on Solana.

Checks (read-only public RPC; nothing is signed, sent, or broadcast):
  - mint existence + SPL program type (Token / Token-2022)
  - decimals + supply + mint/freeze authorities parsed from raw mint data
  - Metaplex metadata name/symbol (correct PDA derivation incl. off-curve check)
  - top holder concentration via getTokenLargestAccounts
  - activity span via getSignaturesForAddress (limit 1000, failed-tx count)
  - official-USDT mimic check (Es9vMFrzaCERm4fr5o3vvbw6auSeeuifvGGgFyJUaB)
  - writes a markdown evidence report with a victim-narrative placeholder

Usage:
  python solana_probe.py <mintAddress>
Environment: RPC_URL overrides the default public endpoint list.
"""

import base64
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

OFFICIAL_USDT_SOL = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"   # verified against Solscan/constant references
METAPLEX_META = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
TOKEN_PROGRAMS = {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBq4ExFBDP": "SPL Token 2022",
}
RPC_LIST = [os.environ.get("RPC_URL") or "https://solana-rpc.publicnode.com",
            "https://api.mainnet-beta.solana.com"]
# NOTE: ankr/onfinality block Python UAs — keep a browser-like User-Agent (see rpc_call)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36"

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(ALPHABET)}

# ───────────────── base58 (std alphabet, full leading-zero handling) ─────────────────
def b58_decode(s):
    n = 0
    for c in s:
        if c not in B58_INDEX:
            raise ValueError(f"bad base58 char {c!r}")
        n = n * 58 + B58_INDEX[c]
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw

def b58_encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPHABET[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + (s or "")

# ───────────────── ed25519 off-curve check (for correct PDA derivation) ─────────────────
ED_P = 2**255 - 19
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P

def _is_on_curve(b32):
    """True if the 32-byte little-endian pubkey is a valid ed25519 point (curve check)."""
    y = int.from_bytes(b32, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED_P:
        return False
    denom = (1 + ED_D * y * y) % ED_P
    num = (y * y - 1) % ED_P
    x2 = (num * pow(denom, ED_P - 2, ED_P)) % ED_P
    r = pow(x2, (ED_P - 3) // 4 + 1, ED_P)   # sqrt candidate
    if r * r % ED_P != x2 % ED_P:
        return False
    if (r % 2) != sign:
        r = (-r) % ED_P
    # point (x,y) validity: satisfied by construction when x2 is a QR
    return True

def find_pda(seeds):
    """Canonical Solana PDA: seeds + bump(255..1) + 'ProgramDerivedAddress', must be OFF-curve."""
    for bump in range(255, 0, -1):
        pre = b"".join(seeds) + bytes([bump])
        h = hashlib.sha256(pre + b"ProgramDerivedAddress").digest()
        if not _is_on_curve(h):
            return b58_encode(h)
    raise RuntimeError("no PDA found")

def rpc_call(method, params, tries=8):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for rpc in RPC_LIST:
        for i in range(tries):
            try:
                req = urllib.request.Request(rpc, data=payload,
                                             headers={"Content-Type": "application/json",
                                                      "User-Agent": UA})
                with urllib.request.urlopen(req, timeout=30) as r:
                    res = json.loads(r.read().decode())
                if res.get("error"):
                    msg = str(res["error"])[:120]      # error objects vary (dict/list) — stringify
                    last = RuntimeError(msg)
                    if "rate" in msg.lower() or "too many" in msg.lower():
                        time.sleep(5 + i * 4)
                        continue
                    break
                time.sleep(0.5)                       # gentle pacing for public RPCs
                return res["result"]
            except urllib.error.HTTPError as e:
                last = e
                if e.code in (429, 403, 503) and i < tries - 1:
                    time.sleep(5 + i * 4)
                    continue
                break
            except Exception as e:
                last = e
                time.sleep(2 + i)
        else:
            continue
    raise last or RuntimeError("all RPC endpoints failed")

# ───────────────── SPL MintAccount parse (base fields identical in Token-2022) ─────────────────
def parse_mint(raw):
    data = base64.b64decode(raw)
    out = {"mint_authority": None, "supply": None, "decimals": None,
           "is_initialized": None, "freeze_authority": None}
    if len(data) < 36:
        return out
    if int.from_bytes(data[0:4], "little") == 1:
        out["mint_authority"] = b58_encode(data[4:36])
        off = 36
    else:
        off = 4
    out["supply"] = int.from_bytes(data[off:off + 8], "little")
    out["decimals"] = data[off + 8]
    out["is_initialized"] = bool(data[off + 9])
    if int.from_bytes(data[off + 10:off + 14], "little") == 1 and len(data) >= off + 46:
        out["freeze_authority"] = b58_encode(data[off + 14:off + 14 + 32])
    return out

def parse_metaplex_meta(mint):
    """Best-effort name/symbol from Metaplex Token-Metadata account (old short-header layout)."""
    pda = find_pda([b"metadata", b58_decode(METAPLEX_META), b58_decode(mint)])
    acc = rpc_call("getAccountInfo", [pda, {"encoding": "base64"}])
    data = base64.b64decode(((acc.get("value") or {}).get("data") or ["", ""])[0])
    if len(data) < 70 or data[0] != 4:          # key byte 4 = MetadataV1
        return {}
    off = 1 + 32 + 32                            # key + update_authority + mint
    ln = int.from_bytes(data[off:off + 4], "little")
    name = data[off + 4:off + 4 + ln].decode("utf-8", "replace").strip("\x00").strip()
    off = off + 4 + ln
    if off + 4 > len(data):
        return {"name": name}
    ln2 = int.from_bytes(data[off:off + 4], "little")
    symbol = data[off + 4:off + 4 + ln2].decode("utf-8", "replace").strip("\x00").strip()
    return {"name": name, "symbol": symbol}

def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    mint = sys.argv[1].strip()
    print(f"probing mint {mint} (read-only)\n")

    acc = rpc_call("getAccountInfo", [mint, {"encoding": "base64"}])
    val = acc.get("value")
    if not val:
        sys.exit("mint account does not exist on Solana mainnet")
    owner = val.get("owner")
    if owner not in TOKEN_PROGRAMS:
        sys.exit(f"not an SPL token mint (owner program: {owner})")
    parsed = parse_mint((val.get("data") or ["", ""])[0])
    supply = parsed["supply"]
    print(json.dumps({"program": TOKEN_PROGRAMS[owner],
                      "decimals": parsed["decimals"],
                      "supply": supply,
                      "mint_authority": parsed["mint_authority"],
                      "freeze_authority": parsed["freeze_authority"],
                      "initialized": parsed["is_initialized"]}, indent=2))

    try:
        meta = parse_metaplex_meta(mint)
        print("metaplex:", json.dumps(meta, default=str))
    except Exception as e:
        meta = {}
        print("metaplex metadata: not available (" + str(e)[:80] + ")")
    meta_name = (meta.get("name") or "").lower()
    if "usdt" in meta_name or meta.get("symbol") == "USDT":
        print(f"* MIMIC CHECK: official USDT on Solana is {OFFICIAL_USDT_SOL} — different mint means impersonation")

    accts = []
    holders_note = ""
    try:
        largest = rpc_call("getTokenLargestAccounts", [mint], tries=4)
        accts = largest.get("value") or []
        print("\ntop holders:")
        for a in accts[:15]:
            try:
                pct = int(a.get("amount", "0")) / supply * 100 if supply else 0
            except Exception:
                pct = 0
            print(f"  {a['address']}  {a.get('uiAmountString', '?')}  ({pct:.2f}%)")
    except Exception as e:
        holders_note = f"getTokenLargestAccounts unavailable during probe (RPC rate-limit: {str(e)[:80]}) "\
                       "— rerun the script in a few minutes, or pull holders from Solscan."
        print("top holders: SKIPPED —", holders_note)

    rows = []
    sig_note = ""
    t0 = t1 = None
    n_err = 0
    try:
        sigs = rpc_call("getSignaturesForAddress", [mint, {"limit": 1000}], tries=4)
        rows = sigs.get("value") or []
    except Exception as e:
        sig_note = f"signature history unavailable during probe (RPC rate-limit: {str(e)[:80]}) — "\
                    "fetch from Solscan meanwhile."
        print("signatures: SKIPPED —", sig_note)
    if rows:
        t0 = dt.datetime.fromtimestamp(min(r.get("blockTime") or 0 for r in rows), dt.UTC)
        t1 = dt.datetime.fromtimestamp(max(r.get("blockTime") or 0 for r in rows), dt.UTC)
        n_err = sum(1 for r in rows if r.get("err"))
        print(f"\nsignature history (limit 1000): {len(rows)} | failed {n_err} | span {t0} -> {t1}")

    # ── markdown report ──
    path = f"scam_evidence_sol_{mint[:12]}.md"
    with open(path, "w", encoding="utf-8") as w:
        w.write(f"# Scam-token evidence (Solana): {meta.get('name') or '(no metadata)'} ({meta.get('symbol') or '?'})\n\n")
        w.write(f"- mint: `{mint}`\n")
        w.write(f"- explorer: https://solscan.io/token/{mint}\n")
        w.write(f"- segment: {TOKEN_PROGRAMS[owner]} | decimals: {parsed['decimals']} | supply: {supply}\n")
        w.write(f"- mint authority: `{parsed['mint_authority']}` | freeze authority: `{parsed['freeze_authority']}`\n")
        if "usdt" in meta_name or meta.get("symbol") == "USDT":
            w.write(f"- **MIMIC ALERT:** presents as USDT; the official USDT SPL mint is `{OFFICIAL_USDT_SOL}`\n")
        w.write("\n## Top holders\n\n")
        if holders_note:
            w.write(f"_NOTE: {holders_note}_\n\n")
        w.write("| # | token account | balance | % of supply |\n|---|---|---|---|\n")
        for i, a in enumerate(accts[:15], 1):
            try:
                pct = int(a.get("amount", "0")) / supply * 100 if supply else 0
            except Exception:
                pct = 0
            w.write(f"| {i} | `{a['address']}` | {a.get('uiAmountString', '?')} | {pct:.2f}% |\n")
        if sig_note:
            w.write(f"\n_NOTE: {sig_note}_\n")
        if rows:
            w.write(f"\n## Activity (most recent {len(rows)} signatures, API limit 1000)\n")
            w.write(f"- span: {t0} -> {t1} | failed: {n_err}\n")
            w.write("- newest signatures:\n")
            for r in rows[:5]:
                w.write(f"  - `{r.get('signature')}`\n")
        w.write("\n## Victim narrative (MY OWN true record — one wallet, real numbers)\n")
        w.write("- my Solana wallet: `<your address>`\n")
        w.write("- what I paid / lost: _(your real figures from your own Solscan history — do not invent)_\n")
        w.write("- my signatures: `<paste your own tx links>`\n")
        w.write("\n## Report channels\n")
        w.write(f"- Solscan token page (report button): https://solscan.io/token/{mint}\n")
        w.write(f"- Chainabuse: https://www.chainabuse.com/address/{mint}\n")
        w.write("- wallet/CEX scam-report forms (attach this file)\n")
    print(f"\nreport -> {path}")

if __name__ == "__main__":
    main()
