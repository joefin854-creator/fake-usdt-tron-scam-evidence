#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_probe.py — read-only TRC-20 fake-token probe for TronGrid.io.

Probes any Tron contract address given as argv[1]:
  - token metadata (name/symbol/decimals/totalSupply/owner)
  - recent raw-transaction aggregation: caller wallets, transfer() recipients,
    fake-token volume, time/block span
  - standard TRC-20 Transfer-event count (0 = non-compliant mimic)

Everything is read-only (triggerconstantcontract + /v1 API). Nothing is signed,
sent or broadcast. Public API only — 429s are retried with backoff.

Usage:  python tron_probe.py TContractAddress
"""

import collections
import datetime as dt
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
OFFICIAL_USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ZERO = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
SUSPECT_WORDS = ("black", "freeze", "pause", "seize", "confisc", "kill",
                 "whitelist", "trap", "bot")


def hex2b58(hx):
    body = bytes.fromhex(hx)
    cs = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = 0
    for x in body + cs:
        n = n * 256 + x
    s = ""
    while n:
        s = B58[n % 58] + s
        n //= 58
    return s


def req(url, body=None, tries=6):
    for i in range(tries):
        try:
            rq = urllib.request.Request(
                url, data=json.dumps(body).encode() if body else None,
                headers={"Content-Type": "application/json",
                         "User-Agent": "scam-evidence/1.0"})
            with urllib.request.urlopen(rq, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < tries - 1:
                time.sleep(3 + i * 3)
                continue
            raise
        except Exception:
            if i < tries - 1:
                time.sleep(2)
                continue
            raise
    raise RuntimeError("retries exhausted")


def dec(token, fn):
    r = req("https://api.trongrid.io/wallet/triggerconstantcontract", body={
        "owner_address": token, "contract_address": token,
        "function_selector": fn, "visible": True})
    return (r.get("constant_result") or [""])[0]


def dec_string(h):
    h = (h or "").lower()
    if len(h) >= 128 and int(h[:64], 16) == 32:
        ln = int(h[64:128], 16) // 2
        return bytes.fromhex(h[128:128 + ln * 2]).decode("utf-8", "replace")
    return None


def dec_addr(h):
    h = (h or "").lower()
    if len(h) >= 66 and h[-42:-40] == "41":      # 41-prefixed 21-byte word
        return hex2b58(h[-42:])
    if len(h) >= 42:                             # plain 20-byte word
        return hex2b58("41" + h[-40:])
    return None


def main():
    token = sys.argv[1]
    plain_metadata = {
        "name": dec_string(dec(token, "name()")),
        "symbol": dec_string(dec(token, "symbol()")),
    }
    d_raw = dec(token, "decimals()")
    s_raw = dec(token, "totalSupply()")
    o_raw = dec(token, "owner()") or dec(token, "getOwner()")
    plain_metadata["decimals"] = int(d_raw, 16) if d_raw else None
    plain_metadata["totalSupply"] = int(s_raw, 16) if s_raw else None
    plain_metadata["owner"] = dec_addr(o_raw)
    print(json.dumps(plain_metadata, default=str, indent=2))
    if plain_metadata["symbol"] and "USDT" in str(plain_metadata["symbol"]).upper():
        print(f"* MIMIC: real Tether TRC-20 is {OFFICIAL_USDT_TRON} — this is not it")
    time.sleep(1.2)

    # compliant-event check
    ev = req(f"https://api.trongrid.io/v1/contracts/{token}/events?event_name=Transfer&limit=20")
    n_ev = (ev.get("meta") or {}).get("total", 0) or len(ev.get("data") or [])
    print(f"standard Transfer events visible: {n_ev}  "
          + ("(non-compliant — balances invisible to real indexers)" if n_ev == 0 else ""))

    # raw call aggregation
    callers = collections.Counter()
    recipients = collections.Counter()
    total_units, n_tx, n_transfer = 0, 0, 0
    blocks, stamps, fp = [], [], None
    for page in range(8):
        p = {"limit": 200}
        if fp:
            p["fingerprint"] = fp
        r = req("https://api.trongrid.io/v1/accounts/%s/transactions?%s"
                % (token, urllib.parse.urlencode(p)))
        data = r.get("data") or []
        if not data:
            break
        for e in data:
            n_tx += 1
            blocks.append(e.get("blockNumber"))
            stamps.append(e.get("block_timestamp"))
            v = e["raw_data"]["contract"][0]["parameter"]["value"]
            callers[hex2b58(v.get("owner_address", ""))] += 1
            b = v.get("data", "")
            if b[:8] == "a9059cbb":
                n_transfer += 1
                w1 = b[8:72]
                rec = hex2b58(w1[-42:]) if w1[-42:-40] == "41" else hex2b58("41" + w1[-40:])
                recipients[rec] += 1
                total_units += int(b[72:136], 16)
        meta = r.get("meta") or {}
        fp = meta.get("fingerprint")
        if not fp or meta.get("page_size", 0) < 200:
            break
        time.sleep(1.2)

    dec_n = plain_metadata["decimals"] or 6
    print(f"\nraw txs scanned: {n_tx} | transfer() calls: {n_transfer} | "
          f"volume: {total_units / 10**dec_n:,.2f}")
    print(f"distinct callers: {len(callers)} | distinct recipients: {len(recipients)}")
    print("top callers:")
    for w, n in callers.most_common(8):
        print(f"  {w}  {n}")
    print("top recipients:")
    for w, n in recipients.most_common(8):
        print(f"  {w}  {n}")
    if stamps:
        print("activity span:",
              dt.datetime.fromtimestamp(min(stamps) / 1000, dt.UTC), "->",
              dt.datetime.fromtimestamp(max(stamps) / 1000, dt.UTC))
        print("block span:", min(blocks), "->", max(blocks))


if __name__ == "__main__":
    main()
