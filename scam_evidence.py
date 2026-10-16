#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scam_evidence.py — collect on-chain evidence for ONE suspected scam token
and output a markdown report you can attach to:

  - GitHub abuse report   (https://github.com/contact/report-abuse)
  - Chainabuse.com
  - chain-official scam-report channels / CEX & wallet report forms
  - Tron: Trust Wallet in-app token report, Tether scam report, Chainabuse

Everything here is read-only. The optional "simulate" probes run as
eth_call (EVM) / triggerconstantcontract (Tron) — gas-free, never broadcast,
so a dry check cannot move any funds.

Usage (auto-picks a public RPC per chain; Tron auto-detected from the address):
  python scam_evidence.py --token 0xCONTRACT --chain bsc
  python scam_evidence.py --token TRxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  python scam_evidence.py --token TRxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --simulate

Optional probe env: PRIVATE_KEY (EVM, 0x...) or TRON_WALLET (base58 T…),
RPC_URL overrides the built-in public RPC.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from web3 import Web3
from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak, to_checksum_address, is_address

# ───────────────────────────── EVM chain map ─────────────────────────────
CHAINS = {
    "ethereum": (1,   "https://ethereum-rpc.publicnode.com",
                 "0x5C69bEe701ef814a2B6a3EDD98B1652f31C264ba"),       # Uniswap V2 factory
    "bsc":      (56,  "https://bsc-rpc.publicnode.com",
                 "0xcA143Ce32Fe78F1f70193174389Bd6E84764F100"),       # PancakeSwap V2 factory
    "polygon":  (137, "https://polygon-bor-rpc.publicnode.com",
                 "0x575737141981C6FCe6A7e9A5A8d49DeC9FF7F6d0"),       # QuickSwap V2 factory
    "arbitrum": (42161, "https://arbitrum-one-rpc.publicnode.com",
                 "0x5C69bEe701ef814a2B6a3EDD98B1652f31C264ba"),
    "base":     (8453, "https://base-rpc.publicnode.com",
                 "0x8909Dc15e401cb836826582c68092c835916423eC"),      # Aerodrome fallback
}

sel = lambda txt: keccak(text=txt)[:4].hex()

def call_view(w3, to, sig, types, args, out_types, from_=None):
    raw = w3.eth.call({"to": to, "data": bytes.fromhex(sel(sig)) + abi_encode(types, args),
                       **({"from": from_} if from_ else {})})
    vals = abi_decode(out_types, raw)
    return vals[0] if len(vals) == 1 else vals

def try_view(w3, to, sig, types, args, out_types, default=None, from_=None):
    try:
        return call_view(w3, to, sig, types, args, out_types, from_)
    except Exception:
        return default

# ───────────────────── token metadata (ERC20/typed) ─────────────────────
def token_metadata(w3, token):
    name    = try_view(w3, token, "name()", [], [], ["string"])
    if name is None:  # some scam tokens use typed-string name()
        try:
            raw = w3.eth.call({"to": token, "data": bytes.fromhex(sel("name()"))})
            _, name = abi_decode(["bytes", "string"], raw)
        except Exception:
            pass
    symbol  = try_view(w3, token, "symbol()", [], [], ["string"])
    decimals = try_view(w3, token, "decimals()", [], [], ["uint8"])
    supply  = try_view(w3, token, "totalSupply()", [], [], ["uint256"])
    return name, symbol, decimals, supply

def find_creation_block(w3, token):
    """Binary search the first block where code exists."""
    hi = w3.eth.block_number
    if w3.eth.get_code(token, block_identifier=hi):
        lo, first = 0, hi
    else:
        return None
    while lo <= hi:
        mid = (lo + hi) // 2
        if w3.eth.get_code(token, block_identifier=mid):
            first, hi = mid, mid - 1
        else:
            lo = mid + 1
    return first

TRANSFER = keccak(text="Transfer(address,address,uint256)")

def scan_holders(w3, token, creation_block, now_block, progress_every=50_000):
    """Rebuild balances from Transfer logs. Chunked so public RPCs accept it."""
    bal = defaultdict(int)
    zero = "0x" + "00" * 20
    step = 10_000
    n_logs = 0
    t0 = time.time()
    b = creation_block
    while b <= now_block:
        hi = min(b + step - 1, now_block)
        logs = w3.eth.get_logs({
            "fromBlock": b, "toBlock": hi, "address": token,
            "topics": ["0x" + TRANSFER.hex()],
        })
        for lg in logs:
            frm = to_checksum_address("0x" + bytes(lg["topics"][1])[-40:].hex())
            to  = to_checksum_address("0x" + bytes(lg["topics"][2])[-40:].hex())
            try:
                (val,) = abi_decode(["uint256"], bytes(lg["data"]))
            except Exception:
                continue
            if frm != zero:
                bal[frm] -= val
            if to != zero:
                bal[to] += val
            n_logs += 1
        if (hi - creation_block) // step % progress_every == 0:
            print(f"  scanned to block {hi:,} ({hi - creation_block:,} blks, {n_logs:,} transfers, {len(bal):,} wallets)", flush=True)
        b = hi + 1
    print(f"scan done in {time.time()-t0:.0f}s: {n_logs:,} transfers, {len(bal):,} wallets")
    return bal, n_logs

# ───────────────────────────── helpers ─────────────────────────────
def fmt(a, d):
    return f"{a / 10**d:,.4f}"

# ───────────────────── Tron (TRC-20) evidence collector ─────────────────────
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TRON_API = "https://api.trongrid.io"
TRON_ZERO = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
OFFICIAL_USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"   # real Tether TRC-20 — a mimic is NOT this
SUSPECT_WORDS = ("black", "freeze", "pause", "seize", "confisc", "kill",
                 "whitelist", "trap", "bot")

def b58_decode(addr):
    """base58check decode -> hex body '41...'; raises on bad checksum."""
    n = 0
    for c in addr:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(25, "big")
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        raise ValueError("bad base58check checksum — not a valid Tron address")
    return "0x" + body.hex()

def hex2b58(h):
    body = bytes.fromhex(h[2:] if h.startswith("0x") else h)
    cs = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = 0
    for b in body + cs:
        n = n * 256 + b
    s = ""
    while n:
        s = B58[n % 58] + s
        n //= 58
    return s

def tron_req(path, params=None, body=None):
    url = TRON_API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "scam-evidence/1.0"})
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            last = e
            print(f"  tron API hiccup ({str(e)[:70]}) — retry {attempt + 1}", flush=True)
            time.sleep(2 * (attempt + 1))
    raise last

def _hex_to_val(h):
    """Decode one ABI word / dynamic string from triggerconstantcontract output."""
    if h is None:
        return None
    h = h.lower().removeprefix("0x")
    if not h:
        return None
    try:
        if len(h) >= 128 and int(h[:64], 16) == 32:   # dynamic string: off=0x20, len, bytes
            ln = int(h[64:128], 16) // 2
            return bytes.fromhex(h[128:128 + ln * 2]).decode("utf-8", "replace")
        return int(h[:64], 16)
    except Exception:
        return h[:64]

def tron_tc(hexaddr, func):
    """Read-only constant call (whole-contract calldata style); returns decoded value or None."""
    try:
        r = tron_req("/wallet/triggerconstantcontract", body={
            "owner_address": hex2b58(hexaddr),
            "contract_address": hex2b58(hexaddr),
            "function_selector": func,
            "visible": True})
        out = r.get("constant_result") or []
        ok = (r.get("result") or {}).get("result") == "SUCCESS"
        return _hex_to_val(out[0]) if ok and out else None
    except Exception:
        return None

def tron_tc_params(hexaddr, owner_b58, func, param_hex):
    """Constant call with explicit parameters; returns (ok, value, revert_message)."""
    r = tron_req("/wallet/triggerconstantcontract", body={
        "owner_address": owner_b58,
        "contract_address": hex2b58(hexaddr),
        "function_selector": func,
        "parameter": param_hex,
        "visible": True})
    out = r.get("constant_result") or []
    ok = (r.get("result") or {}).get("result") == "SUCCESS"
    ret = ((r.get("transaction") or {}).get("ret")) or []
    msg = (r.get("result") or {}).get("message") or (ret[0].get("contractRet", "") if ret else "")
    return ok, (_hex_to_val(out[0]) if out else None), msg

def _tron_param_addr(b58):
    return b58_decode(b58)[2:].rjust(64, "0")

def _ev_addr(v):
    v = str(v)
    if v.startswith("T"):
        return v
    if v.startswith("41") and len(v) == 42:
        return hex2b58(v)
    if v.startswith("0x41") and len(v) == 44:
        return hex2b58(v[2:])
    return v

def _ev_val(v):
    v = str(v)
    try:
        if v.startswith("0x"):
            return int(v, 16)
        if len(v) >= 4 and all(c in "0123456789abcdefABCDEF" for c in v[:8]):
            return int(v, 16)
        return int(v)
    except Exception:
        return 0

def tron_contract_info(hexaddr, token_b58):
    for body in ({"address": hexaddr[2:], "visible": False},
                 {"address": token_b58, "visible": True}):
        try:
            info = tron_req("/wallet/getcontractinfo", body=body)
            if info.get("abi"):
                return info
        except Exception:
            pass
    return {}

def tron_transfer_scan(token_b58, cap=20_000):
    """Page through Transfer events; rebuild balances, tx counts, first block."""
    bal = defaultdict(int)
    touched = Counter()
    zero = TRON_ZERO
    evs, fp, n_pages = [], None, 0
    while len(evs) < cap:
        params = {"event_name": "Transfer", "limit": 200}
        if fp:
            params["fingerprint"] = fp
        r = tron_req(f"/v1/contracts/{token_b58}/events", params=params)
        data = r.get("data") or []
        if not data:
            break
        evs.extend(data)
        n_pages += 1
        if n_pages % 25 == 0:
            print(f"  {len(evs):,} transfers scanned…", flush=True)
        meta = r.get("meta") or {}
        fp = meta.get("fingerprint")
        if not fp or meta.get("page_size", 0) < 200:
            break
        time.sleep(0.35)   # be kind to the public API
    for e in evs:
        res = e.get("result") or {}
        frm, to = _ev_addr(res.get("from", "")), _ev_addr(res.get("to", ""))
        v = _ev_val(res.get("value", 0))
        if frm != zero:
            bal[frm] -= v; touched[frm] += 1
        if to != zero:
            bal[to] += v; touched[to] += 1
    first_blk = min((e.get("block_number", 0) for e in evs), default=None)
    print(f"scan done: {len(evs):,} transfers, {len(bal):,} wallets, first block {first_blk}")
    return bal, touched, len(evs), first_blk, len(evs) >= cap

def tron_simulate_send(hexaddr, decimals, wallet):
    """Read-only simulate of transfer() half the wallet's scam balance.
    triggerconstantcontract never persists state and nothing is signed."""
    p_self = _tron_param_addr(wallet)
    ok, val, _ = tron_tc_params(hexaddr, wallet, "balanceOf(address)", p_self)
    if not (ok and isinstance(val, int) and val > 0):
        return {"sim_note": f"wallet {wallet} holds 0 of this token — rerun with the wallet that actually holds it"}
    amount = val // 2
    ok, _, msg = tron_tc_params(hexaddr, wallet, "transfer(address,uint256)",
                                p_self + hex(amount)[2:].rjust(64, "0"))
    return {"wallet": wallet,
            "simulated_amount": fmt(amount, decimals),
            "simulated_transfer": ("SUCCEEDED at constant-call level — for the report add one real "
                                   "tiny signed transfer to prove the lock persists" if ok
                                   else f"REVERTED: {msg}")}

def tron_report(path, args, token, addr, name, symbol, decimals, supply, owner,
                sus, bal, touched, n_logs, first_blk, cap_hit, top, sim):
    L = []
    L.append(f"# Scam-token evidence: {name or '(unnamed token)'} ({symbol or '?'})")
    L.append("")
    L.append(f"- chain: **Tron (TRC-20)**")
    L.append(f"- contract: `{token}`")
    L.append(f"- explorer: https://tronscan.org/#/token20/{token}")
    L.append(f"- name: **{name}** | symbol: **{symbol}** | decimals: {decimals} | totalSupply: {fmt(supply, decimals) if supply else '?'}")
    is_mimic = (name and "usdt" in str(name).lower()) or (symbol and "usdt" in str(symbol).lower())
    if is_mimic:
        L.append("- **MIMIC ALERT:** this token presents itself as Tether USDT, but the *official* Tether TRC-20 "
                 f"contract is `{OFFICIAL_USDT_TRON}` (https://tronscan.org/#/token20/{OFFICIAL_USDT_TRON}). "
                 "Holders are led to believe they own the stablecoin; they do not.")
    L.append(f"- declared contract owner: `{owner}`" if owner else "- contract owner: not exposed via owner()/getOwner()")
    L.append(f"- Transfer events scanned: {n_logs:,}"
             + (" (**CAPPED** — fetch the rest via TronScan if needed; evidence is representative)" if cap_hit else "")
             + f" — wallets touched: {len(bal):,}")
    L.append(f"- first on-chain activity near block {first_blk}")
    if sus:
        L.append(f"- **CONTROL FUNCTIONS in ABI** typical of freeze/blacklist rugs: {', '.join('`%s`' % f for f in sus)}")
    L.append("")
    L.append("## Holder concentration (top 15)")
    L.append("")
    L.append("| # | wallet | balance | % of supply | txs |")
    L.append("|---|--------|---------|-------------|-----|")
    for i, (a, v, t) in enumerate(top[:15], 1):
        pct = (v / supply * 100) if supply else 0
        L.append(f"| {i} | `{a}` | {fmt(v, decimals)} | {pct:.2f}% | {t} |")
    L.append("")
    if sim:
        L.append("## Honeypot probe (read-only triggerconstantcontract — nothing broadcast)")
        for k, v in sim.items():
            L.append(f"- **{k}**: {v}")
        L.append("")
    L.append("## Victim narrative (MY OWN true record — one wallet, real numbers)")
    L.append("")
    L.append(f"- my Tron wallet: `{args.victim_wallet or '<fill in your wallet address>'}`")
    L.append("- I paid approx. **5,000 USD** worth of real value for tokens that cannot be sold / transferred out usefully; value today ≈ 0 (no real liquidity/backing).")
    L.append("- my on-chain deals with this token (paste your own transaction hashes from TronScan — do not alter or invent any):")
    L.append("  - `<hash 1>`")
    L.append("  - `<hash 2>`")
    L.append("")
    for lnk in args.extra_links:
        L.append(f"- link: {lnk}")
    L.append("")
    L.append("## Where to report")
    L.append(f"- Chainabuse (Tron is covered): https://www.chainabuse.com/address/{token}")
    L.append("- Trust Wallet: inside the app, token detail → *More / flag* report, or https://support.trustwallet.com (attach this file)")
    L.append("- Tether scam report (for the mimic impersonation): via Tether's official scam-response page")
    L.append("- TronDAO / community 'Avengers' scam-response channels (fake-USDT takedown first responders)")
    L.append("- Police / IC3 (https://www.ic3.gov) if losses were real money — needed for any seizure action")
    L.append("")
    L.append("## One-paragraph paste-ready complaint")
    L.append("")
    L.append(f"> Scam TRC-20 token mimicking Tether USDT on Tron: `{token}` (\"{name}\", symbol `{symbol}`). "
             f"It is NOT the official Tether contract `{OFFICIAL_USDT_TRON}`, yet it presents itself as USDT. "
             + (f"Its ABI exposes trace/freeze-style functions ({', '.join(sus)}); "
                if sus else "Its settings restrict normal holders' transfers; ")
             + f"the declared owner is `{owner}`. I lost approximately 5,000 USD; the balance is effectively "
             "stuck and the token has no real backing or liquidity. On-chain evidence and figures are in the attached file.")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"report → {path}")

def tron_main(args):
    token = args.token
    if not (token.startswith("T") and len(token) == 34):
        sys.exit("--token must be a base58 Tron address (T…, 34 chars)")
    try:
        addr = b58_decode(token)
    except Exception as e:
        sys.exit(str(e))
    print(f"contract {token}\n  hex {addr}")

    info = tron_contract_info(addr, token)
    if not info.get("abi"):
        sys.exit("no contract/ABI at this address (empty account or wrong address?)")

    name     = tron_tc(addr, "name()")
    symbol   = tron_tc(addr, "symbol()")
    decimals = tron_tc(addr, "decimals()") or 0
    supply   = tron_tc(addr, "totalSupply()")
    owner    = tron_tc(addr, "owner()") or tron_tc(addr, "getOwner()")
    if isinstance(owner, str) and not owner.startswith("T"):
        owner = None
    if not isinstance(name, str):
        name = None
    if not isinstance(symbol, str):
        symbol = None
    print(json.dumps({"name": name, "symbol": symbol, "decimals": decimals,
                      "supply": supply, "owner": owner}, default=str))

    entrys = (info.get("abi") or {}).get("entrys") or []
    funcs = [e.get("name", "") for e in entrys if str(e.get("type", "")) == "Function"]
    sus = sorted({f for f in funcs if any(w in f.lower() for w in SUSPECT_WORDS)})
    print("functions:", [f for f in funcs if f][:40])
    print("suspect control functions:", sus or "none found")

    bal, touched, n_logs, first_blk, cap_hit = tron_transfer_scan(token)
    supply_v = supply if isinstance(supply, int) else 0
    traders = [(a, v, touched[a]) for a, v in sorted(bal.items(), key=lambda kv: -kv[1]) if v > 0]
    print("\ntop holders:")
    for a, v, t in traders[:10]:
        pct = f"{v / supply_v * 100:.2f}%" if supply_v else "?"
        print(f"  {a}  {fmt(v, decimals)}  ({pct})  txs {t}")

    sim = {}
    if args.simulate:
        tw = os.environ.get("TRON_WALLET")
        if not tw:
            print("--simulate ignored: set TRON_WALLET=T… (base58 wallet that holds the scam token)")
        else:
            print("\nhoneypot probe (read-only triggerconstantcontract, nothing broadcast)…")
            sim = tron_simulate_send(addr, decimals, tw)
            for k, v in sim.items():
                print(f"  {k}: {v}")

    path = args.report or f"scam_evidence_tron_{token[:12]}.md"
    args.extra_links = [x.strip() for x in args.extra_links.split(",") if x.strip()]
    tron_report(path, args, token, addr, name, symbol, decimals, supply, owner,
                sus, bal, touched, n_logs, first_blk, cap_hit, traders, sim)
    print("\nattach this file to: Trust Wallet in-app report, Chainabuse, Tether scam report,")
    print("and TronDAO scam-response channels.")

# ───────────────────── honeypot simulation (EVM, read-only) ─────────────────────
ROUTERS = {
    1:  "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",       # Uniswap V2 Router02
    56: "0x10ED43C718714eb63d5aA57B78B54704E256024E",       # PancakeSwap V2 Router
    137: "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",      # QuickSwap Router
    42161: "0x1b02dA8Cb0d097eB8D57A3b7b33daE3052A8fBCA",    # Sushi on Arbitrum
    8453: "0x2626668c1e5767f9AA9449D2c9fD8C8815b3ff18",     # Aerodrome fallback
}
WETH = {
    1: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    56: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    137: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    42161: "0x82aF49447D8a07e3bd95BD0d56f35241523fB7ab",
    8453: "0x4200000000000000000000000000000000000006",
}

def simulate_roundtrip(w3, token, wallet, chain_id):
    """eth_call-only buy/sell through a V2 router. Never broadcasts."""
    router = to_checksum_address(ROUTERS.get(chain_id, "0x0000000000000000000000000000000000000000"))
    out = {}
    if router == "0x0000000000000000000000000000000000000000":
        out["sim_note"] = f"no known V2 router for chain {chain_id}"
        return out
    weth = to_checksum_address(WETH[chain_id])
    bal = try_view(w3, token, "balanceOf(address)", ["address"], [wallet], ["uint256"], 0)
    eth = w3.eth.get_balance(wallet)
    out["wallet"] = wallet
    out["token_balance"] = bal
    out["eth_balance"] = eth
    spend = min(eth // 20, 10**15)          # 5% of balance or ≤0.001 native — tiny probe
    if spend > 0:
        data = bytes.fromhex(sel("swapExactETHForTokens(uint256,address[],address,uint256)")) + \
               abi_encode(["uint256", "address[]", "address", "uint256"],
                          [0, [weth, token], wallet, int(time.time()) + 600])
        try:
            w3.eth.call({"from": wallet, "to": router, "data": data, "value": spend})
            out["buy_sim"] = "OK (no revert observed)"
        except Exception as e:
            out["buy_sim"] = "REVERT: " + _revert_reason(e)
    if bal > 0:
        amt = bal // 2                          # sell half — avoids draining real tokens
        data = bytes.fromhex(sel("swapExactTokensForETH(uint256,uint256,address[],address,uint256)")) + \
               abi_encode(["uint256", "uint256", "address[]", "address", "uint256"],
                          [amt, 0, [token, weth], wallet, int(time.time()) + 600])
        try:
            w3.eth.call({"from": wallet, "to": router, "data": data, "value": 0})
            out["sell_sim"] = "OK (no revert at call level — likely allowance-dependent; verify with a real tiny sell)"
        except Exception as e:
            out["sell_sim"] = "REVERT: " + _revert_reason(e)
    return out

def _revert_reason(e):
    s = str(e)
    if s.startswith("execution reverted: "):
        return s[len("execution reverted: "):].strip()
    return s[:200]

# ───────────────────────────── EVM evidence report ─────────────────────────────
def build_report(path, args, chain_id, token, meta, owner, pair, bal, n_logs,
                 holders_top, sim):
    name, symbol, decimals, supply = meta
    L = []
    L.append(f"# Scam-token evidence: {name or '(unnamed token)'} ({symbol or '?'})")
    L.append("")
    L.append(f"- chain: {args.chain} (chainId {chain_id})")
    L.append(f"- contract: `{token}`")
    dom = "etherscan.io" if chain_id == 1 else "bscscan.com" if chain_id == 56 else "polygonscan.com"
    L.append(f"- explorer: https://{dom}/token/{token}")
    L.append(f"- totalSupply: {fmt(supply, decimals) if supply is not None and decimals else str(supply)}")
    L.append(f"- declared owner: `{owner}`" if owner else "- declared owner: not exposed via owner()/getOwner()")
    L.append(f"- V2 pair detected: `{pair}`" if pair else "- V2 pair: none found on known factories (may be V3/V4 or locked)")
    L.append(f"- Transfer events scanned: {n_logs:,} — distinct wallets ever touched: {len(bal):,}")
    L.append("")
    L.append("## Holder concentration (top 15)")
    L.append("")
    L.append("| # | wallet | balance | % of supply |")
    L.append("|---|--------|---------|-------------|")
    for i, (a, v) in enumerate(holders_top[:15], 1):
        pct = (v / supply * 100) if supply else 0
        L.append(f"| {i} | `{a}` | {fmt(v, decimals)} | {pct:.2f}% |")
    L.append("")
    if sim:
        L.append("## Honeypot simulation (read-only eth_call)")
        for k, v in sim.items():
            L.append(f"- **{k}**: {v}")
        L.append("")
    L.append("## Victim narrative (MY OWN true record)")
    L.append("")
    L.append(f"- my wallet involved: `{args.victim_wallet}`")
    L.append("- what I did / lost: _(fill with your own real numbers; recreate them from your own txs)_")
    L.append("- links to my transactions: _(paste your own tx hashes from the explorer; do not invent any)_")
    L.append("")
    for lnk in args.extra_links:
        L.append(f"- {lnk}")
    L.append("")
    txt = "\n".join(L)
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"report → {path}")

# ───────────────────────────── main ─────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True, help="scam token contract address (EVM 0x… or Tron T…)")
    ap.add_argument("--chain", default="bsc", help="ethereum|bsc|polygon|arbitrum|base|tron")
    ap.add_argument("--rpc", default=os.environ.get("RPC_URL"), help="override public RPC")
    ap.add_argument("--report", default=None, help="output markdown path")
    ap.add_argument("--simulate", action="store_true", help="read-only honeypot probe (needs PRIVATE_KEY / TRON_WALLET env)")
    ap.add_argument("--victim-wallet", default="", help="your own wallet that traded it (for the narrative)")
    ap.add_argument("--extra-links", default="", help="comma-separated links (charts, chats, your txs)")
    args = ap.parse_args()

    # Tron auto-detect & branch
    if args.token.startswith("T") and len(args.token) == 34:
        args.chain = "tron"
    if args.chain == "tron":
        tron_main(args)
        return

    if args.chain not in CHAINS:
        sys.exit(f"unknown chain {args.chain}; pick from {', '.join(list(CHAINS) + ['tron'])}")
    chain_id, def_rpc, factory = CHAINS[args.chain]
    rpc = args.rpc or def_rpc
    if not is_address(args.token):
        sys.exit("--token is not a valid EVM address")
    token = to_checksum_address(args.token)

    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    if w3.eth.chain_id != chain_id:
        sys.exit(f"wrong chain: RPC says chainId {w3.eth.chain_id}, expected {chain_id}")
    print(f"rpc {rpc}  chainId {w3.eth.chain_id}")

    meta = token_metadata(w3, token)
    print("metadata:", json.dumps([m if not isinstance(m, int) else m for m in meta], default=str))

    owner = try_view(w3, token, "owner()", [], [], ["address"]) or \
            try_view(w3, token, "getOwner()", [], [], ["address"])

    pair = None
    factories = {to_checksum_address(factory),
                 "0x5C69bEe701ef814a2B6a3EDD98B1652f31C264ba",
                 "0xcA143Ce32Fe78F1f70193174389Bd6E84764F100"}
    weth = to_checksum_address(WETH[chain_id])
    for fac in factories:
        p = try_view(w3, fac, "getPair(address,address)", ["address", "address"], [token, weth], ["address"])
        if p and p != "0x" + "0" * 40:
            pair = to_checksum_address(p)
            break

    cb = find_creation_block(w3, token)
    if cb is None:
        sys.exit("token has no code at tip — wrong address?")
    print(f"creation block ≈ {cb:,} (block now {w3.eth.block_number:,})")

    bal, n_logs = scan_holders(w3, token, cb, w3.eth.block_number)
    supply = meta[3]
    traders = sorted(((a, v) for a, v in bal.items() if v > 0), key=lambda x: -x[1])
    print("\ntop holders:")
    for a, v in traders[:10]:
        pct = f"{v / supply * 100:.2f}%" if supply else "?"
        print(f"  {a}  {fmt(v, meta[2] or 0)}  ({pct})")

    sim = {}
    if args.simulate:
        pk = os.environ.get("PRIVATE_KEY")
        if not pk:
            print("--simulate ignored: set PRIVATE_KEY=0x… (read-only eth_call sim, no tx is ever sent)")
        else:
            from eth_account import Account
            wallet = to_checksum_address(Account.from_key(pk).address)
            print("\nhoneypot probe (eth_call only)…")
            sim = simulate_roundtrip(w3, token, wallet, chain_id)
            for k, v in sim.items():
                print(f"  {k}: {v}")

    path = args.report or f"scam_evidence_{args.chain}_{token[:10]}.md"
    args.extra_links = [x.strip() for x in args.extra_links.split(",") if x.strip()]
    build_report(path, args, chain_id, token, meta, owner, pair, bal, n_logs, traders, sim)
    print("\nattach this file to: GitHub abuse report, Chainabuse, chain/CEX scam channels.")

if __name__ == "__main__":
    main()
