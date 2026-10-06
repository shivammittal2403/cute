"""Blockchain public explorer connectors (keyless, read-only).

 * blockstream.info  -> BTC address info + transactions (BLOCKCHAININT)
 * etherscan.io API requires a key; instead we use the public Cloudflare
   Ethereum gateway eth.llama.fi is not RPC — so for ETH we use the free
   'api.etherscan.io' only when TRACEATLAS_ETHERSCAN_KEY is configured, and
   otherwise honestly report missing credentials (no fabricated data).
Raw bytes preserved as evidence. Cluster/attribution claims are NOT made:
these emit observed transaction relationships only.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

import httpx

from .base import BaseConnector, CollectResult, is_safe_url


class BlockstreamBTCConnector(BaseConnector):
    source_slug = "blockstream-btc"
    connector_type = "public_explorer"
    ADDR_RE = re.compile(r"^[13bc][a-zA-Z0-9]{20,62}$|^bc1[a-z0-9]{20,87}$")

    def collect(self, target: str, capability: str = "wallet.transactions") -> CollectResult:
        addr = target.strip()
        if not self.ADDR_RE.match(addr):
            return CollectResult(ok=False, source_uri="", error=f"not a BTC address: {addr!r}")
        url = f"https://blockstream.info/api/address/{addr}/txs"
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=20.0, headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url, error=f"{type(exc).__name__}: {exc}")
        if resp.status_code != 200:
            return CollectResult(ok=False, source_uri=url, error=f"http {resp.status_code}")
        try:
            txs = json.loads(resp.content)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from blockstream")
        now = datetime.now(timezone.utc).isoformat()
        obs = []
        for tx in (txs if isinstance(txs, list) else [])[:25]:
            vin_addrs = {v.get("prevout", {}).get("scriptpubkey_address")
                         for v in tx.get("vin", []) if v.get("prevout")}
            vout_addrs = {o.get("scriptpubkey_address") for o in tx.get("vout", [])}
            ins = sorted(a for a in vin_addrs if a)
            outs = sorted(a for a in vout_addrs if a)
            obs.append({"subject": addr, "predicate": "wallet.transaction",
                        "value": {"txid": tx.get("txid"), "inputs": ins[:10],
                                  "outputs": outs[:10],
                                  "status": tx.get("status", {})},
                        "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "blockstream.info", "tx_count": len(obs)})


class EtherscanETHConnector(BaseConnector):
    source_slug = "etherscan-eth"
    connector_type = "public_explorer"
    ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

    def collect(self, target: str, capability: str = "wallet.transactions") -> CollectResult:
        addr = target.strip().lower()
        if not self.ADDR_RE.match(addr):
            return CollectResult(ok=False, source_uri="", error=f"not an ETH address: {addr!r}")
        key = os.environ.get("TRACEATLAS_ETHERSCAN_KEY", "")
        if not key:
            return CollectResult(ok=False, source_uri="",
                                 error="credential_required: set TRACEATLAS_ETHERSCAN_KEY")
        url = ("https://api.etherscan.io/api?module=account&action=txlist"
               f"&address={addr}&startblock=0&endblock=99999999&page=1&offset=25&sort=desc&apikey={key}")
        ok, reason = is_safe_url(url)
        if not ok:
            return CollectResult(ok=False, source_uri=url, error=f"url_policy: {reason}")
        try:
            with httpx.Client(timeout=20.0, headers={"User-Agent": "TraceAtlas/0.1"}) as c:
                resp = c.get(url)
        except httpx.HTTPError as exc:
            return CollectResult(ok=False, source_uri=url, error=f"{type(exc).__name__}: {exc}")
        try:
            data = json.loads(resp.content)
        except json.JSONDecodeError:
            return CollectResult(ok=False, source_uri=url, error="invalid JSON from etherscan")
        now = datetime.now(timezone.utc).isoformat()
        obs = []
        for tx in (data.get("result") or []):
            if not isinstance(tx, dict):
                continue
            obs.append({"subject": addr, "predicate": "wallet.transaction",
                        "value": {"hash": tx.get("hash"), "from": tx.get("from"),
                                  "to": tx.get("to"), "value_eth_raw": tx.get("value"),
                                  "timestamp": tx.get("timeStamp")},
                        "observed_at": now})
        return CollectResult(ok=bool(obs), observations=obs, raw_bytes=resp.content,
                             media_type="application/json", source_uri=url,
                             meta={"provider": "etherscan"})
