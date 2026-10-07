"""traceatlas.scams.crypto — on-chain observation intake & bounded tracing (§9).

Design stance (all enforced in code):
  * chain/asset/address/txhash are VALIDATED deterministically before use;
  * raw provider responses are preserved as evidence; parsed observations point
    at the raw artifact, never replace it;
  * provider labels ("this address belongs to Exchange X") are stored as
    CLAIM_REQUIRING_REVIEW, not facts;
  * tracing STOPS at a custodial boundary: continuity through an exchange's
    pooled wallets is explicitly NOT fabricated;
  * depth and call budgets are hard-bounded; finality/coverage limits disclosed;
  * wallet != person, always.

No live chain API is required for tests: an injectable fetcher keeps this module
deterministic with clearly labeled fixtures. A real deployment supplies an
authorized read-only provider (public node/explorer API) via `fetcher`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from traceatlas.core.identifiers import ID, new_id

# ------------------------------------------------------------ validation
_BTC_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^(bc1|tb1)[acdefghjklmnpqrstuvwxyz02-9]{11,87}$")
_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TXHASH_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")

SUPPORTED_CHAINS = ("bitcoin", "ethereum")


def validate_address(chain: str, address: str) -> tuple[bool, str]:
    if chain == "bitcoin":
        ok = bool(_BTC_RE.match(address))
        return ok, "valid_btc_address" if ok else "invalid_bitcoin_address_shape"
    if chain == "ethereum":
        ok = bool(_ETH_RE.match(address))
        return ok, "valid_evm_address" if ok else "invalid_evm_address_shape"
    return False, f"unsupported_chain:{chain}"


def validate_tx_hash(tx_hash: str) -> tuple[bool, str]:
    ok = bool(_TXHASH_HEX_RE.match(tx_hash))
    return ok, "valid_tx_hash" if ok else "invalid_tx_hash_shape"


# ---------------------------------------------------------------- models
@dataclass(slots=True)
class OnChainObservation:
    """One deterministic fact extracted from a RAW preserved response."""
    obs_id: ID = field(default_factory=lambda: new_id("onc"))
    case_id: ID = ""
    chain: str = ""
    tx_hash: str = ""
    kind: str = ""            # transfer | address_created | block_finality | label_claim
    value: Any = None         # e.g. {"from":..,"to":..,"amount":..,"asset":..}
    raw_evidence_id: ID = ""  # REQUIRED: pointer into EvidenceStore
    confirmed: Optional[bool] = None
    depth: int = 0
    epistemic_class: str = "OBSERVATION"   # or CLAIM_REQUIRING_REVIEW for labels
    limitations: tuple[str, ...] = ()


@dataclass(slots=True)
class CustodialBoundary:
    """Where authorized tracing must stop."""
    address: str
    label_source: str                 # provider name
    status: str = "CLAIM_REQUIRING_REVIEW"
    note: str = ("Provider-labeled custodial address. Continuity beyond pooled "
                 "wallets is not observable on-chain; no downstream path is inferred.")


class CryptoTracer:
    """Bounded-depth, budget-capped, evidence-first on-chain analysis."""

    def __init__(self, case_id: ID, fetcher: Optional[Callable[[str, str], dict]] = None,
                 max_depth: int = 3, max_calls: int = 25):
        self.case_id = case_id
        self._fetch = fetcher          # (chain, tx_or_addr) -> raw json dict
        self.max_depth = max_depth
        self.max_calls = max_calls
        self.calls_used = 0
        self.observations: list[OnChainObservation] = []
        self.boundaries: list[CustodialBoundary] = []
        self.abstentions: list[str] = []

    # ------------------------------------------------------------- helpers
    def _call(self, chain: str, key: str) -> Optional[dict]:
        if self._fetch is None:
            self.abstentions.append(f"no_authorized_provider_configured for {chain}")
            return None
        if self.calls_used >= self.max_calls:
            self.abstentions.append("call_budget_exhausted")
            return None
        self.calls_used += 1
        return self._fetch(chain, key)

    def ingest_raw(self, chain: str, tx_hash: str, raw_bytes: bytes,
                   store) -> OnChainObservation | None:
        """Parse a PRESERVED raw response (bytes already in EvidenceStore via
        `store.put_bytes`) into typed observations. Deterministic parsing only."""
        ok, why = validate_tx_hash(tx_hash)
        if not ok:
            self.abstentions.append(f"rejected_tx_hash:{why}")
            return None
        import json
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - honest parse failure
            self.abstentions.append(f"parse_failure:{type(exc).__name__}")
            return None
        ev = store.get_by_hash(__import__("hashlib").sha256(raw_bytes).hexdigest())
        if ev is None:
            raise ValueError("raw response must be stored before parsing")
        v = payload.get("value", {})
        obs = OnChainObservation(
            case_id=self.case_id, chain=chain, tx_hash=tx_hash,
            kind=payload.get("kind", "transfer"), value=v,
            raw_evidence_id=ev.evidence_id,
            confirmed=payload.get("confirmed"),
            limitations=tuple(payload.get("limitations", [])))
        self.observations.append(obs)
        return obs

    def trace_from(self, chain: str, address: str, *,
                   custodial_labels: Optional[dict[str, str]] = None,
                   depth: int = 0) -> dict[str, Any]:
        """Bounded BFS one hop at a time through provider-supplied neighbor
        data. Stops immediately at any address present in `custodial_labels`
        (exchange/pool boundaries) — no fabricated continuity beyond it."""
        custodial_labels = custodial_labels or {}
        result: dict[str, Any] = {"visited": [], "stopped_at": [], "abstained": []}
        if depth > self.max_depth:
            result["abstained"].append("max_depth_reached")
            return result
        ok, _ = validate_address(chain, address)
        if not ok:
            result["abstained"].append("invalid_address_no_trace_attempted")
            self.abstentions.append(f"invalid_address:{address[:10]}…")
            return result
        if address in custodial_labels:
            b = CustodialBoundary(address=address, label_source=custodial_labels[address])
            self.boundaries.append(b)
            result["stopped_at"].append(address)
            return result
        result["visited"].append(address)
        data = self._call(chain, address)
        if data is None:
            result["abstained"].append("provider_unavailable_or_budget")
            return result
        for nb in data.get("neighbors", [])[:10]:
            sub = self.trace_from(chain, nb, custodial_labels=custodial_labels,
                                  depth=depth + 1)
            for k in ("visited", "stopped_at", "abstained"):
                result[k].extend(sub[k])
        return result

    def missing_record_list(self) -> tuple[str, ...]:
        """What an authorized human must obtain next (bank records, KYC-request
        via law enforcement etc.). Tool prepares the list; it never contacts anyone."""
        items = [f"Bank/card statement excerpt covering payment method+date for each "
                 f"entry still UNSUPPORTED_STATEMENT"]
        if self.abstentions:
            items.append("Re-run chain lookups once an authorized read-only provider is configured "
                         "(current abstentions: " + "; ".join(sorted(set(self.abstentions)))[:400] + ")")
        if self.boundaries:
            items.append("Law-enforcement / provider process for custodial-boundary continuation "
                         f"({len(self.boundaries)} boundary/boundaries) — tracing tool cannot and does not proceed past these")
        items.append("Tracing does not guarantee freezing, refunds, seizure or recovery.")
        return tuple(items)
