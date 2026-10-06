"""traceatlas.transforms — evidence-producing, policy-bounded pivot engine.

Maltego-class transforms: typed input entity -> network or deterministic
operation -> new entities + relationships IN the graph, every one linked to
captured evidence. Transforms are selected by the AI Employee's
next-best-action layer; they never run without an authorization check and
they reuse the connector fabric (so SSRF guards, retries and evidence capture
apply uniformly).

Builtins implemented here (all wired to real connectors):
  domain.resolves_to_ip   DNS A/AAAA records for a domain            [network]
  ip.geo_context          ASN/org/location for an IP (ipwhois.co)    [network]
  ip.prefix_owner         RIR RDAP prefix allocation                 [network]
  asn.prefixes            ASN -> announced prefixes (bgp.tools)      [network]
  domain.certificates     crt.sh certificate transparency            [network]
  domain.archived_snapshots  Wayback CDX index                       [network]
  ip.reverse_dns          HackerTarget PTR                           [network]
  domain.derive_urls      deterministic scheme variants              [offline]
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from traceatlas.core.entity import Entity
from traceatlas.core.enums import EntityKind, RelationshipKind
from traceatlas.core.observation import Observation
from traceatlas.core.relationship import Relationship


@dataclass(slots=True)
class TransformManifest:
    id: str
    name: str
    description: str
    accepted_entity_types: tuple[EntityKind, ...]
    output_entity_types: tuple[EntityKind, ...]
    required_capabilities: tuple[str, ...] = ()
    network_access: bool = True
    deterministic: bool = False
    authorization_required: bool = True
    cost_class: str = "free"
    latency_class: str = "fast"
    maturity: str = "integration_tested"


@dataclass(slots=True)
class TransformResult:
    transform_id: str
    ok: bool
    new_entities: list[Entity] = field(default_factory=list)
    new_edges: list[Relationship] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    error: str = ""


class TransformRegistry:
    def __init__(self) -> None:
        self._manifests: dict[str, TransformManifest] = {}
        self._impls: dict[str, Callable] = {}

    def register(self, manifest: TransformManifest, impl) -> None:
        self._manifests[manifest.id] = manifest
        self._impls[manifest.id] = impl

    def manifests_for(self, kind: EntityKind) -> list[TransformManifest]:
        return [m for m in self._manifests.values() if kind in m.accepted_entity_types]

    def get(self, transform_id: str) -> Optional[TransformManifest]:
        return self._manifests.get(transform_id)

    def execute(self, transform_id: str, *, entity: Entity, engine_ctx) -> TransformResult:
        """engine_ctx provides: connectors (slug->obj), graph, evidence store,
        case_id, record_observation(obs), authorization_granted flag."""
        manifest = self._manifests.get(transform_id)
        if manifest is None:
            return TransformResult(transform_id, ok=False, error="unknown transform")
        if entity.kind not in manifest.accepted_entity_types:
            return TransformResult(transform_id, ok=False,
                                   error=f"{entity.kind} not accepted by {transform_id}")
        if manifest.network_access and manifest.authorization_required \
                and not getattr(engine_ctx, "authorization_granted", False):
            return TransformResult(transform_id, ok=False,
                                   error="authorization not granted; refusing network transform")
        result = self._impls[transform_id](entity, engine_ctx)
        result.transform_id = transform_id
        return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _collect(entity: Entity, ctx, slug: str, capability: str,
             edge_kind: RelationshipKind, out_kinds) -> TransformResult:
    conn = ctx.connectors.get(slug)
    if conn is None:
        return TransformResult("", ok=False, error=f"connector {slug!r} unavailable")
    res = conn.collect(entity.display_name, capability)
    result = TransformResult("", ok=res.ok, error=res.error)
    if not res.ok:
        return result
    evidence_id = None
    if getattr(res, "raw_bytes", None):
        ev = ctx.evidence.put_bytes(res.raw_bytes, source_uri=res.source_uri or slug,
                                    media_type=res.media_type, case_id=ctx.case_id)
        evidence_id = ev.evidence_id
    for o in res.observations:
        obs = Observation(case_id=ctx.case_id,
                          subject_id=o.get("subject", entity.display_name),
                          predicate=o["predicate"], value=o["value"],
                          evidence_id=evidence_id, source_id=slug)
        ctx.record_observation(obs)
        result.observations.append(obs)
        for kind, name in out_kinds(o):
            tgt = ctx.graph.add_entity(Entity(kind=kind, display_name=name,
                                              case_id=ctx.case_id,
                                              evidence_ids=(evidence_id,) if evidence_id else ()))
            edge = ctx.graph.add_relationship(Relationship(
                case_id=ctx.case_id, source_entity_id=entity.entity_id,
                target_entity_id=tgt.entity_id, kind=edge_kind,
                properties={"predicate": o["predicate"]},
                evidence_ids=(evidence_id,) if evidence_id else ()))
            result.new_entities.append(tgt)
            result.new_edges.append(edge)
    return result


# --------------------------------------------------------------------- impls
def _t_domain_dns(entity, ctx):
    def outs(o):
        v = str(o["value"])
        return [(EntityKind.IP_ADDRESS, v)] if _looks_ip(v) else []
    r = _collect(entity, ctx, "dns-system", "dns.A",
                 RelationshipKind.RESOLVES_TO, outs)
    r2 = _collect(entity, ctx, "dns-system", "dns.AAAA",
                  RelationshipKind.RESOLVES_TO, outs)
    r.ok = r.ok or r2.ok
    r.new_entities += r2.new_entities
    r.new_edges += r2.new_edges
    r.observations += r2.observations
    if not r.ok:
        r.error = r.error or r2.error
    return r


def _t_ip_geo(entity, ctx):
    def outs(o):
        p, v = o["predicate"], str(o["value"])
        if p == "ip.asn":
            return [(EntityKind.ASN, v.upper())]
        if p == "ip.organization":
            return [(EntityKind.ORGANIZATION, v)]
        if p == "ip.location":
            return [(EntityKind.LOCATION, v)]
        return []
    return _collect(entity, ctx, "ipwhois-co", "ip.geo",
                    RelationshipKind.GENERIC, outs)


def _t_prefix_owner(entity, ctx):
    def outs(o):
        if o["predicate"] == "prefix.owner":
            return [(EntityKind.ORGANIZATION, str(o["value"]))]
        return []
    return _collect(entity, ctx, "rir-rdap-ip", "prefix.owner",
                    RelationshipKind.OWNS, outs)


def _t_asn_prefixes(entity, ctx):
    def outs(o):
        if o["predicate"] == "asn.prefix":
            return [(EntityKind.UNKNOWN, str(o["value"]))]
        return []
    return _collect(entity, ctx, "bgp-tools-asn", "asn.info",
                    RelationshipKind.HOSTS, outs)


def _t_certificates(entity, ctx):
    def outs(o):
        name = str(o["subject"]).lower()
        if name and name != entity.display_name.lower():
            return [(EntityKind.DOMAIN, name)]
        return []
    return _collect(entity, ctx, "crtsh", "certificates.by_domain",
                    RelationshipKind.GENERIC, outs)


def _t_wayback(entity, ctx):
    return _collect(entity, ctx, "archive-org-wayback", "archive.snapshots",
                    RelationshipKind.DERIVED_FROM, lambda o: [])


def _t_ptr(entity, ctx):
    def outs(o):
        return [(EntityKind.DOMAIN, str(o["value"]).lower())]
    return _collect(entity, ctx, "hackertarget-reverse-dns", "dns.ptr",
                    RelationshipKind.HOSTS, outs)


def _t_derive_urls(entity, ctx):
    """Deterministic offline transform: domain -> candidate URLs (no network)."""
    d = entity.display_name.lower().removeprefix("www.")
    created: list[Entity] = []
    for scheme in ("https", "http"):
        for host in (d, f"www.{d}"):
            url = f"{scheme}://{host}/"
            e = ctx.graph.add_entity(Entity(kind=EntityKind.URL, display_name=url,
                                            case_id=ctx.case_id))
            ctx.graph.add_relationship(Relationship(
                case_id=ctx.case_id, source_entity_id=entity.entity_id,
                target_entity_id=e.entity_id, kind=RelationshipKind.GENERIC,
                properties={"derivation": "url-scheme-variant"}))
            created.append(e)
    return TransformResult("domain.derive_urls", ok=True, new_entities=created)


REGISTRY = TransformRegistry()
REGISTRY.register(TransformManifest(
    "domain.resolves_to_ip", "Domain -> IP (DNS A/AAAA)", "Live DNS resolution",
    (EntityKind.DOMAIN,), (EntityKind.IP_ADDRESS,), ("dns.A", "dns.AAAA")), _t_domain_dns)
REGISTRY.register(TransformManifest(
    "ip.geo_context", "IP -> ASN/Org/Location", "ipwhois.co enrichment",
    (EntityKind.IP_ADDRESS,), (EntityKind.ASN, EntityKind.ORGANIZATION, EntityKind.LOCATION),
    ("ip.geo",)), _t_ip_geo)
REGISTRY.register(TransformManifest(
    "ip.prefix_owner", "IP -> Prefix owner (RIR RDAP)", "official RIR allocation record",
    (EntityKind.IP_ADDRESS,), (EntityKind.ORGANIZATION,), ("prefix.owner",)), _t_prefix_owner)
REGISTRY.register(TransformManifest(
    "asn.prefixes", "ASN -> announced prefixes", "bgp.tools status API",
    (EntityKind.ASN,), (), ("asn.info",)), _t_asn_prefixes)
REGISTRY.register(TransformManifest(
    "domain.certificates", "Domain -> CT certificates/subdomains", "crt.sh",
    (EntityKind.DOMAIN,), (EntityKind.DOMAIN,), ("certificates.by_domain",)), _t_certificates)
REGISTRY.register(TransformManifest(
    "domain.archived_snapshots", "Domain -> Wayback snapshots", "Internet Archive CDX",
    (EntityKind.DOMAIN,), (), ("archive.snapshots",)), _t_wayback)
REGISTRY.register(TransformManifest(
    "ip.reverse_dns", "IP -> PTR hostnames", "HackerTarget reverse DNS",
    (EntityKind.IP_ADDRESS,), (EntityKind.DOMAIN,), ("dns.ptr",)), _t_ptr)
REGISTRY.register(TransformManifest(
    "domain.derive_urls", "Domain -> URL variants", "deterministic, offline",
    (EntityKind.DOMAIN,), (EntityKind.URL,), (), network_access=False,
    deterministic=True, authorization_required=False), _t_derive_urls)
