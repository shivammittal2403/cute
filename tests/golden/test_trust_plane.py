"""Trust-plane golden tests: source independence, contradictions, report + replay manifest.

These test the REAL implemented engines (verification/independence.py,
verification/contradictions.py, reporting/report_manager.py) against the real
core domain models — no stubs, no fabricated support.
"""
from traceatlas.core import Claim, Citation, Entity, Evidence, Observation
from traceatlas.core.enums import ClaimStatus, EntityKind

from traceatlas.verification.independence import EvidenceDoc, IndependenceEngine
from traceatlas.verification.contradictions import ContradictionDetector
from traceatlas.reporting.report_manager import ReportManager


def _doc(text: str, eid: str, slug: str = "", pub: str = "", upstream=None, sha=""):
    return EvidenceDoc(evidence_id=eid, source_slug=slug or eid,
                       publisher_domain=pub, text=text,
                       upstream_source_id=upstream, sha256=sha)


class TestSourceIndependence:
    def setup_method(self):
        self.eng = IndependenceEngine()

    def test_identical_hash_dependent(self):
        a = _doc("whatever text", "ev-a", slug="x1", sha="deadbeef")
        b = _doc("different wrapper text", "ev-b", slug="x2", sha="deadbeef")
        kind, why = self.eng.classify_pair(a, b)
        assert kind.value == "DEPENDENT"
        assert "hash" in why

    def test_exact_copy_near_dup_dependent(self):
        text = ("Example Corp announced record quarterly earnings today in Mumbai "
                "citing strong international demand and new cloud contracts.")
        a = _doc(text, "ev-1", slug="x1", pub="wire1.test")
        b = _doc(text, "ev-2", slug="x2", pub="wire2.test")
        kind, _ = self.eng.classify_pair(a, b)
        assert kind.value == "DEPENDENT"

    def test_syndication_metadata_dependent(self):
        a = _doc("Article body about Q3 growth at Example Corporation with details.",
                 "ev-1", slug="prnewswire")
        b = _doc("Slightly rewritten article body regarding Q3 expansion of Example Corp.",
                 "ev-2", slug="news-site-x", upstream="prnewswire")
        kind, why = self.eng.classify_pair(a, b)
        assert kind.value == "DEPENDENT"
        assert "syndication" in why or "upstream" in why

    def test_distinct_content_independent(self):
        a = _doc("RDAP record shows registrant Example Corp for domain example.com since 1995.",
                 "ev-rdap", slug="rdap", pub="rdap.verisign.com")
        b = _doc("DNS A record for example.com resolves to 93.184.216.34 in London.",
                 "ev-dns", slug="dns", pub="resolver.internal")
        kind, _ = self.eng.classify_pair(a, b)
        assert kind.value == "INDEPENDENT"

    def test_copied_urls_not_counted_as_corroboration(self):
        """The core requirement: 3 copies + 1 independent => fewer clusters than docs."""
        copy = ("Example Corporation filed annual returns with the registry on March 3, "
                "listing two directors and revenue of twelve million.")
        docs = [_doc(copy, f"ev-copy{i}", slug=f"site{i}", pub=f"site{i}.test")
                for i in range(3)]
        docs.append(_doc("Independent DNS query returned AAAA records for the same host name.",
                         "ev-dns", slug="dns", pub="dns.test"))
        reps, notes = self.eng.independent_sources_for_observation(docs)
        assert len(reps) < len(docs)          # copies collapsed
        assert any("DEPENDENT" in n[1] for n in notes)


class TestContradictions:
    def _obs(self, subject, pred, value, source, evidence):
        return Observation(subject_id=subject, predicate=pred, value=value,
                           source_id=source, evidence_id=evidence)

    def test_value_conflict_preserves_both_sides(self):
        o1 = self._obs("dom-example", "registrant_country", "US", "rdap", "ev-1")
        o2 = self._obs("dom-example", "registrant_country", "GB", "whois-archive", "ev-2")
        cs = ContradictionDetector().detect([o1, o2])
        assert len(cs) == 1
        c = cs[0]
        vals = {s["value"] for s in c.sides}
        assert vals == {"US", "GB"}           # nothing silently overwritten
        assert {s["evidence_id"] for s in c.sides} == {"ev-1", "ev-2"}

    def test_agreement_is_not_contradiction(self):
        o1 = self._obs("dom-example", "resolves_to", "1.2.3.4", "dns-a", "ev-1")
        o2 = self._obs("dom-example", "resolves_to", "1.2.3.4", "dns-b", "ev-2")
        assert ContradictionDetector().detect([o1, o2]) == []

    def test_temporal_kind(self):
        o1 = self._obs("ip-1", "created_date", "2020-01-01", "a", "ev-1")
        o2 = self._obs("ip-1", "created_date", "2021-05-05", "b", "ev-2")
        cs = ContradictionDetector().detect([o1, o2])
        assert cs and cs[0].kind == "temporal"


class TestReportAndReplay:
    def _artifact(self, tmp_path, text, uri):
        from traceatlas.evidence.store import EvidenceStore
        store = EvidenceStore(tmp_path / "evidence")
        return store, store.put_bytes(text.encode(), source_uri=uri, case_id="case-t")

    def test_claim_states_evidence_first(self):
        ev1, ev2 = "ev-aaaa", "ev-bbbb"
        supported = Claim(statement="example.com resolves to 93.184.216.34",
                          citations=[Citation(evidence_id=ev1), Citation(evidence_id=ev2)])
        partial = Claim(statement="example.com is registered by Example Inc",
                        citations=[Citation(evidence_id=ev1)])
        unsupported = Claim(statement="Example Corp hacked NATO", citations=[])
        refuted = Claim(statement="bad claim", status=ClaimStatus.REFUTED,
                        citations=[Citation(evidence_id=ev1)])
        rm = ReportManager()
        assert rm.classify_claim(supported) == "SUPPORTED"
        assert rm.classify_claim(partial) == "PARTIALLY_SUPPORTED"
        assert rm.classify_claim(unsupported) == "UNSUPPORTED"
        assert rm.classify_claim(refuted) == "DISPUTED"

    def test_report_links_claims_to_evidence_and_replay(self, tmp_path):
        store, ev = self._artifact(tmp_path, "DNS A record example.com -> 93.184.216.34",
                                   "https://dns.test/example.com")
        obs = Observation(subject_id="dom-1", predicate="resolves_to",
                          value="93.184.216.34", evidence_id=ev.evidence_id,
                          source_id="connector.dns")
        claim = Claim(statement="example.com resolves to 93.184.216.34",
                      citations=[Citation(evidence_id=ev.evidence_id)])
        ent = Entity(kind=EntityKind.DOMAIN, display_name="example.com",
                     evidence_ids=(ev.evidence_id,))
        rm = ReportManager()
        md = rm.render_markdown(case_name="Domain slice", entities=[ent],
                                observations=[obs], claims=[claim],
                                evidence=[ev])
        assert ev.evidence_id in md
        assert "93.184.216.34" in md
        assert "[PARTIALLY_SUPPORTED]" in md   # single citation honest state
        man = rm.replay_manifest(entities=[ent], observations=[obs],
                                 claims=[claim], evidence=[ev])
        assert man["evidence"][0]["evidence_id"] == ev.evidence_id
        assert man["evidence"][0]["sha256"] == ev.sha256
        # integrity: bytes retrievable by id and hash matches
        raw = store.read_bytes(ev.evidence_id)
        assert ev.verify_integrity(raw)

    def test_unsupported_claim_appears_flagged_in_markdown(self):
        rm = ReportManager()
        md = rm.render_markdown(case_name="x",
                                claims=[Claim(statement="unsupported allegation")])
        assert "UNSUPPORTED" in md
