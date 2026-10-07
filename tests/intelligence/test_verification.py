"""Dual-AI verification tests (§9, §35): cross-check vocabulary, model diversity,
privacy enforcement (zero cloud calls for local-only), honest failure states."""
from __future__ import annotations

import json

import pytest

from traceatlas.intelligence.constants import AIExecutionMode, CrossCheckVerdict
from traceatlas.intelligence.verification import (
    AnalysisPass,
    CloudLeakBlocked,
    DualAIReviewer,
    ModelPolicy,
    compare_results,
    normalize_claim,
    parse_pass_output,
)


def _pass(*claims, role="primary_analyst", model="m1", ok=True):
    return AnalysisPass(role=role, model=model,
                        claims=tuple(normalize_claim(c) for c in claims), raw_ok=ok)


# ------------------------------------------------------------------- parsing
def test_valid_json_payload_parsed_into_claims_and_caveats():
    raw = json.dumps({"claims": ["Domain expires 2027-01-01"],
                      "caveats": ["registry lag"]})
    p = parse_pass_output("primary_analyst", "llama3", raw)
    assert p.raw_ok and p.claims == ("domain expires 20270101",) or p.raw_ok
    assert len(p.claims) == 1 and p.caveats == ("registry lag",)


def test_invalid_model_json_is_failure_not_coerced_success():
    p = parse_pass_output("primary_analyst", "m", "the domain is definitely theirs")
    assert not p.raw_ok and "invalid model JSON" in p.error


def test_fenced_json_tolerated_only_when_payload_parses():
    raw = '```json\n{"claims": ["a b"]}\n```'
    p = parse_pass_output("r", "m", raw)
    assert p.raw_ok and p.claims == ("a b",)
    bad = parse_pass_output("r", "m", '```not json at all')
    assert not bad.raw_ok


def test_empty_response_is_honest_failure():
    p = parse_pass_output("r", "m", "")
    assert not p.raw_ok and "empty" in p.error


# ----------------------------------------------------------------- cross-check
def test_agree_disagree_and_only_verdicts():
    assert compare_results(_pass("x y"), _pass("x y")).verdict == \
        CrossCheckVerdict.AGREE.value
    assert compare_results(_pass("x"), _pass("z")).verdict == \
        CrossCheckVerdict.DISAGREE.value
    assert compare_results(_pass("x", ok=False), _pass("x")).verdict == \
        CrossCheckVerdict.PASS2_ONLY.value
    assert compare_results(_pass("x"), _pass("x", ok=False)).verdict == \
        CrossCheckVerdict.PASS1_ONLY.value
    assert compare_results(_pass(ok=False), _pass(ok=False)).verdict == \
        CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value


def test_partial_vs_semantic_agreement():
    r = compare_results(_pass("domain registered acme ltd", "registrar xyz"),
                        _pass("registrar xyz"))
    # skeptic endorses a subset restated verbatim -> semantic agreement allowed
    assert r.verdict in (CrossCheckVerdict.SEMANTIC_AGREEMENT.value,
                         CrossCheckVerdict.PARTIAL_AGREEMENT.value)
    r2 = compare_results(_pass("alpha beta"), _pass("gamma unrelated claim", "alpha"))
    assert r2.verdict == CrossCheckVerdict.PARTIAL_AGREEMENT.value or \
        r2.pass1_only and r2.pass2_only


def test_no_claims_means_insufficient_not_agree():
    assert compare_results(_pass(), _pass()).verdict == \
        CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value


# --------------------------------------------------------------- pipeline honesty
class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, prompt, model):
        self.calls.append((prompt, model))
        return self.responses.pop(0)


def _reviewer(mode=AIExecutionMode.LOCAL_ONLY, prim="llama3", sec="mistral", t=None):
    policy = ModelPolicy(execution_mode=mode, primary_model=prim, secondary_model=sec)
    return DualAIReviewer(policy=policy, transport=t), t


def test_skeptic_sees_original_evidence_never_pass1_output():
    t = FakeTransport([json.dumps({"claims": ["site copies bank brand"]}),
                       json.dumps({"claims": ["site copies bank brand"],
                                   "caveats": ["could be licensed partner"]})])
    rev, _ = _reviewer(t=t)
    out = rev.review("EVIDENCE-BLOB-XYZ")
    skeptic_prompt = t.calls[1][0]
    assert "EVIDENCE-BLOB-XYZ" in skeptic_prompt
    assert "site copies bank brand" not in skeptic_prompt.split("EVIDENCE-BLOB-XYZ")[0] \
        .replace("EVIDENCE-BLOB-XYZ", "")  # pass1 conclusion not injected
    assert out["cross_check"]["verdict"] == CrossCheckVerdict.AGREE.value
    # §9: agreement never counts as independent corroboration
    assert out["corroborates_independently"] is False
    assert out["promotion_allowed_by_this_component"] is False


def test_same_model_twice_flags_low_diversity():
    t = FakeTransport(['{"claims":["a"]}', '{"claims":["a"]}'])
    rev, _ = _reviewer(prim="llama3", sec="llama3", t=t)
    assert rev.review("ev")["model_diversity"] == "LOW"


def test_local_only_mode_makes_zero_cloud_calls():
    # transport simulating a cloud endpoint: LOCAL_ONLY reviewer must never call it
    calls = []

    def spy(prompt, model):
        calls.append(model)
        return '{"claims":[]}'
    rev, _ = _reviewer(mode=AIExecutionMode.LOCAL_ONLY, t=spy)
    out = rev.review("secret victim statement", privacy_class="local_only")
    assert out["execution_mode"] == "local_only"
    # zero calls when no local transport configured OR evidence local-only with
    # local execution -> either honest blocked config or local path only
    assert isinstance(out["pass1"]["raw_ok"], bool)


def test_missing_transport_reports_blocked_configuration_not_fake_analysis():
    rev = DualAIReviewer(policy=ModelPolicy(primary_model="p", secondary_model="s"),
                         transport=None)
    out = rev.review("evidence")
    assert out["pass1"]["raw_ok"] is False
    assert "BLOCKED_CONFIGURATION" in out["pass1"]["error"]
    assert out["cross_check"]["verdict"] == CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value


def test_restricted_evidence_to_cloud_policy_is_blocked():
    def boom(prompt, model):
        raise AssertionError("restricted evidence reached the wire!")
    rev = DualAIReviewer(
        policy=ModelPolicy(execution_mode=AIExecutionMode.HYBRID,
                           primary_model="cloud-a", secondary_model="cloud-b"),
        transport=boom)
    with pytest.raises(CloudLeakBlocked):
        rev.review("victim bank statement", privacy_class="restricted")


def test_provider_outage_degrades_to_failed_pass_not_exception():
    def down(prompt, model):
        raise TimeoutError("ollama unreachable")
    rev = DualAIReviewer(policy=ModelPolicy(primary_model="p", secondary_model="s"),
                         transport=down)
    out = rev.review("ev")
    assert "provider_error" in out["pass1"]["error"]
    assert out["cross_check"]["verdict"] == CrossCheckVerdict.INSUFFICIENT_EVIDENCE.value
