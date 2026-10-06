"""AI Employee golden tests: runtime envelopes, policy dispatcher, autonomous loop.

Offline by default (fake manager injected); one live-gated test exercises the
real employee against permitted public sources when network is available.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from traceatlas.ai_employees.runtime.task_envelope import TaskEnvelope
from traceatlas.ai_employees.runtime.result_envelope import (EnvelopeStatus,
                                                             ObservationRecord,
                                                             ResultEnvelope)
from traceatlas.ai_employees.runtime.employee import BaseEmployee, EmployeeManifest, FunctionEmployee
from traceatlas.ai_employees.runtime.dispatcher import DispatchPolicy, Dispatcher
from traceatlas.ai_employees.osint_investigation.investigator import OsintInvestigationEmployee


# --------------------------------------------------------------------- envelopes
class TestEnvelopes:
    def test_roundtrip(self):
        t = TaskEnvelope(case_id="c1", worker="dns_analyst", capability="dns.A",
                         target_kind="domain", target_value="example.com",
                         authorization_granted=True)
        assert TaskEnvelope.from_dict(t.to_dict()) == t

    def test_evidence_first_invariant(self):
        r = ResultEnvelope(task_id="t1", worker="w", status=EnvelopeStatus.SUCCEEDED,
                           observations=(ObservationRecord("s", "p", "v", evidence_id=None),))
        with pytest.raises(ValueError):
            r.validate()

    def test_evidenced_result_validates(self):
        r = ResultEnvelope(task_id="t1", worker="w", status=EnvelopeStatus.SUCCEEDED,
                           observations=(ObservationRecord("s", "p", "v", evidence_id="ev-1"),))
        r.validate()


# --------------------------------------------------------------------- dispatcher
def _task(**kw) -> TaskEnvelope:
    base = dict(case_id="c1", worker="net_worker", capability="dns.A",
                target_kind="domain", target_value="example.com")
    base.update(kw)
    return TaskEnvelope(**base)


def _net_employee():
    man = EmployeeManifest(worker_id="net_worker", display_name="DNS Analyst",
                           capabilities=("dns.A",), network=True)
    def fn(task):
        return EnvelopeStatus.SUCCEEDED, \
            [ObservationRecord(task.target_value, "a_record", "93.184.216.34",
                               evidence_id="ev-x", source_id="dns")], ""
    return FunctionEmployee(man, fn)


class TestDispatcherPolicy:
    def test_network_worker_refused_without_authorization(self):
        d = Dispatcher({"net_worker": _net_employee()})
        res = d.dispatch(_task(authorization_granted=False))
        assert res.status == EnvelopeStatus.BLOCKED_AUTHORIZATION
        assert "authorization" in res.error

    def test_authorized_network_worker_runs(self):
        d = Dispatcher({"net_worker": _net_employee()})
        res = d.dispatch(_task(authorization_granted=True))
        assert res.status == EnvelopeStatus.SUCCEEDED
        assert res.observations[0].evidence_id == "ev-x"

    def test_kill_switch_blocks_before_execution(self):
        d = Dispatcher({"net_worker": _net_employee()},
                       policy=DispatchPolicy(kill_switch=lambda: True))
        res = d.dispatch(_task(authorization_granted=True))
        assert res.status == EnvelopeStatus.CANCELLED

    def test_deadline_blocks(self):
        d = Dispatcher({"net_worker": _net_employee()})
        past = datetime.now(timezone.utc) - timedelta(seconds=5)
        res = d.dispatch(_task(authorization_granted=True, deadline=past))
        assert res.status == EnvelopeStatus.TIMEOUT

    def test_budget_blocks_priced_call(self):
        man = EmployeeManifest(worker_id="paid", display_name="Paid", capabilities=("x",),
                               network=False, cost_per_call_usd=5.0)
        emp = FunctionEmployee(man, lambda t: (EnvelopeStatus.SUCCEEDED, [], ""))
        d = Dispatcher({"paid": emp}, policy=DispatchPolicy(budget_remaining_usd=1.0))
        res = d.dispatch(_task(worker="paid"))
        assert res.status == EnvelopeStatus.BLOCKED_POLICY

    def test_unevidenced_observation_rejected(self):
        man = EmployeeManifest(worker_id="lazy", display_name="Lazy", capabilities=("x",))
        emp = FunctionEmployee(man, lambda t: (
            EnvelopeStatus.SUCCEEDED,
            [ObservationRecord("s", "p", "hallucinated value")], ""))
        d = Dispatcher({"lazy": emp})
        res = d.dispatch(_task(worker="lazy"))
        assert res.status == EnvelopeStatus.FAILED
        assert "unevidenced" in res.error

    def test_dispatch_audit_written(self):
        d = Dispatcher({"net_worker": _net_employee()})
        d.dispatch(_task(authorization_granted=True))
        assert d.audit and d.audit[-1]["status"] == "SUCCEEDED"


# ------------------------------------------------------------- autonomous loop
class FakeManager:
    """Deterministic stand-in for InvestigationManager to test the loop offline."""
    def __init__(self, first_ok=True, statuses=None, targets=(("domain", "example.com"),)):
        self.first_ok = first_ok
        self.statuses = statuses or {"dns.A:example.com": "succeeded",
                                     "rdap.domain:example.com": "failed"}
        self.targets = list(targets)
        self.calls = 0

    def investigate(self, objective_text, case_id=None, authorized=False, scope_note=""):
        self.calls += 1
        if not self.first_ok:
            return {"ok": False, "stage": "authorization", "reason": "no auth"}
        from pathlib import Path
        cdir = Path("/tmp/fake_case")
        cdir.mkdir(exist_ok=True)
        # write observations file so assessment sees evidenced dns findings only
        obs_line = json.dumps({"observation_id": "o1", "case_id": "c",
                               "subject_id": "example.com", "predicate": "a_record",
                               "value": "93.184.216.34", "evidence_id": "ev-1",
                               "source_id": "dns-system"})
        (cdir / "observations.jsonl").write_text(obs_line + "\n")
        return {"ok": True, "case_dir": str(cdir),
                "spec": {"question": "q", "targets": self.targets, "constraints": []},
                "task_statuses": dict(self.statuses),
                "summary": {"tasks_total": len(self.statuses), "tasks_done": 1,
                            "observations": 1, "entities": 1, "edges": 1}}


class TestAutonomousLoop:
    def test_refuses_without_authorization(self):
        emp = OsintInvestigationEmployee(manager=FakeManager(first_ok=False))
        out = emp.investigate("map example.com", authorized=False)
        assert out.stop_reason == "AUTHORIZATION_BOUNDARY"
        assert out.waves_run == 0

    def test_detects_gap_and_justifies_extra_wave(self):
        fake = FakeManager()
        emp = OsintInvestigationEmployee(manager=fake)
        out = emp.investigate("map the public infrastructure of example.com",
                              authorized=True, max_waves=3)
        assert out.waves_run >= 2                      # bounded iteration happened
        assert any(a.action.startswith("collect:") for a in out.actions_taken)
        assert all(a.rationale for a in out.actions_taken)  # every action explained
        assert fake.calls == out.waves_run             # each wave executed via manager

    def test_wave_bound_is_hard(self):
        # all domain caps failed => gaps persist forever; loop must stop at MAX_EXTRA_WAVES
        fake = FakeManager(statuses={f"{c}:example.com": "failed"
                                     for c in ("dns.A", "dns.NS", "rdap.domain",
                                               "certificates.by_domain", "web.fetch")})
        emp = OsintInvestigationEmployee(manager=fake)
        out = emp.investigate("map example.com", authorized=True, max_waves=10)
        assert out.waves_run <= OsintInvestigationEmployee.MAX_EXTRA_WAVES + 1
        assert out.stop_reason in ("WAVE_LIMIT_REACHED", "SOURCE_EXHAUSTED",
                                   "LOW_EXPECTED_INFORMATION_VALUE")

    def test_decision_memory_persisted(self):
        emp = OsintInvestigationEmployee(manager=FakeManager())
        out = emp.investigate("map example.com", authorized=True)
        dm = json.loads(open("/tmp/fake_case/decision_memory.json").read())
        assert dm["stop_reason"] == out.stop_reason
        assert isinstance(dm["decisions"], list)

    def test_no_targets_no_fake_actions(self):
        fake = FakeManager(targets=())
        emp = OsintInvestigationEmployee(manager=fake)
        out = emp.investigate("something vague", authorized=True)
        assert not any(a.action.startswith("collect:") for a in out.actions_taken)
