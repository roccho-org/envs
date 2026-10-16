#!/usr/bin/env python3
"""v6 SOURCE-entry integration with real F1 and disposable Target, never LIVE."""
from __future__ import annotations
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "adapters"), str(ROOT / "checks")]
from host_tool_source_entry import source_step  # noqa: E402
from host_tool_functional_binding import bind  # noqa: E402
from host_tool_selection import read_jsonl  # noqa: E402
from test_host_tool_functional_binding import real_relation_projector  # noqa: E402
from test_host_tool_guard import context  # noqa: E402
from test_host_tool_continuation import facts  # noqa: E402
from test_host_tool_transition_sut import DisposableHost, STORE0, STORE1  # noqa: E402


class Port:
    kind = "envs.syntheticDisposableTargetPort.v0"
    fixture_only = True

    def __init__(self, binding):
        self.host = DisposableHost()
        self.binding = copy.deepcopy(binding)
        self.reads = self.changes = self.records = self.rollbacks = 0
        self.crash = False

    def close(self):
        self.host.close()

    def observe(self):
        self.reads += 1
        state, store = self.host.observe()
        ident = None
        if state in ("ABSENT", "SELECTED"):
            ident = copy.deepcopy(self.binding["identity"])
            ident["tool"] = "ci:rent-tool-T0" if store == STORE0 else (
                "ci:rent-tool-T1" if store == STORE1 else "ci:Tool-ABSENT")
        return {
            "kind": "envs.syntheticPortObservation.v0",
            **{k: self.binding[k] for k in ("target_ref", "host_ref", "unit_ref", "scope")},
            "state": state, "store_path": store, "identity": ident,
            "fresh": state != "UNKNOWN", "closure_valid": state != "UNKNOWN",
        }

    def select(self, store, attempt, rev):
        self.changes += 1
        return self.host.native_set_fixture(store, attempt, desired_revision=rev,
                                            crash_after_selector=self.crash)

    def record(self, receipt, current_revision):
        self.records += 1
        issued = self.host._issued.get(receipt.get("attempt"))
        # The issuer-owned revision (issued[3]), not the caller's previous
        # CONFIRMED/current-q assertion, must match this checked SOURCE D.
        if (not issued or issued[0] is not receipt or issued[1] != receipt
                or issued[3] != current_revision):
            raise ValueError("not a returned SOURCE receipt for current q")
        return "SYNTHETIC_RECORD_ONLY"

    def rollback(self, receipt, attempt, desired):
        self.rollbacks += 1
        return self.host.rollback_fixture(receipt, attempt, quiet=True, writer=True,
                                          current_desired=desired)


class EntryCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fn, _ = real_relation_projector()
        cls.project = staticmethod(fn)
        cls.proposals = read_jsonl(ROOT / "contracts/proposals/host-tool-selection.jsonl")
        cls.targets = read_jsonl(ROOT / "contracts/targets.jsonl")
        cls.f1 = json.loads((ROOT / "checks/fixtures/host-tool-functional-binding.json").read_text())

    def setUp(self):
        self.bound = bind(copy.deepcopy(self.f1), self.proposals, self.targets, self.project)
        self.port = Port(self.bound)
        self.q = "ci-" + self.bound["proposed_q"][7:23]
        _, self.d, _, _, self.e = context()
        self.d.update(revision=self.q, store_path=STORE0,
                      proposed_q=self.bound["proposed_q"])
        self.req = {
            "kind": "envs.syntheticHostSourceRequest.v0", "action": "READ",
            **{k: self.bound[k] for k in ("target_ref", "host_ref", "unit_ref", "scope")},
            "actor_ref": "ci-fixed-W", "work_ref": "ci-source-work",
            "attempt_ref": "ci-attempt-one", "proposed_q": self.bound["proposed_q"],
            "requested_store": None,
        }
        self.access = {
            "kind": "envs.syntheticScopedAuthority.v0",
            **{k: self.req[k] for k in ("target_ref", "host_ref", "unit_ref", "scope",
                                        "actor_ref", "work_ref", "attempt_ref")},
            "read": True, "change": True, "quiet": True, "single_writer": True,
            "recovery": True, "route": True,
        }

    def tearDown(self):
        self.port.close()

    def call(self, action="READ", *, request=None, overrides=None):
        req = dict(self.req, action=action,
                   requested_store=None if action == "READ" else STORE0)
        if request:
            req.update(request)
        read = facts("READ")
        read.update({k: req[k] for k in ("target_ref", "actor_ref", "work_ref", "attempt_ref")})
        change = facts("RECORD" if action == "RECORD" else "TOOL_CHANGE")
        change.update({k: req[k] for k in ("target_ref", "actor_ref", "work_ref", "attempt_ref")})
        params = dict(request=req, binding_source=copy.deepcopy(self.f1),
                      proposals=self.proposals, targets=self.targets,
                      relation_project=self.project, authority=copy.deepcopy(self.access),
                      read_facts=read, change_facts=change, current_q=self.q,
                      desired=copy.deepcopy(self.d), previous=copy.deepcopy(self.e),
                      port=self.port, receipt=None)
        if overrides:
            params.update(overrides)
        return source_step(**params)

    def seed(self):
        self.port.host.native_set_fixture(STORE1, "ci-seed", desired_revision=self.q)

    def inert(self, outcome):
        self.assertEqual(outcome["admission"], "NOT_ADMITTED")
        self.assertIsNone(outcome["accepted_q"])
        self.assertEqual(outcome["target_noop"], "UNPROVEN")
        self.assertEqual(outcome["effect"], "FORBIDDEN")
        self.assertFalse(outcome["target_ready"])
        self.assertFalse(outcome["merge_ready"])

    def test_missing_or_foreign_read_scope_never_observes(self):
        for value in (None, {}, dict(self.access, read=False),
                      dict(self.access, target_ref="ci-other")):
            result = self.call(overrides={"authority": value})
            self.assertEqual(result["stage"], "REFUSED_SOURCE_OR_AUTHORITY")
            self.assertEqual((self.port.reads, self.port.changes), (0, 0))
            self.inert(result)

    def test_host_unit_actor_attempt_and_q_substitution_refuse_before_observe(self):
        for key in ("target_ref", "host_ref", "unit_ref", "scope",
                    "actor_ref", "work_ref", "attempt_ref", "proposed_q"):
            outcome = self.call(request={key: "ci-forged"})
            self.assertEqual(outcome["stage"], "REFUSED_SOURCE_OR_AUTHORITY")
            self.assertEqual((self.port.reads, self.port.changes), (0, 0))

    def test_d_independent_read_allowed_with_unknown_prior_effect(self):
        self.seed()
        authority = dict(self.access, change=False)
        previous = dict(self.e, state="UNKNOWN")
        outcome = self.call(overrides={"authority": authority, "desired": None,
                                       "current_q": None, "previous": previous})
        self.assertEqual(outcome["stage"], "SYNTHETIC_READ_OBSERVED")
        self.assertEqual(outcome["observation"]["store_path"], STORE1)
        self.assertEqual((self.port.reads, self.port.changes), (1, 0))
        self.inert(outcome)

    def test_missing_read_facts_or_wrong_stage_pre_observe(self):
        for data in (None, {}, dict(facts("READ"), step="TOOL_CHANGE")):
            self.assertEqual(self.call(overrides={"read_facts": data})["stage"],
                             "REFUSED_SOURCE_OR_AUTHORITY")
        self.assertEqual((self.port.reads, self.port.changes), (0, 0))

    def test_wrong_current_d_q_or_selected_tool_does_not_write(self):
        self.seed()
        for inputs in ({"desired": None}, {"current_q": "ci-old"},
                       {"authority": dict(self.access, change=False)}):
            self.assertEqual(self.call("CHANGE", overrides=inputs)["stage"],
                             "REFUSED_SOURCE_OR_AUTHORITY")
        self.assertEqual(self.call("CHANGE", request={"requested_store": STORE1})["stage"],
                         "REFUSED_SOURCE_OR_AUTHORITY")
        self.assertEqual(self.port.changes, 0)

    def test_actual_injected_change_readback_and_base_preservation(self):
        self.seed()
        before = self.port.host.snapshot()
        result = self.call("CHANGE")
        self.assertEqual(result["stage"], "SYNTHETIC_READBACK_CANDIDATE_NOT_SUCCESS")
        self.assertEqual(result["issued_receipt"]["preimage"], STORE1)
        self.assertEqual(result["observation"]["store_path"], STORE0)
        self.assertEqual(self.port.host.snapshot(), before)
        self.assertEqual(self.port.changes, 1)
        self.inert(result)

    def test_first_tool_install_requires_complete_observed_base(self):
        result = self.call("CHANGE")
        self.assertEqual(result["stage"], "SYNTHETIC_READBACK_CANDIDATE_NOT_SUCCESS")
        self.assertEqual(result["issued_receipt"]["preimage"], None)
        self.assertEqual(self.port.host.observe(), ("SELECTED", STORE0))

    def test_non_tool_delta_and_wrong_change_stage_block_write(self):
        self.seed()
        for key in ("base", "launch", "config_binding", "state_contract"):
            original = self.port.binding
            self.port.binding = copy.deepcopy(original)
            self.port.binding["identity"][key] = "ci-foreign"
            self.assertEqual(self.call("CHANGE")["stage"], "REFUSED_SOURCE_OR_AUTHORITY")
            self.port.binding = original
        f = facts("SOURCE_FIX")
        self.assertEqual(self.call("CHANGE", overrides={"change_facts": f})["stage"],
                         "REFUSED_SOURCE_OR_AUTHORITY")
        self.assertEqual(self.port.changes, 0)

    def test_lost_receipt_unknown_blocks_replay_but_read_still_works(self):
        self.seed()
        self.port.crash = True
        self.assertEqual(self.call("CHANGE")["stage"], "SYNTHETIC_EFFECT_UNKNOWN_NO_REPLAY")
        self.assertEqual(self.port.changes, 1)
        unknown = dict(self.e, state="UNKNOWN")
        self.assertEqual(self.call("CHANGE", overrides={"previous": unknown})["stage"],
                         "REFUSED_SOURCE_OR_AUTHORITY")
        self.assertEqual(self.port.changes, 1)
        self.assertEqual(self.call("READ", overrides={"previous": unknown,
                                                      "desired": None})["stage"],
                         "SYNTHETIC_READ_OBSERVED")

    def test_record_refuses_genuine_receipt_issued_under_old_q(self):
        # Fixed-R R1: O is selected T0 and previous claims the current q,
        # but THIS SAME disposable issuer actually minted receipt under ci-old.
        self.seed()
        old_receipt = self.port.host.native_set_fixture(
            STORE0, self.req["attempt_ref"], desired_revision="ci-old")
        self.assertIs(self.port.host._issued[self.req["attempt_ref"]][0], old_receipt)
        self.assertEqual(self.port.host._issued[self.req["attempt_ref"]][3], "ci-old")
        self.assertNotEqual("ci-old", self.q)
        claimed = dict(self.e, state="CONFIRMED", revision=self.q, store_path=STORE0)
        before = (self.port.host.effect_count, self.port.host.number,
                  self.port.host.observe(), self.port.host.snapshot())
        result = self.call("RECORD", overrides={
            "previous": claimed, "receipt": old_receipt})
        self.assertEqual(result["stage"], "REFUSED_PORT_PRECONDITION")
        self.assertEqual(self.port.records, 1)
        self.assertEqual(self.port.changes, 0)
        self.assertIsNone(result["issued_receipt"])
        self.assertEqual((self.port.host.effect_count, self.port.host.number,
                          self.port.host.observe(), self.port.host.snapshot()), before)
        self.inert(result)

    def test_record_rejects_copied_or_forged_receipt_but_allows_current_issuer_q(self):
        self.seed()
        changed = self.call("CHANGE")
        self.assertEqual(changed["stage"], "SYNTHETIC_READBACK_CANDIDATE_NOT_SUCCESS")
        issued = changed["issued_receipt"]
        self.assertEqual(self.port.host._issued[issued["attempt"]][3], self.q)
        claimed = dict(self.e, state="CONFIRMED", revision=self.q, store_path=STORE0)
        before = (self.port.host.effect_count, self.port.host.number,
                  self.port.host.observe(), self.port.host.snapshot())
        for forged in (copy.deepcopy(issued),
                       dict(issued, preimage=None),
                       dict(issued, attempt="ci-not-issued")):
            result = self.call("RECORD", overrides={
                "previous": claimed, "receipt": forged})
            self.assertIn(result["stage"],
                          {"REFUSED_SOURCE_OR_AUTHORITY", "REFUSED_PORT_PRECONDITION"})
            self.assertEqual((self.port.host.effect_count, self.port.host.number,
                              self.port.host.observe(), self.port.host.snapshot()), before)
            self.inert(result)
        valid = self.call("RECORD", overrides={"previous": claimed, "receipt": issued})
        self.assertEqual(valid["stage"], "SYNTHETIC_RECORD_ONLY_CANDIDATE")
        self.assertEqual((self.port.host.effect_count, self.port.host.number,
                          self.port.host.observe(), self.port.host.snapshot()), before)
        self.inert(valid)

    def test_record_only_and_issued_rollback_are_separate(self):
        self.seed()
        before = self.port.host.snapshot()
        result = self.call("CHANGE")
        issued = result["issued_receipt"]
        confirmed = dict(self.e, state="CONFIRMED", revision=self.q, store_path=STORE0)
        recorded = self.call("RECORD", overrides={"previous": confirmed, "receipt": issued})
        self.assertEqual(recorded["stage"], "SYNTHETIC_RECORD_ONLY_CANDIDATE")
        self.assertEqual(self.port.changes, 1)
        self.assertEqual(self.port.records, 1)
        copied = self.call("ROLLBACK", overrides={"previous": confirmed,
                                                  "receipt": copy.deepcopy(issued)})
        self.assertEqual(copied["stage"], "REFUSED_PORT_PRECONDITION")
        self.assertEqual(self.port.host.observe(), ("SELECTED", STORE0))
        oldq = self.call("ROLLBACK", overrides={"previous": confirmed, "receipt": issued,
                                                "current_q": "ci-old"})
        self.assertEqual(oldq["stage"], "REFUSED_SOURCE_OR_AUTHORITY")
        restored = self.call("ROLLBACK", overrides={"previous": confirmed, "receipt": issued})
        self.assertEqual(restored["stage"], "SYNTHETIC_ROLLBACK_READBACK_REQUIRED")
        self.assertEqual(self.port.host.observe(), ("SELECTED", STORE1))
        self.assertEqual(self.port.host.snapshot(), before)
        self.inert(restored)

    def test_production_projection_has_no_implicit_source_entry_import(self):
        for path in ("adapters/contract_projection.py", "adapters/jev_api.py"):
            src = (ROOT / path).read_text(encoding="utf-8")
            self.assertNotIn("import host_tool_source_entry", src)
            self.assertNotIn("from host_tool_source_entry import", src)


if __name__ == "__main__":
    unittest.main()
