#!/usr/bin/env python3
"""v6 PROPOSED F1 contract -> actual disposable FS Target receive/observe/recover.

No production integration, admitted D, Host identity, credential, subprocess,
network effect, real Nix, or new engine. The reviewed real-Nix disposable OCI
equivalent is separately executed by windows #93 on this same F1 Git blob/q.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_selection import ProposalError, read_jsonl  # noqa: E402
from host_tool_functional_binding import bind, plan  # noqa: E402
from host_tool_guard import judge  # noqa: E402
from host_tool_continuation import evaluate  # noqa: E402
from test_host_tool_functional_binding import real_relation_projector  # noqa: E402
from test_host_tool_guard import context  # noqa: E402
from test_host_tool_continuation import facts  # noqa: E402
from test_host_tool_transition_sut import DisposableHost, STORE0, STORE1  # noqa: E402

PROPOSAL = ROOT / "contracts/proposals/host-tool-selection.jsonl"
TARGETS = ROOT / "contracts/targets.jsonl"
F1 = ROOT / "checks/fixtures/host-tool-functional-binding.json"
EXPECTED_HOST = "ci-host-rent-1"
EXPECTED_UNIT = "ci-rent-oci-unit-1"
EXPECTED_SCOPE = "ci-session-1"
EXPECTED_SELECTOR = "/nix/var/nix/profiles/rent-dev"
EXPECTED_TARGET = "pc7337-rent"
EXPECTED_Q = "sha256:f531f4c49182a8cf15475103c1890475cefbb634512baf3d3b2fd9369da445a4"
# SOURCE-only actor/work labels: these cannot authenticate a real principal.
SOURCE_ACTOR = "fixed-existing-W"
SOURCE_WORK = "host-tool-ci"
STAGE_SUBJECT = ("step", "target_ref", "actor_ref", "work_ref", "attempt_ref")
# Caller conditions only narrow readiness; they cannot replace operation identity.
STAGE_CONDITIONS = frozenset((
    "identity_current", "step_authority", "route_usable", "safe_boundary",
    "affected_effects_resolved", "inputs_current", "stage_checks",
    "desired_current", "observation_fresh", "tool_compatible",
    "one_writer", "quiet_held", "recovery_available", "write_unresolved",
))


class BoundLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Public immutable reviewed resources Relation implementation, not a
        # copied imitation. Existing F1 tests use this same Git blob verification.
        projector, cls.relation_error = real_relation_projector()
        cls.relation_project = staticmethod(projector)  # no accidental unittest self
        cls.proposals = read_jsonl(PROPOSAL)
        cls.targets = read_jsonl(TARGETS)
        cls.f1_source = json.loads(F1.read_text(encoding="utf-8"))

    def setUp(self):
        self.host = DisposableHost()  # bounded to its own TemporaryDirectory
        self.bound = bind(copy.deepcopy(self.f1_source), self.proposals, self.targets,
                          self.relation_project)
        self.p, self.d, self.o, self.a, self.e = context()
        self.rev = "ci-" + self.bound["proposed_q"][7:23]
        self.d["revision"] = self.rev
        self.d["store_path"] = STORE0  # immutable CI fixture map: F1 desired T0
        self.d["proposed_q"] = self.bound["proposed_q"]
        self.assertEqual(self.p["proposed_q"], self.bound["proposed_q"])
        self.assertEqual(self.bound["proposed_q"], EXPECTED_Q)
        self.assertEqual(self.bound["identity"]["tool"], "ci:rent-tool-T0")

    def tearDown(self):
        self.host.close()

    def observed(self):
        state, store = self.host.observe()
        o = copy.deepcopy(self.o)
        o.update(state=state, store_path=store, fresh=state != "UNKNOWN",
                 closure_valid=state != "UNKNOWN")
        identity = None
        if state == "SELECTED":
            identity = copy.deepcopy(self.bound["identity"])
            identity["tool"] = ("ci:rent-tool-T0" if store == STORE0
                                else "ci:rent-tool-T1")
        return o, identity

    def read(self, authority=None):
        # Rebind the immutable PROPOSED source: READ authority MUST match its
        # Target, but never requires admitted D or resolving a prior UNKNOWN E.
        auth = self.a if authority is None else authority
        if type(auth) is not dict:
            return "READ_AUTH_REQUIRED"
        try:
            verified = bind(copy.deepcopy(self.f1_source), self.proposals, self.targets,
                            self.relation_project)
            read_gate = judge(self.p, desired=None, authority=auth)
        except (ValueError, TypeError, KeyError):
            return "READ_AUTH_REQUIRED"
        if (self.bound != verified or verified["target_ref"] != EXPECTED_TARGET
                or auth.get("target_ref") != verified["target_ref"]
                or read_gate["synthetic_read_preconditions"] is not True):
            return "READ_AUTH_REQUIRED"
        before = self.host.effect_count, self.host.snapshot()
        value = self.host.observe()
        self.assertEqual((self.host.effect_count, self.host.snapshot()), before)
        return value

    def receive(self, *, candidate=None, requested_store=STORE0, authority=None,
                previous=None, revision=None, conditions=None,
                attempt="ci-bound-apply-1", crash=False):
        """Only a CI fixture call can make this ONE local selector write.

        Never trust a caller-supplied bound dict, q, host, or synthetic rights.
        Re-run actual F1 and all SOURCE/READ/CHANGE guards before touching FS.
        """
        bound = self.bound if candidate is None else candidate
        verified = bind(copy.deepcopy(self.f1_source), self.proposals, self.targets,
                        self.relation_project)
        if (type(bound) is not dict or bound != verified
                or bound["target_ref"] != EXPECTED_TARGET
                or bound["host_ref"] != EXPECTED_HOST
                or bound["unit_ref"] != EXPECTED_UNIT
                or bound["scope"] != EXPECTED_SCOPE
                or bound["selector"] != EXPECTED_SELECTOR
                or bound["proposed_q"] != EXPECTED_Q
                or requested_store != STORE0
                or requested_store != self.d["store_path"]
                or self.d["revision"] != self.rev):
            return "REFUSED_SOURCE_BINDING"
        auth = self.a if authority is None else authority
        effect = self.e if previous is None else previous
        desired_q = self.rev if revision is None else revision
        o, observed_identity = self.observed()
        # Fresh actual O and identical F1 plan; matching q alone is insufficient.
        try:
            candidate_plan = plan(
                bound, observed_identity,
                binding_source=copy.deepcopy(self.f1_source),
                proposals=self.proposals, targets=self.targets,
                relation_project=self.relation_project,
                revision=desired_q, effect_resolved=effect.get("state") == "NONE",
                checks_ok=True,
            )
            gate = judge(self.p, desired=self.d, observed=o, authority=auth,
                         previous=effect)
            # One immutable stage subject: same verified Target and same
            # attempt/actor/work as this selector operation, never the
            # unrelated default attempt in facts("TOOL_CHANGE").
            operation = {
                "step": "TOOL_CHANGE", "target_ref": verified["target_ref"],
                "actor_ref": SOURCE_ACTOR, "work_ref": SOURCE_WORK,
                "attempt_ref": attempt,
            }
            stage_facts = facts(operation["step"])
            stage_facts.update(operation)
            if conditions is not None:
                # Caller flags may DENY, but never replace step/target/actor/
                # work/attempt or introduce a fake started/receipt context.
                if (type(conditions) is not dict
                        or any(k not in STAGE_CONDITIONS for k in conditions)
                        or any(v is not None and type(v) is not bool
                               for v in conditions.values())):
                    return "REFUSED_STAGE_BINDING"
                stage_facts.update(conditions)
            step = evaluate(stage_facts)
        except (ValueError, TypeError):
            return "REFUSED_SOURCE_BINDING"
        if (candidate_plan["stage"] != "SYNTHETIC_TOOL_ONLY_CANDIDATE"
                or gate["stage"] != "SYNTHETIC_CHANGE_CANDIDATE"
                or step["step"] != operation["step"]
                or step["target_ref"] != operation["target_ref"]
                or any(stage_facts[k] != operation[k] for k in STAGE_SUBJECT)
                or not step["synthetic_mutation_ready"]
                or auth["target_ref"] != operation["target_ref"]):
            return "REFUSED_GUARD"
        receipt = self.host.native_set_fixture(
            requested_store, attempt, desired_revision=self.rev,
            crash_after_selector=crash,
        )
        observed_after = self.host.observe()
        if observed_after != ("SELECTED", requested_store):
            # An applied-but-not-read-back effect must never be reported success.
            return "UNKNOWN_NO_EQUIVALENT_RETRY"
        return {
            "kind": "envs.syntheticBoundTargetResult.v0",
            "target_ref": EXPECTED_TARGET, "host_ref": EXPECTED_HOST,
            "unit_ref": EXPECTED_UNIT, "scope": EXPECTED_SCOPE,
            "proposed_q": EXPECTED_Q, "issued_receipt": receipt,
            "readback_store": requested_store,
            "admission": "NOT_ADMITTED", "accepted_q": None,
            "target_noop": "UNPROVEN", "effect": "FORBIDDEN",
            "real_target_ready": False, "merge_ready": False,
        }

    def seed_old_t(self):
        self.host.native_set_fixture(STORE1, "ci-old-fixture-setup",
                                     desired_revision=self.rev)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))

    def assert_closed(self, result, before):
        self.assertTrue(str(result).startswith("REFUSED"))
        self.assertEqual(self.host.effect_count, before[0])
        self.assertEqual(self.host.observe(), before[1])
        self.assertEqual(self.host.snapshot(), before[2])

    def test_f1_host_target_unit_q_to_actual_temp_selector_and_readback_receipt(self):
        self.seed_old_t()
        initial = self.host.snapshot()
        self.assertEqual(self.read(), ("SELECTED", STORE1))
        received = self.receive()
        self.assertEqual(received["readback_store"], STORE0)
        self.assertEqual(received["proposed_q"], EXPECTED_Q)
        self.assertEqual(received["admission"], "NOT_ADMITTED")
        self.assertIsNone(received["accepted_q"])
        self.assertEqual(received["effect"], "FORBIDDEN")
        self.assertEqual(received["target_noop"], "UNPROVEN")
        self.assertEqual(received["issued_receipt"]["preimage"], STORE1)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.assertEqual(self.host.snapshot(), initial)
        self.assertEqual(self.host.effect_count, 2)
        rolled_back = self.host.rollback_fixture(
            received["issued_receipt"], "ci-bound-apply-1",
            quiet=True, writer=True, current_desired=self.d,
        )
        self.assertEqual(rolled_back, "SYNTHETIC_ROLLBACK_NOT_NEW_D_SUCCESS")
        self.assertEqual(self.host.observe(), ("SELECTED", STORE1))
        self.assertEqual(self.host.snapshot(), initial)
        self.assertEqual(self.host.effect_count, 3)

    def test_forged_f1_host_target_unit_scope_q_and_mutable_selector_refuse_prewrite(self):
        self.seed_old_t()
        before = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        changes = [
            ("host_ref", "ci-other-host"), ("target_ref", "ci-other-target"),
            ("unit_ref", "ci-other-unit"), ("scope", "ci-other-session"),
            ("selector", "/nix/var/nix/profiles/other"),
            ("proposed_q", "sha256:" + "f" * 64),
            ("admission", "ADMITTED"), ("accepted_q", "ci-fake"),
        ]
        for key, value in changes:
            altered = copy.deepcopy(self.bound)
            altered[key] = value
            with self.subTest(field=key):
                self.assert_closed(self.receive(candidate=altered), before)
        self.assert_closed(self.receive(requested_store=STORE1), before)
        self.assert_closed(self.receive(revision="ci-stale"), before)

    def test_read_permission_separate_from_change_unknown_and_dev_go(self):
        self.seed_old_t()
        before = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        denied = copy.deepcopy(self.a)
        denied["read"] = False
        self.assertEqual(self.read(denied), "READ_AUTH_REQUIRED")
        self.assert_closed(self.receive(authority=denied), before)
        denied["read"] = True
        denied["change"] = False
        self.assertEqual(self.read(denied), ("SELECTED", STORE1))
        self.assert_closed(self.receive(authority=denied), before)
        e = copy.deepcopy(self.e)
        e["state"] = "UNKNOWN"
        self.assertEqual(self.read(), ("SELECTED", STORE1))
        self.assert_closed(self.receive(previous=e), before)

    def test_guard_quiet_writer_recovery_or_stale_revision_refuse_prewrite(self):
        self.seed_old_t()
        original = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        for key in ("change", "quiet", "single_writer", "recovery"):
            with self.subTest(condition=key):
                denied = copy.deepcopy(self.a)
                denied[key] = False
                self.assert_closed(self.receive(authority=denied), original)
        for key in ("quiet_held", "one_writer", "recovery_available",
                    "desired_current", "observation_fresh"):
            with self.subTest(condition=key):
                self.assert_closed(self.receive(conditions={key: False}), original)
        self.assert_closed(self.receive(revision="ci-q2"), original)

    def test_unknown_receipt_lost_after_real_disposable_write_never_replays(self):
        self.seed_old_t()
        old = self.host.snapshot()
        with self.assertRaisesRegex(RuntimeError, "receipt interrupted"):
            self.receive(crash=True)
        self.assertEqual(self.host.observe(), ("SELECTED", STORE0))
        self.assertEqual(self.host.effect_count, 2)
        self.assertEqual(self.host.snapshot(), old)
        self.assertEqual(self.read(), ("SELECTED", STORE0))
        e = copy.deepcopy(self.e)
        e["state"] = "UNKNOWN"
        before = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        self.assert_closed(self.receive(previous=e, attempt="ci-replayed"), before)
        forged = {"attempt": "ci-bound-apply-1", "preimage": STORE1,
                  "selected": STORE0, "effect": "SYNTHETIC_ONLY"}
        with self.assertRaises(ValueError):
            self.host.rollback_fixture(forged, "ci-bound-apply-1", quiet=True,
                                       writer=True, current_desired=self.d)
        self.assertEqual(self.host.effect_count, 2)
        self.assertEqual(self.host.snapshot(), old)

    def test_foreign_generation_or_forged_current_source_never_executes(self):
        self.seed_old_t()
        self.host.selection.unlink()
        self.host.selection.symlink_to("/tmp/not-a-store")
        before = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        self.assertEqual(before[1], ("UNKNOWN", None))
        self.assert_closed(self.receive(), before)
        self.host.selection.unlink()
        self.host.selection.symlink_to("rent-dev-1-link")
        before = (self.host.effect_count, self.host.observe(), self.host.snapshot())
        self.assert_closed(self.receive(candidate={**self.bound, "effect": "ALLOWED"}),
                           before)


if __name__ == "__main__":
    unittest.main()
