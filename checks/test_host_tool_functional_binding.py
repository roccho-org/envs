#!/usr/bin/env python3
"""v6: the real immutable resources projector and envs q on ONE SOURCE target."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
import types
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_selection import ProposalError, read_jsonl  # noqa: E402
from host_tool_functional_binding import bind, plan  # noqa: E402
from host_tool_source_provenance import API, public_get  # noqa: E402

FIXTURE = ROOT / "checks/fixtures/host-tool-functional-binding.json"
TARGETS = ROOT / "contracts/targets.jsonl"
PROPOSALS = ROOT / "contracts/proposals/host-tool-selection.jsonl"
RESOURCES_SOURCE_HEAD = "5746f46b149c15d57a6ea006f4b79cff60dbf83b"
RELATION_BLOB = "4aa50be2c62c714def0b2aa97aa24573bd8b5344"
RELATION_URI = (
    f"{API}/repos/roccho-dev/resources/contents/"
    f"nixos/tests/host_relation_source.py?ref={RESOURCES_SOURCE_HEAD}"
)


def real_relation_projector():
    """Fetch *reviewed source itself*, verify Git blob, then call its project().

    No copied relation implementation, no token and no Target. Fail closed.
    """
    data = public_get(RELATION_URI)
    if data.get("sha") != RELATION_BLOB or data.get("encoding") != "base64":
        raise ValueError("resources source is not the reviewed immutable relation blob")
    raw = base64.b64decode(data["content"], validate=False)
    expected = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if expected != RELATION_BLOB:
        raise ValueError("resources relation source blob bytes mismatched")
    mod = types.ModuleType("reviewed_resources_host_relation_source")
    exec(compile(raw, RELATION_URI, "exec"), mod.__dict__)
    return mod.project, mod.RelationRefused


class ExactProposedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        projector, cls.relation_error = real_relation_projector()
        cls.relation_project = staticmethod(projector)  # never auto-bind testcase 'self'
        cls.source = read_jsonl(PROPOSALS)
        cls.targets = read_jsonl(TARGETS)
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def ok(self, fixture=None):
        return bind(
            copy.deepcopy(self.fixture if fixture is None else fixture),
            self.source, self.targets, self.relation_project,
        )

    def planned(self, binding, observed, *, revision, effect_resolved,
                checks_ok, binding_source=None):
        # Prove the plan came from the same independently checked SOURCE
        # and the actual immutable Relation projector, NOT from a dict claim.
        return plan(
            binding, observed, revision=revision,
            effect_resolved=effect_resolved, checks_ok=checks_ok,
            binding_source=copy.deepcopy(
                self.fixture if binding_source is None else binding_source
            ),
            proposals=self.source, targets=self.targets,
            relation_project=self.relation_project,
        )

    def test_f1_real_relation_projector_and_actual_envs_proposed_q_same_target(self):
        binding = self.ok()
        self.assertEqual(binding["target_ref"], "pc7337-rent")
        self.assertEqual(binding["host_ref"], "ci-host-rent-1")
        self.assertEqual(binding["unit_ref"], "ci-rent-oci-unit-1")
        self.assertEqual(binding["scope"], "ci-session-1")
        self.assertEqual(binding["material"], self.source[0]["material"])
        self.assertEqual(binding["proposed_q"], self.fixture["proposed_q"])
        self.assertEqual(binding["admission"], "NOT_ADMITTED")
        self.assertEqual(binding["effect"], "FORBIDDEN")
        self.assertIsNone(binding["accepted_q"])
        o = copy.deepcopy(binding["identity"])
        o["tool"] = "ci:rent-tool-T1"
        outcome = self.planned(
            binding, o,
            revision="ci-" + binding["proposed_q"][7:23],
            effect_resolved=True, checks_ok=True,
        )
        self.assertEqual(outcome["stage"], "SYNTHETIC_TOOL_ONLY_CANDIDATE")
        self.assertEqual(outcome["gap"], ["tool"])
        self.assertEqual(outcome["effect"], "FORBIDDEN")
        self.assertFalse(outcome["target_ready"])

    def test_r1_mutated_bound_host_target_unit_scope_q_refuses_before_gap(self):
        bound = self.ok()
        observed = copy.deepcopy(bound["identity"])
        observed["tool"] = "ci:rent-tool-T1"
        revisions = []
        mutators = [
            ("host_ref", lambda v: v.update(host_ref="ci-foreign-host")),
            ("parent_ref", lambda v: v.update(parent_ref="ci-foreign-parent")),
            ("target_ref", lambda v: v.update(target_ref="ci-foreign-target")),
            ("unit_ref", lambda v: v.update(unit_ref="ci-foreign-unit")),
            ("scope", lambda v: v.update(scope="ci-foreign-scope")),
            ("selector", lambda v: v.update(selector="/nix/foreign/profile")),
            ("material", lambda v: v["material"].update(source_commit="f" * 40)),
            ("proposed_q", lambda v: v.update(proposed_q="sha256:" + "f" * 64)),
            ("identity_unit", lambda v: v["identity"].update(unit_ref="ci-foreign-unit")),
            ("identity_target", lambda v: v["identity"].update(target_ref="ci-foreign-target")),
            ("identity_tool", lambda v: v["identity"].update(tool="ci:malicious-T3")),
            ("admission", lambda v: v.update(admission="ADMITTED")),
            ("accepted_q", lambda v: v.update(accepted_q="ci-accepted")),
            ("effect", lambda v: v.update(effect="ALLOWED")),
            ("extra", lambda v: v.update(proposal_claim="authenticated")),
        ]
        for label, mutation in mutators:
            with self.subTest(label=label):
                changed = copy.deepcopy(bound)
                mutation(changed)
                revision = "ci-" + changed["proposed_q"][7:23]
                revisions.append(revision)
                with patch("host_tool_functional_binding.target_gap") as gap:
                    with self.assertRaisesRegex(ProposalError, "unvalidated or modified"):
                        self.planned(
                            changed, observed, revision=revision,
                            effect_resolved=True, checks_ok=True,
                        )
                    gap.assert_not_called()
        self.assertEqual(self.ok(), bound)
        self.assertIn("ci-" + "f" * 16, revisions)

    def test_r1_coherent_outer_and_inner_edits_or_foreign_source_refused(self):
        bound = self.ok()
        observed = copy.deepcopy(bound["identity"])
        observed["tool"] = "ci:rent-tool-T1"
        q = "ci-" + bound["proposed_q"][7:23]
        for label, mutate in (
            ("target", lambda b: (b.update(target_ref="ci-foreign-target"),
                                  b["identity"].update(target_ref="ci-foreign-target"))),
            ("unit", lambda b: (b.update(unit_ref="ci-foreign-unit"),
                                b["identity"].update(unit_ref="ci-foreign-unit"))),
            ("host_and_scope", lambda b: b.update(
                host_ref="ci-foreign-host", scope="ci-foreign-scope",
                parent_ref="ci-foreign-parent")),
            ("material_q", lambda b: (
                b["material"].update(source_commit="f" * 40),
                b.update(proposed_q="sha256:" + "f" * 64))),
        ):
            with self.subTest(label=label):
                changed = copy.deepcopy(bound)
                mutate(changed)
                revision = "ci-" + changed["proposed_q"][7:23]
                with patch("host_tool_functional_binding.target_gap") as gap:
                    with self.assertRaises(ProposalError):
                        self.planned(changed, observed, revision=revision,
                                     effect_resolved=True, checks_ok=True)
                    gap.assert_not_called()

        # An attacker cannot substitute a different source graph as the
        # authority for an already returned binding.
        changed_source = copy.deepcopy(self.fixture)
        changed_source["scope"] = "ci-foreign-scope"
        with patch("host_tool_functional_binding.target_gap") as gap:
            with self.assertRaises(ProposalError):
                self.planned(bound, observed, revision=q, effect_resolved=True,
                             checks_ok=True, binding_source=changed_source)
            gap.assert_not_called()
        # Reusing an unchanged content-equivalent dict is fine: integrity,
        # not object identity, is the SOURCE proof. No effects are granted.
        valid = self.planned(copy.deepcopy(bound), observed, revision=q,
                             effect_resolved=True, checks_ok=True)
        self.assertEqual(valid["stage"], "SYNTHETIC_TOOL_ONLY_CANDIDATE")
        self.assertEqual(valid["effect"], "FORBIDDEN")
        self.assertFalse(valid["target_ready"])

    def test_wrong_explicit_host_scope_parent_and_unit_prewrite_refuse(self):
        for key, bad in (
            ("host_ref", "ci-other-host"),
            ("parent_ref", "ci-other-parent"),
            ("scope", "ci-other-session"),
            ("target_ref", "ci-other-target"),
            ("unit_ref", ""),
        ):
            with self.subTest(key=key):
                f = copy.deepcopy(self.fixture)
                f[key] = bad
                with self.assertRaises((ValueError, self.relation_error)):
                    self.ok(f)

    def test_contains_only_manages_wrong_direction_and_wrap_do_not_grant(self):
        f = copy.deepcopy(self.fixture)
        f["relations"] = [e for e in f["relations"] if e["kind"] == "manages"]
        with self.assertRaisesRegex(ProposalError, "does not contain"):
            self.ok(f)
        f = copy.deepcopy(self.fixture)
        f["relations"][0]["parent"], f["relations"][0]["child"] = (
            f["relations"][0]["child"], f["relations"][0]["parent"])
        with self.assertRaises(ProposalError):
            self.ok(f)
        f = copy.deepcopy(self.fixture)
        f["relations"][0]["wrap"] = None
        self.assertEqual(self.ok(f)["admission"], "NOT_ADMITTED")
        f["relations"][0]["wrap"] = "OtherWrap"
        self.assertEqual(self.ok(f)["effect"], "FORBIDDEN")

    def test_real_projector_rejects_self_cycle_and_simultaneous_two_parents(self):
        for name in ("self", "cycle", "second_parent"):
            f = copy.deepcopy(self.fixture)
            first = f["relations"][0]
            if name == "self":
                first["child"] = first["parent"]
            elif name == "cycle":
                f["relations"].append({
                    "kind": "contains", "parent": first["child"],
                    "child": first["parent"], "scope": first["scope"], "wrap": None,
                })
            else:
                f["hosts"].append({
                    "id": "ci-third-parent", "implementation_ref": "ci:third",
                })
                f["relations"].append({
                    "kind": "contains", "parent": "ci-third-parent",
                    "child": first["child"], "scope": first["scope"], "wrap": "OCI",
                })
            with self.subTest(case=name), self.assertRaises(self.relation_error):
                self.ok(f)

    def test_producer_pin_wrong_q_and_injected_admission_fail_closed(self):
        for mutate in (
            lambda x: x["material"].update(source_commit="f" * 40),
            lambda x: x.update(proposed_q="sha256:" + "f" * 64),
            lambda x: x.update(admission="ADMITTED"),
            lambda x: x.update(effect="ALLOWED"),
            lambda x: x.update(selector="/nix/var/nix/profiles/foreign"),
            lambda x: x.update(desired_output="rent-tool-profile-next"),
            lambda x: x.update(secret="synthetic-credential"),
        ):
            f = copy.deepcopy(self.fixture)
            mutate(f)
            with self.subTest(line=mutate.__code__.co_firstlineno):
                with self.assertRaises((ValueError, self.relation_error)):
                    self.ok(f)

    def test_same_material_q_is_not_correct_host_or_correct_target_observation(self):
        b = self.ok()
        o = copy.deepcopy(b["identity"])
        o["base"] = "ci:unexpected-B"
        q = "ci-" + b["proposed_q"][7:23]
        self.assertEqual(self.planned(b, o, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "DIFFERENT_PLAN_REQUIRED")
        o = copy.deepcopy(b["identity"])
        o["unit_ref"] = "ci-wrong-unit"
        self.assertEqual(self.planned(b, o, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "TARGET_OR_UNIT_MISMATCH")
        o = copy.deepcopy(b["identity"])
        o["tool"] = "ci:rent-tool-T1"
        self.assertEqual(self.planned(b, o, revision="ci-stale", effect_resolved=True,
                              checks_ok=True)["stage"], "D_REVISION_NOT_CURRENT")
        self.assertEqual(self.planned(b, o, revision=q, effect_resolved=None,
                              checks_ok=True)["stage"], "E_UNKNOWN")
        self.assertEqual(self.planned(b, None, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "O_NOT_READ")


if __name__ == "__main__":
    unittest.main()
