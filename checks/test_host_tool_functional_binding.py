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
        outcome = plan(
            binding, o,
            revision="ci-" + binding["proposed_q"][7:23],
            effect_resolved=True, checks_ok=True,
        )
        self.assertEqual(outcome["stage"], "SYNTHETIC_TOOL_ONLY_CANDIDATE")
        self.assertEqual(outcome["gap"], ["tool"])
        self.assertEqual(outcome["effect"], "FORBIDDEN")
        self.assertFalse(outcome["target_ready"])

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
        self.assertEqual(plan(b, o, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "DIFFERENT_PLAN_REQUIRED")
        o = copy.deepcopy(b["identity"])
        o["unit_ref"] = "ci-wrong-unit"
        self.assertEqual(plan(b, o, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "TARGET_OR_UNIT_MISMATCH")
        o = copy.deepcopy(b["identity"])
        o["tool"] = "ci:rent-tool-T1"
        self.assertEqual(plan(b, o, revision="ci-stale", effect_resolved=True,
                              checks_ok=True)["stage"], "D_REVISION_NOT_CURRENT")
        self.assertEqual(plan(b, o, revision=q, effect_resolved=None,
                              checks_ok=True)["stage"], "E_UNKNOWN")
        self.assertEqual(plan(b, None, revision=q, effect_resolved=True,
                              checks_ok=True)["stage"], "O_NOT_READ")


if __name__ == "__main__":
    unittest.main()
