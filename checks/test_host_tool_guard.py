#!/usr/bin/env python3
"""SOURCE-only synthetic admitted D/O/permission fixtures; no real Host or provider."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
from host_tool_selection import ProposalError, project_root  # noqa: E402
from host_tool_guard import judge  # noqa: E402

STORE0 = "/nix/store/" + "a" * 32 + "-older-tool"
STORE1 = "/nix/store/" + "b" * 32 + "-chosen-tool"


def context():
    p = project_root(ROOT)[0]
    target = p["target_ref"]
    d = {
        "kind": "envs.syntheticDesired.v0", "target_ref": target,
        "admission": "SYNTHETIC_ADMITTED", "revision": "ci-r1",
        "proposed_q": p["proposed_q"], "material": copy.deepcopy(p["material"]),
        "store_path": STORE1,
    }
    o = {
        "kind": "envs.syntheticObservation.v0", "target_ref": target,
        "state": "SELECTED", "store_path": STORE0,
        "fresh": True, "closure_valid": True,
    }
    a = {
        "kind": "envs.syntheticAuthority.v0", "target_ref": target,
        "read": True, "change": True, "quiet": True,
        "single_writer": True, "recovery": True,
    }
    e = {
        "kind": "envs.syntheticEffect.v0", "target_ref": target,
        "state": "NONE", "revision": None, "store_path": None,
    }
    return p, d, o, a, e


def state(*, proposal=None, desired=True, observation=True, authority=True, effect=True):
    p, d, o, a, e = context()
    return judge(p if proposal is None else proposal,
                 desired=d if desired else None, observed=o if observation else None,
                 authority=a if authority else None, previous=e if effect else None)


class GuardTests(unittest.TestCase):
    def expect_stage(self, expect, p, d, o, a, e, *, read=True, change=False):
        got = judge(p, desired=d, observed=o, authority=a, previous=e)
        self.assertEqual(got["stage"], expect)
        self.assertEqual(got["synthetic_read_preconditions"], read)
        self.assertEqual(got["synthetic_change_preconditions"], change)
        self.assertEqual(got["kind"], "envs.hostToolGuardFixture.v0")
        self.assertEqual(got["admission"], "NOT_ADMITTED")
        self.assertIsNone(got["accepted_q"])
        self.assertEqual(got["target_noop"], "UNPROVEN")
        self.assertEqual(got["effect"], "FORBIDDEN")
        self.assertNotIn("command", got)
        return got

    def test_read_permission_does_not_require_admission_or_effect_resolution(self):
        p, d, o, a, e = context()
        self.expect_stage("READ_AUTH_REQUIRED", p, d, o, None, e, read=False)
        a["read"] = False
        self.expect_stage("READ_AUTH_REQUIRED", p, d, o, a, e, read=False)
        a["read"] = True
        self.expect_stage("D_NOT_ADMITTED", p, None, o, a, e)
        self.expect_stage("O_NOT_READ", p, d, None, a, e)
        o["state"], o["store_path"] = "UNKNOWN", None
        self.expect_stage("O_UNKNOWN_OR_STALE", p, d, o, a, e)
        o["state"], o["store_path"] = "ABSENT", None
        o["fresh"] = False
        self.expect_stage("O_UNKNOWN_OR_STALE", p, d, o, a, e)
        o["fresh"] = True
        e["state"] = "UNKNOWN"
        self.expect_stage("E_UNKNOWN", p, d, o, a, e)
        self.expect_stage("E_NOT_RECONCILED", p, d, o, a, None)

    def test_change_preconditions_are_separate_and_do_not_grant_effect(self):
        p, d, o, a, e = context()
        self.expect_stage("SYNTHETIC_CHANGE_CANDIDATE", p, d, o, a, e, change=True)
        for key, expected in (
            ("change", "CHANGE_AUTH_REQUIRED"),
            ("quiet", "QUIET_UNPROVEN"),
            ("single_writer", "WRITER_UNPROVEN"),
            ("recovery", "RECOVERY_UNPROVEN"),
        ):
            bad = copy.deepcopy(a)
            bad[key] = False
            self.expect_stage(expected, p, d, o, bad, e)
        o["closure_valid"] = False
        self.expect_stage("TOOL_NOT_PROVEN", p, d, o, a, e)
        o["closure_valid"] = True
        o["store_path"] = STORE1
        self.expect_stage("MATCH_WITHOUT_RECEIPT", p, d, o, a, e)
        o["state"], o["store_path"] = "ABSENT", None
        self.expect_stage("SYNTHETIC_CHANGE_CANDIDATE", p, d, o, a, e, change=True)

    def test_even_matching_effect_receipt_is_only_synthetic_readback(self):
        p, d, o, a, e = context()
        e.update(state="CONFIRMED", revision=d["revision"], store_path=d["store_path"])
        self.expect_stage("E_CONFLICT", p, d, o, a, e)
        o["store_path"] = STORE1
        self.expect_stage("SYNTHETIC_READBACK_CANDIDATE", p, d, o, a, e)
        d["revision"] = "ci-r2"
        self.expect_stage("E_CONFLICT", p, d, o, a, e)
        d["revision"] = "ci-r1"
        o["fresh"] = False
        self.expect_stage("O_UNKNOWN_OR_STALE", p, d, o, a, e)

    def test_cross_target_foreign_revision_or_forged_q_refused(self):
        p, d, o, a, e = context()
        for name in ("proposal", "desired", "observed", "authority", "previous"):
            inputs = [copy.deepcopy(item) for item in (p, d, o, a, e)]
            which = {"proposal": 0, "desired": 1, "observed": 2,
                     "authority": 3, "previous": 4}[name]
            inputs[which]["target_ref"] = "other-target"
            with self.subTest(name=name), self.assertRaises(ProposalError):
                judge(inputs[0], desired=inputs[1], observed=inputs[2],
                      authority=inputs[3], previous=inputs[4])
        d["proposed_q"] = "sha256:" + "f" * 64
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=a, previous=e)
        p["proposed_q"] = "sha256:" + "f" * 64
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=a, previous=e)
        p, d, o, a, e = context()
        d["admission"] = "ADMITTED"
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=a, previous=e)

    def test_missing_or_ambiguous_permission_and_receipt_fail_closed(self):
        p, d, o, a, e = context()
        for name, value in (("read", None), ("read", "true"), ("change", 1),
                            ("quiet", "yes"), ("single_writer", None), ("recovery", "true")):
            bad = copy.deepcopy(a)
            bad[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ProposalError):
                judge(p, desired=d, observed=o, authority=bad, previous=e)
        bad = copy.deepcopy(a)
        bad["actor_secret"] = "FAKE"
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=bad, previous=e)
        e["revision"] = "ci-r1"   # unresolved effect cannot claim a receipt
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=a, previous=e)
        e["revision"] = None
        o["state"], o["store_path"] = "UNKNOWN", STORE0  # impossible geometry
        with self.assertRaises(ProposalError):
            judge(p, desired=d, observed=o, authority=a, previous=e)

    def test_no_runtime_or_source_mutation_through_guard(self):
        paths = [ROOT / "contracts/targets.jsonl",
                 ROOT / "contracts/proposals/host-tool-selection.jsonl"]
        before = [p.read_bytes() for p in paths]
        p, d, o, a, e = context()
        for _ in range(4):
            self.expect_stage("SYNTHETIC_CHANGE_CANDIDATE", p, d, o, a, e, change=True)
        self.assertEqual([p.read_bytes() for p in paths], before)


if __name__ == "__main__":
    unittest.main()
