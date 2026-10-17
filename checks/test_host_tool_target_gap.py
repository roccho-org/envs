#!/usr/bin/env python3
"""Executable v6 V01–V14 synthetic D/I/O counterexamples; never Host success."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
from host_tool_selection import ProposalError  # noqa: E402
from host_tool_continuation import target_gap, evaluate  # noqa: E402
from test_host_tool_continuation import facts  # noqa: E402


def identity(tool="T1"):
    return {
        "target_ref": "pc7337-rent", "unit_ref": "synthetic-unit-1",
        "base": "ci-base-B0", "tool": tool, "launch": "ci-launch-S0",
        "config_binding": "ci-binding-D0", "state_contract": "ci-state-K0",
    }


def pair(actual="T0"):
    desired = {
        "kind": "envs.syntheticTargetDesired.v0", "selection_revision": "ci-q1",
        "identity": identity("T1"),
    }
    observed = {
        "kind": "envs.syntheticTargetObserved.v0", "identity": identity(actual),
        "fresh": True, "valid": True,
    }
    return desired, observed


def check(d, o, *, q="ci-q1", effects=True, checks=True):
    return target_gap(d, o, current_revision=q, affected_effects_resolved=effects,
                      required_checks=checks)


class IdentityDiffCases(unittest.TestCase):
    def stage(self, want, d, o, **kwargs):
        got = check(d, o, **kwargs)
        self.assertEqual(got["stage"], want)
        self.assertEqual(got["admission"], "NOT_ADMITTED")
        self.assertIsNone(got["accepted_q"])
        self.assertEqual(got["target_noop"], "UNPROVEN")
        self.assertEqual(got["effect"], "FORBIDDEN")
        self.assertFalse(got["target_ready"])
        self.assertFalse(got["merge_ready"])
        self.assertNotIn("command", got)
        return got

    def test_v01_v03_desired_tool_diff_even_when_source_unchanged(self):
        d, o = pair()
        self.assertEqual(self.stage("SYNTHETIC_TOOL_ONLY_CANDIDATE", d, o)["gap"],
                         ["tool"])
        # No SOURCE delta input is necessary to learn there is still a Target gap.
        self.assertEqual(self.stage("SYNTHETIC_TOOL_ONLY_CANDIDATE", d, o)["gap"],
                         ["tool"])

    def test_v02_separate_target_chooses_old_tool_not_newest_producer(self):
        d, o = pair("T0")
        d["identity"]["tool"] = "T0"
        self.assertEqual(self.stage("MATCH_ONLY_NOT_SUCCESS", d, o)["gap"], [])

    def test_v04_v05_unknown_old_effect_blocks_even_when_versions_look_matching(self):
        d, o = pair()
        self.stage("E_UNKNOWN", d, o, effects=None)
        o["identity"]["tool"] = "T1"
        self.stage("E_UNKNOWN", d, o, effects=False)
        f = facts("READ")
        f["affected_effects_resolved"] = None
        f["write_unresolved"] = True
        self.assertTrue(evaluate(f)["synthetic_read_ready"])

    def test_v06_v07_matching_current_d_and_o_still_need_real_receipt(self):
        d, o = pair("T1")
        r = self.stage("MATCH_ONLY_NOT_SUCCESS", d, o)
        self.assertEqual(r["gap"], [])
        self.assertEqual(r["target_noop"], "UNPROVEN")
        self.assertEqual(r["effect"], "FORBIDDEN")
        f = facts("RECORD")
        self.assertTrue(evaluate(f)["synthetic_mutation_ready"])
        self.assertEqual(evaluate(f)["effect"], "FORBIDDEN")

    def test_v08_different_base_demands_separate_plan(self):
        d, o = pair()
        o["identity"]["base"] = "ci-base-B-older"
        got = self.stage("DIFFERENT_PLAN_REQUIRED", d, o)
        self.assertEqual(set(got["gap"]), {"base", "tool"})

    def test_v09_unadmitted_d_must_stop_noop_and_change(self):
        _, o = pair()
        self.stage("D_NOT_ADMITTED", None, o)

    def test_v10_old_revision_cannot_be_used_as_current_success(self):
        d, o = pair("T1")
        self.stage("D_REVISION_NOT_CURRENT", d, o, q="ci-q2")

    def test_v11_observation_missing_stale_or_invalid(self):
        d, o = pair()
        self.stage("O_NOT_READ", d, None)
        o["fresh"] = False
        self.stage("O_UNKNOWN_OR_STALE", d, o)
        o["fresh"] = True
        o["valid"] = None
        self.stage("O_UNKNOWN_OR_STALE", d, o)
        o["identity"] = None
        self.stage("O_UNKNOWN_OR_STALE", d, o)

    def test_v12_concurrent_writer_or_lost_quiet_denies_real_change(self):
        d, o = pair()
        self.stage("SYNTHETIC_TOOL_ONLY_CANDIDATE", d, o)
        f = facts("TOOL_CHANGE")
        for key in ("quiet_held", "one_writer", "recovery_available"):
            altered = copy.deepcopy(f)
            altered[key] = False
            self.assertIn(key, evaluate(altered)["missing"])
            self.assertFalse(evaluate(altered)["synthetic_mutation_ready"])

    def test_v13_closure_or_auth_session_checks_missing_denies(self):
        d, o = pair("T1")
        self.stage("REQUIRED_CHECKS_UNPROVEN", d, o, checks=False)
        o["valid"] = False
        self.stage("O_UNKNOWN_OR_STALE", d, o)

    def test_v14_binding_launch_or_state_change_is_not_tool_only(self):
        for field in ("launch", "config_binding", "state_contract"):
            d, o = pair()
            o["identity"][field] = "ci-other"
            self.assertIn(field, self.stage("DIFFERENT_PLAN_REQUIRED", d, o)["gap"])

    def test_target_unit_not_derived_from_repo_or_oci_path(self):
        d, o = pair()
        o["identity"]["unit_ref"] = "different-unit"
        self.stage("TARGET_OR_UNIT_MISMATCH", d, o)
        o["identity"]["unit_ref"] = d["identity"]["unit_ref"]
        o["identity"]["target_ref"] = "foreign-target"
        self.stage("TARGET_OR_UNIT_MISMATCH", d, o)

    def test_unknown_or_forged_identity_is_refused_before_any_effect(self):
        for mutate in (
            lambda d, o: d["identity"].update(secret="fake"),
            lambda d, o: o["identity"].update(secret="fake"),
            lambda d, o: d["identity"].update(base=None),
            lambda d, o: o["identity"].update(tool=False),
            lambda d, o: d.update(kind="envs.targetDesired.v1"),
            lambda d, o: o.update(fresh="true"),
            lambda d, o: d.update(selection_revision="current"),
            lambda d, o: d.update(extra="accept"),
        ):
            d, o = pair()
            mutate(d, o)
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                with self.assertRaises(ProposalError):
                    check(d, o)


if __name__ == "__main__":
    unittest.main()
