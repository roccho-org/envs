#!/usr/bin/env python3
"""Finite SOURCE fixture cases for v6 stage-ready/started/continuation boundaries."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "adapters"))
from host_tool_selection import ProposalError  # noqa: E402
from host_tool_continuation import KIND, evaluate  # noqa: E402


def facts(step="READ"):
    return {
        "kind": KIND, "target_ref": "pc7337-rent", "actor_ref": "fixed-existing-W",
        "work_ref": "host-tool-ci", "attempt_ref": "ci-attempt-1",
        "step": step, "identity_current": True, "step_authority": True,
        "route_usable": True, "safe_boundary": True, "duplicate_read": False,
        "affected_effects_resolved": True, "inputs_current": True,
        "stage_checks": True, "dev_ready": True,
        "desired_current": True, "observation_fresh": True,
        "tool_compatible": True, "one_writer": True,
        "quiet_held": True, "recovery_available": True,
        "no_implicit_replay": True, "result_confirmed": True,
        "write_unresolved": False,
        "assignment_current": True, "receiver_start": None,
        "decision_recorded": False, "boundary_outcome": None,
    }


def receiver(f, *, actor=None, attempt=None, started=True):
    return {"actor_ref": f["actor_ref"] if actor is None else actor,
            "work_ref": f["work_ref"], "attempt_ref": f["attempt_ref"] if attempt is None else attempt,
            "step": f["step"], "receiver_started": started}


class ContinuationStageCases(unittest.TestCase):
    def assert_inert(self, result):
        self.assertEqual(result["admission"], "NOT_ADMITTED")
        self.assertIsNone(result["accepted_q"])
        self.assertEqual(result["target_noop"], "UNPROVEN")
        self.assertEqual(result["effect"], "FORBIDDEN")
        self.assertFalse(result["target_ready"])
        self.assertFalse(result["merge_ready"])
        self.assertNotIn("command", result)
        self.assertNotIn("authorization", result)

    def test_read_does_not_require_dev_go_d_o_or_effect_resolution(self):
        f = facts()
        for key in ("dev_ready", "desired_current", "observation_fresh",
                    "affected_effects_resolved", "stage_checks", "result_confirmed",
                    "one_writer", "quiet_held", "recovery_available"):
            f[key] = None
        f["write_unresolved"] = True
        r = evaluate(f)
        self.assertEqual(r["stage"], "SYNTHETIC_STEP_READY")
        self.assertTrue(r["synthetic_read_ready"])
        self.assertFalse(r["synthetic_mutation_ready"])
        self.assertFalse(r["observed_started"])
        self.assert_inert(r)

    def test_read_must_have_actual_target_actor_scope_route_safety_no_duplicate(self):
        for key, value in (("step_authority", False), ("step_authority", None),
                           ("identity_current", False), ("route_usable", None),
                           ("safe_boundary", False), ("duplicate_read", True),
                           ("duplicate_read", None)):
            f = facts()
            f[key] = value
            r = evaluate(f)
            self.assertEqual(r["stage"], "SYNTHETIC_STEP_REFUSED")
            self.assertIn(key, r["missing"])
            self.assert_inert(r)

    def test_source_fix_can_continue_with_unrelated_target_unknown(self):
        f = facts("SOURCE_FIX")
        f.update(write_unresolved=True, desired_current=None, observation_fresh=None,
                 one_writer=None, quiet_held=None)
        self.assertEqual(evaluate(f)["stage"], "SYNTHETIC_STEP_READY")
        for key in ("dev_ready", "affected_effects_resolved", "inputs_current",
                    "stage_checks", "step_authority"):
            bad = copy.deepcopy(f)
            bad[key] = None
            self.assertIn(key, evaluate(bad)["missing"])

    def test_target_change_requires_every_stage_local_condition_and_resolved_effect(self):
        f = facts("TOOL_CHANGE")
        self.assertEqual(evaluate(f)["stage"], "SYNTHETIC_STEP_READY")
        for key in ("step_authority", "route_usable", "safe_boundary", "identity_current",
                    "affected_effects_resolved", "inputs_current", "stage_checks",
                    "desired_current", "observation_fresh", "tool_compatible",
                    "one_writer", "quiet_held", "recovery_available"):
            bad = copy.deepcopy(f)
            bad[key] = None
            result = evaluate(bad)
            self.assertIn(key, result["missing"])
            self.assertFalse(result["synthetic_mutation_ready"])
            self.assert_inert(result)
        f["write_unresolved"] = True
        self.assertIn("write_unresolved", evaluate(f)["missing"])

    def test_record_only_does_not_rewrite_an_already_selected_tool(self):
        f = facts("RECORD")
        f.update(quiet_held=None, one_writer=None, recovery_available=None)
        self.assertTrue(evaluate(f)["synthetic_mutation_ready"])
        for key in ("result_confirmed", "no_implicit_replay", "affected_effects_resolved"):
            bad = copy.deepcopy(f)
            bad[key] = False
            self.assertIn(key, evaluate(bad)["missing"])
        f["write_unresolved"] = None
        self.assertIn("write_unresolved", evaluate(f)["missing"])
        self.assert_inert(evaluate(f))

    def test_recovery_restart_is_mutation_and_not_read(self):
        f = facts("ROUTE_RECOVERY")
        self.assertTrue(evaluate(f)["synthetic_mutation_ready"])
        self.assertFalse(evaluate(f)["synthetic_read_ready"])
        f["no_implicit_replay"] = False
        self.assertIn("no_implicit_replay", evaluate(f)["missing"])
        f["no_implicit_replay"] = True
        f["affected_effects_resolved"] = None
        self.assertIn("affected_effects_resolved", evaluate(f)["missing"])

    def test_observed_start_can_be_real_but_unauthorized(self):
        f = facts("TOOL_CHANGE")
        f["step_authority"] = False
        f["receiver_start"] = receiver(f, started=True)
        r = evaluate(f)
        self.assertTrue(r["observed_started"])
        self.assertFalse(r["authorized_started"])
        self.assertFalse(r["handoff_complete"])
        f["step_authority"] = True
        f["receiver_start"] = receiver(f, actor="foreign-actor")
        r = evaluate(f)
        self.assertTrue(r["observed_started"])
        self.assertFalse(r["authorized_started"])
        f["receiver_start"] = receiver(f, attempt="old-attempt")
        self.assertFalse(evaluate(f)["authorized_started"])
        f["receiver_start"] = receiver(f, started=False)
        self.assertFalse(evaluate(f)["observed_started"])
        f["receiver_start"] = receiver(f)
        self.assertTrue(evaluate(f)["authorized_started"])

    def test_handoff_requires_assigned_actual_start_not_ack(self):
        f = facts("SOURCE_FIX")
        f["assignment_current"] = True
        f["decision_recorded"] = True
        f["boundary_outcome"] = "NEXT_STARTED"
        r = evaluate(f)
        self.assertFalse(r["handoff_complete"])
        self.assertFalse(r["boundary_handled"])
        f["receiver_start"] = receiver(f)
        r = evaluate(f)
        self.assertTrue(r["handoff_complete"])
        self.assertTrue(r["boundary_handled"])
        f["assignment_current"] = False
        r = evaluate(f)
        self.assertTrue(r["observed_started"])
        self.assertFalse(r["handoff_complete"])
        self.assertFalse(r["boundary_handled"])

    def test_external_wait_or_safe_decline_must_be_recorded(self):
        f = facts("SOURCE_FIX")
        for state in ("SAFE_DECLINE", "OWNED_WAIT"):
            f["boundary_outcome"] = state
            self.assertFalse(evaluate(f)["boundary_handled"])
            f["decision_recorded"] = True
            self.assertTrue(evaluate(f)["boundary_handled"])
            f["decision_recorded"] = False
        f["boundary_outcome"] = None
        f["decision_recorded"] = True
        self.assertFalse(evaluate(f)["boundary_handled"])

    def test_forged_scope_and_shape_refused(self):
        f = facts()
        for change in (
            lambda x: x.update(step="EXECUTE_ANYTHING"),
            lambda x: x.update(kind="envs.productionTool.v1"),
            lambda x: x.update(target_ref=""),
            lambda x: x.update(step_authority="true"),
            lambda x: x.update(route_usable=1),
            lambda x: x.update(unknown_action=True),
            lambda x: x.update(boundary_outcome="ACK"),
            lambda x: x.update(receiver_start={"receiver_started": True}),
        ):
            with self.subTest(change=change.__code__.co_firstlineno):
                bad = copy.deepcopy(f)
                change(bad)
                with self.assertRaises(ProposalError):
                    evaluate(bad)


if __name__ == "__main__":
    unittest.main()
