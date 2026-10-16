"""Finite Host Tool step boundary, for isolated SOURCE SUT cases only.

This is NOT a production admission/dispatcher/executor, a Target credential,
a runtime ledger, or a way to construct a real update capability.
All facts here are synthetic, all decisions non-executable, effect=FORBIDDEN.
"""
from __future__ import annotations

from typing import Any

from host_tool_selection import ProposalError, exact_object, require

KIND = "envs.syntheticHostStep.v0"
STAGES = ("READ", "SOURCE_FIX", "TOOL_CHANGE", "RECORD", "ROLLBACK",
          "ROUTE_RECOVERY")
FACT_FIELDS = {
    "kind", "target_ref", "actor_ref", "work_ref", "attempt_ref", "step",
    "identity_current", "step_authority", "route_usable", "safe_boundary",
    "duplicate_read", "affected_effects_resolved", "inputs_current",
    "stage_checks", "dev_ready", "desired_current", "observation_fresh",
    "tool_compatible", "one_writer", "quiet_held", "recovery_available",
    "no_implicit_replay", "result_confirmed", "write_unresolved",
    "assignment_current", "receiver_start", "decision_recorded",
    "boundary_outcome",
}
TRI = (
    "identity_current", "step_authority", "route_usable", "safe_boundary",
    "duplicate_read", "affected_effects_resolved", "inputs_current",
    "stage_checks", "dev_ready", "desired_current", "observation_fresh",
    "tool_compatible", "one_writer", "quiet_held", "recovery_available",
    "no_implicit_replay", "result_confirmed", "write_unresolved",
    "assignment_current", "decision_recorded",
)


def evaluate(facts: dict[str, Any]) -> dict[str, Any]:
    """A stage-local read/change/start verdict, not an action or effect receipt.

    Unknown is represented by None. Every precondition has to be True to pass.
    ReadReady NEVER requires DevReady, future O, or old effect reconciliation;
    other mutations each have their own narrow affected-effect dependencies.
    """
    f = exact_object(facts, FACT_FIELDS, "synthetic step")
    require(f["kind"] == KIND and f["step"] in STAGES,
            "step must be a known SOURCE/READ/change fixture step")
    for key in ("target_ref", "actor_ref", "work_ref", "attempt_ref"):
        require(type(f[key]) is str and bool(f[key]) and len(f[key]) <= 100,
                "missing or malformed exact step identity")
    require(all(f[k] is None or type(f[k]) is bool for k in TRI),
            "a stage condition is not a tri-state fact")
    require(f["boundary_outcome"] in (None, "NEXT_STARTED", "SAFE_DECLINE", "OWNED_WAIT"),
            "unsupported boundary outcome")
    start = f["receiver_start"]
    if start is not None:
        exact_object(start, {"actor_ref", "work_ref", "attempt_ref", "step",
                             "receiver_started"}, "start")
        require(all(type(start[k]) is str and bool(start[k])
                    for k in ("actor_ref", "work_ref", "attempt_ref", "step"))
                and type(start["receiver_started"]) is bool,
                "invalid receiver start fact")
    # Observation of a started step is a FACT, including an unauthorized start.
    # It must never derive from permission, assignment or an API's acceptance.
    observed_started = bool(start and start["receiver_started"])
    matching_start = bool(observed_started
                          and start["actor_ref"] == f["actor_ref"]
                          and start["work_ref"] == f["work_ref"]
                          and start["attempt_ref"] == f["attempt_ref"]
                          and start["step"] == f["step"])

    required = ("identity_current", "step_authority", "route_usable", "safe_boundary")
    if f["step"] == "READ":
        required += ("duplicate_read",)
        # duplicate_read is the inverse: only False is safe.
    elif f["step"] == "SOURCE_FIX":
        required += ("dev_ready", "affected_effects_resolved",
                     "inputs_current", "stage_checks")
        # No dependency on unrelated Target UNKNOWN, Tool D or Target quiet.
    elif f["step"] == "TOOL_CHANGE":
        required += ("affected_effects_resolved", "inputs_current",
                     "stage_checks", "desired_current", "observation_fresh",
                     "tool_compatible", "one_writer", "quiet_held",
                     "recovery_available")
    elif f["step"] == "RECORD":
        required += ("affected_effects_resolved", "result_confirmed",
                     "inputs_current", "stage_checks", "no_implicit_replay")
        # No requirement that the Tool be changed again: only record missing E.
    elif f["step"] == "ROLLBACK":
        # Distinct permit is checked by the caller; here validate post-read
        # stage facts. A valid receipt/preimage is checked by the receiver.
        required += ("affected_effects_resolved", "inputs_current",
                     "stage_checks", "desired_current", "observation_fresh",
                     "tool_compatible", "one_writer", "quiet_held",
                     "recovery_available", "no_implicit_replay")
    elif f["step"] == "ROUTE_RECOVERY":
        required += ("affected_effects_resolved", "inputs_current",
                     "stage_checks", "one_writer", "no_implicit_replay")
        # A service restart is a mutation, NOT a read.

    failed = []
    for key in required:
        expected = False if key == "duplicate_read" else True
        if f[key] is not expected:
            failed.append(key)
    # Unknown write result is not an input to READ/SOURCE_FIX; it blocks
    # potentially equivalent mutations while they remain unresolved.
    if f["step"] in ("TOOL_CHANGE", "RECORD", "ROLLBACK", "ROUTE_RECOVERY"):
        if f["write_unresolved"] is not False:
            failed.append("write_unresolved")
    ready = not failed
    authorized_started = bool(
        ready and matching_start and f["assignment_current"] is True
    )
    # A missing start must not be fabricated from an accepted request.
    handoff_complete = authorized_started
    decision_recorded = f["decision_recorded"] is True
    outcome = f["boundary_outcome"]
    boundary_handled = bool(
        decision_recorded and (
            outcome == "SAFE_DECLINE"
            or outcome == "OWNED_WAIT"
            or (outcome == "NEXT_STARTED" and authorized_started)
        )
    )
    return {
        "kind": "envs.syntheticHostStepVerdict.v0",
        "target_ref": f["target_ref"],
        "step": f["step"],
        "stage": "SYNTHETIC_STEP_READY" if ready else "SYNTHETIC_STEP_REFUSED",
        "missing": failed,
        "synthetic_read_ready": ready if f["step"] == "READ" else False,
        "synthetic_mutation_ready": ready if f["step"] != "READ" else False,
        "observed_started": observed_started,
        "authorized_started": authorized_started,
        "handoff_complete": handoff_complete,
        "boundary_handled": boundary_handled,
        "admission": "NOT_ADMITTED",
        "accepted_q": None,
        "target_noop": "UNPROVEN",
        "effect": "FORBIDDEN",
        "target_ready": False,
        "merge_ready": False,
    }


IDENTITY_FIELDS = ("target_ref", "unit_ref", "base", "tool", "launch",
                   "config_binding", "state_contract")


def target_gap(desired: dict[str, Any] | None,
               observed: dict[str, Any] | None, *,
               current_revision: str | None = None,
               affected_effects_resolved: bool | None = None,
               required_checks: bool | None = None) -> dict[str, Any]:
    """Compare complete synthetic I(Dq) and I(O). Never classify real NOOP/success.

    Distinguish only-T from B, launch, config and state-contract changes;
    do not turn SourceNoChange or a matching material q into TargetNOOP.
    """
    def result(stage: str, gap: list[str] | None = None) -> dict[str, Any]:
        return {
            "kind": "envs.syntheticHostIdentityDiff.v0", "stage": stage,
            "gap": gap, "admission": "NOT_ADMITTED",
            "accepted_q": None, "target_noop": "UNPROVEN",
            "effect": "FORBIDDEN", "target_ready": False,
            "merge_ready": False,
        }

    if desired is None:
        return result("D_NOT_ADMITTED")
    d = exact_object(desired, {"kind", "selection_revision", "identity"}, "desired I")
    require(d["kind"] == "envs.syntheticTargetDesired.v0"
            and type(d["selection_revision"]) is str
            and d["selection_revision"].startswith("ci-")
            and len(d["selection_revision"]) <= 80,
            "invalid synthetic current D revision")
    d_i = exact_object(d["identity"], set(IDENTITY_FIELDS), "desired identity")
    for field in IDENTITY_FIELDS:
        require(type(d_i[field]) is str and bool(d_i[field]) and len(d_i[field]) <= 256,
                "incomplete or ambiguous D target identity")
    if observed is None:
        return result("O_NOT_READ")
    o = exact_object(observed, {"kind", "identity", "fresh", "valid"}, "observed I")
    require(o["kind"] == "envs.syntheticTargetObserved.v0"
            and (o["fresh"] is None or type(o["fresh"]) is bool)
            and (o["valid"] is None or type(o["valid"]) is bool),
            "invalid observed target fixture")
    if o["identity"] is None:
        return result("O_UNKNOWN_OR_STALE")
    o_i = exact_object(o["identity"], set(IDENTITY_FIELDS), "observed identity")
    for field in IDENTITY_FIELDS:
        require(type(o_i[field]) is str and bool(o_i[field]) and len(o_i[field]) <= 256,
                "ambiguous observed identity")
    if d_i["target_ref"] != o_i["target_ref"] or d_i["unit_ref"] != o_i["unit_ref"]:
        return result("TARGET_OR_UNIT_MISMATCH")
    if o["fresh"] is not True or o["valid"] is not True:
        return result("O_UNKNOWN_OR_STALE")
    if current_revision != d["selection_revision"]:
        return result("D_REVISION_NOT_CURRENT")
    if affected_effects_resolved is not True:
        return result("E_UNKNOWN")
    if required_checks is not True:
        return result("REQUIRED_CHECKS_UNPROVEN")
    difference = [field for field in IDENTITY_FIELDS
                  if d_i[field] != o_i[field]]
    if not difference:
        return result("MATCH_ONLY_NOT_SUCCESS", [])
    if difference == ["tool"]:
        return result("SYNTHETIC_TOOL_ONLY_CANDIDATE", difference)
    return result("DIFFERENT_PLAN_REQUIRED", difference)
