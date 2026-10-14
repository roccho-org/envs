"""Unadmitted SOURCE binding: actual resources Relation projector + envs D/q.

Pure function. It performs no Target read, command, effect, admission or route
selection. Explicit Host/Target/Unit, not repo/path-derived Host identity.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from host_tool_selection import ProposalError, exact_object, project, require
from host_tool_continuation import target_gap

KIND = "envs.hostToolFunctionalBindingProposal.v0"
FIELDS = {
    "kind", "admission", "target_ref", "host_ref", "parent_ref", "unit_ref",
    "scope", "selector", "desired_output", "proposed_q", "material",
    "hosts", "relations", "identity",
}
IDENTITY = {"base", "tool", "launch", "config_binding", "state_contract"}
PROFILE = "/nix/var/nix/profiles/rent-dev"
OUTPUT = "rent-tool-profile"


def bind(
    value: dict[str, Any],
    proposals: list[dict[str, Any]],
    targets: list[dict[str, Any]],
    relation_project: Callable[[list[dict[str, Any]], list[dict[str, Any]]], dict[str, Any]],
) -> dict[str, Any]:
    """Bind proposed R, Target/Unit, q and full desired identity, never an effect."""
    f = exact_object(value, FIELDS, "functional binding")
    require(f["kind"] == KIND and f["admission"] == "NOT_ADMITTED",
            "functional binding attempted admission")
    for key in ("target_ref", "host_ref", "parent_ref", "unit_ref", "scope"):
        require(type(f[key]) is str and 1 <= len(f[key]) <= 120,
                "missing explicit Host/Target/unit/scope")
    require(f["host_ref"] != f["parent_ref"] and f["selector"] == PROFILE
            and f["desired_output"] == OUTPUT,
            "foreign selector or non-explicit Host binding")
    require(type(f["proposed_q"]) is str and type(f["hosts"]) is list
            and type(f["relations"]) is list and type(f["material"]) is dict,
            "functional binding malformed")
    desired_i = exact_object(f["identity"], IDENTITY, "full desired identity")
    require(all(type(v) is str and bool(v) and len(v) <= 160
                for v in desired_i.values()), "incomplete B/T/launch/config/state")
    projected = project(proposals, targets)
    require(len(projected) == 1
            and projected[0]["target_ref"] == f["target_ref"]
            and projected[0]["proposed_q"] == f["proposed_q"]
            and projected[0]["material"] == f["material"]
            and projected[0]["admission"] == "NOT_ADMITTED",
            "target/material/proposed q does not match actual envs SOURCE")
    # Invoke the real immutable resources #19 projector supplied by the
    # CI fixture, not an independent imitation of its graph validation.
    relation = relation_project(f["hosts"], f["relations"])
    require(relation["admission"] == "NOT_ADMITTED"
            and relation["effect"] == "FORBIDDEN"
            and relation["target_authority"] == "NOT_GRANTED",
            "foreign relation asserted admission or authority")
    require(f["host_ref"] in relation["host_ids"]
            and f["parent_ref"] in relation["host_ids"],
            "Host identities do not belong to same projected graph")
    # Exactly one scoped CONTAINS path is necessary for this Target. A
    # MANAGES edge or optional wrap does not imply containment/authority.
    contains = [
        edge for edge in relation["relations"]
        if edge["kind"] == "contains" and edge["scope"] == f["scope"]
        and edge["child"] == f["host_ref"]
    ]
    require(len(contains) == 1 and contains[0]["parent"] == f["parent_ref"],
            "Host/scope relation does not contain the bound Target Host")
    require(f["host_ref"].startswith("ci-") and f["parent_ref"].startswith("ci-")
            and f["scope"].startswith("ci-") and f["unit_ref"].startswith("ci-"),
            "only deliberately synthetic Host/unit/scope test binding is supported")
    return {
        "kind": "envs.syntheticHostToolFunctionalBinding.v0",
        "target_ref": f["target_ref"], "host_ref": f["host_ref"],
        "unit_ref": f["unit_ref"], "parent_ref": f["parent_ref"],
        "scope": f["scope"], "selector": f["selector"],
        "material": dict(f["material"]), "proposed_q": f["proposed_q"],
        "identity": {"target_ref": f["target_ref"],
                     "unit_ref": f["unit_ref"], **desired_i},
        "admission": "NOT_ADMITTED", "accepted_q": None,
        "target_noop": "UNPROVEN", "effect": "FORBIDDEN",
        "target_ready": False, "merge_ready": False,
    }


def plan(
    binding: dict[str, Any], observed_identity: dict[str, Any] | None, *,
    binding_source: dict[str, Any],
    proposals: list[dict[str, Any]], targets: list[dict[str, Any]],
    relation_project: Callable[[list[dict[str, Any]], list[dict[str, Any]]], dict[str, Any]],
    revision: str | None, effect_resolved: bool | None,
    checks_ok: bool | None,
) -> dict[str, Any]:
    """Pure I(Dq)/I(O) gap on the SAME independently recomputed SOURCE binding.

    A plain dict returned by bind() is mutable. Require its exact canonical
    equality to a NEW bind() of the explicit PROPOSED source, actual public
    target catalog and reviewed Relation projector before any candidate stage.
    This is NOT an authenticated Target D, an admission or an update authority.
    """
    require(type(binding) is dict, "unvalidated functional binding")
    verified = bind(binding_source, proposals, targets, relation_project)
    try:
        canonical = lambda obj: json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
        require(canonical(binding) == canonical(verified),
                "unvalidated or modified functional binding")
    except (ValueError, TypeError) as exc:
        raise ProposalError("unvalidated or modified functional binding") from exc
    expected = "ci-" + verified["proposed_q"][7:23]
    d = {
        "kind": "envs.syntheticTargetDesired.v0",
        "selection_revision": expected, "identity": verified["identity"],
    }
    o = (None if observed_identity is None else {
        "kind": "envs.syntheticTargetObserved.v0",
        "identity": observed_identity, "fresh": True, "valid": True,
    })
    status = target_gap(d, o, current_revision=revision,
                        affected_effects_resolved=effect_resolved,
                        required_checks=checks_ok)
    return {
        "kind": "envs.syntheticHostToolPlan.v0",
        "target_ref": verified["target_ref"], "host_ref": verified["host_ref"],
        "unit_ref": verified["unit_ref"], "scope": verified["scope"],
        "proposed_q": verified["proposed_q"],
        "stage": status["stage"], "gap": status["gap"],
        "admission": "NOT_ADMITTED", "accepted_q": None,
        "target_noop": "UNPROVEN", "effect": "FORBIDDEN",
        "target_ready": False, "merge_ready": False,
    }
