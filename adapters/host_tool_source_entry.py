"""Narrow PROPOSED Host Tool SOURCE entry. No production imports or live Target.

Explicit SOURCE-only subject, authority, current q and injected disposable port.
Unlike unittest helpers, NONE is never replaced with a positive fixture.
This is an inert future interface, not a listener, accepted D, or effect engine.
"""
from __future__ import annotations

from typing import Any, Callable

from host_tool_functional_binding import bind, plan
from host_tool_selection import ProposalError, exact_object, project, require
from host_tool_continuation import evaluate
from host_tool_guard import judge, STORE

REQUEST_KEYS = {"kind", "action", "target_ref", "host_ref", "unit_ref", "scope",
                "actor_ref", "work_ref", "attempt_ref", "proposed_q",
                "requested_store"}
AUTH_KEYS = {"kind", "target_ref", "host_ref", "unit_ref", "scope",
             "actor_ref", "work_ref", "attempt_ref", "read", "change",
             "quiet", "single_writer", "recovery", "route"}
O_KEYS = {"kind", "target_ref", "host_ref", "unit_ref", "scope", "state",
          "store_path", "identity", "fresh", "closure_valid"}
STEPS = {"READ": "READ", "CHANGE": "TOOL_CHANGE",
         "RECORD": "RECORD", "ROLLBACK": "TOOL_CHANGE"}


def verdict(stage: str, *, observation=None, receipt=None) -> dict[str, Any]:
    return {
        "kind": "envs.syntheticHostSourceEntryVerdict.v0",
        "stage": stage, "observation": observation, "issued_receipt": receipt,
        "admission": "NOT_ADMITTED", "accepted_q": None,
        "target_noop": "UNPROVEN", "effect": "FORBIDDEN",
        "target_ready": False, "merge_ready": False,
    }


def _preflight(req: Any, binding: dict[str, Any], authority: Any,
               read_facts: Any, port: Any) -> dict[str, Any]:
    request = exact_object(req, REQUEST_KEYS, "SOURCE request")
    require(request["kind"] == "envs.syntheticHostSourceRequest.v0"
            and request["action"] in STEPS, "unsupported SOURCE action")
    for field in ("target_ref", "host_ref", "unit_ref", "scope"):
        require(request[field] == binding[field], "foreign Host/Target/Unit/scope")
    require(request["proposed_q"] == binding["proposed_q"],
            "foreign or old PROPOSED q")
    for field in ("actor_ref", "work_ref", "attempt_ref"):
        require(type(request[field]) is str and request[field].startswith("ci-")
                and 4 <= len(request[field]) <= 100,
                "SOURCE subject is not an explicit ci-only identity")
    # A selector path must never be inferred from the caller or accepted contract.
    if request["action"] == "READ":
        require(request["requested_store"] is None, "READ includes mutation material")
    else:
        require(type(request["requested_store"]) is str
                and STORE.fullmatch(request["requested_store"]) is not None,
                "mutation material must be an exact SOURCE store path")
    access = exact_object(authority, AUTH_KEYS, "SOURCE scoped authority")
    require(access["kind"] == "envs.syntheticScopedAuthority.v0"
            and all(access[key] == request[key] for key in
                    ("target_ref", "host_ref", "unit_ref", "scope",
                     "actor_ref", "work_ref", "attempt_ref"))
            and all(type(access[key]) is bool for key in
                    ("read", "change", "quiet", "single_writer", "recovery", "route")),
            "SOURCE scoped authority absent or foreign")
    require(getattr(port, "kind", None) == "envs.syntheticDisposableTargetPort.v0"
            and getattr(port, "fixture_only", None) is True
            and all(callable(getattr(port, field, None)) for field in
                    ("observe", "select", "record", "rollback")),
            "no explicitly injected disposable Target port")
    require(access["read"] and access["route"], "no scoped READ or route")
    read = exact_object(read_facts, set(read_facts) if type(read_facts) is dict
                        else set(), "read facts")
    require(all(read.get(key) == request[key] for key in
                ("target_ref", "actor_ref", "work_ref", "attempt_ref"))
            and read.get("step") == "READ", "READ subject/attempt substitution")
    gate = evaluate(read)
    require(gate["synthetic_read_ready"] is True and gate["step"] == "READ",
            "READ stage not ready")
    return access


def _observation(value: Any, req: dict[str, Any]) -> dict[str, Any]:
    o = exact_object(value, O_KEYS, "Target SOURCE O")
    require(o["kind"] == "envs.syntheticPortObservation.v0"
            and all(o[k] == req[k] for k in
                    ("target_ref", "host_ref", "unit_ref", "scope"))
            and o["state"] in ("ABSENT", "SELECTED", "UNKNOWN")
            and all(type(o[k]) is bool for k in ("fresh", "closure_valid")),
            "observation does not match explicit Target/Unit")
    if o["state"] == "UNKNOWN":
        require(o["store_path"] is None and o["identity"] is None,
                "unknown observation asserted a complete identity")
    elif o["state"] == "ABSENT":
        # Base can be observed independently from its absent Tool. A complete
        # base/launch/config/state identity permits a first explicit T candidate;
        # a geometry-only ABSENT without it remains READ-only.
        require(o["store_path"] is None
                and (o["identity"] is None or type(o["identity"]) is dict),
                "absent Tool falsely asserted selected material")
    else:
        require(type(o["store_path"]) is str
                and STORE.fullmatch(o["store_path"]) is not None
                and type(o["identity"]) is dict,
                "selected Target has malformed material or identity")
    if type(o["identity"]) is dict:
        require(o["identity"].get("target_ref") == req["target_ref"]
                and o["identity"].get("unit_ref") == req["unit_ref"],
                "observation not for exact Target/Unit")
    return o


def source_step(
    request: dict[str, Any], *, binding_source: dict[str, Any],
    proposals: list[dict[str, Any]], targets: list[dict[str, Any]],
    relation_project: Callable, authority: dict[str, Any] | None,
    read_facts: dict[str, Any] | None, change_facts: dict[str, Any] | None,
    current_q: str | None, desired: dict[str, Any] | None,
    previous: dict[str, Any] | None, port: Any, receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Receive exactly one stage against an explicit *synthetic* Target port.

    The caller supplies ALL facts; there are no positive authority/default-D
    fallbacks. No stage ever returns real acceptance or executable permission.
    """
    try:
        binding = bind(binding_source, proposals, targets, relation_project)
        auth = _preflight(request, binding, authority, read_facts, port)
        proposal = project(proposals, targets)[0]
        read_gate = judge(proposal, desired=None, authority={
            "kind": "envs.syntheticAuthority.v0",
            "target_ref": request["target_ref"],
            "read": auth["read"], "change": auth["change"],
            "quiet": auth["quiet"], "single_writer": auth["single_writer"],
            "recovery": auth["recovery"],
        })
        require(read_gate["synthetic_read_preconditions"] is True,
                "separate D-independent READ denied")
        action = request["action"]
        # READ requires no D, old q, change rights, or resolution of prior UNKNOWN.
        if action == "READ":
            # This is the FIRST and only observation site for READ.
            observation = _observation(port.observe(), request)
            return verdict("SYNTHETIC_READ_OBSERVED", observation=observation)

        require(auth["change"] and auth["quiet"] and auth["single_writer"]
                and auth["recovery"], "CHANGE/RECORD/ROLLBACK authority incomplete")
        require(type(desired) is dict and type(current_q) is str
                and desired.get("target_ref") == binding["target_ref"]
                and desired.get("proposed_q") == binding["proposed_q"]
                and desired.get("material") == binding["material"]
                and desired.get("revision") == ("ci-" + binding["proposed_q"][7:23])
                and current_q == desired["revision"]
                and request["requested_store"] == desired.get("store_path"),
                "missing or superseded synthetic D/current q")
        require(type(previous) is dict and previous.get("target_ref") == binding["target_ref"]
                and previous.get("kind") == "envs.syntheticEffect.v0",
                "previous effect is not an exact SOURCE fact")
        stage_name = STEPS[action]
        stage_facts = exact_object(change_facts, set(change_facts)
                                   if type(change_facts) is dict else set(), "mutation facts")
        require(stage_facts.get("step") == stage_name
                and all(stage_facts.get(k) == request[k] for k in
                        ("target_ref", "actor_ref", "work_ref", "attempt_ref")),
                "mutation stage/subject/attempt substitution")
        stage = evaluate(stage_facts)
        require(stage["synthetic_mutation_ready"] is True,
                "mutation stage not independently ready")
        # If E may be unresolved, a read is possible (above), not a blind change.
        require(previous.get("state") == ("NONE" if action == "CHANGE" else "CONFIRMED"),
                "old effect unknown or not yet confirmed")
        # Only after both READ and CHANGE preflight may the disposable port be read.
        obs = _observation(port.observe(), request)
        o = {
            "kind": "envs.syntheticObservation.v0", "target_ref": request["target_ref"],
            "state": obs["state"], "store_path": obs["store_path"],
            "fresh": obs["fresh"], "closure_valid": obs["closure_valid"],
        }
        candidate = plan(
            binding, obs["identity"], binding_source=binding_source,
            proposals=proposals, targets=targets, relation_project=relation_project,
            revision=current_q, effect_resolved=True,
            checks_ok=obs["fresh"] and obs["closure_valid"],
        )
        judged = judge(proposal, desired=desired, observed=o,
                       authority={"kind": "envs.syntheticAuthority.v0",
                                  "target_ref": request["target_ref"],
                                  "read": auth["read"], "change": auth["change"],
                                  "quiet": auth["quiet"],
                                  "single_writer": auth["single_writer"],
                                  "recovery": auth["recovery"]},
                       previous=previous)
        if action == "CHANGE":
            require(candidate["stage"] == "SYNTHETIC_TOOL_ONLY_CANDIDATE"
                    and judged["stage"] == "SYNTHETIC_CHANGE_CANDIDATE",
                    "not a current q Tool-only change")
            # Only this explicit SOURCE port is allowed; no repeat on exception.
            try:
                issued = port.select(request["requested_store"], request["attempt_ref"],
                                     desired["revision"])
            except Exception:
                return verdict("SYNTHETIC_EFFECT_UNKNOWN_NO_REPLAY")
            # The effect may already have occurred. An invalid/undelivered
            # receipt is UNKNOWN, never a pre-effect REFUSED or real SUCCESS.
            if (type(issued) is not dict
                    or issued.get("attempt") != request["attempt_ref"]
                    or issued.get("selected") != request["requested_store"]
                    or issued.get("effect") != "SYNTHETIC_ONLY"
                    or issued.get("preimage") != obs["store_path"]):
                return verdict("SYNTHETIC_EFFECT_UNKNOWN_NO_REPLAY")
            try:
                final = _observation(port.observe(), request)
            except Exception:
                return verdict("SYNTHETIC_READBACK_UNKNOWN_NO_REPLAY", receipt=issued)
            if (final["state"] != "SELECTED"
                    or final["store_path"] != request["requested_store"]
                    or final["identity"] != binding["identity"]
                    or not final["fresh"] or not final["closure_valid"]):
                return verdict("SYNTHETIC_READBACK_UNKNOWN_NO_REPLAY", receipt=issued)
            return verdict("SYNTHETIC_READBACK_CANDIDATE_NOT_SUCCESS",
                           observation=final, receipt=issued)
        require(judged["stage"] == "SYNTHETIC_READBACK_CANDIDATE"
                and candidate["stage"] == "MATCH_ONLY_NOT_SUCCESS"
                and obs["store_path"] == request["requested_store"]
                and obs["identity"] == binding["identity"],
                "not the exact confirmed Tool readback")
        require(type(receipt) is dict and receipt.get("attempt") == request["attempt_ref"]
                and receipt.get("selected") == request["requested_store"]
                and receipt.get("effect") == "SYNTHETIC_ONLY",
                "missing exact test receipt")
        try:
            if action == "RECORD":
                output = port.record(receipt)
            else:
                output = port.rollback(receipt, request["attempt_ref"], desired)
        except ValueError:
            # DisposablePort contract: ValueError is a verified pre-write
            # refusal (invalid/non-issued receipt). It grants no retry.
            return verdict("REFUSED_PORT_PRECONDITION")
        except Exception:
            return verdict("SYNTHETIC_EFFECT_UNKNOWN_NO_REPLAY")
        if output not in ("SYNTHETIC_RECORD_ONLY", "SYNTHETIC_ROLLBACK_NOT_NEW_D_SUCCESS"):
            return verdict("SYNTHETIC_EFFECT_UNKNOWN_NO_REPLAY")
        return verdict("SYNTHETIC_RECORD_ONLY_CANDIDATE" if action == "RECORD"
                       else "SYNTHETIC_ROLLBACK_READBACK_REQUIRED")
    except (ValueError, TypeError, KeyError, AttributeError):
        return verdict("REFUSED_SOURCE_OR_AUTHORITY")
