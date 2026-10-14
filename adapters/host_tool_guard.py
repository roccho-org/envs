"""Isolated, synthetic Host Tool decision guard. NEVER a production effect entry.

No IO, provider, target access, credential, accepted-contract import, or mutation.
Even with a synthetic admitted D and complete synthetic authority, outputs never
authorize execution: they are finite candidate classifications for CI/R review.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from host_tool_selection import (FIXTURE_KIND, WINDOWS_PRODUCER, RENT_OUTPUT, PIN,
                                 ProposalError, exact_object, require)

STORE = re.compile(r"/nix/store/[0-9a-z]{32}-[^/\s]+\Z")
FIXTURE = "envs.hostToolGuardFixture.v0"


def _bool(value: Any) -> bool:
    return type(value) is bool


def judge(proposal: dict[str, Any], *, desired: dict[str, Any] | None = None,
          observed: dict[str, Any] | None = None,
          authority: dict[str, Any] | None = None,
          previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute a non-executable CI verdict; caller inputs are NOT actual authority."""
    p = exact_object(proposal, {"kind", "target_ref", "proposed_q", "material", "admission",
                                "accepted_q", "observation", "target_noop", "effect"}, "proposal")
    require(p["kind"] == FIXTURE_KIND and p["admission"] == "NOT_ADMITTED"
            and p["accepted_q"] is None and p["observation"] == "NOT_READ"
            and p["target_noop"] == "UNPROVEN" and p["effect"] == "FORBIDDEN"
            and type(p["target_ref"]) is str and bool(p["target_ref"])
            and type(p["proposed_q"]) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", p["proposed_q"]) is not None,
            "fixture proposal is not strictly unadmitted")
    material = exact_object(p["material"], {"repository", "source_commit", "flake_output"}, "material")
    require(material["repository"] == WINDOWS_PRODUCER and material["flake_output"] == RENT_OUTPUT
            and type(material["source_commit"]) is str
            and PIN.fullmatch(material["source_commit"]) is not None,
            "proposal material is not exact pinned producer output")
    canonical = json.dumps({"target_ref": p["target_ref"], "material": material},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected_q = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    require(p["proposed_q"] == expected_q, "proposal candidate digest differs")
    target = p["target_ref"]

    def verdict(reason: str, *, read=False) -> dict[str, Any]:
        return {
            "kind": FIXTURE, "target_ref": target, "stage": reason,
            "synthetic_read_preconditions": read,
            "synthetic_change_preconditions": False,
            "admission": "NOT_ADMITTED",
            "accepted_q": None,
            "target_noop": "UNPROVEN",
            "effect": "FORBIDDEN",
        }

    # Read capability is independent of whether D exists or a previous effect is UNKNOWN.
    if authority is None:
        return verdict("READ_AUTH_REQUIRED")
    a = exact_object(authority, {"kind", "target_ref", "read", "change", "quiet",
                                 "single_writer", "recovery"}, "authority")
    require(a["kind"] == "envs.syntheticAuthority.v0" and a["target_ref"] == target
            and all(_bool(a[name]) for name in ("read", "change", "quiet",
                                               "single_writer", "recovery")),
            "authority fixture invalid or cross-target")
    if not a["read"]:
        return verdict("READ_AUTH_REQUIRED")
    if desired is None:
        return verdict("D_NOT_ADMITTED", read=True)
    d = exact_object(desired, {"kind", "target_ref", "admission", "revision",
                               "proposed_q", "material", "store_path"}, "desired")
    require(d["kind"] == "envs.syntheticDesired.v0"
            and d["admission"] == "SYNTHETIC_ADMITTED"
            and d["target_ref"] == target and d["proposed_q"] == p["proposed_q"]
            and d["material"] == p["material"]
            and type(d["revision"]) is str and re.fullmatch(r"ci-[0-9a-z-]+", d["revision"])
            and type(d["store_path"]) is str and STORE.fullmatch(d["store_path"]),
            "desired fixture does not match candidate/target")
    if observed is None:
        return verdict("O_NOT_READ", read=True)
    o = exact_object(observed, {"kind", "target_ref", "state", "store_path",
                                "fresh", "closure_valid"}, "observed")
    require(o["kind"] == "envs.syntheticObservation.v0" and o["target_ref"] == target
            and o["state"] in ("ABSENT", "SELECTED", "UNKNOWN")
            and _bool(o["fresh"]) and _bool(o["closure_valid"])
            and (o["store_path"] is None if o["state"] != "SELECTED"
                 else type(o["store_path"]) is str and STORE.fullmatch(o["store_path"]) is not None),
            "observation fixture invalid or cross-target")
    if o["state"] == "UNKNOWN" or not o["fresh"]:
        return verdict("O_UNKNOWN_OR_STALE", read=True)
    if previous is None:
        return verdict("E_NOT_RECONCILED", read=True)
    e = exact_object(previous, {"kind", "target_ref", "state", "revision", "store_path"}, "previous")
    require(e["kind"] == "envs.syntheticEffect.v0" and e["target_ref"] == target
            and e["state"] in ("NONE", "UNKNOWN", "CONFIRMED"),
            "effect fixture invalid or cross-target")
    if e["state"] != "CONFIRMED":
        require(e["revision"] is None and e["store_path"] is None,
                "unresolved effect must not assert receipt data")
    else:
        require(type(e["revision"]) is str and type(e["store_path"]) is str
                and STORE.fullmatch(e["store_path"]) is not None,
                "effect receipt fixture malformed")
    if e["state"] == "UNKNOWN":
        return verdict("E_UNKNOWN", read=True)
    if not o["closure_valid"]:
        return verdict("TOOL_NOT_PROVEN", read=True)
    # A submitted effect is not success: only matching *synthetic* readback and receipt
    # can classify a readback candidate, and even that NEVER returns accepted/noop/effect.
    if e["state"] == "CONFIRMED":
        if (e["revision"] == d["revision"] and e["store_path"] == d["store_path"]
                and o["state"] == "SELECTED" and o["store_path"] == d["store_path"]):
            result = verdict("SYNTHETIC_READBACK_CANDIDATE", read=True)
            return result
        return verdict("E_CONFLICT", read=True)
    if not a["change"]:
        return verdict("CHANGE_AUTH_REQUIRED", read=True)
    if not a["quiet"]:
        return verdict("QUIET_UNPROVEN", read=True)
    if not a["single_writer"]:
        return verdict("WRITER_UNPROVEN", read=True)
    if not a["recovery"]:
        return verdict("RECOVERY_UNPROVEN", read=True)
    if o["state"] == "SELECTED" and o["store_path"] == d["store_path"]:
        return verdict("MATCH_WITHOUT_RECEIPT", read=True)
    # This remains data for independent R: it grants no callable update capability.
    result = verdict("SYNTHETIC_CHANGE_CANDIDATE", read=True)
    result["synthetic_change_preconditions"] = True
    return result
