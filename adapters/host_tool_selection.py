#!/usr/bin/env python3
"""Unadmitted Host Tool D/q candidate projection. Pure SOURCE/fixture only.

This module is intentionally not imported by envs-effect, a provider, a target
controller or the accepted contract projection. It has no IO except two public
SOURCE JSONL files when project_root() is called explicitly.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROPOSALS = Path("contracts/proposals/host-tool-selection.jsonl")
TARGETS = Path("contracts/targets.jsonl")
PROPOSAL_KIND = "envs.hostToolSelectionProposal.v0"
FIXTURE_KIND = "envs.hostToolSelectionFixture.v0"
WINDOWS_PRODUCER = "roccho-dev/windows"
RENT_OUTPUT = "packages.x86_64-linux.rent-tool-profile"
PIN = re.compile(r"[0-9a-f]{40}\Z")


class ProposalError(ValueError):
    """Fixed, non-secret refusal; no source data echoed."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ProposalError(reason)


def exact_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{name}: unsupported fields")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    # This read is of a caller-provided SOURCE checkout, never a Target or connected app.
    content = path.read_text(encoding="utf-8")
    require(bool(content) and content.endswith("\n"), "proposal input is not newline-terminated")
    lines = content.splitlines()
    require(bool(lines) and all(line.strip() for line in lines), "proposal input has a blank row")
    try:
        return [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        raise ProposalError("proposal input is not JSONL") from exc


def project(proposals: list[dict[str, Any]], targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project bounded candidate facts. Never derive accepted D, Target O, or permission."""
    require(type(proposals) is list and bool(proposals), "no proposal rows")
    require(type(targets) is list and bool(targets), "no target catalog")
    catalog = {}
    for row in targets:
        require(type(row) is dict and row.get("kind") == "envs.target.v1", "unknown target kind")
        target_id = row.get("id")
        require(type(target_id) is str and bool(target_id) and target_id not in catalog,
                "duplicate or invalid target identity")
        catalog[target_id] = row

    result = []
    seen_ids: set[str] = set()
    seen_targets: set[str] = set()
    for value in proposals:
        row = exact_object(value, {"id", "kind", "admission", "target_ref", "material"}, "proposal")
        target_id = row["target_ref"]
        require(type(target_id) is str and target_id in catalog, "unknown target reference")
        require(row["id"] == f"{target_id}.host-tool-selection"
                and row["id"] not in seen_ids and target_id not in seen_targets,
                "ambiguous or duplicate proposal identity")
        seen_ids.add(row["id"])
        seen_targets.add(target_id)
        require(row["kind"] == PROPOSAL_KIND and row["admission"] == "NOT_ADMITTED",
                "proposal attempted admission")
        target = catalog[target_id]
        # Match the actual execution OS/architecture in the accepted public target catalog to
        # the fixed x86_64-linux material BEFORE proposing q. Target ID/owner alone is not ABI proof.
        require(target.get("platform") == "linux"
                and target.get("architecture") == "amd64",
                "target OS/architecture is incompatible with rent Tool material")
        # Only the existing Windows rent consumer shape is proposed here.
        require(target.get("runtime") == "wslc_one_shot"
                and target.get("slot_owner") == WINDOWS_PRODUCER
                and target.get("observation_owner") == WINDOWS_PRODUCER,
                "target is not the rent Tool consumer")
        material = exact_object(row["material"],
                                {"repository", "source_commit", "flake_output"}, "material")
        require(material["repository"] == WINDOWS_PRODUCER
                and material["flake_output"] == RENT_OUTPUT
                and type(material["source_commit"]) is str
                and PIN.fullmatch(material["source_commit"]) is not None,
                "material is not the exact pinned rent Tool output")

        # A proposed q is content-bound and target-specific, never an accepted revision.
        desired = {"target_ref": target_id, "material": material}
        canonical = json.dumps(desired, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        proposed_q = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        result.append({
            "kind": FIXTURE_KIND,
            "target_ref": target_id,
            "proposed_q": proposed_q,
            "material": dict(material),
            "admission": "NOT_ADMITTED",
            "accepted_q": None,
            "observation": "NOT_READ",
            "target_noop": "UNPROVEN",
            "effect": "FORBIDDEN",
        })
    return sorted(result, key=lambda item: item["target_ref"])


def project_root(root: Path) -> list[dict[str, Any]]:
    return project(read_jsonl(root / PROPOSALS), read_jsonl(root / TARGETS))
