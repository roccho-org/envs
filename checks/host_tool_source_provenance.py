#!/usr/bin/env python3
"""Read-only public GitHub provenance for ONE unadmitted SOURCE candidate set.

Not a deployment gate, accepted D/q, Target observer, or effect executor.
No token, credentials, provider integration, mutations, or GitHub write calls.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

API = "https://api.github.com"
SHA = re.compile(r"[0-9a-f]{40}\Z")
NAR = re.compile(r"sha256-[A-Za-z0-9+/]+={0,2}\Z")
FLAKE_PIN = re.compile(r'(?m)^[ \t]*inputs\.windows\.url = "github:roccho-dev/windows/([0-9a-f]{40})";[ \t]*$')
KIND = "envs.hostToolSourceProvenanceCandidate.v0"
REQUIRED = {
    "roccho-dev/windows": {
        "pr": 91,
        "jobs": {"scope", "build", "rent / build-test-publish", "own / build-test",
                 "dev / fresh-develop-replace-continue", "windows"},
        "skipped": {"publish", "own / publish"},
        "steps": {"rent / build-test-publish": {
            "Prove new Base-only OCI starts, retains Tool generations and refuses foreign state",
            "Prove native rent Tool selection, quiet refusal, rollback and retained state"}},
    },
    "roccho-org/envs": {
        "pr": 86,
        "jobs": {"repository", "toolchain", "placement-artifact", "placement-author",
                 "placement-windows", "placement-rent", "effect-shape", "clean-start"},
        "skipped": {"placement-publish"},
        "steps": {
            "repository": {"Test synthetic D/O/authority guard (always effect forbidden)"},
            "toolchain": {"Built source is the named commit",
                          "Test Host Tool proposal at exact source head",
                          "Test synthetic Host Tool guard at exact source head"}},
    },
    "roccho-dev/resources": {
        "pr": 17,
        "jobs": {"source-vm"},
        "skipped": set(),
        "steps": {"source-vm": {"Verify fixed inputs",
                              "Build host, production images, and standard VM proof"}},
    },
}


class ProvenanceError(ValueError):
    """A required evidence field or trusted public read failed, without a credential."""


def require(test: bool, reason: str) -> None:
    if not test:
        raise ProvenanceError(reason)


def sha(value: Any) -> bool:
    return type(value) is str and SHA.fullmatch(value) is not None


def fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == expected, f"{label}: unsupported fields")
    return value


def public_get(url: str) -> dict[str, Any]:
    """Public REST GET only, no GITHUB_TOKEN or Authorization header."""
    require(url.startswith(API + "/repos/"), "foreign API URL")
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "host-tool-source-provenance-ci",
    }, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status == 200, "GitHub GET was not successful")
            payload = response.read(1_000_001)
            require(len(payload) <= 1_000_000, "GitHub response too large")
            value = json.loads(payload)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ProvenanceError(f"public GitHub evidence unavailable: {url}") from exc
    require(type(value) is dict, "GitHub response was not a JSON object")
    return value


def decode_source(payload: dict[str, Any], label: str) -> str:
    require(payload.get("type") == "file" and payload.get("encoding") == "base64",
            f"{label}: not an immutable public file")
    raw = payload.get("content")
    require(type(raw) is str and len(raw) <= 200_000, f"{label}: invalid file size")
    try:
        return base64.b64decode(raw.replace("\n", ""), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ProvenanceError(f"{label}: malformed public file") from exc


def verify_candidate(snapshot: dict[str, Any],
                     get: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    fields(snapshot, {"kind", "admission", "entries"}, "candidate set")
    require(snapshot["kind"] == KIND and snapshot["admission"] == "NOT_ADMITTED",
            "candidate tried to admit SOURCE")
    entries = snapshot["entries"]
    require(type(entries) is list and len(entries) == len(REQUIRED),
            "SOURCE candidate must contain exactly three owner rows")
    by_repo = {}
    for value in entries:
        e = fields(value, {"repository", "pr", "head", "tree", "base", "run_id"}, "source row")
        name = e["repository"]
        require(type(name) is str and name in REQUIRED and name not in by_repo,
                "duplicate or foreign repository")
        require(type(e["pr"]) is int and e["pr"] == REQUIRED[name]["pr"]
                and type(e["run_id"]) is int and e["run_id"] > 0
                and all(sha(e[k]) for k in ("head", "tree", "base")),
                "non-exact PR/source identity")
        by_repo[name] = e
    require(set(by_repo) == set(REQUIRED), "missing SOURCE owner")

    # Each observed object is resolved from public GitHub, never a caller-supplied
    # assertion of completed runs or a synthetic D/O/admission.
    for name, e in by_repo.items():
        root = f"{API}/repos/{name}"
        pr = get(f"{root}/pulls/{e['pr']}")
        require(pr.get("number") == e["pr"] and pr.get("state") == "open"
                and pr.get("draft") is True and pr.get("merged") is False
                and pr.get("head", {}).get("sha") == e["head"]
                and pr.get("head", {}).get("repo", {}).get("full_name") == name
                and pr.get("base", {}).get("sha") == e["base"],
                f"{name}: PR identity or Draft state changed")
        commit = get(f"{root}/commits/{e['head']}")
        require(commit.get("sha") == e["head"]
                and commit.get("commit", {}).get("tree", {}).get("sha") == e["tree"],
                f"{name}: real Git commit tree mismatches candidate")
        run = get(f"{root}/actions/runs/{e['run_id']}")
        require(run.get("id") == e["run_id"] and run.get("head_sha") == e["head"]
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                and run.get("event") == "pull_request",
                f"{name}: CI run is not exact completed PR SUCCESS")
        record = get(f"{root}/actions/runs/{e['run_id']}/jobs?per_page=100")
        jobs = record.get("jobs")
        require(type(jobs) is list and type(record.get("total_count")) is int
                and record["total_count"] == len(jobs) and len(jobs) <= 100,
                f"{name}: CI jobs incomplete/truncated")
        indexed = {}
        for job in jobs:
            key = job.get("name")
            require(type(key) is str and key not in indexed
                    and job.get("run_id") == e["run_id"]
                    and job.get("status") == "completed",
                    f"{name}: duplicate or unfinished CI job")
            indexed[key] = job
        required = REQUIRED[name]["jobs"]
        skipped = REQUIRED[name]["skipped"]
        require(set(indexed) == required | skipped, f"{name}: CI job coverage changed")
        require(all(indexed[key].get("conclusion") == "success" for key in required)
                and all(indexed[key].get("conclusion") == "skipped" for key in skipped),
                f"{name}: required CI failed, skipped or unexpected publication")
        for job_name, expected in REQUIRED[name]["steps"].items():
            steps = indexed[job_name].get("steps")
            require(type(steps) is list, f"{name}: CI step evidence missing")
            actual = {s.get("name"): s.get("conclusion") for s in steps}
            require(all(actual.get(k) == "success" for k in expected),
                    f"{name}: required CI proof step missing or unsuccessful")

    # Verify the actual public immutable consumer pin and envs NOT_ADMITTED
    # material against the SAME exact windows source commit in this snapshot.
    target = by_repo["roccho-dev/windows"]["head"]
    resources = by_repo["roccho-dev/resources"]["head"]
    envs = by_repo["roccho-org/envs"]["head"]
    source_root = API + "/repos/roccho-dev/resources/contents/nixos"
    flake = decode_source(get(f"{source_root}/flake.nix?ref={resources}"), "Nix source")
    matches = FLAKE_PIN.findall(flake)
    require(matches == [target], "resources Nix source Producer pin mismatch")
    locked_text = decode_source(get(f"{source_root}/flake.lock?ref={resources}"), "Nix lock")
    try:
        locked = json.loads(locked_text)["nodes"]["windows"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ProvenanceError("invalid real Nix lock input") from exc
    require(locked.get("original", {}).get("rev") == target
            and locked.get("locked", {}).get("rev") == target
            and type(locked.get("locked", {}).get("narHash")) is str
            and NAR.fullmatch(locked["locked"]["narHash"]) is not None,
            "resources source lock is not pinned to same Producer")
    proposal_text = decode_source(get(
        f"{API}/repos/roccho-org/envs/contents/"
        f"contracts/proposals/host-tool-selection.jsonl?ref={envs}"), "envs proposal")
    try:
        proposals = [json.loads(line) for line in proposal_text.splitlines()]
    except ValueError as exc:
        raise ProvenanceError("envs public proposal is not JSONL") from exc
    require(len(proposals) == 1
            and proposals[0].get("admission") == "NOT_ADMITTED"
            and proposals[0].get("target_ref") == "pc7337-rent"
            and proposals[0].get("material", {}).get("repository") == "roccho-dev/windows"
            and proposals[0].get("material", {}).get("source_commit") == target
            and proposals[0].get("material", {}).get("flake_output")
            == "packages.x86_64-linux.rent-tool-profile",
            "public unadmitted envs candidate differs from pinned Producer")

    return {
        "kind": "envs.hostToolSourceProvenanceReadback.v0",
        "stage": "PUBLIC_SOURCE_CANDIDATE_VERIFIED",
        "sources": [{"repository": name, "pr": e["pr"], "head": e["head"],
                     "tree": e["tree"], "run_id": e["run_id"]}
                    for name, e in sorted(by_repo.items())],
        "producer_pin_match": True,
        "admission": "NOT_ADMITTED",
        "accepted_q": None,
        "target_observation": "NOT_READ",
        "target_noop": "UNPROVEN",
        "effect": "FORBIDDEN",
        "target_ready": False,
        "real_composite_green": False,
        "merge_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=Path(
        "checks/fixtures/host-tool-source-set.json"))
    args = parser.parse_args()
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        result = verify_candidate(snapshot, public_get)
    except (OSError, ValueError) as exc:
        print(f"SOURCE_PROVENANCE_REFUSED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
