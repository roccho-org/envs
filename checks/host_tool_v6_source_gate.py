#!/usr/bin/env python3
"""Verify the frozen F1/F2/relation SOURCE trio from public GitHub, not Target.

Read-only public REST GET, no token or runtime permissions. The exact candidate
was independently reviewed before this new checker was created, preventing a
CI job from using its own unfinished run as proof of success.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

from host_tool_source_provenance import (
    API, ProvenanceError, decode_source, fields, public_get, require, sha,
)

KIND = "envs.hostCommonV6FrozenSourceCandidate.v0"
STEPS = {
    "roccho-dev/windows": {
        "rent / build-test-publish": {
            "Parse native rent SOURCE fixture (no Host or Docker)",
            "Build from locked Nix inputs",
            "Prove new Base-only OCI starts, retains Tool generations and refuses foreign state",
            "Prove bound PROPOSED q/Host and actual native rent Tool/readonly O",
            "Load and test tools, mounts, state, restart, and recreate",
            "Prove rent development continues across seed, upgrade, replacement, GC and rollback",
        },
        "dev / fresh-develop-replace-continue": {
            "Build the locked dev image",
            "Prove actual development continues after replacement",
        },
    },
    "roccho-org/envs": {
        "repository": {
            "Prove real resources Relation and envs Tool q bind same CI Host",
            "Test temporary native Tool generation and UNKNOWN/recovery SUT",
            "Prove ordinary accepted projection rejects Host Tool proposal/admission",
        },
        "toolchain": {
            "Built source is the named commit",
            "Prove current Host Relation / D-q integration on exact SOURCE head",
            "Test disposable native generation SUT at exact head",
        },
    },
    "roccho-dev/resources": {
        "source-vm": {
            "Test synthetic Host contains/manages/optional wrap (NOT_ADMITTED)",
            "Verify fixed inputs",
            "Build host, production images, and standard VM proof",
        },
    },
}
JOBS = {
    "roccho-dev/windows": {
        "success": {"scope", "build", "rent / build-test-publish", "own / build-test",
                    "dev / fresh-develop-replace-continue", "windows"},
        "skipped": {"publish", "own / publish"},
        "pr": 93, "attempt": 2,
    },
    "roccho-org/envs": {
        "success": {"repository", "toolchain", "placement-artifact", "placement-author",
                    "placement-windows", "placement-rent", "effect-shape", "clean-start"},
        "skipped": {"placement-publish"},
        "pr": 90, "attempt": 1,
    },
    "roccho-dev/resources": {
        "success": {"source-vm"}, "skipped": set(), "pr": 19, "attempt": 1,
    },
}
FLAKE_PIN = re.compile(
    r'(?m)^[ \t]*inputs\.windows\.url = "github:roccho-dev/windows/([0-9a-f]{40})";[ \t]*$'
)
BINDING_OLD_REF = "a4e0b9499e02fc0c5cfaafddc0f99a65dfedea44"
BINDING_URL = ("https://raw.githubusercontent.com/roccho-org/envs/" + BINDING_OLD_REF
               + "/checks/fixtures/host-tool-functional-binding.json")
RELATION_TEST = "test_containment_cycles_self_and_multi_parent_refused_same_scope"


def git_blob(content: str) -> str:
    raw = content.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def real_file(repo: str, head: str, path: str,
              get: Callable[[str], dict[str, Any]],
              blob: str | None = None) -> str:
    require(sha(head) and bool(re.fullmatch(r"[A-Za-z0-9_./-]+", path))
            and ".." not in path.split("/"), "unsafe immutable SOURCE path")
    data = get(f"{API}/repos/{repo}/contents/{path}?ref={head}")
    content = decode_source(data, f"{repo}/{path}")
    require(data.get("sha") == git_blob(content), "public content is not its Git blob")
    if blob is not None:
        require(data["sha"] == blob, "unexpected immutable public SOURCE blob")
    return content


def verify(snapshot: dict[str, Any],
           get: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    fields(snapshot, {"kind", "admission", "producer", "binding", "relation",
                      "entries"}, "v6 frozen SOURCE set")
    require(snapshot["kind"] == KIND and snapshot["admission"] == "NOT_ADMITTED",
            "v6 SOURCE set attempts admission")
    producer = fields(snapshot["producer"], {"repository", "head"}, "producer")
    binding = fields(snapshot["binding"], {"repository", "path", "blob"}, "binding")
    relation = fields(snapshot["relation"], {"repository", "path", "blob"}, "relation")
    require(producer["repository"] == "roccho-dev/windows" and sha(producer["head"])
            and binding["repository"] == "roccho-org/envs"
            and binding["path"] == "checks/fixtures/host-tool-functional-binding.json"
            and sha(binding["blob"])
            and relation["repository"] == "roccho-dev/resources"
            and relation["path"] == "nixos/tests/host_relation_source.py"
            and sha(relation["blob"]), "foreign SOURCE material or binding")
    entries = snapshot["entries"]
    require(type(entries) is list and len(entries) == 3, "v6 must bind exactly three owners")
    by_repo = {}
    for item in entries:
        row = fields(item, {"repository", "pr", "head", "tree", "base",
                            "run_id", "run_attempt"}, "SOURCE owner")
        name = row["repository"]
        require(type(name) is str and name in JOBS and name not in by_repo,
                "missing/duplicate/foreign SOURCE owner")
        require(type(row["pr"]) is int and row["pr"] == JOBS[name]["pr"]
                and type(row["run_attempt"]) is int
                and row["run_attempt"] == JOBS[name]["attempt"]
                and type(row["run_id"]) is int and row["run_id"] > 0
                and all(sha(row[field]) for field in ("head", "tree", "base")),
                "SOURCE owner identity or CI attempt is not exact")
        by_repo[name] = row
    require(set(by_repo) == set(JOBS), "v6 owner set incomplete")
    require(by_repo["roccho-dev/windows"]["base"] == producer["head"],
            "F2 must be stacked on the immutable Windows Producer")
    require(by_repo["roccho-org/envs"]["head"] != by_repo["roccho-org/envs"]["base"],
            "F1 cannot be an unevaluated base")

    for name, row in by_repo.items():
        root = f"{API}/repos/{name}"
        pr = get(f"{root}/pulls/{row['pr']}")
        require(pr.get("number") == row["pr"] and pr.get("state") == "open"
                and pr.get("draft") is True and pr.get("merged") is False
                and pr.get("head", {}).get("sha") == row["head"]
                and pr.get("head", {}).get("repo", {}).get("full_name") == name
                and pr.get("base", {}).get("sha") == row["base"],
                f"{name}: reviewed PR head/base/Draft drift")
        commit = get(f"{root}/commits/{row['head']}")
        require(commit.get("sha") == row["head"]
                and commit.get("commit", {}).get("tree", {}).get("sha") == row["tree"],
                f"{name}: real Git commit/tree drift")
        run = get(f"{root}/actions/runs/{row['run_id']}")
        require(run.get("id") == row["run_id"] and run.get("head_sha") == row["head"]
                and run.get("run_attempt") == row["run_attempt"]
                and run.get("event") == "pull_request"
                and run.get("status") == "completed" and run.get("conclusion") == "success",
                f"{name}: wrong CI head/attempt/event/status")
        jobs = get(f"{root}/actions/runs/{row['run_id']}/"
                   f"attempts/{row['run_attempt']}/jobs?per_page=100")
        listed = jobs.get("jobs")
        require(type(listed) is list and type(jobs.get("total_count")) is int
                and jobs["total_count"] == len(listed)
                and len(listed) == len(JOBS[name]["success"] | JOBS[name]["skipped"]),
                f"{name}: truncated or missing attempt-scoped CI jobs")
        indexed = {}
        for job in listed:
            title = job.get("name")
            require(type(title) is str and title not in indexed
                    and job.get("run_id") == row["run_id"]
                    and job.get("run_attempt") == row["run_attempt"]
                    and job.get("status") == "completed",
                    f"{name}: duplicate/foreign/unfinished attempt job")
            indexed[title] = job
        contract = JOBS[name]
        require(set(indexed) == contract["success"] | contract["skipped"]
                and all(indexed[k].get("conclusion") == "success" for k in contract["success"])
                and all(indexed[k].get("conclusion") == "skipped" for k in contract["skipped"]),
                f"{name}: required job failed or publish was not skipped")
        for job_name, expected_steps in STEPS[name].items():
            steps = indexed[job_name].get("steps")
            require(type(steps) is list, f"{name}: missing proof step list")
            actual = {step.get("name"): step.get("conclusion") for step in steps}
            require(all(actual.get(step) == "success" for step in expected_steps),
                    f"{name}: F1/F2/relation proof step missing or not SUCCESS")

    # Attempt 1's unrelated rate-limit failure is historical evidence,
    # never overwritten by the successful retry at the same immutable F2 head.
    w = by_repo["roccho-dev/windows"]
    root = API + "/repos/roccho-dev/windows/actions/runs/"
    old = get(f"{root}{w['run_id']}/attempts/1/jobs?per_page=100")
    prev = {j.get("name"): j for j in old.get("jobs", [])}
    current = get(f"{root}{w['run_id']}/attempts/2/jobs?per_page=100")
    now = {j.get("name"): j for j in current.get("jobs", [])}
    dev = "dev / fresh-develop-replace-continue"
    require(type(old.get("jobs")) is list and type(old.get("total_count")) is int
            and old["total_count"] == len(old["jobs"])
            and type(current.get("jobs")) is list
            and prev.get(dev, {}).get("conclusion") == "failure"
            and prev[dev].get("run_attempt") == 1
            and now.get(dev, {}).get("conclusion") == "success"
            and now[dev].get("run_attempt") == 2
            and type(prev[dev].get("id")) is int
            and type(now[dev].get("id")) is int
            and prev[dev]["id"] != now[dev]["id"],
            "historical failed attempt or actual new dev retry not proven")

    # Same immutable unadmitted F1 binding bytes must feed both the F1 SOURCE
    # test and the F2 disposable real-Nix proof; q is re-derived, not trusted.
    e = by_repo["roccho-org/envs"]["head"]
    f1 = real_file("roccho-org/envs", e, binding["path"], get, binding["blob"])
    try:
        proposal = json.loads(f1)
    except ValueError as ex:
        raise ProvenanceError("F1 functional binding not JSON") from ex
    require(type(proposal) is dict and proposal.get("kind")
            == "envs.hostToolFunctionalBindingProposal.v0"
            and proposal.get("admission") == "NOT_ADMITTED"
            and proposal.get("target_ref") == "pc7337-rent"
            and proposal.get("host_ref") == "ci-host-rent-1"
            and proposal.get("parent_ref") == "ci-host-parent-1"
            and proposal.get("unit_ref") == "ci-rent-oci-unit-1"
            and proposal.get("scope") == "ci-session-1"
            and proposal.get("selector") == "/nix/var/nix/profiles/rent-dev"
            and proposal.get("desired_output") == "rent-tool-profile"
            and proposal.get("material") == {
                "repository": "roccho-dev/windows", "source_commit": producer["head"],
                "flake_output": "packages.x86_64-linux.rent-tool-profile",
            } and isinstance(proposal.get("identity"), dict)
            and set(proposal["identity"]) == {
                "base", "tool", "launch", "config_binding", "state_contract"}
            and all(type(v) is str and v.startswith("ci:")
                    for v in proposal["identity"].values()),
            "F1 binding is foreign/admitted or mismatches immutable Producer")
    canon = json.dumps({"target_ref": proposal["target_ref"],
                        "material": proposal["material"]},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    q = "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
    require(proposal.get("proposed_q") == q,
            "F1 q not derived from immutable target/material")

    # F2's SOURCE workflow must fetch/verify that *same Git blob* and actually
    # pass it to the disposable native proof. It is not a real Target D.
    w_head = w["head"]
    workflow = real_file("roccho-dev/windows", w_head,
                         ".github/workflows/rent-image.yml", get)
    require(BINDING_URL in workflow
            and f'test "$(git hash-object "$fixture")" = {binding["blob"]}' in workflow
            and 'bash hosts/rent/native-proof.sh result-4 "$t0" "$t1" "$fixture"' in workflow,
            "F2 SOURCE does not consume the exact F1 reviewed proposed Git blob")

    # Resources' current fixture relation blob and Nix Producer pin were
    # independently used by F1 SOURCE tests (job proof checked above).
    resource = by_repo["roccho-dev/resources"]["head"]
    relation_src = real_file("roccho-dev/resources", resource,
                             relation["path"], get, relation["blob"])
    require("def test_containment_cycles_self_and_multi_parent_refused_same_scope" in relation_src
            and '"admission": "NOT_ADMITTED"' in relation_src
            and '"effect": "FORBIDDEN"' in relation_src,
            "resources relation is not the unadmitted reviewed SOURCE fixture")
    flake = real_file("roccho-dev/resources", resource, "nixos/flake.nix", get)
    require(FLAKE_PIN.findall(flake) == [producer["head"]],
            "resources Native/OCI Producer does not match F1/F2 material")
    try:
        lock = json.loads(real_file(
            "roccho-dev/resources", resource, "nixos/flake.lock", get))
        pinned = lock["nodes"]["windows"]
    except (KeyError, TypeError, ValueError) as ex:
        raise ProvenanceError("resources source lock malformed") from ex
    require(pinned.get("original", {}).get("rev") == producer["head"]
            and pinned.get("locked", {}).get("rev") == producer["head"]
            and re.fullmatch(r"sha256-[A-Za-z0-9+/]+={0,2}",
                             pinned.get("locked", {}).get("narHash", "")) is not None,
            "resources immutable Producer lock mismatch")

    return {
        "kind": "envs.hostCommonV6FrozenSourceReadback.v0",
        "stage": "V6_F1_F2_DISPOSABLE_SOURCE_EVIDENCE_VERIFIED",
        "entries": [{"repository": name, "pr": v["pr"], "head": v["head"],
                     "tree": v["tree"], "run_id": v["run_id"],
                     "run_attempt": v["run_attempt"]}
                    for name, v in sorted(by_repo.items())],
        "reviewed_binding_blob": binding["blob"],
        "proposed_q": q,
        "producer_pin_match": True,
        "previous_failed_dev_attempt_preserved": True,
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
        "checks/fixtures/host-tool-v6-source-set.json"))
    args = parser.parse_args()
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        output = verify(data, public_get)
    except (ValueError, OSError) as err:
        print(f"V6_SOURCE_PROOF_REFUSED: {err}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
