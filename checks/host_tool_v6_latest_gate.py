#!/usr/bin/env python3
"""P4: noncircular public SOURCE proof for reviewed v6 P1/P2/P3 plus frozen F1/F2.

This explicitly consumes OLD completed PR run/review evidence; it cannot inspect
the yet-unfinished CI run for its own new SOURCE commit. Read-only, no token,
no Target/actor rights, real D admission, product effect, merge or deployment.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable

from host_tool_source_provenance import (API, ProvenanceError, fields, public_get,
                                         require, sha)
from host_tool_v6_source_gate import real_file, verify as verify_frozen

KIND = "envs.hostCommonV6LatestSRC4Candidate.v0"
REQUIRED = {
    "windows": {"scope", "build", "rent / build-test-publish", "own / build-test",
                "dev / fresh-develop-replace-continue", "windows"},
    "envs": {"repository", "toolchain", "placement-artifact", "placement-author",
             "placement-windows", "placement-rent", "effect-shape", "clean-start"},
    "resources": {"source-vm"},
}
SKIPPED = {
    "windows": {"publish", "own / publish"},
    "envs": {"placement-publish"},
    "resources": set(),
}
REVIEW = {
    "F1": (90, 5524498474, "host-common-update-v6-r-envs90-f1-clearance-dda516"),
    "F2": (93, 5525335505, "host-common-update-v6-r-windows93-attempt2-all-ci-green-r2"),
    "RELATION": (19, 5521439539, "host-common-update-v5-r-resources19-r1"),
    "X": (92, 5526358929, "host-common-update-v6-r-envs92-four-col-markdown-r3-9caeed"),
    "BOUND": (94, 5527051531, "host-common-update-v6-r-envs94-r2-pre-read-clearance-r3"),
    "SRC3": (102, 5545987340, "host-common-v6-r-envs102-src3-record-once-clearance-r4"),
    "P1": (103, 5547041299, "host-common-v6-r-envs103-p1-stage-grants-source-r1-20261016"),
    "P2": (97, 5547985960, "host-common-v6-r-windows97-p2-terminal-ci-r4-20261016"),
    "P3": (98, 5548673957, "host-common-v6-r-windows98-p3-full-terminal-r4-fa39"),
}
OWNER = {
    "F1": "roccho-org/envs", "F2": "roccho-dev/windows",
    "RELATION": "roccho-dev/resources", "X": "roccho-org/envs",
    "BOUND": "roccho-org/envs", "SRC3": "roccho-org/envs",
    "P1": "roccho-org/envs", "P2": "roccho-dev/windows",
    "P3": "roccho-dev/windows",
}
STEPS = {
    "X": {"toolchain": {"Test v6 F1/F2 CI-attempt and binding negative cases at exact head"}},
    "BOUND": {"toolchain": {"Exercise F1 to disposable Target lifecycle on exact SOURCE head"}},
    "SRC3": {"toolchain": {"Test inactive SOURCE-entry read/change/receipt at exact head"}},
    "P1": {
        "repository": {"Test inactive SOURCE entry with explicit scoped authority and disposable Target"},
        "toolchain": {"Test inactive SOURCE-entry read/change/receipt at exact head"},
    },
    "P2": {"rent / build-test-publish": {
        "Prove bound PROPOSED q/Host and actual native rent Tool/readonly O",
        "Prove rent development continues across seed, upgrade, replacement, GC and rollback"}},
    "P3": {"rent / build-test-publish": {
        "Prove bound PROPOSED q/Host and actual native rent Tool/readonly O",
        "Prove rent development continues across seed, upgrade, replacement, GC and rollback"}},
}
FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
V6_CASE = re.compile(r"^\| (V\d{2}|[SBGHA]\d|L\d{2}) \|", re.MULTILINE)
P1_SOURCE_BLOB = "758a0b8954719994f03c01c459f68e0ea9bf59e3"
P2_RECEIVER_BLOB = "b60326684befd94bbc91bdc34d5ebaf7988d7fce"
P3_CALLER_BLOB = "46b9487ccb80a5f5c08af22ddc7b29e96e3eb873"
P3_NATIVE_BLOB = "714ee2b54fe43c542ea9213b050656cd18fc99ed"


def verify_latest(snapshot: dict[str, Any], frozen: dict[str, Any],
                  coverage: str, get: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    fields(snapshot, {"kind", "admission", "frozen", "entries"}, "latest SRC4 snapshot")
    require(snapshot["kind"] == KIND and snapshot["admission"] == "NOT_ADMITTED"
            and snapshot["frozen"] == "checks/fixtures/host-tool-v6-source-set.json",
            "P4 candidate is not exact unadmitted frozen SOURCE")
    entries = snapshot["entries"]
    require(type(entries) is list and len(entries) == len(REVIEW),
            "P4 requires all nine immutable SOURCE roles")
    roles = {}
    for row in entries:
        fields(row, {"role", "repository", "pr", "head", "tree", "base",
                     "run_id", "run_attempt", "review_id"}, "P4 role")
        role = row["role"]
        require(type(role) is str and role in REVIEW and role not in roles
                and row["repository"] == OWNER[role]
                and type(row["pr"]) is int and row["pr"] == REVIEW[role][0]
                and type(row["review_id"]) is int and row["review_id"] == REVIEW[role][1]
                and type(row["run_id"]) is int and row["run_id"] > 0
                and type(row["run_attempt"]) is int and row["run_attempt"] >= 1
                and all(sha(row[key]) for key in ("head", "tree", "base")),
                "P4 missing/foreign/source-role identity")
        roles[role] = row
    require(set(roles) == set(REVIEW), "P4 SOURCE roles incomplete")
    frozen_by_repo = {r["repository"]: r for r in frozen.get("entries", [])}
    for role in ("F1", "F2", "RELATION"):
        row = roles[role]
        old = frozen_by_repo.get(row["repository"])
        require(type(old) is dict and all(row[key] == old[key] for key in
                ("pr", "head", "tree", "base", "run_id", "run_attempt")),
                f"{role}: frozen reviewed F1/F2/relation identity changed")
    require(roles["F2"]["run_attempt"] == 2
            and all(roles[r]["run_attempt"] == 1 for r in roles if r != "F2")
            and roles["P2"]["base"] == roles["F2"]["head"]
            and roles["P3"]["base"] == roles["P2"]["head"],
            "P4 attempted to skip actual F2/P2/P3 source ancestry")

    seen: dict[str, dict[str, Any]] = {}
    def cached(url: str) -> dict[str, Any]:
        if url not in seen:
            require(url.startswith(API + "/repos/"), "P4 foreign public read")
            seen[url] = get(url)
        return seen[url]

    # Reuse the already independent-R accepted frozen F1/F2/Relation *code*,
    # including actual public blob, immutable proposed q, failed-attempt history.
    previous = verify_frozen(frozen, cached)
    require(previous["stage"] == "V6_F1_F2_DISPOSABLE_SOURCE_EVIDENCE_VERIFIED"
            and previous["admission"] == "NOT_ADMITTED"
            and previous["effect"] == "FORBIDDEN",
            "old immutable F1/F2 proof not accepted")

    for role, row in roles.items():
        root = f"{API}/repos/{row['repository']}"
        if role not in ("F1", "F2", "RELATION"):
            pr = cached(f"{root}/pulls/{row['pr']}")
            require(pr.get("number") == row["pr"] and pr.get("state") == "open"
                    and pr.get("draft") is True and pr.get("merged") is False
                    and pr.get("head", {}).get("sha") == row["head"]
                    and pr.get("head", {}).get("repo", {}).get("full_name")
                    == row["repository"]
                    and pr.get("base", {}).get("sha") == row["base"],
                    f"{role}: PR head/base or Draft state changed")
            commit = cached(f"{root}/commits/{row['head']}")
            require(commit.get("sha") == row["head"]
                    and commit.get("commit", {}).get("tree", {}).get("sha") == row["tree"],
                    f"{role}: real immutable Git tree mismatch")
            run = cached(f"{root}/actions/runs/{row['run_id']}")
            require(run.get("id") == row["run_id"] and run.get("head_sha") == row["head"]
                    and run.get("run_attempt") == row["run_attempt"]
                    and run.get("event") == "pull_request"
                    and run.get("status") == "completed"
                    and run.get("conclusion") == "success",
                    f"{role}: run head/attempt/event not terminal SOURCE SUCCESS")
            record = cached(f"{root}/actions/runs/{row['run_id']}/"
                            f"attempts/{row['run_attempt']}/jobs?per_page=100")
            jobs = record.get("jobs")
            typ = ("windows" if row["repository"] == "roccho-dev/windows" else
                   "resources" if row["repository"] == "roccho-dev/resources" else "envs")
            allowed = REQUIRED[typ] | SKIPPED[typ]
            require(type(jobs) is list and type(record.get("total_count")) is int
                    and len(jobs) == record["total_count"] == len(allowed),
                    f"{role}: CI job count truncated/missing")
            indexed = {}
            for job in jobs:
                name = job.get("name")
                require(type(name) is str and name not in indexed
                        and job.get("run_id") == row["run_id"]
                        and job.get("run_attempt") == row["run_attempt"]
                        and job.get("status") == "completed",
                        f"{role}: duplicate, foreign or unfinished job")
                indexed[name] = job
            require(set(indexed) == allowed
                    and all(indexed[name].get("conclusion") == "success"
                            for name in REQUIRED[typ])
                    and all(indexed[name].get("conclusion") == "skipped"
                            for name in SKIPPED[typ]),
                    f"{role}: incomplete or false-GREEN CI")
            for jobname, expected in STEPS.get(role, {}).items():
                steps = indexed[jobname].get("steps")
                require(type(steps) is list and len({s.get("name") for s in steps}) == len(steps)
                        and all(any(s.get("name") == name and s.get("conclusion") == "success"
                                    and s.get("status") == "completed" for s in steps)
                                for name in expected),
                        f"{role}: actual SOURCE proof step skipped/missing/failed")

        review = cached(f"{root}/pulls/{row['pr']}/reviews/{row['review_id']}")
        body = review.get("body")
        require(review.get("id") == row["review_id"]
                and review.get("commit_id") == row["head"]
                and review.get("state") == "COMMENTED"
                and review.get("user", {}).get("login") == "roccho-dev"
                and type(body) is str and body.startswith("<!-- " + REVIEW[role][2] + " -->")
                and ("GREEN" in body or "受容" in body),
                f"{role}: required distinct exact-head independent R record missing")
    # SOURCE evidence DOES NOT authenticate independent actors just because
    # their public GitHub reviews exist. Fixed R will separately verify this P4.

    p1, p2, p3 = (roles[key] for key in ("P1", "P2", "P3"))
    p1caller = real_file("roccho-org/envs", p1["head"],
                         "adapters/host_tool_source_entry.py", cached, P1_SOURCE_BLOB)
    receiver = real_file("roccho-dev/windows", p2["head"],
                         "hosts/rent/tool-receiver.py", cached, P2_RECEIVER_BLOB)
    same_receiver = real_file("roccho-dev/windows", p3["head"],
                              "hosts/rent/tool-receiver.py", cached, P2_RECEIVER_BLOB)
    caller = real_file("roccho-dev/windows", p3["head"],
                       "hosts/rent/caller-receiver-proof.py", cached, P3_CALLER_BLOB)
    native = real_file("roccho-dev/windows", p3["head"],
                       "hosts/rent/native-proof.sh", cached, P3_NATIVE_BLOB)
    require(receiver == same_receiver
            and "def source_step(" in p1caller
            and "def receive_step(" in receiver
            and f'ENVS_HEAD = "{p1["head"]}"' in caller
            and f'F1_BLOB = "{frozen["binding"]["blob"]}"' in caller
            and "P2_ACTUAL" in caller and "P2_RECEIVER" in caller
            and "copy.deepcopy(issued)" in caller
            and 'runpy.run_path("hosts/rent/caller-receiver-proof.py"' in native
            and '"P2_ACTUAL": port, "P2_RECEIVER": receiver' in native,
            "P4 actual P1/P2/P3 SOURCE not bound to the same receiver/Port")

    ids = set(re.findall(r"(?m)^\| (V\d{2}|[SBGHA]\d|L\d{2}) \|", coverage))
    required_ids = ({f"V{i:02}" for i in range(1, 15)}
                    | {f"S{i}" for i in range(1, 5)}
                    | {f"B{i}" for i in range(1, 6)}
                    | {f"G{i}" for i in range(1, 7)}
                    | {f"H{i}" for i in range(1, 5)}
                    | {f"A{i}" for i in range(1, 4)}
                    | {f"L{i:02}" for i in range(1, 29)})
    require(ids == required_ids and len(ids) == 64
            and coverage.count("| S2 |") == 1
            and "SOURCE-proven:R" in coverage
            and "REAL_TARGET_UNPROVEN" in coverage
            and "D_ADMITTED=false" in coverage,
            "P4 v6 64-case SOURCE versus REAL_TARGET_UNPROVEN evidence map missing")

    return {
        "kind": "envs.hostCommonV6LatestSRC4Readback.v0",
        "stage": "V6_LATEST_P1_P2_P3_SOURCE_EVIDENCE_CANDIDATE",
        "source_count": len(roles),
        "sources": [{"role": role, "repository": row["repository"],
                     "head": row["head"], "tree": row["tree"],
                     "run_id": row["run_id"], "review_id": row["review_id"]}
                    for role, row in sorted(roles.items())],
        "f1_proposed_q": previous["proposed_q"],
        "source_steps_and_reviews_verified": True,
        "v6_64_case_structure": "SOURCE_REFERENCED_REAL_TARGET_UNPROVEN",
        "admission": "NOT_ADMITTED", "accepted_q": None,
        "target_observation": "NOT_READ", "target_noop": "UNPROVEN",
        "effect": "FORBIDDEN", "real_composite_green": False,
        "all_source_r_accepted": False, "merge_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=Path(
        "checks/fixtures/host-tool-v6-latest-src4.json"))
    args = parser.parse_args()
    try:
        candidate = json.loads(args.snapshot.read_text(encoding="utf-8"))
        frozen = json.loads(Path("checks/fixtures/host-tool-v6-source-set.json").read_text(
            encoding="utf-8"))
        coverage = Path("checks/host_tool_source_coverage.md").read_text(encoding="utf-8")
        result = verify_latest(candidate, frozen, coverage, public_get)
    except (OSError, ValueError) as ex:
        print(f"V6_LATEST_SRC4_REFUSED: {ex}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
