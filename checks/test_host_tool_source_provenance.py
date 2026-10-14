#!/usr/bin/env python3
"""No-network adversarial tests for the public SOURCE evidence reader."""
from __future__ import annotations

import base64
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_source_provenance import (  # noqa: E402
    API, REQUIRED, ProvenanceError, verify_candidate,
)

SNAPSHOT = ROOT / "checks/fixtures/host-tool-source-set.json"


def payload(content: str) -> dict:
    return {"type": "file", "encoding": "base64",
            "content": base64.b64encode(content.encode()).decode()}


def reference_records(snapshot: dict) -> dict:
    refs = {row["repository"]: row for row in snapshot["entries"]}
    windows = refs["roccho-dev/windows"]["head"]
    resources = refs["roccho-dev/resources"]["head"]
    envs = refs["roccho-org/envs"]["head"]
    result = {}
    for item in snapshot["entries"]:
        repo, head, base = item["repository"], item["head"], item["base"]
        pr, run = item["pr"], item["run_id"]
        root = f"{API}/repos/{repo}"
        result[f"{root}/pulls/{pr}"] = {
            "number": pr, "state": "open", "draft": True, "merged": False,
            "head": {"sha": head, "repo": {"full_name": repo}},
            "base": {"sha": base},
        }
        result[f"{root}/commits/{head}"] = {
            "sha": head, "commit": {"tree": {"sha": item["tree"]}},
        }
        result[f"{root}/actions/runs/{run}"] = {
            "id": run, "head_sha": head, "status": "completed",
            "conclusion": "success", "event": "pull_request",
        }
        contract = REQUIRED[repo]
        jobs = []
        for name in sorted(contract["jobs"] | contract["skipped"]):
            steps = [{"name": name2, "conclusion": "success"}
                     for name2 in sorted(contract["steps"].get(name, []))]
            jobs.append({
                "name": name, "run_id": run, "status": "completed",
                "conclusion": "skipped" if name in contract["skipped"] else "success",
                "steps": steps,
            })
        result[f"{root}/actions/runs/{run}/jobs?per_page=100"] = {
            "total_count": len(jobs), "jobs": jobs,
        }
    source_root = API + "/repos/roccho-dev/resources/contents/nixos"
    result[f"{source_root}/flake.nix?ref={resources}"] = payload(
        'inputs.windows.url = "github:roccho-dev/windows/' + windows + '";\n')
    result[f"{source_root}/flake.lock?ref={resources}"] = payload(json.dumps({
        "nodes": {"windows": {
            "original": {"rev": windows},
            "locked": {"rev": windows, "narHash": "sha256-k1k3Y1DuOvXkpntXFyHGaw4ICJBJ1vlsBuDIVAF52nM="},
        }},
    }))
    envs_url = (API + "/repos/roccho-org/envs/contents/contracts/"
                f"proposals/host-tool-selection.jsonl?ref={envs}")
    result[envs_url] = payload(json.dumps({
        "id": "pc7337-rent.host-tool-selection",
        "kind": "envs.hostToolSelectionProposal.v0",
        "admission": "NOT_ADMITTED",
        "target_ref": "pc7337-rent",
        "material": {
            "repository": "roccho-dev/windows",
            "source_commit": windows,
            "flake_output": "packages.x86_64-linux.rent-tool-profile",
        },
    }) + "\n")
    return result


class SourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.records = reference_records(self.snapshot)

    def check(self):
        return verify_candidate(self.snapshot, self.records.__getitem__)

    def refuse(self, reason=None):
        with self.assertRaises(ProvenanceError) as context:
            self.check()
        if reason is not None:
            self.assertIn(reason, str(context.exception))

    def change(self, repo, suffix, mutate):
        record = self.snapshot["entries"]
        row = next(r for r in record if r["repository"] == repo)
        url = f"{API}/repos/{repo}/{suffix.format(**row)}"
        mutate(self.records[url])

    def test_real_shape_source_passes_but_never_grants_target(self):
        result = self.check()
        self.assertEqual(result["stage"], "PUBLIC_SOURCE_CANDIDATE_VERIFIED")
        self.assertEqual(result["admission"], "NOT_ADMITTED")
        self.assertIsNone(result["accepted_q"])
        self.assertEqual(result["target_observation"], "NOT_READ")
        self.assertEqual(result["target_noop"], "UNPROVEN")
        self.assertEqual(result["effect"], "FORBIDDEN")
        self.assertFalse(result["merge_ready"])
        self.assertFalse(result["target_ready"])
        self.assertFalse(result["real_composite_green"])
        self.assertEqual(len(result["sources"]), 3)
        self.assertEqual(self.check(), result)

    def test_37_char_transcription_and_wrong_40_char_tree_refused(self):
        self.snapshot["entries"][0]["tree"] = "8406cd25827891066eb3d3ec4eeaab4abfe07"
        self.refuse("non-exact")
        self.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.snapshot["entries"][0]["tree"] = "f" * 40
        self.refuse("commit tree")

    def test_duplicate_foreign_or_unbounded_candidate_cannot_pass(self):
        self.snapshot["entries"][1]["repository"] = "roccho-dev/windows"
        self.refuse("duplicate")
        self.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.snapshot["entries"][0]["repository"] = "foreign/example"
        self.refuse("foreign")
        self.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.snapshot["admission"] = "ADMITTED"
        self.refuse("admit")
        self.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.snapshot["effects"] = "accepted"
        self.refuse("unsupported fields")

    def test_pr_state_head_base_and_ci_status_drift_refused(self):
        windows = "roccho-dev/windows"
        repo = self.snapshot["entries"][0]
        suffix = "pulls/{pr}"
        for mutate in (
            lambda r: r.update(draft=False),
            lambda r: r.update(state="closed"),
            lambda r: r.update(merged=True),
            lambda r: r["head"].update(sha="a" * 40),
            lambda r: r["base"].update(sha="b" * 40),
        ):
            with self.subTest(mutate=mutate.__code__.co_firstlineno):
                old = copy.deepcopy(self.records)
                self.change(windows, suffix, mutate)
                self.refuse("PR identity")
                self.records = old
        for mutate in (
            lambda r: r.update(conclusion="failure"),
            lambda r: r.update(status="in_progress"),
            lambda r: r.update(head_sha="c" * 40),
            lambda r: r.update(event="push"),
        ):
            with self.subTest(mutate=mutate.__code__.co_firstlineno):
                old = copy.deepcopy(self.records)
                self.change(windows, "actions/runs/{run_id}", mutate)
                self.refuse("CI run")
                self.records = old

    def test_skipped_failed_or_incomplete_job_and_proof_step_refused(self):
        for change in (
            lambda r: r["jobs"][0].update(conclusion="failure"),
            lambda r: r["jobs"][0].update(status="in_progress"),
            lambda r: r["jobs"].pop(),
            lambda r: r.update(total_count=999),
            lambda r: r["jobs"][0].update(run_id=1),
            lambda r: r["jobs"][0].update(name="unexpected-extra-job"),
        ):
            with self.subTest(case=change.__code__.co_firstlineno):
                old = copy.deepcopy(self.records)
                self.change("roccho-org/envs", "actions/runs/{run_id}/jobs?per_page=100", change)
                self.refuse()
                self.records = old
        def fail_proof(record):
            job = next(j for j in record["jobs"] if j["name"] == "source-vm")
            job["steps"][0]["conclusion"] = "skipped"
        self.change("roccho-dev/resources", "actions/runs/{run_id}/jobs?per_page=100",
                    fail_proof)
        self.refuse("required CI proof step")

    def test_immutable_source_pin_lock_and_unadmitted_material_refused(self):
        window_head = self.snapshot["entries"][0]["head"]
        resource_head = self.snapshot["entries"][2]["head"]
        envs_head = self.snapshot["entries"][1]["head"]
        source = (f"{API}/repos/roccho-dev/resources/contents/nixos/"
                  f"flake.nix?ref={resource_head}")
        lock = (f"{API}/repos/roccho-dev/resources/contents/nixos/"
                f"flake.lock?ref={resource_head}")
        proposed = (f"{API}/repos/roccho-org/envs/contents/contracts/"
                    f"proposals/host-tool-selection.jsonl?ref={envs_head}")
        for url, value in (
            (source, payload('inputs.windows.url = "github:roccho-dev/windows/' +
                             "a" * 40 + '";\n')),
            (lock, payload(json.dumps({"nodes": {"windows": {
                "original": {"rev": window_head},
                "locked": {"rev": "b" * 40, "narHash": "sha256-abc="},
            }}}))),
            (proposed, payload(json.dumps({
                "admission": "ADMITTED", "target_ref": "pc7337-rent",
                "material": {"repository": "roccho-dev/windows",
                             "source_commit": window_head},
            }) + "\n")),
        ):
            old = copy.deepcopy(self.records)
            self.records[url] = value
            self.refuse()
            self.records = old

    def test_missing_public_api_evidence_fails_closed(self):
        del self.records[next(iter(self.records))]
        with self.assertRaises(KeyError):
            self.check()


if __name__ == "__main__":
    unittest.main()
