#!/usr/bin/env python3
"""No-network adversarial tests for the public SOURCE evidence reader."""
from __future__ import annotations

import base64
import copy
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_source_provenance import (  # noqa: E402
    API, REQUIRED, RELATION_BLOB, RELATION_METHOD, S2_MARKER,
    ProvenanceError, verify_candidate,
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
    relation_url = (f"{source_root}/tests/host_relation_source.py?ref={resources}")
    result[relation_url] = {
        **payload(
            "import unittest\n"
            "class ProposedRelationCases(unittest.TestCase):\n"
            f"    def {RELATION_METHOD}(self):\n"
            "        pass\n"
            '"admission": "NOT_ADMITTED"\n'
            '"effect": "FORBIDDEN"\n'
        ),
        "sha": RELATION_BLOB,
    }
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
        self.coverage_text = (ROOT / "checks/host_tool_source_coverage.md").read_text(
            encoding="utf-8")

    def check(self):
        return verify_candidate(self.snapshot, self.records.__getitem__,
                                coverage_text=self.coverage_text)

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
        self.assertEqual(result["stage"], "V5_CURRENT_SOURCE_CANDIDATES_VERIFIED")
        self.assertEqual(result["s2_relation_evidence"], "RESOURCES19_TEST_AND_CI_VERIFIED")
        self.assertEqual([(row["repository"], row["pr"]) for row in result["sources"]],
                         [("roccho-dev/resources", 19),
                          ("roccho-dev/windows", 91),
                          ("roccho-org/envs", 87)])
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

    def test_v6_coverage_has_all_64_distinct_obligations_with_exact_sources(self):
        cover = (ROOT / "checks/host_tool_source_coverage.md").read_text(encoding="utf-8")
        ids = re.findall(r"^\| (V\d{2}|[SBGHA]\d|L\d{2}) \|", cover, re.MULTILINE)
        expected = (
            {f"V{i:02}" for i in range(1, 15)}
            | {f"S{i}" for i in range(1, 5)}
            | {f"B{i}" for i in range(1, 6)}
            | {f"G{i}" for i in range(1, 7)}
            | {f"H{i}" for i in range(1, 5)}
            | {f"A{i}" for i in range(1, 4)}
            | {f"L{i:02}" for i in range(1, 29)}
        )
        self.assertEqual(len(ids), 64)
        self.assertEqual(set(ids), expected)
        for row in self.snapshot["entries"]:
            self.assertIn(row["head"], cover)
            self.assertIn(row["tree"], cover)
        self.assertIn("S4_REAL_COMPOSITE_GREEN=false", cover)
        self.assertIn("D_ADMITTED=false", cover)
        self.assertIn("TARGET_READY=false", cover)
        # v5: case IDs alone do NOT constitute exercised SOURCE evidence.
        # Every SOURCE-SUT method reference must exist in a CI-executed test file.
        sut_links = re.findall(
            r"`SOURCE-SUT:(checks/test_host_tool_[A-Za-z0-9_]+\.py)#(test_[A-Za-z0-9_]+)`",
            cover,
        )
        self.assertGreaterEqual(len(sut_links), 50)
        for path, method in sut_links:
            with self.subTest(path=path, method=method):
                file = ROOT / path
                self.assertTrue(file.is_file())
                source = file.read_text(encoding="utf-8")
                self.assertRegex(source, rf"(?m)^    def {re.escape(method)}\(")

    def test_v5_exact_latest_candidates_refuse_fallback_to_old_green_prs(self):
        for repository, obsolete in (("roccho-org/envs", 86),
                                     ("roccho-dev/resources", 17)):
            with self.subTest(repository=repository):
                old = copy.deepcopy(self.snapshot)
                for row in self.snapshot["entries"]:
                    if row["repository"] == repository:
                        row["pr"] = obsolete
                self.refuse("non-exact")
                self.snapshot = old

    def test_s2_missing_skipped_failed_or_removed_relation_step_refused(self):
        resource = self.snapshot["entries"][2]
        url = (f"{API}/repos/roccho-dev/resources/actions/runs/"
               f"{resource['run_id']}/jobs?per_page=100")
        original = copy.deepcopy(self.records[url])
        for action in ("skipped", "failure", "removed"):
            with self.subTest(action=action):
                self.records[url] = copy.deepcopy(original)
                proof = next(job for job in self.records[url]["jobs"]
                             if job["name"] == "source-vm")
                steps = proof["steps"]
                step = next(s for s in steps if s["name"] in (
                    "Test synthetic Host contains/manages/optional wrap (NOT_ADMITTED)",))
                if action == "removed":
                    steps.remove(step)
                else:
                    step["conclusion"] = action
                self.refuse("required CI proof step")
        self.records[url] = original

    def test_s2_evidence_source_and_mapping_must_both_be_real(self):
        resource_head = self.snapshot["entries"][2]["head"]
        url = (f"{API}/repos/roccho-dev/resources/contents/nixos/"
               f"tests/host_relation_source.py?ref={resource_head}")
        original = copy.deepcopy(self.records[url])
        for mutation in ("foreign_blob", "missing_method", "lost_not_admitted"):
            with self.subTest(mutation=mutation):
                self.records[url] = copy.deepcopy(original)
                if mutation == "foreign_blob":
                    self.records[url]["sha"] = "a" * 40
                else:
                    content = base64.b64decode(self.records[url]["content"]).decode()
                    if mutation == "missing_method":
                        content = content.replace(RELATION_METHOD, "test_unrelated_target")
                    else:
                        content = content.replace('"admission": "NOT_ADMITTED"',
                                                  '"admission": "ADMITTED"')
                    self.records[url]["content"] = base64.b64encode(content.encode()).decode()
                self.refuse()
        self.records[url] = original
        before = self.coverage_text
        for tamper in ("missing", "old_target_unit_test", "wrong_resource_method"):
            with self.subTest(tamper=tamper):
                if tamper == "missing":
                    self.coverage_text = before.replace(S2_MARKER, "")
                elif tamper == "old_target_unit_test":
                    self.coverage_text = before.replace(
                        S2_MARKER,
                        "SOURCE-SUT:checks/test_host_tool_target_gap.py"
                        "#test_target_unit_not_derived_from_repo_or_oci_path")
                else:
                    self.coverage_text = before.replace(RELATION_METHOD, "test_nonexistent")
                self.refuse("S2 coverage")
        self.coverage_text = before

    def test_missing_public_api_evidence_fails_closed(self):
        del self.records[next(iter(self.records))]
        with self.assertRaises(KeyError):
            self.check()


if __name__ == "__main__":
    unittest.main()
