#!/usr/bin/env python3
"""Offline adversarial latest-P4 SOURCE proof tests; public GETs are mock records."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_source_provenance import API, ProvenanceError  # noqa: E402
from host_tool_v6_source_gate import git_blob  # noqa: E402
from host_tool_v6_latest_gate import (OWNER, REQUIRED, REVIEW, SKIPPED, STEPS,
                                      P1_SOURCE_BLOB, P2_RECEIVER_BLOB,
                                      P3_CALLER_BLOB, P3_NATIVE_BLOB,
                                      verify_latest)  # noqa: E402
from test_host_tool_v6_source_gate import records, files  # noqa: E402

SNAP = ROOT / "checks/fixtures/host-tool-v6-latest-src4.json"
FROZEN = ROOT / "checks/fixtures/host-tool-v6-source-set.json"
COVERAGE = ROOT / "checks/host_tool_source_coverage.md"


class LatestP4Cases(unittest.TestCase):
    def setUp(self):
        self.snap = json.loads(SNAP.read_text(encoding="utf-8"))
        self.frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
        self.coverage = COVERAGE.read_text(encoding="utf-8")
        self.data = records(self.frozen)
        self.oldfiles = files(self.frozen)
        self.source_changes = {}
        for row in self.snap["entries"]:
            role = row["role"]
            root = f"{API}/repos/{row['repository']}"
            self.data[f"{root}/pulls/{row['pr']}/reviews/{row['review_id']}"] = {
                "id": row["review_id"], "commit_id": row["head"], "state": "COMMENTED",
                "user": {"login": "roccho-dev"},
                "body": "<!-- " + REVIEW[role][2] + " -->\n**固定R** SOURCE GREEN",
            }
            if role in ("F1", "F2", "RELATION"):
                continue
            self.data[f"{root}/pulls/{row['pr']}"] = {
                "number": row["pr"], "state": "open", "draft": True, "merged": False,
                "head": {"sha": row["head"], "repo": {"full_name": row["repository"]}},
                "base": {"sha": row["base"]},
            }
            self.data[f"{root}/commits/{row['head']}"] = {
                "sha": row["head"], "commit": {"tree": {"sha": row["tree"]}},
            }
            self.data[f"{root}/actions/runs/{row['run_id']}"] = {
                "id": row["run_id"], "head_sha": row["head"], "run_attempt": row["run_attempt"],
                "status": "completed", "conclusion": "success", "event": "pull_request",
            }
            typ = ("windows" if row["repository"] == "roccho-dev/windows" else
                   "resources" if row["repository"] == "roccho-dev/resources" else "envs")
            names = sorted(REQUIRED[typ] | SKIPPED[typ])
            jobs = []
            for name in names:
                steps = [{"name": s, "status": "completed", "conclusion": "success"}
                         for s in sorted(STEPS.get(role, {}).get(name, set()))]
                jobs.append({
                    "name": name, "run_id": row["run_id"], "run_attempt": row["run_attempt"],
                    "status": "completed",
                    "conclusion": "skipped" if name in SKIPPED[typ] else "success",
                    "steps": steps,
                })
            self.data[f"{root}/actions/runs/{row['run_id']}/"
                      f"attempts/{row['run_attempt']}/jobs?per_page=100"] = {
                "total_count": len(jobs), "jobs": jobs,
            }
        w = self.row("P3")
        p1 = self.row("P1")
        self.newfiles = {
            ("roccho-org/envs", p1["head"], "adapters/host_tool_source_entry.py"):
                "def source_step(request):\n    pass\n",
            ("roccho-dev/windows", self.row("P2")["head"], "hosts/rent/tool-receiver.py"):
                "def receive_step(request):\n    pass\n",
            ("roccho-dev/windows", w["head"], "hosts/rent/tool-receiver.py"):
                "def receive_step(request):\n    pass\n",
            ("roccho-dev/windows", w["head"], "hosts/rent/caller-receiver-proof.py"):
                ('ENVS_HEAD = "' + p1["head"] + '"\n'
                 + 'F1_BLOB = "' + self.frozen["binding"]["blob"] + '"\n'
                 + 'P2_ACTUAL = True\nP2_RECEIVER = True\ncopy.deepcopy(issued)\n'),
            ("roccho-dev/windows", w["head"], "hosts/rent/native-proof.sh"):
                ('runpy.run_path("hosts/rent/caller-receiver-proof.py", run_name="__main__")\n'
                 '"P2_ACTUAL": port, "P2_RECEIVER": receiver\n'),
        }

    def row(self, role):
        return next(r for r in self.snap["entries"] if r["role"] == role)

    def get(self, url):
        if url not in self.data:
            raise ProvenanceError("missing public GitHub evidence")
        return self.data[url]

    def file(self, repo, head, path, get, blob=None):
        key = (repo, head, path)
        if key in self.newfiles:
            required_blobs = {
                "adapters/host_tool_source_entry.py": P1_SOURCE_BLOB,
                "hosts/rent/tool-receiver.py": P2_RECEIVER_BLOB,
                "hosts/rent/caller-receiver-proof.py": P3_CALLER_BLOB,
                "hosts/rent/native-proof.sh": P3_NATIVE_BLOB,
            }
            if blob != required_blobs[path]:
                raise ProvenanceError("new immutable SOURCE blob mismatch")
            return self.newfiles[key]
        old = self.oldfiles.get(key)
        if old is None:
            raise ProvenanceError("missing immutable SOURCE material")
        if blob is not None and repo == "roccho-org/envs" and git_blob(old) != blob:
            raise ProvenanceError("F1 binding Git blob mismatch")
        if blob is not None and repo == "roccho-dev/resources" and blob != self.frozen["relation"]["blob"]:
            raise ProvenanceError("Relation Git blob mismatch")
        return old

    def check(self):
        with patch("host_tool_v6_source_gate.real_file", side_effect=self.file), \
             patch("host_tool_v6_latest_gate.real_file", side_effect=self.file):
            return verify_latest(self.snap, self.frozen, self.coverage, self.get)

    def refuse(self, expected=None):
        with self.assertRaises(ProvenanceError) as caught:
            self.check()
        if expected:
            self.assertIn(expected, str(caught.exception))

    def test_frozen_latest_full_source_candidate_still_no_admission_or_s4(self):
        result = self.check()
        self.assertEqual(result["stage"], "V6_LATEST_P1_P2_P3_SOURCE_EVIDENCE_CANDIDATE")
        self.assertEqual(result["source_count"], 9)
        self.assertEqual({x["role"] for x in result["sources"]}, set(REVIEW))
        self.assertEqual(result["admission"], "NOT_ADMITTED")
        self.assertIsNone(result["accepted_q"])
        self.assertEqual(result["target_observation"], "NOT_READ")
        self.assertEqual(result["target_noop"], "UNPROVEN")
        self.assertEqual(result["effect"], "FORBIDDEN")
        self.assertFalse(result["real_composite_green"])
        self.assertFalse(result["all_source_r_accepted"])
        self.assertFalse(result["merge_ready"])
        self.assertEqual(result["v6_64_case_structure"], "SOURCE_REFERENCED_REAL_TARGET_UNPROVEN")

    def test_P3_failed_or_missing_integrated_step_is_red_even_when_P2_green(self):
        row = self.row("P3")
        url = f"{API}/repos/{row['repository']}/actions/runs/{row['run_id']}/attempts/1/jobs?per_page=100"
        for mutation in ("skipped", "failure", "remove"):
            old = copy.deepcopy(self.data[url])
            jobs = self.data[url]["jobs"]
            job = next(j for j in jobs if j["name"] == "rent / build-test-publish")
            proof = next(s for s in job["steps"] if s["name"].startswith("Prove bound PROPOSED"))
            if mutation == "remove":
                job["steps"].remove(proof)
            else:
                proof["conclusion"] = mutation
            with self.subTest(case=mutation):
                self.refuse("P3: actual SOURCE proof step")
            self.data[url] = old

    def test_P1_stage_and_P2_receiver_each_required_not_just_other_green(self):
        for role, step in (
            ("P1", "Test inactive SOURCE-entry read/change/receipt at exact head"),
            ("P2", "Prove bound PROPOSED q/Host and actual native rent Tool/readonly O"),
        ):
            row = self.row(role)
            url = (f"{API}/repos/{row['repository']}/actions/runs/{row['run_id']}"
                   f"/attempts/{row['run_attempt']}/jobs?per_page=100")
            old = copy.deepcopy(self.data[url])
            for job in self.data[url]["jobs"]:
                for record in job["steps"]:
                    if record["name"] == step:
                        record["conclusion"] = "skipped"
            self.refuse(f"{role}: actual SOURCE proof step")
            self.data[url] = old

    def test_stale_P3_old_head_base_attempt_or_future_unfinished_run_refuses(self):
        role = self.row("P3")
        for key, value in (("head", "a" * 40), ("base", "a" * 40),
                           ("run_attempt", 2), ("tree", "a" * 40)):
            old = role[key]
            role[key] = value
            self.refuse()
            role[key] = old
        url = f"{API}/repos/roccho-dev/windows/actions/runs/{role['run_id']}"
        old = copy.deepcopy(self.data[url])
        self.data[url]["status"] = "in_progress"
        self.refuse("P3: run head/attempt/event")
        self.data[url] = old

    def test_wrong_or_missing_fixed_R_is_not_independent_source_acceptance(self):
        row = self.row("P3")
        url = f"{API}/repos/roccho-dev/windows/pulls/98/reviews/{row['review_id']}"
        for mutate in (
            lambda a: a.update(commit_id="f" * 40),
            lambda a: a.update(state="PENDING"),
            lambda a: a.update(body="approved without exact source"),
            lambda a: a.update(id=1),
            lambda a: a["user"].update(login="unknown"),
        ):
            old = copy.deepcopy(self.data[url])
            mutate(self.data[url])
            self.refuse("P3: required distinct")
            self.data[url] = old

    def test_wrong_P1_pin_or_foreign_P2_receiver_is_refused(self):
        row = self.row("P3")
        path = ("roccho-dev/windows", row["head"], "hosts/rent/caller-receiver-proof.py")
        old = self.newfiles[path]
        self.newfiles[path] = old.replace(self.row("P1")["head"], "a" * 40)
        self.refuse("P4 actual P1/P2/P3 SOURCE")
        self.newfiles[path] = old
        path = ("roccho-dev/windows", row["head"], "hosts/rent/tool-receiver.py")
        old = self.newfiles[path]
        self.newfiles[path] = "def another_receiver():\n    pass\n"
        self.refuse("P4 actual P1/P2/P3 SOURCE")
        self.newfiles[path] = old

    def test_frozen_F2_retry_run_and_reviewed_F1_blob_still_bound(self):
        # Prior F2 attempt-1 RED remains in the separately accepted F1/F2 X
        # R/CI evidence. P4 requires attempt-2 terminal SUCCESS and the
        # identical immutable F1 binding, without falsely claiming a fresh
        # audit of its older per-step jobs.
        row = self.row("F2")
        url = f"{API}/repos/roccho-dev/windows/actions/runs/{row['run_id']}"
        old = copy.deepcopy(self.data[url])
        self.data[url]["run_attempt"] = 1
        self.refuse("F2: previously R-reviewed SOURCE run")
        self.data[url] = old
        old_blob = self.frozen["binding"]["blob"]
        self.frozen["binding"]["blob"] = "f" * 40
        self.refuse("frozen approved SOURCE binding Git blob changed")
        self.frozen["binding"]["blob"] = old_blob

    def test_R1_X_BOUND_SRC3_immutable_full_head_tree_base_refuse(self):
        # Earlier R-reviewed roles skip costly current PR/commit GETs.
        # Their *full* original identities must therefore remain immutable,
        # rather than accepting arbitrary valid-looking 40-hex tree/base.
        for role in ("X", "BOUND", "SRC3"):
            row = self.row(role)
            for field in ("head", "tree", "base"):
                with self.subTest(role=role, field=field):
                    old = row[field]
                    row[field] = "f" * 40
                    with patch.object(self, "get", side_effect=AssertionError(
                            "historical identity should refuse before any public GET")):
                        self.refuse(f"{role}: reviewed immutable prior SOURCE identity changed")
                    row[field] = old

    def test_R2_single_V11_false_target_success_and_duplicate_case_refuse(self):
        original = self.coverage
        row = next(line for line in original.splitlines()
                   if line.startswith("| V11 |"))
        self.assertEqual(row.count("REAL_TARGET_UNPROVEN"), 1)
        # 64 IDs, the remaining 63 UNPROVEN rows, and other R markers stay valid.
        self.coverage = original.replace(
            row, row.replace("REAL_TARGET_UNPROVEN", "REAL_TARGET_PROVEN"))
        self.refuse("P4 v6 64-case")
        # One ordinary additional V11 would be invisible to a set-only ID test.
        self.coverage = original.replace(row, row + "\n" + row)
        self.refuse("P4 v6 64-case")
        # Nor may the status column claim both PROVEN and UNPROVEN.
        self.coverage = original.replace(
            row, row.replace("REAL_TARGET_UNPROVEN",
                             "REAL_TARGET_PROVEN ; REAL_TARGET_UNPROVEN"))
        self.refuse("P4 v6 64-case")
        self.coverage = original

    def test_64_CASES_source_map_preserved_but_no_real_target(self):
        original = self.coverage
        self.coverage = self.coverage.replace("REAL_TARGET_UNPROVEN", "REAL_TARGET_PROVEN")
        self.refuse("v6 64-case")
        self.coverage = original
        self.coverage = self.coverage.replace("| S2 |", "| G9 |")
        self.refuse("v6 64-case")
        self.coverage = original

    def test_missing_job_or_skipped_publication_change_is_red(self):
        row = self.row("P1")
        url = f"{API}/repos/roccho-org/envs/actions/runs/{row['run_id']}/attempts/1/jobs?per_page=100"
        old = copy.deepcopy(self.data[url])
        job = next(j for j in self.data[url]["jobs"] if j["name"] == "placement-publish")
        job["conclusion"] = "success"
        self.refuse("P1: incomplete or false-GREEN")
        self.data[url] = old

    def test_missing_public_metadata_not_counted_as_success(self):
        row = self.row("P3")
        url = f"{API}/repos/roccho-dev/windows/pulls/98/reviews/{row['review_id']}"
        self.data.pop(url)
        self.refuse("missing public GitHub evidence")


if __name__ == "__main__":
    unittest.main()
