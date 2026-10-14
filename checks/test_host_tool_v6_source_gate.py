#!/usr/bin/env python3
"""Offline refusal tests for F1/F2 actual CI attempts and proposed SOURCE linkage."""
from __future__ import annotations
import base64
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))
from host_tool_source_provenance import API, ProvenanceError  # noqa: E402
from host_tool_v6_source_gate import (  # noqa: E402
    BINDING_URL, JOBS, STEPS, git_blob, real_file, verify,
)
SNAP = ROOT / "checks/fixtures/host-tool-v6-source-set.json"
F1 = ROOT / "checks/fixtures/host-tool-functional-binding.json"


def records(snapshot):
    out = {}
    for e in snapshot["entries"]:
        repo, run, attempt, number = (e["repository"], e["run_id"],
                                      e["run_attempt"], e["pr"])
        root = f"{API}/repos/{repo}"
        out[f"{root}/pulls/{number}"] = {
            "number": number, "state": "open", "draft": True, "merged": False,
            "head": {"sha": e["head"], "repo": {"full_name": repo}},
            "base": {"sha": e["base"]},
        }
        out[f"{root}/commits/{e['head']}"] = {
            "sha": e["head"], "commit": {"tree": {"sha": e["tree"]}},
        }
        out[f"{root}/actions/runs/{run}"] = {
            "id": run, "head_sha": e["head"], "run_attempt": attempt,
            "event": "pull_request", "status": "completed", "conclusion": "success",
        }
        names = sorted(JOBS[repo]["success"] | JOBS[repo]["skipped"])
        jobs = [{
            "id": 9000 + i, "name": name, "run_id": run,
            "run_attempt": attempt, "status": "completed",
            "conclusion": "skipped" if name in JOBS[repo]["skipped"] else "success",
            "steps": [{"name": s, "conclusion": "success"}
                      for s in sorted(STEPS[repo].get(name, ()))],
        } for i, name in enumerate(names)]
        out[f"{root}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100"] = {
            "total_count": len(jobs), "jobs": jobs,
        }
        if repo == "roccho-dev/windows":
            older = copy.deepcopy(jobs)
            for job in older:
                job["id"] -= 1000
                job["run_attempt"] = 1
                if job["name"] == "dev / fresh-develop-replace-continue":
                    job["conclusion"] = "failure"
            out[f"{root}/actions/runs/{run}/attempts/1/jobs?per_page=100"] = {
                "total_count": len(older), "jobs": older,
            }
    return out


def files(snapshot):
    index = {x["repository"]: x for x in snapshot["entries"]}
    source = snapshot["producer"]["head"]
    w, e, r = (index["roccho-dev/windows"]["head"],
               index["roccho-org/envs"]["head"],
               index["roccho-dev/resources"]["head"])
    return {
        ("roccho-org/envs", e, snapshot["binding"]["path"]):
            F1.read_text(encoding="utf-8"),
        ("roccho-dev/windows", w, ".github/workflows/rent-image.yml"):
            (BINDING_URL + "\n"
             + f'test "$(git hash-object "$fixture")" = {snapshot["binding"]["blob"]}\n'
             + 'bash hosts/rent/native-proof.sh result-4 "$t0" "$t1" "$fixture"\n'),
        ("roccho-dev/resources", r, snapshot["relation"]["path"]):
            ("class ProposedRelationCases(unittest.TestCase):\n"
             "    def test_containment_cycles_self_and_multi_parent_refused_same_scope(self):\n"
             "        pass\n"
             '    proof = {"admission": "NOT_ADMITTED", "effect": "FORBIDDEN"}\n'),
        ("roccho-dev/resources", r, "nixos/flake.nix"):
            f'inputs.windows.url = "github:roccho-dev/windows/{source}";\n',
        ("roccho-dev/resources", r, "nixos/flake.lock"):
            json.dumps({"nodes": {"windows": {"original": {"rev": source},
                       "locked": {"rev": source, "narHash": "sha256-k1k3Y1DuOvXkpntXFyHGaw4ICJBJ1vlsBuDIVAF52nM="}}}}),
    }


class FrozenV6Source(unittest.TestCase):
    def setUp(self):
        self.snap = json.loads(SNAP.read_text(encoding="utf-8"))
        self.data = records(self.snap)
        self.sources = files(self.snap)

    def row(self, repo):
        return next(x for x in self.snap["entries"] if x["repository"] == repo)

    def jobs(self, repo):
        e = self.row(repo)
        return self.data[f"{API}/repos/{repo}/actions/runs/{e['run_id']}/attempts/{e['run_attempt']}/jobs?per_page=100"]["jobs"]

    def get(self, url):
        if url not in self.data:
            raise ProvenanceError("missing public source evidence")
        return self.data[url]

    def file(self, repo, head, path, getter, blob=None):
        value = self.sources.get((repo, head, path))
        if value is None:
            raise ProvenanceError("immutable source absent")
        if blob is not None and repo == "roccho-org/envs" and git_blob(value) != blob:
            raise ProvenanceError("F1 blob mismatched")
        if blob is not None and repo == "roccho-dev/resources" and blob != self.snap["relation"]["blob"]:
            raise ProvenanceError("Relation blob mismatched")
        return value

    def check(self):
        with patch("host_tool_v6_source_gate.real_file", side_effect=self.file):
            return verify(self.snap, self.get)

    def refuse(self):
        with self.assertRaises(ProvenanceError):
            self.check()

    def test_current_three_verified_without_admission(self):
        v = self.check()
        self.assertEqual(v["stage"], "V6_F1_F2_DISPOSABLE_SOURCE_EVIDENCE_VERIFIED")
        self.assertEqual(v["proposed_q"], json.loads(F1.read_text())["proposed_q"])
        self.assertTrue(v["previous_failed_dev_attempt_preserved"])
        self.assertEqual([(x["pr"], x["run_attempt"]) for x in v["entries"]],
                         [(19, 1), (93, 2), (90, 1)])
        self.assertEqual(v["admission"], "NOT_ADMITTED")
        self.assertIsNone(v["accepted_q"])
        self.assertEqual(v["target_observation"], "NOT_READ")
        self.assertEqual(v["target_noop"], "UNPROVEN")
        self.assertEqual(v["effect"], "FORBIDDEN")
        self.assertFalse(v["target_ready"] or v["real_composite_green"] or v["merge_ready"])

    def test_old_F1_F2_and_wrong_attempt_head_tree_base_refuse(self):
        for repo, changes in (
            ("roccho-org/envs", {"pr": 86}),
            ("roccho-dev/resources", {"pr": 17}),
            ("roccho-dev/windows", {"run_attempt": 1}),
            ("roccho-dev/windows", {"head": "f" * 40}),
            ("roccho-org/envs", {"tree": "f" * 40}),
            ("roccho-dev/resources", {"base": "f" * 40}),
        ):
            with self.subTest(repo=repo, changes=changes):
                self.setUp()
                self.row(repo).update(changes)
                self.refuse()

    def test_F1_F2_or_relation_critical_step_failed_skipped_missing_refuse(self):
        for repo, job_name, step in (
            ("roccho-dev/windows", "rent / build-test-publish",
             "Prove bound PROPOSED q/Host and actual native rent Tool/readonly O"),
            ("roccho-dev/windows", "dev / fresh-develop-replace-continue",
             "Prove actual development continues after replacement"),
            ("roccho-org/envs", "toolchain",
             "Prove current Host Relation / D-q integration on exact SOURCE head"),
            ("roccho-org/envs", "repository",
             "Prove real resources Relation and envs Tool q bind same CI Host"),
            ("roccho-dev/resources", "source-vm",
             "Test synthetic Host contains/manages/optional wrap (NOT_ADMITTED)"),
        ):
            for mode in ("failure", "skipped", "missing"):
                with self.subTest(repo=repo, step=step, mode=mode):
                    self.setUp()
                    job = next(j for j in self.jobs(repo) if j["name"] == job_name)
                    proof = next(s for s in job["steps"] if s["name"] == step)
                    if mode == "missing":
                        job["steps"].remove(proof)
                    else:
                        proof["conclusion"] = mode
                    self.refuse()

    def test_attempt_1_failure_must_remain_and_latest_retry_must_be_distinct(self):
        w = self.row("roccho-dev/windows")
        prefix = f"{API}/repos/roccho-dev/windows/actions/runs/{w['run_id']}"
        self.data[prefix]["run_attempt"] = 1
        self.refuse()
        self.setUp()
        old = self.data[prefix + "/attempts/1/jobs?per_page=100"]["jobs"]
        next(j for j in old if j["name"] == "dev / fresh-develop-replace-continue")["conclusion"] = "success"
        self.refuse()
        self.setUp()
        new_dev = next(j for j in self.jobs("roccho-dev/windows")
                       if j["name"] == "dev / fresh-develop-replace-continue")
        new_dev["id"] -= 1000
        self.refuse()

    def test_binding_q_wrong_producer_and_windows_blob_refuse(self):
        target = next(k for k in self.sources if k[0] == "roccho-org/envs")
        for mutation in (
            lambda x: x.update(admission="ADMITTED"),
            lambda x: x.update(proposed_q="sha256:" + "f" * 64),
            lambda x: x["material"].update(source_commit="f" * 40),
        ):
            self.setUp()
            target = next(k for k in self.sources if k[0] == "roccho-org/envs")
            obj = json.loads(self.sources[target])
            mutation(obj)
            self.sources[target] = json.dumps(obj) + "\n"
            self.refuse()
        self.setUp()
        win = next(k for k in self.sources if k[0] == "roccho-dev/windows")
        self.sources[win] = self.sources[win].replace(BINDING_URL, "foreign")
        self.refuse()
        self.setUp()
        win = next(k for k in self.sources if k[0] == "roccho-dev/windows")
        self.sources[win] = self.sources[win].replace(self.snap["binding"]["blob"], "f" * 40)
        self.refuse()

    def test_stale_resources_source_pin_and_relation_refuse(self):
        for suffix, value in (
            ("nixos/flake.nix", 'inputs.windows.url = "github:roccho-dev/windows/' + "f" * 40 + '";\n'),
            ("nixos/flake.lock", "{}"),
            ("host_relation_source.py", "class Bad: pass"),
        ):
            self.setUp()
            key = next(k for k in self.sources if k[0] == "roccho-dev/resources"
                       and k[2].endswith(suffix))
            self.sources[key] = value
            self.refuse()

    def test_missing_job_bad_PR_or_publish_effect_refuse(self):
        self.data[next(k for k in self.data if k.endswith("/pulls/93"))]["draft"] = False
        self.refuse()
        self.setUp()
        jobs = self.jobs("roccho-org/envs")
        next(j for j in jobs if j["name"] == "placement-publish")["conclusion"] = "success"
        self.refuse()
        self.setUp()
        self.jobs("roccho-dev/resources")[0]["conclusion"] = "failure"
        self.refuse()

    def test_git_blob_is_verified_independently_of_api_sha_label(self):
        sample = "SOURCE\n"
        contents = {"type": "file", "encoding": "base64",
                    "sha": git_blob(sample),
                    "content": base64.b64encode(sample.encode()).decode()}
        self.assertEqual(real_file("roccho-org/envs", "a" * 40,
                                   "checks/source.txt", lambda _: contents), sample)
        contents["sha"] = "f" * 40
        with self.assertRaises(ProvenanceError):
            real_file("roccho-org/envs", "a" * 40,
                      "checks/source.txt", lambda _: contents)


if __name__ == "__main__":
    unittest.main()
