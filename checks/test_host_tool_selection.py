#!/usr/bin/env python3
"""Finite, secret-free SOURCE tests for an unadmitted Host Tool D/q proposal."""
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("host_tool_selection_proposal",
                                               ROOT / "adapters/host_tool_selection.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def fixture():
    proposals = module.read_jsonl(ROOT / module.PROPOSALS)
    targets = module.read_jsonl(ROOT / module.TARGETS)
    return proposals, targets


class HostToolProposalTests(unittest.TestCase):
    def test_exact_source_is_inert_and_content_bound(self):
        before = [(path, (ROOT / path).read_bytes()) for path in (module.PROPOSALS, module.TARGETS)]
        rows = module.project_root(ROOT)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["target_ref"], "pc7337-rent")
        self.assertEqual(row["material"], {
            "repository": "roccho-dev/windows",
            "source_commit": "355b038bcbe2b24a8ad0121f79b7cc4c72b76b3f",
            "flake_output": "packages.x86_64-linux.rent-tool-profile",
        })
        self.assertEqual(row["kind"], module.FIXTURE_KIND)
        self.assertEqual(row["admission"], "NOT_ADMITTED")
        self.assertIsNone(row["accepted_q"])
        self.assertEqual(row["observation"], "NOT_READ")
        self.assertEqual(row["target_noop"], "UNPROVEN")
        self.assertEqual(row["effect"], "FORBIDDEN")
        self.assertRegex(row["proposed_q"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(before, [(path, (ROOT / path).read_bytes()) for path, _ in before])
        self.assertEqual(rows, module.project_root(ROOT))

    def test_revision_changes_with_target_or_material_but_not_key_order(self):
        p, targets = fixture()
        q1 = module.project(p, targets)[0]["proposed_q"]
        swapped = copy.deepcopy(p)
        swapped[0]["material"] = dict(reversed(list(swapped[0]["material"].items())))
        self.assertEqual(module.project(swapped, targets)[0]["proposed_q"], q1)
        changed = copy.deepcopy(p)
        changed[0]["material"]["source_commit"] = "f" * 40
        self.assertNotEqual(module.project(changed, targets)[0]["proposed_q"], q1)
        # A second target is an in-memory fixture, not a new accepted Host ID or catalog row.
        another = copy.deepcopy(targets[1])
        another["id"] = "fixture-rent-b"
        other_proposal = copy.deepcopy(p[0])
        other_proposal["id"] = "fixture-rent-b.host-tool-selection"
        other_proposal["target_ref"] = "fixture-rent-b"
        projected = module.project(p + [other_proposal], targets + [another])
        self.assertEqual([r["target_ref"] for r in projected],
                         ["fixture-rent-b", "pc7337-rent"])
        self.assertNotEqual(projected[0]["proposed_q"], projected[1]["proposed_q"])
        self.assertEqual(projected[1]["proposed_q"], q1)
        self.assertEqual(projected[0]["effect"], "FORBIDDEN")

    def test_unauthorized_status_fields_and_foreign_material_refused(self):
        p, targets = fixture()
        failures = (
            lambda x: x.update(admission="ADMITTED"),
            lambda x: x.update(admission="ACTIVE"),
            lambda x: x.update(kind="envs.hostToolSelection.v1"),
            lambda x: x.update(id="other-target.host-tool-selection"),
            lambda x: x.update(target_ref="not-declared"),
            lambda x: x.update(accepted_q="approved"),
            lambda x: x.update(observation="SELECTED"),
            lambda x: x.update(secret="PRIVATE_CANARY"),
            lambda x: x["material"].update(repository="untrusted/producer"),
            lambda x: x["material"].update(source_commit="main"),
            lambda x: x["material"].update(source_commit="A" * 40),
            lambda x: x["material"].update(flake_output="latest"),
            lambda x: x["material"].update(secret_name="PRIVATE_CANARY"),
        )
        for mutation in failures:
            case = copy.deepcopy(p)
            mutation(case[0])
            with self.subTest(case=mutation.__code__.co_firstlineno):
                with self.assertRaises(module.ProposalError):
                    module.project(case, targets)

    def test_duplicate_target_or_non_rent_consumer_refused(self):
        p, targets = fixture()
        with self.assertRaises(module.ProposalError):
            module.project(p + copy.deepcopy(p), targets)
        with self.assertRaises(module.ProposalError):
            module.project(p, targets + [copy.deepcopy(targets[1])])
        other = copy.deepcopy(p)
        other[0]["target_ref"] = "g6i3"
        other[0]["id"] = "g6i3.host-tool-selection"
        with self.assertRaises(module.ProposalError):
            module.project(other, targets)
        altered = copy.deepcopy(targets)
        altered[1]["observation_owner"] = "another-owner"
        with self.assertRaises(module.ProposalError):
            module.project(p, altered)

    def test_proposal_parser_strict_and_no_output_file(self):
        with tempfile.TemporaryDirectory(prefix="envs-tool-proposal-ci-") as temp:
            root = Path(temp)
            (root / module.PROPOSALS.parent).mkdir(parents=True)
            (root / module.TARGETS.parent).mkdir(parents=True, exist_ok=True)
            for name in (module.PROPOSALS, module.TARGETS):
                (root / name).write_bytes((ROOT / name).read_bytes())
            snapshot = sorted((p.relative_to(root).as_posix(), p.read_bytes())
                              for p in root.rglob("*") if p.is_file())
            self.assertEqual(module.project_root(root), module.project_root(ROOT))
            self.assertEqual(snapshot, sorted(
                (p.relative_to(root).as_posix(), p.read_bytes())
                for p in root.rglob("*") if p.is_file()))
            for invalid in ("", "{}\n\n", "{\"id\":\n", "{}"):
                (root / module.PROPOSALS).write_text(invalid, encoding="utf-8")
                with self.assertRaises(module.ProposalError):
                    module.project_root(root)


if __name__ == "__main__":
    unittest.main()
