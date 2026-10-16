#!/usr/bin/env python3
"""Actual accepted envs projection refuses Host Tool D/admission without owner meaning."""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "adapters/contract_projection.py"
SPEC = importlib.util.spec_from_file_location("accepted_contract_projection", SRC)
assert SPEC and SPEC.loader
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)


class OrdinaryEntryFailClosed(unittest.TestCase):
    def test_unadmitted_proposal_is_not_an_accepted_contract_or_effect(self):
        proposals = (ROOT / "contracts/proposals/host-tool-selection.jsonl").read_text()
        candidate = json.loads(proposals)
        self.assertEqual(candidate["admission"], "NOT_ADMITTED")
        self.assertNotIn("accepted_q", candidate)
        self.assertEqual(candidate["kind"], "envs.hostToolSelectionProposal.v0")
        bindings = (ROOT / "contracts/bindings.jsonl").read_text()
        consumers = (ROOT / "contracts/provider-consumer.jsonl").read_text()
        # Current accepted contracts have NO Host Tool D/current revision.
        self.assertNotIn("hostToolSelectionProposal", bindings)
        self.assertNotIn("hostToolSelectionProposal", consumers)
        self.assertNotIn("hostToolSelection.v1", bindings)
        # Normal projection of the real accepted input remains well-formed with no effect.
        normal = projection.project(bindings, consumers, {"obligations": []}, "a" * 40)
        self.assertEqual(normal["rows"], [])
        self.assertNotIn("accepted_q", normal)
        self.assertNotIn("effect", normal)
        self.assertNotIn("target_success", normal)

    def test_forged_tool_admission_into_ordinary_bindings_is_rejected(self):
        bindings = (ROOT / "contracts/bindings.jsonl").read_text()
        consumers = (ROOT / "contracts/provider-consumer.jsonl").read_text()
        forged = {
            "id": "pc7337-rent.host-tool-selection",
            "kind": "envs.hostToolSelection.v1",
            "admission": "ADMITTED",
            "target_ref": "pc7337-rent",
            "store_path": "/nix/store/" + "a" * 32 + "-fake",
        }
        with self.assertRaisesRegex(ValueError, "public row kind"):
            projection.project(bindings + json.dumps(forged) + "\n", consumers,
                               {"obligations": []}, "a" * 40)
        # Insertion via an existing authCapability row must also not grant Tool selection.
        forged["kind"] = "envs.authCapability.v1"
        with self.assertRaises(ValueError):
            projection.project(bindings + json.dumps(forged) + "\n", consumers,
                               {"obligations": []}, "a" * 40)

    def test_forged_tool_consumer_in_normal_projection_is_rejected(self):
        bindings = (ROOT / "contracts/bindings.jsonl").read_text()
        consumers = (ROOT / "contracts/provider-consumer.jsonl").read_text()
        forged = {"id": "host.tool.consumer", "kind": "envs.hostToolConsumer.v1",
                  "admission": "ADMITTED", "target_ref": "pc7337-rent"}
        with self.assertRaisesRegex(ValueError, "public row kind"):
            projection.project(bindings, consumers + json.dumps(forged) + "\n",
                               {"obligations": []}, "a" * 40)

    def test_existing_provider_and_projection_do_not_import_fixture_candidate(self):
        for name in ("contract_projection.py", "jev_api.py"):
            source = (ROOT / "adapters" / name).read_text(encoding="utf-8")
            for module in ("host_tool_guard", "host_tool_continuation",
                           "host_tool_selection", "test_host_tool_transition_sut"):
                self.assertNotIn(f"import {module}", source)
                self.assertNotIn(f"from {module} import", source)


if __name__ == "__main__":
    unittest.main()
