"""Go target regression contract. No live values, provider calls or target writes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("jev", ROOT / "adapters/jev_api.py")
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)
TARGET = "opencode-go.versapro"
EXPECTED_TARGET = {"repository": "roccho-dev/resources", "host": "versapro", "kind": "pi_auth_command"}
RECIPIENT = {"name": "VERSAPRO_AGE_RECIPIENT", "type": "age_recipient", "lifecycle": "persistent"}


class GoVersaProTests(unittest.TestCase):
    def test_existing_contract_integrity(self):
        jev.validate_contracts(ROOT)

    def test_author_selects_both_targets(self):
        self.assertIn("opencode-go.oci-dev", jev.AUTHOR_TARGETS)
        self.assertIn(TARGET, jev.AUTHOR_TARGETS)

    def test_exact_target_binding(self):
        contracts = jev.validate_contracts(ROOT)
        self.assertIn(TARGET, contracts["bindings"])
        binding = contracts["bindings"][TARGET]
        self.assertEqual(binding["target"], EXPECTED_TARGET)
        self.assertEqual(binding["capability"], "opencode-go")
        self.assertEqual(binding["source_key"], "OPENCODE_API_KEY")
        self.assertEqual(binding["ciphertext"], "ciphertexts/dev-opencode-go.versapro.sops.yaml")
        self.assertEqual(binding["required_variables"], [RECIPIENT])

    def test_only_selected_inputs(self):
        entries = jev.authoring_inputs(jev.validate_contracts(ROOT), TARGET)
        self.assertEqual(entries, [
            {"name": "OPENCODE_API_KEY", "type": "opaque", "lifecycle": "one_shot_ingress"},
            RECIPIENT,
        ])

    def test_existing_oci_inputs_unchanged(self):
        entries = jev.authoring_inputs(jev.validate_contracts(ROOT), "opencode-go.oci-dev")
        self.assertEqual([entry["name"] for entry in entries], ["OPENCODE_API_KEY", "OCI_DEV_AGE_RECIPIENT"])

    def test_cli_selects_target_without_any_effect(self):
        result = subprocess.run([sys.executable, str(ROOT / "adapters/jev_api.py"), "author", "--help"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn(TARGET, result.stdout)

    def test_unknown_target_rejected_before_tools(self):
        with mock.patch.object(jev, "toolchain") as tools:
            with self.assertRaises(jev.EnvsError):
                jev.author_oci(ROOT, target="opencode-go.unknown")
            tools.assert_not_called()

    def test_invalid_recipient_does_not_run_sops(self):
        runner = mock.Mock()
        with self.assertRaises(jev.EnvsError):
            jev.encrypt_oci_key("dummy-for-test", "invalid", {"sops": "/not-used"}, runner,
                                key="OPENCODE_API_KEY")
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
