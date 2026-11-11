"""Schema and mocked-plan checks only; never initialize a backend or call Cloudflare."""
from pathlib import Path
import argparse
import json
import os
import secrets
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tofu", required=True)
    parser.add_argument("--scratch-parent", type=Path)
    parser.add_argument("--allow-registry", action="store_true", help="Allow provider download during init only; mock tests remain offline")
    args = parser.parse_args()
    source = ROOT / "providers/ssh-browser-host"
    test = (source / "tests/browser.tftest.hcl").read_text()
    if 'mock_provider "cloudflare"' not in test or "command = apply" in test:
        raise RuntimeError("Mock-only plan tests required")
    parent = args.scratch_parent.resolve() if args.scratch_parent else Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="browser-ssh-check-", dir=parent) as folder:
        work = Path(folder).resolve()
        if not work.is_relative_to(parent):
            raise RuntimeError("Scratch escaped its intended parent")
        for name in ("main.tf", "variables.tf"):
            shutil.copyfile(source / name, work / name)
        shutil.copytree(source / "tests", work / "tests")
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("CF_", "CLOUDFLARE_", "TF_HTTP_", "TF_VAR_", "TF_CLI_ARGS", "TF_LOG")) and k.upper() not in {"TF_DATA_DIR", "TF_WORKSPACE", "TF_PLUGIN_CACHE_DIR", "TF_REATTACH_PROVIDERS"}}
        env["TF_IN_AUTOMATION"] = "true"
        # Ephemeral fixture custody, not a provider/backend/encryption credential from the environment.
        env["TF_ENCRYPTION"] = '''key_provider "pbkdf2" "fixture" {
  passphrase = "%s"
}
method "aes_gcm" "fixture" {
  keys = key_provider.pbkdf2.fixture
}
state {
  method = method.aes_gcm.fixture
  enforced = true
}
plan {
  method = method.aes_gcm.fixture
  enforced = true
}
''' % secrets.token_urlsafe(48)
        offline = dict(env, HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9", ALL_PROXY="http://127.0.0.1:9", NO_PROXY="", no_proxy="")
        for label, command, environment in (
            ("init", ["init", "-backend=false", "-input=false", "-no-color"], env if args.allow_registry else offline),
            ("format", ["fmt", "-check", "-recursive", "-no-color"], offline),
            ("validate", ["validate", "-json"], offline),
            ("mock_plan", ["test", "-filter=tests/browser.tftest.hcl", "-json"], offline),
        ):
            run = subprocess.run([args.tofu, *command], cwd=work, env=environment, capture_output=True, text=True, timeout=180)
            if run.returncode:
                # No real secrets or caller inputs are loaded; diagnostics concern the source and mock fixture.
                raise RuntimeError(label + " failed: " + (run.stdout + run.stderr)[-6000:])
    print(json.dumps({"native_schema": "PASS", "mock_plan_tests": "PASS", "backend": "NOT_INITIALIZED", "provider_apply": "NOT_RUN"}))


if __name__ == "__main__":
    main()
