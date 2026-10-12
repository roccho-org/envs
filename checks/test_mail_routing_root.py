#!/usr/bin/env python3
"""M0 manual candidate: synthetic, source-only refusal proof. No real effects."""
from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters/mail_routing_root.py"
WORKFLOW = ROOT / ".github/workflows/operate-dev-mail-routing.yml"
CLOSED = {"kind": "envs.mailM0.manual.v1", "status": "INACTIVE", "effect": "NOT_RUN"}


def check_source() -> None:
    """Even a direct entry invocation has no input-reading or child path."""
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert {(type(n).__name__, getattr(n, "module", None),
             tuple(alias.name for alias in n.names)) for n in imports} == {
        ("ImportFrom", "__future__", ("annotations",)),
        ("Import", None, ("sys",)),
    }
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert sorted(ast.unparse(node.func) for node in calls) == ["main", "print", "sys.exit"]
    attrs = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
    assert attrs == ["sys.exit"]
    mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
    assert len(mains) == 1
    assert [ast.unparse(n) for n in mains[0].body] == [
        "print(CLOSED_RESULT)", "return EXIT_INACTIVE",
    ]
    code = ADAPTER.read_text(encoding="utf-8")
    assert 'EXIT_INACTIVE = 78' in code
    assert "CLOSED_RESULT = " in code


def check_native_entry() -> None:
    with tempfile.TemporaryDirectory(prefix="mail-m0-inactive-fixture-") as directory:
        home = Path(directory)
        child = home / "child-started"
        bin_dir = home / "bin"
        bin_dir.mkdir()
        for executable in ("tofu", "sops", "wrangler", "curl", "envs-effect"):
            path = bin_dir / executable
            path.write_text(f"#!/bin/sh\necho unexpected > '{child}'\nexit 0\n", encoding="utf-8")
            path.chmod(stat.S_IRWXU)

        env = dict(os.environ)
        marker = "PRIVATE_FIXTURE_MUST_NOT_LEAK"
        env.update({
            "PATH": str(bin_dir),
            "CLOUDFLARE_API_TOKEN": marker,
            "AWS_ACCESS_KEY_ID": marker,
            "AWS_SECRET_ACCESS_KEY": marker,
            "RENT_STATE_PASSPHRASE": marker,
            "RENT_STATE_KEY": marker,
            "TF_ENCRYPTION": marker,
            "MAIL_M0_ENABLE": "true",
            "MAIL_M0_PLAN": "apply",
        })
        for argv in ([], ["--activate"], ["plan", "-backend-config=PRIVATE"], ["apply", "--auto-approve"]):
            done = subprocess.run(
                [sys.executable, "-I", str(ADAPTER), *argv],
                cwd=home, env=env, capture_output=True, text=True, timeout=6, check=False,
            )
            assert done.returncode == 78, "inactive adapter must reject every argv"
            assert done.stderr == "", "no tracebacks or credential-bearing diagnostics"
            assert json.loads(done.stdout) == CLOSED
            assert done.stdout == json.dumps(CLOSED, separators=(",", ":")) + "\n"
            assert marker not in done.stdout
            assert not child.exists(), "a child ran before the independent source refusal"
        assert sorted(p.name for p in home.iterdir()) == ["bin"], "unexpected state/output file"


def check_job_disabled() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    gate = "    if: ${{ false && github.repository == 'roccho-org/envs'"
    assert content.count(gate) == 1
    assert content.index(gate) < content.index("    environment: dev-rent-tunnel") < content.index("    steps:")
    assert content.count("    if:") == 1
    assert "on:\n  workflow_dispatch:" in content
    assert "      expected_source_sha:" in content
    assert "${{ secrets." not in content and "${{ vars." not in content
    assert "    needs:" not in content
    assert content.count("run: '\"$ENVS_EFFECT_BIN/mail-routing-root\"'") == 1


def main() -> None:
    check_source()
    check_native_entry()
    check_job_disabled()
    print("mail M0 manual hard-inactive source/CLI test: PASS; no child or protected input")


if __name__ == "__main__":
    main()
