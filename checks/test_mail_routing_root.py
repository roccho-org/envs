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
    """The real CLI stays a literal direct refusal despite source helpers."""
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    modules = {(node.module if isinstance(node, ast.ImportFrom) else node.names[0].name)
               for node in imports}
    assert modules == {"__future__", "sys", "dataclasses", "hashlib", "re", "pathlib", "typing"}
    main_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    assert len(main_functions) == 1
    assert [ast.unparse(node) for node in main_functions[0].body] == [
        "print(CLOSED_RESULT)", "return EXIT_INACTIVE",
    ]
    # There must be no import-time function calls other than the normal
    # guarded __main__ exit. Named native helpers are inert definitions.
    for node in tree.body:
        assert isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign,
                                 ast.AnnAssign, ast.ClassDef, ast.FunctionDef, ast.If, ast.Expr))
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        if isinstance(node, ast.If):
            assert ast.unparse(node.test) == "__name__ == '__main__'"
            assert [ast.unparse(statement) for statement in node.body] == ["sys.exit(main())"]
    code = ADAPTER.read_text(encoding="utf-8")
    assert 'EXIT_INACTIVE = 78' in code and "CLOSED_RESULT = " in code
    assert "import os" not in code and "import subprocess" not in code
    assert "os.environ" not in code and "open(" not in code


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


def check_native_source_and_plan() -> None:
    """Meaningful synthetic native command/data contracts, not merely markers."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("mail_native", ADAPTER)
    assert spec is not None and spec.loader is not None
    mail = importlib.util.module_from_spec(spec)
    # Dataclass module lookup needs a real sys.modules entry during exec.
    sys.modules[spec.name] = mail
    try:
        spec.loader.exec_module(mail)
        with tempfile.TemporaryDirectory(prefix="mail-m0-native-fixture-") as temp:
            home = Path(temp)
            ops = home / "ops-mail-root"
            ops.mkdir()
            body = b"synthetic ops native source, never a real Cloudflare resource\n"
            lock = b"synthetic ops provider lock\n"
            (ops / "main.tf").write_bytes(body)
            (ops / ".terraform.lock.hcl").write_bytes(lock)
            native = (mail.OPS_MAIN_BLOB, mail.OPS_LOCK_BLOB)
            assert mail.OPS_MAIL_COMMIT == "618440c68400bd21f253d0a77027ce4021fe1e33"
            assert mail.OPS_MAIL_TREE == "9cd1757a42bd8a5ae7e43add7dfffe46694f9c2d"
            assert native == ("bf7d90ddd1c2a2b63e47ece40b5409e24ca9b125",
                              "4994a1a2967771935c94bcca83752ffebe78e2ff")
            try:
                mail.OPS_MAIN_BLOB = mail.git_blob(body)
                mail.OPS_LOCK_BLOB = mail.git_blob(lock)
                mail.verify_native_source(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE)
                for wrong_commit, wrong_tree in (("0" * 40, mail.OPS_MAIL_TREE),
                                                 (mail.OPS_MAIL_COMMIT, "0" * 40)):
                    try:
                        mail.verify_native_source(ops, wrong_commit, wrong_tree)
                        raise AssertionError("foreign ops source was accepted")
                    except mail.NativeSourceHold:
                        pass
                (ops / "main.tf").write_bytes(body + b"modified\n")
                try:
                    mail.verify_native_source(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE)
                    raise AssertionError("changed native source accepted")
                except mail.NativeSourceHold:
                    pass
                (ops / "main.tf").write_bytes(body)
                (ops / ".terraform.lock.hcl").unlink()
                (ops / ".terraform.lock.hcl").symlink_to(ops / "main.tf")
                try:
                    mail.verify_native_source(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE)
                    raise AssertionError("symlink native lock accepted")
                except mail.NativeSourceHold:
                    pass
            finally:
                mail.OPS_MAIN_BLOB, mail.OPS_LOCK_BLOB = native

            tofu = "/nix/store/" + "a" * 32 + "-opentofu-with-plugins/bin/tofu"
            curl = "/nix/store/" + "b" * 32 + "-curl/bin/curl"
            private = home / "private"
            init = mail.native_init(tofu, ops, private / "backend.hcl")
            planned = mail.native_plan(tofu, ops, private / "saved-plan.enc")
            inspect = mail.native_inspect(tofu, ops, private / "reviewed-original.enc")
            apply = mail.native_apply(tofu, ops, private / "reviewed-original.enc")
            assert init.argv[2:4] == ("init", "-input=false") and "-lockfile=readonly" in init.argv
            assert planned.argv[2:4] == ("plan", "-input=false") and "-lock=true" in planned.argv
            assert planned.argv[-1] == "-out=" + str(private / "saved-plan.enc")
            assert inspect.argv[-3:] == ("show", "-json", "-plan=" + str(private / "reviewed-original.enc"))
            assert apply.argv[-4:] == ("apply", "-input=false", "-lock=true",
                                        str(private / "reviewed-original.enc"))
            assert all("--auto-approve" not in c.argv and "-destroy" not in c.argv
                       for c in (init, planned, inspect, apply))
            assert planned.argv != apply.argv and planned.argv[-1] != apply.argv[-1]
            for not_nix in ("/usr/bin/tofu", "/tmp/private/bin/tofu", tofu.replace("tofu", "curl")):
                try:
                    mail.native_plan(not_nix, ops, private / "saved-plan.enc")
                    raise AssertionError("ambient native tool accepted")
                except mail.NativeSourceHold:
                    pass

            etag = '"original-r2-etag1234"'
            store_args = dict(curl=curl, account="a" * 32, bucket="mail-fixture-private",
                              key="mail-m0/plans/source/fixture-001", headers=private / "headers",
                              access_id="fixture-access", access_secret="fixture-secret")
            put = mail.private_r2_object(method="PUT", source_or_dest=private / "saved-plan.enc", **store_args)
            head = mail.private_r2_object(method="HEAD", source_or_dest=private / "ignored", etag=etag, **store_args)
            get = mail.private_r2_object(method="GET", source_or_dest=private / "reviewed-original.enc", etag=etag,
                                         **store_args)
            for item in (put, head, get):
                assert item.argv == (curl, "-q", "--config", "-")
                assert b'aws-sigv4 = "aws:amz:auto:s3"' in item.stdin
                assert b'proto = "=https"' in item.stdin
                assert b'noproxy = "*"' in item.stdin and b'proxy = ""' in item.stdin
                assert "fixture-secret" not in " ".join(item.argv)
                assert b"--auto-approve" not in item.stdin
            assert b"If-None-Match: *" in put.stdin and b"If-Match" not in put.stdin
            assert b'If-Match: ' + etag.encode() in head.stdin
            assert b'If-Match: ' + etag.encode() in get.stdin
            assert b'upload-file = ' in put.stdin
            assert b'output = ' in get.stdin
            for method, tag in (("PUT", etag), ("GET", None), ("HEAD", None)):
                if method == "PUT":
                    continue
                try:
                    mail.private_r2_object(method=method, source_or_dest=private / "original",
                                           etag=tag, **store_args)
                    raise AssertionError("unbound private original read accepted")
                except mail.NativeSourceHold:
                    pass
            assert mail.private_etag(b'HTTP/1.1 200 OK\r\nETag: ' + etag.encode() + b'\r\n\r\n') == etag
            for bad in (b'HTTP/1.1 302 Found\r\nETag: "x"\r\n',
                        b'HTTP/1.1 200 OK\r\n',
                        b'HTTP/1.1 200 OK\r\nETag: "a"\r\nETag: "b"\r\n',
                        b'HTTP/1.1 200 OK\r\nETag: private-token\r\n'):
                try:
                    mail.private_etag(bad)
                    raise AssertionError("unproven native ETag accepted")
                except mail.NativeSourceHold:
                    pass

            mail.require_same_original(stored_etag=etag, owner_readback=etag,
                                       fixed_r_readback=etag, before_apply=etag)
            for wrong_field in ("owner_readback", "fixed_r_readback", "before_apply"):
                values = dict(stored_etag=etag, owner_readback=etag,
                              fixed_r_readback=etag, before_apply=etag)
                values[wrong_field] = '"different-r2-original"'
                try:
                    mail.require_same_original(**values)
                    raise AssertionError("changed/unreviewed original accepted")
                except mail.NativeSourceHold:
                    pass

            # Real SOURCE functions do meaningful native sequencing under
            # synthetic runner control; none has a production executable or
            # permission path from the committed CLI.
            (ops / ".terraform.lock.hcl").unlink()
            (ops / ".terraform.lock.hcl").write_bytes(lock)
            mail.OPS_MAIN_BLOB, mail.OPS_LOCK_BLOB = mail.git_blob(body), mail.git_blob(lock)
            events: list[mail.NativeCommand] = []
            header_bytes = ('HTTP/1.1 200 OK\r\nETag: ' + etag + '\r\n\r\n').encode()

            def fake_native(command: mail.NativeCommand) -> mail.PrivateNativeResult:
                events.append(command)
                if command.argv[0].endswith("/bin/curl"):
                    return mail.PrivateNativeResult(0, header_bytes)
                return mail.PrivateNativeResult(0)

            try:
                mail.plan_private_once(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                                       tofu, private / "saved-plan.enc", fake_native)
                assert len(events) == 1 and events[-1].argv[2] == "plan"
                opaque = mail.retain_original_once(curl, store_args["account"],
                    store_args["bucket"], store_args["key"], private / "saved-plan.enc",
                    private / "headers", "fixture-access", "fixture-secret", fake_native)
                assert opaque == etag and len(events) == 2
                mail.inspect_original_once(curl, tofu, ops, store_args["account"],
                    store_args["bucket"], store_args["key"], private / "reviewed-original.enc",
                    private / "headers", "fixture-access", "fixture-secret", opaque, fake_native)
                assert len(events) == 4 and events[-2].argv[0] == curl
                assert events[-1].argv[2] == "show"
                mail.apply_same_original_once(curl, tofu, ops, store_args["account"],
                    store_args["bucket"], store_args["key"], private / "reviewed-original.enc",
                    private / "headers", "fixture-access", "fixture-secret",
                    etag, etag, etag, etag, fake_native)
                assert [x.argv[2] if x.argv[0] == tofu else "s3" for x in events[-3:]] == [
                    "s3", "s3", "apply",
                ]

                before = len(events)
                try:
                    mail.apply_same_original_once(curl, tofu, ops, store_args["account"],
                        store_args["bucket"], store_args["key"], private / "reviewed-original.enc",
                        private / "headers", "fixture-access", "fixture-secret",
                        etag, etag, '"not-fixed-r-reviewed"', etag, fake_native)
                    raise AssertionError("apply ran without matching independent review")
                except mail.NativeSourceHold:
                    pass
                assert len(events) == before

                def mismatched_native(command: mail.NativeCommand) -> mail.PrivateNativeResult:
                    events.append(command)
                    return mail.PrivateNativeResult(
                        0, b'HTTP/1.1 200 OK\r\nETag: "changed-object"\r\n\r\n'
                    )
                try:
                    mail.apply_same_original_once(curl, tofu, ops, store_args["account"],
                        store_args["bucket"], store_args["key"], private / "reviewed-original.enc",
                        private / "headers", "fixture-access", "fixture-secret",
                        etag, etag, etag, etag, mismatched_native)
                    raise AssertionError("changed R2 object entered exact apply")
                except mail.NativeSourceHold:
                    pass
                assert len(events) == before + 1 and events[-1].argv[0] == curl
            finally:
                mail.OPS_MAIN_BLOB, mail.OPS_LOCK_BLOB = native

    finally:
        sys.modules.pop(spec.name, None)


def main() -> None:
    check_source()
    check_native_entry()
    check_job_disabled()
    check_native_source_and_plan()
    print("mail M0 native source/conditional-original and hard-inactive CLI test: PASS; no effects")


if __name__ == "__main__":
    main()
