#!/usr/bin/env python3
"""M0 manual candidate: synthetic, source-only refusal proof. No real effects."""
from __future__ import annotations

import ast
import http.server
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
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
    assert modules == {"__future__", "sys", "importlib.util", "dataclasses",
                       "hashlib", "re", "pathlib", "typing"}
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
    """Synthetic serial SOURCE stages, refusals and immutable native input."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("mail_native", ADAPTER)
    assert spec is not None and spec.loader is not None
    mail = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mail
    try:
        spec.loader.exec_module(mail)
        with tempfile.TemporaryDirectory(prefix="mail-m0-native-fixture-") as directory:
            home = Path(directory)
            ops = home / "ops-mail-root"
            ops.mkdir()
            main_bytes = b"accepted synthetic main tf; not real Cloudflare resource\n"
            lock_bytes = b"accepted synthetic provider lock\n"
            readme_bytes = b"accepted synthetic operator README\n"
            test_bytes = b"accepted synthetic native test file\n"
            fixtures = {
                "main.tf": ("OPS_MAIN_BLOB", main_bytes),
                ".terraform.lock.hcl": ("OPS_LOCK_BLOB", lock_bytes),
                "README.md": ("OPS_README_BLOB", readme_bytes),
                "safety.tftest.hcl": ("OPS_TEST_BLOB", test_bytes),
            }
            original_blobs = {attr: getattr(mail, attr) for attr, _ in fixtures.values()}
            try:
                assert mail.OPS_MAIL_COMMIT == "618440c68400bd21f253d0a77027ce4021fe1e33"
                assert mail.OPS_MAIL_TREE == "9cd1757a42bd8a5ae7e43add7dfffe46694f9c2d"
                for name, (attr, data) in fixtures.items():
                    (ops / name).write_bytes(data)
                    setattr(mail, attr, mail.git_blob(data))

                def verify() -> None:
                    mail.verify_native_source(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE)

                def must_refuse(action, label: str) -> None:
                    try:
                        action()
                        raise AssertionError("SOURCE admitted " + label)
                    except mail.NativeSourceHold:
                        pass

                verify()
                # All other native Terraform input/override variants refuse.
                for extra in ("extra.tf", "override.tf", "main_override.tf",
                              "shadow.tofu", "shadow.tf.json", "shadow.tofu.json",
                              "terraform.tfvars", "x.auto.tfvars", "x.auto.tfvars.json",
                              ".terraform.tfstate", "foreign.lock", "README.bak"):
                    (ops / extra).write_text("synthetic unapproved input\n", encoding="utf-8")
                    must_refuse(verify, extra)
                    (ops / extra).unlink()
                cache = ops / ".terraform"
                cache.mkdir()
                verify()  # Native-init cache is separate from effective source.
                cache.rmdir()
                cache.symlink_to(home)
                must_refuse(verify, "symlink .terraform cache")
                cache.unlink()
                shadow = home / "symlink-root"
                shadow.symlink_to(ops, target_is_directory=True)
                must_refuse(lambda: mail.verify_native_source(
                    shadow, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                ), "symlink root")
                shadow.unlink()
                for name in fixtures:
                    saved = (ops / name).read_bytes()
                    (ops / name).write_bytes(saved + b"malicious modification\n")
                    must_refuse(verify, "changed accepted blob " + name)
                    (ops / name).write_bytes(saved)
                for wrong_c, wrong_t in (
                    ("0" * 40, mail.OPS_MAIL_TREE), (mail.OPS_MAIL_COMMIT, "0" * 40),
                ):
                    must_refuse(lambda: mail.verify_native_source(ops, wrong_c, wrong_t),
                                "foreign source identity")
                # Accepted source (main/lock) is required. Supplementary
                # nonactive source files may be absent in a private root.
                (ops / "README.md").unlink()
                (ops / "safety.tftest.hcl").unlink()
                verify()

                tofu = "/nix/store/" + "a" * 32 + "-opentofu-with-plugins/bin/tofu"
                curl = "/nix/store/" + "b" * 32 + "-curl/bin/curl"
                tools = mail.NativeToolset(tofu=tofu, curl=curl)
                private = home / "private"
                backend = private / "backend.hcl"
                saved_plan = private / "saved-plan.enc"
                original = private / "reviewed-original.enc"
                headers = private / "headers"

                init = mail.native_init(tofu, ops, backend, tools)
                planned = mail.native_plan(tofu, ops, saved_plan, tools)
                inspect = mail.native_inspect(tofu, ops, original, tools)
                apply = mail.native_apply(tofu, ops, original, tools)
                assert init.argv[2:4] == ("init", "-input=false") and "-lockfile=readonly" in init.argv
                assert planned.argv[2:4] == ("plan", "-input=false") and "-lock=true" in planned.argv
                assert planned.argv[-1] == "-out=" + str(saved_plan)
                assert inspect.argv[-3:] == ("show", "-json", "-plan=" + str(original))
                assert apply.argv[-4:] == ("apply", "-input=false", "-lock=true", str(original))
                assert all("--auto-approve" not in x.argv and "-destroy" not in x.argv
                           for x in (init, planned, inspect, apply))
                assert planned.argv != apply.argv
                forged = "/nix/store/" + "0" * 32 + "-unrelated/bin/tofu"
                for other in (forged, "/usr/bin/tofu", "/tmp/private/bin/tofu",
                              tofu.replace("/bin/tofu", "/bin/curl")):
                    must_refuse(lambda other=other: mail.native_plan(other, ops, saved_plan, tools),
                                "unselected binary")
                must_refuse(lambda: mail.native_plan(tofu, ops, saved_plan,
                                                    mail.NativeToolset(tofu=curl, curl=tofu)),
                            "tool mapping mismatched")

                etag = '"original-r2-etag1234"'
                store = dict(curl=curl, account="a" * 32, bucket="mail-fixture-private",
                             key="mail-m0/plans/source/fixture-001", headers=headers,
                             access_id="fixture-access", access_secret="fixture-secret",
                             tools=tools)
                put = mail.private_r2_object(method="PUT", source_or_dest=saved_plan, **store)
                head = mail.private_r2_object(method="HEAD", source_or_dest=private / "ignored",
                                             etag=etag, **store)
                get = mail.private_r2_object(method="GET", source_or_dest=original, etag=etag, **store)
                for cmd in (put, head, get):
                    assert cmd.argv == (curl, "-q", "--config", "-")
                    assert b'aws-sigv4 = "aws:amz:auto:s3"' in cmd.stdin
                    assert b'proto = "=https"' in cmd.stdin
                    assert b'noproxy = "*"' in cmd.stdin and b'proxy = ""' in cmd.stdin
                    assert b"fixture-secret" not in " ".join(cmd.argv).encode()
                assert b'If-None-Match: *' in put.stdin
                exact_header = ("header = " + mail._quote("If-Match: " + etag)).encode()
                assert exact_header in head.stdin and exact_header in get.stdin
                assert b"\nhead\n" in head.stdin  # Native -I, not only -X HEAD.
                assert b"\nhead\n" not in get.stdin and b"\nhead\n" not in put.stdin
                assert b'upload-file = ' in put.stdin and b'output = ' in get.stdin
                for method in ("HEAD", "GET"):
                    must_refuse(lambda method=method: mail.private_r2_object(
                        method=method, source_or_dest=original, etag=None, **store,
                    ), "missing ETag")
                assert mail.private_etag(b'HTTP/1.1 200 OK\r\nETag: ' + etag.encode() + b'\r\n\r\n') == etag
                for bad in (b'HTTP/1.1 302 Found\r\nETag: "x"\r\n',
                            b'HTTP/1.1 200 OK\r\n',
                            b'HTTP/1.1 200 OK\r\nETag: "a"\r\nETag: "b"\r\n',
                            b'HTTP/1.1 200 OK\r\nETag: fixture-secret\r\n'):
                    must_refuse(lambda bad=bad: mail.private_etag(bad), "unproven ETag")
                for wrong in ("owner_readback", "fixed_r_readback", "before_apply"):
                    tags = dict(stored_etag=etag, owner_readback=etag,
                                fixed_r_readback=etag, before_apply=etag)
                    tags[wrong] = '"other-r2-original"'
                    must_refuse(lambda tags=tags: mail.require_same_original(**tags),
                                "missing independent original")

                events: list[mail.NativeCommand] = []
                response_headers = ('HTTP/1.1 200 OK\r\nETag: ' + etag + '\r\n\r\n').encode()

                def synthetic_runner(command: mail.NativeCommand) -> mail.PrivateNativeResult:
                    events.append(command)
                    if command.argv[0] == curl:
                        return mail.PrivateNativeResult(0, response_headers)
                    return mail.PrivateNativeResult(0)

                mail.plan_private_once(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                                       tofu, backend, saved_plan, tools, synthetic_runner)
                assert [cmd.argv[2] for cmd in events] == ["init", "plan"]
                opaque = mail.retain_original_once(curl, store["account"], store["bucket"],
                    store["key"], saved_plan, headers, "fixture-access", "fixture-secret",
                    synthetic_runner, tools)
                assert opaque == etag and len(events) == 3
                mail.inspect_original_once(curl, tofu, ops, store["account"], store["bucket"],
                    store["key"], original, headers, "fixture-access", "fixture-secret",
                    opaque, synthetic_runner, tools)
                assert len(events) == 5
                assert events[-2].argv[0] == curl and events[-1].argv[2] == "show"
                mail.apply_same_original_once(curl, tofu, ops, store["account"],
                    store["bucket"], store["key"], original, headers, "fixture-access",
                    "fixture-secret", etag, etag, etag, etag, synthetic_runner, tools)
                assert len(events) == 8
                assert [cmd.argv[2] if cmd.argv[0] == tofu else "s3" for cmd in events[-3:]] == [
                    "s3", "s3", "apply",
                ]
                for source_change in ("extra.tf", "override.tf"):
                    (ops / source_change).write_text("unaccepted\n", encoding="utf-8")
                    before = len(events)
                    must_refuse(lambda: mail.inspect_original_once(
                        curl, tofu, ops, store["account"], store["bucket"], store["key"],
                        original, headers, "fixture-access", "fixture-secret",
                        etag, synthetic_runner, tools,
                    ), "read changed source")
                    must_refuse(lambda: mail.apply_same_original_once(
                        curl, tofu, ops, store["account"], store["bucket"], store["key"],
                        original, headers, "fixture-access", "fixture-secret",
                        etag, etag, etag, etag, synthetic_runner, tools,
                    ), "apply changed source")
                    assert len(events) == before, "source drift started an effect"
                    (ops / source_change).unlink()
                before = len(events)
                must_refuse(lambda: mail.apply_same_original_once(
                    curl, tofu, ops, store["account"], store["bucket"], store["key"],
                    original, headers, "fixture-access", "fixture-secret",
                    etag, etag, '"not-reviewed"', etag, synthetic_runner, tools,
                ), "missing fixed R review")
                assert len(events) == before
                def mismatched_runner(cmd: mail.NativeCommand) -> mail.PrivateNativeResult:
                    events.append(cmd)
                    return mail.PrivateNativeResult(
                        0, b'HTTP/1.1 200 OK\r\nETag: "changed-object"\r\n\r\n',
                    )
                must_refuse(lambda: mail.apply_same_original_once(
                    curl, tofu, ops, store["account"], store["bucket"], store["key"],
                    original, headers, "fixture-access", "fixture-secret",
                    etag, etag, etag, etag, mismatched_runner, tools,
                ), "changed native object")
                assert len(events) == before + 1 and events[-1].argv[0] == curl
            finally:
                for name, val in original_blobs.items():
                    setattr(mail, name, val)
    finally:
        sys.modules.pop(spec.name, None)


def check_provided_native_toolchain() -> None:
    """Source-only proof from actual Nix artifact and local HEAD fixture."""
    entry = os.environ.get("MAIL_TEST_TOOLCHAIN_ENTRY")
    if not entry:
        # Host-side repository job has no Nix closure. Toolchain job MUST
        # set this explicitly to independently prove real provided identity.
        return
    import importlib.util

    spec = importlib.util.spec_from_file_location("mail_native_real", ADAPTER)
    assert spec is not None and spec.loader is not None
    mail = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mail
    try:
        spec.loader.exec_module(mail)
        # Existing accepted envs-effect CLI authenticates its own exact
        # source-bound Nix manifest; no new identity format/protocol/registry.
        process = subprocess.run([entry, "--root", str(ROOT), "toolchain"],
                                 capture_output=True, text=True, check=False, timeout=15)
        assert process.returncode == 0 and process.stderr == ""
        from_existing = json.loads(process.stdout)
        assert from_existing["source"] and len(from_existing["source"]) == 40
        selection = mail.provided_native_tools(
            ROOT, from_existing["manifest"], os.path.realpath(sys.executable),
        )
        assert selection.tofu == from_existing["tools"]["tofu"]
        assert selection.curl == from_existing["tools"]["curl"]
        assert mail.native_bin(selection.tofu, "tofu", selection) == selection.tofu
        assert mail.native_bin(selection.curl, "curl", selection) == selection.curl
        fake_nix = "/nix/store/" + "0" * 32 + "-other/bin/tofu"
        try:
            mail.native_bin(fake_nix, "tofu", selection)
            raise AssertionError("forged Nix path was treated as selected")
        except mail.NativeSourceHold:
            pass
        for binary, opt, mark in (
            (selection.tofu, "version", "OpenTofu v1.12.3"),
            (selection.curl, "--version", "curl 8.21.0"),
        ):
            completed = subprocess.run([binary, opt], capture_output=True, text=True,
                                       check=False, timeout=15)
            assert completed.returncode == 0 and mark in completed.stdout
        class HeaderWithoutBody(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_HEAD(self) -> None:
                self.send_response(200)
                self.send_header("Content-Length", "8192")
                self.send_header("ETag", '"synthetic-original"')
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HeaderWithoutBody)
        loop = threading.Thread(target=server.serve_forever, daemon=True)
        loop.start()
        try:
            address = "http://127.0.0.1:" + str(server.server_port) + "/"
            cmd = [selection.curl, "-q", "--silent", "--show-error",
                   "--head", "--request", "HEAD", "--max-time", "3",
                   "--noproxy", "*", address]
            got = subprocess.run(cmd, capture_output=True, text=True,
                                 check=False, timeout=6)
            assert got.returncode == 0 and "8192" in got.stdout
            assert '"synthetic-original"' in got.stdout
        finally:
            server.shutdown()
            server.server_close()
            loop.join(timeout=3)
    finally:
        sys.modules.pop(spec.name, None)


def main() -> None:
    check_source()
    check_native_entry()
    check_job_disabled()
    check_native_source_and_plan()
    check_provided_native_toolchain()
    print("mail M0 native source/closed-root/pinned-tool/conditional-original and hard-inactive CLI test: PASS; no effects")


if __name__ == "__main__":
    main()
