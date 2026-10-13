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
                       "hashlib", "re", "pathlib", "typing", "os", "signal",
                       "stat", "subprocess", "json", "types"}
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
    assert code.count("import os\n") == code.count("import subprocess\n") == 1
    assert "os.environ" not in code
    # Real SOURCE-only runner definitions may use subprocess; actual main()
    # stays the two AST statements above and has no reachable activation.


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
                tools = mail.NativeToolset(tofu=tofu, curl=curl, _proof=mail._NATIVE_TOOL_PROOF)
                must_refuse(lambda: mail.native_bin(tofu, "tofu", mail.NativeToolset(tofu=tofu, curl=curl)),
                            "unverified toolset constructor")
                private = home / "private"
                backend = private / "backend.hcl"
                saved_plan = private / "saved-plan.enc"
                original = private / "reviewed-original.enc"
                headers = private / "headers"
                review_json = private / "review-original.json"
                captured_stdout = private / "show.stdout"
                captured_stderr = private / "show.stderr"

                # Every future protected native command requires two explicit
                # distinct private output destinations, including preflight
                # stages that can print human-readable target/plan metadata.
                sink_names = (
                    "init", "plan", "put", "get", "show", "head",
                    "apply_get", "apply",
                )
                sinks = {name: (private / (name + ".stdout"),
                                private / (name + ".stderr"))
                         for name in sink_names}
                captured_stdout, captured_stderr = sinks["show"]

                # Exercise the actual private subprocess Popen/communicate/
                # private capture implementation with an OFFLINE synthetic
                # child, never a provider or Owner key. Native command/source
                # identity is still verified before any child can start.
                private.mkdir(mode=0o700)
                backend.write_text(
                    'bucket = "mail-state-fixture"\n'
                    'key = "mail-m0/state/fixture.tfstate"\n'
                    'endpoints = { s3 = "https://' + "a" * 32
                    + '.r2.cloudflarestorage.com" }\n',
                    encoding="ascii",
                )
                backend.chmod(0o600)
                encryption = (
                    'key_provider "pbkdf2" "mail_fixture" { passphrase = "synthetic" }\n'
                    'method "aes_gcm" "mail_fixture" { keys = key_provider.pbkdf2.mail_fixture }\n'
                    'state { method = method.aes_gcm.mail_fixture }\n'
                    'plan { method = method.aes_gcm.mail_fixture }\n'
                )
                private_values = {
                    "CLOUDFLARE_API_TOKEN": "synthetic-only-cf",
                    "AWS_ACCESS_KEY_ID": "synthetic-only-id",
                    "AWS_SECRET_ACCESS_KEY": "synthetic-only-secret",
                    "TF_ENCRYPTION": encryption,
                    "TF_VAR_account_id": "a" * 32,
                    "TF_VAR_zone_id": "b" * 32,
                    "TF_VAR_zone_name": "example.invalid",
                    "TF_VAR_alias_address": "m0@example.invalid",
                    "TF_VAR_destination_address": "fixture@example.invalid",
                    "TF_VAR_rule_priority": "0",
                }
                config = mail.MailPrivateInputs(
                    home=private, ops_root=ops, backend=backend,
                    account="a" * 32, state_bucket="mail-state-fixture",
                    state_key="mail-m0/state/fixture.tfstate",
                    plan_bucket="mail-plan-fixture",
                    plan_key="mail-m0/plans/source/fixture-001",
                    values=private_values,
                )
                real_runner = mail.MailPrivateRunner(config, tools, timeout=1)
                config.check()
                # Pure private After composition: explicit config/slots only,
                # existing envs formatter, no child/write/default discovery.
                after_config = {
                    "account_id": config.account, "zone_id": "b" * 32,
                    "zone_name": "example.invalid", "alias_address": "m0@example.invalid",
                    "destination_address": "synthetic.fixture@gmail.com", "rule_priority": 0,
                    "state_bucket": config.state_bucket, "state_key": config.state_key,
                    "plan_bucket": config.plan_bucket, "plan_key": config.plan_key,
                    "verified_destination_id": "d" * 32, "manage_dns": False,
                    "manage_destination": False, "manage_rule": False, "preflight_approved": False,
                }
                marker = "PRIVATE_AFTER_INPUT_CANARY"
                after_slots = {
                    "CLOUDFLARE_API_TOKEN": marker + "-cf", "AWS_ACCESS_KEY_ID": marker + "-id",
                    "AWS_SECRET_ACCESS_KEY": marker + "-secret", "RENT_STATE_PASSPHRASE": "c" * 64,
                }
                context = dict(environment_name="dev-rent-tunnel", home=private,
                               ops_root=ops, backend=backend)
                def compose(data=after_config, selected=after_slots, **changed):
                    encoded = json.dumps(data).encode("utf-8") if isinstance(data, dict) else data
                    return mail.compose_after_inputs(encoded, selected, **{**context, **changed})

                def refused_composition(action):
                    try:
                        action()
                        raise AssertionError("invalid private After input was accepted")
                    except mail.NativeSourceHold as error:
                        assert marker not in str(error) and marker not in repr(error)
                        assert len(str(error)) < 80 and "\n" not in str(error)

                before_files = set(home.rglob("*"))
                before_backend = backend.read_bytes()
                before_children = mail.subprocess.Popen
                before_open = mail.os.open
                child_attempts, write_attempts = [], []
                def no_child(*args, **kwargs):
                    child_attempts.append(True)
                    raise AssertionError("input composition launched a child")
                def no_write(path, flags, *args, **kwargs):
                    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                        write_attempts.append(True)
                        raise AssertionError("input composition opened a write")
                    return before_open(path, flags, *args, **kwargs)
                mail.subprocess.Popen, mail.os.open = no_child, no_write
                try:
                    composed = compose()
                    assert marker not in repr(composed)
                    assert composed.values["CLOUDFLARE_API_TOKEN"] == after_slots["CLOUDFLARE_API_TOKEN"]
                    assert composed.values["AWS_ACCESS_KEY_ID"] == after_slots["AWS_ACCESS_KEY_ID"]
                    assert composed.values["AWS_SECRET_ACCESS_KEY"] == after_slots["AWS_SECRET_ACCESS_KEY"]
                    assert "RENT_STATE_PASSPHRASE" not in composed.values
                    assert 'key_provider "pbkdf2" "mail_m0"' in composed.values["TF_ENCRYPTION"]
                    assert 'method "aes_gcm" "mail_m0"' in composed.values["TF_ENCRYPTION"]
                    existing_spec = importlib.util.spec_from_file_location("mail_formatter_fixture", ROOT / "adapters/jev_api.py")
                    existing = importlib.util.module_from_spec(existing_spec)
                    sys.modules[existing_spec.name] = existing
                    try:
                        exec(compile((ROOT / "adapters/jev_api.py").read_bytes(), str(ROOT / "adapters/jev_api.py"), "exec"), existing.__dict__)
                        assert existing.ROOT_PASSPHRASE.fullmatch("c" * 64)
                        assert composed.values["TF_ENCRYPTION"] == existing.encryption_config("mail_m0", "c" * 64)
                    finally:
                        sys.modules.pop(existing_spec.name, None)
                    assert "fallback" not in composed.values["TF_ENCRYPTION"]
                    assert composed.values["TF_VAR_rule_priority"] == "0"
                    assert composed.values["TF_VAR_verified_destination_id"] == "d" * 32
                    assert all(composed.values["TF_VAR_" + name] == "false" for name in mail.MAIL_FLAGS)
                    null_id = compose({**after_config, "verified_destination_id": None})
                    assert "TF_VAR_verified_destination_id" not in null_id.values
                    caller_slots = dict(after_slots)
                    caller_config = dict(after_config)
                    snapshot = compose(caller_config, caller_slots)
                    caller_slots["CLOUDFLARE_API_TOKEN"] = "later-caller-value"
                    caller_slots["RENT_STATE_PASSPHRASE"] = "f" * 64
                    caller_config["zone_id"] = "e" * 32
                    assert snapshot.values["CLOUDFLARE_API_TOKEN"] == marker + "-cf"
                    assert snapshot.values["TF_VAR_zone_id"] == "b" * 32
                    assert snapshot.values["TF_ENCRYPTION"] == composed.values["TF_ENCRYPTION"]
                    try:
                        snapshot.values["TF_VAR_zone_id"] = "e" * 32
                        raise AssertionError("After snapshot remained mutable")
                    except TypeError:
                        pass
                    class ChangingSlots(mail.Mapping):
                        def __init__(self):
                            self.reads = {name: 0 for name in after_slots}
                        def __iter__(self):
                            return iter(after_slots)
                        def __len__(self):
                            return len(after_slots)
                        def __getitem__(self, name):
                            self.reads[name] += 1
                            # Original pre-copy validation read each value
                            # three times; its later copy could get this ESC.
                            if name == "AWS_SECRET_ACCESS_KEY" and self.reads[name] > 3:
                                return marker + "\x1b"
                            return after_slots[name]
                    changing = ChangingSlots()
                    stable = compose(selected=changing)
                    assert all(count == 1 for count in changing.reads.values())
                    assert stable.values["AWS_SECRET_ACCESS_KEY"] == after_slots["AWS_SECRET_ACCESS_KEY"]
                    class UnsafeDuringCopy(ChangingSlots):
                        def __getitem__(self, name):
                            selected = super().__getitem__(name)
                            return marker + "\t" if name == "AWS_SECRET_ACCESS_KEY" else selected
                    refused_composition(lambda: compose(selected=UnsafeDuringCopy()))
                    for key in mail.MAIL_CONFIG_KEYS:
                        missing = dict(after_config)
                        del missing[key]
                        refused_composition(lambda missing=missing: compose(missing))
                    for key in ("CLOUDFLARE_API_TOKEN", "age_identity", "passphrase", "TF_ENCRYPTION", "unknown"):
                        refused_composition(lambda key=key: compose({**after_config, key: marker}))
                    for key, bad in (
                        ("rule_priority", True), ("rule_priority", 1.5), ("rule_priority", -1),
                        ("zone_id", True), ("zone_id", "X" * 32), ("zone_name", "bad..zone"),
                        ("alias_address", "*@example.invalid"), ("alias_address", "m0@other.invalid"),
                        ("destination_address", "synthetic@example.invalid"),
                        ("destination_address", "*bad@gmail.com"),
                        ("verified_destination_id", marker), ("verified_destination_id", "D" * 32),
                        ("verified_destination_id", False), ("manage_dns", "false"),
                        ("preflight_approved", 1), ("state_key", "rent/state.tfstate"),
                        ("plan_key", "mail-m0/plans/../bad"), ("state_bucket", "bad bucket"),
                        ("zone_name", marker + "\n"),
                    ):
                        refused_composition(lambda key=key, bad=bad: compose({**after_config, key: bad}))
                    for raw in (b"", b"\xff", b"{}", b"[]", b"null", b"{" + marker.encode(),
                                b'{"account_id":"' + marker.encode() + b'","account_id":"duplicate"}',
                                b'{"rule_priority":NaN}', b"[" * 1500 + b"]" * 1500,
                                b'{"rule_priority":' + b"9" * 5000 + b"}", b" " * 32769):
                        refused_composition(lambda raw=raw: compose(raw))
                    refused_composition(lambda: mail.compose_after_inputs(marker, after_slots, **context))
                    for key in mail.MAIL_AFTER_SLOTS:
                        missing = dict(after_slots)
                        del missing[key]
                        refused_composition(lambda missing=missing: compose(selected=missing))
                    for selected in ({**after_slots, "AWS_SESSION_TOKEN": marker},
                                     {**after_slots, "RENT_STATE_PASSPHRASE": "AGE-SECRET-KEY-1" + marker},
                                     {**after_slots, "RENT_STATE_PASSPHRASE": "C" * 64},
                                     {**after_slots, "AWS_SECRET_ACCESS_KEY": marker + "\n"},
                                     {**after_slots, "AWS_SECRET_ACCESS_KEY": marker + "\t"},
                                     {**after_slots, "CLOUDFLARE_API_TOKEN": marker + "\x1b"},
                                     {**after_slots, "AWS_ACCESS_KEY_ID": marker + "\x7f"},
                                     {**after_slots, "AWS_ACCESS_KEY_ID": None}):
                        refused_composition(lambda selected=selected: compose(selected=selected))
                    for changed in (dict(environment_name="dev-projection"), dict(home=None),
                                    dict(ops_root=home), dict(backend=home / "absent"),
                                    dict(backend=Path("/dev/stdout"))):
                        refused_composition(lambda changed=changed: compose(**changed))
                    (ops / "extra.tf").write_text("unapproved fixture", encoding="utf-8")
                    try:
                        refused_composition(compose)
                    finally:
                        (ops / "extra.tf").unlink()
                    assert child_attempts == [] and write_attempts == []
                    assert set(home.rglob("*")) == before_files and backend.read_bytes() == before_backend
                finally:
                    mail.subprocess.Popen, mail.os.open = before_children, before_open
                real_popen = mail.subprocess.Popen

                def run_synthetic(command, suffix, *, code=0, pause=False, start_failure=False):
                    # Hook only the *spawn* to a tiny local Python fixture;
                    # the real MailPrivateRunner still performs command
                    # validation, private sink creation, environment bounding,
                    # real subprocess Popen, communicate and response handling.
                    script = (
                        "import sys, time\n"
                        "sys.stdout.buffer.write(b'SYNTHETIC_PRIVATE_STDOUT')\n"
                        "sys.stderr.buffer.write(b'SYNTHETIC_PRIVATE_STDERR')\n"
                        "sys.stdout.flush(); sys.stderr.flush()\n"
                        + ("time.sleep(10)\n" if pause else "")
                        + f"sys.exit({code})\n"
                    )
                    starts = []
                    def local_child(argv, **kwargs):
                        starts.append(tuple(argv))
                        assert tuple(argv) == command.argv
                        assert kwargs["stdout"] >= 0 and kwargs["stderr"] >= 0
                        assert kwargs["close_fds"] and kwargs["start_new_session"]
                        assert kwargs["umask"] == 0o077
                        child_env = kwargs["env"]
                        assert "PATH" not in child_env
                        assert "TF_LOG" not in child_env
                        assert "AWS_PROFILE" not in child_env
                        assert "HTTP_PROXY" not in child_env and "HTTPS_PROXY" not in child_env
                        assert child_env["HOME"] == str(private)
                        assert child_env["TMPDIR"] == str(private)
                        if argv[0] == tofu:
                            assert child_env["TF_ENCRYPTION"] == encryption
                            assert child_env["CLOUDFLARE_API_TOKEN"] == private_values["CLOUDFLARE_API_TOKEN"]
                        else:
                            assert "TF_ENCRYPTION" not in child_env
                            assert "AWS_SECRET_ACCESS_KEY" not in child_env
                        if start_failure:
                            raise OSError("synthetic private startup detail")
                        return real_popen([sys.executable, "-I", "-c", script], **kwargs)
                    mail.subprocess.Popen = local_child
                    try:
                        result = real_runner(command)
                    finally:
                        mail.subprocess.Popen = real_popen
                    assert starts == [command.argv], "native failure retried a child"
                    for stream in (command.private_stdout, command.private_stderr):
                        path = Path(stream)
                        assert path.parent == private
                        assert path.stat().st_mode & 0o077 == 0
                    assert Path(command.private_stdout).read_bytes() == (
                        b"" if start_failure else b"SYNTHETIC_PRIVATE_STDOUT")
                    assert Path(command.private_stderr).read_bytes() == (
                        b"" if start_failure else b"SYNTHETIC_PRIVATE_STDERR")
                    assert result.private_headers == b""
                    return result

                first_cmd = mail.native_init(
                    tofu, ops, backend, tools,
                    private_stdout=private / "real-init.out",
                    private_stderr=private / "real-init.err",
                )
                assert run_synthetic(first_cmd, "init").returncode == 0
                failed_cmd = mail.native_init(
                    tofu, ops, backend, tools,
                    private_stdout=private / "real-fail.out",
                    private_stderr=private / "real-fail.err",
                )
                assert run_synthetic(failed_cmd, "fail", code=7).returncode == 1
                timeout_cmd = mail.native_init(
                    tofu, ops, backend, tools,
                    private_stdout=private / "real-timeout.out",
                    private_stderr=private / "real-timeout.err",
                )
                assert run_synthetic(timeout_cmd, "timeout", pause=True).returncode == 124
                ordinary_two = mail.native_init(
                    tofu, ops, backend, tools,
                    private_stdout=private / "ordinary-two.out",
                    private_stderr=private / "ordinary-two.err",
                )
                assert run_synthetic(ordinary_two, "ordinary-two", code=2).returncode == 1
                ordinary_plan_two = mail.native_plan(
                    tofu, ops, private / "ordinary-two-plan.enc", tools,
                    private_stdout=private / "ordinary-two-plan.out",
                    private_stderr=private / "ordinary-two-plan.err",
                )
                assert run_synthetic(ordinary_plan_two, "ordinary-plan-two", code=2).returncode == 1
                # Exact native convergence variant preserves delta2, but does
                # not retry, initialize, save a plan or turn delta into success.
                for name, code, pause, start_failure, expected in (
                    ("zero", 0, False, False, 0),
                    ("delta", 2, False, False, 2),
                    ("error", 1, False, False, 1),
                    ("other-error", 7, False, False, 1),
                    ("timeout", 0, True, False, 124),
                    ("start-failure", 0, False, True, 125),
                ):
                    command = mail.native_noop(
                        tofu, ops, tools,
                        private_stdout=private / ("noop-" + name + ".out"),
                        private_stderr=private / ("noop-" + name + ".err"),
                    )
                    assert command.argv == (
                        tofu, "-chdir=" + str(ops), "plan", "-input=false",
                        "-lock=true", "-detailed-exitcode",
                    )
                    result = run_synthetic(command, name, code=code, pause=pause,
                                           start_failure=start_failure)
                    assert result.returncode == expected
                    if expected == 2:
                        must_refuse(lambda: mail._require_success(result), "delta as success")

                refused_starts = []
                def refused_child(argv, **_kwargs):
                    refused_starts.append(tuple(argv))
                    raise AssertionError("invalid no-op started a child")
                mail.subprocess.Popen = refused_child
                try:
                    baseline = (tofu, "-chdir=" + str(ops), "plan", "-input=false",
                                "-lock=true", "-detailed-exitcode")
                    bad_args = (
                        baseline[:-1], baseline + ("-out=" + str(saved_plan),),
                        baseline[:4] + ("-lock=false", baseline[-1]),
                        baseline[:3] + ("-input=true",) + baseline[4:],
                        baseline[:-1] + ("-detailed-exitcode=false",),
                        baseline[:-1] + ("-refresh-only",),
                        (tofu, "-chdir=" + str(home), *baseline[2:]),
                        ("/usr/bin/tofu", *baseline[1:]),
                    )
                    for index, argv in enumerate(bad_args):
                        out, err = private / f"bad-noop-{index}.out", private / f"bad-noop-{index}.err"
                        command = mail.NativeCommand(argv, private_stdout=str(out), private_stderr=str(err))
                        must_refuse(lambda command=command: real_runner(command), "altered no-op variant")
                        assert not out.exists() and not err.exists()
                    for out, err in (
                        (Path("/dev/stdout"), private / "unsafe-noop.err"),
                        (private / "alias-noop", private / "alias-noop"),
                        (backend, private / "existing-noop.err"),
                        (home / "outside-noop.out", private / "outside-noop.err"),
                    ):
                        before_files = set(private.iterdir())
                        must_refuse(lambda out=out, err=err: real_runner(mail.native_noop(
                            tofu, ops, tools, private_stdout=out, private_stderr=err,
                        )), "unsafe/existing/aliased no-op capture")
                        assert set(private.iterdir()) == before_files
                    late = mail.native_noop(
                        tofu, ops, tools, private_stdout=private / "late-noop.out",
                        private_stderr=private / "late-noop.err",
                    )
                    Path(late.private_stderr).write_bytes(b"LATE_PRIVATE_CAPTURE")
                    before_files = set(private.iterdir())
                    must_refuse(lambda: real_runner(late), "late-created no-op capture")
                    assert Path(late.private_stderr).read_bytes() == b"LATE_PRIVATE_CAPTURE"
                    assert set(private.iterdir()) == before_files
                    drift = mail.native_noop(
                        tofu, ops, tools, private_stdout=private / "drift-noop.out",
                        private_stderr=private / "drift-noop.err",
                    )
                    (ops / "extra.tf").write_text("unapproved", encoding="utf-8")
                    try:
                        must_refuse(lambda: real_runner(drift), "source drift before no-op")
                    finally:
                        (ops / "extra.tf").unlink()
                    assert not Path(drift.private_stdout).exists() and not Path(drift.private_stderr).exists()
                    assert refused_starts == []
                finally:
                    mail.subprocess.Popen = real_popen
                invalid = dict(private_values)
                invalid["AWS_PROFILE"] = "unaccepted rent fallback"
                must_refuse(lambda: mail.MailPrivateInputs(
                    home=private, ops_root=ops, backend=backend,
                    account="a" * 32, state_bucket="mail-state-fixture",
                    state_key="mail-m0/state/fixture.tfstate",
                    plan_bucket="mail-plan-fixture",
                    plan_key="mail-m0/plans/source/fixture-001",
                    values=invalid,
                ).check(), "ambient foreign AWS profile")
                must_refuse(lambda: real_runner(mail.NativeCommand(
                    (tofu, "-chdir=" + str(ops), "destroy"),
                    private_stdout=str(private / "destroy.out"),
                    private_stderr=str(private / "destroy.err"),
                )), "unselected native destroy command")
                assert not (private / "destroy.out").exists()

                # Native -out/-json-into/curl destinations can truncate files.
                # Exercise intended stage helpers, including their earlier
                # commands, through the actual runner and offline children.
                retained = private / "preserved-original.enc"
                retained.write_bytes(b"OFFLINE_ENCRYPTED_PLAN")
                old_capture = private / "preserved-capture"
                old_capture.write_bytes(b"PRESERVED_PRIVATE_CAPTURE")
                for path in (retained, old_capture):
                    path.chmod(0o600)
                protected = {path: path.read_bytes()
                             for path in (backend, retained, old_capture)}
                physical_events = []
                original_etag = '"offline-retained-original"'
                original_headers = ('HTTP/1.1 200 OK\r\nETag: '
                                    + original_etag + '\r\n\r\n').encode()

                def stage_streams(name):
                    return (private / (name + ".out"), private / (name + ".err"))

                def private_plan(name, destination, *, later_stderr=None):
                    init_out, init_err = stage_streams(name + "-init")
                    plan_out, plan_err = stage_streams(name + "-plan")
                    mail.plan_private_once(
                        ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                        tofu, backend, destination, tools, real_runner,
                        init_stdout=init_out, init_stderr=init_err,
                        plan_stdout=plan_out,
                        plan_stderr=plan_err if later_stderr is None else later_stderr,
                    )

                def private_inspect(name, destination, review):
                    get_out, get_err = stage_streams(name + "-get")
                    show_out, show_err = stage_streams(name + "-show")
                    mail.inspect_original_once(
                        curl, tofu, ops, config.account, config.plan_bucket,
                        config.plan_key, destination, private / (name + ".headers"),
                        private_values["AWS_ACCESS_KEY_ID"],
                        private_values["AWS_SECRET_ACCESS_KEY"],
                        original_etag, real_runner, tools,
                        private_review_json=review, private_stdout=show_out,
                        private_stderr=show_err, private_get_stdout=get_out,
                        private_get_stderr=get_err,
                    )

                def private_apply(name, destination, *, get_header=None,
                                  later_stderr=None):
                    head_out, head_err = stage_streams(name + "-head")
                    get_out, get_err = stage_streams(name + "-get")
                    apply_out, apply_err = stage_streams(name + "-apply")
                    mail.apply_same_original_once(
                        curl, tofu, ops, config.account, config.plan_bucket,
                        config.plan_key, destination, private / (name + "-head.headers"),
                        private_values["AWS_ACCESS_KEY_ID"],
                        private_values["AWS_SECRET_ACCESS_KEY"],
                        original_etag, original_etag, original_etag, original_etag,
                        real_runner, tools,
                        get_headers=private / (name + "-get.headers")
                                    if get_header is None else get_header,
                        head_stdout=head_out, head_stderr=head_err,
                        get_stdout=get_out, get_stderr=get_err,
                        apply_stdout=apply_out,
                        apply_stderr=apply_err if later_stderr is None else later_stderr,
                    )

                def offline_native_child(argv, **kwargs):
                    physical_events.append(tuple(argv))
                    assert kwargs["umask"] == 0o077 and kwargs["close_fds"]
                    writes = []
                    if argv[0] == tofu:
                        assert kwargs["env"]["TF_ENCRYPTION"] == encryption
                        if argv[2] == "plan":
                            writes.append((argv[-1][5:], b"OFFLINE_ENCRYPTED_PLAN"))
                        elif argv[2] == "show":
                            writes.append((argv[4][11:], b'{"synthetic_original":true}'))
                        elif argv[2] == "apply":
                            assert Path(argv[-1]).read_bytes() == b"OFFLINE_ENCRYPTED_PLAN"
                    else:
                        assert argv == (curl, "-q", "--config", "-")
                        assert "AWS_SECRET_ACCESS_KEY" not in kwargs["env"]
                        # communicate supplies native config later; the fixed
                        # offline child reads stdin just as curl does.
                    script = (
                        "import json, pathlib, sys\n"
                        "writes = " + repr(writes) + "\n"
                        + ("fields = {line.split(' = ', 1)[0]: json.loads(line.split(' = ', 1)[1]) "
                           "for line in sys.stdin.read().splitlines() if ' = ' in line}\n"
                           "writes.append((fields['dump-header'], " + repr(original_headers) + "))\n"
                           "if fields['request'] == 'GET': writes.append((fields['output'], b'OFFLINE_ENCRYPTED_PLAN'))\n"
                           if argv[0] == curl else "")
                        + "for name, data in writes: pathlib.Path(name).write_bytes(data)\n"
                        "sys.stdout.buffer.write(b'OFFLINE_PRIVATE_STDOUT')\n"
                        "sys.stderr.buffer.write(b'OFFLINE_PRIVATE_STDERR')\n"
                    )
                    return real_popen([sys.executable, "-I", "-c", script], **kwargs)

                mail.subprocess.Popen = offline_native_child
                try:
                    # A command created with a fresh path must still refuse
                    # if that native output exists when the runner is called.
                    for kind in ("plan", "show"):
                        output = private / ("late-existing-" + kind)
                        stdout, stderr = stage_streams("late-existing-" + kind)
                        command = (
                            mail.native_plan(tofu, ops, output, tools,
                                             private_stdout=stdout, private_stderr=stderr)
                            if kind == "plan" else
                            mail.native_inspect(tofu, ops, retained, output,
                                                stdout, stderr, tools)
                        )
                        output.write_bytes(b"CREATED_AFTER_COMMAND_CONSTRUCTION")
                        output.chmod(0o600)
                        before_files = set(private.iterdir())
                        must_refuse(lambda command=command: real_runner(command),
                                    "late-created native " + kind + " output")
                        assert output.read_bytes() == b"CREATED_AFTER_COMMAND_CONSTRUCTION"
                        assert physical_events == [] and set(private.iterdir()) == before_files

                    # Runner command-shape validation is also a boundary:
                    # a fresh native output cannot alias its own capture.
                    for kind in ("plan", "show"):
                        stdout, stderr = stage_streams("native-alias-" + kind)
                        argv = (
                            (tofu, "-chdir=" + str(ops), "plan", "-input=false",
                             "-lock=true", "-out=" + str(stdout))
                            if kind == "plan" else
                            (tofu, "-chdir=" + str(ops), "show", "-plan=" + str(retained),
                             "-json-into=" + str(stdout), "-no-color")
                        )
                        command = mail.NativeCommand(argv, private_stdout=str(stdout),
                                                     private_stderr=str(stderr))
                        before_files = set(private.iterdir())
                        must_refuse(lambda command=command: real_runner(command),
                                    "native " + kind + " output aliases stdout")
                        assert physical_events == [] and set(private.iterdir()) == before_files

                    bad_stages = (
                        lambda: private_plan("backend-plan", backend),
                        lambda: private_plan("retained-plan", retained),
                        lambda: private_plan("late-capture", private / "late-plan.enc",
                                             later_stderr=old_capture),
                        lambda: private_plan("outside-owner", home / "outside-plan.enc"),
                        lambda: private_inspect("backend-json", private / "get-original.enc", backend),
                        lambda: private_inspect("backend-get", backend, private / "fresh-review.json"),
                        lambda: private_inspect("retained-get", retained, private / "fresh-review.json"),
                        lambda: private_inspect("old-review", private / "get-original.enc", old_capture),
                        lambda: private_inspect("outside-review", private / "get-original.enc",
                                                home / "outside-review.json"),
                        lambda: private_apply("retained-apply", retained),
                        lambda: private_apply("late-header", private / "apply-original.enc",
                                              get_header=old_capture),
                        lambda: private_apply("outside-header", private / "apply-original.enc",
                                              get_header=home / "outside-header"),
                        lambda: private_apply("late-stream", private / "apply-original.enc",
                                              later_stderr=old_capture),
                        lambda: private_apply("same-header", private / "apply-original.enc",
                                              get_header=private / "same-header-head.headers"),
                    )
                    for action in bad_stages:
                        before_files = set(private.iterdir())
                        must_refuse(action, "destructive intended-stage output")
                        assert physical_events == [], "later collision started an earlier child"
                        assert set(private.iterdir()) == before_files
                        assert all(path.read_bytes() == data for path, data in protected.items())

                    fresh_plan = private / "positive-plan.enc"
                    inspection_original = private / "positive-inspection.enc"
                    inspection_json = private / "positive-inspection.json"
                    apply_original = private / "positive-apply.enc"
                    private_plan("positive", fresh_plan)
                    put_out, put_err = stage_streams("positive-put")
                    assert mail.retain_original_once(
                        curl, config.account, config.plan_bucket, config.plan_key,
                        fresh_plan, private / "positive-put.headers",
                        private_values["AWS_ACCESS_KEY_ID"],
                        private_values["AWS_SECRET_ACCESS_KEY"], real_runner, tools,
                        private_stdout=put_out, private_stderr=put_err,
                    ) == original_etag
                    private_inspect("positive-inspect", inspection_original, inspection_json)
                    private_apply("positive-apply", apply_original)
                    assert len(physical_events) == 8
                    assert inspection_original.read_bytes() == apply_original.read_bytes() == fresh_plan.read_bytes()
                    assert inspection_json.read_bytes() == b'{"synthetic_original":true}'
                    assert all(path.read_bytes() == data for path, data in protected.items())
                    for path in private.glob("positive*"):
                        assert path.stat().st_mode & 0o077 == 0
                        if path.suffix == ".out":
                            assert path.read_bytes() == b"OFFLINE_PRIVATE_STDOUT"
                        elif path.suffix == ".err":
                            assert path.read_bytes() == b"OFFLINE_PRIVATE_STDERR"
                finally:
                    mail.subprocess.Popen = real_popen

                def select_sinks(kwargs, stage):
                    kwargs.setdefault("private_stdout", sinks[stage][0])
                    kwargs.setdefault("private_stderr", sinks[stage][1])
                    return kwargs

                def native_init_cmd(*args, **kwargs):
                    return mail.native_init(*args, **select_sinks(kwargs, "init"))

                def native_plan_cmd(*args, **kwargs):
                    return mail.native_plan(*args, **select_sinks(kwargs, "plan"))

                def native_apply_cmd(*args, **kwargs):
                    return mail.native_apply(*args, **select_sinks(kwargs, "apply"))

                def r2_cmd(*args, **kwargs):
                    return mail.private_r2_object(*args, **select_sinks(kwargs, "put"))

                def plan_once(*args, **kwargs):
                    kwargs.setdefault("init_stdout", sinks["init"][0])
                    kwargs.setdefault("init_stderr", sinks["init"][1])
                    kwargs.setdefault("plan_stdout", sinks["plan"][0])
                    kwargs.setdefault("plan_stderr", sinks["plan"][1])
                    return mail.plan_private_once(*args, **kwargs)

                def retain_once(*args, **kwargs):
                    return mail.retain_original_once(*args, **select_sinks(kwargs, "put"))

                def inspect_once(*args, **kwargs):
                    kwargs.setdefault("private_get_stdout", sinks["get"][0])
                    kwargs.setdefault("private_get_stderr", sinks["get"][1])
                    return mail.inspect_original_once(*args, **kwargs)

                def apply_once(*args, **kwargs):
                    kwargs.setdefault("get_headers", private / "apply-get.headers")
                    for stage in ("head", "apply_get", "apply"):
                        kwargs.setdefault(stage + "_stdout" if stage != "apply_get" else "get_stdout",
                                          sinks[stage][0])
                        kwargs.setdefault(stage + "_stderr" if stage != "apply_get" else "get_stderr",
                                          sinks[stage][1])
                    return mail.apply_same_original_once(*args, **kwargs)

                init = native_init_cmd(tofu, ops, backend, tools)
                planned = native_plan_cmd(tofu, ops, saved_plan, tools)
                inspect = mail.native_inspect(tofu, ops, original, review_json,
                                              captured_stdout, captured_stderr, tools)
                apply = native_apply_cmd(tofu, ops, original, tools)
                assert init.argv[2:4] == ("init", "-input=false") and "-lockfile=readonly" in init.argv
                assert planned.argv[2:4] == ("plan", "-input=false") and "-lock=true" in planned.argv
                assert planned.argv[-1] == "-out=" + str(saved_plan)
                assert inspect.argv[-4:] == (
                    "show", "-plan=" + str(original),
                    "-json-into=" + str(review_json), "-no-color",
                )
                assert "-json" not in inspect.argv
                assert inspect.private_stdout == str(captured_stdout)
                assert inspect.private_stderr == str(captured_stderr)
                assert inspect.private_stdout != inspect.private_stderr
                for command in (init, planned, inspect, apply):
                    assert command.private_stdout and command.private_stderr
                    assert command.private_stdout != command.private_stderr
                    assert command.private_stdout.startswith(str(private))
                    assert command.private_stderr.startswith(str(private))
                # None or public descriptor can never form a NativeCommand;
                # there is no optional/implicit runner inheritance path.
                must_refuse(lambda: mail.NativeCommand(
                    ("synthetic",), private_stdout=None,
                    private_stderr=str(sinks["init"][1]),
                ), "missing native stdout capture")
                must_refuse(lambda: mail.NativeCommand(
                    ("synthetic",), private_stdout="/dev/stdout",
                    private_stderr=str(sinks["init"][1]),
                ), "public native stdout descriptor")
                must_refuse(lambda: mail.NativeCommand(
                    ("synthetic",), private_stdout=str(sinks["init"][0]),
                    private_stderr=str(sinks["init"][0]),
                ), "overlapping native streams")
                assert apply.argv[-4:] == ("apply", "-input=false", "-lock=true", str(original))
                assert all("--auto-approve" not in x.argv and "-destroy" not in x.argv
                           for x in (init, planned, inspect, apply))
                assert planned.argv != apply.argv
                unsafe = (
                    Path("/dev/stdout"), Path("/dev/stderr"), Path("/dev/stdin"),
                    Path("/dev/fd/1"), Path("/proc/self/fd/1"),
                    Path("/proc/self/fd/2"), Path("/dev/null"),
                    Path("/tmp/owner-plan"), Path("/var/tmp/owner-plan"),
                )
                for bad in unsafe:
                    must_refuse(lambda bad=bad: native_init_cmd(
                        tofu, ops, backend, tools, private_stdout=bad,
                    ), "unsafe init stdout")
                    must_refuse(lambda bad=bad: native_plan_cmd(
                        tofu, ops, saved_plan, tools, private_stderr=bad,
                    ), "unsafe plan stderr")
                    must_refuse(lambda bad=bad: native_apply_cmd(
                        tofu, ops, original, tools, private_stdout=bad,
                    ), "unsafe apply stdout")
                    must_refuse(lambda bad=bad: r2_cmd(
                        curl, "PUT", "a" * 32, "mail-fixture-private",
                        "mail-m0/plans/source/fixture-001", saved_plan, headers,
                        "fixture-access", "fixture-secret", tools=tools,
                        private_stderr=bad,
                    ), "unsafe R2 stderr")
                    must_refuse(lambda bad=bad: mail.native_inspect(
                        tofu, ops, original, bad, captured_stdout, captured_stderr, tools,
                    ), "unsafe review JSON sink")
                    must_refuse(lambda bad=bad: mail.native_inspect(
                        tofu, ops, original, review_json, bad, captured_stderr, tools,
                    ), "unsafe stdout sink")
                    must_refuse(lambda bad=bad: mail.native_inspect(
                        tofu, ops, original, review_json, captured_stdout, bad, tools,
                    ), "unsafe stderr sink")
                must_refuse(lambda: mail.native_inspect(
                    tofu, ops, original, review_json, review_json, captured_stderr, tools,
                ), "overlapping JSON and stdout")
                alias = home / "aliased-private-sink"
                alias.symlink_to("/dev/stdout")
                must_refuse(lambda: mail.native_inspect(
                    tofu, ops, original, alias, captured_stdout, captured_stderr, tools,
                ), "symlink to public stdout")
                alias.unlink()
                forged = "/nix/store/" + "0" * 32 + "-unrelated/bin/tofu"
                for other in (forged, "/usr/bin/tofu", "/tmp/private/bin/tofu",
                              tofu.replace("/bin/tofu", "/bin/curl")):
                    must_refuse(lambda other=other: native_plan_cmd(other, ops, saved_plan, tools),
                                "unselected binary")
                must_refuse(lambda: native_plan_cmd(tofu, ops, saved_plan,
                                                    mail.NativeToolset(tofu=curl, curl=tofu, _proof=mail._NATIVE_TOOL_PROOF)),
                            "tool mapping mismatched")

                etag = '"original-r2-etag1234"'
                store = dict(curl=curl, account="a" * 32, bucket="mail-fixture-private",
                             key="mail-m0/plans/source/fixture-001", headers=headers,
                             access_id="fixture-access", access_secret="fixture-secret",
                             tools=tools)
                put = r2_cmd(method="PUT", source_or_dest=saved_plan, **store)
                head = r2_cmd(method="HEAD", source_or_dest=private / "ignored",
                                             etag=etag, **store)
                get = r2_cmd(method="GET", source_or_dest=original, etag=etag, **store)
                for cmd in (put, head, get):
                    assert cmd.private_stdout and cmd.private_stderr
                    assert cmd.private_stdout != cmd.private_stderr
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
                for bad in unsafe:
                    must_refuse(lambda bad=bad: r2_cmd(
                        method="GET", source_or_dest=bad, etag=etag, **store,
                    ), "private GET body into public output")
                    must_refuse(lambda bad=bad: r2_cmd(
                        method="PUT", source_or_dest=saved_plan, etag=None,
                        **{**store, "headers": bad},
                    ), "private R2 headers into public descriptor")
                for method in ("HEAD", "GET"):
                    must_refuse(lambda method=method: r2_cmd(
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
                    assert isinstance(command, mail.NativeCommand)
                    assert command.private_stdout and command.private_stderr
                    assert command.private_stdout != command.private_stderr
                    assert command.private_stdout.startswith(str(private))
                    assert command.private_stderr.startswith(str(private))
                    events.append(command)
                    if command.argv[0] == curl:
                        return mail.PrivateNativeResult(0, response_headers)
                    return mail.PrivateNativeResult(0)

                plan_once(ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                                       tofu, backend, saved_plan, tools, synthetic_runner)
                assert [cmd.argv[2] for cmd in events] == ["init", "plan"]
                opaque = retain_once(curl, store["account"], store["bucket"],
                    store["key"], saved_plan, headers, "fixture-access", "fixture-secret",
                    synthetic_runner, tools)
                assert opaque == etag and len(events) == 3
                inspect_once(curl, tofu, ops, store["account"], store["bucket"],
                    store["key"], original, headers, "fixture-access", "fixture-secret",
                    opaque, synthetic_runner, tools,
                    private_review_json=review_json, private_stdout=captured_stdout,
                    private_stderr=captured_stderr)
                assert len(events) == 5
                assert events[-2].argv[0] == curl and events[-1].argv[2] == "show"
                assert events[-1].private_stdout == str(captured_stdout)
                assert events[-1].private_stderr == str(captured_stderr)
                assert "-json-into=" + str(review_json) in events[-1].argv
                # Unsafe sinks fail BEFORE any private R2 GET or Runner call.
                for bad in unsafe:
                    before = len(events)
                    must_refuse(lambda bad=bad: inspect_once(
                        curl, tofu, ops, store["account"], store["bucket"], store["key"],
                        original, headers, "fixture-access", "fixture-secret",
                        opaque, synthetic_runner, tools,
                        private_review_json=bad, private_stdout=captured_stdout,
                        private_stderr=captured_stderr,
                    ), "unsafe inspection source")
                    assert len(events) == before
                before = len(events)
                must_refuse(lambda: inspect_once(
                    curl, tofu, ops, store["account"], store["bucket"], store["key"],
                    original, Path("/dev/stderr"), "fixture-access", "fixture-secret",
                    opaque, synthetic_runner, tools,
                    private_review_json=review_json, private_stdout=captured_stdout,
                    private_stderr=captured_stderr,
                ), "unsafe curl header source")
                assert len(events) == before
                apply_once(curl, tofu, ops, store["account"],
                    store["bucket"], store["key"], original, headers, "fixture-access",
                    "fixture-secret", etag, etag, etag, etag, synthetic_runner, tools)
                assert len(events) == 8
                assert all(c.private_stdout and c.private_stderr for c in events)
                assert len({c.private_stdout for c in events}) == 8
                assert len({c.private_stderr for c in events}) == 8
                # Fail closed BEFORE ANY runner call when a later stage's
                # private stdout/stderr is absent, public or overlapping.
                for bad in unsafe:
                    before = len(events)
                    must_refuse(lambda bad=bad: plan_once(
                        ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                        tofu, backend, saved_plan, tools, synthetic_runner,
                        plan_stdout=bad,
                    ), "future plan stream unsafe before init")
                    must_refuse(lambda bad=bad: retain_once(
                        curl, store["account"], store["bucket"], store["key"],
                        saved_plan, headers, "fixture-access", "fixture-secret",
                        synthetic_runner, tools, private_stderr=bad,
                    ), "future PUT stream unsafe before R2")
                    must_refuse(lambda bad=bad: inspect_once(
                        curl, tofu, ops, store["account"], store["bucket"],
                        store["key"], original, headers, "fixture-access",
                        "fixture-secret", etag, synthetic_runner, tools,
                        private_review_json=review_json,
                        private_stdout=captured_stdout,
                        private_stderr=captured_stderr,
                        private_get_stdout=bad,
                    ), "future GET stream unsafe before R2")
                    must_refuse(lambda bad=bad: apply_once(
                        curl, tofu, ops, store["account"], store["bucket"],
                        store["key"], original, headers, "fixture-access",
                        "fixture-secret", etag, etag, etag, etag,
                        synthetic_runner, tools, apply_stderr=bad,
                    ), "future APPLY stream unsafe before HEAD")
                    assert len(events) == before
                before = len(events)
                must_refuse(lambda: plan_once(
                    ops, mail.OPS_MAIL_COMMIT, mail.OPS_MAIL_TREE,
                    tofu, backend, saved_plan, tools, synthetic_runner,
                    plan_stdout=sinks["init"][0],
                ), "overlapping init and plan streams")
                must_refuse(lambda: apply_once(
                    curl, tofu, ops, store["account"], store["bucket"],
                    store["key"], original, headers, "fixture-access",
                    "fixture-secret", etag, etag, etag, etag,
                    synthetic_runner, tools, get_stdout=sinks["head"][0],
                ), "overlapping conditional original streams")
                assert len(events) == before
                assert [cmd.argv[2] if cmd.argv[0] == tofu else "s3" for cmd in events[-3:]] == [
                    "s3", "s3", "apply",
                ]
                for source_change in ("extra.tf", "override.tf"):
                    (ops / source_change).write_text("unaccepted\n", encoding="utf-8")
                    before = len(events)
                    must_refuse(lambda: inspect_once(
                        curl, tofu, ops, store["account"], store["bucket"], store["key"],
                        original, headers, "fixture-access", "fixture-secret",
                        etag, synthetic_runner, tools,
                        private_review_json=review_json, private_stdout=captured_stdout,
                        private_stderr=captured_stderr,
                    ), "read changed source")
                    must_refuse(lambda: apply_once(
                        curl, tofu, ops, store["account"], store["bucket"], store["key"],
                        original, headers, "fixture-access", "fixture-secret",
                        etag, etag, etag, etag, synthetic_runner, tools,
                    ), "apply changed source")
                    assert len(events) == before, "source drift started an effect"
                    (ops / source_change).unlink()
                before = len(events)
                must_refuse(lambda: apply_once(
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
                must_refuse(lambda: apply_once(
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
        # Actual supplied OpenTofu 1.12.3 (help-only) confirms the native
        # private JSON file option without accessing any plan/state/provider.
        help_show = subprocess.run([selection.tofu, "show", "-help"],
                                   capture_output=True, text=True, check=False, timeout=15)
        assert help_show.returncode == 0 and "-json-into" in help_show.stdout
        help_plan = subprocess.run([selection.tofu, "plan", "-help"],
                                   capture_output=True, text=True, check=False, timeout=15)
        assert help_plan.returncode == 0 and "-detailed-exitcode" in help_plan.stdout
        # The exact current envs formatter, not a hand-written encryption
        # substitute, supplies native compatibility's synthetic-only value.
        formatter_spec = importlib.util.spec_from_file_location("mail_provided_formatter", ROOT / "adapters/jev_api.py")
        formatter = importlib.util.module_from_spec(formatter_spec)
        sys.modules[formatter_spec.name] = formatter
        try:
            exec(compile((ROOT / "adapters/jev_api.py").read_bytes(), str(ROOT / "adapters/jev_api.py"), "exec"), formatter.__dict__)
            assert formatter.ROOT_PASSPHRASE.fullmatch("c" * 64)
            native_encryption = formatter.encryption_config("mail_m0", "c" * 64)
            mail._mail_encryption_source(native_encryption)
        finally:
            sys.modules.pop(formatter_spec.name, None)
        # Actual supplied native0/2/1 behavior, independently of the synthetic
        # runner mapping. These ephemeral roots are NOT the Mail Ops root:
        # empty or built-in terraform_data only; no remote backend/provider,
        # credentials, network, saved plan, apply or persistent real state.
        with tempfile.TemporaryDirectory(prefix="mail-native-noop-provided-") as directory:
            fixture_home = Path(directory)
            fixture_env = {
                "HOME": str(fixture_home), "TMPDIR": str(fixture_home),
                "LANG": "C", "TF_INPUT": "0", "TF_IN_AUTOMATION": "1",
                "CHECKPOINT_DISABLE": "1", "AWS_EC2_METADATA_DISABLED": "true",
            }
            for name, source, expected in (
                ("empty", "", 0),
                ("builtin-delta", 'resource "terraform_data" "fixture" { input = "synthetic-only" }\n', 2),
                ("invalid", 'resource "terraform_data" "broken" {\n', 1),
                ("encrypted-empty", "terraform {\n  encryption {\n    state { enforced = true }\n    plan { enforced = true }\n  }\n}\n", 0),
            ):
                fixture = fixture_home / name
                fixture.mkdir(mode=0o700)
                main_tf = fixture / "main.tf"
                main_tf.write_text("" if expected == 1 else source, encoding="utf-8")
                # Explicit TEST-only init; never part of native_noop().
                commands = (
                    ("init", "-backend=false", "-input=false"),
                    ("plan", "-input=false", "-lock=true", "-detailed-exitcode"),
                )
                native_env = dict(fixture_env)
                if name == "encrypted-empty":
                    native_env["TF_ENCRYPTION"] = native_encryption
                for stage, args in enumerate(commands):
                    if stage == 1 and expected == 1:
                        main_tf.write_text(source, encoding="utf-8")
                    stdout, stderr = fixture_home / f"{name}-{stage}.out", fixture_home / f"{name}-{stage}.err"
                    with stdout.open("xb") as out, stderr.open("xb") as err:
                        stdout.chmod(0o600)
                        stderr.chmod(0o600)
                        native = subprocess.run(
                            [selection.tofu, "-chdir=" + str(fixture), *args],
                            env=native_env, stdin=subprocess.DEVNULL,
                            stdout=out, stderr=err, umask=0o077,
                            check=False, timeout=15,
                        )
                    assert native.returncode == (0 if stage == 0 else expected), (
                        "provided native no-op fixture returned unexpected finite code")
                assert not list(fixture.glob("*.tfstate*")), "test plan persisted state"
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
