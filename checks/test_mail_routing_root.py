#!/usr/bin/env python3
"""Mail manual consumer: synthetic sequencing and refusal. No real effects."""
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


def state_envelope_fixture() -> bytes:
    """Structural fixture only; real SOPS authentication is tested in CI."""
    enc = "ENC[AES256_GCM,data:Zml4dHVyZQ==,iv:" + "a" * 43 + "=,tag:" + "b" * 22 + "==,type:str]"
    return json.dumps({
        **{name: enc for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RENT_STATE_PASSPHRASE")},
        "sops": {"age": [{"recipient": "age1" + "q" * 58,
                          "enc": "-----BEGIN AGE ENCRYPTED FILE-----\nZml4dHVyZQ==\n-----END AGE ENCRYPTED FILE-----\n"}],
                 "lastmodified": "2026-10-14T00:00:00Z", "mac": enc,
                 "unencrypted_suffix": "_unencrypted", "version": "3.13.2"},
    }).encode()


def invalid_state_envelopes(data: bytes) -> list[bytes]:
    bad = [data + b'\n# SYNTHETIC_PLAINTEXT_CANARY', data + data,
           data[:-1] + b',"AWS_SECRET_ACCESS_KEY":"SYNTHETIC_PLAINTEXT_CANARY"}',
           data.replace(b'"version": "3.13.2"', b'"version": "3.13.2","version": "3.13.2"'),
           b'AWS_SECRET_ACCESS_KEY: ENC[AES256_GCM,fixture]\nAWS_SECRET_ACCESS_KEY: SYNTHETIC_PLAINTEXT_CANARY\n']
    for mechanism in ("kms", "gcp_kms", "azure_kv", "hc_vault", "hckms", "pgp", "key_groups"):
        envelope = json.loads(data)
        envelope["sops"][mechanism] = []
        bad.append(json.dumps(envelope).encode())
    for section, name, value in ((None, "UNKNOWN", "SYNTHETIC_PLAINTEXT_CANARY"),
                                 (None, "AWS_ACCESS_KEY_ID", "SYNTHETIC_PLAINTEXT_CANARY"),
                                 ("sops", "mac", "SYNTHETIC_PLAINTEXT_CANARY"),
                                 ("sops", "unencrypted_suffix", "SYNTHETIC_PLAINTEXT_CANARY")):
        envelope = json.loads(data)
        (envelope if section is None else envelope[section])[name] = value
        bad.append(json.dumps(envelope).encode())
    envelope = json.loads(data)
    envelope["sops"]["age"].append(envelope["sops"]["age"][0])
    bad.append(json.dumps(envelope).encode())
    return bad


def preview_journal(delta: bool, marker: str = "SYNTHETIC_PRIVATE_VALUE") -> str:
    events = [{"type": "version", "tofu": "1.12.3", "ui": "1.0"},
              {"type": "state_lock_acquire", "@message": marker}]
    if delta:
        for address in ("cloudflare_email_routing_address.gmail[0]", "cloudflare_email_routing_dns.zone[0]"):
            events.append({"type": "planned_change", "@message": marker,
                           "change": {"resource": {"addr": address}, "action": "create"}})
    events.extend([{"type": "change_summary", "changes": {"operation": "plan", "add": 2 if delta else 0,
                                                          "change": 0, "remove": 0}},
                   {"type": "outputs", "outputs": {"private": {"sensitive": True, "value": marker}}},
                   {"type": "state_lock_release", "@message": marker}])
    return "\n".join(json.dumps(event) for event in events) + "\n"


def check_preview_summary(mail) -> None:
    if os.name != "posix":
        return
    marker = "SYNTHETIC_PRIVATE_PREVIEW_CANARY"
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory) / "private"
        home.mkdir(mode=0o700)
        capture = home / "preview.out"
        for code in (0, 2):
            journal = preview_journal(code == 2, marker)
            capture.write_text(journal, encoding="utf-8")
            capture.chmod(0o600)
            result = mail.preview_summary(capture, code)
            assert result["status"] == ("DELTA" if code == 2 else "NO_OP")
            assert result["totals"] == {"add": 2 if code == 2 else 0, "change": 0, "remove": 0}
            assert result["changes"] == ({"destination": "create", "dns": "create"} if code == 2 else {})
            assert marker not in repr(result)
        base_events = [json.loads(row) for row in preview_journal(True, marker).splitlines()]
        hooks = []
        for address in ("data.cloudflare_email_routing_address.checked[0]",
                        "data.cloudflare_email_routing_settings.checked[0]"):
            for kind in ("apply_start", "apply_progress", "apply_complete"):
                hooks.append({"type": kind, "@message": marker,
                              "hook": {"resource": {"addr": address}, "action": "read", "id_value": marker}})
        data_events = base_events[:2] + hooks + base_events[2:]
        data_journal = "\n".join(json.dumps(event) for event in data_events) + "\n"
        capture.write_text(data_journal, encoding="utf-8")
        assert mail.preview_summary(capture, 2)["totals"] == {"add": 2, "change": 0, "remove": 0}
        assert marker not in repr(mail.preview_summary(capture, 2))
        for bad in (data_journal.replace('"action": "read"', '"action": "create"'),
                    data_journal.replace('data.cloudflare_email_routing_address.checked[0]', marker),
                    data_journal.replace('data.cloudflare_email_routing_address.checked[0]', 'cloudflare_email_routing_dns.zone[0]'),
                    data_journal.replace('"apply_start"', '"apply_progress"'),
                    data_journal.replace('"apply_complete"', '"apply_progress"'),
                    data_journal.replace('"apply_progress"', '"apply_errored"'),
                    preview_journal(True) + "\n".join(json.dumps(event) for event in hooks)):
            capture.write_text(bad, encoding="utf-8")
            try:
                mail.preview_summary(capture, 2)
                raise AssertionError("unsafe preview data hook accepted")
            except mail.NativeSourceHold as error:
                assert marker not in str(error)
        for bad in (journal.replace('"1.0"', '"2.0"'), journal.replace('"1.12.3"', '"1.12.2"'),
                    journal.replace('"add": 2', '"add": true'), journal.replace('"add": 2', '"add": 1'),
                    journal.replace('"create"', '"unknown"'), journal.replace('"create"', '"update"'),
                    journal.replace('"action": "create"', '"action": "create", "importing": {"id": "private"}'),
                    journal.replace('"action": "create"', '"action": "create", "generated_config": "private"'),
                    journal.replace('"operation": "plan"', '"operation": "plan", "import": 2'),
                    journal.replace('"operation": "plan"', '"operation": "plan", "forget": 1'),
                    journal.replace('"addr":', '"addr":"duplicate", "addr":'),
                    journal.replace('cloudflare_email_routing_dns.zone[0]', marker),
                    journal.replace('cloudflare_email_routing_dns.zone[0]', 'cloudflare_email_routing_address.gmail[0]'),
                    preview_journal(False), journal + journal, journal + "malformed", "", " " * 8388609,
                    journal + json.dumps({"type": "version", "tofu": "1.12.3", "ui": "1.0"}),
                    journal + json.dumps({"type": "apply_start", "hook": {"resource": {"addr": marker}}}),
                    journal + json.dumps({"type": "refresh_start", "hook": {"resource": {"addr": marker}}}),
                    journal + json.dumps({"type": "resource_drift", "change": {"resource": {"addr": marker}, "action": "update"}})):
            capture.write_text(bad, encoding="utf-8")
            try:
                mail.preview_summary(capture, 2)
                raise AssertionError("unsafe preview summary accepted")
            except mail.NativeSourceHold:
                pass
        capture.write_text(preview_journal(True), encoding="utf-8")
        for code in (0, 1, 124, 125):
            try:
                mail.preview_summary(capture, code)
                raise AssertionError("inconsistent preview status accepted")
            except mail.NativeSourceHold:
                pass
        capture.chmod(0o644)
        try:
            mail.preview_summary(capture, 2)
            raise AssertionError("public preview capture accepted")
        except mail.NativeSourceHold:
            pass


def check_apply_failure_summary(mail) -> None:
    if os.name != "posix":
        return
    marker = "SYNTHETIC_PRIVATE_ERROR_CANARY"
    version = {"type": "version", "tofu": "1.12.3", "ui": "1.0"}
    envelope = {"success": False, "errors": [{"code": 2007, "message": marker}], "result": marker}
    diagnostic = {"type": "diagnostic", "@message": marker,
                  "diagnostic": {"severity": "error", "summary": "failed to make http request",
                                 "detail": 'POST "https://' + marker + '": 422 Unprocessable Entity ' + json.dumps(envelope)}}
    hook = {"type": "apply_errored", "hook": {"resource": {"addr": "cloudflare_email_routing_dns.zone[0]"}}}
    journal = "\n".join(json.dumps(e) for e in (version, hook, diagnostic)) + "\n"
    expected = {"classification": "PROVIDER_HTTP_ERROR", "resources": ["dns"],
                "http_status": [422], "api_codes": [2007]}
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory) / "private"
        home.mkdir(mode=0o700)
        capture = home / "apply.out"
        capture.write_text(journal, encoding="utf-8")
        capture.chmod(0o600)
        assert mail.apply_failure_summary(capture) == expected
        assert marker not in repr(expected)
        for bad in (journal.replace('"1.12.3"', '"1.12.2"'), journal.replace('"1.0"', '"2.0"'),
                    journal.replace("cloudflare_email_routing_dns.zone[0]", marker),
                    journal.replace("failed to make http request", marker),
                    journal.replace("422 Unprocessable Entity", marker),
                    journal.replace('2007', 'true'), journal.replace('2007', '100000'),
                    journal.replace('2007', '-1'), journal.replace('2007', '0'),
                    journal + json.dumps({"type": "unsupported", "@message": marker}),
                    journal.replace('"severity": "error"', '"severity": "invalid"') + json.dumps(diagnostic),
                    journal + json.dumps({"type": "diagnostic", "diagnostic": {"severity": "warning"}}),
                    journal + json.dumps(version), journal + "malformed", "", " " * 8388609):
            capture.write_text(bad, encoding="utf-8")
            assert mail.apply_failure_summary(capture) == {"classification": "UNCLASSIFIED"}
        capture.write_text(journal, encoding="utf-8")
        capture.chmod(0o644)
        assert mail.apply_failure_summary(capture) == {"classification": "UNCLASSIFIED"}


def check_state_contract(mail) -> None:
    data = state_envelope_fixture()
    assert mail.state_ciphertext(data) == "age1" + "q" * 58
    for bad in invalid_state_envelopes(data):
        try:
            mail.state_ciphertext(bad)
            raise AssertionError("invalid source carrier accepted")
        except mail.NativeSourceHold:
            pass

    values = {"AWS_ACCESS_KEY_ID": "SYNTHETIC_ID", "AWS_SECRET_ACCESS_KEY": "SYNTHETIC_SECRET",
              "RENT_STATE_PASSPHRASE": "c" * 64}
    assert mail._decode_state(json.dumps(values).encode()) == values
    for bad in (json.dumps(list(values.items())).encode(), json.dumps({**values, "UNKNOWN": "x"}).encode(),
                json.dumps({**values, "AWS_ACCESS_KEY_ID": 7}).encode(), b"{}", b"[]", b" " * 65537,
                b'{"AWS_ACCESS_KEY_ID":"x","AWS_ACCESS_KEY_ID":"y"}'):
        try:
            mail._decode_state(bad)
            raise AssertionError("invalid recovered payload accepted")
        except mail.NativeSourceHold:
            pass


def check_source() -> None:
    """Only the closed operation selector can reach protected input handling."""
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    modules = {(node.module if isinstance(node, ast.ImportFrom) else node.names[0].name)
               for node in imports}
    assert modules == {"__future__", "sys", "importlib.util", "dataclasses",
                       "hashlib", "re", "pathlib", "typing", "os", "signal",
                       "stat", "subprocess", "json", "types"}
    main_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    assert len(main_functions) == 1
    gate = main_functions[0].body[0]
    assert isinstance(gate, ast.If)
    assert [ast.unparse(node) for node in gate.body] == ["print(CLOSED_RESULT)", "return EXIT_INACTIVE"]
    assert "sys.argv[2] not in MAIL_OPERATIONS" in ast.unparse(gate.test)
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
    assert code.count("os.environ") == 1
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert not functions & {"native_plan", "native_inspect", "private_r2_object",
                            "retain_original_once", "inspect_original_once",
                            "apply_same_original_once", "require_same_original"}


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
        for operation in ("qualify", "preview", "apply"):
            done = subprocess.run(
                [sys.executable, "-I", str(ADAPTER), "--operation", operation],
                cwd=home, env=env, capture_output=True, text=True, timeout=6, check=False,
            )
            assert done.returncode == 78 and done.stderr == ""
            assert json.loads(done.stdout)["status"] == "INPUT_UNPROVEN"
            assert marker not in done.stdout and not child.exists()
        # The completed recovery is retired: it is an unsupported operation, refused before any input is read.
        done = subprocess.run(
            [sys.executable, "-I", str(ADAPTER), "--operation", "recover"],
            cwd=home, env=env, capture_output=True, text=True, timeout=6, check=False,
        )
        assert done.returncode == 78 and done.stderr == ""
        assert json.loads(done.stdout) == CLOSED and marker not in done.stdout and not child.exists()
        assert sorted(p.name for p in home.iterdir()) == ["bin"], "unexpected state/output file"


def check_manual_job() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    gate = "    if: ${{ github.repository == 'roccho-org/envs'"
    assert content.count(gate) == 1
    assert content.index(gate) < content.index("    environment:") < content.index("    steps:")
    assert content.count("\n    if:") == 1
    assert "on:\n  workflow_dispatch:" in content
    assert "      expected_source_sha:" in content
    for name, count in (("MAIL_CONFIG", 2), ("CLOUDFLARE_API_TOKEN", 2), ("AWS_ACCESS_KEY_ID", 0),
                        ("AWS_SECRET_ACCESS_KEY", 0), ("RENT_STATE_PASSPHRASE", 0), ("MAIL_STATE_INPUTS", 1)):
        assert content.count("${{ secrets." + name + " }}") == count
    assert "secrets.SOPS_AGE_KEY" not in content and "secrets.MAIL_STATE_AGE_KEY" not in content
    for clause in ("github.sha == inputs.expected_source_sha", "github.run_attempt == 1",
                   "github.actor == 'roccho-dev'", "github.actor_id == '40359643'",
                   "github.triggering_actor == 'roccho-dev'"):
        assert clause in content
    assert "${{ vars." not in content
    assert "options: [qualify, preview, apply]" in content and "default: qualify" in content
    assert "ref: afd831dba8f401fb37fc20c27ab8d1f176102050" in content
    assert "mail-state.sops.json" not in content and "cancel-in-progress: false" in content
    assert "contains(fromJSON('[\"qualify\",\"preview\",\"apply\"]'), inputs.operation)" in content
    assert "    environment: dev-projection\n" in content and "dev-rent-" not in content
    assert "recover" not in content and "recipient" not in content
    assert "    needs:" not in content
    assert content.count('"$ENVS_EFFECT_BIN/mail-routing-root" --operation "$MAIL_OPERATION"') == 1


def check_native_source_and_plan() -> None:
    """Synthetic serial SOURCE stages, refusals and immutable native input."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("mail_native", ADAPTER)
    assert spec is not None and spec.loader is not None
    mail = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mail
    try:
        spec.loader.exec_module(mail)
        check_state_contract(mail)
        check_preview_summary(mail)
        check_apply_failure_summary(mail)
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
                assert mail.OPS_MAIL_COMMIT == "afd831dba8f401fb37fc20c27ab8d1f176102050"
                assert mail.OPS_MAIL_TREE == "e6152ee455f1bb699cfb12e1ed84b4885afcd618"
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
                tools = mail.NativeToolset(tofu=tofu, _proof=mail._NATIVE_TOOL_PROOF)
                must_refuse(lambda: mail.native_bin(tofu, "tofu", mail.NativeToolset(tofu=tofu)),
                            "unverified toolset constructor")
                private = home / "private"
                backend = private / "backend.hcl"
                saved_plan = private / "saved-plan.enc"
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
                    "verified_destination_id": "d" * 32, "manage_dns": False,
                    "manage_destination": False, "manage_rule": False, "preflight_approved": False,
                }
                marker = "PRIVATE_AFTER_INPUT_CANARY"
                after_slots = {
                    "CLOUDFLARE_API_TOKEN": marker + "-cf", "AWS_ACCESS_KEY_ID": marker + "-id",
                    "AWS_SECRET_ACCESS_KEY": marker + "-secret", "RENT_STATE_PASSPHRASE": "c" * 64,
                }
                context = dict(environment_name="dev-projection", home=private,
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
                    for key in ("CLOUDFLARE_API_TOKEN", "age_identity", "passphrase", "TF_ENCRYPTION", "plan_bucket", "plan_key", "unknown"):
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
                        ("state_bucket", "bad bucket"),
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
                    for changed in (dict(environment_name="dev-rent-tunnel"), dict(home=None),
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

                # The consumer initializes each fresh runner, then selects
                # exactly one command. Init/error/timeout never retries or
                # starts the other operation; successful apply is unverified.
                for operation, init_code, operation_code, expected in (
                    ("preview", 0, 0, ("NO_OP", 0)),
                    ("preview", 0, 2, ("DELTA", 2)),
                    ("apply", 0, 0, ("APPLIED_UNVERIFIED", 0)),
                    ("apply", 0, 1, ("OPERATION_UNPROVEN", 1)),
                    ("apply", 0, 124, ("OPERATION_UNPROVEN", 124)),
                    ("apply", 0, 125, ("OPERATION_UNPROVEN", 125)),
                    ("apply", 1, 0, ("INIT_UNPROVEN", 1)),
                    ("preview", 124, 0, ("INIT_UNPROVEN", 124)),
                    ("apply", 125, 0, ("INIT_UNPROVEN", 125)),
                ):
                    commands = []
                    def consumer_factory(selected, selected_tools):
                        assert selected is composed and selected_tools is tools
                        def consume(command):
                            commands.append(command)
                            code = init_code if len(commands) == 1 else operation_code
                            return mail.PrivateNativeResult(code)
                        return consume
                    result = mail.run_after(operation, composed, tools, runner_factory=consumer_factory)
                    assert result == expected
                    assert len(commands) == (1 if init_code else 2)
                    assert commands[0].argv[2] == "init"
                    if init_code == 0:
                        assert commands[1].argv[2:] == (
                            mail.NOOP_PLAN_ARGS if operation == "preview" else mail.APPLY_ARGS)
                    captures = [name for cmd in commands for name in (cmd.private_stdout, cmd.private_stderr)]
                    assert len(captures) == len(set(captures))
                    assert all(Path(name).parent == private for name in captures)
                    assert marker not in repr(result)
                for fail_at, expected in ((1, "INIT_UNPROVEN"), (2, "OPERATION_UNPROVEN")):
                    calls = []
                    def exception_factory(*_args):
                        def consume(command):
                            calls.append(command)
                            if len(calls) == fail_at:
                                raise OSError(marker)
                            return mail.PrivateNativeResult(0)
                        return consume
                    assert mail.run_after("apply", composed, tools, runner_factory=exception_factory) == (expected, 1)
                    assert len(calls) == fail_at
                must_refuse(lambda: mail.run_after("destroy", composed, tools), "unsupported consumer operation")
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
                        assert "MAIL_STATE_INPUTS" not in child_env and "SOPS_AGE_KEY" not in child_env
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
                        "-lock=true", "-detailed-exitcode", "-json",
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
                    values=invalid,
                ).check(), "ambient foreign AWS profile")
                must_refuse(lambda: real_runner(mail.NativeCommand(
                    (tofu, "-chdir=" + str(ops), "destroy"),
                    private_stdout=str(private / "destroy.out"),
                    private_stderr=str(private / "destroy.err"),
                )), "unselected native destroy command")
                assert not (private / "destroy.out").exists()

                # Apply re-plans in its own single child. It consumes no saved
                # plan and does not interpret an earlier preview's delta as GO.
                for name, code, pause, start_failure, expected in (
                    ("zero", 0, False, False, 0),
                    ("error", 1, False, False, 1),
                    ("two-is-error", 2, False, False, 1),
                    ("timeout", 0, True, False, 124),
                    ("start-failure", 0, False, True, 125),
                ):
                    command = mail.native_apply(
                        tofu, ops, tools,
                        private_stdout=private / ("apply-" + name + ".out"),
                        private_stderr=private / ("apply-" + name + ".err"),
                    )
                    assert command.argv == (
                        tofu, "-chdir=" + str(ops), "apply", "-input=false",
                        "-lock=true", "-auto-approve", "-json",
                    )
                    assert run_synthetic(command, name, code=code, pause=pause,
                                         start_failure=start_failure).returncode == expected
                starts = []
                def unapproved_child(*args, **kwargs):
                    starts.append(True)
                    raise AssertionError("unselected apply started a child")
                mail.subprocess.Popen = unapproved_child
                try:
                    baseline = (tofu, "-chdir=" + str(ops), *mail.APPLY_ARGS)
                    for index, argv in enumerate((
                        baseline[:-1], baseline + (str(saved_plan),),
                        baseline[:4] + ("-lock=false", baseline[-1]),
                        baseline[:-1] + ("-destroy",),
                        baseline + ("-target=cloudflare_email_routing_rule.literal",),
                        baseline + ("-var-file=foreign.tfvars",),
                        ("/usr/bin/tofu", *baseline[1:]),
                    )):
                        out, err = private / f"bad-apply-{index}.out", private / f"bad-apply-{index}.err"
                        command = mail.NativeCommand(argv, private_stdout=str(out), private_stderr=str(err))
                        must_refuse(lambda command=command: real_runner(command), "altered automatic apply")
                        assert not out.exists() and not err.exists()
                    for out, err in ((backend, private / "apply-backend.err"),
                                     (home / "outside-apply.out", private / "apply-outside.err"),
                                     (private / "apply-alias", private / "apply-alias")):
                        must_refuse(lambda out=out, err=err: real_runner(mail.native_apply(
                            tofu, ops, tools, private_stdout=out, private_stderr=err,
                        )), "unprotected apply capture")
                    late = mail.native_apply(tofu, ops, tools,
                                             private_stdout=private / "late-apply.out",
                                             private_stderr=private / "late-apply.err")
                    Path(late.private_stderr).write_bytes(b"RETAINED_CAPTURE")
                    must_refuse(lambda: real_runner(late), "late-created apply capture")
                    assert Path(late.private_stderr).read_bytes() == b"RETAINED_CAPTURE"
                    assert not Path(late.private_stdout).exists()
                    drift = mail.native_apply(tofu, ops, tools,
                                              private_stdout=private / "drift-apply.out",
                                              private_stderr=private / "drift-apply.err")
                    (ops / "extra.tf").write_text("unapproved", encoding="utf-8")
                    try:
                        must_refuse(lambda: real_runner(drift), "source drift before apply")
                    finally:
                        (ops / "extra.tf").unlink()
                    assert starts == []
                finally:
                    mail.subprocess.Popen = real_popen
            finally:
                for name, val in original_blobs.items():
                    setattr(mail, name, val)
    finally:
        sys.modules.pop(spec.name, None)


def check_manual_integration(mail, manifest: str, identity: str, recipient: str) -> None:
    """Actual input/file/runner consumer; only process spawn is synthetic.

    Runs under the supplied Linux interpreter and real manifest. Fixture
    Ops blobs are deliberately synthetic; no provider/state call is made.
    """
    import importlib.util
    fixtures = {
        "main.tf": ("OPS_MAIN_BLOB", b"synthetic accepted mail source\n"),
        ".terraform.lock.hcl": ("OPS_LOCK_BLOB", b"synthetic accepted provider lock\n"),
        "README.md": ("OPS_README_BLOB", b"synthetic operator notes\n"),
        "safety.tftest.hcl": ("OPS_TEST_BLOB", b"synthetic source test\n"),
    }
    old_blobs = {attr: getattr(mail, attr) for attr, _ in fixtures.values()}
    old_cipher = mail.STATE_CIPHERTEXT
    real_popen = mail.subprocess.Popen
    marker = "PRIVATE_MANUAL_INTEGRATION_CANARY"
    try:
        for attr, data in fixtures.values():
            setattr(mail, attr, mail.git_blob(data))
        with tempfile.TemporaryDirectory(prefix="mail-entry-provided-") as directory:
            cipher_home = Path(directory) / "cipher"
            cipher_home.mkdir(mode=0o700)
            tools = mail.provided_native_tools(ROOT, manifest, sys.executable)
            values = {"AWS_ACCESS_KEY_ID": marker, "AWS_SECRET_ACCESS_KEY": marker,
                      "RENT_STATE_PASSPHRASE": "c" * 64}
            encrypted = mail._sops(tools, cipher_home, json.dumps(values).encode(), recipient=recipient)
            mail.state_ciphertext(encrypted, recipient, values)
            for bad in invalid_state_envelopes(encrypted):
                try:
                    mail.state_ciphertext(bad)
                    raise AssertionError("malformed real SOPS carrier accepted")
                except mail.NativeSourceHold:
                    pass
            assert mail._decode_state(mail._sops(tools, cipher_home, encrypted, identity=identity)) == values
            mail.STATE_CIPHERTEXT = cipher_home / "mail-state.sops.json"
            mail.STATE_CIPHERTEXT.write_bytes(encrypted)
            recovery = Path(directory) / "recovery"
            recovery.mkdir(mode=0o700)
            # The completed one-time recovery is retired: the operation is refused before any slot or child.
            retired_env = {**values, "MAIL_STATE_AGE_RECIPIENT": recipient,
                           "MAIL_HOME": str(recovery), "ENVS_EFFECT_TOOLCHAIN": manifest,
                           "CLOUDFLARE_API_TOKEN": "UNUSED_CF_INPUT", "MAIL_STATE_AGE_KEY": "UNUSED_AGE_INPUT"}
            try:
                mail.manual_entry("recover", retired_env)
                raise AssertionError("retired recovery operation accepted")
            except mail.NativeSourceHold as error:
                assert str(error) == "MAIL_OPERATION_UNSELECTED"
            assert list(recovery.iterdir()) == [], "the retired recovery wrote an output"
            recovered_cipher = encrypted
            assert all(value.encode() not in recovered_cipher for value in values.values())
            for bad in (b"{}", b"[]", json.dumps(list(values.items())).encode(),
                        b'{"RENT_STATE_PASSPHRASE":"x","RENT_STATE_PASSPHRASE":"y"}',
                        json.dumps({**values, "UNKNOWN": "private"}).encode()):
                try:
                    mail._decode_state(bad)
                    raise AssertionError("invalid recovered input accepted")
                except mail.NativeSourceHold:
                    pass
            try:
                mail._sops(tools, cipher_home, recovered_cipher, identity="AGE-SECRET-KEY-INVALID")
                raise AssertionError("wrong identity decrypted the carrier")
            except mail.NativeSourceHold:
                pass

            # Real GET observer with only its socket boundary replaced.
            # Qualification must not enter SOPS or state-input parsing.
            read_spec = importlib.util.spec_from_file_location("mail_read_fixtures", ROOT / "checks/test_mail_routing_read.py")
            read_tests = importlib.util.module_from_spec(read_spec)
            read_spec.loader.exec_module(read_tests)
            reader = mail._source_module("mail_routing_read")
            source_module = mail._source_module
            requests = read_tests.Fake()
            reader.safe_opener = lambda: requests
            mail._source_module = lambda name: reader if name == "mail_routing_read" else source_module(name)
            qualification_config = {
                "account_id": read_tests.ACCOUNT, "zone_id": read_tests.ZONE,
                "zone_name": read_tests.DOMAIN, "alias_address": "fixture@" + read_tests.DOMAIN,
                "destination_address": "fixture@gmail.com", "rule_priority": 0,
                "state_bucket": "mail-state-fixture", "state_key": "mail-m0/state/fixture.tfstate",
                "verified_destination_id": None, "manage_dns": True,
                "manage_destination": True, "manage_rule": False, "preflight_approved": False,
            }
            qualification_env = {"MAIL_CONFIG": json.dumps(qualification_config),
                                 "MAIL_HOME": str(recovery), "ENVS_EFFECT_TOOLCHAIN": manifest,
                                 "CLOUDFLARE_API_TOKEN": read_tests.TOKEN,
                                 "MAIL_STATE_INPUTS": "UNUSED_STATE_INPUTS", "SOPS_AGE_KEY": identity}
            original_sops = mail._sops
            def reject_crypto(*args, **kwargs):
                raise AssertionError("GET qualification entered crypto")
            try:
                mail._sops = reject_crypto
                qualified = mail.manual_entry("qualify", qualification_env)
                assert qualified["status"] == "READ_OBSERVED" and qualified["write_authority"] == "NOT_PROVEN"
                assert "key_recovery" not in qualified and "key_check_stage" not in qualified
                assert all(private not in json.dumps(qualified) for private in
                           (read_tests.TOKEN, read_tests.DOMAIN, identity, "UNUSED_STATE_INPUTS"))
                denied = read_tests.Fake(deny="/user/tokens/verify")
                reader.safe_opener = lambda: denied
                assert mail.manual_entry("qualify", qualification_env)["status"] != "READ_OBSERVED"
            finally:
                mail._source_module, mail._sops = source_module, original_sops
            for index, (operation, init_code, operation_code, expected) in enumerate((
                ("preview", 0, 0, ("NO_OP", 0)),
                ("preview", 0, 2, ("DELTA", 2)),
                ("apply", 0, 0, ("APPLIED_UNVERIFIED", 0)),
                ("apply", 1, 0, ("INIT_UNPROVEN", 1)),
                ("apply", 0, 1, ("OPERATION_UNPROVEN", 1)),
            )):
                home = Path(directory) / str(index)
                home.mkdir(mode=0o700)
                root = home / "root"
                root.mkdir(mode=0o700)
                for name, (_, data) in fixtures.items():
                    (root / name).write_bytes(data)
                    (root / name).chmod(0o600)
                config = {
                    "account_id": "a" * 32, "zone_id": "b" * 32,
                    "zone_name": "example.invalid", "alias_address": "fixture@example.invalid",
                    "destination_address": "fixture@gmail.com", "rule_priority": 0,
                    "state_bucket": "mail-state-fixture", "state_key": "mail-m0/state/fixture.tfstate",
                    "verified_destination_id": None, "manage_dns": True,
                    "manage_destination": True, "manage_rule": False, "preflight_approved": True,
                }
                environ = {
                    "MAIL_HOME": str(home), "MAIL_CONFIG": json.dumps(config),
                    "ENVS_EFFECT_TOOLCHAIN": manifest, "CLOUDFLARE_API_TOKEN": marker,
                    "AWS_ACCESS_KEY_ID": marker, "AWS_SECRET_ACCESS_KEY": marker,
                    "RENT_STATE_PASSPHRASE": "c" * 64,
                    "MAIL_STATE_INPUTS": json.dumps(values), "SOPS_AGE_KEY": identity,
                    "TF_LOG": "TRACE", "AWS_PROFILE": marker, "HTTPS_PROXY": marker,
                }
                starts = []
                def spawn(argv, **kwargs):
                    assert argv[0] != tools.sops, "native operation entered SOPS"
                    starts.append(tuple(argv))
                    assert argv[1] == "-chdir=" + str(root)
                    assert argv[2] == ("init" if len(starts) == 1 else
                                       "plan" if operation == "preview" else "apply")
                    assert kwargs["umask"] == 0o077 and kwargs["close_fds"]
                    assert kwargs["stdin"] == subprocess.DEVNULL
                    child_env = kwargs["env"]
                    assert "MAIL_STATE_INPUTS" not in child_env and "SOPS_AGE_KEY" not in child_env
                    assert child_env["CLOUDFLARE_API_TOKEN"] == marker
                    assert child_env["AWS_SECRET_ACCESS_KEY"] == marker
                    assert child_env["TF_VAR_alias_address"] == config["alias_address"]
                    assert 'key_provider "pbkdf2" "mail_m0"' in child_env["TF_ENCRYPTION"]
                    assert not {"TF_LOG", "AWS_PROFILE", "HTTPS_PROXY", "PATH"} & set(child_env)
                    for stream in (kwargs["stdout"], kwargs["stderr"]):
                        assert stat.S_IMODE(os.fstat(stream).st_mode) == 0o600
                    code = init_code if len(starts) == 1 else operation_code
                    stdout = preview_journal(operation_code == 2, marker) if len(starts) == 2 and operation == "preview" else marker
                    script = ("import sys; sys.stdout.write(" + repr(stdout) + "); "
                              "sys.stderr.write(" + repr(marker) + "); sys.exit(" + str(code) + ")")
                    return real_popen([sys.executable, "-I", "-c", script], **kwargs)
                mail.subprocess.Popen = spawn
                actual = mail.manual_entry(operation, environ)
                if operation == "preview" and init_code == 0 and operation_code in (0, 2):
                    assert actual == {"kind": "envs.mailM0.preview.v1", "status": expected[0],
                                      "changes": {"destination": "create", "dns": "create"} if operation_code == 2 else {},
                                      "drift": {}, "totals": {"add": 2 if operation_code == 2 else 0, "change": 0, "remove": 0}}
                elif operation == "apply" and expected[1] != 0:
                    assert actual == {"kind": "envs.mailM0.manual.v1", "status": expected[0],
                                      "stage": "init" if init_code else "apply",
                                      "failure": {"classification": "UNCLASSIFIED"}, "_code": expected[1]}
                else:
                    assert actual == expected
                assert len(starts) == (1 if init_code else 2)
                backend = home / "backend.hcl"
                assert stat.S_IMODE(backend.stat().st_mode) == 0o600
                assert backend.read_text() == (
                    'bucket = "mail-state-fixture"\nkey = "mail-m0/state/fixture.tfstate"\n'
                    'endpoints = { s3 = "https://' + "a" * 32 + '.r2.cloudflarestorage.com" }\n')
                captures = [home / "init.out", home / "init.err"]
                if init_code == 0:
                    captures += [home / (operation + ".out"), home / (operation + ".err")]
                assert all(path.read_text() == (preview_journal(operation_code == 2, marker)
                           if path.name == "preview.out" else marker) for path in captures)
                assert not any(path.suffix == ".tfplan" for path in home.rglob("*"))

            # Refusals never launch a child, even with valid other inputs.
            for index, failure in enumerate(("config", "slots", "preflight", "source")):
                home = Path(directory) / ("refused-" + str(index))
                home.mkdir(mode=0o700)
                root = home / "root"
                root.mkdir(mode=0o700)
                for name, (_, data) in fixtures.items():
                    (root / name).write_bytes(data)
                bad = {**environ, "MAIL_HOME": str(home)}
                if failure == "config":
                    bad["MAIL_CONFIG"] = '{"private":' + marker
                elif failure == "slots":
                    bad["CLOUDFLARE_API_TOKEN"] = marker + "\n"
                elif failure == "preflight":
                    bad["MAIL_CONFIG"] = json.dumps({**config, "preflight_approved": False})
                else:
                    (root / "main.tf").write_bytes(b"source drift\n")
                def forbidden_spawn(*_args, **_kwargs):
                    raise AssertionError("refused input started a child")
                mail.subprocess.Popen = forbidden_spawn
                try:
                    mail.manual_entry("apply", bad)
                    raise AssertionError("unproven manual input admitted")
                except mail.NativeSourceHold as error:
                    assert marker not in str(error) and "\n" not in str(error)
    finally:
        mail.subprocess.Popen = real_popen
        mail.STATE_CIPHERTEXT = old_cipher
        for attr, value in old_blobs.items():
            setattr(mail, attr, value)


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
        assert mail.native_bin(selection.tofu, "tofu", selection) == selection.tofu
        with tempfile.TemporaryDirectory(prefix="mail-check-age-") as directory:
            key = Path(directory) / "synthetic.key"
            age = os.environ.get("MAIL_TEST_AGE_KEYGEN")
            assert age and age.startswith("/")
            generated = subprocess.run([age, "-o", str(key)], capture_output=True, check=False, timeout=15)
            assert generated.returncode == 0
            public = subprocess.run([age, "-y", str(key)], capture_output=True, text=True, check=False, timeout=15)
            assert public.returncode == 0
            check_manual_integration(mail, from_existing["manifest"], key.read_text(), public.stdout.strip())
        wrapper = str(Path(entry).with_name("mail-routing-root"))
        for operation in ("preview", "apply"):
            refused = subprocess.run(
                [wrapper, "--operation", operation], env={"LANG": "C"},
                capture_output=True, text=True, check=False, timeout=15,
            )
            assert refused.returncode == 78 and refused.stderr == ""
            assert json.loads(refused.stdout)["status"] == "INPUT_UNPROVEN"
        fake_nix = "/nix/store/" + "0" * 32 + "-other/bin/tofu"
        try:
            mail.native_bin(fake_nix, "tofu", selection)
            raise AssertionError("forged Nix path was treated as selected")
        except mail.NativeSourceHold:
            pass
        for binary, opt, mark in (
            (selection.tofu, "version", "OpenTofu v1.12.3"),
        ):
            completed = subprocess.run([binary, opt], capture_output=True, text=True,
                                       check=False, timeout=15)
            assert completed.returncode == 0 and mark in completed.stdout
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
        # Native data reads use apply-style hooks even during plan. The local
        # synthetic input state contains no credentials and contacts no service.
        with tempfile.TemporaryDirectory(prefix="mail-native-data-read-") as directory:
            fixture = Path(directory)
            canary = "SYNTHETIC_PRIVATE_DATA_READ"
            (fixture / "input.tfstate").write_text(json.dumps({
                "version": 4, "terraform_version": "1.12.3", "serial": 1,
                "lineage": "00000000-0000-4000-8000-000000000000",
                "outputs": {"canary": {"value": canary, "type": "string", "sensitive": True}},
                "resources": [],
            }), encoding="utf-8")
            (fixture / "main.tf").write_text(
                'data "terraform_remote_state" "fixture" {\n  backend = "local"\n'
                '  config = { path = "${path.module}/input.tfstate" }\n}\n'
                'resource "terraform_data" "fixture" { input = data.terraform_remote_state.fixture.outputs.canary }\n',
                encoding="utf-8")
            env = {"HOME": str(fixture), "TMPDIR": str(fixture), "LANG": "C",
                   "TF_INPUT": "0", "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"}
            for stage, args, code in (("init", ("init", "-backend=false", "-input=false"), 0),
                                      ("preview", mail.NOOP_PLAN_ARGS, 2)):
                native = subprocess.run([selection.tofu, "-chdir=" + str(fixture), *args], env=env,
                                        stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=15)
                assert native.returncode == code, "native data-read fixture failed"
            journal = native.stdout.decode("utf-8")
            events = [json.loads(row) for row in journal.splitlines()]
            reads = [event for event in events if event.get("type") in ("apply_start", "apply_complete")]
            assert {event["type"] for event in reads} == {"apply_start", "apply_complete"}
            assert all(event["hook"]["action"] == "read" for event in reads)
            home = fixture / "private-summary"
            home.mkdir(mode=0o700)
            capture = home / "data.jsonl"
            capture.write_text(journal.replace("data.terraform_remote_state.fixture", "data.cloudflare_email_routing_address.checked[0]")
                               .replace("terraform_data.fixture", "cloudflare_email_routing_rule.literal[0]"), encoding="utf-8")
            capture.chmod(0o600)
            result = mail.preview_summary(capture, native.returncode)
            assert result["changes"] == {"rule": "create"} and result["totals"] == {"add": 1, "change": 0, "remove": 0}
            assert canary not in repr(result)
            assert not (fixture / "terraform.tfstate").exists() and not list(fixture.glob("*.tfplan"))
        # An actual provider-free native apply re-plans, writes encrypted local
        # TEST state and converges. No saved plan, HTTP backend or provider is
        # involved; this proves command behavior, not the real Mail effect.
        with tempfile.TemporaryDirectory(prefix="mail-native-apply-provided-") as directory:
            fixture = Path(directory)
            canary = "SYNTHETIC_NATIVE_APPLY_ONLY"
            (fixture / "main.tf").write_text(
                'terraform {\n  encryption {\n    state { enforced = true }\n'
                '    plan { enforced = true }\n  }\n}\n'
                'resource "terraform_data" "fixture" { input = "' + canary + '" }\n',
                encoding="utf-8",
            )
            env = {"HOME": str(fixture), "TMPDIR": str(fixture), "LANG": "C",
                   "TF_INPUT": "0", "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1",
                   "AWS_EC2_METADATA_DISABLED": "true", "TF_ENCRYPTION": native_encryption}
            for stage, args, expected in (
                ("init", ("init", "-backend=false", "-input=false"), 0),
                ("preview", mail.NOOP_PLAN_ARGS, 2),
                ("apply", mail.APPLY_ARGS, 0),
                ("converged", mail.NOOP_PLAN_ARGS, 0),
            ):
                with (fixture / (stage + ".out")).open("xb") as out, (fixture / (stage + ".err")).open("xb") as err:
                    native = subprocess.run(
                        [selection.tofu, "-chdir=" + str(fixture), *args], env=env,
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                        umask=0o077, check=False, timeout=15,
                    )
                assert native.returncode == expected, "provided automatic apply did not converge"
                if stage in ("preview", "converged"):
                    journal = (fixture / (stage + ".out")).read_text(encoding="utf-8")
                    private_summary = fixture / (stage + "-summary")
                    private_summary.mkdir(mode=0o700)
                    capture = private_summary / "capture.jsonl"
                    # Test-only resource-name translation; actual native JSON
                    # and exit0/2 still drive the strict privacy boundary.
                    capture.write_text(journal.replace("terraform_data.fixture", "cloudflare_email_routing_dns.zone[0]"), encoding="utf-8")
                    capture.chmod(0o600)
                    try:
                        summary = mail.preview_summary(capture, native.returncode)
                    except mail.NativeSourceHold:
                        # Synthetic fixture only: expose schema metadata to
                        # diagnose a version/event compatibility failure.
                        events = [json.loads(row) for row in capture.read_text(encoding="utf-8").splitlines()]
                        print("SYNTHETIC_NATIVE_SCHEMA", [(event.get("type"), event.get("ui"),
                              event.get("tofu"), event.get("terraform"), event.get("changes")) for event in events])
                        raise
                    assert summary["totals"] == {"add": 1 if stage == "preview" else 0, "change": 0, "remove": 0}
                    assert canary not in repr(summary)
            state = (fixture / "terraform.tfstate").read_bytes()
            assert state and canary.encode() not in state, "synthetic state was not encrypted"
            assert not any(path.suffix in (".tfplan", ".enc") for path in fixture.iterdir())
    finally:
        sys.modules.pop(spec.name, None)


def main() -> None:
    check_source()
    check_native_entry()
    check_manual_job()
    check_native_source_and_plan()
    check_provided_native_toolchain()
    print("mail M0 pinned source/tools, private input/capture, init-first single operation and CLI refusal: PASS; no real effects")


if __name__ == "__main__":
    main()
