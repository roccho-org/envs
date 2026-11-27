#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import http.server
import importlib.util
import io
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The Jev self-test's fixture store, toolchain manifest and environment helpers are shared, not copied.
SPEC = importlib.util.spec_from_file_location("envs_jev_fixtures", ROOT / "checks/test_jev_api.py")
assert SPEC is not None and SPEC.loader is not None
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
jev = fixtures.jev
TOOLS = fixtures.TOOLS

# Every live value is generated per run, so its bytes never appear in tracked source.
RECIPIENT = fixtures.RECIPIENT
REF_TOKEN = "ref-token-" + secrets.token_urlsafe(24)


def email(role: str) -> str:
    return f"{role}-{secrets.token_hex(6)}@versa.invalid"


# The owner alone, and the owner with two invited people (comma, LF and CRLF lists, with blanks around entries).
OWNER = email("owner")
INVITED = [OWNER, email("guest"), email("peer")]
LISTS = {
    "single": (OWNER, [OWNER]),
    "comma": (",".join(INVITED), INVITED),
    "comma-spaced": (" " + " , ".join(INVITED) + "\t", INVITED),
    "lf": ("\n".join(INVITED), INVITED),
    "crlf": ("\r\n".join(INVITED), INVITED),
}
VALUES = {
    "ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST,
    "VERSA_CLOUDFLARE_API_TOKEN": "cf-" + secrets.token_urlsafe(24),
    "VERSA_STATE_PASSPHRASE": secrets.token_hex(32),
    "VERSA_ACCESS_EMAILS": OWNER,
    "VERSA_CLOUDFLARE_ACCOUNT_ID": fixtures.ACCOUNT_ID,
    "VERSA_CLOUDFLARE_ZONE_ID": secrets.token_hex(16),
    "VERSA_SERVICE_TOKEN_DURATION": f"{secrets.randbelow(90000) + 10000}h",
    "VERSA_HANDOFF_AGE_RECIPIENT": RECIPIENT,
    jev.ROOT_STATE_GIT_TOKEN: REF_TOKEN,
}
TOKEN = secrets.token_urlsafe(180)
CLIENT_ID = secrets.token_hex(16) + ".access"
CLIENT_SECRET = secrets.token_hex(32)
PRIVATE = [*(VALUES[name] for name in jev.VERSA_SECRETS), *INVITED, REF_TOKEN, TOKEN, CLIENT_ID, CLIENT_SECRET]
COMMIT = secrets.token_hex(20)


def credentials() -> bytes:
    return json.dumps({"tunnel_token": TOKEN, "service_token_id": CLIENT_ID, "service_token_value": CLIENT_SECRET}).encode()


def envelope(recipients: tuple[str, ...] = (RECIPIENT,), keys: tuple[str, ...] = jev.VERSA_KEYS, data: str = "fixture") -> bytes:
    body = "".join(f"{key}: ENC[AES256_GCM,data:{data}]\n" for key in keys)
    return (body + "sops:\n  age:\n" + "".join(f"    - recipient: {item}\n" for item in recipients)).encode()


def fresh_root() -> Path:
    # The versa plane before its first handoff, whatever the checkout holds.
    root = fixtures.copy_root()
    (root / jev.VERSA_CIPHERTEXT).unlink(missing_ok=True)
    jev.set_dev_active(root, False, (jev.VERSA_PLANE,))
    jev.validate_contracts(root)
    return root


def retained_root() -> Path:
    # A previous handoff's envelope and ACTIVE plane, which a failure before the write leaves byte-identical.
    root = fresh_root()
    (root / jev.VERSA_CIPHERTEXT).parent.mkdir(parents=True, exist_ok=True)
    (root / jev.VERSA_CIPHERTEXT).write_bytes(envelope(data="prior"))
    jev.set_dev_active(root, True, (jev.VERSA_PLANE,))
    jev.validate_contracts(root)
    return root


def snapshot(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in jev.repository_files(root)}


class Children:
    # Fake git, OpenTofu and sops. ref is the ls-remote exit; fail names one step that returns non-zero.
    def __init__(self, ref: int = 2, fail: str | None = None, output: bytes | None = None,
                 recipient: str | None = None) -> None:
        self.ref, self.fail, self.output, self.recipient = ref, fail, credentials() if output is None else output, recipient
        self.calls: list[tuple[list[str], bytes | None, dict[str, str]]] = []

    @staticmethod
    def step(argv: list[str]) -> str:
        return argv[3] if argv[0] == TOOLS["git"] else argv[2] if argv[0] == TOOLS["tofu"] else "sops"

    def __call__(self, argv, input_data, env):
        argv, env = list(argv), dict(env or {})
        self.calls.append((argv, input_data, env))
        assert not any(value in item for value in PRIVATE for item in argv), argv
        assert jev.ROOT_STATE_GIT_TOKEN not in env, "the ref principal reached a non-backend child"
        step = self.step(argv)
        code = self.ref if step == "ls-remote" else 1 if step == self.fail else 0
        body = {"commit-tree": COMMIT.encode() + b"\n", "output": self.output,
                "sops": envelope((self.recipient or env.get("SOPS_AGE_RECIPIENTS", ""),))}.get(step, b"")
        return subprocess.CompletedProcess(argv, code, stdout=body if code == 0 else b"", stderr=b"synthetic")

    def steps(self) -> list[str]:
        return [self.step(argv) for argv, _, _ in self.calls]


class Backend:
    # A fake loopback upstream child: its GET reply decides PRESENT/ABSENT/UNKNOWN; stop is recorded.
    def __init__(self, reply: tuple[int, bytes] = (204, b"")) -> None:
        self.reply, self.spawned, self.gets, self.stopped = reply, [], [], False

    def spawn(self, argv, env):
        self.spawned.append((list(argv), dict(env)))
        backend = self

        class Process:
            def poll(self):
                return None

            def terminate(self):
                backend.stopped = True

            def wait(self, timeout=None):
                return 0

            kill = terminate

        return Process()

    def get(self, url):
        self.gets.append(url)
        return self.reply


def operate(root: Path, children: Children, backend: Backend, values: dict[str, str]) -> tuple[dict | None, str]:
    progress: dict[str, str] = {}
    result = None
    with fixtures.environment(values):
        try:
            result = jev.versa_root(root, runner=children, spawn=backend.spawn, local_get=backend.get,
                                    sleep=lambda _: None, progress=progress)
        except jev.EnvsError as exc:
            assert not any(value in str(exc) for value in PRIVATE), str(exc)
    assert not {"import", "destroy", "force-unlock"} & set(children.steps()), children.steps()
    assert not backend.spawned or backend.stopped, "the loopback backend outlived its operation"
    return result, progress["stage"]


def test_apply() -> None:
    # First handoff and a later one, on a missing and an existing state ref: the same converging operation.
    for make, ref in ((fresh_root, 2), (retained_root, 2), (fresh_root, 0), (retained_root, 0)):
        root, children, backend = make(), Children(ref=ref), Backend()
        before = {row["id"]: row for row in jev.load_jsonl(root / jev.ENVIRONMENTS)}
        result, stage = operate(root, children, backend, VALUES)
        assert result == {"kind": "envs.versaRootResult.v1", "status": "PASS",
                          "ciphertext": jev.VERSA_CIPHERTEXT.as_posix(), "recipient_count": 1,
                          "target_apply": "NOT_RUN", "client_access": "UNPROVED"}, result
        assert stage == "write"
        created = ["commit-tree", "push"] if ref == 2 else []
        assert children.steps() == ["ls-remote", *created, "init", "apply", "output", "sops"], children.steps()
        git = [call for call in children.calls if call[0][0] == TOOLS["git"]]
        url = "https://github.com/roccho-org/envs.git"
        assert git[0][0][1:] == ["-C", str(root), "ls-remote", "--exit-code", url, "refs/heads/tofu-state"]
        if ref == 2:
            assert git[1][0][3:] == ["commit-tree", jev.EMPTY_TREE, "-m", "tofu-state"]
            assert git[2][0][3:] == ["push", "--force-with-lease=refs/heads/tofu-state:", url,
                                     f"{COMMIT}:refs/heads/tofu-state"]
        for _, _, env in git:
            assert set(env) - {"TMPDIR", "LANG", "LC_ALL", "CI"} == {"PATH", "HOME", *jev.STATE_REF_AUTHOR}, sorted(env)
        # Only the backend child holds the ref principal, and it serves the versa state path.
        (argv, env), = backend.spawned
        assert argv[:2] == [TOOLS["terraform_backend_git"], "--address"] and env[jev.ROOT_STATE_GIT_TOKEN] == REF_TOKEN
        assert set(env) - {"TMPDIR", "LANG", "LC_ALL", "CI"} == {"PATH", "HOME", "GIT_USERNAME", jev.ROOT_STATE_GIT_TOKEN}
        assert backend.gets[0].startswith(f"http://{argv[2]}/?type=git&repository=https%3A%2F%2Fgithub.com%2Froccho-org"
                                          "%2Fenvs.git&ref=tofu-state&state=state%2Fdev-versa-cloudflare.json")
        tofu = [call for call in children.calls if call[0][0] == TOOLS["tofu"]]
        assert tofu[0][0][3:] == ["-input=false", "-no-color", "-lock=true", *jev.root_backend_config(backend.gets[0])]
        assert tofu[1][0][3:] == ["-input=false", "-auto-approve", "-no-color", "-lock=true"]
        assert tofu[2][0][3:] == ["-json", "credentials"]
        for _, stdin, env in tofu:
            assert stdin is None and set(env) - {"TMPDIR", "LANG", "LC_ALL", "CI"} == {
                "PATH", "HOME", "CLOUDFLARE_API_TOKEN", "TF_ENCRYPTION", "TF_VAR_account_id", "TF_VAR_zone_id",
                "TF_VAR_access_emails", "TF_VAR_service_token_duration", "TF_IN_AUTOMATION", "TF_INPUT"}, sorted(env)
            assert env["TF_ENCRYPTION"] == jev.encryption_config("k0", VALUES["VERSA_STATE_PASSPHRASE"])
            assert env["TF_VAR_access_emails"] == json.dumps([OWNER])
        (_, stdin, env), = [call for call in children.calls if call[0][0] == TOOLS["sops"]]
        assert set(env) <= {"HOME", "TMPDIR", "LANG", "LC_ALL", "CI", "PATH", "SOPS_AGE_RECIPIENTS"}
        assert env["SOPS_AGE_RECIPIENTS"] == RECIPIENT
        assert json.loads(stdin) == dict(zip(jev.VERSA_KEYS, (TOKEN, CLIENT_ID, CLIENT_SECRET)))
        assert (root / jev.VERSA_CIPHERTEXT).read_bytes() == envelope()
        after = {row["id"]: row for row in jev.load_jsonl(root / jev.ENVIRONMENTS)}
        assert after.pop(jev.VERSA_PLANE)["migration_state"] == "ACTIVE" and before.pop(jev.VERSA_PLANE) and after == before
        assert not any(value.encode() in data for value in PRIVATE for data in snapshot(root).values())
        assert not any(value in json.dumps(result) for value in PRIVATE)


def test_emails() -> None:
    # One email or several (comma, LF or CRLF separated, blanks trimmed) reach OpenTofu as one JSON list, in order.
    for label, (raw, expected) in LISTS.items():
        root, children, backend = fresh_root(), Children(ref=0), Backend()
        result, stage = operate(root, children, backend, {**VALUES, "VERSA_ACCESS_EMAILS": raw})
        assert result is not None and result["status"] == "PASS" and stage == "write", (label, stage)
        tofu = [env for argv, _, env in children.calls if argv[0] == TOOLS["tofu"]]
        assert len(tofu) == 3 and all(env["TF_VAR_access_emails"] == json.dumps(expected) for env in tofu), label
        assert json.loads(tofu[0]["TF_VAR_access_emails"]) == expected, label
        assert not any(value.encode() in data for value in [raw, *expected] for data in snapshot(root).values()), label
    # Empty lists, empty entries (a stray comma, a blank line, a trailing newline), invalid addresses and duplicates
    # (case-insensitive) are RED at gate before any child, and the message names no entry.
    guest = INVITED[1]
    for raw in ("", " ", ",", "\n", f"{OWNER},", f",{OWNER}", f"{OWNER},,{guest}", f"{OWNER}\n", f"{OWNER}\n\n{guest}",
                f"{OWNER}, ,{guest}", f"{OWNER}\r\n", "owner@versa", "owner versa@x.invalid", "a@b@versa.invalid",
                "@versa.invalid", "owner@", "owner@.invalid", "owner@versa..invalid", "own\x01er@versa.invalid",
                f"{OWNER}\r{guest}", f"{OWNER};{guest}", f"{OWNER},{guest},{OWNER}", f"{OWNER},{OWNER.upper()}"):
        root, children, backend = fresh_root(), Children(), Backend()
        before = snapshot(root)
        assert operate(root, children, backend, {**VALUES, "VERSA_ACCESS_EMAILS": raw}) == (None, "gate"), repr(raw)
        assert not children.calls and not backend.spawned and snapshot(root) == before, repr(raw)
        try:
            jev.versa_access_emails(raw)
        except jev.EnvsError as exc:
            assert not any(value in str(exc) for value in (OWNER, guest)) and (raw.strip() == "" or raw not in str(exc))
        else:
            raise AssertionError(f"accepted {raw!r}")
    # One invited address of the list in a tracked file is RED at gate, although the whole Secret is nowhere in Git.
    for leaked in INVITED:
        for raw in (LISTS["comma"][0], LISTS["lf"][0]):
            root, children, backend = fresh_root(), Children(), Backend()
            (root / "contracts/note.txt").write_text(f"invite {leaked}\n")
            assert raw.encode() not in (root / "contracts/note.txt").read_bytes()
            assert operate(root, children, backend, {**VALUES, "VERSA_ACCESS_EMAILS": raw}) == (None, "gate")
            assert not children.calls and not backend.spawned
            try:
                jev.reject_live_values(root, jev.VERSA_EMAILS, [raw, *jev.versa_access_emails(raw)])
            except jev.EnvsError as exc:
                assert leaked not in str(exc) and "contracts/note.txt" in str(exc)
            else:
                raise AssertionError("an invited email stored in Git was accepted")


def test_red() -> None:
    # Every refusal names its stage, stops the backend it started and leaves envelope and plane state unchanged.
    cases = (
        ({"VERSA_ACCESS_EMAILS": ""}, Children(), Backend(), "gate", []),
        ({"VERSA_ACCESS_EMAILS": f"{OWNER},"}, Children(), Backend(), "gate", []),
        ({"VERSA_ACCESS_EMAILS": "owner@versa"}, Children(), Backend(), "gate", []),
        ({"VERSA_ACCESS_EMAILS": f"{OWNER}\n{OWNER}"}, Children(), Backend(), "gate", []),
        ({"VERSA_STATE_PASSPHRASE": "z" * 64}, Children(), Backend(), "gate", []),
        ({"VERSA_HANDOFF_AGE_RECIPIENT": RECIPIENT + "," + RECIPIENT}, Children(), Backend(), "gate", []),
        ({jev.ROOT_STATE_GIT_TOKEN: ""}, Children(), Backend(), "gate", []),
        ({}, Children(ref=128), Backend(), "state_ref", ["ls-remote"]),
        ({}, Children(fail="push"), Backend(), "state_ref", ["ls-remote", "commit-tree", "push"]),
        ({}, Children(), Backend((500, b"")), "backend", ["ls-remote", "commit-tree", "push"]),
        ({}, Children(ref=0, fail="init"), Backend(), "init", ["ls-remote", "init"]),
        # A held lock (or any apply failure) refuses; nothing is unlocked or retried.
        ({}, Children(ref=0, fail="apply"), Backend(), "apply", ["ls-remote", "init", "apply"]),
        ({}, Children(ref=0, output=b'{"tunnel_token":"x"}'), Backend(), "output", ["ls-remote", "init", "apply", "output"]),
        ({}, Children(ref=0, fail="sops"), Backend(), "seal", ["ls-remote", "init", "apply", "output", "sops"]),
        ({}, Children(ref=0, recipient=fixtures.OCI_OTHER), Backend(), "seal",
         ["ls-remote", "init", "apply", "output", "sops"]),
    )
    for make in (fresh_root, retained_root):
        for overrides, children, backend, stage, steps in cases:
            root = make()
            before = snapshot(root)
            children.calls.clear()
            backend.spawned.clear()
            backend.stopped = False
            result, actual = operate(root, children, backend, {**VALUES, **overrides})
            assert result is None and actual == stage and children.steps() == steps, (stage, actual, children.steps())
            assert snapshot(root) == before, f"a refusal at {stage} changed a data file"


def test_contract() -> None:
    # The plane is ACTIVE exactly with its one-recipient envelope; a Variable value in Git is RED before any child.
    def red(mutate) -> None:
        root = fresh_root()
        mutate(root)
        try:
            jev.validate_contracts(root)
        except jev.EnvsError:
            return
        raise AssertionError("an invalid versa plane state was accepted")

    red(lambda root: (root / jev.VERSA_CIPHERTEXT).write_bytes(envelope()))
    red(lambda root: jev.set_dev_active(root, True, (jev.VERSA_PLANE,)))
    for data in (envelope((RECIPIENT, fixtures.OCI_OTHER)), envelope(keys=jev.VERSA_KEYS[:2]),
                 envelope(keys=(*jev.VERSA_KEYS, "EXTRA"))):
        red(lambda root, data=data: ((root / jev.VERSA_CIPHERTEXT).write_bytes(data),
                                     jev.set_dev_active(root, True, (jev.VERSA_PLANE,))))
    root = fresh_root()
    (root / "contracts/note.txt").write_text(VALUES["VERSA_SERVICE_TOKEN_DURATION"])
    children, backend = Children(), Backend()
    assert operate(root, children, backend, VALUES) == (None, "gate") and not children.calls and not backend.spawned
    # The versa account may be the Workers target's public account, which source already names.
    with fixtures.environment({**VALUES, "VERSA_CLOUDFLARE_ACCOUNT_ID": jev.WORKER_GO_TARGET["account_id"]}):
        jev.gate(fresh_root(), jev.validate_contracts(fresh_root()), jev.VERSA_PLANE)


def test_main() -> None:
    # The entry prints only a closed kind and stage on failure.
    root = fresh_root()
    for raw in ("", f"{OWNER},{INVITED[1]},", f"{OWNER}\n{OWNER}"):
        out, err = io.StringIO(), io.StringIO()
        with fixtures.environment({**VALUES, "VERSA_ACCESS_EMAILS": raw}), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = jev.main(["--root", str(root), "versa-root"])
        assert (code, out.getvalue(), err.getvalue()) == (1, "", "VERSA_ROOT=RED: envs at gate\n"), (code, err.getvalue())


class GitServer(http.server.BaseHTTPRequestHandler):
    # Smart-HTTP Git for the loopback roundtrip: each request runs the closure's own `git http-backend`.
    git, project = "", ""

    def handle_one(self) -> None:
        path, _, query = self.path.partition("?")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        env = {"GIT_PROJECT_ROOT": self.project, "GIT_HTTP_EXPORT_ALL": "1", "REMOTE_USER": "fixture",
               "PATH_INFO": path, "QUERY_STRING": query, "REQUEST_METHOD": self.command,
               "CONTENT_TYPE": self.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(len(body)),
               "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
               "HTTP_GIT_PROTOCOL": self.headers.get("Git-Protocol", ""), "PATH": os.path.dirname(self.git)}
        reply = subprocess.run([self.git, "http-backend"], input=body, env=env, capture_output=True, check=True).stdout
        head, _, payload = reply.partition(b"\r\n\r\n")
        lines = [line.decode().split(": ", 1) for line in head.split(b"\r\n") if line]
        status = next((int(value.split()[0]) for name, value in lines if name.lower() == "status"), 200)
        self.send_response(status)
        for name, value in lines:
            if name.lower() != "status":
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = handle_one

    def log_message(self, *args) -> None:
        pass


ROOT_FIXTURE = """terraform {
  backend "http" {}

  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}

variable "credentials" {
  type      = object({ tunnel_token = string, service_token_id = string, service_token_value = string })
  sensitive = true
}

output "credentials" {
  sensitive = true
  value     = var.credentials
}

output "access_rules" {
  sensitive = true
  value     = [for e in var.access_emails : { email = { email = e } }]
}
"""


def access_variable() -> str:
    # The exact access_emails declaration of the versa root (type, sensitivity and validation), not a copy.
    source = (ROOT / jev.VERSA_CONFIG).read_text(encoding="utf-8")
    start = source.index('variable "access_emails" {\n')
    return source[start:source.index("\n}\n", start) + 3]


def real_versa_root(tools: dict[str, str], work: Path, home: Path) -> None:
    # The versa root itself under the closure tofu and its bundled cloudflare/cloudflare 5.21.1 with every network route
    # closed: init and validate as check does, then a refresh-free plan on a local scratch backend (the partial HTTP
    # backend line dropped) whose saved, encrypted plan shows one email include rule per listed address. Empty lists and
    # empty entries are refused by the variable's own validation.
    root = work / "versa-root"
    root.mkdir()
    source = (ROOT / jev.VERSA_CONFIG).read_text(encoding="utf-8")
    assert source.count('  backend "http" {}\n') == 1 and 'version = "5.21.1"' in source
    (root / "main.tf").write_text(source.replace('  backend "http" {}\n', ""), encoding="utf-8")
    closed = {"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "NO_PROXY": ""}
    env = jev.clean_env(tools, {
        **closed, "HOME": str(home), "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
        "TF_ENCRYPTION": jev.encryption_config(jev.ROOT_KEY_NAME, secrets.token_hex(32)),
        "CLOUDFLARE_API_TOKEN": "cf-" + secrets.token_urlsafe(30), "TF_VAR_account_id": secrets.token_hex(16),
        "TF_VAR_zone_id": secrets.token_hex(16), "TF_VAR_service_token_duration": "8760h"})
    jev.tofu(tools, root, env, jev.default_runner, "init", "-input=false", "-no-color")
    jev.tofu(tools, root, env, jev.default_runner, "validate", "-no-color")
    lock = (root / ".terraform.lock.hcl").read_text(encoding="utf-8")
    assert 'provider "registry.opentofu.org/cloudflare/cloudflare" {\n  version     = "5.21.1"' in lock, "provider is not 5.21.1"
    for label, (_, expected) in LISTS.items():
        plan = root / f"{label}.tfplan"
        vars_env = {**env, "TF_VAR_access_emails": json.dumps(expected)}
        jev.tofu(tools, root, vars_env, jev.default_runner, "plan", "-input=false", "-no-color", "-refresh=false",
                 "-lock=false", f"-out={plan}")
        shown = json.loads(jev.tofu(tools, root, vars_env, jev.default_runner, "show", "-json", "-no-color", str(plan)))
        http, = [change["change"] for change in shown["resource_changes"]
                 if change["address"] == "cloudflare_zero_trust_access_policy.http"]
        assert http["actions"] == ["create"] and http["after"]["decision"] == "allow", label
        # The provider schema lists every rule kind and keeps include as a set: exactly the email kind is set, one rule
        # per listed address (order is the provider's own).
        include = http["after"]["include"]
        assert sorted(rule["email"]["email"] for rule in include) == sorted(expected), label
        assert all(value is None for rule in include for kind, value in rule.items() if kind != "email"), label
        plan.unlink()
    for bad in ([], [""], [OWNER, " "]):
        refused = run([tools["tofu"], f"-chdir={root}", "plan", "-input=false", "-no-color", "-refresh=false",
                       "-lock=false"], {**env, "TF_VAR_access_emails": json.dumps(bad)})
        assert refused.returncode != 0 and b"access_emails must hold at least one email" in refused.stderr, bad
    assert not (root / "terraform.tfstate").exists(), "a plan wrote state"


def run(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def real_roundtrip(bin_dir: str, keygen_bin: str) -> None:
    # The closure git, terraform-backend-git, tofu and sops against a loopback Git server: the production functions
    # create the missing ref once, serve it, keep only encrypted state on it, release the lock and seal the envelope.
    tools = {name: os.path.realpath(os.path.join(bin_dir, binary)) for name, binary in (
        ("git", "git"), ("tofu", "tofu"), ("sops", "sops"), ("terraform_backend_git", "terraform-backend-git"))}
    keygen = os.path.realpath(keygen_bin)
    for path in (*tools.values(), keygen):
        assert path.startswith("/nix/store/") and os.access(path, os.X_OK), f"not a locked store tool: {path}"
    work = Path(tempfile.mkdtemp(prefix="envs-versa-root-real-"))
    base = {"PATH": os.path.dirname(tools["git"]), "HOME": str(work)}
    bare = work / "srv" / "roccho-org" / "envs.git"
    for argv in ([tools["git"], "init", "-q", "--bare", str(bare)],
                 [tools["git"], "--git-dir", str(bare), "symbolic-ref", "HEAD", "refs/heads/proposals"]):
        assert run(argv, base).returncode == 0, argv
    GitServer.git, GitServer.project = tools["git"], str(work / "srv")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GitServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host = jev.STATE_GIT_HOST
    jev.STATE_GIT_HOST = f"http://127.0.0.1:{server.server_address[1]}"
    root = fresh_root()
    assert run([tools["git"], "init", "-q", str(root)], base).returncode == 0
    home = work / "home"
    home.mkdir(mode=0o700)
    backend = jev.VERSA_STATE_BACKEND

    def refs() -> dict[str, str]:
        listed = run([tools["git"], "--git-dir", str(bare), "for-each-ref", "--format=%(refname) %(objectname)"], base)
        return dict(line.split(" ") for line in listed.stdout.decode().splitlines())

    try:
        assert jev.ensure_state_ref(root, tools, jev.default_runner, home, backend) == "CREATED"
        created = refs()
        assert set(created) == {"refs/heads/tofu-state"}
        assert jev.ensure_state_ref(root, tools, jev.default_runner, home, backend) == "PRESENT" and refs() == created
        real_versa_root(tools, work, home)
        fixture = work / "root"
        fixture.mkdir()
        (fixture / "main.tf").write_text(ROOT_FIXTURE + "\n" + access_variable(), encoding="utf-8")
        env = jev.clean_env(tools, {
            "HOME": str(home), "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "TF_VAR_credentials": credentials().decode(),
            "TF_VAR_access_emails": json.dumps(INVITED),
            "TF_ENCRYPTION": jev.encryption_config(jev.ROOT_KEY_NAME, secrets.token_hex(32))})
        states = []
        for _ in range(2):
            process, url, state = jev.start_root_backend(tools, home, REF_TOKEN, jev.default_spawn,
                                                         jev.default_local_get, time.sleep, backend)
            states.append(state)
            try:
                jev.tofu(tools, fixture, env, jev.default_runner, "init", "-input=false", "-no-color", "-reconfigure",
                         "-lock=true", *jev.root_backend_config(url))
                jev.tofu(tools, fixture, env, jev.default_runner, "apply", "-input=false", "-auto-approve", "-no-color",
                         "-lock=true")
                value = jev.output(tools, fixture, env, jev.default_runner, "credentials", jev.PROBE_CREDENTIALS)
                rules = json.loads(jev.tofu(tools, fixture, env, jev.default_runner, "output", "-json", "access_rules"))
                assert rules == [{"email": {"email": item}} for item in INVITED], "access rules differ"
            finally:
                jev.stop(process)
        assert states == ["ABSENT", "PRESENT"], states
        # Only the state ref remains (the lock ref is released), and no plaintext is anywhere in its history.
        assert set(refs()) == {"refs/heads/tofu-state"}, refs()
        stored = run([tools["git"], "--git-dir", str(bare), "show", "tofu-state:" + backend["state_path"]], base)
        history = run([tools["git"], "--git-dir", str(bare), "log", "-p", "--all"], base)
        assert stored.returncode == 0 and "encrypted_data" in json.loads(stored.stdout), "state ref is not encrypted"
        assert not any(value_.encode() in history.stdout for value_ in (TOKEN, CLIENT_ID, CLIENT_SECRET, *INVITED)), \
            "plaintext state"
        assert not (fixture / "terraform.tfstate").exists(), "state was kept locally"
        # The production sealer turns the real output into the envelope that only its one identity opens.
        identities = {}
        for name in ("own", "other"):
            key = work / f"{name}.key"
            assert run([keygen, "-o", str(key)], base).returncode == 0
            identities[name] = (key, run([keygen, "-y", str(key)], base).stdout.decode().strip())
        result = jev.seal_versa_output(root, tools, value, identities["own"][1], str(home), jev.default_runner, {})
        assert result["status"] == "PASS"
        sealed = root / jev.VERSA_CIPHERTEXT
        for name, ok in (("own", True), ("other", False)):
            opened = run([tools["sops"], "--decrypt", "--input-type", "yaml", "--output-type", "json", str(sealed)],
                         {**base, "SOPS_AGE_KEY_FILE": str(identities[name][0])})
            assert (opened.returncode == 0) == ok
            assert not ok or json.loads(opened.stdout) == dict(zip(jev.VERSA_KEYS, (TOKEN, CLIENT_ID, CLIENT_SECRET)))
    finally:
        server.shutdown()
        jev.STATE_GIT_HOST = host
        # Only the throwaway private identities are removed; the rest stays in the runner's temporary space.
        for name in ("own", "other"):
            key = work / f"{name}.key"
            if key.is_file() and not key.is_symlink():
                key.unlink()
    print("real versa root plan with an email list (cloudflare 5.21.1), state ref and envelope: PASS "
          f"(git, terraform-backend-git, tofu and sops from {bin_dir})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools")
    parser.add_argument("--age-keygen")
    args = parser.parse_args()
    assert (args.tools is None) == (args.age_keygen is None), "--tools and --age-keygen go together"
    try:
        jev.validate_contracts(ROOT)
        test_apply()
        test_emails()
        test_red()
        test_contract()
        test_main()
        if args.tools is None:
            print("real versa roundtrip: NOT RUN (the check workflow runs it with --tools and --age-keygen)")
        else:
            real_roundtrip(args.tools, args.age_keygen)
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("versa root self-test: PASS")


if __name__ == "__main__":
    main()
