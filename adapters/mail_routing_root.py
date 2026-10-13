#!/usr/bin/env python3
"""M0 candidate: hard-inactive independently of the GitHub job gate.

The actual CLI entry refuses before protected inputs or child processes.
Inert SOURCE-only native helper functions below describe verified Ops blobs,
separate OpenTofu plan/show/apply stages and private conditional R2 originals.
Only a separately admitted future Owner process could call them; main never
does, and this committed entry has no activation path.
"""
from __future__ import annotations

import sys
import importlib.util
import json
import os
import stat
import signal
import subprocess

# SOURCE-only operations. The CLI main() below never references these
# functions: nobody can activate them by argv, environment or GitHub dispatch.
# A separately admitted future owner entry must supply private inputs,
# independent original-review evidence and its own effect-specific permission.
# These are native OpenTofu and pinned curl commands, not a second Mail root.
from dataclasses import dataclass, field
import hashlib
import re
from pathlib import Path
from typing import Callable, Mapping
from types import MappingProxyType

OPS_MAIL_COMMIT = "618440c68400bd21f253d0a77027ce4021fe1e33"
OPS_MAIL_TREE = "9cd1757a42bd8a5ae7e43add7dfffe46694f9c2d"
OPS_MAIN_BLOB = "bf7d90ddd1c2a2b63e47ece40b5409e24ca9b125"
OPS_LOCK_BLOB = "4994a1a2967771935c94bcca83752ffebe78e2ff"
OPS_README_BLOB = "ac6fc265a2380bd1b30cfe5708b8d642e9bc4427"
OPS_TEST_BLOB = "04db81a38059da98bb07a397727cf0fb291e5b29"
NATIVE_PROVIDER_H1 = "h1:HiX8Q7db7YrAYCuOBOMsvcmyX1RmvFqALtgJDvtYRhc="
SHA40 = re.compile(r"^[0-9a-f]{40}$")
NIX_BIN = re.compile(r"^/nix/store/[a-z0-9]{32}-[^/]+/bin/(tofu|curl)$")
ETAG = re.compile(r'^"[A-Za-z0-9._-]{1,128}"$')
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{2,62}$")
KEY = re.compile(r"^mail-m0/plans/[a-zA-Z0-9._/-]{1,160}$")
NOOP_PLAN_ARGS = ("plan", "-input=false", "-lock=true", "-detailed-exitcode")


class NativeSourceHold(Exception):
    """Finite source-stage refusal; never pass its private inputs to output."""


def git_blob(source: bytes) -> str:
    # Git *source* identity only, not a hand-copied private plan-hash gate.
    return hashlib.sha1(b"blob " + str(len(source)).encode("ascii") + b"\0" + source).hexdigest()


def verify_native_source(root: Path, commit: str, tree: str) -> None:
    """Require the *effective* Ops root, not just two matching blobs.

    Native backend/plugin metadata under .terraform is allowed only as a
    directory. All active HCL, override, *.tfvars, *.tofu and JSON variants
    outside the four accepted Ops Git source files are rejected. Private
    Owner var-files, plan and backend config belong OUTSIDE the root.
    """
    if commit != OPS_MAIL_COMMIT or tree != OPS_MAIL_TREE:
        raise NativeSourceHold("OPS_SOURCE_NOT_ADOPTED")
    try:
        if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
                or root.resolve(strict=True) != root):
            raise NativeSourceHold("OPS_SOURCE_UNREADABLE")
        observed = {entry.name: entry for entry in root.iterdir()}
        permitted = {
            "main.tf": OPS_MAIN_BLOB,
            ".terraform.lock.hcl": OPS_LOCK_BLOB,
            "README.md": OPS_README_BLOB,
            "safety.tftest.hcl": OPS_TEST_BLOB,
        }
        # Existing native state/plugin cache from a separately Owner-admitted
        # init is not source HCL. A symlinked cache/root is never accepted.
        extras = set(observed) - set(permitted) - {".terraform"}
        if extras:
            raise NativeSourceHold("OPS_SOURCE_EXTRA_INPUT")
        cache = observed.get(".terraform")
        if cache is not None and (cache.is_symlink() or not cache.is_dir()):
            raise NativeSourceHold("OPS_SOURCE_EXTRA_INPUT")
        for name, expected in permitted.items():
            file = observed.get(name)
            if file is None:
                if name in ("main.tf", ".terraform.lock.hcl"):
                    raise NativeSourceHold("OPS_SOURCE_UNREADABLE")
                continue
            if file.is_symlink() or not file.is_file():
                raise NativeSourceHold("OPS_SOURCE_UNREADABLE")
            if git_blob(file.read_bytes()) != expected:
                raise NativeSourceHold("OPS_SOURCE_MISMATCH")
    except OSError:
        raise NativeSourceHold("OPS_SOURCE_UNREADABLE") from None


_NATIVE_TOOL_PROOF = object()


@dataclass(frozen=True, repr=False)
class NativeToolset:
    """Identity minted only by the existing validated envs toolchain loader."""

    tofu: str
    curl: str
    _proof: object = field(default=None, repr=False, compare=False)


def provided_native_tools(root: Path, manifest: str, interpreter: str) -> NativeToolset:
    """Delegate provenance to existing jev_api.toolchain/flake.lock checks.

    This is a SOURCE helper, not a new runtime entry or private operation.
    The exact source-bound provided artifact selects the manifest and Python.
    A forged store-shaped path alone never provides an identity.
    """
    if (not root.is_absolute() or root.is_symlink()
            or root.resolve(strict=True) != Path(__file__).resolve().parents[1]):
        raise NativeSourceHold("TOOLCHAIN_SOURCE_MISMATCH")
    path = root / "adapters/jev_api.py"
    try:
        spec = importlib.util.spec_from_file_location("_mail_existing_toolchain", path)
        if spec is None or spec.loader is None:
            raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            verified = module.toolchain(
                root, environ={"ENVS_EFFECT_TOOLCHAIN": manifest}, executable=interpreter,
            )
        finally:
            sys.modules.pop(spec.name, None)
        return NativeToolset(tofu=verified["tofu"], curl=verified["curl"], _proof=_NATIVE_TOOL_PROOF)
    except (OSError, LookupError, ValueError, TypeError, RuntimeError):
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None
    except Exception:
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None


def native_bin(value: str, tool: str, selected: NativeToolset) -> str:
    # This is the *result of the existing verified toolchain loader*, not
    # acceptance of arbitrary paths by Nix store-looking string format.
    if (not isinstance(selected, NativeToolset)
            or selected._proof is not _NATIVE_TOOL_PROOF or tool not in ("tofu", "curl")
            or not isinstance(value, str) or not NIX_BIN.fullmatch(value)
            or not value.endswith("/bin/" + tool)
            or value != getattr(selected, tool)):
        raise NativeSourceHold("UNPINNED_NATIVE_TOOL")
    return value


def private_path(path: Path) -> str:
    """Reject public descriptors, unsafe top-level outputs and symlink escapes.

    A valid path is still NOT a proof of actual private owner custody, mode,
    encryption, or fixed-R access; those stay future live-admission gates.
    """
    if not isinstance(path, Path):
        raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED")
    name = str(path)
    if (not path.is_absolute() or path == Path("/") or ".." in path.parts
            or any(x in name for x in ("\n", "\r", "\0"))):
        raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED")
    try:
        resolved = path.resolve(strict=False)
        forbidden = (Path("/dev"), Path("/proc"), Path("/sys"),
                     Path("/run"), Path("/nix/store"))
        if (any(path == prefix or prefix in path.parents
                or resolved == prefix or prefix in resolved.parents for prefix in forbidden)
                or path.parent in (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))
                or any(part.is_symlink() for part in (path, *path.parents))):
            raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED")
        if path.exists() and not (path.is_file() or path.is_dir()):
            raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED")
    except (OSError, RuntimeError):
        raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED") from None
    return name


def private_output_sink(path: Path) -> str:
    name = private_path(path)
    try:
        # Native plan/show/curl outputs may truncate existing files. A prior
        # backend, original or capture is never a new output destination.
        if path.exists():
            raise NativeSourceHold("PRIVATE_OUTPUT_ALREADY_EXISTS")
    except OSError:
        raise NativeSourceHold("PRIVATE_OUTPUT_NOT_PRIVATE") from None
    return name


def _private_streams(stdout: Path, stderr: Path, *other_private: Path) -> tuple[str, str]:
    """Every native child requires two distinct non-public stream destinations.

    This is only a SOURCE refusal; a separately admitted Owner runner must
    actually capture both streams without inheriting public Actions logs.
    """
    paths = [private_output_sink(stdout), private_output_sink(stderr)]
    paths += [private_path(path) for path in other_private]
    if len(set(paths)) != len(paths):
        raise NativeSourceHold("PRIVATE_OUTPUT_PATH_OVERLAP")
    return paths[0], paths[1]


@dataclass(frozen=True, repr=False)
class NativeCommand:
    argv: tuple[str, ...]
    # Neither native stream may inherit public stdout/stderr; required for ALL
    # protected init, plan, show, apply and R2 commands, not only show.
    private_stdout: str = field(repr=False)
    private_stderr: str = field(repr=False)
    stdin: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.private_stdout, str) or not isinstance(self.private_stderr, str):
            raise NativeSourceHold("PRIVATE_OUTPUT_NOT_SELECTED")
        _private_streams(Path(self.private_stdout), Path(self.private_stderr))


def native_init(tofu: str, root: Path, private_backend: Path, tools: NativeToolset,
                *, private_stdout: Path, private_stderr: Path) -> NativeCommand:
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(private_stdout, private_stderr, private_backend)
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
         "init", "-input=false", "-lockfile=readonly",
         "-backend-config=" + private_path(private_backend)),
        private_stdout=stdout, private_stderr=stderr,
    )


def native_plan(tofu: str, root: Path, original: Path, tools: NativeToolset,
                *, private_stdout: Path, private_stderr: Path) -> NativeCommand:
    # A saved encrypted plan is NOT a stdout sink: the human diff/target can
    # still be written to stdout or stderr by OpenTofu.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(private_stdout, private_stderr, original)
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
         "plan", "-input=false", "-lock=true", "-out=" + private_output_sink(original)),
        private_stdout=stdout, private_stderr=stderr,
    )


def native_noop(tofu: str, root: Path, tools: NativeToolset, *,
                private_stdout: Path, private_stderr: Path) -> NativeCommand:
    """One native convergence check, without a saved plan or automatic init.

    A separately initialized, approved backend/state/target and permission
    are operating prerequisites established outside this SOURCE helper.
    Native exit0 means no changes only in that effective initialized context;
    exit2 is a delta, never completion or permission to plan/apply again.
    """
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(private_stdout, private_stderr)
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root), *NOOP_PLAN_ARGS),
        private_stdout=stdout, private_stderr=stderr,
    )


def native_inspect(tofu: str, root: Path, private_original: Path,
                   private_review_json: Path, private_stdout: Path,
                   private_stderr: Path, tools: NativeToolset) -> NativeCommand:
    """Native -json-into must write to a separate private original review file."""
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(
        private_stdout, private_stderr, private_original, private_review_json,
    )
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
         "show", "-plan=" + private_path(private_original),
         "-json-into=" + private_output_sink(private_review_json), "-no-color"),
        private_stdout=stdout, private_stderr=stderr,
    )


def native_apply(tofu: str, root: Path, private_original: Path, tools: NativeToolset,
                 *, private_stdout: Path, private_stderr: Path) -> NativeCommand:
    # Exact saved original; no -auto-approve, re-plan, import, unlock or retry.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(private_stdout, private_stderr, private_original)
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
         "apply", "-input=false", "-lock=true", private_path(private_original)),
        private_stdout=stdout, private_stderr=stderr,
    )


def _quote(value: str) -> str:
    # libcurl native --config grammar, not custom signing/encryption.
    if not value or any(x in value for x in ("\r", "\n", "\0")):
        raise NativeSourceHold("INVALID_PRIVATE_CONFIG")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def private_r2_object(curl: str, method: str, account: str, bucket: str, key: str,
                      source_or_dest: Path, headers: Path,
                      access_id: str, access_secret: str, etag: str | None = None,
                      session_token: str | None = None, tools: NativeToolset | None = None,
                      *, private_stdout: Path, private_stderr: Path) -> NativeCommand:
    """Native curl SigV4 + conditional R2 object; no secret in argv/files/log.

    PUT uses If-None-Match * (write once). HEAD/GET demand the actual
    object ETag selected from the Owner/R private original, not a manual
    plan hash. Header capture and GET output paths must be protected by Owner.
    Credentials travel only via curl stdin config, never argv.
    """
    if (not re.fullmatch(r"[0-9a-f]{32}", account) or not BUCKET.fullmatch(bucket)
            or not KEY.fullmatch(key) or ".." in key.split("/") or "//" in key
            or method not in ("PUT", "HEAD", "GET")):
        raise NativeSourceHold("R2_IDENTITY_NOT_SELECTED")
    if method != "PUT" and (etag is None or not ETAG.fullmatch(etag)):
        raise NativeSourceHold("ORIGINAL_ETAG_NOT_OBSERVED")
    if method == "PUT" and etag is not None:
        raise NativeSourceHold("PUT_MUST_BE_WRITE_ONCE")
    # Validate even an ignored HEAD destination: a purported Owner-private
    # source/destination/header must never be a public file descriptor.
    data_path = private_path(source_or_dest)
    header_path = private_output_sink(headers)
    stdout, stderr = _private_streams(private_stdout, private_stderr, source_or_dest, headers)
    url = f"https://{account}.r2.cloudflarestorage.com/{bucket}/{key}"
    items = [
        "url = " + _quote(url),
        "request = " + _quote(method),
        'aws-sigv4 = "aws:amz:auto:s3"',
        "user = " + _quote(access_id + ":" + access_secret),
        'proto = "=https"', 'noproxy = "*"', 'proxy = ""',
        "silent", 'connect-timeout = "10"', 'max-time = "30"',
        "dump-header = " + _quote(header_path),
    ]
    if session_token is not None:
        items.append("header = " + _quote("x-amz-security-token: " + session_token))
    if method == "HEAD":
        # curl -X HEAD merely rewrites the HTTP method and still expects a
        # response body. Native --head mode suppresses body transfer.
        items.append("head")
    if method == "PUT":
        items.extend(['header = "If-None-Match: *"', "upload-file = " + _quote(data_path)])
    else:
        items.append("header = " + _quote("If-Match: " + etag))
        items.append("output = " + _quote(private_output_sink(source_or_dest) if method == "GET" else "/dev/null"))
    return NativeCommand(
        (native_bin(curl, "curl", tools), "-q", "--config", "-"),
        private_stdout=stdout, private_stderr=stderr,
        stdin=("\n".join(items) + "\n").encode("utf-8"),
    )


def private_etag(header_bytes: bytes) -> str:
    """Only one completed 2xx response and one opaque native ETag permitted."""
    try:
        text = header_bytes.decode("ascii")
        lines = text.replace("\r\n", "\n").split("\n")
        statuses = [x for x in lines if x.startswith("HTTP/")]
        tags = [x.split(":", 1)[1].strip() for x in lines if x.lower().startswith("etag:")]
        if (len(statuses) != 1 or not re.fullmatch(r"HTTP/[0-9.]+ 20[0-9](?: .*|)", statuses[0])
                or len(tags) != 1 or not ETAG.fullmatch(tags[0])):
            raise NativeSourceHold("ORIGINAL_RESPONSE_UNPROVEN")
        return tags[0]
    except UnicodeError:
        raise NativeSourceHold("ORIGINAL_RESPONSE_UNPROVEN") from None



# The following functions are real SOURCE logic callable only by a future,
# separately admitted Owner entry. The committed CLI stays unconditionally
# INACTIVE. Runner callbacks are synthetic in CI; the source has NO default
# subprocess, provider, R2 client, stdout or secret acquisition path.
@dataclass(frozen=True, repr=False)
class PrivateNativeResult:
    # Exact native no-op: 0=NO_OP in its effective context, 2=DELTA (unfinished).
    # Other commands: 0=success. Common finite failures: 1=ERROR,
    # 124=TIMEOUT, 125=START_FAILURE. No private stream content is returned.
    returncode: int
    private_headers: bytes = field(default=b"", repr=False)


MailPrivateRunner = Callable[[NativeCommand], PrivateNativeResult]


def _require_success(receipt: PrivateNativeResult) -> None:
    if not isinstance(receipt, PrivateNativeResult) or receipt.returncode != 0:
        raise NativeSourceHold("NATIVE_STAGE_UNPROVEN")


def _preflight_output_group(sinks: tuple[Path, ...], *protected: Path,
                            runner: MailPrivateRunner | None = None) -> None:
    """Check every output sink of a multi-command stage BEFORE its first runner."""
    if isinstance(runner, MailPrivateRunner):
        # Check the selected Owner boundary for later outputs before an
        # earlier init/HEAD/GET could start, not only at each child call.
        for item in sinks:
            runner._path(str(item))
    names = [private_output_sink(item) for item in sinks]
    names += [private_path(item) for item in protected]
    if len(names) != len(set(names)):
        raise NativeSourceHold("PRIVATE_OUTPUT_PATH_OVERLAP")


def plan_private_once(ops_root: Path, commit: str, tree: str, tofu: str,
                      private_backend: Path, plan_path: Path,
                      tools: NativeToolset, runner: MailPrivateRunner, *,
                      init_stdout: Path, init_stderr: Path,
                      plan_stdout: Path, plan_stderr: Path) -> None:
    # No auto-apply: future Owner chooses four separate private sinks and one
    # private backend + saved original. Reject unsafe PLAN sinks before INIT.
    verify_native_source(ops_root, commit, tree)
    _preflight_output_group((init_stdout, init_stderr, plan_stdout, plan_stderr,
                             plan_path), private_backend, runner=runner)
    init = native_init(tofu, ops_root, private_backend, tools,
                       private_stdout=init_stdout, private_stderr=init_stderr)
    _require_success(runner(init))
    verify_native_source(ops_root, commit, tree)
    plan = native_plan(tofu, ops_root, plan_path, tools,
                       private_stdout=plan_stdout, private_stderr=plan_stderr)
    _require_success(runner(plan))


def retain_original_once(curl: str, account: str, bucket: str, key: str, plan_path: Path,
                         headers: Path, access_id: str, access_secret: str,
                         runner: MailPrivateRunner, tools: NativeToolset, *,
                         private_stdout: Path, private_stderr: Path) -> str:
    # R2 native write-once conditional; stdout and stderr also remain private.
    command = private_r2_object(
        curl, "PUT", account, bucket, key, plan_path, headers,
        access_id, access_secret, tools=tools,
        private_stdout=private_stdout, private_stderr=private_stderr,
    )
    response = runner(command)
    _require_success(response)
    return private_etag(response.private_headers)


def inspect_original_once(curl: str, tofu: str, root: Path, account: str,
                          bucket: str, key: str, private_path_to_original: Path,
                          headers: Path, access_id: str, access_secret: str,
                          expected_etag: str, runner: MailPrivateRunner,
                          tools: NativeToolset, *,
                          private_review_json: Path, private_stdout: Path,
                          private_stderr: Path, private_get_stdout: Path,
                          private_get_stderr: Path) -> None:
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    # Refuse all unsafe GET/SHOW sinks BEFORE any GET or runner callback.
    _preflight_output_group(
        (private_get_stdout, private_get_stderr, private_stdout, private_stderr,
         private_review_json, private_path_to_original, headers),
        runner=runner,
    )
    inspect = native_inspect(tofu, root, private_path_to_original,
                             private_review_json, private_stdout, private_stderr, tools)
    get = private_r2_object(
        curl, "GET", account, bucket, key, private_path_to_original,
        headers, access_id, access_secret, expected_etag, tools=tools,
        private_stdout=private_get_stdout, private_stderr=private_get_stderr,
    )
    result = runner(get)
    _require_success(result)
    if private_etag(result.private_headers) != expected_etag:
        raise NativeSourceHold("ORIGINAL_CHANGED_OR_UNREVIEWED")
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    _require_success(runner(inspect))


def apply_same_original_once(curl: str, tofu: str, root: Path, account: str,
                             bucket: str, key: str, private_path_to_original: Path,
                             headers: Path, access_id: str, access_secret: str,
                             stored_etag: str, owner_readback: str,
                             fixed_r_readback: str, before_apply: str,
                             runner: MailPrivateRunner, tools: NativeToolset, *,
                             get_headers: Path,
                             head_stdout: Path, head_stderr: Path,
                             get_stdout: Path, get_stderr: Path,
                             apply_stdout: Path, apply_stderr: Path) -> None:
    # Separately admitted future Owner exact-original effect only; the live
    # job remains false and the real CLI refuses before child/private input.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    require_same_original(stored_etag=stored_etag, owner_readback=owner_readback,
                          fixed_r_readback=fixed_r_readback, before_apply=before_apply)
    # Refuse missing/public/alias/colliding sink of ANY later native step
    # BEFORE the first conditional HEAD could read private object metadata.
    _preflight_output_group(
        (head_stdout, head_stderr, get_stdout, get_stderr, apply_stdout, apply_stderr,
         private_path_to_original, headers, get_headers),
        runner=runner,
    )
    commands = [
        private_r2_object(
            curl, method, account, bucket, key, private_path_to_original,
            response_headers, access_id, access_secret, stored_etag, tools=tools,
            private_stdout=stdout, private_stderr=stderr,
        )
        for method, response_headers, stdout, stderr in (
            ("HEAD", headers, head_stdout, head_stderr),
            ("GET", get_headers, get_stdout, get_stderr),
        )
    ]
    apply = native_apply(
        tofu, root, private_path_to_original, tools,
        private_stdout=apply_stdout, private_stderr=apply_stderr,
    )
    for command in commands:
        receipt = runner(command)
        _require_success(receipt)
        if private_etag(receipt.private_headers) != stored_etag:
            raise NativeSourceHold("ORIGINAL_CHANGED_OR_UNREVIEWED")
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    _require_success(runner(apply))


def require_same_original(*, stored_etag: str, owner_readback: str,
                          fixed_r_readback: str, before_apply: str) -> None:
    """Opaque native R2 object identity, not a copied plan digest or GO flag.

    The independent private route / actual human GO are external admission
    requirements. This function cannot supply or impersonate either review.
    """
    if (not ETAG.fullmatch(stored_etag) or stored_etag != owner_readback
            or stored_etag != fixed_r_readback or stored_etag != before_apply):
        raise NativeSourceHold("ORIGINAL_CHANGED_OR_UNREVIEWED")



# A real private process implementation, but deliberately NO executable entry:
# the existing whole-job if:false and CLI exit78 are unchanged.
MAIL_REQUIRED = frozenset({
    "CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "TF_ENCRYPTION", "TF_VAR_account_id", "TF_VAR_zone_id",
    "TF_VAR_zone_name", "TF_VAR_alias_address",
    "TF_VAR_destination_address", "TF_VAR_rule_priority",
})
MAIL_OPTIONAL = frozenset({
    "AWS_SESSION_TOKEN", "TF_VAR_verified_destination_id",
    "TF_VAR_manage_dns", "TF_VAR_manage_destination",
    "TF_VAR_manage_rule", "TF_VAR_preflight_approved",
})
MAIL_STATE_KEY = re.compile(r"^mail-m0/state/[A-Za-z0-9._/-]{1,160}\.tfstate$")


def _owner_home(home: Path) -> None:
    private_path(home)
    try:
        info = home.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise NativeSourceHold("MAIL_PRIVATE_HOME_UNPROVEN")
    except OSError:
        raise NativeSourceHold("MAIL_PRIVATE_HOME_UNPROVEN") from None


def _owner_file(path: Path, home: Path, limit: int = 32768) -> bytes:
    private_path(path)
    if path == home or home not in path.parents:
        raise NativeSourceHold("MAIL_PRIVATE_FILE_UNPROVEN")
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise NativeSourceHold("MAIL_PRIVATE_FILE_UNPROVEN")
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read(limit + 1)
            if not data or len(data) > limit:
                raise NativeSourceHold("MAIL_PRIVATE_FILE_UNPROVEN")
            return data
        finally:
            os.close(fd)
    except OSError:
        raise NativeSourceHold("MAIL_PRIVATE_FILE_UNPROVEN") from None


def _mail_encryption_source(value: str) -> None:
    # Native OpenTofu HCL; the pinned Ops root independently enforces both
    # state and plan encryption. No optional/disabled/fallback substitution.
    if (not isinstance(value, str) or len(value) > 16384 or
            any(w in value.lower() for w in ("unencrypted", "disabled", "fallback"))):
        raise NativeSourceHold("MAIL_ENCRYPTION_UNSELECTED")
    methods = re.findall(r'method\s*=\s*method\.aes_gcm\.([A-Za-z][A-Za-z0-9_]*)', value)
    if (len(methods) != 2 or methods[0] != methods[1]
            or not re.search(r'key_provider\s+"pbkdf2"\s+"' + re.escape(methods[0]) + r'"', value)
            or not re.search(r'method\s+"aes_gcm"\s+"' + re.escape(methods[0]) + r'"', value)
            or value.count("{") != 4 or value.count("}") != 4
            or "$" + "{" in value):
        raise NativeSourceHold("MAIL_ENCRYPTION_UNSELECTED")
    for name in ("state", "plan"):
        if not re.search(r'\b' + name + r'\s*\{\s*method\s*=\s*method\.aes_gcm\.'
                         + re.escape(methods[0]) + r'\s*\}', value):
            raise NativeSourceHold("MAIL_ENCRYPTION_UNSELECTED")


@dataclass(frozen=True, repr=False)
class MailPrivateInputs:
    """Future Owner-provided values only, with no credential discovery/default."""
    home: Path
    ops_root: Path
    backend: Path
    account: str
    state_bucket: str
    state_key: str
    plan_bucket: str
    plan_key: str
    values: Mapping[str, str] = field(repr=False)

    def check(self) -> None:
        _owner_home(self.home)
        verify_native_source(self.ops_root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
        if (not isinstance(self.account, str) or
                re.fullmatch(r"[0-9a-f]{32}", self.account) is None
                or not BUCKET.fullmatch(self.state_bucket)
                or not BUCKET.fullmatch(self.plan_bucket)
                or not MAIL_STATE_KEY.fullmatch(self.state_key)
                or ".." in self.state_key.split("/") or "//" in self.state_key
                or not KEY.fullmatch(self.plan_key) or ".." in self.plan_key.split("/")
                or "//" in self.plan_key):
            raise NativeSourceHold("MAIL_PRIVATE_TARGET_UNSELECTED")
        try:
            config = _owner_file(self.backend, self.home).decode("ascii")
        except UnicodeError:
            raise NativeSourceHold("MAIL_PRIVATE_BACKEND_UNPROVEN") from None
        # Explicit native S3 partial config; no credentials or rent state
        # injected via backend HCL, no duplicate or shadow keys.
        expected = [
            'bucket = "' + self.state_bucket + '"',
            'key = "' + self.state_key + '"',
            'endpoints = { s3 = "https://' + self.account + '.r2.cloudflarestorage.com" }',
        ]
        if [line.strip() for line in config.splitlines() if line.strip()] != expected:
            raise NativeSourceHold("MAIL_PRIVATE_BACKEND_UNPROVEN")
        if (not isinstance(self.values, Mapping)
                or set(self.values) - (MAIL_REQUIRED | MAIL_OPTIONAL)
                or MAIL_REQUIRED - set(self.values)):
            raise NativeSourceHold("MAIL_PRIVATE_INPUT_UNSELECTED")
        for name, value in self.values.items():
            if (not isinstance(value, str) or not value or "\0" in value
                    or (name != "TF_ENCRYPTION" and ("\r" in value or "\n" in value))):
                raise NativeSourceHold("MAIL_PRIVATE_INPUT_UNSELECTED")
        _mail_encryption_source(self.values["TF_ENCRYPTION"])
        if (self.values["TF_VAR_account_id"] != self.account
                or not ACCOUNT_32.fullmatch(self.values["TF_VAR_zone_id"])
                or not self.values["TF_VAR_alias_address"].lower().endswith(
                    "@" + self.values["TF_VAR_zone_name"].lower())
                or not self.values["TF_VAR_rule_priority"].isdigit()):
            raise NativeSourceHold("MAIL_PRIVATE_TARGET_UNSELECTED")
        for name in ("manage_dns", "manage_destination", "manage_rule", "preflight_approved"):
            value = self.values.get("TF_VAR_" + name)
            if value is not None and value not in ("true", "false"):
                raise NativeSourceHold("MAIL_PRIVATE_INPUT_UNSELECTED")


ACCOUNT_32 = re.compile(r"^[0-9a-f]{32}$")
MAIL_AFTER_SLOTS = frozenset({
    "CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "RENT_STATE_PASSPHRASE",
})
MAIL_CONFIG_KEYS = frozenset({
    "account_id", "zone_id", "zone_name", "alias_address", "destination_address",
    "rule_priority", "state_bucket", "state_key", "plan_bucket", "plan_key",
    "verified_destination_id", "manage_dns", "manage_destination", "manage_rule",
    "preflight_approved",
})
MAIL_FLAGS = ("manage_dns", "manage_destination", "manage_rule", "preflight_approved")
MAIL_METHOD_NAME = "mail_m0"
MAIL_ZONE_NAME = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAIL_LITERAL_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+%-]*@[A-Za-z0-9.-]+$")


def compose_after_inputs(config_json: bytes, slots: Mapping[str, str], *,
                         environment_name: str, home: Path, ops_root: Path,
                         backend: Path) -> MailPrivateInputs:
    """Compose one explicit private After context; no acquisition or effect.

    Existing envs age/SOPS setup is upstream, not a Mail payload or per-mail
    decryptor. The environment label, flags and IDs cannot supply principal,
    verified status, approved passphrase reuse or Owner/runtime permission.
    All such operating prerequisites remain independently established.
    """
    try:
        if (type(config_json) is not bytes or not 0 < len(config_json) <= 32768
                or environment_name != "dev-rent-tunnel"
                or any(not isinstance(path, Path) for path in (home, ops_root, backend))):
            raise NativeSourceHold("MAIL_AFTER_CONTEXT_UNSELECTED")

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            selected: dict[str, object] = {}
            for name, value in pairs:
                if name in selected:
                    raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")
                selected[name] = value
            return selected

        def nonfinite(_value: str) -> None:
            raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")

        config = json.loads(config_json.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=nonfinite)
        if not isinstance(config, dict) or set(config) != MAIL_CONFIG_KEYS:
            raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")
        string_keys = MAIL_CONFIG_KEYS - {*MAIL_FLAGS, "rule_priority", "verified_destination_id"}
        for name in string_keys:
            value = config[name]
            if (not isinstance(value, str) or not value
                    or any(char.isspace() or char == "\0" for char in value)):
                raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")
        if (not ACCOUNT_32.fullmatch(config["account_id"])
                or not ACCOUNT_32.fullmatch(config["zone_id"])
                or not MAIL_ZONE_NAME.fullmatch(config["zone_name"])
                or not MAIL_LITERAL_ADDRESS.fullmatch(config["alias_address"])
                or not config["alias_address"].lower().endswith("@" + config["zone_name"].lower())
                or not MAIL_LITERAL_ADDRESS.fullmatch(config["destination_address"])
                or config["destination_address"].split("@")[1].lower() not in ("gmail.com", "googlemail.com")
                or type(config["rule_priority"]) is not int or config["rule_priority"] < 0
                or any(type(config[name]) is not bool for name in MAIL_FLAGS)):
            raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")
        verified = config["verified_destination_id"]
        if verified is not None and (not isinstance(verified, str) or not ACCOUNT_32.fullmatch(verified)):
            raise NativeSourceHold("MAIL_AFTER_CONFIG_UNSELECTED")
        if not isinstance(slots, Mapping):
            raise NativeSourceHold("MAIL_AFTER_SLOTS_UNSELECTED")
        # Capture the supplied mapping once BEFORE validation. No later read
        # may substitute a different credential after the copy was checked.
        selected_slots = dict(slots)
        if (set(selected_slots) != MAIL_AFTER_SLOTS
                or any(not isinstance(selected_slots[name], str) or not selected_slots[name]
                       or any(not 33 <= ord(char) <= 126 for char in selected_slots[name])
                       for name in MAIL_AFTER_SLOTS)):
            raise NativeSourceHold("MAIL_AFTER_SLOTS_UNSELECTED")
        # Reuse this exact source's existing formatter and passphrase format.
        # No host environment, key generation, SOPS call or fallback input.
        existing_source = Path(__file__).with_name("jev_api.py")
        spec = importlib.util.spec_from_file_location("_mail_existing_encryption", existing_source)
        if spec is None or spec.loader is None or existing_source.is_symlink():
            raise NativeSourceHold("MAIL_AFTER_CONTEXT_UNSELECTED")
        existing = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = existing
        try:
            # Execute only the fixed provided source in memory: the ordinary
            # import loader would create a checkout bytecode cache file.
            exec(compile(existing_source.read_bytes(), str(existing_source), "exec"), existing.__dict__)
            passphrase = selected_slots["RENT_STATE_PASSPHRASE"]
            if existing.ROOT_PASSPHRASE.fullmatch(passphrase) is None:
                raise NativeSourceHold("MAIL_AFTER_SLOTS_UNSELECTED")
            encryption = existing.encryption_config(MAIL_METHOD_NAME, passphrase)
        finally:
            sys.modules.pop(spec.name, None)
        values = {name: selected_slots[name] for name in MAIL_AFTER_SLOTS
                  if name != "RENT_STATE_PASSPHRASE"}
        values["TF_ENCRYPTION"] = encryption
        for name in ("account_id", "zone_id", "zone_name", "alias_address", "destination_address"):
            values["TF_VAR_" + name] = config[name]
        values["TF_VAR_rule_priority"] = str(config["rule_priority"])
        values.update({"TF_VAR_" + name: "true" if config[name] else "false" for name in MAIL_FLAGS})
        if verified is not None:
            values["TF_VAR_verified_destination_id"] = verified
        result = MailPrivateInputs(
            home=home, ops_root=ops_root, backend=backend, account=config["account_id"],
            state_bucket=config["state_bucket"], state_key=config["state_key"],
            plan_bucket=config["plan_bucket"], plan_key=config["plan_key"],
            values=MappingProxyType(values),
        )
        result.check()
        return result
    except NativeSourceHold:
        raise
    except Exception:
        # Never expose raw JSON/parser/path/slot/formatter exception details.
        raise NativeSourceHold("MAIL_AFTER_INPUT_UNSELECTED") from None


class MailPrivateRunner:
    """A real private subprocess/capture adapter for existing Mail stages.

    Not an arbitrary command executor. No source-defined CLI/dispatch or
    approval state machine; owner admission, original read and GO stay external.
    """
    def __init__(self, inputs: MailPrivateInputs, tools: NativeToolset,
                 *, timeout: int = 90) -> None:
        if (not isinstance(inputs, MailPrivateInputs) or
                not isinstance(tools, NativeToolset) or
                tools._proof is not _NATIVE_TOOL_PROOF or
                type(timeout) is not int or not 1 <= timeout <= 120):
            raise NativeSourceHold("MAIL_RUNNER_UNADMITTED")
        native_bin(tools.tofu, "tofu", tools)
        native_bin(tools.curl, "curl", tools)
        inputs.check()
        self._inputs, self._tools, self._timeout = inputs, tools, timeout

    def _path(self, value: str) -> Path:
        path = Path(value)
        private_path(path)
        if path == self._inputs.home or self._inputs.home not in path.parents:
            raise NativeSourceHold("MAIL_PRIVATE_PATH_OUTSIDE_OWNER")
        return path

    def _command(self, cmd: NativeCommand) -> Path | None:
        inp = self._inputs
        inp.check()
        private_output_sink(self._path(cmd.private_stdout))
        private_output_sink(self._path(cmd.private_stderr))
        args = cmd.argv
        if len(args) >= 4 and args[0] == self._tools.tofu:
            if args[1] != "-chdir=" + str(inp.ops_root) or cmd.stdin is not None:
                raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
            if args[2] == "init":
                valid = args[2:] == (
                    "init", "-input=false", "-lockfile=readonly",
                    "-backend-config=" + str(inp.backend))
            elif args[2] == "plan":
                valid = args[2:] == NOOP_PLAN_ARGS
                if not valid:
                    valid = (len(args) == 6 and args[3:5] == ("-input=false", "-lock=true")
                             and args[5].startswith("-out="))
                    if valid:
                        output = self._path(args[5][5:])
                        _private_streams(Path(cmd.private_stdout), Path(cmd.private_stderr), output)
                        private_output_sink(output)
            elif args[2] == "show":
                valid = (len(args) == 6 and args[3].startswith("-plan=")
                         and args[4].startswith("-json-into=") and args[5] == "-no-color")
                if valid:
                    original = self._path(args[3][6:])
                    output = self._path(args[4][11:])
                    _private_streams(Path(cmd.private_stdout), Path(cmd.private_stderr),
                                     original, output)
                    private_output_sink(output)
            elif args[2] == "apply":
                valid = len(args) == 6 and args[3:5] == ("-input=false", "-lock=true")
                if valid:
                    self._path(args[5])
            else:
                valid = False
            if not valid:
                raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
            return None
        if args != (self._tools.curl, "-q", "--config", "-") or not cmd.stdin:
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
        try:
            text = cmd.stdin.decode("utf-8")
        except UnicodeError:
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED") from None
        # Reject arbitrary curl arguments and even additional native --config
        # directives: require byte equality with this source's bound SigV4
        # builder and the Owner-selected Mail object/credential.
        def only(pattern: str) -> str:
            values = re.findall(pattern, text, re.MULTILINE)
            if len(values) != 1:
                raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
            return values[0]

        method = only(r'^request = "(PUT|HEAD|GET)"$')
        header = self._path(only(r'^dump-header = "([^"\r\n]+)"$'))
        if method == "PUT":
            source = self._path(only(r'^upload-file = "([^"\r\n]+)"$'))
            tag = None
        else:
            tag = '"' + only(r'^header = "If-Match: \\"([A-Za-z0-9._-]{1,128})\\""$') + '"'
            source = self._path(
                only(r'^output = "([^"\r\n]+)"$') if method == "GET"
                else str(inp.home / "unused-head")
            )
        expected = private_r2_object(
            self._tools.curl, method, inp.account, inp.plan_bucket,
            inp.plan_key, source, header,
            inp.values["AWS_ACCESS_KEY_ID"], inp.values["AWS_SECRET_ACCESS_KEY"],
            etag=tag, session_token=inp.values.get("AWS_SESSION_TOKEN"),
            tools=self._tools,
            private_stdout=Path(cmd.private_stdout),
            private_stderr=Path(cmd.private_stderr),
        )
        if cmd != expected:
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
        return header

    def _child_env(self, cmd: NativeCommand) -> dict[str, str]:
        inp = self._inputs
        # Never inherit PATH, arbitrary TF_*, AWS_PROFILE, proxy, token,
        # CI, telemetry, TF_LOG or Actions file descriptors from host.
        env = {"HOME": str(inp.home), "TMPDIR": str(inp.home),
               "XDG_CACHE_HOME": str(inp.home), "LANG": "C",
               "TF_INPUT": "0", "TF_IN_AUTOMATION": "1",
               "AWS_EC2_METADATA_DISABLED": "true", "CHECKPOINT_DISABLE": "1"}
        if cmd.argv[0] == self._tools.tofu:
            env.update(inp.values)
            env["AWS_ENDPOINT_URL_S3"] = ("https://" + inp.account +
                                         ".r2.cloudflarestorage.com")
        return env

    def _sink(self, name: str) -> int:
        self._path(name)
        try:
            return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError:
            raise NativeSourceHold("MAIL_PRIVATE_CAPTURE_UNAVAILABLE") from None

    def __call__(self, command: NativeCommand) -> PrivateNativeResult:
        if not isinstance(command, NativeCommand):
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
        header = self._command(command)
        out = self._sink(command.private_stdout)
        try:
            err = self._sink(command.private_stderr)
        except NativeSourceHold:
            os.close(out)
            raise
        try:
            try:
                child = subprocess.Popen(
                    command.argv, cwd=str(self._inputs.ops_root),
                    env=self._child_env(command), umask=0o077,
                    stdin=subprocess.PIPE if command.stdin is not None else subprocess.DEVNULL,
                    stdout=out, stderr=err, close_fds=True, start_new_session=True,
                )
                try:
                    child.communicate(input=command.stdin, timeout=self._timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    child.communicate()
                    return PrivateNativeResult(124)
                result = child.returncode
            except (OSError, ValueError, TypeError):
                # Fail closed, do not reveal argv, secret, path or exception.
                return PrivateNativeResult(125)
        finally:
            os.close(out)
            os.close(err)
        if (result == 2 and command.argv[0] == self._tools.tofu
                and command.argv[2:] == NOOP_PLAN_ARGS):
            return PrivateNativeResult(2)
        if result != 0:
            return PrivateNativeResult(1)
        if header is not None:
            # The conditional R2 ETag remains in the same private Owner home.
            return PrivateNativeResult(0, _owner_file(header, self._inputs.home, 8192))
        return PrivateNativeResult(0)


EXIT_INACTIVE = 78
CLOSED_RESULT = '{"kind":"envs.mailM0.manual.v1","status":"INACTIVE","effect":"NOT_RUN"}'


def main() -> int:
    # This unconditional refusal is intentionally before any argument or
    # environment evaluation. There is NO activation flag/escape path.
    print(CLOSED_RESULT)
    return EXIT_INACTIVE


if __name__ == "__main__":
    sys.exit(main())
