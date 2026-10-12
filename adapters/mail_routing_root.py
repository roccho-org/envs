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
        if path.exists() and not path.is_file():
            raise NativeSourceHold("PRIVATE_OUTPUT_NOT_PRIVATE")
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
         "plan", "-input=false", "-lock=true", "-out=" + private_path(original)),
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
    returncode: int
    private_headers: bytes = field(default=b"", repr=False)


MailPrivateRunner = Callable[[NativeCommand], PrivateNativeResult]


def _require_success(receipt: PrivateNativeResult) -> None:
    if not isinstance(receipt, PrivateNativeResult) or receipt.returncode != 0:
        raise NativeSourceHold("NATIVE_STAGE_UNPROVEN")


def _preflight_output_group(sinks: tuple[Path, ...], *protected: Path) -> None:
    """Check every output sink of a multi-command stage BEFORE its first runner."""
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
    _preflight_output_group((init_stdout, init_stderr, plan_stdout, plan_stderr),
                            private_backend, plan_path)
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
        (private_get_stdout, private_get_stderr, private_stdout, private_stderr),
        private_review_json, private_path_to_original, headers,
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
        (head_stdout, head_stderr, get_stdout, get_stderr, apply_stdout, apply_stderr),
        private_path_to_original, headers,
    )
    commands = [
        private_r2_object(
            curl, method, account, bucket, key, private_path_to_original,
            headers, access_id, access_secret, stored_etag, tools=tools,
            private_stdout=stdout, private_stderr=stderr,
        )
        for method, stdout, stderr in (
            ("HEAD", head_stdout, head_stderr),
            ("GET", get_stdout, get_stderr),
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


EXIT_INACTIVE = 78
CLOSED_RESULT = '{"kind":"envs.mailM0.manual.v1","status":"INACTIVE","effect":"NOT_RUN"}'


def main() -> int:
    # This unconditional refusal is intentionally before any argument or
    # environment evaluation. There is NO activation flag/escape path.
    print(CLOSED_RESULT)
    return EXIT_INACTIVE


if __name__ == "__main__":
    sys.exit(main())
