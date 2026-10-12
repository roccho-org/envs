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


@dataclass(frozen=True, repr=False)
class NativeToolset:
    """Exact tofu/curl from the existing source-bound envs toolchain."""

    tofu: str
    curl: str


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
        return NativeToolset(tofu=verified["tofu"], curl=verified["curl"])
    except (OSError, LookupError, ValueError, TypeError, RuntimeError):
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None
    except Exception:
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None


def native_bin(value: str, tool: str, selected: NativeToolset) -> str:
    # This is the *result of the existing verified toolchain loader*, not
    # acceptance of arbitrary paths by Nix store-looking string format.
    if (not isinstance(selected, NativeToolset) or tool not in ("tofu", "curl")
            or not isinstance(value, str) or not NIX_BIN.fullmatch(value)
            or not value.endswith("/bin/" + tool)
            or value != getattr(selected, tool)):
        raise NativeSourceHold("UNPINNED_NATIVE_TOOL")
    return value


def private_path(path: Path) -> str:
    # Absolute paths under Owner-owned protected storage only. This check
    # does not assert custody or approval; those require real Owner/R proof.
    name = str(path)
    if (not path.is_absolute() or str(path) in ("/", "/tmp", "/nix/store")
            or "\n" in name or "\r" in name or "\0" in name):
        raise NativeSourceHold("PRIVATE_PATH_NOT_SELECTED")
    return name


@dataclass(frozen=True, repr=False)
class NativeCommand:
    argv: tuple[str, ...]
    stdin: bytes | None = field(default=None, repr=False)


def native_init(tofu: str, root: Path, private_backend: Path, tools: NativeToolset) -> NativeCommand:
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    return NativeCommand((native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
                          "init", "-input=false", "-lockfile=readonly",
                          "-backend-config=" + private_path(private_backend)))


def native_plan(tofu: str, root: Path, original: Path, tools: NativeToolset) -> NativeCommand:
    # Produces a separate encrypted saved plan. NO automatic apply.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    return NativeCommand((native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
                          "plan", "-input=false", "-lock=true", "-out=" + private_path(original)))


def native_inspect(tofu: str, root: Path, private_original: Path, tools: NativeToolset) -> NativeCommand:
    # tofu show -json can reveal sensitive values. The stdout belongs solely
    # to Owner/R protected private review, NEVER public CI/PR/Actions artifacts.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    return NativeCommand((native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
                          "show", "-json", "-plan=" + private_path(private_original)))


def native_apply(tofu: str, root: Path, private_original: Path, tools: NativeToolset) -> NativeCommand:
    # Exact saved plan, no -auto-approve, no re-plan, import, unlock or retry.
    # This is NOT the program entry. A later separately approved Owner effect
    # would have to invoke it after independently reviewing the same original.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    return NativeCommand((native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root),
                          "apply", "-input=false", "-lock=true", private_path(private_original)))


def _quote(value: str) -> str:
    # libcurl native --config grammar, not custom signing/encryption.
    if not value or any(x in value for x in ("\r", "\n", "\0")):
        raise NativeSourceHold("INVALID_PRIVATE_CONFIG")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def private_r2_object(curl: str, method: str, account: str, bucket: str, key: str,
                      source_or_dest: Path, headers: Path,
                      access_id: str, access_secret: str, etag: str | None = None,
                      session_token: str | None = None, tools: NativeToolset | None = None) -> NativeCommand:
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
    url = f"https://{account}.r2.cloudflarestorage.com/{bucket}/{key}"
    items = [
        "url = " + _quote(url),
        "request = " + _quote(method),
        'aws-sigv4 = "aws:amz:auto:s3"',
        "user = " + _quote(access_id + ":" + access_secret),
        'proto = "=https"', 'noproxy = "*"', 'proxy = ""',
        "silent", 'connect-timeout = "10"', 'max-time = "30"',
        "dump-header = " + _quote(private_path(headers)),
    ]
    if session_token is not None:
        items.append("header = " + _quote("x-amz-security-token: " + session_token))
    if method == "HEAD":
        # curl -X HEAD merely rewrites the HTTP method and still expects a
        # response body. Native --head mode suppresses body transfer.
        items.append("head")
    if method == "PUT":
        items.extend(['header = "If-None-Match: *"', "upload-file = " + _quote(private_path(source_or_dest))])
    else:
        items.append("header = " + _quote("If-Match: " + etag))
        items.append("output = " + _quote(private_path(source_or_dest) if method == "GET" else "/dev/null"))
    return NativeCommand((native_bin(curl, "curl", tools), "-q", "--config", "-"),
                         ("\n".join(items) + "\n").encode("utf-8"))


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


def plan_private_once(ops_root: Path, commit: str, tree: str, tofu: str,
                      private_backend: Path, plan_path: Path,
                      tools: NativeToolset, runner: MailPrivateRunner) -> None:
    # One separately Owner-admitted private state/init+plan stage, never apply.
    # The native backend/provider state and encryption inputs are external
    # admission prerequisites; no secret acquisition or driver is supplied.
    verify_native_source(ops_root, commit, tree)
    _require_success(runner(native_init(tofu, ops_root, private_backend, tools)))
    verify_native_source(ops_root, commit, tree)
    _require_success(runner(native_plan(tofu, ops_root, plan_path, tools)))


def retain_original_once(curl: str, account: str, bucket: str, key: str, plan_path: Path,
                         headers: Path, access_id: str, access_secret: str,
                         runner: MailPrivateRunner, tools: NativeToolset) -> str:
    # Standard native R2 write-once conditional. Its opaque ETag stays
    # exclusively in the private Owner/R review route, never a public receipt.
    command = private_r2_object(curl, "PUT", account, bucket, key, plan_path, headers,
                                access_id, access_secret, tools=tools)
    response = runner(command)
    _require_success(response)
    return private_etag(response.private_headers)


def inspect_original_once(curl: str, tofu: str, root: Path, account: str,
                          bucket: str, key: str, private_path_to_original: Path,
                          headers: Path, access_id: str, access_secret: str,
                          expected_etag: str, runner: MailPrivateRunner,
                          tools: NativeToolset) -> None:
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    # Owner and fixed R must access the same original via independent
    # *private* read-only routes. This function does not grant human approval.
    command = private_r2_object(curl, "GET", account, bucket, key, private_path_to_original,
                                headers, access_id, access_secret, expected_etag, tools=tools)
    response = runner(command)
    _require_success(response)
    if private_etag(response.private_headers) != expected_etag:
        raise NativeSourceHold("ORIGINAL_CHANGED_OR_UNREVIEWED")
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    _require_success(runner(native_inspect(tofu, root, private_path_to_original, tools)))


def apply_same_original_once(curl: str, tofu: str, root: Path, account: str,
                             bucket: str, key: str, private_path_to_original: Path,
                             headers: Path, access_id: str, access_secret: str,
                             stored_etag: str, owner_readback: str,
                             fixed_r_readback: str, before_apply: str,
                             runner: MailPrivateRunner, tools: NativeToolset) -> None:
    # Called by a FUTURE distinct Owner-admitted source entry only; today
    # the job is false and the real CLI exits 78 before arguments and secrets.
    # No apply can follow a failed conditional HEAD/GET, missing R review,
    # source change or ambiguous provider result. No implicit retry.
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    require_same_original(stored_etag=stored_etag, owner_readback=owner_readback,
                          fixed_r_readback=fixed_r_readback, before_apply=before_apply)
    for method in ("HEAD", "GET"):
        command = private_r2_object(curl, method, account, bucket, key, private_path_to_original,
                                    headers, access_id, access_secret, stored_etag, tools=tools)
        receipt = runner(command)
        _require_success(receipt)
        if private_etag(receipt.private_headers) != stored_etag:
            raise NativeSourceHold("ORIGINAL_CHANGED_OR_UNREVIEWED")
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    _require_success(runner(native_apply(tofu, root, private_path_to_original, tools)))


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
