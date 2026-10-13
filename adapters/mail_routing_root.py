#!/usr/bin/env python3
"""M0 candidate: hard-inactive independently of the GitHub job gate.

The actual CLI entry refuses before protected inputs or child processes.
Inert SOURCE-only native helper functions below describe verified Ops blobs,
OpenTofu speculative plan and automatic-plan apply with private captures.
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
# fixed-source/target review and its own effect-specific permission.
# These are native OpenTofu commands using the existing Mail root.
from dataclasses import dataclass, field
import hashlib
import re
from pathlib import Path
from typing import Mapping
from types import MappingProxyType

OPS_MAIL_COMMIT = "e0c208356d0e2908224cbbd356c69256cb0e4528"
OPS_MAIL_TREE = "a62b0ccbebda639783341c1e59372977ed0a7299"
OPS_MAIN_BLOB = "bf7d90ddd1c2a2b63e47ece40b5409e24ca9b125"
OPS_LOCK_BLOB = "4994a1a2967771935c94bcca83752ffebe78e2ff"
OPS_README_BLOB = "cf5fa3931eed554eaf8bf75f87888118a16cf238"
OPS_TEST_BLOB = "04db81a38059da98bb07a397727cf0fb291e5b29"
NATIVE_PROVIDER_H1 = "h1:HiX8Q7db7YrAYCuOBOMsvcmyX1RmvFqALtgJDvtYRhc="
NIX_BIN = re.compile(r"^/nix/store/[a-z0-9]{32}-[^/]+/bin/tofu$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{2,62}$")
NOOP_PLAN_ARGS = ("plan", "-input=false", "-lock=true", "-detailed-exitcode")
APPLY_ARGS = ("apply", "-input=false", "-lock=true", "-auto-approve")


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
        return NativeToolset(tofu=verified["tofu"], _proof=_NATIVE_TOOL_PROOF)
    except (OSError, LookupError, ValueError, TypeError, RuntimeError):
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None
    except Exception:
        raise NativeSourceHold("TOOLCHAIN_NOT_PROVEN") from None


def native_bin(value: str, tool: str, selected: NativeToolset) -> str:
    # This is the *result of the existing verified toolchain loader*, not
    # acceptance of arbitrary paths by Nix store-looking string format.
    if (not isinstance(selected, NativeToolset)
            or selected._proof is not _NATIVE_TOOL_PROOF or tool != "tofu"
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
        # A prior backend or capture is never a new output destination.
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
    # protected init, speculative plan and automatic-plan apply commands.
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


def native_apply(tofu: str, root: Path, tools: NativeToolset, *,
                 private_stdout: Path, private_stderr: Path) -> NativeCommand:
    """Re-plan and apply the fixed declaration in one native invocation.

    Approval concerns this source/target/stage, not a prior speculative diff.
    Actual actor/state/permission and Owner stage GO remain external. No saved
    plan, original transfer, automatic init, chained stage or retry is added.
    """
    verify_native_source(root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
    stdout, stderr = _private_streams(private_stdout, private_stderr)
    return NativeCommand(
        (native_bin(tofu, "tofu", tools), "-chdir=" + private_path(root), *APPLY_ARGS),
        private_stdout=stdout, private_stderr=stderr,
    )


@dataclass(frozen=True, repr=False)
class PrivateNativeResult:
    # Exact native no-op: 0=NO_OP in its effective context, 2=DELTA (unfinished).
    # Other commands: 0=success. Common finite failures: 1=ERROR,
    # 124=TIMEOUT, 125=START_FAILURE. No private stream content is returned.
    returncode: int


def _require_success(receipt: PrivateNativeResult) -> None:
    if not isinstance(receipt, PrivateNativeResult) or receipt.returncode != 0:
        raise NativeSourceHold("NATIVE_STAGE_UNPROVEN")


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
    values: Mapping[str, str] = field(repr=False)

    def check(self) -> None:
        _owner_home(self.home)
        verify_native_source(self.ops_root, OPS_MAIL_COMMIT, OPS_MAIL_TREE)
        if (not isinstance(self.account, str) or
                re.fullmatch(r"[0-9a-f]{32}", self.account) is None
                or not BUCKET.fullmatch(self.state_bucket)
                or not MAIL_STATE_KEY.fullmatch(self.state_key)
                or ".." in self.state_key.split("/") or "//" in self.state_key
):
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
    "rule_priority", "state_bucket", "state_key",
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
    approval state machine; fixed-source/target admission and stage GO stay external.
    """
    def __init__(self, inputs: MailPrivateInputs, tools: NativeToolset,
                 *, timeout: int = 90) -> None:
        if (not isinstance(inputs, MailPrivateInputs) or
                not isinstance(tools, NativeToolset) or
                tools._proof is not _NATIVE_TOOL_PROOF or
                type(timeout) is not int or not 1 <= timeout <= 120):
            raise NativeSourceHold("MAIL_RUNNER_UNADMITTED")
        native_bin(tools.tofu, "tofu", tools)
        inputs.check()
        self._inputs, self._tools, self._timeout = inputs, tools, timeout

    def _path(self, value: str) -> Path:
        path = Path(value)
        private_path(path)
        if path == self._inputs.home or self._inputs.home not in path.parents:
            raise NativeSourceHold("MAIL_PRIVATE_PATH_OUTSIDE_OWNER")
        return path

    def _command(self, cmd: NativeCommand) -> None:
        inp = self._inputs
        inp.check()
        private_output_sink(self._path(cmd.private_stdout))
        private_output_sink(self._path(cmd.private_stderr))
        args = cmd.argv
        if (len(args) < 4 or args[0] != self._tools.tofu
                or args[1] != "-chdir=" + str(inp.ops_root) or cmd.stdin is not None):
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")
        valid = args[2:] in (
            ("init", "-input=false", "-lockfile=readonly",
             "-backend-config=" + str(inp.backend)),
            NOOP_PLAN_ARGS,
            APPLY_ARGS,
        )
        if not valid:
            raise NativeSourceHold("MAIL_NATIVE_COMMAND_UNSELECTED")

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
        self._command(command)
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
