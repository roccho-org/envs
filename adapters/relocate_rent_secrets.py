#!/usr/bin/env python3
"""One-time encrypted relocation of the four existing rent Secrets (closure-v2, temporary).

The single guarded `relocate-dev-rent-secrets` run selects the old `dev-rent-tunnel` Environment, which injects the four
existing Secrets into exactly one step. This entry reads their exact bytes from the process environment, seals each with a
standard libsodium sealed box (PyNaCl `SealedBox`) to the existing `dev-projection` Environment public key fixed below, and
writes one encrypted receipt. Nothing here can decrypt it: only GitHub holds the matching private key. The owner then
registers each `encrypted_value` with its `key_id` through the standard Environment Secret API.

Values are never stripped, normalized, decoded or format-checked: only non-empty and a closed size bound are required, so
the destination receives the same bytes the old Environment injected. No value, length, hash or fragment is printed; the
only output is one fixed status line. This proves byte-preserving transport, not provider or runtime acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping

# The existing destination, captured once by the owner from the standard public-key endpoint: public metadata only.
# There is no recipient or key input; a different key needs a reviewed source change.
DEST_ENVIRONMENT = "dev-projection"
DEST_ENVIRONMENT_ID = 22898969883
DEST_KEY_ID = "3380204578043523366"
DEST_PUBLIC_KEY = "0p90Ahe11eOEuKSz+G63Mbzuk81Xx7hKM7b7cwG5ZgQ="
DEST_PUBLIC_KEY_SHA256 = "4e3a4e228c5911cfcc6c3c7804cdd1628ca1e692d9fb5255b48f96de438f1cd1"
SOURCE_ENVIRONMENT = "dev-rent-tunnel"
SOURCE_ENVIRONMENT_ID = 23400924734
# The four existing Secret names and their destination slots; nothing else is read or relocated.
MAPPING = (
    ("CLOUDFLARE_API_TOKEN", "RENT_CLOUDFLARE_API_TOKEN"),
    ("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
    ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"),
    ("RENT_STATE_PASSPHRASE", "RENT_STATE_PASSPHRASE"),
)
# Names that must never reach this process: the unused old Mail Secret, the retired R2 parent token and the
# destination slot name (a run must read the old source names only).
FORBIDDEN_INPUTS = ("MAIL_CONFIG", "R2_PARENT_API_TOKEN", "R2_PARENT_ACCESS_KEY_ID", "RENT_CLOUDFLARE_API_TOKEN")
SECRET_LIMIT = 48 * 1024
RECEIPT_LIMIT = 1024 * 1024
SEAL_OVERHEAD = 48
RECEIPT_KIND = "envs.rentSecretRelocationReceipt.v1"
REPOSITORY = "roccho-org/envs"
REPOSITORY_ID = "1391871347"
REF = "refs/heads/proposals"
WORKFLOW = ".github/workflows/relocate-dev-rent-secrets.yml"
ACTOR = "roccho-dev"
ACTOR_ID = "40359643"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
SEALED_LINE = "RELOCATE=SEALED"
SELFTEST_LINE = "RELOCATE_SELFTEST=PASS"
RECEIPT_KEYS = {
    "kind", "repository", "repository_id", "ref", "workflow", "source_sha", "run_id", "run_attempt", "actor_id",
    "source_environment", "destination_environment", "key_id", "public_key_sha256", "secrets",
}


class RelocationError(Exception):
    """A closed failure kind; its text is never a value, length or exception message."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def require(ok: bool, kind: str) -> None:
    if not ok:
        raise RelocationError(kind)


def public_key(encoded: str = DEST_PUBLIC_KEY, expected_sha256: str = DEST_PUBLIC_KEY_SHA256) -> bytes:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise RelocationError("key") from None
    require(len(raw) == 32 and hashlib.sha256(raw).hexdigest() == expected_sha256, "key")
    return raw


def read_inputs(environ: Mapping[bytes, bytes]) -> list[tuple[str, str, bytes]]:
    # Exact bytes: no strip, decoding, normalization, newline or format admission. Only present, non-empty and bounded.
    require(not any(name.encode() in environ for name in FORBIDDEN_INPUTS), "input")
    values = []
    for source, destination in MAPPING:
        value = environ.get(source.encode())
        require(isinstance(value, bytes) and 0 < len(value) <= SECRET_LIMIT, "input")
        values.append((source, destination, bytes(value)))
    return values


def run_identity(environ: Mapping[bytes, bytes]) -> dict[str, str]:
    # The workflow job gate already admits only this exact dispatch; the entry checks the same facts again.
    def text(name: str) -> str:
        value = environ.get(name.encode(), b"")
        try:
            return value.decode("ascii")
        except UnicodeDecodeError:
            raise RelocationError("identity") from None

    identity = {
        "repository": text("GITHUB_REPOSITORY"), "repository_id": text("GITHUB_REPOSITORY_ID"), "ref": text("GITHUB_REF"),
        "event": text("GITHUB_EVENT_NAME"), "sha": text("GITHUB_SHA"), "expected": text("EXPECTED_SOURCE_SHA"),
        "run_id": text("GITHUB_RUN_ID"), "run_attempt": text("GITHUB_RUN_ATTEMPT"), "actor": text("GITHUB_ACTOR"),
        "actor_id": text("GITHUB_ACTOR_ID"), "triggering_actor": text("GITHUB_TRIGGERING_ACTOR"),
        "workflow_ref": text("GITHUB_WORKFLOW_REF"),
    }
    require(identity["repository"] == REPOSITORY and identity["repository_id"] == REPOSITORY_ID
            and identity["ref"] == REF and identity["event"] == "workflow_dispatch"
            and SHA40.fullmatch(identity["sha"]) is not None and identity["sha"] == identity["expected"]
            and RUN_ID.fullmatch(identity["run_id"]) is not None and identity["run_attempt"] == "1"
            and identity["actor"] == ACTOR and identity["actor_id"] == ACTOR_ID
            and identity["triggering_actor"] == ACTOR
            and identity["workflow_ref"] == f"{REPOSITORY}/{WORKFLOW}@{REF}", "identity")
    return identity


def seal_values(values: list[tuple[str, str, bytes]], key: bytes) -> list[dict[str, str]]:
    from nacl.public import PublicKey, SealedBox

    box = SealedBox(PublicKey(key))
    sealed = []
    for source, destination, value in values:
        cipher = box.encrypt(value)
        require(len(cipher) == len(value) + SEAL_OVERHEAD, "crypto")
        sealed.append({"source": source, "destination": destination,
                       "encrypted_value": base64.b64encode(cipher).decode("ascii")})
    return sealed


def build_receipt(identity: Mapping[str, str], sealed: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "kind": RECEIPT_KIND, "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "ref": REF, "workflow": WORKFLOW,
        "source_sha": identity["sha"], "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
        "actor_id": identity["actor_id"],
        "source_environment": {"name": SOURCE_ENVIRONMENT, "id": SOURCE_ENVIRONMENT_ID},
        "destination_environment": {"name": DEST_ENVIRONMENT, "id": DEST_ENVIRONMENT_ID},
        "key_id": DEST_KEY_ID, "public_key_sha256": DEST_PUBLIC_KEY_SHA256, "secrets": sealed,
    }


def validate_receipt(data: bytes) -> dict[str, Any]:
    # The exact receipt shape the owner validates before any registration; it carries ciphertext only.
    require(0 < len(data) <= RECEIPT_LIMIT, "receipt")
    try:
        receipt = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RelocationError("receipt") from None
    require(isinstance(receipt, dict) and set(receipt) == RECEIPT_KEYS, "receipt")
    require(receipt["kind"] == RECEIPT_KIND and receipt["repository"] == REPOSITORY
            and receipt["repository_id"] == REPOSITORY_ID and receipt["ref"] == REF and receipt["workflow"] == WORKFLOW
            and isinstance(receipt["source_sha"], str) and SHA40.fullmatch(receipt["source_sha"]) is not None
            and isinstance(receipt["run_id"], str) and RUN_ID.fullmatch(receipt["run_id"]) is not None
            and receipt["run_attempt"] == "1" and receipt["actor_id"] == ACTOR_ID
            and receipt["source_environment"] == {"name": SOURCE_ENVIRONMENT, "id": SOURCE_ENVIRONMENT_ID}
            and receipt["destination_environment"] == {"name": DEST_ENVIRONMENT, "id": DEST_ENVIRONMENT_ID}
            and receipt["key_id"] == DEST_KEY_ID and receipt["public_key_sha256"] == DEST_PUBLIC_KEY_SHA256, "receipt")
    secrets = receipt["secrets"]
    require(isinstance(secrets, list) and len(secrets) == len(MAPPING), "receipt")
    for item, (source, destination) in zip(secrets, MAPPING):
        require(isinstance(item, dict) and set(item) == {"source", "destination", "encrypted_value"}
                and item["source"] == source and item["destination"] == destination
                and isinstance(item["encrypted_value"], str), "receipt")
        try:
            cipher = base64.b64decode(item["encrypted_value"], validate=True)
        except (ValueError, TypeError):
            raise RelocationError("receipt") from None
        require(SEAL_OVERHEAD < len(cipher) <= SECRET_LIMIT + SEAL_OVERHEAD, "receipt")
    return receipt


def write_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    data = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    validate_receipt(data)
    path.parent.mkdir(mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def seal(environ: Mapping[bytes, bytes], output: Path) -> None:
    identity = run_identity(environ)
    key = public_key()
    values = read_inputs(environ)
    write_receipt(output, build_receipt(identity, seal_values(values, key)))


def selftest() -> None:
    # Before any Secret is mapped: the wrapped interpreter imports PyNaCl, the fixed key is well formed, and ephemeral
    # synthetic keys round-trip awkward bytes exactly while a wrong key and a tampered box fail.
    from nacl.exceptions import CryptoError
    from nacl.public import PrivateKey, SealedBox

    key = public_key()
    samples = (b"x", "Unicode é中\U0001f511".encode(), b"line one\nline two\n", b"  padded\t ", b"\r\n",
               b"\xff\xfe invalid utf-8 \x80", b"a" * SECRET_LIMIT)
    synthetic = PrivateKey.generate()
    other = PrivateKey.generate()
    for value in samples:
        cipher = seal_values([("CLOUDFLARE_API_TOKEN", "RENT_CLOUDFLARE_API_TOKEN", value)], bytes(synthetic.public_key))
        raw = base64.b64decode(cipher[0]["encrypted_value"])
        require(SealedBox(synthetic).decrypt(raw) == value, "selftest")
        for wrong in (other, None):
            try:
                if wrong is None:
                    SealedBox(synthetic).decrypt(raw[:-1] + bytes([raw[-1] ^ 1]))
                else:
                    SealedBox(wrong).decrypt(raw)
            except CryptoError:
                continue
            raise RelocationError("selftest")
    require(len(seal_values([("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID", b"x")], key)[0]["encrypted_value"]) > 0, "selftest")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["selftest"]:
            selftest()
            print(SELFTEST_LINE)
            return 0
        if len(args) == 3 and args[0] == "seal" and args[1] == "--output":
            seal(os.environb, Path(args[2]))
            print(SEALED_LINE)
            return 0
        raise RelocationError("usage")
    except RelocationError as error:
        print(f"RELOCATE=RED: {error.kind}")
    except ImportError:
        print("RELOCATE=RED: crypto")
    except OSError:
        print("RELOCATE=RED: output")
    except Exception:  # noqa: BLE001 - no message, class name or traceback may carry a value
        print("RELOCATE=RED: other")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
