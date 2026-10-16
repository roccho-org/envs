#!/usr/bin/env python3
"""Synthetic tests for the temporary rent Secret relocation entry.

No real Secret, Variable, public-key request or private key is used: values are synthetic and every decrypting key is
an ephemeral test key generated here. The guard, input and receipt checks run anywhere; the crypto and exact-environment
byte checks need PyNaCl and POSIX byte environments and run in `check` with `--require-nacl` on the locked Python.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters/relocate_rent_secrets.py"
SPEC = importlib.util.spec_from_file_location("relocate_rent_secrets", ADAPTER)
relocate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relocate)

SHA = "0123456789abcdef0123456789abcdef01234567"
# Awkward synthetic bytes the transport must keep exactly: Unicode, inner and trailing newlines, surrounding
# whitespace, CRLF, invalid UTF-8 and a value that is not a passphrase-shaped string.
VALUES = {
    b"CLOUDFLARE_API_TOKEN": "synthetic token é中\n".encode(),
    b"AWS_ACCESS_KEY_ID": b"  leading and trailing whitespace  ",
    b"AWS_SECRET_ACCESS_KEY": b"\xff\xfe synthetic invalid utf-8 \x80\r\n",
    b"RENT_STATE_PASSPHRASE": b"not a hex passphrase\nsecond line",
}
IDENTITY = {
    b"GITHUB_REPOSITORY": b"roccho-org/envs", b"GITHUB_REPOSITORY_ID": b"1391871347",
    b"GITHUB_REF": b"refs/heads/proposals", b"GITHUB_EVENT_NAME": b"workflow_dispatch", b"GITHUB_SHA": SHA.encode(),
    b"EXPECTED_SOURCE_SHA": SHA.encode(), b"GITHUB_RUN_ID": b"38700000001", b"GITHUB_RUN_ATTEMPT": b"1",
    b"GITHUB_ACTOR": b"roccho-dev", b"GITHUB_ACTOR_ID": b"40359643", b"GITHUB_TRIGGERING_ACTOR": b"roccho-dev",
    b"GITHUB_WORKFLOW_REF": b"roccho-org/envs/.github/workflows/relocate-dev-rent-secrets.yml@refs/heads/proposals",
}


def red(kind: str, call, *args) -> None:
    try:
        call(*args)
    except relocate.RelocationError as error:
        assert error.kind == kind, (error.kind, kind)
        return
    raise AssertionError(f"accepted although {kind} must be RED")


def test_constants() -> None:
    key = relocate.public_key()
    assert len(key) == 32
    assert relocate.MAPPING == (
        ("CLOUDFLARE_API_TOKEN", "RENT_CLOUDFLARE_API_TOKEN"), ("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
        ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"), ("RENT_STATE_PASSPHRASE", "RENT_STATE_PASSPHRASE"))
    assert relocate.DEST_ENVIRONMENT == "dev-projection" and relocate.DEST_ENVIRONMENT_ID == 22898969883
    assert relocate.SOURCE_ENVIRONMENT == "dev-rent-tunnel" and relocate.SOURCE_ENVIRONMENT_ID == 23400924734
    assert "MAIL_CONFIG" not in {name for pair in relocate.MAPPING for name in pair}
    other = base64.b64encode(bytes(32)).decode()
    red("key", relocate.public_key, other, relocate.DEST_PUBLIC_KEY_SHA256)
    red("key", relocate.public_key, relocate.DEST_PUBLIC_KEY, "0" * 64)
    red("key", relocate.public_key, base64.b64encode(key + b"x").decode(), relocate.DEST_PUBLIC_KEY_SHA256)
    red("key", relocate.public_key, "not base64!", relocate.DEST_PUBLIC_KEY_SHA256)


def test_inputs() -> None:
    values = relocate.read_inputs(VALUES)
    assert [(source, destination) for source, destination, _ in values] == list(relocate.MAPPING)
    assert [value for _, _, value in values] == [VALUES[source.encode()] for source, _ in relocate.MAPPING]
    for name in VALUES:
        red("input", relocate.read_inputs, {key: value for key, value in VALUES.items() if key != name})
        red("input", relocate.read_inputs, {**VALUES, name: b""})
        red("input", relocate.read_inputs, {**VALUES, name: b"a" * (relocate.SECRET_LIMIT + 1)})
        assert relocate.read_inputs({**VALUES, name: b"a" * relocate.SECRET_LIMIT})
    for forbidden in relocate.FORBIDDEN_INPUTS:
        red("input", relocate.read_inputs, {**VALUES, forbidden.encode(): b"present"})


def test_identity() -> None:
    assert relocate.run_identity(IDENTITY)["sha"] == SHA
    for name, value in (
        (b"GITHUB_REPOSITORY", b"roccho-dev/envs"), (b"GITHUB_REPOSITORY_ID", b"1"),
        (b"GITHUB_REF", b"refs/tags/proposals"), (b"GITHUB_REF", b"refs/heads/main"),
        (b"GITHUB_EVENT_NAME", b"push"), (b"GITHUB_EVENT_NAME", b"pull_request"),
        (b"EXPECTED_SOURCE_SHA", b"f" * 40), (b"GITHUB_SHA", b"short"), (b"GITHUB_RUN_ATTEMPT", b"2"),
        (b"GITHUB_RUN_ID", b"0"), (b"GITHUB_ACTOR", b"someone"), (b"GITHUB_ACTOR_ID", b"1"),
        (b"GITHUB_TRIGGERING_ACTOR", b"someone"), (b"GITHUB_ACTOR", b"roccho-dev\xff"),
        (b"GITHUB_WORKFLOW_REF", b"roccho-org/envs/.github/workflows/check.yml@refs/heads/proposals"),
        (b"GITHUB_WORKFLOW_REF", b"roccho-org/envs/.github/workflows/relocate-dev-rent-secrets.yml@refs/tags/proposals"),
    ):
        red("identity", relocate.run_identity, {**IDENTITY, name: value})
    for name in IDENTITY:
        red("identity", relocate.run_identity, {key: value for key, value in IDENTITY.items() if key != name})


def synthetic_receipt() -> dict:
    sealed = [{"source": source, "destination": destination,
               "encrypted_value": base64.b64encode(os.urandom(len(VALUES[source.encode()]) + relocate.SEAL_OVERHEAD)).decode()}
              for source, destination in relocate.MAPPING]
    return relocate.build_receipt(relocate.run_identity(IDENTITY), sealed)


def encoded(receipt: dict) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()


def test_receipt() -> None:
    receipt = synthetic_receipt()
    assert relocate.validate_receipt(encoded(receipt))["key_id"] == relocate.DEST_KEY_ID
    mutations = (
        lambda r: r.update({"extra": True}), lambda r: r.pop("run_id"), lambda r: r.update({"key_id": "1"}),
        lambda r: r.update({"public_key_sha256": "0" * 64}), lambda r: r.update({"run_attempt": "2"}),
        lambda r: r.update({"ref": "refs/tags/proposals"}), lambda r: r.update({"actor_id": "1"}),
        lambda r: r.update({"destination_environment": {"name": "dev-rent-tunnel", "id": 23400924734}}),
        lambda r: r.update({"source_environment": {"name": "dev-projection", "id": 22898969883}}),
        lambda r: r["secrets"].pop(), lambda r: r["secrets"].reverse(),
        lambda r: r["secrets"].append({"source": "MAIL_CONFIG", "destination": "MAIL_CONFIG", "encrypted_value": "AAAA"}),
        lambda r: r["secrets"][0].update({"destination": "CLOUDFLARE_API_TOKEN"}),
        lambda r: r["secrets"][1].update({"encrypted_value": "not base64!"}),
        lambda r: r["secrets"][2].update({"encrypted_value": base64.b64encode(b"short").decode()}),
        lambda r: r["secrets"][3].update({"plaintext": "x"}),
    )
    for mutate in mutations:
        changed = json.loads(encoded(receipt))
        mutate(changed)
        red("receipt", relocate.validate_receipt, encoded(changed))
    red("receipt", relocate.validate_receipt, b"x" * (relocate.RECEIPT_LIMIT + 1))
    red("receipt", relocate.validate_receipt, b"")


def run_entry(arguments: list[str], environ: dict[bytes, bytes]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([sys.executable, "-I", str(ADAPTER), *arguments], env=environ, capture_output=True,
                          timeout=120, check=False)


def test_cli_refusals() -> None:
    # The real entry: one fixed line, no traceback, no receipt, and no input byte on any stream.
    with tempfile.TemporaryDirectory(prefix="relocate-refusal-") as directory:
        output = Path(directory) / "relocate" / "receipt.json"
        cases = (
            (["seal", "--output", str(output)], {**IDENTITY, **VALUES, b"GITHUB_REF": b"refs/tags/proposals"}, "identity"),
            (["seal", "--output", str(output)], {**IDENTITY, **VALUES, b"GITHUB_RUN_ATTEMPT": b"2"}, "identity"),
            (["seal", "--output", str(output)], {**IDENTITY, b"AWS_ACCESS_KEY_ID": b"x"}, "input"),
            (["seal", "--output", str(output)], {**IDENTITY, **VALUES, b"MAIL_CONFIG": b"x"}, "input"),
            (["seal", "--output", str(output)], {**IDENTITY, **VALUES, b"RENT_STATE_PASSPHRASE": b""}, "input"),
            (["seal"], {**IDENTITY, **VALUES}, "usage"),
            (["seal", "--output", str(output), "--key", "x"], {**IDENTITY, **VALUES}, "usage"),
            ([], {}, "usage"),
        )
        for arguments, environ, kind in cases:
            result = run_entry(arguments, environ)
            assert result.returncode == 1 and result.stderr == b"", (arguments, result.returncode)
            assert result.stdout == f"RELOCATE=RED: {kind}\n".encode(), (arguments, result.stdout)
            assert not output.parent.exists(), "a refused run wrote output"
            for value in VALUES.values():
                assert value not in result.stdout


def test_selftest_cli() -> None:
    result = run_entry(["selftest"], {})
    assert result.returncode == 0 and result.stderr == b"" and result.stdout == b"RELOCATE_SELFTEST=PASS\n", result.stdout


# The child reads its own exact process environment bytes and seals them to an ephemeral synthetic test key.
CHILD = """
import base64, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("relocate", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
values = module.read_inputs(os.environb)
print(json.dumps(module.seal_values(values, base64.b64decode(sys.argv[2]))))
"""


def test_environment_bytes_roundtrip() -> None:
    from nacl.exceptions import CryptoError
    from nacl.public import PrivateKey, SealedBox

    synthetic, other = PrivateKey.generate(), PrivateKey.generate()
    public = base64.b64encode(bytes(synthetic.public_key)).decode()
    samples = dict(VALUES)
    samples[b"RENT_STATE_PASSPHRASE"] = b"b" * relocate.SECRET_LIMIT
    result = subprocess.run([sys.executable, "-I", "-c", CHILD, str(ADAPTER), public], env=samples,
                            capture_output=True, timeout=120, check=False)
    assert result.returncode == 0 and result.stderr == b"", result.stderr[-200:]
    sealed = json.loads(result.stdout)
    assert [(item["source"], item["destination"]) for item in sealed] == list(relocate.MAPPING)
    for item in sealed:
        raw = base64.b64decode(item["encrypted_value"])
        original = samples[item["source"].encode()]
        assert len(raw) == len(original) + relocate.SEAL_OVERHEAD
        assert SealedBox(synthetic).decrypt(raw) == original, "bytes were not preserved exactly"
        for wrong in (lambda: SealedBox(other).decrypt(raw), lambda: SealedBox(synthetic).decrypt(raw[:-1] + bytes([raw[-1] ^ 1]))):
            try:
                wrong()
            except CryptoError:
                continue
            raise AssertionError("a wrong key or tampered box opened")
        assert original not in result.stdout


def test_seal_cli() -> None:
    # The real entry against its fixed destination key: only ciphertext leaves, owner-only, and nothing can open it here.
    with tempfile.TemporaryDirectory(prefix="relocate-seal-") as directory:
        output = Path(directory) / "relocate" / "receipt.json"
        result = run_entry(["seal", "--output", str(output)], {**IDENTITY, **VALUES})
        assert result.returncode == 0 and result.stderr == b"" and result.stdout == b"RELOCATE=SEALED\n", result.stdout
        data = output.read_bytes()
        receipt = relocate.validate_receipt(data)
        assert stat.S_IMODE(output.stat().st_mode) == 0o600 and stat.S_IMODE(output.parent.stat().st_mode) == 0o700
        assert receipt["source_sha"] == SHA and receipt["run_id"] == "38700000001" and receipt["key_id"] == relocate.DEST_KEY_ID
        for item in receipt["secrets"]:
            original = VALUES[item["source"].encode()]
            assert len(base64.b64decode(item["encrypted_value"])) == len(original) + relocate.SEAL_OVERHEAD
            assert original not in data and original not in result.stdout
        again = run_entry(["seal", "--output", str(output)], {**IDENTITY, **VALUES})
        assert again.returncode == 1 and again.stdout == b"RELOCATE=RED: output\n" and output.read_bytes() == data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-nacl", action="store_true")
    args = parser.parse_args()
    test_constants()
    test_inputs()
    test_identity()
    test_receipt()
    crypto = importlib.util.find_spec("nacl") is not None and os.name == "posix"
    if args.require_nacl and not crypto:
        raise AssertionError("PyNaCl and POSIX byte environments are required for the crypto checks")
    if os.name == "posix":
        test_cli_refusals()
    if crypto:
        test_selftest_cli()
        test_environment_bytes_roundtrip()
        test_seal_cli()
        print("relocation entry: guards, inputs, receipt, refusals, exact-byte crypto and sealed receipt: PASS")
    else:
        print("relocation entry: guards, inputs and receipt PASS; crypto/environment-byte checks NOT RUN here")


if __name__ == "__main__":
    main()
