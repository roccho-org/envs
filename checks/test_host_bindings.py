#!/usr/bin/env python3
"""Offline gates for the Tool generation (T) fields of contracts/host-bindings/<target>/<HOST>.json.

`tool` is the exact store path of the selected T. `toolFrom` names the roccho-dev/resources Release asset
`<role>-tool.json` that published it, by URL and that asset's GitHub digest, the way `image`/`imageFrom` name B.
Both are present together or not at all. Only envs and the Target read them; the producer never does.

Consumer rule: a T is accepted only when the downloaded asset has the digest `toolFrom` names, that descriptor
names the same source with `storePath == tool`, and the T realised from that source has BOTH store path == `tool`
AND NAR hash == the descriptor's `narHash`. A match of only one of the two is refused.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "contracts/host-bindings"
STORE = re.compile(r"/nix/store/[0-9a-z]{32}-(?P<name>[A-Za-z0-9+._?=-]+)\Z")
NAR = re.compile(r"sha256-[A-Za-z0-9+/]{43}=\Z")
TOOL_FROM = re.compile(
    r"roccho-dev/resources Release windows-(?P<release>[0-9a-f]{40}); asset=(?P<asset>[a-z]+-tool\.json); "
    r"url=(?P<url>\S+); assetDigest=sha256:(?P<digest>[0-9a-f]{64}); source=(?P<source>[0-9a-f]{40}); "
    r"workflow=ci; run=[1-9][0-9]*\Z")


class Refusal(Exception):
    pass


def tool_from(binding: dict, role: str) -> dict | None:
    """The shape of tool/toolFrom: the parsed toolFrom, or None when the binding selects no T."""
    has = ("tool" in binding, "toolFrom" in binding)
    if has == (False, False):
        return None
    if has != (True, True):
        raise Refusal("tool and toolFrom are selected together")
    tool, origin = binding["tool"], binding["toolFrom"]
    if not isinstance(tool, str) or not isinstance(origin, str):
        raise Refusal("tool and toolFrom are strings")
    store = STORE.match(tool)
    if not store or store["name"] != f"{role}-tool-profile":
        raise Refusal(f"tool is not one {role}-tool-profile store path")
    parsed = TOOL_FROM.match(origin)
    if not parsed:
        raise Refusal("toolFrom does not name one Release asset by URL and digest")
    if parsed["asset"] != f"{role}-tool.json" or parsed["release"] != parsed["source"]:
        raise Refusal("toolFrom names another role's asset or another source's Release")
    url = f"https://github.com/roccho-dev/resources/releases/download/windows-{parsed['source']}/{parsed['asset']}"
    if parsed["url"] != url:
        raise Refusal("toolFrom url is not that Release asset")
    return parsed.groupdict()


def accept(binding: dict, role: str, asset: bytes, store_path: str, nar_hash: str) -> None:
    """The consumer rule: refuses unless the realised T matches in both store path and NAR hash."""
    origin = tool_from(binding, role)
    if origin is None:
        raise Refusal("the binding selects no T")
    if hashlib.sha256(asset).hexdigest() != origin["digest"]:
        raise Refusal("the asset differs from the digest toolFrom names")
    descriptor = json.loads(asset)
    if (descriptor.get("kind") != f"windows.{role}Tool.v1" or descriptor.get("source") != origin["source"]
            or descriptor.get("storePath") != binding["tool"] or not NAR.match(str(descriptor.get("narHash")))):
        raise Refusal("the descriptor does not describe the selected T")
    if store_path != binding["tool"] or nar_hash != descriptor["narHash"]:
        raise Refusal("the realised T differs in store path or NAR hash")


def red(fn) -> None:
    try:
        fn()
    except Refusal:
        return
    raise AssertionError("invalid T admitted")


def main() -> None:
    # GREEN: every committed binding is its own role/site and has a valid T selection or none.
    files = sorted(ROOT.glob("*/*.json"))
    assert files, "no host binding"
    selected = []
    for path in files:
        binding = json.loads(path.read_text(encoding="utf-8"))
        assert binding.get("role") == path.parent.name and binding.get("site") == path.stem, f"{path} names another target"
        if tool_from(binding, path.parent.name) is not None:
            selected.append(path.relative_to(ROOT).as_posix())
    assert "own/VERSAPRO.json" in selected, "own/VERSAPRO (native own) selects no T"

    # Synthetic descriptor and binding for the consumer rule.
    source = "1" * 40
    tool = "/nix/store/" + "a" * 32 + "-own-tool-profile"
    nar = "sha256-" + "B" * 43 + "="

    def descriptor(**change: str) -> bytes:
        fields = {"kind": "windows.ownTool.v1", "source": source, "output": "packages.x86_64-linux.own-profile",
                  "storePath": tool, "narHash": nar}
        fields.update(change)
        return json.dumps(fields, indent=2).encode() + b"\n"

    asset = descriptor()

    def made(asset_bytes: bytes = asset, **change: str) -> dict:
        fields = {"release": source, "asset": "own-tool.json", "digest": hashlib.sha256(asset_bytes).hexdigest(),
                  "source": source}
        fields.update(change)
        url = fields.get("url") or (
            f"https://github.com/roccho-dev/resources/releases/download/windows-{fields['release']}/{fields['asset']}")
        return {"role": "own", "site": "TEST", "tool": tool,
                "toolFrom": f"roccho-dev/resources Release windows-{fields['release']}; asset={fields['asset']}; "
                            f"url={url}; assetDigest=sha256:{fields['digest']}; source={fields['source']}; "
                            "workflow=ci; run=1"}

    accept(made(), "own", asset, tool, nar)

    # RED: the shape of tool/toolFrom.
    for drop in ("tool", "toolFrom"):
        wrong = made()
        del wrong[drop]
        red(lambda x=wrong: tool_from(x, "own"))
    for bad in ("/tmp/own-tool-profile", "/nix/store/" + "a" * 32 + "-rent-tool-profile",
                "/nix/store/" + "a" * 31 + "-own-tool-profile", tool + "\n", 1):
        wrong = made()
        wrong["tool"] = bad
        red(lambda x=wrong: tool_from(x, "own"))
    red(lambda: tool_from(made(), "rent"))
    for change in ({"asset": "rent-tool.json"}, {"release": "2" * 40}, {"source": "2" * 40},
                   {"url": "https://example.invalid/own-tool.json"}, {"digest": "0" * 63}, {"digest": "G" * 64}):
        red(lambda x=made(**change): tool_from(x, "own"))
    wrong = made()
    wrong["toolFrom"] += " "
    red(lambda: tool_from(wrong, "own"))

    # RED: the consumer accepts only when the store path and the NAR hash both match.
    other_store = "/nix/store/" + "b" * 32 + "-own-tool-profile"
    other_nar = "sha256-" + "C" * 43 + "="
    red(lambda: accept(made(), "own", asset, tool, other_nar))
    red(lambda: accept(made(), "own", asset, other_store, nar))
    red(lambda: accept(made(), "own", asset, other_store, other_nar))
    red(lambda: accept(made(), "own", asset + b" ", tool, nar))
    red(lambda: accept({"role": "own", "site": "TEST"}, "own", asset, tool, nar))
    for change in ({"storePath": other_store}, {"source": "2" * 40}, {"kind": "windows.rentTool.v1"},
                   {"narHash": "sha256-short="}):
        changed = descriptor(**change)
        red(lambda x=changed: accept(made(x), "own", x, tool, nar))
    print(f"PASS host bindings: {len(files)} files, T selected in {', '.join(selected)}; "
          "consumer accepts only when store path and NAR hash both match")


if __name__ == "__main__":
    main()
