#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    ".github/pull_request_template.md",
    ".github/workflows/check.yml",
    ".github/workflows/jev-issue-comment.yml",
    ".github/workflows/author-dev-jev-api.yml",
    ".github/workflows/project-dev-jev-api.yml",
    ".github/workflows/project-dev-rent-tunnel.yml",
    ".github/workflows/probe-dev-linode-read.yml",
    ".github/workflows/probe-dev-mail-routing.yml",
    ".github/workflows/operate-dev-mail-routing.yml",
    ".github/workflows/deploy-calendar-pages.yml",
    ".github/workflows/deploy-pi-worker-preview.yml",
    ".gitignore",
    "LICENSE_POLICY.md",
    "LICENSES/README.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "adapters/jev_api.py",
    "adapters/calendar_pages.py",
    "adapters/mail_routing_read.py",
    "adapters/mail_routing_root.py",
    "adapters/place.ps1",
    "adapters/rent-receive.sh",
    "checks/repository.py",
    "checks/test_jev_api.py",
    "checks/test_calendar_pages.py",
    "checks/test_linode_read_probe.py",
    "checks/test_mail_routing_read.py",
    "checks/test_mail_routing_root.py",
    "checks/test_rent_tunnel.py",
    "checks/test_repository.py",
    "contracts/bindings.jsonl",
    "contracts/environments.jsonl",
    "contracts/provider-consumer.jsonl",
    "contracts/targets.jsonl",
    "flake.lock",
    "flake.nix",
    "providers/dev-rent-cloudflare/main.tf",
}
ALLOWED_ROOTS = {
    ".github",
    "LICENSES",
    "adapters",
    "checks",
    "ciphertexts",
    "contracts",
    "handoffs",
    "providers",
}
ALLOWED_ROOT_FILES = {
    ".gitignore",
    "LICENSE_POLICY.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "flake.lock",
    "flake.nix",
}
FORBIDDEN_ROOTS = {
    "appearance",
    "bindings",
    "cmd",
    "docs",
    "environments",
    "hosts",
    "internal",
    "lib",
    "migration",
    "modules",
    "scripts",
    "tests",
}
FORBIDDEN_FILENAMES = {
    ".env",
    ".mise.toml",
    "go.mod",
    "go.sum",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {".go", ".p12", ".pem", ".pfx", ".sh"}
# The one shell text: the rent receiver, which runs inside the rent image and is never executed on this repository.
RENT_RECEIVER = "adapters/rent-receive.sh"
PLACEMENT_ENTRY = "adapters/place.ps1"
# placement-gate (windows #14): the four jobs and the bindings that make each one evidence of the actual outputs.
PLACEMENT_MARKERS = (
    "\n  placement-artifact:\n",
    "\n  placement-author:\n    needs: toolchain\n",
    "\n  placement-windows:\n    needs: [placement-artifact, placement-author]\n    runs-on: windows-latest\n",
    "\n  placement-rent:\n    needs: [toolchain, placement-artifact, placement-author, placement-windows]\n",
    "nix build .#placement-artifact --no-update-lock-file",
    'test "$(cat "$RUNNER_TEMP/placement/SOURCE")" = "$ENVS_SOURCE_SHA"',
    'echo "cb6fec76e23cb4ac56771ac38472b0fe1ba79a849bf2200aeda7c9467a045b7b  $RUNNER_TEMP/placement/sops.exe" | sha256sum -c -',
    "name: envs-placement-${{ env.ENVS_SOURCE_SHA }}",
    "name: placement-identities-${{ env.ENVS_SOURCE_SHA }}",
    'test "$(tar -xOf "$RUNNER_TEMP/effect/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"',
    '"$entry" --root "$data" rent-client',
    "$ref.object.type -cne 'commit' -or $ref.object.sha -cne $source",
    "$release.author.login -cne 'github-actions[bot]'",
    "$asset.uploader.login -cne 'github-actions[bot]'",
    "$required = 'scope', 'build', 'windows', 'rent / build-test-publish', 'publish'",
    "if ('sha256:' + (Sha (Join-Path $dir $asset.name)) -cne $asset.digest)",
    "(Get-Content -LiteralPath \"$zip.sha256\" -Raw).Split(' ')[0] -cne (Sha $zip)",
    "$image.source -cne $source",
    "$n.Name -cin @('ReadRentAccessInput', 'Get-RentAccessProblem')",
    "& (Join-Path $Placement 'place.ps1') -Target client",
    "$placed.verdict.sha256 -cne $values.client_slot_sha256",
    "$wrong.stderr -notlike 'place: decryption failed; nothing placed.*'",
    "$tampered.code -ne 2",
    "manifests/sha-$WINDOWS_SOURCE",
    'docker run --rm -i -v rent-placement-state:/var/lib/rent "$RENT_IMAGE" /bin/bash -c "$receiver"',
    "test \"$(slot 'stat -c %u:%g:%a /s/cloudflared/token')\" = \"0:0:600\"",
    "$oversize.stderr -notlike 'place: the decrypted value exceeds its bound; nothing placed.*'",
    "-Target rent -Identity",
    'test "$(place)" = "rent-receive: unchanged"',
    "for drift in 'chmod 644 /s/cloudflared/token' 'chown 1000:1000 /s/cloudflared/token'; do",
    "for pair in 'chmod 777 /s/cloudflared|chmod 700 /s/cloudflared' 'chmod 770 /s/cloudflared|chmod 700 /s/cloudflared' \\\n"
    "            'chown 1000:0 /s/cloudflared|chown 0:0 /s/cloudflared' \"chmod 775 /s|chmod $root_mode /s\" 'chown 1000:0 /s|chown 0:0 /s'; do",
    'slot \'chmod 755 /s/cloudflared\'\n          test "$(printf \'%s\' "$other" | receive)" = "rent-receive: unchanged"',
)
PLACEMENT_FLAKE = (
    'hash = assert pkgs.sops.version == "3.13.2"; "sha256-y2/sduI8tKxWdxrDhHKw/hunmoSb8iAK7afJRnoEW3s=";',
    'url = "https://github.com/getsops/sops/releases/download/v${pkgs.sops.version}/sops-v${pkgs.sops.version}.amd64.exe";',
    "cp ${self}/adapters/place.ps1 ${self}/adapters/rent-receive.sh \"$out/\"",
    "inherit effect-toolchain effect-artifact placement-artifact;",
)
SECRET_PATTERNS = {
    "age private identity": re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
    "private key": re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "npm token": re.compile(rb"\bnpm_[A-Za-z0-9]{30,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    "Stripe live key": re.compile(rb"\bsk_live_[0-9A-Za-z]{20,}\b"),
    "basic-auth URL": re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@[^\s]+"),
}
ACTION_USE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)")
INPUT_REFERENCE = re.compile(r"\$\{\{\s*(secrets|vars)\.([A-Za-z0-9_]+)\s*\}\}")
EFFECT_WORKFLOWS = {
    "author-dev-jev-api.yml": "dev.authoring",
    "project-dev-jev-api.yml": "dev.projection",
    # The rent workflow applies the persistent root; the standalone rent-tunnel GET stays an entry without a workflow.
    "project-dev-rent-tunnel.yml": "dev.rent-root",
    "probe-dev-linode-read.yml": "dev.linode-read-probe",
    "probe-dev-mail-routing.yml": "dev.projection",
}
RENT_CONFIG = "providers/dev-rent-cloudflare/main.tf"
# Host-specific GitHub Environments are retired: rent stage ingress lives in dev-projection. No workflow may select
# one of these names, and nothing may declare it as a plane's Environment.
RETIRED_ENVIRONMENTS = ("dev-rent-tunnel", "dev-rent-client", "dev-rent-access-probe")
# The retired disposable probe and state proof entrances, their parent token and their roots never return.
RETIRED_PATHS = (
    ".github/workflows/probe-dev-rent-access-ssh.yml",
    ".github/workflows/probe-dev-rent-state.yml",
    "providers/dev-rent-access-probe/main.tf",
    "providers/dev-rent-state-proof/main.tf",
    "providers/dev-rent-state-proof/backend/main.tf",
    "checks/test_rent_access_probe.py",
    "checks/test_rent_state_proof.py",
)
# TEMPORARY one-time encrypted relocation (closure-v2): the only entrance that may select the old dev-rent-tunnel
# Environment. Its retirement removes these paths, this exception and the check.yml steps before dev-rent-tunnel goes.
RELOCATION_WORKFLOW = "relocate-dev-rent-secrets.yml"
RELOCATION_PATHS = (
    ".github/workflows/relocate-dev-rent-secrets.yml",
    "adapters/relocate_rent_secrets.py",
    "checks/test_relocate_rent_secrets.py",
)
RELOCATION_ENVIRONMENT = "dev-rent-tunnel"
RELOCATION_SECRETS = ("CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RENT_STATE_PASSPHRASE")
RELOCATION_GATE = (
    "    if: ${{ github.repository == 'roccho-org/envs' && github.repository_id == '1391871347'"
    " && github.ref == 'refs/heads/proposals' && github.event_name == 'workflow_dispatch'"
    " && github.sha == inputs.expected_source_sha && github.run_attempt == '1' && github.actor == 'roccho-dev'"
    " && github.actor_id == '40359643' && github.triggering_actor == 'roccho-dev' }}\n"
)
RELOCATION_ACTIONS = {
    ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
    ("cachix/install-nix-action", "13d8dd58da0234aa297dedd986986ccb8e7f3e24"),
    ("actions/upload-artifact", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
}
RELOCATION_STEPS = [
    "Checkout exact canonical revision", "Install pinned Nix", "Build locked Python with PyNaCl",
    "Synthetic self-test before any Secret", "Seal the four Secrets to the dev-projection public key",
    "Upload the encrypted receipt only",
]
# The rent inspect job admits the same one native controller dispatch as the relocation, before its Environment.
RENT_INSPECT_GATE = RELOCATION_GATE
RENT_INSPECT_STEPS = [
    "Checkout exact canonical revision", "Obtain provided effect artifact", "Record effect toolchain identity",
    "Inspect old S3 state/lock and Cloudflare world",
]
# Outside the shared consumer, nothing in the inspect job may print, export or keep a value, or gain a write.
RENT_INSPECT_FORBIDDEN = ("echo", "printf", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "outputs:", "upload-artifact",
                          "actions/cache", "add-mask", "set-output", "write", '"$tool/', "tee ")
# The locked nixpkgs Python with PyNaCl, from the existing lock and nothing else; the same expression tests it in check.
RELOCATION_NIXPKGS = "test \"$(nix eval --impure --raw --expr \"($flake).inputs.nixpkgs.rev\")\" = f9948418dc8628ac02b6d6337e191ade9429d59d"
RELOCATION_PYTHON = ('python="$(nix build --impure --no-link --print-out-paths --expr '
                     '"($pkgs).python3.withPackages (ps: [ ps.pynacl ])")/bin/python3"')
RELOCATION_SELFTEST = "run: '\"$RELOCATE_PYTHON\" -I adapters/relocate_rent_secrets.py selftest'\n"
RELOCATION_SEAL = ("run: '\"$RELOCATE_PYTHON\" -I adapters/relocate_rent_secrets.py seal --output "
                   "\"$RUNNER_TEMP/relocate/receipt.json\"'\n")
# check proves the closure client and the persistent root declaration: exact client version, its token flags, and an
# OpenTofu init/validate of the root with every network route closed.
PROBE_TOOL_CHECKS = (
    '"$tool/cloudflared" --version | tee "$RUNNER_TEMP/cloudflared.version"',
    'grep -qF "cloudflared version 2026.6.1 " "$RUNNER_TEMP/cloudflared.version"',
    'grep -qF -- --service-token-id "$RUNNER_TEMP/access-ssh.help"',
    'cp providers/dev-rent-cloudflare/main.tf "$rent/"',
    'HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$tool/tofu" -chdir="$rent" init -backend=false -input=false'
    ' -no-color',
    '"$tool/tofu" -chdir="$rent" validate -no-color',
)
CIPHERTEXTS = {
    "ciphertexts/dev-mail-state.sops.json",
    "ciphertexts/dev-jev-api.sops.yaml", "ciphertexts/dev-rent-tunnel.sops.yaml", "ciphertexts/dev-jev-api.oci-dev.sops.yaml",
    "ciphertexts/dev-rent-client.sops.yaml", "ciphertexts/dev-opencode-go.oci-dev.sops.yaml",
    "ciphertexts/dev-opencode-go.versapro-own-oci.sops.yaml",
    "ciphertexts/dev-typellm-api.oci-dev.sops.yaml",
    "ciphertexts/dev-typellm-api.versapro-own-oci.sops.yaml",
}
# The real SOPS roundtrip runs the locked sops with a check-only age that never enters the effect toolchain; the
# closure tofu joins it so a real root output reaches the production sealing path.
CHECK_AGE_BUILD = 'nix build .#check-age --no-update-lock-file --out-link "$RUNNER_TEMP/check-age"'
REAL_ROUNDTRIP = ('"$tool/python3" -I checks/test_rent_tunnel.py --sops "$tool/sops"'
                  ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen" --tofu "$tool/tofu"')
OCI_ROUNDTRIP = ('"$tool/python3" -I checks/test_jev_api.py --sops "$tool/sops"'
                 ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen"')
# The author dispatch names one declared binding; each has exactly one literal step carrying only its own inputs.
AUTHOR_STEP = re.compile(r"(?ms)^      - name: [^\n]+\n        if: inputs\.target == '([a-z.-]+)'\n(.*?)(?=^      - name: |\Z)")
EFFECT_PACKAGES = ("packages = with pkgs; [ python3 sops wrangler git gh openssh curl ]"
                   " ++ [ cloudflared opentofu terraform-backend-git ];")
PROBE_PINS = (
    'cloudflared = assert pkgs.cloudflared.version == "2026.6.1"; pkgs.cloudflared;',
    "opentofu = pkgs.opentofu.withPlugins (p: [ p.cloudflare_cloudflare ]);",
)
# GitHub-ref state transport: the exact upstream v0.1.12 release binary windows infra/git-state also pins, run
# unmodified through the Nix loader. The toolchain build itself executes it (the existing check builds the toolchain),
# so these lines, including the build-time smoke check, must each appear exactly once.
BACKEND_PINS = (
    'gitBackendElf = pkgs.runCommand "terraform-backend-git-0.1.12-elf" {',
    '          url = "https://github.com/plumber-cd/terraform-backend-git/releases/download/v0.1.12/'
    'terraform-backend-git-linux-amd64";',
    '          hash = "sha256-LumYYi0ryF7WaaGuZ6k+DNi564hn/IOda9bw9iLrDYA=";',
    '      terraform-backend-git = pkgs.writeTextFile {',
    '          exec ${pkgs.stdenv.cc.bintools.dynamicLinker} \\',
    '            ${gitBackendElf}/bin/terraform-backend-git-elf "$@"',
    '        checkPhase = \'\'\n'
    '          "$target" --help >backend.help 2>&1 || true\n'
    '          grep -qF -- --address backend.help\n'
    "        '';",
)
TOOLCHAIN_BUILD = 'nix build .#effect-toolchain --no-update-lock-file'
ARTIFACT_BUILD = 'nix build .#effect-artifact --no-update-lock-file'
SOURCE_SHA = "${{ github.event.pull_request.head.sha || github.sha }}"
ARTIFACT_NAME = "name: envs-effect-${{ env.ENVS_SOURCE_SHA }}"
# The consumer binds the named commit to the producing run and to the artifact's own SOURCE.
CONSUMER_BINDING = (
    '.head_sha == $sha',
    '.repository.full_name == $repo and .head_repository.full_name == $repo',
    '((.id | tostring) == $current or (.event == "push" and .conclusion == "success"))',
    'test "$(tar -xOf "$art/content/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"',
)
EFFECT_ENV = re.compile(r"(?m)^ {10}([A-Za-z_][A-Za-z0-9_-]*):")
EFFECT_STEP_KEYS = {"ref", "fetch-depth", "persist-credentials", "GH_TOKEN", "ENVS_SOURCE_SHA"}
TOOLCHAIN_BIN = '"$RUNNER_TEMP/envs-effect/bin/'
# The one step that obtains the provided artifact; check's clean-start job holds the canonical text.
CONSUMER_STEP = "- name: Obtain provided effect artifact\n"
CONSUMER_RUN = "        run: |\n"
EFFECT_ENTRY = '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE"'
# After the consumer step, effect jobs run only store paths from the provided artifact.
AMBIENT_TOOL = re.compile(r"(?m)(?:^|[\s>|;&(])(?:python3?|git|gh|sops|wrangler|node|npx|npm|pip3?|curl|wget)\s")
RUNTIME_ACQUISITION = ("npx", "npm ", "pip ", "--yes", "nix ", "install-nix", "github:", "--impure")
TOOLCHAIN_IDENTITY = f"{EFFECT_ENTRY} toolchain"
EFFECT_ACTIONS = {"actions/checkout"}
RUN_START = re.compile(r"^(\s*)run:\s*(.*)$")
# Every other effect-step command is a provided store path or a fixed assignment.
ALLOWED_COMMAND = re.compile(
    r'^(?:set -euo pipefail'
    r'|tool="\$ENVS_EFFECT_BIN"'
    r'|branch="[a-z/-]+(?:\$\{GITHUB_RUN_(?:ID|ATTEMPT)\}-?)+"'
    r'|"\$(?:ENVS_EFFECT_BIN|tool)/[a-z0-9-]+"(?: .*)?)$'
)
COMMAND_CONTROL = re.compile(r"[;&|<>`\n]|\$\(")
FLAKE_NIXPKGS = re.compile(r'(?m)^\s*inputs\.nixpkgs\.url = "github:NixOS/nixpkgs/([0-9a-f]{40})";$')


class RepositoryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepositoryError(message)


def files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )


def relative_files(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in files(root)}


def load_adapter(root: Path):
    path = root / "adapters/jev_api.py"
    spec = importlib.util.spec_from_file_location("envs_jev_api", path)
    require(spec is not None and spec.loader is not None, "cannot load Jev adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_shape(root: Path) -> None:
    actual = relative_files(root)
    missing = sorted(REQUIRED_FILES - actual)
    require(not missing, f"required files missing: {missing}")

    for path in root.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            require(path.name in ALLOWED_ROOTS, f"top-level directory is not allowed: {path.name}")
        else:
            require(path.name in ALLOWED_ROOT_FILES, f"top-level file is not allowed: {path.name}")

    for name in FORBIDDEN_ROOTS:
        require(not (root / name).exists(), f"temporary or foreign root survives: {name}")

    for path in files(root):
        relative = path.relative_to(root)
        require(path.name not in FORBIDDEN_FILENAMES, f"forbidden file: {relative}")
        require(path.suffix.lower() not in FORBIDDEN_SUFFIXES or relative.as_posix() == RENT_RECEIVER,
                f"forbidden implementation type: {relative}")
        require("duck" + "db" not in relative.as_posix().lower(), f"database binding path survives: {relative}")

    ciphertext_dir = root / "ciphertexts"
    if ciphertext_dir.exists():
        ciphertexts = sorted(path.relative_to(root).as_posix() for path in ciphertext_dir.rglob("*") if path.is_file())
        require(bool(ciphertexts) and set(ciphertexts) <= CIPHERTEXTS, f"unexpected ciphertexts: {ciphertexts}")

    providers = sorted(path.relative_to(root).as_posix() for path in (root / "providers").rglob("*") if path.is_file())
    require(providers == [RENT_CONFIG],
            f"unexpected provider files (state or lock files are never committed): {providers}")
    for retired in RETIRED_PATHS:
        require(not (root / retired).exists(), f"retired probe/state-proof path survives: {retired}")
    check_rent_config((root / RENT_CONFIG).read_text(encoding="utf-8"))

    handoff_dir = root / "handoffs"
    if handoff_dir.exists():
        handoffs = sorted(path.relative_to(root).as_posix() for path in handoff_dir.rglob("*") if path.is_file())
        require(bool(handoffs) and set(handoffs) <= {"handoffs/dev-jev-api.json", "handoffs/dev-jev-api.github-actions.json"},
                f"unexpected handoffs: {handoffs}")


def check_rent_config(source: str) -> None:
    # Only what native validate accepts and must not: a plaintext local backend, unenforced encryption, a credentials
    # output printed in clear, and a service-token lifetime fixed in source rather than bound at deployment. Comments
    # never count: /* */ blocks and #, // line comments are dropped first (this root has no # or // inside a string).
    text = re.sub(r"(?m)[ \t]*(#|//).*$", "", re.sub(r"(?s)/\*.*?\*/", "", source))
    # S2: the standard HTTP backend, wholly partial; its loopback address and lock endpoints arrive only at init.
    require(text.count('backend "') == 1 and '  backend "http" {}\n' in text,
            "persistent root must use the partial standard HTTP backend")
    require("  encryption {\n    state {\n      enforced = true\n    }\n    plan {\n      enforced = true\n    }\n  }\n" in text,
            "persistent root must enforce state and plan encryption")
    require(re.search(r'(?ms)^output "credentials" \{\n  sensitive = true\n', text) is not None,
            "persistent root credentials must be a sensitive output")
    # Every remaining duration assignment line (horizontal whitespace only).
    durations = [value.strip() for value in re.findall(r"(?m)^[ \t]*duration[ \t]*=[ \t]*(.*)$", text)]
    require('variable "service_token_duration" {\n  type = string\n}\n' in text
            and durations == ["var.service_token_duration"],
            "the service-token duration must be a required input with no default")


def check_text(root: Path) -> None:
    database_name = "duck" + "db"
    for path in files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        for label, pattern in SECRET_PATTERNS.items():
            require(not pattern.search(data), f"{relative}: {label}")
        if relative not in {"checks/repository.py", "checks/test_repository.py"}:
            require(database_name not in data.decode("utf-8", errors="ignore").lower(), f"{relative}: removed database binding survives")

    active_roots = [root / name for name in (".github", "adapters", "checks")]
    for base in active_roots:
        for path in files(base) if base.exists() else []:
            relative = path.relative_to(root).as_posix()
            if relative == "checks/repository.py":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            historical = "roccho-dev/" + "envs-old"
            require(historical not in text, f"{relative}: historical runtime dependency")


def check_jsonl(root: Path) -> None:
    for path in sorted((root / "contracts").glob("*.jsonl")):
        ids: set[str] = set()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RepositoryError(f"{path.relative_to(root)}:{number}: invalid JSON") from exc
            require(isinstance(row, dict), f"{path.relative_to(root)}:{number}: row is not an object")
            identity = row.get("id")
            require(isinstance(identity, str) and identity, f"{path.relative_to(root)}:{number}: missing id")
            require(identity not in ids, f"{path.relative_to(root)}:{number}: duplicate id {identity}")
            ids.add(identity)


def declared_inputs(row: dict[str, Any]) -> set[tuple[str, str]]:
    return {("secrets", item["name"]) for item in row.get("required_secrets", [])} | {
        ("vars", item["name"]) for item in row.get("required_variables", [])
    }


def author_target_inputs(adapter, contracts: dict[str, dict[str, dict[str, Any]]]) -> dict[str, set[tuple[str, str]]]:
    # Each author target's Environment inputs as the adapter reads them, in (namespace, name) form.
    result = {}
    for target in adapter.AUTHOR_TARGETS:
        plane_id = (adapter.TYPELLM_PLANE if target in adapter.TYPELLM_CIPHERTEXTS
                    else adapter.GO_PLANE if target in adapter.GO_CIPHERTEXTS else "dev.authoring")
        secrets = {item["name"] for item in contracts["environments"][plane_id]["required_secrets"]}
        result[target] = {("secrets" if item["name"] in secrets else "vars", item["name"])
                          for item in adapter.authoring_inputs(contracts, target)}
    return result


def run_commands(text: str) -> list[str]:
    lines = text.splitlines()
    commands: list[str] = []
    index = 0
    while index < len(lines):
        match = RUN_START.match(lines[index])
        index += 1
        if match is None:
            continue
        indent, inline = len(match.group(1)), match.group(2).strip()
        if inline not in {"|", ">-"}:
            quoted = len(inline) > 1 and inline[0] == inline[-1] == "'"
            commands.append(inline[1:-1] if quoted else inline)
            continue
        block: list[str] = []
        while index < len(lines) and (not lines[index].strip() or len(lines[index]) - len(lines[index].lstrip()) > indent):
            if lines[index].strip():
                block.append(lines[index].strip())
            index += 1
        if inline == ">-":
            commands.append(" ".join(block))
            continue
        current = ""
        for line in block:
            current = f"{current} {line}" if current else line
            if current.endswith("\\"):
                current = current[:-1].rstrip()
                continue
            commands.append(current)
            current = ""
        if current:
            commands.append(current)
    return commands


def consumer_run(text: str, name: str) -> str:
    start = text.find(CONSUMER_STEP)
    require(start != -1, f"{name}: provided artifact is not obtained")
    body = text.find(CONSUMER_RUN, start)
    require(body != -1 and "- name:" not in text[start + len(CONSUMER_STEP):body], f"{name}: consumer step differs")
    end = text.find("\n\n", body)
    return text[body:] if end == -1 else text[body:end + 1]


def check_author_targets(text: str, targets: dict[str, set[tuple[str, str]]]) -> None:
    options = "".join(f"          - {target}\n" for target in targets)
    require("    inputs:\n      target:\n" in text
            and "        required: true\n        type: choice\n        options:\n" + options in text,
            "author target choice differs from the authorable bindings")
    steps = AUTHOR_STEP.findall(text)
    require([target for target, _ in steps] == list(targets), "author must have exactly one step per binding")
    for target, body in steps:
        require(f"        run: '{EFFECT_ENTRY} author --target {target}'\n" in body and body.count(" author ") == 1,
                f"author step for {target} must run exactly its literal target")
        require(set(INPUT_REFERENCE.findall(body)) == targets[target], f"author step for {target} maps other inputs")
    require(text.count(" author --target ") == len(targets) and text.count("inputs.target") == len(targets),
            "author target is selected or called outside its step")


def check_manual_mail(root: Path, source: str, canonical: str) -> None:
    """Only the Owner's exact-source manual operation consumes Mail inputs."""
    require(source.startswith("name: operate-dev-mail-routing\n")
            and "\non:\n" in source
            and source.count("\non:") == 1,
            "Mail manual entry must be workflow_dispatch only")
    require("      expected_source_sha:\n" in source and "        required: true\n" in source,
            "Mail candidate must name a required source SHA")
    # Admit this exact S1 manual event+input shape only. Remove harmless
    # whole-line comments/blank lines so prose does not become a false alarm.
    # Unlike a blacklist, this rejects schedule, repository_dispatch, etc.
    significant = [line.rstrip() for line in source.splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    require(significant.count("on:") == 1 and significant.count("permissions:") == 1
            and significant.index("on:") < significant.index("permissions:"),
            "Mail candidate requires single on and permissions blocks")
    trigger = significant[significant.index("on:") + 1:significant.index("permissions:")]
    require(trigger == [
        "  workflow_dispatch:",
        "    inputs:",
        "      expected_source_sha:",
        "        description: Exact canonical source SHA (never a private account, mailbox, plan or key)",
        "        type: string",
        "        required: true",
        "      operation:",
        "        description: Qualify, preview, or apply the approved declaration",
        "        type: choice",
        "        options: [qualify, preview, apply]",
        "        default: qualify",
        "        required: true",
    ], "Mail candidate must admit only the one manual event and its source input")
    job = source[source.find("\njobs:\n"):]
    require(re.findall(r"(?m)^  ([a-z0-9-]+):\s*$", job) == ["operate"],
            "Mail candidate must have one and only one job")
    gate = "    if: ${{ github.repository == 'roccho-org/envs' && github.ref_name == 'proposals' && github.sha == inputs.expected_source_sha && github.run_attempt == 1 && github.actor == 'roccho-dev' && github.actor_id == '40359643' && github.triggering_actor == 'roccho-dev' && contains(fromJSON('[\"qualify\",\"preview\",\"apply\"]'), inputs.operation) }}"
    require(source.count(gate) == 1 and source.count("\n    if:") == 1,
            "Mail job must be source/controller-bound without re-runs")
    environment = "    environment: dev-projection\n"
    require(-1 < source.find(gate) < source.find(environment)
            < source.find("    steps:\n"),
            "Mail job must fail before Environment resolution or child execution")
    # The completed one-time recovery is retired: no recover operation, recipient input or rent Environment selector.
    require(source.count("    environment:") == 1 and source.count(environment) == 1
            and "recover" not in source and "recipient" not in source and "dev-rent-" not in source,
            "Mail selects only the static dev-projection Environment and has no recovery path")
    require(source.count("    runs-on: ubuntu-24.04\n") == 1
            and "    timeout-minutes: 10\n" in source,
            "Mail candidate job must be finite and fixed")
    # GitHub job-level permissions override workflow-level defaults. Require
    # the whole noncommented permission map and reject any job override.
    headers = [line for line in significant if re.match(r"^\s*permissions\s*:", line)]
    require(headers == ["permissions:"],
            "Mail candidate must have no job-level permission override")
    require("concurrency:" in significant
            and significant.index("permissions:") < significant.index("concurrency:")
            and significant[significant.index("permissions:"):significant.index("concurrency:")] == [
                "permissions:", "  actions: read", "  contents: read",
            ], "Mail candidate may only grant effective actions/contents read")
    require("  cancel-in-progress: false\n" in source,
            "Mail candidate must not auto-cancel and replay")
    private_step = source[source.find("      - name: Initialize backend and run one selected Mail operation\n"):]
    qualification_step = source[source.find("      - name: Qualify projection with GET only\n"):source.find("      # The state-input Secret")]
    qualification_inputs = {("secrets", name) for name in ("MAIL_CONFIG", "CLOUDFLARE_API_TOKEN")}
    projection_inputs = qualification_inputs | {("secrets", "MAIL_STATE_INPUTS")}
    require(set(INPUT_REFERENCE.findall(source)) == projection_inputs
            and len(INPUT_REFERENCE.findall(source)) == len(qualification_inputs) + len(projection_inputs)
            and set(INPUT_REFERENCE.findall(qualification_step)) == qualification_inputs
            and set(INPUT_REFERENCE.findall(private_step)) == projection_inputs
            and "R2_PARENT_" not in source and "RENT_" not in source and "AWS_" not in source
            and "TF_ENCRYPTION" not in source,
            "Mail inputs must remain isolated to the selected operation's slots")
    require(consumer_run(source, "operate-dev-mail-routing.yml") == canonical,
            "Mail candidate must use the existing exact-SHA artifact consumer")
    require({action for action, _ in ACTION_USE.findall(source)} == EFFECT_ACTIONS
            and "actions/upload-artifact" not in source,
            "Mail uses only the pinned checkout and uploads nothing")
    require(qualification_step.count("if: inputs.operation == 'qualify'") == 1
            and private_step.count("if: inputs.operation == 'preview' || inputs.operation == 'apply'") == 1,
            "Qualification and projection must remain isolated")
    require("          ref: ${{ github.sha }}\n" in source
            and "          persist-credentials: false\n" in source,
            "Mail candidate checkout must be source-bound without retained auth")
    require("          repository: roccho-org/ops\n"
            "          ref: afd831dba8f401fb37fc20c27ab8d1f176102050\n"
            "          path: mail-ops-source\n"
            "          persist-credentials: false\n" in source,
            "Mail must consume the fixed Ops declaration without retained auth")
    require("      - name: Checkout fixed Ops declaration\n"
            "        if: inputs.operation == 'preview' || inputs.operation == 'apply'\n" in source,
            "Qualification must not acquire or initialize the Ops root")
    require(run_commands(source.replace(canonical, "")) == [
        TOOLCHAIN_IDENTITY, "set -euo pipefail", "umask 077",
        'home="$(mktemp -d "$RUNNER_TEMP/mail-m0.XXXXXX")"',
        'if [ "$MAIL_OPERATION" = preview ] || [ "$MAIL_OPERATION" = apply ]; then',
        'mkdir -m 700 "$home/root"',
        'for file in main.tf .terraform.lock.hcl README.md safety.tftest.hcl; do',
        'install -m 600 "$GITHUB_WORKSPACE/mail-ops-source/providers/mail-routing/$file" "$home/root/$file"',
        'done', 'fi', 'echo "MAIL_HOME=$home" >>"$GITHUB_ENV"',
        '"$ENVS_EFFECT_BIN/mail-routing-root" --operation qualify',
        "set +e", '"$ENVS_EFFECT_BIN/mail-routing-root" --operation "$MAIL_OPERATION"',
        'result=$?', 'if [ "$MAIL_OPERATION" = preview ] && [ "$result" -eq 2 ]; then',
        'exit 0', 'fi', 'exit "$result"',
    ], "Mail can run only artifact identity, private root preparation and one operation")
    require(source.count("      - name: ") == 7,
            "Mail manual consumer must retain the bounded step set")
    adapter_source = (root / "adapters/mail_routing_root.py").read_text(encoding="utf-8")
    require("EXIT_INACTIVE = 78\n" in adapter_source
            and "    return EXIT_INACTIVE\n" in adapter_source
            and "CLOSED_RESULT =" in adapter_source,
            "Mail root adapter must independently refuse")
    require(adapter_source.count("import os\n") == 1
            and adapter_source.count("import subprocess\n") == 1
            and adapter_source.count("os.environ") == 1,
            "Mail native private runner must use only its selected input snapshot")
    require('def main() -> int:\n' in adapter_source
            and 'sys.argv[2] not in MAIL_OPERATIONS' in adapter_source
            and '        print(CLOSED_RESULT)\n        return EXIT_INACTIVE\n' in adapter_source,
            "Mail public entry must refuse unsupported/no-argument operation before inputs")
    require('\nMAIL_OPERATIONS = ("qualify", "preview", "apply")\n' in adapter_source
            and "recover_state" not in adapter_source and "MAIL_STATE_AGE_RECIPIENT" not in adapter_source,
            "the completed Mail recovery operation is retired")

def check_workflows(root: Path, environments: dict[str, dict[str, Any]],
                    author_targets: dict[str, set[tuple[str, str]]], adapter) -> None:
    workflow_root = root / ".github/workflows"
    names = {path.name for path in workflow_root.iterdir() if path.is_file()}
    require(
        names == {"check.yml", "jev-issue-comment.yml", "deploy-calendar-pages.yml", "deploy-pi-worker-preview.yml", "operate-dev-mail-routing.yml",
                  RELOCATION_WORKFLOW, *EFFECT_WORKFLOWS},
        f"workflow set differs: {sorted(names)}",
    )
    texts = {path.name: path.read_text(encoding="utf-8") for path in workflow_root.iterdir() if path.is_file()}
    caller = texts["jev-issue-comment.yml"]
    require(caller == ("name: Jev Issue comment evaluation\n\non:\n  issue_comment:\n    types: [created]\n\n"
                       "permissions:\n  actions: read\n  contents: read\n  issues: write\n\njobs:\n  evaluate:\n"
                       "    if: >-\n      github.event.repository.owner.type == 'Organization' &&\n"
                       "      github.repository == 'roccho-org/envs' &&\n      github.event.issue.number == 52 &&\n"
                       "      github.event.comment.body == '/jev-evaluate' &&\n      github.event.issue.pull_request == null\n"
                       "    uses: roccho-org/ops/.github/workflows/jev-issue-comment.yml@9fc663006f1bd0a16dfaff061471a39451878195\n"
                       "    secrets:\n      JEV_API_KEY: ${{ secrets.JEV_API_KEY }}\n"),
            "Issue caller must be the fixed Ops workflow and exact originating-Issue guard/slot only")

    for name, text in texts.items():
        require("pull_request_target:" not in text, f"{name}: pull_request_target is forbidden")
        require("secrets: inherit" not in text, f"{name}: secrets inheritance is forbidden")
        # Every selected Environment is one literal functional dev name: no expression, no host-specific name.
        selected = [value.strip() for value in re.findall(r"(?m)^\s*environment:(.*)$", text)]
        require("${{" not in "".join(selected), f"{name}: dynamic Environment is forbidden")
        if name == RELOCATION_WORKFLOW:
            # The one temporary exception: exactly the old Environment, once, in the strictly checked entrance below.
            require(selected == [RELOCATION_ENVIRONMENT], f"{name}: the relocation selects only {RELOCATION_ENVIRONMENT}")
        else:
            for retired in RETIRED_ENVIRONMENTS:
                require(retired not in selected, f"{name}: retired host-specific Environment {retired} is selected")
            require(set(selected) <= {"dev-authoring", "dev-projection"},
                    f"{name}: Environment outside dev-authoring/dev-projection")
        require("R2_PARENT_" not in text, f"{name}: the retired R2 parent token is referenced")
        for action, ref in ACTION_USE.findall(text):
            if not action.startswith(("./", "docker://")):
                require(re.fullmatch(r"[0-9a-f]{40}", ref) is not None, f"{name}: mutable Action {action}@{ref}")

    check = texts["check.yml"]
    check_relocation(root, texts[RELOCATION_WORKFLOW], check)
    require("pull_request:" in check and "proposals" in check, "check workflow must validate proposals PRs")
    require("${{ secrets." not in check, "check workflow must be secret-free")
    require("checks/repository.py" in check, "check workflow must execute repository oracle")
    require("checks/test_repository.py" in check, "check workflow must test repository oracle")
    require("checks/test_jev_api.py" in check, "check workflow must test Jev adapter")
    require("run: python3 checks/test_rent_tunnel.py\n" in check, "check workflow must test the rent tunnel adapter")
    require("test_rent_access_probe" not in check and "test_rent_state_proof" not in check
            and "dev-rent-access-probe" not in check and "dev-rent-state-proof" not in check,
            "check workflow must not run the retired probe/state-proof roots or tests")
    require("run: python3 checks/test_linode_read_probe.py\n" in check, "check workflow must test the Linode read probe")
    require("run: python3 checks/test_mail_routing_read.py\n" in check, "check must run Mail GET-only/redaction selftest")
    require("run: python3 checks/test_mail_routing_root.py\n" in check,
            "check must test direct Mail hard-inactive source entry")
    require(TOOLCHAIN_BUILD in check, "check workflow must reconstruct the effect toolchain")
    require(f'{TOOLCHAIN_BIN}envs-effect" toolchain' in check, "check workflow must execute the effect entry")
    require(f'{TOOLCHAIN_BIN}python3" -I checks/test_jev_api.py' in check,
            "check workflow must test the adapter on the toolchain interpreter")
    require(f'{TOOLCHAIN_BIN}python3" -I checks/test_mail_routing_read.py' in check,
            "check must test Mail adapter on the pinned toolchain interpreter")
    require(f'{TOOLCHAIN_BIN}python3" -I checks/test_mail_routing_root.py' in check,
            "check must test Mail refusal on provided Python")
    require(f'{TOOLCHAIN_BIN}mail-routing-root' in check and 'test "$code" -eq 78' in check,
            "check must execute and reject the actual provided Mail root wrapper")
    require('nix flake lock "$relock"' in check and 'cmp flake.lock "$relock/flake.lock"' in check,
            "check workflow must prove Nix regenerates the committed lock")
    for tool in ("python3", "sops", "git", "gh", "wrangler"):
        require(f'"$tool/{tool}" --version' in check, f"check workflow must execute closure {tool}")
    require('"$tool/wrangler" pages secret "$command" --help' in check,
            "check workflow must execute the Wrangler argv shape")
    require(ARTIFACT_BUILD in check and ARTIFACT_NAME in check and "actions/upload-artifact@" in check,
            "check workflow must provide the effect artifact")
    require("cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in check,
            "check must not cancel the proposals run that provides an artifact")

    def job(name: str, following: str | None) -> str:
        start = check.find(f"\n  {name}:\n")
        require(start != -1, f"check workflow job missing: {name}")
        end = check.find(f"\n  {following}:\n", start) if following else -1
        return check[start:] if end == -1 else check[start:end]

    toolchain = job("toolchain", "effect-shape")
    for marker in (
        f"      ENVS_SOURCE_SHA: {SOURCE_SHA}\n",
        f"          ref: {SOURCE_SHA}\n",
        'test "$(git rev-parse HEAD)" = "$ENVS_SOURCE_SHA"',
        'test "$(tar -xOf "$RUNNER_TEMP/provide/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"',
    ):
        require(marker in toolchain, f"artifact must be built from and bound to the named commit: {marker.strip()}")
    for marker in (
        CHECK_AGE_BUILD,
        REAL_ROUNDTRIP,
        OCI_ROUNDTRIP,
        'grep -qxF "$sops" "$RUNNER_TEMP/provided.list"',
        'grep -qxF "$curl" "$RUNNER_TEMP/provided.list"',
        'if grep -qxF "$age" "$RUNNER_TEMP/provided.list"; then',
    ):
        require(marker in toolchain, f"check must run the real SOPS roundtrip with check-only age: {marker}")
    for marker in PROBE_TOOL_CHECKS:
        require(marker in toolchain, f"check must prove the closure client and rent root from the closure: {marker}")
    require(toolchain.find(REAL_ROUNDTRIP) < toolchain.find('if grep -qxF "$age"') and toolchain.find(ARTIFACT_BUILD)
            < toolchain.find('if grep -qxF "$age"'), "check-only age must be proven outside the built artifact")
    require(toolchain.find(CHECK_AGE_BUILD) < toolchain.find(OCI_ROUNDTRIP) < toolchain.find('if grep -qxF "$age"'),
            "the OCI dev roundtrip must use the check-only age built before it")
    effect_shape = job("effect-shape", "clean-start")
    clean_start = job("clean-start", None)
    require("    needs: toolchain\n" in clean_start, "check workflow must clean-start from the provided artifact")
    for token in ("actions/checkout", "nix ", "install-nix"):
        require(token not in clean_start, f"clean-start must not use {token.strip()}")
    canonical = consumer_run(clean_start, "check.yml clean-start")
    check_manual_mail(root, texts["operate-dev-mail-routing.yml"], canonical)
    mail_cipher = root / "ciphertexts/dev-mail-state.sops.json"
    if mail_cipher.exists():
        require(not mail_cipher.is_symlink(), "Mail state carrier must be a regular source file")
        spec = importlib.util.spec_from_file_location("mail_cipher_contract", root / "adapters/mail_routing_root.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            module.state_ciphertext(mail_cipher.read_bytes())
        except module.NativeSourceHold:
            raise RepositoryError("Mail state carrier structure is invalid") from None
        finally:
            sys.modules.pop(spec.name, None)
    require(clean_start.count(canonical) == 2, "clean-start must run the canonical consumer and its missing case")
    for marker in CONSUMER_BINDING:
        require(marker in canonical, f"consumer must bind the named commit: {marker}")
    program = next(line.strip() for line in canonical.splitlines() if line.strip().startswith("'.path =="))
    source_check = CONSUMER_BINDING[-1]
    require(clean_start.count(program) == 3 and clean_start.count(source_check) == 3,
            "clean-start must run the canonical producer and SOURCE checks against mismatches")
    # The altered-archive fixture MUST demonstrably change bytes, not just
    # repeat a literal that may already occupy the previous fixed offset.
    # The two cases are exercised by the existing clean-start native shell.
    for marker in (
        "for original_byte in x y; do",
        """printf '%4096s%s' '' "$original_byte" >"$original" """.strip(),
        """printf 'x' >>"$changed" """.strip(),
        'if cmp -s "$original" "$changed"; then',
        'echo "${ENVS_EFFECT_DIGEST#sha256:}  $ENVS_EFFECT_ZIP" | sha256sum -c -',
        """printf 'x' >>"$altered" """.strip(),
        'if cmp -s "$ENVS_EFFECT_ZIP" "$altered"; then',
    ):
        require(marker in clean_start, f"clean-start altered-artifact guarantee missing: {marker}")
    require("""printf 'x' | dd of="$altered" bs=1 seek=4096""" not in clean_start,
            "clean-start must not reuse the collision-prone fixed-offset overwrite")
    for marker in (
        'test "$MISSING" = failure',
        'if echo "${ENVS_EFFECT_DIGEST#sha256:}  $altered" | sha256sum -c -; then',
        "for case in lock adapter; do",
        '"$ENVS_EFFECT_BIN/envs-effect" --root "$copy" toolchain',
        "for change in . \\\n",
        "'.head_sha = \"0000000000000000000000000000000000000000\"'",
        "'.id = 1 | .event = \"pull_request\"'",
        "'.repository.full_name = \"fork/envs\"'",
        "'.head_repository.full_name = \"fork/envs\"'",
        'test "$accepted" = "$expected"',
        "artifact built from another commit was accepted",
    ):
        require(marker in clean_start, f"clean-start destructive case missing: {marker}")

    require(consumer_run(effect_shape, "check.yml effect-shape") == canonical, "effect-shape must run the canonical consumer")
    check_calendar_pages_workflow(texts["deploy-calendar-pages.yml"], canonical)
    check_pi_worker_preview(texts["deploy-pi-worker-preview.yml"], canonical)
    for token in ("nix ", "install-nix"):
        require(token not in effect_shape, f"effect-shape must not use {token.strip()}")
    for marker in (
        f"          ref: {SOURCE_SHA}\n",
        'test "$("$ENVS_EFFECT_BIN/git" -C "$GITHUB_WORKSPACE" rev-parse HEAD)" = "$ENVS_SOURCE_SHA"',
        f"{TOOLCHAIN_IDENTITY} | tee",
        ".status == \"PASS\" and .source == $sha and .root == $root",
        f"{EFFECT_ENTRY} check",
    ):
        require(marker in effect_shape, f"effect-shape must run the effect data-root shape: {marker.strip()}")

    for name, plane in EFFECT_WORKFLOWS.items():
        text = texts[name]
        row = environments[plane]
        for token in RUNTIME_ACQUISITION:
            require(token not in text, f"{name}: runtime acquisition or rebuild {token.strip()}")
        require(consumer_run(text, name) == canonical, f"{name}: consumer differs from the clean-start consumer")
        require("          ENVS_SOURCE_SHA: ${{ github.sha }}\n" in text, f"{name}: artifact must resolve by the dispatched SHA")
        rest = text.replace(canonical, "")
        require(AMBIENT_TOOL.search(rest) is None, f"{name}: ambient tool on the effect path")
        require(re.search(r"(?m)^ {0,4}env:", text) is None, f"{name}: workflow or job env is forbidden")
        # The author Environment also carries each binding's declared inputs; its steps prove which one reads which.
        declared = set().union(*author_targets.values()) if name == "author-dev-jev-api.yml" else declared_inputs(row)
        if name == "probe-dev-mail-routing.yml":
            # P v2 explicitly permits this ONE existing non-secret account
            # locator at the native vars-to-runtime boundary. It is not a
            # credential or a claim of Cloudflare API Write permission.
            declared = {("secrets", "CLOUDFLARE_API_TOKEN"), ("vars", "CLOUDFLARE_ACCOUNT_ID")}
            require(declared <= declared_inputs(row), "Mail must reuse the existing dev-projection slots")
        keys = set(EFFECT_ENV.findall(rest))
        allowed = EFFECT_STEP_KEYS | {input_name for _, input_name in declared}
        require(keys <= allowed, f"{name}: step env or input not allowed: {sorted(keys - allowed)}")
        require("GITHUB_ENV" not in rest and "GITHUB_PATH" not in rest, f"{name}: only the consumer may set step environment")
        consume = text.find(CONSUMER_STEP)
        identity = text.find(TOOLCHAIN_IDENTITY)
        require(-1 < consume < identity < text.find("${{ secrets."),
                f"{name}: artifact must be obtained and its identity recorded before secrets")
        require("shell:" not in text, f"{name}: custom step shell is forbidden")
        require({action for action, _ in ACTION_USE.findall(text)} == EFFECT_ACTIONS, f"{name}: effect Action set differs")
        for command in run_commands(rest):
            require(COMMAND_CONTROL.search(command) is None, f"{name}: command chaining or substitution: {command}")
            require(ALLOWED_COMMAND.fullmatch(command) is not None, f"{name}: non-closure executable: {command}")
        require("workflow_dispatch:" in text, f"{name}: manual dispatch missing")
        require("\n  push:" not in text and "\n  pull_request:" not in text, f"{name}: automatic effect trigger")
        require(f"environment: {row['github_environment']}" in text, f"{name}: static Environment differs")
        expected_repo = "roccho-org/envs" if name in {"author-dev-jev-api.yml", "probe-dev-mail-routing.yml", "project-dev-rent-tunnel.yml"} else "roccho-dev/envs"
        require(f"github.repository == '{expected_repo}'" in text, f"{name}: repository guard missing")
        require("github.ref_name == 'proposals'" in text, f"{name}: canonical ref guard missing")
        require("ref: ${{ github.sha }}" in text, f"{name}: exact checkout missing")
        if name == "probe-dev-mail-routing.yml":
            # 'domain' contains the spelling 'main'; verify the actual branch.
            require("refs/heads/main" not in text and "github.ref_name == 'main'" not in text,
                    "Mail read must not run on main")
        else:
            require("main" not in text, f"{name}: main must not be an effect source")
        require(set(INPUT_REFERENCE.findall(text)) == declared, f"{name}: Environment inputs differ from contract")
        for namespace, input_name in sorted(declared):
            mapping = "^\\s+" + re.escape(f"{input_name}: ${{{{ {namespace}.{input_name} }}}}") + "$"
            require(re.search(mapping, text, re.MULTILINE) is not None, f"{name}: {input_name} mapping differs")

    require(f"{EFFECT_ENTRY} author" in texts["author-dev-jev-api.yml"], "author workflow entry call missing")
    check_author_targets(texts["author-dev-jev-api.yml"], author_targets)
    require(f"{EFFECT_ENTRY} project" in texts["project-dev-jev-api.yml"], "project workflow entry call missing")
    rent = texts["project-dev-rent-tunnel.yml"]
    # The apply/handoff job keeps its whole-job literal false, before Environment resolution, consumer/artifact,
    # apply, ciphertext or PR handoff. The only active selector is a second, repository-read-only job: the native
    # caller gate (repository, ref, event, accepted SHA, first attempt, controller) precedes its Environment, and it
    # admits the inspect entry alone.
    rent_guard = ("    if: ${{ false && github.repository == 'roccho-org/envs' "
                  "&& github.ref_name == 'proposals' }}")
    require(rent.count("\njobs:\n") == 1, "rent workflow must declare one jobs block")
    jobs = rent[rent.index("\njobs:\n"):]
    require(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):$", jobs) == ["project", "inspect"],
            "rent workflow must hold the hard-inactive project job, then the inspect job")
    project = jobs[jobs.index("\n  project:\n"):jobs.index("\n  inspect:\n")]
    inspect_job = jobs[jobs.index("\n  inspect:\n"):]
    require(rent.count(rent_guard) == 1 and project.count(rent_guard) == 1 and
            project.find(rent_guard) < project.find("    runs-on:") < project.find("    environment:"),
            "selected rent workflow must remain source-hard-inactive before Environment")
    inspect_entry = f"run: '{EFFECT_ENTRY} rent-root-inspect'"
    apply_entry = f"run: '{EFFECT_ENTRY} rent-root'"
    require(rent.count(f"{EFFECT_ENTRY} rent-") == 2 and project.count(apply_entry) == 1
            and inspect_entry not in project
            and project.find("Record effect toolchain identity") < project.find(apply_entry)
            < project.find("Open ciphertext handoff PR"),
            "rent apply and handoff must stay only in the hard-inactive project job")
    require("on:\n  workflow_dispatch:\n    inputs:\n      expected_source_sha:\n" in rent
            and "        type: string\n        required: true\n\npermissions:\n" in rent
            and set(re.findall(r"(?<![).\w])inputs\.([A-Za-z0-9_]+)", rent)) == {"expected_source_sha"}
            and rent.count("inputs.expected_source_sha") == 1,
            "rent dispatch must take only the accepted canonical SHA, used by the inspect gate alone")
    require(inspect_job.count(RENT_INSPECT_GATE) == 1
            and inspect_job.find(RENT_INSPECT_GATE) < inspect_job.find("    runs-on:")
            < inspect_job.find("    environment: dev-projection\n")
            < inspect_job.find("    permissions:\n      actions: read\n      contents: read\n    steps:\n"),
            "rent inspect job must hold the native caller gate, then repository read-only permissions")
    require(re.findall(r"(?m)^      - name: (.+)$", inspect_job) == RENT_INSPECT_STEPS
            and inspect_job.count(inspect_entry) == 1 and apply_entry not in inspect_job,
            "rent inspect job runs only checkout, the provided artifact, toolchain identity and inspect")
    # Privacy on the public log: the runner already shows the step env (the four Secrets masked, the nine
    # non-secret variables in plain text); the job adds no copy, output, artifact, cache or write of its own, and
    # maps the Environment inputs on the inspect step alone.
    private_rest = inspect_job.replace(canonical, "")
    require(not any(token in private_rest for token in RENT_INSPECT_FORBIDDEN)
            and private_rest.find("${{ secrets.") > private_rest.find(f"- name: {RENT_INSPECT_STEPS[-1]}\n")
            and private_rest.find("${{ vars.") > private_rest.find(f"- name: {RENT_INSPECT_STEPS[-1]}\n"),
            "rent inspect job may print only the closed receipt and maps inputs only on the inspect step")
    require('"$tool/git" add ciphertexts/dev-rent-tunnel.sops.yaml ciphertexts/dev-rent-client.sops.yaml '
            'contracts/environments.jsonl\n' in rent and rent.count('"$tool/git" add ') == 1,
            "rent handoff must stage only both ciphertexts and plane state")
    # Rent shares dev-projection with Pages/Mail but never their Cloudflare slots: it maps only its RENT_CLOUDFLARE_*
    # storage slots, and the adapter passes them to its children under the provider-native names.
    require(re.search(r"\b(?:secrets|vars)\.CLOUDFLARE_", rent) is None
            and all(f"{name}: ${{{{ {namespace}.{name} }}}}" in rent
                    for namespace, name in (("secrets", "RENT_CLOUDFLARE_API_TOKEN"), ("vars", "RENT_CLOUDFLARE_ACCOUNT_ID"),
                                            ("vars", "RENT_CLOUDFLARE_ZONE_ID"))),
            "rent must map only its distinct RENT_CLOUDFLARE_* slots, never the Pages/Mail Cloudflare slots")
    linode = texts["probe-dev-linode-read.yml"]
    require(f"run: '{EFFECT_ENTRY} linode-read-probe'" in linode and linode.count(" linode-read-probe'") == 1,
            "Linode read workflow entry call missing")
    require("permissions:\n  actions: read\n  contents: read\n" in linode and "write" not in linode,
            "Linode read workflow must be read-only on the repository")
    mail = texts["probe-dev-mail-routing.yml"]
    require("permissions:\n  actions: read\n  contents: read\n" in mail and "write" not in mail,
            "Mail read workflow must have only repository read permissions")
    require("github.sha == inputs.expected_source_sha && github.run_attempt == 1" in mail,
            "Mail read is limited to approved exact source and first attempt")
    require("      domain:\n" in mail and "        required: true\n" in mail
            and "domain_sha256" not in mail,
            "Mail must use one exact non-secret native domain selector")
    require('        run: \'"$ENVS_EFFECT_BIN/mail-routing-read"\'\n' in mail,
            "Mail read must use the provided toolchain entry")
    require("SOPS_AGE_KEY" not in mail and "AWS_" not in mail and "CLOUDFLARE_ZONE_ID" not in mail,
            "Mail read must not borrow age/rent/state secrets or zone identifiers")
    require("GITHUB_EVENT_PATH" not in mail or "      domain:\n" in mail,
            "Mail selected domain must be read from the native event file")
    require("inputs.domain" not in mail,
            "Domain must never be interpolated into a shell/env/argv expression")
    require("CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}" in mail,
            "Mail must use the existing native non-secret account Variable, without a REST auth dependency")
    # The existing artifact-consumer step must retain its own GH_TOKEN.
    # Only the final Cloudflare read step must not request another GitHub
    # token/REST permission to fetch an existing Environment Variable.
    read_step = mail.split("      - name: Read selected Cloudflare zone under existing account\n", 1)
    require(len(read_step) == 2 and "GH_TOKEN: ${{ github.token }}" not in read_step[1],
            "Mail read step must not add a second GitHub token/REST dependency")
    require("github.actor == 'roccho-dev'" in mail and "github.actor_id == '40359643'" in mail
            and "github.triggering_actor == 'roccho-dev'" in mail,
            "Mail dispatch must admit only the fixed GitHub controller, without claiming chat role identity")


def check_relocation(root: Path, source: str, check: str) -> None:
    """TEMPORARY: the one-time encrypted rent Secret relocation entrance, strictly; retired with its exception."""
    for path in RELOCATION_PATHS:
        require((root / path).is_file(), f"relocation path missing: {path}")
    significant = [line.rstrip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    require(significant[significant.index("on:"):significant.index("jobs:")] == [
        "on:", "  workflow_dispatch:", "    inputs:", "      expected_source_sha:",
        "        description: Exact canonical source SHA authorized for this one run", "        type: string",
        "        required: true", "permissions:", "  contents: read", "concurrency:",
        "  group: relocate-dev-rent-secrets", "  cancel-in-progress: false",
    ], "relocation admits only one manual dispatch with its source SHA, contents:read and one serialized run")
    job = source[source.find("\njobs:\n"):]
    require(re.findall(r"(?m)^  ([a-z0-9-]+):\s*$", job) == ["relocate"], "relocation has exactly one job")
    require(source.count(RELOCATION_GATE) == 1 and source.count("\n    if:") == 1 and "\n        if:" not in source
            and source.find(RELOCATION_GATE) < source.find("    runs-on: ubuntu-24.04\n")
            < source.find(f"    environment: {RELOCATION_ENVIRONMENT}\n") < source.find("    steps:\n"),
            "relocation must gate exact repository, branch ref, event, source, attempt and controller before its Environment")
    require(re.search(r"(?m)^ {0,4}(env|permissions|defaults|container|services|outputs|strategy):", job) is None,
            "relocation job may not widen permissions or set job environment")
    require(re.findall(r"(?m)^      - name: (.+)$", source) == RELOCATION_STEPS, "relocation step set differs")
    require({(action, ref) for action, ref in ACTION_USE.findall(source)} == RELOCATION_ACTIONS,
            "relocation uses only the pinned checkout, Nix installer and upload actions")
    steps = {name: source[source.find(f"      - name: {name}\n"):] for name in RELOCATION_STEPS}
    for current, following in zip(RELOCATION_STEPS, RELOCATION_STEPS[1:] + [None]):
        if following:
            steps[current] = steps[current][:steps[current].find(f"      - name: {following}\n")]
    build, selftest, seal = (steps[RELOCATION_STEPS[2]], steps[RELOCATION_STEPS[3]], steps[RELOCATION_STEPS[4]])
    # Tools are built and the synthetic self-test passes before the only step that maps the four existing Secrets.
    require(RELOCATION_NIXPKGS in build and RELOCATION_PYTHON in build
            and 'flake="builtins.getFlake \\"path:$GITHUB_WORKSPACE\\""' in build
            and 'echo "RELOCATE_PYTHON=$python" >>"$GITHUB_ENV"' in build and source.count("GITHUB_ENV") == 1
            and "${{" not in build, "relocation builds only the locked Python with PyNaCl, without any Secret")
    require(selftest.count(RELOCATION_SELFTEST) == 1 and "${{" not in selftest, "relocation self-test must precede Secrets")
    mapped = [f"          {name}: ${{{{ secrets.{name} }}}}\n" for name in RELOCATION_SECRETS]
    require(all(seal.count(line) == 1 for line in mapped) and seal.count("${{ secrets.") == len(RELOCATION_SECRETS)
            and source.count("${{ secrets.") == len(RELOCATION_SECRETS) and "${{ vars." not in source
            and "          EXPECTED_SOURCE_SHA: ${{ inputs.expected_source_sha }}\n" in seal
            and set(re.findall(r"(?<![).\w])inputs\.([A-Za-z0-9_]+)", source)) == {"expected_source_sha"}
            and seal.count(RELOCATION_SEAL) == 1 and "nix " not in seal and "echo" not in seal,
            "relocation maps exactly the four existing Secrets into the one seal step, with no key or recipient input")
    upload = steps[RELOCATION_STEPS[5]]
    require("          name: relocate-receipt-${{ github.sha }}-${{ github.run_id }}\n" in upload
            and "          path: ${{ runner.temp }}/relocate/receipt.json\n" in upload
            and "          if-no-files-found: error\n" in upload and "          retention-days: 3\n" in upload,
            "relocation uploads only the encrypted receipt, kept three days")
    for token in ("set -x", "MAIL_CONFIG", "R2_PARENT_", "RENT_TUNNEL_ID", "pull_request", "secrets: inherit"):
        require(token not in source, f"relocation must not use {token}")
    spec = importlib.util.spec_from_file_location("relocate_rent_secrets_oracle", root / RELOCATION_PATHS[1])
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    try:
        key_ok = len(entry.public_key()) == 32
    except entry.RelocationError:
        key_ok = False
    require(key_ok and entry.DEST_ENVIRONMENT == "dev-projection"
            and entry.DEST_ENVIRONMENT_ID == 22898969883 and entry.SOURCE_ENVIRONMENT == RELOCATION_ENVIRONMENT
            and entry.SOURCE_ENVIRONMENT_ID == 23400924734
            and entry.MAPPING == tuple((name, "RENT_CLOUDFLARE_API_TOKEN" if name == "CLOUDFLARE_API_TOKEN" else name)
                                       for name in RELOCATION_SECRETS)
            and "MAIL_CONFIG" in entry.FORBIDDEN_INPUTS and entry.SECRET_LIMIT == 48 * 1024
            and entry.RECEIPT_LIMIT == 1024 * 1024 and entry.WORKFLOW == RELOCATION_PATHS[0],
            "relocation entry must seal the fixed four names to the fixed existing dev-projection key")
    adapter = (root / RELOCATION_PATHS[1]).read_text(encoding="utf-8")
    require("os.environb" in adapter and ".strip(" not in adapter and "unicodedata" not in adapter
            and "argparse" not in adapter, "relocation must keep injected bytes exactly and take no key input")
    for marker in ('"$python" -I adapters/relocate_rent_secrets.py selftest',
                   '"$python" -I checks/test_relocate_rent_secrets.py --require-nacl', RELOCATION_PYTHON,
                   "run: python3 checks/test_relocate_rent_secrets.py\n"):
        require(marker in check, f"check must test the relocation entry with the locked PyNaCl: {marker}")


def check_pi_worker_preview(source: str, canonical_consumer: str) -> None:
    """One manual projection of the accepted merge; existing secret stays in envs."""
    require("on:\n  workflow_dispatch:\n\npermissions:\n" in source
            and "inputs.ops_sha" not in source,
            "Pi preview must resolve the accepted source without a copied SHA input")
    require("\n  push:" not in source and "\n  pull_request:" not in source,
            "Pi preview must not deploy on a push or PR")
    for guard in ("github.repository == 'roccho-org/envs'", "github.ref == 'refs/heads/proposals'",
                  "github.event_name == 'workflow_dispatch'", "github.actor == 'roccho-dev'",
                  "github.actor_id == '40359643'", "github.triggering_actor == 'roccho-dev'",
                  "github.run_attempt == 1"):
        require(guard in source, f"Pi preview owner admission lost: {guard}")
    require("permissions:\n  actions: read\n  contents: read\n" in source
            and "    environment: dev-projection\n" in source,
            "Pi preview must preserve read-only repository and the existing Environment")
    require(set(INPUT_REFERENCE.findall(source)) == {
                ("secrets", "PI_CLOUDFLARE_API_TOKEN"), ("vars", "CLOUDFLARE_ACCOUNT_ID")},
            "Pi preview may use only its dedicated token and existing account input")
    require(source.count("secrets.PI_CLOUDFLARE_API_TOKEN") == 1
            and source.count("vars.CLOUDFLARE_ACCOUNT_ID") == 1
            and '          CLOUDFLARE_API_TOKEN: ${{ secrets.PI_CLOUDFLARE_API_TOKEN }}\n' in source,
            "Pi preview must map its dedicated token to native auth in one effect step only")
    require(consumer_run(source, "deploy-pi-worker-preview.yml") == canonical_consumer,
            "Pi preview must reuse the already-checked native toolchain")
    require(source.index("--no-bundle --dry-run") < source.index("secrets.PI_CLOUDFLARE_API_TOKEN"),
            "Pi preview must verify and dry-run before provider credentials")
    require("npm install" not in source and "pnpm install" not in source,
            "Pi projection must consume the checked artifact rather than rebuild app source")
    for marker in (
        '.merged == true and .state == "closed" and .base.repo.full_name == "roccho-org/ops" and .base.ref == "proposals" and .head.repo.full_name == "roccho-org/ops" and .head.ref == "poc/pi-worker-oauth-20261017" and (.merge_commit_sha | test("^[0-9a-f]{40}$"))',
        'OPS_SHA="$(jq -r .merge_commit_sha "$RUNNER_TEMP/pi-pr.json")"',
        'repos/roccho-org/ops/compare/$OPS_SHA...proposals',
        '.base_commit.sha == $sha and (.status == "identical" or .status == "ahead")',
        'echo "OPS_SHA=$OPS_SHA" >> "$GITHUB_ENV"',
        '.head_sha == $sha and .path == ".github/workflows/pi-worker-proof.yml" and .head_branch == "proposals" and .event == "push" and .conclusion == "success" and .repository.full_name == "roccho-org/ops" and .head_repository.full_name == "roccho-org/ops"',
        '--config "$PI_SCREEN_DIR/wrangler.json" --name pi --no-bundle --dry-run',
        '--config "$PI_SCREEN_DIR/wrangler.json" --name pi --var "PI_OAUTH_HOST_ID:$host_id" --no-bundle',
        'os.environ["CLOUDFLARE_ACCOUNT_ID"]+":pi"',
    ):
        require(marker in source, f"Pi accepted-source/target admission lost: {marker}")
    before = '"$ENVS_EFFECT_BIN/wrangler" deployments status --name pi --json > "$RUNNER_TEMP/pi-deployment-before.json" 2> "$RUNNER_TEMP/pi-status-before.stderr" || operation_exit=$?'
    upload = 'WRANGLER_OUTPUT_FILE_PATH="$upload_output" "$ENVS_EFFECT_BIN/wrangler" versions upload --config "$PI_SCREEN_DIR/wrangler.json" --name pi --var "PI_OAUTH_HOST_ID:$host_id" --no-bundle > "$RUNNER_TEMP/pi-upload.stdout" 2> "$RUNNER_TEMP/pi-upload.stderr" || operation_exit=$?'
    deploy = '"$ENVS_EFFECT_BIN/wrangler" versions deploy "$version_id@100%" --yes --config "$PI_SCREEN_DIR/wrangler.json" --name pi > "$RUNNER_TEMP/pi-deploy.stdout" 2> "$RUNNER_TEMP/pi-deploy.stderr" || operation_exit=$?'
    after = '"$ENVS_EFFECT_BIN/wrangler" deployments status --name pi --json > "$RUNNER_TEMP/pi-deployment-after.json" 2> "$RUNNER_TEMP/pi-status-after.stderr" || readback_exit=$?'
    for marker in (before, upload, deploy, after, '        run: |\n          set -euo pipefail\n          umask 077\n',
                   '          operation_exit=0\n', '          readback_exit=0\n',
                   '          if [[ "$readback_exit" == 0 ]]; then\n',
                   '          if [[ "$operation_exit" != 0 ]]; then\n            exit "$operation_exit"\n          fi\n          exit "$readback_exit"\n',
                   'upload_output="$(mktemp "$RUNNER_TEMP/pi-version-upload.XXXXXX.jsonl")" || operation_exit=$?',
                   'version_id="$(jq -ser ',
                   '[.[] | select(.type == "version-upload")] | select(length == 1) | .[0] | select(.version == 1 and .worker_name == "pi" and .worker_name_overridden == false) | .version_id | select(type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))',
                   '"$upload_output" 2> "$RUNNER_TEMP/pi-upload-output.stderr")" || operation_exit=$?',
                   '2> "$RUNNER_TEMP/pi-host-id.stderr")" || operation_exit=$?',
                   "jq -ce '{id, versions: [.versions[] | {version_id, percentage}]}' \"$RUNNER_TEMP/pi-deployment-before.json\" 2> \"$RUNNER_TEMP/pi-status-before-jq.stderr\" || operation_exit=$?",
                   "jq -ce '{id, versions: [.versions[] | {version_id, percentage}]}' \"$RUNNER_TEMP/pi-deployment-after.json\" 2> \"$RUNNER_TEMP/pi-status-after-jq.stderr\" || readback_exit=$?",
                   'if [[ "$operation_exit" == 0 && "$readback_exit" == 0 ]]; then',
                   "jq -e --arg version_id \"$version_id\" '(.versions | length) == 1 and .versions[0].version_id == $version_id and .versions[0].percentage == 100' \"$RUNNER_TEMP/pi-deployment-after.json\" > \"$RUNNER_TEMP/pi-status-after-match.stdout\" 2> \"$RUNNER_TEMP/pi-status-after-match.stderr\" || readback_exit=$?",
                   'report_api_error() {',
                   r'raw = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)',
                   r'paths = sorted(set(re.findall(r"A request to the Cloudflare API \((/accounts/[0-9a-f]{32}/workers/[A-Za-z0-9_/-]+|/memberships)\) failed\.", raw)))',
                   r'codes = sorted(set(int(code) for code in re.findall(r"\[code: ([0-9]{1,10})\]", raw)))',
                   'print(json.dumps({"phase": sys.argv[1], "api_paths": paths, "codes": codes}, separators=(",", ":")))',
                   '\' "$@" 2> "$RUNNER_TEMP/pi-api-diagnostic.stderr" || echo "pi diagnostic exit=$?"',
                   'report_api_error status-before "$RUNNER_TEMP/pi-deployment-before.json" "$RUNNER_TEMP/pi-status-before.stderr"',
                   'report_api_error upload "$RUNNER_TEMP/pi-upload.stdout" "$RUNNER_TEMP/pi-upload.stderr"',
                   'report_api_error deploy "$RUNNER_TEMP/pi-deploy.stdout" "$RUNNER_TEMP/pi-deploy.stderr"',
                   'report_api_error status-after "$RUNNER_TEMP/pi-deployment-after.json" "$RUNNER_TEMP/pi-status-after.stderr"'):
        require(marker in source, f"Pi native status/failure/privacy boundary lost: {marker}")
    require(source.index(before) < source.index(upload) < source.index(deploy) < source.index(after)
            and source.count('deployments status --name pi --json') == 2
            and source.count('if [[ "$operation_exit" == 0 ]]; then') == 6
            and '"$ENVS_EFFECT_BIN/wrangler" deploy ' not in source,
            "Pi must gate native version writes on successful prerequisites and always read status afterward")
    for marker in ("repos/roccho-org/ops/pulls/563", "flake-check", "jev-review-fresh-consumer",
                   "PI_OAUTH_HOST_ID", "pi-worker-screen-$OPS_SHA",
                   '".github/workflows/pi-worker-proof.yml"', '"SCREEN_ONLY_NO_TOKEN_EXCHANGE_OR_STORAGE"',
                   '.preview_urls == false', 'has("durable_objects")', 'has("assets")',
                   'has("services")', 'has("vars")', 'has("routes")'):
        require(marker in source, f"Pi preview source/target boundary lost: {marker}")


def check_calendar_pages_workflow(source: str, canonical_consumer: str) -> None:
    """Strictly admit only the one controller + issue scoped Pages effect."""
    require("on:\n  issue_comment:\n    types: [created]\n" in source,
            "calendar deploy must require an issue comment")
    require("\n  push:" not in source and "\n  pull_request:" not in source
            and "workflow_dispatch:" not in source, "calendar deploy must be comment-only")
    require("permissions:\n  actions: read\n  contents: read\n" in source,
            "calendar deploy may only read repo/actions")
    require("    environment: dev-projection\n" in source,
            "calendar deploy may only use the existing Cloudflare Environment")
    for guard in (
        "github.event.repository.owner.type == 'Organization'",
        "github.repository == 'roccho-org/envs'",
        "github.event.issue.number == 69",
        "github.event.issue.pull_request == null",
        "github.event.comment.user.id == 40359643",
        "github.actor == 'roccho-dev'",
        "github.actor_id == '40359643'",
        "github.triggering_actor == 'roccho-dev'",
        "github.ref_name == 'proposals'",
        "github.run_attempt == 1",
        "startsWith(github.event.comment.body, '/deploy-calendar ')",
    ):
        require(guard in source, f"calendar controller guard lost: {guard}")
    require(source.count("github.event.comment.body") == 1,
            "calendar comment cannot enter a shell or environment expression")
    require(consumer_run(source, "deploy-calendar-pages.yml") == canonical_consumer,
            "calendar must consume the exact already-checked envs toolchain")
    require(source.count("actions/checkout@") == 2
            and source.count("persist-credentials: false") == 2,
            "calendar checkouts must be pinned and credential-free")
    require("          repository: roccho-dev/apps\n" in source
            and "          ref: ${{ steps.select.outputs.app_sha }}\n" in source,
            "calendar must fetch the accepted exact apps SHA")
    require("ref: ${{ github.sha }}\n" in source,
            "calendar provider code must be the canonical envs SHA")
    require(source.count("adapters/calendar_pages.py select'") == 1
            and source.count("adapters/calendar_pages.py verify'") == 1
            and source.count("adapters/calendar_pages.py deploy'") == 1,
            "calendar can use only the three bounded adapter commands")
    stage = [source.find("adapters/calendar_pages.py select'"),
             source.find("adapters/calendar_pages.py verify'"),
             source.find("secrets.CLOUDFLARE_API_TOKEN"),
             source.find("adapters/calendar_pages.py deploy'")]
    require(stage[0] >= 0 and stage == sorted(stage),
            "calendar proof must precede any Cloudflare secret or effect")
    require(set(INPUT_REFERENCE.findall(source)) == {
                ("secrets", "CLOUDFLARE_API_TOKEN"), ("vars", "CLOUDFLARE_ACCOUNT_ID")},
            "calendar must use only the existing dev-projection Cloudflare pair")
    require(source.count("secrets.CLOUDFLARE_API_TOKEN") == 1
            and source.count("vars.CLOUDFLARE_ACCOUNT_ID") == 1,
            "calendar provider inputs may be exposed only in the final step")
    require("SOPS_AGE_KEY" not in source and "AWS_" not in source
            and "CLOUDFLARE_ZONE_ID" not in source and "secrets: inherit" not in source,
            "calendar may not borrow unrelated credential classes")
    adapter = (ROOT / "adapters/calendar_pages.py").read_text(encoding="utf-8")
    require('CONTROL_ISSUE = 69' in adapter
            and 'PROJECT = "roccho-family-calendar-2026"' in adapter
            and 'APPS_REPO = "roccho-dev/apps"' in adapter,
            "calendar adapter may target only the fixed issue, Pages project, and source repo")


def check_toolchain(root: Path, adapter) -> None:
    flake = (root / "flake.nix").read_text(encoding="utf-8")
    pinned = FLAKE_NIXPKGS.findall(flake)
    require(len(pinned) == 1 and "inputs." not in FLAKE_NIXPKGS.sub("", flake), "flake must have exactly one pinned nixpkgs input")
    require(adapter.locked_nixpkgs(root)["rev"] == pinned[0], "flake.lock differs from flake.nix")
    for tool in adapter.TOOLCHAIN_TOOLS:
        require(re.search(rf'(?m)^        {tool} = "\$\{{(pkgs\.[a-z0-9]+|cloudflared|opentofu|terraform-backend-git)\}}'
                          r'/bin/[a-z0-9-]+";$', flake) is not None, f"flake does not provide {tool}")
    for pin in PROBE_PINS:
        require(pin in flake, f"flake must pin the probe tool: {pin}")
    for pin in BACKEND_PINS:
        require(flake.count(pin) == 1, f"flake must pin and build-check the upstream state backend exactly once: {pin}")
    require(flake.count("packages = with pkgs; [") == 1 and EFFECT_PACKAGES in flake,
            "effect toolchain packages differ; check-only age must stay outside them")
    require(flake.count("pkgs.age") == 1 and "        check-age = pkgs.age;\n" in flake, "check-age must be a separate check-only output")
    require("export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" in flake,
            "the entry must carry its own CA bundle for provider retrieval")
    require('exec ${tools.python3} -I ${self}/adapters/jev_api.py "$@"' in flake, "flake entry must run only the adapter")
    require('exec ${tools.python3} -I ${self}/adapters/mail_routing_read.py' in flake,
            "Mail read must use the exact pinned interpreter/source")
    require('exec ${tools.python3} -I ${self}/adapters/mail_routing_root.py' in flake,
            "Mail root must use the same source-bound pinned Python")
    require('paths = [ entry contract-projection mail-routing-read mail-routing-root ] ++ packages;' in flake,
            "Mail read and inactive root must be in the same provided closure")
    require("closureInfo { rootPaths = [ effect-toolchain ]; }" in flake and "echo ${effect-toolchain}/bin/envs-effect > ENTRY" in flake,
            "flake artifact must carry the whole entry closure and its ENTRY")
    require('rev = self.rev or (throw "' in flake and "echo ${rev} > SOURCE" in flake and "ENTRY SOURCE $(cat" in flake
            and "source = rev;" in flake, "flake artifact must record the exact committed source it was built from")
    source = (root / "adapters/jev_api.py").read_text(encoding="utf-8")
    for token in ("npx", "--yes", "SOPS_BIN", "NPX_BIN", "WRANGLER_PACKAGE"):
        require(token not in source, f"adapter selects an ambient or runtime tool: {token}")
    check_root_source_gates(source)


# S2: every rent-root entry that could read the root's secrets, spawn a child or act on a backend is gated in source.
# Each gate is one literal, and the entry's first statement after naming its stage is that gate. The readiness grant
# opens only the read-only inspect entry; apply, backend migration and the backend-only plan stay literal False.
ROOT_SOURCE_GATES = {
    "ROOT_INSPECT_SOURCE_ACTIVE": "def rent_root_inspect(",
    "ROOT_APPLY_SOURCE_ACTIVE": "def rent_root(",
    "ROOT_MIGRATE_SOURCE_ACTIVE": "def rent_root_migrate(",
    "ROOT_PLAN_SOURCE_ACTIVE": "def rent_root_plan(",
}
ROOT_OPEN_GATES = frozenset({"ROOT_INSPECT_SOURCE_ACTIVE"})


def check_root_source_gates(source: str) -> None:
    for gate, entry in ROOT_SOURCE_GATES.items():
        literal, meaning = ("True", "readiness-open") if gate in ROOT_OPEN_GATES else ("False", "source-hard-inactive")
        require(source.count(f"\n{gate} = {literal}\n") == 1 and source.count(f"{gate} =") == 1,
                f"{gate} must be one literal {meaning} gate")
        require(source.count(entry) == 1, f"rent-root entry missing: {entry}")
        body = source[source.find(entry):]
        body = body[:body.find("\ndef ", 1)]
        require(source.count(f"require({gate},") == 1 and body.count(f"require({gate},") == 1,
                f"{gate} must guard only its own entry")
        statements = [line.strip() for line in body.splitlines()[1:]
                      if line.strip() and not line.strip().startswith("#") and line.startswith("    ")
                      and not line.startswith("     ")]
        first = [line for line in statements if not line.startswith(("progress = ", 'progress["stage"] = '))]
        require(first and first[0].startswith(f"require({gate},"),
                f"{gate} must be the first check of its entry, before any input, tool or child")
    # Upstream v0.1.12 HTTPS basic auth requires GIT_USERNAME beside the token; the child gets exactly this literal.
    require(source.count('\nROOT_STATE_GIT_USERNAME = "x-access-token"\n') == 1
            and source.count('"GIT_USERNAME": ROOT_STATE_GIT_USERNAME') == 1 and source.count('"GIT_USERNAME"') == 1,
            "the state backend child must receive the fixed non-secret GIT_USERNAME exactly once")
    require(all(name not in source for name in ("GIT_PASSWORD", "GITHUB_TOKEN_FILE", "SSH_PRIVATE_KEY", "SSH_AUTH_SOCK")),
            "the state backend child takes only the workflow token, never another Git credential route")
    require(source.count("ROOT_LEGACY_S3_CONFIG") == 2 and 'backend "s3"' in source
            and source.count('  backend "s3" {\n') == 1,
            "the former S3 backend may exist only as the one source-declared legacy read root")


def check_placement(root: Path) -> None:
    check = (root / ".github/workflows/check.yml").read_text(encoding="utf-8")
    for marker in PLACEMENT_MARKERS:
        require(marker in check, f"placement-gate must bind the actual outputs: {marker.strip()}")
    # The four jobs sit before toolchain, outside the toolchain/effect-shape/clean-start slices checked above.
    require(-1 < check.find("\n  placement-artifact:\n") < check.find("\n  placement-rent:\n") < check.find("\n  toolchain:\n"),
            "placement-gate jobs must precede toolchain")
    gate = check[check.find("\n  placement-artifact:\n"):check.find("\n  toolchain:\n")]
    require("secrets." not in gate and "curl -fsSL -H" not in gate and "-u \"" not in gate,
            "placement-gate must pass no credential in argv")
    flake = (root / "flake.nix").read_text(encoding="utf-8")
    for marker in PLACEMENT_FLAKE:
        require(marker in flake, f"flake must provide the pinned Windows placement distribution: {marker}")
    receiver = (root / RENT_RECEIVER).read_text(encoding="utf-8")
    # One bash -c argument through Windows argv: no quote or backslash, and the slot rule rent-start checks.
    require('"' not in receiver and "\\" not in receiver, "the rent receiver must be argv-safe")
    for marker in ("head -c 4097 >$temp", "[ $size -ge 1 ] && [ $size -le 4096 ]", "chown 0:0 $temp", "chmod 600 $temp",
                   "mv -f -- $temp $slot", "[ ! -L $slot ] || fail",
                   "[ ! -e $slot ] || [ $(stat -c %u:%g:%a $slot) = 0:0:600 ] || fail", "if [ -e $slot ] && cmp -s $temp $slot; then",
                   "safe() { [ -d $1 ] && [ ! -L $1 ] && [ $(stat -c %u $1) = 0 ] && [ $(( 0$(stat -c %a $1) & 022 )) = 0 ]; }",
                   "safe $state || fail", "safe $dir || fail"):
        require(marker in receiver, f"the rent receiver must enforce the slot rule: {marker}")
    entry = (root / PLACEMENT_ENTRY).read_text(encoding="utf-8")
    for marker in ("'-NoProfile -NonInteractive -File \"' + $win + '\" -Mode RentAccess'", "@{ SOPS_AGE_KEY_FILE = $Identity }",
                   "$writer.StandardInput.BaseStream.Write($payload, 0, $payload.Length)",
                   "if ([Console]::InputEncoding.GetPreamble().Length) { Refuse 'the console input encoding would prefix the value' }",
                   "$buffer, $count = [byte[]]::new($Limit + 3), 0",
                   "if ($count -gt $Limit + 2) { try { $child.Kill() } catch { }; Refuse 'the decrypted value exceeds its bound' }",
                   "Decrypt 'RENT_ACCESS_CLIENT_ID' 1024", "Decrypt 'RENT_ACCESS_CLIENT_SECRET' 1024", "Decrypt 'RENT_TUNNEL_TOKEN' 4096",
                   "if ($script.Contains('\"') -or $script.Contains('\\')) { Refuse 'the rent receiver is not argv-safe' }"):
        require(marker in entry, f"the placement entrance differs: {marker}")
    # Child streams are bounded (decryption) or discarded (writer, stderr): nothing reads an unbounded stream to memory.
    for token in ("Write-Host", "Write-Output", "Out-File", "Set-Content", "Add-Content", "Start-Transcript", "$env:TUNNEL",
                  "ReadToEnd", "MemoryStream"):
        require(token not in entry, f"the placement entrance must not emit or store a value: {token}")


def check_readme(root: Path, environments: dict[str, dict[str, Any]]) -> None:
    text = (root / "README.md").read_text(encoding="utf-8")
    for row in environments.values():
        for _, input_name in sorted(declared_inputs(row)):
            marker = f"{row['github_environment']}/{input_name}"
            require(marker in text, f"README missing {marker}")
    for marker in (
        "canonical branch: `proposals`",
        "retained compatibility branch: `main`",
        "contracts/",
        "adapters/jev_api.py",
        "handoffs/dev-jev-api.json",
        "ciphertexts/dev-rent-tunnel.sops.yaml",
        "checks/test_rent_tunnel.py",
        RENT_CONFIG,
        "applied only by `rent-root` under a separate effect grant",
        "dev-authoring/OCI_DEV_AGE_RECIPIENT",
        "dev-authoring/OPENCODE_API_KEY",
        "dev-authoring/TYPELLM_API_KEY",
        "ciphertexts/dev-typellm-api.oci-dev.sops.yaml",
        "`author --target typellm-api.oci-dev`",
        "ciphertexts/dev-typellm-api.versapro-own-oci.sops.yaml",
        "`author --target typellm-api.versapro-own-oci`",
        "dev-authoring/VERSAPRO_OWN_OCI_AGE_RECIPIENT",
        "ciphertexts/dev-jev-api.oci-dev.sops.yaml",
        "ciphertexts/dev-opencode-go.oci-dev.sops.yaml",
        "`author --target opencode-go.oci-dev`",
        "`author --target jev-api.oci-dev`",
        RENT_RECEIVER,
        PLACEMENT_ENTRY,
        "placement-gate",
        "ciphertexts/dev-rent-client.sops.yaml",
        "-Mode RentAccess` glue",
    ):
        require(marker in text, f"README missing {marker}")
    require("delete `main`" not in text.lower(), "README proposes deleting main")
    for retired in RETIRED_ENVIRONMENTS:
        require(f"`{retired}/" not in text, f"README declares an input on the retired Environment {retired}")


def check_main_compatibility_refresh(root: Path) -> None:
    fetch = subprocess.run(
        ["git", "fetch", "--no-tags", "origin", "proposals"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(fetch.returncode == 0, "cannot fetch canonical proposals")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
    )
    canonical = subprocess.run(
        ["git", "rev-parse", "FETCH_HEAD"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
    )
    require(head.returncode == 0 and canonical.returncode == 0, "cannot resolve branch revisions")
    require(head.stdout.strip() == canonical.stdout.strip(), "main compatibility refresh does not equal canonical proposals")


def inspect(root: Path = ROOT, *, verify_main_compatibility_refresh: bool = False) -> dict[str, Any]:
    check_shape(root)
    check_text(root)
    check_jsonl(root)
    adapter = load_adapter(root)
    contracts = adapter.validate_contracts(root)
    environments = contracts["environments"]
    if (root / adapter.HANDOFF).is_file():
        adapter.load_receipt(root / adapter.HANDOFF)
    if (root / adapter.ORG_HANDOFF).is_file():
        adapter.validate_org_receipt(json.loads((root / adapter.ORG_HANDOFF).read_text(encoding="utf-8")))
    check_workflows(root, environments, author_target_inputs(adapter, contracts), adapter)
    check_toolchain(root, adapter)
    check_placement(root)
    check_readme(root, environments)
    if verify_main_compatibility_refresh:
        check_main_compatibility_refresh(root)
    readiness = adapter.readiness(root)
    require(readiness["consumer_runtime_readiness"] == "OUT_OF_SCOPE", "envs claims consumer runtime readiness")
    return {
        "kind": "envs.repositoryCheck.v1",
        "status": "PASS",
        "canonical_branch": "proposals",
        "retained_compatibility_branch": "main",
        "main_independent_authority_count": 0,
        "main_direct_change_count": 0,
        "provider_handoff": readiness["provider_handoff_receipt"],
        "consumer_runtime_readiness": "OUT_OF_SCOPE",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify-main-compatibility-refresh", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(args.root.resolve(), verify_main_compatibility_refresh=args.verify_main_compatibility_refresh)
    except (RepositoryError, ValueError, OSError) as exc:
        print(f"REPOSITORY_CHECK=RED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
