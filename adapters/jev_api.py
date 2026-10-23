#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = Path("contracts/environments.jsonl")
BINDINGS = Path("contracts/bindings.jsonl")
BOUNDARY = Path("contracts/provider-consumer.jsonl")
CIPHERTEXT = Path("ciphertexts/dev-jev-api.sops.yaml")
HANDOFF = Path("handoffs/dev-jev-api.json")
FLAKE_LOCK = Path("flake.lock")
RECEIPT_KIND = "envs.projectionReceipt.v1"
TOOLCHAIN_KIND = "envs.effectToolchain.v1"
TOOLCHAIN_TOOLS = ("python3", "sops", "wrangler", "git", "gh", "tofu", "cloudflared", "ssh", "sshd", "ssh_keygen", "curl",
                   "terraform_backend_git")
STORE = Path("/nix/store")
# Rent tunnel (windows #14): a provider-issued Named Tunnel token, encrypted to exactly one target age recipient.
RENT_PLANE = "dev.rent-tunnel"
RENT_CIPHERTEXT = Path("ciphertexts/dev-rent-tunnel.sops.yaml")
RENT_KEY = "RENT_TUNNEL_TOKEN"
# Rent client (windows #14): the G6I3 normal user's Access service credential from the persistent root's sensitive
# output, encrypted to exactly one target age recipient. place.ps1 decrypts it on the target and hands windows'
# RentAccess the owner-only slot '<client id>LF<client secret>LF' through a private stdin pipe.
CLIENT_PLANE = "dev.rent-client"
CLIENT_CIPHERTEXT = Path("ciphertexts/dev-rent-client.sops.yaml")
CLIENT_KEYS = ("RENT_ACCESS_CLIENT_ID", "RENT_ACCESS_CLIENT_SECRET")
CLIENT_RECIPIENT = "RENT_CLIENT_AGE_RECIPIENT"
# Persistent rent root (windows #8/#14): the declared Cloudflare root applied with standard OpenTofu on its native
# encrypted and locked R2 backend; its sensitive credentials output is sealed in memory into the two envelopes above.
ROOT_PLANE = "dev.rent-root"
ROOT_CONFIG = Path("providers/dev-rent-cloudflare/main.tf")
# Host is not a GitHub Environment: rent stage ingress shares the functional dev-projection Environment, whose Pages/Mail
# Cloudflare slots it never reads. Its own Cloudflare inputs are distinct storage slots (and runtime names); the adapter
# hands each to its children only under the provider-native name below. No equality of value or scope is assumed.
RENT_ENVIRONMENT = "dev-projection"
RENT_CLOUDFLARE_INPUTS = {
    "RENT_CLOUDFLARE_API_TOKEN": "CLOUDFLARE_API_TOKEN",
    "RENT_CLOUDFLARE_ACCOUNT_ID": "CLOUDFLARE_ACCOUNT_ID",
    "RENT_CLOUDFLARE_ZONE_ID": "CLOUDFLARE_ZONE_ID",
}
RETIRED_ENVIRONMENTS = ("dev-rent-tunnel", "dev-rent-client", "dev-rent-access-probe")
ROOT_SECRETS = ("RENT_CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RENT_STATE_PASSPHRASE")
# One key provider and method name for the state's life (a rotation would add a new name with this one as fallback).
ROOT_KEY_NAME = "k0"
# The reviewed readiness source grant opens only the read-only inspect entry; its workflow job admits one dispatch by
# the declared caller on the accepted canonical SHA. Apply, backend migration and the backend-only plan stay closed.
ROOT_INSPECT_SOURCE_ACTIVE = True
ROOT_INSPECT_RESOURCE_TYPES = frozenset({
    "cloudflare_zero_trust_tunnel_cloudflared",
    "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_dns_record",
    "cloudflare_zero_trust_access_service_token",
    "cloudflare_zero_trust_access_policy",
    "cloudflare_zero_trust_access_application",
})
ROOT_INSPECT_STATE_LIMIT = 1048576
# OpenTofu writes a state lineage as a UUID; the inspect receipt carries it only in that closed shape.
ROOT_STATE_LINEAGE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# S2 moves the declared root to the standard HTTP backend, served for one operation by a transient loopback
# terraform-backend-git child that keeps the state on the GitHub ref below. No source path may plan, apply or create
# against that backend before a separately reviewed activation grant: apply, backend migration and the backend-only
# plan each refuse at their first line, before any contract, environment, manifest, secret or child.
ROOT_APPLY_SOURCE_ACTIVE = False
ROOT_MIGRATE_SOURCE_ACTIVE = False
ROOT_PLAN_SOURCE_ACTIVE = False
ROOT_STATE_BACKEND = {
    "kind": "terraform-backend-git", "repository": "roccho-org/envs", "repository_id": 1391871347,
    "ref": "refs/heads/tofu-state", "state_path": "state/dev-rent-cloudflare.json",
    "lock_ref": "refs/heads/locks/state/dev-rent-cloudflare.json",
}
# The existing workflow principal for the state ref; it reaches only the backend child, never OpenTofu or argv.
ROOT_STATE_GIT_TOKEN = "GITHUB_TOKEN"
# Upstream v0.1.12 HTTPS basic auth refuses without GIT_USERNAME even for a token (storages/git/git.go authBasicHTTP);
# GitHub accepts any fixed username with a token. Non-secret, so it is a source literal, not an Environment input.
ROOT_STATE_GIT_USERNAME = "x-access-token"
ROOT_BACKEND_READY_ATTEMPTS = 50
# The root's former R2 S3 backend, used only to read and migrate the existing state until the retire source removes
# it: exactly the partial S3 block and enforced encryption the root declared before S2, with nothing to plan or apply.
ROOT_LEGACY_S3_CONFIG = """terraform {
  backend "s3" {
    region                      = "auto"
    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }

  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}
"""

# The format secrets.token_hex(32) produces, placed inside an HCL string: a format check, not a strength proof.
ROOT_PASSPHRASE = re.compile(r"^[0-9a-f]{64}$")
# The old S3 state object key exactly as the Environment declares it (the contract types it opaque): no prefix is
# assumed. A closed ASCII charset keeps out any query, escape, space or control; every segment is a real name, so
# there is no leading, trailing or doubled slash and no "." or ".." that a client could normalise to another object.
ROOT_STATE_KEY_CHARS = re.compile(r"[A-Za-z0-9_./-]{1,180}")
ROOT_LOCK_SUFFIX = ".tflock"


def root_state_key_ok(key: str) -> bool:
    return (ROOT_STATE_KEY_CHARS.fullmatch(key) is not None and key.endswith(".tfstate") and ".." not in key
            and all(segment not in ("", ".") for segment in key.split("/")))


# The windows slot rule (Get-RentAccessProblem) for each line: 1-1024 printable ASCII characters.
SLOT_LINE = re.compile(r"^[!-~]{1,1024}$")
WINDOWS_CONSUMER = "windows.rent.consumer"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
RETRIEVAL_TIMEOUT = 30.0
RESPONSE_LIMIT = 65536
# Linode/Akamai Cloud read-only connectivity probe: no create/update/delete operation exists here.
LINODE_READ_PLANE = "dev.linode-read-probe"
LINODE_API = "https://api.linode.com/v4"
LINODE_READ_ENDPOINTS = (("profile", "/profile"), ("account", "/account"), ("linodes", "/linode/instances?page_size=25"))
# The persistent root's sensitive credentials output: the tunnel token and the Access service token pair.
PROBE_CREDENTIALS = ("tunnel_token", "service_token_id", "service_token_value")
# The disposable Access probe and R2 state proof (dev.rent-access-probe / dev.rent-state-proof) are retired with their
# Environment; their parent token is never an input. The closed failure facts below remain the root's init hint.
STATE_STATUS = re.compile(rb"StatusCode: ([0-9]{3})\b")
STATE_TRANSIENT = re.compile(rb"(?<![-\w])timeout|timed out|connection (?:refused|reset)|no such host|unexpected EOF",
                             re.IGNORECASE)
# WSLC OCI dev target (roccho-dev/adrs#460): the same one-shot Jev source, encrypted to exactly one target recipient.
# It has no plane state and no handoff; the validated ciphertext at an exact commit is its whole readiness.
OCI_BINDING = "jev-api.oci-dev"
OCI_CIPHERTEXT = Path("ciphertexts/dev-jev-api.oci-dev.sops.yaml")
OCI_RECIPIENT = "OCI_DEV_AGE_RECIPIENT"
# Go uses a distinct source plane on the existing dev-authoring Environment. Only the named recipient is shared;
# Jev and Go secrets never cross selected author steps, tool environments, ciphertexts, or target kinds.
GO_PLANE = "dev.opencode-go-authoring"
GO_BINDING = "opencode-go.oci-dev"
GO_CIPHERTEXT = Path("ciphertexts/dev-opencode-go.oci-dev.sops.yaml")
GO_KEY = "OPENCODE_API_KEY"
# The VersaPro own OCI Pi target (roccho-dev/resources#10): the same Go source plane with its own single recipient,
# ciphertext and exact target. Declaring it never makes it usable; only a validated ciphertext at an exact commit does.
OWN_GO_BINDING = "opencode-go.versapro-own-oci"
OWN_GO_CIPHERTEXT = Path("ciphertexts/dev-opencode-go.versapro-own-oci.sops.yaml")
OWN_GO_RECIPIENT = "VERSAPRO_OWN_OCI_AGE_RECIPIENT"
# Go binding -> its one ciphertext; both read the Go plane's OPENCODE_API_KEY and nothing else.
GO_CIPHERTEXTS = {GO_BINDING: GO_CIPHERTEXT, OWN_GO_BINDING: OWN_GO_CIPHERTEXT}
TYPELLM_PLANE = "dev.typellm-authoring"
TYPELLM_BINDING = "typellm-api.oci-dev"
TYPELLM_CIPHERTEXT = Path("ciphertexts/dev-typellm-api.oci-dev.sops.yaml")
TYPELLM_KEY = "TYPELLM_API_KEY"
# The same TypeLLM source plane, but a distinct own target and one existing public recipient.
OWN_TYPELLM_BINDING = "typellm-api.versapro-own-oci"
OWN_TYPELLM_CIPHERTEXT = Path("ciphertexts/dev-typellm-api.versapro-own-oci.sops.yaml")
OWN_TYPELLM_RECIPIENT = OWN_GO_RECIPIENT
TYPELLM_CIPHERTEXTS = {TYPELLM_BINDING: TYPELLM_CIPHERTEXT, OWN_TYPELLM_BINDING: OWN_TYPELLM_CIPHERTEXT}
# The VersaPro own OCI target for the same one-shot Jev source: its own ciphertext and the existing own public
# recipient that the Go and TypeLLM own targets already use. The OCI dev recipient is never a fallback.
OWN_JEV_BINDING = "jev-api.versapro-own-oci"
OWN_JEV_CIPHERTEXT = Path("ciphertexts/dev-jev-api.versapro-own-oci.sops.yaml")
OWN_JEV_RECIPIENT = OWN_GO_RECIPIENT
JEV_CIPHERTEXTS = {OCI_BINDING: OCI_CIPHERTEXT, OWN_JEV_BINDING: OWN_JEV_CIPHERTEXT}
OCI_CIPHERTEXTS = {**JEV_CIPHERTEXTS, **GO_CIPHERTEXTS, **TYPELLM_CIPHERTEXTS}
# Every binding `author --target` can select; a dispatch names exactly one of them.
AUTHOR_TARGETS = ("jev-api", *OCI_CIPHERTEXTS, "opencode-go.pi-worker")
ORG_BINDING = "jev-api.github-actions"
ORG_HANDOFF = Path("handoffs/dev-jev-api.github-actions.json")
ORG_RECEIPT_KIND = "envs.orgSecretProjectionReceipt.v1"
ORG_PLAN_KIND = "envs.orgSecretProjectionPlan.v1"
ORG_CONTROLLER = "roccho-dev"
ORG_TARGET = {
    "provider": "github-org-secret", "organization": "roccho-org", "organization_id": "319185687",
    "secret_name": "JEV_API_KEY", "repositories": ["roccho-org/ops", "roccho-org/envs"],
    "repository_ids": ["1275606595", "1391871347"],
}

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
AGE_RECIPIENT = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")
AGE_IDENTITY = re.compile(r"^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$")
CLOUDFLARE_ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
CLOUDFLARE_WORKER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CLOUDFLARE_TUNNEL_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLOUDFLARE_TOKEN_ID = re.compile(r"^[0-9a-f]{32}$")
# The target's token file gate accepts 1-4096 non-blank bytes; the provider returns base64 text.
TUNNEL_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]{1,4096}$")
BEARER = re.compile(r"^[\x21-\x7e]+$")
RECIPIENT_METADATA = re.compile(r"(?m)^[ \t]*-?[ \t]*recipient:[ \t]*(age1[0-9a-z]+)[ \t]*$")
PRIVATE_MATERIAL = (
    re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
)
FORBIDDEN_RECEIPT_KEYS = {
    "secret", "secret_value", "plaintext", "private_key", "age_identity",
    "decrypted_value", "secret_hash",
}
SECRET_PLANE_KEYS = {
    "id", "kind", "stage_id", "plane_id", "owner", "github_environment",
    "active_github_environment", "migration_state", "source_kind", "target_kind", "desired_state",
}


class EnvsError(ValueError):
    pass


# State proof: provider doubt (EnvsError) and local launch or storage failures; none may bypass cleanup or become evidence.
STATE_FAILURES = (EnvsError, OSError, subprocess.SubprocessError)


Runner = Callable[
    [Sequence[str], bytes | None, Mapping[str, str] | None],
    subprocess.CompletedProcess[bytes],
]


def require(ok: bool, message: str) -> None:
    if not ok:
        raise EnvsError(message)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EnvsError(f"{path}:{number}: invalid JSON") from exc
        require(isinstance(value, dict), f"{path}:{number}: row must be an object")
        rows.append(value)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def index(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in load_jsonl(path):
        identity = row.get("id")
        require(isinstance(identity, str) and identity, f"{path}: missing id")
        require(identity not in result, f"{path}: duplicate id {identity}")
        result[identity] = row
    return result


def validate_jev_target(target: Any) -> dict[str, Any]:
    require(isinstance(target, dict), "Jev target must be an object")
    provider = target.get("provider")
    if provider == "cloudflare-pages":
        require(target == {
            "provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY",
        }, "Pages Jev target differs")
    elif provider == "cloudflare-workers":
        require(set(target) == {"provider", "account_id", "worker_name", "secret_name"},
                "Workers Jev target fields differ")
        require(isinstance(target.get("account_id"), str)
                and CLOUDFLARE_ACCOUNT_ID.fullmatch(target["account_id"]) is not None,
                "Workers account id invalid")
        require(isinstance(target.get("worker_name"), str)
                and CLOUDFLARE_WORKER_NAME.fullmatch(target["worker_name"]) is not None,
                "Workers name invalid")
        require(target.get("secret_name") == "JEV_API_KEY", "Workers secret name differs")
    else:
        raise EnvsError("Jev target provider unsupported")
    return target


WORKER_GO_BINDING = "opencode-go.pi-worker"
WORKER_GO_PLANE = "dev.pi-opencode-projection"
WORKER_GO_CIPHER = Path("ciphertexts/dev-opencode-go.pi-worker.sops.yaml")
WORKER_GO_HANDOFF = Path("handoffs/dev-opencode-go.pi-worker.json")
WORKER_GO_BOUNDARY = "dev.opencode-go-pi-worker.provider"
WORKER_GO_TARGET = {"provider": "cloudflare-workers", "account_id": "3d17cd263c27a0ea241f0a8fc09ac2bb",
                    "worker_name": "pi", "secret_name": "OPENCODE_API_KEY"}


def expected_worker_go_binding() -> dict[str, Any]:
    return {"id": WORKER_GO_BINDING, "kind": "envs.authCapability.v1", "capability": "opencode-go",
            "ciphertext": WORKER_GO_CIPHER.as_posix(), "source_key": GO_KEY,
            "github_environment": "dev-authoring",
            "required_variables": [{"name": "SOPS_AGE_RECIPIENTS", "type": "age_recipient_list", "lifecycle": "persistent"}],
            "target": dict(WORKER_GO_TARGET)}


def expected_worker_go_boundary() -> dict[str, Any]:
    return {"id": WORKER_GO_BOUNDARY, "kind": "envs.providerConsumerBoundary.v1", "role": "provider",
            "repository": "roccho-org/envs", "stage": "dev", "capability": "opencode-go",
            "binding": WORKER_GO_BINDING, "source_kind": "public_sops", "target_kind": "target_native_auth",
            "owns": ["contract", "target_selected_authoring", "projection", "provider_readback", "projection_receipt"],
            "does_not_own": ["application_runtime_acceptance", "consumer_independent_execution"],
            "handoff_ref_kind": "exact_commit_sha"}


def expected_bindings(jev_target: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    target = {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"} \
        if jev_target is None else validate_jev_target(jev_target)
    return {
        WORKER_GO_BINDING: expected_worker_go_binding(),
        "voice-ui": {
            "id": "voice-ui",
            "kind": "envs.applicationBinding.v1",
            "application": "roccho-dev/apps/packages/voice-ui",
        },
        "jev-api": {
            "id": "jev-api",
            "kind": "envs.authCapability.v1",
            "capability": "jev-api",
            "ciphertext": CIPHERTEXT.as_posix(),
            "source_key": "JEV_API_KEY",
            "target": dict(target),
        },
        "rent-tunnel": {
            "id": "rent-tunnel",
            "kind": "envs.authCapability.v1",
            "capability": "rent-tunnel",
            "ciphertext": RENT_CIPHERTEXT.as_posix(),
            "source_key": RENT_KEY,
            "source": {"provider": "cloudflare", "operation": "cfd_tunnel_token"},
            "target": {"repository": "roccho-dev/windows", "host": "rent", "kind": "cloudflared_token_file"},
        },
        OCI_BINDING: {
            "id": OCI_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "jev-api",
            "ciphertext": OCI_CIPHERTEXT.as_posix(),
            "source_key": "JEV_API_KEY",
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OCI_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/windows", "host": "oci-dev", "kind": "process_env", "secret_name": "JEV_API_KEY"},
        },
        OWN_JEV_BINDING: {
            "id": OWN_JEV_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "jev-api",
            "ciphertext": OWN_JEV_CIPHERTEXT.as_posix(),
            "source_key": "JEV_API_KEY",
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OWN_JEV_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/resources", "host": "versapro-own-oci", "kind": "process_env", "secret_name": "JEV_API_KEY"},
        },
        GO_BINDING: {
            "id": GO_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "opencode-go",
            "ciphertext": GO_CIPHERTEXT.as_posix(),
            "source_key": GO_KEY,
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OCI_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/windows", "host": "oci-dev", "kind": "pi_auth_command"},
        },
        OWN_GO_BINDING: {
            "id": OWN_GO_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "opencode-go",
            "ciphertext": OWN_GO_CIPHERTEXT.as_posix(),
            "source_key": GO_KEY,
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OWN_GO_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/resources", "host": "versapro-own-oci", "kind": "pi_auth_command"},
        },
        TYPELLM_BINDING: {
            "id": TYPELLM_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "typellm-api",
            "ciphertext": TYPELLM_CIPHERTEXT.as_posix(),
            "source_key": TYPELLM_KEY,
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OCI_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/windows", "host": "oci-dev", "kind": "process_env", "secret_name": TYPELLM_KEY},
        },
        OWN_TYPELLM_BINDING: {
            "id": OWN_TYPELLM_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "typellm-api",
            "ciphertext": OWN_TYPELLM_CIPHERTEXT.as_posix(),
            "source_key": TYPELLM_KEY,
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OWN_TYPELLM_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/resources", "host": "versapro-own-oci", "kind": "process_env", "secret_name": TYPELLM_KEY},
        },
        ORG_BINDING: {
            "id": ORG_BINDING, "kind": "envs.authCapability.v1", "capability": "jev-api",
            "ciphertext": OCI_CIPHERTEXT.as_posix(), "source_key": "JEV_API_KEY",
            "target": json.loads(json.dumps(ORG_TARGET)),
        },
    }


def expected_org_boundaries() -> dict[str, dict[str, Any]]:
    provider = {
        "id": "dev.jev-api-github-actions.provider", "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider", "repository": "roccho-org/envs", "stage": "dev", "capability": "jev-api",
        "binding": ORG_BINDING, "source_kind": "public_sops", "target_kind": "github_org_secret",
        "owns": ["contract", "projection", "selected_repository_ids", "provider_readback", "projection_receipt"],
        "does_not_own": ["application_runtime_acceptance", "consumer_independent_execution"],
        "handoff_ref_kind": "exact_commit_sha",
    }
    result = {provider["id"]: provider}
    for repository in ORG_TARGET["repositories"]:
        name = repository.split("/")[1]
        row = {
            "id": f"{name}.jev-issue-comment.consumer", "kind": "envs.providerConsumerBoundary.v1",
            "role": "consumer", "repository": repository, "stage": "dev", "capability": "jev-api",
            "owns": ["trusted_caller_admission", "provider_effect", "same_issue_result_append", "result_readback"],
            "requires": ["org_secret", "exact_binding_handoff", "finite_budget_stop"],
        }
        result[row["id"]] = row
    return result


def expected_rent_boundary() -> dict[str, Any]:
    # envs ends at the target-bound ciphertext PR; apply, client access and SSH acceptance are other owners' effects.
    return {
        "id": "dev.rent-tunnel.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-tunnel",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "bounded_retrieval", "single_recipient_encryption", "ciphertext_handoff_pr",
                 "target_placement_entry"],
        "does_not_own": ["target_apply", "target_age_identity", "client_access_credential", "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_client_boundary() -> dict[str, Any]:
    # envs projects the root output and ships the entrance; the provider apply, running it on the target, the
    # target's identity and the Windows slot writer belong to others.
    return {
        "id": "dev.rent-client.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-client",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "root_output_projection", "single_recipient_encryption", "target_placement_entry"],
        "does_not_own": ["provider_apply", "target_apply", "target_age_identity", "client_slot_writer",
                         "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_root_boundary() -> dict[str, Any]:
    # envs owns the entry that applies the declared root and seals its output; the effect, its authority, the state
    # backend and key custody, the targets and their identities belong to others.
    return {
        "id": "dev.rent-root.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-root",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "root_orchestration_entry", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["provider_apply_authority", "state_backend_custody", "encryption_key_custody", "target_apply",
                         "target_age_identity", "client_slot_writer", "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_windows_consumer(source: str) -> dict[str, Any]:
    # The exact resources source whose published Windows Release (windows-<source>) the placement gate binds.
    return {
        "id": WINDOWS_CONSUMER,
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "consumer",
        "repository": "roccho-dev/resources",
        "stage": "dev",
        "capability": "rent-client",
        "distribution_source": source,
        "owns": ["client_slot_format", "client_slot_writer", "consumer_launcher", "rent_slot_format"],
        "requires": ["exact_release", "release_publication_success", "target_native_slot"],
    }


def expected_oci_boundary() -> dict[str, Any]:
    # envs ends at the target-bound ciphertext PR; the target applies it and apps proves its own runtime.
    return {
        "id": "dev.jev-api-oci-dev.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "jev-api",
        "binding": OCI_BINDING,
        "source_kind": "ephemeral_ingress",
        "target_kind": "public_sops",
        "owns": ["contract", "target_selected_authoring", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["target_apply", "target_age_identity", "application_runtime_acceptance", "deployment"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_own_jev_boundary() -> dict[str, Any]:
    return {**expected_oci_boundary(), "id": "dev.jev-api-versapro-own-oci.provider", "binding": OWN_JEV_BINDING}


def expected_go_boundary() -> dict[str, Any]:
    return {
        "id": "dev.opencode-go-oci-dev.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-org/envs",
        "stage": "dev",
        "capability": "opencode-go",
        "binding": GO_BINDING,
        "source_kind": "ephemeral_ingress",
        "target_kind": "public_sops",
        "owns": ["contract", "target_selected_authoring", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["target_apply", "target_age_identity", "application_runtime_acceptance", "deployment"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_own_go_boundary() -> dict[str, Any]:
    return {**expected_go_boundary(), "id": "dev.opencode-go-versapro-own-oci.provider", "binding": OWN_GO_BINDING}


def expected_typellm_boundary() -> dict[str, Any]:
    return {**expected_go_boundary(), "id": "dev.typellm-api-oci-dev.provider",
            "capability": "typellm-api", "binding": TYPELLM_BINDING}


def expected_own_typellm_boundary() -> dict[str, Any]:
    return {**expected_typellm_boundary(), "id": "dev.typellm-api-versapro-own-oci.provider",
            "binding": OWN_TYPELLM_BINDING}


def expected_inputs() -> dict[str, dict[str, list[dict[str, str]]]]:
    def entries(*values: tuple[str, str, str]) -> list[dict[str, str]]:
        return [{"name": name, "type": kind, "lifecycle": lifecycle} for name, kind, lifecycle in values]

    def stage_projection() -> dict[str, list[dict[str, str]]]:
        return {
            "required_secrets": entries(
                ("JEV_API_KEY", "opaque", "persistent"),
                ("CLOUDFLARE_API_TOKEN", "opaque", "persistent"),
            ),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        }

    return {
        "dev.authoring": {
            "required_secrets": entries(("JEV_API_KEY", "opaque", "one_shot_ingress")),
            "required_variables": entries(("SOPS_AGE_RECIPIENTS", "age_recipient_list", "persistent")),
        },
        GO_PLANE: {
            "required_secrets": entries((GO_KEY, "opaque", "one_shot_ingress")),
            "required_variables": entries((OCI_RECIPIENT, "age_recipient", "persistent"),
                                          (OWN_GO_RECIPIENT, "age_recipient", "persistent")),
        },
        TYPELLM_PLANE: {
            "required_secrets": entries((TYPELLM_KEY, "opaque", "one_shot_ingress")),
            "required_variables": entries((OCI_RECIPIENT, "age_recipient", "persistent"),
                                          (OWN_TYPELLM_RECIPIENT, "age_recipient", "persistent")),
        },
        WORKER_GO_PLANE: {
            "required_secrets": entries(("SOPS_AGE_KEY", "age_identity", "persistent"),
                                        ("PI_CLOUDFLARE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        },
        "dev.projection": {
            "required_secrets": entries(
                ("SOPS_AGE_KEY", "age_identity", "persistent"),
                ("CLOUDFLARE_API_TOKEN", "opaque", "persistent"),
            ),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        },
        "stg.projection": stage_projection(),
        "prd.projection": stage_projection(),
        # Rent stage ingress shares dev-projection under its own RENT_CLOUDFLARE_* slots (RENT_CLOUDFLARE_INPUTS).
        RENT_PLANE: {
            "required_secrets": entries(("RENT_CLOUDFLARE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(
                ("RENT_CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("RENT_TUNNEL_ID", "cloudflare_tunnel_id", "persistent"),
                ("RENT_AGE_RECIPIENT", "age_recipient", "persistent"),
            ),
        },
        # The client plane is an output only: its credential arrives from the root's sensitive output and its one
        # recipient is declared once, by the producing root below, so it has no ingress or Environment of its own.
        # The persistent root's plane names every input the apply reads.
        ROOT_PLANE: {
            "required_secrets": entries(*((name, "opaque", "persistent") for name in ROOT_SECRETS)),
            "required_variables": entries(
                ("RENT_CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("RENT_CLOUDFLARE_ZONE_ID", "cloudflare_zone_id", "persistent"),
                ("RENT_HOSTNAME", "opaque", "persistent"),
                ("RENT_ORIGIN_SERVICE", "opaque", "persistent"),
                ("RENT_SERVICE_TOKEN_DURATION", "opaque", "persistent"),
                ("RENT_STATE_BUCKET", "opaque", "persistent"),
                ("RENT_STATE_KEY", "opaque", "persistent"),
                ("RENT_AGE_RECIPIENT", "age_recipient", "persistent"),
                (CLIENT_RECIPIENT, "age_recipient", "persistent"),
            ),
        },
        LINODE_READ_PLANE: {
            "required_secrets": entries(("LINODE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(),
        },
    }


def recipient_items(value: str) -> list[str] | None:
    items = value.split(",")
    if all(AGE_RECIPIENT.fullmatch(item) for item in items) and len(items) == len(set(items)):
        return items
    return None


def is_age_identity(value: str) -> bool:
    # Native age-keygen output: comment and blank lines plus exactly one X25519 identity.
    lines = [line.strip() for line in value.splitlines()]
    identities = [line for line in lines if line and not line.startswith("#")]
    return len(identities) == 1 and AGE_IDENTITY.fullmatch(identities[0]) is not None


INPUT_TYPES: dict[str, Callable[[str], bool]] = {
    "opaque": lambda value: True,
    "age_identity": is_age_identity,
    "age_recipient_list": lambda value: recipient_items(value) is not None,
    "age_recipient": lambda value: AGE_RECIPIENT.fullmatch(value) is not None,
    "cloudflare_account_id": lambda value: CLOUDFLARE_ACCOUNT_ID.fullmatch(value) is not None,
    "cloudflare_tunnel_id": lambda value: CLOUDFLARE_TUNNEL_ID.fullmatch(value) is not None,
    "cloudflare_zone_id": lambda value: CLOUDFLARE_ACCOUNT_ID.fullmatch(value) is not None,
    "cloudflare_api_token_id": lambda value: CLOUDFLARE_TOKEN_ID.fullmatch(value) is not None,
}


def validate_contracts(root: Path = ROOT) -> dict[str, dict[str, dict[str, Any]]]:
    envs = index(root / ENVIRONMENTS)
    bindings = index(root / BINDINGS)
    boundary = index(root / BOUNDARY)

    require(set(envs) == {
        "dev.authoring", GO_PLANE, TYPELLM_PLANE, WORKER_GO_PLANE, "dev.projection", "dev.runtime", RENT_PLANE, CLIENT_PLANE, ROOT_PLANE, LINODE_READ_PLANE,
        "stg.projection", "stg.runtime", "prd.projection", "prd.runtime",
        "voice-ui.dev", "voice-ui.stg", "voice-ui.prd",
    }, "environment set differs")

    require(envs["dev.authoring"]["github_environment"] == "dev-authoring", "dev authoring Environment differs")
    for plane_id in (GO_PLANE, TYPELLM_PLANE):
        plane = envs[plane_id]
        require(plane["github_environment"] == "dev-authoring" and plane["owner"] == "envs"
                and plane["source_kind"] == "ephemeral_ingress" and plane["target_kind"] == "public_sops"
                and plane["active_github_environment"] is None and plane["migration_state"] == "NOT_CONFIGURED",
                f"{plane_id} source-only authoring plane differs")
    rent = envs[RENT_PLANE]
    require(rent["github_environment"] == RENT_ENVIRONMENT and rent["owner"] == "envs"
            and rent["source_kind"] == "provider_issued" and rent["target_kind"] == "public_sops",
            "dev rent tunnel plane differs")
    require(envs["dev.projection"]["github_environment"] == "dev-projection", "dev projection Environment differs")
    inputs = expected_inputs()
    for identity, row in envs.items():
        if row["kind"] != "envs.secretPlane.v1":
            continue
        declared = inputs.get(identity, {})
        extra = {"state_backend"} if identity == ROOT_PLANE else set()
        require(set(row) == SECRET_PLANE_KEYS | set(declared) | extra, f"{identity} fields differ")
        require((row["github_environment"] is not None) == bool(declared), f"{identity} required inputs differ")
        for group, entries in declared.items():
            require(row[group] == entries, f"{identity} {group} differ")

    for stage in ("dev", "stg", "prd"):
        runtime = envs[f"{stage}.runtime"]
        require(runtime["owner"] == "target", f"{stage}.runtime must be target-owned")
        require(runtime["github_environment"] is None, f"{stage}.runtime must not be a GitHub Environment")
        app = envs[f"voice-ui.{stage}"]
        require(app == {
            "id": f"voice-ui.{stage}", "kind": "envs.applicationEnvironment.v1",
            "application": "voice-ui", "environment": stage, "binding_ref": "voice-ui",
        }, f"voice-ui.{stage} differs")

    for stage in ("stg", "prd"):
        item = envs[f"{stage}.projection"]
        require(item["migration_state"] == "NOT_CONFIGURED", f"{stage}.projection must be NOT_CONFIGURED")
        require(item["active_github_environment"] is None, f"{stage}.projection must not be active")

    cipher = root / CIPHERTEXT
    if cipher.is_file():
        for identity, name in (("dev.authoring", "dev-authoring"), ("dev.projection", "dev-projection")):
            item = envs[identity]
            require(item["active_github_environment"] == name, f"{identity} active Environment differs")
            require(item["migration_state"] == "ACTIVE", f"{identity} must be ACTIVE")
        validate_ciphertext(cipher.read_bytes(), None, None)
    else:
        for identity in ("dev.authoring", "dev.projection"):
            item = envs[identity]
            require(item["active_github_environment"] is None, f"{identity} must not be active")
            require(item["migration_state"] == "NOT_CONFIGURED", f"{identity} must be NOT_CONFIGURED")

    rent_cipher = root / RENT_CIPHERTEXT
    if rent_cipher.is_file():
        require(rent["active_github_environment"] == RENT_ENVIRONMENT and rent["migration_state"] == "ACTIVE",
                f"{RENT_PLANE} must be ACTIVE with its ciphertext")
        validate_rent_ciphertext(rent_cipher.read_bytes(), None, None)
    else:
        require(rent["active_github_environment"] is None and rent["migration_state"] == "NOT_CONFIGURED",
                f"{RENT_PLANE} must be NOT_CONFIGURED without its ciphertext")

    # The client plane is an output plane: no Environment, no ingress of its own; ACTIVE still records its sealed envelope.
    client = envs[CLIENT_PLANE]
    require(client["github_environment"] is None and client["active_github_environment"] is None
            and client["owner"] == "envs"
            and client["source_kind"] == "provider_issued" and client["target_kind"] == "public_sops",
            f"{CLIENT_PLANE} plane differs")
    client_cipher = root / CLIENT_CIPHERTEXT
    if client_cipher.is_file():
        require(client["migration_state"] == "ACTIVE", f"{CLIENT_PLANE} must be ACTIVE with its ciphertext")
        validate_client_ciphertext(client_cipher.read_bytes(), None, None)
    else:
        require(client["migration_state"] == "NOT_CONFIGURED", f"{CLIENT_PLANE} must be NOT_CONFIGURED without its ciphertext")

    # The persistent root has no ciphertext of its own: ACTIVE records only that it sealed both envelopes above
    # (declared plane state, not proof that the Environment, the provider or the backend is configured).
    root_plane = envs[ROOT_PLANE]
    require(root_plane["github_environment"] == rent["github_environment"] and root_plane["owner"] == "envs"
            and root_plane["source_kind"] == "provider_issued" and root_plane["target_kind"] == "public_sops",
            f"{ROOT_PLANE} plane differs")
    # The GitHub-ref state location: this repository's stable identity, a dedicated ref, a state path unique in it and
    # the upstream backend's own lock ref for that path.
    backend = root_plane["state_backend"]
    require(backend == ROOT_STATE_BACKEND and backend["lock_ref"] == "refs/heads/locks/" + backend["state_path"]
            and sum(1 for row in envs.values() if row.get("state_backend", {}).get("state_path") == backend["state_path"]
                    and row.get("state_backend", {}).get("repository") == backend["repository"]) == 1,
            f"{ROOT_PLANE} GitHub-ref state backend differs")
    if root_plane["migration_state"] == "ACTIVE":
        require(root_plane["active_github_environment"] == RENT_ENVIRONMENT and rent_cipher.is_file()
                and client_cipher.is_file(), f"{ROOT_PLANE} is ACTIVE only with both envelopes")
    else:
        require(root_plane["active_github_environment"] is None and root_plane["migration_state"] == "NOT_CONFIGURED",
                f"{ROOT_PLANE} must be NOT_CONFIGURED until it sealed both envelopes")

    # Rent shares the dev-projection trust boundary but never the Pages/Mail Cloudflare slots, and no plane names a
    # retired host-specific Environment or the retired R2 parent token.
    for identity, row in envs.items():
        require(row.get("github_environment") not in RETIRED_ENVIRONMENTS
                and row.get("active_github_environment") not in RETIRED_ENVIRONMENTS,
                f"{identity} names a retired host-specific Environment")
        names = {entry["name"] for group in ("required_secrets", "required_variables") for entry in row.get(group, [])}
        require(not any(name.startswith("R2_PARENT_") for name in names), f"{identity} requires the retired R2 parent token")
        if identity in (RENT_PLANE, ROOT_PLANE):
            require(not names & set(RENT_CLOUDFLARE_INPUTS.values()), f"{identity} reads a Pages/Mail Cloudflare slot")

    linode = envs[LINODE_READ_PLANE]
    require(linode["github_environment"] == "dev-projection" and linode["owner"] == "envs"
            and linode["source_kind"] == "provider_issued" and linode["target_kind"] == "read_probe"
            and linode["active_github_environment"] is None and linode["migration_state"] == "NOT_CONFIGURED",
            f"{LINODE_READ_PLANE} must be a NOT_CONFIGURED read-only probe plane")

    # The OCI target has no state of its own: its ciphertext, when present, is simply valid or RED.
    for path in JEV_CIPHERTEXTS.values():
        if (root / path).is_file():
            validate_oci_ciphertext((root / path).read_bytes(), None, None)
    for path in GO_CIPHERTEXTS.values():
        if (root / path).is_file():
            validate_oci_ciphertext((root / path).read_bytes(), None, None, key=GO_KEY)
    for path in TYPELLM_CIPHERTEXTS.values():
        if (root / path).is_file():
            validate_oci_ciphertext((root / path).read_bytes(), None, None, key=TYPELLM_KEY)

    jev_target = validate_jev_target(bindings.get("jev-api", {}).get("target"))
    require(bindings == expected_bindings(jev_target), "binding set differs")
    require(set(boundary) == {
        WORKER_GO_BOUNDARY, "repository.branch-policy", "dev.jev-api.provider", "dev.rent-tunnel.provider",
        "dev.jev-api-oci-dev.provider", "apps.voice-ui.consumer", "ops.voice-ui.consumer",
        "normal.consumer.path", "dev.rent-client.provider", "dev.rent-root.provider", WINDOWS_CONSUMER,
        "dev.opencode-go-oci-dev.provider", "dev.opencode-go-versapro-own-oci.provider",
        "dev.typellm-api-oci-dev.provider", "dev.typellm-api-versapro-own-oci.provider",
        "dev.jev-api-versapro-own-oci.provider",
    } | set(expected_org_boundaries()), "provider-consumer boundary set differs")
    for identity, expected in expected_org_boundaries().items():
        require(boundary[identity] == expected, "Org provider-consumer boundary differs")
    require(boundary[WORKER_GO_BOUNDARY] == expected_worker_go_boundary(), "OpenCode Worker boundary differs")
    worker_plane = envs[WORKER_GO_PLANE]
    require(worker_plane["github_environment"] == "dev-projection" and worker_plane["owner"] == "envs"
            and worker_plane["source_kind"] == "public_sops" and worker_plane["target_kind"] == "target_native_auth",
            "OpenCode Worker projection plane differs")
    if (root / WORKER_GO_CIPHER).is_file():
        validate_worker_go_ciphertext((root / WORKER_GO_CIPHER).read_bytes())
    configured = (root / WORKER_GO_HANDOFF).is_file()
    require(worker_plane["migration_state"] == ("ACTIVE" if configured else "NOT_CONFIGURED")
            and worker_plane["active_github_environment"] == ("dev-projection" if configured else None),
            "OpenCode Worker projection state differs")
    if configured:
        validate_worker_go_receipt(json.loads((root / WORKER_GO_HANDOFF).read_text()), root)
    require(boundary["dev.rent-tunnel.provider"] == expected_rent_boundary(), "rent tunnel provider boundary differs")
    require(boundary["dev.rent-client.provider"] == expected_client_boundary(), "rent client provider boundary differs")
    require(boundary["dev.rent-root.provider"] == expected_root_boundary(), "rent root provider boundary differs")
    source = boundary[WINDOWS_CONSUMER].get("distribution_source")
    require(isinstance(source, str) and SHA40.fullmatch(source) is not None
            and boundary[WINDOWS_CONSUMER] == expected_windows_consumer(source), "windows rent consumer boundary differs")
    require(boundary["dev.jev-api-oci-dev.provider"] == expected_oci_boundary(), "OCI dev provider boundary differs")
    require(boundary["dev.jev-api-versapro-own-oci.provider"] == expected_own_jev_boundary(),
            "Jev own OCI provider boundary differs")
    require(boundary["dev.opencode-go-oci-dev.provider"] == expected_go_boundary(),
            "OpenCode Go provider boundary differs")
    require(boundary["dev.opencode-go-versapro-own-oci.provider"] == expected_own_go_boundary(),
            "OpenCode Go own OCI provider boundary differs")
    require(boundary["dev.typellm-api-oci-dev.provider"] == expected_typellm_boundary(),
            "TypeLLM OCI provider boundary differs")
    require(boundary["dev.typellm-api-versapro-own-oci.provider"] == expected_own_typellm_boundary(),
            "TypeLLM own OCI provider boundary differs")
    require(boundary["repository.branch-policy"] == {
        "id": "repository.branch-policy", "kind": "envs.branchPolicy.v1",
        "canonical_branch": "proposals", "default_branch": "proposals",
        "retained_compatibility_branches": ["main"],
        "direct_change_forbidden": ["main"],
        "effect_source_branches": ["proposals"],
        "handoff_ref_kind": "exact_commit_sha",
    }, "branch policy differs")
    require(boundary["dev.jev-api.provider"]["does_not_own"] == [
        "application_runtime_acceptance", "consumer_independent_execution",
    ], "provider must not own consumer readiness")
    return {"environments": envs, "bindings": bindings, "boundary": boundary}


def default_runner(argv: Sequence[str], input_data: bytes | None, env: Mapping[str, str] | None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv), input=input_data, env=None if env is None else dict(env),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False,
    )


def run_checked(argv: Sequence[str], *, label: str, input_data: bytes | None = None,
                env: Mapping[str, str] | None = None, runner: Runner = default_runner) -> subprocess.CompletedProcess[bytes]:
    result = runner(argv, input_data, env)
    require(result.returncode == 0, f"{label} failed")
    return result


def without_recipient_metadata(text: str) -> str:
    return RECIPIENT_METADATA.sub("", text)


def validate_ciphertext(data: bytes, secret: bytes | None, recipients: list[str] | None, key: str = "JEV_API_KEY") -> None:
    text = data.decode("utf-8", errors="strict")
    require(f"{key}: ENC[AES256_GCM," in text and "\nsops:" in text, "invalid SOPS ciphertext")
    require(not any(pattern.search(text) for pattern in PRIVATE_MATERIAL), "private material found in ciphertext")
    if secret is not None:
        require(secret not in data, "plaintext survived encryption")
    actual = RECIPIENT_METADATA.findall(text)
    require(bool(actual) and len(actual) == len(set(actual)), "ciphertext recipient metadata is invalid")
    require(all(AGE_RECIPIENT.fullmatch(value) for value in actual), "ciphertext recipient metadata is invalid")
    if recipients is not None:
        require(sorted(actual) == sorted(recipients), "ciphertext recipient set differs")
    body = without_recipient_metadata(text)
    require(not any(value in body for value in actual), "ciphertext recipient outside sops metadata")


def validate_rent_ciphertext(data: bytes, token: bytes | None, recipient: str | None) -> None:
    validate_ciphertext(data, token, None if recipient is None else [recipient], key=RENT_KEY)
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "rent tunnel ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {RENT_KEY, "sops"}, "rent tunnel ciphertext fields differ")


def validate_client_ciphertext(data: bytes, values: Sequence[bytes] | None, recipient: str | None) -> None:
    for index, key in enumerate(CLIENT_KEYS):
        validate_ciphertext(data, None if values is None else values[index], None if recipient is None else [recipient], key=key)
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "rent client ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {*CLIENT_KEYS, "sops"}, "rent client ciphertext fields differ")


def validate_oci_ciphertext(data: bytes, secret: bytes | None, recipient: str | None,
                            key: str = "JEV_API_KEY") -> None:
    require(key in {"JEV_API_KEY", GO_KEY, TYPELLM_KEY}, "OCI dev ciphertext key unsupported")
    validate_ciphertext(data, secret, None if recipient is None else [recipient], key=key)
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "OCI dev ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {key, "sops"}, "OCI dev ciphertext fields differ")


def repository_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
        and path.suffix != ".pyc"
    )


def reject_live_values(root: Path, name: str, values: list[str],
                       allowed_paths: tuple[str, ...] = ()) -> None:
    for path in repository_files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if relative in {WORKER_GO_CIPHER.as_posix(), CIPHERTEXT.as_posix(), RENT_CIPHERTEXT.as_posix(), CLIENT_CIPHERTEXT.as_posix(),
                        *(path.as_posix() for path in OCI_CIPHERTEXTS.values())}:
            data = without_recipient_metadata(data.decode("utf-8", errors="replace")).encode()
        for value in values:
            if value.encode() in data:
                require(relative in allowed_paths, f"{relative}: live {name} value is stored in Git")


def gate(root: Path, contracts: dict[str, dict[str, dict[str, Any]]], plane: str,
         only: Iterable[str] | None = None) -> dict[str, str]:
    # `only` reads a declared subset of the plane's inputs (an output plane uses its producer's declaration).
    row = contracts["environments"][plane]
    selected = None if only is None else set(only)
    declared = [entry for entry in row["required_secrets"] + row["required_variables"]
                if selected is None or entry["name"] in selected]
    require(selected is None or {entry["name"] for entry in declared} == selected, f"{plane}: undeclared input selected")
    values: dict[str, str] = {}
    for entry in declared:
        name, kind = entry["name"], entry["type"]
        value = os.environ.get(name, "")
        require(value != "", f"{plane}: {name} is missing")
        require(INPUT_TYPES[kind](value), f"{plane}: {name} is not a valid {kind}")
        values[name] = value
    for entry in row["required_variables"]:
        if entry["name"] not in values:
            continue
        value = values[entry["name"]]
        live = recipient_items(value) if entry["type"] == "age_recipient_list" else [value]
        allowed_paths: tuple[str, ...] = ()
        if entry["name"] in ("CLOUDFLARE_ACCOUNT_ID", "RENT_CLOUDFLARE_ACCOUNT_ID"):
            target = contracts["bindings"]["jev-api"]["target"]
            if target.get("provider") == "cloudflare-workers":
                # Only the projection account must be the Workers target's; the rent slot is never assumed equal.
                require(entry["name"] != "CLOUDFLARE_ACCOUNT_ID" or value == target["account_id"],
                        "Workers target account differs from projection account")
                # Account ID is a non-secret target identifier. It may occur only in the
                # closed selected binding and its non-secret handoff receipt; every other
                # repository occurrence remains rejected.
                allowed_paths = (BINDINGS.as_posix(), HANDOFF.as_posix())
        if plane == WORKER_GO_PLANE and entry["name"] == "CLOUDFLARE_ACCOUNT_ID":
            require(value == WORKER_GO_TARGET["account_id"], "OpenCode Worker account differs")
            # This fixed public account identifier is allowed only in the declared target, adapter and receipt.
            allowed_paths = (BINDINGS.as_posix(), WORKER_GO_HANDOFF.as_posix(), "adapters/jev_api.py")
        reject_live_values(root, entry["name"], live or [], allowed_paths)
    return values


def set_dev_active(root: Path, active: bool, planes: Iterable[str] = ("dev.authoring", "dev.projection")) -> None:
    rows = load_jsonl(root / ENVIRONMENTS)
    selected = set(planes)
    for row in rows:
        if row.get("id") in selected:
            row["active_github_environment"] = row["github_environment"] if active else None
            row["migration_state"] = "ACTIVE" if active else "NOT_CONFIGURED"
    write_jsonl(root / ENVIRONMENTS, rows)


def locked_nixpkgs(root: Path) -> dict[str, str]:
    try:
        lock = json.loads((root / FLAKE_LOCK).read_text(encoding="utf-8"))
        nodes = lock["nodes"]
        locked = nodes[nodes[lock["root"]]["inputs"]["nixpkgs"]]["locked"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise EnvsError("flake.lock does not lock nixpkgs") from exc
    require(isinstance(locked, dict) and {key: locked.get(key) for key in ("type", "owner", "repo")} == {
        "type": "github", "owner": "NixOS", "repo": "nixpkgs",
    }, "flake.lock nixpkgs source differs")
    rev, nar_hash = locked.get("rev"), locked.get("narHash")
    require(isinstance(rev, str) and SHA40.fullmatch(rev) is not None, "flake.lock nixpkgs revision is not exact")
    require(isinstance(nar_hash, str) and nar_hash.startswith("sha256-"), "flake.lock nixpkgs narHash is not exact")
    return {"rev": rev, "narHash": nar_hash}


def in_store(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    path = Path(value)
    return path.is_absolute() and len(path.parts) > len(STORE.parts) and path.parts[:len(STORE.parts)] == STORE.parts


def toolchain(root: Path, environ: Mapping[str, str] | None = None, executable: str | None = None) -> dict[str, str]:
    # The flake entry exports this manifest; without it, or on any mismatch, no tool runs.
    manifest = (os.environ if environ is None else environ).get("ENVS_EFFECT_TOOLCHAIN", "")
    require(in_store(manifest), "repo-owned effect toolchain is missing")
    try:
        value = json.loads(Path(manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvsError("repo-owned effect toolchain manifest is unreadable") from exc
    require(isinstance(value, dict) and set(value) == {"kind", "nixpkgs", "source", "tools"}
            and value["kind"] == TOOLCHAIN_KIND, "effect toolchain manifest differs")
    require(isinstance(value["source"], str) and SHA40.fullmatch(value["source"]) is not None,
            "effect toolchain source is not an exact commit")
    require(value["nixpkgs"] == locked_nixpkgs(root), "effect toolchain differs from flake.lock")
    try:
        same_adapter = (root / "adapters/jev_api.py").read_bytes() == Path(__file__).read_bytes()
    except OSError as exc:
        raise EnvsError("checkout adapter is unreadable") from exc
    require(same_adapter, "checkout adapter differs from the effect toolchain")
    tools = value["tools"]
    require(isinstance(tools, dict) and set(tools) == set(TOOLCHAIN_TOOLS), "effect toolchain tool set differs")
    for name in TOOLCHAIN_TOOLS:
        path = tools[name]
        require(in_store(path) and os.path.isfile(path) and os.access(path, os.X_OK), f"effect toolchain {name} is missing")
    current = os.path.realpath(sys.executable if executable is None else executable)
    require(current == os.path.realpath(tools["python3"]), "adapter interpreter is not the repo-owned python3")
    return dict(tools)


def clean_env(tools: Mapping[str, str], extra: Mapping[str, str]) -> dict[str, str]:
    result = {key: value for key, value in os.environ.items() if key in {"HOME", "TMPDIR", "LANG", "LC_ALL", "CI"}}
    result["PATH"] = os.pathsep.join(sorted({os.path.dirname(path) for path in tools.values()}))
    result.update(extra)
    return result


def author(root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, "dev.authoring")
    source = inputs["JEV_API_KEY"]
    recipients = recipient_items(inputs["SOPS_AGE_RECIPIENTS"]) or []

    payload = json.dumps({"JEV_API_KEY": source}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": ",".join(recipients)}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_ciphertext(result.stdout, source.encode(), recipients)
    target = root / CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(result.stdout)
    set_dev_active(root, True)
    stale = root / HANDOFF
    if stale.exists():
        stale.unlink()
    validate_contracts(root)
    return {"kind": "envs.authoringResult.v1", "status": "PASS", "ciphertext": CIPHERTEXT.as_posix()}


def validate_worker_go_ciphertext(data: bytes, secret: bytes | None = None,
                                 recipients: list[str] | None = None) -> None:
    validate_ciphertext(data, secret, recipients, key=GO_KEY)
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", data.decode())) == {GO_KEY, "sops"},
            "OpenCode Worker ciphertext fields differ")


def set_worker_go_active(root: Path, active: bool) -> None:
    path = root / ENVIRONMENTS
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    row = next(item for item in rows if item["id"] == WORKER_GO_PLANE)
    row.update(active_github_environment="dev-projection" if active else None,
               migration_state="ACTIVE" if active else "NOT_CONFIGURED")
    path.write_text("".join(json.dumps(item, separators=(",", ":")) + "\n" for item in rows))


def author_worker_go(root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    values = {}
    for entry in authoring_inputs(contracts, WORKER_GO_BINDING):
        value = os.environ.get(entry["name"], "")
        require(bool(value) and INPUT_TYPES[entry["type"]](value), "OpenCode Worker authoring input invalid")
        values[entry["name"]] = value
    source = values[GO_KEY]
    recipients = recipient_items(values["SOPS_AGE_RECIPIENTS"]) or []
    require(bool(recipients), "OpenCode Worker recipient is missing")
    reject_live_values(root, GO_KEY, [source])
    reject_live_values(root, "SOPS_AGE_RECIPIENTS", recipients)
    result = run_checked([tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
                         input_data=json.dumps({GO_KEY: source}, separators=(",", ":")).encode() + b"\n",
                         env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": ",".join(recipients)}),
                         runner=runner, label="OpenCode Worker SOPS encryption")
    validate_worker_go_ciphertext(result.stdout, source.encode(), recipients)
    output = root / WORKER_GO_CIPHER
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result.stdout)
    (root / WORKER_GO_HANDOFF).unlink(missing_ok=True)
    set_worker_go_active(root, False)
    validate_contracts(root)
    return {"kind": "envs.targetAuthoringResult.v1", "status": "PASS", "binding": WORKER_GO_BINDING,
            "ciphertext": WORKER_GO_CIPHER.as_posix(), "recipient_count": len(recipients), "provider_use": "NOT_RUN"}


def validate_worker_go_receipt(receipt: dict[str, Any], root: Path = ROOT) -> None:
    require(set(receipt) == {"kind", "status", "envs_sha", "capability", "binding", "source", "target", "effect",
                             "readback", "workflow", "created_at", "provider_use"}, "OpenCode Worker receipt fields differ")
    require(receipt["kind"] == "envs.opencodeWorkerProjectionReceipt.v1" and receipt["status"] == "PASS"
            and receipt["capability"] == "opencode-go" and receipt["binding"] == WORKER_GO_BINDING,
            "OpenCode Worker receipt identity differs")
    require(isinstance(receipt["envs_sha"], str) and SHA40.fullmatch(receipt["envs_sha"]), "invalid envs SHA")
    cipher = root / WORKER_GO_CIPHER
    require(cipher.is_file() and receipt["source"] == {"kind": "public_sops", "ref": WORKER_GO_CIPHER.as_posix(),
            "sha256": "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest()}, "OpenCode Worker source differs")
    require(receipt["target"] == WORKER_GO_TARGET, "OpenCode Worker receipt target differs")
    require(receipt["effect"] == {"operation": "cloudflare_workers_secret_put", "status": "PASS"}, "OpenCode Worker effect differs")
    require(receipt["readback"] == {"kind": "secret_name_presence", "status": "PASS", "present": True}, "OpenCode Worker readback differs")
    wf = receipt["workflow"]
    require(isinstance(wf, dict) and set(wf) == {"repository", "ref", "run_id", "run_attempt"} and wf["repository"] == "roccho-org/envs"
            and wf["ref"] == "proposals" and type(wf["run_id"]) is int and wf["run_id"] > 0
            and type(wf["run_attempt"]) is int and wf["run_attempt"] > 0, "OpenCode Worker workflow differs")
    require(receipt["provider_use"] == "NOT_RUN", "registration must not claim inference")
    require(isinstance(receipt["created_at"], str) and receipt["created_at"].endswith("Z"), "invalid receipt time")
    try:
        datetime.fromisoformat(receipt["created_at"][:-1] + "+00:00")
    except ValueError:
        raise EnvsError("invalid receipt time") from None
    walk_receipt(receipt)


def project_worker_go(*, envs_sha: str, run_id: int, run_attempt: int, created_at: str,
                      root: Path = ROOT, runner: Runner = default_runner, opener=None) -> dict[str, Any]:
    contracts = validate_contracts(root)
    require(isinstance(envs_sha, str) and SHA40.fullmatch(envs_sha), "expected exact envs SHA")
    require(type(run_id) is int and run_id > 0 and type(run_attempt) is int and run_attempt > 0, "invalid workflow identity")
    require(isinstance(created_at, str) and created_at.endswith("Z"), "invalid receipt time")
    try:
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError:
        raise EnvsError("invalid receipt time") from None
    target = contracts["bindings"][WORKER_GO_BINDING]["target"]
    require(target == WORKER_GO_TARGET, "OpenCode Worker target differs")
    cipher = root / WORKER_GO_CIPHER
    require(cipher.is_file(), "OpenCode Worker ciphertext is not configured")
    tools = toolchain(root)
    inputs = gate(root, contracts, WORKER_GO_PLANE)
    provider_env = clean_env(tools, {"CLOUDFLARE_ACCOUNT_ID": inputs["CLOUDFLARE_ACCOUNT_ID"],
                                  "CLOUDFLARE_API_TOKEN": inputs["PI_CLOUDFLARE_API_TOKEN"]})
    argv = [tools["wrangler"], "secret", "list", "--name", target["worker_name"], "--format", "json"]
    # Existing Worker before decrypt; the shared PUT primitive cannot create a draft on a deletion race.
    preflight = run_checked(argv, env=provider_env, runner=runner, label="OpenCode Worker existence preflight")
    parse_workers_secret_list(preflight.stdout)
    decrypted = run_checked([tools["sops"], "--decrypt", "--output-type", "json", str(cipher)],
                            env=clean_env(tools, {"SOPS_AGE_KEY": inputs["SOPS_AGE_KEY"]}),
                            runner=runner, label="OpenCode Worker SOPS decryption").stdout
    try:
        payload = json.loads(decrypted)
    except (ValueError, UnicodeError):
        raise EnvsError("OpenCode Worker decrypted payload invalid") from None
    require(isinstance(payload, dict) and set(payload) == {GO_KEY}, "OpenCode Worker decrypted fields differ")
    secret = payload[GO_KEY]
    require(isinstance(secret, str) and bool(secret), "OpenCode Worker key is empty")
    if opener is None:
        def opener(request, *, timeout, context):
            return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect).open(request, timeout=timeout)
    _workers_secret_put(account_id=target["account_id"], worker_name=target["worker_name"],
                        secret_name=target["secret_name"], secret=secret,
                        token=inputs["PI_CLOUDFLARE_API_TOKEN"], opener=opener)
    readback = run_checked(argv, env=provider_env, runner=runner, label="OpenCode Worker secret readback")
    parse_workers_secret_list(readback.stdout, target["secret_name"])
    receipt = {"kind": "envs.opencodeWorkerProjectionReceipt.v1", "status": "PASS", "envs_sha": envs_sha,
               "capability": "opencode-go", "binding": WORKER_GO_BINDING,
               "source": {"kind": "public_sops", "ref": WORKER_GO_CIPHER.as_posix(),
                          "sha256": "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest()},
               "target": dict(target), "effect": {"operation": "cloudflare_workers_secret_put", "status": "PASS"},
               "readback": {"kind": "secret_name_presence", "status": "PASS", "present": True},
               "workflow": {"repository": "roccho-org/envs", "ref": "proposals", "run_id": run_id, "run_attempt": run_attempt},
               "created_at": created_at, "provider_use": "NOT_RUN"}
    validate_worker_go_receipt(receipt, root)
    output = root / WORKER_GO_HANDOFF
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    set_worker_go_active(root, True)
    validate_contracts(root)
    return receipt


def authoring_inputs(contracts: dict[str, dict[str, dict[str, Any]]], target: str) -> list[dict[str, str]]:
    # A selected author target reads only its own source plane and recipient. The GitHub Environment
    # can be shared without leaking one source key into another target's process environment.
    require(target in AUTHOR_TARGETS, f"unknown author target: {target}")
    plane_id = TYPELLM_PLANE if target in TYPELLM_CIPHERTEXTS else GO_PLANE if target in GO_CIPHERTEXTS or target == WORKER_GO_BINDING else "dev.authoring"
    plane = contracts["environments"][plane_id]
    if target == "jev-api":
        return plane["required_secrets"] + plane["required_variables"]
    binding = contracts["bindings"][target]
    require(binding["github_environment"] == plane["github_environment"], f"{target} Environment differs")
    source = [entry for entry in plane["required_secrets"] if entry["name"] == binding["source_key"]]
    require(len(source) == 1, f"{target} source secret is not declared")
    return source + binding["required_variables"]


def encrypt_oci_key(source: str, recipient: str, tools: Mapping[str, str], runner: Runner = default_runner,
                    key: str = "JEV_API_KEY") -> bytes:
    # The selected key reaches SOPS on stdin only; the ciphertext must name exactly one recipient and source field.
    require(key in {"JEV_API_KEY", GO_KEY, TYPELLM_KEY}, "OCI dev source field unsupported")
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "OCI dev target needs exactly one age recipient")
    require(source != "", "OCI dev source key is empty")
    payload = json.dumps({key: source}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_oci_ciphertext(result.stdout, source.encode(), recipient, key=key)
    return result.stdout


def author_oci(root: Path = ROOT, runner: Runner = default_runner, target: str = OCI_BINDING) -> dict[str, Any]:
    # Writes only the selected OCI ciphertext: no plane state, handoff or other target's file.
    require(target in OCI_CIPHERTEXTS, "OCI author target not declared")
    contracts = validate_contracts(root)
    tools = toolchain(root)
    binding = contracts["bindings"][target]
    source_key = binding["source_key"]
    # Each target names exactly one recipient variable; another target's recipient is never a fallback.
    require(len(binding["required_variables"]) == 1, f"{target} must name exactly one recipient")
    recipient_name = binding["required_variables"][0]["name"]
    values: dict[str, str] = {}
    for entry in authoring_inputs(contracts, target):
        name, kind = entry["name"], entry["type"]
        value = os.environ.get(name, "")
        require(value != "", f"{target}: {name} is missing")
        require(INPUT_TYPES[kind](value), f"{target}: {name} is not a valid {kind}")
        values[name] = value
    # Secret and Variable alike: a value already in Git is RED before SOPS runs.
    reject_live_values(root, recipient_name, [values[recipient_name]])
    reject_live_values(root, source_key, [values[source_key]])
    data = encrypt_oci_key(values[source_key], values[recipient_name], tools, runner, key=source_key)
    ciphertext_path = OCI_CIPHERTEXTS[target]
    require(binding["ciphertext"] == ciphertext_path.as_posix(), "selected ciphertext differs")
    output = root / ciphertext_path
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    validate_contracts(root)
    return {
        "kind": "envs.targetAuthoringResult.v1", "status": "PASS", "binding": target,
        "ciphertext": ciphertext_path.as_posix(), "recipient_count": 1,
        "target_apply": "NOT_RUN", "application_runtime": "NOT_RUN",
    }


Fetch = Callable[[urllib.request.Request, float], bytes]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect is RED; the bearer token is never re-sent to another location.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def default_fetch(request: urllib.request.Request, timeout: float) -> bytes:
    # The entry exports the repo-owned CA bundle; errors never carry the response or the request headers.
    bundle = os.environ.get("SSL_CERT_FILE", "")
    require(in_store(bundle) and os.path.isfile(bundle), "repo-owned CA bundle is missing")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=bundle)), NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(RESPONSE_LIMIT + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise EnvsError("Cloudflare tunnel token retrieval failed") from None
    require(len(body) <= RESPONSE_LIMIT, "Cloudflare response exceeds its bound")
    return body


def retrieve_tunnel_token(account: str, tunnel: str, api_token: str, fetch: Fetch = default_fetch) -> str:
    # One GET, bounded in time and size; the token is returned in memory only.
    require(CLOUDFLARE_ACCOUNT_ID.fullmatch(account) is not None, "invalid Cloudflare account ID")
    require(CLOUDFLARE_TUNNEL_ID.fullmatch(tunnel) is not None, "invalid Cloudflare tunnel ID")
    require(BEARER.fullmatch(api_token) is not None, "invalid Cloudflare API token shape")
    request = urllib.request.Request(
        f"{CLOUDFLARE_API}/accounts/{account}/cfd_tunnel/{tunnel}/token",
        headers={"Authorization": f"Bearer {api_token}", "Accept": "application/json"},
        method="GET",
    )
    body = fetch(request, RETRIEVAL_TIMEOUT)
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError("Cloudflare response is not JSON") from None
    require(isinstance(value, dict) and value.get("success") is True, "Cloudflare did not return success")
    token = value.get("result")
    require(isinstance(token, str) and TUNNEL_TOKEN.fullmatch(token) is not None, "Cloudflare returned no valid tunnel token")
    return token


def encrypt_rent_token(token: str, recipient: str, tools: Mapping[str, str], runner: Runner = default_runner,
                       home: str | None = None) -> bytes:
    # The token reaches SOPS on stdin only; the ciphertext must name exactly this one recipient. A given home replaces
    # the inherited HOME (rent-root's fresh one); without it the standalone entries keep their existing environment.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "rent tunnel needs exactly one age recipient")
    require(TUNNEL_TOKEN.fullmatch(token) is not None, "invalid tunnel token")
    payload = json.dumps({RENT_KEY: token}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient, **({} if home is None else {"HOME": home})}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_rent_ciphertext(result.stdout, token.encode(), recipient)
    return result.stdout


def rent_author(root: Path = ROOT, runner: Runner = default_runner, fetch: Fetch = default_fetch) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, RENT_PLANE)
    # Secrets as well as Variables: a value already in Git is RED before the provider call, the token before SOPS.
    reject_live_values(root, "RENT_CLOUDFLARE_API_TOKEN", [inputs["RENT_CLOUDFLARE_API_TOKEN"]])
    token = retrieve_tunnel_token(
        inputs["RENT_CLOUDFLARE_ACCOUNT_ID"], inputs["RENT_TUNNEL_ID"], inputs["RENT_CLOUDFLARE_API_TOKEN"], fetch)
    reject_live_values(root, RENT_KEY, [token])
    data = encrypt_rent_token(token, inputs["RENT_AGE_RECIPIENT"], tools, runner)
    target = root / RENT_CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    set_dev_active(root, True, (RENT_PLANE,))
    validate_contracts(root)
    return {
        "kind": "envs.rentTunnelAuthoringResult.v1", "status": "PASS", "ciphertext": RENT_CIPHERTEXT.as_posix(),
        "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


def encrypt_client_credential(client_id: str, secret: str, recipient: str, tools: Mapping[str, str],
                              runner: Runner = default_runner, home: str | None = None) -> bytes:
    # Both values reach SOPS on stdin only; each must be one line of the windows slot rule, for exactly one recipient.
    # A given home replaces the inherited HOME, as for encrypt_rent_token.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "rent client needs exactly one age recipient")
    require(SLOT_LINE.fullmatch(client_id) is not None and SLOT_LINE.fullmatch(secret) is not None,
            "invalid Access client credential")
    payload = json.dumps(dict(zip(CLIENT_KEYS, (client_id, secret))), separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient, **({} if home is None else {"HOME": home})}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_client_ciphertext(result.stdout, (client_id.encode(), secret.encode()), recipient)
    return result.stdout


def client_pair(value: Any, root: Path) -> tuple[str, str]:
    # The root's credentials object: its service token pair, each one line of the windows slot rule, never in Git.
    require(isinstance(value, dict) and set(value) == set(PROBE_CREDENTIALS), "root output is not the credentials object")
    client_id, secret = value["service_token_id"], value["service_token_value"]
    require(isinstance(client_id, str) and isinstance(secret, str) and SLOT_LINE.fullmatch(client_id) is not None
            and SLOT_LINE.fullmatch(secret) is not None, "invalid Access client credential")
    reject_live_values(root, "rent client credential", [client_id, secret])
    return client_id, secret


def client_author(credentials: bytes, root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    # The persistent root's sensitive `credentials` output (tofu output -json credentials) arrives on stdin; only its
    # service token pair is projected. Nothing is printed but this result, which carries no value.
    contracts = validate_contracts(root)
    tools = toolchain(root)
    # The output plane has no ingress: its one recipient is the producing root's declared RENT_CLIENT_AGE_RECIPIENT.
    inputs = gate(root, contracts, ROOT_PLANE, only=(CLIENT_RECIPIENT,))
    require(len(credentials) <= RESPONSE_LIMIT, "root output exceeds its bound")
    try:
        value = json.loads(credentials)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError("root output is not JSON") from None
    client_id, secret = client_pair(value, root)
    data = encrypt_client_credential(client_id, secret, inputs[CLIENT_RECIPIENT], tools, runner)
    target = root / CLIENT_CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    set_dev_active(root, True, (CLIENT_PLANE,))
    validate_contracts(root)
    return {
        "kind": "envs.rentClientAuthoringResult.v1", "status": "PASS", "ciphertext": CLIENT_CIPHERTEXT.as_posix(),
        "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


def root_env(tools: Mapping[str, str], inputs: Mapping[str, str], home: Path) -> dict[str, str]:
    # Only the OpenTofu child gets these: the API token, the backend credential and endpoint, the fixed encryption
    # (pbkdf2 key provider and aes_gcm method, both k0, for state and plan) and the root's five inputs. The rent
    # RENT_CLOUDFLARE_* slots reach it only under the provider-native names (RENT_CLOUDFLARE_INPUTS).
    return clean_env(tools, {
        "CLOUDFLARE_API_TOKEN": inputs["RENT_CLOUDFLARE_API_TOKEN"],
        "AWS_ACCESS_KEY_ID": inputs["AWS_ACCESS_KEY_ID"], "AWS_SECRET_ACCESS_KEY": inputs["AWS_SECRET_ACCESS_KEY"],
        "AWS_ENDPOINT_URL_S3": r2_endpoint(inputs["RENT_CLOUDFLARE_ACCOUNT_ID"]), "AWS_EC2_METADATA_DISABLED": "true",
        "TF_ENCRYPTION": encryption_config(ROOT_KEY_NAME, inputs["RENT_STATE_PASSPHRASE"]),
        "TF_VAR_account_id": inputs["RENT_CLOUDFLARE_ACCOUNT_ID"], "TF_VAR_zone_id": inputs["RENT_CLOUDFLARE_ZONE_ID"],
        "TF_VAR_hostname": inputs["RENT_HOSTNAME"], "TF_VAR_origin_service": inputs["RENT_ORIGIN_SERVICE"],
        "TF_VAR_service_token_duration": inputs["RENT_SERVICE_TOKEN_DURATION"],
        "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "HOME": str(home),
    })


def seal_root_output(root: Path, tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner,
                     rent_recipient: str, client_recipient: str, progress: dict[str, str] | None = None) -> dict[str, Any]:
    # The applied root's sensitive credentials output stays in this process: both envelopes are sealed before the
    # first write. A failure before that write changes no file; one at or after it may leave an unpublished partial
    # diff that is reported, never cleaned up or claimed.
    progress = {} if progress is None else progress
    progress["stage"] = "output"
    value = output(tools, work, env, runner, "credentials", PROBE_CREDENTIALS)
    progress["stage"] = "seal"
    client_id, secret = client_pair(value, root)
    token = value["tunnel_token"]
    require(isinstance(token, str) and TUNNEL_TOKEN.fullmatch(token) is not None, "root output has no valid tunnel token")
    reject_live_values(root, RENT_KEY, [token])
    # The sops children share the run's fresh HOME, never the caller's, and get only their one recipient.
    home = env["HOME"]
    sealed = ((RENT_CIPHERTEXT, encrypt_rent_token(token, rent_recipient, tools, runner, home)),
              (CLIENT_CIPHERTEXT, encrypt_client_credential(client_id, secret, client_recipient, tools, runner, home)))
    progress["stage"] = "write"
    for relative, data in sealed:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    set_dev_active(root, True, (RENT_PLANE, CLIENT_PLANE, ROOT_PLANE))
    validate_contracts(root)
    return {
        "kind": "envs.rentRootResult.v1", "status": "PASS",
        "ciphertexts": [RENT_CIPHERTEXT.as_posix(), CLIENT_CIPHERTEXT.as_posix()],
        "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


def rent_root(root: Path = ROOT, runner: Runner = default_runner, progress: dict[str, str] | None = None) -> dict[str, Any]:
    # Standard OpenTofu applies the declared root on its native backend; no destroy, import, adoption or retry here.
    # progress["stage"] names how far it got, so a failure is reported as a closed kind and stage only; a captured
    # non-zero init child also leaves progress["init_hint"], its closed and unverified failure facts.
    progress = {} if progress is None else progress
    # S2: the root now declares the GitHub-ref HTTP backend, so this S3-era apply refuses before any input or child
    # until a separately reviewed activation source re-binds it.
    progress["stage"] = "source_guard"
    require(ROOT_APPLY_SOURCE_ACTIVE, "rent-root apply is source-hard-inactive")
    progress["stage"] = "gate"
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, ROOT_PLANE)
    require(ROOT_PASSPHRASE.fullmatch(inputs["RENT_STATE_PASSPHRASE"]) is not None,
            f"{ROOT_PLANE}: RENT_STATE_PASSPHRASE is not 64 lowercase hex")
    for name in ROOT_SECRETS:
        reject_live_values(root, name, [inputs[name]])
    # A fresh owner-only scratch per run (an empty HOME and the root's working copy). It is retained, never deleted:
    # automated recursive deletion is forbidden, so it lasts as long as the runner's temporary space.
    scratch = Path(tempfile.mkdtemp(prefix="envs-rent-root-"))
    home, work = scratch / "home", scratch / "root"
    home.mkdir(mode=0o700)
    work.mkdir()
    (work / "main.tf").write_bytes((root / ROOT_CONFIG).read_bytes())
    env = root_env(tools, inputs, home)
    progress["stage"] = "init"

    def init_runner(argv: Sequence[str], input_data: bytes | None,
                    child_env: Mapping[str, str] | None) -> subprocess.CompletedProcess[bytes]:
        # Observed text patterns only, not a cause: the status enum and two booleans, never output or wording.
        result = runner(argv, input_data, child_env)
        if result.returncode != 0:
            facts = failure_facts(result)
            progress["init_hint"] = (f"status={facts['status']} access_denied={str(facts['access_denied']).lower()} "
                                     f"transient={str(facts['transient']).lower()}")
        return result

    tofu(tools, work, env, init_runner, "init", "-input=false", "-no-color",
         f"-backend-config=bucket={inputs['RENT_STATE_BUCKET']}", f"-backend-config=key={inputs['RENT_STATE_KEY']}")
    progress["stage"] = "apply"
    tofu(tools, work, env, runner, "apply", "-input=false", "-auto-approve", "-no-color")
    return seal_root_output(root, tools, work, env, runner, inputs["RENT_AGE_RECIPIENT"], inputs[CLIENT_RECIPIENT],
                            progress)


Spawn = Callable[[Sequence[str], Mapping[str, str]], Any]


def default_spawn(argv: Sequence[str], env: Mapping[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(list(argv), env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, shell=False)


def stop(process: Any) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def tofu(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner, *args: str) -> bytes:
    # Output may carry sensitive values: it is parsed, never printed, and a failure names only the command.
    return run_checked([tools["tofu"], f"-chdir={work}", *args], env=env, runner=runner,
                       label=f"OpenTofu {args[0]}").stdout


def output(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner, name: str,
           keys: Sequence[str]) -> dict[str, Any]:
    try:
        value = json.loads(tofu(tools, work, env, runner, "output", "-json", name))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError(f"OpenTofu output {name} is not JSON") from None
    require(isinstance(value, dict) and set(value) == set(keys), f"OpenTofu output {name} differs")
    return value


# A Cloudflare API call returns (HTTP status, parsed JSON or None); a transport failure is UNKNOWN, never a status.
Api = Callable[[str, str, str, Any], tuple[int, Any]]


def default_api(method: str, path: str, token: str, body: Any) -> tuple[int, Any]:
    # Same bounds as the tunnel token GET; errors never carry the response, the request headers or the token.
    bundle = os.environ.get("SSL_CERT_FILE", "")
    require(in_store(bundle) and os.path.isfile(bundle), "repo-owned CA bundle is missing")
    require(BEARER.fullmatch(token) is not None, "invalid Cloudflare API token shape")
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{CLOUDFLARE_API}{path}", data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=bundle)), NoRedirect)
    try:
        with opener.open(request, timeout=RETRIEVAL_TIMEOUT) as response:
            status, raw = response.status, response.read(RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(RESPONSE_LIMIT + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise EnvsError("Cloudflare request outcome is UNKNOWN") from None
    require(len(raw) <= RESPONSE_LIMIT, "Cloudflare response exceeds its bound")
    try:
        return status, (json.loads(raw) if raw else None)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None


def encryption_config(name: str, passphrase: str, fallback: tuple[str, str] | None = None) -> str:
    # TF_ENCRYPTION text with per-run pbkdf2 passphrases; it reaches OpenTofu only through the process environment.
    # OpenTofu binds encrypted metadata to the key provider and method names, so a key keeps its name for life: a
    # rotation adds a new name and keeps the old key under its original name as the fallback.
    blocks = [f'key_provider "pbkdf2" "{key}" {{\n  passphrase = "{value}"\n}}\n'
              f'method "aes_gcm" "{key}" {{\n  keys = key_provider.pbkdf2.{key}\n}}\n'
              for key, value in [(name, passphrase), *([fallback] if fallback else [])]]
    tail = f"  fallback {{\n    method = method.aes_gcm.{fallback[0]}\n  }}\n" if fallback else ""
    blocks += [f"{target} {{\n  method = method.aes_gcm.{name}\n{tail}}}\n" for target in ("state", "plan")]
    return "".join(blocks)


def failure_facts(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    # The captured output is classified in memory and never printed: only these finite facts leave this function.
    text = result.stderr + result.stdout
    statuses = set(STATE_STATUS.findall(text))
    code = next(iter(statuses)) if len(statuses) == 1 else None
    status = "none" if not statuses else "multiple" if code is None else code.decode() if code in {b"401", b"403"} \
        else "5xx" if code.startswith(b"5") else "other"
    lowered = text.lower()
    word = next((word for word in ("decrypt", "encrypt", "credential") if word.encode() in lowered), "none")
    return {"status": status, "access_denied": b"AccessDenied" in text,
            "transient": STATE_TRANSIENT.search(text) is not None, "word": word}


def failure_cause(result: subprocess.CompletedProcess[bytes]) -> str:
    # An S3 status wins over wording; 401 is the credential as a whole, 403 AccessDenied is its scope; transport
    # noise or any other status is UNKNOWN.
    facts = failure_facts(result)
    if facts["transient"] or facts["status"] in {"5xx", "multiple", "other"}:
        return "unknown"
    if facts["status"] == "401":
        return "unauthorized"
    if facts["status"] == "403":
        return "access_denied" if facts["access_denied"] else "unknown"
    return {"decrypt": "decryption", "encrypt": "encryption", "credential": "credential"}.get(facts["word"], "unknown")


def refusal(control: bool, attempt: subprocess.CompletedProcess[bytes], causes: set[str]) -> str:
    if attempt.returncode == 0:
        return "ADMITTED"
    return "REFUSED" if control and failure_cause(attempt) in causes else "UNKNOWN"


def r2_endpoint(account: str) -> str:
    return f"https://{account}.r2.cloudflarestorage.com"


def curl_value(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rent_inspect_head(tools: Mapping[str, str], inputs: Mapping[str, str], runner: Runner, object_key: str) -> str:
    # The existing persistent root's exact R2 object or native .tflock.
    # curl's SigV4 config enters through stdin only: no secret argv, file,
    # shell, proxy, redirect, request body or retry. Never emit response bytes.
    account = inputs["RENT_CLOUDFLARE_ACCOUNT_ID"]
    bucket = inputs["RENT_STATE_BUCKET"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", bucket) is not None and ".." not in bucket,
            "rent inspect bucket is not a closed R2 object name")
    base = object_key[:-len(ROOT_LOCK_SUFFIX)] if object_key.endswith(ROOT_LOCK_SUFFIX) else object_key
    require(root_state_key_ok(base), "rent inspect object key is not bounded")
    endpoint = r2_endpoint(account)
    lines = [
        f"url = {curl_value(f'{endpoint}/{bucket}/{object_key}')}",
        'request = "HEAD"', 'aws-sigv4 = "aws:amz:auto:s3"',
        f"user = {curl_value(inputs['AWS_ACCESS_KEY_ID'] + ':' + inputs['AWS_SECRET_ACCESS_KEY'])}",
        'proto = "=https"', 'noproxy = "*"', "silent",
        'connect-timeout = "10"', 'max-time = "30"',
        'write-out = "%{stderr}%{http_code}"',
    ]
    if os.environ.get("SSL_CERT_FILE"):
        require(in_store(os.environ["SSL_CERT_FILE"]), "rent inspect CA bundle is not Nix-owned")
        lines.append(f"cacert = {curl_value(os.environ['SSL_CERT_FILE'])}")
    result = runner([tools["curl"], "-q", "-I", "--config", "-"],
                    ("\n".join(lines) + "\n").encode(), clean_env(tools, {}))
    code = result.stderr.strip()
    require(result.returncode == 0 and code in (b"200", b"404")
            and len(result.stdout) <= 4096, "rent inspect S3 HEAD is UNKNOWN")
    return "PRESENT" if code == b"200" else "ABSENT"


def root_scratch(prefix: str) -> tuple[Path, Path]:
    # A fresh owner-only scratch (an empty HOME and the root's working copy), retained like rent-root's.
    scratch = Path(tempfile.mkdtemp(prefix=prefix))
    home, work = scratch / "home", scratch / "root"
    home.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    return home, work


def legacy_root_env(tools: Mapping[str, str], inputs: Mapping[str, str], home: Path) -> dict[str, str]:
    # Only what the former S3 state needs: its R2 credential and endpoint and the state encryption. No provider token.
    return clean_env(tools, {
        "HOME": str(home), "AWS_ACCESS_KEY_ID": inputs["AWS_ACCESS_KEY_ID"],
        "AWS_SECRET_ACCESS_KEY": inputs["AWS_SECRET_ACCESS_KEY"],
        "AWS_ENDPOINT_URL_S3": r2_endpoint(inputs["RENT_CLOUDFLARE_ACCOUNT_ID"]),
        "AWS_EC2_METADATA_DISABLED": "true",
        "TF_ENCRYPTION": encryption_config(ROOT_KEY_NAME, inputs["RENT_STATE_PASSPHRASE"]),
        "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
    })


def root_state_identity(payload: bytes) -> dict[str, Any]:
    # The root's own state, in memory only: a lineage, a positive serial and exactly the six owned resources.
    require(0 < len(payload) <= ROOT_INSPECT_STATE_LIMIT, "rent-root state size UNKNOWN")
    try:
        state = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise EnvsError("rent-root state is not valid JSON") from None
    require(isinstance(state, dict) and isinstance(state.get("lineage"), str) and state["lineage"]
            and type(state.get("serial")) is int and state["serial"] > 0,
            "rent-root state identity UNKNOWN")
    resources = state.get("resources")
    require(isinstance(resources, list), "rent-root managed resource set UNKNOWN")
    managed = [item for item in resources if isinstance(item, dict) and item.get("mode") == "managed"]
    require(len(managed) == len(ROOT_INSPECT_RESOURCE_TYPES)
            and {item.get("type") for item in managed} == ROOT_INSPECT_RESOURCE_TYPES
            and all(item.get("name") == "rent" for item in managed),
            "rent-root state owned-resource identity UNKNOWN")
    return state


def legacy_root_state(tools: Mapping[str, str], inputs: Mapping[str, str], work: Path, env: Mapping[str, str],
                      runner: Runner) -> dict[str, Any]:
    # The former S3 backend from source alone (the root itself now declares HTTP); state pull reads it into memory.
    (work / "main.tf").write_text(ROOT_LEGACY_S3_CONFIG, encoding="utf-8")
    tofu(tools, work, env, runner, "init", "-input=false", "-no-color",
         f"-backend-config=bucket={inputs['RENT_STATE_BUCKET']}", f"-backend-config=key={inputs['RENT_STATE_KEY']}")
    return root_state_identity(tofu(tools, work, env, runner, "state", "pull"))


LocalGet = Callable[[str], tuple[int, bytes]]


def default_local_get(url: str) -> tuple[int, bytes]:
    # The loopback backend only: no proxy or retry, and the reply stays in this process.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=5) as reply:
            return reply.status, reply.read(ROOT_INSPECT_STATE_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError):
        return 0, b""


def loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def root_backend_url(port: int) -> str:
    query = urllib.parse.urlencode({
        "type": "git", "repository": f"https://github.com/{ROOT_STATE_BACKEND['repository']}.git",
        "ref": ROOT_STATE_BACKEND["ref"].removeprefix("refs/heads/"), "state": ROOT_STATE_BACKEND["state_path"],
    })
    return f"http://127.0.0.1:{port}/?{query}"


def root_backend_config(url: str) -> list[str]:
    # The standard HTTP backend's own state and lock protocol against the loopback child.
    return [f"-backend-config=address={url}", f"-backend-config=lock_address={url}",
            f"-backend-config=unlock_address={url}", "-backend-config=lock_method=LOCK",
            "-backend-config=unlock_method=UNLOCK"]


def root_ref_principal(root: Path) -> str:
    token = os.environ.get(ROOT_STATE_GIT_TOKEN, "")
    require(BEARER.fullmatch(token) is not None, "rent-root state ref principal is not bound")
    reject_live_values(root, ROOT_STATE_GIT_TOKEN, [token])
    return token


def start_root_backend(tools: Mapping[str, str], home: Path, token: str, spawn: Spawn, local_get: LocalGet,
                       sleep: Callable[[float], None]) -> tuple[Any, str, str]:
    # One transient upstream child on loopback for this one operation; only it receives the ref principal. Its GET is
    # the standard HTTP backend read: 200 with a body is PRESENT, 204 or 404 ABSENT, anything else UNKNOWN.
    port = loopback_port()
    url = root_backend_url(port)
    process = spawn([tools["terraform_backend_git"], "--address", f"127.0.0.1:{port}"],
                    clean_env(tools, {"HOME": str(home), "GIT_USERNAME": ROOT_STATE_GIT_USERNAME,
                                      ROOT_STATE_GIT_TOKEN: token}))
    try:
        for _ in range(ROOT_BACKEND_READY_ATTEMPTS):
            require(process.poll() is None, "rent-root state backend exited")
            status, body = local_get(url)
            if status == 200 and body.strip():
                return process, url, "PRESENT"
            if status in (204, 404):
                return process, url, "ABSENT"
            require(status == 0, "rent-root GitHub-ref state is UNKNOWN")
            sleep(0.2)
        raise EnvsError("rent-root state backend not ready")
    except BaseException:
        stop(process)
        raise


def root_s3_inventory(tools: Mapping[str, str], inputs: Mapping[str, str], runner: Runner) -> None:
    key = inputs["RENT_STATE_KEY"]
    require(root_state_key_ok(key), "rent-root requires the declared old-S3 state key")
    require(rent_inspect_head(tools, inputs, runner, key) == "PRESENT", "rent-root old-S3 state missing or UNKNOWN")
    require(rent_inspect_head(tools, inputs, runner, key + ROOT_LOCK_SUFFIX) == "ABSENT",
            "rent-root old-S3 lock present or UNKNOWN")


def rent_root_migrate(root: Path = ROOT, *, runner: Runner = default_runner, spawn: Spawn = default_spawn,
                      local_get: LocalGet = default_local_get, sleep: Callable[[float], None] = time.sleep,
                      progress: dict[str, str] | None = None) -> dict[str, Any]:
    # Standard OpenTofu backend migration of the existing state from the former S3 backend to the GitHub-ref HTTP
    # backend, holding both native locks: same lineage and resources, the serial kept or advanced once by the
    # migration write. The former object is retained; no plan, apply, import, unlock or retry.
    progress = {} if progress is None else progress
    progress["stage"] = "source_guard"
    require(ROOT_MIGRATE_SOURCE_ACTIVE, "rent-root backend migration is source-hard-inactive")
    progress["stage"] = "contracts"
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, ROOT_PLANE)
    require(ROOT_PASSPHRASE.fullmatch(inputs["RENT_STATE_PASSPHRASE"]) is not None,
            "rent-root migration encryption input invalid")
    for name in ROOT_SECRETS:
        reject_live_values(root, name, [inputs[name]])
    token = root_ref_principal(root)
    progress["stage"] = "s3_head"
    root_s3_inventory(tools, inputs, runner)
    progress["stage"] = "state_read"
    home, work = root_scratch("envs-rent-migrate-")
    env = legacy_root_env(tools, inputs, home)
    before = legacy_root_state(tools, inputs, work, env, runner)
    progress["stage"] = "backend"
    process, url, target = start_root_backend(tools, home, token, spawn, local_get, sleep)
    try:
        require(target == "ABSENT", "rent-root GitHub-ref state already present or UNKNOWN; no overwrite")
        progress["stage"] = "migrate"
        (work / "main.tf").write_bytes((root / ROOT_CONFIG).read_bytes())
        tofu(tools, work, env, runner, "init", "-input=false", "-no-color", "-migrate-state", "-force-copy",
             "-lock=true", *root_backend_config(url))
        progress["stage"] = "readback"
        after = root_state_identity(tofu(tools, work, env, runner, "state", "pull"))
    finally:
        stop(process)
    require(after["lineage"] == before["lineage"] and after["resources"] == before["resources"]
            and after["serial"] in (before["serial"], before["serial"] + 1),
            "rent-root migrated state identity differs")
    progress["stage"] = "complete"
    return {
        "kind": "envs.rentRootMigrate.v1", "status": "BACKEND_MIGRATED", "lineage": "UNCHANGED",
        "resources": "UNCHANGED", "serial": "UNCHANGED" if after["serial"] == before["serial"] else "MIGRATION_WRITE",
        "old_state": "RETAINED", "plan": "NOT_RUN", "apply": "NOT_RUN",
    }


def rent_root_plan(root: Path = ROOT, *, runner: Runner = default_runner, spawn: Spawn = default_spawn,
                   local_get: LocalGet = default_local_get, sleep: Callable[[float], None] = time.sleep,
                   progress: dict[str, str] | None = None) -> dict[str, Any]:
    # Backend-only proof: the unchanged root planned by standard OpenTofu against the existing GitHub-ref state must
    # be empty. Any planned change, or a plan failure, refuses. Nothing is applied, imported or saved.
    progress = {} if progress is None else progress
    progress["stage"] = "source_guard"
    require(ROOT_PLAN_SOURCE_ACTIVE, "rent-root backend-only plan is source-hard-inactive")
    progress["stage"] = "contracts"
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, ROOT_PLANE)
    require(ROOT_PASSPHRASE.fullmatch(inputs["RENT_STATE_PASSPHRASE"]) is not None,
            "rent-root plan encryption input invalid")
    for name in ROOT_SECRETS:
        reject_live_values(root, name, [inputs[name]])
    token = root_ref_principal(root)
    home, work = root_scratch("envs-rent-plan-")
    (work / "main.tf").write_bytes((root / ROOT_CONFIG).read_bytes())
    env = {key: value for key, value in root_env(tools, inputs, home).items() if not key.startswith("AWS_")}
    progress["stage"] = "backend"
    process, url, target = start_root_backend(tools, home, token, spawn, local_get, sleep)
    try:
        require(target == "PRESENT", "rent-root GitHub-ref state absent or UNKNOWN; nothing to plan against")
        progress["stage"] = "init"
        tofu(tools, work, env, runner, "init", "-input=false", "-no-color", "-lock=true", *root_backend_config(url))
        progress["stage"] = "plan"
        result = runner([tools["tofu"], f"-chdir={work}", "plan", "-input=false", "-no-color", "-lock=true",
                         "-detailed-exitcode"], None, env)
    finally:
        stop(process)
    require(result.returncode == 0, "rent-root backend-only plan is not empty or failed; no apply")
    progress["stage"] = "complete"
    return {"kind": "envs.rentRootPlan.v1", "status": "EMPTY_PLAN", "apply": "NOT_RUN", "saved_plan": "NONE"}


# One bounded Cloudflare inventory page holds at most this many items; the route asks for exactly this page size.
ROOT_CLOUDFLARE_PAGE = 50
# Closed HTTP reasons; every other non-200 status is http_other. The number itself never leaves.
ROOT_CLOUDFLARE_HTTP = {401: "http_auth", 403: "http_auth", 404: "http_not_found", 429: "http_rate"}


def rent_inspect_page(label: str, path: str, token: str, api: Api, progress: dict[str, str]) -> int:
    # One GET of one route's first page. Each refusal names its route and closed reason as the stage, in this order:
    # token_shape, request, http_*, response, page_shape, completeness. No status, message, body or identifier leaves.
    def reason(name: str) -> None:
        progress["stage"] = f"cloudflare_{label}_{name}"

    reason("token_shape")
    require(BEARER.fullmatch(token) is not None, "rent-root Cloudflare token shape is invalid")
    reason("request")
    status, reply = api("GET", path, token, None)
    if status != 200:
        reason(ROOT_CLOUDFLARE_HTTP.get(status, "http_other"))
        raise EnvsError("rent-root Cloudflare read status is not 200")
    reason("response")
    require(isinstance(reply, dict) and reply.get("success") is True, "rent-root Cloudflare read is UNKNOWN")
    # Only the fields every route's public schema declares: page, count and total_count, each an int and never a
    # bool. total_pages is optional (the tunnel list does not declare it) and, when present, an int too.
    reason("page_shape")
    values, page = reply.get("result"), reply.get("result_info")
    require(isinstance(values, list) and isinstance(page, dict)
            and all(type(page.get(name)) is int for name in ("page", "count", "total_count"))
            and ("total_pages" not in page or type(page["total_pages"]) is int),
            "rent-root Cloudflare inventory page shape is UNKNOWN")
    # The whole inventory is this one first page: no other page is followed and the bound is not raised. An empty
    # list may report total_pages 0 or 1; a non-empty one only 1.
    reason("completeness")
    require(len(values) <= ROOT_CLOUDFLARE_PAGE and page["page"] == 1
            and page["count"] == len(values) and page["total_count"] == len(values)
            and ("total_pages" not in page or page["total_pages"] in ((1,) if values else (0, 1))),
            "rent-root Cloudflare inventory is not one complete page")
    return len(values)


def rent_root_inspect(root: Path = ROOT, *, runner: Runner = default_runner,
                      api: Api = default_api, progress: dict[str, str] | None = None) -> dict[str, Any]:
    # First gate is compile-time/source-owned and cannot be flipped by env,
    # a workflow input or CLI argument. Tests patch it only with fake children.
    progress = {} if progress is None else progress
    progress["stage"] = "source_guard"
    require(ROOT_INSPECT_SOURCE_ACTIVE, "rent-root inspect is source-hard-inactive")
    # Each preflight names its own closed stage, so a refusal says which check failed and never with what value.
    progress["stage"] = "contracts"
    contracts = validate_contracts(root)
    progress["stage"] = "toolchain"
    tools = toolchain(root)
    progress["stage"] = "inputs"
    inputs = gate(root, contracts, ROOT_PLANE)
    progress["stage"] = "encryption_input"
    require(ROOT_PASSPHRASE.fullmatch(inputs["RENT_STATE_PASSPHRASE"]) is not None,
            "rent-root inspect encryption input invalid")
    progress["stage"] = "secret_live"
    for name in ROOT_SECRETS:
        reject_live_values(root, name, [inputs[name]])
    progress["stage"] = "state_key"
    key = inputs["RENT_STATE_KEY"]
    require(root_state_key_ok(key), "rent-root inspect requires the declared old-S3 state key")

    # The old S3 state and its native lock are each classified PRESENT or ABSENT; only an unanswerable HEAD is
    # UNKNOWN and stops red here. An absent state or a held lock is reported, and the state is then not read.
    progress["stage"] = "s3_head"
    old_state = rent_inspect_head(tools, inputs, runner, key)
    old_lock = rent_inspect_head(tools, inputs, runner, key + ROOT_LOCK_SUFFIX)
    identity: dict[str, Any] = {"old_state_read": "NOT_READ", "lineage": None, "serial": None,
                                "managed_root_resources": None}
    if old_state == "PRESENT" and old_lock == "ABSENT":
        # Existing RootRunner/standard OpenTofu, in an owner-only scratch: init
        # configures ONLY old S3 and state pull reads it; no plan/apply/import/write.
        # State plaintext remains in process memory; the receipt carries only its identity.
        progress["stage"] = "state_read"
        home, work = root_scratch("envs-rent-inspect-")
        state = legacy_root_state(tools, inputs, work, legacy_root_env(tools, inputs, home), runner)
        require(ROOT_STATE_LINEAGE.fullmatch(state["lineage"]) is not None, "rent-root state lineage UNKNOWN")
        managed = [item for item in state["resources"] if item.get("mode") == "managed"]
        identity = {"old_state_read": "ENCRYPTED_READ", "lineage": state["lineage"], "serial": state["serial"],
                    "managed_root_resources": len(managed)}

    # Cloudflare GET-only bounded pages. Counts intentionally do not claim
    # object identity, equality to state, complete Q or an accepted delta.
    progress["stage"] = "cloudflare_read"
    account, zone, token = (inputs[name] for name in
                            ("RENT_CLOUDFLARE_ACCOUNT_ID", "RENT_CLOUDFLARE_ZONE_ID", "RENT_CLOUDFLARE_API_TOKEN"))
    routes = (
        ("tunnels", f"/accounts/{account}/cfd_tunnel?per_page=50"),
        ("applications", f"/accounts/{account}/access/apps?per_page=50"),
        ("service_tokens", f"/accounts/{account}/access/service_tokens?per_page=50"),
        ("dns", f"/zones/{zone}/dns_records?per_page=50"),
    )
    # The tunnel list is unfiltered, so its count includes deleted tunnels: a count, not a live inventory.
    counts: dict[str, int] = {}
    for label, path in routes:
        counts[label] = rent_inspect_page(label, path, token, api, progress)
    progress["stage"] = "complete"
    return {
        "kind": "envs.rentRootInspect.v1", "status": "BOUNDED_READ_ONLY",
        "old_state": old_state, "old_lock": old_lock, **identity, "cloudflare_counts": counts,
        "world_state_equivalence": "NOT_PROVEN", "provider_delta_F": "NOT_PROVEN",
        "native_migration": "NOT_RUN", "effect": "NONE",
    }

def failure_class(error: BaseException) -> str:
    # One of the handled failure kinds, never its message or class name.
    return "envs" if isinstance(error, EnvsError) else "subprocess" if isinstance(error, subprocess.SubprocessError) \
        else "os"


def walk_receipt(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(key not in FORBIDDEN_RECEIPT_KEYS, f"forbidden receipt key {key}")
            walk_receipt(item)
    elif isinstance(value, list):
        for item in value:
            walk_receipt(item)
    elif isinstance(value, str):
        require(not any(pattern.search(value) for pattern in PRIVATE_MATERIAL), "private material found in receipt")


def _receipt_operation(target: dict[str, Any]) -> str:
    validate_jev_target(target)
    return "cloudflare_workers_secret_put" if target["provider"] == "cloudflare-workers" \
        else "cloudflare_pages_secret_put"


def parse_workers_secret_list(stdout: bytes, expected_name: str | None = None) -> list[dict[str, str]]:
    require(len(stdout) <= RESPONSE_LIMIT, "Workers secret list output too large")
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EnvsError("Workers secret list output is not JSON") from exc
    require(isinstance(value, list) and len(value) <= 10000, "Workers secret list shape differs")
    names: set[str] = set()
    rows: list[dict[str, str]] = []
    for item in value:
        require(isinstance(item, dict) and set(item) == {"name", "type"},
                "Workers secret list entry fields differ")
        name, kind = item["name"], item["type"]
        require(isinstance(name, str) and name and isinstance(kind, str) and kind,
                "Workers secret list entry differs")
        require(name not in names, "Workers secret list contains duplicate names")
        names.add(name)
        rows.append({"name": name, "type": kind})
    if expected_name is not None:
        target = next((row for row in rows if row["name"] == expected_name), None)
        require(target is not None, f"Workers secret list lacks exact {expected_name}")
        require(target["type"] == "secret_text",
                f"Workers secret list exact {expected_name} binding type differs")
    return rows


def _workers_secret_put(*, account_id: str, worker_name: str, secret_name: str,
                        secret: str, token: str, opener=None) -> None:
    # Wrangler 4.93.0 secret put may create a draft Worker on not-found. We deliberately
    # bypass that convenience branch and call the same provider secret endpoint directly.
    # A missing/deleted Worker therefore fails instead of creating infrastructure.
    require(CLOUDFLARE_ACCOUNT_ID.fullmatch(account_id) is not None, "Workers account id invalid")
    require(CLOUDFLARE_WORKER_NAME.fullmatch(worker_name) is not None, "Workers name invalid")
    require((secret_name == "JEV_API_KEY" or (secret_name == GO_KEY and account_id == WORKER_GO_TARGET["account_id"] and worker_name == "pi"))
            and isinstance(secret, str) and secret, "Workers secret input invalid")
    open_request = urllib.request.urlopen if opener is None else opener
    url = (CLOUDFLARE_API + "/accounts/" + account_id + "/workers/scripts/"
           + urllib.parse.quote(worker_name, safe="") + "/secrets")
    body = json.dumps(
        {"name": secret_name, "text": secret, "type": "secret_text"},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    try:
        with open_request(request, timeout=RETRIEVAL_TIMEOUT, context=ssl.create_default_context()) as response:
            status = response.status if hasattr(response, "status") else response.getcode()
            require(200 <= status < 300, f"Cloudflare Workers secret put returned HTTP {status}")
            response_body = response.read(RESPONSE_LIMIT + 1)
            require(len(response_body) <= RESPONSE_LIMIT,
                    "Cloudflare Workers secret put response too large")
            try:
                envelope = json.loads(response_body.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise EnvsError("Cloudflare Workers secret put response is not JSON") from exc
            require(isinstance(envelope, dict), "Cloudflare Workers secret put response shape differs")
            require(envelope.get("success") is True, "Cloudflare Workers secret put did not report success")
            result = envelope.get("result")
            require(isinstance(result, dict), "Cloudflare Workers secret put result missing")
            require(result.get("name") == secret_name,
                    "Cloudflare Workers secret put result name differs")
            require(result.get("type") == "secret_text",
                    "Cloudflare Workers secret put result type differs")
    except urllib.error.HTTPError as exc:
        raise EnvsError(f"Cloudflare Workers secret put returned HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise EnvsError("Cloudflare Workers secret put transport failed") from None


def project_github_org_secret(*, target: dict[str, Any], tools: Mapping[str, str],
                              authorization: Mapping[str, str], secret_loader: Callable[[], bytes],
                              runner: Runner | None = None, apply: bool = True) -> dict[str, Any]:
    """Bound Org materialization primitive; not a grant, binding, CLI route or Jev-use receipt.

    The owning projector supplies its admitted target/toolchain, authorized GH_TOKEN and
    lazy SOPS loader. Native gh seals plaintext on stdin; the only write uses fixed repo IDs,
    not gh's name-based lookup. No Repository/Environment endpoint or automatic retry exists.
    """
    try:
        selected = json.loads(json.dumps(target, allow_nan=False))
        spec = importlib.util.spec_from_file_location("envs_org_target", Path(__file__).with_name("contract_projection.py"))
        require(spec is not None and spec.loader is not None, "Org target validator missing")
        public = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(public)
        public.public_target(selected)
        require(selected["provider"] == "github-org-secret" and selected["secret_name"] == "JEV_API_KEY",
                "Org Jev target differs")
        gh = tools["gh"]
        require(in_store(gh) and os.path.isfile(gh) and os.access(gh, os.X_OK), "fixed gh tool missing")
        require(set(authorization) == {"GH_TOKEN"} and isinstance(authorization["GH_TOKEN"], str)
                and bool(authorization["GH_TOKEN"]), "Org projection authorization missing")
        require(type(apply) is bool, "Org apply mode invalid")
    except (ValueError, TypeError, KeyError):
        raise EnvsError("Org projection input invalid") from None
    org, name = selected["organization"], selected["secret_name"]
    expected = dict(zip(selected["repositories"], selected["repository_ids"], strict=True))

    with tempfile.TemporaryDirectory(prefix="envs-org-gh-") as home:
        child_env = clean_env(tools, {"GH_TOKEN": authorization["GH_TOKEN"], "GH_HOST": "github.com",
                                      "HOME": home, "GH_CONFIG_DIR": home, "GH_PROMPT_DISABLED": "1"})

        def command(args: list[str], stdin: bytes | None = None, limit: int = RESPONSE_LIMIT) -> bytes:
            argv = [gh, *args]
            try:
                result = subprocess.run(argv, input=stdin, env=child_env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, check=False, shell=False, timeout=30) \
                    if runner is None else runner(argv, stdin, child_env)
            except Exception:
                raise EnvsError("Org gh operation unresolved") from None
            require(result.returncode == 0 and len(result.stdout) <= limit, "Org gh operation failed")
            return result.stdout

        def api(route: str) -> Any:
            try:
                return json.loads(command(["api", "-X", "GET", route]).decode("utf-8"))
            except (ValueError, UnicodeError):
                raise EnvsError("Org metadata response invalid") from None

        def identity() -> None:
            observed = api(f"orgs/{org}")
            require(isinstance(observed, dict) and observed.get("type") == "Organization"
                    and observed.get("login") == org and str(observed.get("id")) == selected["organization_id"],
                    "Org identity differs")
            for repository, repository_id in expected.items():
                observed = api(f"repos/{repository}")
                owner = observed.get("owner", {}) if isinstance(observed, dict) else {}
                require(isinstance(observed, dict) and isinstance(owner, dict)
                        and observed.get("full_name") == repository and str(observed.get("id")) == repository_id
                        and owner.get("type") == "Organization" and owner.get("login") == org
                        and str(owner.get("id")) == selected["organization_id"], "Org repository identity differs")

        def public_key() -> dict[str, str]:
            key = api(f"orgs/{org}/actions/secrets/public-key")
            require(isinstance(key, dict) and set(key) == {"key_id", "key"}
                    and isinstance(key["key_id"], str) and bool(key["key_id"])
                    and isinstance(key["key"], str), "Org public key invalid")
            try:
                require(len(base64.b64decode(key["key"], validate=True)) == 32, "Org public key invalid")
            except ValueError:
                raise EnvsError("Org public key invalid") from None
            return key

        # Read-only identity and Org API access preflight, before the owning loader reads plaintext.
        identity()
        key = public_key()
        if not apply:
            return {"operation": "github_org_secret_put", "target": selected,
                    "readback": "NOT_RUN", "provider_use": "NOT_RUN"}
        try:
            secret = secret_loader()
        except Exception:
            raise EnvsError("Org source decryption failed") from None
        require(isinstance(secret, bytes) and 0 < len(secret) <= 48 * 1024, "Org source secret size invalid")
        encrypted = command(["secret", "set", name, "--app", "actions", "--org", org, "--no-store"],
                            secret, 2 * RESPONSE_LIMIT).strip()
        try:
            require(bool(base64.b64decode(encrypted, validate=True)), "Org sealed value invalid")
            encrypted_text = encrypted.decode("ascii")
        except (ValueError, UnicodeError):
            raise EnvsError("Org sealed value invalid") from None
        require(public_key() == key, "Org public key changed before write")
        identity()
        # The native encrypted envelope goes through stdin. Repo IDs remain bound even if a name changes.
        body = json.dumps({"encrypted_value": encrypted_text, "key_id": key["key_id"], "visibility": "selected",
                           "selected_repository_ids": [int(i) for i in selected["repository_ids"]]},
                          separators=(",", ":")).encode("utf-8")
        try:
            command(["api", "-X", "PUT", f"orgs/{org}/actions/secrets/{name}", "--input", "-"], body)
            metadata = api(f"orgs/{org}/actions/secrets/{name}")
            require(isinstance(metadata, dict) and metadata.get("name") == name
                    and metadata.get("visibility") == "selected", "Org secret metadata differs")
            access = api(f"orgs/{org}/actions/secrets/{name}/repositories?per_page=100")
            rows = access.get("repositories") if isinstance(access, dict) else None
            require(isinstance(rows, list) and access.get("total_count") == len(expected) == len(rows),
                    "Org selected repository readback incomplete")
            actual: dict[str, str] = {}
            for row in rows:
                require(isinstance(row, dict) and isinstance(row.get("full_name"), str)
                        and row["full_name"] not in actual, "Org selected repository readback invalid")
                actual[row["full_name"]] = str(row.get("id"))
            require(actual == expected, "Org selected repository readback differs")
            identity()
        except Exception:
            # A failed/unknown write or later readback is not a no-effect record. Never retry automatically.
            raise EnvsError("Org projection write/readback unresolved; do not repeat") from None
        return {"operation": "github_org_secret_put", "target": selected,
                "readback": "SECRET_NAME_AND_SELECTED_REPOSITORY_IDS", "provider_use": "NOT_RUN"}


def org_projection(*, envs_sha: str, auth_config: Path, identity: Path, apply: bool = False,
                   root: Path = ROOT, runner: Runner | None = None) -> dict[str, Any]:
    """The owner-only OCI setup route; consumers get no decryptor or controller credential."""
    contracts = validate_contracts(root)
    tools = toolchain(root)
    manifest = json.loads(Path(os.environ["ENVS_EFFECT_TOOLCHAIN"]).read_text(encoding="utf-8"))
    require(SHA40.fullmatch(envs_sha) is not None and envs_sha == manifest["source"], "Org source identity differs")
    for relative in (BINDINGS, BOUNDARY, ENVIRONMENTS, OCI_CIPHERTEXT, FLAKE_LOCK):
        path = root / relative
        require(not path.is_symlink() and path.read_bytes() == (ROOT / relative).read_bytes(),
                "Org data differs from the provided source")
    require(not (root / ORG_HANDOFF).exists() and not (root / ORG_HANDOFF).is_symlink(),
            "Org handoff already exists; reconcile before another operation")
    require(not (root / ORG_HANDOFF).parent.is_symlink()
            and (not (root / ORG_HANDOFF).parent.exists() or (root / ORG_HANDOFF).parent.is_dir()),
            "Org handoff parent differs")
    require(auth_config.is_absolute() and identity.is_absolute(), "Org private input paths must be absolute")
    require(auth_config.resolve() == auth_config and identity.resolve() == identity,
            "Org private input path contains a link")

    def owned(path: Path, mode: int, directory: bool = False) -> None:
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == os.geteuid()
                and info.st_mode & 0o777 == mode and (path.is_dir() if directory else path.is_file()),
                "Org private input ownership differs")

    owned(auth_config, 0o700, True)
    owned(auth_config / "hosts.yml", 0o600)
    owned(identity.parent, 0o700, True)
    owned(identity, 0o600)

    def command(argv: Sequence[str], env: Mapping[str, str], stdin: bytes | None = None) -> bytes:
        try:
            value = subprocess.run(list(argv), input=stdin, env=dict(env), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False, shell=False, timeout=30) \
                if runner is None else runner(argv, stdin, env)
        except Exception:
            raise EnvsError("Org setup child unresolved") from None
        require(value.returncode == 0 and len(value.stdout) <= RESPONSE_LIMIT, "Org setup child failed")
        return value.stdout

    # The explicit existing account slot only; no GH_TOKEN/HOME/account-switch fallback.
    env = clean_env(tools, {"GH_CONFIG_DIR": str(auth_config), "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1"})
    try:
        token = command([tools["gh"], "auth", "token", "--hostname", "github.com", "--user", ORG_CONTROLLER], env).decode("ascii").strip()
    except UnicodeError:
        raise EnvsError("Org controller authorization invalid") from None
    require(0 < len(token) <= 8192 and all(33 <= ord(char) <= 126 for char in token), "Org controller authorization invalid")
    with tempfile.TemporaryDirectory(prefix="envs-org-controller-") as private_home:
        private_env = clean_env(tools, {"GH_TOKEN": token, "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1",
                                        "HOME": private_home, "GH_CONFIG_DIR": private_home})
        try:
            controller = json.loads(command([tools["gh"], "api", "-X", "GET", "user"], private_env))
        except ValueError:
            raise EnvsError("Org controller response invalid") from None
        require(isinstance(controller, dict) and controller.get("login") == ORG_CONTROLLER
                and controller.get("type") == "User", "Org controller identity differs")
        try:
            slots = json.loads(command([tools["gh"], "api", "-X", "GET",
                                       f"orgs/{ORG_TARGET['organization']}/actions/secrets?per_page=100"], private_env))
        except ValueError:
            raise EnvsError("Org existing slot response invalid") from None
        rows = slots.get("secrets") if isinstance(slots, dict) else None
        require(isinstance(rows, list) and slots.get("total_count") == len(rows)
                and all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in rows),
                "Org existing slot readback incomplete")
        require(all(row["name"] != ORG_TARGET["secret_name"] for row in rows),
                "Org slot already exists; reconcile before an authorized rotation")

    binding = contracts["bindings"][ORG_BINDING]
    cipher = ROOT / binding["ciphertext"]
    validate_oci_ciphertext(cipher.read_bytes(), None, None)

    def load_secret() -> bytes:
        owned(identity, 0o600)
        data = command([tools["sops"], "--decrypt", "--output-type", "json", str(cipher)],
                       clean_env(tools, {"SOPS_AGE_KEY_FILE": str(identity)}))
        try:
            spec = importlib.util.spec_from_file_location("envs_org_payload", Path(__file__).with_name("contract_projection.py"))
            require(spec is not None and spec.loader is not None, "Org payload validator missing")
            public = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(public)
            payload = public.read_json(data.decode("utf-8"))
            require(isinstance(payload, dict) and set(payload) == {"JEV_API_KEY"}
                    and isinstance(payload["JEV_API_KEY"], str) and bool(payload["JEV_API_KEY"]), "Org payload fields differ")
            return payload["JEV_API_KEY"].encode("utf-8")
        except (ValueError, UnicodeError, KeyError, TypeError):
            raise EnvsError("Org source payload invalid") from None

    result = project_github_org_secret(target=binding["target"], tools=tools, authorization={"GH_TOKEN": token},
                                      secret_loader=load_secret, runner=runner, apply=apply)
    if not apply:
        return {"kind": ORG_PLAN_KIND, "source": envs_sha, "binding": ORG_BINDING,
                "controller": ORG_CONTROLLER, "projection": "NOT_RUN", **result}
    receipt = {"kind": ORG_RECEIPT_KIND, "source": envs_sha, "binding": ORG_BINDING,
               "controller": ORG_CONTROLLER, "created_at": utc_now(), **result}
    validate_org_receipt(receipt)
    destination = root / ORG_HANDOFF
    require(not destination.parent.is_symlink(), "Org handoff parent differs")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    except OSError:
        raise EnvsError("Org write succeeded but handoff unresolved; reconcile, do not repeat") from None
    return receipt


def validate_org_receipt(receipt: Any) -> None:
    require(isinstance(receipt, dict) and set(receipt) == {
        "kind", "source", "binding", "controller", "created_at", "operation", "target", "readback", "provider_use",
    }, "Org receipt fields differ")
    require(receipt["kind"] == ORG_RECEIPT_KIND and receipt["binding"] == ORG_BINDING
            and receipt["controller"] == ORG_CONTROLLER and isinstance(receipt["source"], str)
            and SHA40.fullmatch(receipt["source"]) is not None and receipt["target"] == ORG_TARGET
            and receipt["operation"] == "github_org_secret_put"
            and receipt["readback"] == "SECRET_NAME_AND_SELECTED_REPOSITORY_IDS"
            and receipt["provider_use"] == "NOT_RUN", "Org receipt identity differs")
    require(isinstance(receipt["created_at"], str) and receipt["created_at"].endswith("Z"),
            "Org receipt time invalid")
    try:
        datetime.fromisoformat(receipt["created_at"][:-1] + "+00:00")
    except ValueError:
        raise EnvsError("Org receipt time invalid") from None
    walk_receipt(receipt)


def validate_receipt(receipt: dict[str, Any], expected_target: dict[str, Any] | None = None) -> None:
    require(set(receipt) == {
        "kind", "status", "envs_sha", "environment", "capability", "source",
        "target", "projector", "effect", "readback", "workflow", "created_at",
    }, "receipt fields differ")
    require(receipt["kind"] == RECEIPT_KIND and receipt["status"] == "PASS", "receipt is not PASS")
    require(isinstance(receipt["envs_sha"], str) and SHA40.fullmatch(receipt["envs_sha"]), "invalid envs SHA")
    require(receipt["environment"] == "dev" and receipt["capability"] == "jev-api", "receipt identity differs")
    source = receipt["source"]
    require(source.get("kind") == "public_sops" and source.get("ref") == CIPHERTEXT.as_posix(), "receipt source differs")
    require(isinstance(source.get("sha256"), str) and SHA256.fullmatch(source["sha256"]), "invalid ciphertext digest")
    target = validate_jev_target(receipt["target"])
    if expected_target is not None:
        require(target == validate_jev_target(expected_target), "receipt target differs")
    require(receipt["projector"] == {
        "workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py",
    }, "projector identity differs")
    require(receipt["effect"] == {"operation": _receipt_operation(target), "status": "PASS"},
            "provider effect is not PASS")
    require(receipt["readback"] == {"kind": "secret_name_presence", "status": "PASS", "present": True},
            "provider readback is not PASS")
    workflow = receipt["workflow"]
    require(workflow.get("repository") == "roccho-dev/envs" and workflow.get("ref") == "proposals", "workflow identity differs")
    require(isinstance(workflow.get("run_id"), int) and workflow["run_id"] > 0, "invalid workflow run id")
    require(isinstance(workflow.get("run_attempt"), int) and workflow["run_attempt"] > 0, "invalid workflow run attempt")
    created_at = receipt["created_at"]
    require(isinstance(created_at, str) and created_at.endswith("Z"), "invalid timestamp")
    try:
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError as exc:
        raise EnvsError("invalid timestamp") from exc
    walk_receipt(receipt)


def build_receipt(*, envs_sha: str, ciphertext_sha256: str, target: dict[str, Any],
                  run_id: int, run_attempt: int, created_at: str) -> dict[str, Any]:
    target = dict(validate_jev_target(target))
    receipt = {
        "kind": RECEIPT_KIND, "status": "PASS", "envs_sha": envs_sha,
        "environment": "dev", "capability": "jev-api",
        "source": {"kind": "public_sops", "ref": CIPHERTEXT.as_posix(), "sha256": "sha256:" + ciphertext_sha256},
        "target": target,
        "projector": {"workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py"},
        "effect": {"operation": _receipt_operation(target), "status": "PASS"},
        "readback": {"kind": "secret_name_presence", "status": "PASS", "present": True},
        "workflow": {"repository": "roccho-dev/envs", "ref": "proposals", "run_id": run_id, "run_attempt": run_attempt},
        "created_at": created_at,
    }
    validate_receipt(receipt, target)
    return receipt


def project(*, envs_sha: str, run_id: int, run_attempt: int, created_at: str,
            output: Path, root: Path = ROOT, runner: Runner = default_runner, opener=None) -> dict[str, Any]:
    contracts = validate_contracts(root)
    require(SHA40.fullmatch(envs_sha) is not None, "expected exact envs SHA")
    target = validate_jev_target(contracts["bindings"]["jev-api"]["target"])
    cipher = root / CIPHERTEXT
    require(cipher.is_file(), "ciphertext is not configured")
    tools = toolchain(root)
    inputs = gate(root, contracts, "dev.projection")
    age_key = inputs["SOPS_AGE_KEY"]
    account = inputs["CLOUDFLARE_ACCOUNT_ID"]
    token = inputs["CLOUDFLARE_API_TOKEN"]
    provider_env = clean_env(tools, {"CLOUDFLARE_ACCOUNT_ID": account, "CLOUDFLARE_API_TOKEN": token})
    wrangler = tools["wrangler"]

    # Workers must already exist. This read-only call fails on a missing Worker before
    # decryption or any write. Direct provider PUT below also cannot enter Wrangler's
    # createDraftWorker() fallback, closing the deletion race between preflight and put.
    if target["provider"] == "cloudflare-workers":
        require(account == target["account_id"], "Workers target account differs from projection account")
        preflight = run_checked(
            [wrangler, "secret", "list", "--name", target["worker_name"], "--format", "json"],
            env=provider_env, runner=runner, label="Cloudflare Workers existence preflight",
        )
        parse_workers_secret_list(preflight.stdout)

    decrypted = run_checked(
        [tools["sops"], "--decrypt", "--output-type", "json", str(cipher)],
        env=clean_env(tools, {"SOPS_AGE_KEY": age_key}), runner=runner, label="SOPS decryption",
    ).stdout
    try:
        payload = json.loads(decrypted)
    except json.JSONDecodeError as exc:
        raise EnvsError("decrypted payload is not JSON") from exc
    require(isinstance(payload, dict) and set(payload) == {"JEV_API_KEY"}, "decrypted payload fields differ")
    secret = payload["JEV_API_KEY"]
    require(isinstance(secret, str) and secret, "decrypted JEV_API_KEY is empty")

    if target["provider"] == "cloudflare-workers":
        _workers_secret_put(
            account_id=target["account_id"], worker_name=target["worker_name"],
            secret_name=target["secret_name"], secret=secret, token=token, opener=opener,
        )
        readback = run_checked(
            [wrangler, "secret", "list", "--name", target["worker_name"], "--format", "json"],
            env=provider_env, runner=runner, label="Cloudflare Workers secret readback",
        )
        # Wrangler 4.93.0 JSON stdout is the sole presence evidence. stderr may
        # contain diagnostics/warnings but is never interpreted as a positive.
        parse_workers_secret_list(readback.stdout, target["secret_name"])
    else:
        run_checked(
            [wrangler, "pages", "secret", "put", "JEV_API_KEY", "--project-name", target["project"]],
            input_data=secret.encode(), env=provider_env, runner=runner, label="Cloudflare secret projection",
        )
        readback = run_checked(
            [wrangler, "pages", "secret", "list", "--project-name", target["project"]],
            env=provider_env, runner=runner, label="Cloudflare secret readback",
        )
        # Pages stays legacy-compatible in this source slice. It is never a
        # Workers receipt and cannot satisfy #443's Workers handoff.
        require(b"JEV_API_KEY" in readback.stdout + readback.stderr,
                "provider readback did not contain JEV_API_KEY")

    receipt = build_receipt(
        envs_sha=envs_sha, ciphertext_sha256=hashlib.sha256(cipher.read_bytes()).hexdigest(),
        target=target, run_id=run_id, run_attempt=run_attempt, created_at=created_at,
    )
    destination = root / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def load_receipt(path: Path, expected_target: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvsError("handoff receipt is invalid JSON") from exc
    require(isinstance(value, dict), "handoff receipt must be an object")
    validate_receipt(value, expected_target)
    return value


def linode_read_probe(root: Path = ROOT, opener=None) -> dict[str, Any]:
    """Prove authenticated GET access only; credential scope is not narrowed by this probe."""
    contracts = validate_contracts(root)
    token = gate(root, contracts, LINODE_READ_PLANE)["LINODE_API_TOKEN"]
    require(BEARER.fullmatch(token) is not None, "Linode API token format is invalid")
    reject_live_values(root, "LINODE_API_TOKEN", [token])
    open_request = urllib.request.urlopen if opener is None else opener
    checks: dict[str, str] = {}
    context = ssl.create_default_context()
    for name, path in LINODE_READ_ENDPOINTS:
        request = urllib.request.Request(
            LINODE_API + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with open_request(request, timeout=RETRIEVAL_TIMEOUT, context=context) as response:
                status = response.status if hasattr(response, "status") else response.getcode()
                require(status == 200, f"Linode {name} read returned HTTP {status}")
                response.read(1)
        except urllib.error.HTTPError as exc:
            raise EnvsError(f"Linode {name} read returned HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise EnvsError(f"Linode {name} read transport failed") from None
        checks[name] = "PASS"
    return {"kind": "envs.linodeReadProbe.v1", "status": "PASS", "checks": checks}


def readiness(root: Path = ROOT) -> dict[str, Any]:
    contracts = validate_contracts(root)
    cipher, handoff = root / CIPHERTEXT, root / HANDOFF
    configured = cipher.is_file()
    physical, state = ("NOT_RUN", "ABSENT") if configured else ("NOT_CONFIGURED", "ABSENT")
    current = "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest() if configured else None
    receipt_digest = None
    if handoff.is_file():
        require(configured, "handoff cannot exist without ciphertext")
        receipt_digest = load_receipt(handoff, contracts["bindings"]["jev-api"]["target"])["source"]["sha256"]
        physical = state = "PASS" if receipt_digest == current else "STALE"
    return {
        "kind": "envs.providerReadiness.v1", "repository": "roccho-dev/envs",
        "canonical_branch": "proposals", "retained_compatibility_branch": "main",
        "stage": "dev", "capability": "jev-api", "public_source_provider": "PASS",
        "provider_mechanism": "PASS_SOURCE", "physical_dev_projection": physical,
        "provider_handoff_receipt": state, "provider_handoff_ready": state == "PASS",
        "consumer_runtime_readiness": "OUT_OF_SCOPE",
        "current_ciphertext_sha256": current, "receipt_ciphertext_sha256": receipt_digest,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    # Data root (contracts, ciphertext, handoff); defaults to the source carrying this adapter.
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("readiness")
    sub.add_parser("toolchain")
    # A dispatch names its one target; there is no default, and an unknown one stops before any input is read.
    author_parser = sub.add_parser("author")
    author_parser.add_argument("--target", required=True, choices=AUTHOR_TARGETS)
    sub.add_parser("rent-tunnel")
    # The root's sensitive credentials output on stdin only, never an argument, environment value or file.
    sub.add_parser("rent-client")
    # Applies the persistent root and seals both envelopes; its inputs come only from the declared environment.
    sub.add_parser("rent-root")
    # S2 source composes the closed future read-only entry, never activates it.
    sub.add_parser("rent-root-inspect")
    # S2 source composes the backend-only migration and empty-plan proof onto the GitHub ref; neither is activated.
    sub.add_parser("rent-root-migrate")
    sub.add_parser("rent-root-plan")
    sub.add_parser("linode-read-probe")
    project_parser = sub.add_parser("project")
    project_parser.add_argument("--target", choices=("jev-api", WORKER_GO_BINDING), default="jev-api")
    project_parser.add_argument("--envs-sha", required=True)
    project_parser.add_argument("--run-id", type=int, required=True)
    project_parser.add_argument("--run-attempt", type=int, required=True)
    project_parser.add_argument("--created-at")
    project_parser.add_argument("--output", type=Path, default=HANDOFF)
    org_parser = sub.add_parser("project-org-secret")
    org_parser.add_argument("--envs-sha", required=True)
    org_parser.add_argument("--auth-config", type=Path, required=True)
    org_parser.add_argument("--identity", type=Path, required=True)
    org_parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "check":
            contracts = validate_contracts(root)
            if (root / HANDOFF).is_file():
                load_receipt(root / HANDOFF, contracts["bindings"]["jev-api"]["target"])
            print("JEV_API_CONTRACT=PASS")
        elif args.command == "readiness":
            print(json.dumps(readiness(root), indent=2, sort_keys=True))
        elif args.command == "toolchain":
            tools = toolchain(root)
            print(json.dumps({
                "kind": "envs.effectToolchainCheck.v1", "status": "PASS", "root": str(root),
                "manifest": os.environ["ENVS_EFFECT_TOOLCHAIN"], "nixpkgs": locked_nixpkgs(root), "tools": tools,
                "source": json.loads(Path(os.environ["ENVS_EFFECT_TOOLCHAIN"]).read_text(encoding="utf-8"))["source"],
            }, indent=2, sort_keys=True))
        elif args.command == "project-org-secret":
            result = org_projection(envs_sha=args.envs_sha, auth_config=args.auth_config,
                                    identity=args.identity, apply=args.apply, root=root)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "author":
            result = author(root) if args.target == "jev-api" else author_worker_go(root) if args.target == WORKER_GO_BINDING else author_oci(root, target=args.target)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "rent-tunnel":
            print(json.dumps(rent_author(root), indent=2, sort_keys=True))
        elif args.command == "rent-client":
            print(json.dumps(client_author(sys.stdin.buffer.read(RESPONSE_LIMIT + 1), root), indent=2, sort_keys=True))
        elif args.command == "rent-root":
            # Only a closed kind and stage leave on failure, plus a failed init child's closed unverified hint line:
            # never a message, class name, traceback, child output or value.
            progress: dict[str, str] = {}
            try:
                result = rent_root(root, progress=progress)
            except Exception as exc:
                kind = failure_class(exc) if isinstance(exc, STATE_FAILURES) else "other"
                print(f"RENT_ROOT=RED: {kind} at {progress.get('stage', 'start')}", file=sys.stderr)
                if "init_hint" in progress:
                    print(f"RENT_ROOT_INIT_HINT_UNVERIFIED={progress['init_hint']}", file=sys.stderr)
                return 1
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "rent-root-inspect":
            # Closed source/phase gate runs before any contract, env, tool,
            # secret read or child. Never disclose traceback or secret input.
            progress: dict[str, str] = {}
            try:
                result = rent_root_inspect(root, progress=progress)
            except Exception as exc:
                kind = failure_class(exc) if isinstance(exc, STATE_FAILURES) else "other"
                print(f"RENT_ROOT_INSPECT=RED: {kind} at {progress.get('stage', 'source_guard')}", file=sys.stderr)
                return 1
            print(json.dumps(result, sort_keys=True))
        elif args.command in {"rent-root-migrate", "rent-root-plan"}:
            # Same closed failure surface: a kind and a stage, never a message, child output or value.
            progress = {}
            label = "RENT_ROOT_MIGRATE" if args.command == "rent-root-migrate" else "RENT_ROOT_PLAN"
            try:
                result = (rent_root_migrate if args.command == "rent-root-migrate" else rent_root_plan)(
                    root, progress=progress)
            except Exception as exc:
                kind = failure_class(exc) if isinstance(exc, STATE_FAILURES) else "other"
                print(f"{label}=RED: {kind} at {progress.get('stage', 'source_guard')}", file=sys.stderr)
                return 1
            print(json.dumps(result, sort_keys=True))
        elif args.command == "linode-read-probe":
            print(json.dumps(linode_read_probe(root), indent=2, sort_keys=True))
            return 0
        elif args.command == "project" and args.target == WORKER_GO_BINDING:
            require(args.output == HANDOFF or args.output == WORKER_GO_HANDOFF, "OpenCode Worker output differs")
            receipt = project_worker_go(envs_sha=args.envs_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                                        created_at=args.created_at or utc_now(), root=root)
            print(json.dumps({"kind": receipt["kind"], "status": "PASS", "output": WORKER_GO_HANDOFF.as_posix(),
                              "provider_use": "NOT_RUN"}, sort_keys=True))
        else:
            receipt = project(
                envs_sha=args.envs_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                created_at=args.created_at or utc_now(), output=args.output, root=root,
            )
            print(json.dumps({"kind": receipt["kind"], "status": "PASS", "output": str(args.output)}, sort_keys=True))
    except (EnvsError, OSError) as exc:
        label = {"rent-tunnel": "RENT_TUNNEL", "rent-client": "RENT_CLIENT",
                 "linode-read-probe": "LINODE_READ_PROBE"}.get(args.command, "JEV_API")
        print(f"{label}=RED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
