"""Offline admission for a native OpenTofu JSON *initial creation* plan.

Not an apply command, policy grant, provider validator or update approval.
The JSON may contain sensitive values: keep it in the owner's private work area.
Only fixed diagnostics are printed. Never print or commit the input plan.
"""
import json
from pathlib import Path
import sys

MANAGED = {
    "cloudflare_zero_trust_tunnel_cloudflared.host",
    "cloudflare_zero_trust_tunnel_cloudflared_config.host",
    "cloudflare_dns_record.host",
    "cloudflare_zero_trust_access_policy.host",
    "cloudflare_zero_trust_access_application.host",
}
TOKEN = "data.cloudflare_zero_trust_tunnel_cloudflared_token.host"


def check(plan):
    if not isinstance(plan, dict) or str(plan.get("format_version", "")).split(".")[0] != "1":
        raise ValueError("Unsupported native plan format")
    if plan.get("errored") or plan.get("complete") is False or plan.get("deferred_changes"):
        raise ValueError("Incomplete or failed plan")
    seen = set()
    for resource in plan.get("resource_changes", []):
        address = resource.get("address")
        if address in seen:
            raise ValueError("Repeated resource address")
        seen.add(address)
        actions = resource.get("change", {}).get("actions")
        if address in MANAGED:
            if resource.get("mode") != "managed" or actions != ["create"]:
                raise ValueError("Initial adoption requires creation only")
        elif address == TOKEN:
            if resource.get("mode") != "data" or actions not in (["read"], ["no-op"]):
                raise ValueError("Unexpected connector-token operation")
        else:
            raise ValueError("Resource outside this standalone root")
    if not MANAGED <= seen:
        raise ValueError("Required managed resource is absent")
    outputs = plan.get("output_changes", {})
    if set(outputs) != {"public_binding", "connector_token"}:
        raise ValueError("Unexpected output surface")
    if outputs["connector_token"].get("after_sensitive") is not True:
        raise ValueError("Connector-token output must remain sensitive")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected one private native plan JSON file")
        check(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    except (ValueError, TypeError, KeyError, OSError):
        raise SystemExit("INITIAL_PLAN=REFUSED")
    print("INITIAL_PLAN=ACCEPTED_FOR_OWNER_REVIEW; apply=NOT_RUN")
