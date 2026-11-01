#!/usr/bin/env python3
"""Source-only guard: cannot be mistaken for a live Cloudflare policy test."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
text = (root / "providers/dev-versa-cloudflare/main.tf").read_text()
for required in (
    'backend "http" {}', "state { enforced = true }", "plan  { enforced = true }",
    'config_src = "cloudflare"', '"versa-private-ssh"',
    'endswith(var.versa_ipv4_cidr, "/32")',
    '10[.]|192[.]168[.]|172[.]',
    'net.dst.port == 22', 'net.protocol == \\"tcp\\"', "muccho_posture_check_id", "identity.email",
    'action         = "allow"', 'action      = "block"',
    "cloudflare_zero_trust_gateway_policy.versa_allow,",
    "cloudflare_zero_trust_gateway_policy.versa_block,",
    "network    = var.versa_ipv4_cidr",
    'sensitive = true',
):
    assert required in text, f"missing versa boundary: {required}"
for forbidden in (
    "cloudflare_dns_record", "cloudflare_zero_trust_access_application",
    "cloudflare_zero_trust_tunnel_cloudflared_config", 'ingress =',
    "cloudflare_zero_trust_access_service_token", 'default =',
):
    assert forbidden not in text, f"unexpected public route or default: {forbidden}"
assert text.index("resource \"cloudflare_zero_trust_gateway_policy\" \"versa_block\"") < text.index(
    "resource \"cloudflare_zero_trust_tunnel_cloudflared_route\" \"versa\""
)
print("PASS: source-only /32 route, explicit allow+block, and no public ingress; no provider call")
