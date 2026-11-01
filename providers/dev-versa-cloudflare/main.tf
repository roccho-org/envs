# Source-only private Tunnel for Versa (#143); no workflow, grant or live apply is authorized.
# A public DNS record/hostname/ingress is intentionally NOT part of this root.
# Before apply, independently verify the account's effective Gateway precedence
# and WARP split routes: network policy defaults to allow if unmatched.
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }
  backend "http" {}
  encryption {
    state { enforced = true }
    plan  { enforced = true }
  }
}

variable "account_id" { type = string }

# Real, LAN-reachable Versa host address with /32 mask; not a subnet.
variable "versa_ipv4_cidr" {
  type = string
  validation {
    condition     = can(cidrhost(var.versa_ipv4_cidr, 0)) && endswith(var.versa_ipv4_cidr, "/32")
    error_message = "versa_ipv4_cidr must be one IPv4 /32 host route."
  }
}

# Both an exact WARP identity AND a dedicated muccho-only device posture check
# are required; a shared email alone does not identify the muccho VM.
variable "muccho_email" { type = string }
variable "muccho_posture_check_id" { type = string }

# Assigned only after reading the current account's policy precedence.
variable "allow_precedence" { type = number }
variable "block_precedence" {
  type = number
  validation {
    condition     = var.block_precedence > var.allow_precedence
    error_message = "The muccho allow must run before the Versa deny."
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = "versa-private-ssh"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_gateway_policy" "versa_allow" {
  account_id     = var.account_id
  name           = "versa-private-ssh-allow-muccho"
  description    = "Only the enrolled muccho VM may reach Versa TCP/22"
  filters        = ["l4"]
  enabled        = true
  action         = "allow"
  precedence     = var.allow_precedence
  traffic        = "net.dst.ip in {${var.versa_ipv4_cidr}} and net.dst.port == 22"
  identity       = "identity.email == ${jsonencode(var.muccho_email)}"
  device_posture = "any(device_posture.checks.passed[*] in {${jsonencode(var.muccho_posture_check_id)}})"
}

resource "cloudflare_zero_trust_gateway_policy" "versa_block" {
  account_id  = var.account_id
  name        = "versa-private-ssh-deny-others"
  description = "Block all other clients and ports routed to the Versa host"
  filters     = ["l4"]
  enabled     = true
  action      = "block"
  precedence  = var.block_precedence
  traffic     = "net.dst.ip in {${var.versa_ipv4_cidr}}"
}

# Never provision the route before the restriction rules. The real Gateway
# account policy order must *also* be checked to exclude earlier bypasses.
resource "cloudflare_zero_trust_tunnel_cloudflared_route" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  network    = var.versa_ipv4_cidr
  comment    = "Versa host only; muccho private SSH, resources#143"
  depends_on = [
    cloudflare_zero_trust_gateway_policy.versa_allow,
    cloudflare_zero_trust_gateway_policy.versa_block,
  ]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}

# Token must only be consumed through encrypted, explicitly approved custody.
output "connector_token" {
  sensitive = true
  value     = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
}
