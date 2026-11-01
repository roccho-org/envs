# Independent Versa private SSH Tunnel. No public DNS, ingress route or other Host changes.
# The private hostname route depends on the exact Access app and its narrow policy.
# This root has NO effect workflow; source/CI alone never applies provider resources.
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
    plan { enforced = true }
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "Exact Cloudflare account ID required."
  }
}
variable "muccho_email" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.muccho_email))
    error_message = "One exact muccho enrollment email is required."
  }
}
variable "muccho_device_posture_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.muccho_device_posture_id))
    error_message = "Exact device-posture check UUID required; no any-device fallback."
  }
}

locals {
  private_host = "versa.roccho.internal"
  tunnel_name  = "versa-private-ssh"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = local.tunnel_name
  config_src = "cloudflare"
}

# No published app, even if another operator were to add public DNS.
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  config = { ingress = [{ service = "http_status:404" }] }
}

resource "cloudflare_zero_trust_access_policy" "muccho" {
  account_id = var.account_id
  name       = "versa-private-ssh-muccho"
  decision   = "allow"
  include    = [{ email = { email = var.muccho_email } }]
  require    = [{ device_posture = { integration_uid = var.muccho_device_posture_id } }]
}

resource "cloudflare_zero_trust_access_application" "versa" {
  account_id                  = var.account_id
  name                        = local.tunnel_name
  type                        = "self_hosted"
  app_launcher_visible        = false
  allow_authenticate_via_warp = true
  destinations = [{
    type        = "private"
    hostname    = local.private_host
    l4_protocol = "tcp"
    port_range  = "22"
  }]
  policies = [{ id = cloudflare_zero_trust_access_policy.muccho.id, precedence = 1 }]
}

# Source ordering is deliberate: never create reachability before narrow auth.
resource "cloudflare_zero_trust_network_hostname_route" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  hostname   = local.private_host
  comment    = "muccho to versa dev SSH only; no published hostname"
  depends_on = [cloudflare_zero_trust_access_application.versa]
}

output "private_hostname" {
  value = local.private_host
}
