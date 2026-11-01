# Private-only Versa connector: no DNS, published application, or Access web ingress.
# A separate admission/readback gate is required before any effect. #143
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }
  backend "http" {}
  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}

variable "account_id" {
  type = string
}
variable "versa_private_cidr" {
  type = string
  validation {
    condition = can(cidrnetmask(var.versa_private_cidr)) && can(regex("^((10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})|(192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})|(172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}))/32$", var.versa_private_cidr))
    error_message = "Require one observed RFC1918 IPv4 host /32; never route an entire LAN."
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = "versa-muccho-private"
  config_src = "cloudflare"
}

# The empty published-app configuration intentionally returns 404 for every hostname.
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  config = {
    ingress = [{ service = "http_status:404" }]
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_route" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  network    = var.versa_private_cidr
  comment    = "Only the observed Versa host /32; SSH admission is separately controlled"
}

# Block by default. Adding the single muccho-specific allow rule requires independent
# existing-policy precedence and device-identity readback before any apply.
resource "cloudflare_zero_trust_gateway_policy" "versa_deny" {
  account_id = var.account_id
  name       = "versa-muccho-private-default-deny"
  action     = "block"
  enabled    = true
  filters    = ["l4"]
  # Reserve precedence 1 for a separately reviewed muccho-only SSH allow policy.
  precedence = 2
  traffic    = "any(net.dst.ip[*] in {${var.versa_private_cidr}})"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}

output "tunnel_token" {
  sensitive = true
  value     = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
}
output "private_binding" {
  value = {
    tunnel_id = cloudflare_zero_trust_tunnel_cloudflared.versa.id
    route_id  = cloudflare_zero_trust_tunnel_cloudflared_route.versa.id
    network   = var.versa_private_cidr
  }
}
