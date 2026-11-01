# #143: source-only, standalone remotely managed Versa tunnel.
# No published hostname, private network route, Gateway/Access policy or provider apply workflow.
# A route is forbidden until muccho WARP enrollment, exact Versa /32 and deny-by-default authorization are proved.
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

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = "versa-private-ssh"
  config_src = "cloudflare"
}

# Deny all published applications. Private WARP routes are separate, not implicitly enabled.
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  config = {
    ingress = [{ service = "http_status:404" }]
  }
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}

output "connector_token" {
  sensitive = true
  value     = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
}

output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}
