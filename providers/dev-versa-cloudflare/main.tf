# Versa-only Cloudflare connector: first admission stage.
# No private route, DNS, published application, Access/Gateway policy or effect workflow is created by this root.
# A /32 route MUST wait for muccho-only Gateway deny/allow verification (resources #143).
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
  name       = "versa-muccho-private-ssh"
  config_src = "cloudflare"
}

# Explicit catch-all prevents this connector from publishing any application.
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  config = {
    ingress = [
      { service = "http_status:404" },
    ]
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
