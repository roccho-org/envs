# Inert Cloudflare Tunnel source candidate for resources#143. The route/policy are intentionally
# absent. Terraform state/plan hold a sensitive tunnel token and MUST remain encrypted.
# No apply workflow, public hostname, DNS, service token or secret delivery is added.
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

locals {
  name = "versa-private-ssh"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = local.name
  config_src = "cloudflare"
}

# No publicly reachable ingress. Later /32 private route + Gateway policy is a separate gate.
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

output "credentials" {
  sensitive = true
  value = {
    tunnel_token = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
  }
}
