# #143: Source-only, remote-managed Versa Tunnel identity.
# No route, public hostname, DNS, Access application, Gateway policy or effect
# entry is created in this stage. The Tunnel alone is not reachable by a client.
# A separate explicit admission must prove the muccho-only private route
# (including destination port 22) and the matched NixOS local origin first.
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }

  # Provider/lock custody is selected by a separately authorized exact-source caller.
  backend "http" {}

  encryption {
    state { enforced = true }
    plan { enforced = true }
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

data "cloudflare_zero_trust_tunnel_cloudflared_token" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}

output "tunnel_token" {
  sensitive = true
  value     = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
}
