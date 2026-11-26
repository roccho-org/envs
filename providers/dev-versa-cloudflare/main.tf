# The versa Cloudflare root: one named Tunnel for versa with its two public names, their DNS records, a self-hosted
# Access application and policy for each name, and the one service token for muse. versa-ssh admits only that token
# (Service Auth); versa admits only the bound identity, and cloudflared also requires that application's Access JWT.
#
# Applied only by the effect entry `versa-root` from the manual project-dev-versa-tunnel workflow; CI only validates it.
# Its state holds the Tunnel token and the service-token secret, encrypted. Nothing here adopts, imports or moves an
# existing resource.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }

  # Partial standard HTTP backend: the state and lock addresses are given at init and point at a transient loopback
  # terraform-backend-git child that keeps this state on the envs GitHub ref declared in contracts/environments.jsonl.
  backend "http" {}

  # Methods and keys come only from TF_ENCRYPTION; enforced state and plan encryption refuses plaintext without it.
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

variable "zone_id" {
  type = string
}

# The one identity the versa HTTP application admits; bound at deployment, never written in source.
variable "access_email" {
  type      = string
  sensitive = true
}

# The service token's lifetime is a deployment decision (rotation and delivery are later gates); no default.
variable "service_token_duration" {
  type = string
}

locals {
  ssh  = "versa-ssh.roccho.com"
  http = "versa.roccho.com"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "versa" {
  account_id = var.account_id
  name       = "versa"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
  config = {
    ingress = [
      { hostname = local.ssh, service = "ssh://127.0.0.1:22" },
      {
        hostname = local.http
        service  = "http://127.0.0.1:7824"
        origin_request = {
          access = {
            required  = true
            team_name = "roccho"
            aud_tag   = [cloudflare_zero_trust_access_application.http.aud]
          }
        }
      },
      { service = "http_status:404" },
    ]
  }
}

resource "cloudflare_dns_record" "versa" {
  for_each = toset([local.ssh, local.http])
  zone_id  = var.zone_id
  name     = each.value
  type     = "CNAME"
  content  = "${cloudflare_zero_trust_tunnel_cloudflared.versa.id}.cfargotunnel.com"
  proxied  = true
  ttl      = 1
}

resource "cloudflare_zero_trust_access_service_token" "muse" {
  account_id = var.account_id
  name       = "muse"
  duration   = var.service_token_duration
}

# Service Auth for exactly the muse token; no identity, bypass or any-token rule.
resource "cloudflare_zero_trust_access_policy" "ssh" {
  account_id = var.account_id
  name       = "versa-ssh"
  decision   = "non_identity"
  include    = [{ service_token = { token_id = cloudflare_zero_trust_access_service_token.muse.id } }]
}

# Exactly the bound identity; no group, domain or everyone rule.
resource "cloudflare_zero_trust_access_policy" "http" {
  account_id = var.account_id
  name       = "versa"
  decision   = "allow"
  include    = [{ email = { email = var.access_email } }]
}

resource "cloudflare_zero_trust_access_application" "ssh" {
  account_id = var.account_id
  name       = "versa-ssh"
  domain     = local.ssh
  type       = "self_hosted"
  policies   = [{ id = cloudflare_zero_trust_access_policy.ssh.id, precedence = 1 }]
}

resource "cloudflare_zero_trust_access_application" "http" {
  account_id = var.account_id
  name       = "versa"
  domain     = local.http
  type       = "self_hosted"
  policies   = [{ id = cloudflare_zero_trust_access_policy.http.id, precedence = 1 }]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "versa" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.versa.id
}

output "credentials" {
  sensitive = true
  value = {
    tunnel_token        = data.cloudflare_zero_trust_tunnel_cloudflared_token.versa.token
    service_token_id    = cloudflare_zero_trust_access_service_token.muse.client_id
    service_token_value = cloudflare_zero_trust_access_service_token.muse.client_secret
  }
}
