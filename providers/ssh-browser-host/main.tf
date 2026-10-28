# Independent first adoption. Never initialize this root against rent's state.
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }

  # The owner supplies this root's dedicated state/lock addresses at init.
  backend "http" {}

  # Same enforced OpenTofu state/plan encryption shape as dev-rent-cloudflare.
  # Supply encryption configuration through TF_ENCRYPTION; never commit it.
  encryption {
    state { enforced = true }
    plan { enforced = true }
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "host" {
  account_id = var.account_id
  name       = "ssh-${var.host_id}"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "host" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.host.id
  config = {
    ingress = [
      { hostname = var.hostname, service = var.origin_service },
      { service = "http_status:404" },
    ]
  }
}

resource "cloudflare_dns_record" "host" {
  zone_id = var.zone_id
  name    = var.hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.host.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# Browser identity only: no domain-wide, everyone, bypass or Service Auth rule.
resource "cloudflare_zero_trust_access_policy" "host" {
  account_id       = var.account_id
  name             = "ssh-${var.host_id}"
  decision         = "allow"
  session_duration = var.session_duration
  include = [for email in sort(tolist(var.allowed_emails)) : {
    email = { email = email }
  }]
}

resource "cloudflare_zero_trust_access_application" "host" {
  account_id       = var.account_id
  name             = "ssh-${var.host_id}"
  domain           = var.hostname
  type             = "self_hosted"
  session_duration = var.session_duration
  policies = [{
    id         = cloudflare_zero_trust_access_policy.host.id
    precedence = 1
  }]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "host" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.host.id
}

output "public_binding" {
  value = {
    host_id          = var.host_id
    hostname         = var.hostname
    access_mode      = "browser"
    tunnel_id        = cloudflare_zero_trust_tunnel_cloudflared.host.id
    application_id   = cloudflare_zero_trust_access_application.host.id
    policy_id        = cloudflare_zero_trust_access_policy.host.id
    session_duration = var.session_duration
  }
}

# Only the target connector's existing secret-custody/delivery boundary consumes this.
# `sensitive` hides normal CLI display; it does not remove the value from state/plan.
output "connector_token" {
  sensitive = true
  value     = data.cloudflare_zero_trust_tunnel_cloudflared_token.host.token
}
