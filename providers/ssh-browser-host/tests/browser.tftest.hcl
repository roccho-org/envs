# Only the schema and local plan are tested. No real provider configuration or API is used.
mock_provider "cloudflare" {
  mock_resource "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = { id = "11111111-1111-4111-8111-111111111111" }
  }
  mock_resource "cloudflare_zero_trust_access_application" {
    defaults = { id = "22222222-2222-4222-8222-222222222222" }
  }
  mock_resource "cloudflare_zero_trust_access_policy" {
    defaults = { id = "33333333-3333-4333-8333-333333333333" }
  }
}

variables {
  host_id          = "fixture-host"
  account_id       = "00000000000000000000000000000000"
  zone_id          = "11111111111111111111111111111111"
  hostname         = "ssh.example.invalid"
  origin_service   = "ssh://127.0.0.1:22"
  allowed_emails   = ["fixture@example.invalid"]
  session_duration = "1h"
}

run "identity_only_loopback_ssh" {
  command = plan
  assert {
    condition     = cloudflare_zero_trust_access_policy.host.decision == "allow" && length(cloudflare_zero_trust_access_policy.host.include) == 1 && one(cloudflare_zero_trust_access_policy.host.include).email.email == "fixture@example.invalid"
    error_message = "Exactly the adopted browser identity must be allowed."
  }
  assert {
    condition     = length(cloudflare_zero_trust_tunnel_cloudflared_config.host.config.ingress) == 2 && cloudflare_zero_trust_tunnel_cloudflared_config.host.config.ingress[0].service == "ssh://127.0.0.1:22" && cloudflare_zero_trust_tunnel_cloudflared_config.host.config.ingress[1].service == "http_status:404"
    error_message = "The SSH origin and fail-closed fallback must remain bounded."
  }
  assert {
    condition     = output.public_binding.access_mode == "browser" && output.public_binding.hostname == "ssh.example.invalid" && output.public_binding.session_duration == "1h"
    error_message = "Public output must describe the adopted browser endpoint."
  }
}

run "wildcard_identity_refused" {
  command = plan
  variables { allowed_emails = ["*@example.invalid"] }
  expect_failures = [var.allowed_emails]
}

run "empty_identity_refused" {
  command = plan
  variables { allowed_emails = [] }
  expect_failures = [var.allowed_emails]
}

run "non_loopback_origin_refused" {
  command = plan
  variables { origin_service = "ssh://192.0.2.1:22" }
  expect_failures = [var.origin_service]
}

run "origin_port_overflow_refused" {
  command = plan
  variables { origin_service = "ssh://127.0.0.1:65536" }
  expect_failures = [var.origin_service]
}

run "unbounded_session_refused" {
  command = plan
  variables { session_duration = "720h" }
  expect_failures = [var.session_duration]
}
