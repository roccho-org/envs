variable "host_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,39}$", var.host_id))
    error_message = "An explicitly adopted lower-case host ID is required."
  }
}

variable "account_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "An adopted Cloudflare account ID is required."
  }
}

variable "zone_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "An adopted Cloudflare zone ID is required."
  }
}

variable "hostname" {
  type     = string
  nullable = false
  validation {
    condition     = length(var.hostname) <= 253 && can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.hostname))
    error_message = "One explicitly adopted lower-case public FQDN is required."
  }
}

variable "origin_service" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^ssh://(127\\.0\\.0\\.1|localhost|\\[::1\\]):[1-9][0-9]{0,4}$", var.origin_service)) && can(regex(":([0-9]+)$", var.origin_service)) ? tonumber(regex(":([0-9]+)$", var.origin_service)[0]) <= 65535 : false
    error_message = "An explicit loopback SSH origin with port 1..65535 is required."
  }
}

variable "allowed_emails" {
  type     = set(string)
  nullable = false
  validation {
    condition = length(var.allowed_emails) >= 1 && length(var.allowed_emails) <= 16 && alltrue([
      for email in var.allowed_emails : can(regex("^[a-z0-9._%+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", email)) && !strcontains(email, "..")
    ])
    error_message = "One to sixteen explicit lower-case email identities are required; wildcards/domains are forbidden."
  }
}

variable "session_duration" {
  type     = string
  nullable = false
  validation {
    condition     = contains(["15m", "30m", "1h", "2h", "4h", "8h"], var.session_duration)
    error_message = "The owner must select a session duration from 15m, 30m, 1h, 2h, 4h or 8h."
  }
}
