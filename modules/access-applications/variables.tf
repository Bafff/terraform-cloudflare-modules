variable "account_id" {
  description = "Cloudflare account identifier that owns the identity provider and reusable policy."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a lowercase 32-character hexadecimal Cloudflare account identifier."
  }
}

variable "zone_id" {
  description = "Cloudflare zone identifier that owns the Access applications."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a lowercase 32-character hexadecimal Cloudflare zone identifier."
  }
}

variable "allowed_emails" {
  description = "Email addresses permitted by the reusable Access policy."
  type        = set(string)
  nullable    = false
  sensitive   = true

  validation {
    condition     = length(var.allowed_emails) > 0
    error_message = "allowed_emails must contain at least one address."
  }

  validation {
    condition = alltrue([
      for address in var.allowed_emails :
      length(address) <= 254 &&
      length(split("@", address)[0]) <= 64 &&
      can(regex("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$", address))
    ])
    error_message = "Every allowed_emails value must use valid email address syntax, a local part no longer than 64 characters, a total length no longer than 254 characters, and a fully qualified domain."
  }
}

variable "applications" {
  description = "Self-hosted Access applications keyed by stable Terraform identity."
  type = map(object({
    name   = string
    domain = string
  }))
  nullable = false

  validation {
    condition     = length(var.applications) > 0
    error_message = "applications must contain at least one application."
  }

  validation {
    condition     = alltrue([for key in keys(var.applications) : can(regex("^[a-z0-9]+(?:-[a-z0-9]+)*$", key))])
    error_message = "Application keys must be lowercase semantic slugs."
  }

  validation {
    condition     = alltrue([for application in values(var.applications) : length(trimspace(application.name)) > 0])
    error_message = "Every application name must contain a non-whitespace character."
  }

  validation {
    condition = alltrue([
      for application in values(var.applications) :
      length(application.domain) <= 253 &&
      can(regex("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$", application.domain))
    ])
    error_message = "Every application domain must be a lowercase fully qualified hostname without a path or trailing dot."
  }
}

variable "session_duration" {
  description = "Access application and reusable policy session duration."
  type        = string
  nullable    = false

  validation {
    condition     = var.session_duration == "730h"
    error_message = "session_duration must be exactly 730h."
  }
}
