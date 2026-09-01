variable "account_id" {
  description = "Cloudflare account identifier that owns the tunnel."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a lowercase 32-character hexadecimal Cloudflare account identifier."
  }
}

variable "name" {
  description = "Name of the Cloudflare Tunnel."
  type        = string
  nullable    = false

  validation {
    condition     = length(trimspace(var.name)) > 0
    error_message = "name must not be empty."
  }
}
