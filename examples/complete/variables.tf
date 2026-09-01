variable "account_id" {
  description = "Synthetic Cloudflare account identifier used by this non-deployable example."
  type        = string
  default     = "00000000000000000000000000000000"
}

variable "zone_id" {
  description = "Synthetic Cloudflare zone identifier used by this non-deployable example."
  type        = string
  default     = "00000000000000000000000000000000"
}

variable "domain" {
  description = "Reserved example domain used throughout this non-deployable composition."
  type        = string
  default     = "example.com"
}

variable "allowed_emails" {
  description = "Synthetic owners permitted by the example Access policy."
  type        = set(string)
  default     = ["owner-a@example.com", "owner-b@example.com"]
  sensitive   = true
}
