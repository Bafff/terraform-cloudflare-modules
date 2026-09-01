variable "zone_id" {
  description = "Cloudflare zone identifier that owns the DNS records."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a lowercase 32-character hexadecimal Cloudflare zone identifier."
  }
}

variable "records" {
  description = "DNS records keyed by stable Terraform identity."
  type = map(object({
    name     = string
    type     = string
    content  = string
    ttl      = number
    proxied  = bool
    priority = optional(number)
    comment  = optional(string)
    settings = optional(object({
      flatten_cname = optional(bool)
      ipv4_only     = optional(bool)
      ipv6_only     = optional(bool)
    }))
    tags = optional(set(string), [])
  }))
  nullable = false

  validation {
    condition     = alltrue([for key in keys(var.records) : can(regex("^[a-z0-9]+(?:-[a-z0-9]+)*$", key))])
    error_message = "Record keys must be lowercase semantic slugs."
  }

  validation {
    condition = alltrue([
      for record in values(var.records) :
      length(trimspace(record.name)) > 0 &&
      length(trimspace(record.content)) > 0 &&
      contains(["A", "AAAA", "CNAME", "MX", "NS", "OPENPGPKEY", "PTR", "TXT"], record.type) &&
      (record.ttl == 1 || (record.ttl >= 60 && record.ttl <= 86400)) &&
      (record.priority == null || (record.priority == floor(record.priority) && record.priority >= 0 && record.priority <= 65535))
    ])
    error_message = "Each record must use a supported uppercase type, non-empty name/content, valid TTL, and integer priority from 0 through 65535."
  }

  validation {
    condition = alltrue([
      for record in values(var.records) :
      contains(["MX"], record.type) ? record.priority != null : record.priority == null
    ])
    error_message = "MX records require priority; other supported record types must omit it."
  }

  validation {
    condition = alltrue([
      for record in values(var.records) :
      !record.proxied || (contains(["A", "AAAA", "CNAME"], record.type) && record.ttl == 1)
    ])
    error_message = "Proxied records must use type A, AAAA, or CNAME with automatic TTL 1."
  }
}
