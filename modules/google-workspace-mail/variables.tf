variable "zone_id" {
  description = "Cloudflare zone identifier that owns the mail DNS records."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a lowercase 32-character hexadecimal Cloudflare zone identifier."
  }
}

variable "domain" {
  description = "Lowercase DNS domain used to derive mail record names."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$", var.domain))
    error_message = "domain must be a lowercase fully qualified DNS name without a trailing dot."
  }
}

variable "mail" {
  description = "Verified Google Workspace DNS content and imported timing and priority values."
  type = object({
    mx = map(object({
      content  = string
      priority = number
      ttl      = number
    }))
    spf = object({
      content = string
      ttl     = number
    })
    dkim = object({
      selector = string
      content  = string
      ttl      = number
    })
    dmarc = object({
      content = string
      ttl     = number
    })
    bimi = object({
      selector = string
      content  = string
      ttl      = number
    })
  })
  nullable = false

  validation {
    condition     = length(var.mail.mx) > 0 && alltrue([for key in keys(var.mail.mx) : can(regex("^mail-mx-[a-z0-9]+(?:-[a-z0-9]+)*$", key))])
    error_message = "mail.mx must contain at least one entry keyed by a stable mail-mx-* slug."
  }

  validation {
    condition = alltrue(concat(
      [for record in values(var.mail.mx) : length(trimspace(record.content)) > 0],
      [length(trimspace(var.mail.spf.content)) > 0],
      [length(trimspace(var.mail.dkim.content)) > 0],
      [length(trimspace(var.mail.dmarc.content)) > 0],
      [length(trimspace(var.mail.bimi.content)) > 0],
    ))
    error_message = "Mail record content must not be empty."
  }

  validation {
    condition = alltrue(concat(
      [for record in values(var.mail.mx) : record.ttl == 1 || (record.ttl >= 60 && record.ttl <= 86400)],
      [for ttl in [var.mail.spf.ttl, var.mail.dkim.ttl, var.mail.dmarc.ttl, var.mail.bimi.ttl] : ttl == 1 || (ttl >= 60 && ttl <= 86400)],
    ))
    error_message = "Mail TTL must be automatic 1 or between 60 and 86400 seconds."
  }

  validation {
    condition     = alltrue([for record in values(var.mail.mx) : record.priority == floor(record.priority) && record.priority >= 0 && record.priority <= 65535])
    error_message = "MX priority must be an integer from 0 through 65535."
  }

  validation {
    condition = alltrue([
      for selector in [var.mail.dkim.selector, var.mail.bimi.selector] :
      can(regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", selector))
    ])
    error_message = "DKIM and BIMI selectors must be lowercase DNS labels."
  }
}
