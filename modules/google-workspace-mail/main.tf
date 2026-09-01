locals {
  mail_records = merge(
    {
      for key, record in var.mail.mx : key => {
        name     = var.domain
        type     = "MX"
        content  = record.content
        ttl      = record.ttl
        priority = record.priority
      }
    },
    {
      spf = {
        name     = var.domain
        type     = "TXT"
        content  = var.mail.spf.content
        ttl      = var.mail.spf.ttl
        priority = null
      }
      google-dkim = {
        name     = "${var.mail.dkim.selector}._domainkey.${var.domain}"
        type     = "TXT"
        content  = var.mail.dkim.content
        ttl      = var.mail.dkim.ttl
        priority = null
      }
      dmarc = {
        name     = "_dmarc.${var.domain}"
        type     = "TXT"
        content  = var.mail.dmarc.content
        ttl      = var.mail.dmarc.ttl
        priority = null
      }
      bimi = {
        name     = "${var.mail.bimi.selector}._bimi.${var.domain}"
        type     = "TXT"
        content  = var.mail.bimi.content
        ttl      = var.mail.bimi.ttl
        priority = null
      }
    },
  )
}

resource "cloudflare_dns_record" "this" {
  for_each = local.mail_records

  zone_id  = var.zone_id
  name     = each.value.name
  type     = each.value.type
  content  = each.value.content
  ttl      = each.value.ttl
  proxied  = false
  priority = each.value.priority

  lifecycle {
    prevent_destroy = true
  }
}
