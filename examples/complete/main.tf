locals {
  applications = {
    docs = {
      name   = "Documentation"
      domain = "docs.${var.domain}"
    }
    lots = {
      name   = "Lots"
      domain = "lots.${var.domain}"
    }
  }

  tunnel_dns_targets = {
    for key in keys(local.applications) :
    key => "${module.cloudflare_tunnel.tunnel_id}.tunnel.example.com"
  }

  dns_records = {
    for key, application in local.applications : key => {
      name    = application.domain
      type    = "CNAME"
      content = local.tunnel_dns_targets[key]
      ttl     = 1
      proxied = true
    }
  }
}

module "cloudflare_tunnel" {
  source = "../../modules/cloudflare-tunnel"

  account_id = var.account_id
  name       = "example-tunnel"
}

module "dns_records" {
  source = "../../modules/dns-records"

  zone_id = var.zone_id
  records = local.dns_records
}

module "google_workspace_mail" {
  source = "../../modules/google-workspace-mail"

  zone_id = var.zone_id
  domain  = var.domain
  mail = {
    mx = {
      mail-mx-primary = {
        content  = "smtp.${var.domain}"
        priority = 10
        ttl      = 1
      }
    }
    spf   = { content = "v=spf1 include:_spf.${var.domain} ~all", ttl = 3600 }
    dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
    dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@${var.domain}", ttl = 3600 }
    bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo", ttl = 3600 }
  }
}

module "access_applications" {
  source = "../../modules/access-applications"

  account_id       = var.account_id
  zone_id          = var.zone_id
  allowed_emails   = var.allowed_emails
  applications     = local.applications
  session_duration = "730h"
}
