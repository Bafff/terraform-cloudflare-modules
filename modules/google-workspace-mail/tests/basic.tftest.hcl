mock_provider "cloudflare" {}

run "derived_protected_mail_records" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mail-mx-primary = {
          content  = "smtp.example.com"
          priority = 10
          ttl      = 1
        }
      }
      spf = {
        content = "v=spf1 include:_spf.example.com ~all"
        ttl     = 600
      }
      dkim = {
        selector = "google"
        content  = "v=DKIM1; k=rsa; p=ZmFrZQ=="
        ttl      = 120
      }
      dmarc = {
        content = "v=DMARC1; p=none; rua=mailto:owner@example.com"
        ttl     = 1800
      }
      bimi = {
        selector = "default"
        content  = "v=BIMI1; l=https://example.com/logo.svg"
        ttl      = 7200
      }
    }
  }

  assert {
    condition     = toset(keys(cloudflare_dns_record.this)) == toset(["mail-mx-primary", "spf", "google-dkim", "dmarc", "bimi"])
    error_message = "Mail records must use the reviewed stable logical keys."
  }

  assert {
    condition     = cloudflare_dns_record.this["mail-mx-primary"].name == "example.com" && cloudflare_dns_record.this["mail-mx-primary"].type == "MX" && cloudflare_dns_record.this["mail-mx-primary"].priority == 10
    error_message = "MX name, type, and imported priority must be preserved."
  }

  assert {
    condition     = cloudflare_dns_record.this["spf"].name == "example.com" && cloudflare_dns_record.this["spf"].type == "TXT"
    error_message = "SPF must be a TXT record at the supplied domain."
  }

  assert {
    condition     = cloudflare_dns_record.this["google-dkim"].name == "google._domainkey.example.com" && cloudflare_dns_record.this["dmarc"].name == "_dmarc.example.com" && cloudflare_dns_record.this["bimi"].name == "default._bimi.example.com"
    error_message = "The module must derive DKIM, DMARC, and BIMI names from semantic inputs."
  }

  assert {
    condition     = alltrue([for record in cloudflare_dns_record.this : !record.proxied])
    error_message = "Every mail record must remain DNS-only."
  }

  assert {
    condition     = alltrue([for record in cloudflare_dns_record.this : record.zone_id == "00000000000000000000000000000000"])
    error_message = "Every mail record must use the supplied zone ID."
  }

  assert {
    condition     = cloudflare_dns_record.this["mail-mx-primary"].ttl == 1 && cloudflare_dns_record.this["spf"].ttl == 600 && cloudflare_dns_record.this["google-dkim"].ttl == 120 && cloudflare_dns_record.this["dmarc"].ttl == 1800 && cloudflare_dns_record.this["bimi"].ttl == 7200
    error_message = "The module must preserve each imported TTL without choosing defaults."
  }

  assert {
    condition     = cloudflare_dns_record.this["spf"].content == "v=spf1 include:_spf.example.com ~all" && cloudflare_dns_record.this["google-dkim"].content == "v=DKIM1; k=rsa; p=ZmFrZQ==" && cloudflare_dns_record.this["dmarc"].content == "v=DMARC1; p=none; rua=mailto:owner@example.com" && cloudflare_dns_record.this["bimi"].content == "v=BIMI1; l=https://example.com/logo.svg"
    error_message = "The module must preserve verified policy content exactly."
  }

  assert {
    condition     = cloudflare_dns_record.this["mail-mx-primary"].type == "MX" && alltrue([for key in ["spf", "google-dkim", "dmarc", "bimi"] : cloudflare_dns_record.this[key].type == "TXT"])
    error_message = "The module must derive MX and TXT types without caller input."
  }
}

run "rejects_invalid_mx_key" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mx-primary = {
          content  = "smtp.example.com"
          priority = 10
          ttl      = 1
        }
      }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.mail]
}

run "rejects_empty_content" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mail-mx-primary = {
          content  = "smtp.example.com"
          priority = 10
          ttl      = 1
        }
      }
      spf   = { content = "", ttl = 3600 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.mail]
}

run "rejects_ttl_below_minimum" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mail-mx-primary = {
          content  = "smtp.example.com"
          priority = 10
          ttl      = 1
        }
      }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 59 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.mail]
}

run "rejects_fractional_priority" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mail-mx-primary = {
          content  = "smtp.example.com"
          priority = 1.5
          ttl      = 1
        }
      }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.mail]
}

run "rejects_invalid_selector" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "example.com"
    mail = {
      mx = {
        mail-mx-primary = {
          content  = "smtp.example.com"
          priority = 10
          ttl      = 1
        }
      }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
      dkim  = { selector = "Google._domainkey", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.mail]
}

run "rejects_invalid_zone_id" {
  command = plan

  variables {
    zone_id = "0000000000000000000000000000000G"
    domain  = "example.com"
    mail = {
      mx    = { mail-mx-primary = { content = "smtp.example.com", priority = 10, ttl = 1 } }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.zone_id]
}

run "rejects_invalid_domain" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    domain  = "Example.COM"
    mail = {
      mx    = { mail-mx-primary = { content = "smtp.example.com", priority = 10, ttl = 1 } }
      spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
      dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
      dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
      bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
    }
  }

  expect_failures = [var.domain]
}
