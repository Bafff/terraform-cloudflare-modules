mock_provider "cloudflare" {
  override_resource {
    target          = module.cloudflare_tunnel.cloudflare_zero_trust_tunnel_cloudflared.this
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = module.dns_records.cloudflare_dns_record.this["docs"]
    override_during = plan
    values = {
      id = "00000000000000000000000000000000"
    }
  }

  override_resource {
    target          = module.dns_records.cloudflare_dns_record.this["lots"]
    override_during = plan
    values = {
      id = "00000000000000000000000000000000"
    }
  }

  override_resource {
    target          = module.google_workspace_mail.cloudflare_dns_record.this
    override_during = plan
    values = {
      id = "00000000000000000000000000000000"
    }
  }

  override_resource {
    target          = module.access_applications.cloudflare_zero_trust_access_identity_provider.otp
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = module.access_applications.cloudflare_zero_trust_access_policy.owners
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = module.access_applications.cloudflare_zero_trust_access_application.this["docs"]
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = module.access_applications.cloudflare_zero_trust_access_application.this["lots"]
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "random" {
  override_resource {
    target          = module.cloudflare_tunnel.random_bytes.tunnel_secret
    override_during = plan
    values = {
      base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}

run "all_modules_compose" {
  command = plan

  assert {
    condition = { for key, record in local.dns_records : key => record.content } == {
      docs = "00000000-0000-0000-0000-000000000000.tunnel.example.com"
      lots = "00000000-0000-0000-0000-000000000000.tunnel.example.com"
    }
    error_message = "Both application DNS targets must be derived from the tunnel ID."
  }

  assert {
    condition     = toset(keys(output.dns_record_ids)) == toset(["docs", "lots"])
    error_message = "Ordinary DNS record keys must match the protected hostnames."
  }

  assert {
    condition     = toset(keys(output.access_application_ids)) == toset(["docs", "lots"])
    error_message = "Access application keys must match the protected hostnames."
  }

  assert {
    condition = { for key, application in local.applications : key => application.domain } == {
      docs = "docs.example.com"
      lots = "lots.example.com"
    }
    error_message = "Access applications must protect the same docs and lots hostnames as DNS."
  }

  assert {
    condition     = toset(keys(output.mail_dns_record_ids)) == toset(["mail-mx-primary", "spf", "google-dkim", "dmarc", "bimi"])
    error_message = "The mail module must own the complete synthetic mail record set."
  }
}
