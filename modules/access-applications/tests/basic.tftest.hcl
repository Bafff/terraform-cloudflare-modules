mock_provider "cloudflare" {
  override_resource {
    target          = cloudflare_zero_trust_access_identity_provider.otp
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = cloudflare_zero_trust_access_policy.owners
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = cloudflare_zero_trust_access_application.this["docs"]
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target          = cloudflare_zero_trust_access_application.this["lots"]
    override_during = plan
    values = {
      id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  account_id     = "00000000000000000000000000000000"
  zone_id        = "00000000000000000000000000000000"
  allowed_emails = ["owner-a@example.com", "owner-b@example.com"]
  applications = {
    docs = {
      name   = "Documentation"
      domain = "docs.example.com"
    }
    lots = {
      name   = "Lots"
      domain = "lots.example.com"
    }
  }
  session_duration = "730h"
}

run "shared_otp_protected_applications" {
  command = plan

  variables {
    account_id     = "00000000000000000000000000000000"
    zone_id        = "00000000000000000000000000000000"
    allowed_emails = ["owner-a@example.com", "owner-b@example.com"]
    applications = {
      docs = {
        name   = "Documentation"
        domain = "docs.example.com"
      }
      lots = {
        name   = "Lots"
        domain = "lots.example.com"
      }
    }
    session_duration = "730h"
  }

  assert {
    condition     = cloudflare_zero_trust_access_identity_provider.otp.account_id == "00000000000000000000000000000000" && cloudflare_zero_trust_access_identity_provider.otp.zone_id == null
    error_message = "The OTP identity provider must use account scope only."
  }

  assert {
    condition     = cloudflare_zero_trust_access_identity_provider.otp.name == "Owner email OTP" && cloudflare_zero_trust_access_identity_provider.otp.type == "onetimepin"
    error_message = "The shared identity provider must be the named email one-time PIN provider."
  }

  assert {
    condition = nonsensitive(alltrue([
      for key, value in cloudflare_zero_trust_access_identity_provider.otp.config :
      value == null if !contains(["enable_encryption", "redirect_url", "restrict_to_account_members"], key)
    ]))
    error_message = "The one-time PIN identity provider must use an empty config object."
  }

  assert {
    condition     = cloudflare_zero_trust_access_policy.owners.account_id == "00000000000000000000000000000000" && cloudflare_zero_trust_access_policy.owners.name == "Owners" && cloudflare_zero_trust_access_policy.owners.decision == "allow"
    error_message = "The reusable Owners policy must be an account-scoped allow policy."
  }

  assert {
    condition     = nonsensitive(toset([for rule in cloudflare_zero_trust_access_policy.owners.include : rule.email.email])) == nonsensitive(var.allowed_emails)
    error_message = "The shared policy must contain exactly one email rule for every supplied address."
  }

  assert {
    condition     = cloudflare_zero_trust_access_policy.owners.session_duration == "730h"
    error_message = "The shared policy must use the supplied one-month session duration."
  }

  assert {
    condition     = toset(keys(cloudflare_zero_trust_access_application.this)) == toset(["docs", "lots"])
    error_message = "Application map keys must become stable resource instance keys."
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.this["docs"].name == "Documentation" && cloudflare_zero_trust_access_application.this["docs"].domain == "docs.example.com" && cloudflare_zero_trust_access_application.this["lots"].name == "Lots" && cloudflare_zero_trust_access_application.this["lots"].domain == "lots.example.com"
    error_message = "Applications must preserve the supplied names and whole hostnames."
  }

  assert {
    condition     = alltrue([for application in cloudflare_zero_trust_access_application.this : application.zone_id == "00000000000000000000000000000000" && application.account_id == null && application.type == "self_hosted" && application.session_duration == "730h"])
    error_message = "Every application must be zone-scoped, self-hosted, and use the exact one-month session duration."
  }

  assert {
    condition     = alltrue([for application in cloudflare_zero_trust_access_application.this : application.allowed_idps == toset([cloudflare_zero_trust_access_identity_provider.otp.id]) && application.auto_redirect_to_identity])
    error_message = "Every application must permit only the OTP provider and redirect to it automatically."
  }

  assert {
    condition     = alltrue([for application in cloudflare_zero_trust_access_application.this : length(application.policies) == 1 && application.policies[0].id == cloudflare_zero_trust_access_policy.owners.id && application.policies[0].precedence == 1])
    error_message = "Every application must reference the same reusable policy at precedence 1."
  }

  assert {
    condition     = output.otp_identity_provider_id == "00000000-0000-0000-0000-000000000000" && output.owners_access_policy_id == "00000000-0000-0000-0000-000000000000"
    error_message = "Shared resource outputs must return their mocked identifiers."
  }

  assert {
    condition     = toset(keys(output.access_application_ids)) == toset(["docs", "lots"])
    error_message = "The application ID output must preserve caller-selected application keys."
  }
}

run "rejects_invalid_account_id" {
  command = plan

  variables {
    account_id = "0000000000000000000000000000000G"
  }

  expect_failures = [var.account_id]
}

run "rejects_invalid_zone_id" {
  command = plan

  variables {
    zone_id = "0000000000000000000000000000000G"
  }

  expect_failures = [var.zone_id]
}

run "rejects_invalid_email" {
  command = plan

  variables {
    allowed_emails = ["owner-a.example.com"]
  }

  expect_failures = [var.allowed_emails]
}

run "rejects_email_with_empty_local_atom" {
  command = plan

  variables {
    allowed_emails = ["owner..a@example.com"]
  }

  expect_failures = [var.allowed_emails]
}

run "rejects_empty_email_set" {
  command = plan

  variables {
    allowed_emails = []
  }

  expect_failures = [var.allowed_emails]
}

run "rejects_invalid_application_domain" {
  command = plan

  variables {
    applications = {
      docs = {
        name   = "Documentation"
        domain = "Docs.example.com"
      }
    }
  }

  expect_failures = [var.applications]
}

run "rejects_empty_application_map" {
  command = plan

  variables {
    applications = {}
  }

  expect_failures = [var.applications]
}

run "rejects_unstable_application_key" {
  command = plan

  variables {
    applications = {
      "docs!" = {
        name   = "Documentation"
        domain = "docs.example.com"
      }
    }
  }

  expect_failures = [var.applications]
}

run "rejects_empty_application_name" {
  command = plan

  variables {
    applications = {
      docs = {
        name   = "   "
        domain = "docs.example.com"
      }
    }
  }

  expect_failures = [var.applications]
}

run "rejects_other_session_duration" {
  command = plan

  variables {
    session_duration = "720h"
  }

  expect_failures = [var.session_duration]
}
