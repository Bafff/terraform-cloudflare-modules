resource "cloudflare_zero_trust_access_identity_provider" "otp" {
  account_id = var.account_id
  name       = "Owner email OTP"
  type       = "onetimepin"
  config     = {}
}

resource "cloudflare_zero_trust_access_policy" "owners" {
  account_id       = var.account_id
  name             = "Owners"
  decision         = "allow"
  session_duration = var.session_duration
  include = [for address in var.allowed_emails : {
    email = { email = address }
  }]
}

resource "cloudflare_zero_trust_access_application" "this" {
  for_each = var.applications

  zone_id                   = var.zone_id
  name                      = each.value.name
  domain                    = each.value.domain
  type                      = "self_hosted"
  session_duration          = var.session_duration
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.otp.id]
  auto_redirect_to_identity = true
  policies = [{
    id         = cloudflare_zero_trust_access_policy.owners.id
    precedence = 1
  }]
}
