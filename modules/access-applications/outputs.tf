output "otp_identity_provider_id" {
  description = "Identifier of the account-scoped email one-time PIN identity provider."
  value       = cloudflare_zero_trust_access_identity_provider.otp.id
}

output "owners_access_policy_id" {
  description = "Identifier of the shared Owners Access policy."
  value       = cloudflare_zero_trust_access_policy.owners.id
}

output "access_application_ids" {
  description = "Access application identifiers keyed by stable Terraform identity."
  value       = { for key, application in cloudflare_zero_trust_access_application.this : key => application.id }
}
