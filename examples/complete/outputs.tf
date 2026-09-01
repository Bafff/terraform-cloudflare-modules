output "dns_record_ids" {
  description = "Ordinary DNS record IDs keyed by application identity."
  value       = module.dns_records.dns_record_ids
}

output "mail_dns_record_ids" {
  description = "Google Workspace mail DNS record IDs keyed by mail record identity."
  value       = module.google_workspace_mail.dns_record_ids
}

output "access_application_ids" {
  description = "Access application IDs keyed by application identity."
  value       = module.access_applications.access_application_ids
}
