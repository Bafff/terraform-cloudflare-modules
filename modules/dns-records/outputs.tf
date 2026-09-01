output "dns_record_ids" {
  description = "Cloudflare DNS record identifiers keyed by stable Terraform identity."
  value       = { for key, record in cloudflare_dns_record.this : key => record.id }
}
