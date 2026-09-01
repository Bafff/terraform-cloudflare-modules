output "tunnel_id" {
  description = "Cloudflare Tunnel identifier."
  value       = cloudflare_zero_trust_tunnel_cloudflared.this.id
}

output "credentials_json" {
  description = "Sensitive cloudflared credentials JSON for delivery through a caller-selected secret mechanism."
  sensitive   = true
  value = jsonencode({
    AccountTag   = var.account_id
    TunnelID     = cloudflare_zero_trust_tunnel_cloudflared.this.id
    TunnelSecret = random_bytes.tunnel_secret.base64
  })
}
