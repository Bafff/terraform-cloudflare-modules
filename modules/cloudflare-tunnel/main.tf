resource "random_bytes" "tunnel_secret" {
  length = 32
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  account_id    = var.account_id
  name          = var.name
  config_src    = "local"
  tunnel_secret = random_bytes.tunnel_secret.base64

  lifecycle {
    prevent_destroy = true
  }
}
