mock_provider "cloudflare" {
  override_resource {
    target          = cloudflare_zero_trust_tunnel_cloudflared.this
    override_during = plan
    values = {
      id          = "00000000000000000000000000000000"
      account_tag = "00000000000000000000000000000000"
    }
  }
}

mock_provider "random" {
  override_resource {
    target          = random_bytes.tunnel_secret
    override_during = plan
    values = {
      base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}

run "locally_configured_tunnel" {
  command = plan

  variables {
    account_id = "00000000000000000000000000000000"
    name       = "example-tunnel"
  }

  assert {
    condition     = random_bytes.tunnel_secret.length == 32
    error_message = "The tunnel secret must contain 32 random bytes."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared.this.account_id == "00000000000000000000000000000000"
    error_message = "The tunnel must use the supplied account identifier."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared.this.name == "example-tunnel"
    error_message = "The tunnel must use the supplied name."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared.this.config_src == "local"
    error_message = "The tunnel must keep ingress configuration local."
  }

  assert {
    condition     = nonsensitive(cloudflare_zero_trust_tunnel_cloudflared.this.tunnel_secret) == nonsensitive(random_bytes.tunnel_secret.base64)
    error_message = "The tunnel must use the generated random secret."
  }

  assert {
    condition     = output.tunnel_id == "00000000000000000000000000000000"
    error_message = "The tunnel_id output must return the Cloudflare tunnel identifier."
  }

  assert {
    condition = jsondecode(nonsensitive(output.credentials_json)) == {
      AccountTag   = "00000000000000000000000000000000"
      TunnelID     = "00000000000000000000000000000000"
      TunnelSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
    error_message = "The credentials output must contain exactly the account tag, tunnel ID, and generated tunnel secret."
  }
}

run "rejects_invalid_account_id" {
  command = plan

  variables {
    account_id = "0000000000000000000000000000000G"
    name       = "example-tunnel"
  }

  expect_failures = [var.account_id]
}

run "rejects_empty_tunnel_name" {
  command = plan

  variables {
    account_id = "00000000000000000000000000000000"
    name       = "   "
  }

  expect_failures = [var.name]
}
