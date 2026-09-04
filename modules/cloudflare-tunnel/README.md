# Cloudflare Tunnel module

This module creates one locally configured Cloudflare Tunnel and a 32-byte random tunnel secret. It does not manage tunnel ingress configuration or write credentials to a file.

The caller configures the Cloudflare and Random providers and the Terraform backend. This child module contains none of that configuration.

The tunnel resource and generated secret use `prevent_destroy`. Remove those protections only through a deliberate module change when tunnel deletion or secret rotation is intended.

Cloudflare treats a locally configured tunnel secret as write-only: the API does not return it, and provider 5.24.0 cannot populate it while importing an existing tunnel. The tunnel resource therefore ignores changes to `tunnel_secret` after creation. This allows an imported tunnel and its separately imported `random_bytes.tunnel_secret` to converge without sending an unnecessary update to Cloudflare, while a newly created tunnel still receives the generated secret.

Secret rotation is intentionally outside this module's normal update path. Replacement of the tracked `random_bytes.tunnel_secret` triggers replacement of the tunnel, and `prevent_destroy` blocks that replacement during routine use. Terraform lifecycle rules cannot detect manual removal or loss of the random resource's state, so the recovery rule below remains mandatory.

## Importing an existing tunnel

Import requires the original base64-encoded 32-byte secret used by the live locally configured tunnel. Terraform and the Cloudflare API cannot verify that value. Back up state first, then import both resources in this order:

```bash
terraform import 'module.cloudflare_tunnel.random_bytes.tunnel_secret' 'ORIGINAL_BASE64_SECRET'
terraform import 'module.cloudflare_tunnel.cloudflare_zero_trust_tunnel_cloudflared.this' 'ACCOUNT_ID/TUNNEL_ID'
terraform plan -detailed-exitcode
```

Do not apply unless the final unscoped plan exits `0` with `No changes`. Importing only the Cloudflare resource is unsafe: Terraform would otherwise plan a new random value that cannot authenticate to the existing tunnel.

If the random resource is ever missing from state while the tunnel remains present, do not apply, remove lifecycle protection, or generate a replacement. Restore the verified state backup or re-import the original live secret, then require another `No changes` plan. If the original secret is unavailable, treat that as credential loss and follow a deliberate Cloudflare tunnel-secret rotation procedure before distributing new credentials.

## Requirements

| Name | Version |
| --- | --- |
| Terraform | `>= 1.16.0` |
| Cloudflare provider | `>= 5.24.0` |
| Random provider | `>= 3.9.0` |

## Inputs

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `account_id` | `string` | yes | Lowercase 32-character hexadecimal Cloudflare account ID. |
| `name` | `string` | yes | Non-empty Cloudflare Tunnel name. |

## Outputs

| Name | Sensitive | Description |
| --- | --- | --- |
| `tunnel_id` | no | Cloudflare Tunnel ID. |
| `credentials_json` | yes | Exact cloudflared credentials JSON containing `AccountTag`, `TunnelID`, and `TunnelSecret`. |

Terraform stores the generated secret and credentials value in state even though the output is sensitive. Protect the caller's backend accordingly. The module returns credentials only as a sensitive output, and the caller chooses an external secret-delivery mechanism.

## Example

```hcl
module "cloudflare_tunnel" {
  source = "./modules/cloudflare-tunnel"

  account_id = "00000000000000000000000000000000"
  name       = "example-tunnel"
}
```

The all-zero account ID is a public placeholder and cannot identify a real Cloudflare account.
