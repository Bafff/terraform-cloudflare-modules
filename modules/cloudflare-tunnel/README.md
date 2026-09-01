# Cloudflare Tunnel module

This module creates one locally configured Cloudflare Tunnel and a 32-byte random tunnel secret. It does not manage tunnel ingress configuration or write credentials to a file.

The caller configures the Cloudflare and Random providers and the Terraform backend. This child module contains none of that configuration.

The tunnel resource uses `prevent_destroy`. Remove that protection only through a deliberate module change when tunnel deletion is intended.

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
