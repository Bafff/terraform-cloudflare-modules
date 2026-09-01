# Access applications module

This module creates one account-scoped email one-time PIN identity provider, one reusable allow policy for the supplied email addresses, and one zone-scoped self-hosted Access application for each map entry. Every application protects one whole hostname, redirects directly to the shared identity provider, and attaches the shared policy at precedence 1.

The caller configures the Cloudflare provider and the Terraform backend. This child module contains neither configuration. It does not create DNS records, tunnels, Zero Trust organisation settings, service tokens, or origin configuration.

## Requirements

| Name | Version |
| --- | --- |
| Terraform | `>= 1.16.0` |
| Cloudflare provider | `>= 5.24.0` |

## Inputs

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `account_id` | `string` | yes | Lowercase 32-character hexadecimal Cloudflare account ID. |
| `zone_id` | `string` | yes | Lowercase 32-character hexadecimal Cloudflare zone ID. |
| `allowed_emails` | `set(string)` | yes | Non-empty set of authorised email addresses. Terraform treats this input and the derived policy rules as sensitive. |
| `applications` | `map(object({ name = string, domain = string }))` | yes | Non-empty application map keyed by stable lowercase slugs. Domains must be lowercase fully qualified hostnames without paths or trailing dots. |
| `session_duration` | `string` | yes | Exact duration `730h`. The module applies it to the reusable policy and every application. |

The module copies each supplied email address into one policy rule. It does not normalise, expand, or invent addresses. The hostname validation accepts public fully qualified domains and does not restrict callers to `example.com`.

## Outputs

| Name | Type | Description |
| --- | --- | --- |
| `otp_identity_provider_id` | `string` | ID of the shared email one-time PIN identity provider. |
| `owners_access_policy_id` | `string` | ID of the shared Owners policy. |
| `access_application_ids` | `map(string)` | Application IDs keyed by the same stable slugs supplied by the caller. |

The outputs expose only provider-generated resource IDs. The module does not output email addresses or derived policy rules.

## Example

```hcl
module "access_applications" {
  source = "./modules/access-applications"

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
```

Application map keys become Terraform resource instance keys. Choose each key before importing an existing application:

```text
module.access_applications.cloudflare_zero_trust_access_application.this["docs"]
```

The all-zero account and zone IDs are public placeholders, not usable Cloudflare identifiers.
