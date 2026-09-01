# Google Workspace mail DNS module

This module owns the MX, SPF, DKIM, DMARC, and BIMI records for one domain. It derives DNS names, record types, DNS-only proxy mode, and stable keys. It preserves the supplied policy content, TTLs, and MX priorities without constructing or normalising them.

The caller configures the Cloudflare provider and the Terraform backend. This child module contains neither configuration.

## Requirements

| Name | Version |
| --- | --- |
| Terraform | `>= 1.16.0` |
| Cloudflare provider | `>= 5.24.0` |

## Inputs

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `zone_id` | `string` | yes | Lowercase 32-character hexadecimal Cloudflare zone ID. |
| `domain` | `string` | yes | Lowercase fully qualified domain without a trailing dot. |
| `mail` | `object` | yes | Verified MX, SPF, DKIM, DMARC, and BIMI data. MX entries use stable `mail-mx-*` keys and contain `content`, integer `priority`, and `ttl`. SPF and DMARC contain `content` and `ttl`. DKIM and BIMI also contain a lowercase `selector`. |

Every TTL accepts `1` for automatic mode or `60` through `86400`. MX priority accepts integers from `0` through `65535`.

## Output

| Name | Type | Description |
| --- | --- | --- |
| `dns_record_ids` | `map(string)` | Mail record IDs keyed by `mail-mx-*`, `spf`, `google-dkim`, `dmarc`, and `bimi`. |

## Example

```hcl
module "google_workspace_mail" {
  source = "./modules/google-workspace-mail"

  zone_id = "00000000000000000000000000000000"
  domain  = "example.com"
  mail = {
    mx = {
      mail-mx-primary = {
        content  = "smtp.example.com"
        priority = 10
        ttl      = 1
      }
    }
    spf   = { content = "v=spf1 include:_spf.example.com ~all", ttl = 3600 }
    dkim  = { selector = "google", content = "v=DKIM1; k=rsa; p=ZmFrZQ==", ttl = 3600 }
    dmarc = { content = "v=DMARC1; p=none; rua=mailto:owner@example.com", ttl = 3600 }
    bimi  = { selector = "default", content = "v=BIMI1; l=https://example.com/logo.svg", ttl = 3600 }
  }
}
```

The module sets `prevent_destroy = true` on every mail record. A key rename still changes Terraform identity, and Terraform reports the blocked destroy unless the configuration includes an explicit state migration. Import existing records at their final addresses, for example:

```text
module.google_workspace_mail.cloudflare_dns_record.this["mail-mx-primary"]
module.google_workspace_mail.cloudflare_dns_record.this["spf"]
```

Use the Cloudflare provider's documented import ID format with each address. The all-zero zone ID above is a public placeholder, not a usable import ID.
