# DNS records module

This module manages ordinary Cloudflare DNS records. Use a separate module call for records whose lifecycle belongs to another service, such as mail.

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
| `records` | `map(object)` | yes | Records keyed by a stable lowercase slug. Each record has `name`, `type`, `content`, `ttl`, and `proxied`; `priority`, `comment`, `settings`, and `tags` are optional. Supported types are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `OPENPGPKEY`, `PTR`, and `TXT`. |

`name` accepts `@` or a DNS owner name no longer than 253 characters whose labels are each no longer than 63 characters. `ttl` accepts `1` for automatic mode or `60` through `86400`. A proxied record must use type `A`, `AAAA`, or `CNAME` and automatic TTL `1`. MX records require an integer `priority` from `0` through `65535`; other supported record types must omit it.

## Output

| Name | Type | Description |
| --- | --- | --- |
| `dns_record_ids` | `map(string)` | Record IDs keyed by the same stable slugs. |

## Example

```hcl
module "dns_records" {
  source = "./modules/dns-records"

  zone_id = "00000000000000000000000000000000"
  records = {
    apex-a = {
      name    = "example.com"
      type    = "A"
      content = "192.0.2.10"
      ttl     = 1
      proxied = true
    }
  }
}
```

The map key is part of the Terraform address. Choose the final key before importing an existing record:

```text
module.dns_records.cloudflare_dns_record.this["apex-a"]
```

Use the Cloudflare provider's documented import ID format with that address. The all-zero zone ID above is a public placeholder, not a usable import ID.
