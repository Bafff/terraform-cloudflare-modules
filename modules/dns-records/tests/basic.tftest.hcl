mock_provider "cloudflare" {}

run "stable_typed_records" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    records = {
      apex-a = {
        name    = "example.com"
        type    = "A"
        content = "192.0.2.10"
        ttl     = 3600
        proxied = true
        comment = "Synthetic public example"
        tags    = ["owner:example"]
        settings = {
          ipv4_only = true
        }
      }
      apex-aaaa = {
        name    = "example.com"
        type    = "AAAA"
        content = "2001:db8::10"
        ttl     = 3600
        proxied = false
      }
      app-cname = {
        name    = "app.example.com"
        type    = "CNAME"
        content = "target.example.com"
        ttl     = 3600
        proxied = true
      }
      mail-mx-primary = {
        name     = "example.com"
        type     = "MX"
        content  = "smtp.example.com"
        ttl      = 1
        proxied  = false
        priority = 10
      }
      delegate-ns = {
        name    = "delegated.example.com"
        type    = "NS"
        content = "ns1.example.com"
        ttl     = 3600
        proxied = false
      }
      openpgpkey = {
        name    = "hash._openpgpkey.example.com"
        type    = "OPENPGPKEY"
        content = "ZmFrZQ=="
        ttl     = 3600
        proxied = false
      }
      reverse-ptr = {
        name    = "10.2.0.192.in-addr.arpa"
        type    = "PTR"
        content = "host.example.com"
        ttl     = 3600
        proxied = false
      }
      spf-txt = {
        name    = "example.com"
        type    = "TXT"
        content = "v=spf1 -all"
        ttl     = 3600
        proxied = false
      }
    }
  }

  assert {
    condition     = toset(keys(cloudflare_dns_record.this)) == toset(["apex-a", "apex-aaaa", "app-cname", "mail-mx-primary", "delegate-ns", "openpgpkey", "reverse-ptr", "spf-txt"])
    error_message = "Record map keys must become stable resource instance keys."
  }

  assert {
    condition     = { for key, record in cloudflare_dns_record.this : key => record.type } == { apex-a = "A", apex-aaaa = "AAAA", app-cname = "CNAME", mail-mx-primary = "MX", delegate-ns = "NS", openpgpkey = "OPENPGPKEY", reverse-ptr = "PTR", spf-txt = "TXT" }
    error_message = "Every supported content-based record shape must retain its provider type."
  }

  assert {
    condition     = cloudflare_dns_record.this["apex-a"].zone_id == "00000000000000000000000000000000" && cloudflare_dns_record.this["apex-a"].proxied && cloudflare_dns_record.this["apex-a"].ttl == 3600
    error_message = "The module must pass zone, proxy, and TTL fields without normalising them."
  }

  assert {
    condition     = cloudflare_dns_record.this["apex-a"].comment == "Synthetic public example" && cloudflare_dns_record.this["apex-a"].tags == toset(["owner:example"])
    error_message = "The module must preserve comments and tags."
  }

  assert {
    condition     = cloudflare_dns_record.this["apex-a"].settings.ipv4_only && cloudflare_dns_record.this["mail-mx-primary"].priority == 10
    error_message = "The module must preserve settings and MX priority."
  }
}

run "rejects_invalid_zone_id" {
  command = plan

  variables {
    zone_id = "0000000000000000000000000000000G"
    records = {}
  }

  expect_failures = [var.zone_id]
}

run "rejects_non_slug_record_key" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    records = {
      "not-a-slug!" = {
        name    = "example.com"
        type    = "A"
        content = "192.0.2.10"
        ttl     = 3600
        proxied = false
      }
    }
  }

  expect_failures = [var.records]
}

run "rejects_invalid_record_fields" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    records = {
      invalid-a = {
        name    = " "
        type    = "a"
        content = " "
        ttl     = 2
        proxied = false
      }
    }
  }

  expect_failures = [var.records]
}

run "requires_mx_priority" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    records = {
      mail-mx = {
        name    = "example.com"
        type    = "MX"
        content = "smtp.example.com"
        ttl     = 3600
        proxied = false
      }
    }
  }

  expect_failures = [var.records]
}

run "rejects_priority_on_non_mx" {
  command = plan

  variables {
    zone_id = "00000000000000000000000000000000"
    records = {
      apex-a = {
        name     = "example.com"
        type     = "A"
        content  = "192.0.2.10"
        ttl      = 3600
        proxied  = false
        priority = 10
      }
    }
  }

  expect_failures = [var.records]
}
