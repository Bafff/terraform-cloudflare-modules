# Complete synthetic example

This example composes `cloudflare-tunnel`, `dns-records`, `google-workspace-mail`, and `access-applications`. The `docs` and `lots` keys identify the same hostnames in the ordinary DNS and Access modules, while Google Workspace mail records remain owned by the mail module.

The DNS values are derived from the tunnel ID to demonstrate Terraform data flow. Their `.tunnel.example.com` suffix is deliberately reserved and is not a real Cloudflare Tunnel routing target. The all-zero account and zone IDs, `example.com` hostnames, example email addresses, mail policies, and mocked provider IDs make this configuration non-deployable by design.

The example configures neither providers nor a backend. Its native test uses mocked Cloudflare and Random providers, requires no credentials, and makes no live API calls.

Run the test from the repository root:

```sh
terraform -chdir=examples/complete init -backend=false
terraform -chdir=examples/complete test
```

This example demonstrates composition only. A private root supplies real identifiers, provider and backend configuration, authoritative DNS content, and a separate mechanism for delivering the tunnel module's sensitive credentials output.
