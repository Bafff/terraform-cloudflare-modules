# Terraform Cloudflare Modules

Reusable Terraform modules for generic Cloudflare configurations.

Available modules:

- `access-applications`
- `cloudflare-tunnel`
- `dns-records`
- `google-workspace-mail`

Planned modules:

- `dns-zone`
- `workers-service`
- `r2-bucket`

The credential-free [`complete` example](examples/complete) composes all available modules with reserved placeholder values and mocked providers. It is intentionally non-deployable.

Examples and documentation use only `example.com` domains and all-zero sentinel identifiers. macOS ARM64 is for local operator work; Linux AMD64 is for CI. Native Windows support is explicitly deferred because it adds maintenance work without a current use case.

Run the repository checks with:

```sh
make check
```
