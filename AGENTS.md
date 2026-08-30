# Repository guidance

Use a feature branch for each change. Run `make check` before every commit.

This is a public repository: keep credentials, live metadata, and customer data
out of commits. CI must remain credential-free. Releases use one immutable,
repository-wide tag.
