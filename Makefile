SHELL := /bin/bash
.DEFAULT_GOAL := check

.PHONY: check fmt-check validate test-unit test-terraform shellcheck actionlint scan-public providers-lock

fmt-check:
	terraform fmt -check -recursive

validate:
	@set -eu; \
	for module in modules/* examples/*; do \
		[ ! -d "$$module" ] || terraform -chdir="$$module" init -backend=false -input=false -lockfile=readonly >/dev/null; \
		[ ! -d "$$module" ] || terraform -chdir="$$module" validate; \
	done

test-unit:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

test-terraform:
	@set -eu; \
	for module in modules/* examples/*; do \
		[ ! -d "$$module" ] || terraform -chdir="$$module" init -backend=false -input=false -lockfile=readonly >/dev/null; \
		[ ! -d "$$module" ] || terraform -chdir="$$module" test; \
	done

shellcheck:
	@files="$$(find scripts -type f -name '*.sh' 2>/dev/null)"; \
	[ -z "$$files" ] || shellcheck $$files

actionlint:
	@[ ! -d .github/workflows ] || actionlint

scan-public:
	python3 scripts/scan-public.py --path .

# Provider versions are pinned per directory in .terraform.lock.hcl; this
# moves every lock to the newest release the constraints allow.
providers-lock:
	@set -eu; \
	for module in modules/* examples/*; do \
		[ ! -d "$$module" ] || terraform -chdir="$$module" init -backend=false -input=false -upgrade >/dev/null; \
		[ ! -d "$$module" ] || terraform -chdir="$$module" providers lock -platform=linux_amd64 -platform=darwin_arm64; \
	done

check: fmt-check validate test-unit test-terraform shellcheck actionlint scan-public
