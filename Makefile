SHELL := /bin/bash
.DEFAULT_GOAL := check

.PHONY: check fmt-check validate test-unit test-terraform shellcheck actionlint scan-public

fmt-check:
	terraform fmt -check -recursive

validate:
	@for module in modules/* examples/*; do \
		[ ! -d "$$module" ] || terraform -chdir="$$module" init -backend=false -input=false >/dev/null; \
		[ ! -d "$$module" ] || terraform -chdir="$$module" validate; \
	done

test-unit:
	python3 -m unittest discover -s tests -p 'test_*.py' -v

test-terraform:
	@for module in modules/* examples/*; do \
		[ ! -d "$$module" ] || terraform -chdir="$$module" init -backend=false -input=false >/dev/null; \
		[ ! -d "$$module" ] || terraform -chdir="$$module" test; \
	done

shellcheck:
	@files="$$(find scripts -type f -name '*.sh' 2>/dev/null)"; \
	[ -z "$$files" ] || shellcheck $$files

actionlint:
	@[ ! -d .github/workflows ] || actionlint

scan-public:
	python3 scripts/scan-public.py --path .

check: fmt-check validate test-unit test-terraform shellcheck actionlint scan-public
