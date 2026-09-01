.PHONY: build lint run dev dev-watch test integration clean deploy help install-precommit

help:
	@echo "Available targets:"
	@echo "  make build                  Build the prism binary"
	@echo "  make lint                   Run golangci-lint"
	@echo "  make test                   Run tests"
	@echo "  make run                    Run locally (requires cleave in PATH)"
	@echo "  make dev                    Run locally against PRODUCTION hopper-db + hopper-api"
	@echo "  make dev-watch              Like 'dev' but auto-rebuilds/restarts on changes (needs air)"
	@echo "  make clean                  Clean build artifacts"
	@echo "  make deploy                 git pull + native rollout (Bastille or systemd + Cloudflare)"
	@echo "  make install-precommit      Install the pre-commit hook (test + lint + no go.mod overrides)"
	@echo ""

GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

BUILD ?= build
RUN ?= prism

deploy: export MAKEFLAGS :=
deploy:
	env -u HOPPER_DB_PASS -u CF_TUNNEL_TOKEN git pull --ff-only
	@case "$$(uname -s)" in \
		FreeBSD) ./hacks/rollout-bastille.sh "$(BUILD)" "$(RUN)" ;; \
		Linux) ./hacks/rollout-systemd.sh ;; \
		*) echo "error: deploy supports FreeBSD/Bastille and Linux/systemd"; exit 1 ;; \
	esac

build:
	CGO_ENABLED=0 go build -o prism -ldflags="-s -w -X main.buildCommit=$(GIT_COMMIT)" .

test:
	go test -v ./...

integration:
	go test -tags integration -timeout 10m -v -run TestIntegration .

run: build
	PORT=8080 CLEAVE_PATH=cleave ./prism

# Local dev pointed at PRODUCTION hopper: reads come from hopper-db, analysis
# publishes go to hopper-api. Requires:
#   - "hopper-db" and "hopper-api" resolvable (e.g. /etc/hosts entries)
#   - ~/.pgpass holding the hopper-db password, chmod 600
# NOTE: this is LIVE prod data. Browsing is read-only, but write actions
# (the per-file rescan button, uploads if enabled) hit production — use with care.
DEV_PORT ?= 8080
DEV_ENV := \
	PORT=$(DEV_PORT) \
	HOPPER_DSN='postgres://hopper@hopper-db:5432/hopper?sslmode=disable' \
	HOPPER_API_ADDR=hopper-api:8081 \
	PGPASSFILE=$(HOME)/.pgpass \
	PRISM_CSRF_KEY=local-dev-csrf-key-not-a-secret-0123456789 \
	CLEAVE_PATH=cleave

dev: build
	@echo "prism dev → http://localhost:$(DEV_PORT)  (PRODUCTION hopper-db + hopper-api)"
	$(DEV_ENV) ./prism

dev-watch:
	@command -v air >/dev/null 2>&1 || { echo "air not found — install with: go install github.com/air-verse/air@latest"; exit 1; }
	@echo "prism dev (auto-reload) → http://localhost:$(DEV_PORT)  (PRODUCTION hopper-db + hopper-api)"
	$(DEV_ENV) air \
		-build.cmd 'CGO_ENABLED=0 go build -o prism -ldflags="-s -w -X main.buildCommit=$(GIT_COMMIT)" .' \
		-build.bin './prism' \
		-build.include_ext 'go,html,js,css' \
		-build.exclude_dir 'dist,out,.git,.revelara'

clean:
	rm -f prism
	rm -rf dist/

install-precommit:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed (runs: go.mod override check, make test, make lint)."

# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

SHELLCHECK_VERSION ?= v0.11.0
SHELLCHECK_BIN := $(LINT_ROOT)/out/linters/shellcheck-$(SHELLCHECK_VERSION)-$(LINT_ARCH)
$(SHELLCHECK_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	curl -sSfL -o $@.tar.xz https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(LINT_OS_LOWER).$(LINT_ARCH).tar.xz \
		|| echo "Unable to fetch shellcheck for $(LINT_OS)/$(LINT_ARCH): falling back to locally install"
	test -f $@.tar.xz \
		&& tar -C $(LINT_ROOT)/out/linters -xJf $@.tar.xz \
		&& mv $(LINT_ROOT)/out/linters/shellcheck-$(SHELLCHECK_VERSION)/shellcheck $@ \
		|| printf "#!/usr/bin/env shellcheck\n" > $@
	chmod u+x $@

LINTERS += shellcheck-lint
shellcheck-lint: $(SHELLCHECK_BIN)
	$(SHELLCHECK_BIN) $(shell find . -name "*.sh")

FIXERS += shellcheck-fix
shellcheck-fix: $(SHELLCHECK_BIN)
	$(SHELLCHECK_BIN) $(shell find . -name "*.sh") -f diff | { read -t 1 line || exit 0; { echo "$$line" && cat; } | git apply -p2; }

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v2.13.1
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	@exit_code=0; \
	for gomod in $$(find . -name go.mod); do \
		(cd "$$(dirname "$$gomod")" && "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)") || exit_code=1; \
	done; \
	exit $$exit_code

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	@exit_code=0; \
	for gomod in $$(find . -name go.mod); do \
		(cd "$$(dirname "$$gomod")" && "$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix) || true; \
	done; \
	exit $$exit_code

YAMLLINT_VERSION ?= 1.37.1
YAMLLINT_ROOT := $(LINT_ROOT)/out/linters/yamllint-$(YAMLLINT_VERSION)
YAMLLINT_BIN := $(YAMLLINT_ROOT)/dist/bin/yamllint
$(YAMLLINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/yamllint-*
	curl -sSfL https://github.com/adrienverge/yamllint/archive/refs/tags/v$(YAMLLINT_VERSION).tar.gz | tar -C $(LINT_ROOT)/out/linters -zxf -
	cd $(YAMLLINT_ROOT) && pip3 install --target dist . || pip install --target dist .

LINTERS += yamllint-lint
yamllint-lint: $(YAMLLINT_BIN)
	PYTHONPATH=$(YAMLLINT_ROOT)/dist $(YAMLLINT_ROOT)/dist/bin/yamllint .

BIOME_VERSION ?= 2.3.8
BIOME_BIN := $(LINT_ROOT)/out/linters/biome-$(BIOME_VERSION)-$(LINT_ARCH)
BIOME_CONFIG := $(LINT_ROOT)/biome.json

# Map architecture names for Biome downloads
BIOME_ARCH := $(LINT_ARCH)
ifeq ($(LINT_ARCH),x86_64)
	BIOME_ARCH := x64
endif

$(BIOME_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/biome-*
	curl -sSfL -o $@ https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%40$(BIOME_VERSION)/biome-$(LINT_OS_LOWER)-$(BIOME_ARCH) \
		|| echo "Unable to fetch biome for $(LINT_OS_LOWER)/$(BIOME_ARCH), falling back to local install"
	test -f $@ || printf "#!/usr/bin/env biome\n" > $@
	chmod u+x $@

LINTERS += biome-lint
biome-lint: $(BIOME_BIN)
	$(BIOME_BIN) check --config-path=$(BIOME_CONFIG) .

FIXERS += biome-fix
biome-fix: $(BIOME_BIN)
	$(BIOME_BIN) check --write --config-path=$(BIOME_CONFIG) .

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .
