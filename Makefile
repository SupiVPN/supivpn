# Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
# Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
# SPDX-License-Identifier: AGPL-3.0-only

.DEFAULT_GOAL := help
.NOTPARALLEL:
SHELL := /bin/sh

GO ?= go
DOCKER ?= docker
ROOT := $(CURDIR)
LOCAL := $(ROOT)/local
PYTHON ?= $(if $(wildcard $(LOCAL)/dev-venv/bin/python3),$(LOCAL)/dev-venv/bin/python3,python3)
PYYAML_VERSION := 6.0.3
export GOPATH := $(LOCAL)/go
export GOCACHE := $(LOCAL)/build-cache
export GOTOOLCHAIN := local
export GOWORK := off

PKG ?= ./...
RUN ?= .
TEST_VERBOSE ?=
TIMEOUT ?= 300s
FUZZ_TIME ?= 20s
FUZZ_SAML_TIME ?= $(FUZZ_TIME)
GOVULNCHECK_VERSION := v1.9.0
VULNCHECK := $(LOCAL)/tools/$(GOVULNCHECK_VERSION)/govulncheck
OPENVPN_IMAGE ?= supivpn-openvpn-test:2.7.8-$(ARCH)
XMLSEC_IMAGE ?= supivpn-xmlsec-test:$(ARCH)
POSTGRES_IMAGE ?= postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c
POSTGRES_CONTAINER ?= supivpn-pg18-test
POSTGRES_PORT ?= 55432
POSTGRES_WAIT_TIMEOUT ?= 60
ARCH ?= $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
VM_DATABASE ?= local
ifneq ($(words $(ARCH)),1)
$(error ARCH must be exactly one architecture)
endif
ifneq ($(ARCH),arm64)
ifneq ($(ARCH),amd64)
$(error ARCH must be arm64 or amd64)
endif
endif
BUILD_DIR := local/$(ARCH)
LINUX := env CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH)
BUILD_FLAGS := -trimpath -buildvcs=false

# Pass release inputs as literal environment values, never shell source.
COMMIT ?= main
unexport VERSION COMMIT
tag: export SUPIVPN_TAG_VERSION := $(value VERSION)
tag: export SUPIVPN_TAG_COMMIT := $(value COMMIT)

.PHONY: help setup all prepare build build-all security-binaries-all agent controller profile migrate lambda bootstrap \
 test test-saml test-security vet integration test-all check fuzz fuzz-xml fuzz-saml test-xmlsec test-openvpn test-connect \
 xmlsec-image openvpn-image postgres-start postgres-stop test-db-restart \
  security security-source security-binaries deps-verify deps-check audit ci-test-coverage tag deb deb-test deb-vm-test test-setup-db

.PHONY: okta-probe
okta-probe: | $(LOCAL)/go.mod
	@mkdir -p "$(LOCAL)/okta-ci"
	@$(GO) build -race -o "$(LOCAL)/okta-ci/profile-probe" ./testdata/okta

help:
	@printf '%s\n' \
	 'setup             Install project-local Python tools and download Go modules' \
	 'build / all       Build Linux binaries for the host architecture; ARCH=arm64 or amd64 overrides it' \
	 'build-all         Build both ARM64 and AMD64 into local/<arch>/' \
	 'deb / deb-test    Build Debian 13 packages + corresponding source; optionally check package lifecycle; ARCH=arm64|amd64' \
	 'deb-vm-test       Build/check packages, then boot disposable Debian 13 with real systemd and VPN traffic' \
 'test-setup-db     Check remote setup against isolated PostgreSQL 18 with real TLS and migrations' \
	 'ci-test-coverage  Ensure integration tags retain all ordinary Go source and test files' \
	 'prepare           Source audit -> unit/race -> vet -> build + manifest' \
	 'tag               Local GPG tag with automatic release notes; VERSION=vX.Y.Z[-rc.N] [COMMIT=main|<full SHA>]; no push' \
	 'audit             Source/secret-pattern and language checks + audit unit tests' \
	 'agent controller profile migrate lambda  Build one component' \
	 'test              Unit/race tests; PKG=./... RUN=. TIMEOUT=300s' \
	 'test-saml         SAML and controller unit/race tests' \
	 'test-security     Adversarial auth/API/signature regression tests (race)' \
	 'vet               Go vet, including integration test code' \
	 'integration       PostgreSQL 18 tests; requires local test DB + opt-in env' \
	 'test-xmlsec       Independent XMLSec interoperability (Docker)' \
	 'test-openvpn      Real OpenVPN 2.7.8 / two-node failover (Docker)' \
	 'test-connect      Interactive local OpenVPN Connect expiry/reconnect test' \
	 'fuzz              XML/C14N + signed-claim mutation fuzzing; FUZZ_TIME=20s each' \
	 'fuzz-xml / fuzz-saml  Run one fuzz target' \
	 'security          Adversarial tests + govulncheck source/binaries' \
	 'deps-verify       Verify downloaded module integrity' \
	 'deps-check        Verify modules and list updates/retractions' \
	 'check             test + vet + security + deps-check' \
	 'test-all          check + integration + XMLSec + OpenVPN + fuzz' \
	 'postgres-start / postgres-stop  Disposable loopback PostgreSQL 18' \
	 'xmlsec-image / openvpn-image    Build local test images' \
	 'test-db-restart    Interactive restart check; see BUILD.md' \
	 'Details: BUILD.md; artifacts: local/'

all: build

deb: | $(LOCAL)/go.mod
	@$(PYTHON) -B tools/debian_packages.py --arch "$(ARCH)" --go "$(GO)" --docker "$(DOCKER)"

deb-test: | $(LOCAL)/go.mod
	@$(PYTHON) -B tools/debian_packages.py --arch "$(ARCH)" --go "$(GO)" --docker "$(DOCKER)" --test

deb-vm-test: | $(LOCAL)/go.mod
	@$(PYTHON) -B tools/debian_packages.py --arch "$(ARCH)" --go "$(GO)" --docker "$(DOCKER)" --vm --vm-database "$(VM_DATABASE)"

setup: | $(LOCAL)/go.mod
	@test -x "$(LOCAL)/dev-venv/bin/python3" || python3 -m venv "$(LOCAL)/dev-venv"
	@"$(LOCAL)/dev-venv/bin/python3" -m pip install --disable-pip-version-check 'PyYAML==$(PYYAML_VERSION)'
	@$(GO) mod download
	@$(GO) mod verify
	@printf '%s\n' 'Setup complete. Run make test; make audit uses the local Python environment automatically.'

build-all:
	@$(MAKE) build ARCH=arm64
	@$(MAKE) build ARCH=amd64

security-binaries-all:
	@$(MAKE) security-binaries ARCH=arm64
	@$(MAKE) security-binaries ARCH=amd64

prepare: audit test vet build

# Keep downloaded modules and generated Go files outside recursive package scans.
$(LOCAL)/go.mod:
	@mkdir -p "$(LOCAL)"
	@printf 'module supivpn-local-artifacts\n' > "$@"

build agent controller profile migrate bootstrap lambda test ci-test-coverage \
 vet integration fuzz-xml fuzz-saml test-security security-source security-binaries \
 deps-verify deps-check test-xmlsec test-openvpn test-connect $(VULNCHECK): | $(LOCAL)/go.mod

tag:
	@$(PYTHON) -B tools/github_release.py tag

audit:
	@$(PYTHON) -B -m unittest discover -s tools -p 'test_*.py' -v
	@$(PYTHON) -B tools/release_notes.py --audit
	@$(PYTHON) -B tools/repository_audit.py
	@$(PYTHON) -B tools/check_language.py

build: agent controller profile migrate lambda
	@cd "$(ROOT)" && $(GO) run ./cmd/supivpn-release-manifest -artifact-dir "$(BUILD_DIR)"

agent:
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -o "$(BUILD_DIR)/supivpn" ./cmd/supivpn

controller:
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -o "$(BUILD_DIR)/supivpn-controller" ./cmd/supivpn-controller

profile:
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -o "$(BUILD_DIR)/supivpn-profile" ./cmd/supivpn-profile

migrate:
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -o "$(BUILD_DIR)/supivpn-migrate" ./cmd/supivpn-migrate

test-setup-db: migrate
	@$(DOCKER) build --platform linux/$(ARCH) -t "supivpn-setup-db-test:$(ARCH)" "$(ROOT)/ci/debian/remote-database"
	@$(DOCKER) run --rm --platform linux/$(ARCH) --network none --security-opt no-new-privileges \
	 --env SUPIVPN_SETUP_DB_TEST=1 \
	 --mount "type=bind,source=$(ROOT)/tools/debian_setup.py,target=/test/debian_setup.py,readonly" \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/supivpn-migrate,target=/usr/sbin/supivpn-migrate,readonly" \
	 "supivpn-setup-db-test:$(ARCH)"

bootstrap:
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -tags=lambda.norpc -o "$(BUILD_DIR)/bootstrap" ./cmd/supivpn-lambda
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -tags=lambda.norpc -o "$(BUILD_DIR)/bootstrap-agent" ./cmd/supivpn-agent-lambda
	@cd "$(ROOT)" && $(LINUX) $(GO) build $(BUILD_FLAGS) -tags=lambda.norpc -o "$(BUILD_DIR)/bootstrap-recovery" ./cmd/supivpn-recovery-lambda

lambda: bootstrap
	@cd "$(ROOT)" && $(GO) run ./cmd/supivpn-package -arch "$(ARCH)" -binary "$(BUILD_DIR)/bootstrap" -output "$(BUILD_DIR)/supivpn-lambda.zip"
	@cd "$(ROOT)" && $(GO) run ./cmd/supivpn-package -service-only -arch "$(ARCH)" -binary "$(BUILD_DIR)/bootstrap-agent" -output "$(BUILD_DIR)/supivpn-agent-lambda.zip"
	@cd "$(ROOT)" && $(GO) run ./cmd/supivpn-package -service-only -arch "$(ARCH)" -binary "$(BUILD_DIR)/bootstrap-recovery" -output "$(BUILD_DIR)/supivpn-recovery-lambda.zip"

test:
	@cd "$(ROOT)" && $(GO) test $(TEST_VERBOSE) -race -count=1 -timeout="$(TIMEOUT)" -run="$(RUN)" $(PKG)

ci-test-coverage:
	@$(PYTHON) -B ci/check_test_coverage.py

test-saml:
	@$(MAKE) test PKG='./internal/saml ./internal/controller'

test-security:
	@cd "$(ROOT)" && $(GO) test -race -count=1 -timeout="$(TIMEOUT)" ./...

vet:
	@cd "$(ROOT)" && $(GO) vet -tags=integration ./...

integration:
	@test -n "$$SUPIVPN_TEST_POSTGRES_URL" && test "$$SUPIVPN_TEST_POSTGRES_ALLOW_RESET" = 1 || \
	 { printf '%s\n' 'Set SUPIVPN_TEST_POSTGRES_URL and SUPIVPN_TEST_POSTGRES_ALLOW_RESET=1; see BUILD.md.'; exit 1; }
	@cd "$(ROOT)" && $(GO) test $(TEST_VERBOSE) -race -tags=integration -count=1 -timeout="$(TIMEOUT)" -run="$(RUN)" $(PKG)

test-db-restart:
	@SUPIVPN_TEST_RESTART=1 $(MAKE) integration PKG=./internal/agent RUN='^TestPostgresServerRestart$$' TEST_VERBOSE=-v

fuzz: fuzz-xml fuzz-saml

fuzz-xml:
	@cd "$(ROOT)" && $(GO) test ./internal/saml -run='^$$' -fuzz='^FuzzSAMLXML$$' -fuzztime="$(FUZZ_TIME)" -parallel=2 -timeout="$(TIMEOUT)"

fuzz-saml:
	@cd "$(ROOT)" && $(GO) test ./internal/saml -run='^$$' -fuzz='^FuzzSignedSAMLClaims$$' -fuzztime="$(FUZZ_SAML_TIME)" -parallel=2 -timeout="$(TIMEOUT)"

$(VULNCHECK):
	@cd "$(ROOT)" && GOBIN="$(LOCAL)/tools/$(GOVULNCHECK_VERSION)" $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

security: test-security security-source security-binaries
security-source: $(VULNCHECK)
	@cd "$(ROOT)" && "$(VULNCHECK)" -test -tags=integration -show=verbose ./...
	@cd "$(ROOT)" && env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$(VULNCHECK)" -test -tags=integration -show=verbose ./...
	@cd "$(ROOT)" && env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$(VULNCHECK)" -test -tags=integration -show=verbose ./...

security-binaries: build $(VULNCHECK)
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/supivpn"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/supivpn-controller"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/supivpn-profile"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/supivpn-migrate"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/bootstrap"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/bootstrap-agent"
	@cd "$(ROOT)" && "$(VULNCHECK)" -mode=binary -show=verbose "$(BUILD_DIR)/bootstrap-recovery"

deps-verify:
	@cd "$(ROOT)" && $(GO) mod verify

deps-check: deps-verify
	@cd "$(ROOT)" && $(GO) list -m -u -retracted -f '{{.Path}} {{.Version}}{{if .Update}} -> {{.Update.Version}}{{end}}{{if .Retracted}} RETRACTED: {{.Retracted}}{{end}}' all
	@cd "$(ROOT)" && $(GO) list -m golang.org/x/vuln@latest

check: test vet security deps-check
test-all: check integration test-xmlsec test-openvpn fuzz

xmlsec-image:
	@$(DOCKER) build --platform linux/$(ARCH) -t "$(XMLSEC_IMAGE)" "$(ROOT)/testdata/saml"

test-xmlsec: xmlsec-image
	@cd "$(ROOT)" && $(LINUX) $(GO) test -c -o "$(BUILD_DIR)/saml.test" ./internal/saml
	@$(DOCKER) run --rm --platform linux/$(ARCH) --network none \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/saml.test,target=/test/saml.test,readonly" \
	 --env SUPIVPN_TEST_XMLSEC=/usr/bin/xmlsec1 "$(XMLSEC_IMAGE)" \
	 /test/saml.test -test.run TestXMLSec -test.v -test.timeout 90s

openvpn-image:
	@$(DOCKER) build --platform linux/$(ARCH) -t "$(OPENVPN_IMAGE)" \
	 -f "$(ROOT)/ci/Dockerfile" "$(ROOT)/ci"

test-openvpn: agent
	@cd "$(ROOT)" && $(LINUX) $(GO) test -c -o "$(BUILD_DIR)/openvpn.test" ./internal/agent
	@$(DOCKER) run --rm --platform linux/$(ARCH) --user 0:0 --network none --cap-add NET_ADMIN --device /dev/net/tun \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/openvpn.test,target=/test/openvpn.test,readonly" \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/supivpn,target=/test/supivpn,readonly" \
	 --env SUPIVPN_TEST_OPENVPN=/usr/sbin/openvpn --env SUPIVPN_TEST_AGENT=/test/supivpn \
	 "$(OPENVPN_IMAGE)" /test/openvpn.test -test.run TestOpenVPN -test.v -test.timeout 300s

test-connect: agent
	@mkdir -p "$(LOCAL)/connect-test"
	@cd "$(ROOT)" && $(LINUX) $(GO) test -c -o "$(BUILD_DIR)/connect.test" ./internal/agent
	@$(DOCKER) run --rm --user 0:0 --name supivpn-connect-test --cap-add NET_ADMIN --device /dev/net/tun \
	 --platform linux/$(ARCH) -p 127.0.0.1:11194:1194/udp -p 127.0.0.1:18443:18443/tcp \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/connect.test,target=/test/connect.test,readonly" \
	 --mount "type=bind,source=$(ROOT)/$(BUILD_DIR)/supivpn,target=/test/supivpn,readonly" \
	 --mount "type=bind,source=$(LOCAL)/connect-test,target=/out" \
	 --env SUPIVPN_TEST_CONNECT=1 --env SUPIVPN_TEST_OPENVPN=/usr/sbin/openvpn --env SUPIVPN_TEST_AGENT=/test/supivpn \
	 "$(OPENVPN_IMAGE)" /test/connect.test -test.run '^TestOpenVPNConnectExpiryManual$$' -test.v -test.timeout 22m

postgres-start:
	@container_id="$$($(DOCKER) run --detach --rm --platform linux/$(ARCH) --name "$(POSTGRES_CONTAINER)" \
	 --label supivpn.disposable-test=true -p "127.0.0.1:$(POSTGRES_PORT):5432" \
	 -e POSTGRES_DB=supivpn_test -e POSTGRES_HOST_AUTH_METHOD=trust \
	 --health-cmd='pg_isready -U postgres -d supivpn_test' --health-interval=1s --health-timeout=3s --health-retries=30 \
	 "$(POSTGRES_IMAGE)")" && \
	 $(PYTHON) -B tools/wait_container.py --docker "$(DOCKER)" --timeout "$(POSTGRES_WAIT_TIMEOUT)" "$$container_id"

postgres-stop:
	@test "$$($(DOCKER) inspect --format '{{index .Config.Labels "supivpn.disposable-test"}}' "$(POSTGRES_CONTAINER)")" = true || \
	 { printf '%s\n' 'Refusing to stop a container without the SupiVPN disposable-test label.'; exit 1; }
	@$(DOCKER) stop "$(POSTGRES_CONTAINER)"
