.PHONY: build test lint clean test-install-sh-docker

build:
	go build -o aguara-mcp .

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f aguara-mcp mcp-aguara

# Reproduces the install.sh execution path under --cap-drop ALL on
# Alpine. Locks two install.sh contracts as two separate stages:
#   1. Happy path: tar extraction works without CAP_CHOWN
#      (install.sh uses tar -xzof). Image has sha256sum available so
#      checksum verification succeeds and the binary lands at INSTALL_DIR.
#   2. Fail-closed: when no sha256 / shasum utility exists on the system,
#      install.sh refuses to install rather than silently skipping
#      verification. Stage 2 uses a companion image with every sha256
#      utility stripped; the docker run is expected to exit non-zero
#      with the documented error message, and the make recipe asserts
#      both conditions.
# Requires network access (the script pulls release archives from
# github.com) so this target is intentionally separate from the unit
# test suite.
# Override INSTALL_SH_TEST_VERSION to pin a specific release; leave
# empty (default) to exercise install.sh's "fetch latest" path.
INSTALL_SH_TEST_VERSION  ?=
INSTALL_SH_TEST_IMAGE    ?= aguara-mcp-install-test:cap-drop
INSTALL_SH_NOSHA_IMAGE   ?= aguara-mcp-install-test:no-sha

test-install-sh-docker:
	@echo "=== Stage 1: happy path under --cap-drop ALL ==="
	docker build -f Dockerfile.install-sh-cap -t $(INSTALL_SH_TEST_IMAGE) .
	docker run --rm \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		-e VERSION=$(INSTALL_SH_TEST_VERSION) \
		$(INSTALL_SH_TEST_IMAGE)
	@echo "=== Stage 2: fail-closed when no sha256 verifier is present ==="
	docker build -f Dockerfile.install-sh-no-sha -t $(INSTALL_SH_NOSHA_IMAGE) .
	@out=$$(docker run --rm \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		-e VERSION=$(INSTALL_SH_TEST_VERSION) \
		$(INSTALL_SH_NOSHA_IMAGE) 2>&1) ; rc=$$? ; \
		echo "$$out" ; \
		test $$rc -ne 0 || { echo "FAIL: install.sh exited 0 without a sha256 verifier" ; exit 1 ; } ; \
		echo "$$out" | grep -q "no sha256 verifier available" || { echo "FAIL: install.sh failed but without the documented fail-closed message" ; exit 1 ; } ; \
		echo "PASS: install.sh fail-closed contract honored"
