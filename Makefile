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
# Alpine. Locks two install.sh contracts:
#   1. tar extraction works without CAP_CHOWN (the `o` flag in tar -xzof)
#   2. checksum verification fails closed if no sha256 utility is found
# Requires network access (the script pulls release archives from
# github.com) so this target is intentionally separate from the unit
# test suite.
# Override INSTALL_SH_TEST_VERSION to pin a specific release; leave
# empty (default) to exercise install.sh's "fetch latest" path.
INSTALL_SH_TEST_VERSION ?=
INSTALL_SH_TEST_IMAGE   ?= aguara-mcp-install-test:cap-drop

test-install-sh-docker:
	docker build -f Dockerfile.install-sh-cap -t $(INSTALL_SH_TEST_IMAGE) .
	docker run --rm \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		-e VERSION=$(INSTALL_SH_TEST_VERSION) \
		$(INSTALL_SH_TEST_IMAGE)
