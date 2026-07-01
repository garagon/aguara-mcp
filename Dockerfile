# Runtime image for the Aguara MCP server. Multi-stage build: compile
# the binary in a pinned Go-on-Alpine builder, then ship it on a tiny
# Alpine runtime image. CGO is disabled so the binary is statically
# linked and runs on the bare runtime without glibc.
#
# Base images are pinned by multi-arch index digest for reproducible
# builds. Bump both digests together with the tag when upgrading.

FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# VERSION defaults to "dev" for local builds without --build-arg. CI
# passes the actual release tag so `aguara-mcp --version` inside the
# container reports the published version instead of the Dockerfile
# default.
ARG VERSION=dev

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /aguara-mcp .

FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
COPY --from=builder /aguara-mcp /usr/local/bin/aguara-mcp

# Ownership marker for the Official MCP Registry: the registry verifies
# that this label matches the server name in server.json before
# accepting an OCI package for io.github.garagon/mcp-aguara.
LABEL io.modelcontextprotocol.server.name="io.github.garagon/mcp-aguara"

# Run as non-root. uid 10001 matches the convention across the Aguara
# stack so host-volume permissions can target a single uid.
RUN adduser -D -u 10001 aguara
USER aguara

# MCP server protocol is stdio. ENTRYPOINT alone (no CMD) so users can
# pass --version / --debug / --help on the docker command line; running
# `docker run -i image` (interactive stdin attached) starts the MCP
# server reading the MCP stdio transport.
ENTRYPOINT ["aguara-mcp"]
