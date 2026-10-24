# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM golang:1.27-alpine AS build

# git is not needed: this module has zero external dependencies by policy, so
# there is nothing to fetch. That also means no module download step and no
# network access during build.
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

# CGO_ENABLED=0 yields a fully static binary so the runtime image needs no
# libc. -trimpath keeps build paths out of the binary.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/cleanerproxy ./cmd/cleanerproxy

# Run the test suite inside the build so a broken detector cannot ship. For a
# security tool the attack corpus passing is a release gate, not a formality.
RUN go test ./...

# ---- runtime --------------------------------------------------------------
FROM alpine:3.21

# ca-certificates is required: the proxy makes outbound TLS connections to the
# upstream provider and to the Tier 2 classifier backend.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S cleaner \
 && adduser -u 10001 -S cleaner -G cleaner

COPY --from=build /out/cleanerproxy /usr/local/bin/cleanerproxy

# The audit log lives on a volume so it survives container replacement.
RUN mkdir -p /var/lib/cleanerproxy && chown cleaner:cleaner /var/lib/cleanerproxy
VOLUME /var/lib/cleanerproxy

USER cleaner:cleaner
EXPOSE 8787

ENV CLEANERPROXY_LISTEN=":8787" \
    CLEANERPROXY_POLICY="defang" \
    CLEANERPROXY_AUDIT_PATH="/var/lib/cleanerproxy/audit.log"

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8787/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/cleanerproxy"]
