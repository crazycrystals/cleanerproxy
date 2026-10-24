#!/bin/sh
# Reproduce every claim made about this proxy, from a clean checkout.
#
#   ./scripts/verify.sh            # everything
#   ./scripts/verify.sh hermetic   # offline tests only, no model or Docker
#   ./scripts/verify.sh live       # detection accuracy against the real model
#   ./scripts/verify.sh eval       # full threshold sweep and variant comparison
#   ./scripts/verify.sh harden     # assert the guardian's attack surface is closed
#
# hermetic needs only a Go toolchain. The rest need Docker and the model.
set -eu

cd "$(dirname "$0")/.."

GUARDIAN_URL="${CLEANERPROXY_GUARDIAN_URL:-http://127.0.0.1:18080}"
GUARDIAN_NAME="${GUARDIAN_NAME:-cp-guardian}"
MODEL_SHA="21e4d79c7a7399182182222636e44fc189947e1ac8c324dda93205d5769c4344"
MODEL_PATH="./models/granite-guardian-3.2-3b-a800m.gguf"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hermetic() {
  say "go vet"
  go vet ./... && echo "clean"

  say "gofmt"
  unformatted="$(gofmt -l . || true)"
  if [ -n "$unformatted" ]; then echo "UNFORMATTED: $unformatted"; exit 1; fi
  echo "clean"

  say "dependency audit (must be stdlib only)"
  # The module graph is the authoritative check. `go list -deps` is not:
  # it reports packages, and the standard library vendors things like
  # vendor/golang.org/x/net, which look third-party but ship with Go.
  echo "module graph:"
  go list -m all | sed 's/^/  /'
  extra="$(go list -m all | grep -vc '^cleanerproxy$' || true)"
  if [ "$extra" != "0" ]; then echo "UNEXPECTED THIRD-PARTY MODULES"; exit 1; fi
  if [ -s go.sum ]; then echo "UNEXPECTED go.sum (implies external modules)"; exit 1; fi
  echo "third-party modules: 0, go.sum absent/empty"

  say "offline test suite"
  go test ./... -count=1

  say "attack + benign corpus detail (Tier 0/1, no model needed)"
  go test ./internal/guard/ -run 'TestAttackCorpus|TestBenignCorpus|TestDualUse|TestObfuscation' -v -count=1 |
    grep -E '^(=== RUN|--- |    --- |ok|FAIL)' | grep -v '=== RUN'

  say "streaming quarantine + template fidelity"
  go test ./internal/wire/ ./internal/classifier/ ./internal/proxy/ -v -count=1 |
    grep -E '^(--- |    --- |ok|FAIL)'
}

require_guardian() {
  if ! curl -fsS --max-time 3 "$GUARDIAN_URL/health" >/dev/null 2>&1; then
    echo "guardian not reachable at $GUARDIAN_URL" >&2
    echo "start it with:" >&2
    echo "  ./scripts/fetch-model.sh" >&2
    echo "  docker build -t cleanerproxy-guardian:dev guardian/" >&2
    echo "  docker run -d --name $GUARDIAN_NAME -p 127.0.0.1:18080:8080 \\" >&2
    echo "    -v \"\$PWD/models:/models:ro\" \\" >&2
    echo "    -e GUARDIAN_MODEL=/models/granite-guardian-3.2-3b-a800m.gguf \\" >&2
    echo "    -e GUARDIAN_MODEL_SHA256=$MODEL_SHA \\" >&2
    echo "    --read-only --tmpfs /tmp --cap-drop ALL \\" >&2
    echo "    --security-opt no-new-privileges:true --memory 4g \\" >&2
    echo "    cleanerproxy-guardian:dev" >&2
    exit 1
  fi
}

live() {
  require_guardian
  say "model integrity (independent of the container's own check)"
  if [ -f "$MODEL_PATH" ]; then
    actual="$(shasum -a 256 "$MODEL_PATH" 2>/dev/null | cut -d' ' -f1 || sha256sum "$MODEL_PATH" | cut -d' ' -f1)"
    echo "expected $MODEL_SHA"
    echo "actual   $actual"
    [ "$actual" = "$MODEL_SHA" ] && echo "MATCH" || { echo "MISMATCH"; exit 1; }
  fi

  say "what the served model actually is"
  curl -fsS "$GUARDIAN_URL/v1/models" |
    python3 -c 'import json,sys; m=json.load(sys.stdin)["data"][0]; print(json.dumps(m.get("meta",{}),indent=1))'

  say "live pipeline accuracy (asserts recall/FPR floors)"
  CLEANERPROXY_GUARDIAN_URL="$GUARDIAN_URL" go test ./internal/guard/ -run Live -v -count=1 -timeout 900s |
    grep -E '^(--- |    --- |    live_test|ok|FAIL)'
}

evalsweep() {
  require_guardian
  say "variant comparison and threshold sweep"
  go run ./cmd/guardian-eval -url "$GUARDIAN_URL" -variants function_call
}

harden() {
  require_guardian
  say "guardian attack surface"
  printf 'GET  /tools    -> %s  (want 403/404: shell-exec agent tools must be unreachable)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' "$GUARDIAN_URL/tools")"
  printf 'POST /tools    -> %s  (want 403/404)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GUARDIAN_URL/tools" -d '{"tool":"exec_shell_command","params":{"command":"id"}}')"
  for p in /slots /metrics; do
    printf 'GET  %-9s -> %s  (want 501: disabled)\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' "$GUARDIAN_URL$p")"
  done
  printf 'POST /props    -> %s  (want 501: no runtime reconfiguration)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GUARDIAN_URL/props" -d '{}')"
  printf 'GET  /         -> %s  (want 404: no web UI)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' "$GUARDIAN_URL/")"

  say "LLAMA_ARG_* scrub in PID 1 (env-based flag injection)"
  n="$(docker exec "$GUARDIAN_NAME" sh -c 'tr "\0" "\n" </proc/1/environ | grep -c LLAMA_ARG_ || true' 2>/dev/null)"
  echo "LLAMA_ARG_* vars visible to llama-server: $n (want 0)"

  say "container privileges"
  docker inspect "$GUARDIAN_NAME" --format \
    'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}}' \
    2>/dev/null || echo "(container $GUARDIAN_NAME not running under that name)"

  say "process identity"
  docker exec "$GUARDIAN_NAME" id 2>/dev/null || true
}

case "${1:-all}" in
  hermetic) hermetic ;;
  live)     live ;;
  eval)     evalsweep ;;
  harden)   harden ;;
  all)      hermetic; harden; live; evalsweep ;;
  *) echo "usage: $0 [hermetic|live|eval|harden|all]" >&2; exit 2 ;;
esac

say "done"
