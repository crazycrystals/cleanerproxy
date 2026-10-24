#!/bin/sh
# Guardian entrypoint: verify the model, scrub the environment, start
# llama-server with a minimal surface.
set -eu

: "${GUARDIAN_MODEL:?GUARDIAN_MODEL must be the path to the GGUF file}"
: "${GUARDIAN_MODEL_SHA256:?GUARDIAN_MODEL_SHA256 must be set; refusing to load an unverified model}"

# llama-server treats every LLAMA_ARG_* environment variable as a command-line
# flag. LLAMA_ARG_TOOLS in particular enables built-in agent tools, including
# shell execution. Scrub all of them so that nothing injected into this
# container's environment can silently widen what the server is allowed to do.
# (Subprocess support is also compiled out; this is the second layer.)
for var in $(env | sed -n 's/^\(LLAMA_ARG_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$var"
done

# Integrity check on every start, not just at download time. A model silently
# replaced with one that always answers "no risk" would disable Tier 2 while
# looking perfectly healthy; this is what catches that.
echo "guardian: verifying model integrity: $GUARDIAN_MODEL" >&2
actual="$(sha256sum "$GUARDIAN_MODEL" | cut -d' ' -f1)"
if [ "$actual" != "$GUARDIAN_MODEL_SHA256" ]; then
  echo "guardian: MODEL INTEGRITY FAILURE - refusing to start" >&2
  echo "  expected: $GUARDIAN_MODEL_SHA256" >&2
  echo "  actual:   $actual" >&2
  exit 1
fi
echo "guardian: model verified ($actual)" >&2

# Flag rationale:
#   --no-webui --no-slots   no UI, no slot introspection endpoint
#   --parallel 1            one request at a time; on a few CPU cores parallel
#                           slots only divide the same compute
#   --cache-ram             bound the host-RAM prompt cache, which otherwise
#                           defaults to several GiB and would blow the
#                           container's memory limit
#   --ctx-size              guardian prompts are small; a modest context keeps
#                           the KV cache allocation small
# /props writes, /metrics and built-in tools are all off by default and are
# deliberately not enabled.
exec /usr/local/bin/llama-server \
  --model "$GUARDIAN_MODEL" \
  --host 0.0.0.0 \
  --port 8080 \
  --ctx-size "${GUARDIAN_CTX_SIZE:-4096}" \
  --parallel 1 \
  --threads "${GUARDIAN_THREADS:-4}" \
  --threads-batch "${GUARDIAN_THREADS:-4}" \
  --cache-ram "${GUARDIAN_CACHE_RAM_MIB:-256}" \
  --no-webui \
  --no-slots
