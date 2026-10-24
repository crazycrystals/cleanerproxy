#!/bin/sh
# Fetch and verify the Tier 2 classifier weights.
#
# Source: IBM's own published GGUF build of Granite Guardian 3.2 3B-A800M,
# served from Ollama's content-addressed blob store. The URL contains the
# SHA-256 of the file, so the download is verified against the same digest the
# publisher committed to, and the check below fails closed on any mismatch.
#
# IBM does not publish a GGUF of this model on Hugging Face (only the 3.3-8b
# and 4.1-8b variants), and converting the safetensors ourselves would require
# a Python/torch toolchain. Pulling the first-party blob avoids both a
# third-party requantization and a pip dependency.
set -eu

MODEL_DIR="${MODEL_DIR:-./models}"
MODEL_FILE="granite-guardian-3.2-3b-a800m.gguf"
DIGEST="21e4d79c7a7399182182222636e44fc189947e1ac8c324dda93205d5769c4344"
URL="https://registry.ollama.ai/v2/ibm/granite3.2-guardian/blobs/sha256:${DIGEST}"

mkdir -p "$MODEL_DIR"
TARGET="$MODEL_DIR/$MODEL_FILE"

if [ -f "$TARGET" ]; then
  echo "verifying existing $TARGET ..."
  actual="$(shasum -a 256 "$TARGET" 2>/dev/null | cut -d' ' -f1 || sha256sum "$TARGET" | cut -d' ' -f1)"
  if [ "$actual" = "$DIGEST" ]; then
    echo "already present and verified."
    exit 0
  fi
  echo "digest mismatch, re-downloading" >&2
fi

echo "downloading ~2.6 GiB to $TARGET ..."
curl -fL --retry 5 --retry-delay 3 -C - -o "$TARGET" "$URL"

actual="$(shasum -a 256 "$TARGET" 2>/dev/null | cut -d' ' -f1 || sha256sum "$TARGET" | cut -d' ' -f1)"
if [ "$actual" != "$DIGEST" ]; then
  echo "INTEGRITY FAILURE: expected $DIGEST, got $actual" >&2
  exit 1
fi
echo "verified: $actual"
