# syntax=docker/dockerfile:1
#
# Tier 2 classifier: llama.cpp's llama-server, built from source on Alpine,
# serving IBM Granite Guardian.
#
# Why llama.cpp directly rather than Ollama:
#   - Grammar-constrained decoding lets us force the output to exactly one of
#     two tokens, so an injection hidden in tool arguments can at most flip a
#     bit rather than steer free-form output.
#   - Token log-probabilities give a calibrated risk score, not just a label.
#   - No model registry API at runtime (no pull/push/create/delete endpoints);
#     Ollama's equivalents have been a recurring source of RCE and path
#     traversal bugs.
#   - We render the model's exact training chat template ourselves. IBM's own
#     Ollama template for this model diverges from its Hugging Face training
#     template (different delimiters and definition text), and small guardian
#     models are sensitive to that drift.
#
# Weights are NOT baked in. They are bind-mounted read-only and verified by
# SHA-256 at every container start; see entrypoint.sh.

# ---- build ------------------------------------------------------------------
FROM alpine:3.24 AS build

RUN apk add --no-cache build-base cmake git linux-headers

# Pinned by commit, not merely by tag. Tags are mutable references; commits are
# content-addressed. The clone is checked against the expected hash before any
# of it is compiled.
ARG LLAMA_CPP_TAG=v0.5.0
ARG LLAMA_CPP_COMMIT=7fe450e19305b828c199d602c23a8337aaa1f03b

RUN git clone --depth 1 --branch "${LLAMA_CPP_TAG}" https://github.com/ggml-org/llama.cpp /src \
 && actual="$(git -C /src rev-parse HEAD)" \
 && if [ "$actual" != "$LLAMA_CPP_COMMIT" ]; then \
      echo "llama.cpp commit mismatch: got $actual, want $LLAMA_CPP_COMMIT" >&2; exit 1; \
    fi

# Build flags, and why each security-relevant one is set:
#
#   LLAMA_SUBPROCESS=OFF    llama-server ships experimental built-in agent
#                           tools, including exec_shell_command, write_file and
#                           edit_file. A classifier inside a security boundary
#                           must not be able to spawn processes at all, so the
#                           capability is compiled out rather than merely left
#                           disabled at runtime.
#   LLAMA_USE_PREBUILT_UI=OFF
#                           When ON, the build downloads UI assets from a
#                           Hugging Face bucket: an unpinned network fetch in
#                           the middle of an otherwise pinned build.
#   LLAMA_BUILD_UI=OFF      No web UI; this server is only ever called by the
#                           proxy.
#   LLAMA_OPENSSL=OFF       TLS is unnecessary on an internal-only network and
#                           removes a large dependency from the binary.
#   GGML_NATIVE=ON          Tune for the build host's CPU. The image must be
#                           rebuilt for a different CPU family.
RUN cmake -S /src -B /build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DGGML_NATIVE=ON \
      -DLLAMA_SUBPROCESS=OFF \
      -DLLAMA_OPENSSL=OFF \
      -DLLAMA_BUILD_UI=OFF \
      -DLLAMA_USE_PREBUILT_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_APP=OFF \
      -DLLAMA_BUILD_TOOLS=ON \
      -DLLAMA_BUILD_SERVER=ON \
 && cmake --build /build --config Release --target llama-server -j"$(nproc)" \
 && strip /build/bin/llama-server

# ---- runtime ----------------------------------------------------------------
FROM alpine:3.24

RUN apk add --no-cache libstdc++ libgomp \
 && addgroup -g 10002 -S guardian \
 && adduser -u 10002 -S guardian -G guardian

COPY --from=build /build/bin/llama-server /usr/local/bin/llama-server
COPY entrypoint.sh /usr/local/bin/guardian-entrypoint
RUN chmod 0555 /usr/local/bin/guardian-entrypoint

USER guardian:guardian
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=120s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:8080/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/guardian-entrypoint"]
