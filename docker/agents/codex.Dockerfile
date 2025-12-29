# syntax=docker/dockerfile:1.7

ARG BASE_IMAGE=tooltest/devtools:latest
FROM ${BASE_IMAGE}

ARG CODEX_SRC=codex
LABEL org.opencontainers.image.source="https://github.com/lambdalabs/tooltest" \
      org.opencontainers.image.title="tooltest codex agent runtime" \
      org.opencontainers.image.description="User-scoped Codex agent built on the repo devtools image."

USER root
# Copy a prebuilt Codex CLI binary from the build context into the image.
# Provide the binary alongside the Dockerfile (default CODEX_SRC=codex) or override
# with --build-arg CODEX_SRC=path/inside/context.
COPY ${CODEX_SRC} /usr/local/bin/codex
RUN chmod +x /usr/local/bin/codex

USER agent
WORKDIR /workspace
CMD ["/bin/bash"]
