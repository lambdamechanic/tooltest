# syntax=docker/dockerfile:1.7

# Repo-scoped developer tooling layer shared by user agent images.
# Keep this lean: only install debugging aids that every agent needs.

ARG BASE_IMAGE=tooltest/dev-base:latest
FROM ${BASE_IMAGE}

ARG AGENT_NAME="devtools"
LABEL org.opencontainers.image.source="https://github.com/lambdalabs/tooltest" \
      org.opencontainers.image.title="tooltest devtools runtime" \
      org.opencontainers.image.description="Common developer tools layered on the repo base image."

USER root

# Minimal debugging aids that should not ship with the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*

USER agent
WORKDIR /workspace
CMD ["/bin/bash"]
