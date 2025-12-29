# syntax=docker/dockerfile:1.7

ARG BASE_IMAGE=tooltest/dev-base:latest
FROM ${BASE_IMAGE}

ARG AGENT_NAME="ampcode"
LABEL org.opencontainers.image.source="https://github.com/lambdalabs/tooltest" \
      org.opencontainers.image.title="tooltest agent runtime" \
      org.opencontainers.image.description="Containerized terminal for the ${AGENT_NAME} agent built on the shared dev base."

USER root

# Install ${AGENT_NAME}-specific dependencies here. Leave this empty if the base image already
# contains everything the agent needs.

USER agent
WORKDIR /workspace
CMD ["/bin/bash"]
