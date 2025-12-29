#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BAKE_FILE="${ROOT}/docker-bake.hcl"

log() {
  printf "[docker-bake-check] %s\n" "$1"
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "Skipping bake validation: '${cmd}' is not available on this host."
    exit 0
  fi
}

require_command docker

if ! docker info >/dev/null 2>&1; then
  log "Skipping bake validation: Docker daemon is not reachable."
  exit 0
fi

if ! docker buildx version >/dev/null 2>&1; then
  log "Skipping bake validation: docker buildx is missing."
  exit 0
fi

log "Ensuring buildx builder is ready"
if ! docker buildx inspect >/dev/null 2>&1; then
  docker buildx create --use >/dev/null
fi

log "Running docker buildx bake validation"
docker buildx bake \
  --file "$BAKE_FILE" \
  --progress plain \
  agents
