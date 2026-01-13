#!/usr/bin/env bash
set -euo pipefail

version="${1:-2025-11-25}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source_url="https://raw.githubusercontent.com/modelcontextprotocol/specification/main/schema/${version}/schema.json"
dest_path="${repo_root}/tooltest-core/resources/mcp-schema-${version}.json"

mkdir -p "$(dirname "${dest_path}")"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${source_url}" -o "${dest_path}"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${dest_path}" "${source_url}"
else
  echo "missing downloader: install curl or wget" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${dest_path}"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${dest_path}"
fi

echo "updated ${dest_path} from ${source_url}"
