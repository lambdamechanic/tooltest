#!/usr/bin/env bash
set -euo pipefail

version="${1:-2025-11-25}"
ref="${2:-main}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source_url="https://raw.githubusercontent.com/modelcontextprotocol/specification/${ref}/schema/${version}/schema.json"
dest_path="${repo_root}/tooltest-core/resources/mcp-schema-${version}.json"
stamp_path="${repo_root}/tooltest-core/resources/mcp-schema-${version}.source.txt"

if [[ "${ref}" == "main" ]]; then
  echo "warning: using moving ref 'main'; pass a commit hash for reproducibility" >&2
fi

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
  sha256="$(shasum -a 256 "${dest_path}" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256="$(sha256sum "${dest_path}" | awk '{print $1}')"
else
  sha256="unknown"
fi

retrieved_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > "${stamp_path}" <<EOF
version=${version}
ref=${ref}
source_url=${source_url}
sha256=${sha256}
retrieved_at=${retrieved_at}
EOF

echo "updated ${dest_path} from ${source_url}"
echo "wrote ${stamp_path}"
