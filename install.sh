#!/usr/bin/env bash
set -euo pipefail

REPO="lambdamechanic/tooltest"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

case "${os}" in
  Linux) os_id="linux" ;;
  Darwin) os_id="macos" ;;
  MINGW*|MSYS*|CYGWIN*) os_id="windows" ;;
  *)
    echo "Unsupported OS: ${os}" >&2
    exit 1
    ;;
esac

case "${arch}" in
  x86_64|amd64) arch_id="x86_64" ;;
  arm64|aarch64)
    if [ "${os_id}" = "macos" ]; then
      arch_id="arm64"
    else
      arch_id="aarch64"
    fi
    ;;
  *)
    echo "Unsupported architecture: ${arch}" >&2
    exit 1
    ;;
esac

if [ "${os_id}" = "windows" ] && [ "${arch_id}" != "x86_64" ]; then
  echo "Windows builds are only available for x86_64." >&2
  exit 1
fi

if [ "${os_id}" = "windows" ]; then
  asset="tooltest-windows-${arch_id}.exe"
  binary_name="tooltest.exe"
else
  asset="tooltest-${os_id}-${arch_id}"
  binary_name="tooltest"
fi

url="https://github.com/${REPO}/releases/download/latest/${asset}"
checksum_url="${url}.sha256"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${url}" -o "${tmp_dir}/${asset}"
  curl -fsSL "${checksum_url}" -o "${tmp_dir}/${asset}.sha256" || true
elif command -v wget >/dev/null 2>&1; then
  wget -q "${url}" -O "${tmp_dir}/${asset}"
  wget -q "${checksum_url}" -O "${tmp_dir}/${asset}.sha256" || true
else
  echo "curl or wget is required to download ${asset}" >&2
  exit 1
fi

verify_checksum() {
  local checksum_file="$1"
  local target_file="$2"
  if [ ! -f "${checksum_file}" ]; then
    echo "Checksum file not found; skipping verification." >&2
    return 0
  fi

  local expected
  expected="$(awk 'NF {print $1; exit}' "${checksum_file}")"
  if [ -z "${expected}" ]; then
    echo "Checksum file missing hash; skipping verification." >&2
    return 0
  fi

  local actual=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${target_file}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${target_file}" | awk '{print $1}')"
  else
    echo "Checksum verification skipped (sha256sum/shasum not found)." >&2
    return 0
  fi

  if [ "${expected}" != "${actual}" ]; then
    echo "Checksum verification failed for ${target_file}." >&2
    exit 1
  fi
}

verify_checksum "${tmp_dir}/${asset}.sha256" "${tmp_dir}/${asset}"

mkdir -p "${INSTALL_DIR}"
if [ ! -w "${INSTALL_DIR}" ]; then
  fallback="${HOME}/.local/bin"
  mkdir -p "${fallback}"
  INSTALL_DIR="${fallback}"
fi

install_path="${INSTALL_DIR}/${binary_name}"
mv "${tmp_dir}/${asset}" "${install_path}"
chmod +x "${install_path}"

echo "Installed ${binary_name} to ${install_path}"
