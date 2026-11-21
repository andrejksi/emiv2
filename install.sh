#!/bin/sh
set -eu

REPO="andrejksi/emiv2"
INSTALL_DIR="${EMI_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${EMI_VERSION:-latest}"

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
                *) return 1 ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) echo "x86_64-apple-darwin" ;;
                arm64|aarch64) echo "aarch64-apple-darwin" ;;
                *) return 1 ;;
            esac
            ;;
        *)
            return 1
            ;;
    esac
}

verify_sha256() {
    file="$1"
    expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        echo "warning: sha256sum/shasum not found; skipping checksum verification" >&2
        return 0
    fi
    if [ "$actual" != "$expected" ]; then
        echo "error: checksum mismatch for $file (expected $expected, got $actual)" >&2
        exit 1
    fi
}

fallback_cargo() {
    if command -v cargo >/dev/null 2>&1; then
        echo "installing emi from source via cargo..."
        cargo install --locked --git "https://github.com/${REPO}.git" --bin emi
        exit 0
    fi
    echo "error: no prebuilt release found and cargo is not installed" >&2
    exit 1
}

if [ "${1:-}" = "--from-source" ]; then
    fallback_cargo
fi

target="$(detect_target || true)"
if [ -z "$target" ]; then
    echo "unsupported platform $(uname -s)/$(uname -m); falling back to cargo" >&2
    fallback_cargo
fi

archive="emi-${target}.tar.gz"
if [ "$VERSION" = "latest" ]; then
    base_url="https://github.com/${REPO}/releases/latest/download"
else
    base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "downloading ${archive} (${VERSION})..."
if ! curl -fsSL "${base_url}/${archive}" -o "${tmpdir}/${archive}"; then
    echo "prebuilt binary not available at ${base_url}/${archive}; falling back to cargo" >&2
    fallback_cargo
fi

if curl -fsSL "${base_url}/SHA256SUMS.txt" -o "${tmpdir}/SHA256SUMS.txt" 2>/dev/null; then
    expected="$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1; exit}' "${tmpdir}/SHA256SUMS.txt")"
    if [ -n "$expected" ]; then
        verify_sha256 "${tmpdir}/${archive}" "$expected"
    fi
fi

tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
mkdir -p "$INSTALL_DIR"
install -m 755 "${tmpdir}/emi" "${INSTALL_DIR}/emi"

echo "installed emi to ${INSTALL_DIR}/emi"
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
"${INSTALL_DIR}/emi" --help | head -n 1
