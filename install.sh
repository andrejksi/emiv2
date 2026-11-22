#!/bin/sh
set -eu

REPO="andrejksi/emiv2"
if [ -n "${EMI_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$EMI_INSTALL_DIR"
elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi
VERSION="${EMI_VERSION:-latest}"

detect_targets() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64) echo "x86_64-unknown-linux-musl x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-musl aarch64-unknown-linux-gnu" ;;
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
        cargo install --force --git "https://github.com/${REPO}.git" --bin emi
        exit 0
    fi
    echo "error: no prebuilt release found and cargo is not installed" >&2
    exit 1
}

if [ "${1:-}" = "--from-source" ]; then
    fallback_cargo
fi

targets="$(detect_targets || true)"
if [ -z "$targets" ]; then
    echo "unsupported platform $(uname -s)/$(uname -m); falling back to cargo" >&2
    fallback_cargo
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required to download prebuilt binaries; falling back to cargo" >&2
    fallback_cargo
fi

if [ "$VERSION" = "latest" ]; then
    base_urls="https://github.com/${REPO}/releases/latest/download https://github.com/${REPO}/releases/download/edge"
else
    base_urls="https://github.com/${REPO}/releases/download/${VERSION}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

downloaded_archive=""
downloaded_base_url=""

for base_url in $base_urls; do
    for target in $targets; do
        archive="emi-${target}.tar.gz"
        echo "trying ${archive} from ${base_url}..."
        if curl -fsSL "${base_url}/${archive}" -o "${tmpdir}/${archive}" 2>/dev/null; then
            downloaded_archive="$archive"
            downloaded_base_url="$base_url"
            break
        fi
    done
    if [ -n "$downloaded_archive" ]; then
        break
    fi
done

if [ -z "$downloaded_archive" ]; then
    echo "prebuilt binary not available for ${VERSION}; falling back to cargo" >&2
    fallback_cargo
fi

if curl -fsSL "${downloaded_base_url}/SHA256SUMS.txt" -o "${tmpdir}/SHA256SUMS.txt" 2>/dev/null; then
    expected="$(awk -v f="$downloaded_archive" '$2 == f || $2 == "*" f {print $1; exit}' "${tmpdir}/SHA256SUMS.txt")"
    if [ -n "$expected" ]; then
        verify_sha256 "${tmpdir}/${downloaded_archive}" "$expected"
    fi
fi

tar -xzf "${tmpdir}/${downloaded_archive}" -C "$tmpdir"
mkdir -p "$INSTALL_DIR"
install -m 755 "${tmpdir}/emi" "${INSTALL_DIR}/emi"

echo "installed emi to ${INSTALL_DIR}/emi"
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "add to PATH: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
"${INSTALL_DIR}/emi" --help | head -n 1
