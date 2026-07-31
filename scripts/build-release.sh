#!/usr/bin/env bash
# Build hiewLM release binaries for one or more targets.
#
#   ./scripts/build-release.sh                 # host only
#   ./scripts/build-release.sh windows         # + x86_64 Windows
#   ./scripts/build-release.sh windows macos   # several
#   ./scripts/build-release.sh all
#
# Cross-compiling to Windows from macOS/Linux needs mingw-w64:
#   macOS:  brew install mingw-w64
#   Debian: apt install gcc-mingw-w64-x86-64
# Native Windows builds (MSVC toolchain) need none of that — just
# `cargo build --release`.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=dist
mkdir -p "$OUT"

# Homebrew/distro Rust ships std for the host only, so cross-compilation has to
# go through a rustup toolchain. Prefer rustup's cargo when one is available.
if command -v rustup >/dev/null 2>&1; then
    TC_BIN="$(rustup run "$(rustup default | cut -d' ' -f1 | cut -d'(' -f1)" \
        rustc --print sysroot 2>/dev/null)/bin"
    if [ -x "$TC_BIN/cargo" ]; then
        CARGO="$TC_BIN/cargo"
        export PATH="$TC_BIN:$PATH"
    fi
fi
CARGO="${CARGO:-cargo}"

build() {
    local target="$1" label="$2" ext="${3:-}"
    echo "==> $label ($target)"
    if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        echo "    installing std for $target"
        rustup target add "$target"
    fi
    "$CARGO" build --release --target "$target"
    for bin in hiewlm hiewlmc; do
        cp "target/$target/release/$bin$ext" "$OUT/$bin-$label$ext"
    done
    echo "    -> $OUT/hiewlm-$label$ext, $OUT/hiewlmc-$label$ext"
}

targets=("${@:-host}")
[ "${targets[0]}" = "all" ] && targets=(host windows linux)

for t in "${targets[@]}"; do
    case "$t" in
        host)    echo "==> host"; "$CARGO" build --release
                 for b in hiewlm hiewlmc; do cp "target/release/$b" "$OUT/$b-host"; done ;;
        windows) build x86_64-pc-windows-gnu   windows-x64 .exe ;;
        macos)   build x86_64-apple-darwin     macos-x64 ;;
        macos-arm) build aarch64-apple-darwin  macos-arm64 ;;
        linux)   build x86_64-unknown-linux-gnu linux-x64 ;;
        *) echo "unknown target '$t' (host|windows|macos|macos-arm|linux|all)" >&2; exit 2 ;;
    esac
done

echo
echo "Artifacts in $OUT/:"
ls -lh "$OUT"
