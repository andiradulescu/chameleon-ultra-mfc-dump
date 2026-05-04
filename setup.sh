#!/usr/bin/env bash
# Fetch a pinned ChameleonUltra source snapshot, build the C helper
# binaries, and install Python deps via uv. Idempotent.
set -euo pipefail

CHAMELEON_SHA="e4a6e74b4586e9d4bb3515aa86aa90b2e169337d"
REPO_URL="https://github.com/RfidResearchGroup/ChameleonUltra"

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$REPO_ROOT/vendor/ChameleonUltra"
BIN_DIR="$REPO_ROOT/bin"

fetch_vendor() {
    if [ -d "$VENDOR_DIR/script" ] && [ -d "$VENDOR_DIR/src" ]; then
        echo "==> $VENDOR_DIR already populated (rm -rf vendor/ to refetch)"
        return
    fi
    echo "==> Fetching ChameleonUltra @ ${CHAMELEON_SHA:0:8}"
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    curl -fsSL "${REPO_URL}/archive/${CHAMELEON_SHA}.tar.gz" | tar xz -C "$tmp"
    mkdir -p "$VENDOR_DIR"
    mv "$tmp"/ChameleonUltra-*/software/script "$VENDOR_DIR/"
    mv "$tmp"/ChameleonUltra-*/software/src "$VENDOR_DIR/"
    echo "    Extracted to $VENDOR_DIR/{script,src}"
}

build_bin() {
    echo "==> Building C tools into $BIN_DIR/"
    mkdir -p "$BIN_DIR"
    local src="$VENDOR_DIR/src"
    local common="$src/common.c $src/crapto1.c $src/crypto1.c $src/bucketsort.c $src/parity.c"
    local flags="-O2 -I$src -D_GNU_SOURCE"

    # nested family (uses nested_util + pthread)
    cc $flags -o "$BIN_DIR/nested"       $common "$src/nested_util.c" "$src/nested.c"       -lpthread
    cc $flags -o "$BIN_DIR/staticnested" $common "$src/nested_util.c" "$src/staticnested.c" -lpthread

    # darkside (uses mfkey)
    cc $flags -o "$BIN_DIR/darkside"     $common "$src/mfkey.c"       "$src/darkside.c"

    # mfkey* (standalone)
    cc $flags -o "$BIN_DIR/mfkey32"      $common "$src/mfkey32.c"
    cc $flags -o "$BIN_DIR/mfkey32v2"    $common "$src/mfkey32v2.c"
    cc $flags -o "$BIN_DIR/mfkey64"      $common "$src/mfkey64.c"

    # newer staticnested variants for FM11RF08S "static encrypted" cards
    cc $flags -o "$BIN_DIR/staticnested_1nt"             $common "$src/staticnested_1nt.c"
    cc $flags -o "$BIN_DIR/staticnested_2x1nt_rf08s"     $common "$src/staticnested_2x1nt_rf08s.c"
    cc $flags -o "$BIN_DIR/staticnested_2x1nt_rf08s_1key" $common "$src/staticnested_2x1nt_rf08s_1key.c"

    echo "    Built $(ls "$BIN_DIR" | wc -l | tr -d ' ') binaries"
}

build_hardnested() {
    local src="$VENDOR_DIR/src"
    local hn="$src/HardnestedRecovery"

    # Find liblzma. pkg-config first; brew fallbacks for macOS Homebrew.
    local lzma_cflags="" lzma_ldflags="-llzma"
    if pkg-config --exists liblzma 2>/dev/null; then
        lzma_cflags="$(pkg-config --cflags liblzma)"
        lzma_ldflags="$(pkg-config --libs liblzma)"
    elif [ -d /opt/homebrew/opt/xz ]; then
        lzma_cflags="-I/opt/homebrew/opt/xz/include"
        lzma_ldflags="-L/opt/homebrew/opt/xz/lib -llzma"
    elif [ -d /usr/local/opt/xz ]; then
        lzma_cflags="-I/usr/local/opt/xz/include"
        lzma_ldflags="-L/usr/local/opt/xz/lib -llzma"
    else
        echo "==> Skipping hardnested: liblzma not found"
        echo "    macOS:  brew install xz"
        echo "    Debian: apt install liblzma-dev"
        return
    fi

    echo "==> Building hardnested into $BIN_DIR/"
    cc -O3 -D_GNU_SOURCE \
        -I"$src" -I"$hn" -I"$hn/pm3" -I"$hn/hardnested" \
        $lzma_cflags \
        -o "$BIN_DIR/hardnested" \
        "$src"/common.c "$src"/crapto1.c "$src"/crypto1.c "$src"/bucketsort.c "$src"/parity.c \
        "$hn"/hardnested_main.c "$hn"/cmdhfmfhard.c \
        "$hn"/pm3/ui.c "$hn"/pm3/util.c "$hn"/pm3/util_posix.c "$hn"/pm3/commonutil.c \
        "$hn"/hardnested/hardnested_bf_core.c "$hn"/hardnested/hardnested_bruteforce.c \
        "$hn"/hardnested/hardnested_bitarray_core.c "$hn"/hardnested/tables.c \
        $lzma_ldflags -lpthread -lm
    echo "    Built hardnested"
}

ensure_uv_deps() {
    if ! command -v uv > /dev/null; then
        echo "==> uv not installed; install from https://docs.astral.sh/uv/, then run: uv sync"
        return
    fi
    echo "==> uv sync"
    (cd "$REPO_ROOT" && uv sync)
}

fetch_vendor
build_bin
build_hardnested
ensure_uv_deps
echo
echo "Setup complete. Run: uv run python dump_card.py"
