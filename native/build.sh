#!/usr/bin/env bash
#
# Build the cajeta_crypto shim (native/*.c) into the static archive the cajeta
# linker resolves:
#
#     native/<platform>/libcajeta_crypto.a
#
# <platform> follows cajeta's NativeLink: linux-x64, linux-arm64, macos-arm64,
# windows-x64. The shim calls OpenSSL 3 and is compiled against the host's
# headers; it vendors nothing, because the compiler links -lssl -lcrypto into
# every executable already. Point CAJETA_NATIVE_PATH at this native/ directory
# for a local build or test run; `cajeta build` bakes the archive into the .cja.
#
# $CC overrides the C compiler; $CFLAGS adds flags (an OpenSSL include dir such
# as -I"$(brew --prefix openssl@3)/include" on macOS).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"

case "$(uname -s)" in
    Linux)                os=linux   ;;
    Darwin)               os=macos   ;;
    MINGW*|MSYS*|CYGWIN*) os=windows ;;
    *)                    os=linux   ;;
esac
case "$(uname -m)" in
    x86_64|amd64)   arch=x64   ;;
    aarch64|arm64)  arch=arm64 ;;
    *)              arch="$(uname -m)" ;;
esac
platform="${CAJETA_NATIVE_PLATFORM:-$os-$arch}"
out="$here/$platform"
mkdir -p "$out"

obj="$(mktemp -d)"
trap 'rm -rf "$obj"' EXIT

objs=()
for src in "$here"/*.c; do
    o="$obj/$(basename "${src%.c}").o"
    $CC -O2 -DNDEBUG -fPIC ${CFLAGS:-} -c "$src" -o "$o"
    objs+=("$o")
done

rm -f "$out/libcajeta_crypto.a"
${AR:-ar} rcs "$out/libcajeta_crypto.a" "${objs[@]}"
echo "built $out/libcajeta_crypto.a"
