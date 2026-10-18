#!/usr/bin/env bash
# Build and run the self-checking dev.cajeta.crypto tour. CAJETA picks the compiler.
set -euo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"
CAJETA="${CAJETA:-cajeta}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
"$here/native/build.sh" >/dev/null
export CAJETA_NATIVE_PATH="$here/native"
"$CAJETA" --emit=cja -o "$out/crypto.cja" \
    dev.cajeta.crypto.Crypto.run "$here/src/main/cajeta" "$out/lib" >/dev/null
"$CAJETA" --emit=exe --classpath="$out/crypto.cja" -o "$out/crypto-tour" \
    cryptotour.CryptoTour.main "$here/samples/tour/src/main/cajeta" "$out/tour" >/dev/null
"$out/crypto-tour"
