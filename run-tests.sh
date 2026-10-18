#!/usr/bin/env bash
# cajeta-crypto test runner: builds the native shim, the library .cja and the
# test executable (cajeta-unit and the library on the classpath), runs the
# suite, then checks that the shim is linked only when something calls it.
#
#   ./run-tests.sh                 CAJETA=<cajeta> to pick the compiler
#
# cajeta-unit resolves like the sibling libraries: $UNIT_CJA, a ../cajeta-unit
# checkout, ~/.olla at the cajeta.json pin, then a sha256-verified Olla fetch.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
CAJETA="${CAJETA:-cajeta}"
OLLA_HOME="${OLLA_HOME:-$HOME/.olla}"
OLLA_URL="${OLLA_URL:-https://olla.cajeta.dev}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# Under MSYS2 or Git Bash on Windows a comma-separated --classpath reaches the
# compiler unconverted, so each entry is converted to a Windows path first.
winpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

# The compiler writes Windows executables with a .exe suffix.
exe=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1;
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

unit_cja="${UNIT_CJA:-}"
UNIT_REPO="${UNIT_REPO:-$here/../cajeta-unit}"
if [[ -z "$unit_cja" && -d "$UNIT_REPO" ]]; then
    echo ">> building cajeta-unit from checkout ($UNIT_REPO)"
    ( cd "$UNIT_REPO" && "$CAJETA" build >/dev/null )
    unit_cja="$(ls -t "$UNIT_REPO"/build/archive/dev.cajeta.unit-*.cja 2>/dev/null | head -1)"
fi
if [[ -z "$unit_cja" ]]; then
    UNIT_VER="$(sed -n 's/.*"dev\.cajeta\.unit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$here/cajeta.json" | head -1)"
    [[ -n "$UNIT_VER" ]] || { echo "no dev.cajeta.unit pin in cajeta.json" >&2; exit 1; }
    store_cja="$OLLA_HOME/dev.cajeta.unit/$UNIT_VER/dev.cajeta.unit-$UNIT_VER.cja"
    cache_cja="$here/build/.unit-cache/dev.cajeta.unit-$UNIT_VER.cja"
    if [[ -f "$store_cja" ]]; then unit_cja="$store_cja"
    elif [[ -f "$cache_cja" ]]; then unit_cja="$cache_cja"
    else
        echo ">> fetching dev.cajeta.unit $UNIT_VER from $OLLA_URL"
        mkdir -p "$(dirname "$cache_cja")"
        meta="$(curl -fsS "$OLLA_URL/v2/resolve?name=dev.cajeta.unit&version=$UNIT_VER")"
        sha="$(printf '%s' "$meta" | sed -n 's/.*"sha256":"sha256:\([0-9a-f]*\)".*/\1/p')"
        curl -fsS -o "$cache_cja" "$OLLA_URL/v2/blob/$sha"
        got="$(sha256_of "$cache_cja")"
        [[ "$got" == "$sha" ]] || { rm -f "$cache_cja"; echo "sha256 mismatch fetching unit" >&2; exit 1; }
        unit_cja="$cache_cja"
    fi
fi
[[ -f "$unit_cja" ]] || { echo "could not resolve a dev.cajeta.unit archive" >&2; exit 1; }
echo ">> cajeta-unit: $unit_cja"

manifest_version="$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$here/cajeta.json" | head -1)"
source_version="$(sed -n 's/.*version()[^"]*"\([^"]*\)".*/\1/p' \
    "$here/src/main/cajeta/dev/cajeta/crypto/Crypto.cajeta" | head -1)"
[[ "$manifest_version" == "$source_version" ]] \
    || { echo "VERSION DRIFT: cajeta.json says $manifest_version, Crypto.version() says $source_version" >&2; exit 1; }
echo ">> manifest: version $manifest_version matches Crypto.version()"

echo ">> building the native shim"
"$here/native/build.sh" >/dev/null
export CAJETA_NATIVE_PATH="$here/native"

echo ">> building the crypto library .cja"
"$CAJETA" --emit=cja -o "$out/crypto.cja" \
    dev.cajeta.crypto.Crypto.run "$here/src/main/cajeta" "$out/lib" >/dev/null

echo ">> building + running the test binary"
"$CAJETA" --emit=exe --profile=test \
    --classpath="$(winpath "$out/crypto.cja"),$(winpath "$unit_cja")" \
    -o "$out/cryptotests" \
    dev.cajeta.crypto.selftest.TestMain.run "$here/src/test/cajeta" "$out/test" >/dev/null
"$out/cryptotests"

echo ">> native shim linkage (spec 2.4)"
# nm's output is captured first: under pipefail, `nm | grep -q` fails when
# grep exits on its match and nm dies of SIGPIPE.
test_syms="$(nm "$out/cryptotests$exe")"
grep -q ' T __cajeta_crypto_random_fill' <<< "$test_syms" \
    || { echo "FAIL: the test binary does not contain __cajeta_crypto_random_fill" >&2; exit 1; }
# Measured 2026-10-17: every classpath class gets a registration constructor and
# a reflection invoke table that reach its @Native thunks, so a program that
# never calls the library still links the shim. Spec 2.4 records that. When the
# compiler stops rooting unreferenced classes this check fails: return spec 2.4
# to "links none of it" and flip the check back.
"$CAJETA" --emit=exe --classpath="$out/crypto.cja" -o "$out/dcecheck" \
    dcecheck.Main.run "$here/test-dce/src" "$out/dce" >/dev/null
dce_syms="$(nm "$out/dcecheck$exe")"
grep -q ' T __cajeta_crypto_random_fill' <<< "$dce_syms" \
    || { echo "CHANGED: a program that never calls the library no longer links the shim; update spec 2.4 and this check" >&2; exit 1; }
echo "  ok   the shim links into the test binary, and (spec 2.4, reflection rooting) into a program that never calls it"
