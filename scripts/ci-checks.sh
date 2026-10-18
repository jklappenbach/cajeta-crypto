#!/usr/bin/env bash
# The checks CI runs beside the suite: the self-checking tour, and the gate that
# every public type is toured. CAJETA must be a path to the compiler.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
CAJETA="${CAJETA:-$(command -v cajeta)}"
export CAJETA
"$here/samples/tour/run-tour.sh"
"$here/scripts/check-library-tour-coverage.sh" \
    "$here/src/main/cajeta" "$here/samples/tour" "$here/scripts/tour-coverage-ignore.txt"
