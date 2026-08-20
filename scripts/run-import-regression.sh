#!/usr/bin/env bash
# Run the snapshot-import regression against the frozen XPR testnet snapshot.
#
# Usage:
#   scripts/run-import-regression.sh [snapshot.bin]
#
# The argument (or $PULSEVM_SNAPSHOT_BIN) must be the exact frozen fixture
# identified below — the import counterpart to run-replay-regression.sh's
# archive pin, so a changed download can't silently redefine the oracle. The
# harness imports the snapshot into a fresh arena, cross-checks every state
# table against canonical bytes re-derived from the snapshot rows, and verifies
# the per-table fingerprints against the committed golden_import_roots.txt
# (PASS/FAIL per table). Set PULSEVM_CAPTURE_IMPORT_ROOTS=<path> to freeze a
# new reference set instead of verifying; update the sha256 pin and the golden
# file together when the fixture changes.
set -euo pipefail

readonly EXPECTED_SNAPSHOT_SHA256="a70eb56ed71117b3a8052066303091c3307d8d1a3d3a533df570c8e473874996"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT="${1:-${PULSEVM_SNAPSHOT_BIN:-}}"

if [[ -z "${SNAPSHOT}" || ! -f "${SNAPSHOT}" ]]; then
  echo "usage: $0 <snapshot.bin>  (or set PULSEVM_SNAPSHOT_BIN)" >&2
  exit 1
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

actual_sha="$(sha256_file "${SNAPSHOT}")"
if [[ "${actual_sha}" != "${EXPECTED_SNAPSHOT_SHA256}" ]]; then
  echo "snapshot fixture digest mismatch: got ${actual_sha}, expected ${EXPECTED_SNAPSHOT_SHA256}" >&2
  exit 1
fi

cd "${REPO_ROOT}"
PULSEVM_SNAPSHOT_BIN="${SNAPSHOT}" \
PULSEVM_GOLDEN_IMPORT_ROOTS="${REPO_ROOT}/crates/pulsevm_snapshot_import/tests/golden_import_roots.txt" \
cargo test -p pulsevm_snapshot_import --release --locked -- \
  --ignored --nocapture --test-threads=1
