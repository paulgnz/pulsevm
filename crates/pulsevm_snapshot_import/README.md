# pulsevm_snapshot_import

The state writer for Antelope portable chainstate snapshots. [`pulsevm_snapshot`]
decodes a nodeos `create_snapshot` `.bin` into typed rows; this crate writes
those rows into the arena-backed chain database through the same canonical
`hydrate_*` layouts the pure-Rust genesis path uses. Decode stays in
`pulsevm_snapshot`, state layout stays in `pulsevm_chaindb`; this crate only
translates between them. See the crate docs on `lib.rs` for exactly what is
written, what is counted-but-skipped, and how authority keys (K1/R1/WebAuthn) are packed.

## Verification harness

The import is verified the same way the consensus replay is: canonical
per-table state bytes, fingerprinted and frozen. The claim being proven is
byte-exactness — *importing snapshot S produces exactly the state S
describes* — and each layer of the replay regression has a direct import
counterpart:

| Replay regression (upstream)                  | Import regression (this crate)                    |
| --------------------------------------------- | ------------------------------------------------- |
| `replay_testnet_blocks` (`#[ignore]`, pulsevm_core) | `xpr_import_fingerprints_match_the_golden_roots` (`#[ignore]`, `tests/import_regression.rs`) |
| frozen block corpus, pinned by archive sha256 | frozen XPR testnet snapshot, pinned by file sha256 |
| 14 logical tables via `arena_*_state_bytes()` | the same 14 tables plus the five secondary-index families (19 total) |
| per-(block, table) `DefaultHasher` u64 roots in `golden_roots.txt` | per-table `DefaultHasher` u64 roots in `tests/golden_import_roots.txt` |
| `scripts/run-replay-regression.sh`            | `scripts/run-import-regression.sh`                |

Layers, weakest to strongest:

1. **Round-trip units** (`tests/roundtrip.rs`, always run): synthetic rows per
   section; importer → hydrate → serializer must reproduce independently
   stated expected bytes, and re-imports are no-ops.
2. **Harness self-check** (`tests/import_regression.rs`, always run): the full
   pipeline over an in-memory `MiniSnapshot`, so CI catches a drifted
   derivation or serializer without the external fixture.
3. **Source-truth cross-check** (fixture-gated): every table's expected
   canonical bytes are re-derived *from the snapshot rows themselves* —
   reader-side, never calling the writer — and must equal the arena
   serializers byte for byte. This catches row-mapping bugs (a dropped row, a
   swapped field, a wrong sort key), not just writer nondeterminism.
4. **Golden fingerprints** (fixture-gated): the 19 per-table roots must match
   the committed `tests/golden_import_roots.txt`. A writer regression is an
   instant table-level diff.
5. **Determinism + idempotency** (fixture-gated): two imports into fresh
   arenas fingerprint identically, and a re-import into a populated arena
   changes nothing. The fingerprint input is a sorted little-endian byte
   stream, so the committed roots must also reproduce across platforms
   (verified on macOS/arm64 and Linux/x86_64).
6. **Full-fixture counts + spot checks** (`tests/xpr_import.rs`,
   fixture-gated): section row counts pinned against the reader's own
   regression, plus semantic spot checks straight off the arena (permission
   trees, token balances, elastic limits, RAM usage).

## Running

The fixture-gated tests need the frozen XPR testnet snapshot
(`xpr-testnet-snapshot-2026-06-16.bin`, 176 MB, head block 390401414, chain id
`71ee83bc…`), pinned by sha256 in the script:

```sh
scripts/run-import-regression.sh ~/snapshots/xpr-testnet-snapshot-2026-06-16.bin
```

That runs every `#[ignore]`d test in this crate with the golden roots wired
up, printing `PASS <table> <root>` per table. To freeze a new reference set
(only when the fixture itself is deliberately replaced — update the sha256 pin
and the golden file in the same commit):

```sh
PULSEVM_SNAPSHOT_BIN=<snapshot.bin> \
PULSEVM_CAPTURE_IMPORT_ROOTS=crates/pulsevm_snapshot_import/tests/golden_import_roots.txt \
cargo test -p pulsevm_snapshot_import --release -- --ignored --nocapture
```

[`pulsevm_snapshot`]: ../pulsevm_snapshot
