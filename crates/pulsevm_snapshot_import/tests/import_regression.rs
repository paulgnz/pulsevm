//! Byte-exact import verification harness — the import counterpart to the
//! replay regression (`replay_testnet_blocks` + scripts/run-replay-regression.sh).
//!
//! Three layers, mirroring the replay's discipline:
//!
//! 1. **Golden fingerprints**: after `import_chainstate`, every logical state table is serialized
//!    through the same canonical `*_state_bytes()` serializers the replay fingerprints, and hashed
//!    to a per-table u64 root (same `DefaultHasher` construction). The roots for the frozen XPR
//!    testnet snapshot are committed in `tests/golden_import_roots.txt`; any writer regression
//!    shows up as a table-level diff.
//! 2. **Source-truth cross-check**: the expected canonical bytes for every table are *re-derived
//!    from the snapshot rows themselves* — reader-side, without going through the writer — and must
//!    equal the arena serializers byte for byte. That catches row-mapping bugs (a dropped row, a
//!    swapped field, a wrong sort key), not just writer nondeterminism.
//! 3. **Determinism**: a second import into a fresh arena must fingerprint identically, and a
//!    re-import into the populated arena must change nothing. Because the fingerprint input is the
//!    canonical byte stream (little-endian, sorted by table key), the roots are also portable
//!    across platforms — the committed goldens must reproduce on macOS and Linux.
//!
//! The XPR test is `#[ignore]`d (the 176 MB fixture is external); run it via
//! `scripts/run-import-regression.sh <snapshot.bin>`. The `MiniSnapshot` test
//! runs everywhere and keeps the harness itself honest without the fixture.

use std::collections::HashMap;

use pulsevm_chaindb::ChainDatabase;
use pulsevm_crypto::{
    AuthorityPublicKey,
    K1PrivateKey,
};

/// A real secp256k1 point for test authorities (the packer validates keys).
fn k1_point(byte: u8) -> [u8; 33] {
    let packed = K1PrivateKey::from_scalar(&[byte; 32])
        .unwrap()
        .public_key()
        .to_packed();
    let mut point = [0u8; 33];
    point.copy_from_slice(&packed[1..]);
    point
}
use pulsevm_snapshot::{
    SnapshotAuthority,
    SnapshotElasticLimitParameters,
    SnapshotReader,
    UsageAccumulator,
    testing::{
        MiniSnapshot,
        TestAccount,
    },
};
use pulsevm_snapshot_import::import_chainstate;

/// The committed golden roots for the frozen XPR testnet snapshot
/// (`latest-snapshot-20260815.bin`, pinned by sha256 in
/// scripts/run-import-regression.sh).
const DEFAULT_GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden_import_roots.txt");

/// The same fingerprint the replay regression records per table: the
/// `DefaultHasher` of the table's canonical state bytes. SipHash over a
/// little-endian byte stream, so the value is platform-independent.
fn table_root(bytes: &[u8]) -> u64 {
    use std::hash::{
        Hash,
        Hasher,
    };
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Every logical state table the import writes, serialized through the arena's
/// canonical serializers — the replay regression's 14 tables plus the five
/// secondary-index families the importer also carries.
fn arena_tables(db: &ChainDatabase) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("account_metadata", db.account_metadata_state_bytes()),
        ("account", db.account_state_bytes()),
        ("permission", db.permission_state_bytes()),
        ("permission_link", db.permission_link_state_bytes()),
        ("code", db.code_state_bytes()),
        ("transaction", db.transaction_state_bytes()),
        ("resource_usage", db.resource_usage_state_bytes()),
        ("resource_limits", db.account_limits_state_bytes()),
        ("resource_state", db.resource_state_bytes()),
        (
            "dynamic_global_property",
            db.global_action_sequence()
                .unwrap_or(0)
                .to_le_bytes()
                .to_vec(),
        ),
        ("global_property", db.global_property_state_bytes()),
        ("resource_limits_config", db.resource_config_state_bytes()),
        ("contract_table", db.contract_table_state_bytes()),
        ("contract_key_value", db.contract_kv_state_bytes()),
        ("contract_idx64", db.contract_idx64_state_bytes()),
        ("contract_idx128", db.contract_idx128_state_bytes()),
        ("contract_idx256", db.contract_idx256_state_bytes()),
        ("contract_idx_double", db.contract_idx_double_state_bytes()),
        (
            "contract_idx_long_double",
            db.contract_idx_long_double_state_bytes(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Source truth: re-derive each table's expected canonical bytes from the
// snapshot rows, without going through the writer. Field order, endianness and
// sort keys restate the serializer contracts documented on the `*_state_bytes`
// functions in pulsevm_chaindb; none of the code below calls the import crate.
// ---------------------------------------------------------------------------

fn put_acc(out: &mut Vec<u8>, acc: &UsageAccumulator) {
    out.extend_from_slice(&acc.value_ex.to_le_bytes());
    out.extend_from_slice(&acc.consumed.to_le_bytes());
    out.extend_from_slice(&acc.last_ordinal.to_le_bytes());
}

/// The arena `shared_authority` blob a snapshot authority must land as:
/// threshold, then every key (K1, R1, WebAuthn) as a length-prefixed canonical
/// `AuthorityPublicKey::to_packed` form + weight, then accounts and waits in
/// full.
fn expected_auth_blob(auth: &SnapshotAuthority) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&auth.threshold.to_le_bytes());
    out.extend_from_slice(&(auth.keys.len() as u32).to_le_bytes());
    for kw in &auth.keys {
        let packed = AuthorityPublicKey::try_from(&kw.key)
            .expect("source snapshot keys are canonical")
            .to_packed();
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(&packed);
        out.extend_from_slice(&kw.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.accounts.len() as u32).to_le_bytes());
    for a in &auth.accounts {
        out.extend_from_slice(&a.actor.as_u64().to_le_bytes());
        out.extend_from_slice(&a.permission.as_u64().to_le_bytes());
        out.extend_from_slice(&a.weight.to_le_bytes());
    }
    out.extend_from_slice(&(auth.waits.len() as u32).to_le_bytes());
    for w in &auth.waits {
        out.extend_from_slice(&w.wait_sec.to_le_bytes());
        out.extend_from_slice(&w.weight.to_le_bytes());
    }
    out
}

fn expected_elastic(out: &mut Vec<u8>, p: &SnapshotElasticLimitParameters) {
    for v in [
        p.target,
        p.max,
        p.contract_rate.numerator,
        p.contract_rate.denominator,
        p.expand_rate.numerator,
        p.expand_rate.denominator,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Expected canonical bytes for every table, derived from the snapshot rows.
/// Table names match `arena_tables` one-to-one.
fn derive_expected(snapshot: &SnapshotReader) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // account_metadata: name order; name, privileged, four sequences,
    // code_hash, vm_type, vm_version. (last_code_update is not part of the
    // canonical form.)
    let mut rows: Vec<_> = snapshot
        .account_metadata()
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.sort_by_key(|r| r.name.as_u64());
    let mut bytes = Vec::new();
    for r in &rows {
        bytes.extend_from_slice(&r.name.as_u64().to_le_bytes());
        bytes.push(r.is_privileged() as u8);
        bytes.extend_from_slice(&r.recv_sequence.to_le_bytes());
        bytes.extend_from_slice(&r.auth_sequence.to_le_bytes());
        bytes.extend_from_slice(&r.code_sequence.to_le_bytes());
        bytes.extend_from_slice(&r.abi_sequence.to_le_bytes());
        bytes.extend_from_slice(&r.code_hash.0);
        bytes.push(r.vm_type);
        bytes.push(r.vm_version);
    }
    out.push(("account_metadata", bytes));

    // account: name order; name, creation slot, length-prefixed abi.
    let mut rows: Vec<_> = snapshot.accounts().unwrap().map(|r| r.unwrap()).collect();
    rows.sort_by_key(|r| r.name.as_u64());
    let mut bytes = Vec::new();
    for r in &rows {
        bytes.extend_from_slice(&r.name.as_u64().to_le_bytes());
        bytes.extend_from_slice(&r.creation_date.slot().to_le_bytes());
        bytes.extend_from_slice(&(r.abi.0.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&r.abi.0);
    }
    out.push(("account", bytes));

    // permission: chainbase ids are authored in snapshot row order from 1
    // (the reserved owner-0/name-0 row is id 0 and not serialized); parents
    // resolve by (owner, parent-name) through already-numbered rows. Canonical
    // order is (owner, perm_name).
    let mut ids: HashMap<(u64, u64), u64> = HashMap::new();
    let mut next_id = 1u64;
    let mut rows: Vec<(u64, u64, u64, u64, u64, u64, Vec<u8>)> = Vec::new();
    for r in snapshot.permissions().unwrap() {
        let r = r.unwrap();
        let owner = r.owner.as_u64();
        let name = r.name.as_u64();
        if owner == 0 && name == 0 {
            continue;
        }
        let id = next_id;
        next_id += 1;
        ids.insert((owner, name), id);
        let parent = match r.parent.as_u64() {
            0 => 0,
            p => ids[&(owner, p)],
        };
        let last_used = r.last_used.time_since_epoch().count() as u64;
        let last_updated = r.last_updated.time_since_epoch().count() as u64;
        rows.push((
            owner,
            name,
            id,
            parent,
            last_used,
            last_updated,
            expected_auth_blob(&r.auth),
        ));
    }
    rows.sort_by_key(|r| (r.0, r.1));
    let mut bytes = Vec::new();
    for (owner, name, id, parent, last_used, last_updated, auth) in &rows {
        for v in [owner, name, id, parent, last_used, last_updated] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&(auth.len() as u32).to_le_bytes());
        bytes.extend_from_slice(auth);
    }
    out.push(("permission", bytes));

    // permission_link: (account, code, message_type) order; four names.
    let mut rows: Vec<_> = snapshot
        .permission_links()
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.sort_by_key(|l| (l.account.as_u64(), l.code.as_u64(), l.message_type.as_u64()));
    let mut bytes = Vec::new();
    for l in &rows {
        for v in [l.account, l.code, l.message_type, l.required_permission] {
            bytes.extend_from_slice(&v.as_u64().to_le_bytes());
        }
    }
    out.push(("permission_link", bytes));

    // code: (code_hash, vm_type, vm_version) order; hash, vms, ref_count,
    // first_block_used, length-prefixed wasm.
    let mut rows: Vec<_> = snapshot.code().unwrap().map(|r| r.unwrap()).collect();
    rows.sort_by_key(|c| (c.code_hash.0, c.vm_type, c.vm_version));
    let mut bytes = Vec::new();
    for c in &rows {
        bytes.extend_from_slice(&c.code_hash.0);
        bytes.push(c.vm_type);
        bytes.push(c.vm_version);
        bytes.extend_from_slice(&c.code_ref_count.to_le_bytes());
        bytes.extend_from_slice(&c.first_block_used.to_le_bytes());
        bytes.extend_from_slice(&(c.code.0.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&c.code.0);
    }
    out.push(("code", bytes));

    // transaction: trx_id order; id, expiration seconds.
    let mut rows: Vec<_> = snapshot
        .transactions()
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.sort_by_key(|t| t.trx_id.0);
    let mut bytes = Vec::new();
    for t in &rows {
        bytes.extend_from_slice(&t.trx_id.0);
        bytes.extend_from_slice(&t.expiration.sec_since_epoch().to_le_bytes());
    }
    out.push(("transaction", bytes));

    // resource_usage: owner order; owner, ram, net accumulator, cpu
    // accumulator.
    let mut rows: Vec<_> = snapshot
        .resource_usage()
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.sort_by_key(|r| r.owner.as_u64());
    let mut bytes = Vec::new();
    for r in &rows {
        bytes.extend_from_slice(&r.owner.as_u64().to_le_bytes());
        bytes.extend_from_slice(&r.ram_usage.to_le_bytes());
        put_acc(&mut bytes, &r.net_usage);
        put_acc(&mut bytes, &r.cpu_usage);
    }
    out.push(("resource_usage", bytes));

    // resource_limits: (pending, owner) order — snapshot rows are all
    // committed, so pending is 0 throughout; ram/net/cpu as u64 bit patterns.
    let mut rows: Vec<_> = snapshot
        .resource_limits()
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.sort_by_key(|r| r.owner.as_u64());
    let mut bytes = Vec::new();
    for r in &rows {
        bytes.push(0);
        bytes.extend_from_slice(&r.owner.as_u64().to_le_bytes());
        bytes.extend_from_slice(&(r.ram_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&(r.net_weight as u64).to_le_bytes());
        bytes.extend_from_slice(&(r.cpu_weight as u64).to_le_bytes());
    }
    out.push(("resource_limits", bytes));

    // resource_state singleton: the two block-usage accumulators, then the
    // seven scalars.
    let s = snapshot.resource_limits_state().unwrap();
    let mut bytes = Vec::new();
    put_acc(&mut bytes, &s.average_block_net_usage);
    put_acc(&mut bytes, &s.average_block_cpu_usage);
    for v in [
        s.pending_net_usage,
        s.pending_cpu_usage,
        s.total_net_weight,
        s.total_cpu_weight,
        s.total_ram_bytes,
        s.virtual_net_limit,
        s.virtual_cpu_limit,
    ] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    out.push(("resource_state", bytes));

    // dynamic_global_property: the global action sequence, LE.
    let dgp = snapshot.dynamic_global_property().unwrap();
    out.push((
        "dynamic_global_property",
        dgp.global_action_sequence.to_le_bytes().to_vec(),
    ));

    // global_property: the 16 tracked chain-config fields in ChainConfigV0
    // order (deferred_trx_expiration_window and max_action_return_value_size
    // are not tracked by the arena and must not appear).
    let c = snapshot.global_property().unwrap().configuration.base;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&c.max_block_net_usage.to_le_bytes());
    for v in [
        c.target_block_net_usage_pct,
        c.max_transaction_net_usage,
        c.base_per_transaction_net_usage,
        c.net_usage_leeway,
        c.context_free_discount_net_usage_num,
        c.context_free_discount_net_usage_den,
        c.max_block_cpu_usage,
        c.target_block_cpu_usage_pct,
        c.max_transaction_cpu_usage,
        c.min_transaction_cpu_usage,
        c.max_transaction_lifetime,
        c.max_transaction_delay,
        c.max_inline_action_size,
    ] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes.extend_from_slice(&c.max_inline_action_depth.to_le_bytes());
    bytes.extend_from_slice(&c.max_authority_depth.to_le_bytes());
    out.push(("global_property", bytes));

    // resource_limits_config singleton: the cpu then net elastic parameters
    // (target, max, contract ratio, expand ratio as u64s), then periods /
    // multipliers and the two averaging windows as u32s.
    let cfg = snapshot.resource_limits_config().unwrap();
    let mut bytes = Vec::new();
    expected_elastic(&mut bytes, &cfg.cpu_limit_parameters);
    expected_elastic(&mut bytes, &cfg.net_limit_parameters);
    for v in [
        cfg.cpu_limit_parameters.periods,
        cfg.cpu_limit_parameters.max_multiplier,
        cfg.net_limit_parameters.periods,
        cfg.net_limit_parameters.max_multiplier,
        cfg.account_cpu_usage_average_window,
        cfg.account_net_usage_average_window,
    ] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    out.push(("resource_limits_config", bytes));

    // contract tables + the six row families, in one pass over the section.
    // Canonical order for every family is (code, scope, table[, primary_key]).
    type Key = (u64, u64, u64);
    type IdxRow<const N: usize> = (Key, u64, u64, [u8; N]);
    let mut tables: Vec<(Key, u64, u32)> = Vec::new();
    let mut kv: Vec<(Key, u64, u64, Vec<u8>)> = Vec::new();
    let mut idx64: Vec<(Key, u64, u64, [u8; 8])> = Vec::new();
    let mut idx128: Vec<(Key, u64, u64, [u8; 16])> = Vec::new();
    let mut idx256: Vec<(Key, u64, u64, [u8; 32])> = Vec::new();
    let mut idx_double: Vec<(Key, u64, u64, [u8; 8])> = Vec::new();
    let mut idx_long_double: Vec<(Key, u64, u64, [u8; 16])> = Vec::new();
    for table in snapshot.contract_tables().unwrap() {
        let table = table.unwrap();
        let t = &table.table;
        let key = (t.code.as_u64(), t.scope.as_u64(), t.table.as_u64());
        tables.push((key, t.payer.as_u64(), t.count));
        for r in &table.key_values {
            kv.push((key, r.primary_key, r.payer.as_u64(), r.value.0.clone()));
        }
        for r in &table.idx64 {
            idx64.push((
                key,
                r.primary_key,
                r.payer.as_u64(),
                r.secondary_key.to_le_bytes(),
            ));
        }
        for r in &table.idx128 {
            idx128.push((
                key,
                r.primary_key,
                r.payer.as_u64(),
                r.secondary_key.to_le_bytes(),
            ));
        }
        for r in &table.idx256 {
            idx256.push((key, r.primary_key, r.payer.as_u64(), r.secondary_key.0));
        }
        for r in &table.idx_double {
            idx_double.push((
                key,
                r.primary_key,
                r.payer.as_u64(),
                r.secondary_key.to_bits().to_le_bytes(),
            ));
        }
        for r in &table.idx_long_double {
            idx_long_double.push((
                key,
                r.primary_key,
                r.payer.as_u64(),
                r.secondary_key.to_le_bytes(),
            ));
        }
    }

    tables.sort_by_key(|r| r.0);
    let mut bytes = Vec::new();
    for ((code, scope, table), payer, count) in &tables {
        for v in [code, scope, table, payer] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    out.push(("contract_table", bytes));

    kv.sort_by_key(|r| (r.0, r.1));
    let mut bytes = Vec::new();
    for ((code, scope, table), primary, payer, value) in &kv {
        for v in [code, scope, table, primary, payer] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
    }
    out.push(("contract_key_value", bytes));

    fn idx_bytes<const N: usize>(mut rows: Vec<IdxRow<N>>) -> Vec<u8> {
        rows.sort_by_key(|r| (r.0, r.1));
        let mut bytes = Vec::new();
        for ((code, scope, table), primary, payer, secondary) in &rows {
            for v in [code, scope, table, primary, payer] {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            bytes.extend_from_slice(secondary);
        }
        bytes
    }
    out.push(("contract_idx64", idx_bytes(idx64)));
    out.push(("contract_idx128", idx_bytes(idx128)));
    out.push(("contract_idx256", idx_bytes(idx256)));
    out.push(("contract_idx_double", idx_bytes(idx_double)));
    out.push(("contract_idx_long_double", idx_bytes(idx_long_double)));

    out
}

// ---------------------------------------------------------------------------
// Comparison plumbing.
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Byte-for-byte comparison with a first-diff window, like the replay's SHiP
/// mismatch report — a megabyte-long `assert_eq!` dump helps nobody.
fn assert_same_bytes(table: &str, arena: &[u8], expected: &[u8]) {
    if arena == expected {
        return;
    }
    let at = arena
        .iter()
        .zip(expected.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(arena.len().min(expected.len()));
    let lo = at.saturating_sub(8);
    panic!(
        "source-truth mismatch in {table}: arena {} bytes, expected {} bytes; first diff at offset {at}\n  arena   : {}\n  expected: {}",
        arena.len(),
        expected.len(),
        hex(&arena[lo..(at + 16).min(arena.len())]),
        hex(&expected[lo..(at + 16).min(expected.len())]),
    );
}

/// Cross-checks the arena serializers against the reader-derived source truth,
/// byte for byte, and returns the per-table fingerprints.
fn verify_against_source_truth(
    db: &ChainDatabase,
    snapshot: &SnapshotReader,
) -> Vec<(&'static str, u64)> {
    let arena = arena_tables(db);
    let expected = derive_expected(snapshot);
    assert_eq!(
        arena.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        expected.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        "table lists must line up"
    );
    for ((name, arena_bytes), (_, expected_bytes)) in arena.iter().zip(&expected) {
        assert_same_bytes(name, arena_bytes, expected_bytes);
    }
    arena
        .iter()
        .map(|(name, bytes)| (*name, table_root(bytes)))
        .collect()
}

fn parse_golden(path: &str) -> Vec<(String, u64)> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read golden roots {path}: {e}"))
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let table = it.next().expect("golden line: table name").to_string();
            let root = u64::from_str_radix(it.next().expect("golden line: root"), 16)
                .expect("golden line: hex root");
            (table, root)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The XPR-snapshot regression (fixture-gated, run via
// scripts/run-import-regression.sh).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs the 176MB XPR testnet snapshot fixture (PULSEVM_SNAPSHOT_BIN)"]
fn xpr_import_fingerprints_match_the_golden_roots() {
    let path = std::env::var("PULSEVM_SNAPSHOT_BIN")
        .expect("set PULSEVM_SNAPSHOT_BIN to the XPR testnet snapshot .bin");
    let bytes = std::fs::read(&path).expect("read snapshot file");
    let snapshot = SnapshotReader::new(&bytes).expect("parse container");

    // Import into a fresh arena and cross-check every table against the
    // reader-derived source truth.
    let db = ChainDatabase::new().expect("fresh arena");
    let report = import_chainstate(&db, &snapshot).expect("import chainstate");
    // Guard against a silent no-op (an empty fixture would fingerprint
    // "correctly" while verifying nothing).
    assert!(
        report.accounts > 0
            && report.permissions.written > 0
            && report.code_objects > 0
            && report.contract_tables.key_values > 0,
        "import wrote no state — wrong fixture?"
    );
    let roots = verify_against_source_truth(&db, &snapshot);
    eprintln!(
        "source truth: all {} tables re-derived from the snapshot rows match the arena byte-for-byte",
        roots.len()
    );

    // Determinism: a second import into a second fresh arena fingerprints
    // identically.
    let db2 = ChainDatabase::new().expect("second fresh arena");
    import_chainstate(&db2, &snapshot).expect("second import");
    let roots2: Vec<(&'static str, u64)> = arena_tables(&db2)
        .iter()
        .map(|(name, bytes)| (*name, table_root(bytes)))
        .collect();
    assert_eq!(
        roots, roots2,
        "two fresh imports must fingerprint identically"
    );
    drop(db2);

    // Idempotency: re-importing into the populated arena changes nothing.
    import_chainstate(&db, &snapshot).expect("re-import");
    let roots3: Vec<(&'static str, u64)> = arena_tables(&db)
        .iter()
        .map(|(name, bytes)| (*name, table_root(bytes)))
        .collect();
    assert_eq!(roots, roots3, "a re-import must not change any table");

    // Capture mode: freeze the roots (plus the snapshot identity, as a
    // comment) instead of verifying.
    if let Ok(out) = std::env::var("PULSEVM_CAPTURE_IMPORT_ROOTS") {
        let mut text = format!(
            "# per-table DefaultHasher roots of the canonical state bytes after\n\
             # import_chainstate of the frozen XPR testnet snapshot\n\
             # chain_id {} head {}\n",
            report.chain_id, report.head_block_num,
        );
        for (name, root) in &roots {
            text.push_str(&format!("{name} {root:016x}\n"));
        }
        std::fs::write(&out, text).expect("write captured import roots");
        eprintln!("captured {} import roots to {out}", roots.len());
        return;
    }

    // Verify mode (the default): every fingerprint must match the frozen
    // reference set, table by table.
    let golden_path =
        std::env::var("PULSEVM_GOLDEN_IMPORT_ROOTS").unwrap_or_else(|_| DEFAULT_GOLDEN.into());
    let golden = parse_golden(&golden_path);
    assert_eq!(
        golden.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        roots.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        "golden table list must match the harness table list"
    );
    let mut failed = Vec::new();
    for ((name, root), (_, want)) in roots.iter().zip(&golden) {
        if root == want {
            eprintln!("PASS {name:<24} {root:016x}");
        } else {
            eprintln!("FAIL {name:<24} arena {root:016x} != golden {want:016x}");
            failed.push(*name);
        }
    }
    assert!(
        failed.is_empty(),
        "import roots diverged from {golden_path} for: {}",
        failed.join(", ")
    );
    eprintln!(
        "all {} import roots matched the frozen reference set (chain {} head {})",
        roots.len(),
        report.chain_id,
        report.head_block_num,
    );
}

// ---------------------------------------------------------------------------
// Fixture-free coverage of the harness itself: the same pipeline over a
// synthetic MiniSnapshot, so CI catches a drifted derivation or serializer
// without the external fixture.
// ---------------------------------------------------------------------------

#[test]
fn mini_snapshot_import_agrees_with_the_source_truth() {
    let mini = MiniSnapshot {
        chain_id: [0xCD; 32],
        head_block_num: 42,
        head_slot: 1_600_000_000,
        head_producer: "protonnz".parse().unwrap(),
        accounts: vec![
            TestAccount {
                name: "alice".parse().unwrap(),
                key: k1_point(2),
            },
            TestAccount {
                name: "bob".parse().unwrap(),
                key: k1_point(3),
            },
        ],
    };
    let bytes = mini.build();
    let snapshot = SnapshotReader::new(&bytes).expect("parse mini snapshot");

    let db = ChainDatabase::new().expect("fresh arena");
    import_chainstate(&db, &snapshot).expect("import mini snapshot");
    let roots = verify_against_source_truth(&db, &snapshot);

    // Two fresh imports fingerprint identically.
    let db2 = ChainDatabase::new().expect("second fresh arena");
    import_chainstate(&db2, &snapshot).expect("second import");
    let roots2: Vec<(&'static str, u64)> = arena_tables(&db2)
        .iter()
        .map(|(name, bytes)| (*name, table_root(bytes)))
        .collect();
    assert_eq!(roots, roots2);

    // The populated tables really are populated (no vacuous pass): both
    // accounts, four permissions, limits and usage.
    let by_name: HashMap<&str, u64> = roots.iter().copied().collect();
    let empty = table_root(&[]);
    for populated in [
        "account",
        "account_metadata",
        "permission",
        "resource_limits",
        "resource_usage",
        "resource_state",
        "dynamic_global_property",
        "global_property",
        "resource_limits_config",
    ] {
        assert_ne!(
            by_name[populated], empty,
            "{populated} should carry state in the mini snapshot"
        );
    }
}
