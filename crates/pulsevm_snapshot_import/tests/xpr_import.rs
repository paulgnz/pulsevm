//! End-to-end import of the real XPR testnet snapshot (head block 390401414,
//! nodeos 5.0.3, chain snapshot version 6, 176 MB) into a fresh arena — the
//! full chainstate of a production Antelope testnet through the writer.
//!
//! The fixture is too large to commit, so the test is `#[ignore]`d and takes
//! the file from `PULSEVM_SNAPSHOT_BIN`:
//!
//! ```sh
//! PULSEVM_SNAPSHOT_BIN=~/snapshots/latest-snapshot-20260815.bin \
//! cargo test -p pulsevm_snapshot_import --release -- --ignored --nocapture
//! ```
//!
//! The expected counts are the ones the reader's own regression test pinned
//! against the same file; here they must come back out of the arena.

use pulsevm_chaindb::ChainDatabase;
use pulsevm_name::Name;
use pulsevm_snapshot::SnapshotReader;
use pulsevm_snapshot_import::import_chainstate;

const XPR_TESTNET_CHAIN_ID: &str =
    "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

fn name(s: &str) -> u64 {
    s.parse::<Name>().expect("valid name").as_u64()
}

#[test]
#[ignore = "needs the 176MB XPR testnet snapshot fixture (PULSEVM_SNAPSHOT_BIN)"]
fn imports_the_xpr_testnet_snapshot() {
    let path = std::env::var("PULSEVM_SNAPSHOT_BIN")
        .expect("set PULSEVM_SNAPSHOT_BIN to the XPR testnet snapshot .bin");
    let bytes = std::fs::read(&path).expect("read snapshot file");
    let snapshot = SnapshotReader::new(&bytes).expect("parse container");
    let db = ChainDatabase::new().expect("fresh arena");

    let started = std::time::Instant::now();
    let report = import_chainstate(&db, &snapshot).expect("import chainstate");
    println!("import took {:?}", started.elapsed());
    println!("{report:#?}");

    // Source-chain identity and head, for height continuity.
    assert_eq!(report.chain_id.to_string(), XPR_TESTNET_CHAIN_ID);
    assert_eq!(report.head_block_num, 400588707);

    // The counts the reader pinned, now written.
    assert_eq!(report.accounts, 32496);
    assert_eq!(report.account_metadata, 32496);
    assert_eq!(report.code_objects, 633, "each sha256-verified on write");
    assert_eq!(
        report.permissions.written + report.permissions.reserved_skipped,
        65769
    );
    assert_eq!(report.permissions.reserved_skipped, 1);
    assert_eq!(report.permissions.r1_keys_skipped, 6);
    assert_eq!(report.permissions.webauthn_keys_skipped, 1016);
    assert_eq!(report.permissions.k1_keys, 64088);
    assert_eq!(report.permission_links, 862);
    assert_eq!(report.contract_tables.tables, 75327);
    assert_eq!(report.contract_tables.key_values, 822887);
    assert_eq!(report.contract_tables.idx64, 479842);
    assert_eq!(report.contract_tables.idx128, 194369);
    assert_eq!(report.contract_tables.idx256, 457416);
    assert_eq!(report.contract_tables.idx_double, 134);
    assert_eq!(report.contract_tables.idx_long_double, 0);
    assert_eq!(report.resource_limits, 32496);
    assert_eq!(report.resource_usage, 32496);
    assert_eq!(report.transactions, 784);
    assert_eq!(report.block_summaries_skipped, 65536);
    assert_eq!(report.generated_transactions_skipped, 0);
    assert_eq!(report.ram_corrections_skipped, 0);

    // Spot checks straight off the arena — the state the node would serve.
    let eosio = name("eosio");
    let protonnz = name("protonnz");
    assert!(db.account_exists(protonnz));
    assert_eq!(db.account_metadata_privileged(eosio), Some(true));
    assert_eq!(db.account_metadata_privileged(protonnz), Some(false));
    let eosio_meta = db.account_metadata(eosio).expect("eosio metadata");
    assert_ne!(eosio_meta.5, [0u8; 32], "eosio must have code");
    assert!(
        db.code_by_hash(eosio_meta.5, eosio_meta.6, eosio_meta.7)
            .is_some(),
        "eosio's code object must be importable and addressable by hash"
    );
    assert!(
        db.account_last_code_update(eosio).unwrap() > 0,
        "last_code_update must be restored from the snapshot"
    );

    // protonnz's permission tree: active hangs off owner.
    let owner_id = db
        .permission_cb_id(protonnz, name("owner"))
        .expect("protonnz owner permission");
    let (active_parent, active_threshold) = db
        .permission(protonnz, name("active"))
        .expect("protonnz active permission");
    assert_eq!(active_parent, owner_id);
    assert!(active_threshold >= 1);

    // protonnz holds a liquid XPR balance row in eosio.token.
    let balance = db
        .kv_get(name("eosio.token"), protonnz, name("accounts"), {
            // The XPR symbol code as the primary key: "XPR" packed.
            u64::from_le_bytes(*b"XPR\0\0\0\0\0")
        })
        .expect("protonnz XPR balance row");
    assert!(balance.len() >= 16);

    // Resource state carried the elastic limits, not the genesis defaults.
    assert_eq!(db.state_virtual_limits(), Some((200000000, 1048576000)));
    let params = db.chain_config_params().expect("chain config imported");
    assert_eq!(params.max_block_cpu_usage, 200000);
    assert_eq!(params.max_transaction_cpu_usage, 150000);
    assert!(db.account_ram_usage(protonnz).unwrap() > 0);

    // Idempotency at scale: a second full import writes nothing new.
    let again = import_chainstate(&db, &snapshot).expect("re-import");
    assert_eq!(again.accounts, report.accounts);
    assert_eq!(
        db.contract_table_state_bytes().len(),
        75327 * 36,
        "re-import must not duplicate tables"
    );
}
