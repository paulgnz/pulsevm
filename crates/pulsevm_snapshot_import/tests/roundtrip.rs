//! Per-section round-trip tests: synthetic snapshot rows go in through the
//! importer, and the arena's canonical `*_state_bytes()` serializers must
//! reproduce the exact bytes the same rows would serialize to. That closes the
//! loop importer → hydrate layout → arena → serializer with no fixture files.

use pulsevm_chain_types::{
    BlockTimestamp,
    Microseconds,
    TimePoint,
    TimePointSec,
};
use pulsevm_chaindb::ChainDatabase;
use pulsevm_crypto::{
    Bytes,
    Digest,
};
use pulsevm_name::Name;
use pulsevm_snapshot::{
    AccountMetadataRow,
    AccountRow,
    ChainSnapshotHeader,
    CodeRow,
    DynamicGlobalPropertyRow,
    GlobalPropertyRow,
    Index64Row,
    Index128Row,
    Index256Row,
    IndexDoubleRow,
    IndexLongDoubleRow,
    KeyValueRow,
    KvDatabaseConfig,
    PermissionLinkRow,
    PermissionRow,
    ProducerAuthoritySchedule,
    ResourceLimitsConfigRow,
    ResourceLimitsRow,
    ResourceLimitsStateRow,
    ResourceUsageRow,
    SnapshotAuthority,
    SnapshotChainConfig,
    SnapshotElasticLimitParameters,
    SnapshotError,
    SnapshotKeyWeight,
    SnapshotPermissionLevelWeight,
    SnapshotPublicKey,
    SnapshotRatio,
    SnapshotWaitWeight,
    TableIdRow,
    TableSnapshot,
    TransactionRow,
    U256Key,
    UsageAccumulator,
    WasmConfig,
    WebAuthnPublicKey,
};
use pulsevm_snapshot_import::{
    ImportError,
    import_account_metadata,
    import_accounts,
    import_code,
    import_contract_tables,
    import_dynamic_global_property,
    import_global_property,
    import_permission_links,
    import_permissions,
    import_resource_limits,
    import_resource_limits_config,
    import_resource_limits_state,
    import_resource_usage,
    import_transactions,
};

fn db() -> ChainDatabase {
    ChainDatabase::new().expect("fresh arena")
}

fn name(s: &str) -> Name {
    s.parse().expect("valid name")
}

fn ok<T>(rows: Vec<T>) -> impl Iterator<Item = Result<T, SnapshotError>> {
    rows.into_iter().map(Ok)
}

fn tp(us: i64) -> TimePoint {
    TimePoint::new(Microseconds::new(us))
}

/// A `chain_snapshot_header` is only needed by the container; row-level tests
/// never touch it, but keep the type linked so the import crate's re-exports
/// stay honest.
#[allow(dead_code)]
fn header() -> ChainSnapshotHeader {
    ChainSnapshotHeader { version: 6 }
}

#[test]
fn accounts_round_trip_and_are_idempotent() {
    let d = db();
    let rows = vec![
        AccountRow {
            name: name("alice"),
            creation_date: BlockTimestamp::new(42),
            abi: Bytes(vec![]),
        },
        AccountRow {
            name: name("eosio"),
            creation_date: BlockTimestamp::new(1),
            abi: Bytes(b"abi!".to_vec()),
        },
    ];
    assert_eq!(import_accounts(&d, ok(rows.clone())).unwrap(), 2);

    // Expected canonical bytes, in name order (alice < eosio in name encoding).
    let mut expected = Vec::new();
    let mut sorted = rows.clone();
    sorted.sort_by_key(|r| r.name.as_u64());
    for r in &sorted {
        expected.extend_from_slice(&r.name.as_u64().to_le_bytes());
        expected.extend_from_slice(&r.creation_date.slot().to_le_bytes());
        expected.extend_from_slice(&(r.abi.0.len() as u32).to_le_bytes());
        expected.extend_from_slice(&r.abi.0);
    }
    assert_eq!(d.account_state_bytes(), expected);
    assert!(d.account_exists(name("alice").as_u64()));
    assert_eq!(
        d.account_abi_bytes(name("eosio").as_u64()).unwrap(),
        b"abi!".to_vec()
    );

    // Re-importing the same rows changes nothing.
    assert_eq!(import_accounts(&d, ok(rows)).unwrap(), 2);
    assert_eq!(d.account_state_bytes(), expected);
}

#[test]
fn account_metadata_round_trips_with_last_code_update() {
    let d = db();
    let code_hash = Digest::hash(b"wasm");
    let rows = vec![
        AccountMetadataRow {
            name: name("eosio"),
            recv_sequence: 7,
            auth_sequence: 8,
            code_sequence: 9,
            abi_sequence: 10,
            code_hash,
            last_code_update: tp(1_234_567),
            flags: 1, // privileged
            vm_type: 0,
            vm_version: 0,
        },
        AccountMetadataRow {
            name: name("alice"),
            recv_sequence: 0,
            auth_sequence: 1,
            code_sequence: 0,
            abi_sequence: 0,
            code_hash: Digest::default(),
            last_code_update: tp(0),
            flags: 0,
            vm_type: 0,
            vm_version: 0,
        },
    ];
    assert_eq!(import_account_metadata(&d, ok(rows.clone())).unwrap(), 2);

    let mut expected = Vec::new();
    let mut sorted = rows;
    sorted.sort_by_key(|r| r.name.as_u64());
    for r in &sorted {
        expected.extend_from_slice(&r.name.as_u64().to_le_bytes());
        expected.push(r.is_privileged() as u8);
        expected.extend_from_slice(&r.recv_sequence.to_le_bytes());
        expected.extend_from_slice(&r.auth_sequence.to_le_bytes());
        expected.extend_from_slice(&r.code_sequence.to_le_bytes());
        expected.extend_from_slice(&r.abi_sequence.to_le_bytes());
        expected.extend_from_slice(&r.code_hash.0);
        expected.push(r.vm_type);
        expected.push(r.vm_version);
    }
    assert_eq!(d.account_metadata_state_bytes(), expected);

    // The metadata accessors see the imported values, including the
    // last_code_update restored after hydration.
    let eosio = d.account_metadata(name("eosio").as_u64()).unwrap();
    assert!(eosio.0, "eosio must be privileged");
    assert_eq!(eosio.5, code_hash.0);
    assert_eq!(
        d.account_last_code_update(name("eosio").as_u64()).unwrap(),
        1_234_567
    );
    assert_eq!(
        d.account_last_code_update(name("alice").as_u64()).unwrap(),
        0
    );
}

#[test]
fn code_round_trips_and_rejects_a_bad_hash() {
    let d = db();
    let wasm = b"\0asm-something".to_vec();
    let good = CodeRow {
        code_hash: Digest::hash(&wasm),
        code: Bytes(wasm.clone()),
        code_ref_count: 3,
        first_block_used: 77,
        vm_type: 0,
        vm_version: 0,
    };
    assert_eq!(import_code(&d, ok(vec![good.clone()])).unwrap(), 1);

    let mut expected = Vec::new();
    expected.extend_from_slice(&good.code_hash.0);
    expected.push(0);
    expected.push(0);
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&77u32.to_le_bytes());
    expected.extend_from_slice(&(wasm.len() as u32).to_le_bytes());
    expected.extend_from_slice(&wasm);
    assert_eq!(d.code_state_bytes(), expected);
    assert_eq!(d.code_by_hash(good.code_hash.0, 0, 0).unwrap(), wasm);

    // A row whose wasm does not hash to its declared hash is rejected before
    // anything is written.
    let bad = CodeRow {
        code_hash: Digest::hash(b"something else"),
        ..good
    };
    let d2 = db();
    assert!(matches!(
        import_code(&d2, ok(vec![bad])),
        Err(ImportError::CodeHashMismatch { .. })
    ));
    assert!(d2.code_state_bytes().is_empty());
}

fn k1_key(byte: u8) -> SnapshotPublicKey {
    SnapshotPublicKey::K1([byte; 33])
}

fn auth(threshold: u32, keys: Vec<SnapshotKeyWeight>) -> SnapshotAuthority {
    SnapshotAuthority {
        threshold,
        keys,
        accounts: vec![],
        waits: vec![],
    }
}

/// The arena `shared_authority` blob for K1-only parts, mirroring the
/// importer's encoding — used to state the expected bytes independently.
fn auth_blob(
    threshold: u32,
    keys: &[([u8; 34], u16)],
    accounts: &[(u64, u64, u16)],
    waits: &[(u32, u16)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&threshold.to_le_bytes());
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for (packed, weight) in keys {
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(packed);
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for (actor, permission, weight) in accounts {
        out.extend_from_slice(&actor.to_le_bytes());
        out.extend_from_slice(&permission.to_le_bytes());
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out.extend_from_slice(&(waits.len() as u32).to_le_bytes());
    for (wait_sec, weight) in waits {
        out.extend_from_slice(&wait_sec.to_le_bytes());
        out.extend_from_slice(&weight.to_le_bytes());
    }
    out
}

#[test]
fn permissions_author_ids_resolve_parents_and_drop_non_k1_keys() {
    let d = db();
    let rows = vec![
        // The reserved permission chainbase creates at id 0.
        PermissionRow {
            parent: Name::default(),
            owner: Name::default(),
            name: Name::default(),
            last_updated: tp(0),
            last_used: tp(0),
            auth: auth(0, vec![]),
        },
        PermissionRow {
            parent: Name::default(),
            owner: name("alice"),
            name: name("owner"),
            last_updated: tp(5),
            last_used: tp(6),
            auth: auth(
                1,
                vec![SnapshotKeyWeight {
                    key: k1_key(2),
                    weight: 1,
                }],
            ),
        },
        PermissionRow {
            parent: name("owner"),
            owner: name("alice"),
            name: name("active"),
            last_updated: tp(7),
            last_used: tp(8),
            auth: SnapshotAuthority {
                threshold: 2,
                keys: vec![
                    SnapshotKeyWeight {
                        key: k1_key(3),
                        weight: 1,
                    },
                    SnapshotKeyWeight {
                        key: SnapshotPublicKey::R1([4; 33]),
                        weight: 1,
                    },
                    SnapshotKeyWeight {
                        key: SnapshotPublicKey::WebAuthn(WebAuthnPublicKey {
                            key: [5; 33],
                            user_presence: 1,
                            rpid: "example.com".into(),
                        }),
                        weight: 1,
                    },
                ],
                accounts: vec![SnapshotPermissionLevelWeight {
                    actor: name("bob"),
                    permission: name("active"),
                    weight: 1,
                }],
                waits: vec![SnapshotWaitWeight {
                    wait_sec: 30,
                    weight: 1,
                }],
            },
        },
        PermissionRow {
            parent: name("active"),
            owner: name("alice"),
            name: name("custom"),
            last_updated: tp(9),
            last_used: tp(10),
            auth: auth(1, vec![]),
        },
    ];
    let stats = import_permissions(&d, ok(rows)).unwrap();
    assert_eq!(stats.written, 3);
    assert_eq!(stats.reserved_skipped, 1);
    assert_eq!(stats.k1_keys, 2);
    assert_eq!(stats.r1_keys_skipped, 1);
    assert_eq!(stats.webauthn_keys_skipped, 1);
    assert_eq!(stats.permissions_with_dropped_keys, 1);

    let alice = name("alice").as_u64();
    // Ids were authored in row order from 1; parents resolve through them.
    assert_eq!(d.permission_cb_id(alice, name("owner").as_u64()), Some(1));
    assert_eq!(d.permission_cb_id(alice, name("active").as_u64()), Some(2));
    assert_eq!(d.permission_cb_id(alice, name("custom").as_u64()), Some(3));
    assert_eq!(d.permission(alice, name("owner").as_u64()), Some((0, 1)));
    assert_eq!(d.permission(alice, name("active").as_u64()), Some((1, 2)));
    assert_eq!(d.permission(alice, name("custom").as_u64()), Some((2, 1)));
    assert_eq!(
        d.permission_last_used(alice, name("active").as_u64()),
        Some(8)
    );

    // The active permission's auth blob: the K1 key kept, R1/WebAuthn dropped,
    // accounts and waits carried in full.
    let expected_active = auth_blob(
        2,
        &[(SnapshotPublicKey::K1([3; 33]).to_tagged_point(), 1)],
        &[(name("bob").as_u64(), name("active").as_u64(), 1)],
        &[(30, 1)],
    );
    assert_eq!(
        d.permission_auth_blob(alice, name("active").as_u64())
            .unwrap(),
        expected_active
    );

    // The id counter continues after the imported ids.
    assert_eq!(d.next_permission_id().unwrap(), 4);

    // A child that references a parent no earlier row defined is an error.
    let orphan = PermissionRow {
        parent: name("ghost"),
        owner: name("carol"),
        name: name("active"),
        last_updated: tp(0),
        last_used: tp(0),
        auth: auth(1, vec![]),
    };
    assert!(matches!(
        import_permissions(&db(), ok(vec![orphan])),
        Err(ImportError::MissingParentPermission { .. })
    ));
}

#[test]
fn permission_links_round_trip() {
    let d = db();
    let rows = vec![
        PermissionLinkRow {
            account: name("alice"),
            code: name("eosio.token"),
            message_type: name("transfer"),
            required_permission: name("spend"),
        },
        PermissionLinkRow {
            account: name("alice"),
            code: name("eosio"),
            message_type: Name::default(),
            required_permission: name("ops"),
        },
    ];
    assert_eq!(import_permission_links(&d, ok(rows.clone())).unwrap(), 2);

    let mut sorted = rows.clone();
    sorted.sort_by_key(|l| (l.account.as_u64(), l.code.as_u64(), l.message_type.as_u64()));
    let mut expected = Vec::new();
    for l in &sorted {
        expected.extend_from_slice(&l.account.as_u64().to_le_bytes());
        expected.extend_from_slice(&l.code.as_u64().to_le_bytes());
        expected.extend_from_slice(&l.message_type.as_u64().to_le_bytes());
        expected.extend_from_slice(&l.required_permission.as_u64().to_le_bytes());
    }
    assert_eq!(d.permission_link_state_bytes(), expected);
    assert_eq!(
        d.permission_link(
            name("alice").as_u64(),
            name("eosio.token").as_u64(),
            name("transfer").as_u64()
        ),
        Some(name("spend").as_u64())
    );

    // Idempotent.
    assert_eq!(import_permission_links(&d, ok(rows)).unwrap(), 2);
    assert_eq!(d.permission_link_state_bytes(), expected);
}

#[test]
fn contract_tables_round_trip_every_index_family() {
    let d = db();
    let code = name("eosio.token");
    let scope = name("alice");
    let payer = name("alice");
    let table = TableSnapshot {
        table: TableIdRow {
            code,
            scope,
            table: name("accounts"),
            payer,
            count: 7, // 2 kv + 1 of each index family
        },
        key_values: vec![
            KeyValueRow {
                primary_key: 5,
                payer,
                value: Bytes(vec![0xBE, 0xEF]),
            },
            KeyValueRow {
                primary_key: 9,
                payer,
                value: Bytes(vec![]),
            },
        ],
        idx64: vec![Index64Row {
            primary_key: 5,
            payer,
            secondary_key: 99,
        }],
        idx128: vec![Index128Row {
            primary_key: 5,
            payer,
            secondary_key: (7u128 << 64) | 3,
        }],
        idx256: vec![Index256Row {
            primary_key: 5,
            payer,
            secondary_key: U256Key([0xAB; 32]),
        }],
        idx_double: vec![IndexDoubleRow {
            primary_key: 5,
            payer,
            secondary_key: 2.5,
        }],
        idx_long_double: vec![IndexLongDoubleRow {
            primary_key: 5,
            payer,
            secondary_key: (11u128 << 64) | 22,
        }],
    };
    let stats = import_contract_tables(&d, ok(vec![table.clone()])).unwrap();
    assert_eq!(stats.tables, 1);
    assert_eq!(stats.key_values, 2);
    assert_eq!((stats.idx64, stats.idx128, stats.idx256), (1, 1, 1));
    assert_eq!((stats.idx_double, stats.idx_long_double), (1, 1));

    let (c, s, t, p) = (
        code.as_u64(),
        scope.as_u64(),
        name("accounts").as_u64(),
        payer.as_u64(),
    );
    let head = |primary: u64| {
        let mut out = Vec::new();
        for v in [c, s, t, primary, p] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    };

    // table_id: identity, payer, and the snapshot's count — kept verbatim.
    let mut expected_tables = Vec::new();
    for v in [c, s, t, p] {
        expected_tables.extend_from_slice(&v.to_le_bytes());
    }
    expected_tables.extend_from_slice(&7u32.to_le_bytes());
    assert_eq!(d.contract_table_state_bytes(), expected_tables);

    // key_value rows.
    let mut expected_kv = head(5);
    expected_kv.extend_from_slice(&2u32.to_le_bytes());
    expected_kv.extend_from_slice(&[0xBE, 0xEF]);
    expected_kv.extend(head(9));
    expected_kv.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(d.contract_kv_state_bytes(), expected_kv);
    assert_eq!(d.kv_get(c, s, t, 5).unwrap(), vec![0xBE, 0xEF]);

    // Every secondary-index family round-trips and is readable.
    let mut expected = head(5);
    expected.extend_from_slice(&99u64.to_le_bytes());
    assert_eq!(d.contract_idx64_state_bytes(), expected);
    assert_eq!(d.idx64_find_primary(c, s, t, 5), Some(99));

    let mut expected = head(5);
    expected.extend_from_slice(&((7u128 << 64) | 3).to_le_bytes());
    assert_eq!(d.contract_idx128_state_bytes(), expected);

    let mut expected = head(5);
    expected.extend_from_slice(&[0xAB; 32]);
    assert_eq!(d.contract_idx256_state_bytes(), expected);

    let mut expected = head(5);
    expected.extend_from_slice(&2.5f64.to_bits().to_le_bytes());
    assert_eq!(d.contract_idx_double_state_bytes(), expected);

    let mut expected = head(5);
    expected.extend_from_slice(&((11u128 << 64) | 22).to_le_bytes());
    assert_eq!(d.contract_idx_long_double_state_bytes(), expected);

    // Idempotent across the whole section.
    let stats2 = import_contract_tables(&d, ok(vec![table])).unwrap();
    assert_eq!(stats2.tables, 1);
    assert_eq!(d.contract_kv_state_bytes(), expected_kv);
    assert_eq!(d.contract_table_state_bytes(), expected_tables);
}

fn acc(value_ex: u64, consumed: u64, last_ordinal: u32) -> UsageAccumulator {
    UsageAccumulator {
        last_ordinal,
        value_ex,
        consumed,
    }
}

fn put_acc(out: &mut Vec<u8>, a: &UsageAccumulator) {
    out.extend_from_slice(&a.value_ex.to_le_bytes());
    out.extend_from_slice(&a.consumed.to_le_bytes());
    out.extend_from_slice(&a.last_ordinal.to_le_bytes());
}

#[test]
fn resources_round_trip() {
    let d = db();
    let alice = name("alice");

    let limits = vec![ResourceLimitsRow {
        owner: alice,
        net_weight: 100,
        cpu_weight: 200,
        ram_bytes: 4096,
    }];
    assert_eq!(import_resource_limits(&d, ok(limits)).unwrap(), 1);
    let mut expected = vec![0u8];
    expected.extend_from_slice(&alice.as_u64().to_le_bytes());
    expected.extend_from_slice(&4096u64.to_le_bytes());
    expected.extend_from_slice(&100u64.to_le_bytes());
    expected.extend_from_slice(&200u64.to_le_bytes());
    assert_eq!(d.account_limits_state_bytes(), expected);
    assert_eq!(d.account_limits(alice.as_u64()), Some((4096, 100, 200)));

    let usage = vec![ResourceUsageRow {
        owner: alice,
        net_usage: acc(11, 12, 13),
        cpu_usage: acc(21, 22, 23),
        ram_usage: 555,
    }];
    assert_eq!(import_resource_usage(&d, ok(usage)).unwrap(), 1);
    let mut expected = Vec::new();
    expected.extend_from_slice(&alice.as_u64().to_le_bytes());
    expected.extend_from_slice(&555u64.to_le_bytes());
    put_acc(&mut expected, &acc(11, 12, 13));
    put_acc(&mut expected, &acc(21, 22, 23));
    assert_eq!(d.resource_usage_state_bytes(), expected);
    assert_eq!(d.account_ram_usage(alice.as_u64()), Some(555));

    let state = ResourceLimitsStateRow {
        average_block_net_usage: acc(1, 2, 3),
        average_block_cpu_usage: acc(4, 5, 6),
        pending_net_usage: 7,
        pending_cpu_usage: 8,
        total_net_weight: 9,
        total_cpu_weight: 10,
        total_ram_bytes: 11,
        virtual_net_limit: 12,
        virtual_cpu_limit: 13,
    };
    import_resource_limits_state(&d, &state, 1).unwrap();
    let mut expected = Vec::new();
    put_acc(&mut expected, &acc(1, 2, 3));
    put_acc(&mut expected, &acc(4, 5, 6));
    for v in [7u64, 8, 9, 10, 11, 12, 13] {
        expected.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(d.resource_state_bytes(), expected);
    assert_eq!(d.state_virtual_limits(), Some((13, 12)));
    assert_eq!(d.state_total_weights(), Some((10, 9)));

    // The state singleton is written once: a second import (e.g. a re-run)
    // does not clobber it.
    let other = ResourceLimitsStateRow {
        virtual_net_limit: 999,
        ..state
    };
    import_resource_limits_state(&d, &other, 1).unwrap();
    assert_eq!(d.state_virtual_limits(), Some((13, 12)));
}

#[test]
fn global_property_config_and_sequence_round_trip() {
    let d = db();
    let base = pulsevm_chain_types::ChainConfigV0 {
        max_block_net_usage: 1048576,
        target_block_net_usage_pct: 1000,
        max_transaction_net_usage: 524288,
        base_per_transaction_net_usage: 12,
        net_usage_leeway: 500,
        context_free_discount_net_usage_num: 20,
        context_free_discount_net_usage_den: 100,
        max_block_cpu_usage: 200000,
        target_block_cpu_usage_pct: 1000,
        max_transaction_cpu_usage: 150000,
        min_transaction_cpu_usage: 100,
        max_transaction_lifetime: 3600,
        deferred_trx_expiration_window: 600,
        max_transaction_delay: 3888000,
        max_inline_action_size: 4096,
        max_inline_action_depth: 4,
        max_authority_depth: 6,
    };
    let gpo = GlobalPropertyRow {
        proposed_schedule_block_num: None,
        proposed_schedule: ProducerAuthoritySchedule {
            version: 0,
            producers: vec![],
        },
        configuration: SnapshotChainConfig {
            base,
            max_action_return_value_size: 256,
        },
        chain_id: Digest::hash(b"a chain"),
        kv_configuration: KvDatabaseConfig {
            max_key_size: 0,
            max_value_size: 0,
            max_iterators: 0,
        },
        wasm_configuration: WasmConfig {
            max_mutable_global_bytes: 1024,
            max_table_elements: 1024,
            max_section_elements: 8192,
            max_linear_memory_init: 65536,
            max_func_local_bytes: 8192,
            max_nested_structures: 1024,
            max_symbol_bytes: 8192,
            max_module_bytes: 20971520,
            max_code_bytes: 20971520,
            max_pages: 528,
            max_call_depth: 251,
        },
    };
    import_global_property(&d, &gpo, 1).unwrap();
    let params = d.chain_config_params().unwrap();
    assert_eq!(params.max_block_cpu_usage, 200000);
    assert_eq!(params.max_transaction_cpu_usage, 150000);
    assert_eq!(params.max_block_net_usage, 1048576);
    assert_eq!(params.max_authority_depth, 6);
    assert_eq!(d.global_property_state_bytes(), params.to_state_bytes());

    import_dynamic_global_property(
        &d,
        &DynamicGlobalPropertyRow {
            global_action_sequence: 987654321,
        },
    )
    .unwrap();
    assert_eq!(d.global_action_sequence(), Some(987654321));

    let elastic = |target: u64, max: u64| SnapshotElasticLimitParameters {
        target,
        max,
        periods: 120,
        max_multiplier: 1000,
        contract_rate: SnapshotRatio {
            numerator: 99,
            denominator: 100,
        },
        expand_rate: SnapshotRatio {
            numerator: 1000,
            denominator: 999,
        },
    };
    import_resource_limits_config(
        &d,
        &ResourceLimitsConfigRow {
            cpu_limit_parameters: elastic(20000, 200000),
            net_limit_parameters: elastic(104857, 1048576),
            account_cpu_usage_average_window: 172800,
            account_net_usage_average_window: 172800,
        },
        1,
    )
    .unwrap();
    let (cpu, net) = d.resource_config_elastic().unwrap();
    assert_eq!((cpu.target, cpu.max), (20000, 200000));
    assert_eq!((net.target, net.max), (104857, 1048576));
    assert_eq!(d.usage_average_windows(), Some((172800, 172800)));
}

#[test]
fn transactions_round_trip() {
    let d = db();
    let rows = vec![
        TransactionRow {
            expiration: TimePointSec::new(1000),
            trx_id: Digest::hash(b"tx-b"),
        },
        TransactionRow {
            expiration: TimePointSec::new(2000),
            trx_id: Digest::hash(b"tx-a"),
        },
    ];
    assert_eq!(import_transactions(&d, ok(rows.clone())).unwrap(), 2);

    let mut sorted = rows.clone();
    sorted.sort_by_key(|t| t.trx_id.0);
    let mut expected = Vec::new();
    for t in &sorted {
        expected.extend_from_slice(&t.trx_id.0);
        expected.extend_from_slice(&t.expiration.sec_since_epoch().to_le_bytes());
    }
    assert_eq!(d.transaction_state_bytes(), expected);
    assert!(d.transaction_exists(Digest::hash(b"tx-a").0));

    // Idempotent.
    assert_eq!(import_transactions(&d, ok(rows)).unwrap(), 2);
    assert_eq!(d.transaction_state_bytes(), expected);
}

/// The cpu_scale conversion (source µs -> metering points) reaches exactly the
/// CPU-denominated consensus config and nothing else. The values are XPR
/// testnet's real ones: imported at scale 1 a transaction gets a 150000-POINT
/// budget (too small to run a transfer); at scale 143 the same config carries
/// the source's semantics in this VM's points.
#[test]
fn cpu_scale_converts_the_cpu_denominated_config_only() {
    let d = db();
    let base = pulsevm_chain_types::ChainConfigV0 {
        max_block_net_usage: 1048576,
        target_block_net_usage_pct: 1000,
        max_transaction_net_usage: 524288,
        base_per_transaction_net_usage: 12,
        net_usage_leeway: 500,
        context_free_discount_net_usage_num: 20,
        context_free_discount_net_usage_den: 100,
        max_block_cpu_usage: 200000,
        target_block_cpu_usage_pct: 1000,
        max_transaction_cpu_usage: 150000,
        min_transaction_cpu_usage: 100,
        max_transaction_lifetime: 3600,
        deferred_trx_expiration_window: 600,
        max_transaction_delay: 3888000,
        max_inline_action_size: 4096,
        max_inline_action_depth: 4,
        max_authority_depth: 6,
    };
    let gpo = GlobalPropertyRow {
        proposed_schedule_block_num: None,
        proposed_schedule: ProducerAuthoritySchedule {
            version: 0,
            producers: vec![],
        },
        configuration: SnapshotChainConfig {
            base,
            max_action_return_value_size: 256,
        },
        chain_id: Digest::hash(b"a chain"),
        kv_configuration: KvDatabaseConfig {
            max_key_size: 0,
            max_value_size: 0,
            max_iterators: 0,
        },
        wasm_configuration: WasmConfig {
            max_mutable_global_bytes: 1024,
            max_table_elements: 1024,
            max_section_elements: 8192,
            max_linear_memory_init: 65536,
            max_func_local_bytes: 8192,
            max_nested_structures: 1024,
            max_symbol_bytes: 8192,
            max_module_bytes: 20971520,
            max_code_bytes: 20971520,
            max_pages: 528,
            max_call_depth: 251,
        },
    };
    import_global_property(&d, &gpo, 143).unwrap();
    let params = d.chain_config_params().unwrap();
    // CPU magnitudes are converted...
    assert_eq!(params.max_block_cpu_usage, 200000 * 143);
    assert_eq!(params.max_transaction_cpu_usage, 150000 * 143);
    assert_eq!(params.min_transaction_cpu_usage, 100 * 143);
    // ...while percentages and NET/byte-denominated fields are untouched.
    assert_eq!(params.target_block_cpu_usage_pct, 1000);
    assert_eq!(params.max_block_net_usage, 1048576);
    assert_eq!(params.max_transaction_net_usage, 524288);
    assert_eq!(params.max_inline_action_size, 4096);

    // Elastic CPU parameters scale; NET parameters do not.
    let elastic = |target: u64, max: u64| SnapshotElasticLimitParameters {
        target,
        max,
        periods: 120,
        max_multiplier: 1000,
        contract_rate: SnapshotRatio {
            numerator: 99,
            denominator: 100,
        },
        expand_rate: SnapshotRatio {
            numerator: 1000,
            denominator: 999,
        },
    };
    import_resource_limits_config(
        &d,
        &ResourceLimitsConfigRow {
            cpu_limit_parameters: elastic(20000, 200000),
            net_limit_parameters: elastic(104857, 1048576),
            account_cpu_usage_average_window: 172800,
            account_net_usage_average_window: 172800,
        },
        143,
    )
    .unwrap();
    let (cpu, net) = d.resource_config_elastic().unwrap();
    assert_eq!((cpu.target, cpu.max), (20000 * 143, 200000 * 143));
    assert_eq!((net.target, net.max), (104857, 1048576));

    // Virtual CPU capacity and pending CPU usage scale; weights, RAM and the
    // NET side do not.
    let state = ResourceLimitsStateRow {
        average_block_net_usage: acc(1, 2, 3),
        average_block_cpu_usage: acc(4, 5, 6),
        pending_net_usage: 7,
        pending_cpu_usage: 8,
        total_net_weight: 9,
        total_cpu_weight: 10,
        total_ram_bytes: 11,
        virtual_net_limit: 12,
        virtual_cpu_limit: 200000000,
    };
    import_resource_limits_state(&d, &state, 143).unwrap();
    assert_eq!(d.state_virtual_limits(), Some((200000000 * 143, 12)));
    assert_eq!(d.state_total_weights(), Some((10, 9)));

    // A u32 config field saturates at its range instead of wrapping.
    assert_eq!(u32::MAX, {
        let d2 = db();
        let mut big = gpo.clone();
        big.configuration.base.max_block_cpu_usage = u32::MAX;
        import_global_property(&d2, &big, 143).unwrap();
        d2.chain_config_params().unwrap().max_block_cpu_usage
    });
}
