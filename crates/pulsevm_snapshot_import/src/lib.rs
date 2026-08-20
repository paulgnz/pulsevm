//! State writer for Antelope portable chainstate snapshots.
//!
//! [`pulsevm_snapshot`] decodes a nodeos `create_snapshot` `.bin` into typed
//! rows; this crate writes those rows into the arena-backed chain database.
//! Each section goes through the same canonical byte layout the pure-Rust
//! genesis path uses (`ChainDatabase::hydrate_*`), so an import is idempotent
//! the way genesis hydration is: a row that already exists is left untouched,
//! and re-running an interrupted import completes it.
//!
//! What is written: accounts (+ ABI), account metadata, contract code
//! (sha256-verified against each declared code hash), permissions,
//! permission links, every contract table with its key-value rows and all
//! five secondary-index families, per-account resource limits and usage, the
//! resource-limits state and config singletons, the global property
//! (chain config) and global action sequence, and the unexpired-transaction
//! dedupe set.
//!
//! What is *not* written, because the arena has no corresponding state yet
//! (each is counted in the [`ImportReport`]):
//! - the TAPOS block-summary ring (TAPOS is not enforced upstream),
//! - generated (deferred) transactions (no deferred-tx support upstream),
//! - account RAM corrections,
//! - activated protocol features (no feature-activation framework upstream).
//!
//! Key support: the workspace's consensus crypto is K1-only, so R1 and
//! WebAuthn keys inside imported authorities are dropped (counted and logged
//! per import; see `TODO(crypto)` in [`encode_authority_k1`]). A permission
//! whose keys are all dropped keeps its accounts/waits and simply cannot be
//! satisfied by key until upstream grows R1/WebAuthn support.

use pulsevm_chaindb::{
    ChainConfigParams,
    ChainDatabase,
    ElasticParams,
};
use pulsevm_crypto::Digest;
use pulsevm_snapshot::{
    AccountMetadataRow,
    AccountRow,
    CodeRow,
    DynamicGlobalPropertyRow,
    GlobalPropertyRow,
    PermissionLinkRow,
    PermissionRow,
    ResourceLimitsConfigRow,
    ResourceLimitsRow,
    ResourceLimitsStateRow,
    ResourceUsageRow,
    SnapshotAuthority,
    SnapshotElasticLimitParameters,
    SnapshotError,
    SnapshotPublicKey,
    SnapshotReader,
    TableSnapshot,
    TransactionRow,
    UsageAccumulator,
};
use spdlog::{
    info,
    warn,
};

mod error;
pub use error::ImportError;

/// What one import wrote (and what it had to leave behind).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// The snapshot's chain id — the identity of the source chain.
    pub chain_id: Digest,
    /// The head block the snapshot was taken at, for height continuity.
    pub head_block_num: u32,
    pub head_block_id: Digest,

    pub accounts: u64,
    pub account_metadata: u64,
    /// Code objects written, each verified `sha256(code) == code_hash`.
    pub code_objects: u64,
    pub permissions: PermissionImportStats,
    pub permission_links: u64,
    pub contract_tables: TableImportStats,
    pub resource_limits: u64,
    pub resource_usage: u64,
    /// Unexpired input transactions carried into the dedupe set.
    pub transactions: u64,

    /// Rows counted but not written — arena state that does not exist yet.
    pub block_summaries_skipped: u64,
    pub generated_transactions_skipped: u64,
    pub ram_corrections_skipped: u64,
    pub protocol_features_skipped: u64,
}

/// Permission-section outcome, including the key material that could not be
/// carried (the workspace's consensus crypto is K1-only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermissionImportStats {
    /// Permission rows written (the reserved permission 0 is not one of them).
    pub written: u64,
    /// Reserved rows (owner 0, name 0) recognised and skipped.
    pub reserved_skipped: u64,
    /// K1 keys carried into authority blobs.
    pub k1_keys: u64,
    /// R1 keys dropped — pending upstream R1 support.
    pub r1_keys_skipped: u64,
    /// WebAuthn keys dropped — pending upstream WebAuthn support.
    pub webauthn_keys_skipped: u64,
    /// Permissions that lost at least one key to the K1-only restriction.
    pub permissions_with_dropped_keys: u64,
}

/// Contract-tables-section outcome: the table rows plus every index family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableImportStats {
    pub tables: u64,
    pub key_values: u64,
    pub idx64: u64,
    pub idx128: u64,
    pub idx256: u64,
    pub idx_double: u64,
    pub idx_long_double: u64,
}

/// Imports a parsed snapshot's full chainstate into `db`. Sections are written
/// in dependency order (tables before their rows, accounts before the
/// resources that reference them); every row list is drained through the
/// snapshot reader's byte-exact section verification.
pub fn import_chainstate(
    db: &ChainDatabase,
    snapshot: &SnapshotReader,
) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport::default();

    let head = snapshot.block_header_state()?;
    report.head_block_num = head.block_num;
    report.head_block_id = head.id;

    let gpo = snapshot.global_property()?;
    report.chain_id = gpo.chain_id;
    import_global_property(db, &gpo)?;
    import_dynamic_global_property(db, &snapshot.dynamic_global_property()?)?;
    import_resource_limits_config(db, &snapshot.resource_limits_config()?)?;
    import_resource_limits_state(db, &snapshot.resource_limits_state()?)?;

    report.accounts = import_accounts(db, snapshot.accounts()?)?;
    report.account_metadata = import_account_metadata(db, snapshot.account_metadata()?)?;
    report.code_objects = import_code(db, snapshot.code()?)?;
    report.permissions = import_permissions(db, snapshot.permissions()?)?;
    report.permission_links = import_permission_links(db, snapshot.permission_links()?)?;
    report.contract_tables = import_contract_tables(db, snapshot.contract_tables()?)?;
    report.resource_limits = import_resource_limits(db, snapshot.resource_limits()?)?;
    report.resource_usage = import_resource_usage(db, snapshot.resource_usage()?)?;
    report.transactions = import_transactions(db, snapshot.transactions()?)?;

    // Sections the arena has no state for yet: count them so nothing is
    // silently lost, and verify their decode (the iterators are byte-exact).
    report.block_summaries_skipped = count_rows(snapshot.block_summaries()?)?;
    report.generated_transactions_skipped = count_rows(snapshot.generated_transactions()?)?;
    report.ram_corrections_skipped = count_rows(snapshot.account_ram_corrections()?)?;
    report.protocol_features_skipped =
        snapshot.protocol_state()?.activated_protocol_features.len() as u64;

    info!(
        "snapshot import complete: chain {} head {} — {} accounts, {} permissions ({} K1 keys kept, {} R1 + {} WebAuthn dropped), {} code objects, {} tables / {} kv rows, {} links, {} dedupe txs",
        report.chain_id,
        report.head_block_num,
        report.accounts,
        report.permissions.written,
        report.permissions.k1_keys,
        report.permissions.r1_keys_skipped,
        report.permissions.webauthn_keys_skipped,
        report.code_objects,
        report.contract_tables.tables,
        report.contract_tables.key_values,
        report.permission_links,
        report.transactions,
    );
    Ok(report)
}

/// Writes the global property (chain config) singleton. The snapshot's
/// `deferred_trx_expiration_window` and `max_action_return_value_size` are not
/// tracked by the arena's `chain_config` and are dropped, exactly as the
/// `setparams` path drops them.
pub fn import_global_property(
    db: &ChainDatabase,
    gpo: &GlobalPropertyRow,
) -> Result<(), ImportError> {
    let c = &gpo.configuration.base;
    db.set_global_properties(ChainConfigParams {
        max_block_net_usage: c.max_block_net_usage,
        target_block_net_usage_pct: c.target_block_net_usage_pct,
        max_transaction_net_usage: c.max_transaction_net_usage,
        base_per_transaction_net_usage: c.base_per_transaction_net_usage,
        net_usage_leeway: c.net_usage_leeway,
        context_free_discount_net_usage_num: c.context_free_discount_net_usage_num,
        context_free_discount_net_usage_den: c.context_free_discount_net_usage_den,
        max_block_cpu_usage: c.max_block_cpu_usage,
        target_block_cpu_usage_pct: c.target_block_cpu_usage_pct,
        max_transaction_cpu_usage: c.max_transaction_cpu_usage,
        min_transaction_cpu_usage: c.min_transaction_cpu_usage,
        max_transaction_lifetime: c.max_transaction_lifetime,
        max_transaction_delay: c.max_transaction_delay,
        max_inline_action_size: c.max_inline_action_size,
        max_inline_action_depth: c.max_inline_action_depth,
        max_authority_depth: c.max_authority_depth,
    })?;
    Ok(())
}

/// Writes the global action sequence singleton.
pub fn import_dynamic_global_property(
    db: &ChainDatabase,
    row: &DynamicGlobalPropertyRow,
) -> Result<(), ImportError> {
    db.set_global_action_sequence(row.global_action_sequence)?;
    Ok(())
}

/// Seeds the resource-limits config singleton (elastic cpu/net parameters and
/// the account usage averaging windows) from the snapshot's committed config.
pub fn import_resource_limits_config(
    db: &ChainDatabase,
    row: &ResourceLimitsConfigRow,
) -> Result<(), ImportError> {
    db.seed_resource_config(
        elastic_params(&row.cpu_limit_parameters),
        elastic_params(&row.net_limit_parameters),
        row.account_cpu_usage_average_window,
        row.account_net_usage_average_window,
    )?;
    Ok(())
}

/// Seeds the resource-limits state singleton: block-usage averages, pending
/// usage, total weights and the elastic virtual limits.
pub fn import_resource_limits_state(
    db: &ChainDatabase,
    row: &ResourceLimitsStateRow,
) -> Result<(), ImportError> {
    let mut bytes = Vec::with_capacity(96);
    put_acc(&mut bytes, &row.average_block_net_usage);
    put_acc(&mut bytes, &row.average_block_cpu_usage);
    for v in [
        row.pending_net_usage,
        row.pending_cpu_usage,
        row.total_net_weight,
        row.total_cpu_weight,
        row.total_ram_bytes,
        row.virtual_net_limit,
        row.virtual_cpu_limit,
    ] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    db.hydrate_resource_state(&bytes)?;
    Ok(())
}

/// Writes `account_object` rows (name, creation date, ABI). Returns the row
/// count.
pub fn import_accounts(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<AccountRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        bytes.extend_from_slice(&row.name.as_u64().to_le_bytes());
        bytes.extend_from_slice(&row.creation_date.slot().to_le_bytes());
        bytes.extend_from_slice(&(row.abi.0.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&row.abi.0);
        count += 1;
    }
    db.hydrate_accounts(&bytes)?;
    Ok(count)
}

/// Writes `account_metadata_object` rows, then restores each row's
/// `last_code_update` (the canonical hydrate layout does not carry it).
/// Returns the row count.
pub fn import_account_metadata(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<AccountMetadataRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut code_updates = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        bytes.extend_from_slice(&row.name.as_u64().to_le_bytes());
        bytes.push(row.is_privileged() as u8);
        bytes.extend_from_slice(&row.recv_sequence.to_le_bytes());
        bytes.extend_from_slice(&row.auth_sequence.to_le_bytes());
        bytes.extend_from_slice(&row.code_sequence.to_le_bytes());
        bytes.extend_from_slice(&row.abi_sequence.to_le_bytes());
        bytes.extend_from_slice(&row.code_hash.0);
        bytes.push(row.vm_type);
        bytes.extend_from_slice(&[row.vm_version]);
        let last_code_update = row.last_code_update.time_since_epoch().count();
        if last_code_update != 0 {
            code_updates.push((row.name.as_u64(), last_code_update));
        }
        count += 1;
    }
    db.hydrate_account_metadata(&bytes)?;
    for (name, at) in code_updates {
        db.set_account_last_code_update(name, at)?;
    }
    Ok(count)
}

/// Writes deduplicated `code_object` rows, verifying every image hashes to its
/// declared code hash before it is written. Returns the row count.
pub fn import_code(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<CodeRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        let computed = Digest::hash(&row.code.0);
        if computed != row.code_hash {
            return Err(ImportError::CodeHashMismatch {
                declared: row.code_hash,
                computed,
            });
        }
        bytes.extend_from_slice(&row.code_hash.0);
        bytes.push(row.vm_type);
        bytes.push(row.vm_version);
        bytes.extend_from_slice(&row.code_ref_count.to_le_bytes());
        bytes.extend_from_slice(&row.first_block_used.to_le_bytes());
        bytes.extend_from_slice(&(row.code.0.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&row.code.0);
        count += 1;
    }
    db.hydrate_code(&bytes)?;
    Ok(count)
}

/// Writes `permission_object` rows. The snapshot stores parents by name, so
/// ids are authored here: rows arrive in chainbase id order (parents before
/// children), each non-reserved row takes the next id from 1, and a parent
/// link resolves through the `(owner, parent-name)` pairs already assigned —
/// the same resolution nodeos performs when it restores a snapshot. The
/// hydrate seeds the arena's permission-id counter to `max(id) + 1`.
pub fn import_permissions(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<PermissionRow, SnapshotError>>,
) -> Result<PermissionImportStats, ImportError> {
    let mut stats = PermissionImportStats::default();
    let mut bytes = Vec::new();
    let mut ids = std::collections::HashMap::<(u64, u64), i64>::new();
    let mut next_id = 1i64;
    for row in rows {
        let row = row?;
        let owner = row.owner.as_u64();
        let name = row.name.as_u64();
        if owner == 0 && name == 0 {
            // The reserved permission chainbase creates at id 0.
            stats.reserved_skipped += 1;
            continue;
        }
        let cb_id = next_id;
        next_id += 1;
        ids.insert((owner, name), cb_id);
        let parent = match row.parent.as_u64() {
            0 => 0,
            parent_name => *ids.get(&(owner, parent_name)).ok_or_else(|| {
                ImportError::MissingParentPermission {
                    owner: row.owner.to_string(),
                    name: row.name.to_string(),
                    parent: row.parent.to_string(),
                }
            })?,
        };
        let auth = encode_authority_k1(&row.auth, &mut stats);
        bytes.extend_from_slice(&owner.to_le_bytes());
        bytes.extend_from_slice(&name.to_le_bytes());
        bytes.extend_from_slice(&(cb_id as u64).to_le_bytes());
        bytes.extend_from_slice(&(parent as u64).to_le_bytes());
        bytes.extend_from_slice(&(row.last_used.time_since_epoch().count() as u64).to_le_bytes());
        bytes.extend_from_slice(&(auth.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&auth);
        stats.written += 1;
    }
    db.hydrate_permissions(&bytes)?;
    if stats.r1_keys_skipped + stats.webauthn_keys_skipped > 0 {
        warn!(
            "snapshot import dropped non-K1 key material: {} R1 keys and {} WebAuthn keys across {} permissions (consensus crypto is K1-only)",
            stats.r1_keys_skipped, stats.webauthn_keys_skipped, stats.permissions_with_dropped_keys,
        );
    }
    Ok(stats)
}

/// Writes `permission_link_object` rows (`linkauth` bindings). Returns the row
/// count.
pub fn import_permission_links(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<PermissionLinkRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        for name in [
            row.account,
            row.code,
            row.message_type,
            row.required_permission,
        ] {
            bytes.extend_from_slice(&name.as_u64().to_le_bytes());
        }
        count += 1;
    }
    db.hydrate_permission_links(&bytes)?;
    Ok(count)
}

/// Writes the `contract_tables` section: every `table_id_object` (with the
/// snapshot's child-row count) and all of its key-value and secondary-index
/// rows across the five index families. Takes any [`TableSnapshot`] stream —
/// [`pulsevm_snapshot::ContractTablesReader`] is one.
pub fn import_contract_tables(
    db: &ChainDatabase,
    tables: impl Iterator<Item = Result<TableSnapshot, SnapshotError>>,
) -> Result<TableImportStats, ImportError> {
    let mut stats = TableImportStats::default();
    let mut table_bytes = Vec::new();
    let mut kv = Vec::new();
    let mut idx64 = Vec::new();
    let mut idx128 = Vec::new();
    let mut idx256 = Vec::new();
    let mut idx_double = Vec::new();
    let mut idx_long_double = Vec::new();

    let put_names = |out: &mut Vec<u8>, names: &[u64]| {
        for n in names {
            out.extend_from_slice(&n.to_le_bytes());
        }
    };
    for table in tables {
        let table = table?;
        let t = &table.table;
        let key = [t.code.as_u64(), t.scope.as_u64(), t.table.as_u64()];
        put_names(&mut table_bytes, &key);
        table_bytes.extend_from_slice(&t.payer.as_u64().to_le_bytes());
        table_bytes.extend_from_slice(&t.count.to_le_bytes());
        stats.tables += 1;

        for row in &table.key_values {
            put_names(&mut kv, &key);
            put_names(&mut kv, &[row.primary_key, row.payer.as_u64()]);
            kv.extend_from_slice(&(row.value.0.len() as u32).to_le_bytes());
            kv.extend_from_slice(&row.value.0);
        }
        stats.key_values += table.key_values.len() as u64;

        for row in &table.idx64 {
            put_names(&mut idx64, &key);
            put_names(&mut idx64, &[row.primary_key, row.payer.as_u64()]);
            idx64.extend_from_slice(&row.secondary_key.to_le_bytes());
        }
        stats.idx64 += table.idx64.len() as u64;

        for row in &table.idx128 {
            put_names(&mut idx128, &key);
            put_names(&mut idx128, &[row.primary_key, row.payer.as_u64()]);
            idx128.extend_from_slice(&row.secondary_key.to_le_bytes());
        }
        stats.idx128 += table.idx128.len() as u64;

        for row in &table.idx256 {
            put_names(&mut idx256, &key);
            put_names(&mut idx256, &[row.primary_key, row.payer.as_u64()]);
            idx256.extend_from_slice(&row.secondary_key.0);
        }
        stats.idx256 += table.idx256.len() as u64;

        for row in &table.idx_double {
            put_names(&mut idx_double, &key);
            put_names(&mut idx_double, &[row.primary_key, row.payer.as_u64()]);
            idx_double.extend_from_slice(&row.secondary_key.to_bits().to_le_bytes());
        }
        stats.idx_double += table.idx_double.len() as u64;

        for row in &table.idx_long_double {
            put_names(&mut idx_long_double, &key);
            put_names(&mut idx_long_double, &[row.primary_key, row.payer.as_u64()]);
            idx_long_double.extend_from_slice(&row.secondary_key.to_le_bytes());
        }
        stats.idx_long_double += table.idx_long_double.len() as u64;
    }

    db.hydrate_contract_tables(&table_bytes)?;
    db.hydrate_contract_kv(&kv)?;
    db.hydrate_contract_idx64(&idx64)?;
    db.hydrate_contract_idx128(&idx128)?;
    db.hydrate_contract_idx256(&idx256)?;
    db.hydrate_contract_idx_double(&idx_double)?;
    db.hydrate_contract_idx_long_double(&idx_long_double)?;
    Ok(stats)
}

/// Writes committed per-account resource limits. Returns the row count.
pub fn import_resource_limits(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<ResourceLimitsRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        bytes.push(0); // committed, never pending, in a snapshot
        bytes.extend_from_slice(&row.owner.as_u64().to_le_bytes());
        bytes.extend_from_slice(&(row.ram_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&(row.net_weight as u64).to_le_bytes());
        bytes.extend_from_slice(&(row.cpu_weight as u64).to_le_bytes());
        count += 1;
    }
    db.hydrate_account_limits(&bytes)?;
    Ok(count)
}

/// Writes per-account resource usage (RAM plus the net/cpu averaging
/// accumulators). Returns the row count.
pub fn import_resource_usage(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<ResourceUsageRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        bytes.extend_from_slice(&row.owner.as_u64().to_le_bytes());
        bytes.extend_from_slice(&row.ram_usage.to_le_bytes());
        put_acc(&mut bytes, &row.net_usage);
        put_acc(&mut bytes, &row.cpu_usage);
        count += 1;
    }
    db.hydrate_resource_usage(&bytes)?;
    Ok(count)
}

/// Writes the unexpired-input-transaction dedupe set. Returns the row count.
pub fn import_transactions(
    db: &ChainDatabase,
    rows: impl Iterator<Item = Result<TransactionRow, SnapshotError>>,
) -> Result<u64, ImportError> {
    let mut bytes = Vec::new();
    let mut count = 0u64;
    for row in rows {
        let row = row?;
        bytes.extend_from_slice(&row.trx_id.0);
        bytes.extend_from_slice(&row.expiration.sec_since_epoch().to_le_bytes());
        count += 1;
    }
    db.hydrate_transactions(&bytes)?;
    Ok(count)
}

/// Encodes a snapshot authority in the arena's `shared_authority` blob layout,
/// keeping only K1 keys.
///
/// TODO(crypto): carry R1 and WebAuthn keys once `pulsevm_crypto` grows
/// support for them — until then they are counted into `stats` (and logged by
/// the permission import) rather than silently lost. Accounts and waits are
/// carried in full, so a permission that loses every key remains satisfiable
/// through its account delegations, or not at all — never trivially.
fn encode_authority_k1(auth: &SnapshotAuthority, stats: &mut PermissionImportStats) -> Vec<u8> {
    let k1_keys: Vec<&pulsevm_snapshot::SnapshotKeyWeight> = auth
        .keys
        .iter()
        .filter(|kw| match kw.key {
            SnapshotPublicKey::K1(_) => true,
            SnapshotPublicKey::R1(_) => {
                stats.r1_keys_skipped += 1;
                false
            }
            SnapshotPublicKey::WebAuthn(_) => {
                stats.webauthn_keys_skipped += 1;
                false
            }
        })
        .collect();
    if k1_keys.len() != auth.keys.len() {
        stats.permissions_with_dropped_keys += 1;
    }
    stats.k1_keys += k1_keys.len() as u64;

    let mut out = Vec::new();
    out.extend_from_slice(&auth.threshold.to_le_bytes());
    out.extend_from_slice(&(k1_keys.len() as u32).to_le_bytes());
    for kw in k1_keys {
        let packed = kw.key.to_tagged_point();
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

/// Maps the snapshot's elastic limit parameters onto the arena's.
fn elastic_params(p: &SnapshotElasticLimitParameters) -> ElasticParams {
    ElasticParams {
        target: p.target,
        max: p.max,
        periods: p.periods,
        max_multiplier: p.max_multiplier,
        contract: (p.contract_rate.numerator, p.contract_rate.denominator),
        expand: (p.expand_rate.numerator, p.expand_rate.denominator),
    }
}

/// Serializes a usage accumulator in the canonical order the hydrates read
/// (`value_ex`, `consumed`, `last_ordinal`).
fn put_acc(out: &mut Vec<u8>, acc: &UsageAccumulator) {
    out.extend_from_slice(&acc.value_ex.to_le_bytes());
    out.extend_from_slice(&acc.consumed.to_le_bytes());
    out.extend_from_slice(&acc.last_ordinal.to_le_bytes());
}

/// Drains a row iterator, surfacing any decode error, and returns the count.
fn count_rows<T>(rows: impl Iterator<Item = Result<T, SnapshotError>>) -> Result<u64, ImportError> {
    let mut count = 0u64;
    for row in rows {
        row?;
        count += 1;
    }
    Ok(count)
}
