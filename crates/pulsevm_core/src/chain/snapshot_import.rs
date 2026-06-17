//! Native snapshot import (Path 4) — bulk-load chainstate directly into chainbase at the
//! genesis window, before the first block is produced. This is the PulseVM analogue of
//! `nodeos --snapshot`: it reuses the same privileged direct-write primitives genesis uses
//! (no resource billing, no undo session), so any contract's tables are present at boot.
//!
//! Phase 0 (this increment): contract tables + rows + the uint64 secondary index — the bulk
//! of chainstate and the highest-risk path to prove (a contract picking up its own tables).
//! Later phases add accounts/permissions/code translation and the native Leap `.bin` reader
//! (see wiki/28). The on-disk format here is a simple JSON intermediate; the Leap `.bin`
//! reader will feed this same apply path.

use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

use pulsevm_error::ChainError;
use pulsevm_ffi::{
    AccountMetadataObject, AccountObject, Authority, CxxDigest, CxxTimePoint, Database, KeyWeight,
    PermissionLevel, PermissionLevelWeight, TableObject, WaitWeight, parse_public_key,
};
use pulsevm_name::Name;

#[derive(Debug, Default, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub accounts: Vec<AccountDump>,
    #[serde(default)]
    pub tables: Vec<TableDump>,
    /// Optional source-chain head, so the migrated chain resumes at the snapshot's
    /// block height + time (like an Antelope snapshot restore) instead of block 1.
    #[serde(default)]
    pub head: Option<HeadDump>,
}

#[derive(Debug, Deserialize)]
pub struct HeadDump {
    pub block_num: u32,
    /// BlockTimestamp slot (500ms since the 2000 epoch) of the source head block.
    pub slot: u32,
}

#[derive(Debug, Deserialize)]
pub struct AccountDump {
    pub name: String,
    #[serde(default)]
    pub creation_date: u32,
    #[serde(default)]
    pub privileged: bool,
    /// packed ABI bytes (hex), optional — needed for table reads to decode to JSON.
    #[serde(default)]
    pub abi_hex: Option<String>,
    /// contract wasm (hex), optional — so the contract EXECUTES on Pulse (transfers, dapp actions).
    #[serde(default)]
    pub code_hex: Option<String>,
    #[serde(default)]
    pub ram: Option<i64>,
    #[serde(default)]
    pub net: Option<i64>,
    #[serde(default)]
    pub cpu: Option<i64>,
    /// actual RAM bytes the account is using (from resource_usage_object). Must be set so contract
    /// RAM rebilling on imported rows doesn't underflow ("Ram usage delta would underflow").
    #[serde(default)]
    pub ram_usage: Option<i64>,
    /// owner/active (and any custom) permissions — so users can log in with their existing keys.
    #[serde(default)]
    pub permissions: Vec<PermDump>,
    /// linkauth bindings (action -> permission) so action-scoping carries over — e.g. fdxten's
    /// 'keeper' perm linked to its automation actions, and eosio governance/staking/voting links.
    #[serde(default)]
    pub permission_links: Vec<PermLinkDump>,
}

#[derive(Debug, Deserialize)]
pub struct PermLinkDump {
    /// contract the action belongs to.
    pub code: String,
    /// action name; "" applies the link to all actions on `code`.
    #[serde(default)]
    pub action: String,
    /// permission required to call the action(s).
    pub requirement: String,
}

#[derive(Debug, Deserialize)]
pub struct PermDump {
    pub perm: String,
    /// parent permission name ("" for owner)
    #[serde(default)]
    pub parent: String,
    #[serde(default = "one")]
    pub threshold: u32,
    #[serde(default)]
    pub keys: Vec<KeyW>,
    #[serde(default)]
    pub accounts: Vec<AcctW>,
    #[serde(default)]
    pub waits: Vec<WaitW>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct KeyW {
    pub key: String,
    #[serde(default = "one16")]
    pub weight: u16,
}

#[derive(Debug, Deserialize)]
pub struct AcctW {
    pub actor: String,
    pub permission: String,
    #[serde(default = "one16")]
    pub weight: u16,
}

#[derive(Debug, Deserialize)]
pub struct WaitW {
    pub wait_sec: u32,
    #[serde(default = "one16")]
    pub weight: u16,
}

fn one16() -> u16 {
    1
}

#[derive(Debug, Deserialize)]
pub struct TableDump {
    pub code: String,
    pub scope: String,
    pub table: String,
    pub payer: String,
    #[serde(default)]
    pub rows: Vec<Row>,
    #[serde(default)]
    pub idx64: Vec<Idx64>,
    #[serde(default)]
    pub idx128: Vec<Idx128>,
    #[serde(default)]
    pub idx_double: Vec<IdxF64>,
}

#[derive(Debug, Deserialize)]
pub struct Row {
    /// primary key (u64). Serde accepts a JSON number or a quoted number.
    #[serde(deserialize_with = "de_u64")]
    pub id: u64,
    /// row value, hex-encoded (the raw fc-serialized struct bytes the contract stores).
    pub value_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct Idx64 {
    #[serde(deserialize_with = "de_u64")]
    pub id: u64,
    #[serde(deserialize_with = "de_u64")]
    pub secondary: u64,
}

#[derive(Debug, Deserialize)]
pub struct Idx128 {
    #[serde(deserialize_with = "de_u64")]
    pub id: u64,
    /// u128 secondary key as a decimal string
    pub secondary: String,
}

#[derive(Debug, Deserialize)]
pub struct IdxF64 {
    #[serde(deserialize_with = "de_u64")]
    pub id: u64,
    pub secondary: f64,
}

#[derive(Debug, Default)]
pub struct ImportStats {
    pub accounts: u64,
    pub permissions: u64,
    pub code: u64,
    pub tables: u64,
    pub rows: u64,
    pub idx64: u64,
    pub idx128: u64,
    pub idx_double: u64,
    pub links: u64,
    /// (block_num, slot) of the source head, if the snapshot carried it.
    pub head: Option<(u32, u32)>,
}

/// Order permissions parent-before-child (owner before active, etc.). Roots (parent "") first,
/// then repeatedly emit any whose parent was already emitted.
fn order_perms(perms: &[PermDump]) -> Vec<&PermDump> {
    let mut out: Vec<&PermDump> = Vec::with_capacity(perms.len());
    let mut placed: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut remaining: Vec<&PermDump> = perms.iter().collect();
    loop {
        let before = remaining.len();
        remaining.retain(|p| {
            if p.parent.is_empty() || placed.contains(p.parent.as_str()) {
                out.push(p);
                placed.insert(p.perm.as_str());
                false
            } else {
                true
            }
        });
        if remaining.is_empty() || remaining.len() == before {
            break;
        }
    }
    // any cycle remainder: emit anyway (parent resolves to 0)
    out.extend(remaining);
    out
}

fn build_authority(p: &PermDump) -> Result<Authority, ChainError> {
    let mut keys = Vec::with_capacity(p.keys.len());
    for k in &p.keys {
        let pk = parse_public_key(&k.key)
            .map_err(|e| ChainError::ParseError(format!("pubkey {}: {}", k.key, e)))?;
        keys.push(KeyWeight {
            key: pk,
            weight: k.weight,
        });
    }
    let mut accounts = Vec::with_capacity(p.accounts.len());
    for a in &p.accounts {
        accounts.push(PermissionLevelWeight {
            permission: PermissionLevel {
                actor: name(&a.actor)?,
                permission: name(&a.permission)?,
            },
            weight: a.weight,
        });
    }
    let waits = p
        .waits
        .iter()
        .map(|w| WaitWeight {
            wait_sec: w.wait_sec,
            weight: w.weight,
        })
        .collect();
    Ok(Authority {
        threshold: p.threshold,
        keys,
        accounts,
        waits,
    })
}

/// Accept either a JSON integer or a quoted integer for u64 fields (JSON can't always carry
/// full-width u64 safely as a number, and name-derived primary keys are large).
fn de_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| D::Error::custom("not a u64")),
        serde_json::Value::String(s) => s.parse::<u64>().map_err(D::Error::custom),
        _ => Err(D::Error::custom("expected u64 number or string")),
    }
}

fn name(s: &str) -> Result<u64, ChainError> {
    Ok(Name::from_str(s)?.as_u64())
}

/// Apply a JSON snapshot file to the freshly-initialized database. Must be called inside the
/// genesis window (revision still 0, indices added, no undo session) — same context as
/// `initialize_database`.
pub fn apply_snapshot_file(db: &mut Database, path: &str) -> Result<ImportStats, ChainError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| ChainError::InternalError(format!("snapshot read {}: {}", path, e)))?;
    let snap: Snapshot = serde_json::from_str(&data)
        .map_err(|e| ChainError::ParseError(format!("snapshot parse: {}", e)))?;
    apply_snapshot(db, &snap)
}

pub fn apply_snapshot(db: &mut Database, snap: &Snapshot) -> Result<ImportStats, ChainError> {
    let mut stats = ImportStats::default();
    stats.head = snap.head.as_ref().map(|h| (h.block_num, h.slot));

    // Accounts first — the contract account must exist before its tables can be served (the
    // table-read RPCs look up the code account's ABI). create_account/_metadata are the same
    // privileged primitives genesis uses.
    for a in &snap.accounts {
        let acct = name(&a.name)?;
        if !db.find_account(acct)?.is_null() {
            continue; // already exists (e.g. a genesis account)
        }
        let aptr = db.create_account(acct, a.creation_date)?;
        let mptr = db.create_account_metadata(acct, a.privileged)?;
        // Every account needs its resource_limits/usage rows (genesis does this in
        // create_native_account) before set_account_limits can modify them.
        db.initialize_account_resource_limits(acct)?;
        // Set the account's real RAM usage so contract RAM rebilling on imported rows doesn't
        // underflow. add_pending_ram_usage adds to the (zeroed) baseline from initialize above.
        if let Some(ru) = a.ram_usage {
            if ru > 0 {
                db.add_pending_ram_usage(acct, ru)?;
            }
        }
        // SAFETY: chainbase objects live in stable mmap; refs valid across subsequent calls.
        let aref: &AccountObject = unsafe { &*aptr };
        let mref: &AccountMetadataObject = unsafe { &*mptr };
        let t = CxxTimePoint::new((a.creation_date as i64) * 1_000_000);
        let tref: &CxxTimePoint = t.as_ref().expect("CxxTimePoint::new non-null");
        // contract code (wasm) — so the contract executes on Pulse (mirrors setcode)
        if let Some(code_hex) = &a.code_hex {
            let code = hex::decode(code_hex)
                .map_err(|e| ChainError::ParseError(format!("account {} code_hex: {}", a.name, e)))?;
            if !code.is_empty() {
                let code_hash = CxxDigest::hash(&code)?;
                db.update_account_code(
                    mref,
                    &code,
                    0,
                    tref,
                    code_hash.as_ref().expect("code hash"),
                    0,
                    0,
                )?;
                stats.code += 1;
            }
        }
        if let Some(abi_hex) = &a.abi_hex {
            let abi = hex::decode(abi_hex)
                .map_err(|e| ChainError::ParseError(format!("account {} abi_hex: {}", a.name, e)))?;
            db.update_account_abi(aref, mref, &abi)?;
        }
        if a.ram.is_some() || a.net.is_some() || a.cpu.is_some() {
            db.set_account_limits(
                acct,
                a.ram.unwrap_or(-1),
                a.net.unwrap_or(-1),
                a.cpu.unwrap_or(-1),
            )?;
        }
        // Permissions (owner/active/custom) — so the account's real keys carry over and the
        // user can log in + sign on Pulse exactly as on XPR. Created parent-before-child.
        if !a.permissions.is_empty() {
            let mut ids: HashMap<&str, u64> = HashMap::new();
            for p in order_perms(&a.permissions) {
                let parent_id = if p.parent.is_empty() {
                    0
                } else {
                    *ids.get(p.parent.as_str()).unwrap_or(&0)
                };
                let auth = build_authority(p)?;
                let pptr = db.create_permission(acct, name(&p.perm)?, parent_id, &auth, tref)?;
                // SAFETY: stable mmap object; read id immediately.
                let pid = unsafe { &*pptr }.get_id() as u64;
                ids.insert(p.perm.as_str(), pid);
                stats.permissions += 1;
            }
        }
        stats.accounts += 1;
    }
    // flush any pending resource-limit updates so totals/state are consistent
    if stats.accounts > 0 {
        db.process_account_limit_updates()?;
    }

    // 1:1 migration: the elastic virtual block CPU/NET limits are runtime accumulators not
    // carried in the snapshot — genesis starts them at the "congested" floor (= per-block max),
    // ~1000x below the source chain's long-expanded ceiling. Without this, every imported
    // account sees ~1000x less CPU/NET until the chain slowly ramps (e.g. fdxdg3 31ms vs the
    // source's 862ms). Seed the virtual limits to the elastic ceiling (max * max_multiplier)
    // so accounts have source-equivalent resources from block 1; the model contracts under
    // real load thereafter. Derived from chain config — no snapshot field needed.
    db.seed_virtual_block_limits_to_ceiling()?;

    // Replay permission_links (linkauth) so action->permission scoping carries over — e.g.
    // fdxten's 'keeper' perm bound to its automation actions, plus eosio governance/staking/
    // voting links. Done after all accounts + permissions exist (a link references this account's
    // permission and a code account). Tolerant: a link whose perm/code is absent is logged and
    // skipped rather than aborting the whole import.
    for a in &snap.accounts {
        for l in &a.permission_links {
            match db.link_auth(name(&a.name)?, name(&l.code)?, name(&l.requirement)?, name(&l.action)?) {
                Ok(_) => stats.links += 1,
                Err(e) => eprintln!(
                    "snapshot import: permission_link {}::{} -> {} for {} skipped: {}",
                    l.code, l.action, l.requirement, a.name, e
                ),
            }
        }
    }

    for t in &snap.tables {
        let code = name(&t.code)?;
        let scope = name(&t.scope)?;
        let table = name(&t.table)?;
        let payer = name(&t.payer)?;

        // find-or-create the table_id_object
        let existing = db.find_table(code, scope, table)?;
        let tref: &TableObject = if existing.is_null() {
            let p = db.create_table(code, scope, table, payer)?;
            // SAFETY: chainbase objects live in a stable mmap region; the pointer remains
            // valid across subsequent create_* calls (same pattern as apply_context).
            unsafe { &*p }
        } else {
            unsafe { &*existing }
        };

        for r in &t.rows {
            let bytes = hex::decode(&r.value_hex)
                .map_err(|e| ChainError::ParseError(format!("row {} value_hex: {}", r.id, e)))?;
            db.create_key_value_object(tref, payer, r.id, &bytes)?;
            stats.rows += 1;
        }
        for i in &t.idx64 {
            db.create_index64_object(tref, payer, i.id, i.secondary)?;
            stats.idx64 += 1;
        }
        for i in &t.idx128 {
            let sec: u128 = i
                .secondary
                .parse()
                .map_err(|e| ChainError::ParseError(format!("idx128 secondary {}: {}", i.secondary, e)))?;
            db.create_index128_object(tref, payer, i.id, sec)?;
            stats.idx128 += 1;
        }
        for i in &t.idx_double {
            db.create_index_double_object(tref, payer, i.id, i.secondary)?;
            stats.idx_double += 1;
        }
        stats.tables += 1;
    }
    Ok(stats)
}
