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
use std::str::FromStr;

use pulsevm_error::ChainError;
use pulsevm_ffi::{Database, TableObject};
use pulsevm_name::Name;

#[derive(Debug, Default, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub tables: Vec<TableDump>,
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

#[derive(Debug, Default)]
pub struct ImportStats {
    pub tables: u64,
    pub rows: u64,
    pub idx64: u64,
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
        stats.tables += 1;
    }
    Ok(stats)
}
