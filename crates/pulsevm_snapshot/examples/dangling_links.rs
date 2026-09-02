//! Count permission links whose target permission or code account does not exist
//! (the state PR #75 wants to prevent). Usage: dangling_links <snapshot.bin>
use std::collections::HashSet;
use pulsevm_snapshot::SnapshotReader;
fn main() {
    let path = std::env::args().nth(1).expect("snapshot path");
    let bytes = std::fs::read(&path).expect("read");
    let snap = SnapshotReader::new(&bytes).expect("parse");
    let accounts: HashSet<u64> = snap.accounts().unwrap().map(|r| r.unwrap().name.as_u64()).collect();
    let perms: HashSet<(u64, u64)> = snap.permissions().unwrap().map(|r| { let r = r.unwrap(); (r.owner.as_u64(), r.name.as_u64()) }).collect();
    let (mut total, mut missing_perm, mut missing_code, mut any_links) = (0u64, 0u64, 0u64, 0u64);
    let mut examples = Vec::new();
    for r in snap.permission_links().unwrap() {
        let l = r.unwrap(); total += 1;
        let req = l.required_permission.to_string();
        if req == "eosio.any" { any_links += 1; continue; }
        let perm_ok = perms.contains(&(l.account.as_u64(), l.required_permission.as_u64()));
        let code_ok = accounts.contains(&l.code.as_u64());
        if !perm_ok { missing_perm += 1; if examples.len() < 12 { examples.push(format!("{}@{} -> {}::{} (permission missing)", l.account, req, l.code, l.message_type)); } }
        if !code_ok { missing_code += 1; if examples.len() < 12 { examples.push(format!("{}@{} -> {}::{} (code account missing)", l.account, req, l.code, l.message_type)); } }
    }
    println!("links={total} to_eosio_any={any_links} dangling_permission={missing_perm} dangling_code_account={missing_code}");
    for e in examples { println!("  {e}"); }
}
