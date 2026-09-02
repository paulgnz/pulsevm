//! Count imported code blobs whose CODE section contains bulk-memory ops (0xFC 0x0A memory.copy / 0xFC 0x0B memory.fill).
//! Minimal wasm section walk: only the code section (id 10) is scanned, so data segments cannot produce false hits.
use pulsevm_snapshot::SnapshotReader;
fn leb(b: &[u8], p: &mut usize) -> u64 { let (mut r, mut s) = (0u64, 0); loop { let x = b[*p]; *p += 1; r |= ((x & 0x7f) as u64) << s; if x & 0x80 == 0 { return r } s += 7; } }
fn code_section(w: &[u8]) -> Option<&[u8]> {
    if w.len() < 8 || &w[0..4] != b"\0asm" { return None }
    let mut p = 8;
    while p < w.len() { let id = w[p]; p += 1; let len = leb(w, &mut p) as usize; if p + len > w.len() { return None } if id == 10 { return Some(&w[p..p + len]) } p += len; }
    None
}
fn main() {
    let path = std::env::args().nth(1).expect("snapshot");
    let bytes = std::fs::read(&path).expect("read");
    let snap = SnapshotReader::new(&bytes).expect("parse");
    let (mut total, mut parsed, mut copy, mut fill, mut either) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for r in snap.code().unwrap() {
        let c = r.unwrap(); total += 1;
        let Some(code) = code_section(c.code.as_ref()) else { continue }; parsed += 1;
        let has_copy = code.windows(2).any(|p| p == [0xfc, 0x0a]);
        let has_fill = code.windows(2).any(|p| p == [0xfc, 0x0b]);
        if has_copy { copy += 1 } if has_fill { fill += 1 } if has_copy || has_fill { either += 1 }
    }
    println!("code blobs={total} parsed={parsed} with_memory_copy={copy} with_memory_fill={fill} with_either={either}");
}
