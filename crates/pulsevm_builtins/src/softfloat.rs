//! 128-bit long double (IEEE-754 binary128) soft-float builtins — the compiler-rt `__*tf*`
//! functions that Antelope CDT contracts import from `env`. Implemented with `rustc_apfloat`
//! (pure-Rust, exact IEEE-754) so results are deterministic and match Antelope bit-for-bit,
//! enabling XPR's real contract wasm to run unmodified (true byte-1:1).
//!
//! Values are the raw binary128 bit pattern as `u128` (little-endian in wasm memory).

use core::cmp::Ordering;
use rustc_apfloat::ieee::{Double, Quad, Single};
use rustc_apfloat::{Float, FloatConvert, Round};

#[inline]
fn q(bits: u128) -> Quad {
    Quad::from_bits(bits)
}

// --- extend (smaller float -> binary128) ---
pub fn extendsftf2(a: f32) -> u128 {
    let mut loses = false;
    let r: Quad = Single::from_bits(a.to_bits() as u128).convert(&mut loses).value;
    r.to_bits()
}
pub fn extenddftf2(a: f64) -> u128 {
    let mut loses = false;
    let r: Quad = Double::from_bits(a.to_bits() as u128).convert(&mut loses).value;
    r.to_bits()
}

// --- truncate (binary128 -> smaller float) ---
pub fn trunctfdf2(a: u128) -> f64 {
    let mut loses = false;
    let r: Double = q(a).convert(&mut loses).value;
    f64::from_bits(r.to_bits() as u64)
}
pub fn trunctfsf2(a: u128) -> f32 {
    let mut loses = false;
    let r: Single = q(a).convert(&mut loses).value;
    f32::from_bits(r.to_bits() as u32)
}

// --- arithmetic ---
pub fn addtf3(a: u128, b: u128) -> u128 {
    (q(a) + q(b)).value.to_bits()
}
pub fn subtf3(a: u128, b: u128) -> u128 {
    (q(a) - q(b)).value.to_bits()
}
pub fn multf3(a: u128, b: u128) -> u128 {
    (q(a) * q(b)).value.to_bits()
}
pub fn divtf3(a: u128, b: u128) -> u128 {
    (q(a) / q(b)).value.to_bits()
}

// --- float -> int (truncate toward zero, like compiler-rt __fix*) ---
pub fn fixtfsi(a: u128) -> i32 {
    let mut exact = false;
    q(a).to_i128_r(32, Round::TowardZero, &mut exact).value as i32
}
pub fn fixunstfsi(a: u128) -> u32 {
    let mut exact = false;
    q(a).to_u128_r(32, Round::TowardZero, &mut exact).value as u32
}

// --- int -> binary128 ---
pub fn floatsitf(a: i32) -> u128 {
    Quad::from_i128(a as i128).value.to_bits()
}
pub fn floatunsitf(a: u32) -> u128 {
    Quad::from_u128(a as u128).value.to_bits()
}

// --- comparisons (compiler-rt soft-float compare ABI) ---
fn ord(a: u128, b: u128) -> Option<Ordering> {
    q(a).partial_cmp(&q(b))
}
/// __eqtf2 / __netf2: 0 iff equal, nonzero otherwise (unordered => nonzero).
pub fn eqtf2(a: u128, b: u128) -> i32 {
    if ord(a, b) == Some(Ordering::Equal) { 0 } else { 1 }
}
pub fn netf2(a: u128, b: u128) -> i32 {
    eqtf2(a, b)
}
/// __getf2: <0 if a<b, 0 if a==b, >0 if a>b; unordered => -1.
pub fn getf2(a: u128, b: u128) -> i32 {
    match ord(a, b) {
        Some(Ordering::Less) => -1,
        Some(Ordering::Equal) => 0,
        Some(Ordering::Greater) => 1,
        None => -1,
    }
}
/// __letf2: <0 if a<b, 0 if a==b, >0 if a>b; unordered => 1.
pub fn letf2(a: u128, b: u128) -> i32 {
    match ord(a, b) {
        Some(Ordering::Less) => -1,
        Some(Ordering::Equal) => 0,
        Some(Ordering::Greater) => 1,
        None => 1,
    }
}
/// __unordtf2: nonzero iff either operand is NaN.
pub fn unordtf2(a: u128, b: u128) -> i32 {
    if ord(a, b).is_none() { 1 } else { 0 }
}
