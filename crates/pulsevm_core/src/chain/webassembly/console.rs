use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

// TODO: Implement console functions to log output from WASM modules. For now, these functions are no-ops to avoid unnecessary overhead in the current implementation.

// Antelope `prints(const char* cstr)` — a single null-terminated pointer (NOT a
// ptr+len pair; that's `prints_l`). Signature must be (i32)->().
pub fn prints(
    _env: FunctionEnvMut<WasmContext>,
    _msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    Ok(())
}

pub fn prints_l(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    Ok(())
}

#[inline]
pub fn printi(_env: FunctionEnvMut<WasmContext>, _val: i64) {
    // No op
}

#[inline]
pub fn printui(_env: FunctionEnvMut<WasmContext>, _val: u64) {
    // No op
}

#[inline]
pub fn printi128(_env: FunctionEnvMut<WasmContext>, _val: WasmPtr<i128>) {
    // No op
}

#[inline]
pub fn printui128(_env: FunctionEnvMut<WasmContext>, _val: WasmPtr<u128>) {
    // No op
}

#[inline]
pub fn printsf(_env: FunctionEnvMut<WasmContext>, _val: f32) {
    // No op
}

#[inline]
pub fn printdf(_env: FunctionEnvMut<WasmContext>, _val: f64) {
    // No op
}

#[inline]
pub fn printn(_env: FunctionEnvMut<WasmContext>, _val: u64) {
    // No op
}

#[inline]
pub fn printhex(_env: FunctionEnvMut<WasmContext>, _data_ptr: u32, _data_len: u32) {
    // No op
}