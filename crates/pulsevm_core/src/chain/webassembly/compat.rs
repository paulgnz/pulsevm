//! Antelope-compatibility aliases. EOSIO CDT-compiled contracts import these
//! exact symbols from `env`; without them the module fails to instantiate at
//! all, even if the functions are never called. Error strings deliberately
//! match Leap's wording ("assertion failure with message: ...") because
//! ecosystem tooling pattern-matches on it.
//!
//! Note: Antelope assert semantics are fail-on-zero (any non-zero condition
//! passes), unlike `pulse_assert` which currently passes only on exactly 1.

use wasmer::{FunctionEnvMut, MemoryView, RuntimeError, WasmPtr};

use crate::chain::wasm_runtime::WasmContext;

/// Sentinel recognized by `WasmRuntime::run` to terminate execution successfully.
pub const PULSE_EXIT_SENTINEL: &str = "__pulse_exit__";

const MAX_ASSERT_MSG_LEN: usize = 64 * 1024;

fn read_cstr(view: &MemoryView, ptr: WasmPtr<u8>) -> Result<String, RuntimeError> {
    let mem_size = view.data_size();
    let mut offset = ptr.offset() as u64;
    let mut bytes: Vec<u8> = Vec::new();
    let mut buf = [0u8; 256];

    while offset < mem_size && bytes.len() < MAX_ASSERT_MSG_LEN {
        let chunk = (mem_size - offset).min(buf.len() as u64) as usize;
        view.read(offset, &mut buf[..chunk])?;
        if let Some(pos) = buf[..chunk].iter().position(|b| *b == 0) {
            bytes.extend_from_slice(&buf[..pos]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&buf[..chunk]);
        offset += chunk as u64;
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `eosio_assert(uint32_t test, const char* msg)` — msg is null-terminated.
pub fn eosio_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    if condition != 0 {
        return Ok(());
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let msg = read_cstr(&view, msg_ptr)?;

    Err(RuntimeError::new(format!(
        "assertion failure with message: {}",
        msg
    )))
}

/// `eosio_assert_message(uint32_t test, const char* msg, uint32_t msg_len)`
pub fn eosio_assert_message(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    if condition != 0 {
        return Ok(());
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let mut bytes = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        msg_ptr.slice(&view, msg_len)?.read_slice(&mut bytes)?;
    }
    let msg = String::from_utf8_lossy(&bytes);

    Err(RuntimeError::new(format!(
        "assertion failure with message: {}",
        msg
    )))
}

/// `eosio_assert_code(uint32_t test, uint64_t code)`
pub fn eosio_assert_code(
    _env: FunctionEnvMut<WasmContext>,
    condition: u32,
    code: u64,
) -> Result<(), RuntimeError> {
    if condition != 0 {
        return Ok(());
    }

    Err(RuntimeError::new(format!(
        "assertion failure with error code: {}",
        code
    )))
}

/// `eosio_exit(int32_t code)` — terminates execution successfully regardless of
/// code, matching Leap. Implemented as a sentinel error unwound through wasmer
/// and converted back to success in `WasmRuntime::run`.
pub fn eosio_exit(_env: FunctionEnvMut<WasmContext>, _code: i32) -> Result<(), RuntimeError> {
    Err(RuntimeError::new(PULSE_EXIT_SENTINEL))
}
