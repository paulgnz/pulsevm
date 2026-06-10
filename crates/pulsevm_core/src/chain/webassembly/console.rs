use wasmer::{FunctionEnvMut, MemoryView, RuntimeError, WasmPtr};

use crate::chain::{name::Name, wasm_runtime::WasmContext};

// Caps null-terminated string scans so a missing terminator can't walk all of linear memory.
const MAX_CONSOLE_STR_LEN: usize = 64 * 1024;

fn read_cstr(view: &MemoryView, ptr: WasmPtr<u8>) -> Result<String, RuntimeError> {
    let mem_size = view.data_size();
    let mut offset = ptr.offset() as u64;
    let mut bytes: Vec<u8> = Vec::new();
    let mut buf = [0u8; 256];

    while offset < mem_size && bytes.len() < MAX_CONSOLE_STR_LEN {
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

fn read_bytes(view: &MemoryView, ptr: WasmPtr<u8>, len: u32) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = vec![0u8; len as usize];
    if len > 0 {
        ptr.slice(view, len)?.read_slice(&mut bytes)?;
    }
    Ok(bytes)
}

fn append(env: &FunctionEnvMut<WasmContext>, text: &str) -> Result<(), RuntimeError> {
    env.data()
        .apply_context()
        .console_append(text)
        .map_err(|e| RuntimeError::new(e.to_string()))
}

pub fn prints(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        read_cstr(&view, msg_ptr)?
    };
    append(&env, &text)
}

pub fn prints_l(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        let bytes = read_bytes(&view, msg_ptr, msg_len)?;
        String::from_utf8_lossy(&bytes).into_owned()
    };
    append(&env, &text)
}

pub fn printi(env: FunctionEnvMut<WasmContext>, value: i64) -> Result<(), RuntimeError> {
    append(&env, &value.to_string())
}

pub fn printui(env: FunctionEnvMut<WasmContext>, value: u64) -> Result<(), RuntimeError> {
    append(&env, &value.to_string())
}

pub fn printi128(
    mut env: FunctionEnvMut<WasmContext>,
    value_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        let bytes = read_bytes(&view, value_ptr, 16)?;
        i128::from_le_bytes(bytes.try_into().unwrap()).to_string()
    };
    append(&env, &text)
}

pub fn printui128(
    mut env: FunctionEnvMut<WasmContext>,
    value_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        let bytes = read_bytes(&view, value_ptr, 16)?;
        u128::from_le_bytes(bytes.try_into().unwrap()).to_string()
    };
    append(&env, &text)
}

pub fn printsf(env: FunctionEnvMut<WasmContext>, value: f32) -> Result<(), RuntimeError> {
    append(&env, &value.to_string())
}

pub fn printdf(env: FunctionEnvMut<WasmContext>, value: f64) -> Result<(), RuntimeError> {
    append(&env, &value.to_string())
}

// float128 has no native Rust representation; emit raw bits as hex rather than
// approximating a decimal rendering.
pub fn printqf(
    mut env: FunctionEnvMut<WasmContext>,
    value_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        let bytes = read_bytes(&view, value_ptr, 16)?;
        format!("0x{}", hex::encode(bytes))
    };
    append(&env, &text)
}

pub fn printn(env: FunctionEnvMut<WasmContext>, value: u64) -> Result<(), RuntimeError> {
    append(&env, &Name::new(value).to_string())
}

pub fn printhex(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<(), RuntimeError> {
    let text = {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        let bytes = read_bytes(&view, data_ptr, data_len)?;
        hex::encode(bytes)
    };
    append(&env, &text)
}
