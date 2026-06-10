use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

#[inline]
pub fn memmove(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    src_ptr: WasmPtr<u8>,
    src_size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    if src_size == 0 {
        return Ok(dest_ptr);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Bounds-check + obtain access guards (no Vec)
    let mut dest_access = dest_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid dest range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memmove: cannot access dest: {e}")))?;

    let src_access = src_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid src range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memmove: cannot access src: {e}")))?;

    let dst: &mut [u8] = dest_access.as_mut();
    let src: &[u8] = src_access.as_ref();

    // memmove semantics: overlap-safe
    unsafe {
        std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), src_size as usize);
    }

    Ok(dest_ptr)
}

#[inline]
pub fn memcpy(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    src_ptr: WasmPtr<u8>,
    src_size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    if src_size == 0 {
        return Ok(dest_ptr);
    }

    // Leap rejects overlapping regions rather than silently behaving like memmove
    let dest_offset = dest_ptr.offset() as i64;
    let src_offset = src_ptr.offset() as i64;
    if (dest_offset - src_offset).abs() < src_size as i64 {
        return Err(RuntimeError::new(
            "memcpy can only accept non-aliasing pointers",
        ));
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut dest_access = dest_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memcpy: invalid dest range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memcpy: cannot access dest: {e}")))?;

    let src_access = src_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memcpy: invalid src range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memcpy: cannot access src: {e}")))?;

    let dst: &mut [u8] = dest_access.as_mut();
    let src: &[u8] = src_access.as_ref();

    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src_size as usize);
    }

    Ok(dest_ptr)
}

#[inline]
pub fn memset(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    value: i32,
    size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    if size == 0 {
        return Ok(dest_ptr);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut dest_access = dest_ptr
        .slice(&view, size)
        .map_err(|e| RuntimeError::new(format!("memset: invalid dest range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memset: cannot access dest: {e}")))?;

    dest_access.as_mut().fill(value as u8);

    Ok(dest_ptr)
}

#[inline]
pub fn memcmp(
    mut env: FunctionEnvMut<WasmContext>,
    lhs_ptr: WasmPtr<u8>,
    rhs_ptr: WasmPtr<u8>,
    size: u32,
) -> Result<i32, RuntimeError> {
    if size == 0 {
        return Ok(0);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let lhs_access = lhs_ptr
        .slice(&view, size)
        .map_err(|e| RuntimeError::new(format!("memcmp: invalid lhs range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memcmp: cannot access lhs: {e}")))?;

    let rhs_access = rhs_ptr
        .slice(&view, size)
        .map_err(|e| RuntimeError::new(format!("memcmp: invalid rhs range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memcmp: cannot access rhs: {e}")))?;

    // Leap normalizes to -1/0/1 rather than returning the byte difference
    match lhs_access.as_ref().cmp(rhs_access.as_ref()) {
        std::cmp::Ordering::Less => Ok(-1),
        std::cmp::Ordering::Equal => Ok(0),
        std::cmp::Ordering::Greater => Ok(1),
    }
}
