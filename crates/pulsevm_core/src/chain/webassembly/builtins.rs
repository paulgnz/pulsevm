use pulsevm_builtins::floatuntidf;
use pulsevm_builtins::softfloat as sf;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

// ---------------------------------------------------------------------------
// 128-bit long double (IEEE-754 binary128) soft-float intrinsics.
// Antelope CDT contracts import these compiler-rt `__*tf*` builtins from `env`.
// binary128 operands/results are passed via memory pointers (wasm32 ABI); we
// read/write the 16-byte little-endian value and delegate the math to
// pulsevm_builtins::softfloat (rustc_apfloat — exact IEEE-754, deterministic).
// ---------------------------------------------------------------------------

macro_rules! mem_view {
    ($env:expr, $store:ident, $view:ident) => {
        let (env_data, $store) = $env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let $view = memory.view(&$store);
    };
}
#[inline]
fn rd128(view: &wasmer::MemoryView, ptr: WasmPtr<u8>) -> Result<u128, RuntimeError> {
    let mut b = [0u8; 16];
    view.read(ptr.offset() as u64, &mut b)?;
    Ok(u128::from_le_bytes(b))
}

pub fn __extendsftf2(
    mut env: FunctionEnvMut<WasmContext>,
    ret: WasmPtr<u8>,
    a: f32,
) -> Result<(), RuntimeError> {
    let r = sf::extendsftf2(a);
    mem_view!(env, store, view);
    view.write(ret.offset() as u64, &r.to_le_bytes())?;
    Ok(())
}
pub fn __extenddftf2(
    mut env: FunctionEnvMut<WasmContext>,
    ret: WasmPtr<u8>,
    a: f64,
) -> Result<(), RuntimeError> {
    let r = sf::extenddftf2(a);
    mem_view!(env, store, view);
    view.write(ret.offset() as u64, &r.to_le_bytes())?;
    Ok(())
}
pub fn __trunctfdf2(
    mut env: FunctionEnvMut<WasmContext>,
    a: WasmPtr<u8>,
) -> Result<f64, RuntimeError> {
    mem_view!(env, store, view);
    Ok(sf::trunctfdf2(rd128(&view, a)?))
}
pub fn __trunctfsf2(
    mut env: FunctionEnvMut<WasmContext>,
    a: WasmPtr<u8>,
) -> Result<f32, RuntimeError> {
    mem_view!(env, store, view);
    Ok(sf::trunctfsf2(rd128(&view, a)?))
}
macro_rules! tf_binop {
    ($name:ident, $f:path) => {
        pub fn $name(
            mut env: FunctionEnvMut<WasmContext>,
            ret: WasmPtr<u8>,
            a: WasmPtr<u8>,
            b: WasmPtr<u8>,
        ) -> Result<(), RuntimeError> {
            mem_view!(env, store, view);
            let r = $f(rd128(&view, a)?, rd128(&view, b)?);
            view.write(ret.offset() as u64, &r.to_le_bytes())?;
            Ok(())
        }
    };
}
tf_binop!(__addtf3, sf::addtf3);
tf_binop!(__subtf3, sf::subtf3);
tf_binop!(__multf3, sf::multf3);
tf_binop!(__divtf3, sf::divtf3);

pub fn __fixtfsi(
    mut env: FunctionEnvMut<WasmContext>,
    a: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    mem_view!(env, store, view);
    Ok(sf::fixtfsi(rd128(&view, a)?))
}
pub fn __fixunstfsi(
    mut env: FunctionEnvMut<WasmContext>,
    a: WasmPtr<u8>,
) -> Result<u32, RuntimeError> {
    mem_view!(env, store, view);
    Ok(sf::fixunstfsi(rd128(&view, a)?))
}
pub fn __floatsitf(
    mut env: FunctionEnvMut<WasmContext>,
    ret: WasmPtr<u8>,
    a: i32,
) -> Result<(), RuntimeError> {
    let r = sf::floatsitf(a);
    mem_view!(env, store, view);
    view.write(ret.offset() as u64, &r.to_le_bytes())?;
    Ok(())
}
pub fn __floatunsitf(
    mut env: FunctionEnvMut<WasmContext>,
    ret: WasmPtr<u8>,
    a: u32,
) -> Result<(), RuntimeError> {
    let r = sf::floatunsitf(a);
    mem_view!(env, store, view);
    view.write(ret.offset() as u64, &r.to_le_bytes())?;
    Ok(())
}
macro_rules! tf_cmp {
    ($name:ident, $f:path) => {
        pub fn $name(
            mut env: FunctionEnvMut<WasmContext>,
            a: WasmPtr<u8>,
            b: WasmPtr<u8>,
        ) -> Result<i32, RuntimeError> {
            mem_view!(env, store, view);
            Ok($f(rd128(&view, a)?, rd128(&view, b)?))
        }
    };
}
tf_cmp!(__eqtf2, sf::eqtf2);
tf_cmp!(__netf2, sf::netf2);
tf_cmp!(__getf2, sf::getf2);
tf_cmp!(__letf2, sf::letf2);
tf_cmp!(__unordtf2, sf::unordtf2);

pub fn __ashlti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // fc::uint128::operator<<= explicitly defines shift >= 128 as zero —
    // NOT shift-masking like __ashrti3. checked_shl returns None at >= 128.
    let result = value.checked_shl(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __ashrti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    // Reassemble the i128: high word shifted up, low word OR'd in,
    // then *signed* shift right ("retain the signedness")
    let value = (((high as u128) << 64) | (low as u128)) as i128;

    // wrapping_shr masks the shift amount to & 127, matching what x86-64
    // codegen of the C++ does for shift >= 128 (hardware shifts mask cl,
    // branch tests bit 6) — see note below
    let result = value.wrapping_shr(shift);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // legacy_ptr<__int128>: 16-byte write, bounds-checked, no alignment requirement
    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __lshlti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // Same fc::uint128 semantics as __ashlti3: shift >= 128 is defined as zero
    let result = value.checked_shl(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __lshrti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // Logical (zero-filling) right shift in u128, through the fc::uint128
    // path: operator>>= explicitly defines shift >= 128 as zero
    let result = value.checked_shr(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __divti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    if rhs == 0 {
        // EOS_ASSERT(..., arithmetic_exception, "divide by zero") —
        // a host-side error aborting the action, not a WASM trap
        return Err(RuntimeError::new("divide by zero"));
    }

    // i128::MIN / -1 must wrap to i128::MIN, matching compiler-rt's
    // sign-and-unsigned-divide implementation; a bare `/` would panic
    let result = lhs.wrapping_div(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __udivti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = ((ha as u128) << 64) | (la as u128);
    let rhs = ((hb as u128) << 64) | (lb as u128);

    if rhs == 0 {
        // arithmetic_exception, same classification as __divti3
        return Err(RuntimeError::new("divide by zero"));
    }

    // Unsigned: no MIN/-1 overflow case exists, plain division is total
    let result = lhs / rhs;

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __multi3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    // No assert in nodeos, and overflow truncates to the low 128 bits —
    // compiler-rt's __multi3 is a wrapping word multiply. Bare `*` would
    // panic in debug builds on overflow.
    let result = lhs.wrapping_mul(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __modti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    if rhs == 0 {
        // arithmetic_exception, same as the division pair
        return Err(RuntimeError::new("divide by zero"));
    }

    // i128::MIN % -1 must yield 0 without panicking (the lone overflow case)
    let result = lhs.wrapping_rem(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __umodti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = ((ha as u128) << 64) | (la as u128);
    let rhs = ((hb as u128) << 64) | (lb as u128);

    if rhs == 0 {
        return Err(RuntimeError::new("divide by zero"));
    }

    // Unsigned remainder is total once the divisor is nonzero — no
    // overflow case, bare % cannot panic
    let result = lhs % rhs;

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __floatuntidf(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f64, RuntimeError> {
    Ok(floatuntidf(((ha as u128) << 64) | (la as u128)))
}