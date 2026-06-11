use std::collections::HashSet;
use std::str::FromStr;

use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{
    chain::{
        authority::{Authority, PermissionLevel},
        authority_checker::AuthorityChecker,
        wasm_runtime::WasmContext,
    },
    crypto::PublicKey,
    name::Name,
};
use pulsevm_serialization::Read;

const MAX_ASSERT_MESSAGE: usize = 1024;

pub fn eosio_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    if condition != 1 {
        if msg_ptr.is_null() {
            return Err(RuntimeError::new(
                "pulse assertion is false with no message",
            ));
        }

        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);

        // The message is a NUL-terminated C string of unknown length. Reading a
        // fixed MAX_ASSERT_MESSAGE window grabs whatever follows the terminator
        // (and traps OOB when the string sits near the end of linear memory), and
        // that trailing garbage then fails strict UTF-8 validation — collapsing
        // every assert to a message-less "pulse assert failed". Clamp the window
        // to the memory bounds, cut at the terminator, and decode lossily.
        let offset = msg_ptr.offset() as u64;
        let mem_size = view.data_size();
        let window = mem_size.saturating_sub(offset).min(MAX_ASSERT_MESSAGE as u64);
        if window == 0 {
            return Err(RuntimeError::new("pulse assert failed"));
        }
        let slice = msg_ptr.slice(&view, window as u32)?;
        let mut src_bytes = vec![0u8; window as usize];
        slice.read_slice(&mut src_bytes)?;
        let len = src_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(src_bytes.len());
        let msg = String::from_utf8_lossy(&src_bytes[..len]);

        return Err(RuntimeError::new(format!("pulse assert failed: {}", msg)));
    }

    Ok(())
}

pub fn pulse_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    if condition != 1 {
        if msg_len == 0 {
            return Err(RuntimeError::new(
                "pulse assertion is false with no message",
            ));
        }

        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);

        // Bounds-check the full msg_len before truncation (an oversized len must
        // trap as OOB, not silently clamp) — same contract as pulse_assert_message.
        let slice = msg_ptr.slice(&view, msg_len)?;
        let sz = (msg_len as usize).min(MAX_ASSERT_MESSAGE);
        let mut src_bytes = vec![0u8; sz];
        slice.subslice(0..sz as u64).read_slice(&mut src_bytes)?;

        // Lossy decode so the message always surfaces — strict validation turned
        // any stray non-UTF-8 byte into a message-less "pulse assert failed".
        let msg = String::from_utf8_lossy(&src_bytes);
        return Err(RuntimeError::new(format!("pulse assert failed: {}", msg)));
    }

    Ok(())
}

pub fn pulse_assert_message(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    if condition == 0 {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);

        // The legacy_span is bounds-checked for the FULL msg_len before
        // truncation — an oversized len must trap as OOB, not silently clamp.
        let slice = msg_ptr.slice(&view, msg_len)?;

        // Truncation to max_assert_message happens after validation
        let sz = (msg_len as usize).min(MAX_ASSERT_MESSAGE);
        let mut src_bytes = vec![0u8; sz];
        slice
            .subslice(0..sz as u64)
            .read_slice(&mut src_bytes)?;

        let msg = String::from_utf8_lossy(&src_bytes);
        return Err(RuntimeError::new(format!(
            "assertion failure with message: {}",
            msg
        )));
    }

    Ok(())
}

pub fn pulse_assert_code(
    _env: FunctionEnvMut<WasmContext>,
    condition: u32,
    error_code: u64,
) -> Result<(), RuntimeError> {
    if condition == 0 {
        return Err(RuntimeError::new(format!(
            "assertion failure with error code: {}",
            error_code
        )));
    }

    Ok(())
}

pub fn pulse_exit(
    _env: FunctionEnvMut<WasmContext>,
    code: u32,
) -> Result<(), RuntimeError> {
    return Err(RuntimeError::new(format!(
        "exit called with code: {}",
        code
    )));
}

pub fn abort(
    _env: FunctionEnvMut<WasmContext>,
) -> Result<(), RuntimeError> {
    return Err(RuntimeError::new("abort called"));
}

pub fn current_time(env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    let result = env
        .data()
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();

    Ok(result as u64)
}

/// Pack the active producer schedule as a list of account names (u64 LE each).
/// PulseVM is a single-producer Avalanche subnet: the only producer is `pulse`.
/// Returns the total byte size (8 = one name). buffer_size==0 is a size probe.
pub fn get_active_producers(
    mut env: FunctionEnvMut<WasmContext>,
    producers_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<i32, RuntimeError> {
    // Single producer: "pulse".
    let pulse: u64 = Name::from_str("pulse")
        .map_err(|e| RuntimeError::new(format!("get_active_producers: {}", e)))?
        .as_u64();
    let packed = pulse.to_le_bytes();
    let total = packed.len() as i32; // 8

    if buffer_size == 0 {
        return Ok(total);
    }

    let to_write = (buffer_size as usize).min(packed.len());
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    producers_ptr
        .slice(&view, to_write as u32)?
        .write_slice(&packed[..to_write])?;

    Ok(total)
}

/// Return the account creation time as microseconds since epoch (Antelope time_point).
pub fn get_account_creation_time(
    env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<i64, RuntimeError> {
    let db = env.data().db();
    let account_obj = db
        .get_account(account)
        .map_err(|e| RuntimeError::new(format!("get_account_creation_time: {}", e)))?;
    // block_timestamp -> time_point -> microseconds since epoch.
    let us = account_obj
        .get_creation_date()
        .to_time_point()
        .time_since_epoch()
        .count();
    Ok(us)
}

/// Permission last-used time (microseconds). PulseVM does not track per-permission
/// last-used timestamps, so we return the account creation time as a monotonic, sane
/// lower bound. STUB — see report.
pub fn get_permission_last_used(
    env: FunctionEnvMut<WasmContext>,
    account: u64,
    _permission: u64,
) -> Result<i64, RuntimeError> {
    let db = env.data().db();
    let account_obj = db
        .get_account(account)
        .map_err(|e| RuntimeError::new(format!("get_permission_last_used: {}", e)))?;
    let us = account_obj
        .get_creation_date()
        .to_time_point()
        .time_since_epoch()
        .count();
    Ok(us)
}

/// Returns 1 if the provided keys/permissions satisfy `account@permission`, else 0.
/// `delay_us` (waits) is not modelled on this chain and is ignored.
pub fn check_permission_authorization(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
    pubkeys_ptr: WasmPtr<u8>,
    pubkeys_len: u32,
    perms_ptr: WasmPtr<u8>,
    perms_len: u32,
    _delay_us: i64,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let mut provided_keys: HashSet<PublicKey> = HashSet::new();
    let mut provided_permissions: HashSet<PermissionLevel> = HashSet::new();

    if pubkeys_len > 0 {
        let mut b = vec![0u8; pubkeys_len as usize];
        pubkeys_ptr.slice(&view, pubkeys_len)?.read_slice(&mut b)?;
        provided_keys = HashSet::<PublicKey>::read(&b, &mut 0).map_err(|e| {
            RuntimeError::new(format!("failed to deserialize provided public keys: {}", e))
        })?;
    }

    if perms_len > 0 {
        let mut b = vec![0u8; perms_len as usize];
        perms_ptr.slice(&view, perms_len)?.read_slice(&mut b)?;
        provided_permissions = HashSet::<PermissionLevel>::read(&b, &mut 0).map_err(|e| {
            RuntimeError::new(format!(
                "failed to deserialize provided permission levels: {}",
                e
            ))
        })?;
    }

    let db = env_data.db();
    let global_properties = unsafe {
        &*db
            .get_global_properties()
            .map_err(|e| RuntimeError::new(format!("check_permission_authorization: {}", e)))?
    };
    let max_authority_depth = global_properties.get_chain_config().get_max_authority_depth();

    let authority = Authority::new_from_permission_level(&PermissionLevel::new(account, permission));
    let mut checker =
        AuthorityChecker::new(max_authority_depth, &provided_keys, &provided_permissions);

    match checker.satisfied(db, &authority, 0) {
        Ok(true) => Ok(1),
        _ => Ok(0),
    }
}

// --- Deferred transactions (deprecated in Antelope; bound as no-op stubs so the
// eosio.system wasm instance can be created). See report. ---

pub fn send_deferred(
    _env: FunctionEnvMut<WasmContext>,
    _sender_id_ptr: WasmPtr<u8>,
    _payer: u64,
    _tx_ptr: WasmPtr<u8>,
    _tx_size: u32,
    _replace_existing: u32,
) -> Result<(), RuntimeError> {
    // Deferred transactions are not supported on PulseVM. No-op.
    Ok(())
}

pub fn cancel_deferred(
    _env: FunctionEnvMut<WasmContext>,
    _sender_id_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    // Nothing was ever scheduled; report "nothing cancelled".
    Ok(0)
}
