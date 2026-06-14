use std::sync::atomic::{AtomicI64, Ordering};

use pulsevm_error::ChainError;
use pulsevm_name::Name;
use spdlog::info;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::{
    apply_context::ApplyContext, resource_limits::ResourceLimitsManager, utils::pulse_assert,
    wasm_runtime::WasmContext,
};

/// Phase-0 DPoS-on-Avalanche: monotonic version for the recorded proposed (vote-elected)
/// producer schedule. In-memory (resets on restart) — enough to surface the elected set;
/// persistent storage + the ACP-77 validator-manager bridge are Phase 1/2.
static PROPOSED_SCHEDULE_VERSION: AtomicI64 = AtomicI64::new(0);

/// Lenient decode of a packed `vector<producer_authority>` → producer names. Each entry is
/// name(u64) + block_signing_authority{ variant_idx(varuint), threshold(u32),
/// keys: vector<key_weight{ public_key, weight(u16) }> }. K1/R1 keys are 1+33 bytes; on any
/// unexpected shape we stop and return what we have (good enough to surface the elected set).
fn decode_producer_names(bytes: &[u8]) -> Vec<String> {
    let mut pos = 0usize;
    fn varuint(b: &[u8], p: &mut usize) -> u64 {
        let (mut r, mut s) = (0u64, 0u32);
        while *p < b.len() {
            let x = b[*p];
            *p += 1;
            r |= ((x & 0x7f) as u64) << s;
            if x & 0x80 == 0 {
                break;
            }
            s += 7;
        }
        r
    }
    let count = varuint(bytes, &mut pos);
    let mut names = Vec::new();
    for _ in 0..count {
        if pos + 8 > bytes.len() {
            break;
        }
        let name_u64 = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        names.push(Name::from(name_u64).to_string());
        let _variant = varuint(bytes, &mut pos);
        if pos + 4 > bytes.len() {
            break;
        }
        pos += 4; // threshold
        let key_count = varuint(bytes, &mut pos);
        for _ in 0..key_count {
            if pos >= bytes.len() {
                break;
            }
            let key_type = bytes[pos];
            pos += 1;
            match key_type {
                0 | 1 => pos += 33, // K1 / R1
                _ => return names,  // WA/unknown — stop early
            }
            pos += 2; // weight
        }
    }
    names
}

fn privileged_check(context: &ApplyContext) -> Result<(), RuntimeError> {
    if !context.is_privileged()? {
        return Err(RuntimeError::new(
            "attempt to call privileged instruction without proper authorization",
        ));
    }
    Ok(())
}

pub fn is_privileged(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<i32, RuntimeError> {
    let context = env.data_mut().apply_context_mut();
    privileged_check(context)?;
    let db = env.data().db();
    let account = db.get_account_metadata(account)?;

    Ok(account.is_privileged() as i32)
}

pub fn set_privileged(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    is_priv: i32,
) -> Result<(), RuntimeError> {
    let context = env.data_mut().apply_context_mut();
    privileged_check(context)?;
    context.set_privileged(account, is_priv == 1)?;
    Ok(())
}

pub fn set_resource_limits(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    ram_bytes: i64,
    net_weight: i64,
    cpu_weight: i64,
) -> Result<(), RuntimeError> {
    pulse_assert(
        ram_bytes >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for ram resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    pulse_assert(
        net_weight >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for net resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    pulse_assert(
        cpu_weight >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for cpu resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    let context = env.data_mut().apply_context_mut();
    privileged_check(context)?;
    let mut db = env.data_mut().db_mut();
    ResourceLimitsManager::set_account_limits(
        &mut db,
        &account.into(),
        net_weight,
        cpu_weight,
        ram_bytes,
    )?;
    // TODO: Validate ram usage
    Ok(())
}

pub fn get_resource_limits(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    ram_bytes_ptr: WasmPtr<u8>,
    net_weight_ptr: WasmPtr<u8>,
    cpu_weight_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let context = env_data.apply_context_mut();
    privileged_check(context)?;
    let mut db = env_data.db_mut();
    let mut ram_bytes = 0;
    let mut net_weight = 0;
    let mut cpu_weight = 0;
    ResourceLimitsManager::get_account_limits(
        &mut db,
        &account.into(),
        &mut ram_bytes,
        &mut net_weight,
        &mut cpu_weight,
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let ram_bytes_slice = ram_bytes_ptr.slice(&view, 8)?;
    let net_weight_slice = net_weight_ptr.slice(&view, 8)?;
    let cpu_weight_slice = cpu_weight_ptr.slice(&view, 8)?;
    ram_bytes_slice.write_slice(&ram_bytes.to_le_bytes())?;
    net_weight_slice.write_slice(&net_weight.to_le_bytes())?;
    cpu_weight_slice.write_slice(&cpu_weight.to_le_bytes())?;
    Ok(())
}

/// `chain_config` packs as 16 fixed-width little-endian fields (FC_REFLECT order in
/// `chain_config.hpp`): u64 + 12×u32 + 2×u16 + u32 = 64 bytes. This matches the layout
/// Antelope CDT (≥3.1) emits for `set_blockchain_parameters_packed`.
const CHAIN_CONFIG_PACKED_LEN: usize = 64;

pub fn set_blockchain_parameters_packed(
    mut env: FunctionEnvMut<WasmContext>,
    packed_ptr: WasmPtr<u8>,
    packed_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    privileged_check(env_data.apply_context_mut())?;

    // Copy the packed blob out of wasm memory before borrowing the db mutably.
    let src_bytes = {
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);
        let slice = packed_ptr.slice(&view, packed_len)?;
        let mut b = vec![0u8; packed_len as usize];
        slice.read_slice(&mut b)?;
        b
    };
    pulse_assert(
        src_bytes.len() >= CHAIN_CONFIG_PACKED_LEN,
        ChainError::WasmRuntimeError(format!(
            "set_blockchain_parameters_packed: truncated chain_config blob ({} < {})",
            src_bytes.len(),
            CHAIN_CONFIG_PACKED_LEN
        )),
    )?;
    let u64_at = |o: usize| u64::from_le_bytes(src_bytes[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(src_bytes[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u16::from_le_bytes(src_bytes[o..o + 2].try_into().unwrap());

    // Fields 0..=11 (offsets 0..52, through max_transaction_lifetime) are identical in
    // both layouts. The tail differs: PulseVM `chain_config` (64B) ends with
    // max_inline_action_size, max_inline_action_depth, max_authority_depth,
    // max_action_return_value_size; the Antelope CDT `blockchain_parameters` (68B) instead
    // has deferred_trx_expiration_window + max_transaction_delay before max_inline_action_*
    // and has NO max_action_return_value_size. Distinguish by length.
    let (max_inline_action_size, max_inline_action_depth, max_authority_depth, max_action_return_value_size) =
        if src_bytes.len() >= 68 {
            // Antelope blockchain_parameters: skip deferred_trx_expiration_window (52..56)
            // and max_transaction_delay (56..60). Preserve the current
            // max_action_return_value_size since the blob doesn't carry it.
            let current_marv = {
                let db = env_data.db();
                let gpo = unsafe {
                    &*db.get_global_properties().map_err(|e| {
                        RuntimeError::new(format!("set_blockchain_parameters_packed: {}", e))
                    })?
                };
                gpo.get_chain_config().get_max_action_return_value_size()
            };
            (u32_at(60), u16_at(64), u16_at(66), current_marv)
        } else {
            (u32_at(52), u16_at(56), u16_at(58), u32_at(60))
        };

    let mut db = env_data.db_mut();
    db.set_blockchain_config(
        u64_at(0),  // max_block_net_usage
        u32_at(8),  // target_block_net_usage_pct
        u32_at(12), // max_transaction_net_usage
        u32_at(16), // base_per_transaction_net_usage
        u32_at(20), // net_usage_leeway
        u32_at(24), // context_free_discount_net_usage_num
        u32_at(28), // context_free_discount_net_usage_den
        u32_at(32), // max_block_cpu_usage
        u32_at(36), // target_block_cpu_usage_pct
        u32_at(40), // max_transaction_cpu_usage
        u32_at(44), // min_transaction_cpu_usage
        u32_at(48), // max_transaction_lifetime
        max_inline_action_size,
        max_inline_action_depth,
        max_authority_depth,
        max_action_return_value_size,
    )
    .map_err(|e| {
        RuntimeError::new(format!("set_blockchain_parameters_packed: {}", e))
    })?;
    Ok(())
}

pub fn get_blockchain_parameters_packed(
    mut env: FunctionEnvMut<WasmContext>,
    packed_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    privileged_check(env_data.apply_context_mut())?;

    // Serialize the current chain_config into the same 64-byte fixed LE layout.
    let buf = {
        let db = env_data.db();
        let gpo = unsafe {
            &*db.get_global_properties().map_err(|e| {
                RuntimeError::new(format!("get_blockchain_parameters_packed: {}", e))
            })?
        };
        let cfg = gpo.get_chain_config();
        let mut b: Vec<u8> = Vec::with_capacity(CHAIN_CONFIG_PACKED_LEN);
        b.extend_from_slice(&cfg.get_max_block_net_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_target_block_net_usage_pct().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_transaction_net_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_base_per_transaction_net_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_net_usage_leeway().to_le_bytes());
        b.extend_from_slice(&cfg.get_context_free_discount_net_usage_num().to_le_bytes());
        b.extend_from_slice(&cfg.get_context_free_discount_net_usage_den().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_block_cpu_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_target_block_cpu_usage_pct().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_transaction_cpu_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_min_transaction_cpu_usage().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_transaction_lifetime().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_inline_action_size().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_inline_action_depth().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_authority_depth().to_le_bytes());
        b.extend_from_slice(&cfg.get_max_action_return_value_size().to_le_bytes());
        b
    };

    let size = buf.len() as i32;
    // Antelope contract: a zero-size buffer is a "query the required size" probe.
    if buffer_size == 0 {
        return Ok(size);
    }
    let to_write = (buffer_size as usize).min(buf.len());
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = packed_ptr.slice(&view, to_write as u32)?;
    slice.write_slice(&buf[..to_write])?;
    Ok(size)
}

/// Phase-0 DPoS-on-Avalanche: read the packed schedule out of wasm memory, decode the
/// vote-elected producer names, log them, and return a monotonic version. This is the set
/// that the future ACP-77 validator-manager bridge would seat as Avalanche validators
/// (Phase 1/2). Today it surfaces the elected set instead of dropping it.
fn record_proposed_producers(
    env_data: &WasmContext,
    store: &impl wasmer::AsStoreRef,
    packed_ptr: WasmPtr<u8>,
    packed_len: u32,
) -> Result<i64, RuntimeError> {
    let bytes = {
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(store);
        let slice = packed_ptr.slice(&view, packed_len)?;
        let mut b = vec![0u8; packed_len as usize];
        slice.read_slice(&mut b)?;
        b
    };
    let names = decode_producer_names(&bytes);
    let version = PROPOSED_SCHEDULE_VERSION.fetch_add(1, Ordering::SeqCst) + 1;
    info!(
        "[DPoS] set_proposed_producers v{}: {} vote-elected producers: [{}]",
        version,
        names.len(),
        names.join(", ")
    );
    Ok(version)
}

pub fn set_proposed_producers(
    mut env: FunctionEnvMut<WasmContext>,
    packed_producer_schedule_ptr: WasmPtr<u8>,
    packed_producer_schedule_len: u32,
) -> Result<i64, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    privileged_check(env_data.apply_context_mut())?;
    record_proposed_producers(
        env_data,
        &store,
        packed_producer_schedule_ptr,
        packed_producer_schedule_len,
    )
}

pub fn set_proposed_producers_ex(
    mut env: FunctionEnvMut<WasmContext>,
    _producer_data_format: u64,
    packed_producer_schedule_ptr: WasmPtr<u8>,
    packed_producer_schedule_len: u32,
) -> Result<i64, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    privileged_check(env_data.apply_context_mut())?;
    record_proposed_producers(
        env_data,
        &store,
        packed_producer_schedule_ptr,
        packed_producer_schedule_len,
    )
}

pub fn preactivate_feature(
    mut env: FunctionEnvMut<WasmContext>,
    _feature_digest_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    privileged_check(env.data_mut().apply_context_mut())?;
    // PulseVM does not implement Antelope protocol-feature gating, so there are no
    // activation preconditions to record. Accept preactivation as a no-op so eosio.system
    // `activate` executes; the feature simply isn't separately enforced on this chain.
    Ok(())
}
