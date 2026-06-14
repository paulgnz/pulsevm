use pulsevm_error::ChainError;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::{
    apply_context::ApplyContext, resource_limits::ResourceLimitsManager, utils::pulse_assert,
    wasm_runtime::WasmContext,
};

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
        u32_at(52), // max_inline_action_size
        u16_at(56), // max_inline_action_depth
        u16_at(58), // max_authority_depth
        u32_at(60), // max_action_return_value_size
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

pub fn set_proposed_producers(
    mut env: FunctionEnvMut<WasmContext>,
    _packed_producer_schedule_ptr: WasmPtr<u8>,
    _packed_producer_schedule_len: u32,
) -> Result<i64, RuntimeError> {
    privileged_check(env.data_mut().apply_context_mut())?;
    // PulseVM runs as a single-producer Avalanche subnet (the `pulse` node is the sole
    // producer); there is no on-chain proposed-producer schedule object to mutate. Accept
    // the call so eosio.system regproducer/voteproducer/claimrewards flows execute, and
    // report "schedule unchanged" via -1 (Antelope's contract for a no-op proposal).
    Ok(-1)
}

pub fn set_proposed_producers_ex(
    mut env: FunctionEnvMut<WasmContext>,
    _producer_data_format: u64,
    _packed_producer_schedule_ptr: WasmPtr<u8>,
    _packed_producer_schedule_len: u32,
) -> Result<i64, RuntimeError> {
    privileged_check(env.data_mut().apply_context_mut())?;
    // See set_proposed_producers: single-producer subnet, no schedule object to update.
    Ok(-1)
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
