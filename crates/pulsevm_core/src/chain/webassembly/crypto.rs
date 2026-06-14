use sha2::Digest;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use pulsevm_serialization::{NumBytes, Read, Write};

use crate::{
    chain::wasm_runtime::WasmContext,
    crypto::{PublicKey, Signature},
    utils::Digest as ChecksumDigest,
};

pub fn sha224(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha224::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn sha256(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha256::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn sha512(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha512::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn assert_sha224(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha224::digest(data_bytes); // 28 bytes

    // Borrow the expected hash bytes from guest memory (must be 28 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha224 hash mismatch"));
    }

    Ok(())
}

pub fn assert_sha256(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha256::digest(data_bytes); // 32 bytes

    // Borrow the expected hash bytes from guest memory (must be 32 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha256 hash mismatch"));
    }

    Ok(())
}

pub fn assert_sha512(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha512::digest(data_bytes); // 64 bytes

    // Borrow the expected hash bytes from guest memory (must be 64 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha512 hash mismatch"));
    }

    Ok(())
}

pub fn sha1(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha1::Sha1::digest(&src_bytes); // 20 bytes
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn ripemd160(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = ripemd::Ripemd160::digest(&src_bytes); // 20 bytes
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn assert_sha1(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha1::Sha1::digest(data_bytes); // 20 bytes

    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha1 hash mismatch"));
    }

    Ok(())
}

pub fn assert_ripemd160(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = ripemd::Ripemd160::digest(data_bytes); // 20 bytes

    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new(
            "assertion failed: ripemd160 hash mismatch",
        ));
    }

    Ok(())
}

/// Read a 32-byte checksum (already a digest, NOT re-hashed) and a packed signature,
/// recover the public key, and return it packed.
fn recover_key_inner(
    view: &wasmer::MemoryView,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
) -> Result<PublicKey, RuntimeError> {
    // The digest arg is already a 32-byte checksum — wrap it WITHOUT hashing.
    let mut digest_bytes = [0u8; 32];
    digest_ptr
        .slice(view, 32)?
        .read_slice(&mut digest_bytes)?;
    let checksum: ChecksumDigest = ChecksumDigest::from_data(&digest_bytes);

    let mut sig_bytes = vec![0u8; sig_len as usize];
    sig_ptr.slice(view, sig_len)?.read_slice(&mut sig_bytes)?;
    let signature = Signature::read(&sig_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize signature: {}", e)))?;

    signature
        .recover_public_key(&checksum)
        .map_err(|e| RuntimeError::new(format!("recover_key failed: {}", e)))
}

pub fn recover_key(
    mut env: FunctionEnvMut<WasmContext>,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
    pub_ptr: WasmPtr<u8>,
    pub_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let public_key = recover_key_inner(&view, digest_ptr, sig_ptr, sig_len)?;

    // Pack the recovered public key (34 bytes for the fixed packed representation).
    let total = public_key.num_bytes();
    let mut packed = vec![0u8; total];
    public_key
        .write(&mut packed, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to pack recovered public key: {}", e)))?;

    let to_write = (pub_len as usize).min(total);
    if to_write > 0 {
        pub_ptr
            .slice(&view, to_write as u32)?
            .write_slice(&packed[..to_write])?;
    }

    Ok(total as i32)
}

pub fn assert_recover_key(
    mut env: FunctionEnvMut<WasmContext>,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
    pub_ptr: WasmPtr<u8>,
    pub_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let recovered = recover_key_inner(&view, digest_ptr, sig_ptr, sig_len)?;

    // Read the expected packed public key provided by the contract and compare.
    let mut expected_bytes = vec![0u8; pub_len as usize];
    pub_ptr
        .slice(&view, pub_len)?
        .read_slice(&mut expected_bytes)?;
    let expected = PublicKey::read(&expected_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize expected public key: {}", e)))?;

    if recovered != expected {
        return Err(RuntimeError::new(
            "assertion failed: recovered key does not match expected key",
        ));
    }

    Ok(())
}
