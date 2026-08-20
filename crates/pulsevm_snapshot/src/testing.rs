//! Fixture support: build a minimal, well-formed version-6 snapshot in memory.
//!
//! The reader is decode-only, so tests that need a whole container (the boot-
//! from-snapshot path in particular) would otherwise each hand-roll the
//! section framing. [`MiniSnapshot`] centralizes that: it emits every section
//! [`import_chainstate`] consumes, in file order, with a configurable chain
//! id, head block and a set of accounts that each get an owner/active
//! permission pair holding one K1 key — enough state for a booted controller
//! to admit a signed transaction.
//!
//! The head block id is computed the Antelope way (sha256 of the packed legacy
//! header with the big-endian block number spliced into the first four bytes),
//! so a consumer that reconstructs the head header field-for-field can assert
//! it reproduces [`MiniSnapshot::head_id`] byte-for-byte.
//!
//! This module is test/fixture support; nothing in the decode path uses it.
//!
//! [`import_chainstate`]: https://docs.rs/pulsevm_snapshot_import

use pulsevm_crypto::Digest;
use pulsevm_name::Name;

use crate::{
    SNAPSHOT_MAGIC,
    rows::section_names,
};

/// One account the mini snapshot carries: an `account_object`, metadata,
/// unlimited resource rows, and an owner/active permission pair whose single
/// authority key is `key`.
#[derive(Debug, Clone)]
pub struct TestAccount {
    pub name: Name,
    /// Compressed K1 public key point used for both owner and active.
    pub key: [u8; 33],
}

/// Builder for a minimal version-6 snapshot container.
#[derive(Debug, Clone)]
pub struct MiniSnapshot {
    /// The source chain's id, carried in the `global_property` section.
    pub chain_id: [u8; 32],
    /// Head block height the snapshot claims to be taken at (must be >= 2 so
    /// the previous block id can embed `head - 1`).
    pub head_block_num: u32,
    /// `BlockTimestamp` slot (500ms since the 2000 epoch) of the head block.
    pub head_slot: u32,
    /// Producer named in the head block header. Not auto-added to `accounts`;
    /// include it there if the consumer needs the account to exist.
    pub head_producer: Name,
    pub accounts: Vec<TestAccount>,
}

fn vu32(out: &mut Vec<u8>, mut n: u32) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn section(name: &str, row_count: u64, rows: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let section_size = 8 + name.len() as u64 + 1 + rows.len() as u64;
    out.extend(section_size.to_le_bytes());
    out.extend(row_count.to_le_bytes());
    out.extend(name.as_bytes());
    out.push(0);
    out.extend(rows);
    out
}

/// A zeroed usage accumulator (`last_ordinal`, `value_ex`, `consumed`).
fn zero_accumulator(out: &mut Vec<u8>) {
    out.extend(0u32.to_le_bytes());
    out.extend(0u64.to_le_bytes());
    out.extend(0u64.to_le_bytes());
}

impl MiniSnapshot {
    /// The head block's previous-block id: `head - 1` in the first four
    /// big-endian bytes over a deterministic filler, the same shape a real
    /// Antelope block id has.
    pub fn previous_id(&self) -> [u8; 32] {
        let mut prev = Digest::hash(b"mini snapshot previous block").0;
        prev[0..4].copy_from_slice(&(self.head_block_num - 1).to_be_bytes());
        prev
    }

    /// The packed legacy `block_header` of the head block (what both nodeos
    /// and the anchor reconstruction hash).
    fn head_header_bytes(&self) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend(self.head_slot.to_le_bytes());
        h.extend(self.head_producer.as_u64().to_le_bytes());
        h.extend(0u16.to_le_bytes()); // confirmed
        h.extend(self.previous_id());
        h.extend([0u8; 32]); // transaction_mroot
        h.extend([0u8; 32]); // action_mroot
        h.extend(0u32.to_le_bytes()); // schedule_version
        h.push(0); // new_producers = None
        vu32(&mut h, 0); // header_extensions
        h
    }

    /// The head block id, computed the Antelope way: sha256 of the packed
    /// header with the big-endian block number spliced into the first four
    /// bytes.
    pub fn head_id(&self) -> [u8; 32] {
        let mut id = Digest::hash(self.head_header_bytes()).0;
        id[0..4].copy_from_slice(&self.head_block_num.to_be_bytes());
        id
    }

    /// The `eosio::chain::block_state` section row: a legacy
    /// `block_header_state` with an empty schedule/merkle scaffold around the
    /// real head header.
    fn block_state_row(&self) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend(self.head_block_num.to_le_bytes());
        r.extend((self.head_block_num - 1).to_le_bytes()); // dpos_proposed_irreversible_blocknum
        r.extend((self.head_block_num - 1).to_le_bytes()); // dpos_irreversible_blocknum
        // active_schedule: version 0, one producer with an empty v0 authority.
        r.extend(0u32.to_le_bytes());
        vu32(&mut r, 1);
        r.extend(self.head_producer.as_u64().to_le_bytes());
        vu32(&mut r, 0); // authority variant tag: v0
        r.extend(1u32.to_le_bytes()); // threshold
        vu32(&mut r, 0); // keys
        // blockroot_merkle: no active nodes, node count 0.
        vu32(&mut r, 0);
        r.extend(0u64.to_le_bytes());
        vu32(&mut r, 0); // producer_to_last_produced
        vu32(&mut r, 0); // producer_to_last_implied_irb
        // valid_block_signing_authority: v0, threshold 1, no keys.
        vu32(&mut r, 0);
        r.extend(1u32.to_le_bytes());
        vu32(&mut r, 0);
        vu32(&mut r, 0); // confirm_count
        r.extend(self.head_id());
        r.extend(self.head_header_bytes());
        vu32(&mut r, 0); // producer_signature variant tag: K1
        r.extend([0u8; 65]);
        // pending_schedule: lib num 0, zero hash, empty schedule.
        r.extend(0u32.to_le_bytes());
        r.extend([0u8; 32]);
        r.extend(0u32.to_le_bytes());
        vu32(&mut r, 0);
        r.push(0); // activated_protocol_features: absent shared_ptr
        vu32(&mut r, 0); // additional_signatures
        r
    }

    /// The `global_property` section row, carrying `chain_id` and a generous
    /// chain configuration (wide CPU/NET budgets and an unbounded transaction
    /// lifetime, so `TimePointSec::maximum()` expirations are admissible).
    fn global_property_row(&self) -> Vec<u8> {
        let mut r = Vec::new();
        r.push(0); // proposed_schedule_block_num = None
        r.extend(0u32.to_le_bytes()); // proposed_schedule.version
        vu32(&mut r, 0); // proposed_schedule.producers
        // configuration (chain_config_v0 fields, then v1's return value size).
        r.extend(1_048_576u64.to_le_bytes()); // max_block_net_usage
        r.extend(1000u32.to_le_bytes()); // target_block_net_usage_pct
        r.extend(524_288u32.to_le_bytes()); // max_transaction_net_usage
        r.extend(12u32.to_le_bytes()); // base_per_transaction_net_usage
        r.extend(500u32.to_le_bytes()); // net_usage_leeway
        r.extend(20u32.to_le_bytes()); // context_free_discount_net_usage_num
        r.extend(100u32.to_le_bytes()); // context_free_discount_net_usage_den
        r.extend(3_000_000_000u32.to_le_bytes()); // max_block_cpu_usage
        r.extend(2500u32.to_le_bytes()); // target_block_cpu_usage_pct
        r.extend(1_000_000_000u32.to_le_bytes()); // max_transaction_cpu_usage
        r.extend(100u32.to_le_bytes()); // min_transaction_cpu_usage
        r.extend(u32::MAX.to_le_bytes()); // max_transaction_lifetime
        r.extend(600u32.to_le_bytes()); // deferred_trx_expiration_window
        r.extend(3_888_000u32.to_le_bytes()); // max_transaction_delay
        r.extend(4096u32.to_le_bytes()); // max_inline_action_size
        r.extend(6u16.to_le_bytes()); // max_inline_action_depth
        r.extend(6u16.to_le_bytes()); // max_authority_depth
        r.extend(256u32.to_le_bytes()); // max_action_return_value_size
        r.extend(self.chain_id);
        r.extend([0u8; 12]); // kv_database_config (3 x u32)
        r.extend([0u8; 44]); // wasm_config (11 x u32)
        r
    }

    fn resource_limits_state_row(&self) -> Vec<u8> {
        let mut r = Vec::new();
        zero_accumulator(&mut r); // average_block_net_usage
        zero_accumulator(&mut r); // average_block_cpu_usage
        r.extend(0u64.to_le_bytes()); // pending_net_usage
        r.extend(0u64.to_le_bytes()); // pending_cpu_usage
        r.extend(0u64.to_le_bytes()); // total_net_weight
        r.extend(0u64.to_le_bytes()); // total_cpu_weight
        r.extend(0u64.to_le_bytes()); // total_ram_bytes
        r.extend(1_048_576u64.to_le_bytes()); // virtual_net_limit
        r.extend(3_000_000_000u64.to_le_bytes()); // virtual_cpu_limit
        r
    }

    fn resource_limits_config_row(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for (target, max) in [(300_000_000u64, 3_000_000_000u64), (104_857, 1_048_576)] {
            r.extend(target.to_le_bytes());
            r.extend(max.to_le_bytes());
            r.extend(120u32.to_le_bytes()); // periods
            r.extend(1000u32.to_le_bytes()); // max_multiplier
            r.extend(99u64.to_le_bytes()); // contract_rate
            r.extend(100u64.to_le_bytes());
            r.extend(1000u64.to_le_bytes()); // expand_rate
            r.extend(999u64.to_le_bytes());
        }
        r.extend(172_800u32.to_le_bytes()); // account_cpu_usage_average_window
        r.extend(172_800u32.to_le_bytes()); // account_net_usage_average_window
        r
    }

    /// One snapshot `permission_object` row holding a single K1 key.
    fn permission_row(rows: &mut Vec<u8>, parent: u64, owner: u64, name: u64, key: &[u8; 33]) {
        rows.extend(parent.to_le_bytes());
        rows.extend(owner.to_le_bytes());
        rows.extend(name.to_le_bytes());
        rows.extend(0i64.to_le_bytes()); // last_updated
        rows.extend(0i64.to_le_bytes()); // last_used
        rows.extend(1u32.to_le_bytes()); // threshold
        vu32(rows, 1); // one key
        vu32(rows, 0); // K1 variant tag
        rows.extend(key);
        rows.extend(1u16.to_le_bytes()); // weight
        vu32(rows, 0); // accounts
        vu32(rows, 0); // waits
    }

    /// Serialize the container.
    pub fn build(&self) -> Vec<u8> {
        assert!(self.head_block_num >= 2, "head must have a previous block");
        let owner = "owner".parse::<Name>().unwrap().as_u64();
        let active = "active".parse::<Name>().unwrap().as_u64();

        let mut accounts = Vec::new();
        let mut metadata = Vec::new();
        let mut permissions = Vec::new();
        let mut limits = Vec::new();
        let mut usage = Vec::new();
        for account in &self.accounts {
            let name = account.name.as_u64();
            accounts.extend(name.to_le_bytes());
            accounts.extend(0u32.to_le_bytes()); // creation_date slot
            vu32(&mut accounts, 0); // no ABI

            metadata.extend(name.to_le_bytes());
            metadata.extend(0u64.to_le_bytes()); // recv_sequence
            metadata.extend(0u64.to_le_bytes()); // auth_sequence
            metadata.extend(0u64.to_le_bytes()); // code_sequence
            metadata.extend(0u64.to_le_bytes()); // abi_sequence
            metadata.extend([0u8; 32]); // code_hash (no code)
            metadata.extend(0i64.to_le_bytes()); // last_code_update
            metadata.extend(0u32.to_le_bytes()); // flags
            metadata.push(0); // vm_type
            metadata.push(0); // vm_version

            // Chainbase id order: each account's owner row precedes its active
            // row (the importer resolves parents through already-seen rows).
            Self::permission_row(&mut permissions, 0, name, owner, &account.key);
            Self::permission_row(&mut permissions, owner, name, active, &account.key);

            limits.extend(name.to_le_bytes());
            limits.extend((-1i64).to_le_bytes()); // net_weight (unlimited)
            limits.extend((-1i64).to_le_bytes()); // cpu_weight
            limits.extend((-1i64).to_le_bytes()); // ram_bytes

            usage.extend(name.to_le_bytes());
            zero_accumulator(&mut usage); // net_usage
            zero_accumulator(&mut usage); // cpu_usage
            usage.extend(0u64.to_le_bytes()); // ram_usage
        }
        let n = self.accounts.len() as u64;

        let mut protocol_state = Vec::new();
        vu32(&mut protocol_state, 0); // activated_protocol_features
        vu32(&mut protocol_state, 0); // preactivated_protocol_features
        vu32(&mut protocol_state, 0); // whitelisted_intrinsics
        protocol_state.extend(2u32.to_le_bytes()); // num_supported_key_types

        let mut out = Vec::new();
        out.extend(SNAPSHOT_MAGIC.to_le_bytes());
        out.extend(crate::CONTAINER_VERSION.to_le_bytes());
        for s in [
            section(section_names::CHAIN_SNAPSHOT_HEADER, 1, &6u32.to_le_bytes()),
            section(section_names::BLOCK_STATE, 1, &self.block_state_row()),
            section(section_names::ACCOUNT, n, &accounts),
            section(section_names::ACCOUNT_METADATA, n, &metadata),
            section(section_names::ACCOUNT_RAM_CORRECTION, 0, &[]),
            section(
                section_names::GLOBAL_PROPERTY,
                1,
                &self.global_property_row(),
            ),
            section(section_names::PROTOCOL_STATE, 1, &protocol_state),
            section(
                section_names::DYNAMIC_GLOBAL_PROPERTY,
                1,
                &1000u64.to_le_bytes(), // global_action_sequence
            ),
            section(section_names::BLOCK_SUMMARY, 0, &[]),
            section(section_names::TRANSACTION, 0, &[]),
            section(section_names::GENERATED_TRANSACTION, 0, &[]),
            section(section_names::CODE, 0, &[]),
            section(section_names::CONTRACT_TABLES, 0, &[]),
            section(section_names::PERMISSION, 2 * n, &permissions),
            section(section_names::PERMISSION_LINK, 0, &[]),
            section(section_names::RESOURCE_LIMITS, n, &limits),
            section(section_names::RESOURCE_USAGE, n, &usage),
            section(
                section_names::RESOURCE_LIMITS_STATE,
                1,
                &self.resource_limits_state_row(),
            ),
            section(
                section_names::RESOURCE_LIMITS_CONFIG,
                1,
                &self.resource_limits_config_row(),
            ),
        ] {
            out.extend(s);
        }
        out.extend(u64::MAX.to_le_bytes()); // end marker
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SnapshotReader;

    fn mini() -> MiniSnapshot {
        MiniSnapshot {
            chain_id: [0xAB; 32],
            head_block_num: 1_234_567,
            head_slot: 1_514_764_800, // 2024-01-01T00:00:00Z
            head_producer: "protonnz".parse().unwrap(),
            accounts: vec![TestAccount {
                name: "alice".parse().unwrap(),
                key: [2u8; 33],
            }],
        }
    }

    #[test]
    fn builds_a_parseable_snapshot_with_a_consistent_head() {
        let mini = mini();
        let bytes = mini.build();
        let snapshot = SnapshotReader::new(&bytes).unwrap();

        let head = snapshot.block_header_state().unwrap();
        assert_eq!(head.block_num, mini.head_block_num);
        assert_eq!(head.block_num_from_id(), mini.head_block_num);
        assert_eq!(head.id.0, mini.head_id());
        assert_eq!(head.header.timestamp.slot(), mini.head_slot);
        assert_eq!(head.header.producer, mini.head_producer);
        assert_eq!(head.header.previous.0, mini.previous_id());
        assert!(head.header.new_producers.is_none());

        let gpo = snapshot.global_property().unwrap();
        assert_eq!(gpo.chain_id.0, mini.chain_id);

        let accounts: Vec<_> = snapshot
            .accounts()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(accounts.len(), 1);
        let permissions: Vec<_> = snapshot
            .permissions()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(permissions.len(), 2);
        assert_eq!(permissions[0].name, "owner".parse::<Name>().unwrap());
        assert_eq!(permissions[1].parent, "owner".parse::<Name>().unwrap());

        // Every remaining section the importer consumes decodes cleanly.
        assert_eq!(
            snapshot.protocol_state().unwrap().num_supported_key_types,
            2
        );
        assert_eq!(
            snapshot
                .dynamic_global_property()
                .unwrap()
                .global_action_sequence,
            1000
        );
        assert_eq!(
            snapshot.resource_limits_state().unwrap().virtual_cpu_limit,
            3_000_000_000
        );
        assert_eq!(
            snapshot
                .resource_limits_config()
                .unwrap()
                .account_net_usage_average_window,
            172_800
        );
        assert_eq!(snapshot.contract_tables().unwrap().count(), 0);
    }
}
