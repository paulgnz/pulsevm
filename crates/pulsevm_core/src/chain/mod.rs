pub mod abi;
pub mod account;
pub mod apply_context;
pub mod asset;
pub mod authority_checker;
pub mod authorization_manager;
pub mod block;
pub mod config;
pub mod controller;
pub mod crypto;
pub mod id;
pub mod mempool;
pub mod pulse_contract;
pub mod resource;
pub mod resource_limits;
pub mod snapshot_import;
pub mod state_history;
pub mod transaction;
pub mod transaction_context;
pub mod utils;
pub mod wasm_runtime;
mod webassembly;

// Re-export types for easier access
pub mod name {
    pub use pulsevm_name::Name;
}
pub mod authority {
    pub use pulsevm_ffi::{
        Authority, KeyWeight, PermissionLevel, PermissionLevelWeight, WaitWeight,
    };
}

pub use pulsevm_error::ChainError;
use pulsevm_name::Name;
use pulsevm_name_macro::name;
pub use wat::parse_str as wat2wasm;

pub const PULSE_NAME: Name = Name::new(name!("pulse"));
// The 1:1 XPR-network migration uses `eosio` as the system account, so native system
// actions (updateauth/newaccount/setcode/...) must be recognized on `eosio` too.
pub const EOSIO_NAME: Name = Name::new(name!("eosio"));
pub const OWNER_NAME: Name = Name::new(name!("owner"));
pub const ACTIVE_NAME: Name = Name::new(name!("active"));
pub const ANY_NAME: Name = Name::new(name!("pulse.any"));
pub const CODE_NAME: Name = Name::new(name!("pulse.code"));
