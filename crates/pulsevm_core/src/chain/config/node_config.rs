use std::path::PathBuf;

use pulsevm_name::Name;
use serde::Deserialize;

use crate::crypto::PrivateKey;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    // Name of the block producer, must be a valid EOSIO name (up to 12 characters, a-z, 1-5)
    pub producer_name: Name,
    // Private key of the block producer, used for signing blocks and transactions
    pub producer_key: PrivateKey,
    // Size of the memory mapped database in bytes
    #[serde(default = "default_db_size")]
    pub db_size: u64,
    // Wall-clock ceiling on how long a single transaction may spend executing
    // before it is abandoned, in milliseconds. This is a SUBJECTIVE, node-local
    // guard (it depends on this machine's speed, not the transaction's result), so
    // it protects against a native/host code path that the deterministic op
    // metering can't bound; it never affects consensus. Measured against raw
    // wall-clock, which includes module compilation. Generous by default (matching
    // the 30s deadline the C++ layer uses) so it only catches genuine runaways, not
    // a slow-but-legitimate compile of a large contract on a slow machine; a
    // producer would tune it down.
    #[serde(default = "default_max_transaction_time_ms")]
    pub max_transaction_time_ms: u32,
    // Boot-from-snapshot: path to an Antelope portable chainstate snapshot (a
    // nodeos `create_snapshot` .bin). When set and the database is fresh
    // (revision 0), the node imports the snapshot's full chainstate instead of
    // authoring genesis: state, head block number and — critically — the SOURCE
    // chain's chain_id all carry over, so migrated accounts' existing keys keep
    // producing valid signatures, and block production continues from head + 1.
    // Once the database holds state a restart resumes normally and never
    // re-imports (the imported chain_id persists beside the database). Unset =
    // exactly the genesis/resume behavior.
    //
    // Operational note: under Avalanche's proposerVM a blockchain's height only
    // moves forward, so an imported chain (whose height starts at the snapshot
    // head, and which re-genesising would rewind) requires a FRESH blockchainID
    // — create a new chain whose config carries this field; an existing chain
    // cannot be re-pointed at a snapshot in place.
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
}

fn default_db_size() -> u64 {
    20 * 1024 * 1024 * 1024 // 20 GB
}

fn default_max_transaction_time_ms() -> u32 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";

    #[test]
    fn snapshot_path_defaults_to_none() {
        // The minimal config every existing deployment ships: no snapshot_path
        // key at all. It must parse (backwards compatible) and default off.
        let config: NodeConfig = serde_json::from_str(&format!(
            r#"{{"producer_name": "pulse", "producer_key": "{KEY}"}}"#
        ))
        .unwrap();
        assert_eq!(config.snapshot_path, None);
        assert_eq!(config.max_transaction_time_ms, 30_000);
    }

    #[test]
    fn snapshot_path_parses_when_set() {
        let config: NodeConfig = serde_json::from_str(&format!(
            r#"{{"producer_name": "pulse", "producer_key": "{KEY}",
                 "snapshot_path": "/data/xpr-testnet.bin"}}"#
        ))
        .unwrap();
        assert_eq!(
            config.snapshot_path,
            Some(PathBuf::from("/data/xpr-testnet.bin"))
        );
    }
}
