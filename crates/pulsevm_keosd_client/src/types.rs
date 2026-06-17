use pulsevm_core::crypto::Signature;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignedKeosdTransaction {
    // ORDERED (Antelope wire format) — was HashSet, whose nondeterministic iteration order broke
    // the transaction_mroot for cosigned txs. See pulsevm_core packed_transaction.rs.
    pub signatures: Vec<Signature>,
}
