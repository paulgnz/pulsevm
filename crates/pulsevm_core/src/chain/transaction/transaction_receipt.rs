use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Write, WriteError};
use serde::Serialize;

use crate::chain::transaction::{PackedTransaction, TransactionReceiptHeader};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize)]
pub struct TransactionReceipt {
    #[serde(flatten)]
    header: TransactionReceiptHeader,
    #[serde(skip)]
    trx_variant: u8, // always 1 for now
    trx: PackedTransaction,
}

impl TransactionReceipt {
    pub fn new(header: TransactionReceiptHeader, trx: PackedTransaction) -> Self {
        TransactionReceipt {
            header,
            trx_variant: 1,
            trx,
        }
    }

    pub fn trx(&self) -> &PackedTransaction {
        &self.trx
    }

    /// The producer-recorded objective CPU charge (deterministic metered µs) carried in the block.
    /// Used on verify/accept to bill the account this value instead of re-measuring wall-clock.
    pub fn cpu_usage_us(&self) -> u32 {
        self.header.cpu_usage_us
    }

    pub fn digest(&self) -> Result<Digest, WriteError> {
        Ok(Digest::hash(self.pack()?))
    }
}
