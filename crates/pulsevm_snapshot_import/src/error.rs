use std::fmt;

use pulsevm_chaindb::DbError;
use pulsevm_crypto::Digest;
use pulsevm_snapshot::SnapshotError;

/// Everything that can stop a chainstate import: a snapshot decode error, an
/// arena write error, or one of the writer's own integrity checks.
#[derive(Debug)]
pub enum ImportError {
    Snapshot(SnapshotError),
    Db(DbError),
    /// A code object's wasm does not hash to its declared code hash — the
    /// snapshot is corrupt (or was tampered with) and must not be installed.
    CodeHashMismatch {
        declared: Digest,
        computed: Digest,
    },
    /// A permission references a parent that no earlier row defined. Snapshot
    /// rows come in id order, so a missing parent means a corrupt section.
    MissingParentPermission {
        owner: String,
        name: String,
        parent: String,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::Snapshot(e) => write!(f, "snapshot decode: {e}"),
            ImportError::Db(e) => write!(f, "arena write: {e:?}"),
            ImportError::CodeHashMismatch { declared, computed } => write!(
                f,
                "code object corrupt: declared hash {declared}, wasm hashes to {computed}"
            ),
            ImportError::MissingParentPermission {
                owner,
                name,
                parent,
            } => write!(
                f,
                "permission {owner}@{name} references parent '{parent}' before it was defined"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<SnapshotError> for ImportError {
    fn from(e: SnapshotError) -> Self {
        ImportError::Snapshot(e)
    }
}

impl From<DbError> for ImportError {
    fn from(e: DbError) -> Self {
        ImportError::Db(e)
    }
}
