//! Runtime-owned references for transaction-lifetime byte transport.
//!
//! Transaction blob references carry content identity and transaction
//! authority without exposing a filesystem path. Only the runtime creates
//! these values from handler output slots.

use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{LocalKey, TransactionId};

/// Maximum bytes retained by one runtime-owned transaction blob.
pub const MAX_TRANSACTION_BLOB_BYTES: u64 = 32 * 1024 * 1024;
/// Type discriminator for a runtime-generated transaction blob reference.
pub const TRANSACTION_BLOB_REFERENCE_TYPE: &str = "aos-transaction-blob-reference";

/// References one runtime-owned, transaction-lifetime byte sequence.
///
/// The reference deliberately carries no filesystem path. Runtime adapters
/// expose its bytes only to an invocation that receives the checked value
/// through an operation-result edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBlobReference {
    /// Carries [`TRANSACTION_BLOB_REFERENCE_TYPE`].
    #[serde(rename = "_type")]
    pub kind: String,
    /// Binds the reference to its durable transaction.
    pub transaction: TransactionId,
    /// Names the runtime-derived content handle.
    pub handle: LocalKey,
    /// Authenticates the exact blob bytes.
    pub content_sha256: Sha256Digest,
    /// Records the exact byte count verified by the runtime.
    pub size_bytes: u64,
}
