//! Typed failures for pending backend-network output checkpoints.

/// Failure to encode or decode a pending routed network frame.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendNetworkOutputCodecError {
    /// The durable record version is unsupported.
    #[error("unsupported pending network frame checkpoint version")]
    Version,
    /// Deterministic CBOR encoding or decoding failed.
    #[error("malformed pending network frame checkpoint encoding")]
    Encoding,
    /// A representation or allocation exceeds its active resource ceiling.
    #[error(
        "pending network frame checkpoint `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Field whose bound was exceeded.
        field: &'static str,
        /// Units already retained by the operation.
        current: u64,
        /// Additional units requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// The record is well-formed but violates a runtime continuation invariant.
    #[error("invalid pending network frame checkpoint: {0}")]
    Invalid(&'static str),
    /// The record has an alternate or noncanonical representation.
    #[error("noncanonical pending network frame checkpoint")]
    Noncanonical,
}

pub(super) fn backend_network_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    configured: usize,
    hard: usize,
) -> BackendNetworkOutputCodecError {
    BackendNetworkOutputCodecError::ResourceLimit {
        field,
        current: u64::try_from(current).unwrap_or(u64::MAX),
        requested: u64::try_from(requested).unwrap_or(u64::MAX),
        configured: u64::try_from(configured).unwrap_or(u64::MAX),
        hard: u64::try_from(hard).unwrap_or(u64::MAX),
    }
}
