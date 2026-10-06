//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Defines validation and resource failures shared by logical RAM components.

/// A rejected logical RAM operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RamError {
    /// A byte length does not fit the declared geometry.
    #[error("invalid logical RAM length")]
    InvalidLength,
    /// A stable region identifier violates the canonical string contract.
    #[error("invalid logical RAM region identifier")]
    InvalidRegionId,
    /// Inventory entries overlap, repeat, or are not canonically ordered.
    #[error("duplicate or noncanonical region ordering")]
    InvalidOrder,
    /// A class, mask, scope, edition, or record tag is unsupported.
    #[error("unsupported logical RAM encoding")]
    InvalidEncoding,
    /// A record is truncated or contains unexpected trailing data.
    #[error("malformed logical RAM record")]
    Malformed,
    /// A coordinate is outside the admitted inventory.
    #[error("logical RAM coordinate is outside the inventory")]
    OutOfRange,
    /// A supplied digest or proof does not match the expected commitment.
    #[error("logical RAM commitment mismatch")]
    DigestMismatch,
    /// A checked arithmetic operation overflowed.
    #[error("logical RAM arithmetic overflow")]
    Overflow,
    /// An admitted resource ceiling would be exceeded.
    #[error("logical RAM resource limit exceeded")]
    ResourceLimit,
    /// A bounded allocation could not be satisfied.
    #[error("logical RAM allocation failed")]
    Allocation,
    /// A dirty receipt belongs to another incarnation or an older baseline.
    #[error("stale logical RAM dirty receipt")]
    StaleReceipt,
    /// An external full-recomputation reader failed to supply coherent bytes.
    #[error("logical RAM oracle read failed: {0}")]
    Read(String),
}
