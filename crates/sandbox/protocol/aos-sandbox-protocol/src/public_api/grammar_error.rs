//! Shared errors for bounded public request and execution-result grammar.
//!
//! CLI parsing and Controller authorization remain outside this module.

/// Reports invalid bounded CLI grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidCliGrammar {
    /// A selector is empty, oversized, or contains control text.
    #[error("CLI selector is invalid")]
    InvalidSelector,
    /// A relative path is absolute, ambiguous, or oversized.
    #[error("CLI relative path is invalid")]
    InvalidRelativePath,
    /// An opaque value or idempotency key is empty or oversized.
    #[error("CLI opaque value is invalid")]
    InvalidOpaqueValue,
    /// A page, depth, or wait bound is zero or excessive.
    #[error("CLI bound is invalid")]
    InvalidBound,
    /// An execution argument vector is empty or exceeds a byte/count bound.
    #[error("CLI execution argument vector is invalid")]
    InvalidArguments,
}
