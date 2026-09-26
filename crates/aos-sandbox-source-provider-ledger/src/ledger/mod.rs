//! Pure AOSSPL01 values, canonical codecs, and nonauthorizing reducers.
//!
//! This subtree imports no journal guard, security custody, file descriptor,
//! backend execution, or signing type. Runtime modules may turn its validated
//! records and proposed mutations into guarded durable operations, but values
//! here never grant authority to perform those operations.

pub mod artifact;
mod codec;
pub mod completion;
pub mod evidence;
pub mod format;
pub mod model;
mod primitives;
pub mod reducer;
pub mod reopen;

/// Reports pure canonical-format or reducer rejection without runtime coupling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerFormatErrorV1 {
    /// Canonical bytes or graph state violate an invariant.
    Corrupt(&'static str),
    /// A bounded pure value exceeds its hard ceiling.
    LimitExceeded(&'static str),
    /// A legacy migration lacks authenticated facts absent from its source format.
    NeedsProvenance(&'static str),
}
