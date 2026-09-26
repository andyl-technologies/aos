//! Portable Mount-manager startup policy, capture, and derivation state.
//!
//! Namespace 45 stores one monotone `AOSMMSTA1` policy head and immutable
//! `AOSMMCAP1` per-execution capture rows. This module owns their bounded
//! canonical representation and the pure derivation of expected activation
//! descriptors from namespace-40 acquisition, namespace-39 SourcePin, and
//! namespace-2 Mount-resource lifecycle records. It grants no journal,
//! descriptor, process, or recovery authority.

mod control;
mod derivation;
mod format;
mod model;

pub use control::*;
pub use derivation::*;
pub use format::*;
pub use model::*;
