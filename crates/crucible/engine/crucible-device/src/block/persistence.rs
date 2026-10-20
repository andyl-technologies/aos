//! Bounded deterministic persistence dependency graph for block fragments.
//!
//! Every applied write fragment enters this graph before it can reach durable
//! media. The graph owns dependency readiness and persistence ordering; the
//! controller and volatile-cache maps continue to own the fragment bytes.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::DeviceError;

/// Hard maximum live persistence nodes.
pub const HARD_BLOCK_PERSISTENCE_NODES: usize = 4_194_304;
/// Hard maximum aggregate dependency edges across live persistence nodes.
pub const HARD_BLOCK_PERSISTENCE_EDGES: usize = 16_777_216;
/// Hard maximum unconsumed persistence transformation evidence records.
pub const HARD_BLOCK_PERSISTENCE_EVIDENCE: usize = 1_048_576;

mod helpers;
mod runtime;
mod types;

pub use helpers::BlockPersistenceReadyKey;
pub use types::*;

#[cfg(test)]
#[path = "persistence_test.rs"]
mod tests;
