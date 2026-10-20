//! Shares immutable collecting-fixture contracts with ordinary DATA producers.
//!
//! Existing fixture assertions retain their own Source and native custody. The
//! feature-gated producer exports serialized DATA and no authority-bearing owner.

use crucible_node_format::Id;

pub(super) mod continuation;

// crucible-lint: allow panic-shortcut -- Invalid static test identifiers are assertion failures.
#[allow(clippy::unwrap_used)]
pub(super) fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[cfg(feature = "test-support")]
mod producer;
#[cfg(feature = "test-support")]
pub use producer::{CompleteSceneFixtureInputs, write_complete_scene_fixture};
