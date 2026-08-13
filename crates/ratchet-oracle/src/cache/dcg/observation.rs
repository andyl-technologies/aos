//! Behavior for impure-input and impure-trace observation results.

use super::*;

impl ImpureInputObservation {
    /// Returns the observed leaf node.
    pub const fn node(&self) -> DemandNodeId {
        match self {
            Self::Inserted { node } => *node,
            Self::Reconsidered(reconsideration) => reconsideration.node(),
        }
    }
}

impl ImpureTraceObservation {
    pub(super) fn cacheable(leaves: Vec<ImpureInputObservation>) -> Self {
        Self {
            status: ImpureTraceStatus::Cacheable,
            leaves,
        }
    }

    pub(super) fn incomplete() -> Self {
        Self {
            status: ImpureTraceStatus::Incomplete,
            leaves: Vec::new(),
        }
    }

    pub(super) fn uncacheable(input: UncacheableInput) -> Self {
        Self {
            status: ImpureTraceStatus::Uncacheable(input),
            leaves: Vec::new(),
        }
    }

    /// Returns the cacheability status for the ingested trace.
    pub const fn status(&self) -> ImpureTraceStatus {
        self.status
    }

    /// Returns per-leaf observations for cacheable traces.
    pub fn leaves(&self) -> &[ImpureInputObservation] {
        &self.leaves
    }
}
