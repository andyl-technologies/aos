//! Named host predicates folded as pure accumulators.
//!
//! A named host predicate never sees the attempt's history. It declares an
//! initial state per leaf, folds one [`ObservedBatch`] at a time into that
//! state, and answers its leaf from the state alone (RFC-0020 section 15.5).
//! This module holds the vocabulary predicates see; the evaluator's fold,
//! which owns every state and its checkpoint form, is in
//! [`super::assertion_fold`].

use super::*;

/// Largest canonical accumulator state one named leaf may hold.
///
/// RFC-0020 CMEAS-17 bounds every leaf's state so the evaluator checkpoint
/// stays proportional to the scenario's declarations.
pub const MAX_NAMED_PREDICATE_STATE_BYTES: usize = 64 * 1024;

/// One named host predicate leaf declared by an assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamedLeaf<'a> {
    name: &'a str,
    nodes: &'a [NodeId],
}

impl<'a> NamedLeaf<'a> {
    pub(crate) const fn new(name: &'a str, nodes: &'a [NodeId]) -> Self {
        Self { name, nodes }
    }

    /// Returns the predicate name the assertion declared.
    #[must_use]
    pub const fn name(self) -> &'a str {
        self.name
    }

    /// Returns the nodes the assertion passed to the predicate.
    #[must_use]
    pub const fn nodes(self) -> &'a [NodeId] {
        self.nodes
    }
}

/// The observations one scheduler entry contributes, at its evaluation point.
///
/// Raw scheduler entries, RNG draws, host-worker state, and wall-clock data
/// are not part of a batch, just as they are not part of [`ObservedState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedBatch<'a> {
    point: EventEvaluationPoint,
    observable_events: &'a [ObservableEvent],
    ordering_facts: &'a [ObservedOrderingFact],
}

impl<'a> ObservedBatch<'a> {
    /// Returns the empty batch at the run's genesis point.
    ///
    /// Predicates may use it to derive their initial state.
    #[must_use]
    pub const fn genesis() -> Self {
        Self::empty(EventEvaluationPoint::genesis())
    }

    pub(crate) const fn empty(point: EventEvaluationPoint) -> Self {
        Self::new(point, &[], &[])
    }

    pub(crate) const fn new(
        point: EventEvaluationPoint,
        observable_events: &'a [ObservableEvent],
        ordering_facts: &'a [ObservedOrderingFact],
    ) -> Self {
        Self {
            point,
            observable_events,
            ordering_facts,
        }
    }

    /// Returns the evaluation point this batch was observed at.
    #[must_use]
    pub const fn point(self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the virtual time of [`Self::point`].
    #[must_use]
    pub fn at(self) -> VirtualTime {
        self.point.at()
    }

    /// Returns the black-box observable events the entry recorded.
    #[must_use]
    pub const fn observable_events(self) -> &'a [ObservableEvent] {
        self.observable_events
    }

    /// Returns the cross-node ordering facts the entry recorded.
    #[must_use]
    pub const fn ordering_facts(self) -> &'a [ObservedOrderingFact] {
        self.ordering_facts
    }
}

/// Error a named predicate returns when it cannot fold a batch.
///
/// The evaluator stops folding and fails closed; see
/// [`AssertionFoldFailure::Refused`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NamedPredicateError {
    message: String,
}

impl NamedPredicateError {
    /// Builds an error with a human-readable reason.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the reason the predicate gave.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NamedPredicateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for NamedPredicateError {}
