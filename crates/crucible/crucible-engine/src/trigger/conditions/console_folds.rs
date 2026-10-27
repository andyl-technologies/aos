//! Per-pattern console matcher state folded into a condition prefix.
//!
//! Each declared `(node, pattern)` keeps one [`ConsoleAutomaton`] state and the
//! virtual time of the latest batch in which a match ended. Appending console
//! bytes advances only the matchers for that node, so evaluating
//! `console_match` never rescans earlier console output (RFC-0020 CMEAS-18).
//!
//! # Batch points
//!
//! A batch is the run of log entries closed by a scheduler evaluation
//! boundary, and its point is that boundary's time. Native console bytes keep
//! their emission time, which is usually earlier than the boundary of the
//! quantum that delivers them, so a match is reported at the closing boundary
//! rather than at the time of the byte that completed it:
//!
//! ```text
//! entry   byte 'o' @100   byte 'k' @100   boundary @200   boundary @300
//! fold    -               match pending   reported @200   still @200
//! ```
//!
//! Until a boundary closes the batch, a pending match is reported at the time
//! of the byte that ended it, which is the batch's point when that byte is the
//! batch's final entry. Boundaries are retained log entries, so a prefix
//! rebuilt from history folds them in sequence and reaches exactly the state
//! that batch-by-batch appends reached, however the history is divided.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::{ConsoleAutomaton, ConsoleAutomatonState, ConsolePatternError};

/// Identifies one declared console matcher.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ConsoleMatchKey {
    node: NodeId,
    pattern: String,
}

/// Streaming state for one declared console matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConsoleMatchFold {
    automaton: Arc<ConsoleAutomaton>,
    state: ConsoleAutomatonState,
    last_match_at: Option<VirtualTime>,
    // A match ended after the latest evaluation boundary; the next boundary
    // moves `last_match_at` to its own time.
    match_pending: bool,
}

impl ConsoleMatchFold {
    fn started(automaton: Arc<ConsoleAutomaton>) -> Self {
        Self {
            state: automaton.start(),
            automaton,
            last_match_at: None,
            match_pending: false,
        }
    }

    fn observe_bytes(&mut self, at: VirtualTime, bytes: &[u8]) {
        let advance = self.automaton.advance(self.state, bytes);
        self.state = advance.state;
        if advance.matched {
            self.last_match_at = Some(at);
            self.match_pending = true;
        }
    }

    fn close_batch(&mut self, at: VirtualTime) {
        if self.match_pending {
            self.last_match_at = Some(at);
            self.match_pending = false;
        }
    }
}

/// One event-log entry as a console matcher sees it.
enum ConsoleFoldStep<'entry> {
    /// Console bytes on `node` at their own event time.
    Bytes {
        at: VirtualTime,
        node: &'entry NodeId,
        bytes: &'entry [u8],
    },
    /// An evaluation boundary closing the current batch at `at`.
    Boundary { at: VirtualTime },
}

impl<'entry> ConsoleFoldStep<'entry> {
    fn of(entry: &'entry SchedulerEventLogEntry) -> Option<Self> {
        match entry.payload() {
            SchedulerEventLogPayload::Observable(payload) => {
                payload.console_bytes().map(|(node, bytes)| Self::Bytes {
                    at: entry.at(),
                    node,
                    bytes,
                })
            }
            SchedulerEventLogPayload::EvaluationBoundary(_) => {
                Some(Self::Boundary { at: entry.at() })
            }
            _ => None,
        }
    }
}

/// Checkpointed state of one declared console matcher.
///
/// ```text
/// node, pattern     declared matcher identity
/// automaton         content hash of the compiled canonical automaton
/// state             canonical state index after the folded bytes
/// last_match_at     virtual time of the latest batch where a match ended
/// match_pending     present and true only while a match awaits its boundary
/// ```
///
/// `match_pending` is omitted when false, so every state an earlier encoder
/// could write keeps its exact canonical bytes and decodes unchanged. A state
/// checkpointed between a match and its closing boundary carries the field;
/// an older decoder refuses it as an unknown field instead of misreading it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsoleMatchStateWire {
    node: NodeId,
    pattern: String,
    automaton: ContentHash,
    state: u32,
    last_match_at: Option<VirtualTime>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    match_pending: bool,
}

/// Console matcher folds for every pattern a prefix was declared with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ConsoleMatchFolds {
    folds: BTreeMap<ConsoleMatchKey, ConsoleMatchFold>,
}

/// A console pattern that cannot become a streaming matcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RefusedConsolePattern {
    /// Node whose console stream the pattern names.
    pub(crate) node: NodeId,
    /// The refused pattern.
    pub(crate) pattern: String,
    /// Why the console automaton compiler refused it.
    pub(crate) error: ConsolePatternError,
}

impl ConsoleMatchFolds {
    /// Compiles one matcher per declared pattern, each at its start state.
    ///
    /// Returns the first refused pattern with its compiler error.
    pub(crate) fn declared(
        patterns: impl IntoIterator<Item = (NodeId, String)>,
    ) -> Result<Self, RefusedConsolePattern> {
        let mut folds = Self::default();
        for (node, pattern) in patterns {
            if let Err(error) = folds.declare(&node, &pattern, std::iter::empty()) {
                return Err(RefusedConsolePattern {
                    node,
                    pattern,
                    error,
                });
            }
        }
        Ok(folds)
    }

    /// Declares one matcher and folds the entries already observed.
    ///
    /// Declaring an existing key is a no-op, so callers may declare every
    /// pattern a scenario mentions without deduplicating first.
    pub(crate) fn declare<'entry>(
        &mut self,
        node: &NodeId,
        pattern: &str,
        observed: impl IntoIterator<Item = &'entry SchedulerEventLogEntry>,
    ) -> Result<(), ConsolePatternError> {
        let key = ConsoleMatchKey {
            node: node.clone(),
            pattern: pattern.to_owned(),
        };
        if self.folds.contains_key(&key) {
            return Ok(());
        }

        let mut fold = ConsoleMatchFold::started(Arc::new(ConsoleAutomaton::compile(pattern)?));
        for step in observed.into_iter().filter_map(ConsoleFoldStep::of) {
            match step {
                ConsoleFoldStep::Bytes {
                    at,
                    node: step_node,
                    bytes,
                } if step_node == node => fold.observe_bytes(at, bytes),
                ConsoleFoldStep::Bytes { .. } => {}
                ConsoleFoldStep::Boundary { at } => fold.close_batch(at),
            }
        }
        self.folds.insert(key, fold);
        Ok(())
    }

    /// Advances every matcher over appended entries in log order.
    ///
    /// Console bytes advance the matchers for their node; an evaluation
    /// boundary closes the batch of every matcher with a pending match.
    pub(crate) fn observe<'entry>(
        &mut self,
        appended: impl IntoIterator<Item = &'entry SchedulerEventLogEntry>,
    ) {
        if self.folds.is_empty() {
            return;
        }
        for step in appended.into_iter().filter_map(ConsoleFoldStep::of) {
            match step {
                ConsoleFoldStep::Bytes { at, node, bytes } => {
                    for (key, fold) in &mut self.folds {
                        if &key.node == node {
                            fold.observe_bytes(at, bytes);
                        }
                    }
                }
                ConsoleFoldStep::Boundary { at } => {
                    for fold in self.folds.values_mut() {
                        fold.close_batch(at);
                    }
                }
            }
        }
    }

    /// Rebuilds every declared matcher over another prefix's entries.
    ///
    /// Used when a prefix is rewound to an earlier point; the compiled
    /// automata are shared rather than recompiled.
    pub(crate) fn refold<'entry>(
        &self,
        observed: impl IntoIterator<Item = &'entry SchedulerEventLogEntry>,
    ) -> Self {
        let folds = self
            .folds
            .iter()
            .map(|(key, fold)| {
                let restarted = ConsoleMatchFold::started(Arc::clone(&fold.automaton));
                (key.clone(), restarted)
            })
            .collect();
        let mut refolded = Self { folds };
        refolded.observe(observed);
        refolded
    }

    /// Returns every matcher's checkpoint form in canonical key order.
    pub(crate) fn to_wire(&self) -> Vec<ConsoleMatchStateWire> {
        self.folds
            .iter()
            .map(|(key, fold)| ConsoleMatchStateWire {
                node: key.node.clone(),
                pattern: key.pattern.clone(),
                automaton: fold.automaton.content_hash(),
                state: fold.state.index(),
                last_match_at: fold.last_match_at,
                match_pending: fold.match_pending,
            })
            .collect()
    }

    /// Restores checkpointed matcher states onto these declarations.
    ///
    /// The wire must name exactly the declared matchers in canonical order;
    /// each automaton is the one these declarations compiled, verified by
    /// content hash, and each state index must exist in it (RFC-0020
    /// CMEAS-19). A pending match must carry its match time. Returns `None`
    /// on any mismatch.
    pub(crate) fn restored_from(&self, wire: &[ConsoleMatchStateWire]) -> Option<Self> {
        if wire.len() != self.folds.len() {
            return None;
        }
        let mut folds = BTreeMap::new();
        for ((key, fold), state) in self.folds.iter().zip(wire) {
            // A pending match always recorded the time of the byte ending it.
            if key.node != state.node
                || key.pattern != state.pattern
                || fold.automaton.content_hash() != state.automaton
                || (state.match_pending && state.last_match_at.is_none())
            {
                return None;
            }
            let restored = ConsoleMatchFold {
                automaton: Arc::clone(&fold.automaton),
                state: fold.automaton.restore_state(state.state)?,
                last_match_at: state.last_match_at,
                match_pending: state.match_pending,
            };
            folds.insert(key.clone(), restored);
        }
        Some(Self { folds })
    }

    /// Reports whether no matcher is declared.
    pub(crate) fn is_empty(&self) -> bool {
        self.folds.is_empty()
    }

    /// Reports whether both fold sets declare exactly the same matchers.
    pub(crate) fn declares_same_patterns(&self, other: &Self) -> bool {
        self.folds.keys().eq(other.folds.keys())
    }

    /// Reports whether a matcher is declared for `node` and `pattern`.
    pub(crate) fn declares(&self, node: &NodeId, pattern: &str) -> bool {
        self.folds.contains_key(&ConsoleMatchKey {
            node: node.clone(),
            pattern: pattern.to_owned(),
        })
    }

    /// Returns the first `console_match` leaf in `predicates` with no matcher.
    pub(crate) fn first_undeclared<'predicate>(
        &self,
        predicates: impl IntoIterator<Item = &'predicate Predicate>,
    ) -> Option<UndeclaredConsoleMatcher> {
        predicate_console_patterns(predicates)
            .into_iter()
            .find(|(node, pattern)| !self.declares(node, pattern))
            .map(|(node, pattern)| UndeclaredConsoleMatcher { node, pattern })
    }

    /// Reports whether a declared matcher's latest match belongs to the batch
    /// whose point is `at`.
    ///
    /// Returns `None` when the pattern was not declared for `node`.
    pub(crate) fn reported(&self, node: &NodeId, pattern: &str, at: VirtualTime) -> Option<bool> {
        let key = ConsoleMatchKey {
            node: node.clone(),
            pattern: pattern.to_owned(),
        };
        self.folds
            .get(&key)
            .map(|fold| fold.last_match_at == Some(at))
    }
}

/// A `console_match` leaf was evaluated without a declared streaming matcher.
///
/// Console matching never rescans earlier console bytes (RFC-0020 CMEAS-18),
/// so a matcher must be declared before the first byte it could match. An
/// evaluation that meets an undeclared matcher fails closed with this error
/// instead of answering `false`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UndeclaredConsoleMatcher {
    /// Node whose console stream the leaf names.
    pub node: NodeId,
    /// Console pattern the leaf names.
    pub pattern: String,
}

impl fmt::Display for UndeclaredConsoleMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "console_match on node `{}` with pattern `{}` has no declared matcher",
            self.node.name, self.pattern
        )
    }
}

impl Error for UndeclaredConsoleMatcher {}

/// Collects every `console_match` node and pattern an event graph mentions.
///
/// A scheduler or condition prefix that evaluates `triggers` must declare
/// each of these matchers before the run produces console output.
#[must_use]
pub fn event_graph_console_patterns(triggers: &EventGraph) -> BTreeSet<(NodeId, String)> {
    let mut patterns = BTreeSet::new();
    for event in triggers.events() {
        if let Some(trigger) = &event.trigger {
            collect_console_patterns(trigger, &mut patterns);
        }
    }
    patterns
}

/// Collects every `console_match` node and pattern the predicates mention.
///
/// Compound predicates are walked through every child, so the result names
/// each matcher a prefix must declare before evaluating the predicates.
#[must_use]
pub fn predicate_console_patterns<'predicate>(
    predicates: impl IntoIterator<Item = &'predicate Predicate>,
) -> BTreeSet<(NodeId, String)> {
    let mut patterns = BTreeSet::new();
    for predicate in predicates {
        collect_console_patterns(predicate, &mut patterns);
    }
    patterns
}

fn collect_console_patterns(predicate: &Predicate, patterns: &mut BTreeSet<(NodeId, String)>) {
    match predicate {
        Predicate::ConsoleMatch { node, regex } => {
            patterns.insert((node.clone(), regex.pattern.clone()));
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for child in predicates {
                collect_console_patterns(child, patterns);
            }
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            collect_console_patterns(predicate, patterns);
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "console_folds_tests.rs"]
mod tests;
