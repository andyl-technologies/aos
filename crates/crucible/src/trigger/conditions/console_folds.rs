//! Per-pattern console matcher state folded into a condition prefix.
//!
//! Each declared `(node, pattern)` keeps one [`ConsoleAutomaton`] state and the
//! virtual time of the latest batch in which a match ended. Appending console
//! bytes advances only the matchers for that node, so evaluating
//! `console_match` never rescans earlier console output.

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
}

impl ConsoleMatchFold {
    fn observe(&mut self, at: VirtualTime, bytes: &[u8]) {
        let advance = self.automaton.advance(self.state, bytes);
        self.state = advance.state;
        if advance.matched {
            self.last_match_at = Some(at);
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
/// ```
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsoleMatchStateWire {
    node: NodeId,
    pattern: String,
    automaton: ContentHash,
    state: u32,
    last_match_at: Option<VirtualTime>,
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

    /// Declares one matcher and folds the console bytes already observed.
    ///
    /// Declaring an existing key is a no-op, so callers may declare every
    /// pattern a scenario mentions without deduplicating first.
    pub(crate) fn declare<'event>(
        &mut self,
        node: &NodeId,
        pattern: &str,
        observed: impl IntoIterator<Item = &'event ObservableEvent>,
    ) -> Result<(), ConsolePatternError> {
        let key = ConsoleMatchKey {
            node: node.clone(),
            pattern: pattern.to_owned(),
        };
        if self.folds.contains_key(&key) {
            return Ok(());
        }

        let automaton = Arc::new(ConsoleAutomaton::compile(pattern)?);
        let mut fold = ConsoleMatchFold {
            state: automaton.start(),
            automaton,
            last_match_at: None,
        };
        for event in observed {
            if let Some((event_node, bytes)) = event.console_bytes()
                && event_node == node
            {
                fold.observe(event.at(), bytes);
            }
        }
        self.folds.insert(key, fold);
        Ok(())
    }

    /// Advances every matcher for the nodes whose console bytes were appended.
    pub(crate) fn observe<'event>(
        &mut self,
        appended: impl IntoIterator<Item = &'event ObservableEvent>,
    ) {
        if self.folds.is_empty() {
            return;
        }
        for event in appended {
            let Some((node, bytes)) = event.console_bytes() else {
                continue;
            };
            for (key, fold) in &mut self.folds {
                if &key.node == node {
                    fold.observe(event.at(), bytes);
                }
            }
        }
    }

    /// Rebuilds every declared matcher over another prefix's console bytes.
    ///
    /// Used when a prefix is rewound to an earlier point; the compiled
    /// automata are shared rather than recompiled.
    pub(crate) fn refold<'event>(
        &self,
        observed: impl IntoIterator<Item = &'event ObservableEvent>,
    ) -> Self {
        let folds = self
            .folds
            .iter()
            .map(|(key, fold)| {
                let restarted = ConsoleMatchFold {
                    automaton: Arc::clone(&fold.automaton),
                    state: fold.automaton.start(),
                    last_match_at: None,
                };
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
            })
            .collect()
    }

    /// Restores checkpointed matcher states onto these declarations.
    ///
    /// The wire must name exactly the declared matchers in canonical order;
    /// each automaton is the one these declarations compiled, verified by
    /// content hash, and each state index must exist in it (RFC-0020
    /// CMEAS-19). Returns `None` on any mismatch.
    pub(crate) fn restored_from(&self, wire: &[ConsoleMatchStateWire]) -> Option<Self> {
        if wire.len() != self.folds.len() {
            return None;
        }
        let mut folds = BTreeMap::new();
        for ((key, fold), state) in self.folds.iter().zip(wire) {
            if key.node != state.node
                || key.pattern != state.pattern
                || fold.automaton.content_hash() != state.automaton
            {
                return None;
            }
            let restored = ConsoleMatchFold {
                automaton: Arc::clone(&fold.automaton),
                state: fold.automaton.restore_state(state.state)?,
                last_match_at: state.last_match_at,
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

    /// Reports whether a declared matcher saw a match end at `at`.
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
