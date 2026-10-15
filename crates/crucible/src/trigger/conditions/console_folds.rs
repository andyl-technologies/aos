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

/// Console matcher folds for every pattern a prefix was declared with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ConsoleMatchFolds {
    folds: BTreeMap<ConsoleMatchKey, ConsoleMatchFold>,
}

impl ConsoleMatchFolds {
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

    /// Reports whether both fold sets declare exactly the same matchers.
    pub(crate) fn declares_same_patterns(&self, other: &Self) -> bool {
        self.folds.keys().eq(other.folds.keys())
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

/// Collects every `console_match` node and pattern a scenario mentions.
///
/// Properties and trigger events are walked through every compound
/// predicate, so the result names each matcher a run must declare.
#[must_use]
pub fn scenario_console_patterns(
    properties: &Properties,
    triggers: &EventGraph,
) -> BTreeSet<(NodeId, String)> {
    let mut patterns = property_console_patterns(properties);
    for event in triggers.events() {
        if let Some(trigger) = &event.trigger {
            collect_console_patterns(trigger, &mut patterns);
        }
    }
    patterns
}

/// Collects every `console_match` node and pattern the properties mention.
pub(crate) fn property_console_patterns(properties: &Properties) -> BTreeSet<(NodeId, String)> {
    let mut patterns = BTreeSet::new();
    for assertion in properties.assertions() {
        match &assertion.property {
            Property::Always { predicate }
            | Property::Sometimes { predicate }
            | Property::AfterQuiescence { predicate }
            | Property::Reachable { predicate, .. } => {
                collect_console_patterns(predicate, &mut patterns);
            }
            Property::Eventually {
                trigger, property, ..
            } => {
                collect_console_patterns(trigger, &mut patterns);
                collect_console_patterns(property, &mut patterns);
            }
        }
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
