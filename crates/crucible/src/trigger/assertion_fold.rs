//! The assertion evaluator's per-entry fold of named leaves and console
//! matchers.
//!
//! The evaluator never rereads an attempt's history. Every declared named
//! leaf keeps an encoded accumulator state, and every `console_match` leaf in
//! the properties keeps one streaming automaton state. Both advance together,
//! once per scheduler entry, and both travel in the evaluator checkpoint
//! (RFC-0020 CMEAS-17 and CMEAS-19).
//!
//! # Batch partition
//!
//! The evaluator folds exactly one batch per scheduler entry, at the entry's
//! own evaluation point, regardless of where it observes the log. A live run
//! that observes once per quantum and an offline check that observes every
//! prefix therefore fold identical batches and reach identical states. An
//! `eventually` deadline is the only point without an entry: its named leaves
//! are answered from the folded state stepped once more with an empty batch
//! at the deadline, and that step is discarded afterwards. An empty batch
//! carries no console bytes, so console matchers need no deadline step.
//!
//! # Failing closed
//!
//! A refused batch, a state over [`MAX_NAMED_PREDICATE_STATE_BYTES`], a state
//! that does not decode, a console pattern that does not compile, a console
//! leaf without a declared matcher, or a prefix that does not continue the
//! folded entries stops the fold and is kept as an [`AssertionFoldFailure`].
//! Every later folded leaf is false, and the offline check reports the
//! failure instead of a verdict.

use std::sync::Arc;

use super::*;

/// Why the assertion evaluator's fold failed closed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum AssertionFoldFailure {
    /// The predicate refused to fold a batch.
    Refused {
        /// Predicate name of the leaf.
        name: String,
        /// Nodes of the leaf.
        nodes: Vec<NodeId>,
        /// The predicate's error.
        error: NamedPredicateError,
    },
    /// A leaf's canonical state exceeded [`MAX_NAMED_PREDICATE_STATE_BYTES`].
    StateLimit {
        /// Predicate name of the leaf.
        name: String,
        /// Nodes of the leaf.
        nodes: Vec<NodeId>,
        /// Encoded size of the refused state.
        bytes: usize,
    },
    /// A leaf's state could not be encoded, or a stored state did not decode
    /// as the oracle's state type.
    StateEncoding {
        /// Predicate name of the leaf.
        name: String,
        /// Nodes of the leaf.
        nodes: Vec<NodeId>,
    },
    /// A folded entry's observations could not be derived.
    InvalidEntry {
        /// Sequence of the entry.
        sequence: u64,
    },
    /// An observed prefix does not hold the next entry to fold.
    Discontinuous {
        /// Sequence of the next entry to fold.
        folded: u64,
        /// First sequence the prefix holds.
        base_sequence: u64,
        /// Sequence just past the prefix's last entry.
        end_sequence: u64,
    },
    /// A property's console pattern did not compile to a streaming matcher.
    ConsolePattern {
        /// Node whose console stream the pattern matches.
        node: NodeId,
        /// The refused pattern.
        pattern: String,
        /// Why the pattern was refused.
        reason: String,
    },
    /// A `console_match` leaf had no matcher declared by the properties.
    UndeclaredConsoleMatcher(UndeclaredConsoleMatcher),
}

impl AssertionFoldFailure {
    pub(super) fn refused(leaf: NamedLeaf<'_>, error: NamedPredicateError) -> Self {
        Self::Refused {
            name: leaf.name().to_owned(),
            nodes: leaf.nodes().to_vec(),
            error,
        }
    }

    fn state_limit(leaf: NamedLeaf<'_>, bytes: usize) -> Self {
        Self::StateLimit {
            name: leaf.name().to_owned(),
            nodes: leaf.nodes().to_vec(),
            bytes,
        }
    }

    fn state_encoding(leaf: NamedLeaf<'_>) -> Self {
        Self::StateEncoding {
            name: leaf.name().to_owned(),
            nodes: leaf.nodes().to_vec(),
        }
    }
}

impl fmt::Display for AssertionFoldFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { name, error, .. } => {
                write!(formatter, "named predicate {name} refused a batch: {error}")
            }
            Self::StateLimit { name, bytes, .. } => write!(
                formatter,
                "named predicate {name} state is {bytes} bytes, over the \
                 {MAX_NAMED_PREDICATE_STATE_BYTES}-byte limit"
            ),
            Self::StateEncoding { name, .. } => {
                write!(
                    formatter,
                    "named predicate {name} state is not canonical CBOR"
                )
            }
            Self::InvalidEntry { sequence } => write!(
                formatter,
                "event-log entry {sequence} has no derivable observations"
            ),
            Self::Discontinuous {
                folded,
                base_sequence,
                end_sequence,
            } => write!(
                formatter,
                "assertion leaves folded through entry {folded}, but the prefix \
                 holds entries {base_sequence}..{end_sequence}"
            ),
            Self::ConsolePattern {
                node,
                pattern,
                reason,
            } => write!(
                formatter,
                "console pattern `{pattern}` on node `{}` is not streamable: {reason}",
                node.name
            ),
            Self::UndeclaredConsoleMatcher(undeclared) => write!(formatter, "{undeclared}"),
        }
    }
}

impl Error for AssertionFoldFailure {}

/// Encodes a predicate state canonically and enforces the per-leaf bound.
pub(super) fn encode_named_state<S>(
    leaf: NamedLeaf<'_>,
    state: &S,
) -> Result<Vec<u8>, AssertionFoldFailure>
where
    S: serde::Serialize,
{
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .map_err(|_| AssertionFoldFailure::state_encoding(leaf))?;
    if bytes.len() > MAX_NAMED_PREDICATE_STATE_BYTES {
        return Err(AssertionFoldFailure::state_limit(leaf, bytes.len()));
    }
    Ok(bytes)
}

/// Decodes a state the evaluator stored for `leaf`.
pub(super) fn decode_named_state<S>(
    leaf: NamedLeaf<'_>,
    bytes: &[u8],
) -> Result<S, AssertionFoldFailure>
where
    S: serde::de::DeserializeOwned,
{
    ciborium::de::from_reader(bytes).map_err(|_| AssertionFoldFailure::state_encoding(leaf))
}

/// Canonical identity of one declared named leaf.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub(super) struct NamedLeafKey {
    pub(super) name: String,
    pub(super) nodes: Vec<NodeId>,
}

impl NamedLeafKey {
    fn leaf(&self) -> NamedLeaf<'_> {
        NamedLeaf::new(&self.name, &self.nodes)
    }
}

/// Encoded accumulator state per declared leaf.
pub(super) type NamedPredicateStates = BTreeMap<NamedLeafKey, Vec<u8>>;

/// The evaluator's fold of every declared named leaf and console matcher.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AssertionFold {
    declared: Arc<BTreeSet<NamedLeafKey>>,
    // Empty until the first fold supplies an oracle for initial states.
    states: NamedPredicateStates,
    initialized: bool,
    // One streaming matcher per `console_match` leaf in the properties,
    // compiled once at declaration and folded with the named leaves.
    console: ConsoleMatchFolds,
    // Sequence of the next scheduler entry to fold, and the content hash of
    // the entry before it; a prefix continues the fold only if it holds that
    // same entry.
    folded: u64,
    last_folded: Option<ContentHash>,
    failure: Option<AssertionFoldFailure>,
}

/// Checkpointed form of an [`AssertionFold`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssertionFoldWire {
    initialized: bool,
    folded: u64,
    last_folded: Option<ContentHash>,
    states: Vec<NamedPredicateStateWire>,
    console: Vec<ConsoleMatchStateWire>,
    failure: Option<AssertionFoldFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedPredicateStateWire {
    leaf: NamedLeafKey,
    #[serde(with = "serde_bytes_vec")]
    state: Vec<u8>,
}

/// Encodes state bytes as one CBOR byte string rather than an integer array.
mod serde_bytes_vec {
    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl serde::de::Visitor<'_> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte string")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Vec<u8>, E>
            where
                E: serde::de::Error,
            {
                Ok(bytes.to_vec())
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E>
            where
                E: serde::de::Error,
            {
                Ok(bytes)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl AssertionFold {
    /// Declares every named leaf and console matcher the assertions can
    /// evaluate.
    ///
    /// Each console pattern is compiled here, once; a pattern that cannot
    /// become a streaming matcher fails the fold before any entry is folded.
    pub(super) fn declared_by<'a>(predicates: impl IntoIterator<Item = &'a Condition>) -> Self {
        let predicates = predicates.into_iter().collect::<Vec<_>>();
        let mut declared = BTreeSet::new();
        for predicate in &predicates {
            collect_named_leaves(predicate, &mut declared);
        }
        let mut fold = Self {
            declared: Arc::new(declared),
            ..Self::default()
        };
        match ConsoleMatchFolds::declared(predicate_console_patterns(predicates)) {
            Ok(console) => fold.console = console,
            Err(refused) => {
                fold.failure = Some(AssertionFoldFailure::ConsolePattern {
                    node: refused.node,
                    pattern: refused.pattern,
                    reason: refused.error.to_string(),
                });
            }
        }
        fold
    }

    /// Returns the failure that stopped the fold, if any.
    pub(super) fn failure(&self) -> Option<&AssertionFoldFailure> {
        self.failure.as_ref()
    }

    /// Keeps the first failure reported while answering leaves.
    pub(super) fn record_failure(&mut self, failure: Option<AssertionFoldFailure>) {
        if self.failure.is_none() {
            self.failure = failure;
        }
    }

    /// Folds every entry of `prefix` after the last folded one.
    ///
    /// The prefix must hold the next entry to fold. Every entry is folded at
    /// its own evaluation point, so the result does not depend on how the
    /// log was divided into observed prefixes.
    pub(super) fn fold_to<O>(&mut self, prefix: &ConditionEventLogPrefix, oracle: &O)
    where
        O: HostAssertionOracle + ?Sized,
    {
        if (self.declared.is_empty() && self.console.is_empty()) || self.failure.is_some() {
            return;
        }
        if let Err(failure) = self.try_fold_to(prefix, oracle) {
            self.failure = Some(failure);
            self.states.clear();
            self.console = ConsoleMatchFolds::default();
        }
    }

    fn try_fold_to<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &O,
    ) -> Result<(), AssertionFoldFailure>
    where
        O: HostAssertionOracle + ?Sized,
    {
        if !self.initialized {
            for key in self.declared.iter() {
                let state = oracle.initial_named_state(key.leaf())?;
                self.states.insert(key.clone(), state);
            }
            self.initialized = true;
        }

        let entries = prefix.scheduler_entries();
        let base_sequence = prefix.base_sequence;
        let end_sequence = base_sequence.saturating_add(entries.len() as u64);
        let start = self
            .folded
            .checked_sub(base_sequence)
            .filter(|_| self.folded <= end_sequence)
            .and_then(|start| usize::try_from(start).ok())
            .ok_or(AssertionFoldFailure::Discontinuous {
                folded: self.folded,
                base_sequence,
                end_sequence,
            })?;
        // Oracles without per-batch named state still fold console matchers.
        let folds_named = oracle.folds_named_batches();
        if !folds_named && self.console.is_empty() {
            self.folded = end_sequence;
            return Ok(());
        }
        // Folding entries of another log would silently corrupt every state.
        if let (Some(expected), Some(previous)) = (self.last_folded, start.checked_sub(1))
            && entries
                .get(previous)
                .map(SchedulerEventLogEntry::content_hash)
                != Some(expected)
        {
            return Err(AssertionFoldFailure::Discontinuous {
                folded: self.folded,
                base_sequence,
                end_sequence,
            });
        }

        let mut observable_events = Vec::new();
        let mut black_box_observation_kinds = BTreeSet::new();
        let mut ordering_facts = Vec::new();
        for entry in entries.iter_from(start) {
            observable_events.clear();
            ordering_facts.clear();
            push_observed_state_facts(
                entry,
                &mut observable_events,
                &mut black_box_observation_kinds,
                &mut ordering_facts,
            )
            .map_err(|_| AssertionFoldFailure::InvalidEntry {
                sequence: entry.sequence(),
            })?;
            self.console.observe(std::iter::once(entry));
            if !folds_named {
                continue;
            }
            let batch = ObservedBatch::new(
                EventEvaluationPoint::event_log_entry(entry),
                &observable_events,
                &ordering_facts,
            );
            for (key, state) in &mut self.states {
                *state = oracle.step_named_state(key.leaf(), state, &batch)?;
            }
        }
        self.folded = end_sequence;
        if let Some(last) = entries.last() {
            self.last_folded = Some(last.content_hash());
        }
        Ok(())
    }

    /// Returns the folded states stepped once more with an empty batch at
    /// `point`, without committing that step.
    ///
    /// Deadline points carry no entry; their leaves are answered from these
    /// states.
    pub(super) fn stepped_at<O>(
        &mut self,
        point: EventEvaluationPoint,
        oracle: &O,
    ) -> NamedPredicateStates
    where
        O: HostAssertionOracle + ?Sized,
    {
        if self.failure.is_some() || !oracle.folds_named_batches() {
            return self.states.clone();
        }
        let batch = ObservedBatch::empty(point);
        let mut stepped = NamedPredicateStates::new();
        for (key, state) in &self.states {
            match oracle.step_named_state(key.leaf(), state, &batch) {
                Ok(state) => {
                    stepped.insert(key.clone(), state);
                }
                Err(failure) => {
                    self.failure = Some(failure);
                    self.states.clear();
                    self.console = ConsoleMatchFolds::default();
                    return NamedPredicateStates::new();
                }
            }
        }
        stepped
    }

    /// Returns the committed states.
    pub(super) fn states(&self) -> &NamedPredicateStates {
        &self.states
    }

    /// Returns the console matchers folded through the last folded entry.
    pub(super) fn console(&self) -> &ConsoleMatchFolds {
        &self.console
    }

    pub(super) fn to_wire(&self) -> AssertionFoldWire {
        AssertionFoldWire {
            initialized: self.initialized,
            folded: self.folded,
            last_folded: self.last_folded,
            states: self
                .states
                .iter()
                .map(|(leaf, state)| NamedPredicateStateWire {
                    leaf: leaf.clone(),
                    state: state.clone(),
                })
                .collect(),
            console: self.console.to_wire(),
            failure: self.failure.clone(),
        }
    }

    /// Validates a checkpointed fold against this fold's declarations.
    ///
    /// `last_prefix_events` is the end sequence of the prefix the checkpoint
    /// was taken at. Returns `None` when the wire is malformed, does not bind
    /// to the declared leaves and matchers, or was not folded through that
    /// prefix.
    pub(super) fn restored_from(
        &self,
        wire: &AssertionFoldWire,
        last_prefix_events: Option<u64>,
    ) -> Option<Self> {
        if !wire.is_canonical()
            || wire
                .states
                .iter()
                .any(|state| state.state.len() > MAX_NAMED_PREDICATE_STATE_BYTES)
        {
            return None;
        }

        // A live fold holds every declared leaf and matcher and has folded
        // exactly the checkpointed prefix; an uninitialized fold has folded
        // nothing, and a failed fold holds no states.
        let console = match &wire.failure {
            Some(_) if wire.console.is_empty() => ConsoleMatchFolds::default(),
            Some(_) => return None,
            None => self.console.restored_from(&wire.console)?,
        };
        let consistent = match (&wire.failure, wire.initialized) {
            (Some(_), _) => wire.states.is_empty(),
            (None, false) => {
                wire.states.is_empty() && wire.folded == 0 && wire.last_folded.is_none()
            }
            (None, true) => {
                Some(wire.folded) == last_prefix_events
                    && wire.states.len() == self.declared.len()
                    && wire
                        .states
                        .iter()
                        .zip(self.declared.iter())
                        .all(|(state, declared)| &state.leaf == declared)
            }
        };
        consistent.then(|| Self {
            declared: Arc::clone(&self.declared),
            states: wire
                .states
                .iter()
                .map(|state| (state.leaf.clone(), state.state.clone()))
                .collect(),
            initialized: wire.initialized,
            console,
            folded: wire.folded,
            last_folded: wire.last_folded,
            failure: wire.failure.clone(),
        })
    }
}

impl AssertionFoldWire {
    /// Returns whether the wire's state list is in canonical leaf order.
    pub(super) fn is_canonical(&self) -> bool {
        self.states
            .windows(2)
            .all(|pair| pair[0].leaf < pair[1].leaf)
    }
}

/// Returns the predicates an assertion property evaluates.
pub(super) fn property_predicates(property: &Property) -> Vec<&Condition> {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => vec![predicate],
        Property::Eventually {
            trigger, property, ..
        } => vec![trigger, property],
    }
}

fn collect_named_leaves(predicate: &Condition, declared: &mut BTreeSet<NamedLeafKey>) {
    match predicate {
        Predicate::Named { name, nodes } => {
            declared.insert(NamedLeafKey {
                name: name.clone(),
                nodes: nodes.clone(),
            });
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for child in predicates {
                collect_named_leaves(child, declared);
            }
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            collect_named_leaves(predicate, declared);
        }
        _ => {}
    }
}

/// Answers folded assertion leaves during condition evaluation.
pub(super) trait AssertionLeafResolver {
    /// Returns whether `leaf` is true at the current evaluation point.
    fn named_leaf_is_true(&mut self, leaf: NamedLeaf<'_>) -> bool;

    /// Returns whether a console match on `node` ended at virtual time `at`.
    fn console_match(&mut self, node: &NodeId, pattern: &str, at: VirtualTime) -> bool;
}

/// Answers folded leaves from the fold's states through the run's oracle.
pub(super) struct FoldedLeafStates<'a, O: ?Sized> {
    oracle: &'a mut O,
    states: &'a NamedPredicateStates,
    console: &'a ConsoleMatchFolds,
    failure: Option<AssertionFoldFailure>,
}

impl<'a, O> FoldedLeafStates<'a, O>
where
    O: HostAssertionOracle + ?Sized,
{
    pub(super) fn new(
        oracle: &'a mut O,
        states: &'a NamedPredicateStates,
        console: &'a ConsoleMatchFolds,
    ) -> Self {
        Self {
            oracle,
            states,
            console,
            failure: None,
        }
    }

    /// Returns the first failure met while answering leaves.
    pub(super) fn into_failure(self) -> Option<AssertionFoldFailure> {
        self.failure
    }
}

impl<O> AssertionLeafResolver for FoldedLeafStates<'_, O>
where
    O: HostAssertionOracle + ?Sized,
{
    fn named_leaf_is_true(&mut self, leaf: NamedLeaf<'_>) -> bool {
        let key = NamedLeafKey {
            name: leaf.name().to_owned(),
            nodes: leaf.nodes().to_vec(),
        };
        // A missing state means the fold failed; the failure is already kept.
        let Some(state) = self.states.get(&key) else {
            return false;
        };
        match self.oracle.named_leaf_is_true(leaf, state) {
            Ok(value) => value,
            Err(failure) => {
                self.failure.get_or_insert(failure);
                false
            }
        }
    }

    fn console_match(&mut self, node: &NodeId, pattern: &str, at: VirtualTime) -> bool {
        match self.console.reported(node, pattern, at) {
            Some(matched) => matched,
            // Every property pattern is declared when the fold is built, so a
            // miss means the condition came from outside those properties.
            None => {
                self.failure.get_or_insert_with(|| {
                    AssertionFoldFailure::UndeclaredConsoleMatcher(UndeclaredConsoleMatcher {
                        node: node.clone(),
                        pattern: pattern.to_owned(),
                    })
                });
                false
            }
        }
    }
}
