//! Named host predicates folded as pure accumulators.
//!
//! A named host predicate never sees the attempt's history. It declares an
//! initial state per leaf, folds one [`ObservedBatch`] at a time into that
//! state, and answers its leaf from the state alone (RFC-0020 section 15.5).
//! The assertion evaluator owns every state, keeps it in canonical encoded
//! form, and carries it in its checkpoint.
//!
//! # Batch partition
//!
//! The evaluator folds exactly one batch per scheduler entry, at the entry's
//! own evaluation point, regardless of where it observes the log. A live run
//! that observes once per quantum and an offline check that observes every
//! prefix therefore fold identical batches and reach identical states. An
//! `eventually` deadline is the only point without an entry: its leaves are
//! answered from the folded state stepped once more with an empty batch at
//! the deadline, and that step is discarded afterwards.
//!
//! # Failing closed
//!
//! A refused batch, a state over [`MAX_NAMED_PREDICATE_STATE_BYTES`], a state
//! that does not decode, or a prefix that does not continue the folded
//! entries stops the fold and is kept as a [`NamedPredicateFailure`]. Every
//! later named leaf is false, and the offline check reports the failure
//! instead of a verdict.

use std::sync::Arc;

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
        Self {
            point,
            observable_events: &[],
            ordering_facts: &[],
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
/// [`NamedPredicateFailure::Refused`].
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

/// Why named predicate evaluation failed closed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum NamedPredicateFailure {
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
}

impl NamedPredicateFailure {
    pub(super) fn refused(leaf: NamedLeaf<'_>, error: NamedPredicateError) -> Self {
        Self::Refused {
            name: leaf.name.to_owned(),
            nodes: leaf.nodes.to_vec(),
            error,
        }
    }

    fn state_limit(leaf: NamedLeaf<'_>, bytes: usize) -> Self {
        Self::StateLimit {
            name: leaf.name.to_owned(),
            nodes: leaf.nodes.to_vec(),
            bytes,
        }
    }

    fn state_encoding(leaf: NamedLeaf<'_>) -> Self {
        Self::StateEncoding {
            name: leaf.name.to_owned(),
            nodes: leaf.nodes.to_vec(),
        }
    }
}

impl fmt::Display for NamedPredicateFailure {
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
                "named predicates folded through entry {folded}, but the prefix \
                 holds entries {base_sequence}..{end_sequence}"
            ),
        }
    }
}

impl Error for NamedPredicateFailure {}

/// Encodes a predicate state canonically and enforces the per-leaf bound.
pub(super) fn encode_named_state<S>(
    leaf: NamedLeaf<'_>,
    state: &S,
) -> Result<Vec<u8>, NamedPredicateFailure>
where
    S: serde::Serialize,
{
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .map_err(|_| NamedPredicateFailure::state_encoding(leaf))?;
    if bytes.len() > MAX_NAMED_PREDICATE_STATE_BYTES {
        return Err(NamedPredicateFailure::state_limit(leaf, bytes.len()));
    }
    Ok(bytes)
}

/// Decodes a state the evaluator stored for `leaf`.
pub(super) fn decode_named_state<S>(
    leaf: NamedLeaf<'_>,
    bytes: &[u8],
) -> Result<S, NamedPredicateFailure>
where
    S: serde::de::DeserializeOwned,
{
    ciborium::de::from_reader(bytes).map_err(|_| NamedPredicateFailure::state_encoding(leaf))
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

/// The evaluator's fold of every declared named leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct NamedPredicateFold {
    declared: Arc<BTreeSet<NamedLeafKey>>,
    // Empty until the first fold supplies an oracle for initial states.
    states: NamedPredicateStates,
    initialized: bool,
    // Sequence of the next scheduler entry to fold, and the content hash of
    // the entry before it; a prefix continues the fold only if it holds that
    // same entry.
    folded: u64,
    last_folded: Option<ContentHash>,
    failure: Option<NamedPredicateFailure>,
}

/// Checkpointed form of a [`NamedPredicateFold`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamedPredicateFoldWire {
    initialized: bool,
    folded: u64,
    last_folded: Option<ContentHash>,
    states: Vec<NamedPredicateStateWire>,
    failure: Option<NamedPredicateFailure>,
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

impl NamedPredicateFold {
    /// Declares every named leaf the assertions can evaluate.
    pub(super) fn declared_by<'a>(predicates: impl IntoIterator<Item = &'a Condition>) -> Self {
        let mut declared = BTreeSet::new();
        for predicate in predicates {
            collect_named_leaves(predicate, &mut declared);
        }
        Self {
            declared: Arc::new(declared),
            ..Self::default()
        }
    }

    /// Returns the failure that stopped the fold, if any.
    pub(super) fn failure(&self) -> Option<&NamedPredicateFailure> {
        self.failure.as_ref()
    }

    /// Keeps the first failure reported while answering leaves.
    pub(super) fn record_failure(&mut self, failure: Option<NamedPredicateFailure>) {
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
        if self.declared.is_empty() || self.failure.is_some() {
            return;
        }
        if let Err(failure) = self.try_fold_to(prefix, oracle) {
            self.failure = Some(failure);
            self.states.clear();
        }
    }

    fn try_fold_to<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &O,
    ) -> Result<(), NamedPredicateFailure>
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
            .ok_or(NamedPredicateFailure::Discontinuous {
                folded: self.folded,
                base_sequence,
                end_sequence,
            })?;
        if !oracle.folds_named_batches() {
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
            return Err(NamedPredicateFailure::Discontinuous {
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
            .map_err(|_| NamedPredicateFailure::InvalidEntry {
                sequence: entry.sequence(),
            })?;
            let batch = ObservedBatch {
                point: EventEvaluationPoint::event_log_entry(entry),
                observable_events: &observable_events,
                ordering_facts: &ordering_facts,
            };
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

    pub(super) fn to_wire(&self) -> NamedPredicateFoldWire {
        NamedPredicateFoldWire {
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
            failure: self.failure.clone(),
        }
    }

    /// Validates a checkpointed fold against this fold's declarations.
    ///
    /// `last_prefix_events` is the end sequence of the prefix the checkpoint
    /// was taken at. Returns `None` when the wire is malformed, does not bind
    /// to the declared leaves, or was not folded through that prefix.
    pub(super) fn restored_from(
        &self,
        wire: &NamedPredicateFoldWire,
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

        // A live fold holds every declared leaf and has folded exactly the
        // checkpointed prefix; an uninitialized fold has folded nothing, and
        // a failed fold holds no states.
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
            folded: wire.folded,
            last_folded: wire.last_folded,
            failure: wire.failure.clone(),
        })
    }
}

impl NamedPredicateFoldWire {
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

/// Answers named leaves during condition evaluation.
pub(super) trait NamedLeafResolver {
    /// Returns whether `leaf` is true at the current evaluation point.
    fn named_leaf_is_true(&mut self, leaf: NamedLeaf<'_>) -> bool;
}

/// Answers named leaves from folded states through the run's oracle.
pub(super) struct NamedLeafStates<'a, O: ?Sized> {
    oracle: &'a mut O,
    states: &'a NamedPredicateStates,
    failure: Option<NamedPredicateFailure>,
}

impl<'a, O> NamedLeafStates<'a, O>
where
    O: HostAssertionOracle + ?Sized,
{
    pub(super) fn new(oracle: &'a mut O, states: &'a NamedPredicateStates) -> Self {
        Self {
            oracle,
            states,
            failure: None,
        }
    }

    /// Returns the first failure met while answering leaves.
    pub(super) fn into_failure(self) -> Option<NamedPredicateFailure> {
        self.failure
    }
}

impl<O> NamedLeafResolver for NamedLeafStates<'_, O>
where
    O: HostAssertionOracle + ?Sized,
{
    fn named_leaf_is_true(&mut self, leaf: NamedLeaf<'_>) -> bool {
        let key = NamedLeafKey {
            name: leaf.name.to_owned(),
            nodes: leaf.nodes.to_vec(),
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
}
