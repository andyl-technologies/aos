//! Host assertion predicates, oracle adapters, and harness-source lint.

use super::*;
use crate::trigger::assertion_fold::{decode_named_state, encode_named_state};
use crate::trigger::{AssertionFoldFailure, NamedLeaf, NamedPredicateError, ObservedBatch};

/// Host-authored named predicate, folded as a pure accumulator.
///
/// A predicate never sees the attempt's history. For each declared leaf the
/// evaluator starts from [`Self::initial`], folds one [`ObservedBatch`] per
/// scheduler entry through [`Self::step`], and answers the leaf from the
/// folded state with [`Self::leaf_is_true`]. The evaluator owns the states,
/// stores them as canonical CBOR, and carries them in its checkpoint, so live
/// and offline evaluation reach identical states (RFC-0020 CMEAS-17).
///
/// Implementations do not grade runs directly. Wrap them in
/// [`LintedHostAssertionOracle`] with a [`HostAssertionHarnessLint`] proof first,
/// so custom host predicate source cannot bypass `gate:harness-lint`.
///
/// A closure `Fn(NamedLeaf<'_>, &ObservedBatch<'_>) -> bool` is a memoryless
/// predicate: its leaf holds exactly when the closure held for the latest
/// batch, and its initial value is the closure applied to
/// [`ObservedBatch::genesis`].
///
/// # Examples
///
/// ```no_run
/// use crucible_engine::{
///     HostAssertionPredicate, NamedLeaf, NamedPredicateError, ObservableEventPayload,
///     ObservedBatch,
/// };
///
/// /// Holds once any console output has been observed.
/// struct SawConsole;
///
/// impl HostAssertionPredicate for SawConsole {
///     type State = bool;
///
///     fn initial(&self, _leaf: NamedLeaf<'_>) -> bool {
///         false
///     }
///
///     fn step(
///         &self,
///         _leaf: NamedLeaf<'_>,
///         saw: &bool,
///         batch: &ObservedBatch<'_>,
///     ) -> Result<bool, NamedPredicateError> {
///         Ok(*saw
///             || batch.observable_events().iter().any(|event| {
///                 matches!(event.payload(), ObservableEventPayload::ConsoleOutput { .. })
///             }))
///     }
///
///     fn leaf_is_true(&self, _leaf: NamedLeaf<'_>, saw: &bool) -> bool {
///         *saw
///     }
/// }
/// ```
pub trait HostAssertionPredicate {
    /// Accumulator state for one leaf; encoded into the evaluator checkpoint.
    ///
    /// Its canonical CBOR encoding must not exceed
    /// [`crate::MAX_NAMED_PREDICATE_STATE_BYTES`].
    type State: serde::Serialize + serde::de::DeserializeOwned;

    /// Returns the state before any entry has been folded.
    fn initial(&self, leaf: NamedLeaf<'_>) -> Self::State;

    /// Folds one scheduler entry's observations into `state`.
    ///
    /// # Errors
    ///
    /// Returns [`NamedPredicateError`] when the predicate cannot fold the
    /// batch; the evaluator then fails closed.
    fn step(
        &self,
        leaf: NamedLeaf<'_>,
        state: &Self::State,
        batch: &ObservedBatch<'_>,
    ) -> Result<Self::State, NamedPredicateError>;

    /// Returns whether the leaf holds in `state`.
    fn leaf_is_true(&self, leaf: NamedLeaf<'_>, state: &Self::State) -> bool;
}

impl<F> HostAssertionPredicate for F
where
    F: for<'leaf, 'batch> Fn(NamedLeaf<'leaf>, &ObservedBatch<'batch>) -> bool,
{
    type State = bool;

    fn initial(&self, leaf: NamedLeaf<'_>) -> bool {
        self(leaf, &ObservedBatch::genesis())
    }

    fn step(
        &self,
        leaf: NamedLeaf<'_>,
        _state: &bool,
        batch: &ObservedBatch<'_>,
    ) -> Result<bool, NamedPredicateError> {
        Ok(self(leaf, batch))
    }

    fn leaf_is_true(&self, _leaf: NamedLeaf<'_>, state: &bool) -> bool {
        *state
    }
}

/// Lint proof for host-authored assertion harness source.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLint {
    source_len: usize,
}

impl HostAssertionHarnessLint {
    /// Returns the byte length of the linted harness source.
    #[must_use]
    pub const fn source_len(&self) -> usize {
        self.source_len
    }
}

/// Custom host assertion oracle paired with a successful harness-lint proof.
#[derive(Clone, Debug)]
pub struct LintedHostAssertionOracle<O> {
    oracle: O,
    lint: HostAssertionHarnessLint,
}

impl<O> LintedHostAssertionOracle<O> {
    /// Returns the wrapped oracle.
    #[must_use]
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// Consumes this wrapper and returns the wrapped oracle.
    #[must_use]
    pub fn into_inner(self) -> O {
        self.oracle
    }

    /// Returns the lint proof used to authorize this oracle.
    #[must_use]
    pub const fn lint(&self) -> &HostAssertionHarnessLint {
        &self.lint
    }
}

#[cfg(any(debug_assertions, feature = "test-support"))]
pub(crate) fn unchecked_host_assertion_oracle_for_test<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    LintedHostAssertionOracle {
        oracle,
        lint: HostAssertionHarnessLint { source_len: 0 },
    }
}

mod host_assertion_oracle_sealed {
    pub trait Sealed {}
}

/// Assertion oracle accepted by the evaluator.
///
/// This trait is sealed so external host predicate code must flow through
/// [`LintedHostAssertionOracle`] instead of implementing the evaluator-facing
/// oracle directly. Its states are the canonical encodings the evaluator
/// stores and checkpoints.
pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed {
    /// Returns the encoded initial state for `leaf`.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionFoldFailure`] when the state cannot be encoded
    /// within its bound.
    fn initial_named_state(&self, leaf: NamedLeaf<'_>) -> Result<Vec<u8>, AssertionFoldFailure>;

    /// Folds one batch into an encoded state.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionFoldFailure`] when the predicate refuses the batch
    /// or the state does not decode or encode within its bound.
    fn step_named_state(
        &self,
        leaf: NamedLeaf<'_>,
        state: &[u8],
        batch: &ObservedBatch<'_>,
    ) -> Result<Vec<u8>, AssertionFoldFailure>;

    /// Returns whether `leaf` holds in an encoded state.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionFoldFailure`] when the state does not decode.
    fn named_leaf_is_true(
        &mut self,
        leaf: NamedLeaf<'_>,
        state: &[u8],
    ) -> Result<bool, AssertionFoldFailure>;

    /// Returns whether states change with batches.
    ///
    /// Oracles whose answers ignore the log skip folding entirely.
    fn folds_named_batches(&self) -> bool {
        true
    }
}

/// Default zero-guest-cooperation assertion oracle.
///
/// The oracle supplies no named host predicates. Properties that use only the
/// built-in black-box observable vocabulary still evaluate through the checked
/// event-log prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlackBoxHostOracle;

impl host_assertion_oracle_sealed::Sealed for BlackBoxHostOracle {}

impl HostAssertionOracle for BlackBoxHostOracle {
    fn initial_named_state(&self, _leaf: NamedLeaf<'_>) -> Result<Vec<u8>, AssertionFoldFailure> {
        Ok(Vec::new())
    }

    fn step_named_state(
        &self,
        _leaf: NamedLeaf<'_>,
        state: &[u8],
        _batch: &ObservedBatch<'_>,
    ) -> Result<Vec<u8>, AssertionFoldFailure> {
        Ok(state.to_vec())
    }

    fn named_leaf_is_true(
        &mut self,
        _leaf: NamedLeaf<'_>,
        _state: &[u8],
    ) -> Result<bool, AssertionFoldFailure> {
        Ok(false)
    }

    fn folds_named_batches(&self) -> bool {
        false
    }
}

/// Data-only key for a named predicate over search-reconstructed schedule facts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchScheduleNamedPredicateKey {
    name: String,
    nodes: Vec<NodeId>,
}

impl SearchScheduleNamedPredicateKey {
    /// Builds a canonical named-predicate key.
    #[must_use]
    pub fn new(name: impl Into<String>, nodes: Vec<NodeId>) -> Self {
        Self {
            name: name.into(),
            nodes,
        }
    }

    /// Returns the named predicate identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared node references for the named predicate.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }
}

/// Deterministic truth table for search-time named predicate lowering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchScheduleNamedPredicateTruths {
    truths: BTreeMap<SearchScheduleNamedPredicateKey, bool>,
}

impl SearchScheduleNamedPredicateTruths {
    /// Builds an empty truth table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one deterministic named-predicate truth entry.
    #[must_use]
    pub fn with_truth(mut self, key: SearchScheduleNamedPredicateKey, value: bool) -> Self {
        self.insert_truth(key, value);
        self
    }

    /// Inserts one deterministic named-predicate truth entry.
    pub fn insert_truth(&mut self, key: SearchScheduleNamedPredicateKey, value: bool) {
        self.truths.insert(key, value);
    }

    /// Returns the truth value for `key`, if the table declares one.
    #[must_use]
    pub fn truth_for(&self, key: &SearchScheduleNamedPredicateKey) -> Option<bool> {
        self.truths.get(key).copied()
    }

    /// Returns whether the table has no declared named-predicate truths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.truths.is_empty()
    }
}

pub(crate) struct SearchScheduleNamedPredicateHostOracle<'truths> {
    truths: &'truths SearchScheduleNamedPredicateTruths,
    missing_truths: BTreeSet<SearchScheduleNamedPredicateKey>,
}

impl<'truths> SearchScheduleNamedPredicateHostOracle<'truths> {
    pub(crate) const fn new(truths: &'truths SearchScheduleNamedPredicateTruths) -> Self {
        Self {
            truths,
            missing_truths: BTreeSet::new(),
        }
    }

    pub(crate) fn clear_missing_truths(&mut self) {
        self.missing_truths.clear();
    }

    pub(crate) fn has_missing_truths(&self) -> bool {
        !self.missing_truths.is_empty()
    }
}

impl host_assertion_oracle_sealed::Sealed for SearchScheduleNamedPredicateHostOracle<'_> {}

impl HostAssertionOracle for SearchScheduleNamedPredicateHostOracle<'_> {
    fn initial_named_state(&self, _leaf: NamedLeaf<'_>) -> Result<Vec<u8>, AssertionFoldFailure> {
        Ok(Vec::new())
    }

    fn step_named_state(
        &self,
        _leaf: NamedLeaf<'_>,
        state: &[u8],
        _batch: &ObservedBatch<'_>,
    ) -> Result<Vec<u8>, AssertionFoldFailure> {
        Ok(state.to_vec())
    }

    fn named_leaf_is_true(
        &mut self,
        leaf: NamedLeaf<'_>,
        _state: &[u8],
    ) -> Result<bool, AssertionFoldFailure> {
        let key =
            SearchScheduleNamedPredicateKey::new(leaf.name().to_owned(), leaf.nodes().to_vec());
        Ok(match self.truths.truth_for(&key) {
            Some(value) => value,
            None => {
                self.missing_truths.insert(key);
                false
            }
        })
    }

    fn folds_named_batches(&self) -> bool {
        false
    }
}

impl<O> host_assertion_oracle_sealed::Sealed for LintedHostAssertionOracle<O> where
    O: HostAssertionPredicate
{
}

impl<O> HostAssertionOracle for LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    fn initial_named_state(&self, leaf: NamedLeaf<'_>) -> Result<Vec<u8>, AssertionFoldFailure> {
        encode_named_state(leaf, &self.oracle.initial(leaf))
    }

    fn step_named_state(
        &self,
        leaf: NamedLeaf<'_>,
        state: &[u8],
        batch: &ObservedBatch<'_>,
    ) -> Result<Vec<u8>, AssertionFoldFailure> {
        let state = decode_named_state::<O::State>(leaf, state)?;
        let next = self
            .oracle
            .step(leaf, &state, batch)
            .map_err(|error| AssertionFoldFailure::refused(leaf, error))?;
        encode_named_state(leaf, &next)
    }

    fn named_leaf_is_true(
        &mut self,
        leaf: NamedLeaf<'_>,
        state: &[u8],
    ) -> Result<bool, AssertionFoldFailure> {
        let state = decode_named_state::<O::State>(leaf, state)?;
        Ok(self.oracle.leaf_is_true(leaf, &state))
    }
}

/// One banned host assertion harness pattern found by linting.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLintViolation {
    /// Source token or path fragment that matched.
    pub pattern: String,
    /// Determinism contract violated by the matched pattern.
    pub reason: String,
}

/// Error returned when host assertion harness source fails determinism linting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionHarnessLintError {
    violations: Vec<HostAssertionHarnessLintViolation>,
}

impl HostAssertionHarnessLintError {
    /// Returns every banned host assertion source pattern that was found.
    #[must_use]
    pub fn violations(&self) -> &[HostAssertionHarnessLintViolation] {
        &self.violations
    }
}

impl fmt::Display for HostAssertionHarnessLintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "host assertion harness source contains {} banned determinism pattern(s)",
            self.violations.len()
        )
    }
}

impl Error for HostAssertionHarnessLintError {}

/// Lints host-authored assertion predicate source for banned nondeterminism.
///
/// This helper is the assertion layer's `gate:harness-lint` hook. It catches
/// host wall-clock reads, thread RNG, unordered-map/set use, filesystem/process
/// access, and `unsafe` blocks in host predicate harness source before those
/// predicates can grade a run.
///
/// # Errors
///
/// Returns [`HostAssertionHarnessLintError`] with every matched banned pattern.
pub fn lint_host_assertion_harness_source(
    source: &str,
) -> Result<HostAssertionHarnessLint, HostAssertionHarnessLintError> {
    const BANNED_PATTERNS: &[(&str, &str)] = &[
        (
            "HashMap",
            "unordered map iteration can perturb outcome order",
        ),
        (
            "HashSet",
            "unordered set iteration can perturb outcome order",
        ),
        ("SystemTime", "host wall-clock reads are nondeterministic"),
        ("Instant", "host wall-clock reads are nondeterministic"),
        ("std::time", "host wall-clock reads are nondeterministic"),
        ("chrono::", "host wall-clock reads are nondeterministic"),
        (
            "OffsetDateTime::now",
            "host wall-clock reads are nondeterministic",
        ),
        ("getrandom", "direct host RNG access is nondeterministic"),
        ("OsRng", "direct host RNG access is nondeterministic"),
        ("thread_rng", "thread-local RNG is nondeterministic"),
        ("rand::", "direct host RNG access is nondeterministic"),
        ("rand::rng", "direct host RNG access is nondeterministic"),
        ("rand::random", "direct host RNG access is nondeterministic"),
        ("from_entropy", "host entropy seeding is nondeterministic"),
        (
            "DefaultHasher",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "RandomState",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "std::env",
            "environment access is outside the recorded observed state",
        ),
        (
            "env::",
            "environment access is outside the recorded observed state",
        ),
        (
            "std::thread",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread::",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread_local!",
            "host thread-local state is outside the recorded observed state",
        ),
        (
            "std::fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::{fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "fs::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::process",
            "process access is outside the recorded observed state",
        ),
        (
            "std::{process",
            "process access is outside the recorded observed state",
        ),
        (
            "process::Command",
            "process access is outside the recorded observed state",
        ),
        (
            "Command::new",
            "process access is outside the recorded observed state",
        ),
        (
            "std::net",
            "network access is outside the recorded observed state",
        ),
        (
            "TcpStream",
            "network access is outside the recorded observed state",
        ),
        (
            "UdpSocket",
            "network access is outside the recorded observed state",
        ),
        ("std::io", "host I/O is outside the recorded observed state"),
        ("stdin", "host I/O is outside the recorded observed state"),
        ("stdout", "host I/O is outside the recorded observed state"),
        ("stderr", "host I/O is outside the recorded observed state"),
        (
            "println!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "eprintln!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "OpenOptions",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "File::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "tokio::select",
            "host scheduling races are nondeterministic",
        ),
        ("tokio::spawn", "host task scheduling is nondeterministic"),
        ("select!", "host scheduling races are nondeterministic"),
        (
            "Atomic",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Mutex",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "RwLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "LazyLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceCell",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "lazy_static",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Cell<",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "RefCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "UnsafeCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "borrow_mut",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "parking_lot",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "crossbeam",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "unsafe",
            "unsafe host predicates bypass the read-only state contract",
        ),
    ];
    let violations = BANNED_PATTERNS
        .iter()
        .filter(|(pattern, _reason)| source.contains(pattern))
        .map(|(pattern, reason)| HostAssertionHarnessLintViolation {
            pattern: (*pattern).to_owned(),
            reason: (*reason).to_owned(),
        })
        .collect::<Vec<_>>();
    if violations.is_empty() {
        Ok(HostAssertionHarnessLint {
            source_len: source.len(),
        })
    } else {
        Err(HostAssertionHarnessLintError { violations })
    }
}
