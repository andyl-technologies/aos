//! Host assertion predicates, oracle adapters, and harness-source lint.

use super::*;

/// Host-authored resolver for assertion leaves over materialized observed state.
///
/// Implementations do not grade runs directly. Wrap them in
/// [`LintedHostAssertionOracle`] with a [`HostAssertionHarnessLint`] proof first,
/// so custom host predicate source cannot bypass `gate:harness-lint`.
pub trait HostAssertionPredicate {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> HostAssertionPredicate for F
where
    F: for<'log, 'leaf> Fn(ObservedState<'log>, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        self(observed, leaf)
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
/// oracle directly.
pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
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
    fn leaf_is_true(&mut self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => false,
        }
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
    fn leaf_is_true(&mut self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                let key = SearchScheduleNamedPredicateKey::new(name.to_owned(), nodes.to_vec());
                match self.truths.truth_for(&key) {
                    Some(value) => value,
                    None => {
                        self.missing_truths.insert(key);
                        false
                    }
                }
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
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
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        HostAssertionPredicate::leaf_is_true(&self.oracle, observed, leaf)
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
