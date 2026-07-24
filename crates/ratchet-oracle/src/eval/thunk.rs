//! Serial thunk state machine for the tree-walk oracle.
//!
//! The Phase-1 evaluator runs on one thread, but the thunk state word is atomic
//! from the start so the later parallel forcing protocol can extend the same
//! representation. This module implements only the serial subset:
//! `Suspended -> Blackhole -> Forced`.
//!
//! The baseline representation stores the cached result in an
//! `AtomicValueCell` published under a separate state word. Candidate C instead
//! reserves two invalid tagged-value words for suspended and blackholed, then
//! publishes the forced value directly into that same atomic word. In both
//! layouts readers acquire-load the publication word, and `Forced` is terminal:
//! the result is never rewritten after publication.

use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

#[cfg(not(feature = "candidate_c_value"))]
use super::env::AtomicValueCell;
use crate::value::Value;

const SUSPENDED: u64 = 0;
const BLACKHOLE: u64 = 1;
const FORCED: u64 = 2;

/// Invalid Candidate-C value words reserved for the serial thunk state.
#[cfg(feature = "candidate_c_value")]
const COMPACT_SUSPENDED: u64 = u64::MAX;
#[cfg(feature = "candidate_c_value")]
const COMPACT_BLACKHOLE: u64 = u64::MAX - 1;

/// The serial Phase-1 thunk state encoded in the atomic state word.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThunkState {
    /// The thunk has not been evaluated yet.
    Suspended = SUSPENDED,
    /// The thunk is currently being forced on this evaluator stack.
    Blackhole = BLACKHOLE,
    /// The thunk has reached weak head normal form and cached its result.
    Forced = FORCED,
}

impl ThunkState {
    /// Returns the raw `u64` encoding stored in the atomic state word.
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Decodes a raw atomic state word.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if `raw` is not one of the
    /// Phase-1 state encodings.
    pub const fn from_raw(raw: u64) -> Result<Self, ForceError> {
        match raw {
            SUSPENDED => Ok(Self::Suspended),
            BLACKHOLE => Ok(Self::Blackhole),
            FORCED => Ok(Self::Forced),
            _ => Err(ForceError::InvalidStateWord { raw }),
        }
    }
}

impl TryFrom<u64> for ThunkState {
    type Error = ForceError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_raw(value)
    }
}

/// Result of attempting to claim a thunk for forcing.
#[must_use = "a claimed thunk must be finished or aborted"]
#[derive(Debug)]
pub enum ForceClaim<'a> {
    /// The caller transitioned the thunk from suspended to blackholed and must
    /// evaluate the thunk body.
    Claimed(ForceGuard<'a>),
    /// The thunk was already forced and the cached value can be reused.
    AlreadyForced(Value),
}

/// A live claim on a blackholed thunk.
///
/// Dropping the guard before publishing a value resets the thunk to
/// [`ThunkState::Suspended`]. This models evaluator error unwinding: if a thunk
/// body throws before producing WHNF, the temporary blackhole must not poison
/// later forces as an infinite-recursion error.
#[must_use = "finish or abort a claimed thunk"]
#[derive(Debug)]
pub struct ForceGuard<'a> {
    thunk: &'a ThunkCell,
    active: bool,
}

impl ForceGuard<'_> {
    /// Publishes the WHNF result and consumes the claim.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::UnexpectedState`] if the thunk is no longer
    /// blackholed. Returns [`ForceError::InvalidStateWord`] if the private
    /// atomic state word has an unsupported encoding.
    pub fn finish(mut self, value: Value) -> Result<Value, ForceError> {
        let mut barrier = DisabledThunkResolveBarrier;
        let value = self
            .thunk
            .publish_forced_with_barrier(value, &mut barrier)?;
        self.active = false;
        Ok(value)
    }

    /// Publishes the WHNF result after running a thunk-resolution write barrier.
    ///
    /// This is the single tree-walk hook for the future generational
    /// `Blackhole -> Forced(value)` write barrier. The active one-shot arena
    /// path uses [`DisabledThunkResolveBarrier`] through [`ForceGuard::finish`].
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::UnexpectedState`] if the thunk is no longer
    /// blackholed when the barrier runs. Returns
    /// [`ForceError::InvalidStateWord`] if the private atomic state word has an
    /// unsupported encoding. Returns any [`ForceError`] produced by `barrier`.
    pub fn finish_with_barrier(
        mut self,
        value: Value,
        barrier: &mut impl ThunkResolveBarrier,
    ) -> Result<Value, ForceError> {
        let value = self.thunk.publish_forced_with_barrier(value, barrier)?;
        self.active = false;
        Ok(value)
    }

    /// Aborts the claim and returns the thunk to [`ThunkState::Suspended`].
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::UnexpectedState`] if the thunk is no longer
    /// blackholed. Returns [`ForceError::InvalidStateWord`] if the private
    /// atomic state word has an unsupported encoding.
    pub fn abort(mut self) -> Result<(), ForceError> {
        self.thunk.abort_claim()?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ForceGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.thunk.abort_claim();
        }
    }
}

/// A hook that runs immediately before a forced thunk result is published.
///
/// Future daemon GC code uses this hook to record the single generational
/// old-to-young edge that can be created by resolving a thunk. Implementations
/// must not publish the thunk result themselves.
pub trait ThunkResolveBarrier {
    /// Runs the barrier before `value` is installed as the forced result.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError`] if the forced result must not be published.
    fn before_publish_forced(&mut self, value: Value) -> Result<(), ForceError>;
}

/// A thunk-resolution barrier used when no collector is active.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledThunkResolveBarrier;

impl ThunkResolveBarrier for DisabledThunkResolveBarrier {
    fn before_publish_forced(&mut self, _value: Value) -> Result<(), ForceError> {
        Ok(())
    }
}

/// A serial, safe thunk state/result cell.
///
/// The heap thunk object stores this cell beside its deferred work and captured
/// environments. The cached result is stored in an [`AtomicValueCell`] and is
/// published under the atomic state word (see the module docs), so the cell is
/// [`Send`] and [`Sync`] while keeping the serial
/// `Suspended -> Blackhole -> Forced` protocol unchanged.
#[cfg(not(feature = "candidate_c_value"))]
#[derive(Debug)]
pub struct ThunkCell {
    state: AtomicU64,
    result: AtomicValueCell,
}

/// A one-word serial thunk state/result cell for Candidate C.
///
/// Two invalid Candidate-C value encodings represent suspended and blackholed;
/// every other stored word is a validated forced result. The atomically
/// published result therefore carries the terminal state itself.
#[cfg(feature = "candidate_c_value")]
#[derive(Debug)]
pub struct ThunkCell {
    word: AtomicU64,
}

impl Default for ThunkCell {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ThunkCell {
    /// Produces an independent, state-faithful copy of this cell.
    ///
    /// Copies the current force-state word and, when the cell is `Forced`, its
    /// published result into a fresh cell with its own atomics. This is the
    /// independent-record copy used by the inline serial-cell deep clone
    /// (never-shared flat thunks) and by moving-GC relocation. Cells whose force
    /// state must stay identity-linked across record clones are shared through
    /// `Arc<ThunkCell>` and never route through here, so copying a mid-force
    /// `Blackhole` cell is unreachable in practice; were it to occur it would
    /// yield an independent blackholed cell rather than corrupt shared state.
    fn clone(&self) -> Self {
        #[cfg(feature = "candidate_c_value")]
        {
            return Self {
                word: AtomicU64::new(self.word.load(Ordering::Acquire)),
            };
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            let state = self.state.load(Ordering::Acquire);
            let result = match self.result.load() {
                Ok(Some(value)) => AtomicValueCell::filled(value),
                Ok(None) | Err(_) => AtomicValueCell::empty(),
            };
            Self {
                state: AtomicU64::new(state),
                result,
            }
        }
    }
}

impl ThunkCell {
    /// Creates a suspended thunk cell with no cached result.
    pub const fn new() -> Self {
        #[cfg(feature = "candidate_c_value")]
        {
            return Self {
                word: AtomicU64::new(COMPACT_SUSPENDED),
            };
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            Self {
                state: AtomicU64::new(SUSPENDED),
                result: AtomicValueCell::empty(),
            }
        }
    }

    /// Creates a forced thunk cell with an already relocated cached result.
    pub(crate) fn forced(value: Value) -> Self {
        #[cfg(feature = "candidate_c_value")]
        {
            return Self {
                word: AtomicU64::new(value.word().raw()),
            };
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            Self {
                state: AtomicU64::new(FORCED),
                result: AtomicValueCell::filled(value),
            }
        }
    }

    /// Returns the current thunk state using an acquire load.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if the private atomic state word
    /// somehow contains an unsupported encoding.
    pub fn state(&self) -> Result<ThunkState, ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            return Ok(match self.word.load(Ordering::Acquire) {
                COMPACT_SUSPENDED => ThunkState::Suspended,
                COMPACT_BLACKHOLE => ThunkState::Blackhole,
                _ => ThunkState::Forced,
            });
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            ThunkState::from_raw(self.state.load(Ordering::Acquire))
        }
    }

    /// Returns the cached value when the thunk is forced.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if the private atomic state word
    /// has an unsupported encoding. Returns [`ForceError::MissingForcedValue`]
    /// if the state says forced but no result has been installed.
    pub fn cached_value(&self) -> Result<Option<Value>, ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            let word = self.word.load(Ordering::Acquire);
            return match word {
                COMPACT_SUSPENDED | COMPACT_BLACKHOLE => Ok(None),
                _ => Ok(Some(compact_forced_value(word))),
            };
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            if self.state()? != ThunkState::Forced {
                return Ok(None);
            }
            self.read_result()?
                .map(Some)
                .ok_or(ForceError::MissingForcedValue)
        }
    }

    /// Reads the raw cached result cell.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::MissingForcedValue`] if the cell's stored words do
    /// not decode into a runtime value, which is unreachable through
    /// [`ThunkCell`]'s own publication path.
    #[cfg(not(feature = "candidate_c_value"))]
    fn read_result(&self) -> Result<Option<Value>, ForceError> {
        self.result
            .load()
            .map_err(|_| ForceError::MissingForcedValue)
    }

    /// Claims a suspended thunk for evaluation.
    ///
    /// On success, the caller receives a [`ForceGuard`], evaluates the thunk
    /// body, and then calls [`ForceGuard::finish`] with the result. Dropping or
    /// explicitly aborting the guard resets the cell to suspended for evaluator
    /// error unwinding. Re-entering a blackholed thunk is reported as Nix
    /// infinite recursion.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InfiniteRecursion`] if the thunk is already
    /// blackholed on this evaluator stack. Returns [`ForceError::InvalidStateWord`]
    /// if the private atomic state word has an unsupported encoding. Returns
    /// [`ForceError::MissingForcedValue`] if the state says forced but no result
    /// has been installed.
    pub fn begin_force(&self) -> Result<ForceClaim<'_>, ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            loop {
                let word = self.word.load(Ordering::Acquire);
                match word {
                    COMPACT_SUSPENDED => {
                        if self
                            .word
                            .compare_exchange(
                                COMPACT_SUSPENDED,
                                COMPACT_BLACKHOLE,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return Ok(ForceClaim::Claimed(ForceGuard {
                                thunk: self,
                                active: true,
                            }));
                        }
                    }
                    COMPACT_BLACKHOLE => return Err(ForceError::InfiniteRecursion),
                    _ => return Ok(ForceClaim::AlreadyForced(compact_forced_value(word))),
                }
            }
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            loop {
                match ThunkState::from_raw(self.state.load(Ordering::Acquire))? {
                    ThunkState::Suspended => {
                        if self
                            .state
                            .compare_exchange(
                                SUSPENDED,
                                BLACKHOLE,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return Ok(ForceClaim::Claimed(ForceGuard {
                                thunk: self,
                                active: true,
                            }));
                        }
                    }
                    ThunkState::Blackhole => return Err(ForceError::InfiniteRecursion),
                    ThunkState::Forced => {
                        let value = self.read_result()?.ok_or(ForceError::MissingForcedValue)?;
                        return Ok(ForceClaim::AlreadyForced(value));
                    }
                }
            }
        }
    }

    fn publish_forced_with_barrier(
        &self,
        value: Value,
        barrier: &mut impl ThunkResolveBarrier,
    ) -> Result<Value, ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            let actual = self.state()?;
            if actual != ThunkState::Blackhole {
                return Err(ForceError::UnexpectedState {
                    expected: ThunkState::Blackhole,
                    actual,
                });
            }
            barrier.before_publish_forced(value)?;
            self.word.store(value.word().raw(), Ordering::Release);
            return Ok(value);
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            let actual = self.state()?;
            if actual != ThunkState::Blackhole {
                return Err(ForceError::UnexpectedState {
                    expected: ThunkState::Blackhole,
                    actual,
                });
            }
            barrier.before_publish_forced(value)?;
            // The state word is not re-read after the barrier: reaching this method
            // means this thread holds the exclusive `Blackhole` claim minted by the
            // `begin_force` CAS, and the `Blackhole -> {Forced, Suspended}`
            // transitions are performed only by this guard's finish/abort on the
            // claiming thread. The cell's `state`/`result` fields are private and
            // their only mutators (`publish_forced_with_barrier`, `abort_claim`) are
            // module-private, so no `ThunkResolveBarrier` — which is contractually
            // forbidden from publishing and holds at most a shared `&ThunkCell` — can
            // move the state. It therefore remains `Blackhole` across the call above.
            self.result.store(value);
            self.state.store(FORCED, Ordering::Release);
            Ok(value)
        }
    }

    fn abort_claim(&self) -> Result<(), ForceError> {
        #[cfg(feature = "candidate_c_value")]
        {
            let actual = self.state()?;
            if actual != ThunkState::Blackhole {
                return Err(ForceError::UnexpectedState {
                    expected: ThunkState::Blackhole,
                    actual,
                });
            }
            self.word.store(COMPACT_SUSPENDED, Ordering::Release);
            return Ok(());
        }
        #[cfg(not(feature = "candidate_c_value"))]
        {
            let actual = self.state()?;
            if actual != ThunkState::Blackhole {
                return Err(ForceError::UnexpectedState {
                    expected: ThunkState::Blackhole,
                    actual,
                });
            }
            self.result.clear();
            self.state.store(SUSPENDED, Ordering::Release);
            Ok(())
        }
    }
}

/// Rebuilds a forced Candidate-C value from a word written by this cell.
#[cfg(feature = "candidate_c_value")]
#[inline]
#[allow(unsafe_code)]
fn compact_forced_value(word: u64) -> Value {
    debug_assert_ne!(word, COMPACT_SUSPENDED);
    debug_assert_ne!(word, COMPACT_BLACKHOLE);
    // SAFETY: the private word is initialized only to the two sentinels and
    // every non-sentinel write copies a validated Candidate-C `Value` intact.
    unsafe { Value::from_validated_raw_unchecked(word) }
}

/// A thunk forcing failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ForceError {
    /// A thunk was re-entered while it was already being forced on this stack.
    #[error("infinite recursion encountered while forcing thunk")]
    InfiniteRecursion,
    /// A forced state was observed without an installed cached value.
    #[error("forced thunk is missing its cached value")]
    MissingForcedValue,
    /// A transition was attempted from the wrong serial state.
    #[error("expected thunk state {expected:?}, got {actual:?}")]
    UnexpectedState {
        /// The state required by the attempted transition.
        expected: ThunkState,
        /// The state that was observed.
        actual: ThunkState,
    },
    /// The atomic state word contained an unsupported encoding.
    #[error("invalid thunk state word {raw}")]
    InvalidStateWord {
        /// The unsupported raw state word.
        raw: u64,
    },
    /// A thunk-resolution write barrier rejected publishing the forced result.
    #[error("thunk resolve write barrier rejected forced result: {reason}")]
    WriteBarrierRejected {
        /// The reason supplied by the write-barrier hook.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "candidate_c_value", target_pointer_width = "64"))]
    #[test]
    fn candidate_c_thunk_cell_is_one_word() {
        assert_eq!(std::mem::size_of::<ThunkCell>(), 8);
        assert!(
            crate::value::compressed::CompressedValueWord::from_raw(COMPACT_SUSPENDED).is_err()
        );
        assert!(
            crate::value::compressed::CompressedValueWord::from_raw(COMPACT_BLACKHOLE).is_err()
        );
    }

    fn assert_int(value: Value, expected: i64) {
        assert_eq!(value.as_int(), Ok(expected));
    }

    #[test]
    fn states_roundtrip_raw_words() {
        assert_eq!(ThunkState::from_raw(SUSPENDED), Ok(ThunkState::Suspended));
        assert_eq!(ThunkState::from_raw(BLACKHOLE), Ok(ThunkState::Blackhole));
        assert_eq!(ThunkState::from_raw(FORCED), Ok(ThunkState::Forced));
        assert_eq!(
            ThunkState::from_raw(99),
            Err(ForceError::InvalidStateWord { raw: 99 })
        );
        assert_eq!(ThunkState::Forced.as_u64(), FORCED);
    }

    #[test]
    fn new_thunk_starts_suspended_without_cached_value() {
        let thunk = ThunkCell::new();

        assert_eq!(thunk.state(), Ok(ThunkState::Suspended));
        assert!(matches!(thunk.cached_value(), Ok(None)));
    }

    #[test]
    fn begin_force_claims_suspended_thunk_and_detects_blackhole() {
        let thunk = ThunkCell::new();

        let claim = thunk.begin_force().expect("claim succeeds");
        let ForceClaim::Claimed(guard) = claim else {
            panic!("suspended thunk should be claimed");
        };
        assert_eq!(thunk.state(), Ok(ThunkState::Blackhole));
        assert!(matches!(
            thunk.begin_force(),
            Err(ForceError::InfiniteRecursion)
        ));
        guard.abort().expect("claim aborts");
        assert_eq!(thunk.state(), Ok(ThunkState::Suspended));
    }

    #[test]
    fn finish_force_publishes_cached_value() {
        let thunk = ThunkCell::new();
        let claim = thunk.begin_force().expect("claim succeeds");
        let ForceClaim::Claimed(guard) = claim else {
            panic!("suspended thunk should be claimed");
        };

        let value = guard.finish(Value::int(42)).expect("finish succeeds");

        assert_int(value, 42);
        assert_eq!(thunk.state(), Ok(ThunkState::Forced));
        assert_int(
            thunk
                .cached_value()
                .expect("cache is valid")
                .expect("forced"),
            42,
        );
    }

    #[derive(Debug)]
    struct ObservingBarrier<'a> {
        thunk: &'a ThunkCell,
        observed_state: Option<ThunkState>,
        observed_value: Option<Value>,
    }

    impl ThunkResolveBarrier for ObservingBarrier<'_> {
        fn before_publish_forced(&mut self, value: Value) -> Result<(), ForceError> {
            self.observed_state = Some(self.thunk.state()?);
            self.observed_value = Some(value);
            Ok(())
        }
    }

    #[test]
    fn finish_with_barrier_runs_before_forced_value_is_published() {
        let thunk = ThunkCell::new();
        let claim = thunk.begin_force().expect("claim succeeds");
        let ForceClaim::Claimed(guard) = claim else {
            panic!("suspended thunk should be claimed");
        };
        let mut barrier = ObservingBarrier {
            thunk: &thunk,
            observed_state: None,
            observed_value: None,
        };

        let value = guard
            .finish_with_barrier(Value::int(42), &mut barrier)
            .expect("finish succeeds");

        assert_int(value, 42);
        assert_eq!(barrier.observed_state, Some(ThunkState::Blackhole));
        assert_int(barrier.observed_value.expect("barrier saw value"), 42);
        assert_eq!(thunk.state(), Ok(ThunkState::Forced));
    }

    #[derive(Debug)]
    struct RejectingBarrier;

    impl ThunkResolveBarrier for RejectingBarrier {
        fn before_publish_forced(&mut self, _value: Value) -> Result<(), ForceError> {
            Err(ForceError::WriteBarrierRejected { reason: "test" })
        }
    }

    #[test]
    fn rejected_finish_barrier_aborts_claim_without_publishing_value() {
        let thunk = ThunkCell::new();
        let claim = thunk.begin_force().expect("claim succeeds");
        let ForceClaim::Claimed(guard) = claim else {
            panic!("suspended thunk should be claimed");
        };
        let mut barrier = RejectingBarrier;

        let error = guard
            .finish_with_barrier(Value::int(42), &mut barrier)
            .expect_err("barrier rejects publish");

        assert_eq!(error, ForceError::WriteBarrierRejected { reason: "test" });
        assert_eq!(thunk.state(), Ok(ThunkState::Suspended));
        assert!(matches!(thunk.cached_value(), Ok(None)));
    }

    #[test]
    fn already_forced_thunk_returns_cached_value_without_reclaiming() {
        let thunk = ThunkCell::new();
        let ForceClaim::Claimed(guard) = thunk.begin_force().expect("claim succeeds") else {
            panic!("suspended thunk should be claimed");
        };
        guard.finish(Value::int(7)).expect("initial force succeeds");

        let claim = thunk
            .begin_force()
            .expect("forced thunk returns cached value");

        let ForceClaim::AlreadyForced(value) = claim else {
            panic!("forced thunk should not be claimed again");
        };
        assert_int(value, 7);
        assert_eq!(thunk.state(), Ok(ThunkState::Forced));
    }

    #[test]
    fn abort_force_resets_suspended_state() {
        let thunk = ThunkCell::new();
        let ForceClaim::Claimed(guard) = thunk.begin_force().expect("claim succeeds") else {
            panic!("suspended thunk should be claimed");
        };

        guard.abort().expect("abort succeeds");

        assert_eq!(thunk.state(), Ok(ThunkState::Suspended));
        assert!(matches!(thunk.cached_value(), Ok(None)));
    }

    #[test]
    fn dropped_claim_resets_suspended_state_for_error_unwind() {
        let thunk = ThunkCell::new();
        {
            let ForceClaim::Claimed(_guard) = thunk.begin_force().expect("claim succeeds") else {
                panic!("suspended thunk should be claimed");
            };
            assert_eq!(thunk.state(), Ok(ThunkState::Blackhole));
        }

        assert_eq!(thunk.state(), Ok(ThunkState::Suspended));
        let ForceClaim::Claimed(guard) = thunk.begin_force().expect("claim succeeds again") else {
            panic!("aborted thunk should be claimable again");
        };
        guard.finish(Value::int(5)).expect("finish succeeds");
        assert_int(
            thunk
                .cached_value()
                .expect("cache is valid")
                .expect("forced"),
            5,
        );
    }
}
