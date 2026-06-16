//! Serial thunk state machine for the tree-walk oracle.
//!
//! The Phase-1 evaluator runs on one thread, but the thunk state word is atomic
//! from the start so the later parallel forcing protocol can extend the same
//! representation. This module implements only the serial subset:
//! `Suspended -> Blackhole -> Forced`.

use std::cell::Cell;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::value::Value;

const SUSPENDED: u64 = 0;
const BLACKHOLE: u64 = 1;
const FORCED: u64 = 2;

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
        let value = self.thunk.publish_forced(value)?;
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

/// A serial, safe thunk state/result cell.
///
/// This is not yet the full heap `Thunk { state, code, env }` object. It is the
/// safe state and cached-result core that the tree-walk oracle will embed in
/// heap thunks once environments and compiled thunk bodies exist. The cached
/// result uses [`Cell`] and is intentionally single-threaded; the atomic state
/// word exists now to preserve the future representation boundary.
#[derive(Debug)]
pub struct ThunkCell {
    state: AtomicU64,
    result: Cell<Option<Value>>,
}

impl Default for ThunkCell {
    fn default() -> Self {
        Self::new()
    }
}

impl ThunkCell {
    /// Creates a suspended thunk cell with no cached result.
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(SUSPENDED),
            result: Cell::new(None),
        }
    }

    /// Returns the current thunk state using an acquire load.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if the private atomic state word
    /// somehow contains an unsupported encoding.
    pub fn state(&self) -> Result<ThunkState, ForceError> {
        ThunkState::from_raw(self.state.load(Ordering::Acquire))
    }

    /// Returns the cached value when the thunk is forced.
    ///
    /// # Errors
    ///
    /// Returns [`ForceError::InvalidStateWord`] if the private atomic state word
    /// has an unsupported encoding. Returns [`ForceError::MissingForcedValue`]
    /// if the state says forced but no result has been installed.
    pub fn cached_value(&self) -> Result<Option<Value>, ForceError> {
        if self.state()? != ThunkState::Forced {
            return Ok(None);
        }
        self.result
            .get()
            .map(Some)
            .ok_or(ForceError::MissingForcedValue)
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
        loop {
            match ThunkState::from_raw(self.state.load(Ordering::Acquire))? {
                ThunkState::Suspended => {
                    if self
                        .state
                        .compare_exchange(SUSPENDED, BLACKHOLE, Ordering::AcqRel, Ordering::Acquire)
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
                    let value = self.result.get().ok_or(ForceError::MissingForcedValue)?;
                    return Ok(ForceClaim::AlreadyForced(value));
                }
            }
        }
    }

    fn publish_forced(&self, value: Value) -> Result<Value, ForceError> {
        let actual = self.state()?;
        if actual != ThunkState::Blackhole {
            return Err(ForceError::UnexpectedState {
                expected: ThunkState::Blackhole,
                actual,
            });
        }
        self.result.set(Some(value));
        self.state.store(FORCED, Ordering::Release);
        Ok(value)
    }

    fn abort_claim(&self) -> Result<(), ForceError> {
        let actual = self.state()?;
        if actual != ThunkState::Blackhole {
            return Err(ForceError::UnexpectedState {
                expected: ThunkState::Blackhole,
                actual,
            });
        }
        self.result.set(None);
        self.state.store(SUSPENDED, Ordering::Release);
        Ok(())
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
