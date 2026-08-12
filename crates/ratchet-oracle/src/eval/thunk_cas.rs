//! Parallel thunk compare-and-swap state-word precursor.
//!
//! This module owns the safe Phase 3.5 model for the RFC-0007 L2 thunk state
//! machine. It does not replace the serial tree-walk thunk cell in
//! [`super::thunk`]. Instead, it pins the atomic word encoding and transition
//! protocol that later evaluator wiring, waiter lists, and loom models build
//! on: `Suspended`, owner-tagged `Pending`, owner-tagged `Awaited`, `Forced`,
//! and `Failed`.
//!
//! The owner id carried by `Pending` and `Awaited` is the blackhole boundary:
//! re-entering the same claimed thunk from the owning worker is a cycle, while
//! observing a different owner is ordinary cross-worker contention.
//!
//! The await marker here is not a complete no-lost-wakeup protocol. Future
//! waiter parking must pair the state transition with waiter-list registration,
//! a terminal-state recheck, and owner wakeup.

use std::{
    marker::PhantomData,
    num::NonZeroU64,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use thiserror::Error;

const TAG_BITS: u64 = 3;
const TAG_MASK: u64 = (1 << TAG_BITS) - 1;
const SUSPENDED_TAG: u64 = 0;
const FORCED_TAG: u64 = 1;
const FAILED_TAG: u64 = 2;
const PENDING_TAG: u64 = 3;
const AWAITED_TAG: u64 = 4;

/// Ordering used when observing the thunk state word.
pub const PARALLEL_THUNK_STATE_LOAD_ORDERING: Ordering = Ordering::Acquire;
/// Success ordering for `Suspended -> Pending(owner)` claim CAS.
pub const PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING: Ordering = Ordering::AcqRel;
/// Failure ordering for `Suspended -> Pending(owner)` claim CAS.
pub const PARALLEL_THUNK_CLAIM_FAILURE_ORDERING: Ordering = Ordering::Acquire;
/// Success ordering for `Pending(owner) -> Awaited(owner)` waiter-marker CAS.
pub const PARALLEL_THUNK_AWAIT_MARK_SUCCESS_ORDERING: Ordering = Ordering::AcqRel;
/// Failure ordering for `Pending(owner) -> Awaited(owner)` waiter-marker CAS.
pub const PARALLEL_THUNK_AWAIT_MARK_FAILURE_ORDERING: Ordering = Ordering::Acquire;
/// Success ordering for owner publication to a terminal state.
pub const PARALLEL_THUNK_TERMINAL_PUBLISH_SUCCESS_ORDERING: Ordering = Ordering::Release;
/// Failure ordering for owner publication to a terminal state.
pub const PARALLEL_THUNK_TERMINAL_PUBLISH_FAILURE_ORDERING: Ordering = Ordering::Acquire;

const PARALLEL_THUNK_MEMORY_ORDERING_REQUIREMENTS: [ParallelThunkMemoryOrderingRequirement; 7] = [
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::StateLoad,
        Ordering::Acquire,
        PARALLEL_THUNK_STATE_LOAD_ORDERING,
        "state loads must acquire terminal payloads published before release terminal stores",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::ClaimSuccess,
        Ordering::AcqRel,
        PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING,
        "claim CAS must acquire prior state and release ownership before body evaluation",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::ClaimFailure,
        Ordering::Acquire,
        PARALLEL_THUNK_CLAIM_FAILURE_ORDERING,
        "failed claim CAS must acquire the observed owner or terminal state",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::AwaitMarkSuccess,
        Ordering::AcqRel,
        PARALLEL_THUNK_AWAIT_MARK_SUCCESS_ORDERING,
        "await marker CAS must acquire owner state and release waiter visibility",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::AwaitMarkFailure,
        Ordering::Acquire,
        PARALLEL_THUNK_AWAIT_MARK_FAILURE_ORDERING,
        "failed await marker CAS must acquire the observed terminal or owner state",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::TerminalPublishSuccess,
        Ordering::Release,
        PARALLEL_THUNK_TERMINAL_PUBLISH_SUCCESS_ORDERING,
        "terminal publication must release the forced value or captured failure payload",
    ),
    ParallelThunkMemoryOrderingRequirement::new(
        ParallelThunkMemoryOrderingRole::TerminalPublishFailure,
        Ordering::Acquire,
        PARALLEL_THUNK_TERMINAL_PUBLISH_FAILURE_ORDERING,
        "failed terminal publication must acquire the state that defeated the owner",
    ),
];

/// Validates and returns the current parallel thunk memory-ordering contract.
///
/// This audit is intentionally narrower than the final loom/Miri gate. It pins
/// the atomic orderings used by the safe state-word precursor so future loom
/// models and evaluator integration have a concrete contract to check.
///
/// # Errors
///
/// Returns [`ParallelThunkMemoryOrderingError`] if one of the named ordering
/// constants no longer matches the required RFC-0007 acquire/release contract.
pub fn validate_parallel_thunk_memory_ordering()
-> Result<ParallelThunkMemoryOrderingAudit, ParallelThunkMemoryOrderingError> {
    for requirement in PARALLEL_THUNK_MEMORY_ORDERING_REQUIREMENTS {
        if requirement.actual_ordering != requirement.expected_ordering {
            return Err(ParallelThunkMemoryOrderingError::Mismatch {
                role: requirement.role,
                expected_ordering: requirement.expected_ordering,
                actual_ordering: requirement.actual_ordering,
            });
        }
    }
    Ok(ParallelThunkMemoryOrderingAudit {
        requirements: &PARALLEL_THUNK_MEMORY_ORDERING_REQUIREMENTS,
    })
}

/// The largest worker id that can be encoded in a thunk state word.
pub const PARALLEL_THUNK_MAX_WORKER_ID: u64 = u64::MAX >> TAG_BITS;

/// One atomic operation role covered by the parallel thunk ordering audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParallelThunkMemoryOrderingRole {
    /// The acquire load used to observe the state word.
    StateLoad,
    /// The success ordering for a suspended-to-pending claim CAS.
    ClaimSuccess,
    /// The failure ordering for a suspended-to-pending claim CAS.
    ClaimFailure,
    /// The success ordering for a pending-to-awaited marker CAS.
    AwaitMarkSuccess,
    /// The failure ordering for a pending-to-awaited marker CAS.
    AwaitMarkFailure,
    /// The success ordering for publishing a terminal state.
    TerminalPublishSuccess,
    /// The failure ordering for publishing a terminal state.
    TerminalPublishFailure,
}

/// One expected-versus-actual memory-ordering requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelThunkMemoryOrderingRequirement {
    role: ParallelThunkMemoryOrderingRole,
    expected_ordering: Ordering,
    actual_ordering: Ordering,
    rationale: &'static str,
}

impl ParallelThunkMemoryOrderingRequirement {
    const fn new(
        role: ParallelThunkMemoryOrderingRole,
        expected_ordering: Ordering,
        actual_ordering: Ordering,
        rationale: &'static str,
    ) -> Self {
        Self {
            role,
            expected_ordering,
            actual_ordering,
            rationale,
        }
    }

    /// Returns the atomic operation role.
    pub const fn role(self) -> ParallelThunkMemoryOrderingRole {
        self.role
    }

    /// Returns the required ordering for this role.
    pub const fn expected_ordering(self) -> Ordering {
        self.expected_ordering
    }

    /// Returns the ordering currently used by the implementation.
    pub const fn actual_ordering(self) -> Ordering {
        self.actual_ordering
    }

    /// Returns why this ordering is required.
    pub const fn rationale(self) -> &'static str {
        self.rationale
    }
}

/// A successful memory-ordering audit report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelThunkMemoryOrderingAudit {
    requirements: &'static [ParallelThunkMemoryOrderingRequirement],
}

impl ParallelThunkMemoryOrderingAudit {
    /// Returns all validated requirements.
    pub const fn requirements(self) -> &'static [ParallelThunkMemoryOrderingRequirement] {
        self.requirements
    }

    /// Returns the number of validated requirements.
    pub const fn requirement_count(self) -> usize {
        self.requirements.len()
    }

    /// Returns the actual ordering for `role`, if it is audited.
    pub fn ordering_for(self, role: ParallelThunkMemoryOrderingRole) -> Option<Ordering> {
        self.requirements
            .iter()
            .find(|requirement| requirement.role == role)
            .map(|requirement| requirement.actual_ordering)
    }
}

/// A non-zero worker or fiber id encoded in a parallel thunk state word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParallelThunkWorkerId(NonZeroU64);

impl ParallelThunkWorkerId {
    /// The deterministic single-worker id used before scheduler integration.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Creates a worker id that can be stored in a thunk state word.
    ///
    /// Returns [`None`] when `raw` is zero or exceeds
    /// [`PARALLEL_THUNK_MAX_WORKER_ID`].
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 || raw > PARALLEL_THUNK_MAX_WORKER_ID {
            return None;
        }

        match NonZeroU64::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// Returns the raw non-zero worker id.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// The decoded state stored in a parallel thunk state word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParallelThunkState {
    /// The thunk has not been evaluated and can be claimed by one worker.
    Suspended,
    /// One worker is evaluating the thunk and no waiter has been recorded.
    Pending {
        /// The worker that won the suspended-to-pending claim CAS.
        owner: ParallelThunkWorkerId,
    },
    /// One worker is evaluating the thunk and at least one waiter arrived.
    Awaited {
        /// The worker that owns evaluation of the thunk body.
        owner: ParallelThunkWorkerId,
    },
    /// The thunk result has been published.
    Forced,
    /// The thunk body failed and the captured error should be re-raised.
    Failed,
}

impl ParallelThunkState {
    /// Returns the raw `u64` state-word encoding.
    pub const fn as_raw(self) -> u64 {
        match self {
            Self::Suspended => SUSPENDED_TAG,
            Self::Forced => FORCED_TAG,
            Self::Failed => FAILED_TAG,
            Self::Pending { owner } => encode_owned_state(PENDING_TAG, owner),
            Self::Awaited { owner } => encode_owned_state(AWAITED_TAG, owner),
        }
    }

    /// Decodes a raw thunk state word.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::InvalidStateWord`] when `raw` does
    /// not encode a supported terminal or owner-tagged state.
    pub const fn from_raw(raw: u64) -> Result<Self, ParallelThunkStateError> {
        match raw & TAG_MASK {
            SUSPENDED_TAG if raw == SUSPENDED_TAG => Ok(Self::Suspended),
            FORCED_TAG if raw == FORCED_TAG => Ok(Self::Forced),
            FAILED_TAG if raw == FAILED_TAG => Ok(Self::Failed),
            PENDING_TAG => match decode_worker(raw) {
                Some(owner) => Ok(Self::Pending { owner }),
                None => Err(ParallelThunkStateError::InvalidStateWord { raw }),
            },
            AWAITED_TAG => match decode_worker(raw) {
                Some(owner) => Ok(Self::Awaited { owner }),
                None => Err(ParallelThunkStateError::InvalidStateWord { raw }),
            },
            _ => Err(ParallelThunkStateError::InvalidStateWord { raw }),
        }
    }

    /// Returns the owner when this is an owner-tagged claimed state.
    pub const fn owner(self) -> Option<ParallelThunkWorkerId> {
        match self {
            Self::Pending { owner } | Self::Awaited { owner } => Some(owner),
            Self::Suspended | Self::Forced | Self::Failed => None,
        }
    }
}

const fn encode_owned_state(tag: u64, owner: ParallelThunkWorkerId) -> u64 {
    (owner.get() << TAG_BITS) | tag
}

const fn decode_worker(raw: u64) -> Option<ParallelThunkWorkerId> {
    ParallelThunkWorkerId::new(raw >> TAG_BITS)
}

/// An atomic parallel thunk state word.
///
/// This type contains only the synchronization word. The forced value, captured
/// error, waiter list, and evaluator integration remain future work.
#[derive(Debug)]
pub struct ParallelThunkStateWord {
    state: AtomicU64,
}

impl Default for ParallelThunkStateWord {
    fn default() -> Self {
        Self::new()
    }
}

impl ParallelThunkStateWord {
    /// Creates a suspended state word.
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(SUSPENDED_TAG),
        }
    }

    /// Creates a forced state word for relocating an already-terminal payload.
    pub(crate) const fn forced_for_relocation() -> Self {
        Self {
            state: AtomicU64::new(FORCED_TAG),
        }
    }

    /// Creates a failed state word for relocating an already-terminal payload.
    pub(crate) const fn failed_for_relocation() -> Self {
        Self {
            state: AtomicU64::new(FAILED_TAG),
        }
    }

    /// Loads and decodes the current state with acquire ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::InvalidStateWord`] if the private
    /// atomic word contains an unsupported encoding.
    pub fn state(&self) -> Result<ParallelThunkState, ParallelThunkStateError> {
        ParallelThunkState::from_raw(self.state.load(PARALLEL_THUNK_STATE_LOAD_ORDERING))
    }

    /// Attempts to claim the thunk for `worker`.
    ///
    /// A suspended thunk is claimed with a single
    /// `Suspended -> Pending(worker)` compare-and-swap. Owner-tagged states
    /// observed for the same worker are reported as same-worker cycle
    /// detection; owner-tagged states for a different worker are ordinary
    /// contention and should feed the wait-or-steal path.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::InvalidStateWord`] if the private
    /// atomic word contains an unsupported encoding.
    pub fn try_claim(
        &self,
        worker: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkClaim<'_>, ParallelThunkStateError> {
        loop {
            match self.state()? {
                ParallelThunkState::Suspended => {
                    let claimed = ParallelThunkState::Pending { owner: worker }.as_raw();
                    if self
                        .state
                        .compare_exchange(
                            SUSPENDED_TAG,
                            claimed,
                            PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING,
                            PARALLEL_THUNK_CLAIM_FAILURE_ORDERING,
                        )
                        .is_ok()
                    {
                        return Ok(ParallelThunkClaim::Claimed(ParallelThunkClaimGuard {
                            state: self,
                            owner: worker,
                            active: true,
                            _not_send: PhantomData,
                        }));
                    }
                }
                ParallelThunkState::Pending { owner } if owner == worker => {
                    return Ok(ParallelThunkClaim::SelfCycle { owner });
                }
                ParallelThunkState::Pending { owner } => {
                    return Ok(ParallelThunkClaim::ForeignPending { owner });
                }
                ParallelThunkState::Awaited { owner } if owner == worker => {
                    return Ok(ParallelThunkClaim::SelfCycle { owner });
                }
                ParallelThunkState::Awaited { owner } => {
                    return Ok(ParallelThunkClaim::ForeignAwaited { owner });
                }
                ParallelThunkState::Forced => return Ok(ParallelThunkClaim::AlreadyForced),
                ParallelThunkState::Failed => return Ok(ParallelThunkClaim::AlreadyFailed),
            }
        }
    }

    /// Marks a foreign claimed thunk as awaited by `waiter`.
    ///
    /// This is only the state-word contention marker for the future
    /// wait-or-steal path. It does not park the worker, install a waiter-list
    /// node, or prove that a later park cannot miss a wakeup.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::InvalidStateWord`] if the private
    /// atomic word contains an unsupported encoding. Returns
    /// [`ParallelThunkStateError::UnexpectedState`] if a just-marked state word
    /// is no longer awaited by the expected owner and has not reached a terminal
    /// state.
    pub fn mark_awaited(
        &self,
        waiter: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkAwait, ParallelThunkStateError> {
        loop {
            match self.state()? {
                ParallelThunkState::Suspended => return Ok(ParallelThunkAwait::Unclaimed),
                ParallelThunkState::Pending { owner } if owner == waiter => {
                    return Ok(ParallelThunkAwait::SelfCycle { owner });
                }
                ParallelThunkState::Pending { owner } => {
                    let pending = ParallelThunkState::Pending { owner }.as_raw();
                    let awaited = ParallelThunkState::Awaited { owner }.as_raw();
                    if self
                        .state
                        .compare_exchange(
                            pending,
                            awaited,
                            PARALLEL_THUNK_AWAIT_MARK_SUCCESS_ORDERING,
                            PARALLEL_THUNK_AWAIT_MARK_FAILURE_ORDERING,
                        )
                        .is_ok()
                    {
                        return self.observe_awaited_after_mark(owner);
                    }
                }
                ParallelThunkState::Awaited { owner } if owner == waiter => {
                    return Ok(ParallelThunkAwait::SelfCycle { owner });
                }
                ParallelThunkState::Awaited { owner } => {
                    return Ok(ParallelThunkAwait::Awaited {
                        owner,
                        newly_marked: false,
                    });
                }
                ParallelThunkState::Forced => return Ok(ParallelThunkAwait::AlreadyForced),
                ParallelThunkState::Failed => return Ok(ParallelThunkAwait::AlreadyFailed),
            }
        }
    }

    fn observe_awaited_after_mark(
        &self,
        owner: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkAwait, ParallelThunkStateError> {
        match self.state()? {
            ParallelThunkState::Awaited {
                owner: actual_owner,
            } if actual_owner == owner => Ok(ParallelThunkAwait::Awaited {
                owner,
                newly_marked: true,
            }),
            ParallelThunkState::Forced => Ok(ParallelThunkAwait::AlreadyForced),
            ParallelThunkState::Failed => Ok(ParallelThunkAwait::AlreadyFailed),
            actual => Err(ParallelThunkStateError::UnexpectedState {
                expected_owner: owner,
                actual,
            }),
        }
    }

    fn publish_forced(
        &self,
        owner: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkPublish, ParallelThunkStateError> {
        self.publish_terminal(owner, ParallelThunkTerminalState::Forced)
    }

    fn publish_failed(
        &self,
        owner: ParallelThunkWorkerId,
    ) -> Result<ParallelThunkPublish, ParallelThunkStateError> {
        self.publish_terminal(owner, ParallelThunkTerminalState::Failed)
    }

    fn publish_terminal(
        &self,
        owner: ParallelThunkWorkerId,
        terminal_state: ParallelThunkTerminalState,
    ) -> Result<ParallelThunkPublish, ParallelThunkStateError> {
        loop {
            let actual = self.state()?;
            let had_waiters = match actual {
                ParallelThunkState::Pending {
                    owner: actual_owner,
                } if actual_owner == owner => false,
                ParallelThunkState::Awaited {
                    owner: actual_owner,
                } if actual_owner == owner => true,
                _ => {
                    return Err(ParallelThunkStateError::UnexpectedState {
                        expected_owner: owner,
                        actual,
                    });
                }
            };

            if self
                .state
                .compare_exchange(
                    actual.as_raw(),
                    terminal_state.as_state().as_raw(),
                    PARALLEL_THUNK_TERMINAL_PUBLISH_SUCCESS_ORDERING,
                    PARALLEL_THUNK_TERMINAL_PUBLISH_FAILURE_ORDERING,
                )
                .is_ok()
            {
                return Ok(ParallelThunkPublish {
                    owner,
                    terminal_state,
                    had_waiters,
                });
            }
        }
    }
}

/// Result of trying to claim a parallel thunk.
#[must_use = "a claimed parallel thunk must be published as forced or failed"]
#[derive(Debug)]
pub enum ParallelThunkClaim<'a> {
    /// The caller won the suspended-to-pending CAS and owns evaluation.
    Claimed(ParallelThunkClaimGuard<'a>),
    /// The thunk has already published a value.
    AlreadyForced,
    /// The thunk has already published an error.
    AlreadyFailed,
    /// The same worker re-entered a thunk it already owns.
    SelfCycle {
        /// The worker that owns the recursive force.
        owner: ParallelThunkWorkerId,
    },
    /// Another worker is forcing the thunk and no waiter has been marked.
    ForeignPending {
        /// The worker that owns evaluation of the thunk body.
        owner: ParallelThunkWorkerId,
    },
    /// Another worker is forcing the thunk and at least one waiter exists.
    ForeignAwaited {
        /// The worker that owns evaluation of the thunk body.
        owner: ParallelThunkWorkerId,
    },
}

/// A live claim on a parallel thunk state word.
///
/// Dropping an active guard publishes [`ParallelThunkTerminalState::Failed`] so
/// safe unwinding cannot leave the state word stuck in `Pending` or `Awaited`.
/// The later evaluator integration will pair that state with a captured error
/// payload before waiters can re-raise it.
///
/// The guard is worker-affine and intentionally not [`Send`]:
///
/// ```compile_fail
/// use ratchet_oracle::eval::ParallelThunkClaimGuard;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<ParallelThunkClaimGuard<'static>>();
/// ```
#[must_use = "publish the claimed parallel thunk as forced or failed"]
#[derive(Debug)]
pub struct ParallelThunkClaimGuard<'a> {
    state: &'a ParallelThunkStateWord,
    owner: ParallelThunkWorkerId,
    active: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl ParallelThunkClaimGuard<'_> {
    /// Returns the worker that owns this claim.
    pub const fn owner(&self) -> ParallelThunkWorkerId {
        self.owner
    }

    /// Publishes a successful thunk result.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::UnexpectedState`] if the state word
    /// is no longer pending or awaited for this guard's owner. Returns
    /// [`ParallelThunkStateError::InvalidStateWord`] if the private atomic word
    /// contains an unsupported encoding.
    pub fn publish_forced(mut self) -> Result<ParallelThunkPublish, ParallelThunkStateError> {
        let report = self.state.publish_forced(self.owner)?;
        self.active = false;
        Ok(report)
    }

    /// Publishes a failed thunk result.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError::UnexpectedState`] if the state word
    /// is no longer pending or awaited for this guard's owner. Returns
    /// [`ParallelThunkStateError::InvalidStateWord`] if the private atomic word
    /// contains an unsupported encoding.
    pub fn publish_failed(mut self) -> Result<ParallelThunkPublish, ParallelThunkStateError> {
        let report = self.state.publish_failed(self.owner)?;
        self.active = false;
        Ok(report)
    }
}

impl Drop for ParallelThunkClaimGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.state.publish_failed(self.owner);
        }
    }
}

/// Result of marking a claimed thunk as awaited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelThunkAwait {
    /// No worker owns the thunk yet.
    Unclaimed,
    /// The thunk has already published a value.
    AlreadyForced,
    /// The thunk has already published an error.
    AlreadyFailed,
    /// The waiter is the same worker that owns the thunk, so this is a cycle.
    SelfCycle {
        /// The worker that owns the recursive force.
        owner: ParallelThunkWorkerId,
    },
    /// The state word records that another worker owns the thunk.
    ///
    /// This does not by itself make it safe to park; the future waiter-list
    /// protocol must still register the waiter and recheck terminal states.
    Awaited {
        /// The worker that owns evaluation of the thunk body.
        owner: ParallelThunkWorkerId,
        /// Whether this call changed the state from `Pending` to `Awaited`.
        newly_marked: bool,
    },
}

/// A terminal state that can be published by a claim owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParallelThunkTerminalState {
    /// The thunk body produced a value.
    Forced,
    /// The thunk body produced an error.
    Failed,
}

impl ParallelThunkTerminalState {
    const fn as_state(self) -> ParallelThunkState {
        match self {
            Self::Forced => ParallelThunkState::Forced,
            Self::Failed => ParallelThunkState::Failed,
        }
    }
}

/// Metadata returned when a claim owner publishes a terminal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParallelThunkPublish {
    owner: ParallelThunkWorkerId,
    terminal_state: ParallelThunkTerminalState,
    had_waiters: bool,
}

impl ParallelThunkPublish {
    /// Returns the worker that published the terminal state.
    pub const fn owner(self) -> ParallelThunkWorkerId {
        self.owner
    }

    /// Returns the terminal state that was published.
    pub const fn terminal_state(self) -> ParallelThunkTerminalState {
        self.terminal_state
    }

    /// Returns whether the state had reached `Awaited` before publication.
    pub const fn had_waiters(self) -> bool {
        self.had_waiters
    }
}

/// A failure while decoding or transitioning a parallel thunk state word.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkStateError {
    /// The atomic state word contained an unsupported encoding.
    #[error("invalid parallel thunk state word {raw}")]
    InvalidStateWord {
        /// The unsupported raw state word.
        raw: u64,
    },
    /// A transition was attempted from the wrong claimed state.
    #[error("expected parallel thunk owner {expected_owner:?}, got state {actual:?}")]
    UnexpectedState {
        /// The owner required by the live claim.
        expected_owner: ParallelThunkWorkerId,
        /// The state that was observed.
        actual: ParallelThunkState,
    },
}

/// A failure while validating the parallel thunk memory-ordering contract.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ParallelThunkMemoryOrderingError {
    /// A named operation no longer uses the required ordering.
    #[error(
        "parallel thunk memory ordering for {role:?} is {actual_ordering:?}, expected {expected_ordering:?}"
    )]
    Mismatch {
        /// The atomic operation role that failed validation.
        role: ParallelThunkMemoryOrderingRole,
        /// The ordering required by the audit contract.
        expected_ordering: Ordering,
        /// The ordering currently configured for the operation.
        actual_ordering: Ordering,
    },
}

#[cfg(test)]
mod loom_model_tests;
#[cfg(test)]
mod tests;
