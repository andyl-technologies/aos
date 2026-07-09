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
mod tests {
    use std::{
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
        },
        thread,
    };

    use super::*;

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    #[test]
    fn memory_ordering_audit_pins_state_word_orderings() {
        let audit =
            validate_parallel_thunk_memory_ordering().expect("memory ordering audit succeeds");

        assert_eq!(audit.requirement_count(), 7);
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::StateLoad),
            Some(Ordering::Acquire)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::ClaimSuccess),
            Some(Ordering::AcqRel)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::ClaimFailure),
            Some(Ordering::Acquire)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::AwaitMarkSuccess),
            Some(Ordering::AcqRel)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::AwaitMarkFailure),
            Some(Ordering::Acquire)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::TerminalPublishSuccess),
            Some(Ordering::Release)
        );
        assert_eq!(
            audit.ordering_for(ParallelThunkMemoryOrderingRole::TerminalPublishFailure),
            Some(Ordering::Acquire)
        );
        assert!(
            audit
                .requirements()
                .iter()
                .all(|requirement| requirement.expected_ordering()
                    == requirement.actual_ordering()
                    && !requirement.rationale().is_empty())
        );
    }

    #[test]
    fn worker_ids_reject_zero_and_reserved_overflow() {
        assert_eq!(ParallelThunkWorkerId::FIRST.get(), 1);
        assert_eq!(
            ParallelThunkWorkerId::new(1),
            Some(ParallelThunkWorkerId::FIRST)
        );
        assert_eq!(ParallelThunkWorkerId::new(0), None);
        assert_eq!(
            ParallelThunkWorkerId::new(PARALLEL_THUNK_MAX_WORKER_ID)
                .map(ParallelThunkWorkerId::get),
            Some(PARALLEL_THUNK_MAX_WORKER_ID)
        );
        assert_eq!(
            ParallelThunkWorkerId::new(PARALLEL_THUNK_MAX_WORKER_ID + 1),
            None
        );
    }

    #[test]
    fn states_roundtrip_raw_words() {
        let owner = worker(7);
        let states = [
            ParallelThunkState::Suspended,
            ParallelThunkState::Pending { owner },
            ParallelThunkState::Awaited { owner },
            ParallelThunkState::Forced,
            ParallelThunkState::Failed,
        ];

        for state in states {
            assert_eq!(ParallelThunkState::from_raw(state.as_raw()), Ok(state));
        }

        assert_eq!(
            ParallelThunkState::from_raw(PENDING_TAG),
            Err(ParallelThunkStateError::InvalidStateWord { raw: PENDING_TAG })
        );
        assert_eq!(
            ParallelThunkState::from_raw(7),
            Err(ParallelThunkStateError::InvalidStateWord { raw: 7 })
        );
        assert_eq!(ParallelThunkState::Pending { owner }.owner(), Some(owner));
        assert_eq!(ParallelThunkState::Forced.owner(), None);
    }

    #[test]
    fn suspended_thunk_claims_and_publishes_forced() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);

        let ParallelThunkClaim::Claimed(guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };

        assert_eq!(
            state.state(),
            Ok(ParallelThunkState::Pending {
                owner: guard.owner()
            })
        );

        let publish = guard.publish_forced().expect("publish succeeds");

        assert_eq!(publish.owner(), owner);
        assert_eq!(publish.terminal_state(), ParallelThunkTerminalState::Forced);
        assert!(!publish.had_waiters());
        assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
        assert!(matches!(
            state.try_claim(worker(2)),
            Ok(ParallelThunkClaim::AlreadyForced)
        ));
    }

    #[test]
    fn concurrent_claim_has_single_winner() {
        const WORKERS: usize = 8;

        let state = Arc::new(ParallelThunkStateWord::new());
        let start = Arc::new(Barrier::new(WORKERS));
        let finish = Arc::new(Barrier::new(WORKERS));
        let outcomes = Arc::new(Mutex::new(Vec::with_capacity(WORKERS)));
        let mut handles = Vec::with_capacity(WORKERS);

        for raw_worker in 1..=WORKERS as u64 {
            let state = Arc::clone(&state);
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            let outcomes = Arc::clone(&outcomes);
            handles.push(thread::spawn(move || {
                let worker = worker(raw_worker);
                start.wait();

                match state.try_claim(worker).expect("claim checks state") {
                    ParallelThunkClaim::Claimed(guard) => {
                        outcomes.lock().expect("outcomes lock").push("claimed");
                        finish.wait();
                        guard.publish_forced().expect("winner publishes");
                    }
                    ParallelThunkClaim::ForeignPending { .. } => {
                        outcomes.lock().expect("outcomes lock").push("foreign");
                        finish.wait();
                    }
                    other => {
                        panic!("unexpected claim result in contention test: {other:?}");
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().expect("worker joins");
        }

        let outcomes = outcomes.lock().expect("outcomes lock");
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == "claimed")
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == "foreign")
                .count(),
            WORKERS - 1
        );
        assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
    }

    #[test]
    fn awaited_marks_foreign_pending_and_reports_waiters_on_publish() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);
        let waiter = worker(2);
        let second_waiter = worker(3);

        let ParallelThunkClaim::Claimed(guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };

        assert_eq!(
            state.mark_awaited(owner),
            Ok(ParallelThunkAwait::SelfCycle { owner })
        );
        assert_eq!(
            state.mark_awaited(waiter),
            Ok(ParallelThunkAwait::Awaited {
                owner,
                newly_marked: true,
            })
        );
        assert_eq!(state.state(), Ok(ParallelThunkState::Awaited { owner }));
        assert_eq!(
            state.mark_awaited(second_waiter),
            Ok(ParallelThunkAwait::Awaited {
                owner,
                newly_marked: false,
            })
        );

        let publish = guard.publish_forced().expect("publish succeeds");

        assert!(publish.had_waiters());
        assert_eq!(state.state(), Ok(ParallelThunkState::Forced));
    }

    #[test]
    fn failed_state_is_terminal_for_claim_and_await() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);

        let ParallelThunkClaim::Claimed(guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };

        let publish = guard.publish_failed().expect("publish succeeds");

        assert_eq!(publish.terminal_state(), ParallelThunkTerminalState::Failed);
        assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
        assert!(matches!(
            state.try_claim(worker(2)),
            Ok(ParallelThunkClaim::AlreadyFailed)
        ));
        assert_eq!(
            state.mark_awaited(worker(2)),
            Ok(ParallelThunkAwait::AlreadyFailed)
        );
    }

    #[test]
    fn dropped_claim_publishes_failed_to_avoid_stuck_pending() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);

        {
            let ParallelThunkClaim::Claimed(_guard) =
                state.try_claim(owner).expect("claim checks state")
            else {
                panic!("suspended thunk should be claimed");
            };
            assert_eq!(state.state(), Ok(ParallelThunkState::Pending { owner }));
        }

        assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
    }

    #[test]
    fn dropped_claim_publishes_failed_from_awaited_state() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);
        let waiter = worker(2);

        {
            let ParallelThunkClaim::Claimed(_guard) =
                state.try_claim(owner).expect("claim checks state")
            else {
                panic!("suspended thunk should be claimed");
            };
            assert_eq!(
                state.mark_awaited(waiter),
                Ok(ParallelThunkAwait::Awaited {
                    owner,
                    newly_marked: true,
                })
            );
            assert_eq!(state.state(), Ok(ParallelThunkState::Awaited { owner }));
        }

        assert_eq!(state.state(), Ok(ParallelThunkState::Failed));
    }

    #[test]
    fn acquire_load_observes_payload_written_before_release_publish() {
        let state = Arc::new(ParallelThunkStateWord::new());
        let payload = Arc::new(AtomicUsize::new(0));
        let owner_ready = Arc::new(Barrier::new(2));
        let owner = worker(1);

        let owner_thread = {
            let state = Arc::clone(&state);
            let payload = Arc::clone(&payload);
            let owner_ready = Arc::clone(&owner_ready);
            thread::spawn(move || {
                let ParallelThunkClaim::Claimed(guard) =
                    state.try_claim(owner).expect("claim checks state")
                else {
                    panic!("suspended thunk should be claimed");
                };

                owner_ready.wait();
                payload.store(55, AtomicOrdering::Relaxed);
                guard.publish_forced().expect("publish succeeds");
            })
        };

        owner_ready.wait();
        let observed = loop {
            if state.state().expect("state decodes") == ParallelThunkState::Forced {
                break payload.load(AtomicOrdering::Relaxed);
            }
            thread::yield_now();
        };

        owner_thread.join().expect("owner joins");
        assert_eq!(observed, 55);
    }

    #[test]
    fn publish_from_wrong_owner_fails_without_changing_state() {
        let state = ParallelThunkStateWord::new();
        let owner = worker(1);
        let wrong_owner = worker(2);

        let ParallelThunkClaim::Claimed(guard) =
            state.try_claim(owner).expect("claim checks state")
        else {
            panic!("suspended thunk should be claimed");
        };

        assert_eq!(
            state.publish_forced(wrong_owner),
            Err(ParallelThunkStateError::UnexpectedState {
                expected_owner: wrong_owner,
                actual: ParallelThunkState::Pending { owner },
            })
        );
        assert_eq!(state.state(), Ok(ParallelThunkState::Pending { owner }));

        guard.publish_forced().expect("real owner publishes");
    }
}

#[cfg(test)]
mod loom_model_tests {
    use std::sync::{
        Arc as StdArc,
        atomic::{AtomicBool, Ordering as StdOrdering},
    };

    use loom::{
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering as LoomOrdering},
        },
        thread,
    };

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoomClaim {
        Claimed,
        AlreadyForced,
        AlreadyFailed,
        SelfCycle,
        Foreign,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoomAwait {
        AlreadyForced,
        AlreadyFailed,
        SelfCycle,
        Awaited,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoomForceError {
        Failed(u64),
        SelfCycle,
    }

    #[derive(Debug, Default)]
    struct LoomWaiters {
        wait_registrations: usize,
        notifications: usize,
    }

    /// A minimal loom-only model of the RFC-0007 L2 thunk protocol.
    ///
    /// The model deliberately mirrors the production state-word encoding and
    /// ordering constants while keeping the terminal payloads as relaxed side
    /// slots. Any reader that observes `Forced` or `Failed` must rely on the
    /// state acquire load to see the relaxed payload write that happened before
    /// the owner's release publish.
    struct LoomThunk {
        state: AtomicU64,
        waiters: Mutex<LoomWaiters>,
        terminal_ready: Condvar,
        forced_payload: AtomicU64,
        failed_payload: AtomicU64,
        body_runs: AtomicUsize,
    }

    impl LoomThunk {
        fn new() -> Self {
            Self {
                state: AtomicU64::new(SUSPENDED_TAG),
                waiters: Mutex::new(LoomWaiters::default()),
                terminal_ready: Condvar::new(),
                forced_payload: AtomicU64::new(0),
                failed_payload: AtomicU64::new(0),
                body_runs: AtomicUsize::new(0),
            }
        }

        fn state(&self) -> ParallelThunkState {
            ParallelThunkState::from_raw(self.state.load(PARALLEL_THUNK_STATE_LOAD_ORDERING))
                .expect("loom model never observes torn or invalid state words")
        }

        fn try_claim(&self, worker: ParallelThunkWorkerId) -> LoomClaim {
            loop {
                match self.state() {
                    ParallelThunkState::Suspended => {
                        let pending = ParallelThunkState::Pending { owner: worker }.as_raw();
                        if self
                            .state
                            .compare_exchange(
                                SUSPENDED_TAG,
                                pending,
                                PARALLEL_THUNK_CLAIM_SUCCESS_ORDERING,
                                PARALLEL_THUNK_CLAIM_FAILURE_ORDERING,
                            )
                            .is_ok()
                        {
                            return LoomClaim::Claimed;
                        }
                    }
                    ParallelThunkState::Pending { owner }
                    | ParallelThunkState::Awaited { owner }
                        if owner == worker =>
                    {
                        return LoomClaim::SelfCycle;
                    }
                    ParallelThunkState::Pending { .. } | ParallelThunkState::Awaited { .. } => {
                        return LoomClaim::Foreign;
                    }
                    ParallelThunkState::Forced => return LoomClaim::AlreadyForced,
                    ParallelThunkState::Failed => return LoomClaim::AlreadyFailed,
                }
            }
        }

        fn mark_awaited(&self, waiter: ParallelThunkWorkerId) -> LoomAwait {
            loop {
                match self.state() {
                    ParallelThunkState::Suspended => {
                        panic!("foreign waiter saw an unclaimed thunk")
                    }
                    ParallelThunkState::Pending { owner } if owner == waiter => {
                        return LoomAwait::SelfCycle;
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
                            return LoomAwait::Awaited;
                        }
                    }
                    ParallelThunkState::Awaited { owner } if owner == waiter => {
                        return LoomAwait::SelfCycle;
                    }
                    ParallelThunkState::Awaited { .. } => return LoomAwait::Awaited,
                    ParallelThunkState::Forced => return LoomAwait::AlreadyForced,
                    ParallelThunkState::Failed => return LoomAwait::AlreadyFailed,
                }
            }
        }

        fn force_success(
            &self,
            worker: ParallelThunkWorkerId,
            value: u64,
        ) -> Result<u64, LoomForceError> {
            match self.try_claim(worker) {
                LoomClaim::Claimed => {
                    self.run_body_once();
                    self.write_forced_payload(value);
                    self.publish_terminal(worker, ParallelThunkTerminalState::Forced);
                    Ok(value)
                }
                LoomClaim::AlreadyForced => Ok(self.read_forced_payload()),
                LoomClaim::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
                LoomClaim::SelfCycle => Err(LoomForceError::SelfCycle),
                LoomClaim::Foreign => self.wait_for_terminal(worker),
            }
        }

        fn force_failure(
            &self,
            worker: ParallelThunkWorkerId,
            error: u64,
        ) -> Result<u64, LoomForceError> {
            match self.try_claim(worker) {
                LoomClaim::Claimed => {
                    self.run_body_once();
                    self.write_failed_payload(error);
                    self.publish_terminal(worker, ParallelThunkTerminalState::Failed);
                    Err(LoomForceError::Failed(error))
                }
                LoomClaim::AlreadyForced => Ok(self.read_forced_payload()),
                LoomClaim::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
                LoomClaim::SelfCycle => Err(LoomForceError::SelfCycle),
                LoomClaim::Foreign => self.wait_for_terminal(worker),
            }
        }

        fn wait_for_terminal(&self, worker: ParallelThunkWorkerId) -> Result<u64, LoomForceError> {
            let mut waiters = self.waiters.lock().expect("waiter mutex is not poisoned");
            match self.mark_awaited(worker) {
                LoomAwait::AlreadyForced => Ok(self.read_forced_payload()),
                LoomAwait::AlreadyFailed => Err(LoomForceError::Failed(self.read_failed_payload())),
                LoomAwait::SelfCycle => Err(LoomForceError::SelfCycle),
                LoomAwait::Awaited => {
                    waiters.wait_registrations = waiters.wait_registrations.saturating_add(1);
                    loop {
                        match self.state() {
                            ParallelThunkState::Forced => return Ok(self.read_forced_payload()),
                            ParallelThunkState::Failed => {
                                return Err(LoomForceError::Failed(self.read_failed_payload()));
                            }
                            ParallelThunkState::Pending { owner }
                            | ParallelThunkState::Awaited { owner }
                                if owner == worker =>
                            {
                                return Err(LoomForceError::SelfCycle);
                            }
                            ParallelThunkState::Pending { .. }
                            | ParallelThunkState::Awaited { .. } => {
                                waiters = self
                                    .terminal_ready
                                    .wait(waiters)
                                    .expect("waiter mutex is not poisoned");
                            }
                            ParallelThunkState::Suspended => {
                                panic!("waiter observed suspended after marking awaited")
                            }
                        }
                    }
                }
            }
        }

        fn publish_success(&self, owner: ParallelThunkWorkerId, value: u64) {
            self.write_forced_payload(value);
            self.publish_terminal(owner, ParallelThunkTerminalState::Forced);
        }

        fn publish_failure(&self, owner: ParallelThunkWorkerId, error: u64) {
            self.write_failed_payload(error);
            self.publish_terminal(owner, ParallelThunkTerminalState::Failed);
        }

        fn publish_terminal(
            &self,
            owner: ParallelThunkWorkerId,
            terminal_state: ParallelThunkTerminalState,
        ) {
            loop {
                let actual = self.state();
                let had_waiters = match actual {
                    ParallelThunkState::Pending {
                        owner: actual_owner,
                    } if actual_owner == owner => false,
                    ParallelThunkState::Awaited {
                        owner: actual_owner,
                    } if actual_owner == owner => true,
                    _ => panic!("owner attempted to publish from unexpected state: {actual:?}"),
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
                    if had_waiters {
                        let mut waiters =
                            self.waiters.lock().expect("waiter mutex is not poisoned");
                        waiters.notifications = waiters.notifications.saturating_add(1);
                        self.terminal_ready.notify_all();
                    }
                    return;
                }
            }
        }

        fn run_body_once(&self) {
            let previous = self.body_runs.fetch_add(1, LoomOrdering::SeqCst);
            assert_eq!(previous, 0, "loom model ran the thunk body more than once");
        }

        fn body_runs(&self) -> usize {
            self.body_runs.load(LoomOrdering::SeqCst)
        }

        fn waiter_stats(&self) -> (usize, usize) {
            let waiters = self.waiters.lock().expect("waiter mutex is not poisoned");
            (waiters.wait_registrations, waiters.notifications)
        }

        fn write_forced_payload(&self, value: u64) {
            assert_ne!(value, 0, "zero is the uninitialized payload sentinel");
            self.forced_payload.store(value, LoomOrdering::Relaxed);
        }

        fn read_forced_payload(&self) -> u64 {
            let value = self.forced_payload.load(LoomOrdering::Relaxed);
            assert_ne!(value, 0, "forced state exposed an uninitialized payload");
            value
        }

        fn write_failed_payload(&self, error: u64) {
            assert_ne!(error, 0, "zero is the uninitialized error sentinel");
            self.failed_payload.store(error, LoomOrdering::Relaxed);
        }

        fn read_failed_payload(&self) -> u64 {
            let error = self.failed_payload.load(LoomOrdering::Relaxed);
            assert_ne!(error, 0, "failed state exposed an uninitialized payload");
            error
        }
    }

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
    }

    fn bounded_three_worker_claimant_model() -> loom::model::Builder {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(2);
        builder.max_permutations = Some(2048);
        builder.checkpoint_interval = 1;
        builder
    }

    fn exhaustive_three_worker_waiter_model() -> loom::model::Builder {
        let mut builder = loom::model::Builder::new();
        builder.max_permutations = None;
        builder.max_duration = None;
        builder.preemption_bound = None;
        builder.checkpoint_file = None;
        builder
    }

    fn assert_waiters_were_not_stranded(thunk: &LoomThunk) {
        let (registrations, notifications) = thunk.waiter_stats();
        if registrations > 0 {
            assert!(
                notifications > 0,
                "waiter registered but no terminal wakeup notification was observed"
            );
        }
    }

    fn record_waiter_coverage(thunk: &LoomThunk, observed_waiter: &AtomicBool) {
        if thunk.waiter_stats().0 > 0 {
            observed_waiter.store(true, StdOrdering::Relaxed);
        }
    }

    fn assert_combined_model_exercised_waiter_path(observed_waiter: &AtomicBool) {
        assert!(
            observed_waiter.load(StdOrdering::Relaxed),
            "bounded three-worker force model did not exercise a waiter/replay path"
        );
    }

    fn wait_until_waiter_registered(thunk: &LoomThunk) {
        while thunk.waiter_stats().0 == 0 {
            thread::yield_now();
        }
    }

    #[test]
    fn loom_two_racing_workers_force_once_and_replay_published_value() {
        loom::model(|| {
            let thunk = Arc::new(LoomThunk::new());
            let first = {
                let thunk = Arc::clone(&thunk);
                thread::spawn(move || thunk.force_success(worker(1), 11))
            };
            let second = {
                let thunk = Arc::clone(&thunk);
                thread::spawn(move || thunk.force_success(worker(2), 22))
            };

            let first = first.join().expect("first worker joins");
            let second = second.join().expect("second worker joins");

            assert!(first.is_ok());
            assert_eq!(first, second);
            assert!(matches!(first, Ok(11 | 22)));
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Forced);
            assert_waiters_were_not_stranded(&thunk);
        });
    }

    /// Models the Chunk C single-entry CAS bypass (S7).
    ///
    /// A single-entry thunk carries a plain cell: no blackhole CAS, no
    /// update write-back, no parallel payload cell. Its safety argument is
    /// that every cross-thread path to it flows through an enclosing update
    /// thunk's claim protocol — the enclosing CAS cell's release publish
    /// happens-after the single force's relaxed reads and writes, so exactly
    /// one worker ever enters the plain cell and every other worker replays
    /// the enclosing published value without touching it.
    #[test]
    fn loom_single_entry_plain_cell_behind_enclosing_claim_runs_once() {
        loom::model(|| {
            let enclosing = Arc::new(LoomThunk::new());
            // The single-entry thunk: a captured payload and an entry
            // counter with no ordering of their own (Relaxed everywhere).
            let captured = Arc::new(AtomicU64::new(77));
            let entries = Arc::new(AtomicUsize::new(0));

            let spawn_worker = |id: u64| {
                let enclosing = Arc::clone(&enclosing);
                let captured = Arc::clone(&captured);
                let entries = Arc::clone(&entries);
                thread::spawn(move || {
                    // Forcing the enclosing thunk runs its body at most once;
                    // the body is the only reader of the single-entry cell.
                    let winner_value = captured.load(LoomOrdering::Relaxed);
                    match enclosing.try_claim(worker(id)) {
                        LoomClaim::Claimed => {
                            // Single-entry force: plain relaxed entry, no CAS.
                            entries.fetch_add(1, LoomOrdering::Relaxed);
                            enclosing.write_forced_payload(winner_value);
                            enclosing
                                .publish_terminal(worker(id), ParallelThunkTerminalState::Forced);
                            Ok(winner_value)
                        }
                        LoomClaim::AlreadyForced => Ok(enclosing.read_forced_payload()),
                        LoomClaim::Foreign => enclosing.wait_for_terminal(worker(id)),
                        other => panic!("unexpected claim outcome {other:?}"),
                    }
                })
            };

            let first = spawn_worker(1);
            let second = spawn_worker(2);
            let first = first.join().expect("first worker joins");
            let second = second.join().expect("second worker joins");

            assert_eq!(first, Ok(77));
            assert_eq!(second, Ok(77));
            assert_eq!(
                entries.load(LoomOrdering::Relaxed),
                1,
                "the plain single-entry cell must be entered exactly once"
            );
            assert_eq!(enclosing.state(), ParallelThunkState::Forced);
            assert_waiters_were_not_stranded(&enclosing);
        });
    }

    #[test]
    fn loom_bounded_three_racing_claimants_have_one_body_owner() {
        let builder = bounded_three_worker_claimant_model();
        builder.check(|| {
            let thunk = Arc::new(LoomThunk::new());
            let mut handles = Vec::new();

            for raw_worker in 1..=3 {
                let thunk = Arc::clone(&thunk);
                handles.push(thread::spawn(move || {
                    match thunk.try_claim(worker(raw_worker)) {
                        LoomClaim::Claimed => {
                            thunk.run_body_once();
                            thunk.publish_success(worker(raw_worker), raw_worker * 10);
                            true
                        }
                        LoomClaim::AlreadyForced | LoomClaim::Foreign => false,
                        unexpected => panic!("unexpected 3-worker claim outcome: {unexpected:?}"),
                    }
                }));
            }

            let mut claimed = 0;
            for handle in handles {
                if handle.join().expect("worker joins") {
                    claimed += 1;
                }
            }

            assert_eq!(claimed, 1);
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Forced);
            assert!(matches!(thunk.read_forced_payload(), 10 | 20 | 30));
        });
    }

    #[test]
    fn loom_bounded_three_racing_workers_force_once_and_replay_published_value() {
        let builder = bounded_three_worker_claimant_model();
        let observed_waiter = StdArc::new(AtomicBool::new(false));
        let observed_waiter_for_model = StdArc::clone(&observed_waiter);
        builder.check(move || {
            let thunk = Arc::new(LoomThunk::new());
            let mut handles = Vec::new();

            for raw_worker in 1..=3 {
                let thunk = Arc::clone(&thunk);
                handles.push(thread::spawn(move || {
                    thunk.force_success(worker(raw_worker), raw_worker * 10)
                }));
            }

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().expect("worker joins"));
            }

            let winner = results[0];
            assert!(results.iter().all(|result| *result == winner));
            assert!(matches!(winner, Ok(10 | 20 | 30)));
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Forced);
            assert_waiters_were_not_stranded(&thunk);
            record_waiter_coverage(&thunk, &observed_waiter_for_model);
        });
        assert_combined_model_exercised_waiter_path(&observed_waiter);
    }

    #[test]
    fn loom_bounded_three_racing_workers_replay_one_failed_payload() {
        let builder = bounded_three_worker_claimant_model();
        let observed_waiter = StdArc::new(AtomicBool::new(false));
        let observed_waiter_for_model = StdArc::clone(&observed_waiter);
        builder.check(move || {
            let thunk = Arc::new(LoomThunk::new());
            let mut handles = Vec::new();

            for raw_worker in 1..=3 {
                let thunk = Arc::clone(&thunk);
                handles.push(thread::spawn(move || {
                    thunk.force_failure(worker(raw_worker), raw_worker * 100)
                }));
            }

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().expect("worker joins"));
            }

            let winner = results[0];
            assert!(results.iter().all(|result| *result == winner));
            assert!(matches!(
                winner,
                Err(LoomForceError::Failed(100 | 200 | 300))
            ));
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Failed);
            assert_waiters_were_not_stranded(&thunk);
            record_waiter_coverage(&thunk, &observed_waiter_for_model);
        });
        assert_combined_model_exercised_waiter_path(&observed_waiter);
    }

    #[test]
    fn loom_three_workers_replay_one_published_value_after_waiter_registration() {
        let builder = exhaustive_three_worker_waiter_model();
        builder.check(|| {
            let thunk = Arc::new(LoomThunk::new());
            assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);
            thunk.run_body_once();

            let mut handles = Vec::new();
            for raw_worker in 2..=3 {
                let thunk = Arc::clone(&thunk);
                handles.push(thread::spawn(move || {
                    thunk.force_success(worker(raw_worker), raw_worker * 10)
                }));
            }
            wait_until_waiter_registered(&thunk);
            thunk.publish_success(worker(1), 10);

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().expect("worker joins"));
            }

            assert!(results.iter().all(Result::is_ok));
            assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
            assert_eq!(results[0], Ok(10));
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Forced);
            assert!(thunk.waiter_stats().0 > 0);
            assert_waiters_were_not_stranded(&thunk);
        });
    }

    #[test]
    fn loom_three_workers_replay_one_failed_payload_after_waiter_registration() {
        let builder = exhaustive_three_worker_waiter_model();
        builder.check(|| {
            let thunk = Arc::new(LoomThunk::new());
            assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);
            thunk.run_body_once();

            let mut handles = Vec::new();
            for raw_worker in 2..=3 {
                let thunk = Arc::clone(&thunk);
                handles.push(thread::spawn(move || {
                    thunk.force_failure(worker(raw_worker), raw_worker * 100)
                }));
            }
            wait_until_waiter_registered(&thunk);
            thunk.publish_failure(worker(1), 100);

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().expect("worker joins"));
            }

            assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
            assert_eq!(results[0], Err(LoomForceError::Failed(100)));
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Failed);
            assert!(thunk.waiter_stats().0 > 0);
            assert_waiters_were_not_stranded(&thunk);
        });
    }

    #[test]
    fn loom_same_worker_reentry_reports_cycle_without_body_run() {
        loom::model(|| {
            let thunk = LoomThunk::new();
            assert_eq!(thunk.try_claim(worker(1)), LoomClaim::Claimed);

            let recursive = thunk.force_success(worker(1), 99);

            assert_eq!(recursive, Err(LoomForceError::SelfCycle));
            assert_eq!(thunk.body_runs(), 0);
            thunk.publish_success(worker(1), 7);
            assert_eq!(thunk.force_success(worker(2), 22), Ok(7));
            assert_eq!(thunk.body_runs(), 0);
            assert_eq!(thunk.state(), ParallelThunkState::Forced);
        });
    }

    #[test]
    fn loom_failed_terminal_state_wakes_and_replays_to_waiters() {
        loom::model(|| {
            let thunk = Arc::new(LoomThunk::new());
            let first = {
                let thunk = Arc::clone(&thunk);
                thread::spawn(move || thunk.force_failure(worker(1), 101))
            };
            let second = {
                let thunk = Arc::clone(&thunk);
                thread::spawn(move || thunk.force_failure(worker(2), 202))
            };

            let first = first.join().expect("first worker joins");
            let second = second.join().expect("second worker joins");

            assert!(matches!(first, Err(LoomForceError::Failed(101 | 202))));
            assert_eq!(first, second);
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Failed);
            assert_waiters_were_not_stranded(&thunk);
        });
    }

    #[test]
    fn loom_already_failed_replays_same_captured_payload() {
        loom::model(|| {
            let thunk = LoomThunk::new();

            assert_eq!(
                thunk.force_failure(worker(1), 303),
                Err(LoomForceError::Failed(303))
            );
            assert_eq!(
                thunk.force_failure(worker(2), 404),
                Err(LoomForceError::Failed(303))
            );
            assert_eq!(
                thunk.force_success(worker(3), 505),
                Err(LoomForceError::Failed(303))
            );
            assert_eq!(thunk.body_runs(), 1);
            assert_eq!(thunk.state(), ParallelThunkState::Failed);
        });
    }
}
