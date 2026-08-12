//! Device-I/O virtual-time hold state.
//!
//! Block and 9p callbacks submit requests to deterministic executor subnodes.
//! While those requests are in flight, the plugin marks the node's shared-memory
//! `device_io_active` flag and keeps a local pending counter so guest HZ ticks do
//! not advance virtual time through host-timing gaps. Each submit returns a
//! non-`Copy` token that must be consumed by exactly one completion or failure
//! path.

use thiserror::Error;

use core::sync::atomic::{AtomicU64, Ordering};

use crucible_shmem::{FutexError, NodeSlot, WakeAction};

use crate::shmem_ordering::PluginShmemOrdering;

static NEXT_FREEZE_OWNER_ID: AtomicU64 = AtomicU64::new(1);

/// Plugin-owned state for suppressing spurious HZ ticks across device I/O.
#[derive(Debug)]
pub struct PluginDeviceIoFreeze {
    owner_id: u64,
    pending_requests: u32,
    burst_pending_requests: u32,
    burst_active: bool,
    next_request_seq: u64,
}

impl PluginDeviceIoFreeze {
    /// Builds an empty device-I/O freeze state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // This counter is plugin-local diagnostic state, not shared memory.
            // Relaxed ordering is enough for unique token ownership IDs because
            // it does not publish data to another process or order guest-visible
            // behavior.
            owner_id: NEXT_FREEZE_OWNER_ID.fetch_add(1, Ordering::Relaxed),
            pending_requests: 0,
            burst_pending_requests: 0,
            burst_active: false,
            next_request_seq: 0,
        }
    }

    /// Returns the diagnostic owner id carried by this state machine's tokens.
    #[must_use]
    pub const fn owner_id(&self) -> u64 {
        self.owner_id
    }

    /// Returns the number of submitted requests awaiting completion or failure.
    #[must_use]
    pub const fn pending_requests(&self) -> u32 {
        self.pending_requests
    }

    /// Returns whether a multi-request device burst is holding the node.
    #[must_use]
    pub const fn burst_active(&self) -> bool {
        self.burst_active
    }

    /// Returns whether the idle path must suppress guest timer deadlines.
    #[must_use]
    pub fn is_tick_hold_active(&self, slot: &NodeSlot) -> bool {
        self.pending_requests != 0
            || self.burst_active
            || PluginShmemOrdering::device_io_active(slot)
    }

    /// Starts a multi-request device burst and marks device I/O active.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError::BurstAlreadyActive`] if a previous burst
    /// has not reached `burst_done`.
    pub fn begin_burst(
        &mut self,
        slot: &NodeSlot,
    ) -> Result<DeviceIoBurstState, DeviceIoFreezeError> {
        if self.burst_active {
            return Err(DeviceIoFreezeError::BurstAlreadyActive {
                pending_requests: self.pending_requests,
            });
        }

        PluginShmemOrdering::publish_device_io_active(slot);
        self.burst_active = true;
        Ok(self.burst_state(slot))
    }

    /// Records a device-I/O submit before the callback hands work to an executor.
    ///
    /// The shared-memory flag is set before this method returns, so callers can
    /// submit to the device executor immediately after receiving the returned
    /// token.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError::PendingCounterOverflow`] if another
    /// request cannot be represented, or
    /// [`DeviceIoFreezeError::RequestSequenceOverflow`] if the diagnostic request
    /// sequence space is exhausted.
    pub fn begin_submit(
        &mut self,
        slot: &NodeSlot,
        submit_icount: u64,
    ) -> Result<DeviceIoRequestToken, DeviceIoFreezeError> {
        self.begin_submit_with_burst_membership(slot, submit_icount, self.burst_active)
    }

    /// Records an independent request while preserving any unrelated burst.
    ///
    /// Block callbacks use this entry point because a block coroutine can be in
    /// flight concurrently with a 9p burst. The request contributes to the
    /// global device-I/O hold but does not prevent that unrelated burst from
    /// reaching `burst_done`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::begin_submit`].
    pub fn begin_independent_submit(
        &mut self,
        slot: &NodeSlot,
        submit_icount: u64,
    ) -> Result<DeviceIoRequestToken, DeviceIoFreezeError> {
        self.begin_submit_with_burst_membership(slot, submit_icount, false)
    }

    /// Atomically records a batch of independent restored requests.
    ///
    /// No counter, sequence, or shared-memory state changes unless every token
    /// in the requested batch can be represented.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError::PendingCounterOverflow`] or
    /// [`DeviceIoFreezeError::RequestSequenceOverflow`] when the complete batch
    /// cannot be admitted.
    pub fn begin_independent_batch(
        &mut self,
        slot: &NodeSlot,
        submit_icount: u64,
        count: u32,
    ) -> Result<Vec<DeviceIoRequestToken>, DeviceIoFreezeError> {
        let next_pending = self.pending_requests.checked_add(count).ok_or(
            DeviceIoFreezeError::PendingCounterOverflow {
                pending_requests: self.pending_requests,
            },
        )?;
        let next_sequence = self.next_request_seq.checked_add(u64::from(count)).ok_or(
            DeviceIoFreezeError::RequestSequenceOverflow {
                next_request_seq: self.next_request_seq,
            },
        )?;
        let mut tokens = Vec::with_capacity(count as usize);
        for offset in 0..u64::from(count) {
            tokens.push(DeviceIoRequestToken {
                owner_id: self.owner_id,
                request_seq: self.next_request_seq + offset,
                submit_icount,
                burst_member: false,
            });
        }
        if count != 0 {
            PluginShmemOrdering::publish_device_io_active(slot);
        }
        self.pending_requests = next_pending;
        self.next_request_seq = next_sequence;
        Ok(tokens)
    }

    fn begin_submit_with_burst_membership(
        &mut self,
        slot: &NodeSlot,
        submit_icount: u64,
        burst_member: bool,
    ) -> Result<DeviceIoRequestToken, DeviceIoFreezeError> {
        if self.pending_requests == u32::MAX {
            return Err(DeviceIoFreezeError::PendingCounterOverflow {
                pending_requests: self.pending_requests,
            });
        }
        let request_seq = self.next_request_seq;
        self.next_request_seq = self.next_request_seq.checked_add(1).ok_or(
            DeviceIoFreezeError::RequestSequenceOverflow {
                next_request_seq: self.next_request_seq,
            },
        )?;

        PluginShmemOrdering::publish_device_io_active(slot);
        self.pending_requests += 1;
        if burst_member {
            self.burst_pending_requests += 1;
        }
        Ok(DeviceIoRequestToken {
            owner_id: self.owner_id,
            request_seq,
            submit_icount,
            burst_member,
        })
    }

    /// Completes one previously submitted request and releases its pending count.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError`] if the token is not paired with an
    /// in-flight request in this freeze state or if the release wake fails.
    pub fn complete_request(
        &mut self,
        slot: &NodeSlot,
        token: DeviceIoRequestToken,
    ) -> Result<DeviceIoRequestRelease, DeviceIoFreezeError> {
        self.finish_request(slot, token, DeviceIoRequestOutcome::Completed)
    }

    /// Fails one previously submitted request and releases its pending count.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError`] if the token is not paired with an
    /// in-flight request in this freeze state or if the release wake fails.
    pub fn fail_request(
        &mut self,
        slot: &NodeSlot,
        token: DeviceIoRequestToken,
    ) -> Result<DeviceIoRequestRelease, DeviceIoFreezeError> {
        self.finish_request(slot, token, DeviceIoRequestOutcome::Failed)
    }

    /// Ends a multi-request burst after all request tokens have completed.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIoFreezeError::BurstDoneWithoutActiveBurst`] when no burst
    /// is active, or [`DeviceIoFreezeError::BurstDoneWithPendingRequests`] when a
    /// request from the burst is still awaiting completion or failure.
    pub fn burst_done(
        &mut self,
        slot: &NodeSlot,
    ) -> Result<DeviceIoBurstState, DeviceIoFreezeError> {
        if !self.burst_active {
            return Err(DeviceIoFreezeError::BurstDoneWithoutActiveBurst);
        }
        if self.burst_pending_requests != 0 {
            return Err(DeviceIoFreezeError::BurstDoneWithPendingRequests {
                pending_requests: self.burst_pending_requests,
            });
        }

        self.burst_active = false;
        let release_wake = if self.pending_requests == 0 {
            PluginShmemOrdering::clear_device_io_active(slot);
            Some(
                PluginShmemOrdering::wake_for_device_io_release(slot)
                    .map_err(|source| DeviceIoFreezeError::DeviceIoReleaseWake { source })?,
            )
        } else {
            None
        };
        Ok(DeviceIoBurstState {
            release_wake,
            ..self.burst_state(slot)
        })
    }

    fn finish_request(
        &mut self,
        slot: &NodeSlot,
        token: DeviceIoRequestToken,
        outcome: DeviceIoRequestOutcome,
    ) -> Result<DeviceIoRequestRelease, DeviceIoFreezeError> {
        if token.owner_id != self.owner_id {
            return Err(DeviceIoFreezeError::CompletionForDifferentFreezeState {
                expected_owner_id: self.owner_id,
                actual_owner_id: token.owner_id,
                request_seq: token.request_seq,
                submit_icount: token.submit_icount,
                outcome,
            });
        }
        if self.pending_requests == 0 {
            return Err(DeviceIoFreezeError::CompletionWithoutPendingRequest {
                request_seq: token.request_seq,
                submit_icount: token.submit_icount,
                outcome,
            });
        }

        if token.burst_member && self.burst_pending_requests == 0 {
            return Err(DeviceIoFreezeError::BurstMembershipUnderflow {
                request_seq: token.request_seq,
                submit_icount: token.submit_icount,
            });
        }
        self.pending_requests -= 1;
        if token.burst_member {
            self.burst_pending_requests -= 1;
        }
        let mut release_wake = None;
        if self.pending_requests == 0 && !self.burst_active {
            PluginShmemOrdering::clear_device_io_active(slot);
            release_wake = Some(
                PluginShmemOrdering::wake_for_device_io_release(slot)
                    .map_err(|source| DeviceIoFreezeError::DeviceIoReleaseWake { source })?,
            );
        }

        Ok(DeviceIoRequestRelease {
            owner_id: self.owner_id,
            request_seq: token.request_seq,
            submit_icount: token.submit_icount,
            pending_requests: self.pending_requests,
            burst_active: self.burst_active,
            device_io_active: PluginShmemOrdering::device_io_active(slot),
            release_wake,
            outcome,
        })
    }

    fn burst_state(&self, slot: &NodeSlot) -> DeviceIoBurstState {
        DeviceIoBurstState {
            pending_requests: self.pending_requests,
            burst_active: self.burst_active,
            device_io_active: PluginShmemOrdering::device_io_active(slot),
            release_wake: None,
        }
    }
}

impl Default for PluginDeviceIoFreeze {
    fn default() -> Self {
        Self::new()
    }
}

/// A request token created on submit and consumed on completion or failure.
#[must_use = "device-I/O request tokens must be paired with completion or failure"]
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceIoRequestToken {
    owner_id: u64,
    request_seq: u64,
    submit_icount: u64,
    burst_member: bool,
}

impl DeviceIoRequestToken {
    /// Returns the owner id of the freeze state that created this token.
    #[must_use]
    pub const fn owner_id(&self) -> u64 {
        self.owner_id
    }

    /// Returns the local diagnostic sequence assigned at submit time.
    #[must_use]
    pub const fn request_seq(&self) -> u64 {
        self.request_seq
    }

    /// Returns the icount at which the request was submitted.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.submit_icount
    }

    /// Returns whether the request belongs to the active multi-request burst.
    #[must_use]
    pub const fn burst_member(&self) -> bool {
        self.burst_member
    }
}

/// The terminal status that released one request token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceIoRequestOutcome {
    /// The executor produced a completion response.
    Completed,
    /// The executor or callback path failed the request.
    Failed,
}

/// The state observed after one request token was released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIoRequestRelease {
    owner_id: u64,
    request_seq: u64,
    submit_icount: u64,
    pending_requests: u32,
    burst_active: bool,
    device_io_active: bool,
    release_wake: Option<WakeAction>,
    outcome: DeviceIoRequestOutcome,
}

impl DeviceIoRequestRelease {
    /// Returns the owner id of the freeze state that released this token.
    #[must_use]
    pub const fn owner_id(&self) -> u64 {
        self.owner_id
    }

    /// Returns the request sequence that was released.
    #[must_use]
    pub const fn request_seq(&self) -> u64 {
        self.request_seq
    }

    /// Returns the request submit icount.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.submit_icount
    }

    /// Returns the number of requests still awaiting completion or failure.
    #[must_use]
    pub const fn pending_requests(&self) -> u32 {
        self.pending_requests
    }

    /// Returns whether a multi-request burst is still active.
    #[must_use]
    pub const fn burst_active(&self) -> bool {
        self.burst_active
    }

    /// Returns whether the shared-memory flag remains active after release.
    #[must_use]
    pub const fn device_io_active(&self) -> bool {
        self.device_io_active
    }

    /// Returns the wake issued when this release cleared the device-I/O hold.
    #[must_use]
    pub const fn release_wake(&self) -> Option<WakeAction> {
        self.release_wake
    }

    /// Returns the terminal status that released the token.
    #[must_use]
    pub const fn outcome(&self) -> DeviceIoRequestOutcome {
        self.outcome
    }
}

/// The state observed after a burst lifecycle transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIoBurstState {
    pending_requests: u32,
    burst_active: bool,
    device_io_active: bool,
    release_wake: Option<WakeAction>,
}

impl DeviceIoBurstState {
    /// Returns the number of requests still awaiting completion or failure.
    #[must_use]
    pub const fn pending_requests(&self) -> u32 {
        self.pending_requests
    }

    /// Returns whether the burst remains active.
    #[must_use]
    pub const fn burst_active(&self) -> bool {
        self.burst_active
    }

    /// Returns whether the shared-memory device-I/O flag is active.
    #[must_use]
    pub const fn device_io_active(&self) -> bool {
        self.device_io_active
    }

    /// Returns the wake issued when this transition cleared the device-I/O hold.
    #[must_use]
    pub const fn release_wake(&self) -> Option<WakeAction> {
        self.release_wake
    }
}

/// An error produced while maintaining device-I/O virtual-time hold state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DeviceIoFreezeError {
    /// The local pending-request counter cannot represent another submit.
    #[error("device-I/O pending counter overflow at {pending_requests} requests")]
    PendingCounterOverflow {
        /// The pending count observed before the rejected submit.
        pending_requests: u32,
    },
    /// The diagnostic request sequence cannot represent another token.
    #[error("device-I/O request sequence overflow at {next_request_seq}")]
    RequestSequenceOverflow {
        /// The next request sequence that could not be assigned.
        next_request_seq: u64,
    },
    /// A completion or failure token was applied when no request was pending.
    #[error(
        "device-I/O request {request_seq} submitted at {submit_icount} completed as {outcome:?} with no pending request"
    )]
    CompletionWithoutPendingRequest {
        /// The token's local diagnostic request sequence.
        request_seq: u64,
        /// The icount at which the token was created.
        submit_icount: u64,
        /// The completion status attempted for the token.
        outcome: DeviceIoRequestOutcome,
    },
    /// A request token was applied to a different freeze state than its submit state.
    #[error(
        "device-I/O request {request_seq} submitted at {submit_icount} belongs to freeze state {actual_owner_id}, not {expected_owner_id}"
    )]
    CompletionForDifferentFreezeState {
        /// The target freeze state's owner id.
        expected_owner_id: u64,
        /// The token's original freeze-state owner id.
        actual_owner_id: u64,
        /// The token's local diagnostic request sequence.
        request_seq: u64,
        /// The icount at which the token was created.
        submit_icount: u64,
        /// The completion status attempted for the token.
        outcome: DeviceIoRequestOutcome,
    },
    /// The futex wake used to release an idle device-I/O hold failed.
    #[error("device-I/O release wake failed: {source}")]
    DeviceIoReleaseWake {
        /// The wake failure from the shared-memory slot.
        source: FutexError,
    },
    /// A burst was started before the previous burst reached `burst_done`.
    #[error("device-I/O burst already active with {pending_requests} pending requests")]
    BurstAlreadyActive {
        /// The pending count observed at the rejected burst start.
        pending_requests: u32,
    },
    /// A burst-done callback arrived without a matching active burst.
    #[error("device-I/O burst_done arrived with no active burst")]
    BurstDoneWithoutActiveBurst,
    /// A burst-done callback arrived before all request tokens completed.
    #[error("device-I/O burst_done arrived with {pending_requests} pending requests")]
    BurstDoneWithPendingRequests {
        /// The pending count that prevented burst release.
        pending_requests: u32,
    },
    /// A burst-member token was released after its membership count was lost.
    #[error(
        "device-I/O burst membership underflow for request {request_seq} submitted at {submit_icount}"
    )]
    BurstMembershipUnderflow {
        /// Token sequence whose membership could not be released.
        request_seq: u64,
        /// Token submit icount.
        submit_icount: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crucible_shmem::{KIND_VM, NodeSlot};

    #[test]
    fn device_io_submit_sets_active_before_return_and_increments_pending() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();

        let token = begin_submit(&mut freeze, &slot, 40);

        assert_eq!(token.owner_id(), freeze.owner_id());
        assert_eq!(token.request_seq(), 0);
        assert_eq!(token.submit_icount(), 40);
        assert_eq!(freeze.pending_requests(), 1);
        assert!(!freeze.burst_active());
        assert!(freeze.is_tick_hold_active(&slot));
        assert_eq!(slot.snapshot().device_io_active, 1);
    }

    #[test]
    fn device_io_completion_clears_single_request_hold() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let token = begin_submit(&mut freeze, &slot, 50);
        let before_wake = slot.snapshot().wake_signal;

        let release = complete_request(&mut freeze, &slot, token);

        assert_eq!(release.owner_id(), freeze.owner_id());
        assert_eq!(release.request_seq(), 0);
        assert_eq!(release.submit_icount(), 50);
        assert_eq!(release.pending_requests(), 0);
        assert_eq!(release.outcome(), DeviceIoRequestOutcome::Completed);
        assert!(!release.burst_active());
        assert!(!release.device_io_active());
        assert!(release.release_wake().is_some());
        assert!(!freeze.is_tick_hold_active(&slot));
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.device_io_active, 0);
        assert_eq!(snapshot.wake_signal, before_wake.wrapping_add(1));
    }

    #[test]
    fn device_io_failure_releases_the_same_pending_counter() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let token = begin_submit(&mut freeze, &slot, 60);
        let before_wake = slot.snapshot().wake_signal;

        let release = fail_request(&mut freeze, &slot, token);

        assert_eq!(release.pending_requests(), 0);
        assert_eq!(release.outcome(), DeviceIoRequestOutcome::Failed);
        assert!(!release.device_io_active());
        assert!(release.release_wake().is_some());
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.device_io_active, 0);
        assert_eq!(snapshot.wake_signal, before_wake.wrapping_add(1));
    }

    #[test]
    fn device_io_burst_holds_flag_until_burst_done() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();

        let started = match freeze.begin_burst(&slot) {
            Ok(state) => state,
            Err(error) => panic!("burst should start: {error}"),
        };
        assert_eq!(started.pending_requests(), 0);
        assert!(started.burst_active());
        assert!(started.device_io_active());
        assert_eq!(started.release_wake(), None);

        let first = begin_submit(&mut freeze, &slot, 70);
        let second = begin_submit(&mut freeze, &slot, 70);
        assert_eq!(freeze.pending_requests(), 2);

        let first_release = complete_request(&mut freeze, &slot, first);
        assert_eq!(first_release.pending_requests(), 1);
        assert!(first_release.device_io_active());
        assert_eq!(first_release.release_wake(), None);

        let second_release = complete_request(&mut freeze, &slot, second);
        assert_eq!(second_release.pending_requests(), 0);
        assert!(second_release.burst_active());
        assert!(second_release.device_io_active());
        assert_eq!(second_release.release_wake(), None);
        assert!(freeze.is_tick_hold_active(&slot));
        let before_done_wake = slot.snapshot().wake_signal;

        let done = match freeze.burst_done(&slot) {
            Ok(state) => state,
            Err(error) => panic!("burst_done should release an answered burst: {error}"),
        };
        assert_eq!(done.pending_requests(), 0);
        assert!(!done.burst_active());
        assert!(!done.device_io_active());
        assert!(done.release_wake().is_some());
        assert!(!freeze.is_tick_hold_active(&slot));
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.device_io_active, 0);
        assert_eq!(snapshot.wake_signal, before_done_wake.wrapping_add(1));
    }

    #[test]
    fn device_io_burst_done_rejects_pending_requests_and_keeps_flag_active() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        if let Err(error) = freeze.begin_burst(&slot) {
            panic!("burst should start: {error}");
        }
        let _token = begin_submit(&mut freeze, &slot, 80);

        assert_eq!(
            freeze.burst_done(&slot),
            Err(DeviceIoFreezeError::BurstDoneWithPendingRequests {
                pending_requests: 1,
            })
        );
        assert!(freeze.burst_active());
        assert_eq!(freeze.pending_requests(), 1);
        assert!(freeze.is_tick_hold_active(&slot));
        assert_eq!(slot.snapshot().device_io_active, 1);
    }

    #[test]
    fn device_io_foreign_token_with_target_pending_is_fail_loud() {
        let source_slot = NodeSlot::new(KIND_VM);
        let target_slot = NodeSlot::new(KIND_VM);
        let mut source = PluginDeviceIoFreeze::new();
        let mut target = PluginDeviceIoFreeze::new();
        let token = begin_submit(&mut source, &source_slot, 90);
        let _target_token = begin_submit(&mut target, &target_slot, 91);

        assert_eq!(
            target.complete_request(&target_slot, token),
            Err(DeviceIoFreezeError::CompletionForDifferentFreezeState {
                expected_owner_id: target.owner_id(),
                actual_owner_id: source.owner_id(),
                request_seq: 0,
                submit_icount: 90,
                outcome: DeviceIoRequestOutcome::Completed,
            })
        );
        assert_eq!(target.pending_requests(), 1);
        assert_eq!(target_slot.snapshot().device_io_active, 1);
    }

    #[test]
    fn device_io_completion_without_matching_pending_request_is_fail_loud() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let token = DeviceIoRequestToken {
            owner_id: freeze.owner_id(),
            request_seq: 17,
            submit_icount: 90,
            burst_member: false,
        };

        assert_eq!(
            freeze.complete_request(&slot, token),
            Err(DeviceIoFreezeError::CompletionWithoutPendingRequest {
                request_seq: 17,
                submit_icount: 90,
                outcome: DeviceIoRequestOutcome::Completed,
            })
        );
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn device_io_counter_overflow_does_not_publish_active_flag() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze {
            owner_id: 4242,
            pending_requests: u32::MAX,
            burst_pending_requests: 0,
            burst_active: false,
            next_request_seq: 0,
        };

        assert_eq!(
            freeze.begin_submit(&slot, 100),
            Err(DeviceIoFreezeError::PendingCounterOverflow {
                pending_requests: u32::MAX,
            })
        );
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn device_io_sequence_overflow_does_not_publish_active_flag() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze {
            owner_id: 4243,
            pending_requests: 0,
            burst_pending_requests: 0,
            burst_active: false,
            next_request_seq: u64::MAX,
        };

        assert_eq!(
            freeze.begin_submit(&slot, 110),
            Err(DeviceIoFreezeError::RequestSequenceOverflow {
                next_request_seq: u64::MAX,
            })
        );
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn independent_request_keeps_hold_after_unrelated_burst_finishes() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        freeze
            .begin_burst(&slot)
            .unwrap_or_else(|error| panic!("burst should start: {error}"));
        let burst_request = begin_submit(&mut freeze, &slot, 120);
        let independent = freeze
            .begin_independent_submit(&slot, 121)
            .unwrap_or_else(|error| panic!("independent request should submit: {error}"));

        let burst_release = complete_request(&mut freeze, &slot, burst_request);
        assert_eq!(burst_release.pending_requests(), 1);
        let burst_done = freeze
            .burst_done(&slot)
            .unwrap_or_else(|error| panic!("answered burst should finish: {error}"));
        assert_eq!(burst_done.pending_requests(), 1);
        assert!(!burst_done.burst_active());
        assert!(burst_done.device_io_active());
        assert_eq!(burst_done.release_wake(), None);

        let independent_release = complete_request(&mut freeze, &slot, independent);
        assert_eq!(independent_release.pending_requests(), 0);
        assert!(!independent_release.device_io_active());
        assert!(independent_release.release_wake().is_some());
    }

    fn begin_submit(
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        submit_icount: u64,
    ) -> DeviceIoRequestToken {
        match freeze.begin_submit(slot, submit_icount) {
            Ok(token) => token,
            Err(error) => panic!("device I/O submit should begin: {error}"),
        }
    }

    fn complete_request(
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        token: DeviceIoRequestToken,
    ) -> DeviceIoRequestRelease {
        match freeze.complete_request(slot, token) {
            Ok(release) => release,
            Err(error) => panic!("device I/O completion should release: {error}"),
        }
    }

    fn fail_request(
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        token: DeviceIoRequestToken,
    ) -> DeviceIoRequestRelease {
        match freeze.fail_request(slot, token) {
            Ok(release) => release,
            Err(error) => panic!("device I/O failure should release: {error}"),
        }
    }
}
