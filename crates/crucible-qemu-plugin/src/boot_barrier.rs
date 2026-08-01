//! Initial-ceiling boot barrier for the QEMU plugin.
//!
//! The boot barrier parks the plugin before the first guest instruction until
//! the scheduler publishes a nonzero `max_advance_icount` ceiling for this node.
//! It uses the shared-memory slot's non-private `wake_signal` futex path and has
//! no host wall-clock timeout or sleep fallback.

use thiserror::Error;

use crucible_shmem::{FutexError, FutexWait, FutexWaitOutcome, NodeSlot, NodeSlotError};

use crate::{setup::PluginReadySetupAck, shmem_ordering::PluginShmemOrdering};

/// First aggregate icount reached after one guest instruction retires.
pub const BOOT_BARRIER_FIRST_GUEST_ICOUNT: u64 = 1;

/// Prepared futex wait state for the initial boot barrier.
#[derive(Debug)]
pub struct BootBarrierWait {
    _setup_ack: PluginReadySetupAck,
    first_guest_icount: u64,
    futex_wait: FutexWait,
}

impl BootBarrierWait {
    /// Returns the first guest icount that must be scheduler-authorized.
    #[must_use]
    pub const fn first_guest_icount(&self) -> u64 {
        self.first_guest_icount
    }

    /// Returns the race-free futex wait decision for the boot barrier.
    #[must_use]
    pub const fn futex_wait(&self) -> FutexWait {
        self.futex_wait
    }
}

/// Proof that the scheduler released the initial boot barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootBarrierRelease {
    first_guest_icount: u64,
    released_ceiling: u64,
}

impl BootBarrierRelease {
    /// Returns the first guest icount covered by this release.
    #[must_use]
    pub const fn first_guest_icount(self) -> u64 {
        self.first_guest_icount
    }

    /// Returns the scheduler ceiling observed when the barrier released.
    #[must_use]
    pub const fn released_ceiling(self) -> u64 {
        self.released_ceiling
    }
}

/// Safe operations for the initial boot barrier.
#[derive(Debug)]
pub struct PluginBootBarrier;

impl PluginBootBarrier {
    /// Publishes the boot-wait precondition and prepares the futex wait.
    ///
    /// # Errors
    ///
    /// Returns [`BootBarrierError::PublishIdle`] when publishing the initial
    /// idle precondition fails.
    pub fn prepare_initial_ceiling_wait(
        setup_ack: PluginReadySetupAck,
        slot: &NodeSlot,
        icount_shift: u8,
    ) -> Result<BootBarrierWait, BootBarrierError> {
        let futex_wait = PluginShmemOrdering::publish_idle_wait(
            slot,
            0,
            BOOT_BARRIER_FIRST_GUEST_ICOUNT,
            icount_shift,
        )
        .map_err(|source| BootBarrierError::PublishIdle { source })?;
        Ok(BootBarrierWait {
            _setup_ack: setup_ack,
            first_guest_icount: BOOT_BARRIER_FIRST_GUEST_ICOUNT,
            futex_wait,
        })
    }

    /// Waits until the scheduler has published the initial ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BootBarrierError::FutexWait`] when the futex syscall fails, or
    /// [`BootBarrierError::InitialCeilingStillBlocked`] when the non-Linux no-op
    /// futex shim cannot prove a scheduler release.
    pub fn wait_for_initial_ceiling(
        slot: &NodeSlot,
        request: BootBarrierWait,
    ) -> Result<BootBarrierRelease, BootBarrierError> {
        let mut wait = request.futex_wait;
        loop {
            let ceiling = PluginShmemOrdering::load_scheduler_ceiling(slot);
            if ceiling >= request.first_guest_icount {
                PluginShmemOrdering::mark_running_after_wake(slot);
                return Ok(BootBarrierRelease {
                    first_guest_icount: request.first_guest_icount,
                    released_ceiling: ceiling,
                });
            }

            match PluginShmemOrdering::wait_on_wake_signal(slot, wait)
                .map_err(|source| BootBarrierError::FutexWait { source })?
            {
                FutexWaitOutcome::Noop => {
                    return Err(BootBarrierError::InitialCeilingStillBlocked {
                        first_guest_icount: request.first_guest_icount,
                        ceiling_icount: PluginShmemOrdering::load_scheduler_ceiling(slot),
                    });
                }
                FutexWaitOutcome::Runnable
                | FutexWaitOutcome::ValueChanged
                | FutexWaitOutcome::Interrupted
                | FutexWaitOutcome::Woken => {
                    wait = PluginShmemOrdering::prepare_futex_wait(slot);
                }
            }
        }
    }

    /// Publishes the boot-wait precondition and waits for scheduler release.
    ///
    /// # Errors
    ///
    /// Returns [`BootBarrierError`] when publishing the wait precondition or
    /// waiting on the non-private futex fails.
    pub fn wait(
        setup_ack: PluginReadySetupAck,
        slot: &NodeSlot,
        icount_shift: u8,
    ) -> Result<BootBarrierRelease, BootBarrierError> {
        let request = Self::prepare_initial_ceiling_wait(setup_ack, slot, icount_shift)?;
        Self::wait_for_initial_ceiling(slot, request)
    }
}

/// An error produced while waiting for the initial scheduler ceiling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BootBarrierError {
    /// Publishing the initial idle precondition failed.
    #[error("publishing boot-barrier idle precondition failed: {source}")]
    PublishIdle {
        /// The shared-memory slot publication error.
        source: NodeSlotError,
    },
    /// Waiting on the non-private futex failed.
    #[error("boot-barrier futex wait failed: {source}")]
    FutexWait {
        /// The futex syscall error.
        source: FutexError,
    },
    /// The no-op futex shim could not prove the scheduler released the barrier.
    #[error(
        "boot barrier first icount {first_guest_icount} is still blocked by ceiling {ceiling_icount}"
    )]
    InitialCeilingStillBlocked {
        /// The first guest icount that must be authorized.
        first_guest_icount: u64,
        /// The currently observed scheduler ceiling.
        ceiling_icount: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::thread;

    use crucible_shmem::{
        FutexWait, KIND_VM, NodeSlot, STATUS_IDLE, STATUS_RUNNING, authorize_advance_ceiling,
    };

    #[test]
    fn boot_barrier_prepares_futex_wait_with_initial_ceiling_zero() {
        let slot = NodeSlot::new(KIND_VM);

        let request = PluginBootBarrier::prepare_initial_ceiling_wait(setup_ack(), &slot, 0)
            .unwrap_or_else(|error| panic!("boot barrier should prepare: {error}"));

        assert_eq!(
            request.first_guest_icount(),
            BOOT_BARRIER_FIRST_GUEST_ICOUNT
        );
        assert_eq!(request.futex_wait(), FutexWait::Wait { expected: 0 });
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 0);
        assert_eq!(snapshot.idle_wake_icount, BOOT_BARRIER_FIRST_GUEST_ICOUNT);
        assert_eq!(snapshot.status, STATUS_IDLE);
    }

    #[test]
    fn boot_barrier_skips_wait_if_scheduler_prepublished_initial_ceiling() {
        let slot = NodeSlot::new(KIND_VM);
        publish_initial_ceiling(&slot, 4);

        let release = PluginBootBarrier::wait(setup_ack(), &slot, 0)
            .unwrap_or_else(|error| panic!("prepublished ceiling should release: {error}"));

        assert_eq!(
            release.first_guest_icount(),
            BOOT_BARRIER_FIRST_GUEST_ICOUNT
        );
        assert_eq!(release.released_ceiling(), 4);
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn boot_barrier_noop_futex_shim_refuses_unreleased_initial_ceiling() {
        let slot = NodeSlot::new(KIND_VM);

        assert_eq!(
            PluginBootBarrier::wait(setup_ack(), &slot, 0),
            Err(BootBarrierError::InitialCeilingStillBlocked {
                first_guest_icount: BOOT_BARRIER_FIRST_GUEST_ICOUNT,
                ceiling_icount: 0,
            })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn boot_barrier_parks_until_scheduler_publishes_initial_ceiling() {
        let slot = Arc::new(NodeSlot::new(KIND_VM));
        let request = PluginBootBarrier::prepare_initial_ceiling_wait(setup_ack(), &slot, 0)
            .unwrap_or_else(|error| panic!("boot barrier should prepare: {error}"));
        let waiter_slot = Arc::clone(&slot);
        let waiter = thread::spawn(move || {
            PluginBootBarrier::wait_for_initial_ceiling(&waiter_slot, request)
        });

        thread::yield_now();
        publish_initial_ceiling(&slot, 2);

        let release = match waiter.join() {
            Ok(Ok(release)) => release,
            Ok(Err(error)) => panic!("boot barrier wait failed: {error}"),
            Err(payload) => std::panic::resume_unwind(payload),
        };
        assert_eq!(release.released_ceiling(), 2);
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);
    }

    fn publish_initial_ceiling(slot: &NodeSlot, max_advance_icount: u64) {
        let ceiling = authorize_advance_ceiling(0, max_advance_icount, None)
            .unwrap_or_else(|error| panic!("initial ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("initial ceiling should publish: {error}"));
    }

    fn setup_ack() -> PluginReadySetupAck {
        PluginReadySetupAck::test_acknowledged()
    }
}
