//! Joins the existing fixed workers under their retained original interval.
//!
//! Refusal leaves this pool and every remaining handle with its caller. A
//! completion counter alone does not prove thread exit: each actual handle
//! must also report completion before its nonblocking join is entered.

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

use super::*;

/// Preserves worker retirement and its independent original postcut.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum OriginalPoolRetirementError {
    /// The same saved interval refused before further retirement work.
    #[error("original worker retirement refused: {0}")]
    Original(#[from] HostSupervisionError),
    /// The actual stopped worker pool refused final reporting.
    #[error("worker pool retirement refused: {cause}; original post: {post:?}")]
    Pool {
        /// The initiating worker or supervisor cause.
        #[source]
        cause: LocalExecutorPoolShutdownError,
        /// A separately observed raw original refusal.
        post: Option<HostSupervisionError>,
    },
    /// A remaining actor lock prevents physical final inspection.
    #[error("worker pool retirement remains occupied; original post: {post:?}")]
    Occupied {
        /// A separately observed raw original refusal.
        post: Option<HostSupervisionError>,
    },
}

impl<L, V> LocalExecutorWorkerPool<L, V>
where
    L: AssignmentLedger + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    /// Stops drained workers using only the same original wait slices.
    ///
    /// The caller retains the entire pool on refusal. No join is entered while
    /// its thread is running, and no fresh timeout or shutdown owner is born.
    ///
    /// # Errors
    /// Refuses active work, an expired original, retained cleanup or occupied
    /// supervisor. A worker cause remains first across a raw original postcut.
    pub(crate) fn try_retire_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalPoolRetirementError> {
        original.wait_slice()?;
        if self.service.shared.completion.is_retained() {
            return Err(OriginalPoolRetirementError::Pool {
                cause: LocalExecutorPoolShutdownError::CleanupPending,
                post: original.wait_slice().err(),
            });
        }
        let executor = self.service.shared.executor.try_lock().map_err(|_| {
            OriginalPoolRetirementError::Occupied {
                post: original.wait_slice().err(),
            }
        })?;
        if executor.supervisor().active_count() != 0 || executor.supervisor().queued_count() != 0 {
            return Err(OriginalPoolRetirementError::Occupied {
                post: original.wait_slice().err(),
            });
        }
        self.service
            .shared
            .promotions
            .try_stop_quiescent(|| {
                self.service
                    .shared
                    .completion
                    .try_signal_quiescent_stop(&self.service.shared.state)
            })
            .map_err(|_| OriginalPoolRetirementError::Occupied {
                post: original.wait_slice().err(),
            })?;
        self.service.shared.ready.notify_all();
        drop(executor);

        while !self.service.shared.completion.is_finished()
            || self.workers.iter().any(|worker| !worker.is_finished())
        {
            if self.service.shared.completion.is_retained() {
                return Err(OriginalPoolRetirementError::Pool {
                    cause: LocalExecutorPoolShutdownError::CleanupPending,
                    post: original.wait_slice().err(),
                });
            }
            thread::park_timeout(original.wait_slice()?);
        }

        let mut panicked = false;
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                panicked = true;
            }
        }
        let cause = if panicked {
            Some(LocalExecutorPoolShutdownError::ThreadPanicked)
        } else if self.service.shared.state.load(Ordering::Acquire) == POOL_POISONED {
            Some(LocalExecutorPoolShutdownError::WorkerPanicked)
        } else {
            None
        };
        if let Some(cause) = cause {
            return Err(OriginalPoolRetirementError::Pool {
                cause,
                post: original.wait_slice().err(),
            });
        }

        let work = match self.service.shared.executor.try_lock() {
            Ok(executor) => {
                if executor.supervisor().active_count() != 0
                    || executor.supervisor().queued_count() != 0
                {
                    Err(OriginalPoolRetirementError::Occupied { post: None })
                } else {
                    Ok(())
                }
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                Err(OriginalPoolRetirementError::Occupied { post: None })
            }
            Err(std::sync::TryLockError::Poisoned(_)) => Err(OriginalPoolRetirementError::Pool {
                cause: LocalExecutorPoolShutdownError::SupervisorPoisoned,
                post: None,
            }),
        };
        let post = original.wait_slice().err();
        match (work, post) {
            (Ok(()), None) => {
                self.original_retired = true;
                Ok(())
            }
            (Ok(_), Some(cause)) => Err(cause.into()),
            (Err(OriginalPoolRetirementError::Occupied { .. }), post) => {
                Err(OriginalPoolRetirementError::Occupied { post })
            }
            (Err(OriginalPoolRetirementError::Pool { cause, .. }), post) => {
                Err(OriginalPoolRetirementError::Pool { cause, post })
            }
            (Err(cause), _) => Err(cause),
        }
    }
}
