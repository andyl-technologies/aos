//! Joins a genuine preparation watcher without completing its original invocation.
//!
//! The private constructor derives the finite child roster from the one
//! authenticated, returned Preparation guard. The guard's existing Arc must
//! already have its body, aliases and external credits admitted. This module
//! neither allocates that Arc nor issues a resource or deadline. The watcher
//! and child-roster controls likewise require original prebirth payment.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};

use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
    HostSupervisionError, OriginalCaptureSupervisionError,
};

use crate::{ExecutionCancellation, supervision::HOST_WATCHDOG_STACK_BYTES};

mod custody;

pub(crate) use custody::OriginalCaptureCustody;

/// Preserves the first actual supervision refusal observed by the watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginalCaptureWatcherRefusal {
    /// The retained whole-family preparation refused its next real wait.
    Original(HostSupervisionError),
    /// Active-work scanning refused an operation in the shared outer roster.
    CaptureWait {
        /// Actual first wait refusal, including its exact operation and class.
        source: HostSupervisionError,
        /// Separate same-original refusal after that failed wait.
        original_after: Option<HostSupervisionError>,
    },
}

/// Records supervision and join outcomes without erasing a capture's cause.
///
/// The caller retains its capture and physical-cleanup result separately. A
/// joined watcher is not evidence that native or source quarantine retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalCaptureCompletion {
    /// First original refusal before requesting the watcher's stop.
    pub original_before: Option<HostSupervisionError>,
    /// Separate original refusal after the actual join.
    pub original_after: Option<HostSupervisionError>,
    /// Child completion refusal, when it could not complete required work.
    pub child: Option<HostSupervisionError>,
    /// First refusal actually recorded inside the watcher thread.
    pub watcher: Option<OriginalCaptureWatcherRefusal>,
    /// Whether joining the actual watcher returned a panic payload.
    pub join_panicked: bool,
}

impl OriginalCaptureCompletion {
    /// Reports that both guards and the actual watcher accepted completion.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.original_before.is_none()
            && self.original_after.is_none()
            && self.child.is_none()
            && self.watcher.is_none()
            && !self.join_panicked
    }
}

/// Retains a start failure and the same original's independent postcheck.
#[derive(Debug, thiserror::Error)]
pub enum OriginalCaptureStartError {
    /// Authentic derivation refused before a watcher could start.
    #[error(transparent)]
    Derivation(#[from] OriginalCaptureSupervisionError),
    /// The genuine child Preparation operation could not start.
    #[error("original capture operation refused: {source}")]
    Operation {
        /// Actual first child-operation failure.
        #[source]
        source: HostSupervisionError,
        /// Separate same-original refusal after that attempt.
        original: Option<HostSupervisionError>,
    },
    /// The original refused before or after the real watcher construction.
    #[error("original capture boundary refused: {0}")]
    Original(#[source] HostSupervisionError),
    /// A successful thread start was refused at its original postcheck.
    #[error("started capture watcher refused its original boundary: {original}")]
    Started {
        /// Actual original refusal after successful thread publication.
        #[source]
        original: HostSupervisionError,
        /// Real child completion and join, retained separately.
        completion: OriginalCaptureCompletion,
    },
    /// The real, already-budgeted thread could not start.
    #[error("original capture watcher failed: {source}")]
    Watcher {
        /// Actual thread-construction error.
        #[source]
        source: std::io::Error,
        /// Separate same-original refusal after that attempt.
        original: Option<HostSupervisionError>,
    },
}

/// Owns one finite capture watcher and the same returned original guard.
///
/// It stops only its child operation. It never completes, replaces or renews
/// the enclosing supervisor. Keeping this owner in actual failure containment
/// retains the guard alias; dropping a facade alone cannot discharge it.
#[must_use = "join the watcher and retain its completion with physical cleanup"]
pub struct OriginalCaptureWatchdog {
    operation: HostOperationGuard,
    original: Arc<HostOperationGuard>,
    stopped: Arc<AtomicBool>,
    refusal: Arc<OnceLock<OriginalCaptureWatcherRefusal>>,
    cancellation: ExecutionCancellation,
    watcher: Option<JoinHandle<()>>,
    completion: Option<OriginalCaptureCompletion>,
}

/// Retains the one returned Preparation and its exact authenticated root.
///
/// Only the daemon's closed original publisher constructs this authority.
/// Cloning it retains the same guard; it creates no operation, clock or bank.
#[derive(Clone, Debug)]
pub struct OriginalPreparation {
    original: Arc<HostOperationGuard>,
    owner: HostOperationSupervisor,
}

impl OriginalPreparation {
    /// Requests a managed reset while borrowing the retained original guard.
    ///
    /// The driver retains the genuine node/factory owner and authenticates its
    /// completed-write opportunity before this call. The result acknowledges
    /// only QMP acceptance; physical reset, loader reseeding and whole-RAM root
    /// evidence remain separate observations under that same ownership.
    /// This method does not complete the original or create another operation.
    ///
    /// # Errors
    /// Returns the adapter's original typed QMP error for unavailable support,
    /// original refusal, command rejection or uncertain acknowledgement.
    pub fn reset_node_under_original(
        &self,
        node: &mut crucible_qemu::QemuNode,
    ) -> Result<crucible_qemu::QmpCommandComplete, crucible_qemu::QmpError> {
        node.reset_under_original(&self.original)
    }

    pub(crate) fn boundary(&self) -> Result<(), HostSupervisionError> {
        self.original.wait_slice().map(|_| ())
    }

    pub(crate) fn retain_admitted(
        original: Arc<HostOperationGuard>,
        owner: HostOperationSupervisor,
    ) -> Self {
        Self { original, owner }
    }

    pub(crate) fn derive_supervisor(
        &self,
        budgets: HostOperationBudgets,
    ) -> Result<HostOperationSupervisor, OriginalCaptureSupervisionError> {
        self.original
            .begin_original_capture_supervisor(&self.owner, budgets)
    }

    pub(crate) fn stage_capture(
        &self,
        budgets: HostOperationBudgets,
        daemon_epoch: [u8; 32],
    ) -> Result<OriginalCaptureContext, OriginalCaptureStartError> {
        OriginalCaptureContext::derive(
            Arc::clone(&self.original),
            &self.owner,
            budgets,
            daemon_epoch,
        )
    }
}

/// Stages the actual child context before the actor reserves its service.
///
/// No watcher starts until that existing service reservation succeeds. This
/// finite record retains the same original and actual child; it grants no
/// native resource or new clock. Its whole layout needs original payment.
pub(crate) struct OriginalCaptureContext {
    original: Arc<HostOperationGuard>,
    child: HostOperationSupervisor,
    state: crate::supervision::AssignmentHostWatchdog,
    service_owner: [u8; 32],
}

impl OriginalCaptureContext {
    pub(crate) fn derive(
        original: Arc<HostOperationGuard>,
        owner: &HostOperationSupervisor,
        budgets: HostOperationBudgets,
        daemon_epoch: [u8; 32],
    ) -> Result<Self, OriginalCaptureStartError> {
        let child = original.begin_original_capture_supervisor(owner, budgets)?;
        let service_owner = child
            .original_capture_service_owner(&original, daemon_epoch)
            .map_err(OriginalCaptureStartError::Original)?;
        let state = crate::supervision::AssignmentHostWatchdog::for_original_capture(
            child.clone(),
            Arc::clone(&original),
        );
        Ok(Self {
            original,
            child,
            state,
            service_owner,
        })
    }

    pub(crate) const fn service_owner(&self) -> [u8; 32] {
        self.service_owner
    }

    pub(crate) fn start(
        self,
        cancellation: ExecutionCancellation,
    ) -> Result<
        (
            OriginalCaptureWatchdog,
            crate::supervision::AssignmentHostWatchdog,
        ),
        OriginalCaptureStartError,
    > {
        let Self {
            original,
            child,
            state,
            ..
        } = self;
        let watcher = OriginalCaptureWatchdog::start_child(original, child, cancellation)?;
        Ok((watcher, state))
    }
}

impl OriginalCaptureWatchdog {
    /// Samples the existing first-refusal cell before uncertain physical custody is retained.
    pub(crate) fn first_refusal(&self) -> Option<OriginalCaptureWatcherRefusal> {
        self.refusal.get().copied()
    }

    /// Starts one paid watcher under the exact authenticated whole-family Prep.
    ///
    /// `original` owns the same returned guard and must be externally charged
    /// through its final Arc free. `owner` must be its exact original roster;
    /// numeric equality or a child sharing the outer cap is insufficient.
    ///
    /// # Errors
    /// Refuses wrong original identity/class/clock, spent original or child
    /// policy, child control allocation, or actual watcher creation. Missing
    /// whole-purpose admission must already have refused before this call.
    pub fn start(
        original: Arc<HostOperationGuard>,
        owner: &HostOperationSupervisor,
        budgets: HostOperationBudgets,
        cancellation: ExecutionCancellation,
    ) -> Result<Self, OriginalCaptureStartError> {
        let child = original.begin_original_capture_supervisor(owner, budgets)?;
        Self::start_child(original, child, cancellation)
    }

    fn start_child(
        original: Arc<HostOperationGuard>,
        child: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
    ) -> Result<Self, OriginalCaptureStartError> {
        Self::start_child_observed(
            original,
            child,
            cancellation,
            #[cfg(test)]
            None,
        )
    }

    fn start_child_observed(
        original: Arc<HostOperationGuard>,
        child: HostOperationSupervisor,
        cancellation: ExecutionCancellation,
        #[cfg(test)] publication_cut: Option<Arc<tests::RefusalPublicationCut>>,
    ) -> Result<Self, OriginalCaptureStartError> {
        original
            .wait_slice()
            .map_err(OriginalCaptureStartError::Original)?;
        let attempted = child.begin(HostOperationClass::Preparation);
        let after = original.wait_slice();
        let operation = match attempted {
            Ok(operation) => {
                after.map_err(OriginalCaptureStartError::Original)?;
                operation
            }
            Err(source) => {
                return Err(OriginalCaptureStartError::Operation {
                    source,
                    original: after.err(),
                });
            }
        };

        let stopped = Arc::new(AtomicBool::new(false));
        let refusal = Arc::new(OnceLock::new());
        let watcher_stopped = stopped.clone();
        let watcher_refusal = refusal.clone();
        let watcher_original = Arc::clone(&original);
        let watcher_cancellation = cancellation.clone();
        #[cfg(test)]
        let watcher_publication_cut = publication_cut.clone();
        // One existing-size watcher observes both real rosters. The original
        // whole-family Preparation remains finite across repeated captures.
        let attempted = thread::Builder::new()
            .name(String::from("campaign-host-watchdog"))
            .stack_size(HOST_WATCHDOG_STACK_BYTES)
            .spawn(move || {
                while !watcher_stopped.load(Ordering::Acquire) {
                    let observed = match watcher_original.wait_slice() {
                        Err(source) => Err(OriginalCaptureWatcherRefusal::Original(source)),
                        Ok(_) => {
                            let waited = child.wait_for_active_work_change();
                            let after = watcher_original.wait_slice();
                            match waited {
                                Err(source) => Err(OriginalCaptureWatcherRefusal::CaptureWait {
                                    source,
                                    original_after: after.err(),
                                }),
                                Ok(()) => after
                                    .map(|_| ())
                                    .map_err(OriginalCaptureWatcherRefusal::Original),
                            }
                        }
                    };
                    if let Err(source) = observed {
                        #[cfg(test)]
                        if let Some(cut) = &watcher_publication_cut {
                            cut.pause_before_publication();
                        }
                        // A refused wait already happened. Shutdown may stop
                        // signaling, but cannot erase its earlier typed cause.
                        let _ = watcher_refusal.set(source);
                        if !watcher_stopped.load(Ordering::Acquire) {
                            watcher_cancellation.cancel();
                        }
                        break;
                    }
                }
            });

        let watcher = match attempted {
            Ok(watcher) => watcher,
            Err(source) => {
                return Err(OriginalCaptureStartError::Watcher {
                    source,
                    original: original.wait_slice().err(),
                });
            }
        };
        // Publish accessible ownership immediately after a successful spawn,
        // before a post-original refusal can drop an unjoined thread handle.
        let mut custody = Self {
            operation,
            original,
            stopped,
            refusal,
            cancellation,
            watcher: Some(watcher),
            completion: None,
        };
        if let Err(source) = custody.original.wait_slice() {
            #[cfg(test)]
            if let Some(cut) = &publication_cut {
                cut.release();
            }
            let completion = custody.finish();
            return Err(OriginalCaptureStartError::Started {
                original: source,
                completion,
            });
        }
        Ok(custody)
    }

    /// Joins the real watcher while leaving the enclosing invocation live.
    ///
    /// Repeated calls return the same recorded cut. The caller must still
    /// postcheck the retained original at later physical-cleanup boundaries.
    pub fn finish(&mut self) -> OriginalCaptureCompletion {
        if let Some(completion) = self.completion {
            return completion;
        }

        let original_before = self.original.wait_slice().err();
        self.stopped.store(true, Ordering::Release);
        let child = self.operation.complete().err();
        let join_panicked = self
            .watcher
            .take()
            .is_some_and(|watcher| watcher.join().is_err());
        let original_after = self.original.wait_slice().err();
        let completion = OriginalCaptureCompletion {
            original_before,
            original_after,
            child,
            watcher: self.refusal.get().copied(),
            join_panicked,
        };
        if !completion.accepted() {
            self.cancellation.cancel();
        }
        self.completion = Some(completion);
        completion
    }
}

impl Drop for OriginalCaptureWatchdog {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests;
