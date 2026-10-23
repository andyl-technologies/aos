//! Keeps the actual rejected child or complete Node with its original cleanup.
//!
//! The inline mutex makes a Send-only Node safe inside a shared typed error.
//! Cleanup uses nonblocking access; contention or poison never extracts custody.

use super::*;
use crucible_host_resources::host_supervision::HostOperationSupervisor;
use std::sync::Mutex;

#[cfg(target_os = "linux")]
#[path = "failed_launch/issued.rs"]
mod issued;
#[cfg(target_os = "linux")]
pub(crate) use issued::{IssuedLaunchOwner, SourceLaunchReservation};

/// Retains one actual rejected launch phase until all of its RAM bodies return.
///
/// A complete Node retains all channels and its existing shutdown invocation.
/// A pre-Node child enters only its own once-saved containment invocation.
#[must_use = "retain the same launch body through actual process and RAM return"]
pub struct QemuFailedLaunchOwner {
    body: Mutex<FailedBody>,
    #[cfg(target_os = "linux")]
    source_cleanup: FailedSourceCleanup,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum FailedSourceCleanup {
    Existing,
    Required(
        Result<
            crate::linux_attempt_host::SourceCleanupLender,
            crate::linux_attempt_host::OriginalActorAccountError,
        >,
    ),
}

enum FailedBody {
    Child(RetainedChild),
    Node(QemuNode),
}

/// Keeps only the direct child's actual body and its once-entered cleanup.
///
/// Helpers use this smaller body alongside a live Node; they never reserve
/// another full-Node variant merely to retain one direct process.
pub(crate) struct RetainedChild {
    child: QemuNodeProcessControl,
    cleanup: shutdown_continuation::ChildShutdown,
    supervisor: Option<HostOperationSupervisor>,
}

impl RetainedChild {
    pub(crate) fn new(child: QemuNodeChild, supervisor: Option<&HostOperationSupervisor>) -> Self {
        #[cfg(target_os = "linux")]
        let cleanup =
            shutdown_continuation::ChildShutdown::for_launch(child.launch_cleanup.as_ref());
        #[cfg(not(target_os = "linux"))]
        let cleanup = shutdown_continuation::ChildShutdown::new();
        Self {
            child: QemuNodeProcessControl::Direct(child),
            cleanup,
            supervisor: supervisor.cloned(),
        }
    }

    pub(crate) fn process_id(&self) -> u32 {
        self.child.process_id()
    }

    pub(crate) fn direct_child_mut(&mut self) -> Option<&mut QemuNodeChild> {
        match &mut self.child {
            QemuNodeProcessControl::Direct(child) => Some(child),
            QemuNodeProcessControl::External(_) => None,
        }
    }

    pub(crate) fn child_reaped(&self) -> bool {
        self.child.reaped()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_source_original(
        &mut self,
        original: crate::linux_attempt_host::SourceCleanupOriginal,
    ) {
        self.cleanup.retain_source_original(original);
    }

    pub(crate) fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
        let process = self
            .cleanup
            .close_unconstructed(&mut self.child, self.supervisor.as_ref());
        if !self.child.reaped() {
            return process.map(|_| ());
        }
        let ram = self
            .cleanup
            .finish_ram(|original, history| match &mut self.child {
                QemuNodeProcessControl::Direct(child) => {
                    #[cfg(target_os = "linux")]
                    {
                        drop(child.ram_source_start.take());
                        history.source(1, &mut child.ram_source, original)
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        true
                    }
                }
                QemuNodeProcessControl::External(_) => false,
            });
        match (process, ram) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(first), Ok(())) | (Ok(_), Err(first)) => Err(first),
            (Err(first), Err(ram)) => Err(QemuNodeError::ShutdownAndRam {
                first: Box::new(first),
                ram: Box::new(ram),
            }),
        }
    }
}

impl std::fmt::Debug for QemuFailedLaunchOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("QemuFailedLaunchOwner");
        debug.field("process_id", &self.process_id());
        #[cfg(target_os = "linux")]
        debug.field("source_cleanup", &self.source_cleanup);
        debug.finish_non_exhaustive()
    }
}

impl QemuFailedLaunchOwner {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn child(
        child: QemuNodeChild,
        supervisor: Option<&HostOperationSupervisor>,
    ) -> Self {
        Self {
            body: Mutex::new(FailedBody::Child(RetainedChild::new(child, supervisor))),
            #[cfg(target_os = "linux")]
            source_cleanup: FailedSourceCleanup::Existing,
        }
    }

    pub(crate) fn node(node: QemuNode) -> Self {
        Self {
            body: Mutex::new(FailedBody::Node(node)),
            #[cfg(target_os = "linux")]
            source_cleanup: FailedSourceCleanup::Existing,
        }
    }

    /// Returns only the physical identity currently held by this exact body.
    ///
    /// Lock contention or poison supplies no identity or cleanup permission.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        let body = self.body.try_lock().ok()?;
        Some(match &*body {
            FailedBody::Child(child) => child.process_id(),
            FailedBody::Node(node) => node.process_id(),
        })
    }

    /// Observes only the retained process's actual known reap.
    ///
    /// Contention and poison conservatively return false. This fact grants no
    /// RAM/controller return, operation continuation or generation reuse.
    #[must_use]
    pub fn child_reaped(&self) -> bool {
        self.body.try_lock().is_ok_and(|body| match &*body {
            FailedBody::Child(child) => child.child.reaped(),
            FailedBody::Node(node) => node.child_reaped(),
        })
    }

    /// Continues this same body's saved containment and RAM return.
    ///
    /// A negative status never moves the body or renews its Original. Later
    /// physical return is independent of the permanent journaled health.
    ///
    /// # Errors
    /// Returns contention, poison, or the actual process/RAM/Original refusal.
    pub fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
        #[cfg(target_os = "linux")]
        if let FailedSourceCleanup::Required(lender) = &self.source_cleanup {
            let lender = lender
                .as_ref()
                .map_err(|_| QemuNodeError::RamCleanupPending)?;
            let original = lender.clone().retained_original().map_err(|first| {
                QemuNodeError::RamCleanupLender {
                    source: crucible_engine::BackendOperationalCause::new(first),
                }
            })?;
            self.retain_source_original(original)?;
        }
        let mut body = self
            .body
            .try_lock()
            .map_err(|_| QemuNodeError::RamCleanupPending)?;
        match &mut *body {
            FailedBody::Node(node) => node.force_quarantine_and_reap(),
            FailedBody::Child(child) => child.retry_cleanup(),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn require_source_cleanup(
        &mut self,
        lender: Result<
            crate::linux_attempt_host::SourceCleanupLender,
            crate::linux_attempt_host::OriginalActorAccountError,
        >,
    ) {
        self.source_cleanup = FailedSourceCleanup::Required(lender);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_source_original(
        &mut self,
        original: crate::linux_attempt_host::SourceCleanupOriginal,
    ) -> Result<(), QemuNodeError> {
        let mut body = self
            .body
            .try_lock()
            .map_err(|_| QemuNodeError::RamCleanupPending)?;
        match &mut *body {
            FailedBody::Child(child) => child.retain_source_original(original),
            FailedBody::Node(node) => node.child_shutdown.retain_source_original(original),
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod source_return_tests {
    use super::*;
    use crucible_host_resources::host_supervision::HostOperationBudgets;

    #[test]
    fn absent_issued_source_lender_keeps_actual_child_without_fallback_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let process = std::process::Command::new("sleep").arg("60").spawn()?;
        let child = QemuNodeChild::new(process);
        let process_id = child.process_id();
        let mut owner = QemuFailedLaunchOwner::child(child, Some(&supervisor));
        owner.require_source_cleanup(Err(
            crate::linux_attempt_host::OriginalActorAccountError::Unavailable,
        ));
        let before = supervisor.operation_statuses()?.len();

        assert!(matches!(
            owner.retry_cleanup(),
            Err(QemuNodeError::RamCleanupPending)
        ));
        assert_eq!(owner.process_id(), Some(process_id));
        assert!(!owner.child_reaped());
        assert_eq!(supervisor.operation_statuses()?.len(), before);
        assert!(matches!(
            &owner.source_cleanup,
            FailedSourceCleanup::Required(Err(
                crate::linux_attempt_host::OriginalActorAccountError::Unavailable
            ))
        ));

        // The explicit component owner, not an invented Source lender, reaps
        // this test's real child after the negative production cut is checked.
        owner.source_cleanup = FailedSourceCleanup::Existing;
        owner.retry_cleanup()?;
        assert!(owner.child_reaped());
        Ok(())
    }
}
