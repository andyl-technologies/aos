//! Carries one issued launch body back to its preborn Source recipient.
//!
//! The receiver is the existing controller authenticated before child birth.
//! The live guard contains the child or complete Node inline. Publication on
//! unwind performs only the same recipient move, without cleanup or admission.

use super::*;
use std::sync::Arc;

/// Reserves the exact existing receiver before any native child effect.
pub(crate) struct SourceLaunchReservation {
    receiver: crate::linux_attempt_host::RetainedNativeFreshLaunchError,
    lender: crate::linux_attempt_host::SourceCleanupLender,
    supervisor: HostOperationSupervisor,
    armed: bool,
}

impl SourceLaunchReservation {
    pub(crate) fn new(
        receiver: crate::linux_attempt_host::RetainedNativeFreshLaunchError,
        lender: crate::linux_attempt_host::SourceCleanupLender,
        supervisor: HostOperationSupervisor,
    ) -> Self {
        Self {
            receiver,
            lender,
            supervisor,
            armed: true,
        }
    }

    /// Returns an actual born child even when Source enrollment refuses it.
    pub(crate) fn retain_failed_child(&mut self, child: QemuNodeChild) {
        self.receiver.return_issued_owner(QemuFailedLaunchOwner {
            body: Mutex::new(FailedBody::Child(RetainedChild::new(
                child,
                Some(&self.supervisor),
            ))),
            source_cleanup: FailedSourceCleanup::Required(Ok(self.lender.clone())),
        });
        self.armed = false;
    }

    /// Publishes the actual spawn output before any subsequent fallible step.
    pub(crate) fn born(mut self, child: QemuNodeChild) -> IssuedLaunchOwner {
        let process_id = child.process_id();
        let body = FailedBody::Child(RetainedChild::new(child, Some(&self.supervisor)));
        let owner = IssuedLaunchOwner {
            body: Some(body),
            receiver: Some(self.receiver.clone()),
            lender: Some(self.lender.clone()),
            process_id,
        };
        self.armed = false;
        owner
    }
}

impl Drop for SourceLaunchReservation {
    fn drop(&mut self) {
        if self.armed {
            self.receiver.finish_child_borrow();
        }
    }
}

/// Keeps the actual child or full Node with its unique issued return route.
pub(crate) struct IssuedLaunchOwner {
    body: Option<FailedBody>,
    receiver: Option<crate::linux_attempt_host::RetainedNativeFreshLaunchError>,
    lender: Option<crate::linux_attempt_host::SourceCleanupLender>,
    process_id: u32,
}

impl IssuedLaunchOwner {
    /// Retains a component test's actual helper without any issued Source role.
    #[cfg(test)]
    pub(crate) fn component(
        child: QemuNodeChild,
        supervisor: Option<&HostOperationSupervisor>,
    ) -> Self {
        let process_id = child.process_id();
        Self {
            body: Some(FailedBody::Child(RetainedChild::new(child, supervisor))),
            receiver: None,
            lender: None,
            process_id,
        }
    }

    /// Returns the factual PID captured from this guard's actual spawn result.
    pub(crate) const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Borrows the actual child without transferring its return route.
    pub(crate) fn child_mut(&mut self) -> Result<&mut QemuNodeChild, QemuNodeError> {
        match self.body.as_mut() {
            Some(FailedBody::Child(child)) => child
                .direct_child_mut()
                .ok_or(QemuNodeError::RamCleanupPending),
            _ => Err(QemuNodeError::RamCleanupPending),
        }
    }

    /// Stores this issued child's actual source before publishing its worker.
    pub(crate) fn publish_ram_source(
        &mut self,
        socket: std::os::unix::net::UnixStream,
        backing: Arc<dyn crate::ram_source::QemuRamBacking>,
        binding: crucible_qemu_protocol::ram_page::RamPageBinding,
        supervisor: HostOperationSupervisor,
        services: crucible_host_resources::host_services::HostServiceAllocator,
    ) -> Result<(), crate::ram_source::QemuRamSourceError> {
        let receiver = self
            .receiver
            .as_ref()
            .ok_or(crate::ram_source::QemuRamSourceError::Ownership)?;
        let current = self
            .lender
            .as_ref()
            .ok_or(crate::ram_source::QemuRamSourceError::Ownership)?
            .controller()
            .map_err(|_| crate::ram_source::QemuRamSourceError::Ownership)?;
        if !receiver.same_owner(&current) {
            return Err(crate::ram_source::QemuRamSourceError::Ownership);
        }
        let original = receiver.launch_original();
        let child = self
            .child_mut()
            .map_err(|_| crate::ram_source::QemuRamSourceError::Ownership)?;
        if child.ram_source.is_some() || child.ram_source_start.is_some() {
            return Err(crate::ram_source::QemuRamSourceError::Ownership);
        }
        child.ram_source_start = Some(crate::ram_source::SourceInput::new(
            socket, backing, binding,
        ));
        let source = crate::ram_source::QemuRamSourceService::prepare(
            &mut child.ram_source_start,
            supervisor,
            services,
        )?;
        child.ram_source = Some(source);
        let cleanup = child.launch_cleanup.clone();
        child
            .ram_source
            .as_mut()
            .ok_or(crate::ram_source::QemuRamSourceError::Ownership)?
            .publish_retained(&original, cleanup)
    }

    /// Borrows the complete Node after its pure in-place phase conversion.
    pub(crate) fn node_mut(&mut self) -> Result<&mut QemuNode, QemuNodeError> {
        match self.body.as_mut() {
            Some(FailedBody::Node(node)) => Ok(node),
            _ => Err(QemuNodeError::RamCleanupPending),
        }
    }

    /// Converts the same child only after every fallible preparation step.
    ///
    /// The caller supplies the fixed pure Node assembly, with its channels and
    /// runtime allocations already prepared. It must perform no callback or
    /// fallible work while the child is between its two enum variants.
    pub(crate) fn assemble_node(
        &mut self,
        assemble: impl FnOnce(QemuNodeChild) -> QemuNode,
    ) -> Result<(), QemuNodeError> {
        let Some(body) = self.body.take() else {
            return Err(QemuNodeError::RamCleanupPending);
        };
        match body {
            FailedBody::Child(child) => {
                let RetainedChild {
                    child,
                    cleanup,
                    supervisor,
                } = child;
                match child {
                    QemuNodeProcessControl::Direct(child) => {
                        let mut node = assemble(child);
                        node.child_shutdown = cleanup;
                        self.body = Some(FailedBody::Node(node));
                        Ok(())
                    }
                    child => {
                        self.body = Some(FailedBody::Child(RetainedChild {
                            child,
                            cleanup,
                            supervisor,
                        }));
                        Err(QemuNodeError::RamCleanupPending)
                    }
                }
            }
            body => {
                self.body = Some(body);
                Err(QemuNodeError::RamCleanupPending)
            }
        }
    }

    /// Continues the same nominal cleanup while this exact owner remains held.
    pub(crate) fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
        let original = self
            .lender
            .as_ref()
            .map(|lender| lender.clone().retained_original())
            .transpose()
            .map_err(|first| QemuNodeError::RamCleanupLender {
                source: crucible_engine::BackendOperationalCause::new(first),
            })?;
        match self.body.as_mut() {
            Some(FailedBody::Child(child)) => {
                if let Some(original) = original {
                    child.retain_source_original(original);
                }
                child.retry_cleanup()
            }
            Some(FailedBody::Node(node)) => {
                if let Some(original) = original {
                    node.child_shutdown.retain_source_original(original);
                }
                node.force_quarantine_and_reap()
            }
            None => Err(QemuNodeError::RamCleanupPending),
        }
    }

    /// Moves only the successfully assembled Node to its next actual owner.
    pub(crate) fn into_node(mut self) -> Result<QemuNode, Self> {
        match self.body.take() {
            Some(FailedBody::Node(node)) => Ok(node),
            body => {
                self.body = body;
                Err(self)
            }
        }
    }

    /// Moves the retained body to its prebirth receiver without cleanup work.
    pub(crate) fn return_to_receiver(&mut self) {
        if let Some(receiver) = self.receiver.take() {
            if let Some(body) = self.body.take() {
                receiver.return_issued_owner(QemuFailedLaunchOwner {
                    body: Mutex::new(body),
                    source_cleanup: FailedSourceCleanup::Required(
                        self.lender.take().ok_or(
                            crate::linux_attempt_host::OriginalActorAccountError::Unavailable,
                        ),
                    ),
                });
            } else {
                receiver.finish_child_borrow();
            }
        }
    }

    /// Returns the actual body before publishing its retained cleanup error.
    pub(crate) fn retain_cleanup_failure(
        mut self,
        primary: crate::QemuLiveNodeStepGateError,
    ) -> crate::QemuLiveNodeStepGateError {
        let receiver = self.receiver.clone();
        self.return_to_receiver();
        match receiver {
            Some(source) => {
                source.record_returned_cleanup_failure(primary);
                crate::QemuLiveNodeStepGateError::OriginalNativeLaunch { source }
            }
            None => primary,
        }
    }
}

impl Drop for IssuedLaunchOwner {
    fn drop(&mut self) {
        self.return_to_receiver();
    }
}

#[cfg(test)]
#[path = "issued/tests.rs"]
mod tests;
