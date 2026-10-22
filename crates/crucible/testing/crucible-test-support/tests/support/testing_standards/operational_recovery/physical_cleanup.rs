//! Binds physical cleanup observations to the same retained owner and history.
//!
//! These complete local functions continue existing custody; they do not rerun
//! failed tests or replace an Original. Exact expression counts reject added
//! effects or another copy. This source contract proves no allocation funding,
//! Native provider return, RAM release or completed RFC lifecycle qualification.

/// Binds the complete helper settlement body.
pub(super) const HELPER_SETTLEMENT: &str = r##"fn settle_helper(
    &self,
    slot: &mut HelperDebt,
    receiver: &crate::linux_attempt_host::SourceCleanupLender,
) {
    let Some(child) = slot.child.as_mut() else {
        return;
    };
    if !child.child_reaped() {
        let original = match receiver.clone().retained_original() {
            Ok(original) => original,
            Err(first) => {
                slot.observe(crate::QemuNodeError::RamCleanupLender {
                    source: crucible_engine::BackendOperationalCause::new(first),
                });
                return;
            }
        };
        child.retain_source_original(original);
        if let Err(first) = child.retry_cleanup() {
            slot.observe(first);
        }
    }
    // Helpers have no RAM source; actual reap closes their physical leaves.
    if slot
        .child
        .as_ref()
        .is_some_and(crate::node::RetainedChild::child_reaped)
    {
        drop(slot.child.take());
    }
}"##;

/// Binds the complete helper continuation body.
pub(super) const HELPER_CONTINUATION: &str = r##"pub fn retry_retained_helper(&self) -> bool {
    let Ok(mut slot) = self.helper.try_lock() else {
        return false;
    };
    if slot.child.is_none() {
        return true;
    }
    let Some(receiver) = slot.lender.clone() else {
        return false;
    };
    self.settle_helper(&mut slot, &receiver);
    slot.child.is_none()
}"##;

/// Binds the complete controller continuation body.
pub(super) const CONTROLLER_CONTINUATION: &str = r##"pub fn retry_physical_cleanup(&self) -> bool {
        if !self.retry_retained_helper() {
            return false;
        }
        if self
            .child_borrowed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Ok(mut retained) = self.node.try_lock() else {
            return false;
        };
        let Some(owner) = retained.owner.as_mut() else {
            drop(retained);
            return self.exact_launch.close();
        };
        match owner.retry_cleanup() {
            Ok(()) => {
                let returned = retained.owner.take();
                drop(retained);
                drop(returned);
                self.exact_launch.close()
            }
            Err(first) => {
                if retained.first_cleanup.is_none() {
                    retained.first_cleanup = Some(first);
                } else if retained.latest_cleanup.as_ref() != Some(&first) {
                    retained.latest_cleanup = Some(first);
                }
                false
            }
        }
    }"##;

/// Binds the complete issued continuation body.
pub(super) const ISSUED_CONTINUATION: &str = r##"pub(crate) fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
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
}"##;

/// Binds the complete child continuation body.
pub(super) const CHILD_CONTINUATION: &str = r##"pub(crate) fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
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
}"##;

/// Binds the complete failed continuation body.
pub(super) const FAILED_CONTINUATION: &str = r##"pub fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
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
}"##;

/// Binds the complete absent lender control body.
pub(super) const ABSENT_LENDER_CONTROL: &str = r##"fn absent_issued_source_lender_keeps_actual_child_without_fallback_cleanup()
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
}"##;

/// Binds the complete restore settlement body.
pub(super) const RESTORE_SETTLEMENT: &str = r##"pub(super) fn reap_failed_restore_child(
    owner: &mut crate::node::IssuedLaunchOwner,
    primary: QemuNodeFactoryError,
) -> QemuNodeFactoryError {
    match owner.retry_cleanup() {
        Ok(()) => primary,
        Err(cleanup) => QemuNodeFactoryError::FailedRestoreCleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}"##;

/// Binds the complete issued failure settlement body.
pub(super) const ISSUED_FAILURE_SETTLEMENT: &str = r##"fn reap_failed_live_node_child(
    mut child: crate::node::IssuedLaunchOwner,
    primary: QemuLiveNodeStepGateError,
) -> QemuLiveNodeStepGateError {
    match child.retry_cleanup() {
        Ok(()) => primary,
        Err(cleanup) => child.retain_cleanup_failure(QemuLiveNodeStepGateError::FailedCleanup {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}"##;
/// Binds exact resume to the same prebirth issued return route.
pub(super) const EXACT_RESUME_BOUNDARY: &str = r##"pub(crate) fn resume_restored_exact_node(
    mut owner: crate::node::IssuedLaunchOwner,
) -> Result<crate::node::IssuedLaunchOwner, QemuLiveNodeStepGateError> {
    let result = owner.node_mut().and_then(QemuNode::resume_after_restore);
    if let Err(source) = result {
        let primary = QemuLiveNodeStepGateError::Step {
            operation: "resume repository-restored exact node",
            source,
        };
        return Err(reap_failed_live_node_child(owner, primary));
    }
    Ok(owner)
}"##;
