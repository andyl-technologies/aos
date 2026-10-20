//! Retains pre-VM preparation or the actual node through physical cleanup.

use super::*;

#[cfg(test)]
#[path = "retained_node/tests.rs"]
mod tests;

pub(super) enum RetainedLaunch {
    Node(RetainedNodeLaunch),
    Preparation(RetainedFreshPreparation),
}

impl RetainedLaunch {
    pub(super) fn is_preparation(&self) -> bool {
        matches!(self, Self::Preparation(_))
    }

    pub(super) fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        match self {
            Self::Node(node) => node.finish(),
            Self::Preparation(preparation) => preparation.finish(),
        }
    }

    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(super) fn node_mut(&mut self) -> Result<&mut QemuNode, LifecycleApiError> {
        match self {
            Self::Node(node) => node.node_mut(),
            Self::Preparation(_) => Err(LifecycleApiError::CleanupRetained),
        }
    }
}

/// Keeps the exact generation on Main through helper and native admission.
pub(super) struct RetainedFreshPreparation {
    lease: Option<QemuAttemptGenerationLease>,
    directory: Option<QemuPreparedRunDirectory>,
    contract: Option<QemuChildProcessContract>,
    body: FreshPreparationBody,
    receiver: std::sync::Weak<crucible_qemu_host::OriginalNativeFreshLaunchError>,
    helper_returned: bool,
    native: NativeLaunchProgress,
    directory_closing: bool,
}

/// Separates an entered call from its actual return and physical disposition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeLaunchProgress {
    NotEntered,
    Entered,
    Returned,
    AuthenticatedFailure,
    PhysicallyReturned,
    Unresolved,
}

impl NativeLaunchProgress {
    /// Records uncertainty before a physical owner's destructor can unwind.
    fn observe_physical_return(&mut self, poll: impl FnOnce() -> bool) -> bool {
        *self = Self::Unresolved;
        let returned = poll();
        *self = if returned {
            Self::PhysicallyReturned
        } else {
            Self::AuthenticatedFailure
        };
        returned
    }
}

/// Stores either actual returned body in the one preborn inline destination.
pub(super) enum FreshPreparationBody {
    Empty,
    Node(QemuNode),
    Unexpected(crucible_qemu_host::QemuFailedLaunchOwner),
}

impl RetainedFreshPreparation {
    pub(super) fn new(
        lease: QemuAttemptGenerationLease,
        directory: QemuPreparedRunDirectory,
        receiver: std::sync::Weak<crucible_qemu_host::OriginalNativeFreshLaunchError>,
    ) -> Self {
        Self {
            lease: Some(lease),
            directory: Some(directory),
            contract: None,
            body: FreshPreparationBody::Empty,
            receiver,
            helper_returned: false,
            native: NativeLaunchProgress::NotEntered,
            directory_closing: false,
        }
    }

    pub(super) fn directory_mut(
        &mut self,
    ) -> Result<&mut QemuPreparedRunDirectory, LifecycleApiError> {
        self.directory
            .as_mut()
            .ok_or(LifecycleApiError::CleanupRetained)
    }

    pub(super) fn directory(&self) -> Result<&QemuPreparedRunDirectory, LifecycleApiError> {
        self.directory
            .as_ref()
            .ok_or(LifecycleApiError::CleanupRetained)
    }

    /// Saves the existing contract clone before native admission can enter.
    pub(super) fn retain_contract(
        &mut self,
        contract: QemuChildProcessContract,
    ) -> Result<(), LifecycleApiError> {
        if self.contract.is_some()
            || self.native != NativeLaunchProgress::NotEntered
            || self.directory_closing
            || !contract
                .issued_helper_receiver()
                .is_some_and(|receiver| std::sync::Weak::ptr_eq(&self.receiver, &receiver))
        {
            return Err(LifecycleApiError::CleanupRetained);
        }
        self.contract = Some(contract);
        Ok(())
    }

    /// Lends disjoint fields so entry and the returned Node are saved in place.
    pub(super) fn native_inputs(
        &mut self,
    ) -> Result<
        (
            &QemuPreparedRunDirectory,
            &mut NativeLaunchProgress,
            &mut FreshPreparationBody,
        ),
        LifecycleApiError,
    > {
        if self.native != NativeLaunchProgress::NotEntered
            || self.helper_returned
            || self.directory_closing
            || self.lease.is_none()
            || self.contract.is_none()
            || !matches!(self.body, FreshPreparationBody::Empty)
        {
            return Err(LifecycleApiError::CleanupRetained);
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or(LifecycleApiError::CleanupRetained)?;
        Ok((directory, &mut self.native, &mut self.body))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn record_native_failure(
        &mut self,
        receiver: &Arc<crucible_qemu_host::OriginalNativeFreshLaunchError>,
    ) {
        let matches = self.native == NativeLaunchProgress::Returned
            && std::sync::Weak::ptr_eq(&self.receiver, &Arc::downgrade(receiver));
        self.native = if matches {
            NativeLaunchProgress::AuthenticatedFailure
        } else {
            NativeLaunchProgress::Unresolved
        };
    }

    /// Keeps an unexpected actual body without issuing ordinary cleanup for it.
    pub(super) fn retain_unexpected_owner(
        &mut self,
        error: &mut crucible_qemu_host::QemuLiveNodeStepGateError,
    ) {
        if self.native != NativeLaunchProgress::NotEntered {
            self.native = NativeLaunchProgress::Unresolved;
        }
        if matches!(self.body, FreshPreparationBody::Empty)
            && let Some(owner) = error.take_retained_owner()
        {
            self.body = FreshPreparationBody::Unexpected(owner);
        }
    }

    /// Moves all four owners only after the actual native success is installed.
    pub(super) fn into_prepared(self) -> Result<PreparedFreshGeneration, Self> {
        match self {
            Self {
                lease: Some(lease),
                directory: Some(directory),
                contract: Some(contract),
                body: FreshPreparationBody::Node(node),
                native: NativeLaunchProgress::Returned,
                directory_closing: false,
                ..
            } => Ok(PreparedFreshGeneration {
                lease,
                directory,
                node,
                contract,
            }),
            retained => Err(retained),
        }
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        use crate::ProductionVmConstructionCleanupError as CleanupError;

        // Neither a staged successful Node nor a foreign owning error is in
        // the saved controller. Its empty child slot cannot close these bodies.
        if !matches!(self.body, FreshPreparationBody::Empty) {
            return Err(CleanupError::Retained(
                "fresh launch still owns an unresolved same-phase body",
            ));
        }
        if matches!(
            self.native,
            NativeLaunchProgress::Entered
                | NativeLaunchProgress::Returned
                | NativeLaunchProgress::Unresolved
        ) {
            return Err(CleanupError::Retained(
                "fresh native entry has no authenticated returned failure",
            ));
        }
        if self.native == NativeLaunchProgress::AuthenticatedFailure {
            let receiver = self.receiver.upgrade().ok_or(CleanupError::Retained(
                "fresh native receiver is unavailable",
            ))?;
            if !self
                .native
                .observe_physical_return(|| receiver.retry_physical_cleanup())
            {
                return Err(CleanupError::Retained(
                    "fresh native process or RAM return remains pending",
                ));
            }
            self.helper_returned = true;
        } else if !self.helper_returned {
            let receiver = self.receiver.upgrade().ok_or(CleanupError::Retained(
                "pre-VM helper receiver is unavailable",
            ))?;
            if !receiver.retry_retained_helper() {
                return Err(CleanupError::Retained(
                    "pre-VM helper return remains pending",
                ));
            }
            self.helper_returned = true;
        }

        // A destructor unwind leaves uncertain debt, even after Option::take.
        if self.directory_closing {
            return Err(CleanupError::Retained(
                "pre-VM directory closure is uncertain",
            ));
        }
        self.directory_closing = true;
        // Both descriptor owners die before the exact local generation returns.
        drop(self.contract.take());
        drop(self.directory.take());
        self.directory_closing = false;
        if let Some(lease) = self.lease.as_mut() {
            match self.native {
                NativeLaunchProgress::PhysicallyReturned => lease.finish()?,
                NativeLaunchProgress::NotEntered => lease.abort_without_process()?,
                _ => return Err(CleanupError::Retained("fresh native return is unresolved")),
            }
        }
        self.lease = None;

        // The existing Native-funded diagnostic payload has not moved to a
        // fully paid receiver. Local physical progress grants no World return.
        Err(CleanupError::Retained(
            "fresh physical owners and local generation returned; diagnostic funding remains retained",
        ))
    }
}

pub(super) struct RetainedNodeLaunch {
    node: Option<QemuNode>,
    lease: Option<RetainedNodeLease>,
    _run_directory: std::path::PathBuf,
    channels_closed: bool,
}

enum RetainedNodeLease {
    Paired(Box<dyn ProductionVmNodeLease>),
    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    Observed(QemuLifecycleGenerationLease),
}

impl RetainedNodeLaunch {
    pub(super) fn new(launch: ProductionVmNodeLaunch) -> Self {
        let (node, lease, run_directory) = launch.into_retained_parts();
        Self {
            node: Some(node),
            lease: Some(RetainedNodeLease::Paired(lease)),
            _run_directory: run_directory,
            channels_closed: false,
        }
    }

    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(super) fn observed(
        node: QemuNode,
        lease: QemuLifecycleGenerationLease,
        run_directory: std::path::PathBuf,
    ) -> Self {
        Self {
            node: Some(node),
            lease: Some(RetainedNodeLease::Observed(lease)),
            _run_directory: run_directory,
            channels_closed: false,
        }
    }

    #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
    pub(super) fn node_mut(&mut self) -> Result<&mut QemuNode, LifecycleApiError> {
        self.node
            .as_mut()
            .ok_or_else(|| launcher_message("observed native node channels already closed"))
    }

    pub(super) fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        if let Some(node) = self.node.as_mut() {
            node.force_quarantine_and_reap()
                .map_err(crate::ProductionVmConstructionCleanupError::Node)?;
            // An unwind leaves closure unknown and retains this exact lease.
            drop(self.node.take());
            self.channels_closed = true;
        }
        if !self.channels_closed {
            return Err(
                (launcher_message("retained QEMU node channel return is uncertain")).into(),
            );
        }
        if let Some(lease) = self.lease.as_mut() {
            match lease {
                RetainedNodeLease::Paired(lease) => lease.finish()?,
                #[cfg(all(target_os = "linux", any(test, feature = "private-measurement-domain")))]
                RetainedNodeLease::Observed(lease) => lease.finish()?,
            }
        }
        self.lease = None;
        Ok(())
    }
}
