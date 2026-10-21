//! Binds retained native progress, exact owner transfer and physical cleanup.
//!
//! These companions authenticate the existing mechanisms; no local physical
//! progress clears the diagnostic funding barrier or issues another Original.

use super::Companion;

pub(super) const CUSTODY: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/retained_node.rs",
    required: &[
        (
            r#"
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
    receiver: Option<crucible_qemu_host::QemuIssuedHelperReceiver>,
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
}

impl RetainedFreshPreparation {
    pub(super) fn new(
        lease: QemuAttemptGenerationLease,
        directory: QemuPreparedRunDirectory,
        receiver: crucible_qemu_host::QemuIssuedHelperReceiver,
    ) -> Self {
        Self {
            lease: Some(lease),
            directory: Some(directory),
            contract: None,
            body: FreshPreparationBody::Empty,
            receiver: Some(receiver),
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
                .is_some_and(|receiver| { self.receiver.as_ref().is_some_and(|saved| saved.same_identity(&receiver)) })
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
        receiver: &crucible_qemu_host::RetainedNativeFreshLaunchError,
    ) {
        let matches = self.native == NativeLaunchProgress::Returned
            && self.receiver.as_ref().is_some_and(|saved| saved.matches_controller(receiver));
        self.native = if matches {
            NativeLaunchProgress::AuthenticatedFailure
        } else {
            NativeLaunchProgress::Unresolved
        };
    }

    /// Retains uncertainty without inventing an owner outside its receiver.
    pub(super) fn mark_unexpected_launch_failure(&mut self) {
        if self.native != NativeLaunchProgress::NotEntered {
            self.native = NativeLaunchProgress::Unresolved;
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
            let receiver = self.receiver.as_ref().and_then(crucible_qemu_host::QemuIssuedHelperReceiver::upgrade).ok_or(CleanupError::Retained(
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
            let receiver = self.receiver.as_ref().and_then(crucible_qemu_host::QemuIssuedHelperReceiver::upgrade).ok_or(CleanupError::Retained(
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
"#,
            1,
        ),
        ("use super::*;", 1),
    ],
};

pub(super) const BIRTH: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/fresh_generation.rs",
    required: &[(
        r#"
    pub(super) fn prepare_fresh_generation(
        &mut self,
        profile: &crucible_qemu_host::QemuLiveNodeStepGateConfig,
        node_id: &crucible_engine::NodeId,
        identity: QemuLiveNodeIdentity<'_>,
        qemu_executable: &std::path::Path,
        root_image: Option<&std::path::Path>,
        observation: Option<(
            crucible_qemu_host::ram_control::RamControlRegistration,
            crucible_host_resources::host_supervision::HostOperationSupervisor,
        )>,
        lease: QemuAttemptGenerationLease,
    ) -> Result<PreparedFreshGeneration, LifecycleApiError> {
        if self.retained_launch.is_some() {
            return Err(abort_unspawned_generation(
                lease,
                LifecycleApiError::CleanupRetained,
            ));
        }
        if profile.qemu_executable() != qemu_executable || profile.root_image() != root_image {
            return Err(abort_unspawned_generation(
                lease,
                launcher_message(
                    "fresh image-tool inputs do not match the exact QEMU launch profile",
                ),
            ));
        }
        if let Err(error) = self.owner.check_operational_boundary() {
            return Err(abort_unspawned_generation(lease, error));
        }
        // Refuse missing custody before creating directory-owned descriptors.
        let receiver = {
            let process_contract = match self.owner.child_process_contract_for_node(node_id) {
                Ok(contract) => contract,
                Err(error) => return Err(abort_unspawned_generation(lease, error)),
            };
            let receiver = process_contract.issued_helper_receiver();
            match receiver {
                Some(receiver) => receiver,
                None => {
                    return Err(abort_unspawned_generation(
                        lease,
                        launcher_message("fresh preparation has no current issued helper receiver"),
                    ));
                }
            }
        };
        let run_directory = match self
            .owner
            .prepare_generation_run_directory_for_node(node_id, profile.resource_requirements())
        {
            Ok(run_directory) => run_directory,
            Err(error) => return Err(abort_unspawned_generation(lease, error)),
        };
        self.retained_launch = Some(RetainedLaunch::Preparation(RetainedFreshPreparation::new(
            lease,
            run_directory,
            receiver,
        )));

        // Borrow disjoint fields: the Main-contained slot owns both resources
        // before the helper can publish a child, refuse a post or unwind.
        let preparation = {
            let process_contract = self.owner.child_process_contract_for_node(node_id)?;
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::CleanupRetained);
            };
            preparation
                .directory_mut()?
                .prepare_fresh_artifacts_guarded(qemu_executable, root_image, process_contract)
        };
        if let Err(error) = preparation {
            if let Some(source) = error.retained_receiver() {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::from_operational(
                        source.backend_cause(),
                    ),
                });
            }
            return Err(launcher_message(format!(
                "prepare fresh QEMU node `{}` failed before issued helper birth: {error}",
                node_id.name,
            )));
        }
        self.owner.check_operational_boundary()?;

        let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_ref() else {
            return Err(LifecycleApiError::CleanupRetained);
        };
        let launch = profile
            .clone()
            .with_run_directory(preparation.directory()?.path());
        let launch = match observation {
            Some((registration, original)) => launch
                .with_ram_control_registration(registration)
                .with_host_operation_supervisor(original),
            None => launch,
        };
        let launched = {
            let process_contract = self.owner.child_process_contract_for_node(node_id)?;
            let retained_contract = process_contract
                .try_clone_for_attempt_generation()
                .map_err(|error| {
                    launcher_message(format!("retain fresh generation contract: {error}"))
                })?;
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::CleanupRetained);
            };
            preparation.retain_contract(retained_contract)?;
            let (directory, native, node_slot) =
                preparation.native_inputs()?;
            match QemuProductionFreshLaunchAdmission::admit(
                &launch,
                directory,
                process_contract,
                identity,
            ) {
                Ok(admission) => {
                    // The same Main phase owns every input before native entry;
                    // unwind must not rewind the local generation fence.
                    *native = retained_node::NativeLaunchProgress::Entered;
                    let launched = self
                        .owner
                        .launch_fresh_node_for_node(node_id, &launch, admission);
                    // This records the actual call's return before inspecting
                    // either body or typed failure. Entry alone proves neither.
                    *native = retained_node::NativeLaunchProgress::Returned;
                    match launched {
                        Ok(node) => {
                            // Save the actual body before interpreting success.
                            *node_slot = retained_node::FreshPreparationBody::Node(node);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        };
        if let Err(mut error) = launched {
            let Some(RetainedLaunch::Preparation(preparation)) = self.retained_launch.as_mut()
            else {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::new(error),
                });
            };
            #[cfg(target_os = "linux")]
            if let crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeLaunch { source } =
                error
            {
                // Only the same issued controller can close this phase. A
                // foreign report retains its own body and closes no local debt.
                preparation.record_native_failure(&source);
                self.owner.quarantine_original_launch();
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::from_operational(
                        source.backend_cause(),
                    ),
                });
            }
            let has_retained_owner = error.has_retained_owner();
            preparation.mark_unexpected_launch_failure();
            if has_retained_owner {
                return Err(LifecycleApiError::BackendConstruction {
                    source: crucible_control_api::LifecycleBackendConstructionError::new(error),
                });
            }
            let message = launch_error_chain(&error);
            return Err(launcher_message(format!(
                "launch guarded fresh QEMU node `{}` refused: {message}",
                node_id.name,
            )));
        }

        // Native success and its independent post are complete. The validated
        // final cut only moves the same owners; it runs no user code or IO.
        match self.retained_launch.take() {
            Some(RetainedLaunch::Preparation(preparation)) => match preparation.into_prepared() {
                Ok(prepared) => Ok(prepared),
                Err(preparation) => {
                    self.retained_launch = Some(RetainedLaunch::Preparation(preparation));
                    Err(LifecycleApiError::CleanupRetained)
                }
            },
            other => {
                self.retained_launch = other;
                Err(LifecycleApiError::CleanupRetained)
            }
        }
    }
"#,
        1,
    )],
};

pub(super) const NATIVE_RETURN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node.rs",
    required: &[
        (
            r#"fn record(&self, primary: FreshLaunchCause, original_after: Option<HostSupervisionError>) {
        // The issued guard returns its actual body before publishing an error.
        // Recording diagnostics never moves that body out of its prepaid cell.
        let _ = self.primary.set(primary);
        if let Some(after) = original_after {
            let _ = self.original_after.set(after);
        }
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn record_returned_cleanup_failure(&self, primary: QemuLiveNodeStepGateError) {
    self.record(FreshLaunchCause::Launch(primary), None);
}"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_exact_launch(
        &self,
        launch: crate::QemuProductionExactRestoreLaunch,
        after: HostSupervisionError,
    ) {
        drop(launch);
        let _ = self.primary.set(FreshLaunchCause::Binding(
            OriginalActorAccountError::Supervision(after),
        ));
        let _ = self.original_after.set(after);
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_exact_artifacts(
        &self,
        artifacts: crate::supervision::exact_restore::QemuExactRestoreArtifacts,
    ) {
        if let Err(artifacts) = self.exact_launch.retain(artifacts) {
            // Duplicate delivery permanently quarantines the original cell.
            // Retain this additional body as well; neither can certify closure.
            std::mem::forget(artifacts);
        }
    }"#,
            1,
        ),
        (
            r#"pub(super) fn physical_owners_returned(&self) -> bool {
        if self
            .child_borrowed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Ok(helper) = self.helper.try_lock() else {
            return false;
        };
        if helper.child.is_some() {
            return false;
        }
        let Ok(retained) = self.node.try_lock() else {
            return false;
        };
        retained.owner.is_none() && self.exact_launch.returned()
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn reserve_exact_artifact_transfer(&self) -> bool {
        self.exact_launch.reserve_transfer()
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn finish_exact_artifact_transfer(&self) -> bool {
        self.exact_launch.finish_transfer()
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn reserve_child_owner(
    &self,
    lender: super::SourceCleanupLender,
    supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
) -> Result<crate::node::SourceLaunchReservation, OriginalActorAccountError> {
    let current = lender.controller()?;
    if !std::ptr::eq(self, current.as_ref()) || self.primary.get().is_some() {
        return Err(OriginalActorAccountError::Unavailable);
    }
    let retained = self
        .node
        .try_lock()
        .map_err(|_| OriginalActorAccountError::Unavailable)?;
    if retained.owner.is_some()
        || self
            .child_borrowed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
    {
        return Err(OriginalActorAccountError::Unavailable);
    }
    drop(retained);
    Ok(crate::node::SourceLaunchReservation::new(
        current, lender, supervisor,
    ))
}"#,
            1,
        ),
        (
            r#"pub(crate) fn finish_child_borrow(&self) {
    self.child_borrowed.store(false, std::sync::atomic::Ordering::Release);
}
pub(crate) fn return_issued_owner(&self, owner: crate::QemuFailedLaunchOwner) {
    let mut retained = match self.node.lock() {
        Ok(retained) => retained,
        Err(poisoned) => poisoned.into_inner(),
    };
    retained.owner = Some(owner);
    self.finish_child_borrow();
}"#,
            1,
        ),
        (
            r#"pub fn retry_physical_cleanup(&self) -> bool {
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
    }"#,
            1,
        ),
        (
            r#"pub fn launch_fresh_node(
    &self,
    config: &QemuLiveNodeStepGateConfig,
    admission: QemuProductionFreshLaunchAdmission<'_>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    let Some(attempt) = self.original_account.as_ref() else {
        return crate::supervision::launch_qemu_production_fresh_node(config, admission);
    };
    let mut preparation = attempt.prepare_fresh_launch()
        .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
    match preparation.launch(
        self, config, admission, crate::supervision::launch_qemu_original_fresh_node,
        |node, failure, after| {
            let mut owner = crate::QemuFailedLaunchOwner::node(node);
            owner.require_source_cleanup(attempt.bound_source_cleanup_lender(failure));
            failure.return_issued_owner(owner);
            failure.record(
                FreshLaunchCause::Binding(OriginalActorAccountError::Supervision(after)), None,
            );
        },
    ) {
        Ok(node) => Ok(node),
        Err(error) => {
            let source = attempt.retain_launch_refusal(error);
            Err(QemuLiveNodeStepGateError::OriginalNativeLaunch { source })
        }
    }
}"#,
            1,
        ),
    ],
};

pub(super) const NATIVE_OWNER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/failed_launch.rs",
    required: &[
        (
            r#"pub(crate) fn node(node: QemuNode) -> Self {
    Self {
        body: Mutex::new(FailedBody::Node(node)),
        #[cfg(target_os = "linux")]
        source_cleanup: FailedSourceCleanup::Existing,
    }
}"#,
            1,
        ),
        (
            r#"pub fn retry_cleanup(&mut self) -> Result<(), QemuNodeError> {
    #[cfg(target_os = "linux")]
    if let FailedSourceCleanup::Required(lender) = &self.source_cleanup {
        let lender = lender.as_ref().map_err(|_| QemuNodeError::RamCleanupPending)?;
        let original = lender.clone().retained_original().map_err(|first| {
            QemuNodeError::RamCleanupLender {
                source: crucible_engine::BackendOperationalCause::new(first),
            }
        })?;
        self.retain_source_original(original)?;
    }
    let mut body = self.body.try_lock().map_err(|_| QemuNodeError::RamCleanupPending)?;
    match &mut *body {
        FailedBody::Node(node) => node.force_quarantine_and_reap(),
        FailedBody::Child(child) => child.retry_cleanup(),
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn require_source_cleanup(
    &mut self,
    lender: Result<
        crate::linux_attempt_host::SourceCleanupLender,
        crate::linux_attempt_host::OriginalActorAccountError,
    >,
) { self.source_cleanup = FailedSourceCleanup::Required(lender); }"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_source_original(
    &mut self,
    original: crate::linux_attempt_host::SourceCleanupOriginal,
) -> Result<(), QemuNodeError> {
    let mut body = self.body.try_lock().map_err(|_| QemuNodeError::RamCleanupPending)?;
    match &mut *body {
        FailedBody::Child(child) => child.retain_source_original(original),
        FailedBody::Node(node) => node.child_shutdown.retain_source_original(original),
    }
    Ok(())
}"#,
            1,
        ),
    ],
};

pub(super) const ISSUED_RETURN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/failed_launch/issued.rs",
    required: &[
        (
            r#"pub(crate) fn new(
    receiver: crate::linux_attempt_host::RetainedNativeFreshLaunchError,
    lender: crate::linux_attempt_host::SourceCleanupLender,
    supervisor: HostOperationSupervisor,
) -> Self { Self { receiver, lender, supervisor, armed: true, } }"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_failed_child(&mut self, child: QemuNodeChild) {
    self.receiver.return_issued_owner(QemuFailedLaunchOwner {
        body: Mutex::new(FailedBody::Child(RetainedChild::new(child, Some(&self.supervisor),))),
        source_cleanup: FailedSourceCleanup::Required(Ok(self.lender.clone())),
    });
    self.armed = false;
}"#,
            1,
        ),
        (
            r#"pub(crate) fn born(mut self, child: QemuNodeChild) -> IssuedLaunchOwner {
    let process_id = child.process_id();
    let body = FailedBody::Child(RetainedChild::new(child, Some(&self.supervisor)));
    let owner = IssuedLaunchOwner {
        body: Some(body), receiver: Some(self.receiver.clone()),
        lender: Some(self.lender.clone()), process_id,
    };
    self.armed = false;
    owner
}"#,
            1,
        ),
        (
            r#"impl Drop for SourceLaunchReservation {
    fn drop(&mut self) {
        if self.armed { self.receiver.finish_child_borrow(); }
    }
}"#,
            1,
        ),
        (
            r#"pub(crate) fn return_to_receiver(&mut self) {
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
    }"#,
            1,
        ),
        (
            r#"pub(crate) fn retain_cleanup_failure(
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
    }"#,
            1,
        ),
        (
            r#"impl Drop for IssuedLaunchOwner {
    fn drop(&mut self) {
        self.return_to_receiver();
    }
}"#,
            1,
        ),
    ],
};

pub(super) const MONOTONE_FINISH: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_resource_guard/generation_resource.rs",
    required: &[(
        r#"fn finish(&mut self) -> Result<(), LifecycleApiError> {
    if self.finished { return Ok(()); }
    let mut state = self.generations.lock()
        .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
    let active = state.nodes.binary_search_by(|row| row.node.cmp(self.identity.node())).ok()
        .and_then(|index| {
            state.nodes[index].active.iter()
                .position(|generation| *generation == Some(self.identity.generation()))
                .map(|active| (index, active))
        });
    let Some((index, active)) = active else {
        state.abandoned = true;
        return Err(generation_error(format!(
            "QEMU node `{}` generation {} has no active lease",
            self.identity.node().name, self.identity.generation(),
        )));
    };
    state.nodes[index].active[active] = None;
    self.finished = true;
    Ok(())
}"#,
        1,
    )],
};

pub(super) const NATIVE_ISSUER: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/linux_attempt_host/original_node/issuer.rs",
    required: &[
        (
            r#"pub fn launch_fresh_node<'a>(
    &self,
    config: &'a QemuLiveNodeStepGateConfig,
    admission: QemuProductionFreshLaunchAdmission<'a>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    let contract = admission.installed_process_contract();
    self.with_issued_node_launch(
        config, contract,
        |binding, workspace, _| {
            crate::supervision::launch_qemu_original_fresh_node(
                config, admission, binding, workspace,
            )
        },
        |node, refusal, after| {
            let mut owner = crate::QemuFailedLaunchOwner::node(node);
            owner.require_source_cleanup(self.attempt.bound_source_cleanup_lender(refusal));
            refusal.return_issued_owner(owner);
            refusal.record(
                FreshLaunchCause::Binding(OriginalActorAccountError::Supervision(after)), None,
            );
        },
    )
}"#,
            1,
        ),
        (
            r#"pub(crate) fn with_issued_node_launch<'a, T>(
    &self,
    config: &'a QemuLiveNodeStepGateConfig,
    contract: &'a crate::QemuChildProcessContract,
    complete: impl FnOnce(
        OriginalNativeNodeBinding,
        Option<crate::spawn::OriginalDeviceDigestWorkspace>,
        &'a crate::QemuChildProcessContract,
    ) -> Result<T, QemuLiveNodeStepGateError>,
    retain_refusal: impl FnOnce(T, &OriginalNativeFreshLaunchError, HostSupervisionError),
) -> Result<T, QemuLiveNodeStepGateError> {
    self.attempt.require_live_launch_control()
        .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
    contract.verify_process_stage_binding(&self.process_binding)
        .map_err(|_| QemuLiveNodeStepGateError::OriginalNativeAccount {
            source: OriginalActorAccountError::Unavailable,
        })?;
    let mut preparation = self.attempt.prepare_fresh_launch()
        .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
    preparation.enter();
    let result = self.launch_original_node(
        config, contract, &preparation.original, preparation.failure.clone(),
        complete, retain_refusal,
    );
    match result {
        Ok(value) => { preparation.lease.completed = true; Ok(value) }
        Err(source) => Err(QemuLiveNodeStepGateError::OriginalNativeLaunch {
            source: self.attempt.retain_launch_refusal(source),
        }),
    }
}"#,
            1,
        ),
    ],
};

pub(super) const NATIVE_NODE: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node.rs",
    required: &[
        (
            r#"pub fn force_quarantine_and_reap(&mut self) -> Result<(), QemuNodeError> {
    self.retain_target_shutdown_original()?;
    let process = self.child_shutdown.contain(
        &mut self.child, &mut self.channels, &mut self.lifecycle_state,
        self.shutdown_policy, self.host_io_runtime.host_operation_supervisor(),
    );
    self.finish_shutdown(process).map(|_| ())
}"#,
            1,
        ),
        (
            r#"fn retain_target_shutdown_original(&mut self) -> Result<(), QemuNodeError> {
    if self.child_shutdown.entered() { return Ok(()); }
    #[cfg(target_os = "linux")]
    if let Some(ram) = self.hot_fork_ram_continuation.as_ref() {
        let original = match ram.cleanup.retained_target_cleanup() {
            Ok(original) => original,
            Err(source) => {
                let first = QemuNodeError::RamCleanupLender {
                    source: crucible_engine::BackendOperationalCause::new(source),
                };
                self.child_shutdown.retain_ram_refusal(first.clone());
                return Err(first);
            }
        };
        self.child_shutdown.retain_target_original(original);
    }
    Ok(())
}"#,
            1,
        ),
        (
            r#"fn finish_shutdown(
    &mut self,
    process: Result<QemuShutdownReport, QemuNodeError>,
) -> Result<QemuShutdownReport, QemuNodeError> {
    if !self.child.reaped() { return process; }
    let ram = self.finish_host_ram_cleanup();
    match (process, ram) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(first), Ok(())) | (Ok(_), Err(first)) => Err(first),
        (Err(first), Err(ram)) => Err(QemuNodeError::ShutdownAndRam {
            first: Box::new(first), ram: Box::new(ram),
        }),
    }
}"#,
            1,
        ),
    ],
};

pub(super) const NATIVE_CONTAIN: Companion = Companion {
    path: "crates/crucible/qemu/crucible-qemu-host/src/node/shutdown_continuation.rs",
    required: &[
        (
            r#"pub(super) fn entered(&self) -> bool { self.begin_attempted }"#,
            1,
        ),
        (
            r#"pub(super) fn contain(
    &mut self,
    child: &mut QemuNodeProcessControl,
    channels: &mut QemuNodeChannels,
    lifecycle_state: &mut QemuNodeLifecycleState,
    policy: QemuShutdownPolicy,
    supervisor: Option<&HostOperationSupervisor>,
) -> Result<QemuShutdownReport, QemuNodeError> {
    self.close_mode(child, channels, lifecycle_state, policy, supervisor, true)
}"#,
            1,
        ),
        (
            r#"fn close_mode(
    &mut self,
    child: &mut QemuNodeProcessControl,
    channels: &mut QemuNodeChannels,
    lifecycle_state: &mut QemuNodeLifecycleState,
    policy: QemuShutdownPolicy,
    supervisor: Option<&HostOperationSupervisor>,
    containment: bool,
) -> Result<QemuShutdownReport, QemuNodeError> {
    let output = self.close_process(
        child, Some(channels.plugin_control.as_mut()),
        Some(channels.qmp_machine_control.as_mut()), policy, supervisor, containment,
    );
    if child.reaped() {
        channels.qmp_machine_control.retire_process_scoped_endpoints_after_reap();
        *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
    }
    output
}"#,
            1,
        ),
    ],
};

// Keep fixture construction separate from the guarded destructor control so
// each causal mutation reaches that actual control rather than an earlier test.
pub(super) const NATIVE_CONTROLS: Companion = Companion {
    path: "crates/crucible/control/crucible-daemon/src/qemu_lifecycle_launcher/retained_node/tests.rs",
    required: &[
        (
            r#"
use super::*;
use std::os::unix::fs::FileExt;

struct UnexecutedGuard {
    cancellation: ExecutionCancellation,
}

impl crate::QemuAttemptOperationalBoundary for UnexecutedGuard {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        crucible_campaign::AttemptResourceLimits::new(1, 64 * 1024 * 1024, 128 * 1024 * 1024, 8)
            .expect("same component registry limits")
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("descriptor controls cannot execute a guest")
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        panic!("descriptor controls cannot execute a guest")
    }
}

impl crate::QemuAttemptResourceGuard for UnexecutedGuard {
    fn finish(&mut self) -> Result<(), crate::QemuAttemptResourceGuardCleanupFailure> {
        Ok(())
    }

    fn quarantine(&mut self) {
        // This component guard has no native allocation or process to return.
    }
}

struct Fixture {
    owner: QemuAttemptGenerationResourceOwner<UnexecutedGuard>,
    preparation: RetainedFreshPreparation,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let node = crucible_engine::NodeId {
            name: String::from("descriptor-only"),
        };
        let storage = crate::QemuAttemptGenerationStorage::prepare(std::iter::once(&node))?;
        let mut owner = QemuAttemptGenerationResourceOwner::new(
            UnexecutedGuard {
                cancellation: ExecutionCancellation::default(),
            },
            storage,
        );
        let lease = owner.register_generation(ProductionVmNodeGeneration::new(node, 1)?)?;
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory
                .path()
                .join(crucible_qemu_host::DEFAULT_VMSTATE_FILE_NAME),
            b"same pinned VMState",
        )?;
        std::fs::write(
            directory
                .path()
                .join(crucible_qemu_host::DEFAULT_ROOT_OVERLAY_FILE_NAME),
            b"",
        )?;
        let contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
            tempfile::tempfile()?.into(),
            rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?,
            u32::MAX,
            u64::MAX,
            u64::MAX,
        );
        let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
            crucible_qemu_host::QemuLaunchResourceRequirements::from_vm_shape(1, 1, true),
            directory.path(),
            &contract,
        )?;
        assert!(contract.issued_helper_receiver().is_none());
        // This negative fixture has no Source identity and cannot manufacture one.
        let preparation = RetainedFreshPreparation {
            lease: Some(lease),
            directory: Some(prepared),
            contract: Some(contract),
            body: FreshPreparationBody::Empty,
            receiver: None,
            helper_returned: false,
            native: NativeLaunchProgress::NotEntered,
            directory_closing: false,
        };
        Ok(Self {
            owner,
            preparation,
            _directory: directory,
        })
    }

    fn assert_same_owners(&self) -> Result<(), Box<dyn std::error::Error>> {
        let preparation = &self.preparation;
        assert_eq!(
            preparation
                .lease
                .as_ref()
                .expect("same lease")
                .identity()
                .generation(),
            1,
        );
        assert!(preparation.contract.is_some());
        assert!(matches!(preparation.body, FreshPreparationBody::Empty));
        let mut contents = [0; b"same pinned VMState".len()];
        preparation
            .directory()?
            .open_vmstate_for_hot_fork()?
            .read_exact_at(&mut contents, 0)?;
        assert_eq!(&contents, b"same pinned VMState");
        Ok(())
    }

    fn dispose_unexecuted(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // The test created no helper/native call. Dispose its actual descriptors
        // before using the real local registry's exact no-process return.
        drop(self.preparation.contract.take());
        drop(self.preparation.directory.take());
        self.preparation
            .lease
            .as_mut()
            .expect("same lease")
            .abort_without_process()?;
        self.preparation.lease = None;
        self.owner.finish()?;
        Ok(())
    }
}
"#,
            1,
        ),
        (
            r#"
#[test]
fn physical_owner_drop_unwind_keeps_the_actual_return_guard_unresolved()
-> Result<(), Box<dyn std::error::Error>> {
    struct UncertainOwner;

    impl Drop for UncertainOwner {
        fn drop(&mut self) {
            panic!("physical owner destruction interrupted")
        }
    }

    let mut fixture = Fixture::new()?;
    // This invokes only the production progress guard, not an issued Source
    // poll. A normal negative keeps the same retry state; an actual destructor
    // unwind must leave it irrevocably rejecting before any later observation.
    fixture.preparation.native = NativeLaunchProgress::AuthenticatedFailure;
    assert!(
        !fixture
            .preparation
            .native
            .observe_physical_return(|| false)
    );
    assert!(fixture.preparation.native == NativeLaunchProgress::AuthenticatedFailure);

    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.preparation.native.observe_physical_return(|| {
            drop(Some(UncertainOwner));
            true
        })
    }));
    let first = first.expect_err("actual destructor panic must remain outward");
    assert_eq!(
        first.downcast_ref::<&str>(),
        Some(&"physical owner destruction interrupted"),
    );
    assert!(fixture.preparation.native == NativeLaunchProgress::Unresolved);
    for _ in 0..2 {
        assert!(matches!(
            fixture.preparation.finish(),
            Err(crate::ProductionVmConstructionCleanupError::Retained(
                "fresh native entry has no authenticated returned failure",
            ))
        ));
        assert!(fixture.preparation.native == NativeLaunchProgress::Unresolved);
        fixture.assert_same_owners()?;
    }
    fixture.dispose_unexecuted()
}
"#,
            1,
        ),
    ],
};
