//! Lends the installed node issuer without copying its physical owner or bank.
//!
//! The genuine host creates the move-only weak witness. Every launch rechecks
//! the same retained process-stage identity and active original control before
//! admission effects. Its node borrower and failure owners keep actual funding;
//! this witness creates no descriptor, deadline or resource allowance.

use super::super::InstalledProcessPurposeError;
use super::*;

/// Borrows one actual installed host's process-stage and original generation.
///
/// The containing physical owner remains responsible for cleanup. Retired,
/// foreign or uncertain custody refuses before artifact or materialization work.
/// Construction is private to the actual host; copied IDs cannot create it.
pub struct InstalledNodeLaunchIssuer {
    attempt: super::super::NativeAccountAttempt,
    process_binding: crate::QemuProcessStageBinding,
}

impl LinuxQemuAttemptHostOwner {
    /// Lends this actual host's issuer while retaining all physical ownership.
    ///
    /// # Errors
    /// Refuses terminal, absent, retired or uncertain original control, or a
    /// configured contract outside the same retained family assignment.
    pub fn lend_installed_node_issuer(
        &self,
    ) -> Result<InstalledNodeLaunchIssuer, QemuLiveNodeStepGateError> {
        if self.terminal || self.fork_target.is_some() {
            return Err(QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: OriginalActorAccountError::Unavailable,
            });
        }
        let contract = self
            .process_contract()
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeContract { source })?;
        let attempt = self
            .original_account
            .as_ref()
            .ok_or(QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: OriginalActorAccountError::Unavailable,
            })?
            .borrow_installed_issuer_attempt(contract)
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
        Ok(InstalledNodeLaunchIssuer {
            attempt,
            process_binding: contract.retain_process_stage_binding(),
        })
    }
}

impl InstalledNodeLaunchIssuer {
    /// Restores the admitted exact node through this same retained issuer.
    ///
    /// # Errors
    /// Refuses a foreign contract, retired/uncertain control or actual restore.
    pub fn launch_exact_node(
        &self,
        request: crate::QemuProductionExactRestoreRequest,
    ) -> Result<crate::QemuProductionExactRestoreLaunch, QemuLiveNodeStepGateError> {
        request.launch_in_issuer(self)
    }

    /// Builds a fresh node using this same process-stage and original generation.
    ///
    /// # Errors
    /// Refuses retired, foreign or uncertain custody and actual fresh launch.
    pub fn launch_fresh_node<'a>(
        &self,
        config: &'a QemuLiveNodeStepGateConfig,
        admission: QemuProductionFreshLaunchAdmission<'a>,
    ) -> Result<QemuNode, QemuLiveNodeStepGateError> {
        let contract = admission.installed_process_contract();
        self.with_issued_node_launch(
            config,
            contract,
            |binding, workspace, _| {
                crate::supervision::launch_qemu_original_fresh_node(
                    config, admission, binding, workspace,
                )
            },
            |node, refusal, after| {
                refusal.record(
                    FreshLaunchCause::Binding(OriginalActorAccountError::Supervision(after)),
                    None,
                    Some(node),
                )
            },
        )
    }

    /// Admits one launch through the same retained generation and process stage.
    ///
    /// # Errors
    /// Refuses lost physical control, a foreign contract, exhausted original
    /// credit, actual launch failure or the independent original postcut.
    pub(crate) fn with_issued_node_launch<'a, T>(
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
        self.attempt
            .require_live_launch_control()
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
        contract
            .verify_process_stage_binding(&self.process_binding)
            .map_err(|_| QemuLiveNodeStepGateError::OriginalNativeAccount {
                source: OriginalActorAccountError::Unavailable,
            })?;
        let mut preparation = self
            .attempt
            .prepare_fresh_launch()
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
        preparation.enter();
        let result = self.launch_original_node(
            config,
            contract,
            &preparation.original,
            Arc::clone(&preparation.failure),
            complete,
            retain_refusal,
        );
        match result {
            Ok(value) => {
                preparation.lease.completed = true;
                Ok(value)
            }
            Err(source) => Err(QemuLiveNodeStepGateError::OriginalNativeLaunch {
                source: self.attempt.retain_launch_refusal(source),
            }),
        }
    }

    pub(super) fn launch_original_node<'a, T>(
        &self,
        config: &'a QemuLiveNodeStepGateConfig,
        contract: &'a crate::QemuChildProcessContract,
        original: &Arc<HostOperationGuard>,
        failure: Arc<OriginalNativeFreshLaunchError>,
        complete: impl FnOnce(
            OriginalNativeNodeBinding,
            Option<crate::spawn::OriginalDeviceDigestWorkspace>,
            &'a crate::QemuChildProcessContract,
        ) -> Result<T, QemuLiveNodeStepGateError>,
        retain_refusal: impl FnOnce(T, &OriginalNativeFreshLaunchError, HostSupervisionError),
    ) -> Result<T, Arc<OriginalNativeFreshLaunchError>> {
        let attempt = &self.attempt;
        let launch = (|| {
            attempt
                .require_live_launch_control()
                .map_err(FreshLaunchCause::Binding)?;
            let mut binding = attempt
                .prepare_node_binding(original)
                .map_err(FreshLaunchCause::Binding)?;
            let artifact_control = binding
                .prepare_source_artifact_controls(contract, original)
                .map_err(FreshLaunchCause::Purpose)?;
            let controls =
                crate::artifact_identity::InstallerControlIdentity::authenticate_original_paths(
                    config.qemu_executable(),
                    config.original_plugin_path(),
                    original,
                    &artifact_control,
                )
                .map_err(FreshLaunchCause::Artifact)?;
            drop(artifact_control);
            let guest_bytes = u64::from(config.memory_mib())
                .checked_mul(1024 * 1024)
                .ok_or(FreshLaunchCause::Purpose(
                    InstalledProcessPurposeError::Capacity,
                ))?;
            let setup_mapping = super::super::original_roster::SetupMappingRequest::for_config(
                config.original_setup_region_config(),
            )
            .map_err(FreshLaunchCause::Purpose)?;
            let purpose = attempt
                .prepare_installed_process_purpose(
                    original,
                    contract,
                    config.qemu_executable(),
                    config.original_plugin_path(),
                    controls,
                    guest_bytes,
                    setup_mapping,
                    config.original_process_generation(),
                )
                .map_err(FreshLaunchCause::Purpose)?;
            // Move the already reserved workspace host term before snapshotting
            // the issued carrier. The local loan retains the incarnation while
            // this no-body transition runs; the binding owns it before Arc/FD
            // or Setup effects. The wire therefore reflects the same final H.
            let workspace_purpose = config
                .requires_device_digest_workspace()
                .then(|| {
                    attempt.prepare_device_digest_workspace(
                        original,
                        config.original_process_generation(),
                    )
                })
                .transpose()
                .map_err(FreshLaunchCause::Binding)?;
            // The real node keeper owns this borrower before workspace or
            // Setup effects. Failed launch cannot reissue its assigned share.
            let record = purpose
                .with_issued_material(
                    original,
                    contract,
                    config.qemu_executable(),
                    config.original_plugin_path(),
                    config.original_process_generation(),
                    |material| material.encode_record(),
                )
                .map_err(FreshLaunchCause::Purpose)?
                .map_err(FreshLaunchCause::Purpose)?;
            binding
                .retain_installed_process_purpose(purpose, record)
                .map_err(FreshLaunchCause::Purpose)?;
            if let Some(purpose) = workspace_purpose {
                let mut held = failure
                    .workspace
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // The already-precreated failure body owns the holder before
                // its first Arc or FD effect. A refusal retains this same slot.
                *held = Some(crate::spawn::OriginalDeviceDigestWorkspace::new(purpose));
                held.as_mut()
                    .ok_or(FreshLaunchCause::Workspace(
                        crate::spawn::DeviceDigestWorkspaceIssueError::Unavailable,
                    ))?
                    .create()
                    .map_err(FreshLaunchCause::Workspace)?;
            }
            let workspace = failure
                .workspace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            complete(binding, workspace, contract).map_err(FreshLaunchCause::Launch)
        })();
        let original_after = original.wait_slice().err();
        match (launch, original_after) {
            (Ok(value), None) => Ok(value),
            (Ok(value), Some(after)) => {
                retain_refusal(value, &failure, after);
                Err(failure)
            }
            (Err(primary), original_after) => {
                failure.record(primary, original_after, None);
                Err(failure)
            }
        }
    }
}
