//! Existing-only lower writer acquisition, empty provisioning, and deferred Repair startup.
//!
//! The retained sidecar classification is produced by the actual fourth writer.
//! Debt keeps ordinary startup and dispatch closed until the original same-socket
//! settlement proves release. No historical packet or caller flag opens startup.
//! Explicit provisioning creates only empty fixed sidecar names under all
//! three authenticated lower writers, then exits without constructing a runtime.

use std::path::{Path, PathBuf};

use aos_sandbox_core::ObjectDigest;

use super::{
    ProtectedStorageResolverPolicyDirectoryV1, StorageAdmissionCoordinator,
    StorageAdmissionError, StorageApplyConstructionV1, StorageBrokerRuntime,
    StorageIdentityPoolV1, StorageNativeIssuanceLedgerV1, StorageRuntimeError,
    StorageStartupOutcomeV4, SystemdZfsExecutor, ValidatedPendingStorageWorkspaceCatalogV1,
    WorkspacePinRuntimeIo, authenticate_startup_authority, configure_resolver_policy,
    trusted_paired_clock_sample,
};
use crate::DurableStoragePhase;
use crate::operator_recovery::{
    OperatorRepairStartupCustodyV4, StorageOperatorRecoveryOwnerV1,
};
use crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1;

const OPERATOR_STATE_DIRECTORY: &str = "/var/lib/aos/sandbox-storage";

#[derive(Clone, Copy)]
pub(super) enum OperatorStartupSelectionV4<'a> {
    Ordinary,
    Existing(&'a StorageOperatorRecoveryCredentialsV1),
    ProvisionEmpty(&'a StorageOperatorRecoveryCredentialsV1),
}

impl<'a> OperatorStartupSelectionV4<'a> {
    pub(super) fn credentials(self) -> Option<&'a StorageOperatorRecoveryCredentialsV1> {
        match self {
            Self::Ordinary => None,
            Self::Existing(credentials) | Self::ProvisionEmpty(credentials) => Some(credentials),
        }
    }
}

pub(super) struct DeferredOperatorStartupV4 {
    pub(super) custody: OperatorRepairStartupCustodyV4,
    policy_directory: Option<PathBuf>,
    authority_binding: ObjectDigest,
    pub(super) lower_cut: Option<OperatorStartupLowerCutV4>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct OperatorStartupLowerCutV4 {
    primary: (u64, ObjectDigest),
    workspace: crate::workspace_catalog::StorageWorkspaceCatalogSnapshotV1,
    native: (u64, ObjectDigest),
}

impl DeferredOperatorStartupV4 {
    pub(super) fn capture(
        owner: &mut StorageOperatorRecoveryOwnerV1,
        policy_directory: Option<&Path>,
        authority_binding: ObjectDigest,
    ) -> Result<Self, StorageRuntimeError> {
        let custody = owner.operator_repair_startup_custody_v4()?;
        owner.recheck_operator_repair_startup_custody_v4(&custody)?;

        Ok(Self {
            custody,
            policy_directory: policy_directory.map(Path::to_path_buf),
            authority_binding,
            lower_cut: None,
        })
    }

    pub(super) fn has_debt(&self) -> bool {
        matches!(&self.custody, OperatorRepairStartupCustodyV4::Unresolved(_))
    }
}

impl StorageBrokerRuntime {
    /// Provisions only fixed empty receipt custody under actual lower writers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn provision_empty_operator_repair_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        credentials: &StorageOperatorRecoveryCredentialsV1,
    ) -> Result<(), StorageRuntimeError> {
        require_fixed_operator_state_directory(state_directory)?;
        match Self::open_root_owned_selected_v4(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            StorageApplyConstructionV1::DormantProtectedWorker,
            OperatorStartupSelectionV4::ProvisionEmpty(credentials),
        )? {
            StorageStartupOutcomeV4::OperatorProvisioned => Ok(()),
            StorageStartupOutcomeV4::Runtime(_, _) => Err(StorageRuntimeError::Recovery),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_existing_operator_repair_v4(
        authority_directory: &Path,
        bootstrap_directory: &Path,
        state_directory: &Path,
        resolver_policy_directory: Option<&Path>,
        identity_pool: StorageIdentityPoolV1,
        zfs_executable: PathBuf,
        executor: SystemdZfsExecutor,
        credentials: &StorageOperatorRecoveryCredentialsV1,
    ) -> Result<(Self, StorageOperatorRecoveryOwnerV1), StorageRuntimeError> {
        let (runtime, owner) = Self::open_root_owned_inner(
            authority_directory,
            bootstrap_directory,
            state_directory,
            resolver_policy_directory,
            identity_pool,
            zfs_executable,
            executor,
            StorageApplyConstructionV1::DormantProtectedWorker,
            Some(credentials),
        )?;
        let owner = owner.ok_or(StorageRuntimeError::Recovery)?;
        Ok((runtime, owner))
    }

    pub(super) fn finish_operator_construction_v4(
        &mut self,
        owner: &mut StorageOperatorRecoveryOwnerV1,
    ) -> Result<(), StorageRuntimeError> {
        let startup = self.operator_startup.as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        owner.recheck_operator_repair_startup_custody_v4(&startup.custody)?;
        let has_debt = startup.has_debt();
        let cut = self.operator_startup_lower_cut_v4()?;
        let startup = self.operator_startup.as_ref()
            .ok_or(StorageRuntimeError::Recovery)?;
        owner.recheck_operator_repair_startup_custody_v4(&startup.custody)?;

        if has_debt {
            self.retain_operator_terminal_exclusion()?;
            if !self.workspaces.as_ref()
                .is_some_and(|catalog| catalog.is_terminally_materialized())
            {
                return Err(StorageRuntimeError::Recovery);
            }

            self.operator_startup.as_mut()
                .ok_or(StorageRuntimeError::Recovery)?.lower_cut = Some(cut);
            // Retain policy DATA without admitting a floor while debt is unresolved.
            let startup = self.operator_startup.as_ref()
                .ok_or(StorageRuntimeError::Recovery)?;
            self.resolver_policies = match startup.policy_directory.as_deref() {
                Some(path) => {
                    let policy = ProtectedStorageResolverPolicyDirectoryV1::open_root_owned(
                        path,
                        startup.authority_binding,
                    ).map_err(|_| StorageRuntimeError::Recovery)?;
                    policy.load().and_then(|catalog| catalog.binding())
                        .map_err(|_| StorageRuntimeError::Recovery)?;
                    Some(policy)
                }
                None => None,
            };
            owner.recheck_operator_repair_startup_custody_v4(&startup.custody)?;
            if self.operator_startup_lower_cut_v4()? != cut {
                return Err(StorageRuntimeError::Recovery);
            }

            return Ok(());
        }

        self.resume_operator_startup_v4()
    }

    pub(super) fn operator_startup_lower_cut_v4(
        &mut self,
    ) -> Result<OperatorStartupLowerCutV4, StorageRuntimeError> {
        let directory = self.held_reader_state_directory.as_deref()
            .ok_or(StorageRuntimeError::Recovery)?;
        operator_startup_lower_cut_v4(
            &self.coordinator,
            self.workspaces.as_ref(),
            self.native_issuance.as_mut(),
            directory,
        )
    }

    pub(super) fn has_deferred_operator_debt_v4(&self) -> bool {
        self.operator_startup.as_ref()
            .is_some_and(DeferredOperatorStartupV4::has_debt)
    }

    /// Continues once under the same held lower writers; any failure requires reopen.
    pub(super) fn resume_operator_startup_v4(&mut self) -> Result<(), StorageRuntimeError> {
        let startup = self.operator_startup.take()
            .ok_or(StorageRuntimeError::Recovery)?;
        let result = (|| {
            let (policies, readiness) = configure_resolver_policy(
                &mut self.coordinator,
                startup.policy_directory.as_deref(),
                startup.authority_binding,
            )?;
            self.resolver_policies = policies;
            self.prepare_readiness = readiness;

            authenticate_startup_authority(&self.coordinator)?;
            self.coordinator.retire_inactive_prepared_at_startup(&mut || {
                trusted_paired_clock_sample()
                    .map_err(|_| StorageAdmissionError::VerificationFailed)
            }).map_err(|_| StorageRuntimeError::Recovery)?;
            authenticate_startup_authority(&self.coordinator)?;
            let (plan, _) = self.coordinator.workspace_catalog_activation_plan()?;
            self.workspaces.as_mut()
                .ok_or(StorageRuntimeError::Recovery)?.revalidate_plan(plan)?;
            self.readiness = self.reconcile_startup()?;
            Ok(())
        })();

        if result.is_err() {
            self.operator_startup = Some(startup);
            self.latch_reopen_required();
        }

        result
    }
}

fn require_fixed_operator_state_directory(directory: &Path) -> Result<(), StorageRuntimeError> {
    if directory.as_os_str() != Path::new(OPERATOR_STATE_DIRECTORY).as_os_str() {
        return Err(StorageRuntimeError::Recovery);
    }
    Ok(())
}

fn operator_startup_lower_cut_v4(
    coordinator: &StorageAdmissionCoordinator,
    workspaces: Option<&ValidatedPendingStorageWorkspaceCatalogV1>,
    native: Option<&mut StorageNativeIssuanceLedgerV1>,
    directory: &Path,
) -> Result<OperatorStartupLowerCutV4, StorageRuntimeError> {
    authenticate_startup_authority(coordinator)?;
    let primary = coordinator.native_metadata_readback_cut(directory)?;
    let workspace = workspaces
        .ok_or(StorageRuntimeError::Recovery)?
        .native_metadata_readback_cut(directory)?;
    let native = native.ok_or(StorageRuntimeError::Recovery)?;
    native.validate_active_holds(coordinator)
        .map_err(|_| StorageRuntimeError::Recovery)?;
    let native = native.operator_terminal_readback_cut_v4()
        .map_err(|_| StorageRuntimeError::Recovery)?;

    Ok(OperatorStartupLowerCutV4 {
        primary,
        workspace,
        native,
    })
}

pub(super) fn provision_empty_operator_sidecar_v4(
    coordinator: &StorageAdmissionCoordinator,
    workspaces: &ValidatedPendingStorageWorkspaceCatalogV1,
    native: &mut StorageNativeIssuanceLedgerV1,
    pin_io: &super::SystemdWorkspacePinRuntimeIo,
    directory: &Path,
    credentials: &StorageOperatorRecoveryCredentialsV1,
) -> Result<(), StorageRuntimeError> {
    require_fixed_operator_state_directory(directory)?;
    if !workspaces.is_terminally_materialized()
        || coordinator.workspace_catalog_activation_plan()?.1.is_none()
        || coordinator.has_held_repair_guard()
    {
        return Err(StorageRuntimeError::Recovery);
    }
    let entries = coordinator.recovery_entries()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    if entries
        .iter()
        .any(|entry| !provisionable_lower_phase(entry.phase()))
        || coordinator.atomic_dataset_snapshot_inventory()?.iter().any(|record| {
            record.phase() != crate::state::AtomicDatasetSnapshotPhaseV1::Committed
        })
    {
        return Err(StorageRuntimeError::Recovery);
    }

    let before = operator_startup_lower_cut_v4(
        coordinator,
        Some(workspaces),
        Some(&mut *native),
        directory,
    )?;
    let physical_root = pin_io.catalog_binding()?;
    credentials.recheck_for_provisioning_v4()?;

    // The sole new write is the fixed empty fourth journal/lock creation.
    // An error retains partial names; no rollback or NotCommitted claim follows.
    let owner = credentials.provision_empty_owner_v4()?;
    owner.recheck_empty_provisioned_v4()?;
    credentials.recheck_for_provisioning_v4()?;
    let after = operator_startup_lower_cut_v4(
        coordinator,
        Some(workspaces),
        Some(&mut *native),
        directory,
    )?;
    if after != before {
        return Err(StorageRuntimeError::Recovery);
    }
    if pin_io.catalog_binding()? != physical_root {
        return Err(StorageRuntimeError::Recovery);
    }
    owner.recheck_empty_provisioned_v4()?;
    credentials.recheck_for_provisioning_v4()?;
    Ok(())
}

fn provisionable_lower_phase(phase: DurableStoragePhase) -> bool {
    matches!(
        phase,
        DurableStoragePhase::Committed | DurableStoragePhase::Aborted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_provisioning_accepts_only_the_exact_fixed_root() {
        assert!(
            require_fixed_operator_state_directory(Path::new(OPERATOR_STATE_DIRECTORY)).is_ok()
        );
        for directory in [
            "/var/lib/aos/sandbox-storage/",
            "/var/lib/aos//sandbox-storage",
            "/var/lib/aos/./sandbox-storage",
            "/var/lib/aos/sandbox-storage/../sandbox-storage",
            "/var/lib/aos/other-storage",
            "var/lib/aos/sandbox-storage",
        ] {
            assert!(matches!(
                require_fixed_operator_state_directory(Path::new(directory)),
                Err(StorageRuntimeError::Recovery),
            ));
        }
    }

    #[test]
    fn ordinary_startup_has_no_operator_creation_selection() {
        let ordinary = OperatorStartupSelectionV4::Ordinary;
        assert!(ordinary.credentials().is_none());
        assert!(!matches!(
            ordinary,
            OperatorStartupSelectionV4::ProvisionEmpty(_),
        ));
    }

    #[test]
    fn operator_provisioning_refuses_prepared_and_ambiguous_lower_effects() {
        assert!(!provisionable_lower_phase(DurableStoragePhase::Prepared));
        assert!(!provisionable_lower_phase(DurableStoragePhase::Ambiguous));
        assert!(provisionable_lower_phase(DurableStoragePhase::Committed));
        assert!(provisionable_lower_phase(DurableStoragePhase::Aborted));
    }
}
