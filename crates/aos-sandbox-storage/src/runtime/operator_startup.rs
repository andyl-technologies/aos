//! Existing-only lower writer acquisition and deferred Repair startup.
//!
//! The retained sidecar classification is produced by the actual fourth writer.
//! Debt keeps ordinary startup and dispatch closed until the original same-socket
//! settlement proves release. No historical packet or caller flag opens startup.

use std::path::{Path, PathBuf};

use aos_sandbox_core::ObjectDigest;

use super::{
    ProtectedStorageResolverPolicyDirectoryV1, StorageAdmissionError,
    StorageApplyConstructionV1, StorageBrokerRuntime, StorageIdentityPoolV1,
    StorageRuntimeError, SystemdZfsExecutor, authenticate_startup_authority,
    configure_resolver_policy, trusted_paired_clock_sample,
};
use crate::operator_recovery::{
    OperatorRepairStartupCustodyV4, StorageOperatorRecoveryOwnerV1,
};
use crate::operator_recovery_credentials::StorageOperatorRecoveryCredentialsV1;

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
        authenticate_startup_authority(&self.coordinator)?;
        let primary = self.coordinator.native_metadata_readback_cut(directory)?;
        let workspace = self.workspaces.as_ref()
            .ok_or(StorageRuntimeError::Recovery)?
            .native_metadata_readback_cut(directory)?;
        let native = self.native_issuance.as_mut()
            .ok_or(StorageRuntimeError::Recovery)?;
        native.validate_active_holds(&self.coordinator)
            .map_err(|_| StorageRuntimeError::Recovery)?;
        let native = native.operator_terminal_readback_cut_v4()
            .map_err(|_| StorageRuntimeError::Recovery)?;

        Ok(OperatorStartupLowerCutV4 { primary, workspace, native })
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
