//! Fixed-root ownership and ambiguity-safe Mount-manager startup capture.
//!
//! The owner is the only public path from a claimed initial descriptor table to
//! namespace-45 startup authority. It retains the canonical protected Mount
//! journal lock, claims the purpose-scoped guard internally, and reopens the
//! same fixed file to classify an append whose durability became unknown.

use std::path::Path;

use aos_sandbox_linux::startup_fd_table::ClaimedInitialProcessFdTableV1;
use aos_sandbox_protocol::mount_manager_startup::{
    ManagerSourceControlRequestV1, MountManagerStartupPolicyV1,
    SignedManagerSourceControlOutcomeV1, encode_mount_manager_startup_policy_v1,
    mount_manager_startup_policy_key_v1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2;

use super::authority::{StagedMountManagerStartupCaptureV1, stage_mount_manager_startup_v1};
use super::custody::{
    recover_fresh_manager_source_handoff_v1, recover_fresh_manager_source_presence_v1,
    recover_fresh_manager_source_removal_receipt_v1, recover_fresh_manager_source_removal_v1,
    validate_current_manager_source_control_request_v1,
    validate_historical_manager_source_control_request_v1,
};
use super::{
    FreshManagerSourceHandoffPendingV1, FreshManagerSourceHandoffRecoveryV1,
    FreshManagerSourceNegativeReadbackPendingV1, FreshManagerSourcePresenceProjectionV1,
    FreshManagerSourcePresenceV1, FreshManagerSourceReadbackPendingV1,
    FreshManagerSourceRemovalPendingV1, FreshManagerSourceRemovalProjectionV1,
    FreshManagerSourceRemovalReceiptV1, FreshManagerSourceRemovalRecoveryV1,
    ManagerSourceControlAuthorityV1, ManagerSourceCustodyError, MountManagerSourceInventoryError,
    MountManagerStartupAuthorityV1,
};
use crate::journal::{
    Journal, JournalError, JournalLimits, MountManagerStartupCaptureRecoveryV1, RecordNamespace,
    RecoveryReport,
};
use crate::{
    MountSourceAcquisitionJournalAuthorityV2, MountSourceConsumptionJournalAuthorityV1,
    MountSourceMigrationJournalAuthorityV2,
};

const PROTECTED_MOUNT_MANAGER_ROOT: &str = "/var/lib/aos/sandbox-mount";
const MOUNT_MANAGER_JOURNAL: &str = "mount.journal";

/// Reports exact protected replay completed while opening the fixed owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountManagerStartupProtectedOpenReportV1 {
    /// Reports structural journal replay and tail truncation.
    pub journal: RecoveryReport,
    /// Names the validated current `AOSMMSTA1` generation.
    pub policy_generation: u64,
    /// Counts the validated gap-free immutable `AOSMMCAP1` history.
    pub capture_count: usize,
}

/// Reports the sole successful result of protected startup capture.
#[must_use = "startup authority must be consumed by the Mount manager"]
pub enum MountManagerStartupCaptureOutcomeV1 {
    /// Carries descriptor, source-presence, absence, and control capabilities.
    Captured(MountManagerStartupAuthorityV1),
}

/// Owns the dormant fixed-root Mount-manager startup journal boundary.
///
/// The raw journal and namespace-45 claim never escape this type. There is no
/// path, basename, limit, record selector, sequence, or role input on capture.
pub struct MountManagerStartupProtectedOwnerV1 {
    journal: Option<Journal>,
}

/// Borrows the sole already-open fixed Mount journal for source operations.
///
/// This capability retains neither a second lock nor the raw journal beyond
/// its caller's mutable borrow. Its constructor verifies the protected fixed
/// path, limits, and complete startup-policy replay before lending any scope.
pub struct MountManagerStartupJournalBorrowV1<'journal> {
    journal: &'journal mut Journal,
}

/// Borrows the fixed owner while issuing and validating manager control state.
///
/// Every protected check claims the retained fixed journal internally. The
/// session exposes neither a raw [`Journal`] nor a caller-constructible
/// protected authority guard.
pub struct MountManagerSourceControlSessionV1<'owner> {
    journal: &'owner mut Journal,
}

impl<'journal> MountManagerStartupJournalBorrowV1<'journal> {
    /// Borrows an existing protected fixed Mount journal without opening it.
    ///
    /// # Errors
    ///
    /// Rejects a journal from another directory, a replaced fixed path,
    /// incorrect limits, invalid startup replay, or unhealthy journal state.
    pub fn borrow_fixed(
        journal: &'journal mut Journal,
    ) -> Result<Self, MountManagerSourceInventoryError> {
        journal.require_protected_location(
            Path::new(PROTECTED_MOUNT_MANAGER_ROOT),
            MOUNT_MANAGER_JOURNAL,
            0,
            mount_manager_journal_limits(),
        )?;
        {
            let authority = journal.claim_mount_manager_startup_authority()?;
            authority.validate_mount_manager_startup_replay_v1()?;
        }
        Ok(Self { journal })
    }

    /// Lends the exact namespace-40 journal scope for one operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained journal is no longer healthy.
    pub fn source_acquisition_authority(
        &mut self,
    ) -> Result<MountSourceAcquisitionJournalAuthorityV2<'_>, MountManagerSourceInventoryError>
    {
        Ok(MountSourceAcquisitionJournalAuthorityV2::claim(
            self.journal,
        )?)
    }

    /// Lends the purpose-limited source-consumption scope for one operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained journal is no longer healthy.
    pub fn source_consumption_authority(
        &mut self,
    ) -> Result<MountSourceConsumptionJournalAuthorityV1<'_>, MountManagerSourceInventoryError>
    {
        Ok(MountSourceConsumptionJournalAuthorityV1::claim(
            self.journal,
        )?)
    }

    /// Borrows the validated Mount-manager control scope for one operation.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or noncanonical protected startup history.
    pub fn control_session(
        &mut self,
    ) -> Result<MountManagerSourceControlSessionV1<'_>, MountManagerSourceInventoryError> {
        {
            let authority = self.journal.claim_mount_manager_startup_authority()?;
            authority.validate_mount_manager_startup_replay_v1()?;
        }
        Ok(MountManagerSourceControlSessionV1 {
            journal: self.journal,
        })
    }
}

impl MountManagerStartupCaptureOutcomeV1 {
    /// Consumes the successful outcome into its complete startup authority.
    #[must_use]
    pub fn into_authority(self) -> MountManagerStartupAuthorityV1 {
        match self {
            Self::Captured(authority) => authority,
        }
    }
}

impl MountManagerStartupProtectedOwnerV1 {
    /// Installs a canonical policy in the fixed protected Mount journal offline.
    ///
    /// The journal lock excludes the running Mount broker. An exact current
    /// policy is an idempotent retry; a different policy must be its valid
    /// monotone successor. A fresh protected reopen and full replay confirm
    /// the result, including after an ambiguous append.
    ///
    /// # Errors
    ///
    /// Rejects an unsafe or busy journal, a malformed or noncanonical policy,
    /// invalid history, a discontinuous successor, or unconfirmed durability.
    pub fn provision_fixed_protected_policy_v1(
        policy: MountManagerStartupPolicyV1,
    ) -> Result<(u64, [u8; 32]), MountManagerSourceInventoryError> {
        let expected = encode_mount_manager_startup_policy_v1(&policy)
            .map_err(|_| MountManagerSourceInventoryError::InvalidPolicy)?;
        let identity = (policy.generation, policy.record_digest);
        let (mut journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_MOUNT_MANAGER_ROOT),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
        )?;
        let installed = match install_policy_once(&mut journal, policy, &expected) {
            Ok(()) => Ok(()),
            Err(error) if journal.ensure_healthy().is_ok() => return Err(error.into()),
            Err(error) => Err(error),
        };
        drop(journal);

        let reopened = Journal::open_protected_at(
            Path::new(PROTECTED_MOUNT_MANAGER_ROOT),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
        );
        let (mut journal, _) = match reopened {
            Ok(reopened) => reopened,
            Err(source) => {
                return Err(
                    MountManagerSourceInventoryError::PolicyDurabilityIndeterminate { source },
                );
            }
        };
        let confirmed = journal.get(
            RecordNamespace::MountManagerStartupAuthority,
            &mount_manager_startup_policy_key_v1(),
        ) == Some(expected.as_slice());
        if !confirmed {
            return Err(installed
                .err()
                .unwrap_or(JournalError::AuthorityPreflightMismatch)
                .into());
        }
        let authority = journal.claim_mount_manager_startup_authority()?;
        let (generation, _) = authority.validate_mount_manager_startup_replay_v1()?;
        if generation != identity.0 {
            return Err(JournalError::AuthorityPreflightMismatch.into());
        }
        Ok(identity)
    }

    /// Borrows the fixed namespace-40 owner through a nonescaping lifetime brand.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed owner is unavailable or poisoned.
    #[doc(hidden)]
    pub fn source_acquisition_authority(
        &mut self,
    ) -> Result<MountSourceAcquisitionJournalAuthorityV2<'_>, MountManagerSourceInventoryError>
    {
        Ok(MountSourceAcquisitionJournalAuthorityV2::claim(
            self.current_journal()?,
        )?)
    }

    /// Borrows the fixed Mount journal for one authenticated AOSMSA migration.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed owner is unavailable, poisoned, or cannot
    /// establish the namespace-40-only migration scope.
    #[doc(hidden)]
    pub fn source_migration_authority(
        &mut self,
    ) -> Result<MountSourceMigrationJournalAuthorityV2<'_>, MountManagerSourceInventoryError> {
        Ok(MountSourceMigrationJournalAuthorityV2::claim(
            self.current_journal()?,
        )?)
    }

    /// Borrows the same fixed protected journal for one source-consumption edge.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed owner is unavailable, poisoned, or cannot
    /// establish the closed consumption scope.
    #[doc(hidden)]
    pub fn source_consumption_authority(
        &mut self,
    ) -> Result<MountSourceConsumptionJournalAuthorityV1<'_>, MountManagerSourceInventoryError>
    {
        Ok(MountSourceConsumptionJournalAuthorityV1::claim(
            self.current_journal()?,
        )?)
    }

    /// Opens the canonical root-owned Mount-manager journal and validates replay.
    ///
    /// The fixed directory is `/var/lib/aos/sandbox-mount`, the fixed basename
    /// is `mount.journal`, and the limits are returned by the private closed
    /// policy in this module. Callers cannot redirect startup authority to a
    /// different protected journal.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe root/path/file boundary, lock conflict,
    /// malformed protected history, missing startup policy, or exceeded bound.
    pub fn open_fixed_protected()
    -> Result<(Self, MountManagerStartupProtectedOpenReportV1), MountManagerSourceInventoryError>
    {
        let (mut journal, recovery) = Journal::open_protected_at(
            Path::new(PROTECTED_MOUNT_MANAGER_ROOT),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
        )?;
        let (policy_generation, capture_count) = {
            let authority = journal.claim_mount_manager_startup_authority()?;
            authority.validate_mount_manager_startup_replay_v1()?
        };

        Ok((
            Self {
                journal: Some(journal),
            },
            MountManagerStartupProtectedOpenReportV1 {
                journal: recovery,
                policy_generation,
                capture_count,
            },
        ))
    }

    /// Derives and durably admits the complete claimed startup descriptor table.
    ///
    /// Append ambiguity is resolved by dropping the poisoned handle, reopening
    /// the same fixed protected journal, and comparing the complete staged row
    /// with the canonical history tail. An absent row is retried once from an
    /// exact freshly derived preflight; a second ambiguous append receives one
    /// final reopen/readback before this method fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid kernel or protected state, descriptor-role
    /// mismatch, failed durability, divergent replay, or an outcome that cannot
    /// be resolved by protected reopen/readback.
    pub fn capture(
        &mut self,
        claimed: ClaimedInitialProcessFdTableV1,
    ) -> Result<MountManagerStartupCaptureOutcomeV1, MountManagerSourceInventoryError> {
        let mut staged = {
            let journal = self.current_journal()?;
            let mut authority = journal.claim_mount_manager_startup_authority()?;
            stage_mount_manager_startup_v1(&mut authority, claimed)?
        };
        let initial_commit = {
            let journal = self.current_journal()?;
            let mut authority = journal.claim_mount_manager_startup_authority()?;
            staged.commit(&mut authority)
        };
        match initial_commit {
            Ok(receipt) => finish(staged, Some(receipt)),
            Err(error) if self.current_journal()?.ensure_healthy().is_ok() => Err(error.into()),
            Err(_) => {
                let recovery = self.reopen_and_classify(&staged)?;
                match recovery {
                    MountManagerStartupCaptureRecoveryV1::Applied => finish(staged, None),
                    MountManagerStartupCaptureRecoveryV1::Retry(preflight) => {
                        staged.replace_preflight(preflight);
                        self.retry_once(staged)
                    }
                }
            }
        }
    }

    /// Borrows an opaque control session from the current fixed-root owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained journal is unavailable or its full
    /// startup policy, capture, or acquisition replay is no longer canonical.
    pub fn control_session(
        &mut self,
    ) -> Result<MountManagerSourceControlSessionV1<'_>, MountManagerSourceInventoryError> {
        {
            let journal = self.current_journal()?;
            let authority = journal.claim_mount_manager_startup_authority()?;
            authority.validate_mount_manager_startup_replay_v1()?;
        }
        Ok(MountManagerSourceControlSessionV1 {
            journal: self.current_journal()?,
        })
    }

    fn retry_once(
        &mut self,
        staged: StagedMountManagerStartupCaptureV1,
    ) -> Result<MountManagerStartupCaptureOutcomeV1, MountManagerSourceInventoryError> {
        let retry = {
            let journal = self.current_journal()?;
            let mut authority = journal.claim_mount_manager_startup_authority()?;
            staged.commit(&mut authority)
        };
        match retry {
            Ok(receipt) => finish(staged, Some(receipt)),
            Err(error) if self.current_journal()?.ensure_healthy().is_ok() => Err(error.into()),
            Err(_) => match self.reopen_and_classify(&staged)? {
                MountManagerStartupCaptureRecoveryV1::Applied => finish(staged, None),
                MountManagerStartupCaptureRecoveryV1::Retry(_) => {
                    Err(MountManagerSourceInventoryError::CaptureNotCommitted)
                }
            },
        }
    }

    fn reopen_and_classify(
        &mut self,
        staged: &StagedMountManagerStartupCaptureV1,
    ) -> Result<MountManagerStartupCaptureRecoveryV1, MountManagerSourceInventoryError> {
        self.reopen().map_err(|source| {
            MountManagerSourceInventoryError::CaptureDurabilityIndeterminate { source }
        })?;
        let current_kernel_boot_id = staged.capture_model().execution.kernel_boot_id;
        let journal = self.current_journal()?;
        let authority = journal.claim_mount_manager_startup_authority()?;
        authority
            .recover_mount_manager_startup_capture_v1(
                staged.capture_model(),
                current_kernel_boot_id,
            )
            .map_err(Into::into)
    }

    fn reopen(&mut self) -> Result<(), JournalError> {
        drop(self.journal.take());
        let (mut journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_MOUNT_MANAGER_ROOT),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
        )?;
        {
            let authority = journal.claim_mount_manager_startup_authority()?;
            authority.validate_mount_manager_startup_replay_v1()?;
        }
        self.journal = Some(journal);
        Ok(())
    }

    fn current_journal(&mut self) -> Result<&mut Journal, MountManagerSourceInventoryError> {
        self.journal
            .as_mut()
            .ok_or(MountManagerSourceInventoryError::CaptureOwnerUnavailable)
    }
}

fn install_policy_once(
    journal: &mut Journal,
    policy: MountManagerStartupPolicyV1,
    expected: &[u8],
) -> Result<(), JournalError> {
    let current_is_exact = journal.get(
        RecordNamespace::MountManagerStartupAuthority,
        &mount_manager_startup_policy_key_v1(),
    ) == Some(expected);
    let mut authority = journal.claim_mount_manager_startup_authority()?;
    if current_is_exact {
        authority.validate_mount_manager_startup_replay_v1()?;
        return Ok(());
    }
    let identity = (policy.generation, policy.record_digest);
    let receipt = authority.install_mount_manager_startup_policy_v1(policy)?;
    if receipt.policy() != identity {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

impl MountManagerSourceControlSessionV1<'_> {
    /// Issues one fresh handoff from the exact current source row and policy.
    ///
    /// # Errors
    ///
    /// Returns an error for stale protected state, invalid source projection,
    /// unavailable entropy, or exhausted request revision.
    pub fn begin_handoff(
        &mut self,
        control: &mut ManagerSourceControlAuthorityV1,
        source_row: &SourceAcquisitionRowV2,
    ) -> Result<FreshManagerSourceHandoffPendingV1, ManagerSourceCustodyError> {
        self.with_authority(|authority| control.begin_handoff(authority, source_row))
    }

    /// Issues removal by consuming one exact fresh-presence capability.
    ///
    /// # Errors
    ///
    /// Returns an error for stale protected state, another control session,
    /// unavailable entropy, or exhausted request revision.
    pub fn begin_removal(
        &mut self,
        control: &mut ManagerSourceControlAuthorityV1,
        presence: FreshManagerSourcePresenceV1,
    ) -> Result<FreshManagerSourceRemovalPendingV1, ManagerSourceCustodyError> {
        self.with_authority(|authority| control.begin_removal(authority, presence))
    }

    /// Validates a newly received manager request against the current head.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or a stale policy, capture, key, or
    /// manager execution.
    pub fn validate_current_request(
        &mut self,
        request: &ManagerSourceControlRequestV1,
    ) -> Result<(), ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            validate_current_manager_source_control_request_v1(authority, request)
        })
    }

    /// Validates an in-flight request against current or archived policy.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical bytes or the referenced retained policy
    /// and capture are absent from protected history.
    pub fn validate_historical_request(
        &mut self,
        request: &ManagerSourceControlRequestV1,
    ) -> Result<(), ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            validate_historical_manager_source_control_request_v1(authority, request)
        })
    }

    /// Authenticates handoff acceptance after historical-policy revalidation.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained request is no longer authenticated or
    /// the signed outcome is not its exact descriptor-accepted successor.
    pub fn accept_handoff(
        &mut self,
        pending: FreshManagerSourceHandoffPendingV1,
        accepted: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceReadbackPendingV1, ManagerSourceCustodyError> {
        self.validate_historical_request(pending.request())?;
        pending.accept(accepted)
    }

    /// Authenticates positive readback and mints fresh manager presence.
    ///
    /// # Errors
    ///
    /// Returns an error when protected history changed incompatibly or the
    /// signed readback is not the exact distinct `Present` successor.
    pub fn confirm_present(
        &mut self,
        pending: FreshManagerSourceReadbackPendingV1,
        present: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourcePresenceV1, ManagerSourceCustodyError> {
        self.validate_historical_request(pending.proof().0)?;
        let presence = pending.confirm_present(present)?;
        self.validate_presence_current(&presence)?;
        Ok(presence)
    }

    /// Revalidates fresh presence against the current source row and capture.
    ///
    /// # Errors
    ///
    /// Returns an error after row mutation, capture loss, replay corruption, or
    /// substitution of protected state.
    pub fn validate_presence_current(
        &mut self,
        presence: &FreshManagerSourcePresenceV1,
    ) -> Result<(), ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            presence.validate_current(authority)?;
            Ok(())
        })
    }

    /// Authenticates descriptor removal after historical-policy revalidation.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained request is unauthenticated or the
    /// signed outcome is not its exact descriptor-removed successor.
    pub fn accept_removal(
        &mut self,
        pending: FreshManagerSourceRemovalPendingV1,
        removed: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceNegativeReadbackPendingV1, ManagerSourceCustodyError> {
        self.validate_historical_request(pending.request())?;
        pending.accept_removed(removed)
    }

    /// Authenticates negative readback and mints exact removal authority.
    ///
    /// # Errors
    ///
    /// Returns an error when protected history changed incompatibly or the
    /// signed readback is not the exact distinct `Absent` successor.
    pub fn confirm_absent(
        &mut self,
        pending: FreshManagerSourceNegativeReadbackPendingV1,
        absent: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceRemovalReceiptV1, ManagerSourceCustodyError> {
        self.validate_historical_request(pending.proof().0)?;
        let receipt = pending.confirm_absent(absent)?;
        self.validate_removal_current(&receipt)?;
        Ok(receipt)
    }

    /// Revalidates a removal receipt against the current source descendant.
    ///
    /// # Errors
    ///
    /// Returns an error after incompatible row mutation, capture loss, replay
    /// corruption, or substitution of protected state.
    pub fn validate_removal_current(
        &mut self,
        receipt: &FreshManagerSourceRemovalReceiptV1,
    ) -> Result<(), ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            receipt.validate_current(authority)?;
            Ok(())
        })
    }

    /// Restores an in-flight handoff from authenticated durable protocol rows.
    ///
    /// # Errors
    ///
    /// Returns an error when protected history or the optional signed outcome
    /// does not authenticate exactly.
    pub fn recover_handoff(
        &mut self,
        request: ManagerSourceControlRequestV1,
        accepted: Option<SignedManagerSourceControlOutcomeV1>,
    ) -> Result<FreshManagerSourceHandoffRecoveryV1, ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            recover_fresh_manager_source_handoff_v1(authority, request, accepted)
        })
    }

    /// Restores completed fresh presence from its durable signed projection.
    ///
    /// # Errors
    ///
    /// Returns an error unless policy/capture history and both outcomes
    /// reproduce the exact presence proof.
    pub fn recover_presence(
        &mut self,
        projection: FreshManagerSourcePresenceProjectionV1,
    ) -> Result<FreshManagerSourcePresenceV1, ManagerSourceCustodyError> {
        let presence = self.with_authority(|authority| {
            recover_fresh_manager_source_presence_v1(authority, projection)
        })?;
        self.validate_presence_current(&presence)?;
        Ok(presence)
    }

    /// Restores an in-flight removal from authenticated durable protocol rows.
    ///
    /// # Errors
    ///
    /// Returns an error when prior presence, request, protected history, or the
    /// optional signed outcome is inconsistent.
    pub fn recover_removal(
        &mut self,
        prior_presence: FreshManagerSourcePresenceProjectionV1,
        request: ManagerSourceControlRequestV1,
        removed: Option<SignedManagerSourceControlOutcomeV1>,
    ) -> Result<FreshManagerSourceRemovalRecoveryV1, ManagerSourceCustodyError> {
        self.with_authority(|authority| {
            recover_fresh_manager_source_removal_v1(authority, prior_presence, request, removed)
        })
    }

    /// Restores a completed removal and negative-readback receipt.
    ///
    /// # Errors
    ///
    /// Returns an error unless protected history and the full signed removal
    /// chain reproduce the exact receipt and remain current.
    pub fn recover_removal_receipt(
        &mut self,
        projection: FreshManagerSourceRemovalProjectionV1,
    ) -> Result<FreshManagerSourceRemovalReceiptV1, ManagerSourceCustodyError> {
        let receipt = self.with_authority(|authority| {
            recover_fresh_manager_source_removal_receipt_v1(authority, projection)
        })?;
        self.validate_removal_current(&receipt)?;
        Ok(receipt)
    }

    fn with_authority<R>(
        &mut self,
        operation: impl FnOnce(
            &mut crate::ProtectedJournalAuthority<'_>,
        ) -> Result<R, ManagerSourceCustodyError>,
    ) -> Result<R, ManagerSourceCustodyError> {
        let mut authority = self.journal.claim_mount_manager_startup_authority()?;
        operation(&mut authority)
    }
}

fn finish(
    staged: StagedMountManagerStartupCaptureV1,
    receipt: Option<crate::journal::MountManagerStartupCaptureReceiptV1>,
) -> Result<MountManagerStartupCaptureOutcomeV1, MountManagerSourceInventoryError> {
    staged
        .finish(receipt)
        .map(MountManagerStartupCaptureOutcomeV1::Captured)
}

fn mount_manager_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 4_096,
        maximum_transaction_bytes: 64 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 512 * 1024 * 1024,
        maximum_materialized_records: 1_000_000,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_protocol::mount_manager_startup::{
        StartupExecutableIdentityV1, seal_mount_manager_startup_policy_v1,
    };
    use ed25519_dalek::SigningKey;

    use super::*;

    fn policy() -> MountManagerStartupPolicyV1 {
        let executable = StartupExecutableIdentityV1 {
            device: 1,
            inode: 2,
            size: 3,
            mode: 0o100555,
            fs_verity_sha256: [4; 32],
            build_identity_digest: [5; 32],
        };
        let launcher_executable = StartupExecutableIdentityV1 {
            inode: 6,
            ..executable.clone()
        };
        seal_mount_manager_startup_policy_v1(MountManagerStartupPolicyV1 {
            generation: 1,
            predecessor_generation: 0,
            predecessor_digest: [0; 32],
            deployment_id: [7; 16],
            configuration_generation: 1,
            configuration_digest: [8; 32],
            manager_control_key_id: [9; 16],
            manager_control_key_generation: 1,
            manager_control_public_key: SigningKey::from_bytes(&[10; 32])
                .verifying_key()
                .to_bytes(),
            service_uid: 0,
            service_gid: 0,
            service_unit: "aos-sandbox-mountd.service".to_owned(),
            service_cgroup: "/system.slice/aos-sandbox-mountd.service".to_owned(),
            service_executable: executable,
            launcher_uid: 0,
            launcher_gid: 0,
            launcher_unit: "init.scope".to_owned(),
            launcher_cgroup: "/init.scope".to_owned(),
            launcher_executable,
            standard_descriptor_bitmap: 0b111,
            maximum_descriptor_number: 1024,
            maximum_descriptor_count: 64,
            maximum_activation_count: 32,
            maximum_mount_count: 16,
            maximum_source_count: 8,
            maximum_name_bytes: 255,
            maximum_names_bytes: 4096,
            maximum_capture_bytes: 1024 * 1024,
            maximum_capture_duration_ns: 1_000_000_000,
            listener_name: "aos-sandbox-mount".to_owned(),
            listener_domain: 1,
            listener_socket_type: 5,
            listener_accepting: true,
            listener_local_address: b"/run/aos/sandbox-mount/control.sock".to_vec(),
            record_digest: [0; 32],
        })
        .unwrap()
    }

    #[test]
    fn policy_install_replays_exact_head_and_rejects_discontinuous_successor() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(temporary.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            temporary.path(),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
            uid,
        )
        .unwrap();
        let first = policy();
        let first_bytes = encode_mount_manager_startup_policy_v1(&first).unwrap();

        install_policy_once(&mut journal, first.clone(), &first_bytes).unwrap();
        let first_sequence = journal.snapshot_sequence();
        install_policy_once(&mut journal, first.clone(), &first_bytes).unwrap();
        assert_eq!(journal.snapshot_sequence(), first_sequence);

        let mut skipped = first.clone();
        skipped.generation = 3;
        skipped.predecessor_generation = 2;
        skipped.predecessor_digest = [11; 32];
        skipped.configuration_generation = 3;
        let skipped = seal_mount_manager_startup_policy_v1(skipped).unwrap();
        let skipped_bytes = encode_mount_manager_startup_policy_v1(&skipped).unwrap();
        assert!(install_policy_once(&mut journal, skipped, &skipped_bytes).is_err());
        assert_eq!(journal.snapshot_sequence(), first_sequence);
        drop(journal);

        let (mut reopened, _) = Journal::open_existing_protected_at_uid(
            temporary.path(),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
            uid,
        )
        .unwrap();
        let authority = reopened.claim_mount_manager_startup_authority().unwrap();
        assert_eq!(
            authority
                .validate_mount_manager_startup_replay_v1()
                .unwrap(),
            (1, 0)
        );
        assert_eq!(
            reopened.get(
                RecordNamespace::MountManagerStartupAuthority,
                &mount_manager_startup_policy_key_v1()
            ),
            Some(first_bytes.as_slice())
        );

        let mut successor = first.clone();
        successor.generation = 2;
        successor.predecessor_generation = first.generation;
        successor.predecessor_digest = first.record_digest;
        successor.configuration_generation = 2;
        let successor = seal_mount_manager_startup_policy_v1(successor).unwrap();
        let successor_bytes = encode_mount_manager_startup_policy_v1(&successor).unwrap();
        install_policy_once(&mut reopened, successor, &successor_bytes).unwrap();
        drop(reopened);

        let (mut final_journal, _) = Journal::open_existing_protected_at_uid(
            temporary.path(),
            MOUNT_MANAGER_JOURNAL,
            mount_manager_journal_limits(),
            uid,
        )
        .unwrap();
        let authority = final_journal
            .claim_mount_manager_startup_authority()
            .unwrap();
        assert_eq!(
            authority
                .validate_mount_manager_startup_replay_v1()
                .unwrap(),
            (2, 0)
        );
        assert_eq!(
            final_journal.get(
                RecordNamespace::MountManagerStartupAuthority,
                &mount_manager_startup_policy_key_v1()
            ),
            Some(successor_bytes.as_slice())
        );
    }
}
