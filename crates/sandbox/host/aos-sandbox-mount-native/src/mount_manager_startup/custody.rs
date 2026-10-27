//! Move-only fresh SourceRoot handoff, readback, removal, and recovery states.

use aos_sandbox_protocol::mount_manager_startup::{
    ManagerControlPolicyWitnessV1, ManagerControlSourceV1, ManagerSourceControlOperationV1,
    ManagerSourceControlOutcomeKindV1, ManagerSourceControlOutcomeV1,
    ManagerSourceControlProtocolError, ManagerSourceControlRequestV1,
    SignedManagerSourceControlOutcomeV1, derive_manager_control_source_v1,
    seal_manager_source_control_request_v1, verify_signed_manager_source_control_outcome_v1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2;
use rand::{TryRngCore as _, rngs::OsRng};
use sha2::{Digest as _, Sha256};

use super::{ManagerSourcePresenceEvidenceProjectionV1, ManagerSourcePresenceOriginV1};
use crate::{JournalError, ProtectedJournalAuthority};

/// Reports failure to issue or verify manager SourceRoot custody control.
#[derive(Debug, thiserror::Error)]
pub enum ManagerSourceCustodyError {
    /// Protected policy, capture, or execution state is absent or stale.
    #[error("Mount-manager control authority is stale or malformed")]
    Journal(#[from] JournalError),
    /// Canonical request, signed outcome, or transition is invalid.
    #[error("Mount-manager SourceRoot control protocol is invalid")]
    Protocol(#[from] ManagerSourceControlProtocolError),
    /// Kernel randomness for a fresh operation nonce was unavailable.
    #[error("Mount-manager SourceRoot operation entropy is unavailable")]
    Entropy,
    /// The in-memory control-session revision was exhausted.
    #[error("Mount-manager SourceRoot control revision is exhausted")]
    RevisionExhausted,
    /// The fixed-root owner no longer retains a usable protected journal.
    #[error("Mount-manager SourceRoot control owner is unavailable")]
    OwnerUnavailable,
}

/// Issues fresh operations for the exact protected manager execution.
#[must_use = "control authority must remain live while issuing fresh operations"]
pub struct ManagerSourceControlAuthorityV1 {
    policy: ManagerControlPolicyWitnessV1,
    session_id: [u8; 32],
    next_request_revision: u64,
}

/// Waits for the manager to acknowledge a fresh descriptor transfer.
#[must_use = "handoff is not custody until accepted and read back"]
pub struct FreshManagerSourceHandoffPendingV1 {
    request: ManagerSourceControlRequestV1,
}

/// Waits for a distinct positive readback after descriptor acceptance.
#[must_use = "descriptor acceptance alone is not manager presence"]
pub struct FreshManagerSourceReadbackPendingV1 {
    request: ManagerSourceControlRequestV1,
    accepted: SignedManagerSourceControlOutcomeV1,
}

/// Proves fresh manager custody after signed handoff and positive readback.
#[must_use = "fresh manager presence is a move-only custody capability"]
pub struct FreshManagerSourcePresenceV1 {
    projection: FreshManagerSourcePresenceProjectionV1,
}

/// Projects the exact fresh handoff and distinct presence readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshManagerSourcePresenceProjectionV1 {
    /// Common exact custody evidence projection.
    pub evidence: ManagerSourcePresenceEvidenceProjectionV1,
    /// Exact fresh handoff request.
    pub request: ManagerSourceControlRequestV1,
    /// Signed descriptor-accepted outcome.
    pub accepted: SignedManagerSourceControlOutcomeV1,
    /// Signed distinct positive readback.
    pub present: SignedManagerSourceControlOutcomeV1,
    /// Commitment to the complete proof sequence.
    pub presence_commitment: [u8; 32],
}

/// Waits for signed manager removal of one fresh-custody source.
#[must_use = "removal is incomplete until a negative readback"]
pub struct FreshManagerSourceRemovalPendingV1 {
    prior_presence: FreshManagerSourcePresenceProjectionV1,
    request: ManagerSourceControlRequestV1,
}

/// Waits for a distinct negative readback after manager removal.
#[must_use = "descriptor removal alone is not manager absence"]
pub struct FreshManagerSourceNegativeReadbackPendingV1 {
    prior_presence: FreshManagerSourcePresenceProjectionV1,
    request: ManagerSourceControlRequestV1,
    removed: SignedManagerSourceControlOutcomeV1,
}

/// Proves fresh-control removal followed by a distinct negative readback.
#[must_use = "removal receipt is the move-only negative-custody authority"]
pub struct FreshManagerSourceRemovalReceiptV1 {
    projection: FreshManagerSourceRemovalProjectionV1,
}

/// Projects the exact fresh presence, removal, and negative readback chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshManagerSourceRemovalProjectionV1 {
    /// Exact prior fresh presence proof.
    pub prior_presence: FreshManagerSourcePresenceProjectionV1,
    /// Exact removal request.
    pub request: ManagerSourceControlRequestV1,
    /// Signed descriptor-removed outcome.
    pub removed: SignedManagerSourceControlOutcomeV1,
    /// Signed distinct negative readback.
    pub absent: SignedManagerSourceControlOutcomeV1,
    /// Commitment to the complete removal sequence.
    pub removal_commitment: [u8; 32],
}

/// Restores the sole valid in-flight handoff state from durable protocol rows.
#[must_use = "recovered handoff state must be completed or retained"]
pub enum FreshManagerSourceHandoffRecoveryV1 {
    /// No authenticated descriptor-accepted outcome was persisted.
    AwaitingAcceptance(FreshManagerSourceHandoffPendingV1),
    /// Acceptance was authenticated; positive readback remains required.
    AwaitingPresence(FreshManagerSourceReadbackPendingV1),
}

/// Restores the sole valid in-flight removal state from durable protocol rows.
#[must_use = "recovered removal state must be completed or retained"]
pub enum FreshManagerSourceRemovalRecoveryV1 {
    /// No authenticated descriptor-removed outcome was persisted.
    AwaitingRemoval(FreshManagerSourceRemovalPendingV1),
    /// Removal was authenticated; negative readback remains required.
    AwaitingAbsence(FreshManagerSourceNegativeReadbackPendingV1),
}

/// Validates a newly received request against the exact current protected head.
///
/// This is the manager-side admission seam. Historical keys are deliberately
/// rejected so rotation cannot authorize a new operation.
///
/// # Errors
///
/// Returns an error for a malformed request or any policy, capture, key, or
/// manager-execution mismatch with the current protected authority.
pub(crate) fn validate_current_manager_source_control_request_v1(
    authority: &ProtectedJournalAuthority<'_>,
    request: &ManagerSourceControlRequestV1,
) -> Result<(), ManagerSourceCustodyError> {
    aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(request)?;
    authority.validate_manager_control_policy_witness_v1(&request.policy, true)?;
    match request.operation {
        ManagerSourceControlOperationV1::Handoff => {
            authority.validate_mount_manager_source_proof_current_v1(
                request.source.acquisition_id,
                request.source.acquisition_revision,
                request.source.acquisition_record_digest,
                request.policy.capture_id,
                request.policy.capture_record_digest,
            )?;
        }
        ManagerSourceControlOperationV1::Remove => {
            authority.validate_manager_control_source_descendant_v1(
                &request.source,
                request.policy.capture_id,
                request.policy.capture_record_digest,
            )?;
        }
    }
    Ok(())
}

/// Validates a retained in-flight request against current or archived policy.
///
/// This recovery-only seam authenticates exact retained operations but cannot
/// issue a new nonce, session, or request revision.
///
/// # Errors
///
/// Returns an error for malformed bytes or a policy/capture witness absent
/// from the protected monotone history.
pub(crate) fn validate_historical_manager_source_control_request_v1(
    authority: &ProtectedJournalAuthority<'_>,
    request: &ManagerSourceControlRequestV1,
) -> Result<(), ManagerSourceCustodyError> {
    aos_sandbox_protocol::mount_manager_startup::encode_manager_source_control_request_v1(request)?;
    authority.validate_manager_control_policy_witness_v1(&request.policy, false)?;
    authority.validate_manager_control_source_descendant_v1(
        &request.source,
        request.policy.capture_id,
        request.policy.capture_record_digest,
    )?;
    Ok(())
}

impl ManagerSourceControlAuthorityV1 {
    pub(super) fn new(policy: ManagerControlPolicyWitnessV1) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.mount-manager.control-session.v1\0");
        hasher.update(policy.capture_id);
        hasher.update(policy.capture_record_digest);
        hasher.update(policy.control_key_id);
        hasher.update(policy.control_key_generation.to_be_bytes());
        Self {
            policy,
            session_id: hasher.finalize().into(),
            next_request_revision: 1,
        }
    }

    /// Returns the exact policy, capture, and execution witness.
    #[must_use]
    pub const fn policy(&self) -> &ManagerControlPolicyWitnessV1 {
        &self.policy
    }

    /// Issues a fresh handoff request under the still-current protected head.
    ///
    /// The source and activation fields are derived from the reducer's exact
    /// durable row. Two policy-pinned signatures are still required to mint
    /// custody.
    ///
    /// # Errors
    ///
    /// Returns an error for a rotated/stale head, invalid source projection,
    /// unavailable entropy, or exhausted request sequence.
    pub(crate) fn begin_handoff(
        &mut self,
        authority: &ProtectedJournalAuthority<'_>,
        source_row: &SourceAcquisitionRowV2,
    ) -> Result<FreshManagerSourceHandoffPendingV1, ManagerSourceCustodyError> {
        let source = derive_manager_control_source_v1(source_row)
            .map_err(|_| ManagerSourceControlProtocolError::InvalidRecord)?;
        authority.validate_mount_manager_source_proof_current_v1(
            source.acquisition_id,
            source.acquisition_revision,
            source.acquisition_record_digest,
            self.policy.capture_id,
            self.policy.capture_record_digest,
        )?;
        let request = self.issue_request(
            authority,
            ManagerSourceControlOperationV1::Handoff,
            source,
            None,
            None,
        )?;
        Ok(FreshManagerSourceHandoffPendingV1 { request })
    }

    /// Issues removal for one exact fresh-presence capability.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale head, another manager session, unavailable
    /// entropy, or exhausted request sequence.
    pub(crate) fn begin_removal(
        &mut self,
        authority: &ProtectedJournalAuthority<'_>,
        presence: FreshManagerSourcePresenceV1,
    ) -> Result<FreshManagerSourceRemovalPendingV1, ManagerSourceCustodyError> {
        let prior_presence = presence.projection;
        if prior_presence.request.policy != self.policy {
            return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
        }
        authority.validate_manager_control_source_descendant_v1(
            &prior_presence.request.source,
            prior_presence.evidence.capture_id,
            prior_presence.evidence.capture_record_digest,
        )?;
        let request = self.issue_request(
            authority,
            ManagerSourceControlOperationV1::Remove,
            prior_presence.request.source.clone(),
            Some(prior_presence.presence_commitment),
            Some(prior_presence.evidence.manager_descriptor_number),
        )?;
        Ok(FreshManagerSourceRemovalPendingV1 {
            prior_presence,
            request,
        })
    }

    fn issue_request(
        &mut self,
        authority: &ProtectedJournalAuthority<'_>,
        operation: ManagerSourceControlOperationV1,
        source: ManagerControlSourceV1,
        prior_presence_commitment: Option<[u8; 32]>,
        target_descriptor_number: Option<u32>,
    ) -> Result<ManagerSourceControlRequestV1, ManagerSourceCustodyError> {
        authority.validate_manager_control_policy_witness_v1(&self.policy, true)?;
        let request_revision = self.next_request_revision;
        self.next_request_revision = request_revision
            .checked_add(1)
            .ok_or(ManagerSourceCustodyError::RevisionExhausted)?;
        let mut operation_nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut operation_nonce)
            .map_err(|_| ManagerSourceCustodyError::Entropy)?;
        if operation_nonce == [0; 32] {
            return Err(ManagerSourceCustodyError::Entropy);
        }
        seal_manager_source_control_request_v1(ManagerSourceControlRequestV1 {
            operation,
            operation_nonce,
            session_id: self.session_id,
            manager_epoch: self.policy.capture_sequence,
            request_revision,
            policy: self.policy.clone(),
            source,
            prior_presence_commitment: prior_presence_commitment.unwrap_or([0; 32]),
            target_descriptor_number,
            source_entry_commitment: [0; 32],
            request_id: [0; 32],
            record_digest: [0; 32],
        })
        .map_err(Into::into)
    }
}

impl FreshManagerSourceHandoffPendingV1 {
    /// Returns the canonical request for durable storage and transport.
    #[must_use]
    pub const fn request(&self) -> &ManagerSourceControlRequestV1 {
        &self.request
    }

    /// Authenticates descriptor acceptance and advances to positive readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the outcome is the exact signed first response.
    pub(crate) fn accept(
        self,
        accepted: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceReadbackPendingV1, ManagerSourceCustodyError> {
        verify_signed_manager_source_control_outcome_v1(&self.request, None, &accepted)?;
        if accepted.outcome.kind != ManagerSourceControlOutcomeKindV1::DescriptorAccepted {
            return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
        }
        Ok(FreshManagerSourceReadbackPendingV1 {
            request: self.request,
            accepted,
        })
    }
}

impl FreshManagerSourceReadbackPendingV1 {
    /// Returns the request and accepted outcome required for readback.
    #[must_use]
    pub const fn proof(
        &self,
    ) -> (
        &ManagerSourceControlRequestV1,
        &SignedManagerSourceControlOutcomeV1,
    ) {
        (&self.request, &self.accepted)
    }

    /// Authenticates distinct positive readback and mints fresh presence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the outcome is the exact signed successor.
    pub(crate) fn confirm_present(
        self,
        present: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourcePresenceV1, ManagerSourceCustodyError> {
        verify_signed_manager_source_control_outcome_v1(
            &self.request,
            Some(&self.accepted.outcome),
            &present,
        )?;
        if present.outcome.kind != ManagerSourceControlOutcomeKindV1::Present {
            return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
        }
        let presence_commitment = control_sequence_commitment(
            b"aos.sandbox.mount-manager.fresh-presence.v1\0",
            &self.request,
            &self.accepted,
            &present,
        );
        let evidence = fresh_presence_evidence(
            &self.request,
            self.accepted.outcome.manager_descriptor_number,
        );
        Ok(FreshManagerSourcePresenceV1 {
            projection: FreshManagerSourcePresenceProjectionV1 {
                evidence,
                request: self.request,
                accepted: self.accepted,
                present,
                presence_commitment,
            },
        })
    }
}

impl FreshManagerSourcePresenceV1 {
    /// Returns the exact fresh presence projection without consuming authority.
    #[must_use]
    pub const fn projection(&self) -> &FreshManagerSourcePresenceProjectionV1 {
        &self.projection
    }

    /// Returns the common compact custody-evidence projection.
    #[must_use]
    pub const fn custody_evidence(&self) -> &ManagerSourcePresenceEvidenceProjectionV1 {
        &self.projection.evidence
    }

    /// Revalidates the exact source row and capture before custody admission.
    ///
    /// # Errors
    ///
    /// Returns an error after target-row mutation, capture-history loss or
    /// corruption, or use with an unrelated protected authority.
    #[doc(hidden)]
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        let evidence = &self.projection.evidence;
        authority.validate_mount_manager_source_proof_current_v1(
            evidence.acquisition_id,
            evidence.acquisition_revision,
            evidence.acquisition_record_digest,
            evidence.capture_id,
            evidence.capture_record_digest,
        )
    }

    /// Consumes the capability into its durable proof projection.
    #[must_use]
    pub fn into_projection(self) -> FreshManagerSourcePresenceProjectionV1 {
        self.projection
    }
}

impl FreshManagerSourceRemovalPendingV1 {
    /// Returns the exact removal request.
    #[must_use]
    pub const fn request(&self) -> &ManagerSourceControlRequestV1 {
        &self.request
    }

    /// Authenticates descriptor removal and advances to negative readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the outcome is the exact signed first response.
    pub(crate) fn accept_removed(
        self,
        removed: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceNegativeReadbackPendingV1, ManagerSourceCustodyError> {
        verify_signed_manager_source_control_outcome_v1(&self.request, None, &removed)?;
        if removed.outcome.kind != ManagerSourceControlOutcomeKindV1::DescriptorRemoved {
            return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
        }
        Ok(FreshManagerSourceNegativeReadbackPendingV1 {
            prior_presence: self.prior_presence,
            request: self.request,
            removed,
        })
    }
}

impl FreshManagerSourceNegativeReadbackPendingV1 {
    /// Returns the removal proof awaiting its distinct absence readback.
    #[must_use]
    pub const fn proof(
        &self,
    ) -> (
        &ManagerSourceControlRequestV1,
        &SignedManagerSourceControlOutcomeV1,
    ) {
        (&self.request, &self.removed)
    }

    /// Authenticates distinct negative readback and mints removal authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the outcome is the exact signed successor.
    pub(crate) fn confirm_absent(
        self,
        absent: SignedManagerSourceControlOutcomeV1,
    ) -> Result<FreshManagerSourceRemovalReceiptV1, ManagerSourceCustodyError> {
        verify_signed_manager_source_control_outcome_v1(
            &self.request,
            Some(&self.removed.outcome),
            &absent,
        )?;
        if absent.outcome.kind != ManagerSourceControlOutcomeKindV1::Absent {
            return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
        }
        let removal_commitment = control_sequence_commitment(
            b"aos.sandbox.mount-manager.fresh-removal.v1\0",
            &self.request,
            &self.removed,
            &absent,
        );
        Ok(FreshManagerSourceRemovalReceiptV1 {
            projection: FreshManagerSourceRemovalProjectionV1 {
                prior_presence: self.prior_presence,
                request: self.request,
                removed: self.removed,
                absent,
                removal_commitment,
            },
        })
    }
}

impl FreshManagerSourceRemovalReceiptV1 {
    /// Returns the exact removal and negative-readback projection.
    #[must_use]
    pub const fn projection(&self) -> &FreshManagerSourceRemovalProjectionV1 {
        &self.projection
    }

    /// Revalidates the exact target row and capture before removal admission.
    ///
    /// # Errors
    ///
    /// Returns an error after target-row mutation, capture-history loss or
    /// corruption, or use with an unrelated protected authority.
    #[doc(hidden)]
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        let prior = &self.projection.prior_presence;
        authority.validate_manager_control_source_descendant_v1(
            &prior.request.source,
            prior.evidence.capture_id,
            prior.evidence.capture_record_digest,
        )
    }

    /// Consumes the move-only receipt into its durable projection.
    #[must_use]
    pub fn into_projection(self) -> FreshManagerSourceRemovalProjectionV1 {
        self.projection
    }
}

/// Restores an in-flight handoff using a current or archived protected key.
///
/// # Errors
///
/// Returns an error when the policy/capture witness is absent from protected
/// history or the optional accepted outcome does not authenticate exactly.
pub(crate) fn recover_fresh_manager_source_handoff_v1(
    authority: &ProtectedJournalAuthority<'_>,
    request: ManagerSourceControlRequestV1,
    accepted: Option<SignedManagerSourceControlOutcomeV1>,
) -> Result<FreshManagerSourceHandoffRecoveryV1, ManagerSourceCustodyError> {
    authority.validate_manager_control_policy_witness_v1(&request.policy, false)?;
    match accepted {
        Some(accepted) => Ok(FreshManagerSourceHandoffRecoveryV1::AwaitingPresence(
            FreshManagerSourceHandoffPendingV1 { request }.accept(accepted)?,
        )),
        None => Ok(FreshManagerSourceHandoffRecoveryV1::AwaitingAcceptance(
            FreshManagerSourceHandoffPendingV1 { request },
        )),
    }
}

/// Reconstitutes completed fresh presence from its durable signed projection.
///
/// # Errors
///
/// Returns an error unless protected policy/capture history and both signed
/// outcomes reproduce the exact projection commitment.
pub(crate) fn recover_fresh_manager_source_presence_v1(
    authority: &ProtectedJournalAuthority<'_>,
    projection: FreshManagerSourcePresenceProjectionV1,
) -> Result<FreshManagerSourcePresenceV1, ManagerSourceCustodyError> {
    authority.validate_manager_control_policy_witness_v1(&projection.request.policy, false)?;
    validate_fresh_presence_projection(&projection)?;
    Ok(FreshManagerSourcePresenceV1 { projection })
}

/// Restores an in-flight removal using a current or archived protected key.
///
/// # Errors
///
/// Returns an error when protected history, prior presence, the removal
/// request, or its optional first outcome is inconsistent.
pub(crate) fn recover_fresh_manager_source_removal_v1(
    authority: &ProtectedJournalAuthority<'_>,
    prior_presence: FreshManagerSourcePresenceProjectionV1,
    request: ManagerSourceControlRequestV1,
    removed: Option<SignedManagerSourceControlOutcomeV1>,
) -> Result<FreshManagerSourceRemovalRecoveryV1, ManagerSourceCustodyError> {
    authority.validate_manager_control_policy_witness_v1(&request.policy, false)?;
    validate_fresh_presence_projection(&prior_presence)?;
    if request.operation != ManagerSourceControlOperationV1::Remove
        || request.source != prior_presence.request.source
        || request.policy != prior_presence.request.policy
        || request.prior_presence_commitment != prior_presence.presence_commitment
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
    }
    let pending = FreshManagerSourceRemovalPendingV1 {
        prior_presence,
        request,
    };
    match removed {
        Some(removed) => Ok(FreshManagerSourceRemovalRecoveryV1::AwaitingAbsence(
            pending.accept_removed(removed)?,
        )),
        None => Ok(FreshManagerSourceRemovalRecoveryV1::AwaitingRemoval(
            pending,
        )),
    }
}

/// Reconstitutes a completed fresh removal and negative-readback receipt.
///
/// # Errors
///
/// Returns an error unless protected policy/capture history, prior presence,
/// and both signed removal outcomes reproduce the exact receipt commitment.
pub(crate) fn recover_fresh_manager_source_removal_receipt_v1(
    authority: &ProtectedJournalAuthority<'_>,
    projection: FreshManagerSourceRemovalProjectionV1,
) -> Result<FreshManagerSourceRemovalReceiptV1, ManagerSourceCustodyError> {
    authority.validate_manager_control_policy_witness_v1(&projection.request.policy, false)?;
    validate_fresh_presence_projection(&projection.prior_presence)?;
    if projection.request.operation != ManagerSourceControlOperationV1::Remove
        || projection.request.source != projection.prior_presence.request.source
        || projection.request.policy != projection.prior_presence.request.policy
        || projection.request.prior_presence_commitment
            != projection.prior_presence.presence_commitment
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
    }
    verify_signed_manager_source_control_outcome_v1(
        &projection.request,
        None,
        &projection.removed,
    )?;
    verify_signed_manager_source_control_outcome_v1(
        &projection.request,
        Some(&projection.removed.outcome),
        &projection.absent,
    )?;
    if projection.removed.outcome.kind != ManagerSourceControlOutcomeKindV1::DescriptorRemoved
        || projection.absent.outcome.kind != ManagerSourceControlOutcomeKindV1::Absent
        || projection.removal_commitment
            != control_sequence_commitment(
                b"aos.sandbox.mount-manager.fresh-removal.v1\0",
                &projection.request,
                &projection.removed,
                &projection.absent,
            )
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
    }
    Ok(FreshManagerSourceRemovalReceiptV1 { projection })
}

fn control_sequence_commitment(
    domain: &[u8],
    request: &ManagerSourceControlRequestV1,
    first: &SignedManagerSourceControlOutcomeV1,
    second: &SignedManagerSourceControlOutcomeV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(request.request_id);
    hasher.update(request.record_digest);
    hasher.update(first.outcome.outcome_id);
    hasher.update(first.outcome.record_digest);
    hasher.update(Sha256::digest(&first.signature));
    hasher.update(second.outcome.outcome_id);
    hasher.update(second.outcome.record_digest);
    hasher.update(Sha256::digest(&second.signature));
    hasher.finalize().into()
}

fn fresh_presence_evidence(
    request: &ManagerSourceControlRequestV1,
    manager_descriptor_number: u32,
) -> ManagerSourcePresenceEvidenceProjectionV1 {
    let policy = &request.policy;
    let source = &request.source;
    ManagerSourcePresenceEvidenceProjectionV1 {
        origin: ManagerSourcePresenceOriginV1::FreshControlReadback,
        manager_execution: policy.manager_execution.clone(),
        manager_execution_commitment: policy.manager_execution_commitment,
        capture_sequence: policy.capture_sequence,
        capture_id: policy.capture_id,
        capture_record_digest: policy.capture_record_digest,
        descriptor_count: policy.descriptor_count,
        activation_count: policy.activation_count,
        expected_descriptor_count: policy.expected_descriptor_count,
        source_subject_count: policy.source_subject_count,
        cleanup_subject_count: policy.cleanup_subject_count,
        terminal_subject_count: policy.terminal_subject_count,
        acquisition_id: source.acquisition_id,
        acquisition_revision: source.acquisition_revision,
        acquisition_record_digest: source.acquisition_record_digest,
        source_realization_handle: source.source_realization_handle,
        descriptor_commitment: source.descriptor_commitment,
        manager_descriptor_number,
        source_kernel_boot_id: source.kernel_boot_id,
        source_device: source.device,
        source_inode: source.inode,
        source_unique_mount_id: source.unique_mount_id,
        source_entry_commitment: request.source_entry_commitment,
    }
}

fn validate_fresh_presence_projection(
    projection: &FreshManagerSourcePresenceProjectionV1,
) -> Result<(), ManagerSourceCustodyError> {
    verify_signed_manager_source_control_outcome_v1(
        &projection.request,
        None,
        &projection.accepted,
    )?;
    verify_signed_manager_source_control_outcome_v1(
        &projection.request,
        Some(&projection.accepted.outcome),
        &projection.present,
    )?;
    if projection.request.operation != ManagerSourceControlOperationV1::Handoff
        || projection.evidence
            != fresh_presence_evidence(
                &projection.request,
                projection.accepted.outcome.manager_descriptor_number,
            )
        || projection.accepted.outcome.kind != ManagerSourceControlOutcomeKindV1::DescriptorAccepted
        || projection.present.outcome.kind != ManagerSourceControlOutcomeKindV1::Present
        || projection.presence_commitment
            != control_sequence_commitment(
                b"aos.sandbox.mount-manager.fresh-presence.v1\0",
                &projection.request,
                &projection.accepted,
                &projection.present,
            )
    {
        return Err(ManagerSourceControlProtocolError::InvalidRecord.into());
    }
    Ok(())
}
