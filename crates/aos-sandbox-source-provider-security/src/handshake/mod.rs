//! Sealed mutually authenticated hello typestates.

mod mount_request;
mod provider;
mod root_mount;

use core::cell::Cell;

pub use mount_request::{
    AuthorizedMountAcquireVerificationFloorV2, AuthorizedMountProviderOutcomeV2,
    CapturedMountProviderRecoveryOutcomeV2, CommittedReopenedMountSourceRootV2,
    CurrentMountProviderSessionPlanV2, HistoricalMountInventoryAuthorizationV2,
    HistoricalMountReleaseAuthorizationV2, MountProviderAuthorityTrustProjectionV2,
    MountProviderRequestProjectionV2, MountProviderRequestSendRecoveryV2,
    MountProviderSessionProjectionV2, MountProviderSignerProjectionV2,
    PreparedMountProviderRequestV2, ReceivedMountProviderOutcomePartsV2,
    RecoveredMountProviderOutcomePartsV2, RecoveredMountProviderOutcomeV2,
    ReopenedMountSourceRootV2, ReservedMountProviderRequestV2, RetainedRootRecoveryAuthorizationV2,
    SentMountProviderRequestV2, VerifiedMountProviderOutcomeV2,
    VerifiedReceivedMountProviderOutcomeV2,
};
pub use provider::{
    AcquireReceiptFactsV1, CurrentProviderIngressSessionV1, CurrentProviderSessionProjectionV1,
    ProviderCompletionBuilderV1, ProviderIngressReopenCheckpointV1, ProviderOwnerSecurityFacadeV1,
    ProviderSessionSupersessionEvidenceV1, ProviderSourceProviderHandshakeStatusV1,
    ProviderSourceProviderOwnerV1, RevalidatedProviderReplayV1,
};
pub use root_mount::{
    AuthenticatedRootMountCatalogCurrentnessV1, AuthenticatedRootMountRecoveryUnavailableV1,
    CurrentRootMountSourceProviderSessionV1, RootMountSourceProviderHandshakeStatusV1,
    RootMountSourceProviderOwnerV1,
};

/// Carries a provider outcome after exact AOSSPL persistence.
pub struct CommittedProviderOutcomeV1 {
    pub(super) transaction_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) artifact_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) reservation_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) response_sequence: u64,
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) session_binding: aos_sandbox_core::ObjectDigest,
    pub(super) committed_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) response: Option<Vec<u8>>,
}

/// Proves one exact response was durably completed under Provider deadline checks.
///
/// The move-only value has no public constructor or scalar accessors. Mount may
/// consume it only while reauthenticating the same response against its exact
/// protected historical attempt.
pub struct PersistedProviderOutcomeV1 {
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) signed_request_digest: [u8; 32],
    pub(super) response_digest: [u8; 32],
    pub(super) completed_at_seconds: i64,
    pub(super) deadline_seconds: i64,
}

impl core::fmt::Debug for PersistedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PersistedProviderOutcomeV1([protected completion])")
    }
}

/// Retains a provider request verified against live protected session custody.
///
/// The non-cloneable value classifies a request but grants no journal
/// mutation, backend effect, signing, or response-send authority.
pub struct CurrentProviderRequestV1 {
    pub(super) verified: aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1,
    pub(super) provider_process_id: u32,
    pub(super) provider_start_time_ticks: u64,
}

/// Authorizes purpose-specific signing for one exact current admitted request.
///
/// The move-only value has no public constructor or scalar accessors. It is
/// minted only while live custody verifies a request and grants neither
/// journal mutation nor response-send authority.
pub struct ProviderOutcomeAuthorizationV1 {
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) request_id: [u8; 16],
    pub(super) signed_request_digest: aos_sandbox_core::ObjectDigest,
    pub(super) typed_request_digest: aos_sandbox_core::ObjectDigest,
    pub(super) attempt_digest: aos_sandbox_core::ObjectDigest,
    pub(super) operation_intent_digest: aos_sandbox_core::ObjectDigest,
    pub(super) provider: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) holder: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) session_binding: aos_sandbox_core::ObjectDigest,
    pub(super) provider_process_instance: [u8; 16],
    pub(super) acquisition_id: Option<aos_sandbox_core::ObjectDigest>,
    pub(super) lease_id: Option<[u8; 16]>,
    pub(super) lease_digest: Option<aos_sandbox_core::ObjectDigest>,
    pub(super) response_sequence: u64,
    pub(super) request_deadline_seconds: i64,
    pub(super) current_valid_until_seconds: i64,
    pub(super) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) reservation_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) attempt_key_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) claimed_purposes: Cell<u8>,
}

impl core::fmt::Debug for CommittedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedProviderOutcomeV1([redacted])")
    }
}

impl core::fmt::Debug for CurrentProviderRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderRequestV1([redacted])")
    }
}

impl core::fmt::Debug for ProviderOutcomeAuthorizationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderOutcomeAuthorizationV1([redacted])")
    }
}

impl CurrentProviderRequestV1 {
    /// Borrows the authenticated protocol request for owner-side admission.
    #[must_use]
    pub const fn verified(
        &self,
    ) -> &aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1 {
        &self.verified
    }

    /// Returns the live-custody provider process identity retained for recovery fencing.
    ///
    /// The scalar projection grants no death, journal, effect, or signing
    /// authority. A later same-boot death proof is minted only by security
    /// custody after checking the exact protected session record.
    #[must_use]
    pub const fn provider_execution_identity(&self) -> (u32, u64) {
        (self.provider_process_id, self.provider_start_time_ticks)
    }

    /// Consumes this request only after its exact reservation is current.
    ///
    /// The protected snapshot binds the resulting one-shot authorization to
    /// one journal instance, the closed SourceProvider namespace, and its
    /// current sequence. `attempt_key` and `attempt_record` must still be the
    /// exact materialized reservation, whose canonical tail is the request
    /// authenticated by this value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::SourceProviderSecurityError`] when protected journal
    /// authority is stale, the reservation differs, or a sentinel is present.
    pub(super) fn authorize_reserved(
        self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        attempt_record: &[u8],
        response_sequence: u64,
    ) -> Result<ProviderOutcomeAuthorizationV1, crate::SourceProviderSecurityError> {
        use aos_sandbox_source_provider_protocol::{
            SourceProviderMethod, VerifiedProviderRequestV1, digest_acquire_request,
            digest_inventory_request, digest_release_request,
        };

        journal
            .validate_source_provider_authority_snapshot(&journal_snapshot)
            .map_err(|_| crate::SourceProviderSecurityError::SessionContinuity)?;
        let signed_request = authorization_signed_request(&self.verified);
        let projection = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => value.ingress_projection(),
            VerifiedProviderRequestV1::Release(value) => value.ingress_projection(),
            VerifiedProviderRequestV1::Inventory(value) => value.ingress_projection(),
        };
        let (
            method,
            request_id,
            signed_request_digest,
            typed_request_digest,
            operation_intent_digest,
            attempt_digest,
            request_sequence,
            deadline_seconds,
            acquisition_sequence,
        ) = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => (
                SourceProviderMethod::Acquire,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_acquire_request(value.request()),
                value.acquire_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                Some(value.request().acquisition_sequence()),
            ),
            VerifiedProviderRequestV1::Release(value) => (
                SourceProviderMethod::Release,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_release_request(value.request()),
                value.release_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                None,
            ),
            VerifiedProviderRequestV1::Inventory(value) => (
                SourceProviderMethod::Inventory,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_inventory_request(value.request()),
                value.inventory_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                Some(0),
            ),
        };
        let reserved_attempt =
            match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                attempt_key,
                attempt_record,
            ) {
                Ok(
                    aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Attempt(
                        attempt,
                    ),
                ) => attempt,
                _ => return Err(crate::SourceProviderSecurityError::SessionContinuity),
            };
        let authority_key = aos_sandbox_source_provider_ledger::ledger::format::authority_key(
            projection.provider_authority().authority_id(),
        );
        let authority = journal
            .get(&authority_key)
            .ok()
            .flatten()
            .and_then(|bytes| {
                match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                    &authority_key,
                    bytes,
                ) {
                    Ok(
                        aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Authority(
                            value,
                        ),
                    ) => Some(value),
                    _ => None,
                }
            })
            .ok_or(crate::SourceProviderSecurityError::SessionContinuity)?;
        let session_key = aos_sandbox_source_provider_ledger::ledger::format::session_key(
            projection.provider_authority().authority_id(),
            projection.root_mount_authority().authority_id(),
        );
        let session = journal
            .get(&session_key)
            .ok()
            .flatten()
            .and_then(|bytes| {
                match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                    &session_key,
                    bytes,
                ) {
                    Ok(
                        aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Session(
                            value,
                        ),
                    ) => Some(value),
                    _ => None,
                }
            })
            .ok_or(crate::SourceProviderSecurityError::SessionContinuity)?;
        let retained_release_acquisition_sequence = match &self.verified {
            VerifiedProviderRequestV1::Release(value) => {
                let key = aos_sandbox_source_provider_ledger::ledger::format::acquisition_key(
                    &aos_sandbox_source_provider_ledger::ledger::model::AcquisitionKeyV1 {
                        provider_id: projection.provider_authority().authority_id(),
                        holder_id: projection.root_mount_authority().authority_id(),
                        acquisition_id: value.request().acquisition_id(),
                    },
                );
                journal
                    .get(&key)
                    .ok()
                    .flatten()
                    .and_then(|bytes| {
                        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                            &key, bytes,
                        ) {
                            Ok(
                                aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Acquisition(
                                    acquisition,
                                ),
                            ) => Some(acquisition.acquisition_sequence),
                            _ => None,
                        }
                    })
            }
            _ => None,
        };
        if response_sequence == 0
            || attempt_key.is_empty()
            || attempt_record.is_empty()
            || reserved_attempt.state
                != aos_sandbox_source_provider_ledger::ProviderAttemptStateV1::Reserved
            || reserved_attempt.status.is_some()
            || reserved_attempt.method != method
            || reserved_attempt.request_id != request_id
            || reserved_attempt.signed_request != signed_request
            || reserved_attempt.signed_request_digest != signed_request_digest
            || reserved_attempt.signed_request_digest_again
                != reserved_attempt.signed_request_digest
            || reserved_attempt.typed_request_digest != typed_request_digest
            || reserved_attempt.operation_intent_digest != operation_intent_digest
            || reserved_attempt.attempt_digest != attempt_digest
            || reserved_attempt.request_sequence != request_sequence
            || reserved_attempt.deadline_seconds != deadline_seconds
            || acquisition_sequence
                .is_some_and(|sequence| reserved_attempt.acquisition_sequence != sequence)
            || (method == SourceProviderMethod::Release
                && retained_release_acquisition_sequence
                    != Some(reserved_attempt.acquisition_sequence))
            || reserved_attempt.provider != *projection.provider_authority()
            || reserved_attempt.holder != *projection.root_mount_authority()
            || reserved_attempt.root_record_signer != projection.ordered_signers()[1]
            || reserved_attempt.session_binding != projection.session_binding()
            || reserved_attempt.root_process_instance != projection.root_mount_process_instance()
            || reserved_attempt.provider_process_instance != projection.provider_process_instance()
            || reserved_attempt.signer_set_commitment != projection.signer_set_commitment()
            || reserved_attempt.proof_class_capabilities != projection.proof_class_capabilities()
            || reserved_attempt.supports_recursive != projection.supports_recursive()
            || reserved_attempt.supports_kernel_coupled != projection.supports_kernel_coupled()
            || reserved_attempt.verified_at_seconds != projection.verified_at_seconds()
            || reserved_attempt.current_valid_until_seconds
                != projection.current_valid_until_seconds()
            || reserved_attempt.completed_response.len() != 0
            || reserved_attempt.response_sequence.is_some()
            || reserved_attempt.response_digest.is_some()
            || reserved_attempt.result_digest.is_some()
            || authority.provider != *projection.provider_authority()
            || authority.trust_generation != projection.trust_generation()
            || authority.trust_digest != projection.trust_digest()
            || authority.revocation_generation != projection.revocation_generation()
            || authority.revocation_digest != projection.revocation_digest()
            || authority.route_id != projection.route_id()
            || authority.route_generation != projection.route_generation()
            || authority.route_digest != projection.route_digest()
            || authority.resource_namespace_digest != projection.resource_namespace_digest()
            || authority.proof_class_capabilities != projection.proof_class_capabilities()
            || authority.supports_recursive != projection.supports_recursive()
            || authority.supports_kernel_coupled != projection.supports_kernel_coupled()
            || projection.verified_at_seconds() < authority.valid_from_seconds
            || projection.current_valid_until_seconds() > authority.valid_until_seconds
            || session.provider != *projection.provider_authority()
            || session.holder != *projection.root_mount_authority()
            || session.session_binding != projection.session_binding()
            || session.root_process_instance != projection.root_mount_process_instance()
            || session.provider_process_instance != projection.provider_process_instance()
            || session.root_writer.uid != projection.actual_writer_root_mount_process().uid()
            || session.root_writer.gid != projection.actual_writer_root_mount_process().gid()
            || session.root_writer.tgid != projection.actual_writer_root_mount_process().tgid()
            || session.root_writer.start_time_ticks
                != projection
                    .actual_writer_root_mount_process()
                    .start_time_ticks()
            || session.root_writer.cgroup_digest
                != projection
                    .actual_writer_root_mount_process()
                    .cgroup_digest()
            || session.route_id != projection.route_id()
            || session.route_generation != projection.route_generation()
            || session.route_digest != projection.route_digest()
            || session.resource_namespace_digest != projection.resource_namespace_digest()
            || session.trust_generation != projection.trust_generation()
            || session.trust_digest != projection.trust_digest()
            || session.revocation_generation != projection.revocation_generation()
            || session.revocation_digest != projection.revocation_digest()
            || session.signers != *projection.ordered_signers()
            || session.signer_set_commitment != projection.signer_set_commitment()
            || session.root_hello_digest != projection.root_mount_hello_digest()
            || session.provider_hello_digest != projection.provider_hello_digest()
            || session.root_hello != projection.signed_root_mount_hello().to_canonical_bytes()
            || session.provider_hello != projection.signed_provider_hello().to_canonical_bytes()
            || session.pending_attempt_digest != Some(attempt_digest)
            || session.next_response_sequence != response_sequence
            || journal
                .validate_source_provider_authority_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(attempt_key).ok().flatten() != Some(attempt_record)
        {
            return Err(crate::SourceProviderSecurityError::SessionContinuity);
        }
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.protected-reservation.v1\0");
        hasher.update((attempt_key.len() as u32).to_be_bytes());
        hasher.update(attempt_key);
        hasher.update((attempt_record.len() as u32).to_be_bytes());
        hasher.update(attempt_record);
        let reservation_commitment =
            aos_sandbox_core::ObjectDigest::from_bytes(hasher.finalize().into());
        let attempt_key_commitment = {
            let mut hasher = Sha256::new();
            hasher.update(b"aos.sandbox.source-provider.protected-attempt-key.v1\0");
            hasher.update((attempt_key.len() as u32).to_be_bytes());
            hasher.update(attempt_key);
            aos_sandbox_core::ObjectDigest::from_bytes(hasher.finalize().into())
        };

        let authorization = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Acquire,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_acquire_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.acquire_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: Some(value.request().acquisition_id()),
                lease_id: None,
                lease_digest: None,
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
            VerifiedProviderRequestV1::Release(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Release,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_release_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.release_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: Some(value.request().acquisition_id()),
                lease_id: Some(value.request().lease_id()),
                lease_digest: Some(value.request().lease_digest()),
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
            VerifiedProviderRequestV1::Inventory(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Inventory,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_inventory_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.inventory_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: None,
                lease_id: None,
                lease_digest: None,
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
        };
        Ok(authorization)
    }
}

impl ProviderOutcomeAuthorizationV1 {
    pub(super) fn claim_purpose(
        &self,
        purpose: u8,
    ) -> Result<(), crate::SourceProviderSecurityError> {
        let claimed = self.claimed_purposes.get();
        if purpose == 0 || claimed & purpose != 0 {
            return Err(crate::SourceProviderSecurityError::SessionContinuity);
        }
        self.claimed_purposes.set(claimed | purpose);
        Ok(())
    }
}

fn authorization_signed_request<'request>(
    verified: &'request aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1,
) -> &'request [u8] {
    use aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1;
    match verified {
        VerifiedProviderRequestV1::Acquire(value) => value.attempt().canonical_signed_request(),
        VerifiedProviderRequestV1::Release(value) => value.attempt().canonical_signed_request(),
        VerifiedProviderRequestV1::Inventory(value) => value.attempt().canonical_signed_request(),
    }
}

pub(super) enum HandshakeTransitionV1<RetryState, CompleteState> {
    Complete(CompleteState),
    Retry(RetryState),
    Fatal(crate::SourceProviderSecurityError),
}

pub(super) fn current_unix_seconds() -> Result<i64, crate::SourceProviderSecurityError> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if value < 0 {
        Err(crate::SourceProviderSecurityError::ExecutionChanged)
    } else {
        Ok(value)
    }
}

pub(super) fn process_identity(
    evidence: &crate::execution::ProcessExecutionEvidenceV1,
) -> Result<
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1,
    crate::SourceProviderSecurityError,
> {
    let credentials = evidence.credentials();
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1::new(
        credentials.effective_user_id(),
        credentials.effective_group_id(),
        evidence.tgid(),
        evidence.start_time_ticks(),
        crate::execution::cgroup_object_digest(evidence.cgroup_path_digest()),
        evidence.is_alive()?,
    )
    .map_err(|_| crate::SourceProviderSecurityError::SessionContinuity)
}
