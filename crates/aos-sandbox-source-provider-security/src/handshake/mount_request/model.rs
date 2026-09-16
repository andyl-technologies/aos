//! Move-only Mount request, session, and verified-outcome projections.

use super::*;

/// Prepares one exact current-session provider request for durable reservation.
///
/// The value is move-only. It exposes immutable bytes for durable reservation
/// and retains the sole verifier for the corresponding provider outcome.
pub struct PreparedMountProviderRequestV2 {
    signed_request: Vec<u8>,
    projection: MountProviderRequestProjectionV2,
    outcome: AuthorizedMountProviderOutcomeV2,
}

/// Authorizes one exact protected catalog and optional retained-selection floor.
///
/// This value is move-only. Its public projection is nonauthorizing durable
/// data; only the current security session may consume the hidden journal and
/// session bindings while preparing the corresponding Acquire request.
pub struct AuthorizedMountAcquireVerificationFloorV2 {
    pub(super) catalog: ProviderCatalogFloorV1,
    pub(super) selection: Option<SourceSelectionFloorV1>,
    pub(super) current_catalog: crate::ProtectedCurrentCatalogPublicationV1,
    pub(super) session_binding: ObjectDigest,
    pub(super) trust_generation: u64,
    pub(super) trust_digest: ObjectDigest,
    pub(super) revocation_generation: u64,
    pub(super) revocation_digest: ObjectDigest,
    pub(super) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
}

/// Provides one move-only, nonauthorizing current-session planning snapshot.
pub struct CurrentMountProviderSessionPlanV2 {
    session: MountProviderSessionProjectionV2,
    current_request_sequence: u64,
    current_response_sequence: u64,
    freshness_digest: ObjectDigest,
    journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    head_key: Vec<u8>,
    head_record: Vec<u8>,
    predecessor_session_key: Option<Vec<u8>>,
    predecessor_session_record: Option<Vec<u8>>,
    predecessor_death_commitment: Option<ObjectDigest>,
}

/// Proves the exact prepared request is retained by a current protected reservation.
pub struct ReservedMountProviderRequestV2 {
    prepared: PreparedMountProviderRequestV2,
    reservation_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    attempt_key: Vec<u8>,
    attempt_record: Vec<u8>,
    head_key: Vec<u8>,
    head_record: Vec<u8>,
}

/// Retains projections after a durably reserved request was handed to the carrier.
pub struct SentMountProviderRequestV2 {
    projection: MountProviderRequestProjectionV2,
    outcome: AuthorizedMountProviderOutcomeV2,
}

/// Retains an exact durable request reservation when carrier send is incomplete.
#[must_use = "retry through the same protected session or retain exact send custody"]
pub struct MountProviderRequestSendRecoveryV2 {
    pub(super) reservation: ReservedMountProviderRequestV2,
}

impl core::fmt::Debug for MountProviderRequestSendRecoveryV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountProviderRequestSendRecoveryV2([reserved send custody])")
    }
}

/// Projects the exact identities committed by an authorized Acquire-v2 request.
pub struct MountProviderRequestProjectionV2 {
    method: SourceProviderMethod,
    session: MountProviderSessionProjectionV2,
    provider: SourceProviderAuthorityV1,
    holder: SourceProviderAuthorityV1,
    session_binding: ObjectDigest,
    signer_set_commitment: ObjectDigest,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    provider_process_instance: [u8; 16],
    request_id: [u8; 16],
    request_sequence: u64,
    expected_response_sequence: u64,
    acquisition_id: Option<ObjectDigest>,
    acquisition_sequence: Option<u64>,
    normalized_intent: Option<Vec<u8>>,
    normalized_intent_digest: Option<ObjectDigest>,
    typed_request_digest: ObjectDigest,
    signed_request_digest: ObjectDigest,
    deadline_seconds: i64,
    catalog_floor: Option<ProviderCatalogFloorV1>,
    selection_floor: Option<SourceSelectionFloorV1>,
    current_catalog_head_commitment: Option<ObjectDigest>,
    inventory_correlations:
        Option<aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2>,
}

/// Retains the exact authenticated hello transcript and execution bindings.
///
/// This projection is minted only from a live revalidated Root Mount session.
/// It grants no signing, carrier, descriptor, replay, or journal authority.
pub struct MountProviderSessionProjectionV2 {
    signed_root_mount_hello: Vec<u8>,
    signed_provider_hello: Vec<u8>,
    ordered_signers: [MountProviderSignerProjectionV2; 4],
    authority_trust: [MountProviderAuthorityTrustProjectionV2; 2],
    session_binding: ObjectDigest,
    signer_set_commitment: ObjectDigest,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    root_boot_id: [u8; 16],
    node_id: [u8; 16],
    root_process_instance: [u8; 16],
    provider_process_instance: [u8; 16],
    root_writer_uid: u32,
    root_writer_gid: u32,
    root_writer_tgid: u32,
    root_writer_start_time_ticks: u64,
    root_writer_cgroup_digest: ObjectDigest,
    provider_tgid: u32,
    provider_pid: u32,
    provider_parent_pid: u32,
    provider_start_time_ticks: u64,
    provider_cgroup_id: u64,
    provider_cgroup_digest: ObjectDigest,
    provider_credentials: [u32; 8],
    provider_execution_digest: ObjectDigest,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    resource_namespace_digest: ObjectDigest,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    authenticated_at_seconds: i64,
    current_valid_until_seconds: i64,
    trusted_clock_evidence_digest: ObjectDigest,
}

/// Retains one current authority and its protected admission interval.
pub struct MountProviderAuthorityTrustProjectionV2 {
    authority: SourceProviderAuthorityV1,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    state: SourceProviderAuthorityTrustStateV1,
}

/// Retains one ordered signer, its public key, and protected admission facts.
pub struct MountProviderSignerProjectionV2 {
    signer: aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    public_key: [u8; 32],
    authority_valid_from_seconds: i64,
    authority_valid_until_seconds: i64,
    key_valid_from_seconds: i64,
    key_valid_until_seconds: i64,
    authority_state: SourceProviderAuthorityTrustStateV1,
    key_state: SourceProviderKeyTrustStateV1,
    superseded_by_key_generation: u64,
}

/// Verifies exactly one outcome for an authorized Mount Acquire-v2 attempt.
pub struct AuthorizedMountProviderOutcomeV2 {
    pub(super) signed_request: SignedSourceProviderRequestV1,
    pub(super) method: SourceProviderMethod,
    pub(super) provider: SourceProviderAuthorityV1,
    pub(super) holder: SourceProviderAuthorityV1,
    pub(super) provider_outcome_public_key: [u8; 32],
    pub(super) provider_outcome_signer:
        aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
    pub(super) session_binding: ObjectDigest,
    pub(super) provider_process_instance: [u8; 16],
    pub(super) request_id: [u8; 16],
    pub(super) typed_request_digest: ObjectDigest,
    pub(super) signed_request_digest: ObjectDigest,
    pub(super) expected_response_sequence: u64,
    pub(super) request_sequence: u64,
    pub(super) mount_session_id: Option<[u8; 32]>,
    pub(super) mount_attempt_id: Option<[u8; 32]>,
    pub(super) kernel_boot_id: [u8; 16],
    pub(super) trusted_clock_evidence_digest: ObjectDigest,
    pub(super) verification_anchor:
        Option<aos_sandbox_protocol::mount_source_acquisition_state::OutcomeVerificationAnchorV2>,
    pub(super) acquisition_id: Option<ObjectDigest>,
    pub(super) acquisition_sequence: Option<u64>,
    pub(super) lease_id: Option<[u8; 16]>,
    pub(super) lease_digest: Option<ObjectDigest>,
    pub(super) deadline_seconds: i64,
    pub(super) catalog_floor: Option<ProviderCatalogFloorV1>,
    pub(super) selection_floor: Option<SourceSelectionFloorV1>,
    pub(super) current_catalog_head_commitment: Option<ObjectDigest>,
    pub(super) deadline_policy: OutcomeDeadlinePolicyV2,
    pub(super) cleanup_only_current_policy: bool,
    pub(super) inventory_correlations:
        Option<aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2>,
    pub(super) recovered_inventory_terminal_rows: Option<std::collections::BTreeSet<[u8; 32]>>,
    pub(super) historical_session:
        Option<aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutcomeDeadlinePolicyV2 {
    Fresh,
    RetainedReplay,
}

/// Carries one exact provider outcome verified against live Root Mount custody.
pub struct VerifiedMountProviderOutcomeV2 {
    pub(super) canonical_response: Vec<u8>,
    pub(super) status: SourceProviderStatus,
    pub(super) result_digest: ObjectDigest,
    pub(super) descriptor_commitment: ObjectDigest,
    pub(super) acquisition_id: Option<ObjectDigest>,
    pub(super) acquisition_sequence: Option<u64>,
    pub(super) session_binding: ObjectDigest,
    pub(super) response_sequence: u64,
    pub(super) verification_anchor:
        aos_sandbox_protocol::mount_source_acquisition_state::OutcomeVerificationAnchorV2,
    pub(super) cleanup_only_current_policy: bool,
    pub(super) terminal_lineages: Vec<VerifiedTerminalLineageV2>,
}

pub(super) struct VerifiedTerminalLineageV2 {
    pub(super) acquisition_id: ObjectDigest,
    pub(super) acquisition_sequence: u64,
    pub(super) lease_id: [u8; 16],
    pub(super) lease_digest: ObjectDigest,
}

/// Carries one atomically received and fully verified provider outcome.
///
/// Complete Acquire retains the sole move-only SourceRoot descriptor custody;
/// every other method or status is constructed only after proving that the
/// ancillary descriptor set was empty.
pub struct VerifiedReceivedMountProviderOutcomeV2 {
    verified: VerifiedMountProviderOutcomeV2,
    source_root: Option<crate::ObservedSourceRootV1>,
}

/// Separates a verified received outcome by its closed descriptor shape.
pub enum ReceivedMountProviderOutcomePartsV2 {
    /// Carries a Complete Acquire and its nonextractable observed SourceRoot.
    CompleteAcquire {
        /// Carries the exact verified canonical provider response.
        outcome: VerifiedMountProviderOutcomeV2,
        /// Retains the only received SourceRoot descriptor.
        source_root: crate::ObservedSourceRootV1,
    },
    /// Carries a non-Complete-Acquire outcome proven to have no descriptors.
    WithoutSourceRoot(VerifiedMountProviderOutcomeV2),
}

/// Carries one post-crash outcome recovered from exact protected Mount records.
///
/// The value is move-only and nonauthorizing. It proves cryptographic and
/// protected-record correlation only; consuming it does not send bytes or a
/// descriptor and cannot recreate the original request authority.
pub struct RecoveredMountProviderOutcomeV2 {
    pub(super) verified: VerifiedMountProviderOutcomeV2,
    pub(super) source_root: Option<ReopenedMountSourceRootV2>,
}

/// Retains one carrier-received provider response for protected crash recovery.
///
/// Its fields are deliberately opaque. Only a current Root-Mount session can
/// capture it, and only exact durable attempt/session records can consume it.
pub struct CapturedMountProviderRecoveryOutcomeV2 {
    pub(super) method: SourceProviderMethod,
    pub(super) canonical_signed_status: Vec<u8>,
    pub(super) canonical_signed_result: Vec<u8>,
    pub(super) source_root: Option<crate::ProviderSourceRootHandoffV1>,
    pub(super) persisted: Option<crate::PersistedProviderOutcomeV1>,
}

impl core::fmt::Debug for CapturedMountProviderRecoveryOutcomeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CapturedMountProviderRecoveryOutcomeV2([received custody])")
    }
}

/// Retains a freshly reobserved post-crash SourceRoot bound to one exact outcome.
pub struct ReopenedMountSourceRootV2 {
    pub(crate) handoff: crate::ProviderSourceRootHandoffV1,
    pub(crate) acquisition_id: ObjectDigest,
    pub(crate) acquisition_sequence: u64,
    pub(crate) lease_id: [u8; 16],
    pub(crate) lease_digest: ObjectDigest,
    pub(crate) session_binding: ObjectDigest,
    pub(crate) descriptor_commitment: ObjectDigest,
    pub(crate) signed_outcome_digest: ObjectDigest,
}

/// Authorizes restoration of one exact retained manager-held SourceRoot.
///
/// The move-only value is derived from an authenticated dead-session to
/// successor-session edge already retained by the protected Mount graph. It
/// is bound to one acquisition record and cannot be reused for another root.
pub struct RetainedRootRecoveryAuthorizationV2 {
    pub(super) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) acquisition_key: Vec<u8>,
    pub(super) acquisition_record: Vec<u8>,
    pub(super) acquisition_record_digest: [u8; 32],
    pub(super) predecessor_session_id: [u8; 32],
    pub(super) current_session_id: [u8; 32],
    pub(super) session_ancestry_digest: ObjectDigest,
}

/// Owns reopened SourceRoot custody after the recovered disposition commits.
pub struct CommittedReopenedMountSourceRootV2 {
    pub(crate) reopened: ReopenedMountSourceRootV2,
}

/// Separates a recovered outcome by its closed descriptor-custody shape.
pub enum RecoveredMountProviderOutcomePartsV2 {
    /// Carries a recovered Complete Acquire and exact reopened SourceRoot.
    CompleteAcquire {
        /// Carries the verified canonical response.
        outcome: VerifiedMountProviderOutcomeV2,
        /// Retains move-only post-crash descriptor custody.
        source_root: ReopenedMountSourceRootV2,
    },
    /// Carries an outcome proven not to require descriptor custody.
    WithoutSourceRoot(VerifiedMountProviderOutcomeV2),
}

/// Retains one exact predecessor-holder acquisition lineage internally.
pub(super) struct HistoricalMountAcquisitionLineageV2 {
    pub(super) provider_authority_id: [u8; 16],
    pub(super) current_holder: SourceProviderAuthorityV1,
    pub(super) predecessor_holder: SourceProviderAuthorityV1,
    pub(super) acquisition_id: ObjectDigest,
    pub(super) acquisition_sequence: u64,
    pub(super) lease_id: [u8; 16],
    pub(super) lease_digest: ObjectDigest,
    pub(super) session_binding: ObjectDigest,
    pub(super) lineage_commitment: ObjectDigest,
    pub(super) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) acquisition_key: Vec<u8>,
    pub(super) acquisition_record: Vec<u8>,
    pub(super) predecessor_session_key: Vec<u8>,
    pub(super) predecessor_session_record: Vec<u8>,
    pub(super) inventory_expectation:
        aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2,
}

/// Authorizes Release of one exact predecessor-holder acquisition.
///
/// The value is move-only and cannot authorize Acquire, Inventory, session
/// creation, or an unrelated historical acquisition.
pub struct HistoricalMountReleaseAuthorizationV2 {
    pub(super) lineage: HistoricalMountAcquisitionLineageV2,
}

/// Authorizes Inventory correlation for one predecessor-holder acquisition.
///
/// The value is move-only and cannot authorize Acquire, Release, session
/// creation, or an unrelated historical acquisition.
pub struct HistoricalMountInventoryAuthorizationV2 {
    pub(super) lineage: HistoricalMountAcquisitionLineageV2,
}

impl core::fmt::Debug for PreparedMountProviderRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparedMountProviderRequestV2([redacted])")
    }
}

impl core::fmt::Debug for AuthorizedMountAcquireVerificationFloorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedMountAcquireVerificationFloorV2([protected floor])")
    }
}

impl core::fmt::Debug for RetainedRootRecoveryAuthorizationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RetainedRootRecoveryAuthorizationV2([protected root])")
    }
}

impl AuthorizedMountAcquireVerificationFloorV2 {
    /// Returns the exact nonauthorizing floor projection Mount must persist.
    #[must_use]
    pub fn projection(
        &self,
    ) -> aos_sandbox_protocol::mount_source_acquisition_state::AcquireVerificationFloorV2 {
        aos_sandbox_protocol::mount_source_acquisition_state::acquire_verification_floor_v2(
            &self.catalog,
            self.selection.as_ref(),
            Some(
                *self
                    .current_catalog
                    .projection()
                    .head_commitment()
                    .as_bytes(),
            ),
        )
    }
}

impl core::fmt::Debug for CurrentMountProviderSessionPlanV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentMountProviderSessionPlanV2([current planning view])")
    }
}

impl core::fmt::Debug for ReservedMountProviderRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReservedMountProviderRequestV2([protected reservation])")
    }
}

impl core::fmt::Debug for SentMountProviderRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SentMountProviderRequestV2([sent exact request])")
    }
}

impl core::fmt::Debug for MountProviderSessionProjectionV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountProviderSessionProjectionV2([authenticated transcript])")
    }
}

impl core::fmt::Debug for MountProviderAuthorityTrustProjectionV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountProviderAuthorityTrustProjectionV2([authenticated])")
    }
}

impl core::fmt::Debug for MountProviderSignerProjectionV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountProviderSignerProjectionV2([public verification key])")
    }
}

impl core::fmt::Debug for AuthorizedMountProviderOutcomeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedMountProviderOutcomeV2([redacted])")
    }
}

impl core::fmt::Debug for VerifiedMountProviderOutcomeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedMountProviderOutcomeV2([verified])")
    }
}

impl core::fmt::Debug for VerifiedReceivedMountProviderOutcomeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedReceivedMountProviderOutcomeV2([verified carrier])")
    }
}

impl core::fmt::Debug for RecoveredMountProviderOutcomeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RecoveredMountProviderOutcomeV2([protected replay])")
    }
}

impl core::fmt::Debug for ReopenedMountSourceRootV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReopenedMountSourceRootV2([revalidated descriptor])")
    }
}

impl core::fmt::Debug for CommittedReopenedMountSourceRootV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedReopenedMountSourceRootV2([committed custody])")
    }
}

impl core::fmt::Debug for HistoricalMountReleaseAuthorizationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HistoricalMountReleaseAuthorizationV2([protected lineage])")
    }
}

impl core::fmt::Debug for HistoricalMountInventoryAuthorizationV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HistoricalMountInventoryAuthorizationV2([protected lineage])")
    }
}

impl PreparedMountProviderRequestV2 {
    /// Borrows the immutable signed request bytes that Mount must reserve exactly.
    #[must_use]
    pub fn canonical_signed_request(&self) -> &[u8] {
        &self.signed_request
    }

    /// Borrows the exact nonauthorizing request and session projection.
    #[must_use]
    pub const fn projection(&self) -> &MountProviderRequestProjectionV2 {
        &self.projection
    }

    /// Consumes this preparation after its exact namespace-40 reservation commits.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the protected snapshot is
    /// current and retains the exact AOSMSA02 Reserved attempt and owner head
    /// containing this request, session, request sequence, and response head.
    pub(super) fn validate_protected_reservation(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        reservation_snapshot: &aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        attempt_record: &[u8],
        head_key: &[u8],
        head_record: &[u8],
    ) -> Result<(), SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderMethodV2, StoredRecordV2,
            decode_mount_source_state_record_v2,
        };

        let attempt = match decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
            Ok(StoredRecordV2::ProviderQueryAttempt { value }) => value,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        let head = match decode_mount_source_state_record_v2(&head_key, &head_record) {
            Ok(StoredRecordV2::ProviderHead { value }) => value,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        let method = match self.projection.method {
            SourceProviderMethod::Acquire => ProviderMethodV2::Acquire,
            SourceProviderMethod::Release => ProviderMethodV2::Release,
            SourceProviderMethod::Inventory => ProviderMethodV2::Inventory,
            SourceProviderMethod::Hello => {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        };
        let graph = super::validated_mount_state(journal)?;
        let Some(expected_next_request_sequence) = self.projection.request_sequence.checked_add(1)
        else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let attempt_reference = aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        };
        let expected_acquire_floor = self.projection.verification_floors().map(
            |(catalog, selection, current_catalog_head_commitment)| {
                aos_sandbox_protocol::mount_source_acquisition_state::acquire_verification_floor_v2(
                    catalog,
                    selection,
                    Some(*current_catalog_head_commitment.as_bytes()),
                )
            },
        );
        let request_shape_matches = match (
            self.projection.method,
            self.projection.acquisition_identity(),
            self.projection.normalized_intent(),
            self.projection.normalized_intent_digest,
            attempt.provider_acquisition,
            attempt.normalized_acquire_intent.as_ref(),
        ) {
            (
                SourceProviderMethod::Acquire,
                Some((acquisition_id, acquisition_sequence)),
                Some(normalized_bytes),
                Some(normalized_digest),
                Some(identity),
                Some(normalized),
            ) => {
                identity.holder_authority_id == self.projection.holder.authority_id()
                    && identity.holder_authority_generation
                        == self.projection.holder.authority_generation()
                    && identity.holder_authority_digest
                        == *self.projection.holder.authority_digest().as_bytes()
                    && identity.acquisition_sequence == acquisition_sequence
                    && identity.acquisition_id == *acquisition_id.as_bytes()
                    && normalized.bytes == normalized_bytes
                    && normalized.digest == *normalized_digest.as_bytes()
                    && normalized.maximum_lease_expiry_seconds
                        == self
                            .projection
                            .deadline_seconds
                            .min(self.projection.session.current_valid_until_seconds)
            }
            (SourceProviderMethod::Acquire, ..) => false,
            (
                SourceProviderMethod::Release,
                Some((acquisition_id, acquisition_sequence)),
                None,
                None,
                Some(identity),
                None,
            ) => {
                identity.acquisition_sequence == acquisition_sequence
                    && identity.acquisition_id == *acquisition_id.as_bytes()
            }
            (SourceProviderMethod::Release, ..) => false,
            (_, None, None, None, None, None) => true,
            _ => false,
        };
        if !matches!(attempt.state, ProviderAttemptStateV2::Reserved)
            || attempt.method != method
            || attempt.scope.holder_authority_id != self.projection.holder.authority_id()
            || attempt.scope.provider_authority_id != self.projection.provider.authority_id()
            || attempt.signer_set_commitment != *self.projection.signer_set_commitment.as_bytes()
            || attempt.request_id != self.projection.request_id
            || attempt.request_sequence != self.projection.request_sequence
            || attempt.signed_request != self.signed_request
            || attempt.signed_request_digest != *self.projection.signed_request_digest.as_bytes()
            || attempt.acquire_verification_floor != expected_acquire_floor
            || attempt.inventory_correlations != self.projection.inventory_correlations
            || !request_shape_matches
            || head.scope != attempt.scope
            || head.current_session_id != attempt.session_id
            || head.pending_attempt != Some(attempt_reference)
            || head.next_request_sequence != expected_next_request_sequence
            || head.next_response_sequence != self.projection.expected_response_sequence
            || graph
                .provider_sessions
                .get(&attempt.session_id)
                .is_none_or(|session| {
                    !super::stored_mount_session_matches_projection(
                        session,
                        &self.projection.session,
                    )
                })
            || graph.provider_attempts.get(&attempt.attempt_id) != Some(&attempt)
            || graph.provider_heads.get(&(
                head.scope.holder_authority_id,
                head.scope.provider_authority_id,
            )) != Some(&head)
            || journal
                .validate_mount_source_acquisition_snapshot(reservation_snapshot)
                .is_err()
            || journal.get(attempt_key).ok().flatten() != Some(attempt_record)
            || journal.get(head_key).ok().flatten() != Some(head_record)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }

    /// Consumes this preparation after its exact namespace-40 reservation commits.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] unless the protected snapshot and
    /// exact typed attempt/head records prove the request reservation.
    pub fn confirm_protected_reservation(
        mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        reservation_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
    ) -> Result<ReservedMountProviderRequestV2, SourceProviderSecurityError> {
        self.validate_protected_reservation(
            journal,
            &reservation_snapshot,
            &attempt_key,
            &attempt_record,
            &head_key,
            &head_record,
        )?;
        self.into_reserved(
            reservation_snapshot,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
        )
    }

    pub(super) fn into_reserved(
        mut self,
        reservation_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
    ) -> Result<ReservedMountProviderRequestV2, SourceProviderSecurityError> {
        let attempt = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(&attempt_key, &attempt_record) {
            Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { value }) => value,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        };
        Ok(self.bind_reserved(
            reservation_snapshot,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
            attempt.session_id,
            attempt.attempt_id,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn bind_reserved(
        mut self,
        reservation_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        session_id: [u8; 32],
        attempt_id: [u8; 32],
    ) -> ReservedMountProviderRequestV2 {
        self.outcome.mount_session_id = Some(session_id);
        self.outcome.mount_attempt_id = Some(attempt_id);
        ReservedMountProviderRequestV2 {
            prepared: self,
            reservation_snapshot,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
        }
    }
}

impl CurrentMountProviderSessionPlanV2 {
    /// Borrows the complete immutable session projection used for attempt planning.
    #[must_use]
    pub const fn session(&self) -> &MountProviderSessionProjectionV2 {
        &self.session
    }

    /// Returns current request/response sequences authenticated by the owner head.
    #[must_use]
    pub const fn sequences(&self) -> (u64, u64) {
        (
            self.current_request_sequence,
            self.current_response_sequence,
        )
    }

    /// Returns a nonauthorizing commitment to the current session and owner head.
    #[must_use]
    pub const fn freshness_digest(&self) -> ObjectDigest {
        self.freshness_digest
    }
}

impl SentMountProviderRequestV2 {
    /// Borrows the nonauthorizing durable request and session projection.
    #[must_use]
    pub const fn projection(&self) -> &MountProviderRequestProjectionV2 {
        &self.projection
    }

    /// Borrows the verifier while its fixed Mount owner retains sole custody.
    #[must_use]
    #[doc(hidden)]
    pub const fn outcome_authorization(&self) -> &AuthorizedMountProviderOutcomeV2 {
        &self.outcome
    }

    /// Consumes the sent marker into the sole verifier for its exact provider outcome.
    #[must_use]
    pub fn into_outcome_authorization(self) -> AuthorizedMountProviderOutcomeV2 {
        self.outcome
    }
}

impl MountProviderRequestProjectionV2 {
    /// Borrows the sealed immutable session projection.
    #[must_use]
    pub const fn session(&self) -> &MountProviderSessionProjectionV2 {
        &self.session
    }
    /// Returns the request method.
    #[must_use]
    pub const fn method(&self) -> SourceProviderMethod {
        self.method
    }

    /// Returns the current provider authority.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the current holder authority.
    #[must_use]
    pub const fn holder(&self) -> &SourceProviderAuthorityV1 {
        &self.holder
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the ordered signer-set commitment.
    #[must_use]
    pub const fn signer_set_commitment(&self) -> ObjectDigest {
        self.signer_set_commitment
    }

    /// Returns the protected trust and revocation heads.
    #[must_use]
    pub const fn trust_heads(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.trust_generation,
            self.trust_digest,
            self.revocation_generation,
            self.revocation_digest,
        )
    }

    /// Returns the authenticated provider process instance.
    #[must_use]
    pub const fn provider_process_instance(&self) -> [u8; 16] {
        self.provider_process_instance
    }

    /// Returns the request identity and client sequence.
    #[must_use]
    pub const fn request_identity(&self) -> ([u8; 16], u64) {
        (self.request_id, self.request_sequence)
    }

    /// Returns the expected provider response sequence.
    #[must_use]
    pub const fn expected_response_sequence(&self) -> u64 {
        self.expected_response_sequence
    }

    /// Returns the provider acquisition identity and holder-wide sequence.
    #[must_use]
    pub const fn acquisition_identity(&self) -> Option<(ObjectDigest, u64)> {
        match (self.acquisition_id, self.acquisition_sequence) {
            (Some(identifier), Some(sequence)) => Some((identifier, sequence)),
            _ => None,
        }
    }

    /// Borrows the exact canonical AOSNPI01/version-2 bytes.
    #[must_use]
    pub fn normalized_intent(&self) -> Option<&[u8]> {
        self.normalized_intent.as_deref()
    }

    /// Returns normalized, typed-request, and signed-request commitments.
    #[must_use]
    pub const fn request_digests(&self) -> (Option<ObjectDigest>, ObjectDigest, ObjectDigest) {
        (
            self.normalized_intent_digest,
            self.typed_request_digest,
            self.signed_request_digest,
        )
    }

    /// Returns the exact request deadline.
    #[must_use]
    pub const fn deadline_seconds(&self) -> i64 {
        self.deadline_seconds
    }

    /// Borrows the exact Mount-provided catalog and optional selection floors.
    #[must_use]
    pub const fn verification_floors(
        &self,
    ) -> Option<(
        &ProviderCatalogFloorV1,
        Option<&SourceSelectionFloorV1>,
        ObjectDigest,
    )> {
        match &self.catalog_floor {
            Some(catalog) => self
                .current_catalog_head_commitment
                .map(|commitment| (catalog, self.selection_floor.as_ref(), commitment)),
            None => None,
        }
    }

    /// Borrows the exact Inventory correlation preimage fixed before I/O.
    #[must_use]
    pub const fn inventory_correlations(
        &self,
    ) -> Option<&aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2>
    {
        self.inventory_correlations.as_ref()
    }
}

impl MountProviderSessionProjectionV2 {
    /// Borrows the exact canonical signed Root Mount and provider hellos.
    #[must_use]
    pub fn signed_hellos(&self) -> (&[u8], &[u8]) {
        (&self.signed_root_mount_hello, &self.signed_provider_hello)
    }

    /// Returns the ordered RootHello, RootRecord, ProviderHello, ProviderOutcome signers.
    #[must_use]
    pub const fn ordered_signers(&self) -> &[MountProviderSignerProjectionV2; 4] {
        &self.ordered_signers
    }

    /// Returns Root Mount and provider authority admission snapshots in that order.
    #[must_use]
    pub const fn authority_trust(&self) -> &[MountProviderAuthorityTrustProjectionV2; 2] {
        &self.authority_trust
    }

    /// Returns the authenticated session and ordered-signer commitments.
    #[must_use]
    pub const fn session_commitments(&self) -> (ObjectDigest, ObjectDigest) {
        (self.session_binding, self.signer_set_commitment)
    }

    /// Returns the protected trust and revocation heads used for admission.
    #[must_use]
    pub const fn trust_heads(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.trust_generation,
            self.trust_digest,
            self.revocation_generation,
            self.revocation_digest,
        )
    }

    /// Returns root boot and both process-instance identities.
    #[must_use]
    pub const fn process_instances(&self) -> ([u8; 16], [u8; 16], [u8; 16]) {
        (
            self.root_boot_id,
            self.root_process_instance,
            self.provider_process_instance,
        )
    }

    /// Returns the protected deployment node identity.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 16] {
        self.node_id
    }

    /// Returns verified Root Mount writer uid, gid, tgid, start time, and cgroup digest.
    #[must_use]
    pub const fn root_writer(&self) -> (u32, u32, u32, u64, ObjectDigest) {
        (
            self.root_writer_uid,
            self.root_writer_gid,
            self.root_writer_tgid,
            self.root_writer_start_time_ticks,
            self.root_writer_cgroup_digest,
        )
    }

    /// Returns verified provider tgid, start time, and cgroup digest.
    #[must_use]
    pub const fn provider_execution(
        &self,
    ) -> (
        u32,
        u32,
        u32,
        u64,
        u64,
        ObjectDigest,
        [u32; 8],
        ObjectDigest,
    ) {
        (
            self.provider_pid,
            self.provider_tgid,
            self.provider_parent_pid,
            self.provider_start_time_ticks,
            self.provider_cgroup_id,
            self.provider_cgroup_digest,
            self.provider_credentials,
            self.provider_execution_digest,
        )
    }

    /// Returns protected route identity and resource namespace.
    #[must_use]
    pub const fn route(&self) -> ([u8; 16], u64, ObjectDigest, ObjectDigest) {
        (
            self.route_id,
            self.route_generation,
            self.route_digest,
            self.resource_namespace_digest,
        )
    }

    /// Returns negotiated proof, recursive, and kernel-coupled capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> (u8, bool, bool) {
        (
            self.proof_class_capabilities,
            self.supports_recursive,
            self.supports_kernel_coupled,
        )
    }

    /// Returns authentication time, exclusive current-valid-until, and clock evidence.
    #[must_use]
    pub const fn validity(&self) -> (i64, i64, ObjectDigest) {
        (
            self.authenticated_at_seconds,
            self.current_valid_until_seconds,
            self.trusted_clock_evidence_digest,
        )
    }
}

impl MountProviderAuthorityTrustProjectionV2 {
    /// Returns the exact authority tuple.
    #[must_use]
    pub const fn authority(&self) -> &SourceProviderAuthorityV1 {
        &self.authority
    }

    /// Returns the protected validity interval and admission state.
    #[must_use]
    pub const fn admission(&self) -> (i64, i64, SourceProviderAuthorityTrustStateV1) {
        (
            self.valid_from_seconds,
            self.valid_until_seconds,
            self.state,
        )
    }
}

impl MountProviderSignerProjectionV2 {
    /// Returns the complete signer identity and exact Ed25519 verification key.
    #[must_use]
    pub const fn identity(
        &self,
    ) -> (
        &aos_sandbox_source_provider_protocol::SourceProviderSigningKeyV1,
        &[u8; 32],
    ) {
        (&self.signer, &self.public_key)
    }

    /// Returns authority/key intervals, states, and authenticated successor generation.
    #[must_use]
    pub const fn admission(
        &self,
    ) -> (
        i64,
        i64,
        i64,
        i64,
        SourceProviderAuthorityTrustStateV1,
        SourceProviderKeyTrustStateV1,
        u64,
    ) {
        (
            self.authority_valid_from_seconds,
            self.authority_valid_until_seconds,
            self.key_valid_from_seconds,
            self.key_valid_until_seconds,
            self.authority_state,
            self.key_state,
            self.superseded_by_key_generation,
        )
    }
}

impl VerifiedMountProviderOutcomeV2 {
    /// Borrows the exact canonical provider response for tentative disposition construction.
    ///
    /// The bytes are nonauthorizing. A Complete Acquire remains unusable
    /// without consuming its paired SourceRoot custody through the protected
    /// post-commit security transition.
    #[must_use]
    pub fn canonical_response(&self) -> &[u8] {
        &self.canonical_response
    }

    /// Returns the verified terminal or nonterminal status.
    #[must_use]
    pub const fn status(&self) -> SourceProviderStatus {
        self.status
    }

    /// Returns the exact result and descriptor commitments.
    #[must_use]
    pub const fn commitments(&self) -> (ObjectDigest, ObjectDigest) {
        (self.result_digest, self.descriptor_commitment)
    }

    /// Returns the provider acquisition identity.
    #[must_use]
    pub const fn acquisition_id(&self) -> Option<ObjectDigest> {
        self.acquisition_id
    }

    /// Returns the authenticated session and response sequence.
    #[must_use]
    pub const fn response_identity(&self) -> (ObjectDigest, u64) {
        (self.session_binding, self.response_sequence)
    }

    /// Returns the trusted verification-time anchor for this exact outcome.
    #[must_use]
    pub const fn verification_anchor(
        &self,
    ) -> aos_sandbox_protocol::mount_source_acquisition_state::OutcomeVerificationAnchorV2 {
        self.verification_anchor
    }

    /// Consumes the verified outcome into its exact canonical response bytes.
    #[must_use]
    pub fn into_canonical_response(self) -> Vec<u8> {
        self.canonical_response
    }

    pub(crate) fn authorizes_negative_custody(
        &self,
        acquisition_id: ObjectDigest,
        acquisition_sequence: u64,
        lease_id: [u8; 16],
        lease_digest: ObjectDigest,
    ) -> bool {
        self.status == SourceProviderStatus::Complete
            && self.terminal_lineages.iter().any(|lineage| {
                lineage.acquisition_id == acquisition_id
                    && lineage.acquisition_sequence == acquisition_sequence
                    && lineage.lease_id == lease_id
                    && lineage.lease_digest == lease_digest
            })
    }
}

impl VerifiedReceivedMountProviderOutcomeV2 {
    /// Borrows the verified cryptographic outcome projection.
    #[must_use]
    pub const fn outcome(&self) -> &VerifiedMountProviderOutcomeV2 {
        &self.verified
    }

    /// Borrows the exact kernel-observed SourceRoot facts, when present.
    #[must_use]
    pub fn source_root_observation(
        &self,
    ) -> Option<&aos_sandbox_source_provider_protocol::SourceRootObservationV1> {
        self.source_root
            .as_ref()
            .map(crate::ObservedSourceRootV1::protocol_observation)
    }

    /// Consumes the one-shot receive capability into its closed descriptor shape.
    #[must_use]
    pub fn into_parts(self) -> ReceivedMountProviderOutcomePartsV2 {
        match self.source_root {
            Some(source_root) => ReceivedMountProviderOutcomePartsV2::CompleteAcquire {
                outcome: self.verified,
                source_root,
            },
            None => ReceivedMountProviderOutcomePartsV2::WithoutSourceRoot(self.verified),
        }
    }
}

impl RecoveredMountProviderOutcomeV2 {
    /// Borrows the fully verified outcome projection.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedMountProviderOutcomeV2 {
        &self.verified
    }

    /// Borrows the reopened SourceRoot observation, when one is required.
    #[must_use]
    pub fn source_root_observation(
        &self,
    ) -> Option<&aos_sandbox_source_provider_protocol::SourceRootObservationV1> {
        self.source_root
            .as_ref()
            .map(ReopenedMountSourceRootV2::observation)
    }

    /// Consumes the one-shot recovery capability into its closed custody shape.
    #[must_use]
    pub fn into_parts(self) -> RecoveredMountProviderOutcomePartsV2 {
        match self.source_root {
            Some(source_root) => RecoveredMountProviderOutcomePartsV2::CompleteAcquire {
                outcome: self.verified,
                source_root,
            },
            None => RecoveredMountProviderOutcomePartsV2::WithoutSourceRoot(self.verified),
        }
    }
}

impl ReopenedMountSourceRootV2 {
    /// Borrows the exact freshly observed SourceRoot facts.
    #[must_use]
    pub fn observation(&self) -> &aos_sandbox_source_provider_protocol::SourceRootObservationV1 {
        self.handoff.observation()
    }

    pub(crate) fn revalidate(&self) -> Result<(), SourceProviderSecurityError> {
        self.handoff.revalidate()
    }
}

impl HistoricalMountReleaseAuthorizationV2 {
    /// Returns the predecessor-derived provider acquisition identity.
    #[must_use]
    pub const fn acquisition_identity(&self) -> (ObjectDigest, u64) {
        self.lineage.acquisition_identity()
    }

    /// Returns the exact retained lease identity.
    #[must_use]
    pub const fn lease_identity(&self) -> ([u8; 16], ObjectDigest) {
        self.lineage.lease_identity()
    }

    /// Returns predecessor and current authenticated holder authority tuples.
    #[must_use]
    pub const fn holder_transition(
        &self,
    ) -> (&SourceProviderAuthorityV1, &SourceProviderAuthorityV1) {
        self.lineage.holder_transition()
    }

    /// Returns the exact protected-lineage commitment.
    #[must_use]
    pub const fn lineage_commitment(&self) -> ObjectDigest {
        self.lineage.lineage_commitment
    }

    pub(super) fn revalidate(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_session_binding: ObjectDigest,
    ) -> bool {
        self.lineage.revalidate(journal, current_session_binding)
    }
}

impl HistoricalMountInventoryAuthorizationV2 {
    /// Returns the predecessor-derived provider acquisition identity.
    #[must_use]
    pub const fn acquisition_identity(&self) -> (ObjectDigest, u64) {
        self.lineage.acquisition_identity()
    }

    /// Returns the exact retained lease identity.
    #[must_use]
    pub const fn lease_identity(&self) -> ([u8; 16], ObjectDigest) {
        self.lineage.lease_identity()
    }

    /// Returns predecessor and current authenticated holder authority tuples.
    #[must_use]
    pub const fn holder_transition(
        &self,
    ) -> (&SourceProviderAuthorityV1, &SourceProviderAuthorityV1) {
        self.lineage.holder_transition()
    }

    /// Returns the exact protected-lineage commitment.
    #[must_use]
    pub const fn lineage_commitment(&self) -> ObjectDigest {
        self.lineage.lineage_commitment
    }

    pub(super) fn revalidate(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_session_binding: ObjectDigest,
    ) -> bool {
        self.lineage.revalidate(journal, current_session_binding)
    }
}

impl HistoricalMountAcquisitionLineageV2 {
    const fn acquisition_identity(&self) -> (ObjectDigest, u64) {
        (self.acquisition_id, self.acquisition_sequence)
    }

    const fn lease_identity(&self) -> ([u8; 16], ObjectDigest) {
        (self.lease_id, self.lease_digest)
    }

    const fn holder_transition(&self) -> (&SourceProviderAuthorityV1, &SourceProviderAuthorityV1) {
        (&self.predecessor_holder, &self.current_holder)
    }

    pub(super) fn revalidate(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_session_binding: ObjectDigest,
    ) -> bool {
        self.session_binding == current_session_binding
            && journal
                .validate_mount_source_acquisition_snapshot(&self.journal_snapshot)
                .is_ok()
            && journal.get(&self.acquisition_key).ok().flatten()
                == Some(self.acquisition_record.as_slice())
            && journal.get(&self.predecessor_session_key).ok().flatten()
                == Some(self.predecessor_session_record.as_slice())
            && self.lineage_commitment == historical_acquisition_commitment(self)
    }
}

pub(super) fn historical_acquisition_commitment(
    authorization: &HistoricalMountAcquisitionLineageV2,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.security.historical-mount-acquisition.v2\0");
    hasher.update(authorization.provider_authority_id);
    for authority in [
        &authorization.predecessor_holder,
        &authorization.current_holder,
    ] {
        hasher.update(authority.authority_id());
        hasher.update(authority.authority_generation().to_be_bytes());
        hasher.update(authority.authority_digest().as_bytes());
    }
    hasher.update(authorization.acquisition_id.as_bytes());
    hasher.update(authorization.acquisition_sequence.to_be_bytes());
    hasher.update(authorization.lease_id);
    hasher.update(authorization.lease_digest.as_bytes());
    hasher.update(authorization.session_binding.as_bytes());
    hasher.update([match authorization.inventory_expectation {
        aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::PresentActiveOrReaping => 1,
        aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReapingReleasedOrAbsent => 2,
        aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationExpectationV2::ReleasedOrAbsent => 3,
    }]);
    for bytes in [
        authorization.acquisition_key.as_slice(),
        authorization.acquisition_record.as_slice(),
        authorization.predecessor_session_key.as_slice(),
        authorization.predecessor_session_record.as_slice(),
    ] {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
