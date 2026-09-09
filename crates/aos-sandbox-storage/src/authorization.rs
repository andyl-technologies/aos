//! Storage-audience adapter for shared protected authority admission.
//!
//! This module adds no storage trust rules of its own. It maps exact portable
//! storage semantics and the validated assignment carried by the protobuf into
//! the shared broker verifier, then seals its pending fence/effect records for
//! atomic persistence beside the storage transaction intent.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::ApplyStorageRequest;
use aos_sandbox::RecordNamespace;
use aos_sandbox_broker::{
    AdmissionRequest, BrokerAdmissionError, BrokerAuthority, BrokerAuthorityConfigError,
    BrokerAuthorizationFenceV1, BrokerDomain, BrokerEffectIntentV2, BrokerEffectStatusV2,
    BrokerLocalRecordDomain, ProtectedBrokerAuthorityConfiguration, VerifiedBrokerAdmission,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerGrantTarget, BrokerPlanTrustAnchor,
    BrokerResourceHandle, BrokerVerb, DesiredGeneration, IncarnationId, NodeId, ObjectDigest,
    OwnershipLeaseTrustAnchor, ProtocolId, ProtocolVersion, RawPairedClockSample, SandboxId,
};
use aos_sandbox_protocol::semantics::storage::CanonicalStorageSemanticsV1;
use aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1;
use aos_sandbox_protocol::semantics::storage_repair::CanonicalStorageRepairSemanticsV1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::StorageStateKey;
use crate::workspace_pin::{WorkspacePinActionV1, WorkspacePinAttemptV1};
use crate::workspace_repair::StorageWorkspacePinRepairIntentV1;

const PIN_RECEIPT_DOMAIN: [u8; 16] = *b"AOSSTGPINRECV001";
const PREPARATION_RECORD_DOMAIN: [u8; 16] = *b"AOSSTGPREPV10001";
const PREPARATION_RECEIPT_DOMAIN: [u8; 16] = *b"AOSSTGPRCPV10001";
const PIN_RECEIPT_MAGIC: &[u8; 8] = b"AOSPAR01";
const PIN_RECEIPT_VERSION: u16 = 1;
const REPAIR_COMPLETION_MAGIC: &[u8; 8] = b"AOSZRCE1";
const REPAIR_COMPLETION_VERSION: u16 = 1;

/// Storage-audience alias for protected authority configuration failures.
pub type StorageAuthorityConfigError = BrokerAuthorityConfigError;
/// Storage-audience alias for signed admission failures.
pub type StorageAdmissionError = BrokerAdmissionError;

/// Couples Storage authority and durable-state authentication from one read.
///
/// The protected directory remains a restart-time configuration boundary. It
/// must be provisioned completely before startup rather than edited in place.
pub struct StorageProtectedConfigurationV1 {
    authority: StorageAuthorityV1,
    state_key: StorageStateKey,
    public_binding: ObjectDigest,
}

impl StorageProtectedConfigurationV1 {
    /// Loads Storage authority and its matching state key together.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAuthorityConfigError`] when protected configuration is
    /// missing, insecure, malformed, oversized, or internally inconsistent.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, StorageAuthorityConfigError> {
        let configuration = ProtectedBrokerAuthorityConfiguration::from_protected_directory(
            path,
            BrokerDomain::Storage,
        )?;
        let public_binding = configuration.public_binding();
        let (authority, key_id, secret) = configuration.into_parts();
        let state_key = StorageStateKey::new(key_id, *secret)
            .map_err(|_| StorageAuthorityConfigError::Invalid("journal-mac-key"))?;

        Ok(Self {
            authority: StorageAuthorityV1(authority),
            state_key,
            public_binding,
        })
    }

    /// Separates the coupled configuration for lifetime-owned runtime state.
    #[must_use]
    pub fn into_parts(self) -> (StorageAuthorityV1, StorageStateKey, ObjectDigest) {
        (self.authority, self.state_key, self.public_binding)
    }

    /// Returns the non-secret binding persisted with Storage runtime state.
    #[must_use]
    pub const fn public_binding(&self) -> ObjectDigest {
        self.public_binding
    }

    pub(crate) fn authenticate_workspace_pin_worker_request(
        &self,
        configured_contract: &crate::ZfsHelperContract,
        request: crate::pin_worker::WorkspacePinWorkerRequestV1,
    ) -> Result<crate::pin_worker::AuthenticatedWorkspacePinWorkerRequestV1, crate::ZfsWorkerError>
    {
        crate::pin_worker::authenticate_request(
            &self.authority,
            &self.state_key,
            configured_contract,
            request,
        )
    }

    pub(crate) fn authenticate_workspace_pin_observation_request(
        &self,
        configured_contract: &crate::ZfsHelperContract,
        request: crate::pin_worker::WorkspacePinWorkerRequestV1,
    ) -> Result<
        crate::pin_worker::AuthenticatedWorkspacePinObservationRequestV1,
        crate::ZfsWorkerError,
    > {
        crate::pin_worker::authenticate_observation_request(
            &self.authority,
            &self.state_key,
            configured_contract,
            request,
        )
    }

    pub(crate) fn authenticate_workspace_pin_repair_observation_request(
        &self,
        configured_contract: &crate::ZfsHelperContract,
        request: crate::workspace_repair_observer::WorkspacePinRepairObserverRequestV1,
        current_host_scope: crate::workspace_pin::WorkspacePinHostScopeV1,
    ) -> Result<
        crate::workspace_repair_observer::AuthenticatedWorkspacePinRepairObserverRequestV1,
        crate::ZfsWorkerError,
    > {
        crate::workspace_repair_observer::authenticate_request(
            &self.state_key,
            configured_contract,
            request,
            current_host_scope,
        )
    }

    pub(crate) fn authenticate_workspace_pin_repair_admission_request(
        &self,
        configured_contract: &crate::ZfsHelperContract,
        request: crate::workspace_repair_admission::WorkspacePinRepairAdmissionRequestV1,
        current_host_scope: crate::workspace_pin::WorkspacePinHostScopeV1,
    ) -> Result<
        crate::workspace_repair_admission::AuthenticatedWorkspacePinRepairAdmissionRequestV1,
        crate::ZfsWorkerError,
    > {
        crate::workspace_repair_admission::authenticate_request(
            &self.state_key,
            configured_contract,
            request,
            current_host_scope,
        )
    }

    pub(crate) fn authenticate_workspace_pin_repair_worker_request(
        &self,
        configured_contract: &crate::ZfsHelperContract,
        request: crate::workspace_repair_worker::WorkspacePinRepairWorkerRequestV1,
    ) -> Result<
        crate::workspace_repair_worker::AuthenticatedWorkspacePinRepairWorkerRequestV1,
        crate::ZfsWorkerError,
    > {
        crate::workspace_repair_worker::authenticate_request(
            &self.authority,
            &self.state_key,
            configured_contract,
            request,
        )
    }

    pub(crate) fn check_workspace_pin_worker_before_effect<F>(
        &self,
        request: &crate::pin_worker::AuthenticatedWorkspacePinWorkerRequestV1,
        trusted_clock: &mut F,
    ) -> Result<(), crate::ZfsWorkerError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        crate::pin_worker::check_before_effect(&self.authority, request, trusted_clock)
    }

    pub(crate) fn check_workspace_pin_repair_worker_before_effect<F>(
        &self,
        request: &crate::workspace_repair_worker::AuthenticatedWorkspacePinRepairWorkerRequestV1,
        trusted_clock: &mut F,
    ) -> Result<(), crate::ZfsWorkerError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        crate::workspace_repair_worker::check_before_effect(&self.authority, request, trusted_clock)
    }
}

/// Groups the three location-bound records committed with one Storage intent.
pub(crate) struct SealedStorageAdmission {
    pub(crate) current_fence: Vec<u8>,
    pub(crate) effect: Vec<u8>,
    pub(crate) operation_fence: Vec<u8>,
}

/// Owns protected storage-audience trust and record-authentication state.
pub struct StorageAuthorityV1(BrokerAuthority);

impl StorageAuthorityV1 {
    /// Constructs storage authority from validated protected anchors.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAdmissionError::InvalidConfiguration`] for invalid
    /// node or journal-key configuration.
    pub fn new(
        plan_anchor: BrokerPlanTrustAnchor,
        lease_anchor: OwnershipLeaseTrustAnchor,
        node: NodeId,
        journal_key_id: [u8; 16],
        journal_secret: [u8; 32],
    ) -> Result<Self, StorageAdmissionError> {
        BrokerAuthority::new(
            BrokerDomain::Storage,
            plan_anchor,
            lease_anchor,
            node,
            journal_key_id,
            journal_secret,
        )
        .map(Self)
    }

    /// Loads storage authority from the protected fixed-file schema.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAuthorityConfigError`] for missing, insecure,
    /// malformed, oversized, or inconsistent protected credentials.
    pub fn from_protected_directory(
        path: impl AsRef<Path>,
    ) -> Result<Self, StorageAuthorityConfigError> {
        BrokerAuthority::from_protected_directory(path, BrokerDomain::Storage).map(Self)
    }

    pub(crate) fn admit(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        semantics: &CanonicalStorageSemanticsV1,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, StorageAdmissionError> {
        let assignment = decode_assignment(request_body)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage,
                protocol: ProtocolId::StorageBroker,
                protocol_version,
                assignment,
                request_id: *semantics.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.broker_verb(),
                target: semantics.grant_target(),
                argument_commitment: semantics.argument_commitment(),
                request_deadline_boottime_nanoseconds: semantics
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    pub(crate) fn admit_preparation(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        semantics: &CanonicalStoragePreparationSemanticsV1,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, StorageAdmissionError> {
        let assignment = assignment_from_preparation(semantics)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage,
                protocol: ProtocolId::StorageBroker,
                protocol_version,
                assignment,
                request_id: *semantics.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.broker_verb(),
                target: semantics.grant_target(),
                argument_commitment: semantics.argument_commitment(),
                request_deadline_boottime_nanoseconds: semantics
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    pub(crate) fn admit_workspace_pin_repair(
        &self,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        semantics: &CanonicalStorageRepairSemanticsV1,
        request_body: &[u8],
        protocol_version: ProtocolVersion,
        current_clock: &RawPairedClockSample,
        prior_fence: Option<&[u8]>,
    ) -> Result<VerifiedBrokerAdmission, StorageAdmissionError> {
        let assignment = assignment_from_repair(semantics)?;
        self.0.admit(
            artifacts,
            AdmissionRequest {
                audience: BrokerAudience::Storage,
                protocol: ProtocolId::StorageBroker,
                protocol_version,
                assignment,
                request_id: *semantics.header().request_id(),
                request_body,
                descriptor_count: 0,
                verb: semantics.broker_verb(),
                target: semantics.grant_target(),
                argument_commitment: semantics.argument_commitment(),
                request_deadline_boottime_nanoseconds: semantics
                    .header()
                    .deadline_boottime_nanoseconds(),
            },
            current_clock,
            prior_fence,
        )
    }

    pub(crate) fn seal(
        &self,
        sandbox_id: &[u8; 16],
        request_id: &[u8; 16],
        operation_id: &[u8; 16],
        admission: &VerifiedBrokerAdmission,
    ) -> Result<SealedStorageAdmission, StorageAdmissionError> {
        Ok(SealedStorageAdmission {
            current_fence: self.0.seal_fence(sandbox_id, &admission.fence)?,
            effect: self.0.seal_effect(request_id, &admission.effect)?,
            operation_fence: self
                .0
                .seal_operation_fence(operation_id, &admission.fence)?,
        })
    }

    pub(crate) fn open_fence(
        &self,
        sandbox_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, StorageAdmissionError> {
        self.0.open_fence(sandbox_id, bytes)
    }

    pub(crate) fn open_operation_fence(
        &self,
        operation_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerAuthorizationFenceV1, StorageAdmissionError> {
        self.0.open_operation_fence(operation_id, bytes)
    }

    pub(crate) fn open_admission_intent(
        &self,
        request_id: &[u8; 16],
        bytes: &[u8],
    ) -> Result<BrokerEffectIntentV2, StorageAdmissionError> {
        self.0.open_effect(request_id, bytes)
    }

    #[cfg(test)]
    pub(crate) fn seal_effect_for_test(
        &self,
        request_id: &[u8; 16],
        effect: &BrokerEffectIntentV2,
    ) -> Result<Vec<u8>, StorageAdmissionError> {
        self.0.seal_effect(request_id, effect)
    }

    /// Authenticates retained Pending repair authority against its operation fence.
    ///
    /// The exact original Effect bytes are opened at their original namespace
    /// and request key; a later live Effect status does not replace this
    /// immutable admission evidence.
    ///
    /// # Errors
    ///
    /// Returns [`StorageAdmissionError::FenceRejected`] for authentication,
    /// request-digest, semantic, target, assignment, or immutable fence mismatch.
    pub(crate) fn authenticate_workspace_pin_repair_intent(
        &self,
        intent: &StorageWorkspacePinRepairIntentV1,
        sealed_operation_fence: &[u8],
        live_effect_record: &[u8],
    ) -> Result<(BrokerAuthorizationFenceV1, BrokerEffectIntentV2), StorageAdmissionError> {
        let operation_fence =
            self.open_operation_fence(&intent.repair_operation_id(), sealed_operation_fence)?;
        let admitted_effect =
            self.open_admission_intent(&intent.request_id(), intent.admitted_effect_record())?;
        let live_effect = self.open_admission_intent(&intent.request_id(), live_effect_record)?;

        let target = BrokerResourceHandle::from_bytes(intent.workspace_handle())
            .map(BrokerGrantTarget::Resource)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        let expected_live_effect = match live_effect.status() {
            BrokerEffectStatusV2::Pending => admitted_effect.clone(),
            BrokerEffectStatusV2::Complete => admitted_effect
                .clone()
                .complete(live_effect.receipt().to_vec())
                .map_err(|_| StorageAdmissionError::FenceRejected)?,
        };
        if ObjectDigest::from_bytes(Sha256::digest(sealed_operation_fence).into())
            != intent.operation_fence_digest()
            || admitted_effect.status() != BrokerEffectStatusV2::Pending
            || admitted_effect.request_id() != &intent.request_id()
            || admitted_effect.transport_request_digest() != intent.request_digest()
            || admitted_effect.request_digest() != intent.semantic_commitment()
            || admitted_effect.verb() != BrokerVerb::StorageRepairWorkspacePin
            || admitted_effect.target() != target
            || admitted_effect.plan_digest() != operation_fence.plan_digest()
            || admitted_effect.lease_digest() != operation_fence.local_lease_record().lease_digest()
            || operation_fence.assignment().digest() != intent.repair_assignment_digest()
            || live_effect != expected_live_effect
        {
            return Err(StorageAdmissionError::FenceRejected);
        }
        Ok((operation_fence, admitted_effect))
    }

    pub(crate) fn seal_catalog_preparation_record(
        &self,
        operation_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<Vec<u8>, StorageAdmissionError> {
        let domain = BrokerLocalRecordDomain::new(PREPARATION_RECORD_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.seal_local_record(
            RecordNamespace::StorageCatalogPreparation,
            operation_id,
            domain,
            payload,
        )
    }

    pub(crate) fn open_catalog_preparation_record<'a>(
        &self,
        operation_id: &[u8; 16],
        bytes: &'a [u8],
    ) -> Result<&'a [u8], StorageAdmissionError> {
        let domain = BrokerLocalRecordDomain::new(PREPARATION_RECORD_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.open_local_record(
            RecordNamespace::StorageCatalogPreparation,
            operation_id,
            domain,
            bytes,
        )
    }

    pub(crate) fn seal_catalog_preparation_receipt(
        &self,
        operation_id: &[u8; 16],
        payload: &[u8],
    ) -> Result<Vec<u8>, StorageAdmissionError> {
        let domain = BrokerLocalRecordDomain::new(PREPARATION_RECEIPT_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.seal_local_record(
            RecordNamespace::StorageCatalogPreparation,
            operation_id,
            domain,
            payload,
        )
    }

    pub(crate) fn open_catalog_preparation_receipt<'a>(
        &self,
        operation_id: &[u8; 16],
        bytes: &'a [u8],
    ) -> Result<&'a [u8], StorageAdmissionError> {
        let domain = BrokerLocalRecordDomain::new(PREPARATION_RECEIPT_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.open_local_record(
            RecordNamespace::StorageCatalogPreparation,
            operation_id,
            domain,
            bytes,
        )
    }

    pub(crate) fn check_before_effect<F>(
        &self,
        effect: &BrokerEffectIntentV2,
        trusted_clock: &mut F,
    ) -> Result<(), StorageAdmissionError>
    where
        F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
    {
        self.0.check_before_effect(effect, trusted_clock)
    }

    pub(crate) fn check_current_fence(
        &self,
        fence: &BrokerAuthorizationFenceV1,
    ) -> Result<(), StorageAdmissionError> {
        self.0.check_current_fence(fence)
    }

    pub(crate) fn seal_pin_attempt_receipt(
        &self,
        attempt: &WorkspacePinAttemptV1,
        effect: &BrokerEffectIntentV2,
        operation_fence: &BrokerAuthorizationFenceV1,
        parent_operation_id: [u8; 16],
        parent_request_id: [u8; 16],
    ) -> Result<Vec<u8>, StorageAdmissionError> {
        let action_is_authorized = matches!(
            (attempt.action(), effect.verb()),
            (
                WorkspacePinActionV1::Ensure,
                BrokerVerb::StorageCreateWorkspace
                    | BrokerVerb::StorageClone
                    | BrokerVerb::StorageRepairWorkspacePin
            ) | (
                WorkspacePinActionV1::RemoveAndDestroy,
                BrokerVerb::StorageDestroy
            )
        );
        if !action_is_authorized
            || effect.status() != BrokerEffectStatusV2::Pending
            || effect.plan_digest() != operation_fence.plan_digest()
            || effect.lease_digest() != operation_fence.local_lease_record().lease_digest()
            || attempt.effect_operation_id() != parent_operation_id
            || effect.request_id() != &parent_request_id
            || attempt.effect_assignment_digest() != operation_fence.assignment().digest()
            || attempt.host_boot_id() != *effect.host_boot_id()
            || attempt.clock_provenance() != *effect.clock_provenance()
            || attempt.effect_deadline_boottime_nanoseconds()
                != effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(StorageAdmissionError::FenceRejected);
        }
        let payload = pin_attempt_receipt_payload(attempt, effect, parent_operation_id)?;
        let domain = BrokerLocalRecordDomain::new(PIN_RECEIPT_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.seal_local_record(
            RecordNamespace::StorageWorkspacePinAttempt,
            &attempt.attempt_id(),
            domain,
            &payload,
        )
    }

    pub(crate) fn seal_workspace_pin_repair_completion(
        &self,
        effect: &BrokerEffectIntentV2,
        attempt: &WorkspacePinAttemptV1,
    ) -> Result<Vec<u8>, StorageAdmissionError> {
        if effect.status() != BrokerEffectStatusV2::Pending
            || effect.verb() != BrokerVerb::StorageRepairWorkspacePin
            || effect.target()
                != BrokerGrantTarget::Resource(
                    BrokerResourceHandle::from_bytes(attempt.workspace_handle())
                        .map_err(|_| StorageAdmissionError::FenceRejected)?,
                )
            || attempt.action() != WorkspacePinActionV1::Ensure
            || attempt.effect_operation_id() == attempt.creation_operation_id()
            || attempt.host_boot_id() != *effect.host_boot_id()
            || attempt.clock_provenance() != *effect.clock_provenance()
            || attempt.effect_deadline_boottime_nanoseconds()
                != effect.effect_deadline_boottime_nanoseconds()
        {
            return Err(StorageAdmissionError::FenceRejected);
        }
        let mut receipt = Vec::with_capacity(58);
        receipt.extend_from_slice(REPAIR_COMPLETION_MAGIC);
        receipt.extend_from_slice(&REPAIR_COMPLETION_VERSION.to_be_bytes());
        receipt.extend_from_slice(&attempt.attempt_id());
        receipt.extend_from_slice(
            attempt
                .authority_digest()
                .map_err(|_| StorageAdmissionError::FenceRejected)?
                .as_bytes(),
        );
        let completed = effect
            .clone()
            .complete(receipt)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        self.0.seal_effect(effect.request_id(), &completed)
    }

    pub(crate) fn verify_pin_attempt_receipt(
        &self,
        attempt: &WorkspacePinAttemptV1,
        effect: &BrokerEffectIntentV2,
        parent_operation_id: [u8; 16],
    ) -> Result<(), StorageAdmissionError> {
        let domain = BrokerLocalRecordDomain::new(PIN_RECEIPT_DOMAIN)
            .map_err(|_| StorageAdmissionError::FenceRejected)?;
        let payload = self.0.open_local_record(
            RecordNamespace::StorageWorkspacePinAttempt,
            &attempt.attempt_id(),
            domain,
            attempt.authority_receipt(),
        )?;
        if attempt.effect_operation_id() != parent_operation_id
            || payload != pin_attempt_receipt_payload(attempt, effect, parent_operation_id)?
        {
            return Err(StorageAdmissionError::FenceRejected);
        }
        Ok(())
    }
}

fn pin_attempt_receipt_payload(
    attempt: &WorkspacePinAttemptV1,
    effect: &BrokerEffectIntentV2,
    parent_operation_id: [u8; 16],
) -> Result<Vec<u8>, StorageAdmissionError> {
    let attempt_digest = attempt
        .authority_digest()
        .map_err(|_| StorageAdmissionError::FenceRejected)?;
    let mut payload = Vec::with_capacity(250);
    payload.extend_from_slice(PIN_RECEIPT_MAGIC);
    payload.extend_from_slice(&PIN_RECEIPT_VERSION.to_be_bytes());
    payload.extend_from_slice(&attempt.attempt_id());
    payload.extend_from_slice(attempt_digest.as_bytes());
    payload.push(match attempt.action() {
        WorkspacePinActionV1::Ensure => 1,
        WorkspacePinActionV1::RemoveAndDestroy => 2,
    });
    payload.extend_from_slice(&parent_operation_id);
    payload.extend_from_slice(effect.request_id());
    payload.extend_from_slice(effect.transport_request_digest().as_bytes());
    payload.extend_from_slice(effect.request_digest().as_bytes());
    payload.extend_from_slice(effect.plan_digest().as_bytes());
    payload.extend_from_slice(effect.lease_digest().as_bytes());
    payload.extend_from_slice(&effect.effect_deadline_boottime_nanoseconds().to_be_bytes());
    payload.extend_from_slice(attempt.operation_fence_digest().as_bytes());
    payload.extend_from_slice(attempt.effect_assignment_digest().as_bytes());
    Ok(payload)
}

pub(crate) fn decode_assignment(
    request_body: &[u8],
) -> Result<BrokerAssignment, StorageAdmissionError> {
    let request = ApplyStorageRequest::decode_from_slice(request_body)
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let fence = request
        .fence
        .as_option()
        .ok_or(StorageAdmissionError::RequestMismatch)?;
    let sandbox_id: [u8; 16] = fence
        .sandbox_id
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let incarnation_id: [u8; 16] = fence
        .incarnation_id
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    let assignment_digest: [u8; 32] = fence
        .assignment_digest
        .as_slice()
        .try_into()
        .map_err(|_| StorageAdmissionError::RequestMismatch)?;
    BrokerAssignment::new(
        SandboxId::from_bytes(sandbox_id),
        IncarnationId::from_bytes(incarnation_id),
        AssignmentEpoch::new(fence.assignment_epoch),
        DesiredGeneration::new(fence.desired_generation),
        ObjectDigest::from_bytes(assignment_digest),
    )
    .map_err(|_| StorageAdmissionError::RequestMismatch)
}

fn assignment_from_preparation(
    semantics: &CanonicalStoragePreparationSemanticsV1,
) -> Result<BrokerAssignment, StorageAdmissionError> {
    let fence = semantics.fence();
    BrokerAssignment::new(
        SandboxId::from_bytes(*fence.sandbox_id()),
        IncarnationId::from_bytes(*fence.incarnation_id()),
        AssignmentEpoch::new(fence.assignment_epoch()),
        DesiredGeneration::new(fence.desired_generation()),
        ObjectDigest::from_bytes(*fence.assignment_digest()),
    )
    .map_err(|_| StorageAdmissionError::RequestMismatch)
}

fn assignment_from_repair(
    semantics: &CanonicalStorageRepairSemanticsV1,
) -> Result<BrokerAssignment, StorageAdmissionError> {
    let fence = semantics.fence();
    BrokerAssignment::new(
        SandboxId::from_bytes(*fence.sandbox_id()),
        IncarnationId::from_bytes(*fence.incarnation_id()),
        AssignmentEpoch::new(fence.assignment_epoch()),
        DesiredGeneration::new(fence.desired_generation()),
        ObjectDigest::from_bytes(*fence.assignment_digest()),
    )
    .map_err(|_| StorageAdmissionError::RequestMismatch)
}
