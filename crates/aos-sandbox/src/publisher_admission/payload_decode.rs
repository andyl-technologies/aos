//! Typed canonical decoders for every protected publisher payload.

use aos_sandbox_core::{
    CacheDomainId, MediaType, ObjectDescriptor, ObjectDigest, OperationId, PrincipalId, ProjectId,
    PublicationReservationId, PublisherChallengeV1, PublisherInstanceId, ResourceId,
    format::{
        decode_publisher_admission_request_v1, decode_publisher_domain_plan,
        encode_publisher_admission_request_v1, encode_publisher_domain_plan,
    },
    model::{CacheDomain, CacheDomainKind},
};

use super::{
    AdmissionDecisionStateV1, AdmissionDecisionV1, ArtifactCommitmentV1, AuthorityCheckpointV1,
    CapacityAccountV1, CatalogEvictionReceiptV1, ChallengeConsumptionV1, CompletionPermitStateV1,
    CompletionPermitV1, CompletionReceiptV1, ProtectedRecordCodecError, PublicationAuthorityEpoch,
    PublicationPermitId, RecoveryObservationKindCodeV1, RecoveryObservationReceiptV1,
    ReservationStateV1, SourceReleaseStateV1, SourceReleaseV1, digest_parts,
};

const DECISION_DOMAIN: &[u8] = b"aos.sandbox.publisher.admission-decision.v1\0";
const ARTIFACT_DOMAIN: &[u8] = b"aos.sandbox.publisher.prepared-artifact.v1\0";
const PERMIT_DOMAIN: &[u8] = b"aos.sandbox.publisher.completion-permit.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.publisher.completion-receipt.v1\0";
const EVICTION_DOMAIN: &[u8] = b"aos.sandbox.publisher.catalog-eviction.v1\0";
const RECOVERY_DOMAIN: &[u8] = b"aos.sandbox.publisher.recovery-observation.v1\0";

/// Owns the fully decoded semantic value of one protected record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedPublisherPayloadV1 {
    /// Source-release successor.
    SourceRelease(SourceReleaseV1),
    /// Protected root successor.
    Root(crate::publisher_roots::PublicationRootRecordV1),
    /// Challenge consumption.
    Challenge(ChallengeConsumptionV1),
    /// Admission-decision successor.
    Decision(AdmissionDecisionV1),
    /// Accounting successor.
    Account(CapacityAccountV1),
    /// Prepared artifact.
    Artifact(ArtifactCommitmentV1),
    /// Completion-permit successor.
    Permit(CompletionPermitV1),
    /// Terminal completion receipt.
    Receipt(CompletionReceiptV1),
    /// Durable catalog eviction.
    Eviction(CatalogEvictionReceiptV1),
    /// Durable physical/fence recovery observation.
    RecoveryObservation(RecoveryObservationReceiptV1),
    /// Rollback-protected checkpoint.
    Checkpoint(AuthorityCheckpointV1),
    /// Poison evidence digest.
    Poison(ObjectDigest),
}

pub(super) fn decode_source(bytes: &[u8]) -> Result<SourceReleaseV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let release_digest = cursor.digest()?;
    let holder = PrincipalId::from_bytes(cursor.array()?);
    let project = ProjectId::from_bytes(cursor.array()?);
    let cache_resource = ResourceId::from_bytes(cursor.array()?);
    let cache_domain = cursor.domain()?;
    let content = cursor.object_until_nul()?;
    let producer_evidence = cursor.digest()?;
    let release_policy = cursor.digest()?;
    let not_before_seconds = cursor.i64()?;
    let expires_seconds = cursor.i64()?;
    let state = match cursor.u8()? {
        1 => SourceReleaseStateV1::Active,
        2 => SourceReleaseStateV1::Revoked,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    };
    cursor.finish()?;
    SourceReleaseV1 {
        release_digest,
        holder,
        project,
        cache_resource,
        cache_domain,
        content,
        producer_evidence,
        release_policy,
        not_before_seconds,
        expires_seconds,
        state,
    }
    .validate()
    .map_err(|_| ProtectedRecordCodecError::Malformed)
}

pub(super) fn decode_challenge(
    key: &[u8],
    bytes: &[u8],
) -> Result<ChallengeConsumptionV1, ProtectedRecordCodecError> {
    if key.len() != 48 || bytes.len() != 96 {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    Ok(ChallengeConsumptionV1 {
        publisher_instance: PublisherInstanceId::from_bytes(exact(&key[..16])?),
        challenge: PublisherChallengeV1::from_bytes(exact(&key[16..48])?)
            .map_err(|_| ProtectedRecordCodecError::Malformed)?,
        request_commitment: ObjectDigest::from_bytes(exact(&bytes[..32])?),
        operation: OperationId::from_bytes(exact(&bytes[32..48])?),
        reservation: PublicationReservationId::from_bytes(exact(&bytes[48..64])?),
        decision_digest: ObjectDigest::from_bytes(exact(&bytes[64..96])?),
    })
}

pub(super) fn decode_decision(
    bytes: &[u8],
) -> Result<AdmissionDecisionV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let operation = OperationId::from_bytes(cursor.array()?);
    let reservation = PublicationReservationId::from_bytes(cursor.array()?);
    let publisher_instance = PublisherInstanceId::from_bytes(cursor.array()?);
    let runtime_binding_digest = cursor.digest()?;
    let source_release_digest = cursor.digest()?;
    let root_registry_digest = cursor.digest()?;
    let root_registry_generation = cursor.u64()?;
    let selected_root_digest = cursor.digest()?;
    let selected_root_generation = cursor.u64()?;
    let authority_epoch = PublicationAuthorityEpoch::new(cursor.u64()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let state = decision_state(cursor.u8()?)?;
    let decision_digest = cursor.digest()?;
    let canonical_request = cursor.length_prefixed()?;
    let canonical_plan = cursor.length_prefixed()?;
    cursor.finish()?;
    let request = decode_publisher_admission_request_v1(&canonical_request, Default::default())
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let plan = decode_publisher_domain_plan(&canonical_plan, Default::default())
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    if encode_publisher_admission_request_v1(&request) != canonical_request
        || encode_publisher_domain_plan(&plan) != canonical_plan
        || request.plan() != &plan
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    let derived = digest_parts(
        DECISION_DOMAIN,
        &[
            operation.as_bytes(),
            reservation.as_bytes(),
            publisher_instance.as_bytes(),
            &canonical_request,
            &canonical_plan,
            runtime_binding_digest.as_bytes(),
            source_release_digest.as_bytes(),
            root_registry_digest.as_bytes(),
            &root_registry_generation.to_be_bytes(),
            selected_root_digest.as_bytes(),
            &selected_root_generation.to_be_bytes(),
            &authority_epoch.get().to_be_bytes(),
        ],
    );
    if derived != decision_digest {
        return Err(ProtectedRecordCodecError::DigestMismatch);
    }
    Ok(AdmissionDecisionV1 {
        operation,
        reservation,
        publisher_instance,
        canonical_request,
        canonical_plan,
        runtime_binding_digest,
        source_release_digest,
        root_registry_digest,
        root_registry_generation,
        selected_root_digest,
        selected_root_generation,
        authority_epoch,
        state,
        decision_digest,
    })
}

pub(super) fn decode_account(bytes: &[u8]) -> Result<CapacityAccountV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let reservation = PublicationReservationId::from_bytes(cursor.array()?);
    let authority_epoch = PublicationAuthorityEpoch::new(cursor.u64()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let resource = ResourceId::from_bytes(cursor.array()?);
    let project = ProjectId::from_bytes(cursor.array()?);
    let domain = cursor.domain()?;
    let state = match cursor.u8()? {
        1 => ReservationStateV1::Reserved,
        2 => ReservationStateV1::Uncertain,
        3 => ReservationStateV1::Resident,
        4 => ReservationStateV1::Released,
        5 => ReservationStateV1::Evicted,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    };
    let reserved_bytes = cursor.u64()?;
    let resident_bytes = cursor.u64()?;
    let generation = cursor.u64()?;
    let predecessor = cursor.digest()?;
    let digest = cursor.digest()?;
    cursor.finish()?;
    Ok(CapacityAccountV1 {
        reservation,
        authority_epoch,
        resource,
        project,
        domain,
        reserved_bytes,
        resident_bytes,
        state,
        generation,
        predecessor_digest: (predecessor.as_bytes() != &[0; 32]).then_some(predecessor),
        digest,
    })
}

pub(super) fn decode_artifact(
    bytes: &[u8],
) -> Result<ArtifactCommitmentV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let operation = OperationId::from_bytes(cursor.array()?);
    let publisher_instance = PublisherInstanceId::from_bytes(cursor.array()?);
    let decision_digest = cursor.digest()?;
    let root_generation = cursor.u64()?;
    let content = cursor.object_until_nul()?;
    let verity_sha256 = cursor.array()?;
    let private_name_digest = cursor.digest()?;
    let final_name_digest = cursor.digest()?;
    let bytes = cursor.u64()?;
    let allocated_bytes = cursor.u64()?;
    let artifact_digest = cursor.digest()?;
    cursor.finish()?;
    let derived = digest_parts(
        ARTIFACT_DOMAIN,
        &[
            operation.as_bytes(),
            publisher_instance.as_bytes(),
            decision_digest.as_bytes(),
            &root_generation.to_be_bytes(),
            content.media_type().as_str().as_bytes(),
            content.digest().as_bytes(),
            &content.encoded_size().to_be_bytes(),
            &verity_sha256,
            private_name_digest.as_bytes(),
            final_name_digest.as_bytes(),
            &bytes.to_be_bytes(),
            &allocated_bytes.to_be_bytes(),
        ],
    );
    if derived != artifact_digest {
        return Err(ProtectedRecordCodecError::DigestMismatch);
    }
    Ok(ArtifactCommitmentV1 {
        operation,
        publisher_instance,
        decision_digest,
        root_generation,
        content,
        verity_sha256,
        private_name_digest,
        final_name_digest,
        bytes,
        allocated_bytes,
        artifact_digest,
    })
}

pub(super) fn decode_permit(bytes: &[u8]) -> Result<CompletionPermitV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let permit = PublicationPermitId::from_bytes(cursor.array()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let operation = OperationId::from_bytes(cursor.array()?);
    let reservation = PublicationReservationId::from_bytes(cursor.array()?);
    let artifact_digest = cursor.digest()?;
    let decision_digest = cursor.digest()?;
    let publisher_instance = PublisherInstanceId::from_bytes(cursor.array()?);
    let root_generation = cursor.u64()?;
    let authority_epoch = PublicationAuthorityEpoch::new(cursor.u64()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let state = match cursor.u8()? {
        1 => CompletionPermitStateV1::Outstanding,
        2 => CompletionPermitStateV1::RevocationPending,
        3 => CompletionPermitStateV1::Spent,
        4 => CompletionPermitStateV1::RetiredWithoutEffect,
        5 => CompletionPermitStateV1::Uncertain,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    };
    let permit_digest = cursor.digest()?;
    cursor.finish()?;
    let derived = digest_parts(
        PERMIT_DOMAIN,
        &[
            operation.as_bytes(),
            reservation.as_bytes(),
            artifact_digest.as_bytes(),
            decision_digest.as_bytes(),
            publisher_instance.as_bytes(),
            &root_generation.to_be_bytes(),
            &authority_epoch.get().to_be_bytes(),
        ],
    );
    if derived != permit_digest || &permit_digest.as_bytes()[..16] != permit.as_bytes() {
        return Err(ProtectedRecordCodecError::DigestMismatch);
    }
    Ok(CompletionPermitV1 {
        permit,
        operation,
        reservation,
        artifact_digest,
        decision_digest,
        publisher_instance,
        root_generation,
        authority_epoch,
        state,
        permit_digest,
    })
}

pub(super) fn decode_receipt(
    bytes: &[u8],
) -> Result<CompletionReceiptV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let permit = PublicationPermitId::from_bytes(cursor.array()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let operation = OperationId::from_bytes(cursor.array()?);
    let artifact_digest = cursor.digest()?;
    let catalog_generation = cursor.u64()?;
    let catalog_entry_digest = cursor.digest()?;
    let resident_bytes = cursor.u64()?;
    let catalog_entry =
        super::read_authority::decode_committed_read_entry_v1(&cursor.length_prefixed()?)
            .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let receipt_digest = cursor.digest()?;
    cursor.finish()?;
    let derived = digest_parts(
        RECEIPT_DOMAIN,
        &[
            permit.as_bytes(),
            operation.as_bytes(),
            artifact_digest.as_bytes(),
            &catalog_generation.to_be_bytes(),
            catalog_entry_digest.as_bytes(),
            &resident_bytes.to_be_bytes(),
        ],
    );
    if derived != receipt_digest
        || catalog_entry.digest() != catalog_entry_digest
        || catalog_entry.allocated() != resident_bytes
    {
        return Err(ProtectedRecordCodecError::DigestMismatch);
    }
    Ok(CompletionReceiptV1 {
        permit,
        operation,
        artifact_digest,
        catalog_generation,
        catalog_entry_digest,
        catalog_entry,
        resident_bytes,
        receipt_digest,
    })
}

pub(super) fn decode_checkpoint(
    bytes: &[u8],
) -> Result<AuthorityCheckpointV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let epoch = PublicationAuthorityEpoch::new(cursor.u64()?)
        .map_err(|_| ProtectedRecordCodecError::Malformed)?;
    let sequence = cursor.u64()?;
    let state_digest = cursor.digest()?;
    let outstanding_digest = cursor.digest()?;
    let outstanding_count = u32::from_be_bytes(cursor.array()?);
    let poisoned = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    };
    cursor.finish()?;
    Ok(AuthorityCheckpointV1 {
        epoch,
        sequence,
        state_digest,
        outstanding_digest,
        outstanding_count,
        poisoned,
    })
}

pub(super) fn decode_eviction(
    bytes: &[u8],
) -> Result<CatalogEvictionReceiptV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let operation = OperationId::from_bytes(cursor.array()?);
    let catalog_entry_digest = cursor.digest()?;
    let prior_catalog_generation = cursor.u64()?;
    let eviction_catalog_generation = cursor.u64()?;
    let released_bytes = cursor.u64()?;
    let eviction_digest = cursor.digest()?;
    cursor.finish()?;
    let derived = digest_parts(
        EVICTION_DOMAIN,
        &[
            operation.as_bytes(),
            catalog_entry_digest.as_bytes(),
            &prior_catalog_generation.to_be_bytes(),
            &eviction_catalog_generation.to_be_bytes(),
            &released_bytes.to_be_bytes(),
        ],
    );
    if derived != eviction_digest
        || prior_catalog_generation == 0
        || prior_catalog_generation.checked_add(1) != Some(eviction_catalog_generation)
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    Ok(CatalogEvictionReceiptV1 {
        operation,
        catalog_entry_digest,
        prior_catalog_generation,
        eviction_catalog_generation,
        released_bytes,
        eviction_digest,
    })
}

pub(super) fn decode_recovery_observation(
    bytes: &[u8],
) -> Result<RecoveryObservationReceiptV1, ProtectedRecordCodecError> {
    let mut cursor = Cursor::new(bytes);
    let operation = OperationId::from_bytes(cursor.array()?);
    let outcome = match cursor.u8()? {
        1 => RecoveryObservationKindCodeV1::NoEffect,
        2 => RecoveryObservationKindCodeV1::PrivateArtifact,
        3 => RecoveryObservationKindCodeV1::AbsentAfterFence,
        4 => RecoveryObservationKindCodeV1::FinalCatalogAbsent,
        5 => RecoveryObservationKindCodeV1::FinalCatalogRepaired,
        6 => RecoveryObservationKindCodeV1::Committed,
        7 => RecoveryObservationKindCodeV1::Contradiction,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    };
    let artifact = cursor.digest()?;
    let artifact_digest = (artifact.as_bytes() != &[0; 32]).then_some(artifact);
    let catalog_entry = cursor.digest()?;
    let catalog_entry_digest = (catalog_entry.as_bytes() != &[0; 32]).then_some(catalog_entry);
    let repair_prior_catalog_generation = cursor.u64()?;
    let repair = cursor.digest()?;
    let repair_authorization_digest = (repair.as_bytes() != &[0; 32]).then_some(repair);
    let physical_root_digest = cursor.digest()?;
    let physical_observation_digest = cursor.digest()?;
    let executor = PublisherInstanceId::from_bytes(cursor.array()?);
    let executor_instance = (executor.as_bytes() != &[0; 16]).then_some(executor);
    let fence = cursor.digest()?;
    let executor_fence_digest = (fence.as_bytes() != &[0; 32]).then_some(fence);
    let receipt_digest = cursor.digest()?;
    cursor.finish()?;
    let outcome_code = match outcome {
        RecoveryObservationKindCodeV1::NoEffect => 1,
        RecoveryObservationKindCodeV1::PrivateArtifact => 2,
        RecoveryObservationKindCodeV1::AbsentAfterFence => 3,
        RecoveryObservationKindCodeV1::FinalCatalogAbsent => 4,
        RecoveryObservationKindCodeV1::FinalCatalogRepaired => 5,
        RecoveryObservationKindCodeV1::Committed => 6,
        RecoveryObservationKindCodeV1::Contradiction => 7,
    };
    let derived = digest_parts(
        RECOVERY_DOMAIN,
        &[
            operation.as_bytes(),
            &[outcome_code],
            artifact.as_bytes(),
            catalog_entry.as_bytes(),
            &repair_prior_catalog_generation.to_be_bytes(),
            repair.as_bytes(),
            physical_root_digest.as_bytes(),
            physical_observation_digest.as_bytes(),
            executor.as_bytes(),
            fence.as_bytes(),
        ],
    );
    let fence_required = matches!(
        outcome,
        RecoveryObservationKindCodeV1::AbsentAfterFence
            | RecoveryObservationKindCodeV1::FinalCatalogAbsent
            | RecoveryObservationKindCodeV1::FinalCatalogRepaired
    );
    let artifact_shape_valid = match outcome {
        RecoveryObservationKindCodeV1::NoEffect => artifact_digest.is_none(),
        RecoveryObservationKindCodeV1::Contradiction => true,
        _ => artifact_digest.is_some(),
    };
    let catalog_required = matches!(
        outcome,
        RecoveryObservationKindCodeV1::FinalCatalogAbsent
            | RecoveryObservationKindCodeV1::FinalCatalogRepaired
            | RecoveryObservationKindCodeV1::Committed
    );
    let repair_generation_forbidden = !matches!(
        outcome,
        RecoveryObservationKindCodeV1::FinalCatalogAbsent
            | RecoveryObservationKindCodeV1::FinalCatalogRepaired
    ) && repair_prior_catalog_generation != 0;
    if receipt_digest != derived
        || physical_observation_digest.as_bytes() == &[0; 32]
        || physical_root_digest.as_bytes() == &[0; 32]
        || !artifact_shape_valid
        || catalog_required != catalog_entry_digest.is_some()
        || repair_generation_forbidden
        || (outcome == RecoveryObservationKindCodeV1::FinalCatalogRepaired)
            != repair_authorization_digest.is_some()
        || fence_required != executor_instance.is_some()
        || fence_required != executor_fence_digest.is_some()
    {
        return Err(ProtectedRecordCodecError::Malformed);
    }
    Ok(RecoveryObservationReceiptV1 {
        operation,
        outcome,
        artifact_digest,
        catalog_entry_digest,
        repair_prior_catalog_generation,
        repair_authorization_digest,
        physical_root_digest,
        physical_observation_digest,
        executor_instance,
        executor_fence_digest,
        receipt_digest,
    })
}

fn decision_state(code: u8) -> Result<AdmissionDecisionStateV1, ProtectedRecordCodecError> {
    Ok(match code {
        1 => AdmissionDecisionStateV1::Admitted,
        2 => AdmissionDecisionStateV1::ArtifactPrepared,
        3 => AdmissionDecisionStateV1::CompletionPermitted,
        4 => AdmissionDecisionStateV1::RevocationPending,
        5 => AdmissionDecisionStateV1::Completed,
        6 => AdmissionDecisionStateV1::Aborted,
        7 => AdmissionDecisionStateV1::Uncertain,
        8 => AdmissionDecisionStateV1::Poisoned,
        _ => return Err(ProtectedRecordCodecError::Malformed),
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ProtectedRecordCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ProtectedRecordCodecError::LimitExceeded)?;
        let part = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtectedRecordCodecError::Malformed)?;
        self.offset = end;
        Ok(part)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtectedRecordCodecError> {
        exact(self.take(N)?)
    }
    fn u8(&mut self) -> Result<u8, ProtectedRecordCodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, ProtectedRecordCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn i64(&mut self) -> Result<i64, ProtectedRecordCodecError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    fn digest(&mut self) -> Result<ObjectDigest, ProtectedRecordCodecError> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }
    fn domain(&mut self) -> Result<CacheDomain, ProtectedRecordCodecError> {
        let kind = match self.u8()? {
            1 => CacheDomainKind::Private,
            2 => CacheDomainKind::Project,
            3 => CacheDomainKind::TrustDomain,
            4 => CacheDomainKind::Public,
            _ => return Err(ProtectedRecordCodecError::Malformed),
        };
        Ok(CacheDomain::new(
            kind,
            CacheDomainId::from_bytes(self.array()?),
        ))
    }
    fn object_until_nul(&mut self) -> Result<ObjectDescriptor, ProtectedRecordCodecError> {
        let tail = &self.bytes[self.offset..];
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ProtectedRecordCodecError::Malformed)?;
        let media = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ProtectedRecordCodecError::Malformed)?;
        let media =
            MediaType::new(media.to_owned()).map_err(|_| ProtectedRecordCodecError::Malformed)?;
        if self.u8()? != 0 {
            return Err(ProtectedRecordCodecError::Malformed);
        }
        let digest = self.digest()?;
        let size = self.u64()?;
        Ok(ObjectDescriptor::new(media, digest, size))
    }
    fn length_prefixed(&mut self) -> Result<Vec<u8>, ProtectedRecordCodecError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| ProtectedRecordCodecError::LimitExceeded)?;
        let value = self.take(length)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| ProtectedRecordCodecError::Allocation)?;
        owned.extend_from_slice(value);
        Ok(owned)
    }
    fn finish(self) -> Result<(), ProtectedRecordCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtectedRecordCodecError::Malformed)
        }
    }
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ProtectedRecordCodecError> {
    bytes
        .try_into()
        .map_err(|_| ProtectedRecordCodecError::Malformed)
}
