//! Repair-specific authenticated input for the mutating workspace pin worker.
//!
//! The outer magic prevents a repair from entering the ordinary creation or
//! destroy semantic path. The embedded ordinary transport supplies the fixed
//! executable, creation catalog, and authority records, while the additional
//! authenticated repair intent and publication record prove why that creation
//! catalog may be used by a distinct repair effect.
//!
//! ```text
//! AOSZRPW1 | version:u16 | reserved:u16
//! pin-worker-request:(length:u32,AOSZPWR1-bytes)
//! repair-intent:(length:u32,authenticated-bytes)
//! publication-intent:(length:u32,authenticated-bytes)
//! ```

use aos_sandbox_broker::BrokerEffectIntentV2;
use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageAuthorityV1;
use crate::pin_worker::{
    MAXIMUM_PIN_WORKER_REQUEST_BYTES, WorkspacePinWorkerAuthorityV1, WorkspacePinWorkerRequestV1,
    decode_request as decode_pin_worker_request, encode_request as encode_pin_worker_request,
};
use crate::workspace_pin::{
    WorkspacePinActionV1, WorkspacePinAttemptPhaseV1, WorkspacePinAttemptV1,
};
use crate::{
    CatalogPlanV1, ResolvedCatalogCommitmentV1, StorageAdmissionError, StorageStateKey,
    ZfsHelperContract, ZfsWorkerError,
};

const MAGIC: &[u8; 8] = b"AOSZRPW1";
const VERSION: u16 = 1;
const MAXIMUM_REPAIR_INTENT_BYTES: usize = 256 * 1024;
const MAXIMUM_PUBLICATION_INTENT_BYTES: usize = 128 * 1024;

/// Carries all protected records required by one repair worker invocation.
pub(crate) struct WorkspacePinRepairWorkerRequestV1 {
    pin_request: WorkspacePinWorkerRequestV1,
    repair_intent_record: Vec<u8>,
    publication_intent_record: Vec<u8>,
}

impl WorkspacePinRepairWorkerRequestV1 {
    pub(crate) fn new(
        executable: std::path::PathBuf,
        catalog: ResolvedCatalogCommitmentV1,
        authority: WorkspacePinWorkerAuthorityV1,
        repair_intent_record: Vec<u8>,
        publication_intent_record: Vec<u8>,
    ) -> Result<Self, ZfsWorkerError> {
        if repair_intent_record.is_empty()
            || repair_intent_record.len() > MAXIMUM_REPAIR_INTENT_BYTES
            || publication_intent_record.is_empty()
            || publication_intent_record.len() > MAXIMUM_PUBLICATION_INTENT_BYTES
        {
            return Err(ZfsWorkerError::Protocol(
                "repair worker authority records are invalid",
            ));
        }
        Ok(Self {
            pin_request: WorkspacePinWorkerRequestV1 {
                executable,
                catalog,
                authority,
            },
            repair_intent_record,
            publication_intent_record,
        })
    }
}

/// Carries one independently authenticated, non-clone repair worker request.
pub(crate) struct AuthenticatedWorkspacePinRepairWorkerRequestV1 {
    request: WorkspacePinRepairWorkerRequestV1,
    attempt: WorkspacePinAttemptV1,
    effect: BrokerEffectIntentV2,
}

impl AuthenticatedWorkspacePinRepairWorkerRequestV1 {
    pub(crate) const fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.request.pin_request.catalog
    }

    pub(crate) const fn effect_deadline_boottime_nanoseconds(&self) -> u64 {
        self.effect.effect_deadline_boottime_nanoseconds()
    }
}

pub(crate) fn is_repair_worker_request(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub(crate) fn authenticate_request(
    authority: &StorageAuthorityV1,
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinRepairWorkerRequestV1,
) -> Result<AuthenticatedWorkspacePinRepairWorkerRequestV1, ZfsWorkerError> {
    if request.pin_request.executable != configured_contract.executable() {
        return Err(ZfsWorkerError::Authority);
    }
    let worker_authority = &request.pin_request.authority;
    let intent = state_key
        .open_workspace_pin_repair_intent(&request.repair_intent_record)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let attempt = state_key
        .open_workspace_pin_attempt(worker_authority.attempt_record())
        .map_err(|_| ZfsWorkerError::Authority)?;
    let publication = state_key
        .open_workspace_publication_intent(
            attempt.creation_operation_id(),
            &request.publication_intent_record,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let (operation_fence, effect) = authority
        .authenticate_workspace_pin_repair_intent(
            &intent,
            worker_authority.operation_fence(),
            worker_authority.effect(),
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let sandbox_id = *operation_fence.assignment().sandbox().as_bytes();
    let current_fence = authority
        .open_fence(&sandbox_id, worker_authority.current_fence())
        .map_err(|_| ZfsWorkerError::Authority)?;
    if current_fence != operation_fence {
        return Err(ZfsWorkerError::Authority);
    }
    authority
        .check_current_fence(&current_fence)
        .map_err(|_| ZfsWorkerError::Authority)?;

    let destination_name = match request.pin_request.catalog.plan() {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination.name(),
        _ => return Err(ZfsWorkerError::Authority),
    };
    let creation_result_follows_request = request.pin_request.catalog.generation().checked_add(1)
        == Some(attempt.creation_result_catalog().generation())
        && request.pin_request.catalog.binding().digest()
            != attempt.creation_result_catalog().digest();
    if worker_authority.parent_request_id() != intent.request_id()
        || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
        || attempt.action() != WorkspacePinActionV1::Ensure
        || attempt.attempt_ordinal() < 2
        || attempt.effect_operation_id() == attempt.creation_operation_id()
        || attempt.expected_pin().is_some()
        || attempt.satisfied_pin().is_some()
        || intent.repair_attempt_id() != attempt.attempt_id()
        || intent.repair_attempt_ordinal() != attempt.attempt_ordinal()
        || intent.repair_operation_id() != attempt.effect_operation_id()
        || intent.creation_operation_id() != attempt.creation_operation_id()
        || intent.creation_result_catalog() != attempt.creation_result_catalog()
        || intent.creation_result_digest() != attempt.creation_result_digest()
        || intent.workspace_handle() != attempt.workspace_handle()
        || intent.repair_assignment_digest() != attempt.effect_assignment_digest()
        || intent.operation_fence_digest() != attempt.operation_fence_digest()
        || intent.publication_intent_record_digest()
            != ObjectDigest::from_bytes(Sha256::digest(&request.publication_intent_record).into())
        || publication.operation_id() != attempt.creation_operation_id()
        || publication.request_catalog() != request.pin_request.catalog.binding()
        || publication.assignment_digest() != attempt.workspace_assignment_digest()
        || publication.identity_range_start() != attempt.identity_range_start()
        || publication.identity_range_size() != attempt.identity_range_size()
        || !creation_result_follows_request
        || destination_name != attempt.dataset_name()
    {
        return Err(ZfsWorkerError::Authority);
    }
    authority
        .verify_pin_attempt_receipt(&attempt, &effect, attempt.effect_operation_id())
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok(AuthenticatedWorkspacePinRepairWorkerRequestV1 {
        request,
        attempt,
        effect,
    })
}

pub(crate) fn check_before_effect<F>(
    authority: &StorageAuthorityV1,
    request: &AuthenticatedWorkspacePinRepairWorkerRequestV1,
    trusted_clock: &mut F,
) -> Result<(), ZfsWorkerError>
where
    F: FnMut() -> Result<aos_sandbox_core::RawPairedClockSample, StorageAdmissionError>,
{
    authority
        .check_before_effect(&request.effect, trusted_clock)
        .map_err(|_| ZfsWorkerError::Authority)
}

pub(crate) fn encode_request(
    request: &WorkspacePinRepairWorkerRequestV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    let inner = encode_pin_worker_request(
        &ZfsHelperContract::new(request.pin_request.executable.clone())
            .map_err(|_| ZfsWorkerError::Authority)?,
        &request.pin_request.catalog,
        &request.pin_request.authority,
    )?;
    let mut bytes = Vec::with_capacity(
        24 + inner.len()
            + request.repair_intent_record.len()
            + request.publication_intent_record.len(),
    );
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    append_record(&mut bytes, &inner)?;
    append_record(&mut bytes, &request.repair_intent_record)?;
    append_record(&mut bytes, &request.publication_intent_record)?;
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair worker request exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_request(
    bytes: &[u8],
) -> Result<WorkspacePinRepairWorkerRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair worker request exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(MAGIC.len())? != MAGIC || decoder.u16()? != VERSION || decoder.u16()? != 0 {
        return Err(ZfsWorkerError::Protocol(
            "repair worker request header is invalid",
        ));
    }
    let pin_request = decode_pin_worker_request(decoder.record(MAXIMUM_PIN_WORKER_REQUEST_BYTES)?)?;
    let repair_intent_record = decoder.record(MAXIMUM_REPAIR_INTENT_BYTES)?.to_vec();
    let publication_intent_record = decoder.record(MAXIMUM_PUBLICATION_INTENT_BYTES)?.to_vec();
    decoder.finish()?;
    let request = WorkspacePinRepairWorkerRequestV1::new(
        pin_request.executable,
        pin_request.catalog,
        pin_request.authority,
        repair_intent_record,
        publication_intent_record,
    )?;
    if encode_request(&request)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "repair worker request is not canonical",
        ));
    }
    Ok(request)
}

fn append_record(output: &mut Vec<u8>, record: &[u8]) -> Result<(), ZfsWorkerError> {
    let length = u32::try_from(record.len())
        .map_err(|_| ZfsWorkerError::Protocol("repair worker record is too long"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(record);
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ZfsWorkerError::Protocol(
                "repair worker request length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol(
                "repair worker request is truncated",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("repair worker field is invalid"))
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn record(&mut self, maximum: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ZfsWorkerError::Protocol("repair worker length does not fit usize"))?;
        if length == 0 || length > maximum {
            return Err(ZfsWorkerError::Protocol(
                "repair worker record length is invalid",
            ));
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol(
                "repair worker request has trailing bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1, ReservationPolicy,
        ResolvedDataset, WorkspaceSpacePolicyV1,
    };

    fn catalog() -> ResolvedCatalogCommitmentV1 {
        let domains = crate::StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains)
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/work", domains).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        ResolvedCatalogCommitmentV1::new(
            7,
            domains,
            CatalogPlanV1::CreateWorkspace {
                destination,
                space,
                ancestor,
            },
        )
        .unwrap()
    }

    fn request() -> WorkspacePinRepairWorkerRequestV1 {
        WorkspacePinRepairWorkerRequestV1::new(
            "/nix/store/hash-zfs/sbin/zfs".into(),
            catalog(),
            WorkspacePinWorkerAuthorityV1::new(
                [1; 16],
                vec![2; 128],
                vec![3; 129],
                vec![4; 130],
                vec![5; 131],
            )
            .unwrap(),
            vec![6; 132],
            vec![7; 133],
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip_preserves_distinct_repair_authority_records() {
        let encoded = encode_request(&request()).unwrap();
        let decoded = decode_request(&encoded).unwrap();

        assert_eq!(
            decoded.pin_request.executable,
            request().pin_request.executable
        );
        assert_eq!(decoded.pin_request.catalog, request().pin_request.catalog);
        assert_eq!(decoded.pin_request.authority.attempt_record(), vec![2; 128]);
        assert_eq!(decoded.pin_request.authority.current_fence(), vec![3; 129]);
        assert_eq!(decoded.pin_request.authority.effect(), vec![4; 130]);
        assert_eq!(
            decoded.pin_request.authority.operation_fence(),
            vec![5; 131]
        );
        assert_eq!(decoded.repair_intent_record, vec![6; 132]);
        assert_eq!(decoded.publication_intent_record, vec![7; 133]);
    }

    #[test]
    fn request_rejects_header_length_inner_and_trailing_substitution() {
        let encoded = encode_request(&request()).unwrap();

        let mut wrong_reserved = encoded.clone();
        wrong_reserved[11] = 1;
        assert!(decode_request(&wrong_reserved).is_err());

        let mut zero_inner = encoded.clone();
        zero_inner[12..16].copy_from_slice(&0_u32.to_be_bytes());
        assert!(decode_request(&zero_inner).is_err());

        let mut oversized_inner = encoded.clone();
        oversized_inner[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&oversized_inner).is_err());

        let mut corrupted_inner = encoded.clone();
        corrupted_inner[16] ^= 1;
        assert!(decode_request(&corrupted_inner).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }
}
