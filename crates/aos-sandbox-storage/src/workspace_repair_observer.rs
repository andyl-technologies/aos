//! Dedicated observation protocol for retained workspace-pin repair attempts.
//!
//! The envelope carries no effect grant and cannot be converted into a pin
//! worker request. It binds a kernel-generated challenge to the authenticated
//! repair intent, exact latest attempt, original creation catalog, publication
//! intent, and freshly retained host mount scope. The observer returns that
//! probe digest beside ordinary typed ZFS and mount evidence.
//!
//! Version one uses canonical big-endian lengths and requires every reserved
//! field to be zero:
//!
//! ```text
//! AOSZRPO1 | version:u16 | reserved:u16 | challenge:16
//! executable:(length:u16,bytes)
//! creation-catalog:(length:u32,canonical-bytes)
//! repair-intent:(length:u32,authenticated-bytes)
//! repair-attempt:(length:u32,authenticated-bytes)
//! publication-intent:(length:u32,authenticated-bytes)
//!
//! AOSZRPR1 | version:u16 | reserved:u16 | probe-digest:32
//! observation:(length:u32,AOSZPRES-bytes)
//! ```
//!
//! The probe digest covers the random challenge, immutable historical record
//! identities, historical attempt scope, and independently observed current
//! host scope. It is correlation evidence only; the observer authenticates the
//! records and descriptor-backed scope before constructing it.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::pin_worker::{
    MAXIMUM_PIN_WORKER_REQUEST_BYTES, MAXIMUM_PIN_WORKER_RESULT_BYTES, WorkspacePinWorkerResultV1,
    decode_result as decode_pin_worker_result, encode_result as encode_pin_worker_result,
};
use crate::workspace_pin::{
    WorkspacePinActionV1, WorkspacePinAttemptPhaseV1, WorkspacePinAttemptV1,
    WorkspacePinHostScopeV1,
};
use crate::workspace_repair::{StorageWorkspacePinRepairIntentV1, WorkspacePinRepairProbeV1};
use crate::{
    CatalogPlanV1, ResolvedCatalogCommitmentV1, StorageStateKey, ZfsHelperContract, ZfsWorkerError,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSZRPO1";
const RESULT_MAGIC: &[u8; 8] = b"AOSZRPR1";
const VERSION: u16 = 1;
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024;
const MAXIMUM_STATE_RECORD_BYTES: usize = 128 * 1024;
const MAXIMUM_REPAIR_INTENT_BYTES: usize = 256 * 1024;

pub(crate) fn is_repair_request(bytes: &[u8]) -> bool {
    bytes.starts_with(REQUEST_MAGIC)
}

/// Carries opaque authenticated history into the dedicated repair observer.
pub(crate) struct WorkspacePinRepairObserverRequestV1 {
    executable: PathBuf,
    generated_challenge: [u8; 16],
    catalog: ResolvedCatalogCommitmentV1,
    repair_intent_record: Vec<u8>,
    repair_attempt_record: Vec<u8>,
    publication_intent_record: Vec<u8>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum WorkspacePinRepairObserverRecordV1 {
    RepairIntent,
    RepairAttempt,
    PublicationIntent,
}

impl WorkspacePinRepairObserverRequestV1 {
    pub(crate) fn new(
        executable: PathBuf,
        generated_challenge: [u8; 16],
        catalog: ResolvedCatalogCommitmentV1,
        repair_intent_record: Vec<u8>,
        repair_attempt_record: Vec<u8>,
        publication_intent_record: Vec<u8>,
    ) -> Result<Self, ZfsWorkerError> {
        let request = Self {
            executable,
            generated_challenge,
            catalog,
            repair_intent_record,
            repair_attempt_record,
            publication_intent_record,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ZfsWorkerError> {
        ZfsHelperContract::new(self.executable.clone())
            .map_err(|_| ZfsWorkerError::Protocol("repair observer executable is invalid"))?;
        if self.generated_challenge == [0; 16]
            || !bounded(self.catalog.canonical_bytes(), MAXIMUM_CATALOG_BYTES)
            || !bounded(&self.repair_intent_record, MAXIMUM_REPAIR_INTENT_BYTES)
            || !bounded(&self.repair_attempt_record, MAXIMUM_STATE_RECORD_BYTES)
            || !bounded(&self.publication_intent_record, MAXIMUM_STATE_RECORD_BYTES)
        {
            return Err(ZfsWorkerError::Protocol(
                "repair observer authority envelope is invalid",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_record_for_test(&mut self, record: WorkspacePinRepairObserverRecordV1) {
        let bytes = match record {
            WorkspacePinRepairObserverRecordV1::RepairIntent => &mut self.repair_intent_record,
            WorkspacePinRepairObserverRecordV1::RepairAttempt => &mut self.repair_attempt_record,
            WorkspacePinRepairObserverRecordV1::PublicationIntent => {
                &mut self.publication_intent_record
            }
        };
        bytes[0] ^= 1;
    }

    #[cfg(test)]
    pub(crate) fn replace_catalog_for_test(&mut self, catalog: ResolvedCatalogCommitmentV1) {
        self.catalog = catalog;
    }
}

/// Carries a fully authenticated repair observation without any effect object.
pub(crate) struct AuthenticatedWorkspacePinRepairObserverRequestV1 {
    request: WorkspacePinRepairObserverRequestV1,
    attempt: WorkspacePinAttemptV1,
    probe: WorkspacePinRepairProbeV1,
}

impl AuthenticatedWorkspacePinRepairObserverRequestV1 {
    pub(crate) const fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn probe(&self) -> &WorkspacePinRepairProbeV1 {
        &self.probe
    }

    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.request.catalog
    }
}

/// Binds one typed observer result to the broker's fresh probe challenge.
pub(crate) struct WorkspacePinRepairObserverResultV1 {
    probe_digest: ObjectDigest,
    observation: WorkspacePinWorkerResultV1,
}

impl WorkspacePinRepairObserverResultV1 {
    pub(crate) const fn new(
        probe_digest: ObjectDigest,
        observation: WorkspacePinWorkerResultV1,
    ) -> Self {
        Self {
            probe_digest,
            observation,
        }
    }

    pub(crate) const fn probe_digest(&self) -> ObjectDigest {
        self.probe_digest
    }

    pub(crate) const fn observation(&self) -> &WorkspacePinWorkerResultV1 {
        &self.observation
    }

    pub(crate) fn into_observation(self) -> WorkspacePinWorkerResultV1 {
        self.observation
    }
}

pub(crate) fn authenticate_request(
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinRepairObserverRequestV1,
    current_host_scope: WorkspacePinHostScopeV1,
) -> Result<AuthenticatedWorkspacePinRepairObserverRequestV1, ZfsWorkerError> {
    if request.executable != configured_contract.executable() {
        return Err(ZfsWorkerError::Authority);
    }
    let intent = state_key
        .open_workspace_pin_repair_intent(&request.repair_intent_record)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let attempt = state_key
        .open_workspace_pin_attempt(&request.repair_attempt_record)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let publication = state_key
        .open_workspace_publication_intent(
            intent.creation_operation_id(),
            &request.publication_intent_record,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let repair_intent_record_digest = digest_bytes(&request.repair_intent_record);
    let repair_attempt_record_digest = digest_bytes(&request.repair_attempt_record);
    let publication_intent_record_digest = digest_bytes(&request.publication_intent_record);

    let destination_name = match request.catalog.plan() {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination.name(),
        _ => return Err(ZfsWorkerError::Authority),
    };
    let creation_result_follows_request = request.catalog.generation().checked_add(1)
        == Some(intent.creation_result_catalog().generation())
        && request.catalog.binding().digest() != intent.creation_result_catalog().digest();
    let attempt_scope = WorkspacePinHostScopeV1::new(
        attempt.host_boot_id(),
        attempt.host_mount_namespace_device(),
        attempt.host_mount_namespace_inode(),
    )
    .map_err(|_| ZfsWorkerError::Authority)?;
    if intent.repair_attempt_id() != attempt.attempt_id()
        || intent.repair_attempt_ordinal() != attempt.attempt_ordinal()
        || intent.repair_operation_id() != attempt.effect_operation_id()
        || intent.creation_operation_id() != attempt.creation_operation_id()
        || intent.creation_result_catalog() != attempt.creation_result_catalog()
        || intent.creation_result_digest() != attempt.creation_result_digest()
        || intent.workspace_handle() != attempt.workspace_handle()
        || intent.repair_assignment_digest() != attempt.effect_assignment_digest()
        || intent.operation_fence_digest() != attempt.operation_fence_digest()
        || attempt.action() != WorkspacePinActionV1::Ensure
        || attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
        || attempt.expected_pin().is_some()
        || !creation_result_follows_request
        || destination_name != attempt.dataset_name()
        || publication.operation_id() != intent.creation_operation_id()
        || publication.request_catalog() != request.catalog.binding()
        || publication.assignment_digest() != attempt.workspace_assignment_digest()
        || publication.identity_range_start() != attempt.identity_range_start()
        || publication.identity_range_size() != attempt.identity_range_size()
        || intent.publication_intent_record_digest() != publication_intent_record_digest
    {
        return Err(ZfsWorkerError::Authority);
    }

    let probe = bind_probe(
        &intent,
        &attempt,
        request.generated_challenge,
        repair_intent_record_digest,
        publication_intent_record_digest,
        repair_attempt_record_digest,
        attempt_scope,
        current_host_scope,
    )?;

    Ok(AuthenticatedWorkspacePinRepairObserverRequestV1 {
        request,
        attempt,
        probe,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bind_probe(
    intent: &StorageWorkspacePinRepairIntentV1,
    attempt: &WorkspacePinAttemptV1,
    generated_challenge: [u8; 16],
    repair_intent_record_digest: ObjectDigest,
    publication_intent_record_digest: ObjectDigest,
    repair_attempt_record_digest: ObjectDigest,
    historical_attempt_host_scope: WorkspacePinHostScopeV1,
    current_host_scope: WorkspacePinHostScopeV1,
) -> Result<WorkspacePinRepairProbeV1, ZfsWorkerError> {
    if historical_attempt_host_scope.kernel_boot_id() != attempt.host_boot_id()
        || historical_attempt_host_scope.mount_namespace_device()
            != attempt.host_mount_namespace_device()
        || historical_attempt_host_scope.mount_namespace_inode()
            != attempt.host_mount_namespace_inode()
    {
        return Err(ZfsWorkerError::Authority);
    }
    WorkspacePinRepairProbeV1::new(
        generated_challenge,
        intent.repair_operation_id(),
        repair_intent_record_digest,
        intent.request_digest(),
        intent.semantic_commitment(),
        intent.creation_operation_id(),
        intent.creation_result_catalog(),
        intent.creation_result_digest(),
        publication_intent_record_digest,
        intent.workspace_handle(),
        attempt.attempt_id(),
        attempt.attempt_ordinal(),
        attempt.phase(),
        repair_attempt_record_digest,
        historical_attempt_host_scope,
        current_host_scope,
        attempt.dataset_name().to_owned(),
        attempt.dataset_guid(),
        attempt.identity_range_start(),
        attempt.identity_range_size(),
    )
    .map_err(|_| ZfsWorkerError::Authority)
}

pub(crate) fn encode_request(
    request: &WorkspacePinRepairObserverRequestV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    request.validate()?;
    let executable = request.executable.as_os_str().as_bytes();
    let executable_length = u16::try_from(executable.len())
        .map_err(|_| ZfsWorkerError::Protocol("repair observer executable is too long"))?;
    let catalog = request.catalog.canonical_bytes();
    let mut bytes = Vec::with_capacity(
        64 + executable.len()
            + catalog.len()
            + request.repair_intent_record.len()
            + request.repair_attempt_record.len()
            + request.publication_intent_record.len(),
    );
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&request.generated_challenge);
    bytes.extend_from_slice(&executable_length.to_be_bytes());
    bytes.extend_from_slice(executable);
    append_record(&mut bytes, catalog)?;
    append_record(&mut bytes, &request.repair_intent_record)?;
    append_record(&mut bytes, &request.repair_attempt_record)?;
    append_record(&mut bytes, &request.publication_intent_record)?;
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair observer request exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_request(
    bytes: &[u8],
) -> Result<WorkspacePinRepairObserverRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair observer request exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(REQUEST_MAGIC.len())? != REQUEST_MAGIC
        || decoder.u16()? != VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "repair observer request header is invalid",
        ));
    }
    let generated_challenge = decoder.array()?;
    let executable_length = usize::from(decoder.u16()?);
    let executable = PathBuf::from(OsString::from_vec(
        decoder.take(executable_length)?.to_vec(),
    ));
    let catalog =
        ResolvedCatalogCommitmentV1::from_canonical_bytes(decoder.record(MAXIMUM_CATALOG_BYTES)?)
            .map_err(|_| ZfsWorkerError::Protocol("repair observer catalog is invalid"))?;
    let repair_intent_record = decoder.record(MAXIMUM_REPAIR_INTENT_BYTES)?.to_vec();
    let repair_attempt_record = decoder.record(MAXIMUM_STATE_RECORD_BYTES)?.to_vec();
    let publication_intent_record = decoder.record(MAXIMUM_STATE_RECORD_BYTES)?.to_vec();
    decoder.finish()?;
    let request = WorkspacePinRepairObserverRequestV1::new(
        executable,
        generated_challenge,
        catalog,
        repair_intent_record,
        repair_attempt_record,
        publication_intent_record,
    )?;
    if encode_request(&request)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "repair observer request is not canonical",
        ));
    }
    Ok(request)
}

pub(crate) fn encode_result(
    result: &WorkspacePinRepairObserverResultV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    if result.probe_digest.as_bytes() == &[0; 32] {
        return Err(ZfsWorkerError::Protocol(
            "repair observer result probe is invalid",
        ));
    }
    let observation = encode_pin_worker_result(&result.observation)?;
    let mut bytes = Vec::with_capacity(48 + observation.len());
    bytes.extend_from_slice(RESULT_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(result.probe_digest.as_bytes());
    append_record(&mut bytes, &observation)?;
    if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair observer result exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_result(
    bytes: &[u8],
) -> Result<WorkspacePinRepairObserverResultV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair observer result exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(RESULT_MAGIC.len())? != RESULT_MAGIC
        || decoder.u16()? != VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "repair observer result header is invalid",
        ));
    }
    let probe_digest = ObjectDigest::from_bytes(decoder.array()?);
    let observation = decode_pin_worker_result(decoder.record(MAXIMUM_PIN_WORKER_RESULT_BYTES)?)?;
    decoder.finish()?;
    let result = WorkspacePinRepairObserverResultV1::new(probe_digest, observation);
    if encode_result(&result)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "repair observer result is not canonical",
        ));
    }
    Ok(result)
}

pub(crate) fn random_challenge() -> Result<[u8; 16], ZfsWorkerError> {
    let mut challenge = [0_u8; 16];
    let mut filled = 0;
    while filled < challenge.len() {
        let received = rustix::rand::getrandom(
            &mut challenge[filled..],
            rustix::rand::GetRandomFlags::empty(),
        )?;
        if received == 0 {
            return Err(ZfsWorkerError::Protocol(
                "kernel random source returned no repair challenge bytes",
            ));
        }
        filled += received;
    }
    if challenge == [0; 16] {
        return Err(ZfsWorkerError::Protocol(
            "kernel random source returned the reserved repair challenge",
        ));
    }
    Ok(challenge)
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn bounded(bytes: &[u8], maximum: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= maximum
}

fn append_record(output: &mut Vec<u8>, record: &[u8]) -> Result<(), ZfsWorkerError> {
    let length = u32::try_from(record.len())
        .map_err(|_| ZfsWorkerError::Protocol("repair observer record is too long"))?;
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
                "repair observer request length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol(
                "repair observer request is truncated",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("repair observer field is invalid"))
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn record(&mut self, maximum: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ZfsWorkerError::Protocol("repair observer length does not fit usize"))?;
        let record = self.take(length)?;
        if !bounded(record, maximum) {
            return Err(ZfsWorkerError::Protocol(
                "repair observer record length is invalid",
            ));
        }
        Ok(record)
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol(
                "repair observer request has trailing bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::workspace_pin::{WorkspaceDatasetObservationV1, WorkspacePinObservationV1};
    use crate::{
        ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1, ReservationPolicy,
        ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn fixture_catalog() -> ResolvedCatalogCommitmentV1 {
        let domains = StorageDomainsV1::new(
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

    fn request() -> WorkspacePinRepairObserverRequestV1 {
        WorkspacePinRepairObserverRequestV1::new(
            "/nix/store/hash-zfs/sbin/zfs".into(),
            [1; 16],
            fixture_catalog(),
            vec![2; 128],
            vec![3; 129],
            vec![4; 130],
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip_preserves_every_opaque_record_and_catalog() {
        let original = request();
        let encoded = encode_request(&original).unwrap();
        let decoded = decode_request(&encoded).unwrap();

        assert_eq!(decoded.executable, original.executable);
        assert_eq!(decoded.generated_challenge, original.generated_challenge);
        assert_eq!(decoded.catalog, original.catalog);
        assert_eq!(decoded.repair_intent_record, original.repair_intent_record);
        assert_eq!(
            decoded.repair_attempt_record,
            original.repair_attempt_record
        );
        assert_eq!(
            decoded.publication_intent_record,
            original.publication_intent_record
        );
        assert_eq!(encode_request(&decoded).unwrap(), encoded);
    }

    #[test]
    fn request_rejects_header_length_and_trailing_substitution() {
        let original = request();
        let encoded = encode_request(&original).unwrap();

        let mut wrong_reserved = encoded.clone();
        wrong_reserved[11] = 1;
        assert!(decode_request(&wrong_reserved).is_err());

        let executable_length = original.executable.as_os_str().as_bytes().len();
        let catalog_length_offset = 30 + executable_length;
        let mut zero_catalog = encoded.clone();
        zero_catalog[catalog_length_offset..catalog_length_offset + 4].fill(0);
        assert!(decode_request(&zero_catalog).is_err());

        let mut overlong_catalog = encoded.clone();
        overlong_catalog[catalog_length_offset..catalog_length_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&overlong_catalog).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn result_round_trip_binds_probe_attempt_and_typed_observation() {
        let result = WorkspacePinRepairObserverResultV1::new(
            ObjectDigest::from_bytes([5; 32]),
            WorkspacePinWorkerResultV1::new(
                [6; 16],
                WorkspaceDatasetObservationV1::Exact {
                    name: "tank/aos/project/work".to_owned(),
                    guid: 7,
                },
                WorkspacePinObservationV1::Absent,
                ObjectDigest::from_bytes([8; 32]),
            ),
        );
        let encoded = encode_result(&result).unwrap();
        let decoded = decode_result(&encoded).unwrap();

        assert_eq!(decoded.probe_digest(), ObjectDigest::from_bytes([5; 32]));
        assert_eq!(decoded.observation().attempt_id(), [6; 16]);
        assert_eq!(
            decoded.observation().dataset(),
            &WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 7,
            }
        );
        assert_eq!(
            decoded.observation().pin(),
            &WorkspacePinObservationV1::Absent
        );
        assert_eq!(
            decoded.observation().observation_digest(),
            ObjectDigest::from_bytes([8; 32])
        );
        assert_eq!(encode_result(&decoded).unwrap(), encoded);

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(decode_result(&wrong_magic).is_err());

        let mut zero_observation = encoded;
        zero_observation[44..48].fill(0);
        assert!(decode_result(&zero_observation).is_err());
    }
}
