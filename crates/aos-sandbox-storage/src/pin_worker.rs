//! Authenticated descriptor-carrying workspace root-pin worker protocol.
//!
//! The broker sends one bounded envelope containing an exact resolved ZFS
//! catalog and four opaque protected records. The fixed worker independently
//! opens its root-owned Storage authority configuration, authenticates those
//! records, and reconstructs the typed root-pin attempt before using either
//! inherited descriptor. Raw mount paths, ZFS argv, descriptor numbers, and
//! caller-asserted observation results never cross this wire.
//!
//! The version-one request is:
//!
//! ```text
//! AOSZPIN1 | version:u16 | reserved:u16 | parent-request-id:16
//! executable:(length:u16,bytes)
//! catalog:(length:u32,canonical-bytes)
//! attempt-record:(length:u32,authenticated-bytes)
//! current-fence:(length:u32,authenticated-bytes)
//! effect:(length:u32,authenticated-bytes)
//! operation-fence:(length:u32,authenticated-bytes)
//! ```
//!
//! The accompanying descriptor table has exactly two roles in fixed order:
//! the retained initial host mount namespace and retained fixed pin root.
//! The bounded result binds the attempt ID to one digest of the worker's
//! complete closed ZFS observation plan, its typed dataset state, and its
//! descriptor-backed mount proof.

use std::ffi::OsString;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;

use aos_sandbox_broker::{BrokerEffectIntentV2, BrokerEffectStatusV2};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use sha2::{Digest as _, Sha256};

use crate::authorization::StorageAuthorityV1;
use crate::workspace_pin::{
    WorkspaceDatasetObservationV1, WorkspacePinActionV1, WorkspacePinAttemptPhaseV1,
    WorkspacePinAttemptV1, WorkspacePinObservationV1, WorkspaceRootPinProofV1,
};
use crate::{
    CatalogPlanV1, ResolvedCatalogCommitmentV1, StorageAdmissionError, StorageStateKey,
    ZfsHelperContract, ZfsWorkerError,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSZPIN1";
const WIRE_VERSION: u16 = 1;
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024;
const MAXIMUM_ATTEMPT_RECORD_BYTES: usize = 32 * 1024;
const MAXIMUM_AUTHORITY_RECORD_BYTES: usize = 1028 * 1024;
pub(crate) const MAXIMUM_PIN_WORKER_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const PIN_WORKER_DESCRIPTOR_COUNT: usize = 2;
pub(crate) const MAXIMUM_PIN_WORKER_RESULT_BYTES: usize = 16 * 1024;

const FRAME_MAGIC: &[u8; 8] = b"AOSZPFR1";
const FRAME_VERSION: u16 = 1;
const FRAME_FIRST: u16 = 1;
const FRAME_LAST: u16 = 1 << 1;
const FRAME_KNOWN_FLAGS: u16 = FRAME_FIRST | FRAME_LAST;
const FRAME_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.pin-worker-transfer.v1\0";
const FRAME_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4 + 4 + 2;
pub(crate) const MAXIMUM_PIN_WORKER_PACKET_BYTES: usize = 4096;
const MAXIMUM_FRAME_CONTENT_BYTES: usize = MAXIMUM_PIN_WORKER_PACKET_BYTES - FRAME_HEADER_BYTES;
const RESULT_MAGIC: &[u8; 8] = b"AOSZPRES";
const MAXIMUM_RESULT_STRING_BYTES: usize = 4096;

/// Carries the authenticated records needed for independent worker admission.
///
/// The values remain opaque until the worker opens them with its separately
/// provisioned protected keys. This type supplies framing, not authority.
pub(crate) struct WorkspacePinWorkerAuthorityV1 {
    parent_request_id: [u8; 16],
    attempt_record: Vec<u8>,
    current_fence: Vec<u8>,
    effect: Vec<u8>,
    operation_fence: Vec<u8>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum WorkspacePinWorkerAuthorityRecord {
    ParentRequest,
    Attempt,
    CurrentFence,
    Effect,
    OperationFence,
}

impl WorkspacePinWorkerAuthorityV1 {
    pub(crate) fn new(
        parent_request_id: [u8; 16],
        attempt_record: Vec<u8>,
        current_fence: Vec<u8>,
        effect: Vec<u8>,
        operation_fence: Vec<u8>,
    ) -> Result<Self, ZfsWorkerError> {
        let authority = Self {
            parent_request_id,
            attempt_record,
            current_fence,
            effect,
            operation_fence,
        };
        authority.validate()?;
        Ok(authority)
    }

    fn validate(&self) -> Result<(), ZfsWorkerError> {
        if self.parent_request_id == [0; 16]
            || !bounded_record(&self.attempt_record, MAXIMUM_ATTEMPT_RECORD_BYTES)
            || !bounded_record(&self.current_fence, MAXIMUM_AUTHORITY_RECORD_BYTES)
            || !bounded_record(&self.effect, MAXIMUM_AUTHORITY_RECORD_BYTES)
            || !bounded_record(&self.operation_fence, MAXIMUM_AUTHORITY_RECORD_BYTES)
        {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin authority envelope is invalid",
            ));
        }
        Ok(())
    }

    pub(crate) const fn parent_request_id(&self) -> [u8; 16] {
        self.parent_request_id
    }

    pub(crate) fn attempt_record(&self) -> &[u8] {
        &self.attempt_record
    }

    pub(crate) fn current_fence(&self) -> &[u8] {
        &self.current_fence
    }

    pub(crate) fn effect(&self) -> &[u8] {
        &self.effect
    }

    pub(crate) fn operation_fence(&self) -> &[u8] {
        &self.operation_fence
    }

    #[cfg(test)]
    pub(crate) fn substitute_record_from(
        &mut self,
        record: WorkspacePinWorkerAuthorityRecord,
        donor: &Self,
    ) {
        match record {
            WorkspacePinWorkerAuthorityRecord::ParentRequest => {
                self.parent_request_id = donor.parent_request_id;
            }
            WorkspacePinWorkerAuthorityRecord::Attempt => {
                self.attempt_record.clone_from(&donor.attempt_record);
            }
            WorkspacePinWorkerAuthorityRecord::CurrentFence => {
                self.current_fence.clone_from(&donor.current_fence);
            }
            WorkspacePinWorkerAuthorityRecord::Effect => {
                self.effect.clone_from(&donor.effect);
            }
            WorkspacePinWorkerAuthorityRecord::OperationFence => {
                self.operation_fence.clone_from(&donor.operation_fence);
            }
        }
    }
}

/// One decoded fixed-worker request before protected-record authentication.
pub(crate) struct WorkspacePinWorkerRequestV1 {
    pub(crate) executable: PathBuf,
    pub(crate) catalog: ResolvedCatalogCommitmentV1,
    pub(crate) authority: WorkspacePinWorkerAuthorityV1,
}

/// Carries one statically authenticated, non-clone worker request.
///
/// Construction authenticates all four protected records and their catalog
/// relationships. A worker must still validate the transferred namespace/root
/// descriptors and call [`check_before_effect`] immediately before its first
/// mutation.
pub(crate) struct AuthenticatedWorkspacePinWorkerRequestV1 {
    request: WorkspacePinWorkerRequestV1,
    attempt: WorkspacePinAttemptV1,
    effect: BrokerEffectIntentV2,
}

/// Carries a historical attempt admitted only for read-only recovery.
///
/// This deliberately has no conversion to the effect-worker request type and
/// carries no effect object that can be passed to [`check_before_effect`].
pub(crate) struct AuthenticatedWorkspacePinObservationRequestV1 {
    request: WorkspacePinWorkerRequestV1,
    attempt: WorkspacePinAttemptV1,
}

/// Carries one worker-observed terminal candidate back to the locked coordinator.
pub(crate) struct WorkspacePinWorkerResultV1 {
    attempt_id: [u8; 16],
    dataset: WorkspaceDatasetObservationV1,
    pin: WorkspacePinObservationV1,
    observation_digest: ObjectDigest,
}

impl WorkspacePinWorkerResultV1 {
    pub(crate) const fn new(
        attempt_id: [u8; 16],
        dataset: WorkspaceDatasetObservationV1,
        pin: WorkspacePinObservationV1,
        observation_digest: ObjectDigest,
    ) -> Self {
        Self {
            attempt_id,
            dataset,
            pin,
            observation_digest,
        }
    }

    pub(crate) const fn attempt_id(&self) -> [u8; 16] {
        self.attempt_id
    }

    pub(crate) const fn dataset(&self) -> &WorkspaceDatasetObservationV1 {
        &self.dataset
    }

    pub(crate) const fn pin(&self) -> &WorkspacePinObservationV1 {
        &self.pin
    }

    pub(crate) const fn observation_digest(&self) -> ObjectDigest {
        self.observation_digest
    }
}

impl AuthenticatedWorkspacePinWorkerRequestV1 {
    pub(crate) fn request(&self) -> &WorkspacePinWorkerRequestV1 {
        &self.request
    }

    pub(crate) fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn effect_deadline_boottime_nanoseconds(&self) -> u64 {
        self.effect.effect_deadline_boottime_nanoseconds()
    }
}

impl AuthenticatedWorkspacePinObservationRequestV1 {
    pub(crate) fn request(&self) -> &WorkspacePinWorkerRequestV1 {
        &self.request
    }

    pub(crate) fn attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.attempt
    }
}

pub(crate) fn authenticate_request(
    authority: &StorageAuthorityV1,
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinWorkerRequestV1,
) -> Result<AuthenticatedWorkspacePinWorkerRequestV1, ZfsWorkerError> {
    authenticate_request_for(authority, state_key, configured_contract, request, true)
}

/// Authenticates a historical attempt for an observation-only helper.
///
/// Unlike effect dispatch, recovery does not require the old operation fence
/// to remain the sandbox's latest desired-state fence. Both sealed fences must
/// still be valid for the same sandbox, and every immutable attempt/effect/
/// catalog relationship remains authenticated.
pub(crate) fn authenticate_observation_request(
    authority: &StorageAuthorityV1,
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinWorkerRequestV1,
) -> Result<AuthenticatedWorkspacePinObservationRequestV1, ZfsWorkerError> {
    let authenticated =
        authenticate_request_for(authority, state_key, configured_contract, request, false)?;
    Ok(AuthenticatedWorkspacePinObservationRequestV1 {
        request: authenticated.request,
        attempt: authenticated.attempt,
    })
}

fn authenticate_request_for(
    authority: &StorageAuthorityV1,
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinWorkerRequestV1,
    require_current_effect_fence: bool,
) -> Result<AuthenticatedWorkspacePinWorkerRequestV1, ZfsWorkerError> {
    if request.executable != configured_contract.executable() {
        return Err(ZfsWorkerError::Authority);
    }
    let attempt = state_key
        .open_workspace_pin_attempt(&request.authority.attempt_record)
        .map_err(|_| ZfsWorkerError::Authority)?;
    if attempt.phase() != WorkspacePinAttemptPhaseV1::Ambiguous
        || attempt.satisfied_pin().is_some()
        || ObjectDigest::from_bytes(Sha256::digest(&request.authority.operation_fence).into())
            != attempt.operation_fence_digest()
    {
        return Err(ZfsWorkerError::Authority);
    }

    let operation_fence = authority
        .open_operation_fence(
            &attempt.effect_operation_id(),
            &request.authority.operation_fence,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let sandbox_id = *operation_fence.assignment().sandbox().as_bytes();
    let current_fence = authority
        .open_fence(&sandbox_id, &request.authority.current_fence)
        .map_err(|_| ZfsWorkerError::Authority)?;
    if current_fence.assignment().sandbox() != operation_fence.assignment().sandbox()
        || require_current_effect_fence && current_fence != operation_fence
    {
        return Err(ZfsWorkerError::Authority);
    }
    authority
        .check_current_fence(&operation_fence)
        .map_err(|_| ZfsWorkerError::Authority)?;
    authority
        .check_current_fence(&current_fence)
        .map_err(|_| ZfsWorkerError::Authority)?;

    let effect = authority
        .open_admission_intent(
            &request.authority.parent_request_id,
            &request.authority.effect,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let operation = request.catalog.plan().operation();
    let semantic_commitment = operation
        .persisted_argument_commitment(
            operation_fence.assignment(),
            attempt.effect_operation_id(),
            request.catalog.binding(),
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let grant_target = operation
        .grant_target()
        .map_err(|_| ZfsWorkerError::Authority)?;
    let action_is_authorized = matches!(
        (attempt.action(), effect.verb()),
        (
            WorkspacePinActionV1::Ensure,
            aos_sandbox_core::BrokerVerb::StorageCreateWorkspace
                | aos_sandbox_core::BrokerVerb::StorageClone
        ) | (
            WorkspacePinActionV1::RemoveAndDestroy,
            aos_sandbox_core::BrokerVerb::StorageDestroy
        )
    );
    if !action_is_authorized
        || effect.status() != BrokerEffectStatusV2::Pending
        || effect.request_id() != &request.authority.parent_request_id
        || effect.request_digest() != semantic_commitment.digest()
        || effect.verb() != operation.broker_verb()
        || effect.target() != grant_target
        || effect.plan_digest() != operation_fence.plan_digest()
        || effect.plan_expires_seconds() != operation_fence.plan_expires_seconds()
        || effect.local_lease_record() != operation_fence.local_lease_record()
        || effect.lease_digest() != operation_fence.local_lease_record().lease_digest()
        || attempt.effect_assignment_digest() != operation_fence.assignment().digest()
        || attempt.host_boot_id() != *effect.host_boot_id()
        || attempt.clock_provenance() != *effect.clock_provenance()
        || attempt.effect_deadline_boottime_nanoseconds()
            != effect.effect_deadline_boottime_nanoseconds()
        || !attempt_matches_catalog(&attempt, &request.catalog)
    {
        return Err(ZfsWorkerError::Authority);
    }
    authority
        .verify_pin_attempt_receipt(&attempt, &effect, attempt.effect_operation_id())
        .map_err(|_| ZfsWorkerError::Authority)?;
    Ok(AuthenticatedWorkspacePinWorkerRequestV1 {
        request,
        attempt,
        effect,
    })
}

pub(crate) fn check_before_effect<F>(
    authority: &StorageAuthorityV1,
    request: &AuthenticatedWorkspacePinWorkerRequestV1,
    trusted_clock: &mut F,
) -> Result<(), ZfsWorkerError>
where
    F: FnMut() -> Result<RawPairedClockSample, StorageAdmissionError>,
{
    authority
        .check_before_effect(&request.effect, trusted_clock)
        .map_err(|_| ZfsWorkerError::Authority)
}

fn attempt_matches_catalog(
    attempt: &WorkspacePinAttemptV1,
    catalog: &ResolvedCatalogCommitmentV1,
) -> bool {
    match (attempt.action(), catalog.plan()) {
        (
            WorkspacePinActionV1::Ensure,
            CatalogPlanV1::CreateWorkspace { destination, .. }
            | CatalogPlanV1::Clone { destination, .. },
        ) => {
            attempt.effect_operation_id() == attempt.creation_operation_id()
                // The request catalog precedes the resulting catalog recorded
                // by the committed creation. The sealed attempt receipt binds
                // that distinct result identity to this exact create effect.
                && creation_result_follows_request(catalog, attempt.creation_result_catalog())
                && attempt.effect_assignment_digest() == attempt.workspace_assignment_digest()
                && attempt.dataset_name() == destination.name()
                && attempt.expected_pin().is_none()
        }
        (WorkspacePinActionV1::RemoveAndDestroy, CatalogPlanV1::DestroyDataset { dataset }) => {
            attempt.creation_operation_id() != attempt.effect_operation_id()
                && catalog.generation() > attempt.creation_result_catalog().generation()
                && attempt.dataset_name() == dataset.name()
                && attempt.dataset_guid() == dataset.guid()
                && attempt.workspace_handle() == dataset.storage_handle()
                && attempt.expected_pin().is_some()
        }
        _ => false,
    }
}

fn creation_result_follows_request(
    request: &ResolvedCatalogCommitmentV1,
    result: crate::CatalogBindingV1,
) -> bool {
    request.generation().checked_add(1) == Some(result.generation())
        && request.binding().digest() != result.digest()
}

pub(crate) fn encode_request(
    contract: &ZfsHelperContract,
    catalog: &ResolvedCatalogCommitmentV1,
    authority: &WorkspacePinWorkerAuthorityV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    authority.validate()?;
    let executable = contract.executable().as_os_str().as_bytes();
    let executable_length = u16::try_from(executable.len())
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin executable path is too long"))?;
    let catalog_length = checked_length(catalog.canonical_bytes(), MAXIMUM_CATALOG_BYTES)?;
    let attempt_length = checked_length(&authority.attempt_record, MAXIMUM_ATTEMPT_RECORD_BYTES)?;
    let current_fence_length =
        checked_length(&authority.current_fence, MAXIMUM_AUTHORITY_RECORD_BYTES)?;
    let effect_length = checked_length(&authority.effect, MAXIMUM_AUTHORITY_RECORD_BYTES)?;
    let operation_fence_length =
        checked_length(&authority.operation_fence, MAXIMUM_AUTHORITY_RECORD_BYTES)?;

    let mut bytes = Vec::with_capacity(
        64 + executable.len()
            + catalog.canonical_bytes().len()
            + authority.attempt_record.len()
            + authority.current_fence.len()
            + authority.effect.len()
            + authority.operation_fence.len(),
    );
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&authority.parent_request_id);
    bytes.extend_from_slice(&executable_length.to_be_bytes());
    bytes.extend_from_slice(executable);
    append_record(&mut bytes, catalog_length, catalog.canonical_bytes());
    append_record(&mut bytes, attempt_length, &authority.attempt_record);
    append_record(&mut bytes, current_fence_length, &authority.current_fence);
    append_record(&mut bytes, effect_length, &authority.effect);
    append_record(
        &mut bytes,
        operation_fence_length,
        &authority.operation_fence,
    );
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin request exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<WorkspacePinWorkerRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin request exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(REQUEST_MAGIC.len())? != REQUEST_MAGIC
        || decoder.u16()? != WIRE_VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin request header is invalid",
        ));
    }
    let parent_request_id = decoder.array()?;
    let executable_length = usize::from(decoder.u16()?);
    let executable = PathBuf::from(OsString::from_vec(
        decoder.take(executable_length)?.to_vec(),
    ));
    let catalog_bytes = decoder.bounded_record(MAXIMUM_CATALOG_BYTES)?;
    let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(catalog_bytes)
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin catalog is invalid"))?;
    let attempt_record = decoder
        .bounded_record(MAXIMUM_ATTEMPT_RECORD_BYTES)?
        .to_vec();
    let current_fence = decoder
        .bounded_record(MAXIMUM_AUTHORITY_RECORD_BYTES)?
        .to_vec();
    let effect = decoder
        .bounded_record(MAXIMUM_AUTHORITY_RECORD_BYTES)?
        .to_vec();
    let operation_fence = decoder
        .bounded_record(MAXIMUM_AUTHORITY_RECORD_BYTES)?
        .to_vec();
    decoder.finish()?;

    let authority = WorkspacePinWorkerAuthorityV1::new(
        parent_request_id,
        attempt_record,
        current_fence,
        effect,
        operation_fence,
    )?;
    let contract = ZfsHelperContract::new(executable.clone())
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin executable is invalid"))?;
    let request = WorkspacePinWorkerRequestV1 {
        executable,
        catalog,
        authority,
    };
    if encode_request(&contract, &request.catalog, &request.authority)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin request is not canonical",
        ));
    }
    Ok(request)
}

pub(crate) fn encode_result(
    result: &WorkspacePinWorkerResultV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    if result.attempt_id == [0; 16]
        || result.observation_digest.as_bytes() == &[0; 32]
        || matches!(
            &result.dataset,
            WorkspaceDatasetObservationV1::Exact { name, guid }
                if *guid == 0 || !crate::catalog::valid_dataset_name(name)
        )
    {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result identity is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(RESULT_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&result.attempt_id);
    bytes.extend_from_slice(result.observation_digest.as_bytes());
    match &result.dataset {
        WorkspaceDatasetObservationV1::Exact { name, guid } => {
            bytes.push(1);
            append_result_string(&mut bytes, name)?;
            bytes.extend_from_slice(&guid.to_be_bytes());
        }
        WorkspaceDatasetObservationV1::Absent => bytes.push(2),
        WorkspaceDatasetObservationV1::Mismatch => bytes.push(3),
    }
    match &result.pin {
        WorkspacePinObservationV1::Absent => bytes.push(1),
        WorkspacePinObservationV1::Mismatch => bytes.push(2),
        WorkspacePinObservationV1::Present(proof) => {
            bytes.push(3);
            bytes.extend_from_slice(&proof.kernel_boot_id());
            bytes.extend_from_slice(&proof.mount_namespace_device().to_be_bytes());
            bytes.extend_from_slice(&proof.mount_namespace_inode().to_be_bytes());
            bytes.extend_from_slice(&proof.mount_id().to_be_bytes());
            append_result_string(&mut bytes, proof.mount_root())?;
            append_result_string(&mut bytes, proof.mount_point())?;
            append_result_string(&mut bytes, proof.filesystem_type())?;
            append_result_string(&mut bytes, proof.superblock_source())?;
            bytes.extend_from_slice(&proof.dataset_guid().to_be_bytes());
            bytes.extend_from_slice(&proof.root_device().to_be_bytes());
            bytes.extend_from_slice(&proof.root_inode().to_be_bytes());
        }
    }
    if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_result(bytes: &[u8]) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(RESULT_MAGIC.len())? != RESULT_MAGIC
        || decoder.u16()? != WIRE_VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result header is invalid",
        ));
    }
    let attempt_id = decoder.array()?;
    let observation_digest = ObjectDigest::from_bytes(decoder.array()?);
    let dataset = match decoder.byte()? {
        1 => WorkspaceDatasetObservationV1::Exact {
            name: decoder.result_string()?,
            guid: decoder.u64()?,
        },
        2 => WorkspaceDatasetObservationV1::Absent,
        3 => WorkspaceDatasetObservationV1::Mismatch,
        _ => {
            return Err(ZfsWorkerError::Protocol(
                "workspace dataset result is invalid",
            ));
        }
    };
    let pin = match decoder.byte()? {
        1 => WorkspacePinObservationV1::Absent,
        2 => WorkspacePinObservationV1::Mismatch,
        3 => WorkspacePinObservationV1::Present(
            WorkspaceRootPinProofV1::new(
                decoder.array()?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.result_string()?,
                decoder.result_string()?,
                decoder.result_string()?,
                decoder.result_string()?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.u64()?,
            )
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin proof is invalid"))?,
        ),
        _ => {
            return Err(ZfsWorkerError::Protocol("workspace pin result is invalid"));
        }
    };
    decoder.finish()?;
    let result = WorkspacePinWorkerResultV1::new(attempt_id, dataset, pin, observation_digest);
    if encode_result(&result)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result is not canonical",
        ));
    }
    Ok(result)
}

fn append_result_string(destination: &mut Vec<u8>, value: &str) -> Result<(), ZfsWorkerError> {
    if value.is_empty() || value.len() > MAXIMUM_RESULT_STRING_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin result string is invalid",
        ));
    }
    let length = u16::try_from(value.len())
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin result string is too long"))?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Streams one bounded logical request as independently bounded seqpackets.
///
/// The unkeyed digest provides whole-transfer integrity and commits the full
/// request into every frame; it is not application authority. Frame zero alone
/// carries the two descriptor roles. The receiver retains them while it
/// reassembles the envelope, then separately authenticates every protected
/// record before any effect.
pub(crate) struct WorkspacePinRequestFrameEncoder<'a> {
    request: &'a [u8],
    digest: [u8; 32],
    offset: usize,
}

impl<'a> WorkspacePinRequestFrameEncoder<'a> {
    pub(crate) fn new(request: &'a [u8]) -> Result<Self, ZfsWorkerError> {
        if request.is_empty() || request.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin framed request length is invalid",
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(FRAME_DIGEST_DOMAIN);
        hasher.update(request);
        Ok(Self {
            request,
            digest: hasher.finalize().into(),
            offset: 0,
        })
    }

    pub(crate) fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.offset == self.request.len() {
            return None;
        }
        let remaining = self.request.len() - self.offset;
        let content_length = remaining.min(MAXIMUM_FRAME_CONTENT_BYTES);
        let end = self.offset + content_length;
        let mut flags = 0_u16;
        if self.offset == 0 {
            flags |= FRAME_FIRST;
        }
        if end == self.request.len() {
            flags |= FRAME_LAST;
        }

        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + content_length);
        frame.extend_from_slice(FRAME_MAGIC);
        frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&self.digest);
        frame.extend_from_slice(&(self.request.len() as u32).to_be_bytes());
        frame.extend_from_slice(&(self.offset as u32).to_be_bytes());
        frame.extend_from_slice(&(content_length as u16).to_be_bytes());
        frame.extend_from_slice(&self.request[self.offset..end]);
        self.offset = end;
        Some(frame)
    }
}

/// Owns one completely reassembled request and its frame-zero capabilities.
pub(crate) struct ReceivedWorkspacePinRequest {
    pub(crate) bytes: Vec<u8>,
    pub(crate) subject: KernelAuthorizedRecordSubject,
    pub(crate) descriptors: Vec<OwnedFd>,
}

/// Reassembles one exact digest-bound request without trusting frame lengths.
#[derive(Default)]
pub(crate) struct WorkspacePinRequestAssembler {
    digest: Option<[u8; 32]>,
    total_length: usize,
    next_offset: usize,
    bytes: Vec<u8>,
    subject: Option<KernelAuthorizedRecordSubject>,
    descriptors: Vec<OwnedFd>,
    frame_count: usize,
    terminal: bool,
}

impl WorkspacePinRequestAssembler {
    pub(crate) fn accept(
        &mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<Option<ReceivedWorkspacePinRequest>, ZfsWorkerError> {
        if self.terminal {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin transfer is already terminal",
            ));
        }
        let result = self.accept_inner(record);
        if result.is_err() || result.as_ref().is_ok_and(Option::is_some) {
            // A malformed or complete sequence can never be resumed or reused.
            // Dropping this assembler also closes any retained capabilities.
            self.terminal = true;
        }
        result
    }

    fn accept_inner(
        &mut self,
        record: ReceivedDescriptorRecord,
    ) -> Result<Option<ReceivedWorkspacePinRequest>, ZfsWorkerError> {
        let (payload, subject, descriptors) = record.into_parts();
        let frame = decode_frame(&payload)?;
        self.frame_count = self
            .frame_count
            .checked_add(1)
            .filter(|count| *count <= maximum_frame_count())
            .ok_or(ZfsWorkerError::Protocol(
                "workspace pin fragment count exceeded its ceiling",
            ))?;
        if self.digest.is_none() {
            if !frame.first || descriptors.len() != PIN_WORKER_DESCRIPTOR_COUNT {
                return Err(ZfsWorkerError::Protocol(
                    "workspace pin first frame descriptor profile is invalid",
                ));
            }
            if !subject.is_alive()? {
                return Err(ZfsWorkerError::PeerMismatch);
            }
            self.digest = Some(frame.digest);
            self.total_length = frame.total_length;
            self.bytes = Vec::with_capacity(frame.total_length);
            self.subject = Some(subject);
            self.descriptors = descriptors;
        } else {
            if frame.first || !descriptors.is_empty() {
                return Err(ZfsWorkerError::Protocol(
                    "workspace pin continuation descriptor profile is invalid",
                ));
            }
            verify_same_live_subject(
                self.subject
                    .as_ref()
                    .ok_or(ZfsWorkerError::Protocol("workspace pin subject is missing"))?,
                &subject,
            )?;
        }
        if Some(frame.digest) != self.digest
            || frame.total_length != self.total_length
            || frame.offset != self.next_offset
        {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin frame sequence was substituted",
            ));
        }

        self.bytes.extend_from_slice(frame.content);
        self.next_offset =
            self.next_offset
                .checked_add(frame.content.len())
                .ok_or(ZfsWorkerError::Protocol(
                    "workspace pin frame offset overflow",
                ))?;
        if !frame.last {
            return Ok(None);
        }
        if self.next_offset != self.total_length {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin final frame length is invalid",
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(FRAME_DIGEST_DOMAIN);
        hasher.update(&self.bytes);
        let actual_digest: [u8; 32] = hasher.finalize().into();
        if Some(actual_digest) != self.digest {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin framed request digest does not match",
            ));
        }
        if !self
            .subject
            .as_ref()
            .ok_or(ZfsWorkerError::Protocol("workspace pin subject is missing"))?
            .is_alive()?
        {
            return Err(ZfsWorkerError::PeerMismatch);
        }
        let subject = self
            .subject
            .take()
            .ok_or(ZfsWorkerError::Protocol("workspace pin subject is missing"))?;
        let bytes = std::mem::take(&mut self.bytes);
        let descriptors = std::mem::take(&mut self.descriptors);
        Ok(Some(ReceivedWorkspacePinRequest {
            bytes,
            subject,
            descriptors,
        }))
    }
}

const fn maximum_frame_count() -> usize {
    MAXIMUM_PIN_WORKER_REQUEST_BYTES.div_ceil(MAXIMUM_FRAME_CONTENT_BYTES)
}

struct DecodedFrame<'a> {
    first: bool,
    last: bool,
    digest: [u8; 32],
    total_length: usize,
    offset: usize,
    content: &'a [u8],
}

fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>, ZfsWorkerError> {
    if bytes.len() < FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_PIN_WORKER_PACKET_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin frame length is invalid",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(FRAME_MAGIC.len())? != FRAME_MAGIC || decoder.u16()? != FRAME_VERSION {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin frame header is invalid",
        ));
    }
    let flags = decoder.u16()?;
    if flags & !FRAME_KNOWN_FLAGS != 0 {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin frame flags are invalid",
        ));
    }
    let digest = decoder.array()?;
    let total_length = usize::try_from(decoder.u32()?)
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin total length does not fit usize"))?;
    let offset = usize::try_from(decoder.u32()?)
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin offset does not fit usize"))?;
    let content_length = usize::from(decoder.u16()?);
    let content = decoder.take(content_length)?;
    decoder.finish()?;

    let end = offset
        .checked_add(content_length)
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin frame content overflow",
        ))?;
    let first = flags & FRAME_FIRST != 0;
    let last = flags & FRAME_LAST != 0;
    if total_length == 0
        || total_length > MAXIMUM_PIN_WORKER_REQUEST_BYTES
        || content_length == 0
        || content_length > MAXIMUM_FRAME_CONTENT_BYTES
        || end > total_length
        || first != (offset == 0)
        || last != (end == total_length)
        || (!last && content_length != MAXIMUM_FRAME_CONTENT_BYTES)
    {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin frame fields are not canonical",
        ));
    }
    Ok(DecodedFrame {
        first,
        last,
        digest,
        total_length,
        offset,
        content,
    })
}

pub(crate) fn verify_same_live_subject(
    expected: &KernelAuthorizedRecordSubject,
    actual: &KernelAuthorizedRecordSubject,
) -> Result<(), ZfsWorkerError> {
    if !expected.is_alive()? || !actual.is_alive()? {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    if expected.credentials() != actual.credentials()
        || expected.initial_info().pid() != actual.initial_info().pid()
        || expected.initial_info().thread_group_id() != actual.initial_info().thread_group_id()
        || expected.initial_info().cgroup_id() != actual.initial_info().cgroup_id()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

/// Sends one logical request before one absolute `CLOCK_BOOTTIME` deadline.
///
/// An accepted frame is never resent. `EAGAIN` and `EINTR` only retry the same
/// not-yet-accepted frame; any later failure leaves the durable attempt
/// ambiguous and must not cause the caller to start another transfer.
pub(crate) fn send_request_before(
    socket: &mut DescriptorSubjectSocket,
    request: &[u8],
    descriptors: [BorrowedFd<'_>; PIN_WORKER_DESCRIPTOR_COUNT],
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ZfsWorkerError> {
    let result = send_request_inner(socket, request, descriptors, deadline_boottime_nanoseconds);
    if result.is_err() {
        socket.close();
    }
    result
}

fn send_request_inner(
    socket: &mut DescriptorSubjectSocket,
    request: &[u8],
    descriptors: [BorrowedFd<'_>; PIN_WORKER_DESCRIPTOR_COUNT],
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ZfsWorkerError> {
    socket.provision_packet_capacity(MAXIMUM_PIN_WORKER_PACKET_BYTES)?;
    let mut frames = WorkspacePinRequestFrameEncoder::new(request)?;
    let mut first = true;
    while let Some(frame) = frames.next_frame() {
        loop {
            ensure_before_deadline(deadline_boottime_nanoseconds)?;
            let result = if first {
                socket.send_with_descriptors(&frame, &descriptors)
            } else {
                socket.send(&frame)
            };
            match result {
                Ok(()) => break,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => wait_before(
                    socket.as_fd()?,
                    rustix::event::PollFlags::OUT,
                    deadline_boottime_nanoseconds,
                )?,
                Err(error) => return Err(error.into()),
            }
        }
        first = false;
    }
    ensure_before_deadline(deadline_boottime_nanoseconds)
}

/// Receives one complete logical request before an absolute deadline.
///
/// Partial, malformed, expired, or disconnected transfers return no request
/// and drop every retained descriptor. Callers may dispatch only the returned
/// complete value after separately authenticating its protected records.
pub(crate) fn receive_request_before(
    socket: &mut DescriptorSubjectSocket,
    deadline_boottime_nanoseconds: u64,
) -> Result<ReceivedWorkspacePinRequest, ZfsWorkerError> {
    let result = receive_request_inner(socket, deadline_boottime_nanoseconds);
    if result.is_err() {
        socket.close();
    }
    result
}

fn receive_request_inner(
    socket: &mut DescriptorSubjectSocket,
    deadline_boottime_nanoseconds: u64,
) -> Result<ReceivedWorkspacePinRequest, ZfsWorkerError> {
    socket.provision_packet_capacity(MAXIMUM_PIN_WORKER_PACKET_BYTES)?;
    let mut assembler = WorkspacePinRequestAssembler::default();
    loop {
        ensure_before_deadline(deadline_boottime_nanoseconds)?;
        match socket.receive_reply(MAXIMUM_PIN_WORKER_PACKET_BYTES) {
            Ok(record) => {
                if let Some(request) = assembler.accept(record)? {
                    ensure_before_deadline(deadline_boottime_nanoseconds)?;
                    return Ok(request);
                }
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => wait_before(
                socket.as_fd()?,
                rustix::event::PollFlags::IN,
                deadline_boottime_nanoseconds,
            )?,
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn ensure_before_deadline(
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ZfsWorkerError> {
    if boottime_now_nanoseconds()? >= deadline_boottime_nanoseconds {
        Err(ZfsWorkerError::Protocol(
            "workspace pin whole-transfer deadline elapsed",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn wait_before(
    descriptor: BorrowedFd<'_>,
    events: rustix::event::PollFlags,
    deadline_boottime_nanoseconds: u64,
) -> Result<(), ZfsWorkerError> {
    loop {
        let remaining = deadline_boottime_nanoseconds
            .checked_sub(boottime_now_nanoseconds()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Protocol(
                "workspace pin whole-transfer deadline elapsed",
            ))?;
        let timeout = rustix::event::Timespec::try_from(std::time::Duration::from_nanos(remaining))
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin transfer deadline is invalid"))?;
        let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                return Err(ZfsWorkerError::Protocol(
                    "workspace pin whole-transfer deadline elapsed",
                ));
            }
            Ok(_) => return ensure_before_deadline(deadline_boottime_nanoseconds),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn boottime_now_nanoseconds() -> Result<u64, ZfsWorkerError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| ZfsWorkerError::Protocol("CLOCK_BOOTTIME seconds are invalid"))?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| ZfsWorkerError::Protocol("CLOCK_BOOTTIME nanoseconds are invalid"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ZfsWorkerError::Protocol("CLOCK_BOOTTIME overflowed"))
}

fn bounded_record(record: &[u8], maximum: usize) -> bool {
    !record.is_empty() && record.len() <= maximum
}

fn checked_length(record: &[u8], maximum: usize) -> Result<u32, ZfsWorkerError> {
    if !bounded_record(record, maximum) {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin request record length is invalid",
        ));
    }
    u32::try_from(record.len())
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin record length does not fit u32"))
}

fn append_record(destination: &mut Vec<u8>, length: u32, record: &[u8]) {
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(record);
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
                "workspace pin request length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol(
                "workspace pin request is truncated",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("workspace pin u16 is invalid"),
        )?))
    }

    fn byte(&mut self) -> Result<u8, ZfsWorkerError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ZfsWorkerError::Protocol("workspace pin byte is invalid"))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("workspace pin u32 is invalid"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, ZfsWorkerError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("workspace pin u64 is invalid"),
        )?))
    }

    fn result_string(&mut self) -> Result<String, ZfsWorkerError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > MAXIMUM_RESULT_STRING_BYTES {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin result string is invalid",
            ));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin result string is not UTF-8"))?;
        Ok(value.to_owned())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin fixed field is invalid"))
    }

    fn bounded_record(&mut self, maximum: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let length = usize::try_from(self.u32()?).map_err(|_| {
            ZfsWorkerError::Protocol("workspace pin record length does not fit usize")
        })?;
        if length == 0 || length > maximum {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin request record length is invalid",
            ));
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol(
                "workspace pin request has trailing bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::{
        CatalogPlanV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
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

    fn authority() -> WorkspacePinWorkerAuthorityV1 {
        WorkspacePinWorkerAuthorityV1::new(
            [1; 16],
            vec![2; 128],
            vec![3; 129],
            vec![4; 130],
            vec![5; 131],
        )
        .unwrap()
    }

    fn socket_pair() -> (DescriptorSubjectSocket, DescriptorSubjectSocket) {
        let (left, right) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        (
            DescriptorSubjectSocket::from_owned(left).unwrap(),
            DescriptorSubjectSocket::from_owned(right).unwrap(),
        )
    }

    #[test]
    fn request_round_trip_preserves_opaque_records_and_typed_catalog() {
        let contract = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let catalog = fixture_catalog();
        let bytes = encode_request(&contract, &catalog, &authority()).unwrap();
        let decoded = decode_request(&bytes).unwrap();

        assert_eq!(decoded.executable, contract.executable());
        assert_eq!(decoded.catalog, catalog);
        assert_eq!(decoded.authority.parent_request_id, [1; 16]);
        assert_eq!(decoded.authority.attempt_record, vec![2; 128]);
        assert_eq!(decoded.authority.current_fence, vec![3; 129]);
        assert_eq!(decoded.authority.effect, vec![4; 130]);
        assert_eq!(decoded.authority.operation_fence, vec![5; 131]);
    }

    #[test]
    fn ensure_result_catalog_requires_an_exact_distinct_successor() {
        let request = fixture_catalog();
        let successor = crate::CatalogBindingV1::from_publisher(
            request.generation() + 1,
            ObjectDigest::from_bytes([31; 32]),
        )
        .unwrap();
        let non_successor = crate::CatalogBindingV1::from_publisher(
            request.generation() + 2,
            ObjectDigest::from_bytes([32; 32]),
        )
        .unwrap();
        let unchanged_digest = crate::CatalogBindingV1::from_publisher(
            request.generation() + 1,
            request.binding().digest(),
        )
        .unwrap();
        let exhausted =
            ResolvedCatalogCommitmentV1::new(u64::MAX, request.domains(), request.plan().clone())
                .unwrap();
        let wrapped =
            crate::CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([33; 32])).unwrap();

        assert!(creation_result_follows_request(&request, successor));
        assert!(!creation_result_follows_request(&request, non_successor));
        assert!(!creation_result_follows_request(&request, unchanged_digest));
        assert!(!creation_result_follows_request(&exhausted, wrapped));
    }

    #[test]
    fn request_rejects_header_length_and_trailing_substitution() {
        let contract = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let catalog = fixture_catalog();
        let encoded = encode_request(&contract, &catalog, &authority()).unwrap();

        let mut wrong_reserved = encoded.clone();
        wrong_reserved[11] = 1;
        assert!(decode_request(&wrong_reserved).is_err());

        let mut zero_catalog = encoded.clone();
        let catalog_length_offset = 28 + 2 + contract.executable().as_os_str().as_bytes().len();
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
    fn result_round_trip_binds_attempt_observation_and_mount_proof() {
        let proof = WorkspaceRootPinProofV1::new(
            [6; 16],
            7,
            8,
            9,
            "/".to_owned(),
            "/run/aos/sandbox-pins/workspaces/fixture".to_owned(),
            "zfs".to_owned(),
            "tank/aos/project/work".to_owned(),
            10,
            11,
            12,
        )
        .unwrap();
        let result = WorkspacePinWorkerResultV1::new(
            [5; 16],
            WorkspaceDatasetObservationV1::Exact {
                name: "tank/aos/project/work".to_owned(),
                guid: 10,
            },
            WorkspacePinObservationV1::Present(proof.clone()),
            ObjectDigest::from_bytes([13; 32]),
        );
        let bytes = encode_result(&result).unwrap();
        let decoded = decode_result(&bytes).unwrap();

        assert_eq!(decoded.attempt_id(), [5; 16]);
        assert_eq!(decoded.dataset(), result.dataset());
        assert_eq!(decoded.pin(), &WorkspacePinObservationV1::Present(proof));
        assert_eq!(
            decoded.observation_digest(),
            ObjectDigest::from_bytes([13; 32])
        );

        let mut zero_digest = bytes;
        zero_digest[28..60].fill(0);
        assert!(decode_result(&zero_digest).is_err());
    }

    #[test]
    fn authority_envelope_rejects_zero_identity_and_empty_or_oversized_records() {
        assert!(
            WorkspacePinWorkerAuthorityV1::new([0; 16], vec![1], vec![2], vec![3], vec![4])
                .is_err()
        );
        assert!(
            WorkspacePinWorkerAuthorityV1::new([1; 16], Vec::new(), vec![2], vec![3], vec![4])
                .is_err()
        );
        assert!(
            WorkspacePinWorkerAuthorityV1::new(
                [1; 16],
                vec![1],
                vec![2; MAXIMUM_AUTHORITY_RECORD_BYTES + 1],
                vec![3],
                vec![4]
            )
            .is_err()
        );
    }

    #[test]
    fn maximum_valid_authority_envelope_crosses_default_limited_socket_in_frames() {
        let contract = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let authority = WorkspacePinWorkerAuthorityV1::new(
            [1; 16],
            vec![2; MAXIMUM_ATTEMPT_RECORD_BYTES],
            vec![3; MAXIMUM_AUTHORITY_RECORD_BYTES],
            vec![4; MAXIMUM_AUTHORITY_RECORD_BYTES],
            vec![5; MAXIMUM_AUTHORITY_RECORD_BYTES],
        )
        .unwrap();
        let request = encode_request(&contract, &fixture_catalog(), &authority).unwrap();
        assert!(request.len() > 3 * 1024 * 1024);

        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        let expected_identities = [first.metadata().unwrap(), second.metadata().unwrap()]
            .map(|metadata| (metadata.dev(), metadata.ino()));
        let deadline = boottime_now_nanoseconds().unwrap() + 30_000_000_000;
        let sender_request = request.clone();
        let send = std::thread::spawn(move || {
            send_request_before(
                &mut sender,
                &sender_request,
                [first.as_fd(), second.as_fd()],
                deadline,
            )
        });

        let received = receive_request_before(&mut receiver, deadline).unwrap();
        assert_eq!(received.bytes, request);
        assert!(received.subject.is_alive().unwrap());
        assert_eq!(received.descriptors.len(), PIN_WORKER_DESCRIPTOR_COUNT);
        let actual_identities: Vec<_> = received
            .descriptors
            .into_iter()
            .map(|descriptor| {
                let metadata = std::fs::File::from(descriptor).metadata().unwrap();
                (metadata.dev(), metadata.ino())
            })
            .collect();
        assert_eq!(actual_identities, expected_identities);
        send.join().unwrap().unwrap();
    }

    #[test]
    fn malformed_continuation_poisons_assembler_and_never_yields_request() {
        let logical = vec![9; MAXIMUM_FRAME_CONTENT_BYTES + 1];
        let mut encoder = WorkspacePinRequestFrameEncoder::new(&logical).unwrap();
        let first_frame = encoder.next_frame().unwrap();
        let last_frame = encoder.next_frame().unwrap();
        assert!(encoder.next_frame().is_none());

        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(&first_frame, &[first.as_fd(), second.as_fd()])
            .unwrap();
        let mut assembler = WorkspacePinRequestAssembler::default();
        assert!(
            assembler
                .accept(
                    receiver
                        .receive_reply(MAXIMUM_PIN_WORKER_PACKET_BYTES)
                        .unwrap()
                )
                .unwrap()
                .is_none()
        );

        sender
            .send_with_descriptors(&last_frame, &[first.as_fd(), second.as_fd()])
            .unwrap();
        assert!(
            assembler
                .accept(
                    receiver
                        .receive_reply(MAXIMUM_PIN_WORKER_PACKET_BYTES)
                        .unwrap()
                )
                .is_err()
        );

        sender.send(&last_frame).unwrap();
        assert!(
            assembler
                .accept(
                    receiver
                        .receive_reply(MAXIMUM_PIN_WORKER_PACKET_BYTES)
                        .unwrap()
                )
                .is_err()
        );
    }

    #[test]
    fn expired_whole_message_deadline_closes_partial_transfer() {
        let logical = vec![7; MAXIMUM_FRAME_CONTENT_BYTES + 1];
        let mut encoder = WorkspacePinRequestFrameEncoder::new(&logical).unwrap();
        let first_frame = encoder.next_frame().unwrap();
        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(&first_frame, &[first.as_fd(), second.as_fd()])
            .unwrap();

        let elapsed = boottime_now_nanoseconds().unwrap();
        assert!(receive_request_before(&mut receiver, elapsed).is_err());
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
    }

    #[test]
    fn active_partial_transfer_expires_under_one_absolute_deadline() {
        let logical = vec![6; MAXIMUM_FRAME_CONTENT_BYTES + 1];
        let mut encoder = WorkspacePinRequestFrameEncoder::new(&logical).unwrap();
        let first_frame = encoder.next_frame().unwrap();
        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(&first_frame, &[first.as_fd(), second.as_fd()])
            .unwrap();

        let deadline = boottime_now_nanoseconds().unwrap() + 50_000_000;
        assert!(receive_request_before(&mut receiver, deadline).is_err());
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
        assert!(sender.as_fd().is_ok());
    }

    #[test]
    fn disconnected_partial_transfer_never_returns_a_request() {
        let logical = vec![8; MAXIMUM_FRAME_CONTENT_BYTES + 1];
        let mut encoder = WorkspacePinRequestFrameEncoder::new(&logical).unwrap();
        let first_frame = encoder.next_frame().unwrap();
        let (mut receiver, mut sender) = socket_pair();
        let first = tempfile::tempfile().unwrap();
        let second = tempfile::tempfile().unwrap();
        sender
            .send_with_descriptors(&first_frame, &[first.as_fd(), second.as_fd()])
            .unwrap();
        drop(sender);

        let deadline = boottime_now_nanoseconds().unwrap() + 5_000_000_000;
        assert!(receive_request_before(&mut receiver, deadline).is_err());
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
    }
}
