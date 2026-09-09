//! Fresh descriptor-backed observation before workspace root-pin repair admission.
//!
//! This protocol is deliberately distinct from post-commit repair recovery.
//! It carries no effect grant and cannot itself authorize mutation. The
//! observer independently authenticates the latest workspace-pin attempt,
//! creation publication, and optional predecessor repair intent before it
//! derives the current descriptor-backed host scope and observes exact
//! dataset presence and pin absence.
//!
//! ```text
//! AOSZRPA1 | version:u16 | reserved:u16 | challenge:16
//! executable:(length:u16,bytes)
//! repair-request-id:16 | repair-operation-id:16
//! transport-request-digest:32 | semantic-commitment:32
//! repair-assignment-digest:32 | workspace-handle:32
//! predecessor-kind:u8 | reserved:[3]
//! creation-catalog:(length:u32,canonical-bytes)
//! latest-attempt:(length:u32,authenticated-bytes)
//! publication-intent:(length:u32,authenticated-bytes)
//! predecessor-repair-intent:(length:u32,authenticated-bytes-or-empty)
//!
//! AOSZRPS1 | version:u16 | reserved:u16 | probe-digest:32
//! observation:(length:u32,AOSZPRES-bytes)
//! ```

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
    MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE, WorkspaceDatasetObservationV1, WorkspacePinActionV1,
    WorkspacePinAttemptPhaseV1, WorkspacePinAttemptV1, WorkspacePinHostScopeV1,
    WorkspacePinObservationV1,
};
use crate::workspace_repair::StorageWorkspacePinRepairIntentV1;
use crate::{
    CatalogPlanV1, ResolvedCatalogCommitmentV1, StorageStateKey, ZfsHelperContract, ZfsWorkerError,
};

const REQUEST_MAGIC: &[u8; 8] = b"AOSZRPA1";
const RESULT_MAGIC: &[u8; 8] = b"AOSZRPS1";
const VERSION: u16 = 1;
const PROBE_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-repair-admission-probe.v1\0";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024;
const MAXIMUM_STATE_RECORD_BYTES: usize = 128 * 1024;
const MAXIMUM_REPAIR_INTENT_BYTES: usize = 256 * 1024;

/// Distinguishes an initial creation attempt from a previously admitted repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinRepairPredecessorKindV1 {
    /// The latest attempt is the creation effect's ordinal-one Ensure.
    Initial,
    /// The latest attempt is an ordinal-two-or-later repair Ensure.
    Repair,
}

impl WorkspacePinRepairPredecessorKindV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::Initial => 1,
            Self::Repair => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, ZfsWorkerError> {
        match value {
            1 => Ok(Self::Initial),
            2 => Ok(Self::Repair),
            _ => Err(ZfsWorkerError::Protocol(
                "repair admission predecessor kind is invalid",
            )),
        }
    }
}

/// Carries opaque authenticated history into the pre-admission observer.
pub(crate) struct WorkspacePinRepairAdmissionRequestV1 {
    executable: PathBuf,
    generated_challenge: [u8; 16],
    repair_request_id: [u8; 16],
    repair_operation_id: [u8; 16],
    transport_request_digest: ObjectDigest,
    semantic_commitment: ObjectDigest,
    repair_assignment_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    predecessor_kind: WorkspacePinRepairPredecessorKindV1,
    catalog: ResolvedCatalogCommitmentV1,
    latest_attempt_record: Vec<u8>,
    publication_intent_record: Vec<u8>,
    predecessor_repair_intent_record: Vec<u8>,
}

impl WorkspacePinRepairAdmissionRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        executable: PathBuf,
        generated_challenge: [u8; 16],
        repair_request_id: [u8; 16],
        repair_operation_id: [u8; 16],
        transport_request_digest: ObjectDigest,
        semantic_commitment: ObjectDigest,
        repair_assignment_digest: ObjectDigest,
        workspace_handle: [u8; 32],
        predecessor_kind: WorkspacePinRepairPredecessorKindV1,
        catalog: ResolvedCatalogCommitmentV1,
        latest_attempt_record: Vec<u8>,
        publication_intent_record: Vec<u8>,
        predecessor_repair_intent_record: Vec<u8>,
    ) -> Result<Self, ZfsWorkerError> {
        let request = Self {
            executable,
            generated_challenge,
            repair_request_id,
            repair_operation_id,
            transport_request_digest,
            semantic_commitment,
            repair_assignment_digest,
            workspace_handle,
            predecessor_kind,
            catalog,
            latest_attempt_record,
            publication_intent_record,
            predecessor_repair_intent_record,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ZfsWorkerError> {
        ZfsHelperContract::new(self.executable.clone())
            .map_err(|_| ZfsWorkerError::Protocol("repair admission executable is invalid"))?;
        let predecessor_shape_is_valid = match self.predecessor_kind {
            WorkspacePinRepairPredecessorKindV1::Initial => {
                self.predecessor_repair_intent_record.is_empty()
            }
            WorkspacePinRepairPredecessorKindV1::Repair => bounded(
                &self.predecessor_repair_intent_record,
                MAXIMUM_REPAIR_INTENT_BYTES,
            ),
        };
        if self.generated_challenge == [0; 16]
            || self.repair_request_id == [0; 16]
            || self.repair_operation_id == [0; 16]
            || self.transport_request_digest.as_bytes() == &[0; 32]
            || self.semantic_commitment.as_bytes() == &[0; 32]
            || self.repair_assignment_digest.as_bytes() == &[0; 32]
            || self.workspace_handle == [0; 32]
            || !bounded(self.catalog.canonical_bytes(), MAXIMUM_CATALOG_BYTES)
            || !bounded(&self.latest_attempt_record, MAXIMUM_STATE_RECORD_BYTES)
            || !bounded(&self.publication_intent_record, MAXIMUM_STATE_RECORD_BYTES)
            || !predecessor_shape_is_valid
        {
            return Err(ZfsWorkerError::Protocol(
                "repair admission authority envelope is invalid",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches_current_records(
        &self,
        latest_attempt_record: &[u8],
        publication_intent_record: &[u8],
        predecessor_repair_intent_record: &[u8],
    ) -> bool {
        self.latest_attempt_record == latest_attempt_record
            && self.publication_intent_record == publication_intent_record
            && self.predecessor_repair_intent_record == predecessor_repair_intent_record
    }

    pub(crate) fn matches_semantics(
        &self,
        request_id: [u8; 16],
        repair_operation_id: [u8; 16],
        transport_request_digest: ObjectDigest,
        semantic_commitment: ObjectDigest,
        repair_assignment_digest: ObjectDigest,
        workspace_handle: [u8; 32],
    ) -> bool {
        self.repair_request_id == request_id
            && self.repair_operation_id == repair_operation_id
            && self.transport_request_digest == transport_request_digest
            && self.semantic_commitment == semantic_commitment
            && self.repair_assignment_digest == repair_assignment_digest
            && self.workspace_handle == workspace_handle
    }
}

/// Carries authenticated predecessor state and a descriptor-bound probe.
pub(crate) struct AuthenticatedWorkspacePinRepairAdmissionRequestV1 {
    request: WorkspacePinRepairAdmissionRequestV1,
    latest_attempt: WorkspacePinAttemptV1,
    probe: WorkspacePinRepairAdmissionProbeV1,
}

impl AuthenticatedWorkspacePinRepairAdmissionRequestV1 {
    pub(crate) const fn latest_attempt(&self) -> &WorkspacePinAttemptV1 {
        &self.latest_attempt
    }

    pub(crate) const fn probe(&self) -> &WorkspacePinRepairAdmissionProbeV1 {
        &self.probe
    }

    pub(crate) const fn catalog(&self) -> &ResolvedCatalogCommitmentV1 {
        &self.request.catalog
    }
}

/// Binds raw observer output to one exact pre-admission probe.
pub(crate) struct WorkspacePinRepairAdmissionResultV1 {
    probe_digest: ObjectDigest,
    observation: WorkspacePinWorkerResultV1,
}

impl WorkspacePinRepairAdmissionResultV1 {
    pub(crate) const fn new(
        probe_digest: ObjectDigest,
        observation: WorkspacePinWorkerResultV1,
    ) -> Self {
        Self {
            probe_digest,
            observation,
        }
    }
}

/// Validates raw protocol output without granting fresh production authority.
///
/// The fixed systemd observer wraps this value in its private fresh capability
/// only after it has also proved the child identity, exit, and cgroup
/// quiescence. Pure codec tests may construct this validation result, but
/// cannot construct the production capability.
pub(crate) struct ValidatedWorkspacePinRepairAdmissionObservationV1 {
    probe_digest: ObjectDigest,
    latest_attempt_id: [u8; 16],
    repair_operation_id: [u8; 16],
    workspace_handle: [u8; 32],
}

impl ValidatedWorkspacePinRepairAdmissionObservationV1 {
    pub(crate) fn from_result(
        probe: &WorkspacePinRepairAdmissionProbeV1,
        result: WorkspacePinRepairAdmissionResultV1,
    ) -> Result<Self, ZfsWorkerError> {
        let observation = result.observation;
        if result.probe_digest != probe.digest()
            || observation.attempt_id() != probe.latest_attempt_id()
            || observation.dataset()
                != &(WorkspaceDatasetObservationV1::Exact {
                    name: probe.dataset_name().to_owned(),
                    guid: probe.dataset_guid(),
                })
            || observation.pin() != &WorkspacePinObservationV1::Absent
        {
            return Err(ZfsWorkerError::Authority);
        }
        Ok(Self {
            probe_digest: probe.digest(),
            latest_attempt_id: probe.latest_attempt_id(),
            repair_operation_id: probe.repair_operation_id(),
            workspace_handle: probe.workspace_handle(),
        })
    }

    pub(crate) fn matches_probe(&self, probe: &WorkspacePinRepairAdmissionProbeV1) -> bool {
        self.probe_digest == probe.digest()
            && self.latest_attempt_id == probe.latest_attempt_id()
            && self.repair_operation_id == probe.repair_operation_id()
            && self.workspace_handle == probe.workspace_handle()
    }
}

/// Commits the complete authenticated and descriptor-backed observation scope.
pub(crate) struct WorkspacePinRepairAdmissionProbeV1 {
    generated_challenge: [u8; 16],
    repair_request_id: [u8; 16],
    repair_operation_id: [u8; 16],
    transport_request_digest: ObjectDigest,
    semantic_commitment: ObjectDigest,
    repair_assignment_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    predecessor_kind: WorkspacePinRepairPredecessorKindV1,
    predecessor_repair_intent_record_digest: ObjectDigest,
    latest_attempt_id: [u8; 16],
    latest_attempt_ordinal: u8,
    latest_attempt_phase: WorkspacePinAttemptPhaseV1,
    latest_attempt_record_digest: ObjectDigest,
    publication_intent_record_digest: ObjectDigest,
    historical_attempt_host_scope: WorkspacePinHostScopeV1,
    current_host_scope: WorkspacePinHostScopeV1,
    dataset_name: String,
    dataset_guid: u64,
}

impl WorkspacePinRepairAdmissionProbeV1 {
    pub(crate) fn digest(&self) -> ObjectDigest {
        let mut hasher = Sha256::new();
        hasher.update(PROBE_DOMAIN);
        hasher.update(self.generated_challenge);
        hasher.update(self.repair_request_id);
        hasher.update(self.repair_operation_id);
        hasher.update(self.transport_request_digest.as_bytes());
        hasher.update(self.semantic_commitment.as_bytes());
        hasher.update(self.repair_assignment_digest.as_bytes());
        hasher.update(self.workspace_handle);
        hasher.update([self.predecessor_kind.wire()]);
        hasher.update(self.predecessor_repair_intent_record_digest.as_bytes());
        hasher.update(self.latest_attempt_id);
        hasher.update([self.latest_attempt_ordinal]);
        hasher.update([attempt_phase_wire(self.latest_attempt_phase)]);
        hasher.update(self.latest_attempt_record_digest.as_bytes());
        hasher.update(self.publication_intent_record_digest.as_bytes());
        hash_scope(&mut hasher, self.historical_attempt_host_scope);
        hash_scope(&mut hasher, self.current_host_scope);
        hasher.update(
            u16::try_from(self.dataset_name.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hasher.update(self.dataset_name.as_bytes());
        hasher.update(self.dataset_guid.to_be_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    pub(crate) const fn latest_attempt_id(&self) -> [u8; 16] {
        self.latest_attempt_id
    }

    pub(crate) const fn repair_operation_id(&self) -> [u8; 16] {
        self.repair_operation_id
    }

    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    pub(crate) const fn current_host_scope(&self) -> WorkspacePinHostScopeV1 {
        self.current_host_scope
    }

    pub(crate) fn dataset_name(&self) -> &str {
        &self.dataset_name
    }

    pub(crate) const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }
}

pub(crate) fn is_repair_admission_request(bytes: &[u8]) -> bool {
    bytes.starts_with(REQUEST_MAGIC)
}

pub(crate) fn authenticate_request(
    state_key: &StorageStateKey,
    configured_contract: &ZfsHelperContract,
    request: WorkspacePinRepairAdmissionRequestV1,
    current_host_scope: WorkspacePinHostScopeV1,
) -> Result<AuthenticatedWorkspacePinRepairAdmissionRequestV1, ZfsWorkerError> {
    if request.executable != configured_contract.executable() {
        return Err(ZfsWorkerError::Authority);
    }
    let latest_attempt = state_key
        .open_workspace_pin_attempt(&request.latest_attempt_record)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let publication = state_key
        .open_workspace_publication_intent(
            latest_attempt.creation_operation_id(),
            &request.publication_intent_record,
        )
        .map_err(|_| ZfsWorkerError::Authority)?;
    let predecessor_repair = if request.predecessor_repair_intent_record.is_empty() {
        None
    } else {
        Some(
            state_key
                .open_workspace_pin_repair_intent(&request.predecessor_repair_intent_record)
                .map_err(|_| ZfsWorkerError::Authority)?,
        )
    };
    let destination_name = match request.catalog.plan() {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination.name(),
        _ => return Err(ZfsWorkerError::Authority),
    };
    let creation_result_follows_request = request.catalog.generation().checked_add(1)
        == Some(latest_attempt.creation_result_catalog().generation())
        && request.catalog.binding().digest() != latest_attempt.creation_result_catalog().digest();
    if !creation_result_follows_request
        || destination_name != latest_attempt.dataset_name()
        || publication.operation_id() != latest_attempt.creation_operation_id()
        || publication.request_catalog() != request.catalog.binding()
        || publication.assignment_digest() != latest_attempt.workspace_assignment_digest()
        || publication.identity_range_start() != latest_attempt.identity_range_start()
        || publication.identity_range_size() != latest_attempt.identity_range_size()
    {
        return Err(ZfsWorkerError::Authority);
    }

    let publication_intent_record_digest = digest_bytes(&request.publication_intent_record);
    if let Some(intent) = predecessor_repair.as_ref() {
        if intent.publication_intent_record_digest() != publication_intent_record_digest {
            return Err(ZfsWorkerError::Authority);
        }
    }
    let probe = bind_probe(
        &request,
        &latest_attempt,
        predecessor_repair.as_ref(),
        current_host_scope,
    )?;
    Ok(AuthenticatedWorkspacePinRepairAdmissionRequestV1 {
        request,
        latest_attempt,
        probe,
    })
}

pub(crate) fn bind_probe(
    request: &WorkspacePinRepairAdmissionRequestV1,
    latest_attempt: &WorkspacePinAttemptV1,
    predecessor_repair: Option<&StorageWorkspacePinRepairIntentV1>,
    current_host_scope: WorkspacePinHostScopeV1,
) -> Result<WorkspacePinRepairAdmissionProbeV1, ZfsWorkerError> {
    let predecessor_kind = classify_predecessor(latest_attempt, predecessor_repair, true)?;
    if predecessor_kind != request.predecessor_kind
        || request.repair_operation_id == latest_attempt.creation_operation_id()
        || request.repair_operation_id == latest_attempt.effect_operation_id()
        || request.workspace_handle != latest_attempt.workspace_handle()
    {
        return Err(ZfsWorkerError::Authority);
    }
    let historical_attempt_host_scope = WorkspacePinHostScopeV1::new(
        latest_attempt.host_boot_id(),
        latest_attempt.host_mount_namespace_device(),
        latest_attempt.host_mount_namespace_inode(),
    )
    .map_err(|_| ZfsWorkerError::Authority)?;
    let predecessor_repair_intent_record_digest = predecessor_repair
        .map(|_| digest_bytes(&request.predecessor_repair_intent_record))
        .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]));

    Ok(WorkspacePinRepairAdmissionProbeV1 {
        generated_challenge: request.generated_challenge,
        repair_request_id: request.repair_request_id,
        repair_operation_id: request.repair_operation_id,
        transport_request_digest: request.transport_request_digest,
        semantic_commitment: request.semantic_commitment,
        repair_assignment_digest: request.repair_assignment_digest,
        workspace_handle: request.workspace_handle,
        predecessor_kind,
        predecessor_repair_intent_record_digest,
        latest_attempt_id: latest_attempt.attempt_id(),
        latest_attempt_ordinal: latest_attempt.attempt_ordinal(),
        latest_attempt_phase: latest_attempt.phase(),
        latest_attempt_record_digest: digest_bytes(&request.latest_attempt_record),
        publication_intent_record_digest: digest_bytes(&request.publication_intent_record),
        historical_attempt_host_scope,
        current_host_scope,
        dataset_name: latest_attempt.dataset_name().to_owned(),
        dataset_guid: latest_attempt.dataset_guid(),
    })
}

pub(crate) fn classify_predecessor(
    latest_attempt: &WorkspacePinAttemptV1,
    predecessor_repair: Option<&StorageWorkspacePinRepairIntentV1>,
    creation_is_active: bool,
) -> Result<WorkspacePinRepairPredecessorKindV1, ZfsWorkerError> {
    if !creation_is_active
        || latest_attempt.action() != WorkspacePinActionV1::Ensure
        || latest_attempt.expected_pin().is_some()
        || latest_attempt.attempt_ordinal() >= MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE
        || !matches!(
            latest_attempt.phase(),
            WorkspacePinAttemptPhaseV1::Ambiguous | WorkspacePinAttemptPhaseV1::Satisfied
        )
    {
        return Err(ZfsWorkerError::Authority);
    }

    if latest_attempt.attempt_ordinal() == 1 {
        if predecessor_repair.is_some()
            || latest_attempt.effect_operation_id() != latest_attempt.creation_operation_id()
        {
            return Err(ZfsWorkerError::Authority);
        }
        return Ok(WorkspacePinRepairPredecessorKindV1::Initial);
    }

    let intent = predecessor_repair.ok_or(ZfsWorkerError::Authority)?;
    if latest_attempt.effect_operation_id() == latest_attempt.creation_operation_id()
        || intent.repair_attempt_id() != latest_attempt.attempt_id()
        || intent.repair_attempt_ordinal() != latest_attempt.attempt_ordinal()
        || intent.repair_operation_id() != latest_attempt.effect_operation_id()
        || intent.creation_operation_id() != latest_attempt.creation_operation_id()
        || intent.creation_result_catalog() != latest_attempt.creation_result_catalog()
        || intent.creation_result_digest() != latest_attempt.creation_result_digest()
        || intent.workspace_handle() != latest_attempt.workspace_handle()
        || intent.repair_assignment_digest() != latest_attempt.effect_assignment_digest()
        || intent.operation_fence_digest() != latest_attempt.operation_fence_digest()
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(WorkspacePinRepairPredecessorKindV1::Repair)
}

pub(crate) fn encode_request(
    request: &WorkspacePinRepairAdmissionRequestV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    request.validate()?;
    let executable = request.executable.as_os_str().as_bytes();
    let executable_length = u16::try_from(executable.len())
        .map_err(|_| ZfsWorkerError::Protocol("repair admission executable is too long"))?;
    let catalog = request.catalog.canonical_bytes();
    let mut bytes = Vec::with_capacity(
        256 + executable.len()
            + catalog.len()
            + request.latest_attempt_record.len()
            + request.publication_intent_record.len()
            + request.predecessor_repair_intent_record.len(),
    );
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&request.generated_challenge);
    bytes.extend_from_slice(&executable_length.to_be_bytes());
    bytes.extend_from_slice(executable);
    bytes.extend_from_slice(&request.repair_request_id);
    bytes.extend_from_slice(&request.repair_operation_id);
    bytes.extend_from_slice(request.transport_request_digest.as_bytes());
    bytes.extend_from_slice(request.semantic_commitment.as_bytes());
    bytes.extend_from_slice(request.repair_assignment_digest.as_bytes());
    bytes.extend_from_slice(&request.workspace_handle);
    bytes.push(request.predecessor_kind.wire());
    bytes.extend_from_slice(&[0; 3]);
    append_record(&mut bytes, catalog)?;
    append_record(&mut bytes, &request.latest_attempt_record)?;
    append_record(&mut bytes, &request.publication_intent_record)?;
    append_record(&mut bytes, &request.predecessor_repair_intent_record)?;
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair admission request exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_request(
    bytes: &[u8],
) -> Result<WorkspacePinRepairAdmissionRequestV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair admission request exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(REQUEST_MAGIC.len())? != REQUEST_MAGIC
        || decoder.u16()? != VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "repair admission request header is invalid",
        ));
    }
    let generated_challenge = decoder.array()?;
    let executable_length = usize::from(decoder.u16()?);
    let executable = PathBuf::from(OsString::from_vec(
        decoder.take(executable_length)?.to_vec(),
    ));
    let repair_request_id = decoder.array()?;
    let repair_operation_id = decoder.array()?;
    let transport_request_digest = ObjectDigest::from_bytes(decoder.array()?);
    let semantic_commitment = ObjectDigest::from_bytes(decoder.array()?);
    let repair_assignment_digest = ObjectDigest::from_bytes(decoder.array()?);
    let workspace_handle = decoder.array()?;
    let predecessor_kind = WorkspacePinRepairPredecessorKindV1::from_wire(decoder.u8()?)?;
    if decoder.take(3)? != [0; 3] {
        return Err(ZfsWorkerError::Protocol(
            "repair admission request reserved bytes are invalid",
        ));
    }
    let catalog =
        ResolvedCatalogCommitmentV1::from_canonical_bytes(decoder.record(MAXIMUM_CATALOG_BYTES)?)
            .map_err(|_| ZfsWorkerError::Protocol("repair admission catalog is invalid"))?;
    let latest_attempt_record = decoder.record(MAXIMUM_STATE_RECORD_BYTES)?.to_vec();
    let publication_intent_record = decoder.record(MAXIMUM_STATE_RECORD_BYTES)?.to_vec();
    let predecessor_repair_intent_record = decoder
        .optional_record(MAXIMUM_REPAIR_INTENT_BYTES)?
        .to_vec();
    decoder.finish()?;
    let request = WorkspacePinRepairAdmissionRequestV1::new(
        executable,
        generated_challenge,
        repair_request_id,
        repair_operation_id,
        transport_request_digest,
        semantic_commitment,
        repair_assignment_digest,
        workspace_handle,
        predecessor_kind,
        catalog,
        latest_attempt_record,
        publication_intent_record,
        predecessor_repair_intent_record,
    )?;
    if encode_request(&request)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "repair admission request is not canonical",
        ));
    }
    Ok(request)
}

pub(crate) fn encode_result(
    result: &WorkspacePinRepairAdmissionResultV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    if result.probe_digest.as_bytes() == &[0; 32] {
        return Err(ZfsWorkerError::Protocol(
            "repair admission result probe is invalid",
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
            "repair admission result exceeds byte ceiling",
        ));
    }
    Ok(bytes)
}

pub(crate) fn decode_result(
    bytes: &[u8],
) -> Result<WorkspacePinRepairAdmissionResultV1, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_PIN_WORKER_RESULT_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "repair admission result exceeds byte ceiling",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(RESULT_MAGIC.len())? != RESULT_MAGIC
        || decoder.u16()? != VERSION
        || decoder.u16()? != 0
    {
        return Err(ZfsWorkerError::Protocol(
            "repair admission result header is invalid",
        ));
    }
    let probe_digest = ObjectDigest::from_bytes(decoder.array()?);
    let observation = decode_pin_worker_result(decoder.record(MAXIMUM_PIN_WORKER_RESULT_BYTES)?)?;
    decoder.finish()?;
    let result = WorkspacePinRepairAdmissionResultV1::new(probe_digest, observation);
    if encode_result(&result)? != bytes {
        return Err(ZfsWorkerError::Protocol(
            "repair admission result is not canonical",
        ));
    }
    Ok(result)
}

fn hash_scope(hasher: &mut Sha256, scope: WorkspacePinHostScopeV1) {
    hasher.update(scope.kernel_boot_id());
    hasher.update(scope.mount_namespace_device().to_be_bytes());
    hasher.update(scope.mount_namespace_inode().to_be_bytes());
}

const fn attempt_phase_wire(phase: WorkspacePinAttemptPhaseV1) -> u8 {
    match phase {
        WorkspacePinAttemptPhaseV1::Ambiguous => 1,
        WorkspacePinAttemptPhaseV1::Satisfied => 2,
    }
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

fn bounded(bytes: &[u8], maximum: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= maximum
}

fn append_record(output: &mut Vec<u8>, record: &[u8]) -> Result<(), ZfsWorkerError> {
    let length = u32::try_from(record.len())
        .map_err(|_| ZfsWorkerError::Protocol("repair admission record is too long"))?;
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
                "repair admission request length overflow",
            ))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol(
                "repair admission request is truncated",
            ))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("repair admission field is invalid"))
    }

    fn u8(&mut self) -> Result<u8, ZfsWorkerError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn record(&mut self, maximum: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let record = self.optional_record(maximum)?;
        if record.is_empty() {
            return Err(ZfsWorkerError::Protocol(
                "repair admission record length is invalid",
            ));
        }
        Ok(record)
    }

    fn optional_record(&mut self, maximum: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ZfsWorkerError::Protocol("repair admission length does not fit usize"))?;
        if length > maximum {
            return Err(ZfsWorkerError::Protocol(
                "repair admission record length is invalid",
            ));
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol(
                "repair admission request has trailing bytes",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::workspace_pin::WorkspaceRootPinProofV1;
    use crate::{
        CatalogBindingV1, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ReservationPolicy, ResolvedDataset, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn catalog() -> ResolvedCatalogCommitmentV1 {
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

    fn binding() -> CatalogBindingV1 {
        CatalogBindingV1::from_publisher(8, ObjectDigest::from_bytes([31; 32])).unwrap()
    }

    fn pin_proof() -> WorkspaceRootPinProofV1 {
        WorkspaceRootPinProofV1::new(
            [41; 16],
            42,
            43,
            44,
            "/".to_owned(),
            crate::workspace_pin::workspace_pin_path(&[51; 32]),
            "zfs".to_owned(),
            "tank/aos/project/work".to_owned(),
            52,
            53,
            54,
        )
        .unwrap()
    }

    fn ensure_attempt(ordinal: u8, effect_operation_id: [u8; 16]) -> WorkspacePinAttemptV1 {
        WorkspacePinAttemptV1::new_ambiguous(
            [ordinal.wrapping_add(1); 16],
            ordinal,
            WorkspacePinActionV1::Ensure,
            effect_operation_id,
            [61; 16],
            ObjectDigest::from_bytes([62; 32]),
            ObjectDigest::from_bytes([63; 32]),
            ObjectDigest::from_bytes([64; 32]),
            binding(),
            ObjectDigest::from_bytes([65; 32]),
            [51; 32],
            [41; 16],
            42,
            43,
            [66; 16],
            1_000,
            "tank/aos/project/work".to_owned(),
            52,
            65_536,
            65_536,
            None,
        )
        .unwrap()
    }

    fn remove_attempt(ordinal: u8) -> WorkspacePinAttemptV1 {
        WorkspacePinAttemptV1::new_ambiguous(
            [ordinal.wrapping_add(1); 16],
            ordinal,
            WorkspacePinActionV1::RemoveAndDestroy,
            [70; 16],
            [61; 16],
            ObjectDigest::from_bytes([62; 32]),
            ObjectDigest::from_bytes([63; 32]),
            ObjectDigest::from_bytes([64; 32]),
            binding(),
            ObjectDigest::from_bytes([65; 32]),
            [51; 32],
            [41; 16],
            42,
            43,
            [66; 16],
            1_000,
            "tank/aos/project/work".to_owned(),
            52,
            65_536,
            65_536,
            Some(pin_proof()),
        )
        .unwrap()
    }

    fn matching_repair_intent(
        attempt: &WorkspacePinAttemptV1,
    ) -> StorageWorkspacePinRepairIntentV1 {
        StorageWorkspacePinRepairIntentV1::new_for_test(
            attempt.effect_operation_id(),
            [71; 16],
            ObjectDigest::from_bytes([72; 32]),
            ObjectDigest::from_bytes([73; 32]),
            attempt.effect_assignment_digest(),
            vec![74; 64],
            attempt.operation_fence_digest(),
            attempt.creation_operation_id(),
            attempt.creation_result_catalog(),
            attempt.creation_result_digest(),
            ObjectDigest::from_bytes([75; 32]),
            attempt.workspace_handle(),
            [76; 16],
            WorkspacePinAttemptPhaseV1::Ambiguous,
            ObjectDigest::from_bytes([77; 32]),
            attempt.attempt_id(),
            attempt.attempt_ordinal(),
        )
        .unwrap()
    }

    fn request(kind: WorkspacePinRepairPredecessorKindV1) -> WorkspacePinRepairAdmissionRequestV1 {
        WorkspacePinRepairAdmissionRequestV1::new(
            "/nix/store/hash-zfs/sbin/zfs".into(),
            [81; 16],
            [82; 16],
            [83; 16],
            ObjectDigest::from_bytes([84; 32]),
            ObjectDigest::from_bytes([85; 32]),
            ObjectDigest::from_bytes([86; 32]),
            [51; 32],
            kind,
            catalog(),
            vec![87; 128],
            vec![88; 129],
            match kind {
                WorkspacePinRepairPredecessorKindV1::Initial => Vec::new(),
                WorkspacePinRepairPredecessorKindV1::Repair => vec![89; 130],
            },
        )
        .unwrap()
    }

    #[test]
    fn request_round_trip_preserves_initial_and_repair_shapes() {
        for kind in [
            WorkspacePinRepairPredecessorKindV1::Initial,
            WorkspacePinRepairPredecessorKindV1::Repair,
        ] {
            let original = request(kind);
            let bytes = encode_request(&original).unwrap();
            let decoded = decode_request(&bytes).unwrap();

            assert_eq!(decoded.predecessor_kind, kind);
            assert_eq!(encode_request(&decoded).unwrap(), bytes);
        }
    }

    #[test]
    fn initial_ambiguous_and_previously_satisfied_ensure_are_repairable() {
        let ambiguous = ensure_attempt(1, [61; 16]);
        assert_eq!(
            classify_predecessor(&ambiguous, None, true).unwrap(),
            WorkspacePinRepairPredecessorKindV1::Initial
        );

        let satisfied = ambiguous.satisfy(Some(pin_proof())).unwrap();
        assert_eq!(
            classify_predecessor(&satisfied, None, true).unwrap(),
            WorkspacePinRepairPredecessorKindV1::Initial
        );
    }

    #[test]
    fn exact_repair_predecessor_is_repairable() {
        let attempt = ensure_attempt(2, [91; 16]);
        let intent = matching_repair_intent(&attempt);

        assert_eq!(
            classify_predecessor(&attempt, Some(&intent), true).unwrap(),
            WorkspacePinRepairPredecessorKindV1::Repair
        );
    }

    #[test]
    fn retired_remove_and_ordinal_cap_are_rejected() {
        let initial = ensure_attempt(1, [61; 16]);
        assert!(classify_predecessor(&initial, None, false).is_err());
        assert!(classify_predecessor(&remove_attempt(2), None, true).is_err());

        let capped = ensure_attempt(MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE, [92; 16]);
        let intent = matching_repair_intent(&capped);
        assert!(classify_predecessor(&capped, Some(&intent), true).is_err());
    }

    #[test]
    fn pure_result_validation_requires_exact_dataset_and_absent_pin() {
        let initial = ensure_attempt(1, [61; 16]);
        let request = request(WorkspacePinRepairPredecessorKindV1::Initial);
        let probe = bind_probe(
            &request,
            &initial,
            None,
            WorkspacePinHostScopeV1::new([93; 16], 94, 95).unwrap(),
        )
        .unwrap();
        let exact = WorkspacePinWorkerResultV1::new(
            initial.attempt_id(),
            WorkspaceDatasetObservationV1::Exact {
                name: initial.dataset_name().to_owned(),
                guid: initial.dataset_guid(),
            },
            WorkspacePinObservationV1::Absent,
            ObjectDigest::from_bytes([96; 32]),
        );
        let validated = ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
            &probe,
            WorkspacePinRepairAdmissionResultV1::new(probe.digest(), exact),
        )
        .unwrap();
        assert!(validated.matches_probe(&probe));

        let present = WorkspacePinWorkerResultV1::new(
            initial.attempt_id(),
            WorkspaceDatasetObservationV1::Exact {
                name: initial.dataset_name().to_owned(),
                guid: initial.dataset_guid(),
            },
            WorkspacePinObservationV1::Present(pin_proof()),
            ObjectDigest::from_bytes([97; 32]),
        );
        assert!(
            ValidatedWorkspacePinRepairAdmissionObservationV1::from_result(
                &probe,
                WorkspacePinRepairAdmissionResultV1::new(probe.digest(), present),
            )
            .is_err()
        );
    }
}
