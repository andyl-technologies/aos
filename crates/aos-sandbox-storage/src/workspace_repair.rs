//! Authenticated durable admission intents for workspace root-pin repair.
//!
//! A repair intent is committed atomically with the fresh repair attempt and
//! the broker's current authority records before any worker may run. Its
//! `Ambiguous` phase is immutable: once present, recovery may observe the
//! linked attempt but must never dispatch that authority again.
//! `admitted-effect-record-digest` commits the exact Pending admission bytes;
//! it is retained evidence and is not recomputed from a later mutable Effect
//! status during replay.
//!
//! ```text
//! AOSRPI01 | version:u16 | key-id:16
//! repair-operation:16 | request-id:16 | transport-request-digest:32
//! semantic-commitment:32 | repair-assignment-digest:32
//! admitted-effect-record-digest:32 | admitted-effect-record:(len:u32,bytes)
//! operation-fence-digest:32
//! creation-operation:16 | creation-result-catalog:(generation:u64,digest:32)
//! creation-result-digest:32 | publication-intent-record-digest:32
//! workspace-handle:32 | latest-ensure-attempt-id:16
//! latest-ensure-phase:u8 | latest-ensure-record-digest:32
//! repair-attempt-id:16
//! repair-attempt-ordinal:u8 | intent-phase:u8 | hmac-sha256:32
//! ```

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_broker::{BrokerEffectIntentV2, BrokerEffectStatusV2};
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb, ObjectDigest};
use hmac::{Hmac, Mac as _};
use sha2::Digest as _;

use crate::workspace_pin::{
    WorkspaceDatasetObservationV1, WorkspacePinAttemptPhaseV1, WorkspacePinHostScopeV1,
    WorkspacePinObservationV1,
};
use crate::{CatalogBindingV1, StorageStateError};

type HmacSha256 = Hmac<sha2::Sha256>;

const MAGIC: &[u8; 8] = b"AOSRPI01";
const VERSION: u16 = 1;
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-repair-intent.v1\0";
const PROBE_DOMAIN: &[u8] = b"aos.sandbox.storage.workspace-pin-repair-probe.v1\0";
const MAC_BYTES: usize = 32;
const FIXED_ENCODED_BYTES: usize = 8
    + 2
    + 16
    + 16
    + 16
    + 32
    + 32
    + 32
    + 32
    + 4
    + 32
    + 16
    + 8
    + 32
    + 32
    + 32
    + 32
    + 16
    + 1
    + 32
    + 16
    + 1
    + 1
    + MAC_BYTES;
const MAXIMUM_ADMITTED_EFFECT_RECORD_BYTES: usize = 64 * 1024;

/// Identifies the irreversible crash boundary of repair admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspacePinRepairIntentPhaseV1 {
    /// Dispatch eligibility was consumed; recovery is observation-only.
    Ambiguous,
}

impl WorkspacePinRepairIntentPhaseV1 {
    const fn wire(self) -> u8 {
        match self {
            Self::Ambiguous => 1,
        }
    }

    fn from_wire(value: u8) -> Result<Self, StorageStateError> {
        match value {
            1 => Ok(Self::Ambiguous),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }
}

/// Cross-links one fresh repair authorization to immutable workspace history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageWorkspacePinRepairIntentV1 {
    repair_operation_id: [u8; 16],
    request_id: [u8; 16],
    request_digest: ObjectDigest,
    semantic_commitment: ObjectDigest,
    repair_assignment_digest: ObjectDigest,
    admitted_effect_record_digest: ObjectDigest,
    admitted_effect_record: Vec<u8>,
    operation_fence_digest: ObjectDigest,
    creation_operation_id: [u8; 16],
    creation_result_catalog: CatalogBindingV1,
    creation_result_digest: ObjectDigest,
    publication_intent_record_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    latest_ensure_attempt_id: [u8; 16],
    latest_ensure_phase: crate::workspace_pin::WorkspacePinAttemptPhaseV1,
    latest_ensure_attempt_record_digest: ObjectDigest,
    repair_attempt_id: [u8; 16],
    repair_attempt_ordinal: u8,
    phase: WorkspacePinRepairIntentPhaseV1,
}

impl StorageWorkspacePinRepairIntentV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_ambiguous(
        repair_operation_id: [u8; 16],
        admitted_effect: &BrokerEffectIntentV2,
        admitted_effect_record: Vec<u8>,
        repair_assignment_digest: ObjectDigest,
        operation_fence_digest: ObjectDigest,
        creation_operation_id: [u8; 16],
        creation_result_catalog: CatalogBindingV1,
        creation_result_digest: ObjectDigest,
        publication_intent_record_digest: ObjectDigest,
        workspace_handle: [u8; 32],
        latest_ensure_attempt_id: [u8; 16],
        latest_ensure_phase: crate::workspace_pin::WorkspacePinAttemptPhaseV1,
        latest_ensure_attempt_record_digest: ObjectDigest,
        repair_attempt_id: [u8; 16],
        repair_attempt_ordinal: u8,
    ) -> Result<Self, StorageStateError> {
        if admitted_effect.status() != BrokerEffectStatusV2::Pending
            || admitted_effect.verb() != BrokerVerb::StorageRepairWorkspacePin
            || admitted_effect.target()
                != BrokerGrantTarget::Resource(
                    aos_sandbox_core::BrokerResourceHandle::from_bytes(workspace_handle)
                        .map_err(|_| StorageStateError::InvalidValue)?,
                )
        {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        let intent = Self {
            repair_operation_id,
            request_id: *admitted_effect.request_id(),
            request_digest: admitted_effect.transport_request_digest(),
            semantic_commitment: admitted_effect.request_digest(),
            repair_assignment_digest,
            admitted_effect_record_digest: digest_bytes(&admitted_effect_record),
            admitted_effect_record,
            operation_fence_digest,
            creation_operation_id,
            creation_result_catalog,
            creation_result_digest,
            publication_intent_record_digest,
            workspace_handle,
            latest_ensure_attempt_id,
            latest_ensure_phase,
            latest_ensure_attempt_record_digest,
            repair_attempt_id,
            repair_attempt_ordinal,
            phase: WorkspacePinRepairIntentPhaseV1::Ambiguous,
        };
        intent.validate()?;
        Ok(intent)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_test(
        repair_operation_id: [u8; 16],
        request_id: [u8; 16],
        request_digest: ObjectDigest,
        semantic_commitment: ObjectDigest,
        repair_assignment_digest: ObjectDigest,
        admitted_effect_record: Vec<u8>,
        operation_fence_digest: ObjectDigest,
        creation_operation_id: [u8; 16],
        creation_result_catalog: CatalogBindingV1,
        creation_result_digest: ObjectDigest,
        publication_intent_record_digest: ObjectDigest,
        workspace_handle: [u8; 32],
        latest_ensure_attempt_id: [u8; 16],
        latest_ensure_phase: WorkspacePinAttemptPhaseV1,
        latest_ensure_attempt_record_digest: ObjectDigest,
        repair_attempt_id: [u8; 16],
        repair_attempt_ordinal: u8,
    ) -> Result<Self, StorageStateError> {
        let intent = Self {
            repair_operation_id,
            request_id,
            request_digest,
            semantic_commitment,
            repair_assignment_digest,
            admitted_effect_record_digest: digest_bytes(&admitted_effect_record),
            admitted_effect_record,
            operation_fence_digest,
            creation_operation_id,
            creation_result_catalog,
            creation_result_digest,
            publication_intent_record_digest,
            workspace_handle,
            latest_ensure_attempt_id,
            latest_ensure_phase,
            latest_ensure_attempt_record_digest,
            repair_attempt_id,
            repair_attempt_ordinal,
            phase: WorkspacePinRepairIntentPhaseV1::Ambiguous,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), StorageStateError> {
        if self.repair_operation_id == [0; 16]
            || self.repair_operation_id == self.creation_operation_id
            || self.request_id == [0; 16]
            || self.request_digest.as_bytes() == &[0; 32]
            || self.semantic_commitment.as_bytes() == &[0; 32]
            || self.repair_assignment_digest.as_bytes() == &[0; 32]
            || self.admitted_effect_record_digest.as_bytes() == &[0; 32]
            || self.admitted_effect_record.is_empty()
            || self.admitted_effect_record.len() > MAXIMUM_ADMITTED_EFFECT_RECORD_BYTES
            || digest_bytes(&self.admitted_effect_record) != self.admitted_effect_record_digest
            || self.operation_fence_digest.as_bytes() == &[0; 32]
            || self.creation_operation_id == [0; 16]
            || self.creation_result_catalog.generation() == 0
            || self.creation_result_catalog.digest().as_bytes() == &[0; 32]
            || self.creation_result_digest.as_bytes() == &[0; 32]
            || self.publication_intent_record_digest.as_bytes() == &[0; 32]
            || self.workspace_handle == [0; 32]
            || self.latest_ensure_attempt_id == [0; 16]
            || self.latest_ensure_attempt_record_digest.as_bytes() == &[0; 32]
            || self.repair_attempt_id == [0; 16]
            || self.latest_ensure_attempt_id == self.repair_attempt_id
            || !(2..=crate::workspace_pin::MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE)
                .contains(&self.repair_attempt_ordinal)
        {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) const fn repair_operation_id(&self) -> [u8; 16] {
        self.repair_operation_id
    }

    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub(crate) const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    pub(crate) const fn semantic_commitment(&self) -> ObjectDigest {
        self.semantic_commitment
    }

    pub(crate) const fn repair_assignment_digest(&self) -> ObjectDigest {
        self.repair_assignment_digest
    }

    pub(crate) const fn admitted_effect_record_digest(&self) -> ObjectDigest {
        self.admitted_effect_record_digest
    }

    pub(crate) fn admitted_effect_record(&self) -> &[u8] {
        &self.admitted_effect_record
    }

    pub(crate) const fn operation_fence_digest(&self) -> ObjectDigest {
        self.operation_fence_digest
    }

    pub(crate) const fn creation_operation_id(&self) -> [u8; 16] {
        self.creation_operation_id
    }

    pub(crate) const fn creation_result_catalog(&self) -> CatalogBindingV1 {
        self.creation_result_catalog
    }

    pub(crate) const fn creation_result_digest(&self) -> ObjectDigest {
        self.creation_result_digest
    }

    pub(crate) const fn publication_intent_record_digest(&self) -> ObjectDigest {
        self.publication_intent_record_digest
    }

    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }

    pub(crate) const fn latest_ensure_attempt_id(&self) -> [u8; 16] {
        self.latest_ensure_attempt_id
    }

    pub(crate) const fn latest_ensure_phase(
        &self,
    ) -> crate::workspace_pin::WorkspacePinAttemptPhaseV1 {
        self.latest_ensure_phase
    }

    pub(crate) const fn latest_ensure_attempt_record_digest(&self) -> ObjectDigest {
        self.latest_ensure_attempt_record_digest
    }

    pub(crate) const fn repair_attempt_id(&self) -> [u8; 16] {
        self.repair_attempt_id
    }

    pub(crate) const fn repair_attempt_ordinal(&self) -> u8 {
        self.repair_attempt_ordinal
    }
}

/// Carries an observation-only challenge derived from protected current state.
///
/// This request contains no effect authority. Historical attempt scope is
/// committed by record digest, while `current_host_scope` independently binds
/// the namespace in which the fresh observation must run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspacePinRepairProbeV1 {
    generated_challenge: [u8; 16],
    repair_operation_id: [u8; 16],
    repair_intent_record_digest: ObjectDigest,
    request_digest: ObjectDigest,
    semantic_commitment: ObjectDigest,
    creation_operation_id: [u8; 16],
    creation_result_catalog: CatalogBindingV1,
    creation_result_digest: ObjectDigest,
    publication_intent_record_digest: ObjectDigest,
    workspace_handle: [u8; 32],
    latest_ensure_attempt_id: [u8; 16],
    latest_ensure_attempt_ordinal: u8,
    latest_ensure_attempt_phase: WorkspacePinAttemptPhaseV1,
    latest_ensure_attempt_record_digest: ObjectDigest,
    historical_attempt_host_scope: WorkspacePinHostScopeV1,
    current_host_scope: WorkspacePinHostScopeV1,
    dataset_name: String,
    dataset_guid: u64,
    identity_range_start: u32,
    identity_range_size: u32,
}

impl WorkspacePinRepairProbeV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generated_challenge: [u8; 16],
        repair_operation_id: [u8; 16],
        repair_intent_record_digest: ObjectDigest,
        request_digest: ObjectDigest,
        semantic_commitment: ObjectDigest,
        creation_operation_id: [u8; 16],
        creation_result_catalog: CatalogBindingV1,
        creation_result_digest: ObjectDigest,
        publication_intent_record_digest: ObjectDigest,
        workspace_handle: [u8; 32],
        latest_ensure_attempt_id: [u8; 16],
        latest_ensure_attempt_ordinal: u8,
        latest_ensure_attempt_phase: WorkspacePinAttemptPhaseV1,
        latest_ensure_attempt_record_digest: ObjectDigest,
        historical_attempt_host_scope: WorkspacePinHostScopeV1,
        current_host_scope: WorkspacePinHostScopeV1,
        dataset_name: String,
        dataset_guid: u64,
        identity_range_start: u32,
        identity_range_size: u32,
    ) -> Result<Self, StorageStateError> {
        let probe = Self {
            generated_challenge,
            repair_operation_id,
            repair_intent_record_digest,
            request_digest,
            semantic_commitment,
            creation_operation_id,
            creation_result_catalog,
            creation_result_digest,
            publication_intent_record_digest,
            workspace_handle,
            latest_ensure_attempt_id,
            latest_ensure_attempt_ordinal,
            latest_ensure_attempt_phase,
            latest_ensure_attempt_record_digest,
            historical_attempt_host_scope,
            current_host_scope,
            dataset_name,
            dataset_guid,
            identity_range_start,
            identity_range_size,
        };
        probe.validate()?;
        Ok(probe)
    }

    fn validate(&self) -> Result<(), StorageStateError> {
        if self.generated_challenge == [0; 16]
            || self.repair_operation_id == [0; 16]
            || self.repair_operation_id == self.creation_operation_id
            || self.repair_intent_record_digest.as_bytes() == &[0; 32]
            || self.request_digest.as_bytes() == &[0; 32]
            || self.semantic_commitment.as_bytes() == &[0; 32]
            || self.creation_operation_id == [0; 16]
            || self.creation_result_catalog.generation() == 0
            || self.creation_result_catalog.digest().as_bytes() == &[0; 32]
            || self.creation_result_digest.as_bytes() == &[0; 32]
            || self.publication_intent_record_digest.as_bytes() == &[0; 32]
            || self.workspace_handle == [0; 32]
            || self.latest_ensure_attempt_id == [0; 16]
            || !(1..=crate::workspace_pin::MAXIMUM_PIN_ATTEMPTS_PER_WORKSPACE)
                .contains(&self.latest_ensure_attempt_ordinal)
            || self.latest_ensure_attempt_phase != WorkspacePinAttemptPhaseV1::Ambiguous
            || self.latest_ensure_attempt_record_digest.as_bytes() == &[0; 32]
            || self.dataset_name.is_empty()
            || self.dataset_name.len() > 512
            || self.dataset_name.as_bytes().contains(&0)
            || self.dataset_guid == 0
            || self.identity_range_start == 0
            || self.identity_range_size == 0
            || self
                .identity_range_start
                .checked_add(self.identity_range_size)
                .is_none()
        {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> ObjectDigest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(PROBE_DOMAIN);
        hasher.update(self.generated_challenge);
        hasher.update(self.repair_operation_id);
        hasher.update(self.repair_intent_record_digest.as_bytes());
        hasher.update(self.request_digest.as_bytes());
        hasher.update(self.semantic_commitment.as_bytes());
        hasher.update(self.creation_operation_id);
        hasher.update(self.creation_result_catalog.generation().to_be_bytes());
        hasher.update(self.creation_result_catalog.digest().as_bytes());
        hasher.update(self.creation_result_digest.as_bytes());
        hasher.update(self.publication_intent_record_digest.as_bytes());
        hasher.update(self.workspace_handle);
        hasher.update(self.latest_ensure_attempt_id);
        hasher.update([self.latest_ensure_attempt_ordinal]);
        hasher.update([attempt_phase_wire(self.latest_ensure_attempt_phase)]);
        hasher.update(self.latest_ensure_attempt_record_digest.as_bytes());
        hasher.update(self.historical_attempt_host_scope.kernel_boot_id());
        hasher.update(
            self.historical_attempt_host_scope
                .mount_namespace_device()
                .to_be_bytes(),
        );
        hasher.update(
            self.historical_attempt_host_scope
                .mount_namespace_inode()
                .to_be_bytes(),
        );
        hasher.update(self.current_host_scope.kernel_boot_id());
        hasher.update(
            self.current_host_scope
                .mount_namespace_device()
                .to_be_bytes(),
        );
        hasher.update(
            self.current_host_scope
                .mount_namespace_inode()
                .to_be_bytes(),
        );
        hasher.update(
            u16::try_from(self.dataset_name.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hasher.update(self.dataset_name.as_bytes());
        hasher.update(self.dataset_guid.to_be_bytes());
        hasher.update(self.identity_range_start.to_be_bytes());
        hasher.update(self.identity_range_size.to_be_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }

    pub(crate) const fn repair_operation_id(&self) -> [u8; 16] {
        self.repair_operation_id
    }

    pub(crate) const fn repair_intent_record_digest(&self) -> ObjectDigest {
        self.repair_intent_record_digest
    }

    pub(crate) const fn publication_intent_record_digest(&self) -> ObjectDigest {
        self.publication_intent_record_digest
    }

    pub(crate) const fn latest_ensure_attempt_record_digest(&self) -> ObjectDigest {
        self.latest_ensure_attempt_record_digest
    }

    pub(crate) const fn historical_attempt_host_scope(&self) -> WorkspacePinHostScopeV1 {
        self.historical_attempt_host_scope
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

    pub(crate) const fn workspace_handle(&self) -> [u8; 32] {
        self.workspace_handle
    }
}

/// Returns a fresh observation bound to one exact read-only repair probe.
///
/// This value deliberately does not implement `Clone`; admission consumes it
/// once while retaining the same exclusive transaction lock.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WorkspacePinRepairProbeResultV1 {
    probe_digest: ObjectDigest,
    dataset: WorkspaceDatasetObservationV1,
    pin: WorkspacePinObservationV1,
}

impl WorkspacePinRepairProbeResultV1 {
    pub(crate) fn bind(
        probe: &WorkspacePinRepairProbeV1,
        dataset: WorkspaceDatasetObservationV1,
        pin: WorkspacePinObservationV1,
    ) -> Self {
        Self {
            probe_digest: probe.digest(),
            dataset,
            pin,
        }
    }

    pub(crate) fn consume(
        self,
        probe: &WorkspacePinRepairProbeV1,
    ) -> Result<(WorkspaceDatasetObservationV1, WorkspacePinObservationV1), StorageStateError> {
        if self.probe_digest != probe.digest() {
            return Err(StorageStateError::AuthorityLinkMismatch);
        }
        Ok((self.dataset, self.pin))
    }
}

const fn attempt_phase_wire(phase: WorkspacePinAttemptPhaseV1) -> u8 {
    match phase {
        WorkspacePinAttemptPhaseV1::Ambiguous => 1,
        WorkspacePinAttemptPhaseV1::Satisfied => 2,
    }
}

pub(crate) fn load_repair_intents(
    journal: &Journal,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<BTreeMap<[u8; 16], StorageWorkspacePinRepairIntentV1>, StorageStateError> {
    let mut intents = BTreeMap::new();
    for (record_key, bytes) in journal.records(RecordNamespace::StorageWorkspacePinRepairIntent) {
        let intent = decode_intent(bytes, key_id, secret)?;
        if record_key != intent.repair_operation_id()
            || intents
                .insert(intent.repair_operation_id(), intent)
                .is_some()
        {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    Ok(intents)
}

pub(crate) fn repair_intent_record(
    intent: &StorageWorkspacePinRepairIntentV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<JournalRecord, StorageStateError> {
    Ok(JournalRecord::put(
        RecordNamespace::StorageWorkspacePinRepairIntent,
        intent.repair_operation_id().to_vec(),
        encode_intent(intent, key_id, secret)?,
    ))
}

fn encode_intent(
    intent: &StorageWorkspacePinRepairIntentV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    intent.validate()?;
    let mut bytes = Vec::with_capacity(FIXED_ENCODED_BYTES + intent.admitted_effect_record.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&key_id);
    bytes.extend_from_slice(&intent.repair_operation_id);
    bytes.extend_from_slice(&intent.request_id);
    bytes.extend_from_slice(intent.request_digest.as_bytes());
    bytes.extend_from_slice(intent.semantic_commitment.as_bytes());
    bytes.extend_from_slice(intent.repair_assignment_digest.as_bytes());
    bytes.extend_from_slice(intent.admitted_effect_record_digest.as_bytes());
    let effect_record_length = u32::try_from(intent.admitted_effect_record.len())
        .map_err(|_| StorageStateError::InvalidValue)?;
    bytes.extend_from_slice(&effect_record_length.to_be_bytes());
    bytes.extend_from_slice(&intent.admitted_effect_record);
    bytes.extend_from_slice(intent.operation_fence_digest.as_bytes());
    bytes.extend_from_slice(&intent.creation_operation_id);
    bytes.extend_from_slice(&intent.creation_result_catalog.generation().to_be_bytes());
    bytes.extend_from_slice(intent.creation_result_catalog.digest().as_bytes());
    bytes.extend_from_slice(intent.creation_result_digest.as_bytes());
    bytes.extend_from_slice(intent.publication_intent_record_digest.as_bytes());
    bytes.extend_from_slice(&intent.workspace_handle);
    bytes.extend_from_slice(&intent.latest_ensure_attempt_id);
    bytes.push(match intent.latest_ensure_phase {
        crate::workspace_pin::WorkspacePinAttemptPhaseV1::Ambiguous => 1,
        crate::workspace_pin::WorkspacePinAttemptPhaseV1::Satisfied => 2,
    });
    bytes.extend_from_slice(intent.latest_ensure_attempt_record_digest.as_bytes());
    bytes.extend_from_slice(&intent.repair_attempt_id);
    bytes.push(intent.repair_attempt_ordinal);
    bytes.push(intent.phase.wire());
    let tag = record_tag(secret, &intent.repair_operation_id, &bytes)?;
    bytes.extend_from_slice(&tag);
    debug_assert_eq!(
        bytes.len(),
        FIXED_ENCODED_BYTES + intent.admitted_effect_record.len()
    );
    Ok(bytes)
}

pub(crate) fn decode_intent(
    bytes: &[u8],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<StorageWorkspacePinRepairIntentV1, StorageStateError> {
    if bytes.len() < FIXED_ENCODED_BYTES + 1
        || bytes.len() > FIXED_ENCODED_BYTES + MAXIMUM_ADMITTED_EFFECT_RECORD_BYTES
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let (body, supplied_tag) = bytes.split_at(bytes.len() - MAC_BYTES);
    let mut decoder = Decoder::new(body);
    if decoder.array::<8>()? != *MAGIC
        || decoder.u16()? != VERSION
        || decoder.array::<16>()? != key_id
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let repair_operation_id = decoder.array::<16>()?;
    let expected_tag = record_tag(secret, &repair_operation_id, body)?;
    if !constant_time_eq(supplied_tag, &expected_tag) {
        return Err(StorageStateError::CorruptRecord);
    }
    let request_id = decoder.array()?;
    let request_digest = ObjectDigest::from_bytes(decoder.array()?);
    let semantic_commitment = ObjectDigest::from_bytes(decoder.array()?);
    let repair_assignment_digest = ObjectDigest::from_bytes(decoder.array()?);
    let admitted_effect_record_digest = ObjectDigest::from_bytes(decoder.array()?);
    let effect_record_length =
        usize::try_from(decoder.u32()?).map_err(|_| StorageStateError::CorruptRecord)?;
    if effect_record_length == 0 || effect_record_length > MAXIMUM_ADMITTED_EFFECT_RECORD_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    let admitted_effect_record = decoder.take(effect_record_length)?.to_vec();
    let intent = StorageWorkspacePinRepairIntentV1 {
        repair_operation_id,
        request_id,
        request_digest,
        semantic_commitment,
        repair_assignment_digest,
        admitted_effect_record_digest,
        admitted_effect_record,
        operation_fence_digest: ObjectDigest::from_bytes(decoder.array()?),
        creation_operation_id: decoder.array()?,
        creation_result_catalog: CatalogBindingV1::from_publisher(
            decoder.u64()?,
            ObjectDigest::from_bytes(decoder.array()?),
        )
        .map_err(|_| StorageStateError::CorruptRecord)?,
        creation_result_digest: ObjectDigest::from_bytes(decoder.array()?),
        publication_intent_record_digest: ObjectDigest::from_bytes(decoder.array()?),
        workspace_handle: decoder.array()?,
        latest_ensure_attempt_id: decoder.array()?,
        latest_ensure_phase: match decoder.u8()? {
            1 => crate::workspace_pin::WorkspacePinAttemptPhaseV1::Ambiguous,
            2 => crate::workspace_pin::WorkspacePinAttemptPhaseV1::Satisfied,
            _ => return Err(StorageStateError::CorruptRecord),
        },
        latest_ensure_attempt_record_digest: ObjectDigest::from_bytes(decoder.array()?),
        repair_attempt_id: decoder.array()?,
        repair_attempt_ordinal: decoder.u8()?,
        phase: WorkspacePinRepairIntentPhaseV1::from_wire(decoder.u8()?)?,
    };
    if !decoder.is_empty() {
        return Err(StorageStateError::CorruptRecord);
    }
    intent
        .validate()
        .map_err(|_| StorageStateError::CorruptRecord)?;
    Ok(intent)
}

fn record_tag(
    secret: &[u8; 32],
    repair_operation_id: &[u8; 16],
    body: &[u8],
) -> Result<[u8; 32], StorageStateError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(RECORD_DOMAIN);
    mac.update(&[RecordNamespace::StorageWorkspacePinRepairIntent as u8]);
    mac.update(repair_operation_id);
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageStateError::CorruptRecord)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageStateError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageStateError::CorruptRecord)
    }

    fn u8(&mut self) -> Result<u8, StorageStateError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(StorageStateError::CorruptRecord)
    }

    fn u16(&mut self) -> Result<u16, StorageStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, StorageStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StorageStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn digest_bytes(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(sha2::Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY_ID: [u8; 16] = [1; 16];
    const SECRET: [u8; 32] = [2; 32];

    fn intent() -> StorageWorkspacePinRepairIntentV1 {
        let admitted_effect_record = vec![9; 17];
        StorageWorkspacePinRepairIntentV1 {
            repair_operation_id: [3; 16],
            request_id: [4; 16],
            request_digest: ObjectDigest::from_bytes([5; 32]),
            semantic_commitment: ObjectDigest::from_bytes([6; 32]),
            repair_assignment_digest: ObjectDigest::from_bytes([7; 32]),
            admitted_effect_record_digest: digest_bytes(&admitted_effect_record),
            admitted_effect_record,
            operation_fence_digest: ObjectDigest::from_bytes([9; 32]),
            creation_operation_id: [10; 16],
            creation_result_catalog: CatalogBindingV1::from_publisher(
                11,
                ObjectDigest::from_bytes([12; 32]),
            )
            .unwrap(),
            creation_result_digest: ObjectDigest::from_bytes([13; 32]),
            publication_intent_record_digest: ObjectDigest::from_bytes([14; 32]),
            workspace_handle: [15; 32],
            latest_ensure_attempt_id: [16; 16],
            latest_ensure_phase: WorkspacePinAttemptPhaseV1::Ambiguous,
            latest_ensure_attempt_record_digest: ObjectDigest::from_bytes([18; 32]),
            repair_attempt_id: [17; 16],
            repair_attempt_ordinal: 2,
            phase: WorkspacePinRepairIntentPhaseV1::Ambiguous,
        }
    }

    fn probe() -> WorkspacePinRepairProbeV1 {
        WorkspacePinRepairProbeV1::new(
            [21; 16],
            [22; 16],
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
            ObjectDigest::from_bytes([25; 32]),
            [26; 16],
            CatalogBindingV1::from_publisher(27, ObjectDigest::from_bytes([28; 32])).unwrap(),
            ObjectDigest::from_bytes([29; 32]),
            ObjectDigest::from_bytes([30; 32]),
            [31; 32],
            [32; 16],
            1,
            WorkspacePinAttemptPhaseV1::Ambiguous,
            ObjectDigest::from_bytes([33; 32]),
            WorkspacePinHostScopeV1::new([34; 16], 35, 36).unwrap(),
            WorkspacePinHostScopeV1::new([40; 16], 41, 42).unwrap(),
            "tank/aos/workspace".to_owned(),
            37,
            38,
            39,
        )
        .unwrap()
    }

    #[test]
    fn repair_intent_round_trips_exact_authenticated_fields() {
        let original = intent();
        let encoded = encode_intent(&original, KEY_ID, &SECRET).unwrap();

        assert_eq!(encoded.len(), FIXED_ENCODED_BYTES + 17);
        assert_eq!(decode_intent(&encoded, KEY_ID, &SECRET).unwrap(), original);

        let mut satisfied_history = intent();
        satisfied_history.latest_ensure_phase = WorkspacePinAttemptPhaseV1::Satisfied;
        let encoded = encode_intent(&satisfied_history, KEY_ID, &SECRET).unwrap();
        assert_eq!(
            decode_intent(&encoded, KEY_ID, &SECRET).unwrap(),
            satisfied_history
        );
    }

    #[test]
    fn repair_intent_rejects_every_authenticated_bit_flip() {
        let encoded = encode_intent(&intent(), KEY_ID, &SECRET).unwrap();
        for offset in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[offset] ^= 1;
            assert!(decode_intent(&corrupted, KEY_ID, &SECRET).is_err());
        }
    }

    #[test]
    fn repair_intent_rejects_wrong_key_truncation_and_reserved_values() {
        let encoded = encode_intent(&intent(), KEY_ID, &SECRET).unwrap();
        assert!(decode_intent(&encoded, [16; 16], &SECRET).is_err());
        assert!(decode_intent(&encoded[..encoded.len() - 1], KEY_ID, &SECRET).is_err());

        let mut invalid = intent();
        invalid.repair_attempt_ordinal = 1;
        assert!(matches!(
            invalid.validate(),
            Err(StorageStateError::InvalidValue)
        ));
        invalid = intent();
        invalid.latest_ensure_attempt_id = invalid.repair_attempt_id;
        assert!(matches!(
            invalid.validate(),
            Err(StorageStateError::InvalidValue)
        ));
        invalid = intent();
        invalid.repair_operation_id = invalid.creation_operation_id;
        assert!(matches!(
            invalid.validate(),
            Err(StorageStateError::InvalidValue)
        ));
        invalid = intent();
        invalid.admitted_effect_record[0] ^= 1;
        assert!(matches!(
            invalid.validate(),
            Err(StorageStateError::InvalidValue)
        ));
    }

    #[test]
    fn repair_probe_binds_fresh_scope_history_and_single_consumption() {
        let original = probe();
        let mut changed_scope = original.clone();
        changed_scope.current_host_scope = WorkspacePinHostScopeV1::new([32; 16], 33, 99).unwrap();
        assert_ne!(original.digest(), changed_scope.digest());

        let mut changed_historical_scope = original.clone();
        changed_historical_scope.historical_attempt_host_scope =
            WorkspacePinHostScopeV1::new([32; 16], 98, 99).unwrap();
        assert_ne!(original.digest(), changed_historical_scope.digest());

        let mut changed_history = original.clone();
        changed_history.latest_ensure_attempt_phase = WorkspacePinAttemptPhaseV1::Satisfied;
        assert_ne!(original.digest(), changed_history.digest());

        let result = WorkspacePinRepairProbeResultV1::bind(
            &original,
            WorkspaceDatasetObservationV1::Exact {
                name: original.dataset_name().to_owned(),
                guid: original.dataset_guid(),
            },
            WorkspacePinObservationV1::Absent,
        );
        assert!(result.consume(&changed_scope).is_err());

        let result = WorkspacePinRepairProbeResultV1::bind(
            &original,
            WorkspaceDatasetObservationV1::Exact {
                name: original.dataset_name().to_owned(),
                guid: original.dataset_guid(),
            },
            WorkspacePinObservationV1::Absent,
        );
        assert!(matches!(
            result.consume(&original),
            Ok((
                WorkspaceDatasetObservationV1::Exact { .. },
                WorkspacePinObservationV1::Absent
            ))
        ));
    }
}
