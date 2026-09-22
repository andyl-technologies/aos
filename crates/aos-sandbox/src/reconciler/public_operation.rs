//! Durable public metadata and established operation-resource projection.
//!
//! Public metadata is appended only to V2 operation records. The fixed-width
//! representation keeps method, accepted generation, audit identity, and
//! timestamps restart-stable while the enclosing operation record remains the
//! atomic state-transition authority.

use aos_proto::aos::sandbox::v1::{
    Operation, OperationPhase, OperationProgress, RetryClass, Timestamp,
};
use aos_sandbox_core::{OperationId, ProjectId, ResourceKind, Selector};
use sha2::{Digest as _, Sha256};

use crate::controller_query::PublicOperationMethodV1;

use super::{OperationState, ReconcilerError};

pub(super) const PUBLIC_OPERATION_RECORD_BYTES: usize = 64;
const PUBLIC_OPERATION_RESOURCE_VERSION_DOMAIN: &[u8] =
    b"aos.sandbox.public-operation-resource-version.v1\0";
const PUBLIC_OPERATION_AUTHORIZATION_MAGIC: &[u8; 8] = b"AOSOPAU1";
const PUBLIC_OPERATION_AUTHORIZATION_VERSION: u16 = 1;
const PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"aos.sandbox.public-operation-authorization.v1\0";
const PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES: usize = 68;
const MAXIMUM_AUTHORIZATION_SELECTOR_BYTES: usize = 64 * 1024;
const NO_COMPLETION_TIMESTAMP: i64 = i64::MIN;
const MINIMUM_PROTO_SECONDS: i64 = -62_135_596_800;
const MAXIMUM_PROTO_SECONDS: i64 = 253_402_300_799;

/// Supplies immutable public fields when admitting an operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOperationAdmissionV1 {
    method: PublicOperationMethodV1,
    accepted_generation: u64,
    audit_id: [u8; 16],
    accepted_wall_seconds: i64,
    authorization: PublicOperationAuthorizationV1,
}

/// Binds a public operation to its project and capability selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOperationAuthorizationV1 {
    project: ProjectId,
    resource_kind: ResourceKind,
    selector: Selector,
}

impl PublicOperationAuthorizationV1 {
    /// Constructs an immutable current-authorization scope.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for a zero project identity or
    /// a selector whose canonical JSON encoding exceeds the durable bound.
    pub fn new(
        project: ProjectId,
        resource_kind: ResourceKind,
        selector: Selector,
    ) -> Result<Self, ReconcilerError> {
        if project.as_bytes() == &[0; 16] {
            return Err(ReconcilerError::InvalidPlan(
                "public operation authorization has a zero project",
            ));
        }
        let encoded = serde_json::to_vec(&selector).map_err(|_| {
            ReconcilerError::InvalidPlan("public operation selector cannot be encoded")
        })?;
        if encoded.is_empty() || encoded.len() > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "public operation selector exceeds its durable bound",
            ));
        }

        Ok(Self {
            project,
            resource_kind,
            selector,
        })
    }

    /// Returns the project boundary fixed at operation admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the closed capability resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Returns the exact logical capability selector.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, ReconcilerError> {
        let selector = serde_json::to_vec(&self.selector).map_err(|_| {
            ReconcilerError::InvalidPlan("public operation selector cannot be encoded")
        })?;
        if selector.is_empty() || selector.len() > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "public operation selector exceeds its durable bound",
            ));
        }
        let selector_length = u32::try_from(selector.len()).map_err(|_| {
            ReconcilerError::InvalidPlan("public operation selector exceeds its durable bound")
        })?;
        let mut bytes =
            Vec::with_capacity(PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES + selector.len());
        bytes.extend_from_slice(PUBLIC_OPERATION_AUTHORIZATION_MAGIC);
        bytes.extend_from_slice(&PUBLIC_OPERATION_AUTHORIZATION_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.push(resource_kind_code(self.resource_kind));
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&selector_length.to_be_bytes());
        bytes.extend_from_slice(&selector);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, ReconcilerError> {
        if bytes.len() < PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES
            || &bytes[..8] != PUBLIC_OPERATION_AUTHORIZATION_MAGIC
            || u16::from_be_bytes(read_array(&bytes[8..10])?)
                != PUBLIC_OPERATION_AUTHORIZATION_VERSION
            || bytes[10..12] != [0; 2]
            || bytes[29..32] != [0; 3]
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid public operation authorization header",
            ));
        }
        let project = ProjectId::from_bytes(read_array(&bytes[12..28])?);
        let resource_kind = resource_kind_from_code(bytes[28]).ok_or(
            ReconcilerError::CorruptLedger("unknown public operation resource kind"),
        )?;
        let selector_length = u32::from_be_bytes(read_array(&bytes[32..36])?) as usize;
        let expected_length = PUBLIC_OPERATION_AUTHORIZATION_FIXED_BYTES
            .checked_add(selector_length)
            .ok_or(ReconcilerError::CorruptLedger(
                "public operation authorization length overflow",
            ))?;
        if selector_length == 0
            || selector_length > MAXIMUM_AUTHORIZATION_SELECTOR_BYTES
            || bytes.len() != expected_length
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid public operation authorization length",
            ));
        }
        let selector_end = 36 + selector_length;
        let selector_bytes = &bytes[36..selector_end];
        let selector: Selector = serde_json::from_slice(selector_bytes)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid public operation selector"))?;
        let canonical = serde_json::to_vec(&selector)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid public operation selector"))?;
        let recorded_digest = &bytes[selector_end..];
        let expected_digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_OPERATION_AUTHORIZATION_DIGEST_DOMAIN)
            .chain_update(&bytes[..selector_end])
            .finalize()
            .into();
        if project.as_bytes() == &[0; 16]
            || canonical != selector_bytes
            || recorded_digest != expected_digest
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid public operation authorization binding",
            ));
        }

        Ok(Self {
            project,
            resource_kind,
            selector,
        })
    }
}

impl PublicOperationAdmissionV1 {
    /// Constructs checked immutable public operation metadata.
    ///
    /// The timestamp intentionally has second precision because the protected
    /// controller clock supplies Unix wall seconds paired with boot time.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for a zero generation or audit
    /// identity, or a timestamp outside the protobuf timestamp range.
    pub fn new(
        method: PublicOperationMethodV1,
        accepted_generation: u64,
        audit_id: [u8; 16],
        accepted_wall_seconds: i64,
        authorization: PublicOperationAuthorizationV1,
    ) -> Result<Self, ReconcilerError> {
        if accepted_generation == 0
            || audit_id == [0; 16]
            || !valid_timestamp(accepted_wall_seconds)
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid public operation admission metadata",
            ));
        }

        Ok(Self {
            method,
            accepted_generation,
            audit_id,
            accepted_wall_seconds,
            authorization,
        })
    }

    pub(super) const fn authorization(&self) -> &PublicOperationAuthorizationV1 {
        &self.authorization
    }

    pub(super) const fn durable(&self) -> DurablePublicOperationV1 {
        DurablePublicOperationV1 {
            method: self.method,
            accepted_generation: self.accepted_generation,
            observation_sequence: 1,
            audit_id: self.audit_id,
            accepted_wall_seconds: self.accepted_wall_seconds,
            last_reconciliation_wall_seconds: self.accepted_wall_seconds,
            completed_wall_seconds: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DurablePublicOperationV1 {
    method: PublicOperationMethodV1,
    accepted_generation: u64,
    observation_sequence: u64,
    audit_id: [u8; 16],
    accepted_wall_seconds: i64,
    last_reconciliation_wall_seconds: i64,
    completed_wall_seconds: Option<i64>,
}

impl DurablePublicOperationV1 {
    pub(super) fn advance(
        self,
        state: OperationState,
        wall_seconds: i64,
    ) -> Result<Self, ReconcilerError> {
        if !valid_timestamp(wall_seconds) || wall_seconds < self.last_reconciliation_wall_seconds {
            return Err(ReconcilerError::PublicOperationClock);
        }
        let observation_sequence = self
            .observation_sequence
            .checked_add(1)
            .ok_or(ReconcilerError::PublicOperationSequenceExhausted)?;
        let completed_wall_seconds = if state.is_terminal() {
            Some(wall_seconds)
        } else {
            None
        };

        Ok(Self {
            observation_sequence,
            last_reconciliation_wall_seconds: wall_seconds,
            completed_wall_seconds,
            ..self
        })
    }

    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.push(self.method.record_code());
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&self.accepted_generation.to_le_bytes());
        bytes.extend_from_slice(&self.observation_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.audit_id);
        bytes.extend_from_slice(&self.accepted_wall_seconds.to_le_bytes());
        bytes.extend_from_slice(&self.last_reconciliation_wall_seconds.to_le_bytes());
        bytes.extend_from_slice(
            &self
                .completed_wall_seconds
                .unwrap_or(NO_COMPLETION_TIMESTAMP)
                .to_le_bytes(),
        );
    }

    pub(super) fn decode(bytes: &[u8], state: OperationState) -> Result<Self, ReconcilerError> {
        let bytes: &[u8; PUBLIC_OPERATION_RECORD_BYTES] = bytes.try_into().map_err(|_| {
            ReconcilerError::CorruptLedger("invalid public operation metadata length")
        })?;
        let method = PublicOperationMethodV1::from_record_code(bytes[0]).ok_or(
            ReconcilerError::CorruptLedger("unknown public operation method"),
        )?;
        if bytes[1..8] != [0; 7] {
            return Err(ReconcilerError::CorruptLedger(
                "nonzero public operation reserved bytes",
            ));
        }
        let accepted_generation = read_u64(&bytes[8..16])?;
        let observation_sequence = read_u64(&bytes[16..24])?;
        let audit_id: [u8; 16] = bytes[24..40]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid public operation audit ID"))?;
        let accepted_wall_seconds = read_i64(&bytes[40..48])?;
        let last_reconciliation_wall_seconds = read_i64(&bytes[48..56])?;
        let completion = read_i64(&bytes[56..64])?;
        let completed_wall_seconds = (completion != NO_COMPLETION_TIMESTAMP).then_some(completion);
        if accepted_generation == 0
            || observation_sequence == 0
            || audit_id == [0; 16]
            || !valid_timestamp(accepted_wall_seconds)
            || !valid_timestamp(last_reconciliation_wall_seconds)
            || last_reconciliation_wall_seconds < accepted_wall_seconds
            || completed_wall_seconds.is_some_and(|completed| {
                !valid_timestamp(completed)
                    || completed < accepted_wall_seconds
                    || completed > last_reconciliation_wall_seconds
            })
            || state.is_terminal() != completed_wall_seconds.is_some()
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid public operation metadata",
            ));
        }

        Ok(Self {
            method,
            accepted_generation,
            observation_sequence,
            audit_id,
            accepted_wall_seconds,
            last_reconciliation_wall_seconds,
            completed_wall_seconds,
        })
    }

    pub(super) fn project(
        self,
        operation_id: OperationId,
        state: OperationState,
        effect_count: u32,
        applied_effects: u32,
        operation_record: &[u8],
        effect_records: &[&[u8]],
    ) -> Operation {
        let (phase, milestone, retry_class) = match state {
            OperationState::OwnershipPending => (
                OperationPhase::OPERATION_PHASE_COMMITTED,
                "blocked",
                RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE,
            ),
            OperationState::Accepted | OperationState::Applying => (
                OperationPhase::OPERATION_PHASE_COMMITTED,
                "reconciling",
                RetryClass::RETRY_CLASS_SAME_REQUEST,
            ),
            OperationState::Succeeded => (
                OperationPhase::OPERATION_PHASE_SUCCEEDED,
                "complete",
                RetryClass::RETRY_CLASS_NEVER,
            ),
            OperationState::PermanentlyBlocked => (
                OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED,
                "blocked",
                RetryClass::RETRY_CLASS_NEVER,
            ),
        };
        let completed_at = self.completed_wall_seconds.map(timestamp);

        Operation {
            operation_id: operation_id.into_bytes().to_vec(),
            resource_version: resource_version(operation_id, operation_record, effect_records)
                .to_vec(),
            method: self.method.as_str().to_owned(),
            phase: phase.into(),
            accepted_generation: self.accepted_generation,
            progress: Some(OperationProgress {
                milestone: milestone.to_owned(),
                completed_units: applied_effects,
                total_units: effect_count,
                ..Default::default()
            })
            .into(),
            retry_class: retry_class.into(),
            audit_id: self.audit_id.to_vec(),
            accepted_at: Some(timestamp(self.accepted_wall_seconds)).into(),
            completed_at: completed_at.into(),
            cancelable: false,
            observation_sequence: self.observation_sequence,
            last_successful_reconciliation_time: Some(timestamp(
                self.last_reconciliation_wall_seconds,
            ))
            .into(),
            ..Default::default()
        }
    }
}

const fn valid_timestamp(seconds: i64) -> bool {
    seconds >= MINIMUM_PROTO_SECONDS && seconds <= MAXIMUM_PROTO_SECONDS
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp {
        seconds,
        nanoseconds: 0,
        ..Default::default()
    }
}

fn resource_version(
    operation_id: OperationId,
    operation_record: &[u8],
    effect_records: &[&[u8]],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PUBLIC_OPERATION_RESOURCE_VERSION_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update((operation_record.len() as u64).to_be_bytes());
    digest.update(operation_record);
    for effect in effect_records {
        digest.update((effect.len() as u64).to_be_bytes());
        digest.update(effect);
    }
    digest.finalize().into()
}

fn read_u64(bytes: &[u8]) -> Result<u64, ReconcilerError> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        ReconcilerError::CorruptLedger("invalid public operation integer")
    })?))
}

fn read_i64(bytes: &[u8]) -> Result<i64, ReconcilerError> {
    Ok(i64::from_le_bytes(bytes.try_into().map_err(|_| {
        ReconcilerError::CorruptLedger("invalid public operation timestamp")
    })?))
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ReconcilerError> {
    bytes
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("truncated public operation authorization"))
}

const fn resource_kind_code(kind: ResourceKind) -> u8 {
    kind as u8
}

const fn resource_kind_from_code(value: u8) -> Option<ResourceKind> {
    match value {
        0 => Some(ResourceKind::Sandbox),
        1 => Some(ResourceKind::Execution),
        2 => Some(ResourceKind::Snapshot),
        3 => Some(ResourceKind::Tree),
        4 => Some(ResourceKind::LiveExport),
        5 => Some(ResourceKind::PrivateDelta),
        6 => Some(ResourceKind::Secret),
        7 => Some(ResourceKind::Device),
        8 => Some(ResourceKind::NetworkEndpoint),
        9 => Some(ResourceKind::IpcService),
        10 => Some(ResourceKind::CacheRead),
        11 => Some(ResourceKind::CachePublish),
        12 => Some(ResourceKind::Environment),
        13 => Some(ResourceKind::AttachmentSlot),
        14 => Some(ResourceKind::ChildDelegation),
        _ => None,
    }
}
