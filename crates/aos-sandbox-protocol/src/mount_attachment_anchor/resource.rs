//! Owns the sole namespace-resource digest, durable codec and phase transitions.

use super::*;
use aos_proto::aos::sandbox::local::v1::{AttachmentAnchorLifecycleV1 as Phase,
    DestinationSlotReapCorrelation, MountAssignmentBinding, MountOperationCorrelation};
use aos_sandbox_core::DescriptorRole;
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSMNA01";
const DOMAIN: &[u8] = b"aos.sandbox.mount.namespace-anchor.resource.v1\0";
/// Bounds this finite resource record independently of inventory population.
pub const MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1: usize = 4096;

/// Carries complete canonical namespace-resource DATA without native custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAttachmentAnchorResourceV1 {
    fence: ValidatedAssignmentFence,
    namespace_generation: u64,
    sandbox_spec: ObjectDescriptor,
    phase: Phase,
    boot: [u8; 16],
    materialization: ([u8; 16], [u8; 32]),
    reap: Option<([u8; 16], [u8; 32], [u8; 32])>,
    physical: Option<(u64, u64, u64)>,
    digest: [u8; 32],
}

impl ValidatedAttachmentAnchorResourceV1 {
    /// Returns the immutable assignment that owns the namespace.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence { &self.fence }

    /// Returns the exact namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 { self.namespace_generation }

    /// Returns the exact specification descriptor supplied at admission.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &ObjectDescriptor { &self.sandbox_spec }

    /// Returns the durable namespace lifecycle phase.
    #[must_use]
    pub const fn lifecycle(&self) -> Phase { self.phase }

    /// Returns the original materialization kernel boot.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] { &self.boot }

    /// Returns the real device, inode and kernel-unique mount identity.
    #[must_use]
    pub const fn physical_identity_v1(&self) -> Option<(u64, u64, u64)> { self.physical }

    /// Returns the exact canonical complete-record commitment.
    #[must_use]
    pub const fn resource_digest(&self) -> &[u8; 32] { &self.digest }

    /// Returns the materialization's real operation and exact request digest.
    #[must_use]
    pub const fn materialization_v1(&self) -> &([u8; 16], [u8; 32]) { &self.materialization }

    /// Returns the exact retirement correlation and predecessor commitment.
    #[must_use]
    pub const fn reap_v1(&self) -> Option<&([u8; 16], [u8; 32], [u8; 32])> { self.reap.as_ref() }

    /// Encodes the distinct no-slot key in the existing Mount resource namespace.
    #[must_use]
    pub fn key_v1(&self) -> [u8; 40] {
        let mut key = [0; 40];
        key[..16].copy_from_slice(self.fence.sandbox_id());
        key[16..32].copy_from_slice(self.fence.incarnation_id());
        key[32..].copy_from_slice(&self.namespace_generation.to_be_bytes());
        key
    }

    /// Returns the same canonical resource representation used in inventory.
    #[must_use]
    pub fn wire_v1(&self) -> AttachmentAnchorResourceRecordV1 {
        AttachmentAnchorResourceRecordV1 {
            binding: Some(MountAssignmentBinding {
                fence: Some(wire_fence(&self.fence)).into(), namespace_generation: self.namespace_generation,
                ..Default::default()
            }).into(),
            sandbox_spec: Some(wire_descriptor(&self.sandbox_spec)).into(), lifecycle: self.phase.into(),
            resource_kernel_boot_id: self.boot.to_vec(),
            materialization: Some(operation(self.materialization)).into(),
            reap: self.reap.map(|(id, request, expected)| DestinationSlotReapCorrelation {
                operation: Some(operation((id, request))).into(), expected_resource_digest: expected.to_vec(),
                ..Default::default()
            }).into(),
            directory_device: self.physical.map(|value| value.0),
            directory_inode: self.physical.map(|value| value.1),
            anchor_unique_mount_id: self.physical.map(|value| value.2),
            resource_digest: self.digest.to_vec(), ..Default::default()
        }
    }

    /// Derives intent DATA for an exact validated materialization request.
    ///
    /// # Errors
    /// Refuses a different action, empty body, or invalid boot/correlation.
    pub fn materializing_v1(
        request: &ValidatedAttachmentAnchorRequestV1,
        exact_body: &[u8],
        boot: [u8; 16],
    ) -> Result<Self, ProtocolValidationError> {
        if request.action() != AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE
            || exact_body.is_empty()
        {
            return Err(invalid("namespace materialization request"));
        }
        seal_attachment_anchor_resource_v1(AttachmentAnchorResourceRecordV1 {
            binding: Some(MountAssignmentBinding {
                fence: Some(wire_fence(request.binding_fence())).into(),
                namespace_generation: request.namespace_generation(),
                ..Default::default()
            }).into(),
            sandbox_spec: Some(wire_descriptor(request.sandbox_spec())).into(),
            lifecycle: Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_MATERIALIZING.into(),
            resource_kernel_boot_id: boot.to_vec(),
            materialization: Some(operation((*request.header().request_id(),
                Sha256::digest(exact_body).into()))).into(),
            ..Default::default()
        })
    }

    /// Derives Ready DATA from a Materializing row and actual physical identity.
    ///
    /// # Errors
    /// Refuses another phase or invalid device/inode/mount identity.
    pub fn ready_v1(&self, physical: (u64, u64, u64)) -> Result<Self, ProtocolValidationError> {
        if self.phase != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_MATERIALIZING {
            return Err(invalid("namespace Ready predecessor"));
        }
        let mut wire = self.wire_v1();
        wire.lifecycle = Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY.into();
        wire.directory_device = Some(physical.0);
        wire.directory_inode = Some(physical.1);
        wire.anchor_unique_mount_id = Some(physical.2);
        wire.resource_digest.clear();
        seal_attachment_anchor_resource_v1(wire)
    }

    /// Binds a Ready row to the exact separately authorized reap operation.
    ///
    /// # Errors
    /// Refuses another original fence/specification/generation, changed Ready
    /// commitment, reused operation identity, or a non-Reap request.
    pub fn reaping_v1(
        &self,
        request: &ValidatedAttachmentAnchorRequestV1,
        exact_body: &[u8],
    ) -> Result<Self, ProtocolValidationError> {
        if self.phase != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY
            || request.action() != AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP
            || request.binding_fence() != &self.fence
            || request.namespace_generation() != self.namespace_generation
            || request.sandbox_spec() != &self.sandbox_spec
            || request.expected_resource_digest() != Some(&self.digest)
            || request.header().request_id() == &self.materialization.0
            || exact_body.is_empty()
        {
            return Err(invalid("namespace Reap predecessor"));
        }
        let mut wire = self.wire_v1();
        wire.lifecycle = Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING.into();
        wire.reap = Some(DestinationSlotReapCorrelation {
            operation: Some(operation((*request.header().request_id(),
                Sha256::digest(exact_body).into()))).into(),
            expected_resource_digest: self.digest.to_vec(),
            ..Default::default()
        }).into();
        wire.resource_digest.clear();
        seal_attachment_anchor_resource_v1(wire)
    }

    /// Derives a permanent tombstone from the same Reaping row.
    ///
    /// # Errors
    /// Refuses a row without an actual Reaping predecessor.
    pub fn released_v1(&self) -> Result<Self, ProtocolValidationError> {
        if self.phase != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING {
            return Err(invalid("namespace Released predecessor"));
        }
        let mut wire = self.wire_v1();
        wire.lifecycle = Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED.into();
        wire.resource_digest.clear();
        seal_attachment_anchor_resource_v1(wire)
    }

    /// Checks the complete finite lifecycle relation between two canonical rows.
    ///
    /// # Errors
    /// Refuses a skipped phase or any substituted immutable/correlation field.
    pub fn require_successor_v1(&self, next: &Self) -> Result<(), ProtocolValidationError> {
        let expected = match (self.phase, next.phase) {
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_MATERIALIZING,
                Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY) => {
                self.ready_v1(next.physical.ok_or(invalid("namespace Ready identity"))?)?
            }
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY,
                Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING) => {
                let mut wire = self.wire_v1();
                wire.lifecycle = next.phase.into();
                wire.reap = next.wire_v1().reap;
                wire.resource_digest.clear();
                let expected = seal_attachment_anchor_resource_v1(wire)?;
                if next.reap.as_ref().map(|value| value.2) != Some(self.digest) {
                    return Err(invalid("namespace Reap commitment"));
                }
                expected
            }
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING,
                Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED) => self.released_v1()?,
            _ => return Err(invalid("namespace lifecycle successor")),
        };
        if &expected == next { Ok(()) } else { Err(invalid("namespace successor substitution")) }
    }

    /// Checks a completed response against the same exact admitted operation.
    ///
    /// # Errors
    /// Refuses another fence/specification/generation, a changed request digest,
    /// a nonterminal result or an unrelated reap predecessor.
    pub fn require_request_v1(&self, request: &ValidatedAttachmentAnchorRequestV1, body: &[u8])
        -> Result<(), ProtocolValidationError> {
        let correlation = (*request.header().request_id(), Sha256::digest(body).into());
        if self.fence != *request.binding_fence() || self.namespace_generation != request.namespace_generation()
            || self.sandbox_spec != *request.sandbox_spec()
        { return Err(invalid("namespace response binding")); }
        let valid = match request.action() {
            AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_MATERIALIZE =>
                self.phase == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY && self.materialization == correlation,
            AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP =>
                self.phase == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED && self.reap.is_some_and(|(id, digest, expected)|
                    (id, digest) == correlation && Some(&expected) == request.expected_resource_digest()),
            AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_UNSPECIFIED => false,
        };
        if valid { Ok(()) } else { Err(invalid("namespace response operation")) }
    }
}

/// Validates the full canonical namespace row and its sole digest formula.
///
/// # Errors
/// Refuses unknown fields, incomplete binding, phase/correlation/physical
/// contradictions, sentinels, or a digest that does not name these exact fields.
pub fn validate_attachment_anchor_resource_v1(record: &AttachmentAnchorResourceRecordV1)
    -> Result<ValidatedAttachmentAnchorResourceV1, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    if record.compute_size(&mut buffa::SizeCache::new()) as usize
        > MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1 - MAGIC.len()
    {
        return Err(invalid("namespace resource schema bound"));
    }
    let binding = record.binding.as_option().ok_or(ProtocolValidationError::MissingField("binding"))?;
    reject_unknown(&binding.__buffa_unknown_fields)?;
    let fence = validate_fence(binding.fence.as_option().ok_or(ProtocolValidationError::MissingField("binding.fence"))?)?;
    if binding.namespace_generation == 0 { return Err(invalid("namespace generation")); }
    let sandbox_spec = crate::validate_descriptor(record.sandbox_spec.as_option()
        .ok_or(ProtocolValidationError::MissingField("sandbox_spec"))?, DescriptorRole::SnapshotSpec)?;
    let phase = record.lifecycle.as_known().filter(|phase| *phase != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    let boot = exact_nonzero::<16>(&record.resource_kernel_boot_id, "resource_kernel_boot_id")?;
    let materialization = decode_operation(record.materialization.as_option()
        .ok_or(ProtocolValidationError::MissingField("materialization"))?)?;
    let reap = record.reap.as_option().map(|reap| {
        reject_unknown(&reap.__buffa_unknown_fields)?;
        let (id, request) = decode_operation(reap.operation.as_option()
            .ok_or(ProtocolValidationError::MissingField("reap.operation"))?)?;
        Ok::<_, ProtocolValidationError>((id, request, exact_nonzero::<32>(&reap.expected_resource_digest, "reap.expected")?))
    }).transpose()?;
    let physical = match (record.directory_device, record.directory_inode, record.anchor_unique_mount_id) {
        (None, None, None) => None,
        (Some(device), Some(inode), Some(mount)) if inode != 0 && mount != 0 && mount != u64::MAX => Some((device, inode, mount)),
        _ => return Err(invalid("namespace physical identity")),
    };
    let valid = match phase {
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_MATERIALIZING => physical.is_none() && reap.is_none(),
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY => physical.is_some() && reap.is_none(),
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING | Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED =>
            physical.is_some() && reap.is_some_and(|(id, _, _)| id != materialization.0),
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_UNSPECIFIED => false,
    };
    if !valid { return Err(invalid("namespace phase correlation")); }
    let digest = exact_nonzero::<32>(&record.resource_digest, "resource_digest")?;
    let row = ValidatedAttachmentAnchorResourceV1 { fence, namespace_generation: binding.namespace_generation,
        sandbox_spec, phase, boot, materialization, reap, physical, digest };
    if row_digest(&row) != row.digest { return Err(invalid("namespace resource digest")); }
    Ok(row)
}

/// Seals canonical resource DATA after an actual producer supplies its fields.
///
/// # Errors
/// Refuses a supplied digest or malformed record. The result contains no
/// protected writer, role, currentness, descriptor or permission to publish it.
pub fn seal_attachment_anchor_resource_v1(mut record: AttachmentAnchorResourceRecordV1)
    -> Result<ValidatedAttachmentAnchorResourceV1, ProtocolValidationError> {
    if !record.resource_digest.is_empty() { return Err(invalid("namespace digest must be derived")); }
    let digest: [u8;32] = Sha256::new().chain_update(DOMAIN).chain_update(record.encode_to_vec()).finalize().into();
    record.resource_digest = digest.to_vec();
    validate_attachment_anchor_resource_v1(&record)
}

/// Encodes the sole versioned protected namespace-resource row.
#[must_use]
pub fn encode_attachment_anchor_resource_v1(row: &ValidatedAttachmentAnchorResourceV1) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&row.wire_v1().encode_to_vec());
    encoded
}

/// Decodes one exact protected row without manufacturing a native owner.
///
/// # Errors
/// Refuses the wrong version, oversized/noncanonical protobufs, unknown fields,
/// invalid correlations or a mismatched complete-resource digest.
pub fn decode_attachment_anchor_resource_v1(bytes: &[u8])
    -> Result<ValidatedAttachmentAnchorResourceV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1 || !bytes.starts_with(MAGIC) {
        return Err(invalid("namespace resource version or bound"));
    }
    let record = AttachmentAnchorResourceRecordV1::decode_from_slice(&bytes[MAGIC.len()..])
        .map_err(|cause| ProtocolValidationError::MalformedWire(cause.to_string()))?;
    let row = validate_attachment_anchor_resource_v1(&record)?;
    if encode_attachment_anchor_resource_v1(&row) != bytes { return Err(invalid("noncanonical namespace resource")); }
    Ok(row)
}

fn row_digest(row: &ValidatedAttachmentAnchorResourceV1) -> [u8;32] {
    let mut wire = row.wire_v1();
    wire.resource_digest.clear();
    Sha256::new().chain_update(DOMAIN).chain_update(wire.encode_to_vec()).finalize().into()
}

fn decode_operation(value: &MountOperationCorrelation) -> Result<([u8;16],[u8;32]), ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    Ok((exact_nonzero::<16>(&value.operation_id, "operation_id")?,
        exact_nonzero::<32>(&value.request_digest, "request_digest")?))
}

fn operation(value: ([u8;16],[u8;32])) -> MountOperationCorrelation {
    MountOperationCorrelation { operation_id: value.0.to_vec(), request_digest: value.1.to_vec(), ..Default::default() }
}

fn invalid(message: &'static str) -> ProtocolValidationError { ProtocolValidationError::InvalidField(message) }
