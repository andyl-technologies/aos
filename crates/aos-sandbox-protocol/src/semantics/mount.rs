//! Canonical portable authority semantics for mount effects.
//!
//! The compiler consumes only a validated wire request, an opaque digest of a
//! separately verified node-local catalog resolution, and descriptor roles.
//! It never accepts catalog paths, kernel identities, descriptor numbers, or
//! Linux mount/syscall objects.

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorRole, MountAction, MountSourceConsistency,
};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ObjectDigest,
    encode_view_source,
};

use crate::{ValidatedMountAttributes, ValidatedMountRequest};

const FORMAT_MAGIC: &[u8; 8] = b"AOSMSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_DESCRIPTOR_ROLES: usize = 16;
const MAXIMUM_CANONICAL_BYTES: usize = 2 * 1024;

/// Reports a request that cannot have one canonical portable Mount V1 meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountSemanticError {
    /// The catalog commitment is missing, unexpected, or a reserved digest.
    #[error("mount catalog commitment does not match the action")]
    CatalogCommitmentMismatch,
    /// The descriptor-role sequence is oversized or contains the sentinel role.
    #[error("mount descriptor-role semantics are invalid")]
    InvalidDescriptorRoles,
    /// A validated request unexpectedly contains an invalid action or target.
    #[error("mount action target semantics are invalid")]
    InvalidTarget,
    /// The canonical encoding exceeded its invariant V1 ceiling.
    #[error("mount canonical semantic encoding exceeds the V1 ceiling")]
    EncodingTooLarge,
}

/// Carries an opaque digest of one separately verified node-local catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountCatalogBindingV1(ObjectDigest);

impl MountCatalogBindingV1 {
    /// Adopts a nonzero digest from a protected catalog publisher.
    ///
    /// # Errors
    ///
    /// Returns [`MountSemanticError::CatalogCommitmentMismatch`] for the zero
    /// sentinel.
    pub fn from_verified_digest(digest: ObjectDigest) -> Result<Self, MountSemanticError> {
        if digest.as_bytes() == &[0; 32] {
            Err(MountSemanticError::CatalogCommitmentMismatch)
        } else {
            Ok(Self(digest))
        }
    }

    /// Returns the opaque node-local catalog digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Carries exact portable canonical bytes and their grant tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMountSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    verb: BrokerVerb,
    target: BrokerGrantTarget,
}

/// Carries the exact pre-catalog Create template sent to SourceProvider 1.0.
///
/// It is a normal `AOSMSEM1` field sequence except that field 13 is the
/// canonical empty catalog value. Every other field is final. Only the
/// feature-gated Mount Acquire method may consume this representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalPrecatalogMountCreateV1 {
    bytes: Vec<u8>,
    digest: ObjectDigest,
}

/// Retains the exact 27 canonical `AOSMSEM1` field values.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedCanonicalMountSemanticsV1 {
    fields: [Vec<u8>; 27],
}

impl DecodedCanonicalMountSemanticsV1 {
    /// Borrows one canonical field by its one-based tag.
    #[must_use]
    pub fn field(&self, tag: u8) -> Option<&[u8]> {
        tag.checked_sub(1)
            .and_then(|index| self.fields.get(usize::from(index)))
            .map(Vec::as_slice)
    }

    /// Borrows all fields in exact tag order.
    #[must_use]
    #[doc(hidden)]
    pub const fn fields(&self) -> &[Vec<u8>; 27] {
        &self.fields
    }
}

impl CanonicalPrecatalogMountCreateV1 {
    /// Returns the exact deadline-free pre-catalog `AOSMSEM1` bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SourceProvider-defined prospective-template digest.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl CanonicalMountSemanticsV1 {
    /// Returns the exact bytes whose meaning the mount grant commits.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated broker argument commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the closed semantic verb selected by the action.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        self.verb
    }

    /// Returns the exact assignment, resource, or resource-pair grant target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }
}

/// Canonicalizes one validated mount request for portable broker-plan matching.
///
/// # Errors
///
/// Returns [`MountSemanticError`] for an action/catalog mismatch, invalid
/// descriptor roles or target shape, or an internal bound violation.
pub fn canonical_mount_semantics_v1(
    request: &ValidatedMountRequest,
    catalog: Option<MountCatalogBindingV1>,
    descriptor_roles: &[BrokerDescriptorRole],
) -> Result<CanonicalMountSemanticsV1, MountSemanticError> {
    validate_roles(descriptor_roles)?;
    let (verb, target, action_code, requires_catalog) = action_semantics(request)?;
    if requires_catalog != catalog.is_some() {
        return Err(MountSemanticError::CatalogCommitmentMismatch);
    }

    let bytes = encode_mount_semantics(request, catalog, descriptor_roles, action_code)?;
    Ok(CanonicalMountSemanticsV1 {
        commitment: BrokerArgumentCommitment::for_canonical_bytes(&bytes),
        bytes,
        verb,
        target,
    })
}

/// Canonicalizes the sole pre-catalog Mount Create template.
///
/// The ordinary [`canonical_mount_semantics_v1`] contract remains unchanged:
/// a final Create always requires a verified catalog commitment. This helper is
/// exclusively for the preceding source-acquisition query and projects only
/// field 13 to its canonical empty form.
///
/// # Errors
///
/// Returns [`MountSemanticError`] unless `request` is Create, descriptor roles
/// are valid, or the exact encoding exceeds the V1 ceiling.
pub fn canonical_precatalog_mount_create_template_v1(
    request: &ValidatedMountRequest,
    descriptor_roles: &[BrokerDescriptorRole],
) -> Result<CanonicalPrecatalogMountCreateV1, MountSemanticError> {
    validate_roles(descriptor_roles)?;
    let (_, _, action_code, requires_catalog) = action_semantics(request)?;
    if !requires_catalog || request.action() != MountAction::MOUNT_ACTION_CREATE_DETACHED {
        return Err(MountSemanticError::InvalidTarget);
    }
    let bytes = encode_mount_semantics(request, None, descriptor_roles, action_code)?;
    let digest =
        aos_sandbox_source_provider_protocol::prospective_mount_apply_template_digest_v1(&bytes)
            .map_err(|_| MountSemanticError::EncodingTooLarge)?;
    Ok(CanonicalPrecatalogMountCreateV1 { bytes, digest })
}

/// Checks that a final Create reproduces an earlier pre-catalog template.
///
/// The final Create is first required to satisfy the ordinary nonzero catalog
/// contract. Equality then compares the exact template obtained by projecting
/// only field 13 back to its canonical empty value.
///
/// # Errors
///
/// Returns [`MountSemanticError`] for a non-Create request, invalid descriptor
/// roles, a missing catalog commitment, or an encoding bound violation.
pub fn final_mount_create_matches_precatalog_template_v1(
    request: &ValidatedMountRequest,
    catalog: MountCatalogBindingV1,
    descriptor_roles: &[BrokerDescriptorRole],
    expected_template: &[u8],
) -> Result<bool, MountSemanticError> {
    canonical_mount_semantics_v1(request, Some(catalog), descriptor_roles)?;
    let projected = canonical_precatalog_mount_create_template_v1(request, descriptor_roles)?;
    Ok(projected.canonical_bytes() == expected_template)
}

/// Projects canonical final Create semantics back to the pre-catalog form.
///
/// This byte-only verifier is used by protected durable-state owners that do
/// not retain the original protobuf request. It accepts exactly fields 1
/// through 27 in order and replaces only the required nonzero field-13 catalog
/// commitment with the canonical empty value.
///
/// # Errors
///
/// Returns [`MountSemanticError::InvalidTarget`] for malformed field framing,
/// a missing or zero catalog commitment, unknown/trailing fields, or an
/// encoding beyond the canonical Mount ceiling.
pub fn project_final_mount_create_semantics_v1(
    bytes: &[u8],
) -> Result<Vec<u8>, MountSemanticError> {
    let decoded = decode_canonical_mount_semantics_v1(bytes)?;
    let mut projected = Vec::with_capacity(bytes.len());
    for expected_tag in 1_u8..=27 {
        let value = decoded
            .field(expected_tag)
            .ok_or(MountSemanticError::InvalidTarget)?;
        projected.push(expected_tag);
        if expected_tag == 13 {
            if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
                return Err(MountSemanticError::InvalidTarget);
            }
            projected.extend_from_slice(&0_u32.to_be_bytes());
        } else {
            let length =
                u32::try_from(value.len()).map_err(|_| MountSemanticError::InvalidTarget)?;
            projected.extend_from_slice(&length.to_be_bytes());
            projected.extend_from_slice(value);
        }
    }
    Ok(projected)
}

/// Structurally decodes the complete canonical `AOSMSEM1` field sequence.
///
/// # Errors
///
/// Returns [`MountSemanticError::InvalidTarget`] for an over-limit value,
/// missing, reordered, duplicated, truncated, or trailing fields.
pub fn decode_canonical_mount_semantics_v1(
    bytes: &[u8],
) -> Result<DecodedCanonicalMountSemanticsV1, MountSemanticError> {
    if bytes.len() > MAXIMUM_CANONICAL_BYTES {
        return Err(MountSemanticError::InvalidTarget);
    }
    let mut fields = Vec::with_capacity(27);
    let mut cursor = 0usize;
    for expected_tag in 1_u8..=27 {
        if bytes.get(cursor).copied() != Some(expected_tag) {
            return Err(MountSemanticError::InvalidTarget);
        }
        let length = bytes
            .get(cursor + 1..cursor + 5)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(MountSemanticError::InvalidTarget)?;
        let start = cursor
            .checked_add(5)
            .ok_or(MountSemanticError::InvalidTarget)?;
        let end = start
            .checked_add(length)
            .ok_or(MountSemanticError::InvalidTarget)?;
        fields.push(
            bytes
                .get(start..end)
                .ok_or(MountSemanticError::InvalidTarget)?
                .to_vec(),
        );
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(MountSemanticError::InvalidTarget);
    }
    let fields = fields
        .try_into()
        .map_err(|_| MountSemanticError::InvalidTarget)?;
    Ok(DecodedCanonicalMountSemanticsV1 { fields })
}

fn encode_mount_semantics(
    request: &ValidatedMountRequest,
    catalog: Option<MountCatalogBindingV1>,
    descriptor_roles: &[BrokerDescriptorRole],
    action_code: u8,
) -> Result<Vec<u8>, MountSemanticError> {
    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[action_code])?;
    encoder.field(4, request.fence().sandbox_id())?;
    encoder.field(5, request.fence().incarnation_id())?;
    encoder.field(6, &request.fence().assignment_epoch().to_be_bytes())?;
    encoder.field(7, &request.fence().desired_generation().to_be_bytes())?;
    encoder.field(8, request.fence().assignment_digest())?;
    encoder.field(9, request.attachment_id())?;
    encoder.field(10, request.destination_slot_id())?;
    encoder.field(11, &request.source_generation().to_be_bytes())?;
    encoder.field(12, &request.namespace_generation().to_be_bytes())?;
    encoder.optional_digest(13, catalog.map(MountCatalogBindingV1::digest))?;
    encoder.optional_descriptor(14, request.view_revision())?;
    encoder.optional_attributes(15, request.attributes())?;
    encoder.optional_fixed(
        16,
        request.detached_mount_handle().map(<[u8; 32]>::as_slice),
    )?;
    encoder.optional_fixed(
        17,
        request.replacement_mount_handle().map(<[u8; 32]>::as_slice),
    )?;
    encoder.roles(18, descriptor_roles)?;
    encoder.field(19, &request.desired_attachment_generation().to_be_bytes())?;
    encoder.field(20, &request.resource_attachment_generation().to_be_bytes())?;
    encoder.field(21, request.source_view_id())?;
    encoder.optional_fixed(
        22,
        request.source_incarnation_id().map(<[u8; 16]>::as_slice),
    )?;
    encoder.field(23, &[source_consistency_code(request.source_consistency())])?;
    encoder.field(24, request.attachment_lease_id())?;
    encoder.field(25, &request.attachment_lease_issued_seconds().to_be_bytes())?;
    encoder.field(
        26,
        &request.attachment_lease_expires_seconds().to_be_bytes(),
    )?;
    encoder.field(27, &encode_view_source(request.source_handle()))?;
    Ok(encoder.finish())
}

fn action_semantics(
    request: &ValidatedMountRequest,
) -> Result<(BrokerVerb, BrokerGrantTarget, u8, bool), MountSemanticError> {
    let resource = |handle: Option<&[u8; 32]>| {
        handle
            .copied()
            .ok_or(MountSemanticError::InvalidTarget)
            .and_then(|bytes| {
                BrokerResourceHandle::from_bytes(bytes)
                    .map_err(|_| MountSemanticError::InvalidTarget)
            })
    };
    match request.action() {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => Ok((
            BrokerVerb::MountCreate,
            BrokerGrantTarget::Assignment,
            1,
            true,
        )),
        MountAction::MOUNT_ACTION_INSTALL => Ok((
            BrokerVerb::MountInstall,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            2,
            true,
        )),
        MountAction::MOUNT_ACTION_REPLACE => Ok((
            BrokerVerb::MountReplace,
            BrokerGrantTarget::ResourcePair {
                previous: resource(request.replacement_mount_handle())?,
                successor: resource(request.detached_mount_handle())?,
            },
            3,
            true,
        )),
        MountAction::MOUNT_ACTION_DETACH => Ok((
            BrokerVerb::MountDetach,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            4,
            true,
        )),
        MountAction::MOUNT_ACTION_RELEASE => Ok((
            BrokerVerb::MountRelease,
            BrokerGrantTarget::Resource(resource(request.detached_mount_handle())?),
            5,
            false,
        )),
        MountAction::MOUNT_ACTION_UNSPECIFIED => Err(MountSemanticError::InvalidTarget),
    }
}

fn validate_roles(roles: &[BrokerDescriptorRole]) -> Result<(), MountSemanticError> {
    if roles.len() > MAXIMUM_DESCRIPTOR_ROLES
        || roles.contains(&BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED)
    {
        Err(MountSemanticError::InvalidDescriptorRoles)
    } else {
        Ok(())
    }
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), MountSemanticError> {
        let length =
            u32::try_from(value.len()).map_err(|_| MountSemanticError::EncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(MountSemanticError::EncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn optional_fixed(&mut self, tag: u8, value: Option<&[u8]>) -> Result<(), MountSemanticError> {
        self.field(tag, value.unwrap_or_default())
    }

    fn optional_digest(
        &mut self,
        tag: u8,
        value: Option<ObjectDigest>,
    ) -> Result<(), MountSemanticError> {
        self.optional_fixed(
            tag,
            value.as_ref().map(|digest| digest.as_bytes().as_slice()),
        )
    }

    fn optional_descriptor(
        &mut self,
        tag: u8,
        descriptor: Option<&aos_sandbox_core::ObjectDescriptor>,
    ) -> Result<(), MountSemanticError> {
        let Some(descriptor) = descriptor else {
            return self.field(tag, &[]);
        };
        let media_type = descriptor.media_type().as_str().as_bytes();
        let media_length =
            u16::try_from(media_type.len()).map_err(|_| MountSemanticError::EncodingTooLarge)?;
        let mut value = Vec::with_capacity(2 + media_type.len() + 40);
        value.extend_from_slice(&media_length.to_be_bytes());
        value.extend_from_slice(media_type);
        value.extend_from_slice(descriptor.digest().as_bytes());
        value.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
        self.field(tag, &value)
    }

    fn optional_attributes(
        &mut self,
        tag: u8,
        attributes: Option<ValidatedMountAttributes>,
    ) -> Result<(), MountSemanticError> {
        let Some(attributes) = attributes else {
            return self.field(tag, &[]);
        };
        self.field(
            tag,
            &[
                u8::from(attributes.read_only()),
                u8::from(attributes.no_exec()),
                u8::from(attributes.no_suid()),
                u8::from(attributes.no_device()),
                u8::from(attributes.no_atime()),
                u8::from(attributes.recursive()),
                u8::try_from(attributes.mutation_mode())
                    .map_err(|_| MountSemanticError::EncodingTooLarge)?,
            ],
        )
    }

    fn roles(&mut self, tag: u8, roles: &[BrokerDescriptorRole]) -> Result<(), MountSemanticError> {
        let mut value = Vec::with_capacity(2 + roles.len() * 2);
        value.extend_from_slice(
            &u16::try_from(roles.len())
                .map_err(|_| MountSemanticError::EncodingTooLarge)?
                .to_be_bytes(),
        );
        for role in roles {
            value.extend_from_slice(&descriptor_role_code(*role).to_be_bytes());
        }
        self.field(tag, &value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

const fn source_consistency_code(consistency: MountSourceConsistency) -> u8 {
    match consistency {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => 1,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => 2,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE => 3,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => 4,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_UNSPECIFIED => 0,
    }
}

const fn descriptor_role_code(role: BrokerDescriptorRole) -> u16 {
    match role {
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED => 0,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE => 1,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT => 2,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_MOUNT_SOURCE => 3,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_DETACHED_MOUNT => 4,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_RUNTIME_LEADER => 5,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE => 6,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_SLOT => 7,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD => 8,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP => 9,
        BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG => 10,
    }
}
