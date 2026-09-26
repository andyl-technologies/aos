//! Canonical portable authority semantics for storage requests.
//!
//! Storage canonical semantics encode tagged, length-delimited fields in
//! ascending tag order:
//!
//! ```text
//! field := tag:u8 || length:u32be || value:length
//! fields := magic, version, action, assignment fence, operation ID,
//!           optional storage handle, optional version handle, quota,
//!           opaque catalog generation, opaque catalog digest,
//!           optional exact assignment-manifest and sandbox-spec bytes
//! ```
//!
//! The catalog association is opaque portable input. It authenticates a
//! node-local resolution without carrying ZFS names, GUIDs, or properties.

use aos_proto::aos::sandbox::local::v1::{ApplyStorageRequest, StorageAction};
use aos_sandbox_core::model::SandboxSpec;
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerResourceHandle,
    BrokerVerb, CanonicalAssignmentManifestV1, DecodeLimits, ObjectDigest, ProtocolId,
    decode_sandbox_spec, descriptor_for_bytes, encode_sandbox_spec,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_ASSIGNMENT_MANIFEST_BYTES: usize = 48 * 1024;
const MAXIMUM_SANDBOX_SPEC_BYTES: usize = 16 * 1024;
const MAXIMUM_CANONICAL_BYTES: usize = 65 * 1024;

/// Reports a storage request that has no single closed portable meaning.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageSemanticsError {
    /// The common local-protocol envelope or fixed-width field is invalid.
    #[error("invalid local storage request: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The action's optional fields or quota do not have the required shape.
    #[error("storage action fields do not match the selected operation")]
    InvalidActionShape,
    /// The opaque catalog association uses a reserved value.
    #[error("storage catalog association uses a reserved value")]
    InvalidCatalogBinding,
    /// The canonical semantic representation exceeded its fixed invariant.
    #[error("canonical storage semantics exceed the fixed byte ceiling")]
    CanonicalEncodingTooLarge,
    /// Required portable workspace metadata is absent or cross-bound.
    #[error("portable workspace metadata does not match the assignment fence")]
    InvalidWorkspaceMetadata,
}

/// Owns the canonical portable metadata required by workspace creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStorageWorkspaceMetadataV1 {
    manifest: CanonicalAssignmentManifestV1,
    sandbox_spec: SandboxSpec,
    manifest_bytes: Vec<u8>,
    sandbox_spec_bytes: Vec<u8>,
}

impl CanonicalStorageWorkspaceMetadataV1 {
    /// Returns the exact canonical assignment manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }

    /// Returns the exact canonical sandbox specification.
    #[must_use]
    pub const fn sandbox_spec(&self) -> &SandboxSpec {
        &self.sandbox_spec
    }

    /// Returns the exact manifest bytes committed by signed semantics.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Returns the exact sandbox-spec bytes committed by signed semantics.
    #[must_use]
    pub fn sandbox_spec_bytes(&self) -> &[u8] {
        &self.sandbox_spec_bytes
    }
}

/// Carries the sole catalog association permitted in portable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogBindingV1 {
    generation: u64,
    digest: ObjectDigest,
}

impl CatalogBindingV1 {
    /// Adopts an opaque catalog generation and digest.
    ///
    /// # Errors
    ///
    /// Returns [`StorageSemanticsError::InvalidCatalogBinding`] for generation
    /// zero or the all-zero digest.
    pub fn from_publisher(
        generation: u64,
        digest: ObjectDigest,
    ) -> Result<Self, StorageSemanticsError> {
        if generation == 0 || digest.as_bytes() == &[0; 32] {
            Err(StorageSemanticsError::InvalidCatalogBinding)
        } else {
            Ok(Self { generation, digest })
        }
    }

    /// Returns the exact catalog generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the opaque catalog digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }
}

/// Names one validated fixed-function storage mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    /// Creates an empty private workspace with a finite byte quota.
    CreateWorkspace {
        /// Hard logical byte ceiling.
        quota_bytes: u64,
    },
    /// Creates a new immutable version of an existing workspace.
    Snapshot {
        /// Broker-minted workspace handle.
        storage_handle: [u8; 32],
    },
    /// Adds an AOS retention hold to an exact immutable version.
    HoldSnapshot {
        /// Owning workspace handle.
        storage_handle: [u8; 32],
        /// Immutable version handle.
        version_handle: [u8; 32],
    },
    /// Releases an AOS retention hold from an exact immutable version.
    ReleaseHold {
        /// Owning workspace handle.
        storage_handle: [u8; 32],
        /// Immutable version handle.
        version_handle: [u8; 32],
    },
    /// Clones an exact immutable version into a finite workspace.
    Clone {
        /// Source workspace handle.
        storage_handle: [u8; 32],
        /// Source version handle.
        version_handle: [u8; 32],
        /// New private quota.
        quota_bytes: u64,
    },
    /// Replaces the finite quota on an existing workspace.
    SetQuota {
        /// Workspace handle.
        storage_handle: [u8; 32],
        /// New private quota.
        quota_bytes: u64,
    },
    /// Destroys exactly one workspace or immutable version.
    Destroy {
        /// Workspace handle.
        storage_handle: [u8; 32],
        /// Optional exact version handle.
        version_handle: Option<[u8; 32]>,
    },
}

impl StorageOperation {
    /// Reports whether the action creates a workspace and therefore requires
    /// portable workspace metadata.
    #[must_use]
    pub const fn requires_workspace_metadata(self) -> bool {
        matches!(self, Self::CreateWorkspace { .. } | Self::Clone { .. })
    }

    /// Returns the authority verb selected by this operation.
    #[must_use]
    pub const fn broker_verb(self) -> BrokerVerb {
        match self {
            Self::CreateWorkspace { .. } => BrokerVerb::StorageCreateWorkspace,
            Self::Snapshot { .. } => BrokerVerb::StorageSnapshot,
            Self::HoldSnapshot { .. } => BrokerVerb::StorageHoldSnapshot,
            Self::ReleaseHold { .. } => BrokerVerb::StorageReleaseHold,
            Self::Clone { .. } => BrokerVerb::StorageClone,
            Self::SetQuota { .. } => BrokerVerb::StorageSetQuota,
            Self::Destroy { .. } => BrokerVerb::StorageDestroy,
        }
    }

    /// Returns the exact authority grant target for this operation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageSemanticsError::InvalidActionShape`] when an
    /// existing-resource operation contains the reserved zero handle.
    pub fn grant_target(self) -> Result<BrokerGrantTarget, StorageSemanticsError> {
        match self.storage_handle() {
            None => Ok(BrokerGrantTarget::Assignment),
            Some(handle) => BrokerResourceHandle::from_bytes(handle)
                .map(BrokerGrantTarget::Resource)
                .map_err(|_| StorageSemanticsError::InvalidActionShape),
        }
    }

    /// Reconstructs the canonical persisted-effect commitment.
    ///
    /// This is the same encoder used for live request admission. It lets a
    /// broker bind an authenticated durable effect back to its assignment,
    /// operation, and opaque catalog immediately before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`StorageSemanticsError`] for a zero operation identity,
    /// invalid resource target, or canonical-size overflow.
    pub fn persisted_argument_commitment(
        self,
        assignment: BrokerAssignment,
        operation_id: [u8; 16],
        catalog: CatalogBindingV1,
    ) -> Result<BrokerArgumentCommitment, StorageSemanticsError> {
        if operation_id == [0; 16] {
            return Err(StorageSemanticsError::InvalidActionShape);
        }
        self.grant_target()?;
        let bytes = encode_canonical(
            *assignment.sandbox().as_bytes(),
            *assignment.incarnation().as_bytes(),
            assignment.epoch().get(),
            assignment.desired_generation().get(),
            *assignment.digest().as_bytes(),
            operation_id,
            self,
            catalog,
            None,
        )?;
        Ok(BrokerArgumentCommitment::for_canonical_bytes(&bytes))
    }

    /// Reconstructs a workspace commitment from durable portable metadata.
    ///
    /// This uses the same validation and canonical encoder as live request
    /// admission. The byte slices must therefore be the exact canonical
    /// manifest and sandbox specification retained with the operation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageSemanticsError`] when metadata is absent, malformed,
    /// noncanonical, or does not bind the supplied assignment and operation.
    pub fn persisted_workspace_argument_commitment(
        self,
        assignment: BrokerAssignment,
        operation_id: [u8; 16],
        catalog: CatalogBindingV1,
        manifest_bytes: &[u8],
        sandbox_spec_bytes: &[u8],
    ) -> Result<BrokerArgumentCommitment, StorageSemanticsError> {
        if operation_id == [0; 16] {
            return Err(StorageSemanticsError::InvalidActionShape);
        }
        self.grant_target()?;
        let metadata =
            decode_workspace_metadata(self, assignment, manifest_bytes, sandbox_spec_bytes)?
                .ok_or(StorageSemanticsError::InvalidWorkspaceMetadata)?;
        let bytes = encode_canonical(
            *assignment.sandbox().as_bytes(),
            *assignment.incarnation().as_bytes(),
            assignment.epoch().get(),
            assignment.desired_generation().get(),
            *assignment.digest().as_bytes(),
            operation_id,
            self,
            catalog,
            Some(&metadata),
        )?;
        Ok(BrokerArgumentCommitment::for_canonical_bytes(&bytes))
    }

    const fn action_code(self) -> u8 {
        match self {
            Self::CreateWorkspace { .. } => 1,
            Self::Snapshot { .. } => 2,
            Self::HoldSnapshot { .. } => 3,
            Self::ReleaseHold { .. } => 4,
            Self::Clone { .. } => 5,
            Self::SetQuota { .. } => 6,
            Self::Destroy { .. } => 7,
        }
    }

    const fn storage_handle(self) -> Option<[u8; 32]> {
        match self {
            Self::CreateWorkspace { .. } => None,
            Self::Snapshot { storage_handle }
            | Self::HoldSnapshot { storage_handle, .. }
            | Self::ReleaseHold { storage_handle, .. }
            | Self::Clone { storage_handle, .. }
            | Self::SetQuota { storage_handle, .. }
            | Self::Destroy { storage_handle, .. } => Some(storage_handle),
        }
    }

    const fn version_handle(self) -> Option<[u8; 32]> {
        match self {
            Self::HoldSnapshot { version_handle, .. }
            | Self::ReleaseHold { version_handle, .. }
            | Self::Clone { version_handle, .. } => Some(version_handle),
            Self::Destroy { version_handle, .. } => version_handle,
            Self::CreateWorkspace { .. } | Self::Snapshot { .. } | Self::SetQuota { .. } => None,
        }
    }

    const fn quota_bytes(self) -> u64 {
        match self {
            Self::CreateWorkspace { quota_bytes }
            | Self::Clone { quota_bytes, .. }
            | Self::SetQuota { quota_bytes, .. } => quota_bytes,
            Self::Snapshot { .. }
            | Self::HoldSnapshot { .. }
            | Self::ReleaseHold { .. }
            | Self::Destroy { .. } => 0,
        }
    }
}

/// Carries a validated request and its immutable portable authority meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStorageSemanticsV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    operation: StorageOperation,
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    target: BrokerGrantTarget,
    catalog: CatalogBindingV1,
    workspace_metadata: Option<CanonicalStorageWorkspaceMetadataV1>,
}

impl CanonicalStorageSemanticsV1 {
    /// Decodes hostile protobuf bytes and constructs their sole portable V1 meaning.
    ///
    /// # Errors
    ///
    /// Returns [`StorageSemanticsError`] for an oversized or malformed message,
    /// unknown fields/action, peer/header/fence failure, invalid identifiers or
    /// action shape, or a canonical byte-bound violation.
    pub fn decode(
        bytes: &[u8],
        catalog: CatalogBindingV1,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageSemanticsError> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }
        let request = ApplyStorageRequest::decode_from_slice(bytes)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields.into());
        }
        let header = request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?;
        let header = validate_request_header(
            header,
            peer,
            policy,
            ProtocolId::StorageBroker,
            now_boottime_nanoseconds,
        )?;
        let fence = request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?;
        if !fence.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields.into());
        }

        let sandbox_id = exact_nonzero::<16>(&fence.sandbox_id, "fence.sandbox_id")?;
        let incarnation_id = exact_nonzero::<16>(&fence.incarnation_id, "fence.incarnation_id")?;
        if fence.assignment_epoch == 0 {
            return Err(ProtocolValidationError::InvalidField("fence.assignment_epoch").into());
        }
        if fence.desired_generation == 0 {
            return Err(ProtocolValidationError::InvalidField("fence.desired_generation").into());
        }
        let assignment_digest =
            exact_nonzero::<32>(&fence.assignment_digest, "fence.assignment_digest")?;
        let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
        let storage = optional_nonzero::<32>(&request.storage_handle, "storage_handle")?;
        let version =
            optional_nonzero::<32>(&request.source_version_handle, "source_version_handle")?;
        let action = request
            .action
            .as_known()
            .filter(|value| *value != StorageAction::STORAGE_ACTION_UNSPECIFIED)
            .ok_or(ProtocolValidationError::UnknownAction)?;
        let operation = operation_for(action, storage, version, request.quota_bytes)?;
        let assignment = BrokerAssignment::new(
            aos_sandbox_core::SandboxId::from_bytes(sandbox_id),
            aos_sandbox_core::IncarnationId::from_bytes(incarnation_id),
            aos_sandbox_core::AssignmentEpoch::new(fence.assignment_epoch),
            aos_sandbox_core::DesiredGeneration::new(fence.desired_generation),
            ObjectDigest::from_bytes(assignment_digest),
        )
        .map_err(|_| StorageSemanticsError::InvalidWorkspaceMetadata)?;
        let workspace_metadata = decode_workspace_metadata(
            operation,
            assignment,
            &request.assignment_manifest,
            &request.sandbox_spec,
        )?;
        let target = operation.grant_target()?;
        let bytes = encode_canonical(
            sandbox_id,
            incarnation_id,
            fence.assignment_epoch,
            fence.desired_generation,
            assignment_digest,
            operation_id,
            operation,
            catalog,
            workspace_metadata.as_ref(),
        )?;
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(&bytes);
        Ok(Self {
            header,
            operation_id,
            operation,
            bytes,
            commitment,
            target,
            catalog,
            workspace_metadata,
        })
    }

    /// Returns the validated common request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }
    /// Returns the durable nonzero operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }
    /// Returns the closed storage operation.
    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }
    /// Returns exact versioned canonical authority bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Returns the domain-separated argument commitment.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }
    /// Returns the assignment or existing-resource grant target.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        self.target
    }
    /// Returns the exact storage-broker verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        self.operation.broker_verb()
    }
    /// Returns the opaque catalog association in portable semantics.
    #[must_use]
    pub const fn catalog_binding(&self) -> CatalogBindingV1 {
        self.catalog
    }

    /// Returns the portable workspace metadata, when required.
    #[must_use]
    pub const fn workspace_metadata(&self) -> Option<&CanonicalStorageWorkspaceMetadataV1> {
        self.workspace_metadata.as_ref()
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_canonical(
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    operation_id: [u8; 16],
    operation: StorageOperation,
    catalog: CatalogBindingV1,
    workspace_metadata: Option<&CanonicalStorageWorkspaceMetadataV1>,
) -> Result<Vec<u8>, StorageSemanticsError> {
    let mut encoder = Encoder::new();
    encoder.field(1, FORMAT_MAGIC)?;
    encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
    encoder.field(3, &[operation.action_code()])?;
    encoder.field(4, &sandbox_id)?;
    encoder.field(5, &incarnation_id)?;
    encoder.field(6, &assignment_epoch.to_be_bytes())?;
    encoder.field(7, &desired_generation.to_be_bytes())?;
    encoder.field(8, &assignment_digest)?;
    encoder.field(9, &operation_id)?;
    encoder.optional_fixed(10, operation.storage_handle().as_ref())?;
    encoder.optional_fixed(11, operation.version_handle().as_ref())?;
    encoder.field(12, &operation.quota_bytes().to_be_bytes())?;
    encoder.field(13, &catalog.generation().to_be_bytes())?;
    encoder.field(14, catalog.digest().as_bytes())?;
    if let Some(metadata) = workspace_metadata {
        encoder.field(15, metadata.manifest_bytes())?;
        encoder.field(16, metadata.sandbox_spec_bytes())?;
    }
    Ok(encoder.finish())
}

fn decode_workspace_metadata(
    operation: StorageOperation,
    assignment: BrokerAssignment,
    manifest_bytes: &[u8],
    sandbox_spec_bytes: &[u8],
) -> Result<Option<CanonicalStorageWorkspaceMetadataV1>, StorageSemanticsError> {
    let creates_workspace = operation.requires_workspace_metadata();
    if !creates_workspace {
        if !manifest_bytes.is_empty() || !sandbox_spec_bytes.is_empty() {
            return Err(StorageSemanticsError::InvalidWorkspaceMetadata);
        }
        return Ok(None);
    }
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAXIMUM_ASSIGNMENT_MANIFEST_BYTES
        || sandbox_spec_bytes.is_empty()
        || sandbox_spec_bytes.len() > MAXIMUM_SANDBOX_SPEC_BYTES
    {
        return Err(StorageSemanticsError::InvalidWorkspaceMetadata);
    }
    let manifest = CanonicalAssignmentManifestV1::from_canonical_bytes(
        manifest_bytes,
        metadata_decode_limits(MAXIMUM_ASSIGNMENT_MANIFEST_BYTES),
    )
    .map_err(|_| StorageSemanticsError::InvalidWorkspaceMetadata)?;
    let sandbox_spec = decode_sandbox_spec(
        sandbox_spec_bytes,
        metadata_decode_limits(MAXIMUM_SANDBOX_SPEC_BYTES),
    )
    .map_err(|_| StorageSemanticsError::InvalidWorkspaceMetadata)?;
    let spec_descriptor = descriptor_for_bytes(
        manifest.manifest().sandbox_spec().media_type().clone(),
        sandbox_spec_bytes,
    );
    if encode_sandbox_spec(&sandbox_spec) != sandbox_spec_bytes
        || manifest
            .broker_assignment()
            .map_err(|_| StorageSemanticsError::InvalidWorkspaceMetadata)?
            != assignment
        || &spec_descriptor != manifest.manifest().sandbox_spec()
        || manifest.manifest().root_view() != sandbox_spec.root_view()
        || manifest.manifest().environment() != sandbox_spec.environment()
    {
        return Err(StorageSemanticsError::InvalidWorkspaceMetadata);
    }
    Ok(Some(CanonicalStorageWorkspaceMetadataV1 {
        manifest,
        sandbox_spec,
        manifest_bytes: manifest_bytes.to_vec(),
        sandbox_spec_bytes: sandbox_spec_bytes.to_vec(),
    }))
}

fn metadata_decode_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 4_096,
        maximum_total_items: 16_384,
        maximum_byte_string_bytes: maximum_bytes,
        maximum_text_bytes: 4_096,
        maximum_depth: 64,
    }
}

fn operation_for(
    action: StorageAction,
    storage: Option<[u8; 32]>,
    version: Option<[u8; 32]>,
    quota: u64,
) -> Result<StorageOperation, StorageSemanticsError> {
    match (action, storage, version, quota) {
        (StorageAction::STORAGE_ACTION_CREATE_WORKSPACE, None, None, 1..) => {
            Ok(StorageOperation::CreateWorkspace { quota_bytes: quota })
        }
        (StorageAction::STORAGE_ACTION_SNAPSHOT, Some(storage_handle), None, 0) => {
            Ok(StorageOperation::Snapshot { storage_handle })
        }
        (
            StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT,
            Some(storage_handle),
            Some(version_handle),
            0,
        ) => Ok(StorageOperation::HoldSnapshot {
            storage_handle,
            version_handle,
        }),
        (
            StorageAction::STORAGE_ACTION_RELEASE_HOLD,
            Some(storage_handle),
            Some(version_handle),
            0,
        ) => Ok(StorageOperation::ReleaseHold {
            storage_handle,
            version_handle,
        }),
        (StorageAction::STORAGE_ACTION_CLONE, Some(storage_handle), Some(version_handle), 1..) => {
            Ok(StorageOperation::Clone {
                storage_handle,
                version_handle,
                quota_bytes: quota,
            })
        }
        (StorageAction::STORAGE_ACTION_SET_QUOTA, Some(storage_handle), None, 1..) => {
            Ok(StorageOperation::SetQuota {
                storage_handle,
                quota_bytes: quota,
            })
        }
        (StorageAction::STORAGE_ACTION_DESTROY, Some(storage_handle), version_handle, 0) => {
            Ok(StorageOperation::Destroy {
                storage_handle,
                version_handle,
            })
        }
        _ => Err(StorageSemanticsError::InvalidActionShape),
    }
}

fn exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolValidationError> {
    let value = bytes
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidFixedBytes { field, bytes: N })?;
    if value == [0; N] {
        Err(ProtocolValidationError::InvalidFixedBytes { field, bytes: N })
    } else {
        Ok(value)
    }
}

fn optional_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<Option<[u8; N]>, ProtocolValidationError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        exact_nonzero(bytes, field).map(Some)
    }
}

struct Encoder {
    bytes: Vec<u8>,
}
impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(256),
        }
    }
    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), StorageSemanticsError> {
        let length = u32::try_from(value.len())
            .map_err(|_| StorageSemanticsError::CanonicalEncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(StorageSemanticsError::CanonicalEncodingTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn optional_fixed<const N: usize>(
        &mut self,
        tag: u8,
        value: Option<&[u8; N]>,
    ) -> Result<(), StorageSemanticsError> {
        self.field(tag, value.map(<[u8; N]>::as_slice).unwrap_or_default())
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU32;

    use aos_proto::aos::sandbox::local::v1::Audience;
    use aos_sandbox_core::model::{
        AssignmentManifestV1, IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile,
        SandboxAncestry, UnmappableIdentityPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, MediaType,
        NamespaceGeneration, NodeId, ObjectDescriptor, PortableMediaType, ProjectId,
        ResourceVector, SandboxId,
    };

    use super::*;

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn create() -> ApplyStorageRequest {
        let mut request = ApplyStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = StorageAction::STORAGE_ACTION_CREATE_WORKSPACE.into();
        request.operation_id = vec![7; 16];
        request.quota_bytes = 1024;
        request
    }

    fn descriptor(kind: PortableMediaType, marker: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([marker; 32]),
            1,
        )
    }

    fn workspace_metadata() -> (CanonicalAssignmentManifestV1, Vec<u8>) {
        let specification = SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(Vec::new()).unwrap(),
            descriptor(PortableMediaType::Environment, 8),
            descriptor(PortableMediaType::View, 9),
            Vec::new(),
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let specification_bytes = encode_sandbox_spec(&specification);
        let specification_descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::SandboxSpec.as_str().to_owned()).unwrap(),
            &specification_bytes,
        );
        let manifest = AssignmentManifestV1::new(
            SandboxId::from_bytes([2; 16]),
            ProjectId::from_bytes([10; 16]),
            SandboxAncestry::new(SandboxId::from_bytes([2; 16]), Vec::new()).unwrap(),
            IncarnationId::from_bytes([3; 16]),
            NodeId::from_bytes([11; 16]),
            AssignmentEpoch::new(4),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            specification_descriptor,
            descriptor(PortableMediaType::Policy, 12),
            specification.environment().clone(),
            specification.root_view().clone(),
            Vec::new(),
            ObjectDigest::from_bytes([13; 32]),
            ResourceVector::ZERO,
            Vec::new(),
        )
        .unwrap();
        (
            CanonicalAssignmentManifestV1::new(manifest),
            specification_bytes,
        )
    }

    fn create_with_metadata() -> (ApplyStorageRequest, CanonicalAssignmentManifestV1, Vec<u8>) {
        let (manifest, specification_bytes) = workspace_metadata();
        let mut request = create();
        request.fence.get_or_insert_default().assignment_digest =
            manifest.digest().as_bytes().to_vec();
        request.assignment_manifest = manifest.canonical_bytes().to_vec();
        request.sandbox_spec.clone_from(&specification_bytes);
        (request, manifest, specification_bytes)
    }

    #[test]
    fn portable_storage_commitment_has_a_fixed_golden_digest() {
        let binding = CatalogBindingV1::from_publisher(
            9,
            ObjectDigest::from_bytes([
                177, 72, 228, 193, 210, 140, 58, 143, 138, 222, 179, 67, 233, 178, 253, 65, 2, 16,
                58, 28, 223, 91, 196, 107, 234, 245, 80, 144, 23, 248, 26, 177,
            ]),
        )
        .unwrap();
        let (request, _, _) = create_with_metadata();
        let semantics = CanonicalStorageSemanticsV1::decode(
            &request.encode_to_vec(),
            binding,
            peer(),
            policy(),
            100,
        )
        .unwrap();
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                237, 171, 81, 35, 25, 158, 189, 43, 154, 159, 10, 201, 171, 59, 60, 100, 116, 237,
                113, 67, 57, 41, 128, 106, 131, 105, 174, 173, 61, 211, 100, 131,
            ]
        );
        assert!(
            !semantics
                .canonical_bytes()
                .windows(4)
                .any(|bytes| bytes == b"tank")
        );
    }

    #[test]
    fn portable_compiler_rejects_action_field_smuggling() {
        let (mut request, _, _) = create_with_metadata();
        request.storage_handle = vec![8; 32];
        let binding =
            CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([1; 32])).unwrap();
        assert_eq!(
            CanonicalStorageSemanticsV1::decode(
                &request.encode_to_vec(),
                binding,
                peer(),
                policy(),
                100,
            ),
            Err(StorageSemanticsError::InvalidActionShape)
        );
    }

    #[test]
    fn live_and_persisted_workspace_commitments_are_identical() {
        let (request, manifest, specification_bytes) = create_with_metadata();
        let binding =
            CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([1; 32])).unwrap();
        let semantics = CanonicalStorageSemanticsV1::decode(
            &request.encode_to_vec(),
            binding,
            peer(),
            policy(),
            100,
        )
        .unwrap();
        let assignment = manifest.broker_assignment().unwrap();
        let persisted = semantics
            .operation()
            .persisted_workspace_argument_commitment(
                assignment,
                *semantics.operation_id(),
                binding,
                manifest.canonical_bytes(),
                &specification_bytes,
            )
            .unwrap();

        assert_eq!(semantics.argument_commitment(), persisted);
        assert!(semantics.workspace_metadata().is_some());
    }

    #[test]
    fn workspace_metadata_rejects_substitution_and_oversize() {
        let (request, _, _) = create_with_metadata();
        let binding =
            CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([1; 32])).unwrap();

        let mut substituted = request.clone();
        substituted.fence.get_or_insert_default().assignment_digest[0] ^= 1;
        assert_eq!(
            CanonicalStorageSemanticsV1::decode(
                &substituted.encode_to_vec(),
                binding,
                peer(),
                policy(),
                100,
            ),
            Err(StorageSemanticsError::InvalidWorkspaceMetadata)
        );

        let mut substituted = request.clone();
        substituted.sandbox_spec[0] ^= 1;
        assert_eq!(
            CanonicalStorageSemanticsV1::decode(
                &substituted.encode_to_vec(),
                binding,
                peer(),
                policy(),
                100,
            ),
            Err(StorageSemanticsError::InvalidWorkspaceMetadata)
        );

        let mut oversized = request;
        oversized.assignment_manifest = vec![1; MAXIMUM_ASSIGNMENT_MANIFEST_BYTES + 1];
        assert_eq!(
            CanonicalStorageSemanticsV1::decode(
                &oversized.encode_to_vec(),
                binding,
                peer(),
                policy(),
                100,
            ),
            Err(StorageSemanticsError::InvalidWorkspaceMetadata)
        );

        let mut unknown_field = oversized.encode_to_vec();
        unknown_field.extend_from_slice(&[0x52, 0x01, 0x00]);
        assert_eq!(
            CanonicalStorageSemanticsV1::decode(&unknown_field, binding, peer(), policy(), 100,),
            Err(StorageSemanticsError::Protocol(
                ProtocolValidationError::UnknownFields
            ))
        );
    }

    #[test]
    fn workspace_metadata_requirement_covers_exactly_create_and_clone() {
        let storage_handle = [1; 32];
        let version_handle = [2; 32];
        let operations = [
            (StorageOperation::CreateWorkspace { quota_bytes: 1 }, true),
            (StorageOperation::Snapshot { storage_handle }, false),
            (
                StorageOperation::HoldSnapshot {
                    storage_handle,
                    version_handle,
                },
                false,
            ),
            (
                StorageOperation::ReleaseHold {
                    storage_handle,
                    version_handle,
                },
                false,
            ),
            (
                StorageOperation::Clone {
                    storage_handle,
                    version_handle,
                    quota_bytes: 1,
                },
                true,
            ),
            (
                StorageOperation::SetQuota {
                    storage_handle,
                    quota_bytes: 1,
                },
                false,
            ),
            (
                StorageOperation::Destroy {
                    storage_handle,
                    version_handle: None,
                },
                false,
            ),
        ];

        for (operation, expected) in operations {
            assert_eq!(operation.requires_workspace_metadata(), expected);
        }
    }
}
