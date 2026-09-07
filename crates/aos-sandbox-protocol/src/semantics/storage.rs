//! Canonical portable authority semantics for storage requests.
//!
//! Storage V1 encodes tagged, length-delimited fields in ascending tag order:
//!
//! ```text
//! field := tag:u8 || length:u32be || value:length
//! fields := magic, version, action, assignment fence, operation ID,
//!           optional storage handle, optional version handle, quota,
//!           opaque catalog generation, opaque catalog digest
//! ```
//!
//! The catalog association is opaque portable input. It authenticates a
//! node-local resolution without carrying ZFS names, GUIDs, or properties.

use aos_proto::aos::sandbox::local::v1::{ApplyStorageRequest, StorageAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ObjectDigest,
    ProtocolId,
};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_BYTES: usize = 32 * 1024;

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
    #[error("canonical storage semantics exceed the V1 byte ceiling")]
    CanonicalEncodingTooLarge,
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
        let target = match operation.storage_handle() {
            None => BrokerGrantTarget::Assignment,
            Some(handle) => BrokerGrantTarget::Resource(
                BrokerResourceHandle::from_bytes(handle)
                    .map_err(|_| StorageSemanticsError::InvalidActionShape)?,
            ),
        };
        let mut encoder = Encoder::new();
        encoder.field(1, FORMAT_MAGIC)?;
        encoder.field(2, &FORMAT_VERSION.to_be_bytes())?;
        encoder.field(3, &[operation.action_code()])?;
        encoder.field(4, &sandbox_id)?;
        encoder.field(5, &incarnation_id)?;
        encoder.field(6, &fence.assignment_epoch.to_be_bytes())?;
        encoder.field(7, &fence.desired_generation.to_be_bytes())?;
        encoder.field(8, &assignment_digest)?;
        encoder.field(9, &operation_id)?;
        encoder.optional_fixed(10, operation.storage_handle().as_ref())?;
        encoder.optional_fixed(11, operation.version_handle().as_ref())?;
        encoder.field(12, &operation.quota_bytes().to_be_bytes())?;
        encoder.field(13, &catalog.generation().to_be_bytes())?;
        encoder.field(14, catalog.digest().as_bytes())?;
        let bytes = encoder.finish();
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(&bytes);
        Ok(Self {
            header,
            operation_id,
            operation,
            bytes,
            commitment,
            target,
            catalog,
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

    use aos_proto::aos::sandbox::local::v1::Audience;

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
        let semantics = CanonicalStorageSemanticsV1::decode(
            &create().encode_to_vec(),
            binding,
            peer(),
            policy(),
            100,
        )
        .unwrap();
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                85, 58, 176, 86, 105, 221, 225, 64, 92, 183, 216, 216, 221, 171, 103, 28, 107, 183,
                117, 144, 168, 56, 6, 107, 40, 245, 81, 115, 162, 149, 231, 200,
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
        let mut request = create();
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
}
