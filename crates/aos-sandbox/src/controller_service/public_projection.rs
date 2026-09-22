//! Durable public-resource projections retained with accepted desired state.
//!
//! A projection value uses this fixed representation:
//!
//! ```text
//! AOSPRJ01 | version:u16be | kind:u8 | flags:u8 | project:16 |
//! resource:16 | operation:16 | protobuf-len:u32be | protobuf-sha256:32 |
//! canonical-protobuf
//! ```
//!
//! Keys use a reserved prefix followed by the kind byte and resource identity.
//! The record is a checked public projection, not observed-success evidence.
//! Reconcilers must replace requested or pending fields only from authoritative
//! broker receipts and inventory.

use aos_proto::aos::sandbox::v1::{
    Attachment, CacheStatus, Capability, Execution, FilesystemView, Sandbox, Snapshot,
};
use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::cli_model::{AuditAuthorizationV1, CheckedCacheStatusV1};
use crate::controller_query::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedSandboxResourceV1, CheckedSnapshotResourceV1,
    InvalidPublicResource, MAXIMUM_PUBLIC_RESOURCE_BYTES,
};
use crate::{Journal, RecordNamespace};

const PROJECTION_MAGIC: &[u8; 8] = b"AOSPRJ01";
const PROJECTION_VERSION: u16 = 1;
const PROJECTION_FLAGS: u8 = 0;
const PROJECTION_KEY_PREFIX: &[u8] = b"aos.public.resource.v1\0";
const PROJECTION_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 16 + 16 + 16 + 4 + 32;

/// Identifies one durable public projection schema.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PublicProjectionKindV1 {
    /// A sandbox resource.
    Sandbox = 1,
    /// An execution resource.
    Execution = 2,
    /// A filesystem-view resource.
    FilesystemView = 3,
    /// A filesystem-view attachment resource.
    Attachment = 4,
    /// A snapshot resource.
    Snapshot = 5,
    /// A redacted capability resource.
    Capability = 6,
    /// Cache accounting scoped to one project.
    ProjectCacheStatus = 7,
    /// Cache accounting scoped to one sandbox.
    SandboxCacheStatus = 8,
}

impl PublicProjectionKindV1 {
    fn from_byte(value: u8) -> Result<Self, PublicProjectionError> {
        match value {
            1 => Ok(Self::Sandbox),
            2 => Ok(Self::Execution),
            3 => Ok(Self::FilesystemView),
            4 => Ok(Self::Attachment),
            5 => Ok(Self::Snapshot),
            6 => Ok(Self::Capability),
            7 => Ok(Self::ProjectCacheStatus),
            8 => Ok(Self::SandboxCacheStatus),
            _ => Err(PublicProjectionError::CorruptRecord),
        }
    }
}

/// Stores one deeply checked portable resource projection.
#[derive(Clone, Debug, PartialEq)]
pub enum PublicProjectionResourceV1 {
    /// A sandbox projection.
    Sandbox(Sandbox),
    /// An execution projection with holder credentials removed on readback.
    Execution(Execution),
    /// A filesystem-view projection.
    FilesystemView(FilesystemView),
    /// An attachment projection.
    Attachment(Attachment),
    /// A snapshot projection.
    Snapshot(Snapshot),
    /// A non-secret capability projection.
    Capability(Capability),
    /// Cache accounting for the project identified by the record key.
    ProjectCacheStatus {
        /// Names the project scope.
        project_id: [u8; 16],
        /// Carries checked public cache accounting.
        status: CacheStatus,
    },
    /// Cache accounting for the sandbox identified by the record key.
    SandboxCacheStatus {
        /// Names the sandbox scope.
        sandbox_id: [u8; 16],
        /// Carries checked public cache accounting.
        status: CacheStatus,
    },
}

impl PublicProjectionResourceV1 {
    /// Returns the closed projection kind.
    #[must_use]
    pub const fn kind(&self) -> PublicProjectionKindV1 {
        match self {
            Self::Sandbox(_) => PublicProjectionKindV1::Sandbox,
            Self::Execution(_) => PublicProjectionKindV1::Execution,
            Self::FilesystemView(_) => PublicProjectionKindV1::FilesystemView,
            Self::Attachment(_) => PublicProjectionKindV1::Attachment,
            Self::Snapshot(_) => PublicProjectionKindV1::Snapshot,
            Self::Capability(_) => PublicProjectionKindV1::Capability,
            Self::ProjectCacheStatus { .. } => PublicProjectionKindV1::ProjectCacheStatus,
            Self::SandboxCacheStatus { .. } => PublicProjectionKindV1::SandboxCacheStatus,
        }
    }

    /// Returns the exact stable identity carried by the resource.
    #[must_use]
    pub fn resource_id(&self) -> &[u8] {
        match self {
            Self::Sandbox(value) => &value.sandbox_id,
            Self::Execution(value) => &value.execution_id,
            Self::FilesystemView(value) => &value.view_id,
            Self::Attachment(value) => &value.attachment_id,
            Self::Snapshot(value) => &value.snapshot_id,
            Self::Capability(value) => &value.capability_id,
            Self::ProjectCacheStatus { project_id, .. } => project_id,
            Self::SandboxCacheStatus { sandbox_id, .. } => sandbox_id,
        }
    }

    fn encode_checked(self) -> Result<(Self, Vec<u8>), PublicProjectionError> {
        let checked = match self {
            Self::Sandbox(value) => Self::Sandbox(
                CheckedSandboxResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::Execution(value) => Self::Execution(
                CheckedExecutionResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::FilesystemView(value) => Self::FilesystemView(
                CheckedFilesystemViewResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::Attachment(value) => Self::Attachment(
                CheckedAttachmentResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::Snapshot(value) => Self::Snapshot(
                CheckedSnapshotResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::Capability(value) => Self::Capability(
                CheckedCapabilityResourceV1::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto(),
            ),
            Self::ProjectCacheStatus { project_id, status } => Self::ProjectCacheStatus {
                project_id,
                status: CheckedCacheStatusV1::try_from(status)
                    .map_err(|_| PublicProjectionError::InvalidCacheStatus)?
                    .into_proto(),
            },
            Self::SandboxCacheStatus { sandbox_id, status } => Self::SandboxCacheStatus {
                sandbox_id,
                status: CheckedCacheStatusV1::try_from(status)
                    .map_err(|_| PublicProjectionError::InvalidCacheStatus)?
                    .into_proto(),
            },
        };
        let bytes = match &checked {
            Self::Sandbox(value) => value.encode_to_vec(),
            Self::Execution(value) => value.encode_to_vec(),
            Self::FilesystemView(value) => value.encode_to_vec(),
            Self::Attachment(value) => value.encode_to_vec(),
            Self::Snapshot(value) => value.encode_to_vec(),
            Self::Capability(value) => value.encode_to_vec(),
            Self::ProjectCacheStatus { status, .. } | Self::SandboxCacheStatus { status, .. } => {
                status.encode_to_vec()
            }
        };
        if bytes.is_empty() || bytes.len() > MAXIMUM_PUBLIC_RESOURCE_BYTES {
            return Err(PublicProjectionError::ResourceTooLarge);
        }

        Ok((checked, bytes))
    }

    fn decode_checked(
        kind: PublicProjectionKindV1,
        resource_id: [u8; 16],
        bytes: &[u8],
    ) -> Result<Self, PublicProjectionError> {
        macro_rules! decode {
            ($message:ty, $checked:ty, $variant:ident) => {{
                let value = <$message>::decode_from_slice(bytes)
                    .map_err(|_| PublicProjectionError::CorruptRecord)?;
                if value.encode_to_vec() != bytes {
                    return Err(PublicProjectionError::CorruptRecord);
                }
                let value = <$checked>::try_from(value)
                    .map_err(PublicProjectionError::InvalidResource)?
                    .into_proto();
                Self::$variant(value)
            }};
        }

        Ok(match kind {
            PublicProjectionKindV1::Sandbox => {
                decode!(Sandbox, CheckedSandboxResourceV1, Sandbox)
            }
            PublicProjectionKindV1::Execution => {
                decode!(Execution, CheckedExecutionResourceV1, Execution)
            }
            PublicProjectionKindV1::FilesystemView => decode!(
                FilesystemView,
                CheckedFilesystemViewResourceV1,
                FilesystemView
            ),
            PublicProjectionKindV1::Attachment => {
                decode!(Attachment, CheckedAttachmentResourceV1, Attachment)
            }
            PublicProjectionKindV1::Snapshot => {
                decode!(Snapshot, CheckedSnapshotResourceV1, Snapshot)
            }
            PublicProjectionKindV1::Capability => {
                decode!(Capability, CheckedCapabilityResourceV1, Capability)
            }
            PublicProjectionKindV1::ProjectCacheStatus => {
                let status = CacheStatus::decode_from_slice(bytes)
                    .map_err(|_| PublicProjectionError::CorruptRecord)?;
                if status.encode_to_vec() != bytes {
                    return Err(PublicProjectionError::CorruptRecord);
                }
                let status = CheckedCacheStatusV1::try_from(status)
                    .map_err(|_| PublicProjectionError::InvalidCacheStatus)?
                    .into_proto();
                Self::ProjectCacheStatus {
                    project_id: resource_id,
                    status,
                }
            }
            PublicProjectionKindV1::SandboxCacheStatus => {
                let status = CacheStatus::decode_from_slice(bytes)
                    .map_err(|_| PublicProjectionError::CorruptRecord)?;
                if status.encode_to_vec() != bytes {
                    return Err(PublicProjectionError::CorruptRecord);
                }
                let status = CheckedCacheStatusV1::try_from(status)
                    .map_err(|_| PublicProjectionError::InvalidCacheStatus)?
                    .into_proto();
                Self::SandboxCacheStatus {
                    sandbox_id: resource_id,
                    status,
                }
            }
        })
    }
}

/// Carries a validated desired-state key and value for atomic admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicProjectionPlanV1 {
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
}

impl PublicProjectionPlanV1 {
    /// Constructs one versioned projection linked to its accepting operation.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] for zero or mismatched identities,
    /// an invalid public resource, or an oversized canonical protobuf.
    pub fn new(
        project: ProjectId,
        operation: OperationId,
        resource: PublicProjectionResourceV1,
    ) -> Result<Self, PublicProjectionError> {
        if project.as_bytes() == &[0; 16] || operation.as_bytes() == &[0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        let (resource, protobuf) = resource.encode_checked()?;
        let resource_id: [u8; 16] = resource
            .resource_id()
            .try_into()
            .map_err(|_| PublicProjectionError::InvalidIdentity)?;
        if resource_id == [0; 16] || !resource_matches_project(&resource, project) {
            return Err(PublicProjectionError::InvalidIdentity);
        }

        let kind = resource.kind();
        let desired_key = projection_key(kind, resource_id);
        let mut desired_value = Vec::with_capacity(PROJECTION_HEADER_BYTES + protobuf.len());
        desired_value.extend_from_slice(PROJECTION_MAGIC);
        desired_value.extend_from_slice(&PROJECTION_VERSION.to_be_bytes());
        desired_value.push(kind as u8);
        desired_value.push(PROJECTION_FLAGS);
        desired_value.extend_from_slice(project.as_bytes());
        desired_value.extend_from_slice(&resource_id);
        desired_value.extend_from_slice(operation.as_bytes());
        desired_value.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        desired_value.extend_from_slice(Sha256::digest(&protobuf).as_slice());
        desired_value.extend_from_slice(&protobuf);

        Ok(Self {
            desired_key,
            desired_value,
        })
    }

    /// Returns the reserved desired-state key.
    #[must_use]
    pub fn desired_key(&self) -> &[u8] {
        &self.desired_key
    }

    /// Returns the complete versioned desired-state value.
    #[must_use]
    pub fn desired_value(&self) -> &[u8] {
        &self.desired_value
    }

    /// Consumes the plan into the key and value accepted by [`crate::OperationPlan`].
    #[must_use]
    pub fn into_desired_state(self) -> (Vec<u8>, Vec<u8>) {
        (self.desired_key, self.desired_value)
    }
}

/// Stores one replay-validated durable public projection.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicProjectionRecordV1 {
    project: ProjectId,
    operation: OperationId,
    resource: PublicProjectionResourceV1,
    revision: ObjectDigest,
    encoded_bytes: usize,
}

/// Selects one bounded public projection read inside the controller worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicProjectionQueryV1 {
    /// Loads one exact resource identity.
    One {
        /// Selects the closed resource schema.
        kind: PublicProjectionKindV1,
        /// Names the exact stable resource.
        resource_id: [u8; 16],
    },
    /// Lists one resource schema within an authenticated project.
    List {
        /// Selects the closed resource schema.
        kind: PublicProjectionKindV1,
        /// Selects the exact project partition.
        project: ProjectId,
    },
    /// Resolves a scope resource and lists another kind in the same project.
    Related {
        /// Selects the returned resource schema.
        kind: PublicProjectionKindV1,
        /// Selects the resource whose project defines the partition.
        scope_kind: PublicProjectionKindV1,
        /// Names the exact scope resource.
        scope_id: [u8; 16],
    },
}

/// Carries authorization and checked rows from one worker-owned read.
#[must_use = "an authorized public projection read must be returned or deliberately discarded"]
pub struct AuthorizedPublicProjectionReadV1 {
    authorization: AuditAuthorizationV1,
    records: Vec<PublicProjectionRecordV1>,
}

impl AuthorizedPublicProjectionReadV1 {
    pub(crate) fn new(
        authorization: AuditAuthorizationV1,
        records: Vec<PublicProjectionRecordV1>,
    ) -> Self {
        Self {
            authorization,
            records,
        }
    }

    /// Consumes the read into its current authorization and checked rows.
    #[must_use]
    pub fn into_parts(self) -> (AuditAuthorizationV1, Vec<PublicProjectionRecordV1>) {
        (self.authorization, self.records)
    }
}

impl PublicProjectionRecordV1 {
    /// Returns the authenticated project partition retained at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the operation that atomically accepted this projection.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the checked public resource.
    #[must_use]
    pub const fn resource(&self) -> &PublicProjectionResourceV1 {
        &self.resource
    }

    /// Returns the immutable digest of the complete stored record.
    #[must_use]
    pub const fn revision(&self) -> ObjectDigest {
        self.revision
    }

    /// Returns the canonical protobuf byte length retained by this record.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

/// Reads checked public projections from the sole controller journal.
pub struct PublicProjectionStoreV1<'journal> {
    journal: &'journal Journal,
}

impl<'journal> PublicProjectionStoreV1<'journal> {
    /// Borrows the journal without creating another owner or materialized index.
    #[must_use]
    pub const fn new(journal: &'journal Journal) -> Self {
        Self { journal }
    }

    /// Loads one exact projection.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] when a retained record is malformed,
    /// noncanonical, mismatched, or fails the public resource validator.
    pub fn get(
        &self,
        kind: PublicProjectionKindV1,
        resource_id: [u8; 16],
    ) -> Result<Option<PublicProjectionRecordV1>, PublicProjectionError> {
        if resource_id == [0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        let key = projection_key(kind, resource_id);
        self.journal
            .get(RecordNamespace::DesiredState, &key)
            .map(|value| decode_record(&key, value))
            .transpose()
    }

    /// Lists one kind and project in stable resource-identity order.
    ///
    /// # Errors
    ///
    /// Returns [`PublicProjectionError`] when any record under the reserved
    /// prefix is malformed, including a record outside the requested project.
    pub fn list(
        &self,
        kind: PublicProjectionKindV1,
        project: ProjectId,
    ) -> Result<Vec<PublicProjectionRecordV1>, PublicProjectionError> {
        if project.as_bytes() == &[0; 16] {
            return Err(PublicProjectionError::InvalidIdentity);
        }
        let kind_prefix = projection_kind_prefix(kind);
        let mut records = Vec::new();
        for (key, value) in self.journal.records(RecordNamespace::DesiredState) {
            if key.starts_with(&kind_prefix) {
                let record = decode_record(key, value)?;
                if record.project == project {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }
}

/// Reports a rejected public projection or corrupt retained record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicProjectionError {
    /// A project, operation, or resource identity is zero or inconsistent.
    #[error("public projection identity is invalid")]
    InvalidIdentity,
    /// The checked protobuf exceeds the public resource ceiling.
    #[error("public projection resource exceeds its encoded ceiling")]
    ResourceTooLarge,
    /// The generated resource validator rejected the projection.
    #[error("public projection resource is invalid: {0}")]
    InvalidResource(#[source] InvalidPublicResource),
    /// The cache accounting projection is internally inconsistent.
    #[error("public cache-status projection is invalid")]
    InvalidCacheStatus,
    /// A durable value violates the fixed record schema or digest.
    #[error("durable public projection record is corrupt")]
    CorruptRecord,
}

fn projection_kind_prefix(kind: PublicProjectionKindV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(PROJECTION_KEY_PREFIX.len() + 1);
    key.extend_from_slice(PROJECTION_KEY_PREFIX);
    key.push(kind as u8);
    key
}

fn projection_key(kind: PublicProjectionKindV1, resource_id: [u8; 16]) -> Vec<u8> {
    let mut key = projection_kind_prefix(kind);
    key.extend_from_slice(&resource_id);
    key
}

fn decode_record(
    key: &[u8],
    value: &[u8],
) -> Result<PublicProjectionRecordV1, PublicProjectionError> {
    if value.len() < PROJECTION_HEADER_BYTES
        || value.get(..8) != Some(PROJECTION_MAGIC.as_slice())
        || u16::from_be_bytes(exact(value, 8)?) != PROJECTION_VERSION
        || value[11] != PROJECTION_FLAGS
    {
        return Err(PublicProjectionError::CorruptRecord);
    }
    let kind = PublicProjectionKindV1::from_byte(value[10])?;
    let project = ProjectId::from_bytes(exact(value, 12)?);
    let resource_id = exact(value, 28)?;
    let operation = OperationId::from_bytes(exact(value, 44)?);
    let protobuf_length = u32::from_be_bytes(exact(value, 60)?) as usize;
    let expected_digest: [u8; 32] = exact(value, 64)?;
    let protobuf = value
        .get(PROJECTION_HEADER_BYTES..)
        .ok_or(PublicProjectionError::CorruptRecord)?;
    if project.as_bytes() == &[0; 16]
        || resource_id == [0; 16]
        || operation.as_bytes() == &[0; 16]
        || protobuf_length != protobuf.len()
        || protobuf.is_empty()
        || protobuf.len() > MAXIMUM_PUBLIC_RESOURCE_BYTES
        || Sha256::digest(protobuf).as_slice() != expected_digest
        || key != projection_key(kind, resource_id)
    {
        return Err(PublicProjectionError::CorruptRecord);
    }
    let resource = PublicProjectionResourceV1::decode_checked(kind, resource_id, protobuf)?;
    if resource.resource_id() != resource_id || !resource_matches_project(&resource, project) {
        return Err(PublicProjectionError::CorruptRecord);
    }

    Ok(PublicProjectionRecordV1 {
        project,
        operation,
        resource,
        revision: ObjectDigest::from_bytes(Sha256::digest(value).into()),
        encoded_bytes: protobuf.len(),
    })
}

fn resource_matches_project(resource: &PublicProjectionResourceV1, project: ProjectId) -> bool {
    match resource {
        PublicProjectionResourceV1::Sandbox(value) => value.project_id == project.as_bytes(),
        PublicProjectionResourceV1::FilesystemView(value) => value.project_id == project.as_bytes(),
        PublicProjectionResourceV1::Snapshot(value) => value.project_id == project.as_bytes(),
        PublicProjectionResourceV1::Capability(value) => value.project_id == project.as_bytes(),
        PublicProjectionResourceV1::ProjectCacheStatus { project_id, .. } => {
            project_id == project.as_bytes()
        }
        PublicProjectionResourceV1::SandboxCacheStatus { .. } => true,
        PublicProjectionResourceV1::Execution(_) | PublicProjectionResourceV1::Attachment(_) => {
            true
        }
    }
}

fn exact<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PublicProjectionError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(PublicProjectionError::CorruptRecord)
}
