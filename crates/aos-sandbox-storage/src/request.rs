//! Closed validation and canonical authority semantics for storage requests.
//!
//! Storage V1 uses the following canonical byte sequence before the shared
//! broker-argument domain separator is applied:
//!
//! ```text
//! field := tag:u8 || length:u32be || value:length
//! fields := magic, version, action, assignment fence, operation ID,
//!           optional storage handle, optional version handle, quota,
//!           opaque catalog generation, opaque catalog digest
//! ```
//!
//! Every field is emitted in tag order, including absent optional fields as a
//! zero-length value. Consequently different protobuf encodings of the same
//! accepted request have one authority meaning, while action, fence, object,
//! version, operation ID, and quota substitutions change the commitment.

use aos_proto::aos::sandbox::local::v1::{ApplyStorageRequest, StorageAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb, ProtocolId,
};
use aos_sandbox_protocol::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader,
    validate_request_header,
};
use buffa::Message as _;

use crate::catalog::{CatalogBindingV1, CatalogPlanV1, ResolvedCatalogCommitmentV1};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSSEM1";
const FORMAT_VERSION: u16 = 1;
const MAXIMUM_CANONICAL_BYTES: usize = 32 * 1024;

/// Reports a storage request that has no single closed V1 interpretation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageRequestError {
    /// The common local-protocol envelope or fixed-width field is invalid.
    #[error("invalid local storage request: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The action's optional fields or quota do not have the required shape.
    #[error("storage action fields do not match the selected operation")]
    InvalidActionShape,
    /// The resolved catalog plan names a different action or quota.
    #[error("resolved storage catalog plan does not match the wire operation")]
    CatalogPlanMismatch,
    /// The canonical semantic representation exceeded its fixed invariant.
    #[error("canonical storage semantics exceed the V1 byte ceiling")]
    CanonicalEncodingTooLarge,
}

/// Names one validated fixed-function storage mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    /// Creates an empty private workspace with a finite byte quota.
    CreateWorkspace {
        /// Hard logical byte ceiling for the new workspace.
        quota_bytes: u64,
    },
    /// Creates a new immutable version of an existing workspace.
    Snapshot {
        /// Broker-minted workspace handle.
        storage_handle: [u8; 32],
    },
    /// Adds an AOS retention hold to an exact immutable version.
    HoldSnapshot {
        /// Broker-minted workspace handle owning the version.
        storage_handle: [u8; 32],
        /// Broker-minted immutable version handle.
        version_handle: [u8; 32],
    },
    /// Releases an AOS retention hold from an exact immutable version.
    ReleaseHold {
        /// Broker-minted workspace handle owning the version.
        storage_handle: [u8; 32],
        /// Broker-minted immutable version handle.
        version_handle: [u8; 32],
    },
    /// Clones an exact immutable version into a new finite workspace.
    Clone {
        /// Broker-minted source workspace handle.
        storage_handle: [u8; 32],
        /// Broker-minted source immutable version handle.
        version_handle: [u8; 32],
        /// Hard logical byte ceiling for the new clone.
        quota_bytes: u64,
    },
    /// Replaces the finite quota on an existing workspace.
    SetQuota {
        /// Broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// New hard logical byte ceiling.
        quota_bytes: u64,
    },
    /// Destroys exactly one workspace or one immutable version.
    Destroy {
        /// Broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// Exact immutable version, or `None` for the workspace itself.
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

    fn action_code(self) -> u8 {
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

    fn storage_handle(self) -> Option<[u8; 32]> {
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

    fn version_handle(self) -> Option<[u8; 32]> {
        match self {
            Self::HoldSnapshot { version_handle, .. }
            | Self::ReleaseHold { version_handle, .. }
            | Self::Clone { version_handle, .. } => Some(version_handle),
            Self::Destroy { version_handle, .. } => version_handle,
            Self::CreateWorkspace { .. } | Self::Snapshot { .. } | Self::SetQuota { .. } => None,
        }
    }

    fn quota_bytes(self) -> u64 {
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

/// Carries a fully validated request and its immutable authority meaning.
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
    /// Decodes hostile protobuf bytes and constructs their sole V1 meaning.
    ///
    /// The socket peer and policy are passed to the shared header validator.
    /// `catalog` is the opaque generation/digest association published by the
    /// node catalog. It contains no backend name, GUID, or expression. This
    /// controller-side entry point does not prove the handle-to-plan mapping;
    /// the root broker uses [`Self::decode_resolved`] for that check.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRequestError`] for an oversized or malformed message,
    /// unknown protobuf fields or action, peer/header/fence failure, a zero or
    /// wrong-width identifier, an invalid action field combination, or an
    /// internal canonical byte-bound violation.
    pub fn decode(
        bytes: &[u8],
        catalog: CatalogBindingV1,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageRequestError> {
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
        let storage_handle = optional_nonzero::<32>(&request.storage_handle, "storage_handle")?;
        let version_handle =
            optional_nonzero::<32>(&request.source_version_handle, "source_version_handle")?;
        let action = request
            .action
            .as_known()
            .filter(|value| *value != StorageAction::STORAGE_ACTION_UNSPECIFIED)
            .ok_or(ProtocolValidationError::UnknownAction)?;
        let operation = operation_for(action, storage_handle, version_handle, request.quota_bytes)?;
        let target = match operation.storage_handle() {
            None => BrokerGrantTarget::Assignment,
            Some(handle) => BrokerGrantTarget::Resource(
                BrokerResourceHandle::from_bytes(handle)
                    .map_err(|_| StorageRequestError::InvalidActionShape)?,
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

    /// Decodes request semantics and verifies a trusted locally resolved plan.
    ///
    /// The protected catalog constructs `catalog` from its local resolution.
    /// This method mechanically compares every request storage/version handle,
    /// action, and quota with the typed resolved objects before accepting the
    /// opaque binding. The full resolution remains node-local and must later be
    /// persisted with the effect record.
    ///
    /// # Errors
    ///
    /// Returns [`StorageRequestError`] for any failure described by
    /// [`Self::decode`] or when the resolved plan has another action, quota, or
    /// storage/version handle.
    pub fn decode_resolved(
        bytes: &[u8],
        catalog: &ResolvedCatalogCommitmentV1,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, StorageRequestError> {
        let semantics = Self::decode(
            bytes,
            catalog.binding(),
            peer,
            policy,
            now_boottime_nanoseconds,
        )?;
        validate_catalog_plan(semantics.operation, catalog.plan())?;
        Ok(semantics)
    }

    /// Returns the validated common request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the durable, nonzero operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Returns the closed storage operation.
    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }

    /// Returns the exact versioned canonical authority bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the shared domain-separated argument commitment.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the assignment or existing-resource authority target.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the exact shared storage-broker verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        self.operation.broker_verb()
    }

    /// Returns the opaque catalog association incorporated into portable semantics.
    #[must_use]
    pub const fn catalog_binding(&self) -> CatalogBindingV1 {
        self.catalog
    }
}

/// Checks action, quota, and exact handle-to-resolved-object compatibility.
fn validate_catalog_plan(
    operation: StorageOperation,
    plan: &CatalogPlanV1,
) -> Result<(), StorageRequestError> {
    let matches = match (operation, plan) {
        (
            StorageOperation::CreateWorkspace { quota_bytes },
            CatalogPlanV1::CreateWorkspace { space, .. },
        ) => quota_bytes == space.refquota_bytes(),
        (StorageOperation::Snapshot { storage_handle }, CatalogPlanV1::Snapshot { source, .. }) => {
            storage_handle == source.storage_handle()
        }
        (
            StorageOperation::HoldSnapshot {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::HoldSnapshot { snapshot, .. },
        )
        | (
            StorageOperation::ReleaseHold {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::ReleaseHold { snapshot, .. },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == snapshot.version_handle()
        }
        (
            StorageOperation::Clone {
                storage_handle,
                version_handle,
                quota_bytes,
            },
            CatalogPlanV1::Clone { source, space, .. },
        ) => {
            storage_handle == source.dataset().storage_handle()
                && version_handle == source.version_handle()
                && quota_bytes == space.refquota_bytes()
        }
        (
            StorageOperation::SetQuota {
                storage_handle,
                quota_bytes,
            },
            CatalogPlanV1::SetQuota { dataset, space, .. },
        ) => storage_handle == dataset.storage_handle() && quota_bytes == space.refquota_bytes(),
        (
            StorageOperation::Destroy {
                storage_handle,
                version_handle: None,
            },
            CatalogPlanV1::DestroyDataset { dataset },
        ) => storage_handle == dataset.storage_handle(),
        (
            StorageOperation::Destroy {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::DestroySnapshot { snapshot },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == Some(snapshot.version_handle())
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(StorageRequestError::CatalogPlanMismatch)
    }
}

fn operation_for(
    action: StorageAction,
    storage: Option<[u8; 32]>,
    version: Option<[u8; 32]>,
    quota: u64,
) -> Result<StorageOperation, StorageRequestError> {
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
        _ => Err(StorageRequestError::InvalidActionShape),
    }
}

fn exact_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], ProtocolValidationError> {
    let value: [u8; N] = bytes
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

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), StorageRequestError> {
        let length = u32::try_from(value.len())
            .map_err(|_| StorageRequestError::CanonicalEncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(StorageRequestError::CanonicalEncodingTooLarge)?;
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
    ) -> Result<(), StorageRequestError> {
        self.field(tag, value.map(<[u8; N]>::as_slice).unwrap_or_default())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::Audience;
    use aos_sandbox_core::ObjectDigest;

    use crate::catalog::{
        ActiveHoldEvidence, HoldId, ManagedDatasetRoot, PlannedDataset, PlannedSnapshot,
        ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset, ResolvedSnapshot,
        StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

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

    fn request(action: StorageAction) -> ApplyStorageRequest {
        let mut request = ApplyStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
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
        request.action = action.into();
        request.operation_id = vec![7; 16];
        request
    }

    fn decode(
        request: &ApplyStorageRequest,
    ) -> Result<CanonicalStorageSemanticsV1, StorageRequestError> {
        let catalog = catalog_for(request);
        CanonicalStorageSemanticsV1::decode_resolved(
            &request.encode_to_vec(),
            &catalog,
            peer(),
            policy(),
            100,
        )
    }

    fn catalog_for(request: &ApplyStorageRequest) -> ResolvedCatalogCommitmentV1 {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10)
            .unwrap_or_else(|error| panic!("test managed root: {error}"));
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap_or_else(|error| panic!("test domains: {error}"));
        let storage_handle = request
            .storage_handle
            .as_slice()
            .try_into()
            .unwrap_or([1; 32]);
        let version_handle = request
            .source_version_handle
            .as_slice()
            .try_into()
            .unwrap_or([2; 32]);
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [9; 32], domains)
                .unwrap_or_else(|error| panic!("test project ancestor: {error}"));
        let dataset = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project/source",
            11,
            storage_handle,
            domains,
        )
        .unwrap_or_else(|error| panic!("test dataset: {error}"));
        let snapshot =
            ResolvedSnapshot::from_catalog(dataset.clone(), "version", 12, version_handle)
                .unwrap_or_else(|error| panic!("test snapshot: {error}"));
        let active_hold = ActiveHoldEvidence::from_catalog(snapshot.guid(), hold_id())
            .unwrap_or_else(|error| panic!("test active hold: {error}"));
        let action = request
            .action
            .as_known()
            .unwrap_or(StorageAction::STORAGE_ACTION_CREATE_WORKSPACE);
        let space =
            WorkspaceSpacePolicyV1::new(request.quota_bytes.max(1), ReservationPolicy::Exact(1))
                .unwrap_or_else(|error| panic!("test space policy: {error}"));
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16)
            .unwrap_or_else(|error| panic!("test ancestor policy: {error}"));
        let plan = match action {
            StorageAction::STORAGE_ACTION_CREATE_WORKSPACE => CatalogPlanV1::CreateWorkspace {
                destination: PlannedDataset::from_catalog(root, "tank/aos/project/new", domains)
                    .unwrap_or_else(|error| panic!("test destination: {error}")),
                space,
                ancestor,
            },
            StorageAction::STORAGE_ACTION_SNAPSHOT => CatalogPlanV1::Snapshot {
                source: dataset.clone(),
                destination: PlannedSnapshot::from_catalog(dataset, "new-version")
                    .unwrap_or_else(|error| panic!("test planned snapshot: {error}")),
            },
            StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT => CatalogPlanV1::HoldSnapshot {
                snapshot,
                hold_id: hold_id(),
            },
            StorageAction::STORAGE_ACTION_RELEASE_HOLD => CatalogPlanV1::ReleaseHold {
                snapshot,
                hold_id: hold_id(),
            },
            StorageAction::STORAGE_ACTION_CLONE => CatalogPlanV1::Clone {
                source: Box::new(snapshot),
                origin_hold: active_hold,
                destination: PlannedDataset::from_catalog(root, "tank/aos/project/clone", domains)
                    .unwrap_or_else(|error| panic!("test clone destination: {error}")),
                space,
                ancestor,
            },
            StorageAction::STORAGE_ACTION_SET_QUOTA => CatalogPlanV1::SetQuota {
                dataset,
                space,
                ancestor,
            },
            StorageAction::STORAGE_ACTION_DESTROY => {
                if request.source_version_handle.is_empty() {
                    CatalogPlanV1::DestroyDataset { dataset }
                } else {
                    CatalogPlanV1::DestroySnapshot { snapshot }
                }
            }
            StorageAction::STORAGE_ACTION_UNSPECIFIED => CatalogPlanV1::CreateWorkspace {
                destination: PlannedDataset::from_catalog(root, "tank/aos/project/new", domains)
                    .unwrap_or_else(|error| panic!("test destination: {error}")),
                space,
                ancestor,
            },
        };
        ResolvedCatalogCommitmentV1::new(9, domains, plan)
            .unwrap_or_else(|error| panic!("test catalog commitment: {error}"))
    }

    fn hold_id() -> HoldId {
        HoldId::from_bytes([31; 16]).unwrap_or_else(|error| panic!("test hold ID: {error}"))
    }

    #[test]
    fn creation_is_assignment_scoped_and_canonical() {
        let mut request = request(StorageAction::STORAGE_ACTION_CREATE_WORKSPACE);
        request.quota_bytes = 1024;
        let semantics =
            decode(&request).unwrap_or_else(|error| panic!("valid create request: {error}"));
        assert_eq!(semantics.operation_id(), &[7; 16]);
        assert_eq!(semantics.broker_verb(), BrokerVerb::StorageCreateWorkspace);
        assert_eq!(semantics.grant_target(), BrokerGrantTarget::Assignment);
        assert_eq!(
            semantics.operation(),
            StorageOperation::CreateWorkspace { quota_bytes: 1024 }
        );
        let mut expected = Vec::new();
        for (tag, value) in [
            (1, FORMAT_MAGIC.as_slice()),
            (2, FORMAT_VERSION.to_be_bytes().as_slice()),
            (3, [1].as_slice()),
            (4, [2; 16].as_slice()),
            (5, [3; 16].as_slice()),
            (6, 4_u64.to_be_bytes().as_slice()),
            (7, 5_u64.to_be_bytes().as_slice()),
            (8, [6; 32].as_slice()),
            (9, [7; 16].as_slice()),
            (10, [].as_slice()),
            (11, [].as_slice()),
            (12, 1024_u64.to_be_bytes().as_slice()),
            (
                13,
                semantics
                    .catalog_binding()
                    .generation()
                    .to_be_bytes()
                    .as_slice(),
            ),
            (
                14,
                semantics.catalog_binding().digest().as_bytes().as_slice(),
            ),
        ] {
            expected.push(tag);
            expected.extend_from_slice(
                &u32::try_from(value.len())
                    .unwrap_or_else(|error| panic!("fixture field length: {error}"))
                    .to_be_bytes(),
            );
            expected.extend_from_slice(value);
        }
        assert_eq!(semantics.canonical_bytes(), expected);
        assert!(
            !semantics
                .canonical_bytes()
                .windows(b"tank/aos".len())
                .any(|window| window == b"tank/aos")
        );
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                85, 58, 176, 86, 105, 221, 225, 64, 92, 183, 216, 216, 221, 171, 103, 28, 107, 183,
                117, 144, 168, 56, 6, 107, 40, 245, 81, 115, 162, 149, 231, 200,
            ]
        );
    }

    #[test]
    fn existing_object_operations_bind_the_resource() {
        let mut request = request(StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT);
        request.storage_handle = vec![8; 32];
        request.source_version_handle = vec![9; 32];
        let semantics =
            decode(&request).unwrap_or_else(|error| panic!("valid hold request: {error}"));
        let expected = BrokerResourceHandle::from_bytes([8; 32])
            .unwrap_or_else(|error| panic!("nonzero handle: {error}"));
        assert_eq!(
            semantics.grant_target(),
            BrokerGrantTarget::Resource(expected)
        );
        assert_eq!(semantics.broker_verb(), BrokerVerb::StorageHoldSnapshot);
    }

    #[test]
    fn resolved_catalog_rejects_storage_and_version_handle_substitution() {
        let mut request = request(StorageAction::STORAGE_ACTION_CLONE);
        request.storage_handle = vec![8; 32];
        request.source_version_handle = vec![9; 32];
        request.quota_bytes = 4096;
        let catalog = catalog_for(&request);

        let mut changed_storage = request.clone();
        changed_storage.storage_handle = vec![10; 32];
        assert_eq!(
            CanonicalStorageSemanticsV1::decode_resolved(
                &changed_storage.encode_to_vec(),
                &catalog,
                peer(),
                policy(),
                100,
            ),
            Err(StorageRequestError::CatalogPlanMismatch)
        );

        let mut changed_version = request;
        changed_version.source_version_handle = vec![11; 32];
        assert_eq!(
            CanonicalStorageSemanticsV1::decode_resolved(
                &changed_version.encode_to_vec(),
                &catalog,
                peer(),
                policy(),
                100,
            ),
            Err(StorageRequestError::CatalogPlanMismatch)
        );
    }

    #[test]
    fn every_action_rejects_smuggled_or_missing_fields() {
        let mut create = request(StorageAction::STORAGE_ACTION_CREATE_WORKSPACE);
        assert_eq!(
            decode(&create),
            Err(StorageRequestError::InvalidActionShape)
        );
        create.quota_bytes = 1;
        create.storage_handle = vec![8; 32];
        assert_eq!(
            decode(&create),
            Err(StorageRequestError::InvalidActionShape)
        );

        let mut snapshot = request(StorageAction::STORAGE_ACTION_SNAPSHOT);
        snapshot.storage_handle = vec![8; 32];
        snapshot.quota_bytes = 1;
        assert_eq!(
            decode(&snapshot),
            Err(StorageRequestError::InvalidActionShape)
        );

        let mut clone = request(StorageAction::STORAGE_ACTION_CLONE);
        clone.storage_handle = vec![8; 32];
        clone.source_version_handle = vec![9; 32];
        assert_eq!(decode(&clone), Err(StorageRequestError::InvalidActionShape));
    }

    #[test]
    fn authority_commitment_changes_for_every_effect_dimension() {
        let mut first = request(StorageAction::STORAGE_ACTION_CLONE);
        first.storage_handle = vec![8; 32];
        first.source_version_handle = vec![9; 32];
        first.quota_bytes = 4096;
        let baseline =
            decode(&first).unwrap_or_else(|error| panic!("valid clone request: {error}"));

        let mut changed = first.clone();
        changed.quota_bytes += 1;
        assert_ne!(
            baseline.argument_commitment(),
            decode(&changed)
                .unwrap_or_else(|error| panic!("changed quota remains valid: {error}"))
                .argument_commitment()
        );

        let different_binding = crate::CatalogBindingV1::from_publisher(
            baseline.catalog_binding().generation(),
            ObjectDigest::from_bytes([99; 32]),
        )
        .unwrap_or_else(|error| panic!("different catalog binding: {error}"));
        let changed_catalog = CanonicalStorageSemanticsV1::decode(
            &first.encode_to_vec(),
            different_binding,
            peer(),
            policy(),
            100,
        )
        .unwrap_or_else(|error| panic!("opaque catalog substitution remains structural: {error}"));
        assert_ne!(
            baseline.argument_commitment(),
            changed_catalog.argument_commitment()
        );
        changed = first.clone();
        changed.source_version_handle[0] ^= 1;
        assert_ne!(
            baseline.argument_commitment(),
            decode(&changed)
                .unwrap_or_else(|error| panic!("changed version remains valid: {error}"))
                .argument_commitment()
        );
        changed = first.clone();
        changed.operation_id[0] ^= 1;
        assert_ne!(
            baseline.argument_commitment(),
            decode(&changed)
                .unwrap_or_else(|error| panic!("changed operation remains valid: {error}"))
                .argument_commitment()
        );
        changed = first;
        changed.fence.get_or_insert_default().desired_generation += 1;
        assert_ne!(
            baseline.argument_commitment(),
            decode(&changed)
                .unwrap_or_else(|error| panic!("changed fence remains valid: {error}"))
                .argument_commitment()
        );
    }
}
