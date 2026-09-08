//! Canonical non-authorizing semantics for Storage catalog preparation.
//!
//! A preparation resolves one operation-specific catalog from protected local
//! state. These canonical bytes are intended for signature verification under
//! authority distinct from Apply: successful decoding alone grants nothing.
//! Portable fields contain only opaque handles and policy requests;
//! UID/GID/cgroup identity, dataset names, GUIDs, roots, and policy domains
//! stay local.
//!
//! The V1 canonical meaning uses ordered TLV fields. Each field is encoded as
//! an unsigned `u8` tag, an unsigned big-endian `u32` length, and the value:
//!
//! ```text
//!  1 magic = "AOSSPRP1"             2 format version = u16 BE
//!  3 action = u8                    4 sandbox ID = 16 bytes
//!  5 incarnation ID = 16 bytes      6 assignment epoch = u64 BE
//!  7 desired generation = u64 BE    8 assignment digest = 32 bytes
//!  9 operation ID = 16 bytes       10 storage handle = 0 or 32 bytes
//! 11 version handle = 0 or 32 bytes 12 requested quota = u64 BE
//! 13 requested reservation = u64 BE 14 hold ID = 0 or 16 bytes
//! 15 inventory generation = u64 BE  16 inventory digest = 32 bytes
//! 17 expected-head generation = u64 BE
//! 18 expected-head digest = 32 bytes
//! 19 boot-time expiry nanoseconds = u64 BE
//! ```
//!
//! Tags 1 through 19 are always present exactly once in that order; an absent
//! optional fixed-width value is represented by a zero-length value. The
//! common request header, node identity, and signature are intentionally not
//! part of these bytes. Canonical meaning remains distinct from admission and
//! independent authority verification.

use aos_proto::aos::sandbox::local::v1::{PrepareStorageCatalogRequest, StorageAction};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb, ObjectDigest, ProtocolId,
};
use buffa::Message as _;

use super::CatalogBindingV1;
use crate::{
    MAXIMUM_REQUEST_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, validate_fence, validate_request_header,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSPRP1";
const FORMAT_VERSION: u16 = 1;
const MINIMUM_PROTOCOL_MINOR: u16 = 3;
const MAXIMUM_CANONICAL_BYTES: usize = 32 * 1024;

/// Reports a preparation request that has no single closed portable meaning.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoragePreparationSemanticsError {
    /// The common local-protocol envelope or fixed-width field is invalid.
    #[error("invalid Storage catalog preparation request: {0}")]
    Protocol(#[from] ProtocolValidationError),
    /// The action's handles or requested policy fields have the wrong shape.
    #[error("Storage catalog preparation fields do not match the selected action")]
    InvalidActionShape,
    /// An inventory or expected-head binding uses a reserved value.
    #[error("Storage catalog preparation binding uses a reserved value")]
    InvalidCatalogBinding,
    /// The retained preparation is already expired on the current boot.
    #[error("Storage catalog preparation expiry is not in the future")]
    Expired,
    /// The canonical semantic representation exceeded its fixed invariant.
    #[error("canonical Storage catalog preparation exceeds the V1 byte ceiling")]
    CanonicalEncodingTooLarge,
}

/// Names the exact policy inputs for one non-authorizing catalog resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePreparationOperationV1 {
    /// Resolves a future empty workspace.
    CreateWorkspace {
        /// Requested quota before protected policy clamps it.
        quota_bytes: u64,
        /// Requested reservation before protected policy clamps it.
        reservation_bytes: u64,
    },
    /// Resolves a future immutable version of an existing workspace.
    Snapshot {
        /// Existing broker-minted workspace handle.
        storage_handle: [u8; 32],
    },
    /// Resolves adding one exact durable hold.
    HoldSnapshot {
        /// Existing broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// Existing immutable-version handle.
        version_handle: [u8; 32],
        /// Requested durable hold identity.
        hold_id: [u8; 16],
    },
    /// Resolves releasing one exact durable hold.
    ReleaseHold {
        /// Existing broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// Existing immutable-version handle.
        version_handle: [u8; 32],
        /// Requested durable hold identity.
        hold_id: [u8; 16],
    },
    /// Resolves cloning an exact held immutable version.
    Clone {
        /// Existing source workspace handle.
        storage_handle: [u8; 32],
        /// Existing source immutable-version handle.
        version_handle: [u8; 32],
        /// Required origin-hold identity.
        hold_id: [u8; 16],
        /// Requested quota before protected policy clamps it.
        quota_bytes: u64,
        /// Requested reservation before protected policy clamps it.
        reservation_bytes: u64,
    },
    /// Resolves a quota and reservation replacement.
    SetQuota {
        /// Existing broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// Requested quota before protected policy clamps it.
        quota_bytes: u64,
        /// Requested reservation before protected policy clamps it.
        reservation_bytes: u64,
    },
    /// Resolves destruction of one exact workspace or immutable version.
    Destroy {
        /// Existing broker-minted workspace handle.
        storage_handle: [u8; 32],
        /// Optional exact immutable-version handle.
        version_handle: Option<[u8; 32]>,
    },
}

impl StoragePreparationOperationV1 {
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

    const fn hold_id(self) -> Option<[u8; 16]> {
        match self {
            Self::HoldSnapshot { hold_id, .. }
            | Self::ReleaseHold { hold_id, .. }
            | Self::Clone { hold_id, .. } => Some(hold_id),
            Self::CreateWorkspace { .. }
            | Self::Snapshot { .. }
            | Self::SetQuota { .. }
            | Self::Destroy { .. } => None,
        }
    }

    const fn quota_bytes(self) -> u64 {
        match self {
            Self::CreateWorkspace { quota_bytes, .. }
            | Self::Clone { quota_bytes, .. }
            | Self::SetQuota { quota_bytes, .. } => quota_bytes,
            Self::Snapshot { .. }
            | Self::HoldSnapshot { .. }
            | Self::ReleaseHold { .. }
            | Self::Destroy { .. } => 0,
        }
    }

    const fn reservation_bytes(self) -> u64 {
        match self {
            Self::CreateWorkspace {
                reservation_bytes, ..
            }
            | Self::Clone {
                reservation_bytes, ..
            }
            | Self::SetQuota {
                reservation_bytes, ..
            } => reservation_bytes,
            Self::Snapshot { .. }
            | Self::HoldSnapshot { .. }
            | Self::ReleaseHold { .. }
            | Self::Destroy { .. } => 0,
        }
    }
}

/// Carries one validated catalog-preparation meaning for independent authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStoragePreparationSemanticsV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    operation_id: [u8; 16],
    operation: StoragePreparationOperationV1,
    inventory: CatalogBindingV1,
    expected_head: CatalogBindingV1,
    expires_boottime_nanoseconds: u64,
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalStoragePreparationSemanticsV1 {
    /// Decodes hostile protobuf bytes into their sole portable V1 meaning.
    ///
    /// # Errors
    ///
    /// Returns [`StoragePreparationSemanticsError`] for an oversized or
    /// malformed message, unknown fields/action, peer/header/fence failure,
    /// invalid action shape, invalid bindings, stale expiry, or size overflow.
    pub fn decode(
        bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, StoragePreparationSemanticsError> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ProtocolValidationError::RequestTooLarge.into());
        }
        let request = PrepareStorageCatalogRequest::decode_from_slice(bytes)
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
        if header.protocol_version().minor() < MINIMUM_PROTOCOL_MINOR {
            return Err(ProtocolValidationError::InvalidField("header.protocol_minor").into());
        }
        let fence = validate_fence(
            request
                .fence
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("fence"))?,
        )?;
        let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
        let storage_handle = optional_nonzero::<32>(&request.storage_handle, "storage_handle")?;
        let version_handle =
            optional_nonzero::<32>(&request.source_version_handle, "source_version_handle")?;
        let hold_id = optional_nonzero::<16>(&request.requested_hold_id, "requested_hold_id")?;
        let action = request
            .action
            .as_known()
            .filter(|value| *value != StorageAction::STORAGE_ACTION_UNSPECIFIED)
            .ok_or(ProtocolValidationError::UnknownAction)?;
        let operation = operation_for(
            action,
            storage_handle,
            version_handle,
            hold_id,
            request.requested_quota_bytes,
            request.requested_reservation_bytes,
        )?;
        let inventory = binding(
            request.inventory_generation,
            &request.inventory_digest,
            "inventory_digest",
        )?;
        let expected_head = binding(
            request.expected_catalog_generation,
            &request.expected_catalog_digest,
            "expected_catalog_digest",
        )?;
        if request.preparation_expires_boottime_nanoseconds <= now_boottime_nanoseconds {
            return Err(StoragePreparationSemanticsError::Expired);
        }
        let canonical = encode_canonical(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
            operation_id,
            operation,
            inventory,
            expected_head,
            request.preparation_expires_boottime_nanoseconds,
        )?;
        let commitment = BrokerArgumentCommitment::for_canonical_bytes(&canonical);
        Ok(Self {
            header,
            fence,
            operation_id,
            operation,
            inventory,
            expected_head,
            expires_boottime_nanoseconds: request.preparation_expires_boottime_nanoseconds,
            bytes: canonical,
            commitment,
        })
    }

    /// Returns the validated common request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact typed assignment fence committed by preparation authority.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the durable nonzero operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the closed preparation operation and requested policy inputs.
    #[must_use]
    pub const fn operation(&self) -> StoragePreparationOperationV1 {
        self.operation
    }

    /// Returns the controller's exact current-inventory association.
    #[must_use]
    pub const fn inventory_binding(&self) -> CatalogBindingV1 {
        self.inventory
    }

    /// Returns the catalog head that must still be current at durable retain.
    #[must_use]
    pub const fn expected_catalog_head(&self) -> CatalogBindingV1 {
        self.expected_head
    }

    /// Returns the preparation expiry awaiting independent signature verification.
    #[must_use]
    pub const fn expires_boottime_nanoseconds(&self) -> u64 {
        self.expires_boottime_nanoseconds
    }

    /// Returns exact versioned canonical preparation bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated signed-plan argument commitment.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Returns the distinct non-mutating preparation verb.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        BrokerVerb::StoragePrepareCatalog
    }

    /// Returns assignment scope for catalog resolution only.
    ///
    /// Existing handles remain exact canonical inputs. This grant cannot be
    /// reused for any Apply verb and therefore carries no resource mutation
    /// authority.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
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
    operation: StoragePreparationOperationV1,
    inventory: CatalogBindingV1,
    expected_head: CatalogBindingV1,
    expires_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, StoragePreparationSemanticsError> {
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
    encoder.field(13, &operation.reservation_bytes().to_be_bytes())?;
    encoder.optional_fixed(14, operation.hold_id().as_ref())?;
    encoder.field(15, &inventory.generation().to_be_bytes())?;
    encoder.field(16, inventory.digest().as_bytes())?;
    encoder.field(17, &expected_head.generation().to_be_bytes())?;
    encoder.field(18, expected_head.digest().as_bytes())?;
    encoder.field(19, &expires_boottime_nanoseconds.to_be_bytes())?;
    Ok(encoder.finish())
}

fn operation_for(
    action: StorageAction,
    storage_handle: Option<[u8; 32]>,
    version_handle: Option<[u8; 32]>,
    hold_id: Option<[u8; 16]>,
    quota_bytes: u64,
    reservation_bytes: u64,
) -> Result<StoragePreparationOperationV1, StoragePreparationSemanticsError> {
    if quota_bytes > 0 && reservation_bytes > quota_bytes {
        return Err(StoragePreparationSemanticsError::InvalidActionShape);
    }
    match (
        action,
        storage_handle,
        version_handle,
        hold_id,
        quota_bytes,
        reservation_bytes,
    ) {
        (StorageAction::STORAGE_ACTION_CREATE_WORKSPACE, None, None, None, 1.., reservation) => {
            Ok(StoragePreparationOperationV1::CreateWorkspace {
                quota_bytes,
                reservation_bytes: reservation,
            })
        }
        (StorageAction::STORAGE_ACTION_SNAPSHOT, Some(storage_handle), None, None, 0, 0) => {
            Ok(StoragePreparationOperationV1::Snapshot { storage_handle })
        }
        (
            StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT,
            Some(storage_handle),
            Some(version_handle),
            Some(hold_id),
            0,
            0,
        ) => Ok(StoragePreparationOperationV1::HoldSnapshot {
            storage_handle,
            version_handle,
            hold_id,
        }),
        (
            StorageAction::STORAGE_ACTION_RELEASE_HOLD,
            Some(storage_handle),
            Some(version_handle),
            Some(hold_id),
            0,
            0,
        ) => Ok(StoragePreparationOperationV1::ReleaseHold {
            storage_handle,
            version_handle,
            hold_id,
        }),
        (
            StorageAction::STORAGE_ACTION_CLONE,
            Some(storage_handle),
            Some(version_handle),
            Some(hold_id),
            1..,
            reservation,
        ) => Ok(StoragePreparationOperationV1::Clone {
            storage_handle,
            version_handle,
            hold_id,
            quota_bytes,
            reservation_bytes: reservation,
        }),
        (
            StorageAction::STORAGE_ACTION_SET_QUOTA,
            Some(storage_handle),
            None,
            None,
            1..,
            reservation,
        ) => Ok(StoragePreparationOperationV1::SetQuota {
            storage_handle,
            quota_bytes,
            reservation_bytes: reservation,
        }),
        (
            StorageAction::STORAGE_ACTION_DESTROY,
            Some(storage_handle),
            version_handle,
            None,
            0,
            0,
        ) => Ok(StoragePreparationOperationV1::Destroy {
            storage_handle,
            version_handle,
        }),
        _ => Err(StoragePreparationSemanticsError::InvalidActionShape),
    }
}

fn binding(
    generation: u64,
    digest: &[u8],
    field: &'static str,
) -> Result<CatalogBindingV1, StoragePreparationSemanticsError> {
    let digest = ObjectDigest::from_bytes(exact_nonzero::<32>(digest, field)?);
    CatalogBindingV1::from_publisher(generation, digest)
        .map_err(|_| StoragePreparationSemanticsError::InvalidCatalogBinding)
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
            bytes: Vec::with_capacity(400),
        }
    }

    fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), StoragePreparationSemanticsError> {
        let length = u32::try_from(value.len())
            .map_err(|_| StoragePreparationSemanticsError::CanonicalEncodingTooLarge)?;
        let next = self
            .bytes
            .len()
            .checked_add(5)
            .and_then(|size| size.checked_add(value.len()))
            .filter(|size| *size <= MAXIMUM_CANONICAL_BYTES)
            .ok_or(StoragePreparationSemanticsError::CanonicalEncodingTooLarge)?;
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
    ) -> Result<(), StoragePreparationSemanticsError> {
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

    type Mutation = fn(&mut PrepareStorageCatalogRequest);

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

    fn request(action: StorageAction) -> PrepareStorageCatalogRequest {
        let mut request = PrepareStorageCatalogRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = MINIMUM_PROTOCOL_MINOR.into();
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;

        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];

        request.action = action.into();
        request.operation_id = vec![7; 16];
        request.inventory_generation = 11;
        request.inventory_digest = vec![12; 32];
        request.expected_catalog_generation = 13;
        request.expected_catalog_digest = vec![14; 32];
        request.preparation_expires_boottime_nanoseconds = 300;
        request
    }

    fn clone_request() -> PrepareStorageCatalogRequest {
        let mut request = request(StorageAction::STORAGE_ACTION_CLONE);
        request.storage_handle = vec![8; 32];
        request.source_version_handle = vec![9; 32];
        request.requested_quota_bytes = 4096;
        request.requested_reservation_bytes = 1024;
        request.requested_hold_id = vec![10; 16];
        request
    }

    fn decode(
        request: &PrepareStorageCatalogRequest,
    ) -> Result<CanonicalStoragePreparationSemanticsV1, StoragePreparationSemanticsError> {
        CanonicalStoragePreparationSemanticsV1::decode(
            &request.encode_to_vec(),
            peer(),
            policy(),
            100,
        )
    }

    fn commitment(request: &PrepareStorageCatalogRequest) -> BrokerArgumentCommitment {
        decode(request).unwrap().argument_commitment()
    }

    #[test]
    fn canonical_preparation_has_fixed_domain_separated_golden_commitment() {
        let semantics = decode(&clone_request()).unwrap();

        assert_eq!(semantics.broker_verb(), BrokerVerb::StoragePrepareCatalog);
        assert_eq!(semantics.grant_target(), BrokerGrantTarget::Assignment);
        assert_eq!(semantics.canonical_bytes().len(), 386);
        assert_eq!(semantics.canonical_bytes()[5..13], *FORMAT_MAGIC);
        assert_eq!(
            semantics.argument_commitment().digest().as_bytes(),
            &[
                65, 184, 72, 35, 99, 211, 116, 7, 206, 197, 134, 184, 87, 244, 50, 218, 53, 168,
                101, 88, 90, 180, 116, 244, 92, 173, 182, 239, 41, 154, 127, 1,
            ]
        );
    }

    #[test]
    fn every_canonical_request_field_changes_the_commitment() {
        let baseline_request = clone_request();
        let baseline = commitment(&baseline_request);
        let mutations: [(&str, Mutation); 15] = [
            ("sandbox", |request| {
                request.fence.get_or_insert_default().sandbox_id = vec![20; 16]
            }),
            ("incarnation", |request| {
                request.fence.get_or_insert_default().incarnation_id = vec![21; 16]
            }),
            ("assignment epoch", |request| {
                request.fence.get_or_insert_default().assignment_epoch = 6
            }),
            ("desired generation", |request| {
                request.fence.get_or_insert_default().desired_generation = 7
            }),
            ("assignment digest", |request| {
                request.fence.get_or_insert_default().assignment_digest = vec![22; 32]
            }),
            ("operation", |request| request.operation_id = vec![23; 16]),
            ("storage handle", |request| {
                request.storage_handle = vec![24; 32]
            }),
            ("version handle", |request| {
                request.source_version_handle = vec![25; 32]
            }),
            ("quota", |request| request.requested_quota_bytes = 8192),
            ("reservation", |request| {
                request.requested_reservation_bytes = 2048
            }),
            ("hold", |request| request.requested_hold_id = vec![26; 16]),
            ("inventory generation", |request| {
                request.inventory_generation = 12
            }),
            ("inventory digest", |request| {
                request.inventory_digest = vec![27; 32]
            }),
            ("catalog generation", |request| {
                request.expected_catalog_generation = 14
            }),
            ("catalog digest", |request| {
                request.expected_catalog_digest = vec![28; 32]
            }),
        ];
        for (name, mutate) in mutations {
            let mut changed = baseline_request.clone();
            mutate(&mut changed);
            assert_ne!(baseline, commitment(&changed), "{name}");
        }

        let mut changed = baseline_request;
        changed.preparation_expires_boottime_nanoseconds = 301;
        assert_ne!(baseline, commitment(&changed), "preparation expiry");

        let mut hold = request(StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT);
        hold.storage_handle = vec![8; 32];
        hold.source_version_handle = vec![9; 32];
        hold.requested_hold_id = vec![10; 16];
        let mut release = hold.clone();
        release.action = StorageAction::STORAGE_ACTION_RELEASE_HOLD.into();
        assert_ne!(commitment(&hold), commitment(&release), "action");
    }

    #[test]
    fn transport_header_fields_are_not_portable_preparation_authority() {
        let first = clone_request();
        let mut second = first.clone();
        let header = second.header.get_or_insert_default();
        header.request_id = vec![30; 16];
        header.deadline_boottime_nanoseconds = 250;
        header.maximum_response_bytes = 8192;

        assert_eq!(commitment(&first), commitment(&second));
    }

    #[test]
    fn every_storage_action_has_one_closed_shape() {
        let mut create = request(StorageAction::STORAGE_ACTION_CREATE_WORKSPACE);
        create.requested_quota_bytes = 4096;
        create.requested_reservation_bytes = 1024;
        assert!(matches!(
            decode(&create).unwrap().operation(),
            StoragePreparationOperationV1::CreateWorkspace { .. }
        ));

        let mut snapshot = request(StorageAction::STORAGE_ACTION_SNAPSHOT);
        snapshot.storage_handle = vec![8; 32];
        assert!(matches!(
            decode(&snapshot).unwrap().operation(),
            StoragePreparationOperationV1::Snapshot { .. }
        ));

        for action in [
            StorageAction::STORAGE_ACTION_HOLD_SNAPSHOT,
            StorageAction::STORAGE_ACTION_RELEASE_HOLD,
        ] {
            let mut request = request(action);
            request.storage_handle = vec![8; 32];
            request.source_version_handle = vec![9; 32];
            request.requested_hold_id = vec![10; 16];
            assert!(decode(&request).is_ok());
        }

        assert!(matches!(
            decode(&clone_request()).unwrap().operation(),
            StoragePreparationOperationV1::Clone { .. }
        ));

        let mut quota = request(StorageAction::STORAGE_ACTION_SET_QUOTA);
        quota.storage_handle = vec![8; 32];
        quota.requested_quota_bytes = 4096;
        quota.requested_reservation_bytes = 1024;
        assert!(matches!(
            decode(&quota).unwrap().operation(),
            StoragePreparationOperationV1::SetQuota { .. }
        ));

        let mut destroy = request(StorageAction::STORAGE_ACTION_DESTROY);
        destroy.storage_handle = vec![8; 32];
        assert!(decode(&destroy).is_ok());
        destroy.source_version_handle = vec![9; 32];
        assert!(decode(&destroy).is_ok());
    }

    #[test]
    fn action_smuggling_reserved_values_and_expiry_fail_closed() {
        let mut smuggled = clone_request();
        smuggled.action = StorageAction::STORAGE_ACTION_SNAPSHOT.into();
        assert_eq!(
            decode(&smuggled),
            Err(StoragePreparationSemanticsError::InvalidActionShape)
        );

        let mut excessive_reservation = clone_request();
        excessive_reservation.requested_reservation_bytes = 4097;
        assert_eq!(
            decode(&excessive_reservation),
            Err(StoragePreparationSemanticsError::InvalidActionShape)
        );

        let mutations: [Mutation; 8] = [
            |request| request.operation_id.fill(0),
            |request| request.storage_handle.fill(0),
            |request| request.source_version_handle.fill(0),
            |request| request.requested_hold_id.fill(0),
            |request| request.inventory_generation = 0,
            |request| request.inventory_digest.fill(0),
            |request| request.expected_catalog_generation = 0,
            |request| request.expected_catalog_digest.fill(0),
        ];
        for mutate in mutations {
            let mut invalid = clone_request();
            mutate(&mut invalid);
            assert!(decode(&invalid).is_err());
        }

        let mut expired = clone_request();
        expired.preparation_expires_boottime_nanoseconds = 100;
        assert_eq!(
            decode(&expired),
            Err(StoragePreparationSemanticsError::Expired)
        );
    }

    #[test]
    fn unknown_wire_action_and_pre_1_3_version_fail_closed() {
        let mut unknown_field = clone_request().encode_to_vec();
        unknown_field.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(matches!(
            CanonicalStoragePreparationSemanticsV1::decode(&unknown_field, peer(), policy(), 100),
            Err(StoragePreparationSemanticsError::Protocol(
                ProtocolValidationError::UnknownFields
            ))
        ));

        let mut unknown_action = clone_request();
        unknown_action.action = 99.into();
        assert!(matches!(
            decode(&unknown_action),
            Err(StoragePreparationSemanticsError::Protocol(
                ProtocolValidationError::UnknownAction
            ))
        ));

        let mut old_version = clone_request();
        old_version.header.get_or_insert_default().protocol_minor = 2;
        assert!(matches!(
            decode(&old_version),
            Err(StoragePreparationSemanticsError::Protocol(
                ProtocolValidationError::InvalidField("header.protocol_minor")
            ))
        ));

        let mut unknown_version = clone_request();
        unknown_version
            .header
            .get_or_insert_default()
            .protocol_major = 2;
        assert!(decode(&unknown_version).is_err());
    }
}
