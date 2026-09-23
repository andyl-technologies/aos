//! Authoritative Storage workspace-inventory validation.
//!
//! Storage reports current launchable workspace roots plus an optional complete
//! lifecycle catalog extension produced by the protected Storage runtime. Each
//! launch row binds an exact assignment and portable
//! root image to a current-boot root pin, ZFS dataset GUID, subordinate identity
//! range, and broker observation digest. Paths are derived locally from opaque
//! handles:
//!
//! ```text
//! /run/aos/sandbox-pins/workspaces/<64 lowercase hexadecimal digits>
//! ```
//!
//! The complete response is bounded. Launch rows are strictly handle ordered;
//! lifecycle rows and transitions have their own strict canonical order.
//! Identity ranges, physical pins, and dataset GUIDs must be unique across the
//! launch snapshot.

use std::collections::BTreeSet;

use aos_proto::aos::sandbox::local::v1::{
    InventoryStorageRequest, InventoryStorageResourcesResponse, StorageAtomicSnapshotCheckpoint,
    StorageLifecycleInventoryRecord, StorageLifecycleTransitionRecord,
    StorageWorkspaceInventoryRecord,
};
use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_core::{DescriptorRole, ObjectDescriptor, ProtocolId, ProtocolVersion};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_HOST_IDENTITY_RANGE,
    MINIMUM_RESPONSE_BYTES, PeerCredentials, PeerPolicy, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedHeader, WORKSPACE_PIN_PREFIX, exact_nonzero,
    validate_descriptor, validate_fence, validate_request_header,
};

/// Maximum current workspaces accepted in one complete Storage snapshot.
pub const MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS: usize = 16_384;
const STORAGE_RESOURCE_INVENTORY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Carries one complete validated Storage resource snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStorageInventory {
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
    catalog_generation: u64,
    workspaces: Vec<ValidatedStorageWorkspace>,
}

impl ValidatedStorageInventory {
    /// Returns the current Linux boot identifier.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the process identity of the broker that emitted this snapshot.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }

    /// Returns the next durable journal boundary after this snapshot.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the protected Storage catalog generation used for observation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns current launchable workspaces in strict handle order.
    #[must_use]
    pub fn workspaces(&self) -> &[ValidatedStorageWorkspace] {
        &self.workspaces
    }
}

/// Carries one assignment-bound current workspace root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedStorageWorkspace {
    workspace_handle: [u8; 32],
    fence: ValidatedAssignmentFence,
    root_image: ObjectDescriptor,
    resource_kernel_boot_id: [u8; 16],
    root_directory: String,
    root_device: u64,
    root_inode: u64,
    dataset_guid: u64,
    creation_operation_id: [u8; 16],
    guest_root_publication_proof: Option<GuestRootPublicationProofV1>,
    uid_range_start: u32,
    uid_range_size: u32,
    resource_digest: [u8; 32],
}

impl ValidatedStorageWorkspace {
    /// Returns the opaque workspace handle.
    #[must_use]
    pub const fn workspace_handle(&self) -> &[u8; 32] {
        &self.workspace_handle
    }

    /// Returns the exact assignment owning the workspace.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the portable root image bound to the workspace.
    #[must_use]
    pub const fn root_image(&self) -> &ObjectDescriptor {
        &self.root_image
    }

    /// Returns the boot in which the root pin was observed.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }

    /// Returns the fixed root-owned pin derived from the opaque handle.
    #[must_use]
    pub fn root_directory(&self) -> &str {
        &self.root_directory
    }

    /// Returns the observed root-directory device identity.
    #[must_use]
    pub const fn root_device(&self) -> u64 {
        self.root_device
    }

    /// Returns the observed root-directory inode identity.
    #[must_use]
    pub const fn root_inode(&self) -> u64 {
        self.root_inode
    }

    /// Returns the non-recycled ZFS dataset GUID behind this workspace.
    #[must_use]
    pub const fn dataset_guid(&self) -> u64 {
        self.dataset_guid
    }

    /// Returns the operation that originally created this dataset and handle.
    #[must_use]
    pub const fn creation_operation_id(&self) -> &[u8; 16] {
        &self.creation_operation_id
    }

    /// Returns protected Storage's physically read-back guest-root proof, if published.
    ///
    /// Absence is not launch readiness. Callers must compare this proof to the
    /// current assignment and their independently pinned package binding.
    #[must_use]
    pub const fn guest_root_publication_proof(&self) -> Option<GuestRootPublicationProofV1> {
        self.guest_root_publication_proof
    }

    /// Returns the first host identity mapped to guest identity zero.
    #[must_use]
    pub const fn uid_range_start(&self) -> u32 {
        self.uid_range_start
    }

    /// Returns the number of subordinate identities assigned to the workspace.
    #[must_use]
    pub const fn uid_range_size(&self) -> u32 {
        self.uid_range_size
    }

    /// Returns the commitment to the broker's complete current observation.
    #[must_use]
    pub const fn resource_digest(&self) -> &[u8; 32] {
        &self.resource_digest
    }
}

/// Decodes the sole Storage authoritative-inventory request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed request,
/// invalid peer/header semantics, unknown fields, or a protocol version other
/// than the exact Storage baseline.
pub fn decode_storage_resource_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryStorageRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::StorageBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != STORAGE_RESOURCE_INVENTORY_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    Ok(header)
}

/// Decodes and validates one complete Storage resource snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when bounds, protobuf structure,
/// snapshot metadata, launch or lifecycle row fields, ordering, boot identity,
/// physical identity, dataset identity, or subordinate-range isolation is invalid.
pub fn decode_storage_resource_inventory_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedStorageInventory, ProtocolValidationError> {
    validate_response_bounds(bytes, maximum_response_bytes)?;

    let response = InventoryStorageResourcesResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    if response.journal_sequence == 0 || response.catalog_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory generation",
        ));
    }
    if response.workspaces.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "storage inventory workspaces",
            maximum: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
        });
    }

    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let workspaces = validate_workspaces(&response.workspaces, kernel_boot_id)?;
    validate_lifecycle_inventory(&response)?;

    Ok(ValidatedStorageInventory {
        kernel_boot_id,
        broker_instance_id,
        journal_sequence: response.journal_sequence,
        catalog_generation: response.catalog_generation,
        workspaces,
    })
}

fn validate_lifecycle_inventory(
    response: &InventoryStorageResourcesResponse,
) -> Result<(), ProtocolValidationError> {
    let absent = response.lifecycle_source.is_empty()
        && response.lifecycle_resources.is_empty()
        && response.lifecycle_transitions.is_empty()
        && response.lifecycle_source_version == 0
        && response.lifecycle_catalog_head.is_empty()
        && response.lifecycle_catalog_generation == 0
        && response.atomic_snapshot_checkpoints.is_empty();
    if absent {
        return Ok(());
    }
    exact_nonzero::<32>(&response.lifecycle_source, "storage lifecycle source")?;
    match response.lifecycle_source_version {
        0 if response.lifecycle_catalog_head.is_empty()
            && response.lifecycle_catalog_generation == 0
            && response.atomic_snapshot_checkpoints.is_empty() => {}
        3 => {
            exact_nonzero::<32>(&response.lifecycle_catalog_head, "storage lifecycle head")?;
            if response.lifecycle_catalog_generation == 0 {
                return Err(ProtocolValidationError::InvalidField(
                    "storage lifecycle catalog generation",
                ));
            }
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "storage lifecycle source version",
            ));
        }
    }
    if response.lifecycle_resources.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
        || response.lifecycle_transitions.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
        || response.atomic_snapshot_checkpoints.len() > MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS
    {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "storage lifecycle inventory",
            maximum: MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
        });
    }
    if !response
        .lifecycle_resources
        .windows(2)
        .all(|pair| lifecycle_resource_key(&pair[0]) < lifecycle_resource_key(&pair[1]))
        || !response
            .lifecycle_transitions
            .windows(2)
            .all(|pair| lifecycle_transition_key(&pair[0]) < lifecycle_transition_key(&pair[1]))
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle inventory order",
        ));
    }
    for record in &response.lifecycle_resources {
        validate_lifecycle_resource(record)?;
    }
    for record in &response.lifecycle_transitions {
        validate_lifecycle_transition(record)?;
    }
    if !response
        .atomic_snapshot_checkpoints
        .windows(2)
        .all(|pair| pair[0].operation_id < pair[1].operation_id)
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage atomic checkpoint order",
        ));
    }
    let mut request_ids = BTreeSet::new();
    for checkpoint in &response.atomic_snapshot_checkpoints {
        validate_atomic_snapshot_checkpoint(checkpoint, response)?;
        if !request_ids.insert(&checkpoint.request_id) {
            return Err(ProtocolValidationError::InvalidField(
                "storage atomic checkpoint request",
            ));
        }
    }
    Ok(())
}

fn validate_atomic_snapshot_checkpoint(
    checkpoint: &StorageAtomicSnapshotCheckpoint,
    inventory: &InventoryStorageResourcesResponse,
) -> Result<(), ProtocolValidationError> {
    let source = exact_nonzero::<32>(&checkpoint.catalog_source, "atomic catalog source")?;
    let pre_head = exact_nonzero::<32>(&checkpoint.pre_catalog_head, "atomic pre-head")?;
    let post_head = exact_nonzero::<32>(&checkpoint.post_catalog_head, "atomic post-head")?;
    exact_nonzero::<16>(&checkpoint.operation_id, "atomic operation")?;
    exact_nonzero::<16>(&checkpoint.request_id, "atomic request")?;
    exact_nonzero::<32>(&checkpoint.request_digest, "atomic request digest")?;
    exact_nonzero::<32>(&checkpoint.program, "atomic program")?;
    exact_nonzero::<32>(&checkpoint.observation, "atomic observation")?;
    if inventory.lifecycle_source_version != 3
        || source != inventory.lifecycle_source.as_slice()
        || checkpoint.pre_catalog_generation == 0
        || checkpoint.pre_catalog_generation.checked_add(1)
            != Some(checkpoint.post_catalog_generation)
        || checkpoint.post_catalog_generation > inventory.lifecycle_catalog_generation
        || pre_head == post_head
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage atomic checkpoint chain",
        ));
    }
    reject_unknown(&checkpoint.__buffa_unknown_fields)
}

fn validate_lifecycle_resource(
    record: &StorageLifecycleInventoryRecord,
) -> Result<(), ProtocolValidationError> {
    if !(1..=5).contains(&record.kind) || !(1..=9).contains(&record.resource_kind) {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle resource kind",
        ));
    }
    exact_nonzero::<16>(&record.resource_id, "storage lifecycle resource")?;
    exact_nonzero::<32>(&record.effect_subject, "storage lifecycle effect subject")?;
    exact_nonzero::<32>(&record.effect_request, "storage lifecycle effect request")?;
    exact_nonzero::<32>(&record.identity, "storage lifecycle identity")?;
    optional_nonzero::<16>(&record.lifecycle_operation, "storage lifecycle operation")?;
    optional_nonzero::<16>(&record.hold_id, "storage lifecycle hold")?;
    reject_unknown(&record.__buffa_unknown_fields)
}

fn validate_lifecycle_transition(
    record: &StorageLifecycleTransitionRecord,
) -> Result<(), ProtocolValidationError> {
    if !(1..=8).contains(&record.kind) || !(1..=9).contains(&record.resource_kind) {
        return Err(ProtocolValidationError::InvalidField(
            "storage lifecycle transition kind",
        ));
    }
    exact_nonzero::<16>(&record.resource_id, "storage lifecycle transition resource")?;
    exact_nonzero::<32>(
        &record.effect_subject,
        "storage lifecycle transition subject",
    )?;
    exact_nonzero::<32>(
        &record.effect_request,
        "storage lifecycle transition request",
    )?;
    exact_nonzero::<32>(&record.identity, "storage lifecycle transition identity")?;
    optional_nonzero::<16>(&record.hold_id, "storage lifecycle transition hold")?;
    reject_unknown(&record.__buffa_unknown_fields)
}

fn optional_nonzero<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if bytes.is_empty() {
        return Ok(());
    }
    exact_nonzero::<N>(bytes, field).map(|_| ())
}

fn lifecycle_resource_key(record: &StorageLifecycleInventoryRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn lifecycle_transition_key(record: &StorageLifecycleTransitionRecord) -> (u32, &[u8], &[u8]) {
    (record.kind, &record.resource_id, &record.identity)
}

fn validate_workspaces(
    records: &[StorageWorkspaceInventoryRecord],
    kernel_boot_id: [u8; 16],
) -> Result<Vec<ValidatedStorageWorkspace>, ProtocolValidationError> {
    let mut workspaces = Vec::with_capacity(records.len());
    let mut physical_pins = BTreeSet::new();
    let mut dataset_guids = BTreeSet::new();

    for record in records {
        let workspace = validate_workspace(record, kernel_boot_id)?;
        if workspaces
            .last()
            .is_some_and(|previous: &ValidatedStorageWorkspace| {
                previous.workspace_handle >= workspace.workspace_handle
            })
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory workspace order",
            ));
        }
        if !physical_pins.insert((workspace.root_device, workspace.root_inode))
            || !dataset_guids.insert(workspace.dataset_guid)
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory physical identity",
            ));
        }

        workspaces.push(workspace);
    }

    let mut ranges = workspaces
        .iter()
        .map(|workspace| {
            (
                workspace.uid_range_start,
                workspace.uid_range_start + workspace.uid_range_size,
            )
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory identity overlap",
        ));
    }

    Ok(workspaces)
}

fn validate_workspace(
    record: &StorageWorkspaceInventoryRecord,
    kernel_boot_id: [u8; 16],
) -> Result<ValidatedStorageWorkspace, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    let workspace_handle = exact_nonzero::<32>(
        &record.workspace_handle,
        "storage inventory workspace_handle",
    )?;
    let fence = validate_fence(record.fence.as_option().ok_or(
        ProtocolValidationError::MissingField("storage inventory fence"),
    )?)?;
    let root_image = validate_descriptor(
        record
            .root_image
            .as_option()
            .ok_or(ProtocolValidationError::MissingField(
                "storage inventory root_image",
            ))?,
        DescriptorRole::SandboxRootView,
    )?;
    let resource_kernel_boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "storage inventory resource_kernel_boot_id",
    )?;
    if resource_kernel_boot_id != kernel_boot_id {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory current boot",
        ));
    }
    if record.root_device == 0
        || record.root_inode == 0
        || record.dataset_guid == 0
        || record.uid_range_start == 0
        || record.uid_range_size < MINIMUM_HOST_IDENTITY_RANGE
        || record
            .uid_range_start
            .checked_add(record.uid_range_size)
            .is_none()
    {
        return Err(ProtocolValidationError::InvalidField(
            "storage inventory workspace identity",
        ));
    }
    let resource_digest =
        exact_nonzero::<32>(&record.resource_digest, "storage inventory resource_digest")?;
    let creation_operation_id = exact_nonzero::<16>(
        &record.creation_operation_id,
        "storage inventory creation_operation_id",
    )?;
    let guest_root_publication_proof = if record.guest_root_publication_proof.is_empty() {
        None
    } else {
        let proof = GuestRootPublicationProofV1::decode(&record.guest_root_publication_proof)
            .map_err(|_| {
                ProtocolValidationError::InvalidField("storage inventory guest root proof")
            })?;
        if proof.sandbox != *fence.sandbox_id()
            || proof.incarnation != *fence.incarnation_id()
            || proof.assignment_epoch != fence.assignment_epoch()
            || proof.assignment_digest != *fence.assignment_digest()
            || proof.creation_operation != creation_operation_id
            || proof.workspace_handle != workspace_handle
            || proof.dataset_guid != record.dataset_guid
            || proof.root_image_digest != *root_image.digest().as_bytes()
        {
            return Err(ProtocolValidationError::InvalidField(
                "storage inventory guest root binding",
            ));
        }
        Some(proof)
    };

    Ok(ValidatedStorageWorkspace {
        workspace_handle,
        fence,
        root_image,
        resource_kernel_boot_id,
        root_directory: format!("{WORKSPACE_PIN_PREFIX}{}", encode_hex(&workspace_handle)),
        root_device: record.root_device,
        root_inode: record.root_inode,
        dataset_guid: record.dataset_guid,
        creation_operation_id,
        guest_root_publication_proof,
        uid_range_start: record.uid_range_start,
        uid_range_size: record.uid_range_size,
        resource_digest,
    })
}

fn validate_response_bounds(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<(), ProtocolValidationError> {
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    if bytes.len() > maximum_response_bytes as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }

    Ok(())
}

fn reject_unknown(fields: &buffa::UnknownFields) -> Result<(), ProtocolValidationError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ProtocolValidationError::UnknownFields)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, Audience, Descriptor};

    use super::*;

    fn workspace(handle: u8, range_start: u32) -> StorageWorkspaceInventoryRecord {
        StorageWorkspaceInventoryRecord {
            workspace_handle: vec![handle; 32],
            fence: Some(AssignmentFence {
                sandbox_id: vec![handle; 16],
                incarnation_id: vec![handle + 1; 16],
                assignment_epoch: 2,
                desired_generation: 3,
                assignment_digest: vec![handle + 2; 32],
                ..Default::default()
            })
            .into(),
            root_image: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![handle + 3; 32],
                encoded_size: 4,
                ..Default::default()
            })
            .into(),
            resource_kernel_boot_id: vec![9; 16],
            root_device: u64::from(handle),
            root_inode: u64::from(handle) + 10,
            dataset_guid: u64::from(handle) + 20,
            creation_operation_id: vec![handle + 5; 16],
            uid_range_start: range_start,
            uid_range_size: MINIMUM_HOST_IDENTITY_RANGE,
            resource_digest: vec![handle + 4; 32],
            ..Default::default()
        }
    }

    fn response(workspaces: Vec<StorageWorkspaceInventoryRecord>) -> Vec<u8> {
        InventoryStorageResourcesResponse {
            kernel_boot_id: vec![9; 16],
            journal_sequence: 10,
            catalog_generation: 11,
            workspaces,
            broker_instance_id: vec![12; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn request_accepts_only_the_storage_baseline() {
        let mut request = InventoryStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 2;
        header.maximum_response_bytes = MINIMUM_RESPONSE_BYTES;
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };

        let decoded =
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1)
                .unwrap();
        assert_eq!(decoded.protocol_version(), ProtocolVersion::new(1, 0));

        for minor in 1..=5 {
            request.header.get_or_insert_default().protocol_minor = minor;
            assert!(matches!(
                decode_storage_resource_inventory_request(
                    &request.encode_to_vec(),
                    peer,
                    policy,
                    1,
                ),
                Err(ProtocolValidationError::Protocol(_))
            ));
        }

        request.header.get_or_insert_default().protocol_major = 2;
        request.header.get_or_insert_default().protocol_minor = 0;
        assert!(matches!(
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::Protocol(_))
        ));
    }

    #[test]
    fn complete_snapshot_derives_fixed_workspace_pins() {
        let inventory = decode_storage_resource_inventory_response(
            &response(vec![workspace(1, 65_536), workspace(2, 131_072)]),
            65_536,
        )
        .unwrap();

        assert_eq!(inventory.catalog_generation(), 11);
        assert_eq!(inventory.workspaces().len(), 2);
        assert_eq!(
            inventory.workspaces()[0].root_directory(),
            format!("{WORKSPACE_PIN_PREFIX}{}", "01".repeat(32))
        );
    }

    #[test]
    fn snapshot_rejects_order_overlap_and_duplicate_physical_identity() {
        assert!(
            decode_storage_resource_inventory_response(
                &response(vec![workspace(2, 65_536), workspace(1, 131_072)]),
                65_536,
            )
            .is_err()
        );
        assert!(
            decode_storage_resource_inventory_response(
                &response(vec![workspace(1, 65_536), workspace(2, 98_304)]),
                65_536,
            )
            .is_err()
        );

        let first = workspace(1, 65_536);
        let mut duplicate = workspace(2, 131_072);
        duplicate.root_device = first.root_device;
        duplicate.root_inode = first.root_inode;
        assert!(
            decode_storage_resource_inventory_response(&response(vec![first, duplicate]), 65_536,)
                .is_err()
        );
    }

    #[test]
    fn snapshot_rejects_stale_boot_and_incomplete_identity() {
        let mut stale = workspace(1, 65_536);
        stale.resource_kernel_boot_id = vec![8; 16];
        assert!(
            decode_storage_resource_inventory_response(&response(vec![stale]), 65_536).is_err()
        );

        let mut incomplete = workspace(1, 65_536);
        incomplete.dataset_guid = 0;
        assert!(
            decode_storage_resource_inventory_response(&response(vec![incomplete]), 65_536)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_source_version_requires_an_explicit_head() {
        let mut response =
            InventoryStorageResourcesResponse::decode_from_slice(&response(Vec::new())).unwrap();
        response.lifecycle_source = vec![13; 32];
        response.lifecycle_source_version = 3;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );

        response.lifecycle_catalog_head = vec![14; 32];
        response.lifecycle_catalog_generation = 15;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_ok()
        );

        response.lifecycle_source_version = 0;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
    }

    #[test]
    fn atomic_checkpoint_requires_exact_chain_and_canonical_order() {
        let mut response =
            InventoryStorageResourcesResponse::decode_from_slice(&response(Vec::new())).unwrap();
        response.lifecycle_source = vec![13; 32];
        response.lifecycle_source_version = 3;
        response.lifecycle_catalog_head = vec![15; 32];
        response.lifecycle_catalog_generation = 17;
        let checkpoint = StorageAtomicSnapshotCheckpoint {
            operation_id: vec![1; 16],
            request_id: vec![2; 16],
            request_digest: vec![3; 32],
            program: vec![4; 32],
            observation: vec![5; 32],
            catalog_source: vec![13; 32],
            pre_catalog_generation: 15,
            pre_catalog_head: vec![14; 32],
            post_catalog_generation: 16,
            post_catalog_head: vec![15; 32],
            ..Default::default()
        };
        response
            .atomic_snapshot_checkpoints
            .push(checkpoint.clone());
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_ok()
        );

        response.atomic_snapshot_checkpoints[0].post_catalog_generation = 17;
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
        response.atomic_snapshot_checkpoints[0] = checkpoint.clone();
        response.atomic_snapshot_checkpoints.push(checkpoint);
        assert!(
            decode_storage_resource_inventory_response(&response.encode_to_vec(), 65_536).is_err()
        );
    }
}
