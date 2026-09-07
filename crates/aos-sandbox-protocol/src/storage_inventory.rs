//! Authoritative Storage workspace-inventory validation.
//!
//! Storage protocol 1.2 reports only current, launchable workspace roots. Each
//! row binds an exact assignment and portable root image to a current-boot
//! root pin, ZFS dataset GUID, subordinate identity range, and broker
//! observation digest. Paths are derived locally from opaque handles:
//!
//! ```text
//! /run/aos/sandbox-pins/workspaces/<64 lowercase hexadecimal digits>
//! ```
//!
//! The complete snapshot is bounded and strictly handle ordered. Identity
//! ranges, physical pins, and dataset GUIDs must be unique across the snapshot.

use std::collections::BTreeSet;

use aos_proto::aos::sandbox::local::v1::{
    InventoryStorageRequest, InventoryStorageResourcesResponse, StorageWorkspaceInventoryRecord,
};
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
const STORAGE_RESOURCE_INVENTORY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);

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

/// Decodes a Storage 1.2 authoritative-inventory request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed request,
/// invalid peer/header semantics, unknown fields, or any version other than
/// Storage 1.2.
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

/// Decodes and validates one complete Storage workspace snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when bounds, protobuf structure,
/// snapshot metadata, row fields, ordering, boot identity, physical identity,
/// dataset identity, or subordinate-range isolation is invalid.
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

    Ok(ValidatedStorageInventory {
        kernel_boot_id,
        broker_instance_id,
        journal_sequence: response.journal_sequence,
        catalog_generation: response.catalog_generation,
        workspaces,
    })
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

    Ok(ValidatedStorageWorkspace {
        workspace_handle,
        fence,
        root_image,
        resource_kernel_boot_id,
        root_directory: format!("{WORKSPACE_PIN_PREFIX}{}", encode_hex(&workspace_handle)),
        root_device: record.root_device,
        root_inode: record.root_inode,
        dataset_guid: record.dataset_guid,
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
    fn request_requires_storage_one_two() {
        let mut request = InventoryStorageRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 2;
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

        assert!(
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1,)
                .is_ok()
        );
        request.header.get_or_insert_default().protocol_minor = 1;
        assert_eq!(
            decode_storage_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::MethodMismatch)
        );
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
}
