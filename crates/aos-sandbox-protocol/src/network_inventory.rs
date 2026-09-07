//! Authoritative Network namespace-inventory validation.
//!
//! Network protocol 1.2 reports current physical namespace resources rather
//! than replaying the latest action result. Each row carries an exact
//! assignment, current-boot namespace identity, closed lease state, and
//! observation digest. The namespace pin is derived locally:
//!
//! ```text
//! /run/aos/sandbox-pins/netns/<64 lowercase hexadecimal digits>
//! ```
//!
//! Default-drop and armed rows are launchable. Fenced rows remain in inventory
//! as current cleanup evidence but cannot enter a Host launch catalog.

use std::collections::BTreeSet;

use aos_proto::aos::sandbox::local::v1::{
    InventoryNetworkResourcesResponse, InventoryNetworksRequest, NetworkNamespaceInventoryRecord,
    NetworkState,
};
use aos_sandbox_core::{ProtocolId, ProtocolVersion};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES, NETWORK_PIN_PREFIX,
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

/// Maximum current namespaces accepted in one complete Network snapshot.
pub const MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS: usize = 16_384;
const NETWORK_RESOURCE_INVENTORY_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);

/// Carries one complete validated Network resource snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedNetworkInventory {
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
    catalog_generation: u64,
    networks: Vec<ValidatedNetworkNamespace>,
}

impl ValidatedNetworkInventory {
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

    /// Returns the protected Network catalog generation used for observation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns current namespaces in strict handle order.
    #[must_use]
    pub fn networks(&self) -> &[ValidatedNetworkNamespace] {
        &self.networks
    }
}

/// Carries one assignment-bound current network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedNetworkNamespace {
    network_handle: [u8; 32],
    fence: ValidatedAssignmentFence,
    resource_kernel_boot_id: [u8; 16],
    namespace_path: String,
    namespace_device: u64,
    namespace_inode: u64,
    state: NetworkState,
    lease_generation: u64,
    fail_stop_boottime_nanoseconds: u64,
    resource_digest: [u8; 32],
}

impl ValidatedNetworkNamespace {
    /// Returns the opaque network handle.
    #[must_use]
    pub const fn network_handle(&self) -> &[u8; 32] {
        &self.network_handle
    }

    /// Returns the exact assignment owning the namespace.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the boot in which the namespace pin was observed.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }

    /// Returns the fixed root-owned namespace pin derived from the handle.
    #[must_use]
    pub fn namespace_path(&self) -> &str {
        &self.namespace_path
    }

    /// Returns the observed namespace device identity.
    #[must_use]
    pub const fn namespace_device(&self) -> u64 {
        self.namespace_device
    }

    /// Returns the observed namespace inode identity.
    #[must_use]
    pub const fn namespace_inode(&self) -> u64 {
        self.namespace_inode
    }

    /// Returns the closed current network lifecycle state.
    #[must_use]
    pub const fn state(&self) -> NetworkState {
        self.state
    }

    /// Reports whether this namespace may enter a Host launch catalog.
    #[must_use]
    pub const fn is_launchable(&self) -> bool {
        matches!(
            self.state,
            NetworkState::NETWORK_STATE_DEFAULT_DROP | NetworkState::NETWORK_STATE_ARMED
        )
    }

    /// Returns the active or last fail-stop lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the active or last fail-stop BOOTTIME deadline.
    #[must_use]
    pub const fn fail_stop_boottime_nanoseconds(&self) -> u64 {
        self.fail_stop_boottime_nanoseconds
    }

    /// Returns the commitment to the broker's complete current observation.
    #[must_use]
    pub const fn resource_digest(&self) -> &[u8; 32] {
        &self.resource_digest
    }
}

/// Decodes a Network 1.2 authoritative-inventory request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed request,
/// invalid peer/header semantics, unknown fields, or any version other than
/// Network 1.2.
pub fn decode_network_resource_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryNetworksRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::NetworkBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version() != NETWORK_RESOURCE_INVENTORY_VERSION {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    Ok(header)
}

/// Decodes and validates one complete Network namespace snapshot.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when bounds, protobuf structure,
/// snapshot metadata, row fields, ordering, boot identity, physical identity,
/// or lifecycle-dependent lease state is invalid.
pub fn decode_network_resource_inventory_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedNetworkInventory, ProtocolValidationError> {
    validate_response_bounds(bytes, maximum_response_bytes)?;

    let response = InventoryNetworkResourcesResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    if response.journal_sequence == 0 || response.catalog_generation == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "network inventory generation",
        ));
    }
    if response.networks.len() > MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "network inventory networks",
            maximum: MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS,
        });
    }

    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let networks = validate_networks(&response.networks, kernel_boot_id)?;

    Ok(ValidatedNetworkInventory {
        kernel_boot_id,
        broker_instance_id,
        journal_sequence: response.journal_sequence,
        catalog_generation: response.catalog_generation,
        networks,
    })
}

fn validate_networks(
    records: &[NetworkNamespaceInventoryRecord],
    kernel_boot_id: [u8; 16],
) -> Result<Vec<ValidatedNetworkNamespace>, ProtocolValidationError> {
    let mut networks = Vec::with_capacity(records.len());
    let mut physical_namespaces = BTreeSet::new();

    for record in records {
        let network = validate_network(record, kernel_boot_id)?;
        if networks
            .last()
            .is_some_and(|previous: &ValidatedNetworkNamespace| {
                previous.network_handle >= network.network_handle
            })
        {
            return Err(ProtocolValidationError::InvalidField(
                "network inventory handle order",
            ));
        }
        if !physical_namespaces.insert((network.namespace_device, network.namespace_inode)) {
            return Err(ProtocolValidationError::InvalidField(
                "network inventory physical identity",
            ));
        }

        networks.push(network);
    }

    Ok(networks)
}

fn validate_network(
    record: &NetworkNamespaceInventoryRecord,
    kernel_boot_id: [u8; 16],
) -> Result<ValidatedNetworkNamespace, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    let network_handle =
        exact_nonzero::<32>(&record.network_handle, "network inventory network_handle")?;
    let fence = validate_fence(record.fence.as_option().ok_or(
        ProtocolValidationError::MissingField("network inventory fence"),
    )?)?;
    let resource_kernel_boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "network inventory resource_kernel_boot_id",
    )?;
    if resource_kernel_boot_id != kernel_boot_id {
        return Err(ProtocolValidationError::InvalidField(
            "network inventory current boot",
        ));
    }
    if record.namespace_device == 0 || record.namespace_inode == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "network inventory namespace identity",
        ));
    }
    let state = record
        .state
        .as_known()
        .filter(|state| {
            matches!(
                state,
                NetworkState::NETWORK_STATE_DEFAULT_DROP
                    | NetworkState::NETWORK_STATE_ARMED
                    | NetworkState::NETWORK_STATE_FENCED
            )
        })
        .ok_or(ProtocolValidationError::UnknownState)?;
    let lease_shape_valid = match state {
        NetworkState::NETWORK_STATE_DEFAULT_DROP => {
            record.lease_generation == 0 && record.fail_stop_boottime_nanoseconds == 0
        }
        NetworkState::NETWORK_STATE_ARMED | NetworkState::NETWORK_STATE_FENCED => {
            record.lease_generation != 0 && record.fail_stop_boottime_nanoseconds != 0
        }
        _ => false,
    };
    if !lease_shape_valid {
        return Err(ProtocolValidationError::InvalidField(
            "network inventory lease state",
        ));
    }
    let resource_digest =
        exact_nonzero::<32>(&record.resource_digest, "network inventory resource_digest")?;

    Ok(ValidatedNetworkNamespace {
        network_handle,
        fence,
        resource_kernel_boot_id,
        namespace_path: format!("{NETWORK_PIN_PREFIX}{}", encode_hex(&network_handle)),
        namespace_device: record.namespace_device,
        namespace_inode: record.namespace_inode,
        state,
        lease_generation: record.lease_generation,
        fail_stop_boottime_nanoseconds: record.fail_stop_boottime_nanoseconds,
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

    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, Audience};

    use super::*;

    fn network(handle: u8, state: NetworkState) -> NetworkNamespaceInventoryRecord {
        let (lease_generation, fail_stop_boottime_nanoseconds) = match state {
            NetworkState::NETWORK_STATE_DEFAULT_DROP => (0, 0),
            _ => (10, 11),
        };
        NetworkNamespaceInventoryRecord {
            network_handle: vec![handle; 32],
            fence: Some(AssignmentFence {
                sandbox_id: vec![handle; 16],
                incarnation_id: vec![handle + 1; 16],
                assignment_epoch: 2,
                desired_generation: 3,
                assignment_digest: vec![handle + 2; 32],
                ..Default::default()
            })
            .into(),
            resource_kernel_boot_id: vec![9; 16],
            namespace_device: u64::from(handle),
            namespace_inode: u64::from(handle) + 20,
            state: state.into(),
            lease_generation,
            fail_stop_boottime_nanoseconds,
            resource_digest: vec![handle + 3; 32],
            ..Default::default()
        }
    }

    fn response(networks: Vec<NetworkNamespaceInventoryRecord>) -> Vec<u8> {
        InventoryNetworkResourcesResponse {
            kernel_boot_id: vec![9; 16],
            journal_sequence: 10,
            catalog_generation: 11,
            networks,
            broker_instance_id: vec![12; 16],
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn request_requires_network_one_two() {
        let mut request = InventoryNetworksRequest::default();
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
            decode_network_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1,)
                .is_ok()
        );
        request.header.get_or_insert_default().protocol_minor = 1;
        assert_eq!(
            decode_network_resource_inventory_request(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::MethodMismatch)
        );
    }

    #[test]
    fn snapshot_distinguishes_launchable_and_fenced_namespaces() {
        let inventory = decode_network_resource_inventory_response(
            &response(vec![
                network(1, NetworkState::NETWORK_STATE_DEFAULT_DROP),
                network(2, NetworkState::NETWORK_STATE_ARMED),
                network(3, NetworkState::NETWORK_STATE_FENCED),
            ]),
            65_536,
        )
        .unwrap();

        assert!(inventory.networks()[0].is_launchable());
        assert!(inventory.networks()[1].is_launchable());
        assert!(!inventory.networks()[2].is_launchable());
        assert_eq!(
            inventory.networks()[0].namespace_path(),
            format!("{NETWORK_PIN_PREFIX}{}", "01".repeat(32))
        );
    }

    #[test]
    fn snapshot_rejects_order_duplicate_physical_identity_and_stale_boot() {
        assert!(
            decode_network_resource_inventory_response(
                &response(vec![
                    network(2, NetworkState::NETWORK_STATE_DEFAULT_DROP),
                    network(1, NetworkState::NETWORK_STATE_DEFAULT_DROP),
                ]),
                65_536,
            )
            .is_err()
        );

        let first = network(1, NetworkState::NETWORK_STATE_DEFAULT_DROP);
        let mut duplicate = network(2, NetworkState::NETWORK_STATE_DEFAULT_DROP);
        duplicate.namespace_device = first.namespace_device;
        duplicate.namespace_inode = first.namespace_inode;
        assert!(
            decode_network_resource_inventory_response(&response(vec![first, duplicate]), 65_536,)
                .is_err()
        );

        let mut stale = network(1, NetworkState::NETWORK_STATE_DEFAULT_DROP);
        stale.resource_kernel_boot_id = vec![8; 16];
        assert!(
            decode_network_resource_inventory_response(&response(vec![stale]), 65_536).is_err()
        );
    }

    #[test]
    fn snapshot_rejects_invalid_lifecycle_lease_shapes() {
        let mut default_drop = network(1, NetworkState::NETWORK_STATE_DEFAULT_DROP);
        default_drop.lease_generation = 1;
        assert!(
            decode_network_resource_inventory_response(&response(vec![default_drop]), 65_536)
                .is_err()
        );

        let mut armed = network(1, NetworkState::NETWORK_STATE_ARMED);
        armed.fail_stop_boottime_nanoseconds = 0;
        assert!(
            decode_network_resource_inventory_response(&response(vec![armed]), 65_536).is_err()
        );

        assert!(
            decode_network_resource_inventory_response(
                &response(vec![network(1, NetworkState::NETWORK_STATE_FAILED)]),
                65_536,
            )
            .is_err()
        );
    }
}
