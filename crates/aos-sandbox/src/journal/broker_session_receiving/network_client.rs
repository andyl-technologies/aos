//! Prices the closed Start Network Client's additional typed model planes.
//!
//! Generic authenticated packet/history owners have separate suppliers. These
//! bounds grow no model, read no sealed content, and create no payer or grant.
//! The genuine Start loan must join them before its corresponding decoder.

use super::*;
use aos_proto::aos::sandbox::local::v1::{
    ApplyNetworkRequest, InventoryNetworkResourcesResponse, NetworkNamespaceInventoryRecord,
};
use aos_sandbox_protocol::semantics::network::{
    CanonicalNetworkSemanticsV1, MAXIMUM_NETWORK_ENDPOINTS,
};
use aos_sandbox_protocol::{
    MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS, NETWORK_PIN_PREFIX, ValidatedNetworkInventory,
    ValidatedNetworkNamespace,
};

/// Prices the Network63 request's additional typed decoder and semantic model.
///
/// The actual width is the retained authenticated request packet's width; its
/// portable body is no larger. Generic packet/descriptor/history capture is
/// separate. The already owned manifest/specification and sealed descriptor
/// belong to the real Prepared owner; this stage does not decode them again.
///
/// # Errors
/// Refuses an actual packet beyond the established request ceiling or checked
/// model geometry that cannot be represented.
pub fn network_prepare_client_request_additional_demand_v2(
    actual_request_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if actual_request_bytes > AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES {
        return Err(invalid());
    }
    let bytes = as_u64(actual_request_bytes)?;
    let proto = protobuf_carriers(bytes, as_u64(size_of::<Vec<u8>>())?)?;
    let singular = sum(&[
        as_u64(size_of::<ApplyNetworkRequest>())?,
        as_u64(size_of::<RequestHeader>())?,
        as_u64(size_of::<AssignmentFence>())?,
        as_u64(size_of::<CanonicalNetworkSemanticsV1>())?,
    ])?;
    let endpoints = (bytes / 2).min(as_u64(MAXIMUM_NETWORK_ENDPOINTS)?);
    // The canonical decoder allocates the endpoint Vec only after its exact
    // count check. Growth and the concurrently encoded semantic byte string
    // stay Memory; endpoint values do not form a named index here.
    let validated = mul(add(mul(endpoints, 3)?, 4)?, 16)?;
    let memory = sum(&[proto, mul(3, singular)?, validated, mul(16, bytes)?])?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
}

/// Prices the Network19 protobuf, validated rows, derived paths and uniqueness set.
///
/// This is additional to the generic authenticated outcome capture. A hostile
/// packet can allocate repeated protobuf records before the canonical row cap
/// is checked, so only the later validated plane uses that cap. The actual
/// physical-identity uniqueness set contributes one named entry per reached
/// validated row; spare Vec/B-tree capacity and decoder fields remain Memory.
///
/// # Errors
/// Refuses an actual packet beyond the established authenticated response
/// ceiling or unrepresentable checked geometry.
pub fn network_inventory_client_response_decode_demand_v2(
    actual_packet_bytes: usize,
) -> Result<ResourceVector, StorageSessionGeometryRefusalV1> {
    if actual_packet_bytes > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(invalid());
    }
    let bytes = as_u64(actual_packet_bytes)?;
    let width = as_u64(size_of::<NetworkNamespaceInventoryRecord>())?;
    let protobuf = protobuf_carriers(bytes, width)?;
    // Every nested record may own a singular AssignmentFence independently of
    // the repeated-element allocator cap. The common protobuf supplier also
    // includes payload copies and unknown-field/group carriers.
    let singular_fences = mul(
        add(mul(bytes / 2, 3)?, 4)?,
        as_u64(size_of::<AssignmentFence>())?,
    )?;
    let rows = (bytes / 2).min(as_u64(MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS)?);
    let vec_cells = add(mul(rows, 3)?, 4)?;
    let path_bytes = as_u64(
        NETWORK_PIN_PREFIX
            .len()
            .checked_add(64)
            .ok_or_else(invalid)?,
    )?;
    // Derived path formatting may coexist with its intermediate hex String.
    let paths = mul(rows, add(mul(3, path_bytes)?, 64)?)?;
    // validate_networks holds one BTreeSet<(device,inode)>. One complete
    // eleven-key node per row dominates its sparse-node and parent/link share.
    let set_node = sum(&[
        mul(11, as_u64(size_of::<(u64, u64)>())?)?,
        mul(16, as_u64(size_of::<usize>())?)?,
        as_u64(std::mem::align_of::<(u64, u64)>())?,
    ])?;
    let validated = sum(&[
        mul(vec_cells, as_u64(size_of::<ValidatedNetworkNamespace>())?)?,
        paths,
        mul(rows, set_node)?,
        mul(3, as_u64(size_of::<ValidatedNetworkInventory>())?)?,
    ])?;
    let fixed = sum(&[
        as_u64(size_of::<InventoryNetworkResourcesResponse>())?,
        mul(4, width)?,
    ])?;
    Ok(ResourceVector::ZERO
        .with(
            D::MemoryBytes,
            sum(&[protobuf, singular_fences, validated, fixed])?,
        )
        .with(D::MetadataEntries, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_inventory_prefix_keeps_prevalidation_and_named_rows_separate() {
        let tiny = network_inventory_client_response_decode_demand_v2(2).unwrap();
        let full = network_inventory_client_response_decode_demand_v2(64 * 1024).unwrap();
        let larger = network_inventory_client_response_decode_demand_v2(128 * 1024).unwrap();
        assert_eq!(tiny.get(D::MetadataEntries), 1);
        assert!(tiny.get(D::MemoryBytes) < full.get(D::MemoryBytes));
        assert_eq!(
            full.get(D::MetadataEntries),
            MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS as u64
        );
        assert_eq!(full.get(D::MetadataEntries), larger.get(D::MetadataEntries));
        // Buffa may still grow hostile records before the later row-cap check.
        assert!(full.get(D::MemoryBytes) < larger.get(D::MemoryBytes));
        assert_eq!(larger.get(D::OpenFiles), 0);
    }

    #[test]
    fn typed_prepare_has_no_namespace_or_new_transport_charge() {
        let demand = network_prepare_client_request_additional_demand_v2(4096).unwrap();
        assert!(demand.get(D::MemoryBytes) > 4096);
        assert_eq!(demand.get(D::MetadataEntries), 0);
        assert_eq!(demand.get(D::NetworkBytes), 0);
        assert_eq!(demand.get(D::StorageBytes), 0);
        assert!(network_prepare_client_request_additional_demand_v2(usize::MAX).is_err());
        assert!(network_inventory_client_response_decode_demand_v2(usize::MAX).is_err());
    }
}
