//! Bounds the four closed Controller Inventory decoder frontiers.
//!
//! The shared outcome engine retains its actual packet, canonical envelope,
//! traffic and error. Its pure body validators may consume parser scratch on
//! refusal. This recipe pays their dominant byte peak before decoding; it
//! creates no payer, request, native owner or Inventory proof.

use std::mem::size_of;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerError, BrokerMethod, Feature, InventoryMountResourcesResponse,
    InventoryNetworkResourcesResponse, InventoryRuntimeResponse, MountAssignmentBinding,
    MountAttributes, MountFaultCorrelation, MountInventoryRecord, MountKernelObservation,
    MountOperationCorrelation, MountPublicationCorrelation, MountRecipe,
    NetworkNamespaceInventoryRecord, RuntimeObservation,
};
use aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::AuthenticatedBrokerMethodOutcomeCaptureV1;

impl AuthenticatedBrokerMethodOutcomeCaptureV1 {
    /// Bounds dynamic comparison bytes for one fixed Controller Inventory method.
    ///
    /// The byte count is the actual captured packet or protected history extent.
    /// The genuine caller admits this DATA before either the shared terminal
    /// decoder or its complete returned-model decoder. Actual retained namespace
    /// entries are accounted by their native owner, outside these pure parsers.
    ///
    /// Returns `None` for another method or unrepresentable arithmetic.
    #[must_use]
    pub fn controller_inventory_dynamic_receiving_demand_v1(
        method: BrokerMethod,
        actual_prefix_bytes: usize,
    ) -> Option<ResourceVector> {
        let bytes = u64::try_from(actual_prefix_bytes).ok()?;
        let common = Self::dynamic_receiving_demand_v1(actual_prefix_bytes)?
            .get(D::MemoryBytes);
        let body = match method {
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME => {
                let generated = generated_body(bytes, &[
                    size_of::<InventoryRuntimeResponse>(), size_of::<RuntimeObservation>(),
                    size_of::<AssignmentFence>(), size_of::<BrokerError>(), size_of::<Feature>(),
                ])?;
                // Host returns generated runtime rows without a second typed
                // model or index. The ordinary validator also re-encodes the
                // complete canonical body before accepting it.
                generated.checked_add(bytes.checked_mul(3)?)?
                    .checked_add(u64::try_from(3 * size_of::<
                        crate::host_stopped_namespace::HostStoppedNamespaceDataV4>()).ok()?)?
                    .checked_add(u64::try_from(3 * size_of::<
                        crate::host_inventory_absence::HostInventoryAbsenceDataV5>()).ok()?)?
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES => {
                mount_body(bytes)?
            }
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS => {
                destination_slot_body(bytes)?.checked_add(u64::try_from(3 * size_of::<
                    crate::fixed_service_inventory_absence::FixedServiceInventoryAbsenceDataV2>()).ok()?)?
            }
            BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => {
                network_body(bytes)?.checked_add(u64::try_from(3 * size_of::<
                    crate::fixed_service_inventory_absence::FixedServiceInventoryAbsenceDataV2>()).ok()?)?
            }
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
                // Preserve the same decoder's whole generated model beside
                // validated workspaces, including every lifecycle extension.
                // Use the sole full-schema protobuf recipe; no packet-times-
                // largest-DTO or parser-field namespace fee is introduced.
                let body = aos_sandbox_broker_session_protocol::receiving_geometry::
                    schema_protobuf_carriers_v1(bytes, 1).ok()?.checked_mul(3)?;
                body.checked_add(u64::try_from(3 * size_of::<
                    aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse,
                >()).ok()?)?
            }
            _ => return None,
        };
        Some(ResourceVector::ZERO.with(D::MemoryBytes, common.checked_add(body)?))
    }
}

fn generated_body(bytes: u64, widths: &[usize]) -> Option<u64> {
    let width = u64::try_from(*widths.iter().max()?).ok()?;
    // The terminal validator and the later complete returned-model decoder
    // each own a generated body. Every nested message needs tag+length, so
    // the same actual maximum node width bounds repeated and boxed children.
    protobuf_carriers_v1(bytes, width).ok()?.checked_mul(2)
}

fn mount_body(bytes: u64) -> Option<u64> {
    let generated = generated_body(bytes, &[
        size_of::<InventoryMountResourcesResponse>(), size_of::<MountInventoryRecord>(),
        size_of::<MountAssignmentBinding>(), size_of::<AssignmentFence>(),
        size_of::<MountRecipe>(), size_of::<aos_proto::aos::sandbox::local::v1::Descriptor>(),
        size_of::<MountAttributes>(), size_of::<MountKernelObservation>(),
        size_of::<MountOperationCorrelation>(), size_of::<MountPublicationCorrelation>(),
        size_of::<MountFaultCorrelation>(),
    ])?;
    let rows = (bytes / 2).min(u64::try_from(crate::MAXIMUM_MOUNT_INVENTORY_RECORDS).ok()?);
    let models = rows.checked_mul(u64::try_from(
        size_of::<crate::ValidatedMountInventoryRecord>()
            .checked_add(size_of::<crate::SourceRealizationBindingV1>())?
            .checked_add(size_of::<crate::MountSourceProviderHistoryV1>())?,
    ).ok()?)?.checked_mul(3)?;
    // The first kernel-ID map can retain three IDs per row. Source validation
    // additionally holds six maps, followed by the slot map and its claimant
    // vectors. One full node per reached entry dominates sparse B-tree nodes;
    // the largest real key/value is the resource-generation/digest pair.
    let key_value = u64::try_from(size_of::<(([u8; 16], [u8; 32], u64), [u8; 32])>()).ok()?;
    let links = u64::try_from(3 * 12 * size_of::<usize>()).ok()?;
    let indexes = rows.checked_mul(10)?.checked_mul(key_value.checked_mul(11)?.checked_add(links)?)?;
    let claimants = rows.checked_mul(u64::try_from(12 * size_of::<usize>()).ok()?)?;
    // Source binding media strings, generated raw bytes, canonical CBOR
    // re-encoding and the validated kernel paths all derive from this body.
    let backing = bytes.checked_mul(12)?;
    generated.checked_add(models)?.checked_add(indexes)?
        .checked_add(claimants)?.checked_add(backing)
}

fn network_body(bytes: u64) -> Option<u64> {
    let generated = generated_body(bytes, &[
        size_of::<InventoryNetworkResourcesResponse>(),
        size_of::<NetworkNamespaceInventoryRecord>(), size_of::<AssignmentFence>(),
    ])?;
    let rows = (bytes / 2).min(u64::try_from(crate::MAXIMUM_NETWORK_NAMESPACE_INVENTORY_RECORDS).ok()?);
    let model = u64::try_from(size_of::<crate::ValidatedNetworkNamespace>()).ok()?;
    let pin = u64::try_from(crate::NETWORK_PIN_PREFIX.len().checked_add(64)?).ok()?;
    let models = rows.checked_mul(model.checked_add(pin)?)?.checked_mul(3)?;
    let key = u64::try_from(size_of::<(u64, u64)>()).ok()?;
    let links = u64::try_from(3 * 12 * size_of::<usize>()).ok()?;
    let index = rows.checked_mul(key.checked_mul(11)?.checked_add(links)?)?;
    generated.checked_add(models)?.checked_add(index)
}


fn destination_slot_body(bytes: u64) -> Option<u64> {
    use aos_proto::aos::sandbox::local::v1::{
        InventoryDestinationSlotsResponse, DestinationSlotInventoryRecord,
        AttachmentAnchorInventoryRecord, AttachmentAnchorResourceRecordV1,
        DestinationSlotRematerializationCorrelation, DestinationSlotReapCorrelation, Descriptor,
    };
    use crate::mount_destination_slot::{
        MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS, ValidatedDestinationSlotInventoryRecord,
        ValidatedAttachmentAnchorInventoryRecord,
    };
    use crate::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1;
    let generated = generated_body(bytes, &[
        size_of::<InventoryDestinationSlotsResponse>(), size_of::<DestinationSlotInventoryRecord>(),
        size_of::<AttachmentAnchorInventoryRecord>(), size_of::<AttachmentAnchorResourceRecordV1>(),
        size_of::<MountAssignmentBinding>(), size_of::<AssignmentFence>(), size_of::<Descriptor>(),
        size_of::<MountOperationCorrelation>(), size_of::<DestinationSlotRematerializationCorrelation>(),
        size_of::<DestinationSlotReapCorrelation>(),
    ])?;
    // There are at most R slot/namespace resources and R physical anchor rows.
    // Each typed row needs a protobuf tag and length; generated parser growth
    // before the semantic limit is covered independently above.
    let rows = (bytes / 2).min(u64::try_from(MAXIMUM_DESTINATION_SLOT_INVENTORY_RECORDS)
        .ok()?.checked_mul(2)?);
    let width = [size_of::<ValidatedDestinationSlotInventoryRecord>(),
        size_of::<ValidatedAttachmentAnchorInventoryRecord>(), size_of::<ValidatedAttachmentAnchorResourceV1>()]
        .into_iter().max()?;
    let models = rows.checked_mul(u64::try_from(width).ok()?)?.checked_mul(3)?;
    // The actual validator owns a three-ID-per-slot operation set and two
    // native-identity maps. These are Memory for real indices, not Metadata.
    let node = |width: usize| u64::try_from(width.checked_mul(11)?
        .checked_add(3usize.checked_mul(12)?.checked_mul(size_of::<usize>())?)?).ok();
    let operation = node(size_of::<[u8; 16]>())?.checked_mul(3)?;
    let ready = node(size_of::<(([u8; 16], [u8; 16], u64), (u64, u64))>())?;
    let physical = node(size_of::<(([u8; 16], [u8; 16], u64), (u64, u64, u64))>())?;
    let indices = rows.checked_mul(operation.checked_add(ready)?.checked_add(physical)?)?;
    // Three receiving/move copies retain descriptor media backing. Namespace
    // digest comparison also constructs its canonical wire record and encoded
    // bytes; three aggregate-body copies dominate that reached local plane.
    let descriptor_backing = bytes.checked_mul(3)?;
    let namespace_digest_backing = bytes.checked_mul(3)?;
    let backing = descriptor_backing.checked_add(namespace_digest_backing)?;
    generated.checked_add(models)?.checked_add(indices)?.checked_add(backing)
}


#[cfg(test)]
mod destination_slot_tests {
    use super::*;

    #[test]
    fn closed_mount16_supplier_prices_real_indices_and_refuses_overflow() {
        let ordinary = AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES, 512).unwrap();
        let selected = AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS, 512).unwrap();
        assert!(ordinary.get(D::MemoryBytes) > 0);
        assert!(selected.get(D::MemoryBytes) > AuthenticatedBrokerMethodOutcomeCaptureV1::
            dynamic_receiving_demand_v1(512).unwrap().get(D::MemoryBytes));
        assert_eq!(selected.get(D::MetadataEntries), 0);
        assert_eq!(selected.get(D::OpenFiles), 0);
        assert!(AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS, usize::MAX).is_none());
        assert!(AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1, 512).is_none());
    }
}
