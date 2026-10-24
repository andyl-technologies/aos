//! Prices the existing complete inventory producer before validation and probes.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use std::mem::size_of;

impl NetworkNamespaceCatalogV1 {
    pub(crate) fn inventory_receiving_demand_v4(&self) -> Result<ResourceVector, AccountingError> {
        let overflow = || AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let rows = self.records.len();
        let pin_rows = self
            .records
            .values()
            .filter(|record| {
                matches!(record.lifecycle, NamespaceLifecycleV1::Retired)
                    || record.kernel_boot_id == self.kernel_boot_id
            })
            .count();
        let probes =
            NetworkPinObservationOriginalV4::receiving_demand_v4(pin_rows).ok_or_else(overflow)?;

        // validate_record_set keeps request/transition IDs (at most two per
        // row), assignment pairs and full boot/device/inode identities. The
        // canonical response decoder separately keeps device/inode uniqueness.
        let nodes =
            aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<[u8; 16], ()>(
                rows.checked_mul(2).ok_or_else(overflow)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
                        ([u8; 16], [u8; 16]),
                        (),
                    >(rows)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
                        ([u8; 16], u64, u64),
                        (),
                    >(rows)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
                        (u64, u64),
                        (),
                    >(rows)?,
                )
            })
            .ok_or_else(overflow)?;

        // The producer only emits the fixed canonical row fields: 32-byte
        // handle/digest, 16-byte boot and assignment IDs, two fence uint64s,
        // four row uint64s and one closed state. With maximal scalar varints
        // the nested fence is 92 bytes, each row 226, its outer wrapper 229;
        // the snapshot's two IDs and two uint64s contribute at most 58 bytes.
        let wire = canonical_inventory_wire_bound_v4(rows).ok_or_else(overflow)?;
        let slots = rows
            .checked_mul(8)
            .and_then(|slots| slots.checked_add(8))
            .ok_or_else(overflow)?;
        let path = aos_sandbox_protocol::NETWORK_PIN_PREFIX
            .len()
            .checked_add(64)
            .ok_or_else(overflow)?;
        let model = size_of::<NetworkNamespaceInventoryRecord>()
            .checked_add(size_of::<AssignmentFence>())
            .and_then(|bytes| {
                bytes.checked_add(size_of::<aos_sandbox_protocol::ValidatedNetworkNamespace>())
            })
            .and_then(|bytes| bytes.checked_mul(slots))
            // Each source/decoded row owns 144 fixed byte-field payload bytes;
            // derived paths can coexist with their intermediate hex strings.
            .and_then(|bytes| bytes.checked_add(rows.checked_mul(3 * 144)?))
            .and_then(|bytes| {
                bytes.checked_add(rows.checked_mul(path.checked_mul(3)?.checked_add(64)?)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<InventoryNetworkResourcesResponse>().checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<aos_sandbox_protocol::ValidatedNetworkInventory>())
            })
            .ok_or_else(overflow)?;
        // Record digest validation serializes one fixed record at a time.
        let bytes = nodes
            .checked_add(model)
            .and_then(|bytes| bytes.checked_add(wire.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(MAXIMUM_RECORD_BYTES.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<NamespaceRecordV1>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow)?;
        let names =
            u64::try_from(rows.checked_mul(5).ok_or_else(overflow)?).map_err(|_| overflow())?;
        let roots = if self.has_no_namespace_history_v2() {
            let (files, names) =
                super::NetworkPinRootAbsenceOriginalV2::receiving_native_shape_v2()
                    .ok_or_else(overflow)?;
            // The service's complete inline header already includes both raw
            // directory owners. Their native descriptors and names are extra.
            ResourceVector::ZERO
                .with(
                    D::OpenFiles,
                    u64::try_from(files.checked_mul(2).ok_or_else(overflow)?)
                        .map_err(|_| overflow())?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(names.checked_mul(2).ok_or_else(overflow)?)
                        .map_err(|_| overflow())?,
                )
        } else {
            ResourceVector::ZERO
        };
        probes.checked_add(roots)?.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, bytes)
                .with(D::MetadataEntries, names),
        )
    }
}

fn canonical_inventory_wire_bound_v4(rows: usize) -> Option<usize> {
    // The optional 96-byte fixed companion adds one tag, one length and its body.
    rows.checked_mul(229)?.checked_add(58 + 98)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_wire_quote_covers_maximum_scalar_and_fixed_byte_fields() {
        let row = NetworkNamespaceInventoryRecord {
            network_handle: vec![1; 32],
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: u64::MAX,
                desired_generation: u64::MAX,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            resource_kernel_boot_id: vec![5; 16],
            namespace_device: u64::MAX,
            namespace_inode: u64::MAX,
            state: NetworkState::NETWORK_STATE_FENCED.into(),
            lease_generation: u64::MAX,
            fail_stop_boottime_nanoseconds: u64::MAX,
            resource_digest: vec![6; 32],
            ..Default::default()
        };
        let response = InventoryNetworkResourcesResponse {
            kernel_boot_id: vec![5; 16],
            journal_sequence: u64::MAX,
            catalog_generation: u64::MAX,
            networks: vec![row],
            broker_instance_id: vec![7; 16],
            native_absence_v2: vec![8; 96],
            ..Default::default()
        };

        let bytes = response.encode_to_vec();

        assert_eq!(bytes.len(), canonical_inventory_wire_bound_v4(1).unwrap());
        assert!(canonical_inventory_wire_bound_v4(usize::MAX).is_none());
    }
}
