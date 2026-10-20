//! Prices the reached closed Storage comparison from its actual held prefix.
//!
//! This is checked representation DATA. The caller must derive the prefix from
//! its genuine native original and admit the entire result before work. An
//! arbitrary scalar or a successful calculation supplies no payer or permission.

use std::mem::size_of;

use aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope;
use aos_sandbox_broker_session_protocol::artifact::BrokerSessionArtifactVerifyCaptureV1;
use aos_sandbox_broker_session_protocol::receiving_geometry::schema_protobuf_carriers_v1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::*;
use crate::storage_inventory::{MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS,
    ValidatedStorageOperatorRepairCommitV1, ValidatedStorageWorkspace};

impl AuthenticatedBrokerMethodOutcomeCaptureV1 {
    /// Returns this actual fixed owner layout, excluding dynamic destinations.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize { size_of::<Self>() }

    // Preserves the complete existing diagnostic backing bound. These fixed
    // destinations occupy Memory; their Rust fields create no namespace entry.
    fn diagnostic_backing_bytes_v2() -> Option<usize> {
        // Top13 minus its four nested owners =9; response projection raw/error,
        // feature3, table2, completed descriptors/dispositions =9; Inventory20;
        // Prepare5, body Result1 and current-publication Result1. The two lower owners derive their own cells.
        BrokerOutcomePacketAdmissionCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(CanonicalBrokerResponseDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(9 + 9 + 20 + 5 + 1 + 1)?
            // Network9's actual decode/result/action/entry destinations.
            .checked_add(4)?.checked_mul(256)
    }

    /// Bounds complete fixed and dynamic terminal comparison representation.
    ///
    /// `actual_prefix_bytes` comes from the caller's same captured native
    /// prefix, including retained HELLO/request/outcome history. It is an actual
    /// encoded-extent bound, not a configured response ceiling or a grant.
    /// Request/body wire bytes may already be resident; this prices the *new*
    /// decodes, copies, indexes and candidate traffic created by this engine.
    #[must_use]
    pub fn receiving_demand_v1(actual_prefix_bytes: usize) -> Option<ResourceVector> {
        let inline = u64::try_from(Self::inline_bytes_v1()).ok()?;
        Self::dynamic_receiving_demand_v1(actual_prefix_bytes)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, inline)).ok()
    }

    /// Bounds work when the outer owner already paid its inline representation.
    ///
    /// This shares the exact same recipe as [`Self::receiving_demand_v1`]. It
    /// never credits, resets or extracts the actual caller's financial account.
    #[must_use]
    pub fn dynamic_receiving_demand_v1(actual_prefix_bytes: usize) -> Option<ResourceVector> {
        let bytes = u64::try_from(actual_prefix_bytes).ok()?;
        // Packet projection, repeated canonical pass, response projection,
        // nested body, cloned transcript, completed request and canonical scratch
        // are simultaneous backing lanes. The sole shared schema recipe also
        // covers nested fields, unknown trees, Vec floors and old/new growth.
        let schema = schema_protobuf_carriers_v1(bytes, 1).ok()?.checked_mul(7)?;
        let rows = (bytes / 2).min(u64::try_from(MAXIMUM_STORAGE_WORKSPACE_INVENTORY_RECORDS).ok()?);
        let workspace = u64::try_from(size_of::<ValidatedStorageWorkspace>()).ok()?;
        let repair = u64::try_from(size_of::<ValidatedStorageOperatorRepairCommitV1>()).ok()?;
        let ranges = u64::try_from(size_of::<(u32, u32)>()).ok()?;
        // Each supported repeated message costs at least tag+length. Complete
        // model Vecs and ranges are distinct from raw generated message cells;
        // three carrier lanes dominate growth/reallocation overlap.
        let models = rows.checked_mul(workspace.checked_add(repair)?.checked_add(ranges)?)?
            .checked_mul(3)?;
        // One full 11-key/12-link B-tree node for each reached physical, dataset
        // or fixed checkpoint key dominates the actual selected index allocation.
        let key_bytes = u64::try_from(size_of::<(u64, u64)>() + size_of::<u64>() + size_of::<[u8; 16]>()).ok()?;
        let links = u64::try_from(3 * 12 * size_of::<usize>()).ok()?;
        let indexes = rows.checked_mul(key_bytes.checked_mul(11)?.checked_add(links)?)?;
        // Validated workspace pin names are fixed from their opaque handle.
        // Media type and error namespace copies are bounded by reached wire;
        // the shared raw-copy term includes those bytes independently.
        let pin = u64::try_from(crate::WORKSPACE_PIN_PREFIX.len() + 64).ok()?;
        let pins = rows.checked_mul(pin)?.checked_mul(3)?;
        let locals = u64::try_from(2 * size_of::<BrokerSessionTrafficStateV1>()
            + 3 * size_of::<BrokerResponseEnvelope>()
            + 2 * size_of::<AuthenticatedBrokerMethodRequestV1>()
            + 2 * size_of::<Sha256>()).ok()?;
        let crypto = u64::try_from(BrokerSessionArtifactVerifyCaptureV1::receiving_heap_bytes_v1()?).ok()?;
        // Bounded actual diagnostic messages/native signature work coexist with
        // their named destination. Variable input text already lies in schema.
        let diagnostics = u64::try_from(Self::diagnostic_backing_bytes_v2()?).ok()?;
        let memory = schema.checked_add(models)?.checked_add(indexes)?.checked_add(pins)?
            .checked_add(locals)?.checked_add(crypto)?.checked_add(diagnostics)?;
        // Workspace physical/dataset sets and checkpoint request IDs are real
        // validation indices. Both retained and returned-model passes can own
        // them together. Protobuf fields and byte-copy lanes create no names.
        let metadata = rows.checked_mul(6)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::MetadataEntries, metadata))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_and_embedded_owner_recipes_differ_by_only_actual_fixed_layout() {
        let prefix = 8_192;
        let dynamic = AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(prefix).unwrap();
        let total = AuthenticatedBrokerMethodOutcomeCaptureV1::receiving_demand_v1(prefix).unwrap();
        assert_eq!(total.get(D::MemoryBytes) - dynamic.get(D::MemoryBytes),
            AuthenticatedBrokerMethodOutcomeCaptureV1::inline_bytes_v1() as u64);
        assert_eq!(total.get(D::MetadataEntries), dynamic.get(D::MetadataEntries));
        assert_eq!(total.get(D::OpenFiles), 0);
        if usize::BITS == 64 {
            // Reached schema and row counts saturate at their real caps;
            // a larger historical prefix need not overflow this DATA recipe.
            let saturated = AuthenticatedBrokerMethodOutcomeCaptureV1::receiving_demand_v1(usize::MAX).unwrap();
            assert_eq!(
                AuthenticatedBrokerMethodOutcomeCaptureV1::receiving_demand_v1(usize::MAX - 1),
                Some(saturated),
            );
            assert!(saturated.get(D::MemoryBytes) >= total.get(D::MemoryBytes));
            assert!(saturated.get(D::MetadataEntries) >= total.get(D::MetadataEntries));
        }
    }
}
