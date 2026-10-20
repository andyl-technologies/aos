//! Owns no-slot resource pins in the same Mount destination namespace.
//!
//! The protected key is sandbox16 + incarnation16 + namespace-generation8.
//! It never uses an invented slot identifier. Ready inventory reproduces the
//! actual retained directory identity; a stale boot cannot become a new pin.

use super::*;
use aos_proto::aos::sandbox::local::v1::{
    AttachmentAnchorLifecycleV1 as Phase, AttachmentAnchorResourceRecordV1,
};
use std::sync::Arc;

mod physical;
mod mutation;
mod inventory;
mod startup;
pub use startup::DestinationSlotStartupOriginalV4;
pub use inventory::{MountAttachmentAnchorInventoryOriginalV4, MountAttachmentAnchorInventoryShapeDataV4};
pub use mutation::{MountAttachmentAnchorOriginalV4, MountAttachmentAnchorPhysicalShapeDataV1};
pub(super) use physical::{DirectoryParentOriginalV1, DirectorySyncOriginalV1,
    unlink_empty_directory_v1};

type NamespaceKeyV1 = [u8; 40];

pub(super) struct NamespaceAnchorTableV1 {
    records: BTreeMap<NamespaceKeyV1, ValidatedAttachmentAnchorResourceV1>,
    pins: BTreeMap<NamespaceKeyV1, Arc<BeneathRoot>>,
}

impl NamespaceAnchorTableV1 {
    pub(super) fn new(records: BTreeMap<NamespaceKeyV1, ValidatedAttachmentAnchorResourceV1>) -> Self {
        Self { records, pins: BTreeMap::new() }
    }

    pub(super) fn len_v1(&self) -> usize { self.records.len() }

    pub(super) fn inventory_custody_empty_v2(&self) -> bool {
        self.records.is_empty() && self.pins.is_empty()
    }

    pub(super) fn require_slot_namespace_v4(&self, slot: &SlotKey) -> Result<()> {
        // Intent and tombstone rows retain namespace ownership too. This is
        // symmetric with no-slot materialization and the complete cold fold.
        if self.records.values().any(|row| row.fence().sandbox_id() == &slot.sandbox_id
            && row.fence().incarnation_id() == &slot.incarnation_id
            && row.namespace_generation() == slot.namespace_generation)
        {
            return Err(conflict("destination-slot namespace is owned by a no-slot anchor"));
        }
        Ok(())
    }


    pub(super) fn uses_operation_v1(&self, operation: OperationId) -> bool {
        self.records.values().any(|record| {
            &record.materialization_v1().0 == operation.as_bytes()
                || record.reap_v1().is_some_and(|reap| &reap.0 == operation.as_bytes())
        })
    }
}

impl DestinationSlotStoreV1 {
    pub(crate) fn namespace_anchor_resources_v1(&self) -> Vec<AttachmentAnchorResourceRecordV1> {
        self.namespace_anchors.records.values().map(|record| record.wire_v1()).collect()
    }


}

fn namespace_path_v1(record: &ValidatedAttachmentAnchorResourceV1) -> PathBuf {
    anchor_catalog_relative_path(record.fence().sandbox_id(), record.fence().incarnation_id(),
        record.namespace_generation())
}
