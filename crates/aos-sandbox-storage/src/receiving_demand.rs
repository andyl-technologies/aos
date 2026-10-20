//! Passive geometry for the contacted Storage Inventory producer.
//!
//! These values describe objects, never ownership or permission. The sole
//! receiving original pays them before the existing Inventory engine enters.
//! Geometry is collected without cloning, decoding or projecting journal rows.

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_proto::aos::sandbox::local::v1::{
    InventoryStorageResourcesResponse, StorageAtomicSnapshotCheckpoint,
    StorageLifecycleInventoryRecord, StorageLifecycleTransitionRecord,
    StorageOperatorRepairCommitRecordV1, StorageWorkspaceInventoryRecord,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct StorageInventoryGeometryV1 {
    pub(crate) encoded_bytes: u64,
    pub(crate) journal_rows: u64,
    pub(crate) workspace_rows: u64,
    pub(crate) lifecycle_rows: u64,
    pub(crate) transition_rows: u64,
    pub(crate) atomic_rows: u64,
    pub(crate) repair_rows: u64,
    pub(crate) worker_rows: u64,
    // Exact recovered map entries and physical catalog namespace rows from
    // the already-held source, independent of serialization/model copies.
    pub(crate) namespace_entries: u64,
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64, AccountingError> {
    left.checked_add(right).ok_or(AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    })
}

pub(crate) fn multiply(left: u64, right: u64) -> Result<u64, AccountingError> {
    left.checked_mul(right).ok_or(AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    })
}

pub(crate) fn count(value: usize) -> Result<u64, AccountingError> {
    u64::try_from(value).map_err(|_| AccountingError::ArithmeticOverflow {
        dimension: D::MetadataEntries,
    })
}

// These choices identify the actual loader, never a payer or caller-selected
// resource amount. Native replay's own maps/indices remain priced separately.
#[derive(Clone, Copy)]
pub(crate) enum StorageStartupNamespaceRecipeV1 {
    State,
    Workspace,
    NativeIssuance,
    ExecutionOutput,
}

impl StorageStartupNamespaceRecipeV1 {
    fn namespace_entries(self, native_bytes: u64) -> Result<u64, AccountingError> {
        // Every recovered record key needs at least one real native frame.
        // The disjoint State record families and Workspace/issuance keyspaces
        // are counted once; before/after and typed/wire copies are byte costs.
        let record_keys = native_bytes / aos_sandbox_journal::framing::HEADER_BYTES as u64;
        match self {
            Self::State => add(record_keys,
                crate::catalog_transition::startup_namespace_entries_bound_v1(native_bytes)?),
            Self::Workspace | Self::NativeIssuance => Ok(record_keys),
            // Output retains its Journal and scalar byte total. The two local
            // duplicate-detection HashSets are decoder scratch, not a second
            // resident namespace; their bytes remain in the unchanged bound.
            Self::ExecutionOutput => Ok(0),
        }
    }
}

// Shared conservative upper-domain representation, independent of Native's own
// parser. Only related per-domain row cells are supplied; no model is multiplied
// per arbitrary byte. Encoded128 covers nested JSON/string/token/map carriers,
// overlapping canonical copies and Vec growth under the unchanged decoder caps.
pub(crate) fn startup_journal_model_demand_v1(
    extent: &aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1,
    row_cell_bytes: usize,
    inline_owner_bytes: usize,
    recipe: StorageStartupNamespaceRecipeV1,
) -> Result<ResourceVector, AccountingError> {
    let rows = extent.native_bytes / aos_sandbox_journal::framing::HEADER_BYTES as u64;
    let memory = add(multiply(extent.native_bytes, 128)?,
        multiply(multiply(rows, count(row_cell_bytes)?)?, 32)?)?;
    let memory = add(memory, count(inline_owner_bytes + 64 * 1024)?)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, recipe.namespace_entries(extent.native_bytes)?))
}

impl StorageInventoryGeometryV1 {
    pub(crate) fn include_journal(&mut self, journal: &aos_sandbox::Journal)
        -> Result<(), AccountingError>
    {
        for (_, key, value) in journal.all_records() {
            self.journal_rows = add(self.journal_rows, 1)?;
            self.encoded_bytes = add(self.encoded_bytes, count(key.len())?)?;
            self.encoded_bytes = add(self.encoded_bytes, count(value.len())?)?;
        }
        Ok(())
    }

    pub(crate) fn include(&mut self, other: Self) -> Result<(), AccountingError> {
        self.encoded_bytes = add(self.encoded_bytes, other.encoded_bytes)?;
        self.journal_rows = add(self.journal_rows, other.journal_rows)?;
        self.workspace_rows = add(self.workspace_rows, other.workspace_rows)?;
        self.lifecycle_rows = add(self.lifecycle_rows, other.lifecycle_rows)?;
        self.transition_rows = add(self.transition_rows, other.transition_rows)?;
        self.atomic_rows = add(self.atomic_rows, other.atomic_rows)?;
        self.repair_rows = add(self.repair_rows, other.repair_rows)?;
        self.worker_rows = add(self.worker_rows, other.worker_rows)?;
        self.namespace_entries = add(self.namespace_entries, other.namespace_entries)?;
        Ok(())
    }

    pub(crate) fn domain_demand(self) -> Result<ResourceVector, AccountingError> {
        self.retained_model_demand_v1()?
            .checked_add(crate::pin_worker_runtime::catalog_observation_receiving_demand_v1()?)
    }

    // The genuine receiving original separately pays the same fixed worker
    // peak before startup. Contacted Inventory adds these retained domain
    // models while the Runtime's actual settled observer peak is reused.
    pub(crate) fn retained_model_demand_v1(self) -> Result<ResourceVector, AccountingError> {
        // Each generated row has fixed digest/identifier payloads. Twenty bytes
        // per protobuf field covers its tag, length and full-width scalar. A
        // workspace additionally has its nested fence/descriptor and possible
        // 266-byte guest publication proof. Variable media-type/name strings
        // are bounded by the actual retained encoded source below.
        let body = add(512, multiply(self.workspace_rows, 12 * 20 + 32 + 16 + 32 + 16 + 266
            + 5 * 20 + 16 + 16 + 32 + 3 * 20 + 32)?)?;
        let body = add(body, multiply(self.lifecycle_rows, 8 * 20 + 144)?)?;
        let body = add(body, multiply(self.transition_rows, 7 * 20 + 128)?)?;
        let body = add(body, multiply(self.atomic_rows, 10 * 20 + 224)?)?;
        let body = add(body, multiply(self.repair_rows, 4 * 20 + 112)?)?;
        let body = add(body, self.encoded_bytes)?;

        let rows = [self.journal_rows, self.workspace_rows, self.lifecycle_rows,
            self.transition_rows, self.atomic_rows, self.repair_rows, self.worker_rows]
            .into_iter().try_fold(0, add)?;
        let row_cell = count(std::mem::size_of::<StorageWorkspaceInventoryRecord>()
            + std::mem::size_of::<StorageLifecycleInventoryRecord>()
            + std::mem::size_of::<StorageLifecycleTransitionRecord>()
            + std::mem::size_of::<StorageAtomicSnapshotCheckpoint>()
            + std::mem::size_of::<StorageOperatorRepairCommitRecordV1>()
            + std::mem::size_of::<crate::observation_protocol::WorkspaceCatalogObservationRootV1>()
            + std::mem::size_of::<crate::observation_protocol::WorkspaceCatalogObservationObjectV1>()
            + std::mem::size_of::<crate::observation_protocol::WorkspaceCatalogObservationTargetV1>())?;
        // The current chain rereads authenticated resolver state, projects the
        // base inventory, adds lifecycle/repair rows, and performs canonical
        // decode/encode/readback passes. Thirty-two related row carriers cover
        // Vec spare capacity and those overlapping typed/canonical copies.
        // Encoded JSON strings, parser tokens, maps and intermediate copies
        // receive a separate conservative 128x actual encoded-byte allowance.
        let memory = add(multiply(self.encoded_bytes, 128)?, multiply(rows, multiply(row_cell, 32)?)?)?;
        let memory = add(memory, multiply(body, 16)?)?;
        let memory = add(memory, count(std::mem::size_of::<InventoryStorageResourcesResponse>())?)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            // Only actual recovered map/catalog namespace entries participate.
            // Protobuf/JSON fields, typed copies, Vec growth and validation-only
            // duplicate sets remain covered by the unchanged byte bound.
            .with(D::MetadataEntries, self.namespace_entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_namespaces_follow_the_recovered_keyspace() {
        let bytes = 3 * aos_sandbox_journal::framing::HEADER_BYTES as u64;
        assert_eq!(StorageStartupNamespaceRecipeV1::Workspace.namespace_entries(bytes).unwrap(), 3);
        assert_eq!(StorageStartupNamespaceRecipeV1::NativeIssuance.namespace_entries(bytes).unwrap(), 3);
        assert_eq!(StorageStartupNamespaceRecipeV1::ExecutionOutput.namespace_entries(bytes).unwrap(), 0);
        assert_eq!(StorageStartupNamespaceRecipeV1::State.namespace_entries(0).unwrap(), 0);
    }

    #[test]
    fn inventory_namespace_count_is_independent_of_model_copies() {
        let original = StorageInventoryGeometryV1 {
            namespace_entries: 7, ..StorageInventoryGeometryV1::default()
        };
        let additional_models = StorageInventoryGeometryV1 {
            encoded_bytes: 4096, journal_rows: 12, workspace_rows: 4,
            ..original
        };
        let first = original.retained_model_demand_v1().unwrap();
        let second = additional_models.retained_model_demand_v1().unwrap();
        assert_eq!(first.get(D::MetadataEntries), 7);
        assert_eq!(second.get(D::MetadataEntries), 7);
        assert!(second.get(D::MemoryBytes) > first.get(D::MemoryBytes));
    }

    #[test]
    fn empty_catalog_still_pays_real_fixed_worker_entry() {
        let demand = StorageInventoryGeometryV1::default().domain_demand().unwrap();
        let native = crate::pin_worker_runtime::catalog_observation_receiving_demand_v1().unwrap();
        assert!(demand.get(D::MemoryBytes) >= native.get(D::MemoryBytes));
        assert_eq!(demand.get(D::OpenFiles), native.get(D::OpenFiles));
    }

    #[test]
    fn large_actual_group_projection_cannot_wrap_into_an_empty_permit() {
        let geometry = StorageInventoryGeometryV1 {
            lifecycle_rows: u64::MAX, transition_rows: u64::MAX,
            ..StorageInventoryGeometryV1::default()
        };
        assert!(matches!(geometry.domain_demand(), Err(AccountingError::ArithmeticOverflow { .. })));
    }

    #[test]
    fn partial_addition_never_returns_a_smaller_successful_geometry() {
        let mut geometry = StorageInventoryGeometryV1 {
            encoded_bytes: u64::MAX, ..StorageInventoryGeometryV1::default()
        };
        assert!(geometry.include(StorageInventoryGeometryV1 {
            encoded_bytes: 1, ..StorageInventoryGeometryV1::default()
        }).is_err());
        assert_eq!(geometry.encoded_bytes, u64::MAX);
    }
}
