//! Canonical protected inventory consumed by Storage catalog resolution.
//!
//! The format is an internal, bounded snapshot rather than a portable wire
//! contract. Callers must obtain it from authenticated protected state. Every
//! snapshot carries a separately authenticated root-metadata record.
//!
//! ```text
//! snapshot-metadata-record-v1 = canonical AOSSMT01 bytes
//!
//! resolver-inventory-v1 =
//!   magic || version || generation || catalog-head || managed-root || domains ||
//!   dataset-count || dataset-rows || snapshot-count || snapshot-rows ||
//!   hold-count || hold-rows || occupied-name-count || occupied-names
//! dataset-row = storage-handle || name || dataset-guid
//! snapshot-row = storage-handle || version-handle || name || snapshot-guid ||
//!   metadata-record-digest || snapshot-metadata-record-v1
//! hold-row = snapshot-guid || hold-id
//! catalog-head = generation || digest
//! managed-root = pool || dataset-prefix || root-guid
//! domains = disclosure || encryption || accounting || retention
//! name = length:u16 || utf8
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

use crate::clone_identity::CloneIdentityRequirementV1;
use crate::root_policy::{WorkspaceRootPolicyError, WorkspaceRootPolicyV1};
use crate::snapshot_metadata::{CheckedSnapshotMetadataRecordV1, SnapshotMetadataError};
use crate::{
    ActiveHoldEvidence, HoldId, ManagedDatasetRoot, ResolvedDataset, ResolvedSnapshot,
    StorageDomainsV1, state::VerifiedStorageResolverJournalV1,
};

use super::policy::ProtectedStorageResolverPolicyV1;

const INVENTORY_MAGIC: &[u8; 8] = b"AOSSRI01";
const INVENTORY_VERSION: u16 = 1;
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.resolver-inventory.v1\0";
const MAXIMUM_OBJECTS: usize = 256;
const MAXIMUM_HOLDS: usize = 512;
const MAXIMUM_TOMBSTONES: usize = 256;
const MAXIMUM_INVENTORY_BYTES: usize = 64 * 1024;

/// Reports malformed, conflicting, or incomplete protected resolver inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProtectedStorageInventoryError {
    /// A protected snapshot-root record has invalid framing or field values.
    #[error("protected snapshot-root metadata record is malformed")]
    InvalidRootMetadata,
    /// A protected snapshot-root record digest does not authenticate its bytes.
    #[error("protected snapshot-root metadata record authentication failed")]
    RootMetadataAuthentication,
    /// Inventory rows are duplicated, inconsistent, dangling, or out of bounds.
    #[error("protected Storage resolver inventory is inconsistent")]
    InconsistentInventory,
    /// The canonical inventory exceeds its fixed size ceiling.
    #[error("protected Storage resolver inventory exceeds its byte ceiling")]
    InventoryTooLarge,
}

impl From<WorkspaceRootPolicyError> for ProtectedStorageInventoryError {
    fn from(_: WorkspaceRootPolicyError) -> Self {
        Self::InvalidRootMetadata
    }
}

impl From<SnapshotMetadataError> for ProtectedStorageInventoryError {
    fn from(_: SnapshotMetadataError) -> Self {
        Self::InvalidRootMetadata
    }
}

/// Proves that protected state authenticated one exact rich metadata record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedSnapshotMetadataV1 {
    record: CheckedSnapshotMetadataRecordV1,
    record_digest: ObjectDigest,
}

impl AuthenticatedSnapshotMetadataV1 {
    fn from_verified_journal_record(record: CheckedSnapshotMetadataRecordV1) -> Self {
        Self {
            record,
            record_digest: record.record_digest(),
        }
    }

    #[cfg(test)]
    pub(super) fn authenticate_for_test(
        bytes: &[u8],
        expected_record_digest: ObjectDigest,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let record = CheckedSnapshotMetadataRecordV1::from_canonical_bytes(bytes)?;
        let record_digest = record.record_digest();
        if expected_record_digest.as_bytes() == &[0; 32] || record_digest != expected_record_digest
        {
            return Err(ProtectedStorageInventoryError::RootMetadataAuthentication);
        }
        Ok(Self {
            record,
            record_digest,
        })
    }

    pub(crate) const fn record(self) -> CheckedSnapshotMetadataRecordV1 {
        self.record
    }

    pub(crate) const fn record_digest(self) -> ObjectDigest {
        self.record_digest
    }
}

/// Associates one immutable snapshot with authenticated root metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedSnapshotInventoryV1 {
    snapshot: ResolvedSnapshot,
    metadata: AuthenticatedSnapshotMetadataV1,
}

impl ProtectedSnapshotInventoryV1 {
    #[cfg(test)]
    pub(super) fn authenticated_for_test(
        snapshot: ResolvedSnapshot,
        metadata: AuthenticatedSnapshotMetadataV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        Self::authenticated_row(snapshot, metadata)
    }

    fn from_verified_journal_record(
        snapshot: ResolvedSnapshot,
        metadata: CheckedSnapshotMetadataRecordV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let metadata = AuthenticatedSnapshotMetadataV1::from_verified_journal_record(metadata);
        Self::authenticated_row(snapshot, metadata)
    }

    fn authenticated_row(
        snapshot: ResolvedSnapshot,
        metadata: AuthenticatedSnapshotMetadataV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let record = metadata.record();
        if record.snapshot_guid() != snapshot.guid()
            || record.source_dataset_guid() != snapshot.dataset().guid()
            || record.source_storage_handle() != snapshot.dataset().storage_handle()
        {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }
        Ok(Self { snapshot, metadata })
    }

    pub(crate) const fn snapshot(&self) -> &ResolvedSnapshot {
        &self.snapshot
    }

    pub(crate) fn clone_identity_policy(
        &self,
    ) -> Result<(WorkspaceRootPolicyV1, CloneIdentityRequirementV1), ProtectedStorageInventoryError>
    {
        let metadata = self.metadata;
        let record = metadata.record();
        if metadata.record_digest() != record.record_digest() {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }
        let root_policy = WorkspaceRootPolicyV1::clone_preserve(
            record.snapshot_guid(),
            record.root_attributes(),
            record.record_digest(),
        )?;
        let requirement = CloneIdentityRequirementV1::from_snapshot_metadata(&record);
        requirement
            .validate_source_metadata(&record)
            .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)?;
        Ok((root_policy, requirement))
    }
}

/// Carries one canonical, bounded snapshot of already-authenticated local state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedStorageInventoryV1 {
    binding: CatalogBindingV1,
    catalog_head: CatalogBindingV1,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    datasets: BTreeMap<[u8; 32], ResolvedDataset>,
    snapshots: BTreeMap<([u8; 32], [u8; 32]), ProtectedSnapshotInventoryV1>,
    holds: BTreeSet<(u64, [u8; 16])>,
    occupied_names: BTreeSet<String>,
    bytes: Vec<u8>,
}

impl ProtectedStorageInventoryV1 {
    pub(crate) fn from_verified_journal(
        source: VerifiedStorageResolverJournalV1,
        policy: &ProtectedStorageResolverPolicyV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let physical = source.physical();
        if !physical.roots().contains(&policy.root().clone()) {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }

        let ancestor = policy.project_ancestor().dataset().clone();
        let ancestor_is_present = physical.datasets().iter().any(|row| {
            row.name() == ancestor.name()
                && row.guid() == ancestor.guid()
                && row.root() == ancestor.root()
                && row.domains() == ancestor.domains()
                && row.created_by().is_none()
        });
        if !ancestor_is_present {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }

        let mut all_datasets = vec![ancestor];
        for row in physical.datasets() {
            let Some(operation_id) = row.created_by() else {
                continue;
            };
            let operation = source
                .operation(&operation_id)
                .ok_or(ProtectedStorageInventoryError::InconsistentInventory)?;
            let destination = match operation.catalog().plan() {
                crate::CatalogPlanV1::CreateWorkspace { destination, .. }
                | crate::CatalogPlanV1::Clone { destination, .. } => destination,
                _ => return Err(ProtectedStorageInventoryError::InconsistentInventory),
            };
            let result = operation.result();
            let storage_handle = result
                .storage_handle()
                .ok_or(ProtectedStorageInventoryError::InconsistentInventory)?;
            if row.name() != destination.name()
                || row.guid() != result.object_guid().unwrap_or(0)
                || row.root() != destination.root()
                || row.domains() != destination.domains()
                || result.immutable_version_handle().is_some()
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
            all_datasets.push(
                ResolvedDataset::from_catalog(
                    row.root().clone(),
                    row.name(),
                    row.guid(),
                    storage_handle,
                    row.domains(),
                )
                .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)?,
            );
        }

        let datasets_by_identity = all_datasets
            .iter()
            .map(|dataset| ((dataset.name().to_owned(), dataset.guid()), dataset.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut snapshots = Vec::new();
        for row in physical.snapshots() {
            let Some(operation_id) = row.created_by() else {
                continue;
            };
            let operation = source
                .operation(&operation_id)
                .ok_or(ProtectedStorageInventoryError::InconsistentInventory)?;
            let crate::CatalogPlanV1::Snapshot {
                source: planned_source,
                destination,
            } = operation.catalog().plan()
            else {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            };
            let dataset = match datasets_by_identity
                .get(&(row.source_name().to_owned(), row.source_guid()))
            {
                Some(dataset) => dataset.clone(),
                None => {
                    let bootstrap_source = physical.datasets().iter().find(|dataset| {
                        dataset.name() == row.source_name()
                            && dataset.guid() == row.source_guid()
                            && dataset.created_by().is_none()
                    });
                    let Some(bootstrap_source) = bootstrap_source else {
                        return Err(ProtectedStorageInventoryError::InconsistentInventory);
                    };
                    if !bootstrap_source_matches_plan(
                        bootstrap_source.name(),
                        bootstrap_source.guid(),
                        bootstrap_source.root(),
                        bootstrap_source.domains(),
                        planned_source,
                    ) {
                        return Err(ProtectedStorageInventoryError::InconsistentInventory);
                    }
                    planned_source.clone()
                }
            };
            let result = operation.result();
            let version_handle = result
                .immutable_version_handle()
                .ok_or(ProtectedStorageInventoryError::InconsistentInventory)?;
            if &dataset != planned_source
                || row.name() != destination.name()
                || row.guid() != result.object_guid().unwrap_or(0)
                || result.storage_handle() != Some(dataset.storage_handle())
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
            let snapshot = ResolvedSnapshot::from_catalog(
                dataset.clone(),
                destination.component(),
                row.guid(),
                version_handle,
            )
            .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)?;
            let metadata = row
                .metadata()
                .ok_or(ProtectedStorageInventoryError::InconsistentInventory)?;
            if metadata.operation_id() != operation_id
                || metadata.request_catalog() != operation.catalog().binding()
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
            let protected =
                ProtectedSnapshotInventoryV1::from_verified_journal_record(snapshot, metadata)?;
            if dataset.root() == policy.root() && dataset.domains() == policy.domains() {
                snapshots.push(protected);
            }
        }

        let selected_snapshot_guids = snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot().guid())
            .collect::<BTreeSet<_>>();
        let holds = physical
            .holds()
            .iter()
            .filter(|(snapshot_guid, _)| selected_snapshot_guids.contains(snapshot_guid))
            .map(|(snapshot_guid, hold_id)| {
                ActiveHoldEvidence::from_catalog(
                    *snapshot_guid,
                    HoldId::from_bytes(*hold_id)
                        .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)?,
                )
                .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let datasets = all_datasets
            .into_iter()
            .filter(|dataset| {
                dataset.root() == policy.root() && dataset.domains() == policy.domains()
            })
            .collect::<Vec<_>>();
        let resolved_names = datasets
            .iter()
            .map(|dataset| dataset.name().to_owned())
            .chain(
                snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot().name().to_owned()),
            )
            .collect::<BTreeSet<_>>();
        let occupied_only = physical
            .occupied_names()
            .iter()
            .filter(|name| !resolved_names.contains(*name))
            .cloned()
            .collect();
        Self::from_rows(
            physical.binding().generation(),
            Some(physical.binding()),
            physical.binding(),
            policy.root().clone(),
            policy.domains(),
            datasets,
            snapshots,
            holds,
            occupied_only,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(super) fn from_authenticated_rows_for_test(
        generation: u64,
        catalog_head: CatalogBindingV1,
        root: ManagedDatasetRoot,
        domains: StorageDomainsV1,
        datasets: Vec<ResolvedDataset>,
        snapshots: Vec<ProtectedSnapshotInventoryV1>,
        holds: Vec<ActiveHoldEvidence>,
        tombstone_names: Vec<String>,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        Self::from_rows(
            generation,
            None,
            catalog_head,
            root,
            domains,
            datasets,
            snapshots,
            holds,
            tombstone_names,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_rows(
        generation: u64,
        trusted_binding: Option<CatalogBindingV1>,
        catalog_head: CatalogBindingV1,
        root: ManagedDatasetRoot,
        domains: StorageDomainsV1,
        datasets: Vec<ResolvedDataset>,
        snapshots: Vec<ProtectedSnapshotInventoryV1>,
        holds: Vec<ActiveHoldEvidence>,
        tombstone_names: Vec<String>,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        if generation == 0
            || datasets.len() > MAXIMUM_OBJECTS
            || snapshots.len() > MAXIMUM_OBJECTS
            || holds.len() > MAXIMUM_HOLDS
            || tombstone_names.len() > MAXIMUM_TOMBSTONES
        {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }

        let mut dataset_rows = BTreeMap::new();
        let mut dataset_names = BTreeSet::new();
        let mut dataset_guids = BTreeSet::new();
        for dataset in datasets {
            if dataset.root() != &root
                || dataset.domains() != domains
                || !dataset_names.insert(dataset.name().to_owned())
                || !dataset_guids.insert(dataset.guid())
                || dataset_rows
                    .insert(dataset.storage_handle(), dataset)
                    .is_some()
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
        }

        let mut snapshot_rows = BTreeMap::new();
        let mut snapshot_names = BTreeSet::new();
        let mut snapshot_guids = BTreeSet::new();
        for row in snapshots {
            let snapshot = row.snapshot();
            if dataset_rows.get(&snapshot.dataset().storage_handle()) != Some(snapshot.dataset())
                || !snapshot_names.insert(snapshot.name().to_owned())
                || !snapshot_guids.insert(snapshot.guid())
                || snapshot_rows
                    .insert(
                        (
                            snapshot.dataset().storage_handle(),
                            snapshot.version_handle(),
                        ),
                        row,
                    )
                    .is_some()
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
        }

        let mut hold_rows = BTreeSet::new();
        for hold in holds {
            if !snapshot_guids.contains(&hold.snapshot_guid())
                || !hold_rows.insert((hold.snapshot_guid(), hold.hold_id().as_bytes()))
            {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
        }

        let mut occupied_names = dataset_names;
        occupied_names.extend(snapshot_names);
        for name in tombstone_names {
            if name.is_empty() || name.len() > 255 || !occupied_names.insert(name) {
                return Err(ProtectedStorageInventoryError::InconsistentInventory);
            }
        }

        let bytes = encode_inventory(
            generation,
            catalog_head,
            &root,
            domains,
            &dataset_rows,
            &snapshot_rows,
            &hold_rows,
            &occupied_names,
        )?;
        let binding = match trusted_binding {
            Some(binding) if binding.generation() == generation => binding,
            Some(_) => return Err(ProtectedStorageInventoryError::InconsistentInventory),
            None => {
                let inventory_digest = digest(INVENTORY_DIGEST_DOMAIN, &bytes);
                CatalogBindingV1::from_publisher(generation, inventory_digest)
                    .map_err(|_| ProtectedStorageInventoryError::InconsistentInventory)?
            }
        };
        Ok(Self {
            binding,
            catalog_head,
            root,
            domains,
            datasets: dataset_rows,
            snapshots: snapshot_rows,
            holds: hold_rows,
            occupied_names,
            bytes,
        })
    }

    pub(crate) const fn binding(&self) -> CatalogBindingV1 {
        self.binding
    }

    pub(crate) const fn catalog_head(&self) -> CatalogBindingV1 {
        self.catalog_head
    }

    pub(crate) const fn root(&self) -> &ManagedDatasetRoot {
        &self.root
    }

    pub(crate) const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }

    pub(crate) fn dataset(&self, storage_handle: &[u8; 32]) -> Option<&ResolvedDataset> {
        self.datasets.get(storage_handle)
    }

    pub(crate) fn snapshot(
        &self,
        storage_handle: &[u8; 32],
        version_handle: &[u8; 32],
    ) -> Option<&ProtectedSnapshotInventoryV1> {
        self.snapshots.get(&(*storage_handle, *version_handle))
    }

    pub(crate) fn has_hold(&self, snapshot_guid: u64, hold_id: HoldId) -> bool {
        self.holds.contains(&(snapshot_guid, hold_id.as_bytes()))
    }

    pub(crate) fn snapshot_has_holds(&self, snapshot_guid: u64) -> bool {
        self.holds
            .range((snapshot_guid, [0; 16])..=(snapshot_guid, [u8::MAX; 16]))
            .next()
            .is_some()
    }

    pub(crate) fn dataset_has_snapshots(&self, storage_handle: &[u8; 32]) -> bool {
        self.snapshots
            .keys()
            .any(|(candidate, _)| candidate == storage_handle)
    }

    pub(crate) fn name_is_occupied(&self, name: &str) -> bool {
        self.occupied_names.contains(name)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn bootstrap_source_matches_plan(
    bootstrap_name: &str,
    bootstrap_guid: u64,
    bootstrap_root: &ManagedDatasetRoot,
    bootstrap_domains: StorageDomainsV1,
    planned: &ResolvedDataset,
) -> bool {
    bootstrap_name == planned.name()
        && bootstrap_guid == planned.guid()
        && bootstrap_root == planned.root()
        && bootstrap_domains == planned.domains()
}

#[allow(clippy::too_many_arguments)]
fn encode_inventory(
    generation: u64,
    catalog_head: CatalogBindingV1,
    root: &ManagedDatasetRoot,
    domains: StorageDomainsV1,
    datasets: &BTreeMap<[u8; 32], ResolvedDataset>,
    snapshots: &BTreeMap<([u8; 32], [u8; 32]), ProtectedSnapshotInventoryV1>,
    holds: &BTreeSet<(u64, [u8; 16])>,
    occupied_names: &BTreeSet<String>,
) -> Result<Vec<u8>, ProtectedStorageInventoryError> {
    let mut encoder = Encoder::new();
    encoder.fixed(INVENTORY_MAGIC)?;
    encoder.fixed(&INVENTORY_VERSION.to_be_bytes())?;
    encoder.fixed(&generation.to_be_bytes())?;
    encoder.binding(catalog_head)?;
    encoder.variable(root.pool().as_bytes())?;
    encoder.variable(root.dataset_prefix().as_bytes())?;
    encoder.fixed(&root.guid().to_be_bytes())?;
    for domain in [
        domains.disclosure(),
        domains.encryption(),
        domains.accounting(),
        domains.retention(),
    ] {
        encoder.fixed(domain.as_bytes())?;
    }
    encoder.count(datasets.len())?;
    for (handle, dataset) in datasets {
        encoder.fixed(handle)?;
        encoder.variable(dataset.name().as_bytes())?;
        encoder.fixed(&dataset.guid().to_be_bytes())?;
    }
    encoder.count(snapshots.len())?;
    for ((storage_handle, version_handle), row) in snapshots {
        encoder.fixed(storage_handle)?;
        encoder.fixed(version_handle)?;
        encoder.variable(row.snapshot().name().as_bytes())?;
        encoder.fixed(&row.snapshot().guid().to_be_bytes())?;
        encoder.fixed(row.metadata.record_digest().as_bytes())?;
        encoder.fixed(&row.metadata.record().canonical_bytes())?;
    }
    encoder.count(holds.len())?;
    for (snapshot_guid, hold_id) in holds {
        encoder.fixed(&snapshot_guid.to_be_bytes())?;
        encoder.fixed(hold_id)?;
    }
    encoder.count(occupied_names.len())?;
    for name in occupied_names {
        encoder.variable(name.as_bytes())?;
    }
    Ok(encoder.finish())
}

fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4096),
        }
    }

    fn fixed(&mut self, bytes: &[u8]) -> Result<(), ProtectedStorageInventoryError> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= MAXIMUM_INVENTORY_BYTES)
            .ok_or(ProtectedStorageInventoryError::InventoryTooLarge)?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn variable(&mut self, bytes: &[u8]) -> Result<(), ProtectedStorageInventoryError> {
        let length = u16::try_from(bytes.len())
            .map_err(|_| ProtectedStorageInventoryError::InventoryTooLarge)?;
        self.fixed(&length.to_be_bytes())?;
        self.fixed(bytes)
    }

    fn binding(&mut self, binding: CatalogBindingV1) -> Result<(), ProtectedStorageInventoryError> {
        self.fixed(&binding.generation().to_be_bytes())?;
        self.fixed(binding.digest().as_bytes())
    }

    fn count(&mut self, count: usize) -> Result<(), ProtectedStorageInventoryError> {
        let count =
            u16::try_from(count).map_err(|_| ProtectedStorageInventoryError::InventoryTooLarge)?;
        self.fixed(&count.to_be_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn domains(byte: u8) -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([byte; 32]),
            ObjectDigest::from_bytes([byte + 1; 32]),
            ObjectDigest::from_bytes([byte + 2; 32]),
            ObjectDigest::from_bytes([byte + 3; 32]),
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_snapshot_source_requires_full_planned_dataset_identity() {
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 11).unwrap();
        let planned = ResolvedDataset::from_catalog(
            root.clone(),
            "tank/aos/project",
            12,
            [13; 32],
            domains(14),
        )
        .unwrap();

        assert!(bootstrap_source_matches_plan(
            planned.name(),
            planned.guid(),
            planned.root(),
            planned.domains(),
            &planned,
        ));
        assert!(!bootstrap_source_matches_plan(
            "tank/aos/sibling",
            planned.guid(),
            planned.root(),
            planned.domains(),
            &planned,
        ));
        assert!(!bootstrap_source_matches_plan(
            planned.name(),
            planned.guid() + 1,
            planned.root(),
            planned.domains(),
            &planned,
        ));
        let other_root = ManagedDatasetRoot::from_catalog("tank", "tank/other", 15).unwrap();
        assert!(!bootstrap_source_matches_plan(
            planned.name(),
            planned.guid(),
            &other_root,
            planned.domains(),
            &planned,
        ));
        assert!(!bootstrap_source_matches_plan(
            planned.name(),
            planned.guid(),
            planned.root(),
            domains(16),
            &planned,
        ));
    }
}
