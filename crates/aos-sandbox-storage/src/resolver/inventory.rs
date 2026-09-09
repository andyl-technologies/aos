//! Canonical protected inventory consumed by Storage catalog resolution.
//!
//! The format is an internal, bounded snapshot rather than a portable wire
//! contract. Callers must obtain it from authenticated protected state. A
//! snapshot may carry a separately authenticated root-metadata record; legacy
//! snapshots remain inventory-readable but cannot be clone sources.
//!
//! ```text
//! snapshot-root-record-v1 =
//!   magic || version || reserved || snapshot-guid || dataset-guid ||
//!   uid || gid || mode || reserved || storage-handle || version-handle ||
//!   immutable-content-commitment
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::semantics::CatalogBindingV1;
use sha2::{Digest as _, Sha256};

use crate::root_policy::{
    PortableRootAttributesV1, WorkspaceRootPolicyError, WorkspaceRootPolicyV1,
    snapshot_root_metadata_commitment,
};
use crate::{
    ActiveHoldEvidence, HoldId, ManagedDatasetRoot, ResolvedDataset, ResolvedSnapshot,
    StorageDomainsV1, state::VerifiedStorageResolverJournalV2,
};

use super::policy::ProtectedStorageResolverPolicyV1;

const RECORD_MAGIC: &[u8; 8] = b"AOSSRM01";
const RECORD_VERSION: u16 = 1;
const RECORD_BYTES: usize = 136;
const RECORD_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.snapshot-root-record.v1\0";
const INVENTORY_MAGIC: &[u8; 8] = b"AOSSRI02";
const INVENTORY_VERSION: u16 = 2;
const INVENTORY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.resolver-inventory.v2\0";
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
    /// A legacy snapshot lacks authenticated root metadata required for Clone.
    #[error("source snapshot has no authenticated root metadata")]
    LegacySnapshotMetadata,
}

impl From<WorkspaceRootPolicyError> for ProtectedStorageInventoryError {
    fn from(_: WorkspaceRootPolicyError) -> Self {
        Self::InvalidRootMetadata
    }
}

/// Stores one canonically checked rich snapshot-root record.
///
/// This value proves only canonical field consistency. It becomes trusted
/// resolver input only after the enclosing physical-catalog record has passed
/// protected journal authentication and full chain validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckedSnapshotRootMetadataRecordV1 {
    snapshot_guid: u64,
    dataset_guid: u64,
    root_attributes: PortableRootAttributesV1,
    storage_handle: [u8; 32],
    version_handle: [u8; 32],
    content_commitment: ObjectDigest,
}

impl CheckedSnapshotRootMetadataRecordV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        snapshot_guid: u64,
        dataset_guid: u64,
        root_attributes: PortableRootAttributesV1,
        storage_handle: [u8; 32],
        version_handle: [u8; 32],
        content_commitment: ObjectDigest,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        if snapshot_guid == 0
            || dataset_guid == 0
            || storage_handle == [0; 32]
            || version_handle == [0; 32]
            || content_commitment.as_bytes() == &[0; 32]
        {
            return Err(ProtectedStorageInventoryError::InvalidRootMetadata);
        }

        Ok(Self {
            snapshot_guid,
            dataset_guid,
            root_attributes,
            storage_handle,
            version_handle,
            content_commitment,
        })
    }

    pub(crate) fn canonical_bytes(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.snapshot_guid.to_be_bytes());
        bytes[20..28].copy_from_slice(&self.dataset_guid.to_be_bytes());
        bytes[28..32].copy_from_slice(&self.root_attributes.uid().to_be_bytes());
        bytes[32..36].copy_from_slice(&self.root_attributes.gid().to_be_bytes());
        bytes[36..38].copy_from_slice(&self.root_attributes.mode().to_be_bytes());
        bytes[40..72].copy_from_slice(&self.storage_handle);
        bytes[72..104].copy_from_slice(&self.version_handle);
        bytes[104..136].copy_from_slice(self.content_commitment.as_bytes());
        bytes
    }

    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, ProtectedStorageInventoryError> {
        if bytes.len() != RECORD_BYTES
            || &bytes[..8] != RECORD_MAGIC
            || bytes[10..12] != [0, 0]
            || bytes[38..40] != [0, 0]
        {
            return Err(ProtectedStorageInventoryError::InvalidRootMetadata);
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != RECORD_VERSION {
            return Err(ProtectedStorageInventoryError::InvalidRootMetadata);
        }

        let record = Self::new(
            u64::from_be_bytes(array(bytes, 12)?),
            u64::from_be_bytes(array(bytes, 20)?),
            PortableRootAttributesV1::new(
                u32::from_be_bytes(array(bytes, 28)?),
                u32::from_be_bytes(array(bytes, 32)?),
                u32::from(u16::from_be_bytes(array(bytes, 36)?)),
            )?,
            array(bytes, 40)?,
            array(bytes, 72)?,
            ObjectDigest::from_bytes(array(bytes, 104)?),
        )?;
        if record.canonical_bytes() != bytes {
            return Err(ProtectedStorageInventoryError::InvalidRootMetadata);
        }
        Ok(record)
    }

    pub(crate) fn record_digest(self) -> ObjectDigest {
        digest(RECORD_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    pub(crate) const fn snapshot_guid(self) -> u64 {
        self.snapshot_guid
    }

    pub(crate) const fn dataset_guid(self) -> u64 {
        self.dataset_guid
    }

    pub(crate) const fn root_attributes(self) -> PortableRootAttributesV1 {
        self.root_attributes
    }

    pub(crate) const fn storage_handle(self) -> [u8; 32] {
        self.storage_handle
    }

    pub(crate) const fn version_handle(self) -> [u8; 32] {
        self.version_handle
    }

    pub(crate) const fn content_commitment(self) -> ObjectDigest {
        self.content_commitment
    }
}

/// Proves that protected state authenticated one exact rich metadata record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedSnapshotRootMetadataV1 {
    record: CheckedSnapshotRootMetadataRecordV1,
    record_digest: ObjectDigest,
}

impl AuthenticatedSnapshotRootMetadataV1 {
    fn from_verified_journal_record(record: CheckedSnapshotRootMetadataRecordV1) -> Self {
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
        let record = CheckedSnapshotRootMetadataRecordV1::from_canonical_bytes(bytes)?;
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

    pub(crate) const fn record(self) -> CheckedSnapshotRootMetadataRecordV1 {
        self.record
    }

    pub(crate) const fn record_digest(self) -> ObjectDigest {
        self.record_digest
    }
}

/// Associates one immutable snapshot with optional authenticated root metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedSnapshotInventoryV2 {
    snapshot: ResolvedSnapshot,
    content_commitment: Option<ObjectDigest>,
    root_metadata: Option<AuthenticatedSnapshotRootMetadataV1>,
}

impl ProtectedSnapshotInventoryV2 {
    pub(crate) fn legacy(snapshot: ResolvedSnapshot) -> Self {
        Self {
            snapshot,
            content_commitment: None,
            root_metadata: None,
        }
    }

    #[cfg(test)]
    pub(super) fn authenticated_for_test(
        snapshot: ResolvedSnapshot,
        content_commitment: ObjectDigest,
        root_metadata: AuthenticatedSnapshotRootMetadataV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        Self::authenticated_row(snapshot, content_commitment, root_metadata)
    }

    fn from_verified_journal_record(
        snapshot: ResolvedSnapshot,
        root_metadata: CheckedSnapshotRootMetadataRecordV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let metadata =
            AuthenticatedSnapshotRootMetadataV1::from_verified_journal_record(root_metadata);
        Self::authenticated_row(snapshot, root_metadata.content_commitment(), metadata)
    }

    fn authenticated_row(
        snapshot: ResolvedSnapshot,
        content_commitment: ObjectDigest,
        root_metadata: AuthenticatedSnapshotRootMetadataV1,
    ) -> Result<Self, ProtectedStorageInventoryError> {
        let record = root_metadata.record();
        if content_commitment.as_bytes() == &[0; 32]
            || record.snapshot_guid != snapshot.guid()
            || record.dataset_guid != snapshot.dataset().guid()
            || record.storage_handle != snapshot.dataset().storage_handle()
            || record.version_handle != snapshot.version_handle()
            || record.content_commitment != content_commitment
        {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }
        Ok(Self {
            snapshot,
            content_commitment: Some(content_commitment),
            root_metadata: Some(root_metadata),
        })
    }

    pub(crate) const fn snapshot(&self) -> &ResolvedSnapshot {
        &self.snapshot
    }

    pub(crate) fn clone_root_policy(
        &self,
    ) -> Result<WorkspaceRootPolicyV1, ProtectedStorageInventoryError> {
        let metadata = self
            .root_metadata
            .ok_or(ProtectedStorageInventoryError::LegacySnapshotMetadata)?;
        let record = metadata.record();
        if self.content_commitment != Some(record.content_commitment) {
            return Err(ProtectedStorageInventoryError::InconsistentInventory);
        }
        let compact =
            snapshot_root_metadata_commitment(record.snapshot_guid, record.root_attributes)?;
        WorkspaceRootPolicyV1::clone_preserve(record.snapshot_guid, record.root_attributes, compact)
            .map_err(Into::into)
    }
}

/// Carries one canonical, bounded snapshot of already-authenticated local state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedStorageInventoryV2 {
    binding: CatalogBindingV1,
    catalog_head: CatalogBindingV1,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    datasets: BTreeMap<[u8; 32], ResolvedDataset>,
    snapshots: BTreeMap<([u8; 32], [u8; 32]), ProtectedSnapshotInventoryV2>,
    holds: BTreeSet<(u64, [u8; 16])>,
    occupied_names: BTreeSet<String>,
    bytes: Vec<u8>,
}

impl ProtectedStorageInventoryV2 {
    pub(crate) fn from_verified_journal(
        source: VerifiedStorageResolverJournalV2,
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
            let protected = match row.root_metadata() {
                Some(metadata) => {
                    ProtectedSnapshotInventoryV2::from_verified_journal_record(snapshot, metadata)?
                }
                None => ProtectedSnapshotInventoryV2::legacy(snapshot),
            };
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
        snapshots: Vec<ProtectedSnapshotInventoryV2>,
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
        snapshots: Vec<ProtectedSnapshotInventoryV2>,
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
    ) -> Option<&ProtectedSnapshotInventoryV2> {
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
    snapshots: &BTreeMap<([u8; 32], [u8; 32]), ProtectedSnapshotInventoryV2>,
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
        match (row.content_commitment, row.root_metadata) {
            (None, None) => encoder.fixed(&[0])?,
            (Some(content), Some(metadata)) => {
                encoder.fixed(&[1])?;
                encoder.fixed(content.as_bytes())?;
                encoder.fixed(metadata.record_digest().as_bytes())?;
                encoder.fixed(&metadata.record().canonical_bytes())?;
            }
            _ => return Err(ProtectedStorageInventoryError::InconsistentInventory),
        }
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

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProtectedStorageInventoryError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProtectedStorageInventoryError::InvalidRootMetadata)
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
