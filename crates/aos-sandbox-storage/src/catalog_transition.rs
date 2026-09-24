//! Protected physical Storage catalog transitions.
//!
//! The resolved request catalog selects one fixed mutation, while this module
//! owns the canonical physical state produced by observing that mutation. The
//! physical state deliberately excludes broker-minted resource handles: those
//! handles depend on the resulting catalog binding and remain authenticated in
//! the committed operation record. Rows instead retain the creating operation
//! and observed GUID, which gives restart validation a non-circular join.
//!
//! This pre-release V1 physical snapshot encoding is a hard reset of the
//! earlier experimental shape. Decoding fails closed on those bytes, and no
//! migration is provided because that shape was never activated or shipped.

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CatalogBindingV1, CatalogObjectKind, CatalogPlanV1, DurableStoragePhase, ManagedDatasetRoot,
    ProjectAncestorPolicyV1, ReservationPolicy, ResolvedCatalogCommitmentV1, ResolvedDataset,
    ResolvedSnapshot, StorageDomainsV1, StorageStateError, WorkspaceSpacePolicyV1,
    root_policy::PortableRootAttributesV1,
    snapshot_metadata::{
        CatalogCommitSupplementV1, CheckedSnapshotMetadataRecordV1, SnapshotMetadataRecordPartsV1,
        snapshot_commit_observation_digest,
    },
};

pub(crate) mod execution_capture;
mod format;
mod provider;
mod validation;

pub(crate) use provider::StorageCatalogTransitionProvider;
use validation::normalize_and_validate;

use format::{
    decode_head_payload, decode_reservation_payload, decode_transition_payload, digest_bytes,
    encode_head_payload, encode_reservation_payload, encode_transition_payload,
    encoded_transition_size, transition_digest, transition_payload, validate_catalog_chain,
    validate_head, validate_reserved_transition_bound,
};

const STATE_MAGIC: &str = "AOSSCS01";
const RESERVATION_MAGIC: &str = "AOSSCR01";
const TRANSITION_MAGIC: &str = "AOSSCT01";
const HEAD_MAGIC: &str = "AOSSCH01";
const FORMAT_VERSION: u16 = 1;
const STORAGE_RECORD_VERSION: u16 = 1;
const STATE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-state.v1\0";
const RECORD_MAC_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-record.v1\0";
const TRANSITION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-transition.v1\0";
const HEAD_KEY: &[u8] = b"physical-head";
const MAXIMUM_STATE_BYTES: usize = 48 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const MAXIMUM_HEAD_BYTES: usize = 4 * 1024;
const MAXIMUM_OBJECTS: usize = 256;
const MAXIMUM_HOLDS: usize = 512;
const MAXIMUM_TOMBSTONES: usize = 256;
const MAXIMUM_NAME_BYTES: usize = 255;
// The synthetic transition fixes the observation digest to decimal `255`
// bytes and the captured GUID to `u64::MAX`. The result-state digest and
// envelope MAC remain data-dependent for every format; an execution Snapshot
// also derives the whole-tree metadata record and combined observation
// digests. JSON renders each byte in
// one to three decimal digits, so two extra digits per byte is a complete
// upper bound independent of their values.
const VARIABLE_TRANSITION_ARRAY_BYTES: usize = 32 + 32;
const SNAPSHOT_VARIABLE_ARRAY_BYTES: usize = 384 + 32 + 32;
const MAXIMUM_JSON_BYTE_EXPANSION: usize = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    generation: u64,
    digest: [u8; 32],
}

impl BindingWire {
    fn binding(self) -> Result<CatalogBindingV1, StorageStateError> {
        CatalogBindingV1::from_publisher(self.generation, ObjectDigest::from_bytes(self.digest))
            .map_err(|_| StorageStateError::CorruptRecord)
    }
}

impl From<CatalogBindingV1> for BindingWire {
    fn from(value: CatalogBindingV1) -> Self {
        Self {
            generation: value.generation(),
            digest: *value.digest().as_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct DomainsWire {
    disclosure: [u8; 32],
    encryption: [u8; 32],
    accounting: [u8; 32],
    retention: [u8; 32],
}

impl From<StorageDomainsV1> for DomainsWire {
    fn from(value: StorageDomainsV1) -> Self {
        Self {
            disclosure: *value.disclosure().as_bytes(),
            encryption: *value.encryption().as_bytes(),
            accounting: *value.accounting().as_bytes(),
            retention: *value.retention().as_bytes(),
        }
    }
}

fn domains_from_wire(wire: DomainsWire) -> Result<StorageDomainsV1, StorageStateError> {
    StorageDomainsV1::new(
        ObjectDigest::from_bytes(wire.disclosure),
        ObjectDigest::from_bytes(wire.encryption),
        ObjectDigest::from_bytes(wire.accounting),
        ObjectDigest::from_bytes(wire.retention),
    )
    .map_err(|_| StorageStateError::CorruptRecord)
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct RootWire {
    pool: String,
    dataset_prefix: String,
    guid: u64,
}

impl From<&ManagedDatasetRoot> for RootWire {
    fn from(value: &ManagedDatasetRoot) -> Self {
        Self {
            pool: value.pool().to_owned(),
            dataset_prefix: value.dataset_prefix().to_owned(),
            guid: value.guid(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SpaceWire {
    refquota_bytes: u64,
    reservation_bytes: Option<u64>,
}

impl From<WorkspaceSpacePolicyV1> for SpaceWire {
    fn from(value: WorkspaceSpacePolicyV1) -> Self {
        Self {
            refquota_bytes: value.refquota_bytes(),
            reservation_bytes: match value.reservation() {
                ReservationPolicy::None => None,
                ReservationPolicy::Exact(bytes) => Some(bytes),
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateWire {
    quota_bytes: u64,
    filesystem_limit: u64,
    snapshot_limit: u64,
}

impl From<&ProjectAncestorPolicyV1> for AggregateWire {
    fn from(value: &ProjectAncestorPolicyV1) -> Self {
        Self {
            quota_bytes: value.quota_bytes(),
            filesystem_limit: value.filesystem_limit(),
            snapshot_limit: value.snapshot_limit(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginWire {
    name: String,
    guid: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct DatasetWire {
    name: String,
    guid: u64,
    root: RootWire,
    domains: DomainsWire,
    space: Option<SpaceWire>,
    aggregate: Option<AggregateWire>,
    origin: Option<OriginWire>,
    created_by: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    name: String,
    guid: u64,
    source_name: String,
    source_guid: u64,
    created_by: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMetadataWireV1 {
    version: u16,
    record: Vec<u8>,
    record_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWireV1 {
    name: String,
    guid: u64,
    source_name: String,
    source_guid: u64,
    created_by: Option<[u8; 16]>,
    snapshot_metadata: Option<SnapshotMetadataWireV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct HoldWire {
    snapshot_name: String,
    snapshot_guid: u64,
    hold_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObjectKindWire {
    Dataset,
    Snapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct TombstoneWire {
    name: String,
    kind: ObjectKindWire,
    guid: u64,
    retired_by: [u8; 16],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalStateWire {
    magic: String,
    version: u16,
    generation: u64,
    predecessor_state: Option<BindingWire>,
    resolution: Option<BindingWire>,
    roots: Vec<RootWire>,
    datasets: Vec<DatasetWire>,
    snapshots: Vec<SnapshotWire>,
    holds: Vec<HoldWire>,
    tombstones: Vec<TombstoneWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalStateWireV1 {
    magic: String,
    version: u16,
    generation: u64,
    predecessor_state: Option<BindingWire>,
    resolution: Option<BindingWire>,
    roots: Vec<RootWire>,
    datasets: Vec<DatasetWire>,
    snapshots: Vec<SnapshotWireV1>,
    holds: Vec<HoldWire>,
    tombstones: Vec<TombstoneWire>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalCatalogState {
    wire: PhysicalStateWire,
    snapshot_metadata: BTreeMap<(String, u64), SnapshotMetadataWireV1>,
    bytes: Vec<u8>,
    binding: CatalogBindingV1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PhysicalWorkspaceProjection {
    Active {
        operation_id: [u8; 16],
        object_guid: u64,
    },
    Retired {
        operation_id: [u8; 16],
        object_guid: u64,
    },
}

/// Carries a physical-catalog snapshot obtained only by fresh journal recovery.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedPhysicalCatalogSnapshotV1 {
    binding: CatalogBindingV1,
    roots: Vec<ManagedDatasetRoot>,
    datasets: Vec<VerifiedPhysicalDatasetV1>,
    snapshots: Vec<VerifiedPhysicalSnapshotV1>,
    holds: Vec<(u64, [u8; 16])>,
    tombstones: Vec<(String, u64, [u8; 16])>,
    occupied_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPhysicalDatasetV1 {
    name: String,
    guid: u64,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    space: Option<(u64, Option<u64>)>,
    aggregate: Option<(u64, u64, u64)>,
    origin: Option<(String, u64)>,
    created_by: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPhysicalSnapshotV1 {
    name: String,
    guid: u64,
    source_name: String,
    source_guid: u64,
    created_by: Option<[u8; 16]>,
    metadata: Option<CheckedSnapshotMetadataRecordV1>,
}

impl VerifiedPhysicalCatalogSnapshotV1 {
    fn from_state(state: PhysicalCatalogState) -> Result<Self, StorageStateError> {
        let roots = state
            .wire
            .roots
            .iter()
            .map(|root| {
                ManagedDatasetRoot::from_catalog(&root.pool, &root.dataset_prefix, root.guid)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StorageStateError::CorruptRecord)?;
        let datasets = state
            .wire
            .datasets
            .iter()
            .map(|dataset| {
                Ok(VerifiedPhysicalDatasetV1 {
                    name: dataset.name.clone(),
                    guid: dataset.guid,
                    root: ManagedDatasetRoot::from_catalog(
                        &dataset.root.pool,
                        &dataset.root.dataset_prefix,
                        dataset.root.guid,
                    )
                    .map_err(|_| StorageStateError::CorruptRecord)?,
                    domains: domains_from_wire(dataset.domains)?,
                    space: dataset
                        .space
                        .map(|space| (space.refquota_bytes, space.reservation_bytes)),
                    aggregate: dataset.aggregate.as_ref().map(|aggregate| {
                        (
                            aggregate.quota_bytes,
                            aggregate.filesystem_limit,
                            aggregate.snapshot_limit,
                        )
                    }),
                    origin: dataset
                        .origin
                        .as_ref()
                        .map(|origin| (origin.name.clone(), origin.guid)),
                    created_by: dataset.created_by,
                })
            })
            .collect::<Result<Vec<_>, StorageStateError>>()?;
        let snapshots = state
            .wire
            .snapshots
            .iter()
            .map(|snapshot| {
                let metadata = state
                    .snapshot_metadata
                    .get(&(snapshot.name.clone(), snapshot.guid))
                    .map(|wire| {
                        validate_snapshot_metadata_wire(
                            wire,
                            snapshot.guid,
                            snapshot.source_guid,
                            None,
                        )
                    })
                    .transpose()?;
                Ok(VerifiedPhysicalSnapshotV1 {
                    name: snapshot.name.clone(),
                    guid: snapshot.guid,
                    source_name: snapshot.source_name.clone(),
                    source_guid: snapshot.source_guid,
                    created_by: snapshot.created_by,
                    metadata,
                })
            })
            .collect::<Result<Vec<_>, StorageStateError>>()?;
        let holds = state
            .wire
            .holds
            .iter()
            .map(|hold| (hold.snapshot_guid, hold.hold_id))
            .collect();
        let tombstones = state
            .wire
            .tombstones
            .iter()
            .filter(|row| row.kind == ObjectKindWire::Dataset)
            .map(|row| (row.name.clone(), row.guid, row.retired_by))
            .collect();
        let occupied_names = state
            .wire
            .datasets
            .iter()
            .map(|row| row.name.clone())
            .chain(state.wire.snapshots.iter().map(|row| row.name.clone()))
            .chain(state.wire.tombstones.iter().map(|row| row.name.clone()))
            .collect();
        Ok(Self {
            binding: state.binding,
            roots,
            datasets,
            snapshots,
            holds,
            tombstones,
            occupied_names,
        })
    }

    pub(crate) const fn binding(&self) -> CatalogBindingV1 {
        self.binding
    }

    pub(crate) fn roots(&self) -> &[ManagedDatasetRoot] {
        &self.roots
    }

    pub(crate) fn datasets(&self) -> &[VerifiedPhysicalDatasetV1] {
        &self.datasets
    }

    pub(crate) fn snapshots(&self) -> &[VerifiedPhysicalSnapshotV1] {
        &self.snapshots
    }

    pub(crate) fn holds(&self) -> &[(u64, [u8; 16])] {
        &self.holds
    }

    pub(crate) fn occupied_names(&self) -> &[String] {
        &self.occupied_names
    }

    pub(crate) fn dataset_tombstones(&self) -> &[(String, u64, [u8; 16])] {
        &self.tombstones
    }
}

impl VerifiedPhysicalDatasetV1 {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn guid(&self) -> u64 {
        self.guid
    }

    pub(crate) const fn root(&self) -> &ManagedDatasetRoot {
        &self.root
    }

    pub(crate) const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }

    pub(crate) const fn space(&self) -> Option<(u64, Option<u64>)> {
        self.space
    }

    pub(crate) const fn aggregate(&self) -> Option<(u64, u64, u64)> {
        self.aggregate
    }

    pub(crate) fn origin(&self) -> Option<(&str, u64)> {
        self.origin
            .as_ref()
            .map(|(name, guid)| (name.as_str(), *guid))
    }

    pub(crate) const fn created_by(&self) -> Option<[u8; 16]> {
        self.created_by
    }
}

impl VerifiedPhysicalSnapshotV1 {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn guid(&self) -> u64 {
        self.guid
    }

    pub(crate) fn source_name(&self) -> &str {
        &self.source_name
    }

    pub(crate) const fn source_guid(&self) -> u64 {
        self.source_guid
    }

    pub(crate) const fn created_by(&self) -> Option<[u8; 16]> {
        self.created_by
    }

    pub(crate) const fn metadata(&self) -> Option<CheckedSnapshotMetadataRecordV1> {
        self.metadata
    }
}

impl PhysicalCatalogState {
    fn bootstrap(
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<Self, StorageStateError> {
        if generation == 0 || catalogs.is_empty() {
            return Err(StorageStateError::InvalidValue);
        }
        if catalogs
            .iter()
            .any(|catalog| catalog.format_version() != FORMAT_VERSION)
        {
            return Err(StorageStateError::InvalidValue);
        }
        let mut wire = PhysicalStateWire {
            magic: STATE_MAGIC.to_owned(),
            version: FORMAT_VERSION,
            generation,
            predecessor_state: None,
            resolution: None,
            roots: Vec::new(),
            datasets: Vec::new(),
            snapshots: Vec::new(),
            holds: Vec::new(),
            tombstones: Vec::new(),
        };
        for catalog in catalogs {
            ingest_plan_inputs(&mut wire, catalog.plan(), true)?;
        }
        Self::canonicalize(wire, BTreeMap::new())
    }

    fn from_wire(wire: PhysicalStateWireV1) -> Result<Self, StorageStateError> {
        let original = wire.clone();
        let (base, metadata) = split_wire(wire)?;
        let state = Self::canonicalize(base, metadata)?;
        if state.persistent_wire()? != original {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(state)
    }

    fn canonicalize(
        mut wire: PhysicalStateWire,
        snapshot_metadata: BTreeMap<(String, u64), SnapshotMetadataWireV1>,
    ) -> Result<Self, StorageStateError> {
        normalize_and_validate(&mut wire)?;
        validate_snapshot_metadata_set(&wire, &snapshot_metadata)?;
        let bytes = serde_json::to_vec(&persistent_wire(&wire, &snapshot_metadata)?)
            .map_err(|_| StorageStateError::CorruptRecord)?;
        if bytes.len() > MAXIMUM_STATE_BYTES {
            return Err(StorageStateError::InvalidValue);
        }
        let mut hash = Sha256::new();
        hash.update(STATE_DIGEST_DOMAIN);
        hash.update(&bytes);
        let digest = ObjectDigest::from_bytes(hash.finalize().into());
        let binding = CatalogBindingV1::from_publisher(wire.generation, digest)
            .map_err(|_| StorageStateError::InvalidValue)?;
        Ok(Self {
            wire,
            snapshot_metadata,
            bytes,
            binding,
        })
    }

    fn persistent_wire(&self) -> Result<PhysicalStateWireV1, StorageStateError> {
        persistent_wire(&self.wire, &self.snapshot_metadata)
    }

    fn apply(
        &self,
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
    ) -> Result<Self, StorageStateError> {
        self.apply_with_snapshot_metadata(operation_id, catalog, object_guid, None)
    }

    fn apply_with_snapshot_metadata(
        &self,
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
    ) -> Result<Self, StorageStateError> {
        if self.binding.generation().checked_add(1) != Some(catalog.generation()) {
            return Err(StorageStateError::InvalidTransition);
        }
        if catalog.format_version() != FORMAT_VERSION {
            return Err(StorageStateError::InvalidTransition);
        }
        let mut wire = self.wire.clone();
        wire.version = FORMAT_VERSION;
        let mut metadata = self.snapshot_metadata.clone();
        ingest_plan_inputs(&mut wire, catalog.plan(), false)?;
        apply_postcondition(&mut wire, operation_id, catalog.plan(), object_guid)?;
        match (catalog.plan(), snapshot_metadata) {
            (CatalogPlanV1::Snapshot { destination, .. }, Some(metadata_record)) => {
                let guid = object_guid.ok_or(StorageStateError::InvalidValue)?;
                validate_snapshot_metadata_record(
                    metadata_record,
                    operation_id,
                    guid,
                    destination.dataset().guid(),
                    Some(destination.dataset().storage_handle()),
                )?;
                let metadata_wire = snapshot_metadata_wire(metadata_record);
                if metadata
                    .insert((destination.name().to_owned(), guid), metadata_wire)
                    .is_some()
                {
                    return Err(StorageStateError::InvalidTransition);
                }
            }
            (CatalogPlanV1::Snapshot { .. }, None) => {
                return Err(StorageStateError::InvalidValue);
            }
            (_, Some(_)) => {
                return Err(StorageStateError::InvalidValue);
            }
            _ => {}
        }
        if let CatalogPlanV1::DestroySnapshot { snapshot } = catalog.plan() {
            metadata.remove(&(snapshot.name().to_owned(), snapshot.guid()));
        }
        wire.generation = catalog
            .generation()
            .checked_add(1)
            .ok_or(StorageStateError::InvalidValue)?;
        wire.predecessor_state = Some(self.binding.into());
        wire.resolution = Some(catalog.binding().into());
        Self::canonicalize(wire, metadata)
    }

    fn apply_atomic_snapshot_group(
        &self,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        member_guids: &[u64],
    ) -> Result<Self, StorageStateError> {
        if program.format_version() != 2
            || self.binding.generation() != program.catalog_generation()
            || self.binding.digest() != program.catalog_head()
            || member_guids.len() != program.member_count()
            || member_guids.contains(&0)
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let next_generation = self
            .binding
            .generation()
            .checked_add(1)
            .ok_or(StorageStateError::InvalidTransition)?;
        let resolution = CatalogBindingV1::from_publisher(next_generation, program.commitment())
            .map_err(|_| StorageStateError::InvalidTransition)?;
        let mut wire = self.wire.clone();
        for (member, guid) in program.members().iter().zip(member_guids) {
            if !wire.datasets.iter().any(|dataset| {
                dataset.name == member.source_name() && dataset.guid == member.source_guid()
            }) || wire.snapshots.iter().any(|snapshot| {
                snapshot.name == member.destination_name() || snapshot.guid == *guid
            }) {
                return Err(StorageStateError::InvalidTransition);
            }
            wire.snapshots.push(SnapshotWire {
                name: member.destination_name().to_owned(),
                guid: *guid,
                source_name: member.source_name().to_owned(),
                source_guid: member.source_guid(),
                // Group ownership is proved by the protected atomic record;
                // the singular catalog creator index is one-to-one.
                created_by: None,
            });
        }
        wire.generation = next_generation;
        wire.predecessor_state = Some(self.binding.into());
        wire.resolution = Some(resolution.into());
        Self::canonicalize(wire, self.snapshot_metadata.clone())
    }

    pub(crate) const fn binding(&self) -> CatalogBindingV1 {
        self.binding
    }

    fn workspace_projection(&self) -> Vec<PhysicalWorkspaceProjection> {
        let mut projection = self
            .wire
            .datasets
            .iter()
            .filter_map(|dataset| {
                dataset
                    .created_by
                    .map(|operation_id| PhysicalWorkspaceProjection::Active {
                        operation_id,
                        object_guid: dataset.guid,
                    })
            })
            .chain(self.wire.tombstones.iter().filter_map(|tombstone| {
                (tombstone.kind == ObjectKindWire::Dataset).then_some(
                    PhysicalWorkspaceProjection::Retired {
                        operation_id: tombstone.retired_by,
                        object_guid: tombstone.guid,
                    },
                )
            }))
            .collect::<Vec<_>>();
        projection.sort_unstable();
        projection
    }
}

fn split_wire(
    wire: PhysicalStateWireV1,
) -> Result<
    (
        PhysicalStateWire,
        BTreeMap<(String, u64), SnapshotMetadataWireV1>,
    ),
    StorageStateError,
> {
    let mut metadata = BTreeMap::new();
    let mut snapshots = Vec::with_capacity(wire.snapshots.len());
    for snapshot in wire.snapshots {
        if let Some(snapshot_metadata) = snapshot.snapshot_metadata {
            if metadata
                .insert((snapshot.name.clone(), snapshot.guid), snapshot_metadata)
                .is_some()
            {
                return Err(StorageStateError::CorruptRecord);
            }
        }
        snapshots.push(SnapshotWire {
            name: snapshot.name,
            guid: snapshot.guid,
            source_name: snapshot.source_name,
            source_guid: snapshot.source_guid,
            created_by: snapshot.created_by,
        });
    }
    Ok((
        PhysicalStateWire {
            magic: wire.magic,
            version: wire.version,
            generation: wire.generation,
            predecessor_state: wire.predecessor_state,
            resolution: wire.resolution,
            roots: wire.roots,
            datasets: wire.datasets,
            snapshots,
            holds: wire.holds,
            tombstones: wire.tombstones,
        },
        metadata,
    ))
}

fn persistent_wire(
    wire: &PhysicalStateWire,
    metadata: &BTreeMap<(String, u64), SnapshotMetadataWireV1>,
) -> Result<PhysicalStateWireV1, StorageStateError> {
    let snapshots = wire
        .snapshots
        .iter()
        .map(|snapshot| SnapshotWireV1 {
            name: snapshot.name.clone(),
            guid: snapshot.guid,
            source_name: snapshot.source_name.clone(),
            source_guid: snapshot.source_guid,
            created_by: snapshot.created_by,
            snapshot_metadata: metadata
                .get(&(snapshot.name.clone(), snapshot.guid))
                .cloned(),
        })
        .collect();
    Ok(PhysicalStateWireV1 {
        magic: wire.magic.clone(),
        version: wire.version,
        generation: wire.generation,
        predecessor_state: wire.predecessor_state,
        resolution: wire.resolution,
        roots: wire.roots.clone(),
        datasets: wire.datasets.clone(),
        snapshots,
        holds: wire.holds.clone(),
        tombstones: wire.tombstones.clone(),
    })
}

fn validate_snapshot_metadata_set(
    wire: &PhysicalStateWire,
    metadata: &BTreeMap<(String, u64), SnapshotMetadataWireV1>,
) -> Result<(), StorageStateError> {
    for snapshot in &wire.snapshots {
        let metadata_wire = metadata.get(&(snapshot.name.clone(), snapshot.guid));
        match (snapshot.created_by, metadata_wire) {
            (Some(operation_id), Some(metadata_wire)) => {
                let record = validate_snapshot_metadata_wire(
                    metadata_wire,
                    snapshot.guid,
                    snapshot.source_guid,
                    None,
                )?;
                if record.operation_id() != operation_id {
                    return Err(StorageStateError::CorruptRecord);
                }
            }
            (None, None) => {}
            _ => return Err(StorageStateError::CorruptRecord),
        }
    }
    Ok(())
}

fn validate_snapshot_metadata_wire(
    wire: &SnapshotMetadataWireV1,
    snapshot_guid: u64,
    dataset_guid: u64,
    storage_handle: Option<[u8; 32]>,
) -> Result<CheckedSnapshotMetadataRecordV1, StorageStateError> {
    if wire.version != 1 || wire.record.len() != 384 {
        return Err(StorageStateError::CorruptRecord);
    }
    let record = CheckedSnapshotMetadataRecordV1::from_canonical_bytes(&wire.record)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    if record.record_digest().as_bytes() != &wire.record_digest
        || record.snapshot_guid() != snapshot_guid
        || record.source_dataset_guid() != dataset_guid
        || storage_handle.is_some_and(|handle| record.source_storage_handle() != handle)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(record)
}

fn validate_snapshot_metadata_record(
    record: CheckedSnapshotMetadataRecordV1,
    operation_id: [u8; 16],
    snapshot_guid: u64,
    source_dataset_guid: u64,
    source_storage_handle: Option<[u8; 32]>,
) -> Result<(), StorageStateError> {
    if record.operation_id() != operation_id
        || record.snapshot_guid() != snapshot_guid
        || record.source_dataset_guid() != source_dataset_guid
        || source_storage_handle.is_some_and(|handle| record.source_storage_handle() != handle)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

fn snapshot_metadata_wire(record: CheckedSnapshotMetadataRecordV1) -> SnapshotMetadataWireV1 {
    SnapshotMetadataWireV1 {
        version: 1,
        record: record.canonical_bytes().to_vec(),
        record_digest: *record.record_digest().as_bytes(),
    }
}

#[allow(clippy::too_many_arguments)]
fn maximum_snapshot_metadata_record(
    operation_id: [u8; 16],
    request_digest: ObjectDigest,
    mutation_digest: ObjectDigest,
    catalog: &ResolvedCatalogCommitmentV1,
    snapshot_guid: u64,
    zfs_observation_digest: ObjectDigest,
) -> Result<Option<CheckedSnapshotMetadataRecordV1>, StorageStateError> {
    let CatalogPlanV1::Snapshot { source, .. } = catalog.plan() else {
        return Ok(None);
    };
    CheckedSnapshotMetadataRecordV1::new(SnapshotMetadataRecordPartsV1 {
        operation_id,
        request_digest,
        mutation_digest,
        request_catalog: catalog.binding(),
        snapshot_guid,
        source_dataset_guid: source.guid(),
        source_storage_handle: source.storage_handle(),
        source_creation_operation_id: [u8::MAX; 16],
        source_publication_record_digest: ObjectDigest::from_bytes([u8::MAX; 32]),
        source_pin_attempt_id: [u8::MAX; 16],
        source_pin_record_digest: ObjectDigest::from_bytes([u8::MAX; 32]),
        zfs_observation_digest,
        root_attributes: PortableRootAttributesV1::new(u32::MAX - 1, u32::MAX - 1, 0o7777)
            .map_err(|_| StorageStateError::InvalidValue)?,
        maximum_portable_uid: u32::MAX - 1,
        maximum_portable_gid: u32::MAX - 1,
        distinct_inode_count: u64::MAX,
        directory_entry_count: u64::MAX,
        identity_tree_digest: ObjectDigest::from_bytes([u8::MAX; 32]),
    })
    .map(Some)
    .map_err(|_| StorageStateError::InvalidValue)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationPayloadV1 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    catalog_bytes_digest: [u8; 32],
    predecessor: BindingWire,
    predecessor_state: PhysicalStateWireV1,
    maximum_transition_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GroupReservationPayloadV2 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    catalog_bytes_digest: [u8; 32],
    predecessor: BindingWire,
    predecessor_state: PhysicalStateWireV1,
    maximum_transition_bytes: u32,
    group_program: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionPayloadV1 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    predecessor: BindingWire,
    result: BindingWire,
    observation_digest: [u8; 32],
    object_guid: Option<u64>,
    result_state: PhysicalStateWireV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GroupTransitionPayloadV2 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    predecessor: BindingWire,
    result: BindingWire,
    observation_digest: [u8; 32],
    group_program: [u8; 32],
    member_guids: Vec<u64>,
    result_state: PhysicalStateWireV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadPayloadV1 {
    magic: String,
    version: u16,
    binding: BindingWire,
    operation_id: Option<[u8; 16]>,
    transition_digest: Option<[u8; 32]>,
    genesis_state: Option<PhysicalStateWireV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReservationPayload {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    catalog_bytes_digest: [u8; 32],
    predecessor: BindingWire,
    maximum_transition_bytes: u32,
    group_program: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupTransitionEvidence {
    program: [u8; 32],
    member_guids: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransitionPayload {
    operation_id: [u8; 16],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    predecessor: BindingWire,
    result: BindingWire,
    observation_digest: [u8; 32],
    object_guid: Option<u64>,
    group: Option<GroupTransitionEvidence>,
    result_state: PhysicalCatalogState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeadPayload {
    binding: BindingWire,
    operation_id: Option<[u8; 16]>,
    transition_digest: Option<[u8; 32]>,
    genesis_state: Option<PhysicalCatalogState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedRecord<T> {
    payload: T,
    key_id: [u8; 16],
    mac: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct CatalogReservation {
    payload: ReservationPayload,
    bytes: Vec<u8>,
    predecessor: PhysicalCatalogState,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedCatalogTransition {
    operation_id: [u8; 16],
    snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
    transition: TransitionPayload,
    transition_bytes: Vec<u8>,
    head_bytes: Vec<u8>,
    result_state: PhysicalCatalogState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CatalogTransitionEvidence {
    pub(crate) result_catalog: CatalogBindingV1,
    pub(crate) observation_digest: ObjectDigest,
    pub(crate) object_guid: Option<u64>,
    pub(crate) snapshot_metadata: Option<CheckedSnapshotMetadataRecordV1>,
}

pub(crate) struct PreparedCatalogBootstrap {
    head_bytes: Vec<u8>,
    state: PhysicalCatalogState,
}

impl PreparedCatalogBootstrap {
    pub(crate) const fn binding(&self) -> CatalogBindingV1 {
        self.state.binding()
    }

    pub(crate) fn record(&self) -> JournalRecord {
        JournalRecord::put(
            RecordNamespace::StorageCatalogHead,
            HEAD_KEY.to_vec(),
            self.head_bytes.clone(),
        )
    }
}

impl PreparedCatalogTransition {
    pub(crate) const fn result_binding(&self) -> CatalogBindingV1 {
        self.result_state.binding()
    }

    pub(crate) const fn observation_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.transition.observation_digest)
    }

    pub(crate) const fn snapshot_metadata(&self) -> Option<CheckedSnapshotMetadataRecordV1> {
        self.snapshot_metadata
    }

    pub(crate) fn records(&self) -> Vec<JournalRecord> {
        vec![
            JournalRecord::put(
                RecordNamespace::StorageCatalogTransition,
                self.operation_id.to_vec(),
                self.transition_bytes.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::StorageCatalogHead,
                HEAD_KEY.to_vec(),
                self.head_bytes.clone(),
            ),
        ]
    }
}

fn capture_guid(plan: &CatalogPlanV1) -> bool {
    !matches!(
        plan,
        CatalogPlanV1::DestroyDataset { .. } | CatalogPlanV1::DestroySnapshot { .. }
    )
}

fn ingest_plan_inputs(
    state: &mut PhysicalStateWire,
    plan: &CatalogPlanV1,
    allow_seed: bool,
) -> Result<(), StorageStateError> {
    let root = match plan {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination.root(),
        CatalogPlanV1::Snapshot { source, .. } => source.root(),
        CatalogPlanV1::HoldSnapshot { snapshot, .. }
        | CatalogPlanV1::ReleaseHold { snapshot, .. }
        | CatalogPlanV1::DestroySnapshot { snapshot } => snapshot.dataset().root(),
        CatalogPlanV1::SetQuota { dataset, .. } | CatalogPlanV1::DestroyDataset { dataset } => {
            dataset.root()
        }
    };
    ensure_root(state, root, allow_seed)?;

    match plan {
        CatalogPlanV1::CreateWorkspace {
            destination,
            ancestor,
            ..
        } => {
            ensure_dataset(state, ancestor.dataset(), allow_seed)?;
            require_available_name(state, destination.name())?;
        }
        CatalogPlanV1::Snapshot {
            source,
            destination,
        } => {
            ensure_dataset(state, source, allow_seed)?;
            require_available_name(state, destination.name())?;
        }
        CatalogPlanV1::HoldSnapshot { snapshot, .. }
        | CatalogPlanV1::DestroySnapshot { snapshot } => {
            ensure_dataset(state, snapshot.dataset(), allow_seed)?;
            ensure_snapshot(state, snapshot, allow_seed)?;
        }
        CatalogPlanV1::ReleaseHold { snapshot, hold_id } => {
            ensure_dataset(state, snapshot.dataset(), allow_seed)?;
            ensure_snapshot(state, snapshot, allow_seed)?;
            ensure_hold(state, snapshot, hold_id.as_bytes(), allow_seed)?;
        }
        CatalogPlanV1::Clone {
            source,
            origin_hold,
            destination,
            ancestor,
            ..
        } => {
            ensure_dataset(state, source.dataset(), allow_seed)?;
            ensure_snapshot(state, source, allow_seed)?;
            ensure_hold(state, source, origin_hold.hold_id().as_bytes(), allow_seed)?;
            ensure_dataset(state, ancestor.dataset(), allow_seed)?;
            require_available_name(state, destination.name())?;
        }
        CatalogPlanV1::SetQuota {
            dataset, ancestor, ..
        } => {
            ensure_dataset(state, dataset, allow_seed)?;
            ensure_dataset(state, ancestor.dataset(), allow_seed)?;
        }
        CatalogPlanV1::DestroyDataset { dataset } => {
            ensure_dataset(state, dataset, allow_seed)?;
        }
    }
    Ok(())
}

fn apply_postcondition(
    state: &mut PhysicalStateWire,
    operation_id: [u8; 16],
    plan: &CatalogPlanV1,
    object_guid: Option<u64>,
) -> Result<(), StorageStateError> {
    match plan {
        CatalogPlanV1::CreateWorkspace {
            destination,
            space,
            ancestor,
        } => {
            insert_created_dataset(
                state,
                operation_id,
                destination.name(),
                object_guid.ok_or(StorageStateError::InvalidValue)?,
                destination.root(),
                destination.domains(),
                *space,
                None,
            )?;
            set_aggregate(state, ancestor)?;
        }
        CatalogPlanV1::Snapshot {
            source,
            destination,
        } => state.snapshots.push(SnapshotWire {
            name: destination.name().to_owned(),
            guid: object_guid.ok_or(StorageStateError::InvalidValue)?,
            source_name: source.name().to_owned(),
            source_guid: source.guid(),
            created_by: Some(operation_id),
        }),
        CatalogPlanV1::HoldSnapshot { snapshot, hold_id } => {
            state.holds.push(HoldWire {
                snapshot_name: snapshot.name().to_owned(),
                snapshot_guid: snapshot.guid(),
                hold_id: hold_id.as_bytes(),
            });
        }
        CatalogPlanV1::ReleaseHold { snapshot, hold_id } => {
            let before = state.holds.len();
            state.holds.retain(|hold| {
                hold.snapshot_name != snapshot.name() || hold.hold_id != hold_id.as_bytes()
            });
            if state.holds.len() == before {
                return Err(StorageStateError::InvalidTransition);
            }
        }
        CatalogPlanV1::Clone {
            source,
            destination,
            space,
            ancestor,
            ..
        } => {
            insert_created_dataset(
                state,
                operation_id,
                destination.name(),
                object_guid.ok_or(StorageStateError::InvalidValue)?,
                destination.root(),
                destination.domains(),
                *space,
                Some(OriginWire {
                    name: source.name().to_owned(),
                    guid: source.guid(),
                }),
            )?;
            set_aggregate(state, ancestor)?;
        }
        CatalogPlanV1::SetQuota {
            dataset,
            space,
            ancestor,
        } => {
            let row = dataset_mut(state, dataset.name(), dataset.guid())?;
            row.space = Some((*space).into());
            set_aggregate(state, ancestor)?;
        }
        CatalogPlanV1::DestroyDataset { dataset } => {
            if state
                .snapshots
                .iter()
                .any(|snapshot| snapshot.source_name == dataset.name())
            {
                return Err(StorageStateError::InvalidTransition);
            }
            remove_dataset(state, operation_id, dataset)?;
        }
        CatalogPlanV1::DestroySnapshot { snapshot } => {
            if state.holds.iter().any(|hold| {
                hold.snapshot_name == snapshot.name() && hold.snapshot_guid == snapshot.guid()
            }) {
                return Err(StorageStateError::InvalidTransition);
            }
            remove_snapshot(state, operation_id, snapshot)?;
        }
    }
    Ok(())
}

fn ensure_root(
    state: &mut PhysicalStateWire,
    root: &ManagedDatasetRoot,
    allow_seed: bool,
) -> Result<(), StorageStateError> {
    let expected = RootWire::from(root);
    match state
        .roots
        .iter()
        .find(|candidate| candidate.dataset_prefix == expected.dataset_prefix)
    {
        Some(candidate) if candidate == &expected => Ok(()),
        Some(_) => Err(StorageStateError::InvalidTransition),
        None if allow_seed => {
            state.roots.push(expected);
            Ok(())
        }
        None => Err(StorageStateError::InvalidTransition),
    }
}

fn ensure_dataset(
    state: &mut PhysicalStateWire,
    dataset: &ResolvedDataset,
    allow_seed: bool,
) -> Result<(), StorageStateError> {
    match state
        .datasets
        .iter()
        .find(|candidate| candidate.name == dataset.name())
    {
        Some(candidate)
            if candidate.guid == dataset.guid()
                && candidate.root == RootWire::from(dataset.root())
                && candidate.domains == dataset.domains().into() =>
        {
            Ok(())
        }
        Some(_) => Err(StorageStateError::InvalidTransition),
        None if allow_seed => {
            state.datasets.push(DatasetWire {
                name: dataset.name().to_owned(),
                guid: dataset.guid(),
                root: dataset.root().into(),
                domains: dataset.domains().into(),
                space: None,
                aggregate: None,
                origin: None,
                created_by: None,
            });
            Ok(())
        }
        None => Err(StorageStateError::InvalidTransition),
    }
}

fn ensure_snapshot(
    state: &mut PhysicalStateWire,
    snapshot: &ResolvedSnapshot,
    allow_seed: bool,
) -> Result<(), StorageStateError> {
    match state
        .snapshots
        .iter()
        .find(|candidate| candidate.name == snapshot.name())
    {
        Some(candidate)
            if candidate.guid == snapshot.guid()
                && candidate.source_name == snapshot.dataset().name()
                && candidate.source_guid == snapshot.dataset().guid() =>
        {
            Ok(())
        }
        Some(_) => Err(StorageStateError::InvalidTransition),
        None if allow_seed => {
            state.snapshots.push(SnapshotWire {
                name: snapshot.name().to_owned(),
                guid: snapshot.guid(),
                source_name: snapshot.dataset().name().to_owned(),
                source_guid: snapshot.dataset().guid(),
                created_by: None,
            });
            Ok(())
        }
        None => Err(StorageStateError::InvalidTransition),
    }
}

fn ensure_hold(
    state: &mut PhysicalStateWire,
    snapshot: &ResolvedSnapshot,
    hold_id: [u8; 16],
    allow_seed: bool,
) -> Result<(), StorageStateError> {
    let expected = HoldWire {
        snapshot_name: snapshot.name().to_owned(),
        snapshot_guid: snapshot.guid(),
        hold_id,
    };
    if state.holds.contains(&expected) {
        Ok(())
    } else if allow_seed {
        state.holds.push(expected);
        Ok(())
    } else {
        Err(StorageStateError::InvalidTransition)
    }
}

fn require_available_name(state: &PhysicalStateWire, name: &str) -> Result<(), StorageStateError> {
    if state.datasets.iter().any(|row| row.name == name)
        || state.snapshots.iter().any(|row| row.name == name)
        || state.tombstones.iter().any(|row| row.name == name)
    {
        Err(StorageStateError::InvalidTransition)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_created_dataset(
    state: &mut PhysicalStateWire,
    operation_id: [u8; 16],
    name: &str,
    guid: u64,
    root: &ManagedDatasetRoot,
    domains: StorageDomainsV1,
    space: WorkspaceSpacePolicyV1,
    origin: Option<OriginWire>,
) -> Result<(), StorageStateError> {
    require_available_name(state, name)?;
    state.datasets.push(DatasetWire {
        name: name.to_owned(),
        guid,
        root: root.into(),
        domains: domains.into(),
        space: Some(space.into()),
        aggregate: None,
        origin,
        created_by: Some(operation_id),
    });
    Ok(())
}

fn set_aggregate(
    state: &mut PhysicalStateWire,
    ancestor: &ProjectAncestorPolicyV1,
) -> Result<(), StorageStateError> {
    let row = dataset_mut(state, ancestor.dataset().name(), ancestor.dataset().guid())?;
    row.aggregate = Some(ancestor.into());
    Ok(())
}

fn dataset_mut<'a>(
    state: &'a mut PhysicalStateWire,
    name: &str,
    guid: u64,
) -> Result<&'a mut DatasetWire, StorageStateError> {
    state
        .datasets
        .iter_mut()
        .find(|row| row.name == name && row.guid == guid)
        .ok_or(StorageStateError::InvalidTransition)
}

fn remove_dataset(
    state: &mut PhysicalStateWire,
    operation_id: [u8; 16],
    dataset: &ResolvedDataset,
) -> Result<(), StorageStateError> {
    let before = state.datasets.len();
    state
        .datasets
        .retain(|row| row.name != dataset.name() || row.guid != dataset.guid());
    if state.datasets.len() == before {
        return Err(StorageStateError::InvalidTransition);
    }
    state.tombstones.push(TombstoneWire {
        name: dataset.name().to_owned(),
        kind: ObjectKindWire::Dataset,
        guid: dataset.guid(),
        retired_by: operation_id,
    });
    Ok(())
}

fn remove_snapshot(
    state: &mut PhysicalStateWire,
    operation_id: [u8; 16],
    snapshot: &ResolvedSnapshot,
) -> Result<(), StorageStateError> {
    let before = state.snapshots.len();
    state
        .snapshots
        .retain(|row| row.name != snapshot.name() || row.guid != snapshot.guid());
    if state.snapshots.len() == before {
        return Err(StorageStateError::InvalidTransition);
    }
    state.tombstones.push(TombstoneWire {
        name: snapshot.name().to_owned(),
        kind: ObjectKindWire::Snapshot,
        guid: snapshot.guid(),
        retired_by: operation_id,
    });
    Ok(())
}

impl From<CatalogObjectKind> for ObjectKindWire {
    fn from(value: CatalogObjectKind) -> Self {
        match value {
            CatalogObjectKind::Dataset => Self::Dataset,
            CatalogObjectKind::Snapshot => Self::Snapshot,
        }
    }
}

#[cfg(test)]
mod tests;
