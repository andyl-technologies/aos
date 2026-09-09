//! Protected physical Storage catalog transitions.
//!
//! The resolved request catalog selects one fixed mutation, while this module
//! owns the canonical physical state produced by observing that mutation. The
//! physical state deliberately excludes broker-minted resource handles: those
//! handles depend on the resulting catalog binding and remain authenticated in
//! the committed operation record. Rows instead retain the creating operation
//! and observed GUID, which gives restart validation a non-circular join.

use std::collections::BTreeMap;

use aos_sandbox::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CatalogBindingV1, CatalogObjectKind, CatalogPlanV1, DurableStoragePhase, ManagedDatasetRoot,
    ProjectAncestorPolicyV1, ReservationPolicy, ResolvedCatalogCommitmentV1, ResolvedDataset,
    ResolvedSnapshot, StorageDomainsV1, StorageStateError, WorkspaceSpacePolicyV1,
    resolver::inventory::CheckedSnapshotRootMetadataRecordV1,
    root_policy::PortableRootAttributesV1,
};

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
const LEGACY_FORMAT_VERSION: u16 = 1;
const EXECUTION_FORMAT_VERSION: u16 = 2;
const STORAGE_RECORD_LEGACY_VERSION: u16 = 2;
const STORAGE_RECORD_IDENTITY_VERSION: u16 = 3;
const STORAGE_RECORD_TRANSITION_VERSION: u16 = 4;
const STATE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-state.v1\0";
const EXECUTION_STATE_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-state.v2\0";
const RECORD_MAC_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-record.v1\0";
const TRANSITION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-transition.v1\0";
const EXECUTION_TRANSITION_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.catalog-transition.v2\0";
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
// also derives the rich root-metadata record digest. JSON renders each byte in
// one to three decimal digits, so two extra digits per byte is a complete
// upper bound independent of their values.
const VARIABLE_TRANSITION_ARRAY_BYTES: usize = 32 + 32;
const EXECUTION_SNAPSHOT_VARIABLE_ARRAY_BYTES: usize = 32;
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
struct SnapshotRootMetadataWireV1 {
    version: u16,
    record: Vec<u8>,
    record_digest: [u8; 32],
    content_commitment: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWireV2 {
    name: String,
    guid: u64,
    source_name: String,
    source_guid: u64,
    created_by: Option<[u8; 16]>,
    root_metadata: Option<SnapshotRootMetadataWireV1>,
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
struct PhysicalStateWireV2 {
    magic: String,
    version: u16,
    generation: u64,
    predecessor_state: Option<BindingWire>,
    resolution: Option<BindingWire>,
    roots: Vec<RootWire>,
    datasets: Vec<DatasetWire>,
    snapshots: Vec<SnapshotWireV2>,
    holds: Vec<HoldWire>,
    tombstones: Vec<TombstoneWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PhysicalStateEnvelopeV2 {
    version: u16,
    legacy_v1: Option<PhysicalStateWire>,
    execution_v2: Option<PhysicalStateWireV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhysicalStateFormatV1 {
    LegacyV1,
    ExecutionV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalCatalogState {
    format: PhysicalStateFormatV1,
    wire: PhysicalStateWire,
    snapshot_root_metadata: BTreeMap<(String, u64), SnapshotRootMetadataWireV1>,
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
pub(crate) struct VerifiedPhysicalCatalogSnapshotV2 {
    binding: CatalogBindingV1,
    roots: Vec<ManagedDatasetRoot>,
    datasets: Vec<VerifiedPhysicalDatasetV1>,
    snapshots: Vec<VerifiedPhysicalSnapshotV2>,
    holds: Vec<(u64, [u8; 16])>,
    occupied_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPhysicalDatasetV1 {
    name: String,
    guid: u64,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    created_by: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPhysicalSnapshotV2 {
    name: String,
    guid: u64,
    source_name: String,
    source_guid: u64,
    created_by: Option<[u8; 16]>,
    root_metadata: Option<CheckedSnapshotRootMetadataRecordV1>,
}

impl VerifiedPhysicalCatalogSnapshotV2 {
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
                    created_by: dataset.created_by,
                })
            })
            .collect::<Result<Vec<_>, StorageStateError>>()?;
        let snapshots = state
            .wire
            .snapshots
            .iter()
            .map(|snapshot| {
                let root_metadata = state
                    .snapshot_root_metadata
                    .get(&(snapshot.name.clone(), snapshot.guid))
                    .map(|wire| {
                        validate_snapshot_root_metadata_wire(
                            wire,
                            snapshot.guid,
                            snapshot.source_guid,
                            None,
                            None,
                        )
                    })
                    .transpose()?;
                Ok(VerifiedPhysicalSnapshotV2 {
                    name: snapshot.name.clone(),
                    guid: snapshot.guid,
                    source_name: snapshot.source_name.clone(),
                    source_guid: snapshot.source_guid,
                    created_by: snapshot.created_by,
                    root_metadata,
                })
            })
            .collect::<Result<Vec<_>, StorageStateError>>()?;
        let holds = state
            .wire
            .holds
            .iter()
            .map(|hold| (hold.snapshot_guid, hold.hold_id))
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

    pub(crate) fn snapshots(&self) -> &[VerifiedPhysicalSnapshotV2] {
        &self.snapshots
    }

    pub(crate) fn holds(&self) -> &[(u64, [u8; 16])] {
        &self.holds
    }

    pub(crate) fn occupied_names(&self) -> &[String] {
        &self.occupied_names
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

    pub(crate) const fn created_by(&self) -> Option<[u8; 16]> {
        self.created_by
    }
}

impl VerifiedPhysicalSnapshotV2 {
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

    pub(crate) const fn root_metadata(&self) -> Option<CheckedSnapshotRootMetadataRecordV1> {
        self.root_metadata
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
        let format = if catalogs.iter().all(|catalog| catalog.format_version() == 2) {
            PhysicalStateFormatV1::LegacyV1
        } else if catalogs.iter().all(|catalog| catalog.format_version() == 3) {
            PhysicalStateFormatV1::ExecutionV2
        } else {
            return Err(StorageStateError::InvalidValue);
        };
        let mut wire = PhysicalStateWire {
            magic: STATE_MAGIC.to_owned(),
            version: match format {
                PhysicalStateFormatV1::LegacyV1 => LEGACY_FORMAT_VERSION,
                PhysicalStateFormatV1::ExecutionV2 => EXECUTION_FORMAT_VERSION,
            },
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
        Self::canonicalize(format, wire, BTreeMap::new())
    }

    fn from_legacy_wire(wire: PhysicalStateWire) -> Result<Self, StorageStateError> {
        let original = wire.clone();
        let state = Self::canonicalize(PhysicalStateFormatV1::LegacyV1, wire, BTreeMap::new())?;
        if state.wire != original {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(state)
    }

    fn from_execution_wire(wire: PhysicalStateWireV2) -> Result<Self, StorageStateError> {
        let original = wire.clone();
        let (base, metadata) = split_execution_wire(wire)?;
        let state = Self::canonicalize(PhysicalStateFormatV1::ExecutionV2, base, metadata)?;
        if state.execution_wire()? != original {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(state)
    }

    fn from_envelope(envelope: PhysicalStateEnvelopeV2) -> Result<Self, StorageStateError> {
        if envelope.version != 1 {
            return Err(StorageStateError::CorruptRecord);
        }
        match (envelope.legacy_v1, envelope.execution_v2) {
            (Some(wire), None) => Self::from_legacy_wire(wire),
            (None, Some(wire)) => Self::from_execution_wire(wire),
            _ => Err(StorageStateError::CorruptRecord),
        }
    }

    fn envelope(&self) -> Result<PhysicalStateEnvelopeV2, StorageStateError> {
        match self.format {
            PhysicalStateFormatV1::LegacyV1 => Ok(PhysicalStateEnvelopeV2 {
                version: 1,
                legacy_v1: Some(self.wire.clone()),
                execution_v2: None,
            }),
            PhysicalStateFormatV1::ExecutionV2 => Ok(PhysicalStateEnvelopeV2 {
                version: 1,
                legacy_v1: None,
                execution_v2: Some(self.execution_wire()?),
            }),
        }
    }

    fn canonicalize(
        format: PhysicalStateFormatV1,
        mut wire: PhysicalStateWire,
        snapshot_root_metadata: BTreeMap<(String, u64), SnapshotRootMetadataWireV1>,
    ) -> Result<Self, StorageStateError> {
        normalize_and_validate(&mut wire, format)?;
        validate_snapshot_root_metadata_set(&wire, &snapshot_root_metadata)?;
        let bytes = match format {
            PhysicalStateFormatV1::LegacyV1 if snapshot_root_metadata.is_empty() => {
                serde_json::to_vec(&wire).map_err(|_| StorageStateError::CorruptRecord)?
            }
            PhysicalStateFormatV1::LegacyV1 => return Err(StorageStateError::CorruptRecord),
            PhysicalStateFormatV1::ExecutionV2 => {
                serde_json::to_vec(&execution_wire(&wire, &snapshot_root_metadata)?)
                    .map_err(|_| StorageStateError::CorruptRecord)?
            }
        };
        if bytes.len() > MAXIMUM_STATE_BYTES {
            return Err(StorageStateError::InvalidValue);
        }
        let mut hash = Sha256::new();
        hash.update(match format {
            PhysicalStateFormatV1::LegacyV1 => STATE_DIGEST_DOMAIN,
            PhysicalStateFormatV1::ExecutionV2 => EXECUTION_STATE_DIGEST_DOMAIN,
        });
        hash.update(&bytes);
        let digest = ObjectDigest::from_bytes(hash.finalize().into());
        let binding = CatalogBindingV1::from_publisher(wire.generation, digest)
            .map_err(|_| StorageStateError::InvalidValue)?;
        Ok(Self {
            format,
            wire,
            snapshot_root_metadata,
            bytes,
            binding,
        })
    }

    fn execution_wire(&self) -> Result<PhysicalStateWireV2, StorageStateError> {
        if self.format != PhysicalStateFormatV1::ExecutionV2 {
            return Err(StorageStateError::InvalidTransition);
        }
        execution_wire(&self.wire, &self.snapshot_root_metadata)
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
        snapshot_root_metadata: Option<SnapshotRootMetadataWireV1>,
    ) -> Result<Self, StorageStateError> {
        if self.binding.generation().checked_add(1) != Some(catalog.generation()) {
            return Err(StorageStateError::InvalidTransition);
        }
        let format = match (self.format, catalog.format_version()) {
            (PhysicalStateFormatV1::LegacyV1, 2) => PhysicalStateFormatV1::LegacyV1,
            (PhysicalStateFormatV1::LegacyV1 | PhysicalStateFormatV1::ExecutionV2, 3) => {
                PhysicalStateFormatV1::ExecutionV2
            }
            (PhysicalStateFormatV1::ExecutionV2, 2) => {
                return Err(StorageStateError::InvalidTransition);
            }
            _ => return Err(StorageStateError::InvalidTransition),
        };
        let mut wire = self.wire.clone();
        wire.version = match format {
            PhysicalStateFormatV1::LegacyV1 => LEGACY_FORMAT_VERSION,
            PhysicalStateFormatV1::ExecutionV2 => EXECUTION_FORMAT_VERSION,
        };
        let mut metadata = self.snapshot_root_metadata.clone();
        ingest_plan_inputs(&mut wire, catalog.plan(), false)?;
        apply_postcondition(&mut wire, operation_id, catalog.plan(), object_guid)?;
        match (catalog.plan(), snapshot_root_metadata) {
            (CatalogPlanV1::Snapshot { destination, .. }, Some(metadata_wire))
                if format == PhysicalStateFormatV1::ExecutionV2 =>
            {
                let guid = object_guid.ok_or(StorageStateError::InvalidValue)?;
                validate_snapshot_root_metadata_wire(
                    &metadata_wire,
                    guid,
                    destination.dataset().guid(),
                    Some(destination.dataset().storage_handle()),
                    None,
                )?;
                if metadata
                    .insert((destination.name().to_owned(), guid), metadata_wire)
                    .is_some()
                {
                    return Err(StorageStateError::InvalidTransition);
                }
            }
            (CatalogPlanV1::Snapshot { .. }, None)
                if format == PhysicalStateFormatV1::ExecutionV2 =>
            {
                return Err(StorageStateError::InvalidValue);
            }
            (CatalogPlanV1::Snapshot { .. }, Some(_)) | (_, Some(_)) => {
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
        Self::canonicalize(format, wire, metadata)
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

fn split_execution_wire(
    wire: PhysicalStateWireV2,
) -> Result<
    (
        PhysicalStateWire,
        BTreeMap<(String, u64), SnapshotRootMetadataWireV1>,
    ),
    StorageStateError,
> {
    let mut metadata = BTreeMap::new();
    let mut snapshots = Vec::with_capacity(wire.snapshots.len());
    for snapshot in wire.snapshots {
        if let Some(root_metadata) = snapshot.root_metadata {
            if metadata
                .insert((snapshot.name.clone(), snapshot.guid), root_metadata)
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

fn execution_wire(
    wire: &PhysicalStateWire,
    metadata: &BTreeMap<(String, u64), SnapshotRootMetadataWireV1>,
) -> Result<PhysicalStateWireV2, StorageStateError> {
    let snapshots = wire
        .snapshots
        .iter()
        .map(|snapshot| SnapshotWireV2 {
            name: snapshot.name.clone(),
            guid: snapshot.guid,
            source_name: snapshot.source_name.clone(),
            source_guid: snapshot.source_guid,
            created_by: snapshot.created_by,
            root_metadata: metadata
                .get(&(snapshot.name.clone(), snapshot.guid))
                .cloned(),
        })
        .collect();
    Ok(PhysicalStateWireV2 {
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

fn validate_snapshot_root_metadata_set(
    wire: &PhysicalStateWire,
    metadata: &BTreeMap<(String, u64), SnapshotRootMetadataWireV1>,
) -> Result<(), StorageStateError> {
    for ((name, guid), metadata_wire) in metadata {
        let snapshot = wire
            .snapshots
            .iter()
            .find(|snapshot| snapshot.name == *name && snapshot.guid == *guid)
            .ok_or(StorageStateError::CorruptRecord)?;
        validate_snapshot_root_metadata_wire(
            metadata_wire,
            snapshot.guid,
            snapshot.source_guid,
            None,
            None,
        )?;
    }
    Ok(())
}

fn validate_snapshot_root_metadata_wire(
    wire: &SnapshotRootMetadataWireV1,
    snapshot_guid: u64,
    dataset_guid: u64,
    storage_handle: Option<[u8; 32]>,
    version_handle: Option<[u8; 32]>,
) -> Result<CheckedSnapshotRootMetadataRecordV1, StorageStateError> {
    if wire.version != 1 || wire.record.len() != 136 {
        return Err(StorageStateError::CorruptRecord);
    }
    let record = CheckedSnapshotRootMetadataRecordV1::from_canonical_bytes(&wire.record)
        .map_err(|_| StorageStateError::CorruptRecord)?;
    if record.record_digest().as_bytes() != &wire.record_digest
        || record.content_commitment().as_bytes() != &wire.content_commitment
        || record.snapshot_guid() != snapshot_guid
        || record.dataset_guid() != dataset_guid
        || storage_handle.is_some_and(|handle| record.storage_handle() != handle)
        || version_handle.is_some_and(|handle| record.version_handle() != handle)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(record)
}

fn maximum_snapshot_root_metadata_wire(
    catalog: &ResolvedCatalogCommitmentV1,
    snapshot_guid: u64,
) -> Result<Option<SnapshotRootMetadataWireV1>, StorageStateError> {
    if catalog.format_version() != 3 {
        return Ok(None);
    }
    let CatalogPlanV1::Snapshot { destination, .. } = catalog.plan() else {
        return Ok(None);
    };
    let record = CheckedSnapshotRootMetadataRecordV1::new(
        snapshot_guid,
        destination.dataset().guid(),
        PortableRootAttributesV1::new(u32::MAX - 1, u32::MAX - 1, 0o7777)
            .map_err(|_| StorageStateError::InvalidValue)?,
        destination.dataset().storage_handle(),
        [u8::MAX; 32],
        ObjectDigest::from_bytes([u8::MAX; 32]),
    )
    .map_err(|_| StorageStateError::InvalidValue)?;
    Ok(Some(SnapshotRootMetadataWireV1 {
        version: 1,
        record: record.canonical_bytes().to_vec(),
        record_digest: *record.record_digest().as_bytes(),
        content_commitment: *record.content_commitment().as_bytes(),
    }))
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
    predecessor_state: PhysicalStateWire,
    maximum_transition_bytes: u32,
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
    result_state: PhysicalStateWire,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadPayloadV1 {
    magic: String,
    version: u16,
    binding: BindingWire,
    operation_id: Option<[u8; 16]>,
    transition_digest: Option<[u8; 32]>,
    genesis_state: Option<PhysicalStateWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationPayloadV2 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    catalog_bytes_digest: [u8; 32],
    predecessor: BindingWire,
    predecessor_state: PhysicalStateEnvelopeV2,
    maximum_transition_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionPayloadV2 {
    magic: String,
    version: u16,
    operation_id: [u8; 16],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    predecessor: BindingWire,
    result: BindingWire,
    observation_digest: [u8; 32],
    object_guid: Option<u64>,
    result_state: PhysicalStateWireV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadPayloadV2 {
    magic: String,
    version: u16,
    binding: BindingWire,
    operation_id: Option<[u8; 16]>,
    transition_digest: Option<[u8; 32]>,
    genesis_state: Option<PhysicalStateEnvelopeV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogRecordFormatV1 {
    LegacyV1,
    ExecutionV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReservationPayload {
    format: CatalogRecordFormatV1,
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    catalog_bytes_digest: [u8; 32],
    predecessor: BindingWire,
    maximum_transition_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransitionPayload {
    format: CatalogRecordFormatV1,
    operation_id: [u8; 16],
    mutation_digest: [u8; 32],
    catalog: BindingWire,
    predecessor: BindingWire,
    result: BindingWire,
    observation_digest: [u8; 32],
    object_guid: Option<u64>,
    result_state: PhysicalCatalogState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeadPayload {
    format: CatalogRecordFormatV1,
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
