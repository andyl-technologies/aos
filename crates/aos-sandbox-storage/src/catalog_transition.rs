//! Protected physical Storage catalog transitions.
//!
//! The resolved request catalog selects one fixed mutation, while this module
//! owns the canonical physical state produced by observing that mutation. The
//! physical state deliberately excludes broker-minted resource handles: those
//! handles depend on the resulting catalog binding and remain authenticated in
//! the committed operation record. Rows instead retain the creating operation
//! and observed GUID, which gives restart validation a non-circular join.

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CatalogBindingV1, CatalogObjectKind, CatalogPlanV1, DurableStoragePhase, ManagedDatasetRoot,
    ProjectAncestorPolicyV1, ReservationPolicy, ResolvedCatalogCommitmentV1, ResolvedDataset,
    ResolvedSnapshot, StorageDomainsV1, StorageStateError, WorkspaceSpacePolicyV1,
};

mod format;

use format::{
    decode_authenticated, digest_bytes, encode_authenticated, encoded_transition_size,
    transition_digest, transition_payload, validate_catalog_chain, validate_head,
    validate_reservation_payload, validate_reserved_transition_bound, validate_transition_payload,
};

const STATE_MAGIC: &str = "AOSSCS01";
const RESERVATION_MAGIC: &str = "AOSSCR01";
const TRANSITION_MAGIC: &str = "AOSSCT01";
const HEAD_MAGIC: &str = "AOSSCH01";
const FORMAT_VERSION: u16 = 1;
const STORAGE_RECORD_LEGACY_VERSION: u16 = 2;
const STORAGE_RECORD_IDENTITY_VERSION: u16 = 3;
const STORAGE_RECORD_TRANSITION_VERSION: u16 = 4;
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
// bytes and the captured GUID to `u64::MAX`. Only the derived result-state
// digest and envelope MAC remain data-dependent byte arrays. JSON renders
// each byte in one to three decimal digits, so two extra digits per byte is a
// complete upper bound independent of their values.
const VARIABLE_TRANSITION_ARRAY_BYTES: usize = 32 + 32;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalCatalogState {
    wire: PhysicalStateWire,
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

impl PhysicalCatalogState {
    fn bootstrap(
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<Self, StorageStateError> {
        if generation == 0 || catalogs.is_empty() {
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
        Self::canonicalize(wire)
    }

    fn from_wire(wire: PhysicalStateWire) -> Result<Self, StorageStateError> {
        let original = wire.clone();
        let state = Self::canonicalize(wire)?;
        if state.wire != original {
            return Err(StorageStateError::CorruptRecord);
        }
        Ok(state)
    }

    fn canonicalize(mut wire: PhysicalStateWire) -> Result<Self, StorageStateError> {
        normalize_and_validate(&mut wire)?;
        let bytes = serde_json::to_vec(&wire).map_err(|_| StorageStateError::CorruptRecord)?;
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
            bytes,
            binding,
        })
    }

    fn apply(
        &self,
        operation_id: [u8; 16],
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
    ) -> Result<Self, StorageStateError> {
        if catalog.generation() != self.binding.generation().saturating_add(1) {
            return Err(StorageStateError::InvalidTransition);
        }
        let mut wire = self.wire.clone();
        ingest_plan_inputs(&mut wire, catalog.plan(), false)?;
        apply_postcondition(&mut wire, operation_id, catalog.plan(), object_guid)?;
        wire.generation = catalog
            .generation()
            .checked_add(1)
            .ok_or(StorageStateError::InvalidValue)?;
        wire.predecessor_state = Some(self.binding.into());
        wire.resolution = Some(catalog.binding().into());
        Self::canonicalize(wire)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationPayload {
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
struct TransitionPayload {
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
struct HeadPayload {
    magic: String,
    version: u16,
    binding: BindingWire,
    operation_id: Option<[u8; 16]>,
    transition_digest: Option<[u8; 32]>,
    genesis_state: Option<PhysicalStateWire>,
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

#[derive(Debug)]
pub(crate) struct StorageCatalogTransitionProvider {
    genesis: Option<CatalogBindingV1>,
    head: Option<PhysicalCatalogState>,
    reservations: BTreeMap<[u8; 16], CatalogReservation>,
    transitions: BTreeMap<[u8; 16], TransitionPayload>,
}

impl StorageCatalogTransitionProvider {
    pub(crate) fn load(
        journal: &Journal,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<Self, StorageStateError> {
        let mut reservations = BTreeMap::new();
        for (record_key, bytes) in journal.records(RecordNamespace::StorageCatalogReservation) {
            let payload: ReservationPayload = decode_authenticated(bytes, key_id, secret)?;
            validate_reservation_payload(&payload)?;
            if record_key != payload.operation_id {
                return Err(StorageStateError::CorruptRecord);
            }
            let predecessor = PhysicalCatalogState::from_wire(payload.predecessor_state.clone())?;
            if predecessor.binding != payload.predecessor.binding()? {
                return Err(StorageStateError::CorruptRecord);
            }
            let reservation = CatalogReservation {
                payload,
                bytes: bytes.to_vec(),
                predecessor,
            };
            if reservations
                .insert(reservation.payload.operation_id, reservation)
                .is_some()
            {
                return Err(StorageStateError::CorruptRecord);
            }
        }

        let mut transitions = BTreeMap::new();
        for (record_key, bytes) in journal.records(RecordNamespace::StorageCatalogTransition) {
            let payload: TransitionPayload = decode_authenticated(bytes, key_id, secret)?;
            if record_key != payload.operation_id {
                return Err(StorageStateError::CorruptRecord);
            }
            validate_transition_payload(&payload)?;
            if transitions.insert(payload.operation_id, payload).is_some() {
                return Err(StorageStateError::CorruptRecord);
            }
        }

        let head_payload = match journal.get(RecordNamespace::StorageCatalogHead, HEAD_KEY) {
            Some(bytes) => {
                let payload: HeadPayload = decode_authenticated(bytes, key_id, secret)?;
                validate_head(&payload, &transitions)?;
                Some(payload)
            }
            None if transitions.is_empty() && reservations.is_empty() => None,
            None => return Err(StorageStateError::CorruptRecord),
        };
        let head = match head_payload.as_ref() {
            Some(payload) => match (&payload.genesis_state, payload.operation_id) {
                (Some(wire), None) => Some(PhysicalCatalogState::from_wire(wire.clone())?),
                (None, Some(operation_id)) => {
                    let transition = transitions
                        .get(&operation_id)
                        .ok_or(StorageStateError::CorruptRecord)?;
                    Some(PhysicalCatalogState::from_wire(
                        transition.result_state.clone(),
                    )?)
                }
                _ => return Err(StorageStateError::CorruptRecord),
            },
            None => None,
        };
        validate_catalog_chain(
            head_payload.as_ref(),
            head.as_ref(),
            &reservations,
            &transitions,
        )?;
        let genesis = genesis_binding(head_payload.as_ref(), &reservations, &transitions)?;

        Ok(Self {
            genesis,
            head,
            reservations,
            transitions,
        })
    }

    pub(crate) fn prepare_bootstrap(
        &self,
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogBootstrap, StorageStateError> {
        if self.head.is_some() || !self.reservations.is_empty() || !self.transitions.is_empty() {
            return Err(StorageStateError::InvalidTransition);
        }
        let state = PhysicalCatalogState::bootstrap(generation, catalogs)?;
        let payload = HeadPayload {
            magic: HEAD_MAGIC.to_owned(),
            version: FORMAT_VERSION,
            binding: state.binding.into(),
            operation_id: None,
            transition_digest: None,
            genesis_state: Some(state.wire.clone()),
        };
        let head_bytes = encode_authenticated(&payload, key_id, secret)?;
        Ok(PreparedCatalogBootstrap { head_bytes, state })
    }

    pub(crate) fn head_binding(&self) -> Option<CatalogBindingV1> {
        self.head.as_ref().map(PhysicalCatalogState::binding)
    }

    pub(crate) fn workspace_projection(
        &self,
    ) -> Result<Vec<PhysicalWorkspaceProjection>, StorageStateError> {
        self.head
            .as_ref()
            .map(PhysicalCatalogState::workspace_projection)
            .ok_or(StorageStateError::InvalidTransition)
    }

    pub(crate) const fn genesis_binding(&self) -> Option<CatalogBindingV1> {
        self.genesis
    }

    pub(crate) fn bootstrap_binding(
        generation: u64,
        catalogs: &[ResolvedCatalogCommitmentV1],
    ) -> Result<CatalogBindingV1, StorageStateError> {
        PhysicalCatalogState::bootstrap(generation, catalogs).map(|state| state.binding)
    }

    pub(crate) fn install_bootstrap(&mut self, bootstrap: PreparedCatalogBootstrap) {
        self.genesis = Some(bootstrap.state.binding());
        self.head = Some(bootstrap.state);
    }

    pub(crate) fn reserve(
        &self,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<CatalogReservation, StorageStateError> {
        if let Some(existing) = self.reservations.get(&operation_id) {
            if existing.payload.request_digest == *request_digest.as_bytes()
                && existing.payload.mutation_digest == *mutation_digest.as_bytes()
                && existing.payload.catalog == catalog.binding().into()
                && existing.payload.catalog_bytes_digest == digest_bytes(catalog.canonical_bytes())
            {
                return Ok(existing.clone());
            }
            return Err(StorageStateError::Equivocation);
        }
        if self
            .reservations
            .keys()
            .any(|reserved| !self.transitions.contains_key(reserved))
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let predecessor = self
            .head
            .as_ref()
            .cloned()
            .ok_or(StorageStateError::InvalidTransition)?;
        if catalog.generation() != predecessor.binding.generation().saturating_add(1) {
            return Err(StorageStateError::InvalidTransition);
        }
        ingest_plan_inputs(&mut predecessor.wire.clone(), catalog.plan(), false)?;

        let worst_case_guid = capture_guid(catalog.plan()).then_some(u64::MAX);
        let worst_case_state = predecessor.apply(operation_id, catalog, worst_case_guid)?;
        let maximum_transition_bytes = encoded_transition_size(
            operation_id,
            mutation_digest,
            catalog,
            &predecessor,
            &worst_case_state,
            worst_case_guid,
            ObjectDigest::from_bytes([u8::MAX; 32]),
            key_id,
            secret,
        )?;
        if maximum_transition_bytes > MAXIMUM_RECORD_BYTES {
            return Err(StorageStateError::InvalidValue);
        }

        let payload = ReservationPayload {
            magic: RESERVATION_MAGIC.to_owned(),
            version: FORMAT_VERSION,
            operation_id,
            request_digest: *request_digest.as_bytes(),
            mutation_digest: *mutation_digest.as_bytes(),
            catalog: catalog.binding().into(),
            catalog_bytes_digest: digest_bytes(catalog.canonical_bytes()),
            predecessor: predecessor.binding.into(),
            predecessor_state: predecessor.wire.clone(),
            maximum_transition_bytes: u32::try_from(maximum_transition_bytes)
                .map_err(|_| StorageStateError::InvalidValue)?,
        };
        let bytes = encode_authenticated(&payload, key_id, secret)?;
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(CatalogReservation {
            payload,
            bytes,
            predecessor,
        })
    }

    pub(crate) fn reservation_record(reservation: &CatalogReservation) -> JournalRecord {
        JournalRecord::put(
            RecordNamespace::StorageCatalogReservation,
            reservation.payload.operation_id.to_vec(),
            reservation.bytes.clone(),
        )
    }

    pub(crate) fn effect_capacity_records(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Vec<JournalRecord>, StorageStateError> {
        let reservation = self
            .reservations
            .get(&operation_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        let transition_bytes = usize::try_from(reservation.payload.maximum_transition_bytes)
            .map_err(|_| StorageStateError::InvalidValue)?;
        Ok(vec![
            JournalRecord::put(
                RecordNamespace::StorageCatalogTransition,
                operation_id.to_vec(),
                vec![0; transition_bytes],
            ),
            JournalRecord::put(
                RecordNamespace::StorageCatalogHead,
                HEAD_KEY.to_vec(),
                vec![0; MAXIMUM_HEAD_BYTES],
            ),
        ])
    }

    pub(crate) fn install_reservation(&mut self, reservation: CatalogReservation) {
        self.reservations
            .insert(reservation.payload.operation_id, reservation);
    }

    #[cfg(test)]
    pub(crate) fn remove_reservation_for_test(&mut self, operation_id: [u8; 16]) {
        self.reservations.remove(&operation_id);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_transition(
        &self,
        operation_id: [u8; 16],
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        object_guid: Option<u64>,
        observation_digest: ObjectDigest,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<PreparedCatalogTransition, StorageStateError> {
        if self.transitions.contains_key(&operation_id) {
            return Err(StorageStateError::InvalidTransition);
        }
        let reservation = self
            .reservations
            .get(&operation_id)
            .ok_or(StorageStateError::InvalidTransition)?;
        if reservation.payload.mutation_digest != *mutation_digest.as_bytes()
            || reservation.payload.catalog != catalog.binding().into()
            || reservation.payload.catalog_bytes_digest != digest_bytes(catalog.canonical_bytes())
            || self
                .head
                .as_ref()
                .is_some_and(|head| head.binding != reservation.predecessor.binding)
        {
            return Err(StorageStateError::InvalidTransition);
        }
        if capture_guid(catalog.plan()) != object_guid.is_some()
            || object_guid == Some(0)
            || observation_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageStateError::InvalidValue);
        }
        let result_state = reservation
            .predecessor
            .apply(operation_id, catalog, object_guid)?;
        let transition = transition_payload(
            operation_id,
            mutation_digest,
            catalog,
            &reservation.predecessor,
            &result_state,
            object_guid,
            observation_digest,
        )?;
        let transition_bytes = encode_authenticated(&transition, key_id, secret)?;
        if transition_bytes.len() > reservation.payload.maximum_transition_bytes as usize
            || transition_bytes.len() > MAXIMUM_RECORD_BYTES
        {
            return Err(StorageStateError::InvalidTransition);
        }
        let transition_digest = transition_digest(&transition)?;
        let head_payload = HeadPayload {
            magic: HEAD_MAGIC.to_owned(),
            version: FORMAT_VERSION,
            binding: result_state.binding.into(),
            operation_id: Some(operation_id),
            transition_digest: Some(*transition_digest.as_bytes()),
            genesis_state: None,
        };
        let head_bytes = encode_authenticated(&head_payload, key_id, secret)?;
        if head_bytes.len() > MAXIMUM_HEAD_BYTES {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(PreparedCatalogTransition {
            operation_id,
            transition,
            transition_bytes,
            head_bytes,
            result_state,
        })
    }

    pub(crate) fn install_transition(&mut self, prepared: PreparedCatalogTransition) {
        self.head = Some(prepared.result_state);
        self.transitions
            .insert(prepared.operation_id, prepared.transition);
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validates_operation_transition(
        &self,
        record_version: u16,
        operation_id: [u8; 16],
        request_digest: ObjectDigest,
        mutation_digest: ObjectDigest,
        catalog: &ResolvedCatalogCommitmentV1,
        phase: DurableStoragePhase,
        result_catalog: Option<CatalogBindingV1>,
        key_id: [u8; 16],
        secret: &[u8; 32],
    ) -> Result<Option<CatalogTransitionEvidence>, StorageStateError> {
        let reservation = self.reservations.get(&operation_id);
        let transition = self.transitions.get(&operation_id);
        if matches!(
            record_version,
            STORAGE_RECORD_LEGACY_VERSION | STORAGE_RECORD_IDENTITY_VERSION
        ) {
            return if reservation.is_none() && transition.is_none() {
                Ok(None)
            } else {
                Err(StorageStateError::CorruptRecord)
            };
        }
        if record_version != STORAGE_RECORD_TRANSITION_VERSION {
            return Err(StorageStateError::CorruptRecord);
        }

        let reservation = reservation.ok_or(StorageStateError::CorruptRecord)?;
        if reservation.payload.request_digest != *request_digest.as_bytes()
            || reservation.payload.mutation_digest != *mutation_digest.as_bytes()
            || reservation.payload.catalog != catalog.binding().into()
            || reservation.payload.catalog_bytes_digest != digest_bytes(catalog.canonical_bytes())
        {
            return Err(StorageStateError::CorruptRecord);
        }
        validate_reserved_transition_bound(reservation, catalog, key_id, secret)?;

        match (phase, transition, result_catalog) {
            (DurableStoragePhase::Prepared | DurableStoragePhase::Ambiguous, None, None) => {
                Ok(None)
            }
            (DurableStoragePhase::Committed, Some(transition), Some(result_catalog)) => {
                let result_state =
                    reservation
                        .predecessor
                        .apply(operation_id, catalog, transition.object_guid)?;
                if transition.operation_id != operation_id
                    || transition.mutation_digest != *mutation_digest.as_bytes()
                    || transition.catalog != catalog.binding().into()
                    || transition.predecessor != reservation.payload.predecessor
                    || transition.result != result_state.binding.into()
                    || transition.result_state != result_state.wire
                    || result_catalog != result_state.binding
                {
                    return Err(StorageStateError::CorruptRecord);
                }
                Ok(Some(CatalogTransitionEvidence {
                    result_catalog,
                    observation_digest: ObjectDigest::from_bytes(transition.observation_digest),
                    object_guid: transition.object_guid,
                }))
            }
            _ => Err(StorageStateError::CorruptRecord),
        }
    }

    pub(crate) fn validate_operation_set(
        &self,
        operation_ids: impl Iterator<Item = [u8; 16]>,
    ) -> Result<(), StorageStateError> {
        let operations = operation_ids.collect::<std::collections::BTreeSet<_>>();
        if self
            .reservations
            .keys()
            .chain(self.transitions.keys())
            .any(|operation_id| !operations.contains(operation_id))
        {
            Err(StorageStateError::CorruptRecord)
        } else {
            Ok(())
        }
    }
}

fn genesis_binding(
    head: Option<&HeadPayload>,
    reservations: &BTreeMap<[u8; 16], CatalogReservation>,
    transitions: &BTreeMap<[u8; 16], TransitionPayload>,
) -> Result<Option<CatalogBindingV1>, StorageStateError> {
    let Some(head) = head else {
        return Ok(None);
    };
    if head.genesis_state.is_some() {
        return head.binding.binding().map(Some);
    }

    let transition_results = transitions
        .values()
        .map(|transition| transition.result.binding())
        .collect::<Result<Vec<_>, _>>()?;
    let mut roots = reservations
        .values()
        .filter(|reservation| transitions.contains_key(&reservation.payload.operation_id))
        .filter(|reservation| !transition_results.contains(&reservation.predecessor.binding))
        .map(|reservation| reservation.predecessor.binding);
    let root = roots.next().ok_or(StorageStateError::CorruptRecord)?;
    if roots.next().is_some() {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(Some(root))
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

fn normalize_and_validate(state: &mut PhysicalStateWire) -> Result<(), StorageStateError> {
    state.roots.sort();
    state.datasets.sort();
    state.snapshots.sort();
    state.holds.sort();
    state.tombstones.sort();
    if state.magic != STATE_MAGIC
        || state.version != FORMAT_VERSION
        || state.generation == 0
        || state.roots.len() > MAXIMUM_OBJECTS
        || state.datasets.len() > MAXIMUM_OBJECTS
        || state.snapshots.len() > MAXIMUM_OBJECTS
        || state.holds.len() > MAXIMUM_HOLDS
        || state.tombstones.len() > MAXIMUM_TOMBSTONES
        || !unique(state.roots.iter().map(|row| row.dataset_prefix.as_str()))
        || !unique(state.roots.iter().map(|row| row.guid))
        || !unique(state.datasets.iter().map(|row| row.name.as_str()))
        || !unique(state.datasets.iter().map(|row| row.guid))
        || !unique(state.snapshots.iter().map(|row| row.name.as_str()))
        || !unique(state.snapshots.iter().map(|row| row.guid))
        || !unique(
            state
                .holds
                .iter()
                .map(|row| (row.snapshot_name.as_str(), row.hold_id)),
        )
        || !unique(
            state
                .tombstones
                .iter()
                .map(|row| (row.kind, row.name.as_str())),
        )
        || !unique(state.tombstones.iter().map(|row| row.guid))
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let valid_name = |name: &str| !name.is_empty() && name.len() <= MAXIMUM_NAME_BYTES;
    if state
        .roots
        .iter()
        .any(|root| root.guid == 0 || !valid_name(&root.pool) || !valid_name(&root.dataset_prefix))
        || state
            .datasets
            .iter()
            .any(|row| row.guid == 0 || !valid_name(&row.name))
        || state.snapshots.iter().any(|row| {
            row.guid == 0
                || row.source_guid == 0
                || !valid_name(&row.name)
                || !valid_name(&row.source_name)
        })
        || state.holds.iter().any(|row| {
            row.snapshot_guid == 0 || row.hold_id == [0; 16] || !valid_name(&row.snapshot_name)
        })
        || state
            .tombstones
            .iter()
            .any(|row| row.guid == 0 || row.retired_by == [0; 16] || !valid_name(&row.name))
    {
        return Err(StorageStateError::CorruptRecord);
    }
    for hold in &state.holds {
        if !state.snapshots.iter().any(|snapshot| {
            snapshot.name == hold.snapshot_name && snapshot.guid == hold.snapshot_guid
        }) {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    for dataset in &state.datasets {
        if !state.roots.iter().any(|root| root == &dataset.root) {
            return Err(StorageStateError::CorruptRecord);
        }
        if let Some(origin) = &dataset.origin
            && !state
                .snapshots
                .iter()
                .any(|snapshot| snapshot.name == origin.name && snapshot.guid == origin.guid)
        {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    for snapshot in &state.snapshots {
        if !state.datasets.iter().any(|dataset| {
            dataset.name == snapshot.source_name && dataset.guid == snapshot.source_guid
        }) {
            return Err(StorageStateError::CorruptRecord);
        }
    }
    let live_guids = state
        .roots
        .iter()
        .map(|row| row.guid)
        .chain(state.datasets.iter().map(|row| row.guid))
        .chain(state.snapshots.iter().map(|row| row.guid));
    if !unique(live_guids)
        || state.tombstones.iter().any(|tombstone| {
            state.roots.iter().any(|row| row.guid == tombstone.guid)
                || state.datasets.iter().any(|row| row.guid == tombstone.guid)
                || state.snapshots.iter().any(|row| row.guid == tombstone.guid)
        })
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let creating_operations = state
        .datasets
        .iter()
        .filter_map(|row| row.created_by)
        .chain(state.snapshots.iter().filter_map(|row| row.created_by));
    if creating_operations
        .clone()
        .any(|operation| operation == [0; 16])
        || !unique(creating_operations)
    {
        return Err(StorageStateError::CorruptRecord);
    }
    if state.tombstones.iter().any(|tombstone| {
        state.datasets.iter().any(|row| row.name == tombstone.name)
            || state.snapshots.iter().any(|row| row.name == tombstone.name)
    }) {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(())
}

fn unique<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
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
